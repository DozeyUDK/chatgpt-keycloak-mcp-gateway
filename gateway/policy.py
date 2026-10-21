"""Immutable-at-runtime role/group + tool + filesystem authorization policy.

A valid Keycloak OAuth access token is a prerequisite, NOT a capability grant.
Policy paths are host-operated, container-mounted read-only and never writable
through the MCP tool interface. Invalid/missing policy => fail startup.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_TOOLS = frozenset({"demo_ping", "permissions_inspect", "fs_read", "fs_write"})
PRIVILEGED_TOOLS = frozenset({"fs_read", "fs_write"})
FORBIDDEN_ROOTS = frozenset({"/", "/etc", "/root", "/proc", "/sys", "/dev", "/run", "/var/run"})


def _keys(obj: Any, allowed: set[str], required: set[str] = frozenset()) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("Invalid policy: expected an object")
    if not required.issubset(obj) or set(obj) - allowed:
        raise ValueError("Invalid policy keys (unsupported or missing)")
    return obj


def _string_list(obj: Any) -> tuple[str, ...]:
    if not isinstance(obj, list) or len(obj) > 100 or any(
        not isinstance(x, str) or not x.strip() or x != x.strip() or len(x) > 255
        for x in obj
    ):
        raise ValueError("Invalid policy string list")
    if len(obj) != len(set(obj)):
        raise ValueError("Duplicate policy entries")
    return tuple(obj)


def _roots(obj: Any, *, policy_file: Path) -> tuple[Path, ...]:
    values = _string_list(obj)
    roots: list[Path] = []
    for value in values:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or str(path) != value:
            raise ValueError("Root must be a normalized absolute path")
        # Require pre-existing physical directory; never follow symlink roots.
        if not path.is_dir() or path.is_symlink() or path.resolve() != path:
            raise ValueError("Root does not exist or contains symlinks")
        if str(path) in FORBIDDEN_ROOTS or any(
            str(path) == p or str(path).startswith(p + "/")
            for p in ("/etc", "/proc", "/sys", "/dev", "/run", "/root")
        ):
            raise ValueError("Reserved system directories may not be roots")
        if path == policy_file or path in policy_file.parents:
            raise ValueError("Policy file must not reside in a tool-accessible root")
        roots.append(path)
    for index, first in enumerate(roots):
        for other in roots[index + 1:]:
            if first in other.parents or other in first.parents:
                raise ValueError("Overlapping roots are not allowed")
    return tuple(roots)


@dataclass(frozen=True)
class ToolRule:
    enabled: bool
    scopes: tuple[str, ...]
    any_roles: tuple[str, ...]
    any_groups: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    file: Path
    client_id: str
    capabilities: dict[str, bool]
    readable_roots: tuple[Path, ...]
    editable_roots: tuple[Path, ...]
    max_read_bytes: int
    max_write_bytes: int
    tools: dict[str, ToolRule]

    def enabled(self, name: str) -> bool:
        rule = self.tools.get(name)
        if rule is None or not rule.enabled:
            return False
        if name == "permissions_inspect":
            return self.capabilities["INSPECT_PERMISSIONS"]
        if name == "fs_read":
            return self.capabilities["READ_ACCESS"] and bool(self.readable_roots)
        if name == "fs_write":
            return self.capabilities["WRITE_AND_ACCESS"] and bool(self.editable_roots)
        return True

    def allowed(self, name: str, claims: dict[str, Any]) -> bool:
        if not self.enabled(name):
            return False
        rule = self.tools[name]
        raw_scopes = claims.get("scope", "")
        scopes = set(raw_scopes.split()) if isinstance(raw_scopes, str) else set()
        if not set(rule.scopes).issubset(scopes):
            return False
        realm = claims.get("realm_access")
        rroles = realm.get("roles", []) if isinstance(realm, dict) else []
        resource = claims.get("resource_access")
        client = resource.get(self.client_id) if isinstance(resource, dict) else None
        croles = client.get("roles", []) if isinstance(client, dict) else []
        roles = {r for r in [*rroles, *croles] if isinstance(r, str)} if isinstance(rroles, list) and isinstance(croles, list) else set()
        raw_groups = claims.get("groups")
        groups = {g for g in raw_groups if isinstance(g, str)} if isinstance(raw_groups, list) else set()
        # Privileged tools MUST specify at least one role or group constraint.
        if name in PRIVILEGED_TOOLS and not (rule.any_roles or rule.any_groups):
            return False
        if rule.any_roles or rule.any_groups:
            if not (roles.intersection(rule.any_roles) or groups.intersection(rule.any_groups)):
                return False
        return True

    def inspect(self, claims: dict[str, Any]) -> dict:
        # No absolute host paths or privileged deployment secrets are returned.
        hints = {
            "fs_read": "Admin: set READ_ACCESS=true, READABLE_ROOTS, tools.fs_read.enabled; grant its role/group.",
            "fs_write": "Admin: set WRITE_AND_ACCESS=true, EDITABLE_ROOTS, tools.fs_write.enabled; grant mcp:write and its role/group; mount approved roots RW.",
            "permissions_inspect": "Admin: set INSPECT_PERMISSIONS=true, tools.permissions_inspect.enabled.",
        }
        return {
            "policy_version": 1,
            "capabilities": {
                name: {"available": self.allowed(name, claims), "admin_action_if_disabled": None if self.allowed(name, claims) else hints.get(name, "Admin: enable this tool in the policy.")}
                for name in sorted(SUPPORTED_TOOLS)
            },
            "policy_managed_outside_agent": True,
        }


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    if not p.is_absolute() or p.is_symlink() or not p.is_file():
        raise ValueError("POLICY_FILE must reference a regular absolute non-symlink file")
    # Policy should be mounted read-only by host and must not be writable by
    # runtime uid (mode bits are not definitive; deployment enforces ro mount).
    if os.access(p, os.W_OK) and os.geteuid() != 0:
        raise ValueError("POLICY_FILE is writable by connector process")
    with p.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("Policy file too large")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid policy JSON") from exc
    _keys(data, {"version", "keycloak", "capabilities", "filesystem", "tools"},
          {"version", "keycloak", "capabilities", "filesystem", "tools"})
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("Unsupported policy version")
    kc = _keys(data["keycloak"], {"client_id"}, {"client_id"})
    client_id = kc["client_id"]
    if not isinstance(client_id, str) or not client_id or len(client_id) > 128:
        raise ValueError("Invalid keycloak client_id")
    caps = _keys(data["capabilities"],
                 {"WRITE_AND_ACCESS", "READ_ACCESS", "INSPECT_PERMISSIONS"},
                 {"WRITE_AND_ACCESS", "READ_ACCESS", "INSPECT_PERMISSIONS"})
    if any(type(val) is not bool for val in caps.values()):
        raise ValueError("Capabilities must be booleans")
    fs = _keys(data["filesystem"],
               {"READABLE_ROOTS", "EDITABLE_ROOTS", "max_read_bytes", "max_write_bytes"},
               {"READABLE_ROOTS", "EDITABLE_ROOTS", "max_read_bytes", "max_write_bytes"})
    max_read = fs["max_read_bytes"]
    max_write = fs["max_write_bytes"]
    for limit in (max_read, max_write):
        if type(limit) is not int or not 1 <= limit <= 1_048_576:
            raise ValueError("Invalid max read/write size")
    readable = _roots(fs["READABLE_ROOTS"], policy_file=p)
    editable = _roots(fs["EDITABLE_ROOTS"], policy_file=p)
    parsed: dict[str, ToolRule] = {}
    _keys(data["tools"], set(SUPPORTED_TOOLS), {"demo_ping", "permissions_inspect", "fs_read", "fs_write"})
    for name, raw_rule in data["tools"].items():
        _keys(raw_rule, {"enabled", "required_scopes", "any_roles", "any_groups"},
              {"enabled", "required_scopes", "any_roles", "any_groups"})
        if type(raw_rule["enabled"]) is not bool:
            raise ValueError("Invalid tool enable flag")
        scopes = _string_list(raw_rule["required_scopes"])
        roles = _string_list(raw_rule["any_roles"])
        groups = _string_list(raw_rule["any_groups"])
        if not scopes or not set(scopes).issuperset({"mcp:read"}):
            raise ValueError("Every tool requires mcp:read scope")
        if name == "fs_write" and "mcp:write" not in scopes:
            raise ValueError("fs_write must also require mcp:write")
        if name in PRIVILEGED_TOOLS and raw_rule["enabled"] and not (roles or groups):
            raise ValueError("Privileged tools require explicit role/group constraints")
        parsed[name] = ToolRule(raw_rule["enabled"], scopes, roles, groups)
    return Policy(p, client_id, dict(caps), readable, editable, max_read, max_write, parsed)
