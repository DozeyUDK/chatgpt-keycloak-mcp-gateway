"""Minimal structured authorization audit events without token or file content leaks.

Audit records are intentionally metadata-only. Production should send them to
a protected collector with retention and rate limits configured outside MCP.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

LOG = logging.getLogger("gateway.audit")
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(_handler)
LOG.propagate = False  # Avoid duplicate events if the host configures root logging.

KNOWN_TOOLS = frozenset({"demo_ping", "permissions_inspect", "fs_read", "fs_write"})
KNOWN_REASONS = frozenset({
    "ok", "disabled", "missing_scope", "role_or_group_denied",
    "bad_arguments", "invalid_path", "unknown_tool",
})


def _fingerprint(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def record_tool_event(
    claims: dict[str, Any],
    name: Any,
    decision: str,
    reason: str,
    arguments: Any = None,
) -> None:
    """Log only stable metadata; never log raw JWTs, paths or file contents."""
    entry: dict[str, Any] = {
        "event": "mcp_tool_authorization",
        "subject_hash": _fingerprint(claims.get("sub")),
        "tool": name if isinstance(name, str) and name in KNOWN_TOOLS else "unknown",
        "decision": decision if decision in {"allow", "deny"} else "deny",
        "reason": reason if reason in KNOWN_REASONS else "unknown",
    }
    if isinstance(arguments, dict):
        path = arguments.get("path")
        if isinstance(path, str):
            entry["path_hash"] = _fingerprint(path)
        # Values, JWT claims, argument names and full source paths intentionally omitted.
        content = arguments.get("content")
        if isinstance(content, str):
            entry["content_bytes"] = len(content.encode("utf-8", errors="replace"))
    LOG.info("%s", json.dumps(entry, sort_keys=True, separators=(",", ":")))
