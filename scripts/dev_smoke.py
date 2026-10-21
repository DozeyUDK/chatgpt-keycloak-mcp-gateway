"""Local integration smoke: a *real* Keycloak access token calling MCP.

The client secret is a throwaway development-only value provisioned by
dev/keycloak/realm.json. Never run this against a production realm.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = os.environ["KEYCLOAK_DEV_ISSUER"]
CLIENT_ID = os.environ["KEYCLOAK_DEV_CLIENT_ID"]
CLIENT_SECRET = os.environ["KEYCLOAK_DEV_CLIENT_SECRET"]
MCP = os.environ["MCP_DEV_LOCAL_URL"]


def request_json(url: str, *, payload: bytes | None = None, bearer: str | None = None) -> tuple[int, dict]:
    headers = {"Accept": "application/json, text/event-stream"}
    if payload is not None:
        headers["Content-Type"] = "application/json" if bearer else "application/x-www-form-urlencoded"
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    request = urllib.request.Request(url, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, json.loads(response.read(65536))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read(65536))


def token_from_keycloak() -> str:
    token_url = ISSUER + "/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "mcp:read",
    }).encode("utf-8")
    end = time.monotonic() + 150
    last_error = "Keycloak not ready"
    while time.monotonic() < end:
        try:
            status, body = request_json(token_url, payload=data)
            if status != 200:
                raise RuntimeError(f"Keycloak token endpoint returned HTTP {status}; check imported dev realm")
            token = body.get("access_token")
            if not isinstance(token, str) or not token:
                raise RuntimeError("Keycloak returned no access_token")
            return token
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = type(exc).__name__
            time.sleep(3)
    raise RuntimeError(f"Keycloak failed to become reachable: {last_error}")


def rpc(token: str, method: str, parameters: dict | None = None) -> tuple[int, dict]:
    packet = {"jsonrpc": "2.0", "id": 1, "method": method, "params": parameters or {}}
    return request_json(MCP, payload=json.dumps(packet).encode(), bearer=token)


def run() -> None:
    token = token_from_keycloak()
    # No printing of bearer token, client secret or credential-bearing request.
    print("PASS: obtained signed OAuth access token from real local Keycloak")

    status, initialized = rpc(token, "initialize", {"protocolVersion": "2025-11-25"})
    assert status == 200 and initialized.get("result", {}).get("protocolVersion") == "2025-11-25", "MCP initialize failed"
    print("PASS: authenticated MCP initialize")

    status, tools = rpc(token, "tools/list")
    assert status == 200 and "result" in tools, "tools/list failed"
    names = {item["name"] for item in tools["result"]["tools"]}
    assert names == {"demo_ping", "permissions_inspect"}, f"Unexpected tools: {sorted(names)}"
    print("PASS: policy filters tools (fs_read/fs_write remain disabled)")

    status, pong = rpc(token, "tools/call", {"name": "demo_ping", "arguments": {}})
    assert status == 200 and pong["result"]["content"][0]["text"] == "pong", "demo_ping failed"
    print("PASS: real access token -> tools/call -> demo_ping")

    status, inspected = rpc(token, "tools/call", {"name": "permissions_inspect", "arguments": {}})
    assert status == 200 and inspected.get("result"), "permissions_inspect failed"
    print("PASS: permission introspection")

    status, _ = rpc("not-a-valid-jwt", "tools/list")
    assert status == 401, f"Invalid JWT should be 401, received {status}"
    print("PASS: invalid JWT rejected")

    status, denied = rpc(token, "tools/call", {"name": "fs_write", "arguments": {
        "path": "/etc/passwd", "content": "deny",
    }})
    assert status == 200 and denied.get("error"), "Disabled write tool unexpectedly succeeded"
    print("PASS: disabled filesystem write rejected")

    print("ALL LOCAL KEYCLOAK-MCP SMOKE CHECKS PASSED")


if __name__ == "__main__":
    run()
