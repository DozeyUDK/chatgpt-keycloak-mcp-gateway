"""Integration test: real RS256 JWT signature -> MCP HTTP -> policy -> filesystem.

Keycloak discovery/JWKS HTTP is stubbed; this is NOT a real-Keycloak or
ChatGPT browser-login end-to-end test.
"""
import json

from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings
from gateway.policy import load_policy
from tests.test_auth import signed, fixture_keys
from tests.test_policy import policy_fixture


def test_signed_access_token_authorizes_real_mcp_file_io(monkeypatch, fixture_keys, tmp_path):
    private_key, jwks = fixture_keys
    workspace, private_policy = policy_fixture(tmp_path)
    settings = Settings(
        "https://mcp.example.com/mcp",
        "https://auth.example.com/realms/demo",
        "mcp-api",
    )
    seen = []

    def mock_oidc_fetch(url):
        seen.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": settings.issuer,
                "jwks_uri": "https://auth.example.com/realms/demo/protocol/openid-connect/certs",
            }
        assert url == "https://auth.example.com/realms/demo/protocol/openid-connect/certs"
        return jwks

    monkeypatch.setattr("gateway.auth._fetch_json", mock_oidc_fetch)
    # Uses the real OIDCVerifier, not a fake verifier.
    client = TestClient(create_app(settings, policy=load_policy(private_policy)))

    token = signed(
        private_key,
        scope="mcp:read mcp:write",
        realm_access={"roles": ["mcp-reader", "mcp-writer"]},
    )
    headers = {"Authorization": f"Bearer {token}"}

    def call(method, params=None):
        return client.post(
            "/mcp", headers=headers,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        )

    names = {item["name"] for item in call("tools/list").json()["result"]["tools"]}
    assert "fs_write" in names
    assert "fs_read" in names
    assert seen and len(seen) == 2  # discovery + JWKS loaded and cached

    target = str(workspace / "integrated.txt")
    write = call("tools/call", {"name": "fs_write",
                                "arguments": {"path": target, "content": "signed-jwt-ok"}})
    assert write.status_code == 200
    assert json.loads(write.json()["result"]["content"][0]["text"]) == {"bytes_written": 13}
    assert call("tools/call", {"name": "fs_read",
                              "arguments": {"path": target}}).json()["result"]["content"][0]["text"] == "signed-jwt-ok"

    token_without_write = signed(
        private_key,
        scope="mcp:read",
        realm_access={"roles": ["mcp-reader", "mcp-writer"]},
    )
    denial = client.post("/mcp", headers={"Authorization": f"Bearer {token_without_write}"},
                         json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "fs_write",
                                          "arguments": {"path": target, "content": "denied"}}})
    assert denial.status_code == 403
    assert (workspace / "integrated.txt").read_text() == "signed-jwt-ok"
