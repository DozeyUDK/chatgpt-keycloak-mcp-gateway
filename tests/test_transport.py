"""MCP 2025-11-25 Streamable HTTP transport smoke and negative tests."""
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.config import Settings


class DemoVerifier:
    def verify(self, token):
        return {"sub": "example", "scope": "mcp:read"}


@pytest.fixture
def client():
    return TestClient(create_app(
        Settings("https://mcp.example.com/mcp",
                 "https://auth.example.com/realms/demo",
                 "mcp-api",
                 allowed_origins=("https://client.example.com",)),
        verifier=DemoVerifier(),
    ))


def _post(client, **headers):
    values = {"Authorization": "Bearer demo", "Accept": "application/json, text/event-stream"}
    values.update(headers)
    return client.post("/mcp", headers=values,
                       json={"jsonrpc": "2.0", "id": 7, "method": "tools/list"})


def test_get_without_bearer_challenges(client):
    response = client.get("/mcp", headers={"Accept": "text/event-stream"})
    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["WWW-Authenticate"]


def test_get_with_bearer_returns_405_without_sse(client):
    response = client.get("/mcp", headers={
        "Authorization": "Bearer demo",
        "Accept": "text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
    })
    assert response.status_code == 405
    assert response.headers["Allow"] == "POST"


@pytest.mark.parametrize("origin", [
    "null",
    "https://attacker.example.com",
    "http://mcp.example.com",
    "https://mcp.example.com.attacker.test",
    "https://mcp.example.com/",
    "https://client.example.com.evil.test",
])
def test_untrusted_origins_denied(client, origin):
    assert _post(client, Origin=origin).status_code == 403
    assert client.get("/mcp", headers={"Origin": origin}).status_code == 403


@pytest.mark.parametrize("origin", ["https://mcp.example.com", "https://client.example.com"])
def test_exact_origins_allowed(client, origin):
    assert _post(client, Origin=origin).status_code == 200


def test_server_to_server_without_origin_allowed(client):
    assert _post(client).status_code == 200


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18", "2025-03-26"])
def test_supported_protocol_version(client, version):
    assert _post(client, **{"MCP-Protocol-Version": version}).status_code == 200


@pytest.mark.parametrize("version", ["2026-99-99", "2024-11-05", "1", "", "2025-11-25,2025-06-18"])
def test_bad_protocol_version(client, version):
    # Empty version header is invalid too: a present header must be supported.
    assert _post(client, **{"MCP-Protocol-Version": version}).status_code == 400


def test_missing_write_scope_gets_mcp_scope_challenge(tmp_path):
    import json
    from pathlib import Path
    from gateway.policy import load_policy

    workspace = tmp_path / "approved"
    workspace.mkdir()
    policy_data = json.loads(
        (Path(__file__).resolve().parents[1] / "config/policy.example.json").read_text()
    )
    policy_data["capabilities"]["WRITE_AND_ACCESS"] = True
    policy_data["filesystem"]["EDITABLE_ROOTS"] = [str(workspace)]
    policy_data["tools"]["fs_write"]["enabled"] = True
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    policy_file.chmod(0o444)

    class ReadOnlyVerifier:
        def verify(self, token):
            return {"scope": "mcp:read", "realm_access": {"roles": ["mcp-writer"]}}

    app = create_app(
        Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api"),
        verifier=ReadOnlyVerifier(),
        policy=load_policy(policy_file),
    )
    client = TestClient(app)
    response = client.post(
        "/mcp",
        headers={"Authorization": "Bearer test", "Accept": "application/json, text/event-stream"},
        json={"jsonrpc": "2.0", "id": 8, "method": "tools/call",
              "params": {"name": "fs_write", "arguments": {
                  "path": str(workspace / "forbidden.txt"), "content": "no"}
              }},
    )
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]
    assert 'scope="mcp:read mcp:write"' in response.headers["www-authenticate"]
    assert not (workspace / "forbidden.txt").exists()


def test_denied_write_role_is_not_falsely_labeled_missing_scope(tmp_path):
    import json
    from pathlib import Path
    from gateway.policy import load_policy

    workspace = tmp_path / "approved"
    workspace.mkdir()
    policy_data = json.loads(
        (Path(__file__).resolve().parents[1] / "config/policy.example.json").read_text()
    )
    policy_data["capabilities"]["WRITE_AND_ACCESS"] = True
    policy_data["filesystem"]["EDITABLE_ROOTS"] = [str(workspace)]
    policy_data["tools"]["fs_write"]["enabled"] = True
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(policy_data))
    policy_file.chmod(0o444)

    class NoRoleVerifier:
        def verify(self, token):
            return {"scope": "mcp:read mcp:write", "realm_access": {"roles": ["guest"]}}

    client = TestClient(create_app(
        Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api"),
        verifier=NoRoleVerifier(), policy=load_policy(policy_file),
    ))
    r = client.post("/mcp", headers={"Authorization": "Bearer example"},
                    json={"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                          "params": {"name": "fs_write", "arguments": {
                              "path": str(workspace / "blocked.txt"), "content": "no"
                          }}})
    assert r.status_code == 403
    assert "insufficient_scope" not in r.text
    assert not (workspace / "blocked.txt").exists()


@pytest.mark.parametrize("origins", [
    ("http://client.example.com",),
    ("https://client.example.com/path",),
    ("https://client.example.com/",),
    ("*",),
    ("null",),
])
def test_invalid_configured_origins_rejected(origins):
    with pytest.raises(ValueError):
        Settings("https://mcp.example.com/mcp",
                 "https://auth.example.com/realms/demo",
                 "mcp-api",
                 allowed_origins=origins)
