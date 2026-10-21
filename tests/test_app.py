import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.auth import AuthBackendError, InsufficientScope, InvalidAccessToken
from gateway.config import Settings


@pytest.fixture
def client():
    settings = Settings(
        public_url="https://mcp.example.com/mcp",
        issuer="https://auth.example.com/realms/demo",
        audience="mcp-api",
    )

    class FakeVerifier:
        def verify(self, token):
            if token == "ok":
                return {"sub": "demo", "scope": "mcp:read"}
            if token == "no-scope":
                raise InsufficientScope()
            if token == "backend-down":
                raise AuthBackendError()
            raise InvalidAccessToken()

    return TestClient(create_app(settings, FakeVerifier()))


def rpc(client, method, *, token="ok", params=None, request_id=1):
    return client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}},
    )


def test_health_public(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_metadata_public_and_both_locations(client):
    for location in ["/.well-known/oauth-protected-resource",
                     "/.well-known/oauth-protected-resource/mcp"]:
        r = client.get(location)
        assert r.status_code == 200
        assert r.json() == {
            "resource": "https://mcp.example.com/mcp",
            "authorization_servers": ["https://auth.example.com/realms/demo"],
            "scopes_supported": ["mcp:read"],
            "bearer_methods_supported": ["header"],
        }


def test_missing_auth_has_resource_metadata_challenge(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert 'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"' in r.headers["www-authenticate"]
    assert 'scope="mcp:read"' in r.headers["www-authenticate"]


@pytest.mark.parametrize("header", ["Basic AAA", "Bearer bad", "Bearer ok trailing", "Bearer"])
def test_bad_bearer_fails(client, header):
    r = client.post("/mcp", headers={"Authorization": header}, json={"method": "ping"})
    assert r.status_code == 401


def test_missing_scope_fails_403(client):
    assert rpc(client, "tools/list", token="no-scope").status_code == 403


def test_backend_error_fails_closed_503(client):
    assert rpc(client, "tools/list", token="backend-down").status_code == 503


def test_initialize_and_tools(client):
    r = rpc(client, "initialize", params={"protocolVersion": "2025-11-25"})
    assert r.status_code == 200
    assert r.json()["result"]["protocolVersion"] == "2025-11-25"
    assert rpc(client, "tools/list").json()["result"]["tools"][0]["name"] == "demo_ping"
    assert rpc(client, "tools/call", params={"name": "demo_ping", "arguments": {}}).json()["result"]["content"][0]["text"] == "pong"


def test_notification_has_no_body(client):
    r = client.post("/mcp", headers={"Authorization": "Bearer ok"}, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202
    assert not r.content


def test_unrecognized_method_is_not_executed(client):
    r = rpc(client, "tools/call", params={"name": "shell_exec", "arguments": {"command": "id"}})
    assert r.json()["error"]["code"] == -32602


def test_invalid_payload_and_size(client):
    r = client.post("/mcp", headers={"Authorization": "Bearer ok", "Content-Type": "text/plain"}, content="hi")
    assert r.status_code == 415
    r = client.post("/mcp", headers={"Authorization": "Bearer ok", "Content-Type": "application/json"},
                    content="[" + "a" * 66000 + "]")
    assert r.status_code == 413


def test_unknown_method(client):
    assert rpc(client, "resources/list").json()["error"]["code"] == -32601
