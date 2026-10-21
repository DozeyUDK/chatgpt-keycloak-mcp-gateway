"""Authorization decision audit: emit a structured event without secrets."""
import json
import logging

from fastapi.testclient import TestClient
from gateway.app import create_app
from gateway.config import Settings
from gateway.policy import load_policy
from tests.test_policy import policy_fixture


class ReaderWriterVerifier:
    def verify(self, token):
        return {
            "sub": "test-sensitive-subject",
            "scope": "mcp:read mcp:write",
            "realm_access": {"roles": ["mcp-reader", "mcp-writer"]},
        }


def _client(policy):
    settings = Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api")
    return TestClient(create_app(settings, verifier=ReaderWriterVerifier(), policy=policy))


def _call(client, name, args):
    return client.post("/mcp", headers={"Authorization": "Bearer testing"},
                       json={"jsonrpc": "2.0", "id": 42, "method": "tools/call",
                             "params": {"name": name, "arguments": args}})


def test_audit_records_allow_and_denied_without_arguments(tmp_path, caplog):
    root, policy_file = policy_fixture(tmp_path)
    client = _client(load_policy(policy_file))
    logging.getLogger("gateway.audit").addHandler(caplog.handler)
    caplog.set_level(logging.INFO, logger="gateway.audit")
    path = str(root / "my-private-filename.txt")
    secret_payload = "do-not-log-this-contents"
    ok = _call(client, "fs_write", {"path": path, "content": secret_payload})
    assert ok.status_code == 200
    denied = _call(client, "fs_write", {"path": "/etc/passwd", "content": secret_payload})
    assert denied.json()["error"]["code"] == -32602
    raw_records = [record.getMessage() for record in caplog.records if record.name == "gateway.audit"]
    assert len(raw_records) == 2
    records = [json.loads(item) for item in raw_records]
    assert records[0]["decision"] == "allow"
    assert records[0]["reason"] == "ok"
    assert records[1]["decision"] == "deny"
    assert records[1]["reason"] == "invalid_path"
    assert all(event["tool"] == "fs_write" for event in records)
    assert all(event["subject_hash"] for event in records)
    assert "path_hash" in records[0]
    assert "content_bytes" in records[0]
    logged = " ".join(raw_records)
    for secret in [secret_payload, path, "/etc/passwd", "testing", "test-sensitive-subject"]:
        assert secret not in logged


def test_audit_logs_disabled_tool_without_bad_input(tmp_path, caplog):
    _, policy_file = policy_fixture(tmp_path, write=False)
    client = _client(load_policy(policy_file))
    logging.getLogger("gateway.audit").addHandler(caplog.handler)
    caplog.set_level(logging.INFO, logger="gateway.audit")
    response = _call(client, "fs_write", {"path": "/etc/shadow", "content": "private"})
    assert response.json()["error"]["code"] == -32602
    raw = [record.getMessage() for record in caplog.records if record.name == "gateway.audit"]
    assert len(raw) == 1
    obj = json.loads(raw[0])
    assert obj["decision"] == "deny"
    assert obj["reason"] == "disabled"
    assert "/etc/shadow" not in raw[0]
    assert "private" not in raw[0]
