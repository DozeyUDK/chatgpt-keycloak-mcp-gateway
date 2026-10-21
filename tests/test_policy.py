"""Security tests for policy grants and filesystem root boundaries."""
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from gateway.app import create_app
from gateway.config import Settings
from gateway.fs_safe import FileAccessDenied, read_text, write_text
from gateway.policy import load_policy


def policy_fixture(tmp_path, *, write=True, read=True, mutate=None):
    root = tmp_path / "workspace"
    root.mkdir()
    data = json.loads((Path(__file__).resolve().parents[1] / "config/policy.example.json").read_text())
    data["filesystem"]["READABLE_ROOTS"] = [str(root)]
    data["filesystem"]["EDITABLE_ROOTS"] = [str(root)]
    data["capabilities"]["WRITE_AND_ACCESS"] = write
    data["capabilities"]["READ_ACCESS"] = read
    data["tools"]["fs_read"]["enabled"] = True
    data["tools"]["fs_write"]["enabled"] = True
    if mutate:
        mutate(data)
    config = tmp_path / "policy.json"
    config.write_text(json.dumps(data))
    config.chmod(0o444)
    return root, config


def claims(roles=(), groups=(), scope="mcp:read mcp:write"):
    return {
        "scope": scope,
        "realm_access": {"roles": list(roles)},
        "resource_access": {"mcp-api": {"roles": []}},
        "groups": list(groups),
    }


def test_roles_groups_scopes_all_required(tmp_path):
    _, config = policy_fixture(tmp_path)
    p = load_policy(config)
    assert p.allowed("fs_write", claims(roles=["mcp-writer"]))
    assert p.allowed("fs_write", claims(groups=["/ai-writers"]))
    assert p.allowed("fs_read", claims(roles=["mcp-reader"]))
    assert p.allowed("fs_read", claims(groups=["/ai-readers"]))
    assert not p.allowed("fs_write", claims(roles=["mcp-reader"]))
    assert not p.allowed("fs_read", claims(roles=["mcp-writer"]))
    assert not p.allowed("fs_write", claims(roles=["mcp-writer"], scope="mcp:read"))
    token = claims()
    token["resource_access"]["other-client"] = {"roles": ["mcp-writer"]}
    assert not p.allowed("fs_write", token)
    token["resource_access"]["mcp-api"] = {"roles": ["mcp-writer"]}
    assert p.allowed("fs_write", token)


def test_disabled_write_even_with_role_and_scopes(tmp_path):
    _, config = policy_fixture(tmp_path, write=False)
    p = load_policy(config)
    assert not p.allowed("fs_write", claims(roles=["mcp-writer"]))
    assert "WRITE_AND_ACCESS=true" in p.inspect(claims())["capabilities"]["fs_write"]["admin_action_if_disabled"]


def test_tool_dispatch_respects_policy(tmp_path):
    root, config = policy_fixture(tmp_path)
    p = load_policy(config)
    class Verifier:
        def verify(self, token):
            return claims(roles=["mcp-reader", "mcp-writer"])
    app = create_app(Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api"),
                     verifier=Verifier(), policy=p)
    client = TestClient(app)
    def invoke(method, params=None):
        return client.post("/mcp",
                           headers={"Authorization": "Bearer test"},
                           json={"jsonrpc": "2.0", "id": 10, "method": method, "params": params or {}}).json()
    names = {tool["name"] for tool in invoke("tools/list")["result"]["tools"]}
    assert {"demo_ping", "permissions_inspect", "fs_read", "fs_write"} == names
    path = str(root / "demo.txt")
    result = invoke("tools/call", {"name": "fs_write", "arguments": {"path": path, "content": "hello"}})
    assert json.loads(result["result"]["content"][0]["text"]) == {"bytes_written": 5}
    assert invoke("tools/call", {"name": "fs_read", "arguments": {"path": path}})["result"]["content"][0]["text"] == "hello"
    assert root.joinpath("demo.txt").read_text() == "hello"


@pytest.mark.parametrize("relative", [
    "../outside.txt", "sub/../../outside.txt", ".env", ".git/config",
    "policy.json", ".ssh/id_ed25519", "sub/../data.txt",
])
def test_path_denied(tmp_path, relative):
    root = tmp_path / "workspace"
    root.mkdir()
    path = str(root / relative)
    with pytest.raises(FileAccessDenied):
        write_text((root,), path, "blocked", 128)
    with pytest.raises(FileAccessDenied):
        read_text((root,), path, 128)


def test_symlink_and_hardlink(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private")
    (root / "link.txt").symlink_to(outside)
    with pytest.raises(FileAccessDenied):
        read_text((root,), str(root / "link.txt"), 1024)
    with pytest.raises(FileAccessDenied):
        write_text((root,), str(root / "link.txt"), "bad", 1024)
    (root / "dirlink").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(FileAccessDenied):
        write_text((root,), str(root / "dirlink" / "other.txt"), "bad", 1024)
    os.link(outside, root / "hardlink.txt")
    write_text((root,), str(root / "hardlink.txt"), "replacement", 1024)
    assert outside.read_text() == "private"
    assert (root / "hardlink.txt").read_text() == "replacement"


def test_limits_and_outside_root(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    with pytest.raises(FileAccessDenied):
        write_text((root,), str(tmp_path / "outside.txt"), "bad", 4)
    with pytest.raises(FileAccessDenied):
        write_text((root,), str(root / "a.txt"), "too long", 3)


def test_policy_file_inside_root_denied(tmp_path):
    def mutate(data):
        data["filesystem"]["READABLE_ROOTS"] = []
        data["filesystem"]["EDITABLE_ROOTS"] = [str(tmp_path)]
    _, config = policy_fixture(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="Policy file"):
        load_policy(config)


@pytest.mark.parametrize("mutation", [
    lambda d: d["capabilities"].update({"WRITE_AND_ACCESS": "true"}),
    lambda d: d["tools"]["fs_write"].update({"required_scopes": ["mcp:read"]}),
    lambda d: d["tools"]["fs_write"].update({"any_roles": [], "any_groups": []}),
    lambda d: d["tools"]["fs_write"].update({"enabled": "true"}),
    lambda d: d.update({"unrecognized_key": True}),
])
def test_policy_schema_fails_closed(tmp_path, mutation):
    _, config = policy_fixture(tmp_path, mutate=mutation)
    with pytest.raises(ValueError):
        load_policy(config)


def test_policy_inspection_redacts_roots(tmp_path):
    root, config = policy_fixture(tmp_path, write=False)
    p = load_policy(config)
    result = p.inspect(claims())
    assert str(root) not in json.dumps(result)
    assert result["capabilities"]["fs_write"]["available"] is False
