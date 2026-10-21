"""Only public fictitious example values are injected for import-time app setup."""
import os
import atexit
import shutil
import tempfile
from pathlib import Path

os.environ.setdefault("MCP_PUBLIC_URL", "https://mcp.example.com/mcp")
os.environ.setdefault("KEYCLOAK_ISSUER", "https://auth.example.com/realms/demo")
os.environ.setdefault("KEYCLOAK_AUDIENCE", "mcp-api")
# The runtime must never be able to write its authorization policy.
# Tests use a separate read-only temporary policy (not the tracked example).
_policy_directory = tempfile.TemporaryDirectory(prefix="mcp-policy-test-")
atexit.register(_policy_directory.cleanup)
_policy_path = Path(_policy_directory.name) / "policy.json"
shutil.copyfile(Path(__file__).resolve().parents[1] / "config" / "policy.example.json", _policy_path)
_policy_path.chmod(0o444)
os.environ.setdefault("POLICY_FILE", str(_policy_path))
