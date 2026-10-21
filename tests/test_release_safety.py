"""Pre-release checks for accidentally committed secrets and local infrastructure.

History inspection supplements, but does not replace, a dedicated secret scanner
such as Gitleaks. This test reads all blobs reachable from local Git refs.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

# Regexes are intentionally limited to stronger indicators to avoid matching
# innocent examples or environment variable names.
BAD_CONTENT = {
    "private_key": re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    "github_token": re.compile(rb"\bgh[pousr]_[a-zA-Z0-9]{20,}\b"),
    "aws_key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "openai_key": re.compile(rb"\bsk-[a-zA-Z0-9_-]{30,}\b"),
    "private_ipv4": re.compile(
        rb"\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|"
        rb"192\.168\.[0-9]{1,3}\.[0-9]{1,3}|"
        rb"172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})\b"
    ),
}
BAD_NAMES = {".env", "id_rsa", "id_ed25519", "private.pem", "credentials.json", "client-secret.json"}
ALLOWED_EXAMPLE = {".env.example"}
# This filename contains deliberately written detector examples.
SELF = Path(__file__).relative_to(BASE).as_posix()


def _git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=BASE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15, check=True,
    ).stdout


def _scan_file(path: str, data: bytes) -> list[str]:
    if Path(path).name in BAD_NAMES and path not in ALLOWED_EXAMPLE:
        return [f"{path}: sensitive filename"]
    if len(data) > 500_000 or b"\x00" in data[:4096]:
        return [f"{path}: oversized/binary blob"]
    if path == SELF:
        return []
    return [f"{path}: possible {name}" for name, pattern in BAD_CONTENT.items() if pattern.search(data)]


def test_all_git_history_objects_have_no_obvious_secrets():
    objects = _git("rev-list", "--objects", "--all").decode().splitlines()
    assert objects, "Expected nonempty Git history"
    seen = set()
    problems = []
    for entry in objects:
        oid, _, path = entry.partition(" ")
        if oid in seen or not path:
            continue
        seen.add(oid)
        if _git("cat-file", "-t", oid).strip() != b"blob":
            continue
        data = _git("cat-file", "-p", oid)
        problems.extend(_scan_file(path, data))
    assert not problems, "Git history scan flagged: " + "; ".join(problems)


def test_current_working_tree_has_no_obvious_secrets():
    ignored = {".git", "__pycache__", ".pytest_cache", ".venv", "dist", "build"}
    problems = []
    for path in BASE.rglob("*"):
        if not path.is_file() or set(path.relative_to(BASE).parts) & ignored:
            continue
        problems.extend(_scan_file(path.relative_to(BASE).as_posix(), path.read_bytes()))
    assert not problems, "Working tree scan flagged: " + "; ".join(problems)
