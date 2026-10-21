"""Lightweight pre-publication tripwire. Not a substitute for Gitleaks/TruffleHog."""
from __future__ import annotations

import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "__pycache__", ".venv", ".pytest_cache", "dist", "build"}
EXEMPT = {".env.example"}
SENSITIVE_NAMES = {".env", "id_rsa", "id_ed25519", "credentials.json", "client-secret.json"}
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "openai_token": re.compile(r"\bsk-[A-Za-z0-9_-]{30,}\b"),
    "private_ip": re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
}
failures: list[str] = []
for item in BASE.rglob("*"):
    if not item.is_file() or set(item.relative_to(BASE).parts) & SKIP_DIRS:
        continue
    if item.name in SENSITIVE_NAMES and item.name not in EXEMPT:
        failures.append(f"{item.relative_to(BASE)}: sensitive filename")
        continue
    if item.stat().st_size > 500_000:
        failures.append(f"{item.relative_to(BASE)}: oversized file (manual review)")
        continue
    try:
        content = item.read_text(encoding="utf-8")
    except UnicodeError:
        failures.append(f"{item.relative_to(BASE)}: non-text file (manual review)")
        continue
    # Check only project content; scanner source itself contains regex literals.
    if item.resolve() == Path(__file__).resolve():
        continue
    for name, pattern in PATTERNS.items():
        if pattern.search(content):
            failures.append(f"{item.relative_to(BASE)}: possible {name}")
if failures:
    print("SECURITY CHECK FAILED:")
    for failure in failures:
        print(" -", failure)
    raise SystemExit(1)
print("Security tripwire passed (perform independent manual review before publication).")
