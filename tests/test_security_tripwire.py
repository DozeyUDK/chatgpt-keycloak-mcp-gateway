"""Check that the sample itself meets the local pre-publication tripwire."""
import runpy
from pathlib import Path


def test_repo_contains_no_obvious_secrets():
    scanner = Path(__file__).resolve().parents[1] / "scripts" / "security_check.py"
    runpy.run_path(str(scanner), run_name="__main__")
