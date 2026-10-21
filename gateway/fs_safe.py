"""Race-resistant, per-root, symlink-rejecting UTF-8 file operations.

Tools cannot read or write outside pre-mounted roots. No arbitrary subprocess,
directory listing, wildcard expansion, symlink traversal or file deletion.
Writes replace a target atomically, without following target hardlinks.
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path


class FileAccessDenied(Exception):
    pass


DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _relative_parts(root: Path, value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise FileAccessDenied()
    given = Path(value)
    if not given.is_absolute() or ".." in given.parts or str(given) != value:
        raise FileAccessDenied()
    try:
        parts = given.relative_to(root).parts
    except ValueError as exc:
        raise FileAccessDenied() from exc
    denied = {
        ".git", ".ssh", ".aws", ".kube", ".secrets", ".github",
        "secrets", "credentials", "__pycache__",
        "policy.json", "authorized_keys",
    }
    if not parts or any(
        p in ("", ".", "..") or
        p in denied or
        p.startswith(".env") or
        p.endswith((".pem", ".key", ".p12", ".pfx")) for p in parts
    ):
        raise FileAccessDenied()
    return parts


def _open_parent(root: Path, parts: tuple[str, ...]) -> int:
    try:
        fd = os.open(root, DIR_FLAGS)
        for component in parts[:-1]:
            try:
                child = os.open(component, DIR_FLAGS, dir_fd=fd)
            finally:
                os.close(fd)
            fd = child
        return fd
    except OSError as exc:
        raise FileAccessDenied() from exc


def _open_from_roots(roots: tuple[Path, ...], path: str) -> tuple[int, str]:
    for root in roots:
        try:
            parts = _relative_parts(root, path)
        except FileAccessDenied:
            continue
        return _open_parent(root, parts), parts[-1]
    raise FileAccessDenied()


def read_text(roots: tuple[Path, ...], path: str, max_bytes: int) -> str:
    fd, name = _open_from_roots(roots, path)
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        except OSError as exc:
            raise FileAccessDenied() from exc
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise FileAccessDenied()
            with os.fdopen(file_fd, "rb", closefd=False) as file:
                data = file.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise FileAccessDenied()
            try:
                return data.decode("utf-8")
            except UnicodeError as exc:
                raise FileAccessDenied() from exc
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def write_text(roots: tuple[Path, ...], path: str, content: str, max_bytes: int) -> int:
    if not isinstance(content, str):
        raise FileAccessDenied()
    try:
        encoded = content.encode("utf-8")
    except UnicodeError as exc:
        raise FileAccessDenied() from exc
    if len(encoded) > max_bytes:
        raise FileAccessDenied()
    fd, name = _open_from_roots(roots, path)
    tmpname = ".mcp-tmp-" + secrets.token_hex(16)
    try:
        try:
            existing = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode):
                raise FileAccessDenied()
        except FileNotFoundError:
            pass
        try:
            file_fd = os.open(
                tmpname, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                mode=0o600, dir_fd=fd,
            )
        except OSError as exc:
            raise FileAccessDenied() from exc
        try:
            with os.fdopen(file_fd, "wb", closefd=False) as file:
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
        finally:
            os.close(file_fd)
        try:
            # Atomic replacement; symlink/hardlink targets are not followed.
            os.replace(tmpname, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        except OSError as exc:
            raise FileAccessDenied() from exc
        return len(encoded)
    except OSError as exc:
        raise FileAccessDenied() from exc
    finally:
        try:
            os.unlink(tmpname, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)
