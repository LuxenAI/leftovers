from __future__ import annotations

import os
import stat
from pathlib import Path


class PrivateStateError(OSError):
    pass


def private_directory(path: Path) -> Path:
    """Create or tighten a final state directory without accepting a symlink."""
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise PrivateStateError(f"private state directory may not be a symlink: {expanded}")
    expanded.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = expanded.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise PrivateStateError(f"private state directory has unsafe ownership: {expanded}")
    os.chmod(expanded, 0o700)
    return expanded.resolve()


def private_file(path: Path) -> Path:
    """Pre-create and verify a user-only regular state file."""
    parent = private_directory(path.parent)
    candidate = parent / path.name
    if candidate.is_symlink():
        raise PrivateStateError(f"private state file may not be a symlink: {candidate}")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise PrivateStateError(f"private state file has unsafe ownership: {candidate}")
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    return candidate
