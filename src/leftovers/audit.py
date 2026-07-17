from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import isoformat, utc_now
from .statefs import private_directory, private_file

_ANSI = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_REDACTIONS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"),
)


def redact(value: str, limit: int = 16_384) -> str:
    cleaned = _ANSI.sub("", value)
    for pattern in _REDACTIONS:
        cleaned = pattern.sub(
            lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]",
            cleaned,
        )
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "\n[TRUNCATED]"
    return cleaned


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return isoformat(value)
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"cannot serialize {type(value).__name__}")


class AuditJournal:
    """Append-only JSONL journal with a hash chain and redacted bounded text."""

    def __init__(self, state_dir: Path, run_id: str):
        root = private_directory(state_dir)
        self.directory = private_directory(root / "runs")
        self.path = private_file(self.directory / f"{run_id}.jsonl")
        self._previous_hash = "0" * 64

    def append(self, event: str, **payload: Any) -> str:
        sanitized = self._sanitize(payload)
        record = {
            "at": isoformat(utc_now()),
            "event": event,
            "payload": sanitized,
            "previous_hash": self._previous_hash,
        }
        canonical = json.dumps(record, default=_json_default, sort_keys=True, separators=(",", ":"))
        record_hash = hashlib.sha256(canonical.encode()).hexdigest()
        record["record_hash"] = record_hash
        line = json.dumps(record, default=_json_default, sort_keys=True) + "\n"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise OSError("audit journal has unsafe type or ownership")
            os.fchmod(descriptor, 0o600)
            pending = memoryview(line.encode())
            while pending:
                written = os.write(descriptor, pending)
                if written < 1:
                    raise OSError("audit journal write made no progress")
                pending = pending[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._previous_hash = record_hash
        return record_hash

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, str):
            return redact(value)
        if isinstance(value, dict):
            return {str(key): self._sanitize(item) for key, item in value.items()}
        if isinstance(value, list | tuple):
            return [self._sanitize(item) for item in value]
        if isinstance(value, datetime):
            return isoformat(value)
        if is_dataclass(value):
            return self._sanitize(asdict(value))
        if hasattr(value, "value"):
            return value.value
        return value
