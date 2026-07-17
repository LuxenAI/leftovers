#!/usr/bin/env python3
"""Deterministic, credential-free adapter used only by Leftovers rehearsals.

This is deliberately not a model client. It exercises the same stage result and
telemetry transports as a real adapter while making every token count synthetic.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROVIDER = "leftovers-rehearsal"
MODEL = "deterministic-parser-fixture-v1"
ADAPTER_VERSION = "1.0.0"
TEST_COMMAND = ["python3", "-m", "unittest", "-q", "test_parser.py"]
_FORBIDDEN_ENVIRONMENT = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PAT",
    "GIT_ASKPASS",
    "LEFTOVERS_REHEARSAL_GITHUB_TOKEN",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
}
_USAGE = {
    "planning": {
        "input_tokens": 120,
        "output_tokens": 80,
        "cached_input_tokens": 24,
        "reasoning_tokens": 16,
    },
    "implementation": {
        "input_tokens": 160,
        "output_tokens": 120,
        "cached_input_tokens": 32,
        "reasoning_tokens": 24,
    },
    "review": {
        "input_tokens": 180,
        "output_tokens": 90,
        "cached_input_tokens": 36,
        "reasoning_tokens": 18,
    },
}


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_all(descriptor: int, payload: bytes) -> None:
    pending = memoryview(payload)
    while pending:
        written = os.write(descriptor, pending)
        if written < 1:
            raise OSError("output write made no progress")
        pending = pending[written:]


def _open_new_regular(path: Path) -> int:
    if not path.is_absolute() or path.parent.is_symlink() or not path.parent.is_dir():
        raise RuntimeError("adapter output path has an unsafe parent")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(descriptor)
        raise RuntimeError("adapter output is not a single-link regular file")
    return descriptor


class TelemetryWriter:
    def __init__(self, path: Path):
        self.descriptor = _open_new_regular(path)
        self.sequence = 0

    def emit(self, event_type: str, **payload: Any) -> None:
        self.sequence += 1
        event = {
            "version": 1,
            "sequence": self.sequence,
            "type": event_type,
            **payload,
        }
        raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(raw) > 4_096:
            raise RuntimeError("rehearsal telemetry event is unexpectedly large")
        _write_all(self.descriptor, raw)
        os.fsync(self.descriptor)

    def close(self) -> None:
        os.close(self.descriptor)


def _write_result(path: Path, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = _open_new_regular(path)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_environment_is_credential_free() -> None:
    exposed = sorted(_FORBIDDEN_ENVIRONMENT.intersection(os.environ))
    exposed.extend(
        sorted(
            name
            for name in os.environ
            if name.startswith(("DOCKER_", "PODMAN_", "CONTAINER_", "KUBE"))
        )
    )
    if exposed:
        raise RuntimeError("forbidden worker environment names: " + ", ".join(exposed))


def _expect_write_denied(path: Path) -> bool:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError:
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)
    with suppress(OSError):
        path.unlink()
    return False


def _expect_existing_write_denied(path: Path) -> bool:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return False


def _container_assertions(stage: str, workspace: Path) -> dict[str, bool]:
    rootfs_read_only = _expect_existing_write_denied(Path("/opt/leftovers/rootfs-write-probe"))
    interfaces_path = Path("/sys/class/net")
    interfaces = {entry.name for entry in interfaces_path.iterdir()}
    network_only_loopback = interfaces == {"lo"}
    assertions = {
        "worker_secrets_absent": True,
        "rootfs_read_only": rootfs_read_only,
        "network_only_loopback": network_only_loopback,
    }
    if stage in {"planning", "review"}:
        assertions["workspace_read_only"] = _expect_write_denied(
            workspace / ".leftovers-rehearsal-write-probe"
        )
    if stage == "implementation":
        assertions["git_metadata_read_only"] = _expect_write_denied(
            workspace / ".git" / "leftovers-rehearsal-write-probe"
        )
    if not all(assertions.values()):
        failed = ", ".join(name for name, passed in assertions.items() if not passed)
        raise RuntimeError(f"container isolation assertion failed: {failed}")
    return assertions


def _run_fixture_tests(expect_success: bool) -> str:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "-q", "test_parser.py"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        env=environment,
    )
    if (result.returncode == 0) is not expect_success:
        raise RuntimeError("fixture reproduction returned the wrong status")
    combined = (result.stdout + result.stderr)[-4_096:]
    if not expect_success and "terminal escape" not in combined:
        raise RuntimeError("fixture reproduction did not expose the expected failing assertion")
    return "fixture test passed" if expect_success else "terminal escape regression reproduced"


def _planning() -> dict[str, Any]:
    observed = _run_fixture_tests(expect_success=False)
    return {
        "status": "planned",
        "acceptance_criteria": ["terminal escape characters are preserved"],
        "reproduction": {"argv": TEST_COMMAND, "observed": observed},
        "root_cause": [
            {
                "path": "parser.py",
                "evidence": "decode_escaped drops a pending terminal escape before returning",
            }
        ],
        "steps": ["append a terminal backslash when the parser exits in escaping state"],
        "tests": [TEST_COMMAND],
        "risks": ["avoid changing non-terminal escape decoding"],
        "estimated_remaining_tokens": 750,
        "stop_conditions": ["fixture scope expands beyond parser.py"],
    }


def _implementation(workspace: Path) -> dict[str, Any]:
    parser_path = workspace / "parser.py"
    original = parser_path.read_text(encoding="utf-8")
    old = '    return "".join(decoded)\n'
    new = '    if escaping:\n        decoded.append("\\\\")\n    return "".join(decoded)\n'
    if new not in original:
        if original.count(old) != 1:
            raise RuntimeError("fixture parser no longer has the expected deterministic shape")
        parser_path.write_text(original.replace(old, new), encoding="utf-8")
    return {
        "status": "implemented",
        "summary": "preserved a pending terminal escape before returning decoded text",
        "changed_files": ["parser.py"],
        "commands": [],
        "acceptance_criteria": [
            {
                "criterion": "terminal escape characters are preserved",
                "evidence": "parser.py now appends the pending terminal backslash",
            }
        ],
        "remaining_risks": [],
    }


def _review(workspace: Path) -> dict[str, Any]:
    source = (workspace / "parser.py").read_text(encoding="utf-8")
    if 'if escaping:\n        decoded.append("\\\\")' not in source:
        raise RuntimeError("review did not find the required parser fix")
    _run_fixture_tests(expect_success=True)
    return {
        "verdict": "approve",
        "findings": [],
        "missing_verification": [],
        "pr_claims_supported": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("container", "process"), required=True)
    args = parser.parse_args(argv)

    stage = os.environ.get("LEFTOVERS_STAGE", "")
    if stage not in _USAGE:
        raise RuntimeError("LEFTOVERS_STAGE is missing or unsupported")
    result_path = Path(os.environ.get("LEFTOVERS_RESULT_PATH", ""))
    telemetry_path = Path(os.environ.get("LEFTOVERS_TELEMETRY_PATH", ""))
    prompt = sys.stdin.buffer.read(2_000_001)
    if not prompt or len(prompt) > 2_000_000:
        raise RuntimeError("rehearsal prompt is missing or oversized")
    if b'"no_github_writes": true' not in prompt:
        raise RuntimeError("trusted rehearsal envelope did not prohibit GitHub writes")

    _assert_environment_is_credential_free()
    workspace = Path.cwd().resolve()
    telemetry = TelemetryWriter(telemetry_path)
    try:
        telemetry.emit(
            "checkin",
            provider=PROVIDER,
            model=MODEL,
            adapter_version=ADAPTER_VERSION,
            capabilities=[
                "planning",
                "implementation",
                "review",
                "offline-fixture",
                "synthetic-usage",
            ],
            observed_at=_now(),
        )
        assertions = (
            _container_assertions(stage, workspace)
            if args.mode == "container"
            else {"worker_secrets_absent": True, "process_mode_supplemental": True}
        )
        if stage == "planning":
            payload = _planning()
        elif stage == "implementation":
            payload = _implementation(workspace)
        else:
            payload = _review(workspace)
        payload["rehearsal_assertions"] = assertions
        telemetry.emit("heartbeat", observed_at=_now())
        usage = _USAGE[stage]
        telemetry.emit(
            "usage",
            **usage,
            total_tokens=usage["input_tokens"] + usage["output_tokens"],
            source="synthetic",
            exact=True,
            final=True,
            observed_at=_now(),
        )
        _write_result(result_path, payload)
    finally:
        telemetry.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
