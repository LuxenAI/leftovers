#!/usr/bin/env python3
"""Headless Codex CLI adapter for Leftovers' strict stage protocol.

This adapter is intentionally suitable only for the host-agent, dry-run profile. The Codex
process owns subscription authentication while its model-generated shell commands run in Codex's
workspace sandbox. A production publisher still requires the container/broker credential topology
documented in ``docs/AGENT_ADAPTERS.md``.
"""

from __future__ import annotations

import io
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MODEL = "gpt-5.6-terra"
PROVIDER = "openai-codex-cli"
ADAPTER_VERSION = "leftovers-codex-adapter/1"
MINIMUM_CODEX_VERSION = (0, 144, 5)
STAGE_TIMEOUTS = {"planning": 360, "implementation": 1_200, "review": 480}
MAX_PROMPT_BYTES = 2_000_000
MAX_EVENT_BYTES = 16_000_000
MAX_DIAGNOSTIC_BYTES = 8_000_000
MAX_RESULT_BYTES = 1_000_000
MAX_JSONL_LINE_BYTES = 4_000_000
HEARTBEAT_SECONDS = 15
TERMINATION_GRACE_SECONDS = 5
KILL_CONFIRM_SECONDS = 2
SCHEMAS = {
    "planning": "codex-planning.schema.json",
    "implementation": "codex-implementation.schema.json",
    "review": "codex-review.schema.json",
}
_ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
_SENSITIVE = re.compile(
    rb"(?i)(?:sk-[A-Za-z0-9_-]{10,}|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|bearer\s+\S+)"
)


class AdapterError(RuntimeError):
    pass


_pending_signal: signal.Signals | None = None
_RUNNER_PROCESS_GROUP_ENV = "LEFTOVERS_RUNNER_OWNS_PROCESS_GROUP"


def _child_requires_new_session() -> bool:
    """Honor the explicit controller process-group ownership contract."""

    value = os.environ.get(_RUNNER_PROCESS_GROUP_ENV)
    if value is None:
        return True
    if value != "1":
        raise AdapterError("invalid runner process-group ownership contract")
    try:
        if os.getpgrp() != os.getpid():
            raise AdapterError("runner-owned adapter is not its process-group leader")
    except PermissionError as exc:
        raise AdapterError("could not determine the adapter process group") from exc
    return False


def _managed_process_group(process: subprocess.Popen[bytes]) -> int | None:
    """Return a separately owned Codex group, if the adapter owns one.

    Under the runner contract, the adapter and Codex deliberately share the
    runner-created group.  The adapter must never terminate that group because
    it contains itself; the runner removes residual descendants after this
    adapter has exited.
    """

    if os.environ.get(_RUNNER_PROCESS_GROUP_ENV) != "1":
        return process.pid
    try:
        process_group = os.getpgrp()
    except OSError as exc:
        raise AdapterError("could not determine the runner-owned process group") from exc
    if process_group != os.getpid():
        raise AdapterError("runner-owned adapter lost its process-group ownership")
    return None


def _install_cancellation_handlers() -> dict[signal.Signals, signal.Handlers]:
    """Let direct adapter invocation clean up its separately isolated Codex child."""

    global _pending_signal
    _pending_signal = None
    previous: dict[signal.Signals, signal.Handlers] = {}

    def cancel(received: int, _frame: Any) -> None:
        global _pending_signal
        _pending_signal = signal.Signals(received)

    for received in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous[received] = signal.getsignal(received)
        signal.signal(received, cancel)
    return previous


def _restore_cancellation_handlers(previous: dict[signal.Signals, signal.Handlers]) -> None:
    global _pending_signal
    for received, handler in previous.items():
        signal.signal(received, handler)
    _pending_signal = None


def _raise_if_cancelled() -> None:
    global _pending_signal
    received = _pending_signal
    if received is not None:
        _pending_signal = None
        raise AdapterError(f"Codex adapter received {received.name}")


def _utc_text() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _resolve_codex() -> Path:
    configured = os.environ.get("LEFTOVERS_CODEX_BIN")
    candidates = (
        Path(configured).expanduser() if configured else None,
        Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
        Path("/Applications/Codex.app/Contents/Resources/codex"),
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_absolute() and os.access(candidate, os.X_OK):
            return candidate
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / "codex"
        if directory and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise AdapterError("no executable Codex CLI was found")


def _codex_version(binary: Path, *, timeout: float = 10) -> tuple[int, int, int]:
    child_requires_new_session = _child_requires_new_session()
    try:
        process = subprocess.Popen(
            [str(binary), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=child_requires_new_session,
        )
    except OSError as exc:
        raise AdapterError("could not inspect the Codex CLI version") from exc
    process_group = _managed_process_group(process)
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            _raise_if_cancelled()
            if time.monotonic() >= deadline:
                _terminate(process, process_group=process_group, deadline=deadline)
                raise AdapterError("could not inspect the Codex CLI version")
            try:
                process.wait(timeout=min(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                continue
        stdout, _ = process.communicate()
        match = re.search(r"codex-cli\s+(\d+)\.(\d+)\.(\d+)", stdout.decode(errors="replace"))
        if process.returncode != 0 or match is None:
            raise AdapterError("Codex CLI returned an unrecognized version")
        version = tuple(int(value) for value in match.groups())
        if version < MINIMUM_CODEX_VERSION:
            required = ".".join(str(value) for value in MINIMUM_CODEX_VERSION)
            actual = ".".join(str(value) for value in version)
            raise AdapterError(
                f"Codex CLI {actual} is too old; version {required} or newer is required"
            )
        return version
    finally:
        cleanup_error: AdapterError | None = None
        try:
            _terminate(process, process_group=process_group, deadline=time.monotonic() + 7)
        except AdapterError as exc:
            cleanup_error = exc
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    if cleanup_error is None:
                        cleanup_error = AdapterError("Codex version capture cleanup failed")
        if cleanup_error is not None:
            raise cleanup_error


def _stage_deadline(stage: str) -> float:
    timeout = STAGE_TIMEOUTS[stage]
    if type(timeout) not in (int, float) or timeout <= 0:
        raise AdapterError("Codex stage timeout must be positive")
    return time.monotonic() + timeout


def _remaining_timeout(deadline: float, stage: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AdapterError(f"Codex {stage} stage exceeded its hard time limit")
    return remaining


def _read_prompt(deadline: float, stage: str) -> bytes:
    try:
        descriptor = sys.stdin.buffer.fileno()
    except (AttributeError, OSError, ValueError) as exc:
        raise AdapterError("Leftovers prompt stream must provide a file descriptor") from exc
    payload = bytearray()
    while len(payload) <= MAX_PROMPT_BYTES:
        try:
            readable, _, _ = select.select(
                [descriptor], [], [], _remaining_timeout(deadline, stage)
            )
        except InterruptedError:
            continue
        if not readable:
            _remaining_timeout(deadline, stage)
            continue
        try:
            chunk = os.read(descriptor, min(65_536, MAX_PROMPT_BYTES + 1 - len(payload)))
        except InterruptedError:
            continue
        if not chunk:
            break
        payload.extend(chunk)
    if not payload or len(payload) > MAX_PROMPT_BYTES:
        raise AdapterError("Leftovers prompt is empty or oversized")
    return bytes(payload)


def _canonical_output_path(value: str) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError) as exc:
        raise AdapterError("Leftovers output paths must be unambiguous absolute paths") from exc
    if (
        not path.is_absolute()
        or value != os.path.abspath(value)
        or value != os.path.realpath(value)
    ):
        raise AdapterError("Leftovers output paths must be unambiguous absolute paths")
    return path


def _secure_new_file(path: Path) -> int:
    parent = path.parent
    current = parent
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise AdapterError("adapter output directory is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise AdapterError("adapter output directory may not contain symlinked ancestors")
        if current.parent == current:
            break
        current = current.parent
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        parent_descriptor = os.open(parent, directory_flags)
    except OSError as exc:
        raise AdapterError("adapter output directory is unavailable") from exc
    try:
        info = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise AdapterError("adapter output directory is not owner-controlled")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            return os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise AdapterError(f"refusing existing adapter output path: {path.name}") from exc
    finally:
        os.close(parent_descriptor)


def _append_event(descriptor: int, sequence: int, event_type: str, **fields: Any) -> int:
    sequence += 1
    event = {
        "version": 1,
        "sequence": sequence,
        "type": event_type,
        **fields,
        "observed_at": _utc_text(),
    }
    payload = json.dumps(event, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    pending = memoryview(payload)
    while pending:
        written = os.write(descriptor, pending)
        if written < 1:
            raise AdapterError("telemetry write made no progress")
        pending = pending[written:]
    os.fsync(descriptor)
    return sequence


def _process_group_is_alive(process: subprocess.Popen[bytes], process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        process.poll()
        return False
    except PermissionError as exc:
        if process.poll() is not None:
            # After the leader is reaped, EPERM means this same-user supervisor can
            # no longer observe a signalable member of the managed process group.
            return False
        raise AdapterError("cannot inspect the Codex process group") from exc
    except OSError as exc:
        raise AdapterError("cannot inspect the Codex process group") from exc
    return True


def _signal_process_group(process_group: int, received: signal.Signals) -> None:
    try:
        os.killpg(process_group, received)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise AdapterError("cannot signal the Codex process group") from exc


def _wait_for_process_group_exit(
    process: subprocess.Popen[bytes], process_group: int, deadline: float
) -> bool:
    while _process_group_is_alive(process, process_group):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        process.poll()
        time.sleep(min(0.1, remaining))
    # The process group can disappear a few scheduler ticks before waitpid(2)
    # reports its leader as reapable.  Do not return a live Popen object to its
    # destructor: that both emits a ResourceWarning and loses proof that the
    # managed leader actually exited.
    remaining = deadline - time.monotonic()
    try:
        process.wait(timeout=max(0.01, remaining))
    except subprocess.TimeoutExpired:
        return False
    return True


def _terminate(
    process: subprocess.Popen[bytes], *, process_group: int | None, deadline: float
) -> None:
    """Stop the complete Codex session, including children left by its leader."""

    if process_group is None:
        # The runner owns this shared group.  Reap or bound the direct Codex
        # leader, then return so the runner can terminate any descendants once
        # this adapter is no longer a member of the group.
        if process.poll() is not None:
            process.wait(timeout=KILL_CONFIRM_SECONDS)
            return
        now = time.monotonic()
        if now < deadline:
            with suppress(ProcessLookupError):
                process.send_signal(signal.SIGINT)
            try:
                process.wait(
                    timeout=max(0.01, min(deadline, now + TERMINATION_GRACE_SECONDS) - now)
                )
                return
            except subprocess.TimeoutExpired:
                pass
        with suppress(ProcessLookupError):
            process.kill()
        try:
            process.wait(timeout=KILL_CONFIRM_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise AdapterError("Codex process leader could not be terminated") from exc
        return

    if not _process_group_is_alive(process, process_group):
        try:
            process.wait(timeout=KILL_CONFIRM_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise AdapterError("Codex process leader could not be reaped") from exc
        return
    now = time.monotonic()
    if now < deadline:
        _signal_process_group(process_group, signal.SIGINT)
        graceful_deadline = min(deadline, now + TERMINATION_GRACE_SECONDS)
        if _wait_for_process_group_exit(process, process_group, graceful_deadline):
            return
    _signal_process_group(process_group, signal.SIGKILL)
    if not _wait_for_process_group_exit(
        process, process_group, time.monotonic() + KILL_CONFIRM_SECONDS
    ):
        raise AdapterError("Codex process group could not be terminated")


def _open_bounded_artifact(
    path: Path,
    *,
    maximum_bytes: int,
    allow_empty: bool,
    unavailable_message: str,
    size_message: str,
) -> tuple[int, os.stat_result]:
    """Open one worker artifact without following links or trusting a stale size."""

    try:
        path_info = path.lstat()
    except OSError as exc:
        raise AdapterError(unavailable_message) from exc
    if (
        not stat.S_ISREG(path_info.st_mode)
        or path_info.st_uid != os.getuid()
        or path_info.st_nlink != 1
        or stat.S_IMODE(path_info.st_mode) & 0o022
    ):
        raise AdapterError(unavailable_message)
    if path_info.st_size > maximum_bytes or (not allow_empty and path_info.st_size == 0):
        raise AdapterError(size_message)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AdapterError(unavailable_message) from exc
    try:
        descriptor_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_info.st_mode)
            or descriptor_info.st_uid != os.getuid()
            or descriptor_info.st_nlink != 1
            or stat.S_IMODE(descriptor_info.st_mode) & 0o022
            or (descriptor_info.st_dev, descriptor_info.st_ino)
            != (path_info.st_dev, path_info.st_ino)
        ):
            raise AdapterError(unavailable_message)
        if descriptor_info.st_size > maximum_bytes or (
            not allow_empty and descriptor_info.st_size == 0
        ):
            raise AdapterError(size_message)
        return descriptor, descriptor_info
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded_artifact(
    path: Path,
    *,
    maximum_bytes: int,
    allow_empty: bool,
    unavailable_message: str,
    size_message: str,
) -> bytes:
    descriptor, _ = _open_bounded_artifact(
        path,
        maximum_bytes=maximum_bytes,
        allow_empty=allow_empty,
        unavailable_message=unavailable_message,
        size_message=size_message,
    )
    try:
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    except OSError as exc:
        raise AdapterError(unavailable_message) from exc
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes or (not allow_empty and not payload):
        raise AdapterError(size_message)
    return bytes(payload)


def _read_bounded_tail(
    path: Path,
    *,
    maximum_bytes: int,
    unavailable_message: str,
    size_message: str,
) -> bytes:
    descriptor, info = _open_bounded_artifact(
        path,
        maximum_bytes=maximum_bytes,
        allow_empty=True,
        unavailable_message=unavailable_message,
        size_message=size_message,
    )
    try:
        os.lseek(descriptor, max(0, info.st_size - 65_536), os.SEEK_SET)
        return os.read(descriptor, 65_536)
    except OSError as exc:
        raise AdapterError(unavailable_message) from exc
    finally:
        os.close(descriptor)


def _validate_capture_descriptor(descriptor: int, maximum_bytes: int, message: str) -> None:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise AdapterError(message) from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum_bytes:
        raise AdapterError(message)


def _usage_from_events(path: Path) -> dict[str, int]:
    usage: dict[str, Any] | None = None
    raw = _read_bounded_artifact(
        path,
        maximum_bytes=MAX_EVENT_BYTES,
        allow_empty=True,
        unavailable_message="Codex JSONL output is unavailable or unsafe",
        size_message="Codex JSONL output exceeded its safety limit",
    )
    stream = io.BytesIO(raw)
    while True:
        raw_line = stream.readline(MAX_JSONL_LINE_BYTES + 1)
        if not raw_line:
            break
        if len(raw_line) > MAX_JSONL_LINE_BYTES:
            raise AdapterError("Codex emitted an oversized JSONL event")
        try:
            event = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterError("Codex emitted malformed JSONL") from exc
        if isinstance(event, dict) and event.get("type") == "turn.completed":
            candidate = event.get("usage")
            if isinstance(candidate, dict):
                usage = candidate
    if usage is None:
        raise AdapterError("Codex did not emit a final usage receipt")
    keys = {
        "input_tokens": "input_tokens",
        "output_tokens": "output_tokens",
        "cached_input_tokens": "cached_input_tokens",
        "reasoning_tokens": "reasoning_output_tokens",
    }
    parsed: dict[str, int] = {}
    for output_key, input_key in keys.items():
        value = usage.get(input_key, 0)
        if type(value) is not int or not 0 <= value <= 1_000_000_000:
            raise AdapterError("Codex returned invalid token usage")
        parsed[output_key] = value
    if parsed["cached_input_tokens"] > parsed["input_tokens"]:
        raise AdapterError("Codex cached input exceeds total input")
    if parsed["reasoning_tokens"] > parsed["output_tokens"]:
        raise AdapterError("Codex reasoning usage exceeds total output")
    parsed["total_tokens"] = parsed["input_tokens"] + parsed["output_tokens"]
    return parsed


def _load_result(path: Path) -> bytes:
    raw = _read_bounded_artifact(
        path,
        maximum_bytes=MAX_RESULT_BYTES,
        allow_empty=False,
        unavailable_message="Codex did not write a safe regular structured result",
        size_message="Codex structured result is empty or oversized",
    )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("Codex structured result is not valid JSON") from exc
    if not isinstance(value, dict):
        raise AdapterError("Codex structured result must be a JSON object")
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def _failure_detail(diagnostic_path: Path, event_path: Path) -> str:
    fallback = ""
    for path, maximum_bytes in (
        (diagnostic_path, MAX_DIAGNOSTIC_BYTES),
        (event_path, MAX_EVENT_BYTES),
    ):
        try:
            raw = _read_bounded_tail(
                path,
                maximum_bytes=maximum_bytes,
                unavailable_message="Codex diagnostic artifact is unavailable or unsafe",
                size_message="Codex diagnostic artifact exceeded its safety limit",
            )
        except AdapterError:
            continue
        redacted = _SENSITIVE.sub(b"[REDACTED]", _ANSI.sub(b"", raw))
        text = redacted.decode("utf-8", errors="replace")
        lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
        interesting = [
            line
            for line in lines
            if re.search(
                r"(?i)\b(error|failed|invalid|unknown|unrecognized|unsupported|requires)\b",
                line,
            )
        ]
        if interesting:
            return " ".join(interesting[-4:])[-800:]
        if lines and not fallback:
            fallback = " ".join(lines[-4:])[-800:]
    return fallback or "no bounded diagnostic was emitted"


def _write_result(path: Path, payload: bytes) -> None:
    descriptor = _secure_new_file(path)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise AdapterError("result write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_stage(
    *,
    process: subprocess.Popen[bytes] | None,
    process_group: int | None,
    deadline: float,
    descriptors: tuple[int, ...],
    paths: tuple[Path | None, ...],
    previous_handlers: dict[signal.Signals, signal.Handlers],
) -> None:
    """Attempt every cleanup action and report the first unproven failure."""

    cleanup_error: AdapterError | None = None
    if process is not None and process_group is not None:
        try:
            _terminate(process, process_group=process_group, deadline=deadline)
        except (AdapterError, OSError) as exc:
            cleanup_error = (
                exc if isinstance(exc, AdapterError) else AdapterError("Codex cleanup failed")
            )
    if process is not None and process.stdin is not None and not process.stdin.closed:
        with suppress(OSError):
            process.stdin.close()
    for descriptor in descriptors:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = AdapterError("Codex artifact descriptor cleanup failed")
                    cleanup_error.__cause__ = exc
    for path in paths:
        if path is None:
            continue
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = AdapterError("Codex temporary artifact cleanup failed")
                cleanup_error.__cause__ = exc
    _restore_cancellation_handlers(previous_handlers)
    if cleanup_error is not None:
        raise cleanup_error


def _command(binary: Path, schema: Path, result: Path, stage: str) -> list[str]:
    sandbox = "workspace-write" if stage == "implementation" else "read-only"
    disabled_features = (
        "apps",
        "browser_use",
        "chronicle",
        "computer_use",
        "hooks",
        "image_generation",
        "in_app_browser",
        "memories",
        "multi_agent",
        "plugins",
        "remote_plugin",
        "skill_search",
    )
    command = [
        str(binary),
        "exec",
        "--strict-config",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--model",
        MODEL,
        "-c",
        'model_reasoning_effort="high"',
        "-c",
        'model_verbosity="low"',
        "-c",
        'approval_policy="never"',
        "-c",
        "allow_login_shell=false",
        "-c",
        "sandbox_workspace_write.network_access=false",
        "-c",
        "sandbox_workspace_write.exclude_slash_tmp=true",
        "-c",
        "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "-c",
        'shell_environment_policy.inherit="none"',
        "-c",
        'shell_environment_policy.set={PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",CI="1"}',
        "-c",
        "analytics.enabled=false",
    ]
    for feature in disabled_features:
        command.extend(("--disable", feature))
    command.extend(
        (
            "--sandbox",
            sandbox,
            "--color",
            "never",
            "--json",
            "--output-schema",
            str(schema),
            "--output-last-message",
            str(result),
            "-",
        )
    )
    return command


def main() -> int:
    stage = os.environ.get("LEFTOVERS_STAGE", "")
    result_text = os.environ.get("LEFTOVERS_RESULT_PATH", "")
    telemetry_text = os.environ.get("LEFTOVERS_TELEMETRY_PATH", "")
    if stage not in SCHEMAS or not result_text or not telemetry_text:
        raise AdapterError("Leftovers stage and output paths are required")
    deadline = _stage_deadline(stage)
    root = Path(__file__).resolve().parents[1]
    schema = root / "schemas" / SCHEMAS[stage]
    if not schema.is_file():
        raise AdapterError(f"missing Codex stage schema: {schema.name}")
    result_path = _canonical_output_path(result_text)
    telemetry_path = _canonical_output_path(telemetry_text)
    if result_path == telemetry_path or result_path.parent != telemetry_path.parent:
        raise AdapterError("Leftovers output paths must be distinct normalized sibling files")
    prompt = _read_prompt(deadline, stage)
    binary = _resolve_codex()
    probe_handlers = _install_cancellation_handlers()
    try:
        _codex_version(binary, timeout=min(10, _remaining_timeout(deadline, stage)))
        # A fast probe can finish between its polling ticks.  Consume a
        # deferred signal before restoring handlers so it cannot be lost.
        _raise_if_cancelled()
    except AdapterError:
        _remaining_timeout(deadline, stage)
        raise
    finally:
        _restore_cancellation_handlers(probe_handlers)
    _remaining_timeout(deadline, stage)

    telemetry_descriptor = _secure_new_file(telemetry_path)
    sequence = 0
    event_descriptor = -1
    diagnostic_descriptor = -1
    event_path: Path | None = None
    diagnostic_path: Path | None = None
    codex_result_path: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    process_group: int | None = None
    prompt_pending: memoryview | None = None
    prompt_error = False
    previous_handlers: dict[signal.Signals, signal.Handlers] = {}
    try:
        sequence = _append_event(
            telemetry_descriptor,
            sequence,
            "checkin",
            provider=PROVIDER,
            model=MODEL,
            adapter_version=ADAPTER_VERSION,
            capabilities=[
                "ephemeral-session",
                "stage-timeout",
                "structured-output",
                "usage-jsonl",
            ],
        )
        event_descriptor, event_name = tempfile.mkstemp(
            prefix=".codex-events-", dir=result_path.parent
        )
        diagnostic_descriptor, diagnostic_name = tempfile.mkstemp(
            prefix=".codex-diagnostics-", dir=result_path.parent
        )
        result_descriptor, result_name = tempfile.mkstemp(
            prefix=".codex-result-", dir=result_path.parent
        )
        os.close(result_descriptor)
        os.unlink(result_name)
        event_path = Path(event_name)
        diagnostic_path = Path(diagnostic_name)
        codex_result_path = Path(result_name)
        command = _command(binary, schema, codex_result_path, stage)
        previous_handlers = _install_cancellation_handlers()
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=event_descriptor,
            stderr=diagnostic_descriptor,
            start_new_session=_child_requires_new_session(),
        )
        process_group = _managed_process_group(process)
        assert process.stdin is not None
        prompt_descriptor = process.stdin.fileno()
        os.set_blocking(prompt_descriptor, False)
        prompt_pending = memoryview(prompt)
        heartbeat_at = time.monotonic() + HEARTBEAT_SECONDS
        while process.poll() is None:
            _raise_if_cancelled()
            now = time.monotonic()
            if now >= deadline:
                _terminate(process, process_group=process_group, deadline=deadline)
                raise AdapterError(f"Codex {stage} stage exceeded its hard time limit")
            if prompt_pending:
                try:
                    _, writable, _ = select.select(
                        [], [prompt_descriptor], [], min(1, _remaining_timeout(deadline, stage))
                    )
                except InterruptedError:
                    continue
                if writable:
                    try:
                        written = os.write(prompt_descriptor, prompt_pending)
                    except BlockingIOError:
                        pass
                    except (BrokenPipeError, OSError):
                        prompt_error = True
                        prompt_pending = None
                    else:
                        prompt_pending = prompt_pending[written:]
                if not prompt_pending and not process.stdin.closed:
                    with suppress(OSError):
                        process.stdin.close()
            if os.fstat(event_descriptor).st_size > MAX_EVENT_BYTES:
                _terminate(process, process_group=process_group, deadline=deadline)
                raise AdapterError("Codex JSONL output exceeded its safety limit")
            if os.fstat(diagnostic_descriptor).st_size > MAX_DIAGNOSTIC_BYTES:
                _terminate(process, process_group=process_group, deadline=deadline)
                raise AdapterError("Codex diagnostics exceeded their safety limit")
            if now >= heartbeat_at:
                sequence = _append_event(telemetry_descriptor, sequence, "heartbeat")
                heartbeat_at = now + HEARTBEAT_SECONDS
            if not prompt_pending:
                time.sleep(min(1, _remaining_timeout(deadline, stage)))
        _terminate(process, process_group=process_group, deadline=deadline)
        os.fsync(event_descriptor)
        os.fsync(diagnostic_descriptor)
        _validate_capture_descriptor(
            event_descriptor,
            MAX_EVENT_BYTES,
            "Codex JSONL output exceeded its safety limit",
        )
        _validate_capture_descriptor(
            diagnostic_descriptor,
            MAX_DIAGNOSTIC_BYTES,
            "Codex diagnostics exceeded their safety limit",
        )
        if process.returncode != 0:
            detail = _failure_detail(diagnostic_path, event_path)
            raise AdapterError(
                f"Codex {stage} stage failed with status {process.returncode}: {detail}"
            )
        if prompt_error:
            raise AdapterError("Codex closed its prompt stream before the request completed")
        if prompt_pending:
            raise AdapterError("Codex exited before accepting the complete prompt")
        payload = _load_result(codex_result_path)
        usage = _usage_from_events(event_path)
        _write_result(result_path, payload)
        _append_event(
            telemetry_descriptor,
            sequence,
            "usage",
            **usage,
            source="provider_response",
            exact=True,
            final=True,
        )
        return 0
    finally:
        _cleanup_stage(
            process=process,
            process_group=process_group,
            deadline=deadline,
            descriptors=(event_descriptor, diagnostic_descriptor, telemetry_descriptor),
            paths=(event_path, diagnostic_path, codex_result_path),
            previous_handlers=previous_handlers,
        )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdapterError as exc:
        print(f"codex adapter failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
