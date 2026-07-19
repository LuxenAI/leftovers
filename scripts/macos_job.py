#!/usr/bin/env python3
"""One bounded, fail-closed Leftovers macOS job launched independently of the desktop app."""

from __future__ import annotations

import argparse
import fcntl
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import tomllib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_CAPTURE_BYTES = 2_000_000
MAX_JOURNAL_BYTES = 2_000_000
MAX_JOURNAL_LINE_BYTES = 262_144
STRICT_VM_EXECUTION_ENABLED = False
OUTER_JOB_SECONDS = 2_700
TERMINATION_GRACE_SECONDS = 10
KILL_CONFIRM_SECONDS = 2
TERMINATION_RESERVE_SECONDS = TERMINATION_GRACE_SECONDS + KILL_CONFIRM_SECONDS
POLL_INTERVAL_SECONDS = 0.1
CLEANUP_PENDING_FILENAME = "cleanup-pending.json"
_RUN_ID = re.compile(r"[a-f0-9]{32}")
_LAUNCH_LABEL = re.compile(r"dev\.leftovers\.once\.(\d+)\.\d{14}\.\d+")
LAUNCH_HANDOFF_SECONDS = 30
COMMAND_PATH = (
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:"
    "/Applications/Docker.app/Contents/Resources/bin:/opt/podman/bin"
)


class JobError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _JobSupervisor:
    """Own the one active child process group and the job-wide deadline."""

    def __init__(
        self,
        deadline: float,
        termination_deadline: float | None = None,
        *,
        cleanup_pending_path: Path | None = None,
    ):
        self.deadline = deadline
        self.termination_deadline = termination_deadline or deadline
        self.cleanup_pending_path = cleanup_pending_path
        self.active_process: subprocess.Popen[bytes] | None = None
        self.stop_reason: str | None = None
        self._terminating = False
        self._previous_handlers: dict[int, Any] = {}
        self._previous_timer: tuple[float, float] | None = None

    def install(self, seconds: float) -> None:
        for received in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            self._previous_handlers[received] = signal.getsignal(received)
            signal.signal(received, self._on_signal)
        self._previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)

    def close(self) -> None:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for received, previous in self._previous_handlers.items():
            signal.signal(received, previous)
        if self._previous_timer is not None and self._previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *self._previous_timer)

    def _on_signal(self, received: int, _frame: Any) -> None:
        if received == signal.SIGALRM:
            self.stop_reason = "job-wide deadline expired"
        else:
            self.stop_reason = f"job received {signal.Signals(received).name}"
        try:
            self.terminate_active()
        except JobError as exc:
            self.stop_reason = f"{self.stop_reason}; {exc}"

    def track(self, process: subprocess.Popen[bytes]) -> None:
        self.active_process = process
        self.check()

    def untrack(self, process: subprocess.Popen[bytes]) -> None:
        if self.active_process is process:
            self.active_process = None

    def terminate_active(self) -> None:
        if self.active_process is None or self._terminating:
            return
        self._terminating = True
        try:
            self.terminate(self.active_process)
        finally:
            self._terminating = False

    def terminate(self, process: subprocess.Popen[bytes]) -> None:
        """Terminate a tracked group, preserving evidence if death cannot be proven."""

        try:
            _terminate(process, deadline=self.termination_deadline)
        except JobError as exc:
            self._record_cleanup_pending(process, str(exc))
            raise
        self._clear_cleanup_pending_if_owned(process)

    def assert_no_cleanup_pending(self) -> None:
        if self.cleanup_pending_path is None or (
            not self.cleanup_pending_path.exists() and not self.cleanup_pending_path.is_symlink()
        ):
            return
        evidence = _read_cleanup_evidence(self.cleanup_pending_path)
        raise JobError(
            "a prior preview cleanup remains unresolved "
            f"(state={evidence['state']}, run_id={evidence.get('run_id', 'unknown')}); "
            "refusing a new run"
        )

    def record_nested_runner_cleanup(self, process_group: int, reason: str) -> None:
        """Persist a runner-reported cleanup failure after its wrapper exits."""

        if type(process_group) is not int or process_group <= 0:
            raise JobError("nested runner cleanup evidence omitted a valid process group")
        self._record_cleanup_pending_for_group(
            process_group,
            f"nested RunnerCleanupError: {reason}",
            source="nested-runner",
        )

    def _record_cleanup_pending(
        self,
        process: subprocess.Popen[bytes],
        reason: str,
        *,
        source: str = "outer-process-group",
    ) -> None:
        if self.cleanup_pending_path is None:
            return
        pid = process.pid
        if type(pid) is not int or pid <= 0:
            raise JobError("cannot record unproven cleanup without a valid child PID")
        self._record_cleanup_pending_for_group(pid, reason, source=source)

    def _record_cleanup_pending_for_group(
        self,
        process_group: int,
        reason: str,
        *,
        source: str,
    ) -> None:
        """Persist unproven cleanup for the exact group identity supplied by its owner."""

        if self.cleanup_pending_path is None:
            return
        pid = process_group
        if type(pid) is not int or pid <= 0:
            raise JobError("cannot record unproven cleanup without a valid child PID")
        if self.cleanup_pending_path.exists() or self.cleanup_pending_path.is_symlink():
            previous = _read_cleanup_evidence(self.cleanup_pending_path)
            if previous.get("state") == "cleanup_in_progress":
                previous.update(
                    {
                        "state": "cleanup_pending",
                        "pid": pid,
                        "pgid": pid,
                        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "reason": reason[:500],
                        "source": source,
                    }
                )
                _atomic_write(
                    self.cleanup_pending_path,
                    (json.dumps(previous, indent=2, sort_keys=True) + "\n").encode(),
                )
                return
            if previous["pid"] == pid and previous["pgid"] == pid:
                return
            raise JobError("refusing to overwrite cleanup evidence for a different process group")
        evidence = {
            "version": 1,
            "state": "cleanup_pending",
            "pid": pid,
            "pgid": pid,
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "reason": reason[:500],
            "source": source,
        }
        _atomic_write(
            self.cleanup_pending_path,
            (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode(),
        )

    def _clear_cleanup_pending_if_owned(self, process: subprocess.Popen[bytes]) -> None:
        """Clear only evidence this supervisor can prove belongs to its dead child."""

        if self.cleanup_pending_path is None or (
            not self.cleanup_pending_path.exists() and not self.cleanup_pending_path.is_symlink()
        ):
            return
        evidence = _read_cleanup_evidence(self.cleanup_pending_path)
        if evidence.get("version") == 2:
            # No process-group observation can prove that daemon-owned OCI
            # containers and the bound workspace were removed.  Every v2
            # preview lease, including one converted to cleanup_pending after
            # an outer termination failure, requires the matching controller
            # cleanup receipt consumed by _consume_preview_result().
            return
        if evidence.get("source") == "nested-runner":
            # This wrapper may be dead while the separately-owned nested group
            # remains unproven.  It can never clear that nested owner's marker.
            return
        if evidence["pid"] != process.pid or evidence["pgid"] != process.pid:
            raise JobError("refusing to clear cleanup evidence for a different process group")
        try:
            self.cleanup_pending_path.unlink()
        except OSError as exc:
            raise JobError("could not clear proven cleanup evidence") from exc

    def check(self) -> None:
        if time.monotonic() >= self.deadline and self.stop_reason is None:
            self.stop_reason = "job-wide deadline expired"
        if self.stop_reason is not None:
            self.terminate_active()
            raise JobError(self.stop_reason)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="run one bounded Leftovers macOS job")
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--scout-only", action="store_true")
    parser.add_argument("--launch-label")
    return parser


def _lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _validated_install_root(path: Path) -> Path:
    requested = _lexical_path(path)
    expected = Path(__file__).resolve().parents[1]
    if requested != expected:
        raise JobError("job install root does not match its installed package location")
    current = Path(expected.anchor)
    for component in expected.parts[1:]:
        current /= component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise JobError(f"installed path component may not be a symlink: {current}")
    return expected


def _acquire_job_lock(root: Path, launch_label: str | None = None) -> int | None:
    """Acquire the package lock, allowing only a bound launchd handoff to wait."""

    if launch_label is not None:
        match = _LAUNCH_LABEL.fullmatch(launch_label)
        if match is None or int(match.group(1)) != os.getuid():
            raise JobError("launch handoff label is invalid or belongs to another user")
    lock_path = root / "job.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    lock_info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(lock_info.st_mode)
        or lock_info.st_uid != os.getuid()
        or lock_info.st_nlink != 1
    ):
        os.close(descriptor)
        raise JobError("job lock is not a single-link owner-controlled file")
    os.fchmod(descriptor, 0o600)
    deadline = time.monotonic() + (LAUNCH_HANDOFF_SECONDS if launch_label is not None else 0)
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            if launch_label is None or time.monotonic() >= deadline:
                os.close(descriptor)
                return None
            time.sleep(POLL_INTERVAL_SECONDS)


def _private_directory(path: Path) -> Path:
    path = _lexical_path(path)
    installed_root = Path(__file__).resolve().parents[1]
    if path == installed_root or installed_root in path.parents:
        current = installed_root
        relative = path.relative_to(installed_root)
        for component in relative.parts:
            current /= component
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(info.st_mode):
                raise JobError(f"managed path component may not be a symlink: {current}")
    if path.is_symlink():
        raise JobError(f"managed directory may not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise JobError(f"managed directory is not private and owner-controlled: {path}")
    return path.resolve()


def _atomic_write(path: Path, payload: bytes) -> None:
    parent = _private_directory(path.parent)
    target = parent / path.name
    if target.is_symlink():
        raise JobError(f"managed report may not be a symlink: {target}")
    if target.exists():
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise JobError(f"managed report is not owner-controlled: {target}")
    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise JobError("report write made no progress")
            pending = pending[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)


def _read_private_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    allow_empty: bool,
) -> bytes:
    """Read a private artifact through a no-follow descriptor and a hard byte cap."""

    try:
        path_info = path.lstat()
    except FileNotFoundError as exc:
        raise JobError(f"{label} is missing") from exc
    except OSError as exc:
        raise JobError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(path_info.st_mode)
        or path_info.st_uid != os.getuid()
        or path_info.st_nlink != 1
        or stat.S_IMODE(path_info.st_mode) & 0o077
        or path_info.st_size > maximum_bytes
        or (not allow_empty and path_info.st_size == 0)
    ):
        raise JobError(f"{label} is not a private owner-controlled file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise JobError(f"{label} is unavailable") from exc
    try:
        descriptor_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(descriptor_info.st_mode)
            or descriptor_info.st_uid != os.getuid()
            or descriptor_info.st_nlink != 1
            or stat.S_IMODE(descriptor_info.st_mode) & 0o077
            or descriptor_info.st_size > maximum_bytes
            or (not allow_empty and descriptor_info.st_size == 0)
            or (descriptor_info.st_dev, descriptor_info.st_ino)
            != (path_info.st_dev, path_info.st_ino)
        ):
            raise JobError(f"{label} is not a private owner-controlled file")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    except OSError as exc:
        raise JobError(f"{label} could not be read") from exc
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes or (not allow_empty and not payload):
        raise JobError(f"{label} is not a private owner-controlled file")
    return bytes(payload)


def _read_bounded_descriptor(descriptor: int, *, label: str) -> bytes:
    """Read a completed capture descriptor without trusting its last polled size."""

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CAPTURE_BYTES:
            raise JobError(f"bounded command {label} exceeded its safety limit")
        os.lseek(descriptor, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) <= MAX_CAPTURE_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_CAPTURE_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
    except OSError as exc:
        raise JobError(f"bounded command {label} capture could not be read") from exc
    if len(payload) > MAX_CAPTURE_BYTES:
        raise JobError(f"bounded command {label} exceeded its safety limit")
    return bytes(payload)


def _read_cleanup_evidence(path: Path) -> dict[str, Any]:
    """Read private preview cleanup evidence without treating intent as proof."""

    value = _read_json_file(path, label="cleanup-pending evidence", maximum_bytes=8_192)
    if (
        value.get("version") not in {1, 2}
        or value.get("state") not in {"cleanup_in_progress", "cleanup_pending"}
        or type(value.get("pid")) is not int
        or value["pid"] <= 0
        or type(value.get("pgid")) is not int
        or value["pgid"] <= 0
        or not isinstance(value.get("observed_at"), str)
        or not value["observed_at"]
        or not isinstance(value.get("reason"), str)
        or not value["reason"]
    ):
        raise JobError("cleanup-pending evidence has an invalid shape")
    if value["version"] == 2 and (
        _RUN_ID.fullmatch(str(value.get("run_id", ""))) is None
        or value.get("container_label") != f"io.leftovers.job={value['run_id']}"
        or not all(
            isinstance(value.get(name), str) and value[name]
            for name in ("install_root", "state_dir", "workspace_root")
        )
    ):
        raise JobError("preview cleanup evidence has an invalid lease context")
    return value


def _read_cleanup_pending(path: Path) -> dict[str, Any]:
    """Compatibility alias for callers that only need fail-closed evidence."""

    return _read_cleanup_evidence(path)


def _start_preview_cleanup_lease(root: Path, config: dict[str, Any]) -> dict[str, Any]:
    """Write a durable lease before a controller can create an OCI container.

    The marker is intentionally evidence of *unresolved* cleanup, not a lock
    substitute.  A SIGKILL can release the advisory lock, but cannot erase this
    owner-private record.
    """

    state_dir = config.get("state_dir")
    workspace_root = config.get("temp_root")
    if not isinstance(state_dir, str) or not isinstance(workspace_root, str):
        raise JobError("generated config omitted preview cleanup paths")
    state_path = _lexical_path(Path(state_dir))
    workspace_path = _lexical_path(Path(workspace_root))
    for label, path in (("state", state_path), ("workspace", workspace_path)):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise JobError(f"generated {label} path escapes the installed preview root") from exc
    run_id = uuid.uuid4().hex
    evidence = {
        "version": 2,
        "state": "cleanup_in_progress",
        "run_id": run_id,
        "container_label": f"io.leftovers.job={run_id}",
        "install_root": str(root),
        "state_dir": str(state_path),
        "workspace_root": str(workspace_path),
        "pid": os.getpid(),
        "pgid": os.getpgrp(),
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "reason": "controller execution started; cleanup receipt not yet proven",
        "source": "preview-cleanup-lease",
    }
    _atomic_write(
        root / CLEANUP_PENDING_FILENAME,
        (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode(),
    )
    return evidence


def _mark_preview_cleanup_pending(root: Path, reason: str, *, source: str) -> dict[str, Any]:
    path = root / CLEANUP_PENDING_FILENAME
    evidence = _read_cleanup_evidence(path)
    if evidence.get("version") != 2:
        raise JobError("cannot convert legacy cleanup evidence into a preview lease")
    evidence.update(
        {
            "state": "cleanup_pending",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "reason": reason[:500],
            "source": source,
        }
    )
    _atomic_write(path, (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode())
    return evidence


def _verified_cleanup_receipt(root: Path, evidence: dict[str, Any], result: dict[str, Any]) -> bool:
    """Require the controller's exact run id plus a hash-chained cleanup receipt."""

    if result.get("run_id") != evidence.get("run_id") or result.get("stage") not in {
        "complete",
        "deferred",
        "skipped",
        "failed",
        "aborted",
    }:
        return False
    state_dir = Path(str(evidence["state_dir"]))
    journal_path = state_dir / "runs" / f"{evidence['run_id']}.jsonl"
    try:
        raw = _read_private_file(
            journal_path,
            label="cleanup journal",
            maximum_bytes=MAX_JOURNAL_BYTES,
            allow_empty=False,
        )
    except JobError:
        return False
    previous = "0" * 64
    receipt = False
    try:
        stream = io.BytesIO(raw)
        while True:
            line = stream.readline(MAX_JOURNAL_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_JOURNAL_LINE_BYTES:
                return False
            record = json.loads(line)
            if not isinstance(record, dict) or record.get("previous_hash") != previous:
                return False
            record_hash = record.pop("record_hash", None)
            if (
                not isinstance(record_hash, str)
                or re.fullmatch(r"[a-f0-9]{64}", record_hash) is None
            ):
                return False
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
            if __import__("hashlib").sha256(canonical.encode()).hexdigest() != record_hash:
                return False
            previous = record_hash
            if record.get("event") == "cleanup_receipt":
                payload = record.get("payload")
                receipt = (
                    isinstance(payload, dict)
                    and payload.get("containers_removed") is True
                    and payload.get("local_workspace_removed") is True
                    and type(payload.get("resources_acquired")) is bool
                )
            elif record.get("event") == "cleanup_failed":
                receipt = False
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return receipt


def _consume_preview_result(
    root: Path, result: CommandResult, evidence: dict[str, Any]
) -> dict[str, Any]:
    """Clear a lease only after a complete, independently checked receipt."""

    if not 0 < len(result.stdout) <= MAX_CAPTURE_BYTES:
        _mark_preview_cleanup_pending(
            root, "controller returned an empty or oversized result", source="controller-result"
        )
        raise JobError("bounded contribution preview returned an empty or oversized result")
    try:
        payload = json.loads(result.stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _mark_preview_cleanup_pending(
            root, "controller returned malformed result JSON", source="controller-result"
        )
        raise JobError("bounded contribution preview returned invalid JSON") from exc
    if not isinstance(payload, dict):
        _mark_preview_cleanup_pending(
            root, "controller returned non-object result", source="controller-result"
        )
        raise JobError("bounded contribution preview returned an invalid result shape")
    if not _verified_cleanup_receipt(root, evidence, payload):
        _mark_preview_cleanup_pending(
            root,
            "controller completion did not prove matching container and workspace cleanup",
            source="controller-result",
        )
        raise JobError("bounded contribution preview lacked a trusted cleanup receipt")
    try:
        (root / CLEANUP_PENDING_FILENAME).unlink()
    except PermissionError as exc:
        raise JobError("could not clear proven preview cleanup evidence") from exc
    if result.returncode != 0:
        raise JobError(f"bounded contribution preview failed with status {result.returncode}")
    return payload


def _process_group_is_alive(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        if process.poll() is not None:
            # After the leader is reaped, EPERM means this same-user supervisor can
            # no longer observe a signalable member of the managed process group.
            return False
        raise JobError("cannot inspect the active child process group") from exc
    except OSError as exc:
        raise JobError("cannot inspect the active child process group") from exc
    return True


def _signal_process_group(process: subprocess.Popen[bytes], received: signal.Signals) -> None:
    try:
        os.killpg(process.pid, received)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise JobError("cannot signal the active child process group") from exc


def _reap_process_leader(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait(timeout=KILL_CONFIRM_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise JobError("active child process leader could not be reaped") from exc


def _terminate(process: subprocess.Popen[bytes], *, deadline: float) -> None:
    """Terminate the entire child session, never merely its leader process."""
    if not _process_group_is_alive(process):
        _reap_process_leader(process)
        return
    _signal_process_group(process, signal.SIGTERM)
    grace_deadline = min(deadline, time.monotonic() + TERMINATION_GRACE_SECONDS)
    while _process_group_is_alive(process):
        remaining = grace_deadline - time.monotonic()
        if remaining <= 0:
            break
        process.poll()
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
    if not _process_group_is_alive(process):
        _reap_process_leader(process)
        return
    _signal_process_group(process, signal.SIGKILL)
    kill_deadline = time.monotonic() + KILL_CONFIRM_SECONDS
    while _process_group_is_alive(process):
        remaining = kill_deadline - time.monotonic()
        if remaining <= 0:
            break
        process.poll()
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))
    if _process_group_is_alive(process):
        raise JobError("active child process group could not be terminated after SIGKILL")
    _reap_process_leader(process)


def _runner_cleanup_failure(stderr: bytes) -> tuple[int, str] | None:
    """Recognize only the runner's complete, structured cleanup-proof contract."""

    if not 0 < len(stderr) <= 4_096:
        return None
    try:
        value = json.loads(stderr.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(value, dict)
        or value.get("error") != "RunnerCleanupError"
        or type(value.get("process_group")) is not int
        or value["process_group"] <= 0
        or not isinstance(value.get("message"), str)
        or not value["message"]
        or len(value["message"]) > 500
    ):
        return None
    return value["process_group"], value["message"]


def _run(
    command: list[str],
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout: float,
    supervisor: _JobSupervisor,
    propagate_runner_cleanup_failure: bool = False,
) -> CommandResult:
    stdout_fd = -1
    stderr_fd = -1
    stdout_name: str | None = None
    stderr_name: str | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        stdout_fd, stdout_name = tempfile.mkstemp(prefix=".stdout-", dir=cwd / "tmp")
        stderr_fd, stderr_name = tempfile.mkstemp(prefix=".stderr-", dir=cwd / "tmp")
        supervisor.check()
        global_deadline = supervisor.deadline
        command_deadline = min(global_deadline, time.monotonic() + timeout)
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            start_new_session=True,
        )
        supervisor.track(process)
        while process.poll() is None:
            if time.monotonic() >= command_deadline:
                supervisor.terminate(process)
                raise JobError(f"bounded command timed out after {timeout} seconds")
            supervisor.check()
            if os.fstat(stdout_fd).st_size > MAX_CAPTURE_BYTES:
                supervisor.terminate(process)
                raise JobError("bounded command stdout exceeded its safety limit")
            if os.fstat(stderr_fd).st_size > MAX_CAPTURE_BYTES:
                supervisor.terminate(process)
                raise JobError("bounded command stderr exceeded its safety limit")
            time.sleep(POLL_INTERVAL_SECONDS)
        os.fsync(stdout_fd)
        os.fsync(stderr_fd)
        stdout = _read_bounded_descriptor(stdout_fd, label="stdout")
        stderr = _read_bounded_descriptor(stderr_fd, label="stderr")
        if propagate_runner_cleanup_failure:
            nested_cleanup = _runner_cleanup_failure(stderr)
            if nested_cleanup is not None:
                nested_process_group, cleanup_reason = nested_cleanup
                supervisor.record_nested_runner_cleanup(nested_process_group, cleanup_reason)
        # A deadline can arrive after the wrapper has already written its
        # cleanup-proof failure.  Preserve that evidence before honoring the
        # job-wide stop request.
        supervisor.check()
        supervisor.terminate(process)
        supervisor.untrack(process)
        return CommandResult(process.returncode or 0, stdout, stderr)
    finally:
        cleanup_error: JobError | None = None
        if process is not None and supervisor.active_process is process:
            try:
                supervisor.terminate(process)
            except JobError as exc:
                cleanup_error = exc
            else:
                supervisor.untrack(process)
        for descriptor in (stdout_fd, stderr_fd):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except OSError:
                if cleanup_error is None:
                    cleanup_error = JobError("bounded command capture cleanup failed")
        for name in (stdout_name, stderr_name):
            if name is None:
                continue
            try:
                Path(name).unlink()
            except FileNotFoundError:
                pass
            except OSError:
                if cleanup_error is None:
                    cleanup_error = JobError("bounded command temporary cleanup failed")
        if cleanup_error is not None:
            raise cleanup_error


def _read_config(path: Path) -> dict[str, Any]:
    try:
        raw = _read_private_file(
            path,
            label="generated configuration",
            maximum_bytes=1_000_000,
            allow_empty=True,
        )
        value = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise JobError(f"cannot read generated configuration: {exc}") from exc
    if not isinstance(value, dict):
        raise JobError("generated configuration has an invalid shape")
    return value


def _read_json_file(path: Path, *, label: str, maximum_bytes: int = 2_000_000) -> dict[str, Any]:
    try:
        raw = _read_private_file(
            path,
            label=label,
            maximum_bytes=maximum_bytes,
            allow_empty=False,
        )
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JobError(f"{label} contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise JobError(f"{label} has an invalid shape")
    return value


def _read_manifest(path: Path, root: Path) -> dict[str, Any]:
    manifest = _read_json_file(path, label="install manifest")
    if (
        manifest.get("version") != 1
        or manifest.get("install_root") != str(root)
        or manifest.get("publication") != "disabled"
        or manifest.get("model") != "gpt-5.6-terra"
        or manifest.get("reasoning_effort") != "high"
    ):
        raise JobError("install manifest does not match the safe package identity")
    return manifest


def _verified_report(
    root: Path,
    path_text: object,
    *,
    label: str,
    execution_profile: str,
) -> Path:
    if not isinstance(path_text, str):
        raise JobError(f"{label} path is not recorded")
    path = _lexical_path(Path(path_text))
    reports = root / "reports"
    if path.parent != reports:
        raise JobError(f"{label} path escapes the package reports directory")
    report = _read_json_file(path, label=label)
    checks = report.get("checks")
    if (
        report.get("success") is not True
        or report.get("execution_profile") != execution_profile
        or not isinstance(checks, list)
        or not checks
        or any(not isinstance(check, dict) or check.get("ok") is not True for check in checks)
    ):
        raise JobError(f"{label} does not contain successful complete evidence")
    return path


def _remaining_timeout(deadline: float, maximum: int) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise JobError("job-wide deadline is exhausted")
    return min(maximum, remaining)


def _github_token(environment: dict[str, str], supervisor: _JobSupervisor) -> str:
    gh = shutil.which("gh", path=environment["PATH"])
    if gh is None:
        raise JobError("GitHub CLI is required for authenticated read-only scouting")
    process: subprocess.Popen[bytes] | None = None
    try:
        supervisor.check()
        command_deadline = min(supervisor.deadline, time.monotonic() + 20)
        process = subprocess.Popen(
            [gh, "auth", "token"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        supervisor.track(process)
        while process.poll() is None:
            if time.monotonic() >= command_deadline:
                supervisor.terminate(process)
                raise JobError("GitHub CLI token lookup exceeded its bounded deadline")
            supervisor.check()
            time.sleep(POLL_INTERVAL_SECONDS)
        supervisor.terminate(process)
        supervisor.untrack(process)
        if process.stdout is None:
            raise JobError("GitHub CLI token lookup did not provide stdout")
        output = process.stdout.read(513)
        if len(output) > 512:
            raise JobError("GitHub CLI returned an oversized authenticated token")
        token = output.decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise JobError("GitHub CLI could not provide an authenticated token") from exc
    finally:
        cleanup_error: JobError | None = None
        if process is not None and supervisor.active_process is process:
            try:
                supervisor.terminate(process)
            except JobError as exc:
                cleanup_error = exc
            else:
                supervisor.untrack(process)
        if process is not None and process.stdout is not None and not process.stdout.closed:
            try:
                process.stdout.close()
            except OSError:
                if cleanup_error is None:
                    cleanup_error = JobError("GitHub CLI token capture cleanup failed")
        if cleanup_error is not None:
            raise cleanup_error
    if (
        process.returncode != 0
        or not 20 <= len(token) <= 512
        or re.fullmatch(r"[A-Za-z0-9_.-]+", token) is None
    ):
        raise JobError("GitHub CLI did not provide a valid authenticated token")
    return token


def _curated_preview_available(config: dict[str, Any]) -> bool:
    publication = config.get("publication")
    agent = config.get("agent")
    repositories = config.get("repositories")
    if (
        not isinstance(publication, dict)
        or publication.get("mode") != "dry-run"
        or publication.get("external_writes_acknowledged") is not False
        or not isinstance(agent, dict)
        or agent.get("backend") != "host"
        or agent.get("model") != "gpt-5.6-terra"
        or not isinstance(repositories, list)
    ):
        return False
    return any(
        isinstance(repository, dict)
        and repository.get("enabled") is True
        and repository.get("ai_contributions_allowed") is True
        and isinstance(repository.get("ai_policy_url"), str)
        and isinstance(repository.get("ai_policy_checked_at"), str)
        and isinstance(repository.get("test_commands"), list)
        and bool(repository["test_commands"])
        for repository in repositories
    )


def _runtime_ready(
    config: dict[str, Any],
    manifest: dict[str, Any],
    environment: dict[str, str],
    root: Path,
    deadline: float,
    supervisor: _JobSupervisor,
) -> tuple[bool, str]:
    # Keep the call shape stable for the package status/tests, but never let an
    # OCI rehearsal become authorization for hostile repository execution.
    # Docker and Podman share the host kernel and the model process in this
    # preview is host-native, so neither can satisfy the strict VM contract.
    del config, manifest, environment, root, deadline, supervisor
    return False, "OCI and host-agent profiles are rehearsal-only; strict VM execution is disabled"


def _json_output(result: CommandResult, label: str) -> dict[str, Any]:
    if result.returncode != 0:
        raise JobError(f"{label} failed with status {result.returncode}")
    if not 0 < len(result.stdout) <= MAX_CAPTURE_BYTES:
        raise JobError(f"{label} returned empty or oversized JSON")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JobError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise JobError(f"{label} returned an invalid result shape")
    return value


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = _private_directory(_validated_install_root(args.install_root))
    descriptor = _acquire_job_lock(root, args.launch_label)
    if descriptor is None:
        print(json.dumps({"status": "skipped", "reason": "job already active"}))
        return 0
    reports = _private_directory(root / "reports")
    _private_directory(root / "tmp")
    wrapper = root / "bin" / "leftovers"
    config_path = root / "config.toml"
    if wrapper.is_symlink() or not os.access(wrapper, os.X_OK):
        raise JobError("installed Leftovers launcher is missing or unsafe")
    wrapper_info = wrapper.lstat()
    if (
        not stat.S_ISREG(wrapper_info.st_mode)
        or wrapper_info.st_uid != os.getuid()
        or wrapper_info.st_nlink != 1
        or stat.S_IMODE(wrapper_info.st_mode) & 0o077
    ):
        raise JobError("installed Leftovers launcher is not private and owner-controlled")
    config = _read_config(config_path)
    manifest = _read_manifest(root / "manifest.json", root)
    if args.launch_label is not None and (
        manifest.get("launch_label") != args.launch_label
        or manifest.get("launch_plist") != str(root / "launchd" / f"{args.launch_label}.plist")
    ):
        os.close(descriptor)
        print(
            json.dumps(
                {
                    "status": "skipped",
                    "reason": "launch handoff no longer matches the installed manifest",
                }
            )
        )
        return 0
    budget = config.get("budget")
    job_seconds = budget.get("max_run_seconds") if isinstance(budget, dict) else None
    if type(job_seconds) is not int or not 60 <= job_seconds <= OUTER_JOB_SECONDS:
        raise JobError("generated config has no conservative job-wide deadline")

    environment = {
        "PATH": COMMAND_PATH,
        "HOME": str(Path.home()),
        "LEFTOVERS_REHEARSAL_AGENT": os.environ.get("LEFTOVERS_REHEARSAL_AGENT", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(root / "tmp"),
        "XDG_CACHE_HOME": str(_private_directory(root / "cache")),
        "XDG_CONFIG_HOME": str(_private_directory(root / "xdg-config")),
        "XDG_DATA_HOME": str(_private_directory(root / "xdg-data")),
    }
    termination_deadline = time.monotonic() + job_seconds
    deadline = termination_deadline - TERMINATION_RESERVE_SECONDS
    supervisor = _JobSupervisor(
        deadline,
        termination_deadline,
        cleanup_pending_path=root / CLEANUP_PENDING_FILENAME,
    )
    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    summary: dict[str, Any] = {
        "version": 1,
        "started_at": started_at,
        "mode": "scout-only" if args.scout_only else "bounded-preview",
        "publication_attempted": False,
        "preview_started": False,
        "candidate_count": 0,
        "job_deadline_seconds": job_seconds,
        "errors": [],
    }
    try:
        supervisor.assert_no_cleanup_pending()
        supervisor.install(_remaining_timeout(deadline, job_seconds))
        seatbelt_path = manifest.get("seatbelt_report")
        if seatbelt_path is not None:
            verified_seatbelt = _verified_report(
                root,
                seatbelt_path,
                label="Seatbelt rehearsal report",
                execution_profile="macos-seatbelt-supplemental",
            )
            summary["seatbelt_rehearsal"] = str(verified_seatbelt)
            summary["seatbelt_rehearsal_reused"] = True
        token = _github_token(environment, supervisor)
        scout_environment = {**environment, "LEFTOVERS_GITHUB_READ_TOKEN": token}
        scout_result = _run(
            [str(wrapper), "repo-scout", "--scan", "12", "--limit", "7"],
            environment=scout_environment,
            cwd=root,
            timeout=_remaining_timeout(deadline, 180),
            supervisor=supervisor,
        )
        scout = _json_output(scout_result, "repository scouting")
        candidates = scout.get("candidates")
        if not isinstance(candidates, list):
            raise JobError("repository scouting omitted its candidate list")
        _atomic_write(
            reports / "repository-candidates.json",
            (json.dumps(scout, indent=2, sort_keys=True) + "\n").encode(),
        )
        summary["candidate_count"] = len(candidates)
        summary["candidate_report"] = str(reports / "repository-candidates.json")

        if args.scout_only:
            summary["stop_reason"] = "scout-only mode requested"
        elif not STRICT_VM_EXECUTION_ENABLED:
            summary["stop_reason"] = (
                "unattended execution is disabled until the no-NIC strict VM worker, "
                "guest image, and bounded artifact handoff have live attestation"
            )
        elif not _curated_preview_available(config):
            summary["stop_reason"] = (
                "no manually curated AI-permitted repository with verification commands"
            )
        else:
            runtime_ok, runtime_reason = _runtime_ready(
                config,
                manifest,
                environment,
                root,
                deadline,
                supervisor,
            )
            if not runtime_ok:
                summary["stop_reason"] = runtime_reason
            else:
                cleanup_lease = _start_preview_cleanup_lease(root, config)
                summary["preview_cleanup_lease"] = {
                    "run_id": cleanup_lease["run_id"],
                    "container_label": cleanup_lease["container_label"],
                }
                preview_result = _run(
                    [str(wrapper), "run", "--execute", "--run-id", cleanup_lease["run_id"]],
                    environment=scout_environment,
                    cwd=root,
                    timeout=_remaining_timeout(deadline, OUTER_JOB_SECONDS),
                    supervisor=supervisor,
                    propagate_runner_cleanup_failure=True,
                )
                preview = _consume_preview_result(root, preview_result, cleanup_lease)
                _atomic_write(
                    reports / "last-preview.json",
                    (json.dumps(preview, indent=2, sort_keys=True) + "\n").encode(),
                )
                summary["preview_started"] = True
                summary["preview_report"] = str(reports / "last-preview.json")
                summary["stop_reason"] = "dry-run preview completed; publication remained disabled"
    except (JobError, OSError, UnicodeDecodeError) as exc:
        summary["errors"].append(str(exc)[:500])
        summary.setdefault("stop_reason", "job failed closed")
    finally:
        try:
            supervisor.terminate_active()
        except JobError as exc:
            if str(exc) not in summary["errors"]:
                summary["errors"].append(str(exc)[:500])
            summary.setdefault("stop_reason", "job failed closed")
        try:
            supervisor.check()
        except JobError as exc:
            if str(exc) not in summary["errors"]:
                summary["errors"].append(str(exc)[:500])
            summary.setdefault("stop_reason", "job failed closed")
        supervisor.close()
        summary["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        _atomic_write(
            reports / "job-summary.json",
            (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode(),
        )
        os.close(descriptor)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not summary["errors"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except JobError as exc:
        print(json.dumps({"error": "JobError", "message": str(exc)}))
        raise SystemExit(2) from None
