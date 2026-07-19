"""One-epoch controller for the deliberately disabled strict-VM backend.

This module is intentionally *not* wired into the orchestrator.  It is the
small host-side half of a future contribution worker: it creates only opaque
disk records, invokes the pinned Virtualization.framework launcher through one
fixed argv, and consumes a result only after a receipt proves guest shutdown.
No repository archive is unpacked or executed by this controller.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import StrictVMConfig
from .strict_vm_lease import StrictVMRunLease, VMCleanupReceipt
from .vm_bundle import (
    ALIGNMENT,
    TailResult,
    VerifiedGuestResult,
    build_authorized_request_bundle,
    extract_tail_result,
    fixture_vm_bundle_capability,
    read_raw_section,
    validate_guest_result,
)

# This must remain false until the guest policy, narrow model mediator, and
# adversarial live evidence are connected in the production controller.
STRICT_VM_EXECUTION_ENABLED = False

_EXPECTED_LAUNCHER_VERSION = "0.3.0-proof"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
_LAUNCHER_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,6}Z\Z")
_MAX_RECEIPT_BYTES = 64 * 1_024
_MAX_STDERR_BYTES = 64 * 1_024
_READ_CHUNK_BYTES = 8 * 1_024
_OUTER_SETUP_GRACE_SECONDS = 90
_GROUP_GRACE_SECONDS = 5.0
_GROUP_KILL_SECONDS = 2.0
_RECEIPT_CLOCK_SKEW = timedelta(seconds=5)
_MAX_GUEST_POLICY_BYTES = 64 * 1_024
_GUEST_POLICY_NAME = "guest-policy.json"
_GUEST_POLICY_PROFILE = "leftovers-guest-rejection-only-v1"
_GUEST_POLICY_EXECUTION_MODE = "reject-all-actions"


class StrictVMRunnerError(RuntimeError):
    """A strict VM epoch could not be safely prepared, stopped, or verified."""


class StrictVMReadinessError(StrictVMRunnerError):
    """A supposedly pinned launcher or boot artifact is not safe to invoke."""


class StrictVMLaunchError(StrictVMRunnerError):
    """The launcher did not produce a bounded, proven guest shutdown."""


class StrictVMReceiptError(StrictVMLaunchError):
    """A launcher receipt is malformed or does not bind to this exact epoch."""


class StrictVMOutputOverflow(StrictVMLaunchError):
    """The launcher exceeded its bounded stdout or stderr contract."""


@dataclass(frozen=True)
class StrictVMReadiness:
    launcher_sha256: str
    kernel_sha256: str
    initrd_sha256: str
    root_disk_sha256: str
    root_disk_bytes: int
    guest_policy_sha256: str


@dataclass(frozen=True)
class VerifiedLauncherReceipt:
    canonical_json: bytes
    manifest_sha256: str
    run_id: str
    scratch_sha256: str | None


@dataclass(frozen=True)
class StrictVMEpochResult:
    run_id: str
    request_sha256: str
    manifest_sha256: str
    receipt: VerifiedLauncherReceipt
    result: TailResult
    verified_result: VerifiedGuestResult
    canonical_patch: bytes
    cleanup: VMCleanupReceipt


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _walk_json(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 20 or nodes[0] > 4_096:
        raise StrictVMReceiptError("launcher receipt exceeds JSON complexity limits")
    if isinstance(value, dict):
        if len(value) > 256 or any(not isinstance(key, str) or len(key) > 128 for key in value):
            raise StrictVMReceiptError("launcher receipt object shape is unsafe")
        for item in value.values():
            _walk_json(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        if len(value) > 64:
            raise StrictVMReceiptError("launcher receipt array is too large")
        for item in value:
            _walk_json(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, str):
        if len(value) > 4_096 or any(ord(character) < 32 for character in value):
            raise StrictVMReceiptError("launcher receipt string is unsafe")
    elif isinstance(value, float):
        raise StrictVMReceiptError("launcher receipt may not contain floats")
    elif value is not None and not isinstance(value, bool | int):
        raise StrictVMReceiptError("launcher receipt contains an unsupported JSON value")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StrictVMReceiptError("launcher receipt cannot be canonicalized") from exc


def _require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise StrictVMReceiptError(f"launcher receipt {label} fields are not exact")
    return value


def _require_int(value: Any, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise StrictVMReceiptError(f"launcher receipt {label} does not match")


def _require_string(value: Any, expected: str, label: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise StrictVMReceiptError(f"launcher receipt {label} does not match")


def _parse_launcher_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _LAUNCHER_TIMESTAMP.fullmatch(value) is None:
        raise StrictVMReceiptError(f"launcher receipt {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise StrictVMReceiptError(f"launcher receipt {label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise StrictVMReceiptError(f"launcher receipt {label} is not UTC")
    return parsed.astimezone(UTC)


def _canonical_absolute_path(path: Path, role: str) -> Path:
    if (
        not path.is_absolute()
        or os.path.abspath(os.fspath(path)) != os.fspath(path)
        or os.path.realpath(path) != os.fspath(path)
    ):
        raise StrictVMReadinessError(f"{role} path is not canonical or contains a symlink")
    return path


def _require_immutable_ancestors(path: Path, *, trusted_owner: int, role: str) -> None:
    """Require every directory through ``path`` to be root/trusted and non-writable.

    Hashing a file is not a pin if the controller account can rename a parent
    after the hash but before ``exec``/Virtualization.framework opens it.
    Production therefore installs launch and boot inputs outside the operator's
    writable home under a root or dedicated build account.
    """

    path = _canonical_absolute_path(path, role)
    current = Path(path.anchor)
    components = path.parts[1:]
    for component in components:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise StrictVMReadinessError(f"{role} ancestor is unavailable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, trusted_owner}
            or stat.S_IMODE(info.st_mode) & 0o222
        ):
            raise StrictVMReadinessError(
                f"{role} ancestors must be immutable and root/trusted-owner controlled"
            )


def _hash_pinned_file(
    path: Path,
    expected: str,
    *,
    role: str,
    expected_owner: int,
    maximum: int | None = None,
    exact_mode: int | None = None,
) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise StrictVMReadinessError(f"{role} is unavailable") from exc
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_owner
        or before.st_nlink != 1
        or mode & 0o222
        or (exact_mode is not None and mode != exact_mode)
        or before.st_size <= 0
        or (maximum is not None and before.st_size > maximum)
    ):
        raise StrictVMReadinessError(f"{role} identity or permissions are unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise StrictVMReadinessError(f"{role} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_uid != before.st_uid
            or opened.st_nlink != before.st_nlink
            or opened.st_size != before.st_size
            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(before.st_mode)
        ):
            raise StrictVMReadinessError(f"{role} identity changed while opening")
        digest = hashlib.sha256()
        total = 0
        while True:
            raw = os.read(descriptor, 64 * 1_024)
            if not raw:
                break
            total += len(raw)
            if maximum is not None and total > maximum:
                raise StrictVMReadinessError(f"{role} exceeds its configured size cap")
            digest.update(raw)
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise StrictVMReadinessError(f"{role} path disappeared while hashing") from exc
        if (
            total != before.st_size
            or after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or path_after.st_dev != opened.st_dev
            or path_after.st_ino != opened.st_ino
            or path_after.st_uid != opened.st_uid
            or path_after.st_mode != opened.st_mode
            or path_after.st_size != opened.st_size
            or path_after.st_mtime_ns != opened.st_mtime_ns
            or path_after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise StrictVMReadinessError(f"{role} changed while hashing")
    finally:
        os.close(descriptor)
    actual = digest.hexdigest()
    if actual != expected:
        raise StrictVMReadinessError(f"{role} SHA-256 does not match its pin")
    return actual


def _read_pinned_policy(
    path: Path,
    *,
    expected_owner: int,
) -> tuple[bytes, str]:
    """Read one small immutable policy artifact through a no-follow descriptor.

    Unlike the boot-image digest pins, this value is intentionally not copied
    from configuration.  Its digest is derived from the exact canonical bytes
    that are validated below, while the enclosing immutable boot directory
    prevents the controller account from swapping it after readiness checks.
    """

    try:
        before = path.lstat()
    except OSError as exc:
        raise StrictVMReadinessError("guest policy is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_owner
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o400
        or not 0 < before.st_size <= _MAX_GUEST_POLICY_BYTES
    ):
        raise StrictVMReadinessError("guest policy identity or permissions are unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise StrictVMReadinessError("guest policy cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_uid != before.st_uid
            or opened.st_nlink != before.st_nlink
            or opened.st_size != before.st_size
            or opened.st_mode != before.st_mode
            or opened.st_ctime_ns != before.st_ctime_ns
        ):
            raise StrictVMReadinessError("guest policy identity changed while opening")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise StrictVMReadinessError("guest policy changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise StrictVMReadinessError("guest policy grew while reading")
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise StrictVMReadinessError("guest policy path disappeared while reading") from exc
        for observed in (after, path_after):
            if (
                observed.st_dev != before.st_dev
                or observed.st_ino != before.st_ino
                or observed.st_uid != before.st_uid
                or observed.st_mode != before.st_mode
                or observed.st_nlink != before.st_nlink
                or observed.st_size != before.st_size
                or observed.st_mtime_ns != before.st_mtime_ns
                or observed.st_ctime_ns != before.st_ctime_ns
            ):
                raise StrictVMReadinessError("guest policy changed while reading")
    finally:
        os.close(descriptor)
    return raw, hashlib.sha256(raw).hexdigest()


def _validate_guest_policy(
    raw: bytes,
    *,
    kernel_sha256: str,
    initrd_sha256: str,
    root_disk_sha256: str,
) -> None:
    """Require a canonical, rejection-only policy bound to these boot bytes."""

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise StrictVMReadinessError("guest policy is not strict JSON") from exc
    try:
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StrictVMReadinessError("guest policy cannot be canonicalized") from exc
    if canonical != raw:
        raise StrictVMReadinessError("guest policy bytes are not canonical JSON")
    expected = {
        "schema_version",
        "profile",
        "execution_mode",
        "boot_artifacts",
    }
    if type(value) is not dict or set(value) != expected:
        raise StrictVMReadinessError("guest policy fields are not exact")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["profile"] != _GUEST_POLICY_PROFILE
        or value["execution_mode"] != _GUEST_POLICY_EXECUTION_MODE
    ):
        raise StrictVMReadinessError("guest policy profile is not the rejection-only profile")
    boot = value["boot_artifacts"]
    expected_boot = {
        "kernel_sha256": kernel_sha256,
        "initrd_sha256": initrd_sha256,
        "root_disk_sha256": root_disk_sha256,
    }
    if type(boot) is not dict or boot != expected_boot:
        raise StrictVMReadinessError("guest policy is not bound to the pinned boot artifacts")


def _require_boot_directory(config: StrictVMConfig) -> tuple[Path, os.stat_result]:
    boot = _canonical_absolute_path(Path(config.boot_artifact_directory), "boot directory")
    try:
        info = boot.lstat()
    except OSError as exc:
        raise StrictVMReadinessError("boot artifact directory is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid == os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o222
    ):
        raise StrictVMReadinessError(
            "boot artifact directory must be immutable under a non-controller owner"
        )
    _require_immutable_ancestors(boot, trusted_owner=info.st_uid, role="boot directory")
    return boot, info


def verify_static_readiness(config: StrictVMConfig) -> StrictVMReadiness:
    """Hash exact controller-owned files without loading them or following links."""

    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise StrictVMReadinessError("strict VM requires macOS on arm64")
    if not config.enabled:
        raise StrictVMReadinessError("strict VM is disabled")
    if not all(
        _SHA256.fullmatch(value)
        for value in (
            config.launcher_sha256,
            config.kernel_sha256,
            config.initrd_sha256,
            config.root_disk_sha256,
        )
    ):
        raise StrictVMReadinessError("strict VM pin is malformed")
    launcher = _canonical_absolute_path(Path(config.launcher_path), "strict VM launcher")
    try:
        launcher_info = launcher.lstat()
    except OSError as exc:
        raise StrictVMReadinessError("strict VM launcher is unavailable") from exc
    if (
        not stat.S_ISREG(launcher_info.st_mode)
        or launcher_info.st_uid == os.geteuid()
        or launcher_info.st_nlink != 1
        or stat.S_IMODE(launcher_info.st_mode) != 0o555
    ):
        raise StrictVMReadinessError(
            "strict VM launcher must be immutable mode 0555 under a non-controller owner"
        )
    _require_immutable_ancestors(
        launcher.parent,
        trusted_owner=launcher_info.st_uid,
        role="strict VM launcher",
    )
    boot, boot_info = _require_boot_directory(config)
    artifact_paths = {
        "kernel": Path(config.kernel_path),
        "initrd": Path(config.initrd_path),
        "root_disk": Path(config.root_disk_path),
        "guest_policy": Path(config.guest_policy_path),
    }
    expected_names = {
        "kernel": "kernel",
        "initrd": "initrd",
        "root_disk": "root.raw",
        "guest_policy": _GUEST_POLICY_NAME,
    }
    if any(
        _canonical_absolute_path(path, role).parent != boot or path.name != expected_names[role]
        for role, path in artifact_paths.items()
    ):
        raise StrictVMReadinessError("boot artifacts are not direct pinned boot-directory children")
    root = artifact_paths["root_disk"]
    try:
        root_size = root.lstat().st_size
    except OSError as exc:
        raise StrictVMReadinessError("root disk is unavailable") from exc
    if root_size < 1 << 20 or root_size % ALIGNMENT:
        raise StrictVMReadinessError("root disk size is unsafe")
    launcher_sha256 = _hash_pinned_file(
        launcher,
        config.launcher_sha256,
        role="launcher",
        expected_owner=launcher_info.st_uid,
        maximum=64 << 20,
        exact_mode=0o555,
    )
    kernel_sha256 = _hash_pinned_file(
        artifact_paths["kernel"],
        config.kernel_sha256,
        role="kernel",
        expected_owner=boot_info.st_uid,
        maximum=128 << 20,
    )
    initrd_sha256 = _hash_pinned_file(
        artifact_paths["initrd"],
        config.initrd_sha256,
        role="initrd",
        expected_owner=boot_info.st_uid,
        maximum=512 << 20,
    )
    root_disk_sha256 = _hash_pinned_file(
        root,
        config.root_disk_sha256,
        role="root disk",
        expected_owner=boot_info.st_uid,
        maximum=16 << 30,
    )
    policy_raw, guest_policy_sha256 = _read_pinned_policy(
        artifact_paths["guest_policy"], expected_owner=boot_info.st_uid
    )
    _validate_guest_policy(
        policy_raw,
        kernel_sha256=kernel_sha256,
        initrd_sha256=initrd_sha256,
        root_disk_sha256=root_disk_sha256,
    )
    readiness = StrictVMReadiness(
        launcher_sha256=launcher_sha256,
        kernel_sha256=kernel_sha256,
        initrd_sha256=initrd_sha256,
        root_disk_sha256=root_disk_sha256,
        root_disk_bytes=root_size,
        guest_policy_sha256=guest_policy_sha256,
    )
    try:
        boot_after = boot.lstat()
    except OSError as exc:
        raise StrictVMReadinessError("boot artifact directory disappeared while hashing") from exc
    if (
        boot_after.st_dev,
        boot_after.st_ino,
        boot_after.st_uid,
        boot_after.st_mode,
        boot_after.st_mtime_ns,
        boot_after.st_ctime_ns,
    ) != (
        boot_info.st_dev,
        boot_info.st_ino,
        boot_info.st_uid,
        boot_info.st_mode,
        boot_info.st_mtime_ns,
        boot_info.st_ctime_ns,
    ):
        raise StrictVMReadinessError("boot artifact directory changed while hashing")
    return readiness


class _BoundedPipe:
    def __init__(self, descriptor: int, maximum: int) -> None:
        self.descriptor = descriptor
        self.maximum = maximum
        self.data = bytearray()
        self.overflowed = False
        self.error: BaseException | None = None

    def drain(self) -> None:
        try:
            while True:
                raw = os.read(self.descriptor, _READ_CHUNK_BYTES)
                if not raw:
                    return
                remaining = self.maximum - len(self.data)
                if remaining <= 0 or len(raw) > remaining:
                    self.overflowed = True
                    if remaining > 0:
                        self.data.extend(raw[:remaining])
                    continue
                self.data.extend(raw)
        except BaseException as exc:  # pragma: no cover - platform pipe failure
            self.error = exc


def _group_alive(process_group: int, process: subprocess.Popen[bytes] | None = None) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        # Darwin can report EPERM for an already-reaped session leader. Once
        # our direct child is reaped, never signal a possibly reused PGID.
        if process is not None and process.poll() is not None:
            return False
        raise StrictVMLaunchError("launcher process group cannot be inspected") from exc
    except OSError as exc:
        raise StrictVMLaunchError("launcher process group inspection failed") from exc
    return True


def _stop_group(process: subprocess.Popen[bytes]) -> bool:
    """Stop one controller-created process group and prove it no longer exists."""

    # ``Popen.poll`` reaps the direct launcher.  On Linux, an exited but
    # unreaped session leader can still make ``killpg(pgid, 0)`` succeed, so
    # repeatedly probing that numeric PGID until the zombie disappears races
    # with reaping and can falsely report cleanup failure for a launcher that
    # has already exited.  Once the direct child is reaped, never probe or
    # signal the recycled numeric PGID again.  The caller separately requires
    # both capture pipes to reach EOF; the reviewed launcher is a
    # single-process boundary, so a descendant retaining either pipe remains
    # a fail-closed cleanup error.
    if process.poll() is not None:
        return True
    process_group = process.pid
    if not _group_alive(process_group, process):
        return True
    phases = ((signal.SIGTERM, _GROUP_GRACE_SECONDS), (signal.SIGKILL, _GROUP_KILL_SECONDS))
    for signal_value, seconds in phases:
        try:
            os.killpg(process_group, signal_value)
        except ProcessLookupError:
            return True
        except PermissionError as exc:
            # Darwin may surface EPERM instead of ESRCH if the session leader
            # exits between the liveness probe and this signal. Reap/check the
            # immutable direct child before deciding whether this is failure;
            # never retry a numeric PGID after that child is gone.
            if process.poll() is not None:
                return True
            raise StrictVMLaunchError("launcher process group cannot be terminated") from exc
        except OSError as exc:
            raise StrictVMLaunchError("launcher process group cannot be terminated") from exc
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return True
            if not _group_alive(process_group, process):
                return True
            time.sleep(0.02)
    return not _group_alive(process_group, process)


def _close_launcher_pipes(
    process: subprocess.Popen[bytes], readers: list[threading.Thread]
) -> None:
    for reader in readers:
        reader.join(timeout=_GROUP_KILL_SECONDS)
    if any(reader.is_alive() for reader in readers):
        raise StrictVMLaunchError("launcher output pipe cleanup was not proven")
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()


def _drain_launcher(
    launcher_path: str, manifest_path: Path, *, timeout_seconds: int
) -> tuple[int, bytes, bytes]:
    """Execute the sole permitted launcher argv with bounded pipe collection."""

    argv = [launcher_path, "--run", str(manifest_path)]

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        raise StrictVMLaunchError("strict VM launcher could not be started") from exc
    assert process.stdout is not None and process.stderr is not None
    stdout = _BoundedPipe(process.stdout.fileno(), _MAX_RECEIPT_BYTES)
    stderr = _BoundedPipe(process.stderr.fileno(), _MAX_STDERR_BYTES)
    readers = [threading.Thread(target=item.drain, daemon=True) for item in (stdout, stderr)]
    for reader in readers:
        reader.start()
    try:
        deadline = time.monotonic() + timeout_seconds
        failed: StrictVMLaunchError | None = None
        while process.poll() is None:
            if stdout.overflowed or stderr.overflowed:
                failed = StrictVMOutputOverflow("strict VM launcher output exceeded its hard cap")
                break
            if time.monotonic() >= deadline:
                failed = StrictVMLaunchError("strict VM launcher exceeded its outer deadline")
                break
            time.sleep(0.01)
        if failed is not None and not _stop_group(process):
            raise StrictVMLaunchError("launcher timeout/output cleanup was not proven") from failed
        try:
            returncode = process.wait(timeout=_GROUP_KILL_SECONDS)
        except subprocess.TimeoutExpired as exc:
            _stop_group(process)
            raise StrictVMLaunchError("launcher process leader could not be reaped") from exc
        _close_launcher_pipes(process, readers)
        if stdout.error or stderr.error:
            raise StrictVMLaunchError("launcher output pipe cleanup was not proven")
        # ``wait`` has reaped the session leader, so its PID/PGID can now be
        # reused.  Never probe or signal that numeric group after this point:
        # doing so could target an unrelated same-UID process.  The immutable
        # launcher is a single-process boundary; a descendant retaining either
        # capture pipe prevents the bounded readers from joining above and is
        # therefore cleanup failure, not a target for an identity-unsafe kill.
        if failed is not None:
            raise failed
        if stdout.overflowed or stderr.overflowed:
            raise StrictVMOutputOverflow("strict VM launcher output exceeded its hard cap")
        return returncode, bytes(stdout.data), bytes(stderr.data)
    except BaseException as primary_error:
        cleanup_error: BaseException | None = None
        if process.poll() is None:
            try:
                if not _stop_group(process):
                    cleanup_error = StrictVMLaunchError("launcher process cleanup was not proven")
                else:
                    process.wait(timeout=_GROUP_KILL_SECONDS)
            except BaseException as exc:  # pragma: no cover - hostile OS failure
                cleanup_error = exc
        try:
            _close_launcher_pipes(process, readers)
        except BaseException as exc:
            cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise StrictVMLaunchError(
                "launcher process/pipe cleanup was not proven"
            ) from cleanup_error
        raise primary_error


def _parse_and_verify_receipt(
    raw: bytes,
    *,
    config: StrictVMConfig,
    readiness: StrictVMReadiness,
    manifest_sha256: str,
    request_sha256: str,
    request_bytes: int,
    run_id: str,
    launched_at: datetime,
    received_at: datetime,
) -> VerifiedLauncherReceipt:
    if not 0 < len(raw) <= _MAX_RECEIPT_BYTES:
        raise StrictVMReceiptError("launcher receipt is empty or oversized")
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise StrictVMReceiptError("launcher receipt framing is not exact")
    payload = raw[:-1]
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise StrictVMReceiptError("launcher receipt is not strict JSON") from exc
    _walk_json(value)
    receipt = _require_exact_keys(
        value,
        {
            "schema_version",
            "launcher_version",
            "manifest_sha256",
            "run_id",
            "mode",
            "status",
            "started_at",
            "finished_at",
            "config_validated",
            "stop_reason",
            "limits",
            "artifacts",
            "devices",
            "scratch_retained",
            "error_code",
        },
        "top-level",
    )
    _require_int(receipt["schema_version"], 2, "schema_version")
    _require_string(receipt["launcher_version"], _EXPECTED_LAUNCHER_VERSION, "launcher_version")
    canonical = _canonical_json(receipt)
    if canonical + b"\n" != raw:
        raise StrictVMReceiptError("launcher receipt is not canonical JSON")
    _require_string(receipt["manifest_sha256"], manifest_sha256, "manifest_sha256")
    _require_string(receipt["run_id"], run_id, "run_id")
    _require_string(receipt["mode"], "run", "mode")
    _require_string(receipt["status"], "guest_stopped", "status")
    _require_string(receipt["stop_reason"], "guest_shutdown", "stop_reason")
    if receipt["config_validated"] is not True or receipt["scratch_retained"] is not True:
        raise StrictVMReceiptError(
            "launcher receipt does not prove retained validated guest shutdown"
        )
    if receipt["error_code"] is not None:
        raise StrictVMReceiptError("launcher receipt reports an error")
    if (
        launched_at.tzinfo is None
        or received_at.tzinfo is None
        or launched_at.utcoffset() is None
        or received_at.utcoffset() is None
    ):
        raise StrictVMReceiptError("controller receipt observation timestamps are invalid")
    started_at = _parse_launcher_timestamp(receipt["started_at"], "started_at")
    finished_at = _parse_launcher_timestamp(receipt["finished_at"], "finished_at")
    launched_at = launched_at.astimezone(UTC)
    received_at = received_at.astimezone(UTC)
    if (
        started_at > finished_at
        or started_at < launched_at - _RECEIPT_CLOCK_SKEW
        or finished_at > received_at + _RECEIPT_CLOCK_SKEW
        or finished_at - started_at > timedelta(seconds=config.wall_time_seconds + 15)
    ):
        raise StrictVMReceiptError("launcher receipt timestamps do not fit the observed epoch")
    limits = _require_exact_keys(
        receipt["limits"],
        {"cpu_count", "memory_bytes", "wall_time_seconds", "scratch_bytes"},
        "limits",
    )
    _require_int(limits["cpu_count"], config.cpu_count, "limits.cpu_count")
    _require_int(limits["memory_bytes"], config.memory_bytes, "limits.memory_bytes")
    _require_int(limits["wall_time_seconds"], config.wall_time_seconds, "limits.wall_time_seconds")
    _require_int(limits["scratch_bytes"], config.scratch_bytes, "limits.scratch_bytes")
    artifacts = _require_exact_keys(
        receipt["artifacts"],
        {"kernel_sha256", "initrd_sha256", "root_disk_sha256", "request_disk_sha256"},
        "artifacts",
    )
    for key, expected in (
        ("kernel_sha256", config.kernel_sha256),
        ("initrd_sha256", config.initrd_sha256),
        ("root_disk_sha256", config.root_disk_sha256),
        ("request_disk_sha256", request_sha256),
    ):
        _require_string(artifacts[key], expected, f"artifacts.{key}")
    devices = _require_exact_keys(
        receipt["devices"],
        {
            "platform",
            "boot_loader",
            "network_devices",
            "socket_devices",
            "directory_shares",
            "serial_ports",
            "console_devices",
            "graphics_devices",
            "audio_devices",
            "usb_controllers",
            "keyboards",
            "pointing_devices",
            "entropy_devices",
            "memory_balloon_devices",
            "storage_devices",
        },
        "devices",
    )
    _require_string(devices["platform"], "generic", "devices.platform")
    _require_string(devices["boot_loader"], "linux", "devices.boot_loader")
    for key in (
        "network_devices",
        "socket_devices",
        "directory_shares",
        "serial_ports",
        "console_devices",
        "graphics_devices",
        "audio_devices",
        "usb_controllers",
        "keyboards",
        "pointing_devices",
        "entropy_devices",
        "memory_balloon_devices",
    ):
        _require_int(devices[key], 0, f"devices.{key}")
    storage = devices["storage_devices"]
    if not isinstance(storage, list) or len(storage) != 3:
        raise StrictVMReceiptError("launcher receipt storage device list is invalid")
    expected_storage = (
        ("root", True, readiness.root_disk_bytes),
        ("scratch", False, config.scratch_bytes),
        ("request", True, request_bytes),
    )
    # The request size is not a configured scalar. It is bound by its digest
    # and the launcher, so verify roles/read-only flags and the two fixed sizes.
    for index, (role, read_only, expected_size) in enumerate(expected_storage):
        item = _require_exact_keys(
            storage[index], {"role", "kind", "read_only", "size_bytes"}, "storage"
        )
        _require_string(item["role"], role, "storage.role")
        _require_string(item["kind"], "virtio-block", "storage.kind")
        if (
            item["read_only"] is not read_only
            or type(item["size_bytes"]) is not int
            or item["size_bytes"] <= 0
        ):
            raise StrictVMReceiptError("launcher receipt storage binding is invalid")
        if expected_size is not None:
            _require_int(item["size_bytes"], expected_size, "storage.size_bytes")
    return VerifiedLauncherReceipt(canonical, manifest_sha256, run_id, None)


class StrictVMOneEpochController:
    """Build and run one opaque strict-VM epoch; it does not enable production."""

    def __init__(self, config: StrictVMConfig, lease_root: Path) -> None:
        self.config = config
        self.lease_root = Path(lease_root)

    def run_epoch(
        self,
        *,
        run_id: str,
        round: int,
        stage: str,
        source_capsule: Path,
        task: Mapping[str, Any],
        authorization: object,
        cumulative_patch: bytes | str | Path | None = None,
        prior_observations: Mapping[str, Any] | None = None,
    ) -> StrictVMEpochResult:
        if not STRICT_VM_EXECUTION_ENABLED:
            raise StrictVMRunnerError("strict VM epoch execution is hard-disabled in this release")
        if _RUN_ID.fullmatch(run_id) is None:
            raise StrictVMRunnerError(
                "strict VM run_id must be exactly 32 lowercase hex characters"
            )
        if round < 0 or round >= self.config.max_rounds:
            raise StrictVMRunnerError("strict VM round is outside the configured cap")
        # Readiness is intentionally deferred: merely constructing a controller
        # must not open a lease, create files, or touch a VM resource.
        readiness = verify_static_readiness(self.config)
        lease = StrictVMRunLease(self.lease_root, run_id).acquire()
        launch_started = False
        guest_stop_proven = False
        try:
            request_path = lease.path / "request.raw"
            scratch_path = lease.path / "scratch.raw"
            manifest_path = lease.path / "manifest.json"
            parsed_request = build_authorized_request_bundle(
                request_path,
                run_id=run_id,
                round=round,
                stage=stage,
                manifest={
                    "schema_version": 2,
                    "run_id": run_id,
                    "round": round,
                    "stage": stage,
                    "guest_policy_sha256": readiness.guest_policy_sha256,
                },
                source_capsule=Path(source_capsule),
                task=task,
                authorization=authorization,
                cumulative_patch=cumulative_patch,
                prior_observations=prior_observations,
                fixture_capability=fixture_vm_bundle_capability(),
            )
            if request_path.stat().st_size > self.config.max_request_bytes:
                raise StrictVMRunnerError("sealed request exceeds the configured strict VM cap")
            lease.register_artifact(
                request_path,
                role="request",
                mode=0o400,
                maximum_bytes=self.config.max_request_bytes,
                sha256=parsed_request.sha256,
            )
            manifest = {
                "schema_version": 2,
                "run_id": run_id,
                "guest_policy_sha256": readiness.guest_policy_sha256,
                "boot_artifact_directory": self.config.boot_artifact_directory,
                "run_directory": str(lease.path),
                "kernel": {"path": self.config.kernel_path, "sha256": self.config.kernel_sha256},
                "initrd": {"path": self.config.initrd_path, "sha256": self.config.initrd_sha256},
                "root_disk": {
                    "path": self.config.root_disk_path,
                    "sha256": self.config.root_disk_sha256,
                },
                "request_disk": {"path": str(request_path), "sha256": parsed_request.sha256},
                "scratch_disk": {
                    "path": str(scratch_path),
                    "size_bytes": self.config.scratch_bytes,
                },
                "cpu_count": self.config.cpu_count,
                "memory_bytes": self.config.memory_bytes,
                "wall_time_seconds": self.config.wall_time_seconds,
            }
            raw_manifest = _canonical_json(manifest)
            descriptor = os.open(
                manifest_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                view = memoryview(raw_manifest)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise StrictVMRunnerError(
                            "sealed strict VM manifest write made no progress"
                        )
                    view = view[written:]
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
            lease.register_artifact(
                manifest_path,
                role="manifest",
                mode=0o400,
                maximum_bytes=_MAX_RECEIPT_BYTES,
                sha256=manifest_sha256,
            )
            launch_started = True
            launched_at = datetime.now(UTC)
            returncode, stdout, _stderr = _drain_launcher(
                self.config.launcher_path,
                manifest_path,
                timeout_seconds=self.config.wall_time_seconds + _OUTER_SETUP_GRACE_SECONDS,
            )
            received_at = datetime.now(UTC)
            if returncode != 0:
                raise StrictVMLaunchError("strict VM launcher returned a nonzero exit status")
            if _stderr:
                raise StrictVMLaunchError("successful strict VM launcher emitted diagnostics")
            receipt = _parse_and_verify_receipt(
                stdout,
                config=self.config,
                readiness=readiness,
                manifest_sha256=manifest_sha256,
                request_sha256=parsed_request.sha256,
                request_bytes=request_path.stat().st_size,
                run_id=run_id,
                launched_at=launched_at,
                received_at=received_at,
            )
            guest_stop_proven = True
            lease.register_artifact(
                scratch_path,
                role="scratch",
                mode=0o600,
                maximum_bytes=self.config.scratch_bytes,
            )
            if scratch_path.stat().st_size != self.config.scratch_bytes:
                raise StrictVMRunnerError("strict VM scratch size does not match the manifest")
            result = extract_tail_result(
                scratch_path,
                scratch_size=self.config.scratch_bytes,
                tail_region_bytes=self.config.result_region_bytes,
                run_id=run_id,
                round=round,
                stage=stage,
            )
            verified_result = validate_guest_result(
                result,
                parsed_request,
                guest_policy_sha256=readiness.guest_policy_sha256,
                max_observation_bytes=self.config.max_observation_bytes,
                fixture_capability=fixture_vm_bundle_capability(),
            )
            patch = read_raw_section(
                scratch_path,
                result,
                "canonical_patch",
                scratch_size=self.config.scratch_bytes,
                tail_region_bytes=self.config.result_region_bytes,
            )
        except BaseException:
            # Before Popen, cleanup is exact and safe. After Popen, do not
            # erase an epoch whose guest shutdown was not proven by the bound
            # launcher receipt; retain it for explicit reconciliation.
            if not launch_started or guest_stop_proven:
                lease.cleanup()
            else:
                lease.close()
            raise
        cleanup = lease.cleanup()
        return StrictVMEpochResult(
            run_id=run_id,
            request_sha256=parsed_request.sha256,
            manifest_sha256=manifest_sha256,
            receipt=receipt,
            result=result,
            verified_result=verified_result,
            canonical_patch=patch,
            cleanup=cleanup,
        )
