"""Independent, fail-closed post-stop verifier for a future strict-VM cycle.

This module is deliberately separate from the VM launcher, broker, mediator,
and publisher.  It accepts only three bounded, descriptor-read artifacts after
the launcher says the VM has stopped: a canonical result frame, a canonical
cleanup frame, and a canonical patch.  It then reconstructs a controller-owned
verification checkout, applies and inspects the patch, and runs an exact
controller registry of offline checks.

It is *not* production authority.  ``STRICT_VM_POSTSTOP_ENABLED`` remains
false and no value returned here is accepted by ``publisher.py``.  The module
exists so that the eventual activation has a small, testable boundary instead
of trusting guest-written paths, result claims, or model-written check output.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .strict_vm_cycle import (
    CyclePlan,
    HostCheckEvidence,
    IndependentHostReceipt,
    StrictVMCycleError,
    patch_sha256,
)

# A release gate, not a tunable setting.  Calling code must not enable this
# module by configuration or mistake a locally useful receipt for publisher
# authority.  A reviewed broker, guest, provider boundary, and live evidence
# are still required before any production integration.
STRICT_VM_POSTSTOP_ENABLED = False

MAX_ARTIFACT_BYTES = 512 * 1024
MAX_FRAME_BYTES = 16 * 1024
MAX_CLEANUP_BYTES = 16 * 1024
MAX_JSON_DEPTH = 16
MAX_CHECK_OUTPUT_BYTES = 32 * 1024
MAX_CHECKS = 32
MAX_DIFF_BYTES = 512 * 1024
MAX_CHANGED_PATHS = 128
MAX_CHANGED_LINES = 8_000
PROCESS_CLEANUP_GRACE_SECONDS = 1.0
ORPHANED_PIPE_GRACE_SECONDS = 0.25

_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_CHECK_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_BASE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_ARTIFACT_NAME = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_PATH_SEPARATOR = chr(0)
_SECRET_PATTERNS = (
    re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)(?:github_pat|ghp|gho|ghu|ghs)_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?i)AKIA[0-9A-Z]{16}"),
    re.compile(rb"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{20,}"),
)
_DEFAULT_FORBIDDEN_PREFIXES = (
    ".git/",
    ".github/actions/",
    ".github/workflows/",
    "CODEOWNERS",
    "SECURITY.md",
    "Dockerfile",
    "docker-compose",
)
_SAFE_MODES = {"100644"}


class PostStopVerificationError(StrictVMCycleError):
    """A post-stop artifact or independently reconstructed result is unsafe."""


class StrictVMPostStopDisabled(PostStopVerificationError):
    """The source-level production post-stop gate rejected before all I/O."""


class OfflineExecutionUnavailable(PostStopVerificationError):
    """The host cannot prove its fixed checks run without network access."""


class FixturePostStopCapability:
    """Explicitly non-production capability for deterministic verifier tests.

    This value is intentionally obtainable by fixture code.  It is a naming
    and type barrier against accidentally calling the fixture engine from a
    production-looking entry point, not a secret and never publisher authority.
    """

    __slots__ = ("_identity",)

    def __init__(self, identity: object) -> None:
        if identity is not _FIXTURE_CAPABILITY_IDENTITY:
            raise PostStopVerificationError("fixture post-stop capability is not constructible")
        self._identity = identity


_FIXTURE_CAPABILITY_IDENTITY = object()
_FIXTURE_CAPABILITY = FixturePostStopCapability(_FIXTURE_CAPABILITY_IDENTITY)


def fixture_post_stop_capability() -> FixturePostStopCapability:
    """Return the singleton capability for clearly labeled fixture-only calls."""

    return _FIXTURE_CAPABILITY


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PostStopVerificationError(f"{label} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PostStopVerificationError("artifact JSON cannot be canonicalized") from exc


def _json_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PostStopVerificationError("artifact JSON contains duplicate keys")
        result[key] = value
    return result


def _reject_json_non_integer(_value: str) -> object:
    raise PostStopVerificationError("artifact JSON permits only finite integer numbers")


def _bounded_json(raw: bytes, *, label: str) -> dict[str, object]:
    if not raw or len(raw) > MAX_FRAME_BYTES:
        raise PostStopVerificationError(f"{label} artifact exceeds its byte cap")
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_object_pairs,
            parse_float=_reject_json_non_integer,
            parse_constant=_reject_json_non_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PostStopVerificationError(f"{label} artifact is not valid JSON") from exc

    def walk(value: object, depth: int) -> None:
        if depth > MAX_JSON_DEPTH:
            raise PostStopVerificationError(f"{label} artifact exceeds JSON depth cap")
        if isinstance(value, dict):
            if any(type(key) is not str for key in value):
                raise PostStopVerificationError(f"{label} artifact has a non-string key")
            for item in value.values():
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)
        elif value is not None and type(value) not in {str, int, bool}:
            raise PostStopVerificationError(f"{label} artifact has an unsupported JSON value")

    walk(parsed, 0)
    if type(parsed) is not dict or _canonical_json(parsed) != raw:
        raise PostStopVerificationError(f"{label} artifact is not canonically framed")
    return parsed


def _require_exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise PostStopVerificationError(f"{label} artifact keys are not exact")


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode)) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _trusted_directory_mode(info: os.stat_result, *, label: str, exact_owner: bool) -> None:
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PostStopVerificationError(f"{label} is not a real directory")
    permitted_owners = {os.geteuid()} if exact_owner else {0, os.geteuid()}
    if info.st_uid not in permitted_owners:
        raise PostStopVerificationError(f"{label} owner is not trusted")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PostStopVerificationError(f"{label} is writable by another principal")


@dataclass
class _TrustedDirectory:
    """An opened directory plus its exact current pathname and parent identity."""

    path: Path
    label: str
    fd: int
    parent_fd: int
    identity: os.stat_result
    parent_identity: os.stat_result

    def __enter__(self) -> _TrustedDirectory:
        return self

    def __exit__(self, *_args: object) -> None:
        os.close(self.fd)
        os.close(self.parent_fd)

    def revalidate(self) -> None:
        try:
            descriptor = os.fstat(self.fd)
            parent_descriptor = os.fstat(self.parent_fd)
            entry = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            pathname = os.stat(self.path, follow_symlinks=False)
            parent_pathname = os.stat(self.path.parent, follow_symlinks=False)
        except OSError as exc:
            raise PostStopVerificationError(f"{self.label} identity cannot be revalidated") from exc
        if not all(
            (
                _same_identity(descriptor, self.identity),
                _same_identity(entry, self.identity),
                _same_identity(pathname, self.identity),
                _same_identity(parent_descriptor, self.parent_identity),
                _same_identity(parent_pathname, self.parent_identity),
            )
        ):
            raise PostStopVerificationError(f"{self.label} identity changed during verification")
        _trusted_directory_mode(descriptor, label=self.label, exact_owner=True)
        _trusted_directory_mode(parent_descriptor, label=f"{self.label} parent", exact_owner=False)


def _open_trusted_directory(path: Path, *, label: str) -> _TrustedDirectory:
    if not isinstance(path, Path) or not path.is_absolute() or path.name in {"", ".", ".."}:
        raise PostStopVerificationError(f"{label} path is not an exact absolute child")
    parent_fd: int | None = None
    child_fd: int | None = None
    try:
        parent_path_info = os.lstat(path.parent)
        _trusted_directory_mode(parent_path_info, label=f"{label} parent", exact_owner=False)
        parent_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        parent_info = os.fstat(parent_fd)
        if not _same_identity(parent_path_info, parent_info):
            raise PostStopVerificationError(f"{label} parent changed while opening")
        child_fd = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        child_info = os.fstat(child_fd)
        _trusted_directory_mode(child_info, label=label, exact_owner=True)
        entry_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_identity(child_info, entry_info):
            raise PostStopVerificationError(f"{label} changed while opening")
        opened = _TrustedDirectory(
            path=path,
            label=label,
            fd=child_fd,
            parent_fd=parent_fd,
            identity=child_info,
            parent_identity=parent_info,
        )
        opened.revalidate()
        child_fd = None
        parent_fd = None
        return opened
    except OSError as exc:
        raise PostStopVerificationError(
            f"{label} cannot be opened without following links"
        ) from exc
    finally:
        if child_fd is not None:
            os.close(child_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _read_nofollow_artifact(
    directory: _TrustedDirectory, name: str, *, maximum_bytes: int
) -> bytes:
    directory.revalidate()
    file_fd: int | None = None
    try:
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory.fd,
            )
        except OSError as exc:
            raise PostStopVerificationError(
                "artifact cannot be opened without following links"
            ) from exc
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PostStopVerificationError("artifact is not an unaliased regular file")
        if before.st_uid != os.geteuid():
            raise PostStopVerificationError("artifact owner is not the controller")
        if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PostStopVerificationError("artifact is writable by another principal")
        if before.st_size < 1 or before.st_size > maximum_bytes:
            raise PostStopVerificationError("artifact exceeds its byte cap")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(file_fd, min(16 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise PostStopVerificationError("artifact changed while being read")
        if len(raw) != before.st_size or len(raw) > maximum_bytes:
            raise PostStopVerificationError("artifact read is incomplete or oversized")
        directory.revalidate()
        return raw
    finally:
        if file_fd is not None:
            os.close(file_fd)


def read_nofollow_artifact(root: Path, name: str, *, maximum_bytes: int) -> bytes:
    """Read one regular artifact through stable directory/file descriptors.

    Pathnames are never resolved after the root descriptor is opened.  A
    replacement after open affects neither the descriptor nor the bytes used
    for verification; symlinks, non-regular files, hard-link aliases, and
    oversized streams are rejected.
    """

    if not isinstance(name, str) or _ARTIFACT_NAME.fullmatch(name) is None:
        raise PostStopVerificationError("artifact name is invalid")
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_ARTIFACT_BYTES:
        raise PostStopVerificationError("artifact cap is invalid")
    with _open_trusted_directory(root, label="artifact root") as directory:
        return _read_nofollow_artifact(directory, name, maximum_bytes=maximum_bytes)


@dataclass(frozen=True)
class OfflineCheckSpec:
    """One controller-curated fixed argv check, never model-provided text."""

    check_id: str
    argv: tuple[str, ...]
    timeout_seconds: int

    def __post_init__(self) -> None:
        _require_hex(self.check_id, _CHECK_ID, "offline check ID")
        if (
            type(self.argv) is not tuple
            or not self.argv
            or len(self.argv) > 32
            or any(type(part) is not str or not part or "\x00" in part for part in self.argv)
        ):
            raise PostStopVerificationError("offline check argv is invalid")
        if (
            self.argv[0].startswith("-")
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 900
        ):
            raise PostStopVerificationError("offline check execution bounds are invalid")


@dataclass(frozen=True)
class BoundedCommandResult:
    exit_code: int | None
    timed_out: bool
    truncated: bool
    output_sha256: str

    def __post_init__(self) -> None:
        if self.timed_out and self.exit_code is not None:
            raise PostStopVerificationError("timed-out check returned an exit code")
        if not self.timed_out and (
            type(self.exit_code) is not int or not -255 <= self.exit_code <= 255
        ):
            raise PostStopVerificationError("check exit code is invalid")
        if type(self.truncated) is not bool:
            raise PostStopVerificationError("check truncation flag is invalid")
        _require_hex(self.output_sha256, _HEX64, "check output digest")


class OfflineCheckExecutor(Protocol):
    """A reviewed executor that proves its check process has no network route."""

    def run(self, spec: OfflineCheckSpec, *, cwd: Path) -> BoundedCommandResult: ...


class UnavailableOfflineExecutor:
    """Default executor: no unreviewed host command becomes an 'offline' check."""

    def run(self, spec: OfflineCheckSpec, *, cwd: Path) -> BoundedCommandResult:
        del spec, cwd
        raise OfflineExecutionUnavailable(
            "a platform-reviewed no-network post-stop check executor is not integrated"
        )


def _run_bounded(argv: Sequence[str], *, cwd: Path, timeout_seconds: int) -> BoundedCommandResult:
    """Run fixture argv with bounded pipes and session-scoped timeout cleanup.

    This helper provides process/output bounds only. It is not an offline or
    filesystem-isolation boundary and therefore is never the default executor.
    """

    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "PYTHONNOUSERSITE": "1",
    }
    try:
        process = subprocess.Popen(
            tuple(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise PostStopVerificationError("offline check could not start") from exc
    exit_code, timed_out, truncated, stdout, stderr = _collect_bounded(
        process, maximum_bytes=MAX_CHECK_OUTPUT_BYTES, timeout_seconds=timeout_seconds
    )
    return BoundedCommandResult(
        exit_code=exit_code,
        timed_out=timed_out,
        truncated=truncated,
        output_sha256=_sha256(stdout + stderr),
    )


@dataclass(frozen=True)
class PostStopPlan:
    """Controller-fixed identities and policy for one independently checked patch."""

    cycle: CyclePlan
    epoch: int
    request_sha256: str
    mediator_receipt_sha256: str
    source_repository: Path
    checks: tuple[OfflineCheckSpec, ...]
    forbidden_path_prefixes: tuple[str, ...] = _DEFAULT_FORBIDDEN_PREFIXES

    def __post_init__(self) -> None:
        if type(self.cycle) is not CyclePlan:
            raise PostStopVerificationError("post-stop cycle plan is invalid")
        if type(self.epoch) is not int or self.epoch != 0:
            raise PostStopVerificationError("post-stop epoch is not the fixed first epoch")
        _require_hex(self.request_sha256, _HEX64, "post-stop request digest")
        _require_hex(self.mediator_receipt_sha256, _HEX64, "post-stop mediator receipt digest")
        if not isinstance(self.source_repository, Path) or not self.source_repository.is_absolute():
            raise PostStopVerificationError("source repository path must be absolute")
        if (
            type(self.checks) is not tuple
            or len(self.checks) > MAX_CHECKS
            or any(type(item) is not OfflineCheckSpec for item in self.checks)
            or tuple(item.check_id for item in self.checks) != self.cycle.required_check_ids
        ):
            raise PostStopVerificationError("check registry does not exactly match plan")
        if (
            type(self.forbidden_path_prefixes) is not tuple
            or not self.forbidden_path_prefixes
            or any(
                type(prefix) is not str
                or not prefix
                or prefix.startswith("/")
                or ".." in Path(prefix).parts
                or "\x00" in prefix
                for prefix in self.forbidden_path_prefixes
            )
        ):
            raise PostStopVerificationError("forbidden path policy is invalid")


@dataclass(frozen=True)
class PostStopVerificationReceipt:
    """Non-authoritative result of independent post-stop verification."""

    run_id: str
    epoch: int
    request_sha256: str
    mediator_receipt_sha256: str
    patch_sha256: str
    inspected_diff_sha256: str
    cleanup_sha256: str
    base_sha_before: str
    base_sha_after: str
    checks: tuple[HostCheckEvidence, ...]
    verification_clone_removed: bool

    def host_receipt(self, plan: PostStopPlan) -> IndependentHostReceipt:
        """Adapt facts only for offline fixture tests, never publisher authority."""

        if not self.verification_clone_removed:
            raise PostStopVerificationError("verification clone cleanup is unproven")
        return IndependentHostReceipt(
            run_id=self.run_id,
            base_sha_observed=self.base_sha_before,
            applied_patch_sha256=self.patch_sha256,
            inspected_patch_sha256=self.patch_sha256,
            inspected_diff_sha256=self.inspected_diff_sha256,
            policy_sha256=plan.cycle.policy_sha256,
            policy_allowed=True,
            review_unresolved=False,
            checks=self.checks,
        )


def _validate_result_frame(
    frame: dict[str, object], plan: PostStopPlan, cleanup_raw: bytes
) -> None:
    _require_exact_keys(
        frame,
        {
            "cleanup_sha256",
            "epoch",
            "kind",
            "launcher_stop_proven",
            "mediator_receipt_sha256",
            "patch_sha256",
            "request_sha256",
            "result_extracted_after_stop",
            "run_id",
        },
        "post-stop result",
    )
    if frame["kind"] != "leftovers.strict-vm.poststop-result.v1":
        raise PostStopVerificationError("post-stop result artifact kind is invalid")
    if type(frame["run_id"]) is not str or type(frame["epoch"]) is not int:
        raise PostStopVerificationError("post-stop result identity types are invalid")
    if frame["run_id"] != plan.cycle.run_id or frame["epoch"] != plan.epoch:
        raise PostStopVerificationError("post-stop result run or epoch identity does not match")
    for name in (
        "request_sha256",
        "mediator_receipt_sha256",
        "patch_sha256",
        "cleanup_sha256",
    ):
        _require_hex(frame[name], _HEX64, f"post-stop result {name}")
    if frame["request_sha256"] != plan.request_sha256:
        raise PostStopVerificationError("post-stop request identity does not match")
    if frame["mediator_receipt_sha256"] != plan.mediator_receipt_sha256:
        raise PostStopVerificationError("post-stop mediator identity does not match")
    for name in ("launcher_stop_proven", "result_extracted_after_stop"):
        if frame[name] is not True:
            raise PostStopVerificationError("post-stop result lacks required stop proof")
    _require_hex(frame["patch_sha256"], _HEX64, "post-stop patch digest")
    if frame["cleanup_sha256"] != _sha256(cleanup_raw):
        raise PostStopVerificationError("post-stop cleanup artifact is not bound to result")


def _validate_cleanup_frame(frame: dict[str, object], plan: PostStopPlan) -> None:
    _require_exact_keys(
        frame,
        {"epoch", "kind", "launcher_stop_proven", "resources_removed", "run_id", "vm_stopped"},
        "cleanup",
    )
    if frame["kind"] != "leftovers.strict-vm.cleanup.v1":
        raise PostStopVerificationError("cleanup artifact kind is invalid")
    if type(frame["run_id"]) is not str or type(frame["epoch"]) is not int:
        raise PostStopVerificationError("cleanup artifact identity types are invalid")
    if frame["run_id"] != plan.cycle.run_id or frame["epoch"] != plan.epoch:
        raise PostStopVerificationError("cleanup artifact run or epoch identity does not match")
    if any(
        frame[name] is not True
        for name in ("launcher_stop_proven", "resources_removed", "vm_stopped")
    ):
        raise PostStopVerificationError("cleanup proof is incomplete")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        raise PostStopVerificationError("bounded subprocess group could not be stopped") from exc


def _collect_bounded(
    process: subprocess.Popen[bytes], *, maximum_bytes: int, timeout_seconds: int
) -> tuple[int | None, bool, bool, bytes, bytes]:
    """Collect two pipe streams without allowing an unbounded Python buffer."""

    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    timed_out = False
    truncated = False
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, stdout)
    selector.register(process.stderr, selectors.EVENT_READ, stderr)
    deadline = time.monotonic() + timeout_seconds
    orphaned_pipe_deadline: float | None = None
    aborted = False
    try:
        while selector.get_map() and not aborted:
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                timed_out = True
                aborted = True
                break
            if process.poll() is not None:
                if orphaned_pipe_deadline is None:
                    orphaned_pipe_deadline = now + ORPHANED_PIPE_GRACE_SECONDS
                if now >= orphaned_pipe_deadline:
                    timed_out = True
                    aborted = True
                    break
                remaining = min(remaining, orphaned_pipe_deadline - now)
            # Polling keeps a leader that exited without closing descendant-held
            # pipes from consuming a full check timeout (which may be 900s).
            for key, _event in selector.select(min(remaining, 0.05)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = key.data
                room = maximum_bytes - len(stdout) - len(stderr)
                if room <= 0:
                    truncated = True
                    aborted = True
                    break
                target.extend(chunk[:room])
                if len(chunk) > room:
                    truncated = True
                    aborted = True
                    break
        if aborted:
            # A descendant may have created a new session and kept the capture
            # descriptors open. Kill the owned group, then close our read ends
            # immediately rather than waiting for EOF from an escaped holder.
            _kill_process_group(process)
            for key in tuple(selector.get_map().values()):
                with suppress(KeyError):
                    selector.unregister(key.fileobj)
                key.fileobj.close()
        process.wait(timeout=PROCESS_CLEANUP_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _kill_process_group(process)
        try:
            process.wait(timeout=PROCESS_CLEANUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired as cleanup_exc:
            raise PostStopVerificationError(
                "bounded subprocess exceeded cleanup/reap grace"
            ) from cleanup_exc
        raise PostStopVerificationError("bounded subprocess cleanup was not proven") from exc
    finally:
        selector.close()
        if not process.stdout.closed:
            process.stdout.close()
        if not process.stderr.closed:
            process.stderr.close()
    return (
        None if timed_out else process.returncode,
        timed_out,
        truncated,
        bytes(stdout),
        bytes(stderr),
    )


def _git(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    input_data: bytes | None = None,
) -> bytes:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": tempfile.gettempdir(),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/usr/bin/false",
        "SSH_ASKPASS": "/usr/bin/false",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
    }
    command = (
        "/usr/bin/git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=always",
        *argv,
    )

    def invoke(input_file: object) -> tuple[int | None, bool, bool, bytes]:
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdin=input_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise PostStopVerificationError("hardened Git operation could not complete") from exc
        exit_code, timed_out, truncated, stdout, _stderr = _collect_bounded(
            process, maximum_bytes=MAX_DIFF_BYTES, timeout_seconds=60
        )
        return exit_code, timed_out, truncated, stdout

    if input_data is None:
        exit_code, timed_out, truncated, stdout = invoke(subprocess.DEVNULL)
    else:
        with tempfile.TemporaryFile() as input_file:
            input_file.write(input_data)
            input_file.seek(0)
            exit_code, timed_out, truncated, stdout = invoke(input_file)
    if timed_out or truncated:
        raise PostStopVerificationError("hardened Git operation exceeded output cap")
    if exit_code != 0:
        raise PostStopVerificationError("hardened Git operation rejected verification input")
    return stdout


def _source_base_sha(plan: PostStopPlan, source: _TrustedDirectory) -> str:
    base_ref = plan.cycle.base_ref
    if _BASE_REF.fullmatch(base_ref) is None or base_ref.startswith("-") or ".." in base_ref:
        raise PostStopVerificationError("base ref is unsafe for direct freshness lookup")
    source.revalidate()
    raw = _git(
        (
            "-C",
            str(source.path),
            "rev-parse",
            "--verify",
            f"refs/heads/{base_ref}^{{commit}}",
        )
    )
    source.revalidate()
    value = raw.decode("ascii", "strict").strip()
    _require_hex(value, re.compile(r"[a-f0-9]{40}\Z"), "fresh base SHA")
    return value


def _patch_declares_unsafe_path(patch: bytes) -> None:
    for line in patch.splitlines():
        if line.startswith((b"diff --git ", b"--- ", b"+++ ")):
            text = line.decode("utf-8", "strict")
            for token in text.split():
                if token in {"a/", "b/", "/dev/null"}:
                    continue
                if token.startswith(("a/", "b/")):
                    token = token[2:]
                if (
                    token.startswith("/")
                    or token == ".."
                    or token.startswith("../")
                    or "/../" in token
                ):
                    raise PostStopVerificationError("patch declares a path escape")


def _raw_diff_paths(raw: bytes, policy: tuple[str, ...]) -> tuple[str, ...]:
    parts = raw.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(parts) - 1:
        header = parts[index]
        index += 1
        if not header:
            continue
        try:
            prefix, status = header.decode("ascii", "strict").rsplit(" ", 1)
            metadata = prefix.split()
            old_mode, new_mode = metadata[0][1:], metadata[1]
        except (UnicodeDecodeError, IndexError, ValueError) as exc:
            raise PostStopVerificationError("Git raw diff framing is invalid") from exc
        if old_mode not in _SAFE_MODES and old_mode != "000000":
            raise PostStopVerificationError("diff contains an unsafe source mode")
        if new_mode not in _SAFE_MODES and new_mode != "000000":
            raise PostStopVerificationError("diff contains an unsafe destination mode")
        count = 2 if status[:1] in {"R", "C"} else 1
        if index + count > len(parts):
            raise PostStopVerificationError("Git raw diff paths are truncated")
        for raw_path in parts[index : index + count]:
            index += 1
            try:
                path = raw_path.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise PostStopVerificationError("diff path is not UTF-8") from exc
            normalized = Path(path)
            if (
                not path
                or path.startswith("/")
                or ".." in normalized.parts
                or normalized.parts[0] == ".git"
                or any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in policy)
            ):
                raise PostStopVerificationError("diff touches a forbidden or escaping path")
            paths.append(path)
    if not paths or len(paths) > MAX_CHANGED_PATHS:
        raise PostStopVerificationError("diff path count is outside policy")
    return tuple(paths)


def _inspect_patch(clone: Path, patch: bytes, plan: PostStopPlan) -> str:
    _patch_declares_unsafe_path(patch)
    if any(pattern.search(patch) for pattern in _SECRET_PATTERNS):
        raise PostStopVerificationError("patch contains a forbidden secret-like value")
    if (
        sum(
            1
            for line in patch.splitlines()
            if line.startswith((b"+", b"-")) and not line.startswith((b"+++", b"---"))
        )
        > MAX_CHANGED_LINES
    ):
        raise PostStopVerificationError("patch exceeds changed-line cap")
    _git(
        ("-C", clone, "apply", "--index", "--recount", "--whitespace=error-all", "-"),
        input_data=patch,
    )
    raw = _git(
        ("-C", clone, "diff", "--cached", "--raw", "-z", "--no-ext-diff"),
    )
    _raw_diff_paths(raw, plan.forbidden_path_prefixes)
    inspected = _git(
        ("-C", clone, "diff", "--cached", "--binary", "--full-index", "--no-ext-diff"),
    )
    if not inspected or len(inspected) > MAX_DIFF_BYTES:
        raise PostStopVerificationError("independent diff exceeds policy")
    if any(pattern.search(inspected) for pattern in _SECRET_PATTERNS):
        raise PostStopVerificationError("independent diff contains a forbidden secret-like value")
    return _sha256(inspected)


def _create_verification_clone_directory(
    root: _TrustedDirectory,
) -> tuple[str, int, os.stat_result]:
    for _attempt in range(16):
        name = f"leftovers-poststop-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=root.fd)
        except FileExistsError:
            continue
        descriptor = -1
        created: os.stat_result | None = None
        try:
            created = os.stat(name, dir_fd=root.fd, follow_symlinks=False)
            _trusted_directory_mode(created, label="verification clone", exact_owner=True)
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=root.fd,
            )
            identity = os.fstat(descriptor)
            _trusted_directory_mode(identity, label="verification clone", exact_owner=True)
            entry = os.stat(name, dir_fd=root.fd, follow_symlinks=False)
            if not _same_identity(created, identity) or not _same_identity(identity, entry):
                raise PostStopVerificationError("verification clone changed while opening")
            return name, descriptor, identity
        except BaseException as primary:
            cleanup_errors: list[BaseException] = []
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    cleanup_errors.append(exc)
            try:
                current = os.stat(name, dir_fd=root.fd, follow_symlinks=False)
                if (
                    created is None
                    or not _same_identity(created, current)
                    or not stat.S_ISDIR(current.st_mode)
                ):
                    raise PostStopVerificationError(
                        "verification clone setup identity changed before rollback"
                    )
                os.rmdir(name, dir_fd=root.fd)
                os.fsync(root.fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
            if cleanup_errors:
                raise PostStopVerificationError(
                    "verification clone setup cleanup is unproven"
                ) from primary
            if isinstance(primary, PostStopVerificationError):
                raise
            raise PostStopVerificationError("verification clone cannot be opened") from primary
    raise PostStopVerificationError("verification clone name allocation was exhausted")


def _revalidate_verification_clone(
    root: _TrustedDirectory, name: str, descriptor: int, identity: os.stat_result
) -> None:
    try:
        current_descriptor = os.fstat(descriptor)
        entry = os.stat(name, dir_fd=root.fd, follow_symlinks=False)
    except OSError as exc:
        raise PostStopVerificationError(
            "verification clone identity cannot be revalidated"
        ) from exc
    if not _same_identity(identity, current_descriptor) or not _same_identity(identity, entry):
        raise PostStopVerificationError("verification clone identity changed during verification")
    _trusted_directory_mode(current_descriptor, label="verification clone", exact_owner=True)


def _remove_verification_clone(
    root: _TrustedDirectory, name: str, descriptor: int, identity: os.stat_result
) -> None:
    _revalidate_verification_clone(root, name, descriptor, identity)
    if not shutil.rmtree.avoids_symlink_attacks:
        raise PostStopVerificationError("descriptor-relative clone cleanup is unsupported")
    try:
        shutil.rmtree(name, dir_fd=root.fd)
    except OSError as exc:
        raise PostStopVerificationError("verification clone cleanup is unproven") from exc
    try:
        os.stat(name, dir_fd=root.fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PostStopVerificationError("verification clone cleanup cannot be rechecked") from exc
    raise PostStopVerificationError("verification clone cleanup is unproven")


class _FixturePostStopVerifier:
    """Fixture engine for bounded artifacts and a disposable verification clone."""

    def __init__(self, plan: PostStopPlan, *, executor: OfflineCheckExecutor | None = None) -> None:
        self._plan = plan
        self._executor = executor if executor is not None else UnavailableOfflineExecutor()
        if not hasattr(self._executor, "run"):
            raise PostStopVerificationError("offline check executor is invalid")

    def verify(
        self,
        *,
        artifact_root: Path,
        verification_root: Path,
        fixture_capability: FixturePostStopCapability,
    ) -> PostStopVerificationReceipt:
        """Verify one stopped epoch; failure leaves no handoff or authority."""

        if fixture_capability is not _FIXTURE_CAPABILITY:
            raise PostStopVerificationError("explicit fixture post-stop capability is required")
        with (
            _open_trusted_directory(artifact_root, label="artifact root") as artifacts,
            _open_trusted_directory(
                self._plan.source_repository, label="source repository"
            ) as source,
            _open_trusted_directory(verification_root, label="verification root") as verification,
        ):
            cleanup_raw = _read_nofollow_artifact(
                artifacts, "cleanup.json", maximum_bytes=MAX_CLEANUP_BYTES
            )
            result_raw = _read_nofollow_artifact(
                artifacts, "result.json", maximum_bytes=MAX_FRAME_BYTES
            )
            patch = _read_nofollow_artifact(
                artifacts, "canonical.patch", maximum_bytes=MAX_ARTIFACT_BYTES
            )
            cleanup = _bounded_json(cleanup_raw, label="cleanup")
            result = _bounded_json(result_raw, label="post-stop result")
            _validate_cleanup_frame(cleanup, self._plan)
            _validate_result_frame(result, self._plan, cleanup_raw)
            actual_patch_sha = patch_sha256(patch)
            if result["patch_sha256"] != actual_patch_sha:
                raise PostStopVerificationError("artifact patch does not match result frame")
            source.revalidate()
            base_before = _source_base_sha(self._plan, source)
            if base_before != self._plan.cycle.base_sha:
                raise PostStopVerificationError("base moved before verification clone")
            verification.revalidate()
            clone_name, clone_fd, clone_identity = _create_verification_clone_directory(
                verification
            )
            receipt: PostStopVerificationReceipt | None = None
            try:
                source_path = self._plan.source_repository
                clone_path = verification_root / clone_name
                source.revalidate()
                verification.revalidate()
                _revalidate_verification_clone(verification, clone_name, clone_fd, clone_identity)
                _git(
                    (
                        "clone",
                        "--no-local",
                        "--no-checkout",
                        "--",
                        source_path,
                        clone_path,
                    )
                )
                source.revalidate()
                verification.revalidate()
                _revalidate_verification_clone(verification, clone_name, clone_fd, clone_identity)
                _git(
                    (
                        "-C",
                        clone_path,
                        "checkout",
                        "--detach",
                        "--force",
                        self._plan.cycle.base_sha,
                    )
                )
                verification.revalidate()
                _revalidate_verification_clone(verification, clone_name, clone_fd, clone_identity)
                if _git(
                    ("-C", clone_path, "status", "--porcelain=v1", "-uall"),
                ):
                    raise PostStopVerificationError(
                        "verification clone is not clean at planned base"
                    )
                _revalidate_verification_clone(verification, clone_name, clone_fd, clone_identity)
                inspected_sha = _inspect_patch(clone_path, patch, self._plan)
                verification.revalidate()
                _revalidate_verification_clone(verification, clone_name, clone_fd, clone_identity)
                checks: list[HostCheckEvidence] = []
                for spec in self._plan.checks:
                    observed = self._executor.run(spec, cwd=clone_path)
                    checks.append(
                        HostCheckEvidence(
                            spec.check_id,
                            observed.exit_code,
                            observed.timed_out,
                            observed.truncated,
                        )
                    )
                    if observed.exit_code != 0 or observed.timed_out or observed.truncated:
                        raise PostStopVerificationError("fixed offline check did not succeed")
                artifacts.revalidate()
                source.revalidate()
                verification.revalidate()
                _revalidate_verification_clone(verification, clone_name, clone_fd, clone_identity)
                # This is deliberately after patch inspection and the complete
                # check registry: no stale clone can approach a publisher.
                base_after = _source_base_sha(self._plan, source)
                if base_after != self._plan.cycle.base_sha:
                    raise PostStopVerificationError("base moved immediately before handoff")
                receipt = PostStopVerificationReceipt(
                    run_id=self._plan.cycle.run_id,
                    epoch=self._plan.epoch,
                    request_sha256=self._plan.request_sha256,
                    mediator_receipt_sha256=self._plan.mediator_receipt_sha256,
                    patch_sha256=actual_patch_sha,
                    inspected_diff_sha256=inspected_sha,
                    cleanup_sha256=_sha256(cleanup_raw),
                    base_sha_before=base_before,
                    base_sha_after=base_after,
                    checks=tuple(checks),
                    verification_clone_removed=False,
                )
            finally:
                try:
                    _remove_verification_clone(verification, clone_name, clone_fd, clone_identity)
                finally:
                    os.close(clone_fd)
                verification.revalidate()
        if receipt is None:
            raise PostStopVerificationError("post-stop verification did not produce a receipt")
        return PostStopVerificationReceipt(
            run_id=receipt.run_id,
            epoch=receipt.epoch,
            request_sha256=receipt.request_sha256,
            mediator_receipt_sha256=receipt.mediator_receipt_sha256,
            patch_sha256=receipt.patch_sha256,
            inspected_diff_sha256=receipt.inspected_diff_sha256,
            cleanup_sha256=receipt.cleanup_sha256,
            base_sha_before=receipt.base_sha_before,
            base_sha_after=receipt.base_sha_after,
            checks=receipt.checks,
            verification_clone_removed=True,
        )


def verify_post_stop(
    plan: PostStopPlan,
    *,
    artifact_root: Path,
    verification_root: Path,
) -> PostStopVerificationReceipt:
    """Production-looking entry point; gate before any argument-dependent I/O."""

    del plan, artifact_root, verification_root
    if not STRICT_VM_POSTSTOP_ENABLED:
        raise StrictVMPostStopDisabled(
            "strict-VM post-stop verification is source-disabled before filesystem or process work"
        )
    raise StrictVMPostStopDisabled(
        "strict-VM post-stop broker attestation and OS-isolated checks are unimplemented"
    )


def verify_post_stop_fixture(
    plan: PostStopPlan,
    *,
    artifact_root: Path,
    verification_root: Path,
    executor: OfflineCheckExecutor | None,
    fixture_capability: FixturePostStopCapability,
) -> PostStopVerificationReceipt:
    """Run the explicit non-production verifier fixture.

    Injected executors are accepted only here. They remain fixture claims; a
    production verifier needs a broker-selected OS-isolated check service with
    no host-account filesystem or network authority.
    """

    verifier = _FixturePostStopVerifier(plan, executor=executor)
    return verifier.verify(
        artifact_root=artifact_root,
        verification_root=verification_root,
        fixture_capability=fixture_capability,
    )
