"""Deterministic, no-authority wiring rehearsal for the strict-VM design.

This is deliberately *not* a VM runner.  It creates only synthetic bytes in
an operator-provided private directory, never calls a provider, launches a
VM, runs Git or a check, contacts GitHub, or imports the publisher.  Its sole
purpose is to make the boundary between the future broker, provider mediator,
guest contract, post-stop reader, and pure cycle verifier executable while all
production release gates remain false.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .codex_cli_mediator import (
    MODEL,
    PRODUCTION_CODEX_MEDIATION_ENABLED,
    PROVIDER,
    REASONING_EFFORT,
    ZERO_TOOL_CONFIGURATION_PROVEN,
    CodexCliIdentity,
    CodexInvocationPlan,
    derive_mediation_result,
    parse_codex_event_evidence,
    prepare_codex_invocation_plan,
    verify_codex_cli_identity,
)
from .model_mediator import (
    PRODUCTION_MEDIATION_ENABLED,
    MediationLimits,
    MediationRequest,
    MediationStage,
    canonical_json_bytes,
)
from .strict_vm_broker import STRICT_VM_BROKER_ENABLED
from .strict_vm_broker_installation import (
    STRICT_VM_BROKER_INSTALLATION_ENABLED,
    STRICT_VM_BROKER_NATIVE_TRUST_ADAPTER_VERIFIED,
)
from .strict_vm_broker_journal import STRICT_VM_BROKER_DESCRIPTOR_ADMISSION_ENABLED
from .strict_vm_broker_service import (
    STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED,
    STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED,
    STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED,
    STRICT_VM_BROKER_SERVICE_ENABLED,
    FixturePrivateRunRoot,
    issue_fixture_broker_service_capability,
)
from .strict_vm_broker_storage import STRICT_VM_BROKER_JOURNAL_STORAGE_ENABLED
from .strict_vm_cycle import (
    STRICT_VM_WHOLE_CYCLE_CAPABILITY,
    CyclePlan,
    CycleState,
    HostCheckEvidence,
    MediatorReceipt,
    StoppedGuestReceipt,
    accept_stopped_epoch,
    create_fixture_publisher_handoff,
    patch_sha256,
    start_offline_cycle,
)
from .strict_vm_os_executor import STRICT_VM_OS_EXECUTOR_ENABLED
from .strict_vm_poststop import (
    STRICT_VM_POSTSTOP_ENABLED,
    OfflineCheckSpec,
    PostStopPlan,
    PostStopVerificationReceipt,
    read_nofollow_artifact,
)
from .strict_vm_runner import STRICT_VM_EXECUTION_ENABLED
from .strict_vm_source_capsule import STRICT_VM_SOURCE_CAPSULE_PACKING_ENABLED

SYNTHETIC_REHEARSAL_ONLY = True
"""This module intentionally has no switch that permits a live execution."""

_RUN_ID = "a" * 32
_BASE_SHA = "b" * 40
_POLICY_SHA256 = "c" * 64
_PATCH = (
    b"diff --git a/rehearsal.txt b/rehearsal.txt\n"
    b"index 0000000..1111111 100644\n"
    b"--- a/rehearsal.txt\n"
    b"+++ b/rehearsal.txt\n"
    b"@@ -0,0 +1 @@\n"
    b"+synthetic-only\n"
)
_CHECK_ID = "rehearsal.check"
_SYNTHETIC_CLI = b"leftovers synthetic provider fixture\n"


class SyntheticRehearsalError(RuntimeError):
    """The deterministic rehearsal cannot prove its intentionally narrow contract."""


@dataclass
class _RootRecord:
    """Caller root bound to a retained parent descriptor and exact basename."""

    path: Path
    name: str
    fd: int
    parent_fd: int
    identity: tuple[int, int]
    parent_identity: tuple[int, int]


@dataclass
class _DirectoryRecord:
    """One fixture directory registered before its fallible validation completes."""

    path: Path
    name: str
    fd: int = -1
    identity: tuple[int, int] | None = None


@dataclass
class _LeafRecord:
    """One fixture leaf bound to retained parent and leaf descriptors."""

    path: Path
    name: str
    parent_fd: int
    expected_parent_identity: tuple[int, int]
    mode: int
    fd: int = -1
    identity: tuple[int, int] | None = None


@dataclass(frozen=True)
class SyntheticRehearsalEvidence:
    """Non-authoritative evidence emitted by one entirely local fixture run."""

    invocation_plan: CodexInvocationPlan
    request_sha256: str
    action_batch_sha256: str
    canonical_patch_sha256: str
    guest_contract_sha256: str
    cycle_state: CycleState
    artifact_digests: tuple[tuple[str, str], ...]
    broker_workspace_removed: bool
    fixture_handoff_created: bool
    production_authorities_disabled: bool
    guest_interpreter_reachable: bool
    provider_called: bool
    vm_launched: bool
    git_or_check_executed: bool
    github_write_attempted: bool


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded_regular(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    """Read one caller-provided fixture without following or blocking on a special file."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or type(maximum_bytes) is not int
        or maximum_bytes < 1
    ):
        raise SyntheticRehearsalError(f"{label} read contract is invalid")
    try:
        named_before = path.lstat()
    except OSError as exc:
        raise SyntheticRehearsalError(f"{label} cannot be inspected") from exc
    if (
        not stat.S_ISREG(named_before.st_mode)
        or named_before.st_nlink != 1
        or named_before.st_uid not in {0, os.geteuid()}
        or named_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 0 < named_before.st_size <= maximum_bytes
    ):
        raise SyntheticRehearsalError(f"{label} is not a bounded trusted regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)

        def identity(item: os.stat_result) -> tuple[int, ...]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_uid,
                item.st_mode,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if identity(before) != identity(named_before) or not stat.S_ISREG(before.st_mode):
            raise SyntheticRehearsalError(f"{label} changed while opening")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            total != before.st_size
            or total > maximum_bytes
            or identity(before) != identity(after)
            or identity(after) != identity(named_after)
        ):
            raise SyntheticRehearsalError(f"{label} changed or exceeded its cap while reading")
        return b"".join(chunks)
    except OSError as exc:
        raise SyntheticRehearsalError(f"{label} cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _trusted_fixture_parent(info: os.stat_result) -> bool:
    """Recognize a controlled parent or the root-owned sticky temp boundary."""

    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
        return False
    if not mode & (stat.S_IWGRP | stat.S_IWOTH):
        return True
    return info.st_uid == 0 and bool(mode & stat.S_ISVTX)


def _open_private_empty_directory(path: Path, label: str) -> _RootRecord:
    """Open and retain the caller-owned fixture root after exact validation."""

    parent_descriptor = -1
    descriptor = -1
    try:
        parent_named = path.parent.lstat()
        named = path.lstat()
    except OSError as exc:
        raise SyntheticRehearsalError(f"{label} cannot be inspected") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(named.st_mode)
        or named.st_uid != os.geteuid()
        or stat.S_IMODE(named.st_mode) != 0o700
    ):
        raise SyntheticRehearsalError(f"{label} must be an owner-private real directory")
    if not _trusted_fixture_parent(parent_named):
        raise SyntheticRehearsalError(f"{label} parent is not trusted")
    try:
        parent_descriptor = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        parent_opened = os.fstat(parent_descriptor)
        if (parent_opened.st_dev, parent_opened.st_ino) != (
            parent_named.st_dev,
            parent_named.st_ino,
        ):
            raise SyntheticRehearsalError(f"{label} parent changed while opening")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if identity != (named.st_dev, named.st_ino):
            raise SyntheticRehearsalError(f"{label} changed while opening")
        if os.listdir(descriptor):
            raise SyntheticRehearsalError(f"{label} must be empty before rehearsal")
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise SyntheticRehearsalError(f"{label} cannot be enumerated") from exc
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise
    return _RootRecord(
        path=path,
        name=path.name,
        fd=descriptor,
        parent_fd=parent_descriptor,
        identity=identity,
        parent_identity=(parent_opened.st_dev, parent_opened.st_ino),
    )


def _revalidate_root(record: _RootRecord) -> None:
    try:
        held = os.fstat(record.fd)
        parent_held = os.fstat(record.parent_fd)
        named = os.stat(record.name, dir_fd=record.parent_fd, follow_symlinks=False)
        named_by_canonical_path = record.path.lstat()
    except OSError as exc:
        raise SyntheticRehearsalError(
            "synthetic fixture root binding cannot be revalidated"
        ) from exc
    if (
        (held.st_dev, held.st_ino) != record.identity
        or (named.st_dev, named.st_ino) != record.identity
        or (named_by_canonical_path.st_dev, named_by_canonical_path.st_ino) != record.identity
        or (parent_held.st_dev, parent_held.st_ino) != record.parent_identity
        or not stat.S_ISDIR(named.st_mode)
    ):
        raise SyntheticRehearsalError("synthetic fixture root pathname identity changed")


def _verify_retained_directory(
    descriptor: int, identity: tuple[int, int] | None, *, label: str
) -> None:
    try:
        details = os.fstat(descriptor)
    except OSError as exc:
        raise SyntheticRehearsalError(f"{label} descriptor is unavailable") from exc
    if (
        (details.st_dev, details.st_ino) != identity
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise SyntheticRehearsalError(f"{label} retained identity is unsafe")


def _mkdir_private(
    root_fd: int,
    root_identity: tuple[int, int],
    path: Path,
    records: list[_DirectoryRecord],
) -> _DirectoryRecord:
    """Create and immediately register one direct fixture child directory."""

    _verify_retained_directory(root_fd, root_identity, label="synthetic fixture root")
    record = _DirectoryRecord(path=path, name=path.name)
    try:
        os.mkdir(record.name, 0o700, dir_fd=root_fd)
        records.append(record)
        named = os.stat(record.name, dir_fd=root_fd, follow_symlinks=False)
        record.identity = (named.st_dev, named.st_ino)
        record.fd = os.open(
            record.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        opened = os.fstat(record.fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or (opened.st_dev, opened.st_ino) != record.identity
        ):
            raise SyntheticRehearsalError("synthetic fixture directory identity is unsafe")
        os.fsync(root_fd)
        return record
    except OSError as exc:
        raise SyntheticRehearsalError("synthetic fixture directory creation failed") from exc


def _write_private(
    parent: _DirectoryRecord | None,
    *,
    root_fd: int,
    root_identity: tuple[int, int],
    path: Path,
    raw: bytes,
    mode: int,
    records: list[_LeafRecord],
) -> _LeafRecord:
    """Create one tracked leaf through an already retained parent descriptor."""

    if parent is None:
        parent_fd = root_fd
        parent_identity = root_identity
    else:
        if parent.fd < 0 or parent.identity is None:
            raise SyntheticRehearsalError("synthetic fixture parent is not fully tracked")
        parent_fd = parent.fd
        parent_identity = parent.identity
    _verify_retained_directory(parent_fd, parent_identity, label="synthetic fixture parent")
    record = _LeafRecord(path, path.name, parent_fd, parent_identity, mode)
    try:
        record.fd = os.open(
            record.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
            dir_fd=parent_fd,
        )
        # Register immediately after the mutating syscall, before fstat/write/fsync.
        records.append(record)
        details = os.fstat(record.fd)
        record.identity = (details.st_dev, details.st_ino)
        written = 0
        while written < len(raw):
            count = os.write(record.fd, raw[written:])
            if count <= 0:
                raise SyntheticRehearsalError("synthetic fixture write made no progress")
            written += count
        os.fsync(record.fd)
        details = os.fstat(record.fd)
        named = os.stat(record.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != mode
            or details.st_size != len(raw)
            or record.identity != (named.st_dev, named.st_ino)
        ):
            raise SyntheticRehearsalError("synthetic fixture leaf identity is unsafe")
        os.fsync(parent_fd)
        return record
    except OSError as exc:
        raise SyntheticRehearsalError("synthetic fixture write failed") from exc


def _remove_exact(root_fd: int, record: _DirectoryRecord) -> None:
    """Remove one exact tracked directory relative to the retained root."""

    try:
        if record.identity is None:
            raise SyntheticRehearsalError("synthetic fixture directory identity was not recorded")
        if record.fd < 0:
            record.fd = os.open(
                record.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
        held = os.fstat(record.fd)
        observed = os.stat(record.name, dir_fd=root_fd, follow_symlinks=False)
        if (
            (held.st_dev, held.st_ino) != record.identity
            or (observed.st_dev, observed.st_ino) != record.identity
            or not stat.S_ISDIR(observed.st_mode)
        ):
            raise SyntheticRehearsalError("synthetic fixture directory identity changed")
        os.rmdir(record.name, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise SyntheticRehearsalError("synthetic fixture cleanup is unproven") from exc


def _unlink_exact(record: _LeafRecord) -> None:
    """Unlink one tracked leaf relative to its retained parent descriptor."""

    try:
        if record.fd < 0:
            raise SyntheticRehearsalError("synthetic fixture leaf descriptor was not recorded")
        if record.identity is None:
            held = os.fstat(record.fd)
            record.identity = (held.st_dev, held.st_ino)
        _verify_retained_directory(
            record.parent_fd,
            record.expected_parent_identity,
            label="synthetic fixture cleanup parent",
        )
        held = os.fstat(record.fd)
        observed = os.stat(record.name, dir_fd=record.parent_fd, follow_symlinks=False)
        if (
            (held.st_dev, held.st_ino) != record.identity
            or (observed.st_dev, observed.st_ino) != record.identity
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
        ):
            raise SyntheticRehearsalError("synthetic fixture leaf identity changed")
        os.unlink(record.name, dir_fd=record.parent_fd)
        os.fsync(record.parent_fd)
    except OSError as exc:
        raise SyntheticRehearsalError("synthetic fixture leaf cleanup is unproven") from exc


def _cleanup_fixture_tree(
    root: _RootRecord,
    leaves: list[_LeafRecord],
    directories: list[_DirectoryRecord],
) -> list[BaseException]:
    """Attempt every exact cleanup and descriptor close, aggregating failures."""

    errors: list[BaseException] = []
    for record in reversed(leaves):
        try:
            _unlink_exact(record)
        except BaseException as exc:
            errors.append(exc)
        if record.fd >= 0:
            try:
                os.close(record.fd)
            except OSError as exc:
                errors.append(exc)
            record.fd = -1
    for record in reversed(directories):
        try:
            _remove_exact(root.fd, record)
        except BaseException as exc:
            errors.append(exc)
        if record.fd >= 0:
            try:
                os.close(record.fd)
            except OSError as exc:
                errors.append(exc)
            record.fd = -1
    try:
        _revalidate_root(root)
    except BaseException as exc:
        errors.append(exc)
    try:
        os.close(root.fd)
    except OSError as exc:
        errors.append(exc)
    root.fd = -1
    try:
        os.close(root.parent_fd)
    except OSError as exc:
        errors.append(exc)
    root.parent_fd = -1
    return errors


def _require_all_production_authorities_disabled() -> None:
    gates = (
        PRODUCTION_CODEX_MEDIATION_ENABLED,
        ZERO_TOOL_CONFIGURATION_PROVEN,
        PRODUCTION_MEDIATION_ENABLED,
        STRICT_VM_BROKER_ENABLED,
        STRICT_VM_BROKER_DESCRIPTOR_ADMISSION_ENABLED,
        STRICT_VM_BROKER_JOURNAL_STORAGE_ENABLED,
        STRICT_VM_BROKER_SERVICE_ENABLED,
        STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED,
        STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED,
        STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED,
        STRICT_VM_BROKER_INSTALLATION_ENABLED,
        STRICT_VM_BROKER_NATIVE_TRUST_ADAPTER_VERIFIED,
        STRICT_VM_EXECUTION_ENABLED,
        STRICT_VM_OS_EXECUTOR_ENABLED,
        STRICT_VM_POSTSTOP_ENABLED,
        STRICT_VM_SOURCE_CAPSULE_PACKING_ENABLED,
        STRICT_VM_WHOLE_CYCLE_CAPABILITY,
    )
    if any(gates):
        raise SyntheticRehearsalError("a production authority gate is unexpectedly enabled")


def _request(now: datetime) -> MediationRequest:
    return MediationRequest(
        run_id=_RUN_ID,
        round=0,
        stage=MediationStage.IMPLEMENTATION,
        provider=PROVIDER,
        model=MODEL,
        reasoning_effort=REASONING_EFFORT,
        input_bytes=canonical_json_bytes({"synthetic": "untrusted fixture bytes"}),
        allowed_check_ids=frozenset({_CHECK_ID}),
        limits=MediationLimits(
            max_response_bytes=8_192,
            max_patch_bytes=8_192,
            max_actions=4,
            # The invocation-plan contract reserves the provider context in
            # addition to the fixture prompt itself; this is a ceiling, not a
            # claimed provider spend.
            input_token_cap=17_000,
            output_token_cap=100,
            total_token_cap=17_100,
            call_index=1,
            call_cap=1,
        ),
        deadline_at=now + timedelta(minutes=10),
    )


def _synthetic_event_stream() -> bytes:
    events = (
        {"type": "thread.started", "thread_id": "synthetic-thread"},
        {"type": "turn.started"},
        {
            "type": "item.started",
            "item": {"id": "synthetic-item", "type": "agent_message", "text": ""},
        },
        {
            "type": "item.completed",
            "item": {"id": "synthetic-item", "type": "agent_message", "text": "fixture"},
        },
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "output_tokens": 10,
                "reasoning_output_tokens": 1,
            },
        },
    )
    return b"".join(
        json.dumps(event, separators=(",", ":")).encode("utf-8") + b"\n" for event in events
    )


def _synthetic_envelope(request: MediationRequest) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": 1,
            "run_id": request.run_id,
            "round": request.round,
            "stage": request.stage.value,
            "provider": PROVIDER,
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "input_sha256": _sha256(request.input_bytes),
            "actions": [
                {"id": "patch", "type": "apply_patch"},
                {"id": "finish", "type": "finish", "status": "complete", "summary": "fixture"},
            ],
            "patch": _PATCH.decode("utf-8"),
        }
    )


def _validate_source_only_guest_contract(interpreter: Path, supervisor: Path) -> str:
    """Bind fixture evidence to the checked-in, intentionally unreachable guest contract."""

    try:
        interpreter_bytes = _read_bounded_regular(
            interpreter, label="guest interpreter source", maximum_bytes=2_000_000
        )
        supervisor_bytes = _read_bounded_regular(
            supervisor, label="guest supervisor source", maximum_bytes=2_000_000
        )
        interpreter_text = interpreter_bytes.decode("utf-8")
        supervisor_text = supervisor_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SyntheticRehearsalError("guest contract sources cannot be read as UTF-8") from exc
    required_interpreter = (
        "lfr_parse_request",
        "lfr_apply_exact_controller_patch",
        "lfr_emit_bounded_result",
        "repo-tree-safety-v1",
        "repo-root-regular-v1",
        "return false; /* no implicit partial write",
    )
    if any(token not in interpreter_text for token in required_interpreter):
        raise SyntheticRehearsalError("guest interpreter contract is incomplete")
    if (
        '#include "guest_interpreter.c"' not in supervisor_text
        or "if (false)" not in supervisor_text
    ):
        raise SyntheticRehearsalError(
            "guest interpreter is not compiled source-only and unreachable"
        )
    return _sha256(
        b"LEFTOVERS_SYNTHETIC_GUEST_CONTRACT_V1\0" + interpreter_bytes + b"\0" + supervisor_bytes
    )


def run_synthetic_rehearsal(
    workspace_root: Path,
    *,
    provider_schema: Path,
    guest_interpreter_source: Path,
    guest_supervisor_source: Path,
    now: datetime,
) -> SyntheticRehearsalEvidence:
    """Exercise one synthetic receipt chain without any live authority.

    ``workspace_root`` must be an empty ``0700`` directory controlled by the
    caller.  On success it is empty again; the function only removes children
    whose exact names it created.  ``provider_schema`` is copied into that
    private directory before it is pinned into the non-executing invocation
    plan, so no repository checkout or user configuration reaches the fixture.
    """

    if not SYNTHETIC_REHEARSAL_ONLY:
        raise SyntheticRehearsalError("synthetic rehearsal mode was weakened")
    if now.tzinfo is None or now.utcoffset() is None:
        raise SyntheticRehearsalError("synthetic rehearsal time must be timezone-aware")
    observed_now = now.astimezone(UTC)
    _require_all_production_authorities_disabled()
    guest_contract_sha256 = _validate_source_only_guest_contract(
        guest_interpreter_source, guest_supervisor_source
    )
    try:
        # macOS commonly exposes its temporary directory through /var, which
        # is a symlink to /private/var.  The invocation-plan contract rightly
        # rejects that textual path, so normalize the caller-owned root before
        # creating any child fixture.
        workspace_root = workspace_root.resolve(strict=True)
    except OSError as exc:
        raise SyntheticRehearsalError("synthetic rehearsal root cannot be resolved") from exc
    schema_bytes = _read_bounded_regular(
        provider_schema, label="provider schema fixture", maximum_bytes=65_536
    )
    root = _open_private_empty_directory(workspace_root, "synthetic rehearsal root")
    root_fd, root_identity = root.fd, root.identity

    cli_path = workspace_root / "synthetic-codex"
    schema_path = workspace_root / "provider-envelope.schema.json"
    cwd = workspace_root / "provider-cwd"
    broker_runs = workspace_root / "broker-runs"
    artifact_root = workspace_root / "poststop-artifacts"
    source_root = workspace_root / "synthetic-source"
    directory_records: list[_DirectoryRecord] = []
    leaf_records: list[_LeafRecord] = []
    broker_workspace_removed = False
    primary_error: BaseException | None = None
    evidence: SyntheticRehearsalEvidence | None = None
    try:
        cwd_record = _mkdir_private(root_fd, root_identity, cwd, directory_records)
        broker_record = _mkdir_private(root_fd, root_identity, broker_runs, directory_records)
        artifact_record = _mkdir_private(root_fd, root_identity, artifact_root, directory_records)
        _mkdir_private(root_fd, root_identity, source_root, directory_records)
        _write_private(
            None,
            root_fd=root_fd,
            root_identity=root_identity,
            path=cli_path,
            raw=_SYNTHETIC_CLI,
            mode=0o500,
            records=leaf_records,
        )
        _write_private(
            None,
            root_fd=root_fd,
            root_identity=root_identity,
            path=schema_path,
            raw=schema_bytes,
            mode=0o400,
            records=leaf_records,
        )

        request = _request(observed_now)
        cli_identity = CodexCliIdentity(cli_path, _sha256(_SYNTHETIC_CLI), "0.0.0-fixture")
        invocation = prepare_codex_invocation_plan(
            verify_codex_cli_identity(cli_identity),
            request,
            private_cwd=cwd,
            output_schema=schema_path,
            output_last_message=cwd / "result.json",
            now=observed_now,
        )
        _verify_retained_directory(cwd_record.fd, cwd_record.identity, label="provider cwd")
        event_evidence = parse_codex_event_evidence(_synthetic_event_stream(), request)
        mediation = derive_mediation_result(
            _synthetic_envelope(request),
            request,
            event_evidence=event_evidence,
            started_at=observed_now,
            finished_at=observed_now,
        )
        if mediation.patch != _PATCH or mediation.receipt.patch_sha256 is None:
            raise SyntheticRehearsalError("synthetic mediator did not bind its canonical patch")

        staged_request = canonical_json_bytes(
            {
                "action_batch_sha256": mediation.receipt.action_batch_sha256,
                "invocation_sha256": invocation.attestation_sha256,
                "request_sha256": invocation.stdin_sha256,
                "run_id": _RUN_ID,
            }
        )
        # The explicit fixture capability is intentionally distinct from the
        # unavailable production broker authority. The broker receives the
        # already retained O_NOFOLLOW descriptor, never a reopened path.
        fixture_capability = issue_fixture_broker_service_capability()
        with FixturePrivateRunRoot(
            broker_record.fd,
            broker_uid=os.geteuid(),
            capability=fixture_capability,
        ) as private_runs:
            run = private_runs.create_run(_RUN_ID)
            run.write_request(staged_request, _sha256(staged_request))
            run.cleanup()
            broker_workspace_removed = True

        cleanup_raw = _canonical_json(
            {
                "epoch": 0,
                "kind": "leftovers.strict-vm.cleanup.v1",
                "launcher_stop_proven": True,
                "resources_removed": True,
                "run_id": _RUN_ID,
                "vm_stopped": True,
            }
        )
        result_raw = _canonical_json(
            {
                "cleanup_sha256": _sha256(cleanup_raw),
                "epoch": 0,
                "kind": "leftovers.strict-vm.poststop-result.v1",
                "launcher_stop_proven": True,
                "mediator_receipt_sha256": _sha256(
                    canonical_json_bytes(mediation.receipt.to_dict())
                ),
                "patch_sha256": mediation.receipt.patch_sha256,
                "request_sha256": invocation.stdin_sha256,
                "result_extracted_after_stop": True,
                "run_id": _RUN_ID,
            }
        )
        for artifact_path, artifact_bytes in (
            (artifact_root / "cleanup.json", cleanup_raw),
            (artifact_root / "result.json", result_raw),
            (artifact_root / "canonical.patch", _PATCH),
        ):
            _write_private(
                artifact_record,
                root_fd=root_fd,
                root_identity=root_identity,
                path=artifact_path,
                raw=artifact_bytes,
                mode=0o600,
                records=leaf_records,
            )
        _verify_retained_directory(
            artifact_record.fd,
            artifact_record.identity,
            label="post-stop artifact root",
        )
        artifacts = (
            (
                "cleanup.json",
                read_nofollow_artifact(artifact_root, "cleanup.json", maximum_bytes=16_384),
            ),
            (
                "result.json",
                read_nofollow_artifact(artifact_root, "result.json", maximum_bytes=16_384),
            ),
            (
                "canonical.patch",
                read_nofollow_artifact(artifact_root, "canonical.patch", maximum_bytes=512 * 1024),
            ),
        )
        if dict(artifacts)["canonical.patch"] != _PATCH:
            raise SyntheticRehearsalError("post-stop descriptor read changed the synthetic patch")

        cycle_plan = CyclePlan(
            run_id=_RUN_ID,
            repository="synthetic/rehearsal",
            issue_number=1,
            base_ref="main",
            base_sha=_BASE_SHA,
            policy_sha256=_POLICY_SHA256,
            required_check_ids=(_CHECK_ID,),
            max_rounds=1,
            token_cap=200,
            deadline_at=observed_now + timedelta(minutes=10),
        )
        poststop_plan = PostStopPlan(
            cycle=cycle_plan,
            epoch=0,
            request_sha256=invocation.stdin_sha256,
            mediator_receipt_sha256=_sha256(canonical_json_bytes(mediation.receipt.to_dict())),
            source_repository=source_root,
            checks=(OfflineCheckSpec(_CHECK_ID, ("/usr/bin/false",), 1),),
        )
        poststop_receipt = PostStopVerificationReceipt(
            run_id=_RUN_ID,
            epoch=0,
            request_sha256=invocation.stdin_sha256,
            mediator_receipt_sha256=poststop_plan.mediator_receipt_sha256,
            patch_sha256=mediation.receipt.patch_sha256,
            inspected_diff_sha256=patch_sha256(_PATCH),
            cleanup_sha256=_sha256(cleanup_raw),
            base_sha_before=_BASE_SHA,
            base_sha_after=_BASE_SHA,
            checks=(HostCheckEvidence(_CHECK_ID, 0, False, False),),
            verification_clone_removed=True,
        )
        state = accept_stopped_epoch(
            start_offline_cycle(cycle_plan, now=observed_now),
            MediatorReceipt(
                run_id=_RUN_ID,
                round=0,
                request_sha256=invocation.stdin_sha256,
                action_batch_sha256=mediation.receipt.action_batch_sha256,
                patch_sha256=mediation.receipt.patch_sha256,
                charged_tokens=mediation.receipt.total_tokens,
            ),
            StoppedGuestReceipt(
                run_id=_RUN_ID,
                round=0,
                request_sha256=invocation.stdin_sha256,
                action_batch_sha256=mediation.receipt.action_batch_sha256,
                canonical_patch=_PATCH,
                canonical_patch_sha256=mediation.receipt.patch_sha256,
                launcher_stop_proven=True,
                result_extracted_after_stop=True,
                cleanup_proven=True,
            ),
            now=observed_now,
        )
        state, _handoff = create_fixture_publisher_handoff(
            state,
            poststop_receipt.host_receipt(poststop_plan),
            base_sha_rechecked=_BASE_SHA,
            now=observed_now,
        )
        _require_all_production_authorities_disabled()
        evidence = SyntheticRehearsalEvidence(
            invocation_plan=invocation,
            request_sha256=invocation.stdin_sha256,
            action_batch_sha256=mediation.receipt.action_batch_sha256,
            canonical_patch_sha256=mediation.receipt.patch_sha256,
            guest_contract_sha256=guest_contract_sha256,
            cycle_state=state,
            artifact_digests=tuple((name, _sha256(raw)) for name, raw in artifacts),
            broker_workspace_removed=broker_workspace_removed,
            fixture_handoff_created=True,
            production_authorities_disabled=True,
            guest_interpreter_reachable=False,
            provider_called=False,
            vm_launched=False,
            git_or_check_executed=False,
            github_write_attempted=False,
        )
    except BaseException as exc:
        primary_error = exc

    cleanup_errors = _cleanup_fixture_tree(root, leaf_records, directory_records)
    if cleanup_errors:
        summaries = "; ".join(str(error) for error in cleanup_errors)
        cleanup_error = SyntheticRehearsalError(
            f"synthetic fixture cleanup is unproven ({len(cleanup_errors)} failures): {summaries}"
        )
        if primary_error is not None:
            raise cleanup_error from primary_error
        raise cleanup_error
    if primary_error is not None:
        raise primary_error
    if evidence is None:
        raise SyntheticRehearsalError("synthetic rehearsal produced no evidence")
    return evidence
