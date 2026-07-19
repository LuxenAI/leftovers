"""Fail-closed contract for a future OS-isolated post-stop check executor.

Process groups and captured pipes are useful cleanup mechanisms, but are not
descendant proofs: a process can ``setsid()``, daemonize, or close the pipes
before its original leader exits.  The only contemplated proof shape here is
Linux cgroup v2 evidence from a service-owned, non-delegated process unit.

This module deliberately performs no process, cgroup, service-manager, or
filesystem work.  ``STRICT_VM_OS_EXECUTOR_ENABLED`` is source-disabled and
the public collection entry point rejects before it consults a platform
adapter.  The immutable values and pure validator make the future adapter's
required evidence reviewable without treating fixture data as authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .strict_vm_cycle import StrictVMCycleError

# This is a release gate, not a configuration option.  No caller may turn it
# on with TOML, environment, or injected evidence.
STRICT_VM_OS_EXECUTOR_ENABLED = False

LINUX_CGROUP_V2 = "linux-cgroup-v2"
MAX_WALL_SECONDS = 900
MAX_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
MAX_PIDS = 256
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MIN_EMPTY_OBSERVATION_GAP_NS = 10_000_000

_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_REQUIRED_CONTROLLERS = ("cpu", "memory", "pids")
_CGROUP_EVENT_KEY = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_MAX_CGROUP_OBSERVATION_BYTES = 4_096


class OSExecutorEvidenceError(StrictVMCycleError):
    """OS executor evidence is absent, malformed, or insufficient."""


class StrictVMOSExecutorDisabled(OSExecutorEvidenceError):
    """The source-level OS-executor gate rejected before platform access."""


class PlatformEvidenceUnavailable(OSExecutorEvidenceError):
    """The host lacks the reviewed cgroup/service evidence adapter."""


def _require_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise OSExecutorEvidenceError(f"{label} is invalid")
    return value


def _canonical_digest(value: object) -> str:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise OSExecutorEvidenceError("executor evidence cannot be canonicalized") from exc
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ProcessUnitIdentity:
    """Identity of one OS-owned cgroup, never a PID or process-group ID.

    ``boot_id_sha256`` and the cgroup mount/inode prevent a PID or a reused
    cgroup pathname from being accepted as the prior workload.  The
    controller-generated ``service_unit_id`` binds the creation event; an
    eventual adapter must obtain all fields from its privileged service
    manager, not from workload output.
    """

    run_id: str
    platform: str
    boot_id_sha256: str
    cgroup_mount_id: int
    cgroup_inode: int
    service_unit_id: str

    def __post_init__(self) -> None:
        _require_hex(self.run_id, _HEX32, "process-unit run ID")
        if self.platform != LINUX_CGROUP_V2:
            raise OSExecutorEvidenceError("process-unit platform is unsupported")
        _require_hex(self.boot_id_sha256, _HEX64, "process-unit boot identity")
        _require_hex(self.service_unit_id, _HEX32, "process-unit service identity")
        if (
            type(self.cgroup_mount_id) is not int
            or type(self.cgroup_inode) is not int
            or self.cgroup_mount_id <= 0
            or self.cgroup_inode <= 0
        ):
            raise OSExecutorEvidenceError("process-unit cgroup identity is invalid")

    @property
    def sha256(self) -> str:
        return _canonical_digest(
            {
                "boot_id_sha256": self.boot_id_sha256,
                "cgroup_inode": self.cgroup_inode,
                "cgroup_mount_id": self.cgroup_mount_id,
                "platform": self.platform,
                "run_id": self.run_id,
                "service_unit_id": self.service_unit_id,
            }
        )


@dataclass(frozen=True)
class OSExecutorCaps:
    """Controller-fixed resource caps that must be enforced by the OS unit."""

    wall_seconds: int
    cpu_quota_usec: int
    cpu_period_usec: int
    memory_max_bytes: int
    pids_max: int
    output_max_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.wall_seconds) is not int
            or not 1 <= self.wall_seconds <= MAX_WALL_SECONDS
            or type(self.cpu_quota_usec) is not int
            or type(self.cpu_period_usec) is not int
            or not 1_000 <= self.cpu_quota_usec <= self.cpu_period_usec <= 1_000_000
            or type(self.memory_max_bytes) is not int
            or not 1_048_576 <= self.memory_max_bytes <= MAX_MEMORY_BYTES
            or type(self.pids_max) is not int
            or not 1 <= self.pids_max <= MAX_PIDS
            or type(self.output_max_bytes) is not int
            or not 1 <= self.output_max_bytes <= MAX_OUTPUT_BYTES
        ):
            raise OSExecutorEvidenceError("OS executor resource caps are invalid")

    @property
    def sha256(self) -> str:
        return _canonical_digest(
            {
                "cpu_period_usec": self.cpu_period_usec,
                "cpu_quota_usec": self.cpu_quota_usec,
                "memory_max_bytes": self.memory_max_bytes,
                "output_max_bytes": self.output_max_bytes,
                "pids_max": self.pids_max,
                "wall_seconds": self.wall_seconds,
            }
        )


@dataclass(frozen=True)
class CgroupV2EmptySample:
    """One post-stop direct reading of ``cgroup.events`` and ``cgroup.procs``."""

    unit_sha256: str
    observed_monotonic_ns: int
    cgroup_events_raw: bytes
    cgroup_procs_raw: bytes

    def __post_init__(self) -> None:
        _require_hex(self.unit_sha256, _HEX64, "empty-sample process-unit identity")
        if (
            type(self.observed_monotonic_ns) is not int
            or self.observed_monotonic_ns <= 0
            or type(self.cgroup_events_raw) is not bytes
            or not 0 < len(self.cgroup_events_raw) <= _MAX_CGROUP_OBSERVATION_BYTES
            or type(self.cgroup_procs_raw) is not bytes
            or len(self.cgroup_procs_raw) > _MAX_CGROUP_OBSERVATION_BYTES
        ):
            raise OSExecutorEvidenceError("empty-sample framing is invalid")
        _parse_cgroup_events(self.cgroup_events_raw)
        _parse_cgroup_procs(self.cgroup_procs_raw)

    @property
    def cgroup_events_sha256(self) -> str:
        return hashlib.sha256(self.cgroup_events_raw).hexdigest()

    @property
    def cgroup_procs_sha256(self) -> str:
        return hashlib.sha256(self.cgroup_procs_raw).hexdigest()

    def proves_empty(self) -> bool:
        """Return true only for the exact kernel-facing empty observations."""

        events = _parse_cgroup_events(self.cgroup_events_raw)
        return events["populated"] == 0 and not _parse_cgroup_procs(self.cgroup_procs_raw)


def _parse_cgroup_events(raw: bytes) -> dict[str, int]:
    """Parse one bounded flat-keyed kernel file without trusting claimed fields."""

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OSExecutorEvidenceError("cgroup.events is not bounded ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise OSExecutorEvidenceError("cgroup.events framing is invalid")
    values: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split(" ")
        if (
            len(fields) != 2
            or _CGROUP_EVENT_KEY.fullmatch(fields[0]) is None
            or not fields[1].isdigit()
            or fields[0] in values
        ):
            raise OSExecutorEvidenceError("cgroup.events entry is invalid")
        values[fields[0]] = int(fields[1])
    if values.get("populated") not in {0, 1}:
        raise OSExecutorEvidenceError("cgroup.events lacks an exact populated value")
    return values


def _parse_cgroup_procs(raw: bytes) -> tuple[int, ...]:
    """Parse the kernel PID list; only an empty tuple can prove cleanup."""

    if not raw:
        return ()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OSExecutorEvidenceError("cgroup.procs is not bounded ASCII") from exc
    if not text.endswith("\n") or "\r" in text:
        raise OSExecutorEvidenceError("cgroup.procs framing is invalid")
    pids: list[int] = []
    for line in text.splitlines():
        if not line.isdigit() or int(line) <= 0:
            raise OSExecutorEvidenceError("cgroup.procs PID entry is invalid")
        pids.append(int(line))
    return tuple(pids)


@dataclass(frozen=True)
class CgroupV2DescendantProof:
    """Evidence an eventual privileged Linux adapter must collect after stop.

    The service manager must keep the workload in an un-delegated cgroup: the
    workload cannot write ``cgroup.procs`` or create a child cgroup.  That
    containment is the property that makes a cgroup sample meaningful for
    daemonized/``setsid`` descendants; neither leader exit nor pipe closure is
    accepted as a substitute.
    """

    unit: ProcessUnitIdentity
    caps_sha256: str
    cgroup_type: str
    required_controllers: tuple[str, ...]
    unit_not_delegated: bool
    resource_limits_enforced: bool
    network_denied: bool
    filesystem_scope_enforced: bool
    workload_cgroup_migration_blocked: bool
    stop_requested: bool
    cgroup_kill_completed: bool
    leader_exited: bool
    capture_pipes_closed: bool
    first_empty: CgroupV2EmptySample
    second_empty: CgroupV2EmptySample
    unit_reaped_after_empty: bool

    def __post_init__(self) -> None:
        if type(self.unit) is not ProcessUnitIdentity:
            raise OSExecutorEvidenceError("descendant proof process-unit is invalid")
        _require_hex(self.caps_sha256, _HEX64, "descendant proof cap digest")
        if (
            type(self.cgroup_type) is not str
            or self.cgroup_type != "domain"
            or type(self.required_controllers) is not tuple
            or self.required_controllers != tuple(sorted(set(self.required_controllers)))
            or any(type(item) is not str for item in self.required_controllers)
            or type(self.first_empty) is not CgroupV2EmptySample
            or type(self.second_empty) is not CgroupV2EmptySample
        ):
            raise OSExecutorEvidenceError("descendant proof framing is invalid")
        for value in (
            self.unit_not_delegated,
            self.resource_limits_enforced,
            self.network_denied,
            self.filesystem_scope_enforced,
            self.workload_cgroup_migration_blocked,
            self.stop_requested,
            self.cgroup_kill_completed,
            self.leader_exited,
            self.capture_pipes_closed,
            self.unit_reaped_after_empty,
        ):
            if type(value) is not bool:
                raise OSExecutorEvidenceError("descendant proof boolean is invalid")


@dataclass(frozen=True)
class OSExecutorReceipt:
    """Pure, non-authoritative receipt for future post-stop artifact binding."""

    run_id: str
    unit_sha256: str
    caps_sha256: str
    descendant_empty_proven: bool
    proof_sha256: str

    def __post_init__(self) -> None:
        _require_hex(self.run_id, _HEX32, "OS executor receipt run ID")
        for value, label in (
            (self.unit_sha256, "OS executor receipt unit digest"),
            (self.caps_sha256, "OS executor receipt cap digest"),
            (self.proof_sha256, "OS executor receipt proof digest"),
        ):
            _require_hex(value, _HEX64, label)
        if self.descendant_empty_proven is not True:
            raise OSExecutorEvidenceError("OS executor receipt cannot claim partial proof")


class LinuxCgroupV2EvidenceSource(Protocol):
    """Privileged adapter boundary; no implementation is shipped in this repo."""

    def stop_and_collect(
        self, unit: ProcessUnitIdentity, caps: OSExecutorCaps
    ) -> CgroupV2DescendantProof: ...


class UnavailableLinuxCgroupV2EvidenceSource:
    """Default source that refuses a host-process or process-group fallback."""

    def stop_and_collect(
        self, unit: ProcessUnitIdentity, caps: OSExecutorCaps
    ) -> CgroupV2DescendantProof:
        del unit, caps
        raise PlatformEvidenceUnavailable(
            "no reviewed Linux cgroup-v2/service post-stop evidence source is integrated"
        )


def _proof_digest(proof: CgroupV2DescendantProof) -> str:
    def sample(value: CgroupV2EmptySample) -> dict[str, object]:
        return {
            "cgroup_events_sha256": value.cgroup_events_sha256,
            "cgroup_procs_sha256": value.cgroup_procs_sha256,
            "observed_monotonic_ns": value.observed_monotonic_ns,
            "unit_sha256": value.unit_sha256,
        }

    return _canonical_digest(
        {
            "caps_sha256": proof.caps_sha256,
            "capture_pipes_closed": proof.capture_pipes_closed,
            "cgroup_type": proof.cgroup_type,
            "cgroup_kill_completed": proof.cgroup_kill_completed,
            "filesystem_scope_enforced": proof.filesystem_scope_enforced,
            "first_empty": sample(proof.first_empty),
            "leader_exited": proof.leader_exited,
            "network_denied": proof.network_denied,
            "required_controllers": proof.required_controllers,
            "resource_limits_enforced": proof.resource_limits_enforced,
            "second_empty": sample(proof.second_empty),
            "stop_requested": proof.stop_requested,
            "unit": proof.unit.__dict__,
            "unit_not_delegated": proof.unit_not_delegated,
            "unit_reaped_after_empty": proof.unit_reaped_after_empty,
            "workload_cgroup_migration_blocked": proof.workload_cgroup_migration_blocked,
        }
    )


def validate_linux_cgroup_v2_descendant_proof(
    unit: ProcessUnitIdentity, caps: OSExecutorCaps, proof: CgroupV2DescendantProof
) -> OSExecutorReceipt:
    """Validate the exact evidence required to prove a unit is descendant-empty.

    This is deliberately a pure structural validator.  It does not make
    caller-constructed data authoritative and is not reachable from a
    production path while the source gate remains disabled.
    """

    if type(unit) is not ProcessUnitIdentity or type(caps) is not OSExecutorCaps:
        raise OSExecutorEvidenceError("expected OS executor identity or caps are invalid")
    if type(proof) is not CgroupV2DescendantProof or proof.unit != unit:
        raise OSExecutorEvidenceError("descendant proof process-unit identity does not match")
    if proof.caps_sha256 != caps.sha256:
        raise OSExecutorEvidenceError("descendant proof resource caps do not match")
    if not set(_REQUIRED_CONTROLLERS).issubset(proof.required_controllers):
        raise OSExecutorEvidenceError("cgroup proof lacks a required resource controller")
    if not all(
        (
            proof.unit_not_delegated,
            proof.resource_limits_enforced,
            proof.network_denied,
            proof.filesystem_scope_enforced,
            proof.workload_cgroup_migration_blocked,
            proof.stop_requested,
            proof.cgroup_kill_completed,
            proof.leader_exited,
            proof.capture_pipes_closed,
            proof.unit_reaped_after_empty,
        )
    ):
        raise OSExecutorEvidenceError("cgroup proof lacks required containment or stop evidence")
    first, second = proof.first_empty, proof.second_empty
    if first.unit_sha256 != unit.sha256 or second.unit_sha256 != unit.sha256:
        raise OSExecutorEvidenceError("empty samples do not bind to the expected process unit")
    if not first.proves_empty() or not second.proves_empty():
        raise OSExecutorEvidenceError("cgroup still contains a descendant after stop")
    if second.observed_monotonic_ns - first.observed_monotonic_ns < MIN_EMPTY_OBSERVATION_GAP_NS:
        raise OSExecutorEvidenceError("empty cgroup evidence lacks a separated later observation")
    return OSExecutorReceipt(
        run_id=unit.run_id,
        unit_sha256=unit.sha256,
        caps_sha256=caps.sha256,
        descendant_empty_proven=True,
        proof_sha256=_proof_digest(proof),
    )


def collect_descendant_empty_receipt(
    unit: ProcessUnitIdentity,
    caps: OSExecutorCaps,
    *,
    source: LinuxCgroupV2EvidenceSource | None = None,
) -> OSExecutorReceipt:
    """Disabled production-shaped collection entry point.

    It rejects before reading a cgroup, contacting a service manager, or even
    invoking an injected adapter.  A future activation must wire a reviewed,
    privileged adapter and bind its receipt into the post-stop result schema.
    """

    del unit, caps, source
    if not STRICT_VM_OS_EXECUTOR_ENABLED:
        raise StrictVMOSExecutorDisabled(
            "strict-VM OS executor is source-disabled before platform or process work"
        )
    raise PlatformEvidenceUnavailable("OS executor activation requires a reviewed platform adapter")
