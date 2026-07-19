"""Pure, fixture-only whole-cycle contract for Docker Sandboxes.

This is deliberately *not* an execution backend.  ``DOCKER_SANDBOX_CYCLE_ENABLED``
is a source release gate which stays false: Docker Sandboxes v0.35 has no
controller-verifiable daemon-generation, destruction, or post-stop export
authority.  The public live entry rejects before it reads an argument.  The
remaining API only validates caller-constructible, sealed fixture values and
performs no I/O, provider, Docker, GitHub, clock, or sandbox work.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Never

from .sbx_execution import (
    MAX_MODEL_CALLS,
    RUN_TOKEN_CAP,
    STAGE_LIMITS,
    ExecutionStage,
    SbxExecutionPlan,
    SbxInspectionAttestation,
    fixed_sbx_codex_argv,
    validate_fixture_execution_plan,
)
from .sbx_result import (
    FIXED_CAPTURE_DEADLINE_MS,
    MAX_CAPTURE_BYTES,
    CapabilityFreeSbxHandoff,
    ExactCallUsage,
    ExactUsageReceipt,
    FixtureSbxResultCapability,
    RunningCaptureEvidence,
    SbxCleanupPending,
    SbxResultError,
    SbxResultPlan,
    SbxRunBinding,
    StopCleanupEvidence,
    usage_event_stream_tree_sha256,
    verify_sbx_result_fixture,
)

SBX_WHOLE_CYCLE_ENABLED: Final = False
"""Permanent source gate; neither configuration nor fixture data can enable it."""

# Compatibility spelling for callers that describe the release gate rather
# than the boundary.  It is deliberately an alias, not a configurable value.
DOCKER_SANDBOX_CYCLE_ENABLED: Final = SBX_WHOLE_CYCLE_ENABLED

SBX_V035_WHOLE_CYCLE_ATTESTATION_AVAILABLE: Final = False
"""Activation blocker: v0.35 cannot attest the full run/capture/cleanup chain."""

CURRENT_SBX_CYCLE_ACTIVATION_BLOCKERS: Final = (
    "daemon UUID/generation attestation is unavailable",
    "identity-bound destruction attestation is unavailable",
    "post-stop export is unavailable; fixed sbx cp is transport only",
    "whole-cycle durable ledger anchor is unavailable",
)

WHOLE_CYCLE_TOKEN_CAP: Final = RUN_TOKEN_CAP
WHOLE_CYCLE_TIMEOUT_NS: Final = 45 * 60 * 1_000_000_000
CLEANUP_START_BY_NS: Final = 43 * 60 * 1_000_000_000
CAPTURE_BEFORE_STOP_NS: Final = FIXED_CAPTURE_DEADLINE_MS * 1_000_000
_HEX64 = frozenset("0123456789abcdef")


class SbxCycleError(RuntimeError):
    """The fixture whole-cycle chain is malformed, replayed, or out of order."""


class SbxCycleDisabled(SbxCycleError):
    """The source-disabled production entry rejected before argument access."""


class SbxCycleCleanupPending(SbxCycleError):
    """A failure or ambiguous cleanup makes the cycle non-finalizable."""


class CyclePhase(StrEnum):
    READY = "ready"
    CALL_RESERVED = "call_reserved"
    STAGE_RESERVED = "stage_reserved"
    PLANNING_DONE = "planning_done"
    IMPLEMENTATION_DONE = "implementation_done"
    VERIFICATION_DONE = "verification_done"
    PATCH_CAPTURED = "patch_captured"
    CLEANUP_REQUIRED = "cleanup_required"
    REJECTED_CLEAN = "rejected_clean"
    WORKER_CLEANED = "worker_cleaned"
    HANDOFF_READY = "handoff_ready"
    CLEANUP_PENDING = "cleanup_pending"


def _sha256(value: object) -> str:
    try:
        raw = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SbxCycleError("cycle value cannot be canonicalized") from exc
    return hashlib.sha256(raw).hexdigest()


def _hex(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise SbxCycleError(f"{label} is not a canonical SHA-256 digest")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SbxCycleError(f"{label} is invalid")
    return value


def _stage_limit(stage: object, call_index: object, label: str):
    if type(stage) is not ExecutionStage or type(call_index) is not int:
        raise SbxCycleError(f"{label} stage or call index is invalid")
    if not 0 <= call_index < len(STAGE_LIMITS) or STAGE_LIMITS[call_index].stage is not stage:
        raise SbxCycleError(f"{label} call index is not fixed for its stage")
    return STAGE_LIMITS[call_index]


class FixtureSbxCycleCapability:
    """Singleton marker for pure cycle fixtures; never production authority."""

    __slots__ = ("_identity",)

    def __init__(self, identity: object) -> None:
        if identity is not _FIXTURE_IDENTITY:
            raise SbxCycleError("fixture sbx-cycle capability is not constructible")
        self._identity = identity


_FIXTURE_IDENTITY = object()
_FIXTURE_CAPABILITY = FixtureSbxCycleCapability(_FIXTURE_IDENTITY)


def fixture_sbx_cycle_capability() -> FixtureSbxCycleCapability:
    """Return the sole non-authoritative cycle-fixture marker."""

    return _FIXTURE_CAPABILITY


def _require_capability(value: object) -> None:
    if (
        type(value) is not FixtureSbxCycleCapability
        or value is not _FIXTURE_CAPABILITY
        or value._identity is not _FIXTURE_IDENTITY
    ):
        raise SbxCycleError("fixture sbx-cycle capability is invalid")


def _cross_check_plan(plan: object) -> SbxResultPlan:
    if type(plan) is not SbxResultPlan:
        raise SbxCycleError("result plan is not an exact fixture type")
    if type(plan.binding) is not SbxRunBinding:
        raise SbxCycleError("result plan binding is not an exact fixture type")
    binding = SbxRunBinding(
        daemon_sandbox_uuid=plan.binding.daemon_sandbox_uuid,
        daemon_sandbox_generation=plan.binding.daemon_sandbox_generation,
        controller_sandbox_name=plan.binding.controller_sandbox_name,
        controller_run_id=plan.binding.controller_run_id,
        repository=plan.binding.repository,
        issue_number=plan.binding.issue_number,
        base_sha=plan.binding.base_sha,
        source_manifest_sha256=plan.binding.source_manifest_sha256,
        policy_epoch=plan.binding.policy_epoch,
        policy_sha256=plan.binding.policy_sha256,
        secret_epoch=plan.binding.secret_epoch,
        secret_inventory_sha256=plan.binding.secret_inventory_sha256,
        model=plan.binding.model,
        reasoning_effort=plan.binding.reasoning_effort,
        total_token_cap=plan.binding.total_token_cap,
    )
    # Rebuild to defend against in-process frozen-dataclass mutation.
    return SbxResultPlan(
        binding=binding,
        controller_uid=plan.controller_uid,
        controller_boot_sha256=plan.controller_boot_sha256,
        freshness_challenge_sha256=plan.freshness_challenge_sha256,
        verifier_identity_sha256=plan.verifier_identity_sha256,
        verification_profile_sha256=plan.verification_profile_sha256,
        required_check_ids=plan.required_check_ids,
        max_changed_files=plan.max_changed_files,
        max_changed_lines=plan.max_changed_lines,
        forbidden_paths=plan.forbidden_paths,
    )


def _cross_check_inspection(value: object) -> SbxInspectionAttestation:
    if type(value) is not SbxInspectionAttestation:
        raise SbxCycleError("inspection is not an exact fixture type")
    # The fixed argv helper revalidates the private adapter seal and all
    # canonical inspection fields without touching a daemon or a path.
    fixed_sbx_codex_argv(value)
    return value


@dataclass(frozen=True, slots=True)
class SbxWholeCyclePlan:
    """One immutable worker identity, result plan, and 45-minute lifecycle."""

    result_plan: SbxResultPlan
    inspection: SbxInspectionAttestation
    run_started_monotonic_ns: int

    def __post_init__(self) -> None:
        result = _cross_check_plan(self.result_plan)
        inspection = _cross_check_inspection(self.inspection)
        _integer(self.run_started_monotonic_ns, "cycle run start", minimum=1)
        binding = result.binding
        if not (
            inspection.controller.run_id == binding.controller_run_id
            and inspection.controller.name == binding.controller_sandbox_name
            and inspection.daemon.controller_name == binding.controller_sandbox_name
            and inspection.daemon.opaque_uuid == binding.daemon_sandbox_uuid
            and inspection.daemon.generation == binding.daemon_sandbox_generation
            and inspection.policy_epoch_sha256 == binding.policy_sha256
            and inspection.secret_epoch_sha256 == binding.secret_inventory_sha256
            and binding.model == "gpt-5.6-terra"
            and binding.reasoning_effort == "high"
            and binding.total_token_cap == WHOLE_CYCLE_TOKEN_CAP
        ):
            raise SbxCycleError("result binding does not exactly match the inspected sandbox")
        # Retain the validation-only reconstructed plan if the caller mutated it.
        object.__setattr__(self, "result_plan", result)

    @property
    def binding_sha256(self) -> str:
        return self.result_plan.binding.sha256

    @property
    def inspection_sha256(self) -> str:
        return self.inspection.canonical_sha256

    @property
    def controller_boot_sha256(self) -> str:
        return self.result_plan.controller_boot_sha256


@dataclass(frozen=True, slots=True)
class SbxWholeRunReservationReceipt:
    """Durable-ledger-shaped whole-run reservation, fixture data only."""

    binding_sha256: str
    inspection_sha256: str
    controller_boot_sha256: str
    stage_token_caps: tuple[int, int, int]
    total_token_cap: int
    genesis_head_sha256: str
    reservation_head_sha256: str
    fsync_confirmed: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_sha256, "run reservation binding"),
            (self.inspection_sha256, "run reservation inspection"),
            (self.controller_boot_sha256, "run reservation boot"),
            (self.genesis_head_sha256, "run ledger genesis head"),
            (self.reservation_head_sha256, "run ledger reservation head"),
        ):
            _hex(value, label)
        if self.stage_token_caps != tuple(limit.total_token_cap for limit in STAGE_LIMITS):
            raise SbxCycleError("whole-run reservation does not use fixed stage token caps")
        if self.total_token_cap != WHOLE_CYCLE_TOKEN_CAP:
            raise SbxCycleError("whole-run reservation does not reserve exactly 55k tokens")
        if type(self.fsync_confirmed) is not bool or not self.fsync_confirmed:
            raise SbxCycleError("whole-run reservation is not fsync-confirmed")
        if self.genesis_head_sha256 == self.reservation_head_sha256:
            raise SbxCycleError("whole-run reservation did not advance the durable ledger")


@dataclass(frozen=True, slots=True)
class SbxStageReservationReceipt:
    """Fsynced stage reservation that must exist before a call may launch."""

    binding_sha256: str
    inspection_sha256: str
    controller_boot_sha256: str
    stage: ExecutionStage
    call_index: int
    execution_plan_sha256: str
    previous_head_sha256: str
    reservation_head_sha256: str
    reserved_tokens: int
    fsync_confirmed: bool

    def __post_init__(self) -> None:
        limit = _stage_limit(self.stage, self.call_index, "stage reservation")
        for value, label in (
            (self.binding_sha256, "stage reservation binding"),
            (self.inspection_sha256, "stage reservation inspection"),
            (self.controller_boot_sha256, "stage reservation boot"),
            (self.execution_plan_sha256, "stage reservation execution plan"),
            (self.previous_head_sha256, "stage reservation previous head"),
            (self.reservation_head_sha256, "stage reservation new head"),
        ):
            _hex(value, label)
        if self.previous_head_sha256 == self.reservation_head_sha256:
            raise SbxCycleError("stage reservation did not advance the ledger")
        if self.reserved_tokens != limit.total_token_cap:
            raise SbxCycleError("stage reservation must charge the full fixed call cap")
        if type(self.fsync_confirmed) is not bool or not self.fsync_confirmed:
            raise SbxCycleError("stage reservation is not fsync-confirmed")


@dataclass(frozen=True, slots=True)
class SbxStageLedgerReceipt:
    """Fsynced settlement appended after one previously reserved call."""

    binding_sha256: str
    inspection_sha256: str
    controller_boot_sha256: str
    stage: ExecutionStage
    call_index: int
    execution_plan_sha256: str
    raw_event_jsonl_sha256: str
    previous_head_sha256: str
    reservation_head_sha256: str
    settlement_head_sha256: str
    settled_usage: ExactCallUsage
    fsync_confirmed: bool

    def __post_init__(self) -> None:
        _stage_limit(self.stage, self.call_index, "stage settlement")
        for value, label in (
            (self.binding_sha256, "stage settlement binding"),
            (self.inspection_sha256, "stage settlement inspection"),
            (self.controller_boot_sha256, "stage settlement boot"),
            (self.execution_plan_sha256, "stage settlement execution plan"),
            (self.raw_event_jsonl_sha256, "stage settlement JSONL"),
            (self.previous_head_sha256, "stage settlement previous head"),
            (self.reservation_head_sha256, "stage settlement reservation head"),
            (self.settlement_head_sha256, "stage settlement new head"),
        ):
            _hex(value, label)
        if (
            len(
                {
                    self.previous_head_sha256,
                    self.reservation_head_sha256,
                    self.settlement_head_sha256,
                }
            )
            != 3
        ):
            raise SbxCycleError("stage settlement heads do not advance uniquely")
        if type(self.settled_usage) is not ExactCallUsage:
            raise SbxCycleError("stage settlement needs exact typed usage")
        if (
            self.settled_usage.stage is not self.stage
            or self.settled_usage.call_index != self.call_index
            or self.settled_usage.event_stream_sha256 != self.raw_event_jsonl_sha256
        ):
            raise SbxCycleError("stage settlement does not bind its stage or raw JSONL")
        if type(self.fsync_confirmed) is not bool or not self.fsync_confirmed:
            raise SbxCycleError("stage settlement is not fsync-confirmed")


@dataclass(frozen=True, slots=True)
class SbxStageCompletionReceipt:
    """Bounded execution observation for one already-reserved model call."""

    binding_sha256: str
    inspection_sha256: str
    controller_boot_sha256: str
    execution_plan_sha256: str
    stage: ExecutionStage
    call_index: int
    started_monotonic_ns: int
    finished_monotonic_ns: int
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    exit_code: int
    timed_out: bool
    truncated: bool
    process_reaped: bool
    usage: ExactCallUsage
    previous_ledger_head_sha256: str
    reservation_ledger_head_sha256: str
    settlement_ledger_head_sha256: str

    def __post_init__(self) -> None:
        limit = _stage_limit(self.stage, self.call_index, "stage completion")
        for value, label in (
            (self.binding_sha256, "completion binding"),
            (self.inspection_sha256, "completion inspection"),
            (self.controller_boot_sha256, "completion boot"),
            (self.execution_plan_sha256, "completion plan"),
            (self.stdout_sha256, "stdout digest"),
            (self.stderr_sha256, "stderr digest"),
            (self.previous_ledger_head_sha256, "completion previous ledger head"),
            (self.reservation_ledger_head_sha256, "completion reservation ledger head"),
            (self.settlement_ledger_head_sha256, "completion settlement ledger head"),
        ):
            _hex(value, label)
        _integer(self.started_monotonic_ns, "completion start", minimum=1)
        _integer(self.finished_monotonic_ns, "completion finish", minimum=1)
        _integer(self.stdout_bytes, "stdout bytes", maximum=limit.combined_output_bytes)
        _integer(self.stderr_bytes, "stderr bytes", maximum=limit.combined_output_bytes)
        if self.stdout_bytes + self.stderr_bytes > limit.combined_output_bytes:
            raise SbxCycleError("completion output exceeds fixed combined output cap")
        _integer(self.exit_code, "completion exit", minimum=-255, maximum=255)
        for value, label in (
            (self.timed_out, "timeout"),
            (self.truncated, "truncation"),
            (self.process_reaped, "process reap"),
        ):
            if type(value) is not bool:
                raise SbxCycleError(f"completion {label} is not an exact boolean")
        if (
            len(
                {
                    self.previous_ledger_head_sha256,
                    self.reservation_ledger_head_sha256,
                    self.settlement_ledger_head_sha256,
                }
            )
            != 3
        ):
            raise SbxCycleError("completion ledger heads do not advance uniquely")
        if type(self.usage) is not ExactCallUsage:
            raise SbxCycleError("completion needs exact call usage")
        if self.usage.stage is not self.stage or self.usage.call_index != self.call_index:
            raise SbxCycleError("completion usage does not bind its fixed stage")
        if self.stdout_sha256 != self.usage.event_stream_sha256:
            raise SbxCycleError("stdout digest does not bind exact controller-parsed JSONL")


_STATE_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class SbxCycleState:
    """Sealed immutable state; every transition revalidates the entire chain."""

    plan: SbxWholeCyclePlan
    phase: CyclePhase
    reservation: SbxWholeRunReservationReceipt | None
    stage_reservations: tuple[SbxStageReservationReceipt, ...]
    settlements: tuple[SbxStageLedgerReceipt, ...]
    completions: tuple[SbxStageCompletionReceipt, ...]
    pending_stage: SbxStageReservationReceipt | None
    capture: RunningCaptureEvidence | None
    cleanup: StopCleanupEvidence | None
    cleanup_reason: str | None
    conservative_charged_tokens: int
    _seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        plan: SbxWholeCyclePlan,
        phase: CyclePhase,
        reservation: SbxWholeRunReservationReceipt | None,
        stage_reservations: tuple[SbxStageReservationReceipt, ...],
        settlements: tuple[SbxStageLedgerReceipt, ...],
        completions: tuple[SbxStageCompletionReceipt, ...],
        pending_stage: SbxStageReservationReceipt | None,
        capture: RunningCaptureEvidence | None,
        cleanup: StopCleanupEvidence | None,
        cleanup_reason: str | None,
        conservative_charged_tokens: int,
        seal: object,
    ) -> None:
        if seal is not _STATE_SEAL:
            raise SbxCycleError("cycle state requires fixture transition authority")
        for name, value in (
            ("plan", plan),
            ("phase", phase),
            ("reservation", reservation),
            ("stage_reservations", stage_reservations),
            ("settlements", settlements),
            ("completions", completions),
            ("pending_stage", pending_stage),
            ("capture", capture),
            ("cleanup", cleanup),
            ("cleanup_reason", cleanup_reason),
            ("conservative_charged_tokens", conservative_charged_tokens),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_seal", seal)
        _validate_state(self)


def _state(
    previous: SbxCycleState | None = None,
    **changes: object,
) -> SbxCycleState:
    values: dict[str, object] = {
        "plan": previous.plan if previous is not None else changes.pop("plan"),
        "phase": previous.phase if previous is not None else CyclePhase.READY,
        "reservation": previous.reservation if previous is not None else None,
        "stage_reservations": previous.stage_reservations if previous is not None else (),
        "settlements": previous.settlements if previous is not None else (),
        "completions": previous.completions if previous is not None else (),
        "pending_stage": previous.pending_stage if previous is not None else None,
        "capture": previous.capture if previous is not None else None,
        "cleanup": previous.cleanup if previous is not None else None,
        "cleanup_reason": previous.cleanup_reason if previous is not None else None,
        "conservative_charged_tokens": (
            previous.conservative_charged_tokens if previous is not None else 0
        ),
    }
    unknown = set(changes).difference(values)
    if unknown:
        raise SbxCycleError("cycle transition contains unknown state fields")
    values.update(changes)
    return SbxCycleState(**values, seal=_STATE_SEAL)  # type: ignore[arg-type]


def _validated_usage(usage: object) -> ExactCallUsage:
    if type(usage) is not ExactCallUsage:
        raise SbxCycleError("state usage is not an exact typed call receipt")
    try:
        rebuilt = ExactCallUsage(
            stage=usage.stage,
            call_index=usage.call_index,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cached_input_tokens=usage.cached_input_tokens,
            cache_write_input_tokens=usage.cache_write_input_tokens,
            reasoning_tokens=usage.reasoning_tokens,
            total_tokens=usage.total_tokens,
            source=usage.source,
            exact=usage.exact,
            event_stream_sha256=usage.event_stream_sha256,
            thread_id=usage.thread_id,
            reservation_sha256=usage.reservation_sha256,
        )
    except SbxResultError as exc:
        raise SbxCycleError("stored exact usage no longer validates") from exc
    if rebuilt != usage:
        raise SbxCycleError("stored exact usage changed after validation")
    return rebuilt


def _validate_state(state: object) -> SbxCycleState:
    """Revalidate all state facts and links, including after object mutation."""

    if type(state) is not SbxCycleState:
        raise SbxCycleError("cycle state is not an exact fixture type")
    try:
        seal = state._seal
    except AttributeError as exc:
        raise SbxCycleError("cycle state is unsealed") from exc
    if seal is not _STATE_SEAL:
        raise SbxCycleError("cycle state is unsealed")
    try:
        rebuilt_plan = SbxWholeCyclePlan(
            state.plan.result_plan,
            state.plan.inspection,
            state.plan.run_started_monotonic_ns,
        )
    except (AttributeError, SbxCycleError, SbxResultError) as exc:
        raise SbxCycleError("stored whole-cycle plan no longer validates") from exc
    if rebuilt_plan != state.plan or type(state.phase) is not CyclePhase:
        raise SbxCycleError("stored plan or phase changed after validation")

    if state.reservation is not None:
        if type(state.reservation) is not SbxWholeRunReservationReceipt:
            raise SbxCycleError("stored whole-run reservation has an invalid type")
        rebuilt_run = SbxWholeRunReservationReceipt(
            state.reservation.binding_sha256,
            state.reservation.inspection_sha256,
            state.reservation.controller_boot_sha256,
            state.reservation.stage_token_caps,
            state.reservation.total_token_cap,
            state.reservation.genesis_head_sha256,
            state.reservation.reservation_head_sha256,
            state.reservation.fsync_confirmed,
        )
        if rebuilt_run != state.reservation or not (
            rebuilt_run.binding_sha256 == state.plan.binding_sha256
            and rebuilt_run.inspection_sha256 == state.plan.inspection_sha256
            and rebuilt_run.controller_boot_sha256 == state.plan.controller_boot_sha256
        ):
            raise SbxCycleError("stored whole-run reservation has binding drift")

    if (
        type(state.stage_reservations) is not tuple
        or type(state.settlements) is not tuple
        or type(state.completions) is not tuple
        or len(state.stage_reservations) > MAX_MODEL_CALLS
        or len(state.settlements) != len(state.completions)
        or len(state.settlements) > len(state.stage_reservations)
    ):
        raise SbxCycleError("stored stage chain has invalid lengths or container types")
    if state.reservation is None and (
        state.stage_reservations or state.settlements or state.completions
    ):
        raise SbxCycleError("stage chain exists without a whole-run reservation")

    previous_head = (
        state.reservation.reservation_head_sha256 if state.reservation is not None else None
    )
    for index, reservation in enumerate(state.stage_reservations):
        if type(reservation) is not SbxStageReservationReceipt:
            raise SbxCycleError("stored stage reservation has an invalid type")
        rebuilt = SbxStageReservationReceipt(
            reservation.binding_sha256,
            reservation.inspection_sha256,
            reservation.controller_boot_sha256,
            reservation.stage,
            reservation.call_index,
            reservation.execution_plan_sha256,
            reservation.previous_head_sha256,
            reservation.reservation_head_sha256,
            reservation.reserved_tokens,
            reservation.fsync_confirmed,
        )
        if rebuilt != reservation or not (
            reservation.call_index == index
            and reservation.binding_sha256 == state.plan.binding_sha256
            and reservation.inspection_sha256 == state.plan.inspection_sha256
            and reservation.controller_boot_sha256 == state.plan.controller_boot_sha256
            and reservation.previous_head_sha256 == previous_head
        ):
            raise SbxCycleError("stored stage reservation is replayed, skipped, or drifted")
        if index < len(state.settlements):
            settlement = state.settlements[index]
            completion = state.completions[index]
            usage = _validated_usage(settlement.settled_usage)
            rebuilt_settlement = SbxStageLedgerReceipt(
                settlement.binding_sha256,
                settlement.inspection_sha256,
                settlement.controller_boot_sha256,
                settlement.stage,
                settlement.call_index,
                settlement.execution_plan_sha256,
                settlement.raw_event_jsonl_sha256,
                settlement.previous_head_sha256,
                settlement.reservation_head_sha256,
                settlement.settlement_head_sha256,
                usage,
                settlement.fsync_confirmed,
            )
            if type(completion) is not SbxStageCompletionReceipt:
                raise SbxCycleError("stored stage completion has an invalid type")
            completion_usage = _validated_usage(completion.usage)
            rebuilt_completion = SbxStageCompletionReceipt(
                completion.binding_sha256,
                completion.inspection_sha256,
                completion.controller_boot_sha256,
                completion.execution_plan_sha256,
                completion.stage,
                completion.call_index,
                completion.started_monotonic_ns,
                completion.finished_monotonic_ns,
                completion.stdout_bytes,
                completion.stderr_bytes,
                completion.stdout_sha256,
                completion.stderr_sha256,
                completion.exit_code,
                completion.timed_out,
                completion.truncated,
                completion.process_reaped,
                completion_usage,
                completion.previous_ledger_head_sha256,
                completion.reservation_ledger_head_sha256,
                completion.settlement_ledger_head_sha256,
            )
            if rebuilt_settlement != settlement or rebuilt_completion != completion:
                raise SbxCycleError("stored settlement or completion changed after validation")
            if not (
                settlement.stage is reservation.stage is completion.stage
                and settlement.call_index == reservation.call_index == completion.call_index
                and settlement.execution_plan_sha256
                == reservation.execution_plan_sha256
                == completion.execution_plan_sha256
                and settlement.previous_head_sha256
                == reservation.previous_head_sha256
                == completion.previous_ledger_head_sha256
                and settlement.reservation_head_sha256
                == reservation.reservation_head_sha256
                == completion.reservation_ledger_head_sha256
                and settlement.settlement_head_sha256 == completion.settlement_ledger_head_sha256
                and settlement.settled_usage == completion.usage
                and completion.stdout_sha256
                == settlement.raw_event_jsonl_sha256
                == completion.usage.event_stream_sha256
            ):
                raise SbxCycleError("stored stage reservation/settlement/completion links drifted")
            if completion.usage.reservation_sha256 != state.reservation.reservation_head_sha256:
                raise SbxCycleError("stored usage does not bind the whole-run reservation")
            prior_finish = (
                state.plan.run_started_monotonic_ns
                if index == 0
                else state.completions[index - 1].finished_monotonic_ns
            )
            limit = STAGE_LIMITS[index]
            if not (
                completion.started_monotonic_ns > prior_finish
                and completion.finished_monotonic_ns > completion.started_monotonic_ns
                and completion.finished_monotonic_ns - completion.started_monotonic_ns
                <= limit.timeout_seconds * 1_000_000_000
                and completion.finished_monotonic_ns
                <= state.plan.run_started_monotonic_ns + CLEANUP_START_BY_NS
            ):
                raise SbxCycleError("stored stage timestamps overlap or exceed fixed bounds")
            previous_head = settlement.settlement_head_sha256
        else:
            previous_head = reservation.reservation_head_sha256

    pending_count = len(state.stage_reservations) - len(state.settlements)
    if pending_count not in {0, 1}:
        raise SbxCycleError("state has more than one pending stage reservation")
    expected_pending = state.stage_reservations[-1] if pending_count == 1 else None
    if state.pending_stage != expected_pending:
        raise SbxCycleError("pending stage marker does not match the durable reservation")

    calls = tuple(completion.usage for completion in state.completions)
    events = tuple(call.event_stream_sha256 for call in calls)
    threads = tuple(call.thread_id for call in calls)
    settlement_heads = tuple(item.settlement_head_sha256 for item in state.settlements)
    if (
        len(events) != len(set(events))
        or len(threads) != len(set(threads))
        or len(settlement_heads) != len(set(settlement_heads))
        or sum(call.total_tokens for call in calls) > WHOLE_CYCLE_TOKEN_CAP
    ):
        raise SbxCycleError("stored stage chain replays evidence or exceeds 55k tokens")
    expected_charge = sum(call.total_tokens for call in calls)
    if state.pending_stage is not None and state.phase in {
        CyclePhase.CLEANUP_REQUIRED,
        CyclePhase.REJECTED_CLEAN,
        CyclePhase.CLEANUP_PENDING,
    }:
        expected_charge += state.pending_stage.reserved_tokens
    if state.conservative_charged_tokens != expected_charge:
        raise SbxCycleError("conservative token charge does not match durable stage state")

    successful = all(
        item.exit_code == 0 and not item.timed_out and not item.truncated and item.process_reaped
        for item in state.completions
    )
    normal_counts = {
        CyclePhase.READY: 0,
        CyclePhase.CALL_RESERVED: 0,
        CyclePhase.PLANNING_DONE: 1,
        CyclePhase.IMPLEMENTATION_DONE: 2,
        CyclePhase.VERIFICATION_DONE: 3,
        CyclePhase.PATCH_CAPTURED: 3,
        CyclePhase.WORKER_CLEANED: 3,
        CyclePhase.HANDOFF_READY: 3,
    }
    if state.phase in normal_counts and (
        len(state.completions) != normal_counts[state.phase] or not successful
    ):
        raise SbxCycleError("cycle phase does not match its successful completion chain")
    if state.phase is CyclePhase.STAGE_RESERVED and state.pending_stage is None:
        raise SbxCycleError("stage_reserved lacks its durable pending reservation")
    if (
        state.phase is not CyclePhase.STAGE_RESERVED
        and state.pending_stage is not None
        and (
            state.phase
            not in {
                CyclePhase.CLEANUP_REQUIRED,
                CyclePhase.REJECTED_CLEAN,
                CyclePhase.CLEANUP_PENDING,
            }
        )
    ):
        raise SbxCycleError("pending reservation is reachable outside cleanup-only states")
    if state.phase is CyclePhase.READY:
        if state.reservation is not None:
            raise SbxCycleError("ready cycle already has a whole-run reservation")
    elif state.reservation is None:
        raise SbxCycleError("non-ready cycle lacks its whole-run reservation")
    if (
        state.phase
        in {
            CyclePhase.PATCH_CAPTURED,
            CyclePhase.WORKER_CLEANED,
            CyclePhase.HANDOFF_READY,
        }
        and state.capture is None
    ):
        raise SbxCycleError("successful post-capture phase lacks capture evidence")
    if (
        state.phase
        in {
            CyclePhase.WORKER_CLEANED,
            CyclePhase.HANDOFF_READY,
            CyclePhase.REJECTED_CLEAN,
            CyclePhase.CLEANUP_PENDING,
        }
        and state.cleanup is None
    ):
        raise SbxCycleError("terminal cleanup phase lacks cleanup evidence")
    if state.cleanup_reason is not None and (
        type(state.cleanup_reason) is not str
        or not state.cleanup_reason
        or len(state.cleanup_reason) > 256
    ):
        raise SbxCycleError("cleanup reason is invalid")
    return state


def new_fixture_sbx_cycle(
    plan: SbxWholeCyclePlan, *, capability: FixtureSbxCycleCapability
) -> SbxCycleState:
    _require_capability(capability)
    if type(plan) is not SbxWholeCyclePlan:
        raise SbxCycleError("whole-cycle plan is invalid")
    return _state(plan=plan)


def reserve_fixture_sbx_cycle(
    state: SbxCycleState,
    reservation: SbxWholeRunReservationReceipt,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    _require_capability(capability)
    _validate_state(state)
    if state.phase is not CyclePhase.READY:
        raise SbxCycleError("whole-run reservation is not allowed in this cycle phase")
    if type(reservation) is not SbxWholeRunReservationReceipt:
        raise SbxCycleError("whole-run reservation receipt is invalid")
    plan = state.plan
    if not (
        reservation.binding_sha256 == plan.binding_sha256
        and reservation.inspection_sha256 == plan.inspection_sha256
        and reservation.controller_boot_sha256 == plan.controller_boot_sha256
    ):
        raise SbxCycleError("whole-run reservation has a substituted binding")
    return _state(state, phase=CyclePhase.CALL_RESERVED, reservation=reservation)


def _stage_phase(count: int) -> CyclePhase:
    return (CyclePhase.PLANNING_DONE, CyclePhase.IMPLEMENTATION_DONE, CyclePhase.VERIFICATION_DONE)[
        count - 1
    ]


def _validated_execution_plan(value: object) -> SbxExecutionPlan:
    try:
        return validate_fixture_execution_plan(value)
    except Exception as exc:
        raise SbxCycleError("execution plan is not a sealed exact fixture plan") from exc


def reserve_fixture_stage(
    state: SbxCycleState,
    execution_plan: SbxExecutionPlan,
    reservation: SbxStageReservationReceipt,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    """Fsync exactly the next stage reservation before any fixture launch."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase not in {
        CyclePhase.CALL_RESERVED,
        CyclePhase.PLANNING_DONE,
        CyclePhase.IMPLEMENTATION_DONE,
    }:
        raise SbxCycleError("stage reservation is replayed, skipped, or out of order")
    if type(reservation) is not SbxStageReservationReceipt or state.reservation is None:
        raise SbxCycleError("stage reservation requires an exact typed receipt")
    plan = _validated_execution_plan(execution_plan)
    index = len(state.completions)
    limit = STAGE_LIMITS[index]
    previous = (
        state.reservation.reservation_head_sha256
        if not state.settlements
        else state.settlements[-1].settlement_head_sha256
    )
    whole = state.plan
    if not (
        plan.inspection is whole.inspection
        and plan.inspection.canonical_sha256 == whole.inspection_sha256
        and plan.stage is limit.stage
        and plan.call_index == index
        and reservation.stage is limit.stage
        and reservation.call_index == index
        and reservation.binding_sha256 == whole.binding_sha256
        and reservation.inspection_sha256 == whole.inspection_sha256
        and reservation.controller_boot_sha256 == whole.controller_boot_sha256
        and reservation.execution_plan_sha256 == plan.attestation_sha256
        and reservation.previous_head_sha256 == previous
        and reservation.reservation_head_sha256
        not in {
            state.reservation.genesis_head_sha256,
            state.reservation.reservation_head_sha256,
            *(item.reservation_head_sha256 for item in state.stage_reservations),
            *(item.settlement_head_sha256 for item in state.settlements),
        }
    ):
        raise SbxCycleError("stage reservation has plan, binding, order, or ledger-head drift")
    return _state(
        state,
        phase=CyclePhase.STAGE_RESERVED,
        stage_reservations=state.stage_reservations + (reservation,),
        pending_stage=reservation,
    )


def crash_fixture_stage(
    state: SbxCycleState,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    """Quarantine one pending reservation with no invented settlement or usage."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase is not CyclePhase.STAGE_RESERVED or state.pending_stage is None:
        raise SbxCycleError("only an exact pending stage reservation can crash")
    return _state(
        state,
        phase=CyclePhase.CLEANUP_REQUIRED,
        cleanup_reason="pending stage crashed; full fixed cap charged and retry forbidden",
        conservative_charged_tokens=(
            state.conservative_charged_tokens + state.pending_stage.reserved_tokens
        ),
    )


def complete_fixture_stage(
    state: SbxCycleState,
    execution_plan: SbxExecutionPlan,
    ledger: SbxStageLedgerReceipt,
    completion: SbxStageCompletionReceipt,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    """Settle the exact pending reservation once; failures permit only cleanup."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase is not CyclePhase.STAGE_RESERVED or state.pending_stage is None:
        raise SbxCycleError("stage completion has no exact pending reservation")
    if (
        type(ledger) is not SbxStageLedgerReceipt
        or type(completion) is not SbxStageCompletionReceipt
    ):
        raise SbxCycleError("stage settlement or completion receipt has an invalid type")
    plan = _validated_execution_plan(execution_plan)
    pending = state.pending_stage
    whole = state.plan
    if not (
        plan.inspection is whole.inspection
        and plan.attestation_sha256 == pending.execution_plan_sha256
        and ledger.binding_sha256 == pending.binding_sha256 == completion.binding_sha256
        and ledger.inspection_sha256 == pending.inspection_sha256 == completion.inspection_sha256
        and ledger.controller_boot_sha256
        == pending.controller_boot_sha256
        == completion.controller_boot_sha256
        and ledger.stage is pending.stage is completion.stage is plan.stage
        and ledger.call_index == pending.call_index == completion.call_index == plan.call_index
        and ledger.execution_plan_sha256
        == pending.execution_plan_sha256
        == completion.execution_plan_sha256
        and ledger.previous_head_sha256
        == pending.previous_head_sha256
        == completion.previous_ledger_head_sha256
        and ledger.reservation_head_sha256
        == pending.reservation_head_sha256
        == completion.reservation_ledger_head_sha256
        and ledger.settlement_head_sha256 == completion.settlement_ledger_head_sha256
        and ledger.settled_usage == completion.usage
        and completion.stdout_sha256
        == ledger.raw_event_jsonl_sha256
        == completion.usage.event_stream_sha256
    ):
        raise SbxCycleError("settlement does not exactly bind the pending stage reservation")
    if (
        state.reservation is None
        or completion.usage.reservation_sha256 != state.reservation.reservation_head_sha256
    ):
        raise SbxCycleError("stage usage does not bind the whole-run reservation")
    if ledger.settlement_head_sha256 in {
        state.reservation.genesis_head_sha256,
        state.reservation.reservation_head_sha256,
        *(item.reservation_head_sha256 for item in state.stage_reservations),
        *(item.settlement_head_sha256 for item in state.settlements),
    }:
        raise SbxCycleError("stage settlement replays an earlier durable ledger head")
    prior_finish = (
        whole.run_started_monotonic_ns
        if not state.completions
        else state.completions[-1].finished_monotonic_ns
    )
    limit = STAGE_LIMITS[pending.call_index]
    if not (
        completion.started_monotonic_ns > prior_finish
        and completion.finished_monotonic_ns > completion.started_monotonic_ns
        and completion.finished_monotonic_ns - completion.started_monotonic_ns
        <= limit.timeout_seconds * 1_000_000_000
        and completion.finished_monotonic_ns <= whole.run_started_monotonic_ns + CLEANUP_START_BY_NS
    ):
        raise SbxCycleError("stage completion timestamps overlap or exceed fixed bounds")
    settlements = state.settlements + (ledger,)
    completions = state.completions + (completion,)
    charged = state.conservative_charged_tokens + completion.usage.total_tokens
    failed = (
        completion.exit_code != 0
        or completion.timed_out
        or completion.truncated
        or not completion.process_reaped
    )
    return _state(
        state,
        phase=CyclePhase.CLEANUP_REQUIRED if failed else _stage_phase(len(completions)),
        settlements=settlements,
        completions=completions,
        pending_stage=None,
        cleanup_reason="settled stage failed; retry forbidden" if failed else None,
        conservative_charged_tokens=charged,
    )


def capture_fixture_patch(
    state: SbxCycleState,
    capture: RunningCaptureEvidence,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    """Record opaque capture only; no patch bytes are accepted or parsed here."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase is not CyclePhase.VERIFICATION_DONE:
        raise SbxCycleError("patch capture requires all three exact stage completions")
    if type(capture) is not RunningCaptureEvidence:
        raise SbxCycleError("capture evidence is invalid")
    if not (
        capture.binding_sha256 == state.plan.binding_sha256
        and capture.controller_boot_sha256 == state.plan.controller_boot_sha256
        and capture.capture_deadline_ms == FIXED_CAPTURE_DEADLINE_MS
        and capture.destination_quota_bytes == MAX_CAPTURE_BYTES
        and capture.capture_started_monotonic_ns > state.completions[-1].finished_monotonic_ns
        and capture.capture_started_monotonic_ns
        < state.plan.run_started_monotonic_ns + CLEANUP_START_BY_NS
        and capture.capture_finished_monotonic_ns > capture.capture_started_monotonic_ns
        and capture.capture_finished_monotonic_ns
        <= state.plan.run_started_monotonic_ns + CLEANUP_START_BY_NS
        and (
            capture.capture_finished_monotonic_ns - capture.capture_started_monotonic_ns
            <= CAPTURE_BEFORE_STOP_NS
        )
        and capture.patch_bytes <= MAX_CAPTURE_BYTES
        and capture.opened_nofollow
        and capture.descriptor_cloexec
        and capture.fixed_cp_used
        and not capture.follow_links
        and not capture.generic_cp_used
        and not capture.issue_controlled_path_used
        and capture.sandbox_running_before
        and capture.sandbox_running_after
        and capture.destination_regular_files
        and capture.destination_unaliased_files
        and capture.destination_quota_enforced
        and capture.capture_deadline_enforced
        and capture.capture_process_reaped
        and capture.bytes_unparsed
    ):
        raise SbxCycleError("capture evidence is not opaque, fixed, and plan-bound")
    return _state(state, phase=CyclePhase.PATCH_CAPTURED, capture=capture)


def require_fixture_cleanup(
    state: SbxCycleState,
    reason: str,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    """Failure path: it cannot retry work and can only proceed to cleanup."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase in {
        CyclePhase.WORKER_CLEANED,
        CyclePhase.HANDOFF_READY,
        CyclePhase.CLEANUP_PENDING,
        CyclePhase.REJECTED_CLEAN,
    }:
        raise SbxCycleError("cleanup cannot replace a terminal cycle state")
    if type(reason) is not str or not reason or len(reason) > 256:
        raise SbxCycleError("cleanup reason is invalid")
    charged = state.conservative_charged_tokens
    if state.pending_stage is not None and state.phase is CyclePhase.STAGE_RESERVED:
        charged += state.pending_stage.reserved_tokens
    return _state(
        state,
        phase=CyclePhase.CLEANUP_REQUIRED,
        cleanup_reason=reason,
        conservative_charged_tokens=charged,
    )


def cleanup_fixture_worker(
    state: SbxCycleState,
    cleanup: StopCleanupEvidence,
    *,
    capability: FixtureSbxCycleCapability,
) -> SbxCycleState:
    """Validate stop/cleanup evidence; ambiguity becomes terminal cleanup_pending."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase not in {
        CyclePhase.PATCH_CAPTURED,
        CyclePhase.CLEANUP_REQUIRED,
    }:
        raise SbxCycleError("worker cleanup is not allowed in this cycle phase")
    if type(cleanup) is not StopCleanupEvidence:
        raise SbxCycleError("cleanup evidence is invalid")
    plan = state.plan
    ambiguous = not (
        cleanup.binding_sha256 == plan.binding_sha256
        and cleanup.controller_boot_sha256 == plan.controller_boot_sha256
        and cleanup.stop_returncode == 0
        and cleanup.remove_returncode == 0
        and cleanup.stop_acknowledged
        and cleanup.removal_acknowledged
        and cleanup.exact_name_absent
        and cleanup.sandbox_instance_absent
        and cleanup.identity_authority_independent
        and cleanup.destruction_authority_independent
        and cleanup.uncertainty_reason is None
        and cleanup.cleanup_observed_monotonic_ns > cleanup.stop_observed_monotonic_ns
        and cleanup.stop_observed_monotonic_ns
        <= plan.run_started_monotonic_ns + CLEANUP_START_BY_NS
        and cleanup.cleanup_observed_monotonic_ns
        <= plan.run_started_monotonic_ns + WHOLE_CYCLE_TIMEOUT_NS
    )
    if state.capture is not None:
        capture = state.capture
        ambiguous = ambiguous or not (
            capture.capture_started_monotonic_ns >= plan.run_started_monotonic_ns
            and capture.capture_finished_monotonic_ns > capture.capture_started_monotonic_ns
            and capture.capture_finished_monotonic_ns < cleanup.stop_observed_monotonic_ns
            and cleanup.stop_observed_monotonic_ns - capture.capture_finished_monotonic_ns
            <= CAPTURE_BEFORE_STOP_NS
        )
    if ambiguous:
        return _state(
            state,
            phase=CyclePhase.CLEANUP_PENDING,
            cleanup=cleanup,
            cleanup_reason="cleanup unproven",
        )
    terminal = (
        CyclePhase.WORKER_CLEANED
        if state.phase is CyclePhase.PATCH_CAPTURED
        else CyclePhase.REJECTED_CLEAN
    )
    return _state(state, phase=terminal, cleanup=cleanup)


def aggregate_fixture_usage(state: SbxCycleState) -> ExactUsageReceipt:
    """Recompute the only accepted exact aggregate from immutable state calls."""

    _validate_state(state)
    if len(state.completions) != MAX_MODEL_CALLS:
        raise SbxCycleError("exact usage needs all three state-bound calls")
    calls = tuple(item.usage for item in state.completions)
    if state.reservation is None:
        raise SbxCycleError("state has no exact settled usage")
    exact_calls = calls
    return ExactUsageReceipt(
        calls=exact_calls,
        input_tokens=sum(call.input_tokens for call in exact_calls),
        output_tokens=sum(call.output_tokens for call in exact_calls),
        cached_input_tokens=sum(call.cached_input_tokens for call in exact_calls),
        cache_write_input_tokens=sum(call.cache_write_input_tokens for call in exact_calls),
        reasoning_tokens=sum(call.reasoning_tokens for call in exact_calls),
        total_tokens=sum(call.total_tokens for call in exact_calls),
        source="codex-cli-jsonl-v1",
        exact=True,
        provider_call_count=MAX_MODEL_CALLS,
        aggregate_event_stream_sha256=usage_event_stream_tree_sha256(exact_calls),
        reservation_sha256=state.reservation.reservation_head_sha256,
    )


def finalize_fixture_sbx_cycle(
    state: SbxCycleState,
    *,
    result_document: bytes,
    patch: bytes,
    verifier: object,
    controller_result: object,
    base_recheck: object,
    handoff_observed_monotonic_ns: int,
    result_fixture_capability: FixtureSbxResultCapability,
    capability: FixtureSbxCycleCapability,
) -> tuple[SbxCycleState, CapabilityFreeSbxHandoff]:
    """Only a cleaned worker can invoke the post-stop fixture verifier."""

    _require_capability(capability)
    _validate_state(state)
    if state.phase is not CyclePhase.WORKER_CLEANED:
        raise SbxCycleError("only worker_cleaned may finalize a whole cycle")
    if state.cleanup is None or state.capture is None:
        raise SbxCycleError("finalization lacks required capture or cleanup evidence")
    usage = aggregate_fixture_usage(state)
    try:
        handoff = verify_sbx_result_fixture(
            state.plan.result_plan,
            result_document=result_document,
            patch=patch,
            cleanup=state.cleanup,
            capture=state.capture,
            verifier=verifier,  # type: ignore[arg-type]
            controller_result=controller_result,  # type: ignore[arg-type]
            base_recheck=base_recheck,  # type: ignore[arg-type]
            handoff_observed_monotonic_ns=handoff_observed_monotonic_ns,
            fixture_capability=result_fixture_capability,
        )
    except SbxCleanupPending as exc:
        raise SbxCycleCleanupPending("post-stop verifier reports cleanup_pending") from exc
    except SbxResultError as exc:
        raise SbxCycleError("post-stop result verifier rejected the state-bound handoff") from exc
    if handoff.binding != state.plan.result_plan.binding or handoff.usage != usage:
        raise SbxCycleError("post-stop handoff substituted binding or aggregate exact usage")
    return _state(state, phase=CyclePhase.HANDOFF_READY), handoff


def execute_live_sbx_cycle(*_args: object, **_kwargs: object) -> Never:
    """Reject production before argument inspection, I/O, sandbox, or provider access."""

    raise SbxCycleDisabled("Docker Sandboxes whole-cycle execution is source-disabled before input")
