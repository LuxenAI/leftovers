"""Pure, hard-disabled verifier fixture for a future strict-VM contribution cycle.

This module has intentionally *no* filesystem, subprocess, network, provider,
VM, Git, or publisher dependency.  It models the evidence that an external,
separately-reviewed controller would need to collect.  In particular, it does
not treat a guest receipt as proof that a patch is safe: a host-side verifier
must independently apply the canonical patch, inspect its diff, enforce policy,
run the curated checks, and re-read the upstream base before it can create the
capability-free handoff consumed by ``publisher.py``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

# This is a release gate, not a configuration option.  No function in this
# module can perform an epoch, clone a repository, invoke a provider/VM, or
# publish a pull request.
STRICT_VM_WHOLE_CYCLE_CAPABILITY = False

_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_GIT_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_CHECK_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")

# Tonight's unattended profile deliberately permits no repair loop. A future
# multi-round design needs a separately reviewed state transition and durable
# broker accounting rather than a larger integer in this fixture.
MAX_ROUNDS = 1
MAX_TOKEN_CAP = 2_000_000
MAX_WALL_TIME = timedelta(hours=4)
MAX_PATCH_BYTES = 256 * 1024
MAX_REPOSITORY_LENGTH = 140


class StrictVMCycleError(RuntimeError):
    """Evidence is incomplete, inconsistent, or exceeds a bounded cycle."""


class StrictVMCycleDisabled(StrictVMCycleError):
    """The source-level production gate rejects an attempted live cycle."""


class CyclePhase(StrEnum):
    READY = "ready"
    EPOCH_VERIFIED = "epoch_verified"
    CLEANUP_PENDING = "cleanup_pending"
    PUBLISH_READY = "publish_ready"
    REJECTED = "rejected"


def _require(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise StrictVMCycleError(f"{label} is invalid")
    return value


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise StrictVMCycleError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _canonical_patch(value: bytes) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > MAX_PATCH_BYTES:
        raise StrictVMCycleError("canonical patch is empty or exceeds its cap")
    if b"\0" in value or not value.endswith(b"\n"):
        raise StrictVMCycleError("canonical patch has unsafe framing")
    try:
        value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictVMCycleError("canonical patch is not UTF-8") from exc
    return value


def patch_sha256(patch: bytes) -> str:
    """Return the sole accepted digest of a bounded canonical patch."""

    return hashlib.sha256(_canonical_patch(patch)).hexdigest()


@dataclass(frozen=True)
class CyclePlan:
    """Controller-curated identity and resource bounds for exactly one issue."""

    run_id: str
    repository: str
    issue_number: int
    base_ref: str
    base_sha: str
    policy_sha256: str
    required_check_ids: tuple[str, ...]
    max_rounds: int
    token_cap: int
    deadline_at: datetime

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "run ID")
        _require(self.repository, _REPOSITORY, "repository")
        if len(self.repository) > MAX_REPOSITORY_LENGTH:
            raise StrictVMCycleError("repository is too long")
        if type(self.issue_number) is not int or self.issue_number <= 0:
            raise StrictVMCycleError("issue number is invalid")
        if not isinstance(self.base_ref, str) or not self.base_ref or len(self.base_ref) > 255:
            raise StrictVMCycleError("base ref is invalid")
        _require(self.base_sha, _GIT_SHA, "base SHA")
        _require(self.policy_sha256, _HEX64, "policy digest")
        if (
            type(self.required_check_ids) is not tuple
            or not self.required_check_ids
            or len(self.required_check_ids) > 32
            or tuple(sorted(self.required_check_ids)) != self.required_check_ids
            or len(set(self.required_check_ids)) != len(self.required_check_ids)
            or any(_CHECK_ID.fullmatch(item) is None for item in self.required_check_ids)
        ):
            raise StrictVMCycleError("required check IDs are not exact and curated")
        if type(self.max_rounds) is not int or not 1 <= self.max_rounds <= MAX_ROUNDS:
            raise StrictVMCycleError("round cap is invalid")
        if type(self.token_cap) is not int or not 1 <= self.token_cap <= MAX_TOKEN_CAP:
            raise StrictVMCycleError("token cap is invalid")
        object.__setattr__(self, "deadline_at", _utc(self.deadline_at, "deadline"))


@dataclass(frozen=True)
class MediatorReceipt:
    """A controller-validated model receipt, never model or guest authority."""

    run_id: str
    round: int
    request_sha256: str
    action_batch_sha256: str
    patch_sha256: str
    charged_tokens: int

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "mediator run ID")
        if type(self.round) is not int or not 0 <= self.round < MAX_ROUNDS:
            raise StrictVMCycleError("mediator round is invalid")
        for value, label in (
            (self.request_sha256, "mediator request digest"),
            (self.action_batch_sha256, "action batch digest"),
            (self.patch_sha256, "mediator patch digest"),
        ):
            _require(value, _HEX64, label)
        if type(self.charged_tokens) is not int or self.charged_tokens < 0:
            raise StrictVMCycleError("charged tokens are invalid")


@dataclass(frozen=True)
class StoppedGuestReceipt:
    """A bounded result accepted only after the launcher has proven VM stop."""

    run_id: str
    round: int
    request_sha256: str
    action_batch_sha256: str
    canonical_patch: bytes
    canonical_patch_sha256: str
    launcher_stop_proven: bool
    result_extracted_after_stop: bool
    cleanup_proven: bool

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "guest run ID")
        if type(self.round) is not int or not 0 <= self.round < MAX_ROUNDS:
            raise StrictVMCycleError("guest round is invalid")
        for value, label in (
            (self.request_sha256, "guest request digest"),
            (self.action_batch_sha256, "guest action digest"),
            (self.canonical_patch_sha256, "guest patch digest"),
        ):
            _require(value, _HEX64, label)
        if (
            type(self.launcher_stop_proven) is not bool
            or type(self.result_extracted_after_stop) is not bool
        ):
            raise StrictVMCycleError("guest stop evidence is invalid")
        if type(self.cleanup_proven) is not bool:
            raise StrictVMCycleError("guest cleanup evidence is invalid")
        if patch_sha256(self.canonical_patch) != self.canonical_patch_sha256:
            raise StrictVMCycleError("guest canonical patch digest does not match")


@dataclass(frozen=True)
class HostCheckEvidence:
    """Result of a host-owned, fixed-argv check after patch application."""

    check_id: str
    exit_code: int | None
    timed_out: bool
    truncated: bool

    def __post_init__(self) -> None:
        _require(self.check_id, _CHECK_ID, "host check ID")
        if type(self.timed_out) is not bool or type(self.truncated) is not bool:
            raise StrictVMCycleError("host check status is invalid")
        if self.timed_out:
            if self.exit_code is not None:
                raise StrictVMCycleError("timed-out host check may not have an exit code")
        elif type(self.exit_code) is not int or not -255 <= self.exit_code <= 255:
            raise StrictVMCycleError("host check exit code is invalid")


@dataclass(frozen=True)
class IndependentHostReceipt:
    """Independent host result; it intentionally contains no guest/model authority."""

    run_id: str
    base_sha_observed: str
    applied_patch_sha256: str
    inspected_diff_sha256: str
    policy_sha256: str
    policy_allowed: bool
    review_unresolved: bool
    checks: tuple[HostCheckEvidence, ...]

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "host run ID")
        for value, label, pattern in (
            (self.base_sha_observed, "observed base SHA", _GIT_SHA),
            (self.applied_patch_sha256, "applied patch digest", _HEX64),
            (self.inspected_diff_sha256, "inspected diff digest", _HEX64),
            (self.policy_sha256, "host policy digest", _HEX64),
        ):
            _require(value, pattern, label)
        if type(self.policy_allowed) is not bool or type(self.review_unresolved) is not bool:
            raise StrictVMCycleError("host policy/review evidence is invalid")
        if (
            type(self.checks) is not tuple
            or len(self.checks) > 32
            or any(type(item) is not HostCheckEvidence for item in self.checks)
        ):
            raise StrictVMCycleError("host check evidence is invalid")


@dataclass(frozen=True)
class FixturePublisherHandoff:
    """Capability-free fixture output after all simulated rechecks succeed.

    It deliberately omits model receipts, guest results, paths, commands,
    credentials, and any publisher instance. Constructing it cannot publish,
    and production code must never accept this caller-constructible value as
    authorization.
    """

    run_id: str
    repository: str
    issue_number: int
    base_ref: str
    base_sha: str
    patch_sha256: str
    policy_sha256: str
    check_ids: tuple[str, ...]


@dataclass(frozen=True)
class CycleState:
    plan: CyclePlan
    phase: CyclePhase
    spent_tokens: int = 0
    completed_rounds: tuple[int, ...] = ()
    patch_sha256: str | None = None
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        if type(self.plan) is not CyclePlan or type(self.phase) is not CyclePhase:
            raise StrictVMCycleError("cycle state identity is invalid")
        if type(self.spent_tokens) is not int or not 0 <= self.spent_tokens <= self.plan.token_cap:
            raise StrictVMCycleError("cycle state token accounting is invalid")
        if (
            type(self.completed_rounds) is not tuple
            or self.completed_rounds != tuple(range(len(self.completed_rounds)))
            or len(self.completed_rounds) > self.plan.max_rounds
        ):
            raise StrictVMCycleError("cycle state rounds are invalid")
        if self.patch_sha256 is not None:
            _require(self.patch_sha256, _HEX64, "cycle state patch digest")
        if self.rejection_reason is not None and (
            not isinstance(self.rejection_reason, str)
            or not self.rejection_reason
            or len(self.rejection_reason) > 256
            or any(character in self.rejection_reason for character in "\r\n\0")
        ):
            raise StrictVMCycleError("cycle state rejection reason is invalid")
        if self.phase is CyclePhase.READY and (
            self.spent_tokens != 0
            or self.completed_rounds
            or self.patch_sha256 is not None
            or self.rejection_reason is not None
        ):
            raise StrictVMCycleError("ready cycle state contains forged progress")
        if self.phase in {CyclePhase.EPOCH_VERIFIED, CyclePhase.PUBLISH_READY} and (
            not self.completed_rounds
            or self.patch_sha256 is None
            or self.rejection_reason is not None
        ):
            raise StrictVMCycleError("verified cycle state is incomplete")
        if self.phase is CyclePhase.CLEANUP_PENDING and (
            self.patch_sha256 is None or self.rejection_reason != "strict-VM cleanup is unproven"
        ):
            raise StrictVMCycleError("cleanup-pending state is invalid")
        if self.phase is CyclePhase.REJECTED and self.rejection_reason is None:
            raise StrictVMCycleError("rejected cycle state lacks a reason")


def disabled_live_cycle(*_args: object, **_kwargs: object) -> None:
    """Fail before any live backend, admission, filesystem, or budget work."""

    raise StrictVMCycleDisabled(
        "strict-VM whole-cycle execution is source-disabled pending live evidence"
    )


def create_publisher_handoff(*_args: object, **_kwargs: object) -> None:
    """Never return a production-looking authorization from plain Python data."""

    raise StrictVMCycleDisabled(
        "production publisher handoff is source-disabled pending broker attestation"
    )


def start_offline_cycle(plan: CyclePlan, *, now: datetime) -> CycleState:
    """Start an in-memory verifier state for deterministic offline evidence tests."""

    now = _utc(now, "current time")
    if now >= plan.deadline_at:
        raise StrictVMCycleError("cycle deadline is exhausted before admission")
    if plan.deadline_at - now > MAX_WALL_TIME:
        raise StrictVMCycleError("cycle deadline exceeds the maximum wall-time cap")
    return CycleState(plan=plan, phase=CyclePhase.READY)


def accept_stopped_epoch(
    state: CycleState,
    mediator: MediatorReceipt,
    guest: StoppedGuestReceipt,
    *,
    now: datetime,
) -> CycleState:
    """Bind one mediated patch to a stopped VM result without trusting its claims.

    Cleanup failure is a distinct ``cleanup_pending`` outcome.  It is not a
    successful epoch and can never be converted into a publisher handoff.
    """

    now = _utc(now, "current time")
    if state.phase is not CyclePhase.READY:
        raise StrictVMCycleError("cycle is not accepting another epoch")
    if now >= state.plan.deadline_at:
        raise StrictVMCycleError("cycle deadline is exhausted")
    if len(state.completed_rounds) >= state.plan.max_rounds:
        raise StrictVMCycleError("cycle round cap is exhausted")
    if mediator.run_id != state.plan.run_id or guest.run_id != state.plan.run_id:
        raise StrictVMCycleError("epoch run identity does not match the cycle")
    expected_round = len(state.completed_rounds)
    if mediator.round != expected_round or guest.round != expected_round:
        raise StrictVMCycleError("epoch round is not the next bounded round")
    if (
        mediator.request_sha256 != guest.request_sha256
        or mediator.action_batch_sha256 != guest.action_batch_sha256
        or mediator.patch_sha256 != guest.canonical_patch_sha256
    ):
        raise StrictVMCycleError("mediator and guest receipts do not bind the same epoch")
    if not guest.launcher_stop_proven or not guest.result_extracted_after_stop:
        raise StrictVMCycleError("guest result was not proven to be post-stop")
    total = state.spent_tokens + mediator.charged_tokens
    if total > state.plan.token_cap:
        raise StrictVMCycleError("cycle token cap is exhausted")
    if not guest.cleanup_proven:
        return CycleState(
            plan=state.plan,
            phase=CyclePhase.CLEANUP_PENDING,
            spent_tokens=total,
            completed_rounds=state.completed_rounds,
            patch_sha256=guest.canonical_patch_sha256,
            rejection_reason="strict-VM cleanup is unproven",
        )
    return CycleState(
        plan=state.plan,
        phase=CyclePhase.EPOCH_VERIFIED,
        spent_tokens=total,
        completed_rounds=(*state.completed_rounds, expected_round),
        patch_sha256=guest.canonical_patch_sha256,
    )


def create_fixture_publisher_handoff(
    state: CycleState,
    host: IndependentHostReceipt,
    *,
    base_sha_rechecked: str,
    now: datetime,
) -> tuple[CycleState, FixturePublisherHandoff]:
    """Simulate evidence checks and return an explicitly non-authoritative fixture."""

    now = _utc(now, "current time")
    _require(base_sha_rechecked, _GIT_SHA, "rechecked base SHA")
    if state.phase is CyclePhase.CLEANUP_PENDING:
        raise StrictVMCycleError("cleanup_pending cannot be published or approved")
    if state.phase is not CyclePhase.EPOCH_VERIFIED or state.patch_sha256 is None:
        raise StrictVMCycleError("no proven stopped epoch is ready for host re-verification")
    if now >= state.plan.deadline_at:
        raise StrictVMCycleError("cycle deadline is exhausted before publisher handoff")
    if host.run_id != state.plan.run_id:
        raise StrictVMCycleError("host receipt run identity does not match")
    if host.base_sha_observed != state.plan.base_sha or base_sha_rechecked != state.plan.base_sha:
        raise StrictVMCycleError("base moved before publisher handoff")
    if host.applied_patch_sha256 != state.patch_sha256:
        raise StrictVMCycleError("host-applied patch drifted from the guest canonical patch")
    if host.inspected_diff_sha256 != state.patch_sha256:
        raise StrictVMCycleError("independently inspected diff does not match the canonical patch")
    if host.policy_sha256 != state.plan.policy_sha256 or not host.policy_allowed:
        raise StrictVMCycleError("independent policy re-verification did not pass")
    if host.review_unresolved:
        raise StrictVMCycleError("independent review contains unresolved findings")
    check_ids = tuple(item.check_id for item in host.checks)
    if check_ids != state.plan.required_check_ids:
        raise StrictVMCycleError("host checks do not exactly match the curated check registry")
    if any(item.exit_code != 0 or item.timed_out or item.truncated for item in host.checks):
        raise StrictVMCycleError("independent host checks did not all succeed")
    handoff = FixturePublisherHandoff(
        run_id=state.plan.run_id,
        repository=state.plan.repository,
        issue_number=state.plan.issue_number,
        base_ref=state.plan.base_ref,
        base_sha=state.plan.base_sha,
        patch_sha256=state.patch_sha256,
        policy_sha256=state.plan.policy_sha256,
        check_ids=check_ids,
    )
    return (
        CycleState(
            plan=state.plan,
            phase=CyclePhase.PUBLISH_READY,
            spent_tokens=state.spent_tokens,
            completed_rounds=state.completed_rounds,
            patch_sha256=state.patch_sha256,
        ),
        handoff,
    )
