from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


class RunStage(StrEnum):
    SCHEDULED = "scheduled"
    BUDGET_CHECK = "budget_check"
    DISCOVERING = "discovering"
    SCORING = "scoring"
    SELECTED = "selected"
    PREFLIGHT = "preflight"
    SANDBOX_READY = "sandbox_ready"
    PLANNING = "planning"
    IMPLEMENTING = "implementing"
    VERIFYING = "verifying"
    REVIEWING = "reviewing"
    APPROVED = "approved"
    AWAITING_APPROVAL = "awaiting_approval"
    PUBLISHING = "publishing"
    PR_OPEN = "pr_open"
    CLEANING = "cleaning"
    COMPLETE = "complete"
    DEFERRED = "deferred"
    SKIPPED = "skipped"
    FAILED = "failed"
    ABORTED = "aborted"
    CLEANUP_PENDING = "cleanup_pending"


class FailureCode(StrEnum):
    BUDGET_EXHAUSTED = "budget_exhausted"
    POLICY_DENIED = "policy_denied"
    NO_CANDIDATE = "no_candidate"
    NO_REPRODUCTION = "no_reproduction"
    TEST_FAILED = "test_failed"
    REVIEW_REJECTED = "review_rejected"
    UPSTREAM_MOVED = "upstream_moved"
    RATE_LIMITED = "rate_limited"
    AUTH_FAILED = "auth_failed"
    PUBLISH_PARTIAL = "publish_partial"
    CLEANUP_FAILED = "cleanup_failed"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    AGENT_FAILED = "agent_failed"
    INVALID_OUTPUT = "invalid_output"


@dataclass(frozen=True)
class RepositoryMetadata:
    slug: str
    stars: int
    archived: bool
    disabled: bool
    license_spdx: str | None
    default_branch: str
    pushed_at: datetime | None = None
    open_issues: int = 0
    forking_allowed: bool | None = None
    pull_requests_enabled: bool | None = None
    pull_request_creation_policy: str | None = None


@dataclass(frozen=True)
class IssueCandidate:
    repo: RepositoryMetadata
    number: int
    node_id: str
    title: str
    body: str
    url: str
    labels: tuple[str, ...]
    created_at: datetime
    updated_at: datetime
    comments: int
    reactions: int
    assignees: tuple[str, ...]
    locked: bool
    author_association: str
    has_open_linked_pr: bool = False
    has_recent_claim: bool = False
    state: str = "unknown"

    @property
    def ref(self) -> str:
        return f"{self.repo.slug}#{self.number}"


@dataclass(frozen=True)
class ScoreBreakdown:
    repository_impact: float
    urgency: float
    user_demand: float
    maintainer_signal: float
    tractability: float
    neglect: float
    technical_risk: float
    collision_risk: float
    scope_uncertainty: float
    total: int
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RankedCandidate:
    issue: IssueCandidate
    score: ScoreBreakdown
    eligible: bool
    gate_failures: tuple[str, ...]
    estimated_tokens_p50: int
    estimated_tokens_p95: int


@dataclass(frozen=True)
class BudgetSnapshot:
    source: str
    remaining_tokens: int | None
    reserve_tokens: int
    spendable_tokens: int | None
    confidence: str
    observed_at: datetime
    resets_at: datetime | None = None
    maximum_tokens: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "remaining_tokens": self.remaining_tokens,
            "reserve_tokens": self.reserve_tokens,
            "spendable_tokens": self.spendable_tokens,
            "confidence": self.confidence,
            "observed_at": isoformat(self.observed_at),
            "resets_at": isoformat(self.resets_at),
            "maximum_tokens": self.maximum_tokens,
        }


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    duration_seconds: float
    stdout_tail: str
    stderr_tail: str
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    reasoning_tokens: int
    total_tokens: int
    source: str
    exact: bool
    reported_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "total_tokens": self.total_tokens,
            "source": self.source,
            "exact": self.exact,
            "reported_at": isoformat(self.reported_at),
        }


@dataclass(frozen=True)
class AgentResult:
    stage: str
    status: str
    payload: dict[str, Any]
    command: CommandResult
    usage: TokenUsage | None = None


@dataclass
class RunOutcome:
    run_id: str
    stage: RunStage
    issue_ref: str | None = None
    score: int | None = None
    failure_code: FailureCode | None = None
    message: str = ""
    pr_url: str | None = None
    branch: str | None = None
    tests: list[CommandResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "stage": self.stage.value,
            "issue_ref": self.issue_ref,
            "score": self.score,
            "failure_code": self.failure_code.value if self.failure_code else None,
            "message": self.message,
            "pr_url": self.pr_url,
            "branch": self.branch,
            "tests": [asdict(result) for result in self.tests],
        }
