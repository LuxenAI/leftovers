"""Inference-only action mediation for the future strict-VM worker.

This module deliberately has no online implementation.  The default mediator
always refuses work, while ``FixtureMediator`` exists only for deterministic,
offline protocol tests.  A future authenticated backend must produce the same
bounded action and usage receipts without gaining filesystem or command
authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Final, Protocol, TypeAlias

PRODUCTION_MEDIATION_ENABLED: Final = False
ACTION_BATCH_SCHEMA_VERSION: Final = 1
MAX_INPUT_BYTES: Final = 2_000_000
MAX_RESPONSE_BYTES: Final = 262_144
MAX_PATCH_BYTES: Final = 262_144
MAX_ACTIONS: Final = 32
MAX_CALLS: Final = 64
MAX_TOKEN_COMPONENT: Final = 10_000_000
MAX_DEADLINE_HORIZON: Final = timedelta(hours=4)

_RUN_ID = re.compile(r"[a-f0-9]{32}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ACTION_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_CHECK_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_DIGEST = re.compile(r"[a-f0-9]{64}")
_REASONING_EFFORTS = frozenset({"low", "medium", "high"})
_FINISH_STATUSES = frozenset({"complete", "blocked", "failed"})
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 2_048
_MAX_JSON_STRING_BYTES = 65_536


class MediatorError(RuntimeError):
    """Base class for fail-closed mediation errors."""


class MediationDisabled(MediatorError):
    """Raised whenever the production-disabled mediator is invoked."""


class MediatorValidationError(MediatorError):
    """Raised for a malformed, over-authorized, or unbound response."""


class MediationStage(StrEnum):
    PLANNING = "planning"
    IMPLEMENTATION = "implementation"
    FINAL_VERIFY = "final_verify"
    REVIEW = "review"


class ActionKind(StrEnum):
    READ_FILE = "read_file"
    LIST_DIR = "list_dir"
    SEARCH_LITERAL = "search_literal"
    APPLY_PATCH = "apply_patch"
    RUN_CHECK = "run_check"
    FINISH = "finish"


@dataclass(frozen=True)
class MediationLimits:
    max_response_bytes: int
    max_patch_bytes: int
    max_actions: int
    input_token_cap: int
    output_token_cap: int
    total_token_cap: int
    call_index: int
    call_cap: int


@dataclass(frozen=True)
class MediationRequest:
    run_id: str
    round: int
    stage: MediationStage
    provider: str
    model: str
    reasoning_effort: str
    input_bytes: bytes
    allowed_check_ids: frozenset[str]
    limits: MediationLimits
    deadline_at: datetime


@dataclass(frozen=True)
class ReadFileAction:
    action_id: str
    path: str
    offset: int
    max_bytes: int
    kind: ActionKind = ActionKind.READ_FILE


@dataclass(frozen=True)
class ListDirAction:
    action_id: str
    path: str
    max_entries: int
    kind: ActionKind = ActionKind.LIST_DIR


@dataclass(frozen=True)
class SearchLiteralAction:
    action_id: str
    path: str
    literal: str
    max_matches: int
    kind: ActionKind = ActionKind.SEARCH_LITERAL


@dataclass(frozen=True)
class ApplyPatchAction:
    action_id: str
    patch_sha256: str
    kind: ActionKind = ActionKind.APPLY_PATCH


@dataclass(frozen=True)
class RunCheckAction:
    action_id: str
    check_id: str
    kind: ActionKind = ActionKind.RUN_CHECK


@dataclass(frozen=True)
class FinishAction:
    action_id: str
    status: str
    summary: str
    kind: ActionKind = ActionKind.FINISH


StrictAction: TypeAlias = (
    ReadFileAction
    | ListDirAction
    | SearchLiteralAction
    | ApplyPatchAction
    | RunCheckAction
    | FinishAction
)


@dataclass(frozen=True)
class ActionBatch:
    run_id: str
    round: int
    stage: MediationStage
    provider: str
    model: str
    reasoning_effort: str
    actions: tuple[StrictAction, ...]


@dataclass(frozen=True)
class ReportedTokenCounts:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    reasoning_tokens: int
    total_tokens: int
    source: str
    exact: bool


@dataclass(frozen=True)
class MediationReceipt:
    schema_version: int
    run_id: str
    round: int
    stage: MediationStage
    provider: str
    model: str
    reasoning_effort: str
    input_sha256: str
    action_batch_sha256: str
    patch_sha256: str | None
    output_sha256: str
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    reasoning_tokens: int
    total_tokens: int
    usage_source: str
    exact_usage: bool
    max_response_bytes: int
    max_patch_bytes: int
    max_actions: int
    input_token_cap: int
    output_token_cap: int
    total_token_cap: int
    call_index: int
    call_cap: int
    deadline_at: datetime
    started_at: datetime
    finished_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "round": self.round,
            "stage": self.stage.value,
            "provider": self.provider,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "input_sha256": self.input_sha256,
            "action_batch_sha256": self.action_batch_sha256,
            "patch_sha256": self.patch_sha256,
            "output_sha256": self.output_sha256,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "total_tokens": self.total_tokens,
            "usage_source": self.usage_source,
            "exact_usage": self.exact_usage,
            "max_response_bytes": self.max_response_bytes,
            "max_patch_bytes": self.max_patch_bytes,
            "max_actions": self.max_actions,
            "input_token_cap": self.input_token_cap,
            "output_token_cap": self.output_token_cap,
            "total_token_cap": self.total_token_cap,
            "call_index": self.call_index,
            "call_cap": self.call_cap,
            "deadline_at": _iso_utc(self.deadline_at),
            "started_at": _iso_utc(self.started_at),
            "finished_at": _iso_utc(self.finished_at),
        }


@dataclass(frozen=True)
class MediationResult:
    batch: ActionBatch
    patch: bytes | None
    receipt: MediationReceipt


@dataclass(frozen=True)
class FixtureTurn:
    output_bytes: bytes
    usage: ReportedTokenCounts
    patch_bytes: bytes | None = None


class ModelMediator(Protocol):
    def mediate(self, request: MediationRequest) -> MediationResult:
        """Return one validated inference-only action batch."""


class DisabledMediator:
    """The default production-safe mediator."""

    production_capable: Final = False

    def mediate(self, request: MediationRequest) -> MediationResult:
        del request
        raise MediationDisabled("strict-VM model mediation is disabled")


DEFAULT_MEDIATOR: Final[ModelMediator] = DisabledMediator()


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _reject_float(_value: str) -> Any:
    raise MediatorValidationError("floating-point JSON numbers are forbidden")


def _reject_constant(_value: str) -> Any:
    raise MediatorValidationError("non-finite JSON numbers are forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MediatorValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _contains_control(value: str) -> bool:
    return any(unicodedata.category(character) == "Cc" for character in value)


def _utf8_length(value: str, field: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise MediatorValidationError(f"{field} is not valid Unicode text") from exc


def _validate_json_tree(value: Any, *, reject_controls: bool) -> None:
    nodes = 0

    def visit(candidate: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise MediatorValidationError("JSON response exceeds structural bounds")
        if candidate is None or type(candidate) is bool:
            return
        if type(candidate) is int:
            if abs(candidate) > 2**63 - 1:
                raise MediatorValidationError("JSON integer exceeds signed 64-bit bounds")
            return
        if type(candidate) is float:
            raise MediatorValidationError("floating-point JSON numbers are forbidden")
        if type(candidate) is str:
            if _utf8_length(candidate, "JSON string") > _MAX_JSON_STRING_BYTES:
                raise MediatorValidationError("JSON string exceeds its byte bound")
            if reject_controls and _contains_control(candidate):
                raise MediatorValidationError("control characters are forbidden")
            return
        if type(candidate) is list:
            for item in candidate:
                visit(item, depth + 1)
            return
        if type(candidate) is dict:
            for key, item in candidate.items():
                if type(key) is not str:
                    raise MediatorValidationError("JSON object keys must be strings")
                visit(key, depth + 1)
                visit(item, depth + 1)
            return
        raise MediatorValidationError("unsupported JSON value type")

    visit(value, 0)


def canonical_json_bytes(value: Any, *, reject_controls: bool = False) -> bytes:
    """Encode the narrow canonical JSON form used by the mediator boundary."""

    _validate_json_tree(value, reject_controls=reject_controls)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise MediatorValidationError("value cannot be encoded as canonical JSON") from exc


def _parse_canonical_json(
    raw: bytes,
    *,
    maximum_bytes: int,
    reject_controls: bool,
) -> Any:
    if type(raw) is not bytes:
        raise MediatorValidationError("mediator JSON must be supplied as immutable bytes")
    if not raw or len(raw) > maximum_bytes:
        raise MediatorValidationError("mediator JSON is empty or oversized")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except MediatorValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MediatorValidationError("mediator JSON is malformed") from exc
    _validate_json_tree(value, reject_controls=reject_controls)
    if canonical_json_bytes(value, reject_controls=reject_controls) != raw:
        raise MediatorValidationError("mediator JSON bytes are not canonical")
    return value


def _require_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise MediatorValidationError(f"{context} must be an object")
    keys = set(value)
    if keys != expected:
        unknown = sorted(keys - expected)
        missing = sorted(expected - keys)
        detail = []
        if unknown:
            detail.append("unknown=" + ",".join(unknown))
        if missing:
            detail.append("missing=" + ",".join(missing))
        raise MediatorValidationError(f"{context} fields are invalid ({'; '.join(detail)})")
    return value


def _bounded_int(value: Any, *, minimum: int, maximum: int, field: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise MediatorValidationError(f"{field} is outside its integer bounds")
    return value


def _bounded_text(
    value: Any,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    field: str,
) -> str:
    if type(value) is not str or _contains_control(value):
        raise MediatorValidationError(f"{field} must be control-free text")
    if unicodedata.normalize("NFC", value) != value:
        raise MediatorValidationError(f"{field} must use NFC normalization")
    length = _utf8_length(value, field)
    if not minimum_bytes <= length <= maximum_bytes:
        raise MediatorValidationError(f"{field} is outside its byte bounds")
    return value


def _matched_identifier(value: Any, pattern: re.Pattern[str], field: str) -> str:
    text = _bounded_text(value, minimum_bytes=1, maximum_bytes=128, field=field)
    if pattern.fullmatch(text) is None:
        raise MediatorValidationError(f"{field} is not a safe identifier")
    return text


def _safe_path(value: Any, field: str) -> str:
    path = _bounded_text(value, minimum_bytes=1, maximum_bytes=512, field=field)
    if "\\" in path or ":" in path or path.startswith("/") or path.endswith("/"):
        raise MediatorValidationError(f"{field} is not a safe relative path")
    if "//" in path:
        raise MediatorValidationError(f"{field} is not canonical")
    components = path.split("/")
    if (
        len(components) > 32
        or any(component in {"", ".", ".."} for component in components)
        or any(component.casefold() == ".git" for component in components)
        or any(len(component.encode("utf-8")) > 255 for component in components)
    ):
        raise MediatorValidationError(f"{field} escapes or targets protected metadata")
    if PurePosixPath(path).as_posix() != path:
        raise MediatorValidationError(f"{field} is not canonical")
    return path


def _validate_limits(limits: MediationLimits) -> None:
    if not isinstance(limits, MediationLimits):
        raise MediatorValidationError("mediation limits have an invalid type")
    _bounded_int(
        limits.max_response_bytes,
        minimum=1,
        maximum=MAX_RESPONSE_BYTES,
        field="max_response_bytes",
    )
    _bounded_int(
        limits.max_patch_bytes,
        minimum=1,
        maximum=MAX_PATCH_BYTES,
        field="max_patch_bytes",
    )
    if limits.max_patch_bytes > limits.max_response_bytes:
        raise MediatorValidationError("max_patch_bytes may not exceed max_response_bytes")
    _bounded_int(limits.max_actions, minimum=1, maximum=MAX_ACTIONS, field="max_actions")
    for field, value in (
        ("input_token_cap", limits.input_token_cap),
        ("output_token_cap", limits.output_token_cap),
        ("total_token_cap", limits.total_token_cap),
    ):
        _bounded_int(value, minimum=1, maximum=MAX_TOKEN_COMPONENT, field=field)
    if not (
        max(limits.input_token_cap, limits.output_token_cap)
        <= limits.total_token_cap
        <= limits.input_token_cap + limits.output_token_cap
    ):
        raise MediatorValidationError("token component and total caps are inconsistent")
    _bounded_int(limits.call_cap, minimum=1, maximum=MAX_CALLS, field="call_cap")
    _bounded_int(limits.call_index, minimum=1, maximum=limits.call_cap, field="call_index")


def validate_mediation_request(
    request: MediationRequest,
    *,
    now: datetime | None = None,
) -> None:
    if type(request) is not MediationRequest:
        raise MediatorValidationError("mediation request has an invalid type")
    _matched_identifier(request.run_id, _RUN_ID, "run_id")
    _bounded_int(request.round, minimum=0, maximum=1_000_000, field="round")
    if type(request.stage) is not MediationStage:
        raise MediatorValidationError("stage must be a MediationStage")
    _matched_identifier(request.provider, _IDENTIFIER, "provider")
    _matched_identifier(request.model, _IDENTIFIER, "model")
    if (
        type(request.reasoning_effort) is not str
        or request.reasoning_effort not in _REASONING_EFFORTS
    ):
        raise MediatorValidationError("reasoning_effort is unsupported")
    _parse_canonical_json(
        request.input_bytes,
        maximum_bytes=MAX_INPUT_BYTES,
        reject_controls=False,
    )
    if type(request.allowed_check_ids) is not frozenset or len(request.allowed_check_ids) > 32:
        raise MediatorValidationError("allowed_check_ids must be a bounded frozenset")
    for check_id in request.allowed_check_ids:
        _matched_identifier(check_id, _CHECK_ID, "allowed_check_id")
    if request.stage is MediationStage.FINAL_VERIFY and not request.allowed_check_ids:
        raise MediatorValidationError("final_verify requires at least one curated check ID")
    _validate_limits(request.limits)
    if (
        type(request.deadline_at) is not datetime
        or request.deadline_at.tzinfo is None
        or request.deadline_at.utcoffset() is None
    ):
        raise MediatorValidationError("deadline_at must be timezone-aware")
    observed = datetime.now(UTC) if now is None else now
    if type(observed) is not datetime or observed.tzinfo is None or observed.utcoffset() is None:
        raise MediatorValidationError("validation time must be timezone-aware")
    observed = observed.astimezone(UTC)
    deadline = request.deadline_at.astimezone(UTC)
    if deadline <= observed:
        raise MediatorValidationError("mediation deadline is exhausted")
    if deadline - observed > MAX_DEADLINE_HORIZON:
        raise MediatorValidationError("mediation deadline exceeds the hard horizon")


def _parse_action(
    value: Any,
    request: MediationRequest,
    proposed_patch_sha256: str | None,
) -> StrictAction:
    if type(value) is not dict:
        raise MediatorValidationError("each action must be an object")
    kind_value = value.get("type")
    if type(kind_value) is not str:
        raise MediatorValidationError("action type is required")
    try:
        kind = ActionKind(kind_value)
    except ValueError as exc:
        raise MediatorValidationError("action type is not allowlisted") from exc

    if kind is ActionKind.READ_FILE:
        action = _require_keys(value, {"id", "type", "path", "offset", "max_bytes"}, "read_file")
        return ReadFileAction(
            action_id=_matched_identifier(action["id"], _ACTION_ID, "action.id"),
            path=_safe_path(action["path"], "read_file.path"),
            offset=_bounded_int(
                action["offset"], minimum=0, maximum=1_073_741_824, field="read_file.offset"
            ),
            max_bytes=_bounded_int(
                action["max_bytes"], minimum=1, maximum=65_536, field="read_file.max_bytes"
            ),
        )
    if kind is ActionKind.LIST_DIR:
        action = _require_keys(value, {"id", "type", "path", "max_entries"}, "list_dir")
        return ListDirAction(
            action_id=_matched_identifier(action["id"], _ACTION_ID, "action.id"),
            path=_safe_path(action["path"], "list_dir.path"),
            max_entries=_bounded_int(
                action["max_entries"], minimum=1, maximum=1_024, field="list_dir.max_entries"
            ),
        )
    if kind is ActionKind.SEARCH_LITERAL:
        action = _require_keys(
            value,
            {"id", "type", "path", "literal", "max_matches"},
            "search_literal",
        )
        return SearchLiteralAction(
            action_id=_matched_identifier(action["id"], _ACTION_ID, "action.id"),
            path=_safe_path(action["path"], "search_literal.path"),
            literal=_bounded_text(
                action["literal"],
                minimum_bytes=1,
                maximum_bytes=1_024,
                field="search_literal.literal",
            ),
            max_matches=_bounded_int(
                action["max_matches"],
                minimum=1,
                maximum=1_000,
                field="search_literal.max_matches",
            ),
        )
    if kind is ActionKind.APPLY_PATCH:
        action = _require_keys(value, {"id", "type", "patch_sha256"}, "apply_patch")
        digest = action["patch_sha256"]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise MediatorValidationError("apply_patch.patch_sha256 is invalid")
        if proposed_patch_sha256 is None:
            raise MediatorValidationError(
                "proposed patch bytes and apply_patch authority must be present together"
            )
        if digest != proposed_patch_sha256:
            raise MediatorValidationError("apply_patch does not match the separately bound patch")
        return ApplyPatchAction(
            action_id=_matched_identifier(action["id"], _ACTION_ID, "action.id"),
            patch_sha256=digest,
        )
    if kind is ActionKind.RUN_CHECK:
        action = _require_keys(value, {"id", "type", "check_id"}, "run_check")
        check_id = _matched_identifier(action["check_id"], _CHECK_ID, "run_check.check_id")
        if check_id not in request.allowed_check_ids:
            raise MediatorValidationError("run_check references an unknown check ID")
        return RunCheckAction(
            action_id=_matched_identifier(action["id"], _ACTION_ID, "action.id"),
            check_id=check_id,
        )
    if kind is ActionKind.FINISH:
        action = _require_keys(value, {"id", "type", "status", "summary"}, "finish")
        status = action["status"]
        if type(status) is not str or status not in _FINISH_STATUSES:
            raise MediatorValidationError("finish.status is invalid")
        return FinishAction(
            action_id=_matched_identifier(action["id"], _ACTION_ID, "action.id"),
            status=status,
            summary=_bounded_text(
                action["summary"], minimum_bytes=1, maximum_bytes=4_096, field="finish.summary"
            ),
        )
    raise AssertionError("unreachable action kind")


def validate_action_batch(
    raw: bytes,
    request: MediationRequest,
    *,
    proposed_patch_sha256: str | None = None,
) -> ActionBatch:
    validate_mediation_request(request)
    if proposed_patch_sha256 is not None and (
        type(proposed_patch_sha256) is not str
        or _DIGEST.fullmatch(proposed_patch_sha256) is None
        or request.stage is not MediationStage.IMPLEMENTATION
    ):
        raise MediatorValidationError("proposed patch binding is invalid for this stage")
    payload = _parse_canonical_json(
        raw,
        maximum_bytes=request.limits.max_response_bytes,
        reject_controls=True,
    )
    top = _require_keys(
        payload,
        {
            "schema_version",
            "run_id",
            "round",
            "stage",
            "provider",
            "model",
            "reasoning_effort",
            "actions",
        },
        "action batch",
    )
    if (
        type(top["schema_version"]) is not int
        or top["schema_version"] != ACTION_BATCH_SCHEMA_VERSION
    ):
        raise MediatorValidationError("action batch schema_version is unsupported")
    if top["run_id"] != request.run_id:
        raise MediatorValidationError("action batch run_id does not match")
    if type(top["round"]) is not int or top["round"] != request.round:
        raise MediatorValidationError("action batch round does not match")
    if top["stage"] != request.stage.value:
        raise MediatorValidationError("action batch stage does not match")
    if top["provider"] != request.provider:
        raise MediatorValidationError("action batch provider does not match")
    if top["model"] != request.model:
        raise MediatorValidationError("action batch model does not match")
    if top["reasoning_effort"] != request.reasoning_effort:
        raise MediatorValidationError("action batch reasoning_effort does not match")
    raw_actions = top["actions"]
    if (
        type(raw_actions) is not list
        or not raw_actions
        or len(raw_actions) > request.limits.max_actions
    ):
        raise MediatorValidationError("action count is outside the request limit")
    actions = tuple(_parse_action(value, request, proposed_patch_sha256) for value in raw_actions)

    action_ids = [action.action_id for action in actions]
    if len(action_ids) != len(set(action_ids)):
        raise MediatorValidationError("action IDs must be unique")
    finish_positions = [
        index for index, action in enumerate(actions) if action.kind is ActionKind.FINISH
    ]
    if finish_positions != [len(actions) - 1]:
        raise MediatorValidationError("exactly one finish action must be final")
    if sum(action.kind is ActionKind.APPLY_PATCH for action in actions) > 1:
        raise MediatorValidationError("at most one apply_patch action is allowed")
    has_patch_action = any(action.kind is ActionKind.APPLY_PATCH for action in actions)
    if has_patch_action != (proposed_patch_sha256 is not None):
        raise MediatorValidationError(
            "proposed patch bytes and apply_patch authority must be present together"
        )
    check_ids = [action.check_id for action in actions if isinstance(action, RunCheckAction)]
    if len(check_ids) != len(set(check_ids)):
        raise MediatorValidationError("a curated check may run at most once per batch")

    read_only = {
        ActionKind.READ_FILE,
        ActionKind.LIST_DIR,
        ActionKind.SEARCH_LITERAL,
        ActionKind.FINISH,
    }
    allowed_by_stage = {
        MediationStage.PLANNING: read_only,
        MediationStage.REVIEW: read_only,
        MediationStage.IMPLEMENTATION: read_only | {ActionKind.APPLY_PATCH},
        MediationStage.FINAL_VERIFY: {ActionKind.RUN_CHECK, ActionKind.FINISH},
    }
    forbidden = [
        action.kind.value
        for action in actions
        if action.kind not in allowed_by_stage[request.stage]
    ]
    if forbidden:
        raise MediatorValidationError(
            f"{request.stage.value} contains forbidden action type(s): {','.join(forbidden)}"
        )
    if request.stage is MediationStage.FINAL_VERIFY and not check_ids:
        raise MediatorValidationError("final_verify must execute at least one curated check")

    return ActionBatch(
        run_id=request.run_id,
        round=request.round,
        stage=request.stage,
        provider=request.provider,
        model=request.model,
        reasoning_effort=request.reasoning_effort,
        actions=actions,
    )


def validate_reported_token_counts(
    usage: ReportedTokenCounts,
    limits: MediationLimits,
    *,
    fixture: bool,
) -> None:
    _validate_limits(limits)
    if type(usage) is not ReportedTokenCounts:
        raise MediatorValidationError("exact token usage is required")
    expected_source = "fixture" if fixture else "provider"
    if usage.source != expected_source or usage.exact is not True:
        raise MediatorValidationError("token counts are not exact for the expected source")
    for field, value, cap in (
        ("input_tokens", usage.input_tokens, limits.input_token_cap),
        ("output_tokens", usage.output_tokens, limits.output_token_cap),
        ("cached_input_tokens", usage.cached_input_tokens, limits.input_token_cap),
        ("reasoning_tokens", usage.reasoning_tokens, limits.output_token_cap),
        ("total_tokens", usage.total_tokens, limits.total_token_cap),
    ):
        _bounded_int(value, minimum=0, maximum=cap, field=field)
    if usage.cached_input_tokens > usage.input_tokens:
        raise MediatorValidationError("cached input tokens exceed input tokens")
    if usage.reasoning_tokens > usage.output_tokens:
        raise MediatorValidationError("reasoning tokens exceed output tokens")
    if usage.total_tokens != usage.input_tokens + usage.output_tokens:
        raise MediatorValidationError("total tokens do not equal input plus output")


def validate_proposed_patch(
    patch: bytes | None,
    request: MediationRequest,
    *,
    action_batch_bytes: int,
) -> tuple[bytes | None, str | None]:
    """Validate a model-produced patch as bounded data, never executable authority.

    The digest is derived *after* the mediator receives the bytes.  The model's
    action batch may only reference that derived digest; callers no longer need
    to know a patch hash before asking the model to create a patch.
    """

    if patch is None:
        return None, None
    if type(patch) is not bytes:
        raise MediatorValidationError("proposed patch must be immutable bytes")
    if request.stage is not MediationStage.IMPLEMENTATION:
        raise MediatorValidationError("only implementation may return proposed patch bytes")
    if not patch or len(patch) > request.limits.max_patch_bytes:
        raise MediatorValidationError("proposed patch is empty or oversized")
    if action_batch_bytes + len(patch) > request.limits.max_response_bytes:
        raise MediatorValidationError("combined mediator output exceeds max_response_bytes")
    if b"\0" in patch:
        raise MediatorValidationError("proposed patch contains NUL bytes")
    try:
        patch.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MediatorValidationError("proposed patch is not valid UTF-8") from exc
    return patch, hashlib.sha256(patch).hexdigest()


def _framed_output_sha256(action_batch: bytes, patch: bytes | None) -> str:
    digest = hashlib.sha256()
    digest.update(b"LEFTOVERS_MEDIATION_OUTPUT_V1\0")
    digest.update(len(action_batch).to_bytes(8, "big"))
    digest.update(action_batch)
    patch_bytes = b"" if patch is None else patch
    digest.update(len(patch_bytes).to_bytes(8, "big"))
    digest.update(patch_bytes)
    return digest.hexdigest()


class FixtureMediator:
    """A deterministic in-memory mediator for offline protocol tests only."""

    production_capable: Final = False

    def __init__(self, turns: tuple[FixtureTurn, ...]) -> None:
        if type(turns) is not tuple or any(type(turn) is not FixtureTurn for turn in turns):
            raise MediatorValidationError("fixture turns must be an immutable FixtureTurn tuple")
        if len(turns) > MAX_CALLS:
            raise MediatorValidationError("fixture exceeds the hard call cap")
        self._turns = turns
        self._next_turn = 0

    def mediate(self, request: MediationRequest) -> MediationResult:
        started_at = datetime.now(UTC)
        validate_mediation_request(request, now=started_at)
        expected_call = self._next_turn + 1
        if request.limits.call_index != expected_call:
            raise MediatorValidationError("fixture call index is out of sequence")
        if len(self._turns) > request.limits.call_cap:
            raise MediatorValidationError("fixture turn count exceeds the request call cap")
        if self._next_turn >= len(self._turns):
            raise MediatorValidationError("fixture has no response for this call")
        turn = self._turns[self._next_turn]
        validate_reported_token_counts(turn.usage, request.limits, fixture=True)
        proposed_patch, patch_sha256 = validate_proposed_patch(
            turn.patch_bytes,
            request,
            action_batch_bytes=len(turn.output_bytes),
        )
        batch = validate_action_batch(
            turn.output_bytes,
            request,
            proposed_patch_sha256=patch_sha256,
        )
        finished_at = datetime.now(UTC)
        if finished_at >= request.deadline_at.astimezone(UTC):
            raise MediatorValidationError("mediation response missed its deadline")
        receipt = MediationReceipt(
            schema_version=ACTION_BATCH_SCHEMA_VERSION,
            run_id=request.run_id,
            round=request.round,
            stage=request.stage,
            provider=request.provider,
            model=request.model,
            reasoning_effort=request.reasoning_effort,
            input_sha256=hashlib.sha256(request.input_bytes).hexdigest(),
            action_batch_sha256=hashlib.sha256(turn.output_bytes).hexdigest(),
            patch_sha256=patch_sha256,
            output_sha256=_framed_output_sha256(turn.output_bytes, proposed_patch),
            input_tokens=turn.usage.input_tokens,
            output_tokens=turn.usage.output_tokens,
            cached_input_tokens=turn.usage.cached_input_tokens,
            reasoning_tokens=turn.usage.reasoning_tokens,
            total_tokens=turn.usage.total_tokens,
            usage_source=turn.usage.source,
            exact_usage=True,
            max_response_bytes=request.limits.max_response_bytes,
            max_patch_bytes=request.limits.max_patch_bytes,
            max_actions=request.limits.max_actions,
            input_token_cap=request.limits.input_token_cap,
            output_token_cap=request.limits.output_token_cap,
            total_token_cap=request.limits.total_token_cap,
            call_index=request.limits.call_index,
            call_cap=request.limits.call_cap,
            deadline_at=request.deadline_at.astimezone(UTC),
            started_at=started_at,
            finished_at=finished_at,
        )
        self._next_turn += 1
        return MediationResult(batch=batch, patch=proposed_patch, receipt=receipt)


def action_batch_document(batch: ActionBatch) -> dict[str, Any]:
    """Return the one canonical, data-only representation of a typed batch.

    This is intentionally kept beside the parser: a controller can only bind a
    mediator result to an LFRQ request after re-serializing and re-validating it.
    It is not an execution interface and never supplies an argv or a tool.
    """

    if type(batch) is not ActionBatch:
        raise MediatorValidationError("action batch has an invalid type")

    actions: list[dict[str, Any]] = []
    for action in batch.actions:
        if isinstance(action, ReadFileAction):
            actions.append(
                {
                    "id": action.action_id,
                    "type": action.kind.value,
                    "path": action.path,
                    "offset": action.offset,
                    "max_bytes": action.max_bytes,
                }
            )
        elif isinstance(action, ListDirAction):
            actions.append(
                {
                    "id": action.action_id,
                    "type": action.kind.value,
                    "path": action.path,
                    "max_entries": action.max_entries,
                }
            )
        elif isinstance(action, SearchLiteralAction):
            actions.append(
                {
                    "id": action.action_id,
                    "type": action.kind.value,
                    "path": action.path,
                    "literal": action.literal,
                    "max_matches": action.max_matches,
                }
            )
        elif isinstance(action, ApplyPatchAction):
            actions.append(
                {
                    "id": action.action_id,
                    "type": action.kind.value,
                    "patch_sha256": action.patch_sha256,
                }
            )
        elif isinstance(action, RunCheckAction):
            actions.append(
                {
                    "id": action.action_id,
                    "type": action.kind.value,
                    "check_id": action.check_id,
                }
            )
        elif isinstance(action, FinishAction):
            actions.append(
                {
                    "id": action.action_id,
                    "type": action.kind.value,
                    "status": action.status,
                    "summary": action.summary,
                }
            )
        else:
            raise MediatorValidationError("action batch contains an unknown typed action")
    return {
        "schema_version": ACTION_BATCH_SCHEMA_VERSION,
        "run_id": batch.run_id,
        "round": batch.round,
        "stage": batch.stage.value,
        "provider": batch.provider,
        "model": batch.model,
        "reasoning_effort": batch.reasoning_effort,
        "actions": actions,
    }


def validate_mediation_result(result: MediationResult, request: MediationRequest) -> bytes:
    """Re-validate a typed mediation result before controller authorization.

    A result remains untrusted data until this check succeeds.  The return
    value is the exact canonical action-batch bytes whose digest is recorded in
    the receipt; callers must not substitute an independently supplied batch.
    """

    if type(result) is not MediationResult:
        raise MediatorValidationError("mediation result has an invalid type")
    validate_mediation_request(request)
    raw = canonical_json_bytes(action_batch_document(result.batch), reject_controls=True)
    patch, patch_sha256 = validate_proposed_patch(
        result.patch, request, action_batch_bytes=len(raw)
    )
    parsed = validate_action_batch(raw, request, proposed_patch_sha256=patch_sha256)
    if parsed != result.batch:
        raise MediatorValidationError("typed action batch did not round-trip exactly")

    receipt = result.receipt
    if type(receipt) is not MediationReceipt:
        raise MediatorValidationError("mediation receipt has an invalid type")
    identity = (
        (receipt.run_id, request.run_id),
        (receipt.round, request.round),
        (receipt.stage, request.stage),
        (receipt.provider, request.provider),
        (receipt.model, request.model),
        (receipt.reasoning_effort, request.reasoning_effort),
    )
    if any(actual != expected for actual, expected in identity):
        raise MediatorValidationError("mediation receipt identity does not match its request")
    if receipt.schema_version != ACTION_BATCH_SCHEMA_VERSION:
        raise MediatorValidationError("mediation receipt schema version is unsupported")
    if receipt.input_sha256 != hashlib.sha256(request.input_bytes).hexdigest():
        raise MediatorValidationError("mediation receipt input digest does not match")
    if receipt.action_batch_sha256 != hashlib.sha256(raw).hexdigest():
        raise MediatorValidationError("mediation receipt action-batch digest does not match")
    if receipt.patch_sha256 != patch_sha256:
        raise MediatorValidationError("mediation receipt patch digest does not match")
    if receipt.output_sha256 != _framed_output_sha256(raw, patch):
        raise MediatorValidationError("mediation receipt output digest does not match")
    if (
        receipt.max_response_bytes != request.limits.max_response_bytes
        or receipt.max_patch_bytes != request.limits.max_patch_bytes
        or receipt.max_actions != request.limits.max_actions
        or receipt.input_token_cap != request.limits.input_token_cap
        or receipt.output_token_cap != request.limits.output_token_cap
        or receipt.total_token_cap != request.limits.total_token_cap
        or receipt.call_index != request.limits.call_index
        or receipt.call_cap != request.limits.call_cap
        or receipt.deadline_at.astimezone(UTC) != request.deadline_at.astimezone(UTC)
    ):
        raise MediatorValidationError("mediation receipt limits do not match its request")
    fixture = receipt.usage_source == "fixture"
    validate_reported_token_counts(
        ReportedTokenCounts(
            input_tokens=receipt.input_tokens,
            output_tokens=receipt.output_tokens,
            cached_input_tokens=receipt.cached_input_tokens,
            reasoning_tokens=receipt.reasoning_tokens,
            total_tokens=receipt.total_tokens,
            source=receipt.usage_source,
            exact=receipt.exact_usage,
        ),
        request.limits,
        fixture=fixture,
    )
    for label, value in (("started_at", receipt.started_at), ("finished_at", receipt.finished_at)):
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise MediatorValidationError(f"mediation receipt {label} is not timezone-aware")
    if receipt.finished_at.astimezone(UTC) < receipt.started_at.astimezone(UTC):
        raise MediatorValidationError("mediation receipt timestamps are reversed")
    if receipt.finished_at.astimezone(UTC) >= request.deadline_at.astimezone(UTC):
        raise MediatorValidationError("mediation receipt finished after its deadline")
    return raw
