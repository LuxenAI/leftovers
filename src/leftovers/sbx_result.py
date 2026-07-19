"""Pure, source-disabled post-stop result contract for Docker Sandboxes.

The Docker Sandboxes CLI and daemon are external authorities.  This module
therefore performs no sandbox command, copy, path lookup, descriptor open, Git
operation, provider call, or publication. It defines a two-phase target
contract: capture one fixed opaque patch while a clone-mode worker still runs,
then parse and verify it only after identity-bound cleanup is proven. The
controller later constructs result JSON from its own exact Codex JSONL usage;
the workspace is never a result-document authority.

Production admission is deliberately impossible: :func:`verify_sbx_result`
rejects before inspecting arguments.  The fixture API accepts bounded bytes
and caller-constructible evidence only when an explicit fixture capability is
provided.  A successful fixture result is capability-free data, never
publisher authority.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Never

from .config import MANDATORY_FORBID_PATHS
from .policy import (
    _DEPENDENCY_FILE_PATTERNS,
    _DEPENDENCY_FILES,
    _DEPENDENCY_PATH_PATTERNS,
)
from .sbx import controller_sandbox_name
from .sbx_execution import MAX_MODEL_CALLS, RUN_TOKEN_CAP, STAGE_LIMITS, ExecutionStage

# A source release gate, never configuration.  The eventual production adapter
# must replace fixture evidence with independently attested daemon/descriptor
# evidence and live adversarial verification before this can change.
DOCKER_SANDBOX_RESULT_ENABLED = False

# Docker Sandboxes v0.35 does not document any of these as controller-verifiable
# authorities.  They remain explicit activation blockers; fixture receipts
# below model what a future independently reviewed adapter would have to prove.
SBX_V035_UUID_GENERATION_ATTESTATION_AVAILABLE = False
SBX_V035_DESTRUCTION_ATTESTATION_AVAILABLE = False
SBX_V035_POST_STOP_EXPORT_AVAILABLE = False
CURRENT_SBX_ACTIVATION_BLOCKERS = (
    "daemon UUID/generation attestation is unavailable",
    "identity-bound destruction attestation is unavailable",
    "post-stop export is unavailable; fixed sbx cp is transport only",
)

RESULT_KIND = "leftovers.sbx.post-stop-result.v1"
USAGE_KIND = "leftovers.sbx.exact-usage.v1"
CLEANUP_KIND = "leftovers.sbx.stop-cleanup.v2"
CAPTURE_KIND = "leftovers.sbx.running-fixed-cp-capture.v1"
VERIFIER_KIND = "leftovers.sbx.independent-verifier.v1"
CONTROLLER_RESULT_KIND = "leftovers.sbx.controller-result-evidence.v1"
BASE_RECHECK_KIND = "leftovers.sbx.fresh-base-recheck.v1"
HANDOFF_KIND = "leftovers.sbx.capability-free-handoff.v1"

# Post-cleanup result validation has a stricter immutable-control baseline than
# ordinary repository diff inspection. In particular, unattended output cannot
# rewrite the instruction surfaces that would govern a later agent run.
SBX_RESULT_MANDATORY_FORBID_PATHS = (
    *MANDATORY_FORBID_PATHS,
    "AGENTS.md",
    "**/AGENTS.md",
    ".agents/**",
    "**/.agents/**",
    ".codex/**",
    "**/.codex/**",
    ".leftovers-export/**",
    "**/.leftovers-export/**",
    "CONTRIBUTING.md",
    "**/CONTRIBUTING.md",
)

MAX_RESULT_BYTES = 64 * 1024
MAX_PATCH_BYTES = 256 * 1024
MAX_CAPTURE_BYTES = MAX_PATCH_BYTES
FIXED_CAPTURE_DEADLINE_MS = 30_000
MAX_PATCH_FILES = 32
MAX_CHANGED_LINES = 2_000
MAX_PATCH_LINE_BYTES = 16 * 1024
MAX_PATH_BYTES = 240
MAX_PATH_DEPTH = 32
MAX_FORBIDDEN_PATHS = 256
MAX_JSON_DEPTH = 16
MAX_TOKEN_COUNT = 10_000_000
MAX_FRESH_BASE_AGE_NS = 30_000_000_000

_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX40_OR_64 = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\Z"
)
_CHECK_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_THREAD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SANDBOX_NAME = re.compile(r"leftovers-[a-f0-9]{24}\Z")
_SAFE_PATH = re.compile(r"[A-Za-z0-9._@+,/-]+\Z")
_DIFF_HEADER = re.compile(rb"diff --git a/([A-Za-z0-9._@+,/-]+) b/([A-Za-z0-9._@+,/-]+)\n\Z")
_INDEX_HEADER = re.compile(rb"index ([a-f0-9]{7,64})\.\.([a-f0-9]{7,64})(?: (100644))?\n\Z")
_HUNK_HEADER = re.compile(
    rb"@@ -(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? "
    rb"\+(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*))? @@(?: [^\r\n]*)?\n\Z"
)


class SbxResultError(RuntimeError):
    """The post-stop result or one of its evidence bindings is unsafe."""


class SbxResultDisabled(SbxResultError):
    """Production result verification rejected before any external access."""


class SbxCleanupPending(SbxResultError):
    """Cleanup is failed, ambiguous, stale, or bound to another sandbox."""


class FixtureSbxResultCapability:
    """Explicit non-production marker for pure, caller-constructible tests."""

    __slots__ = ("_identity",)

    def __init__(self, identity: object) -> None:
        if identity is not _FIXTURE_CAPABILITY_IDENTITY:
            raise SbxResultError("fixture sbx-result capability is not constructible")
        self._identity = identity


_FIXTURE_CAPABILITY_IDENTITY = object()
_FIXTURE_CAPABILITY = FixtureSbxResultCapability(_FIXTURE_CAPABILITY_IDENTITY)


def fixture_sbx_result_capability() -> FixtureSbxResultCapability:
    """Return the singleton fixture marker; it cannot activate production."""

    return _FIXTURE_CAPABILITY


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise SbxResultError(f"{label} is invalid")
    return value


def _require_exact_int(value: object, *, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SbxResultError(f"{label} is invalid")
    return value


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise SbxResultError(f"{label} must be an exact boolean")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SbxResultError("result JSON cannot be canonicalized") from exc


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SbxResultError("result JSON contains duplicate keys")
        result[key] = value
    return result


def _reject_non_integer(_value: str) -> object:
    raise SbxResultError("result JSON permits only finite integer numbers")


def _parse_canonical_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_RESULT_BYTES:
        raise SbxResultError("result document exceeds its byte cap")
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_float=_reject_non_integer,
            parse_constant=_reject_non_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SbxResultError("result document is not valid bounded JSON") from exc

    def walk(value: object, depth: int) -> None:
        if depth > MAX_JSON_DEPTH:
            raise SbxResultError("result JSON exceeds its depth cap")
        if type(value) is dict:
            for key, item in value.items():
                walk(key, depth + 1)
                walk(item, depth + 1)
        elif type(value) is list:
            for item in value:
                walk(item, depth + 1)
        elif type(value) is str:
            if unicodedata.normalize("NFC", value) != value or any(
                ord(character) < 32 or ord(character) == 127 for character in value
            ):
                raise SbxResultError("result JSON contains a non-canonical string")
        elif value is not None and type(value) not in {int, bool}:
            raise SbxResultError("result JSON contains an unsupported value")

    walk(parsed, 0)
    if type(parsed) is not dict or _canonical_json(parsed) != raw:
        raise SbxResultError("result document is not canonical JSON")
    return parsed


def _exact_keys(value: object, expected: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != expected:
        raise SbxResultError(f"{label} keys are not exact")
    return value


@dataclass(frozen=True)
class SbxRunBinding:
    """Controller-selected identity that every post-stop receipt must bind.

    UUID/generation are target-contract fields for a future independent
    identity adapter. Docker Sandboxes v0.35 does not document them as exposed
    controller evidence, so the production entry remains source-disabled.
    """

    daemon_sandbox_uuid: str
    daemon_sandbox_generation: int
    controller_sandbox_name: str
    controller_run_id: str
    repository: str
    issue_number: int
    base_sha: str
    source_manifest_sha256: str
    policy_epoch: int
    policy_sha256: str
    secret_epoch: int
    secret_inventory_sha256: str
    model: str
    reasoning_effort: str
    total_token_cap: int

    def __post_init__(self) -> None:
        try:
            parsed_uuid = uuid.UUID(self.daemon_sandbox_uuid)
        except (AttributeError, TypeError, ValueError) as exc:
            raise SbxResultError("daemon sandbox UUID is invalid") from exc
        if str(parsed_uuid) != self.daemon_sandbox_uuid or parsed_uuid.int == 0:
            raise SbxResultError("daemon sandbox UUID is not canonical and nonzero")
        _require_exact_int(
            self.daemon_sandbox_generation,
            minimum=1,
            maximum=2**63 - 1,
            label="daemon sandbox generation",
        )
        if (
            type(self.controller_sandbox_name) is not str
            or _SANDBOX_NAME.fullmatch(self.controller_sandbox_name) is None
        ):
            raise SbxResultError("controller sandbox name is invalid")
        _require_hex(self.controller_run_id, _HEX32, "controller run ID")
        if self.controller_sandbox_name != controller_sandbox_name(self.controller_run_id):
            raise SbxResultError("controller sandbox name is not derived from the run ID")
        if type(self.repository) is not str or _REPOSITORY.fullmatch(self.repository) is None:
            raise SbxResultError("repository identity is invalid")
        _require_exact_int(self.issue_number, minimum=1, maximum=2**31 - 1, label="issue number")
        _require_hex(self.base_sha, _HEX40_OR_64, "base SHA")
        _require_hex(self.source_manifest_sha256, _HEX64, "source manifest digest")
        _require_exact_int(self.policy_epoch, minimum=0, maximum=2**63 - 1, label="policy epoch")
        _require_hex(self.policy_sha256, _HEX64, "policy digest")
        _require_exact_int(self.secret_epoch, minimum=0, maximum=2**63 - 1, label="secret epoch")
        _require_hex(self.secret_inventory_sha256, _HEX64, "secret inventory digest")
        if self.model != "gpt-5.6-terra" or self.reasoning_effort != "high":
            raise SbxResultError("model and reasoning effort are not the fixed Terra-high profile")
        if type(self.total_token_cap) is not int or self.total_token_cap != RUN_TOKEN_CAP:
            raise SbxResultError("total token cap is not the fixed three-call run cap")

    def to_dict(self) -> dict[str, object]:
        return {
            "base_sha": self.base_sha,
            "controller_run_id": self.controller_run_id,
            "controller_sandbox_name": self.controller_sandbox_name,
            "daemon_sandbox_generation": self.daemon_sandbox_generation,
            "daemon_sandbox_uuid": self.daemon_sandbox_uuid,
            "issue_number": self.issue_number,
            "model": self.model,
            "policy_epoch": self.policy_epoch,
            "policy_sha256": self.policy_sha256,
            "reasoning_effort": self.reasoning_effort,
            "repository": self.repository,
            "secret_epoch": self.secret_epoch,
            "secret_inventory_sha256": self.secret_inventory_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "total_token_cap": self.total_token_cap,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class ExactCallUsage:
    """Exact controller-parsed usage for one fixed execution stage."""

    stage: ExecutionStage
    call_index: int
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    cache_write_input_tokens: int
    reasoning_tokens: int
    total_tokens: int
    source: str
    exact: bool
    event_stream_sha256: str
    thread_id: str
    reservation_sha256: str

    def __post_init__(self) -> None:
        if type(self.stage) is not ExecutionStage:
            raise SbxResultError("usage stage is not an exact execution stage")
        limit = next((item for item in STAGE_LIMITS if item.stage is self.stage), None)
        if limit is None or type(self.call_index) is not int or self.call_index != limit.call_index:
            raise SbxResultError("usage call index does not match its fixed execution stage")
        for label, value in (
            ("call input tokens", self.input_tokens),
            ("call output tokens", self.output_tokens),
            ("call cached input tokens", self.cached_input_tokens),
            ("call cache-write input tokens", self.cache_write_input_tokens),
            ("call reasoning tokens", self.reasoning_tokens),
            ("call total tokens", self.total_tokens),
        ):
            _require_exact_int(value, minimum=0, maximum=MAX_TOKEN_COUNT, label=label)
        if self.input_tokens < 1 or self.total_tokens != self.input_tokens + self.output_tokens:
            raise SbxResultError("exact per-call usage totals are inconsistent")
        if (
            self.input_tokens > limit.input_token_cap
            or self.output_tokens > limit.output_token_cap
            or self.total_tokens > limit.total_token_cap
        ):
            raise SbxResultError("exact per-call usage exceeds its fixed stage cap")
        if (
            self.cached_input_tokens > self.input_tokens
            or self.cache_write_input_tokens > self.input_tokens
            or self.reasoning_tokens > self.output_tokens
        ):
            raise SbxResultError("exact per-call usage sub-counts exceed their parent count")
        if self.source != "codex-cli-jsonl-v1" or self.exact is not True:
            raise SbxResultError("call usage is not exact controller-parsed Codex evidence")
        _require_hex(self.event_stream_sha256, _HEX64, "call event stream digest")
        if type(self.thread_id) is not str or _THREAD_ID.fullmatch(self.thread_id) is None:
            raise SbxResultError("Codex thread identity is invalid")
        _require_hex(self.reservation_sha256, _HEX64, "call usage reservation digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "cache_write_input_tokens": self.cache_write_input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "call_index": self.call_index,
            "event_stream_sha256": self.event_stream_sha256,
            "exact": self.exact,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "reservation_sha256": self.reservation_sha256,
            "source": self.source,
            "stage": self.stage.value,
            "thread_id": self.thread_id,
            "total_tokens": self.total_tokens,
        }


def usage_event_stream_tree_sha256(calls: tuple[ExactCallUsage, ...]) -> str:
    """Bind the ordered, stage-labelled JSONL streams without concatenation ambiguity."""

    if type(calls) is not tuple or any(type(call) is not ExactCallUsage for call in calls):
        raise SbxResultError("usage event-stream tree requires exact call receipts")
    return _sha256(
        _canonical_json(
            {
                "kind": "leftovers.sbx.codex-event-stream-tree.v1",
                "streams": [
                    {
                        "call_index": call.call_index,
                        "event_stream_sha256": call.event_stream_sha256,
                        "stage": call.stage.value,
                        "thread_id": call.thread_id,
                    }
                    for call in calls
                ],
            }
        )
    )


@dataclass(frozen=True)
class ExactUsageReceipt:
    """Exact aggregate for all three fixed Codex calls, never model-authored text."""

    calls: tuple[ExactCallUsage, ...]
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    cache_write_input_tokens: int
    reasoning_tokens: int
    total_tokens: int
    source: str
    exact: bool
    provider_call_count: int
    aggregate_event_stream_sha256: str
    reservation_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.calls) is not tuple
            or len(self.calls) != MAX_MODEL_CALLS
            or any(type(call) is not ExactCallUsage for call in self.calls)
        ):
            raise SbxResultError("usage must contain exactly three typed call receipts")
        expected = tuple((limit.stage, limit.call_index) for limit in STAGE_LIMITS)
        observed = tuple((call.stage, call.call_index) for call in self.calls)
        if observed != expected:
            raise SbxResultError("usage calls are missing, duplicated, or out of fixed stage order")
        for label, value in (
            ("aggregate input tokens", self.input_tokens),
            ("aggregate output tokens", self.output_tokens),
            ("aggregate cached input tokens", self.cached_input_tokens),
            ("aggregate cache-write input tokens", self.cache_write_input_tokens),
            ("aggregate reasoning tokens", self.reasoning_tokens),
            ("aggregate total tokens", self.total_tokens),
        ):
            _require_exact_int(value, minimum=0, maximum=RUN_TOKEN_CAP, label=label)
        aggregate_fields = (
            ("input_tokens", self.input_tokens),
            ("output_tokens", self.output_tokens),
            ("cached_input_tokens", self.cached_input_tokens),
            ("cache_write_input_tokens", self.cache_write_input_tokens),
            ("reasoning_tokens", self.reasoning_tokens),
            ("total_tokens", self.total_tokens),
        )
        if any(
            sum(getattr(call, field) for call in self.calls) != value
            for field, value in aggregate_fields
        ):
            raise SbxResultError("aggregate usage does not equal its exact three-call receipts")
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise SbxResultError("aggregate exact usage totals are inconsistent")
        if self.source != "codex-cli-jsonl-v1" or self.exact is not True:
            raise SbxResultError("usage receipt is not exact controller-parsed Codex evidence")
        if type(self.provider_call_count) is not int or self.provider_call_count != MAX_MODEL_CALLS:
            raise SbxResultError("usage receipt must bind exactly three provider calls")
        _require_hex(
            self.aggregate_event_stream_sha256,
            _HEX64,
            "aggregate event stream digest",
        )
        if self.aggregate_event_stream_sha256 != usage_event_stream_tree_sha256(self.calls):
            raise SbxResultError("aggregate event stream digest does not bind all call streams")
        _require_hex(self.reservation_sha256, _HEX64, "usage reservation digest")
        if any(call.reservation_sha256 != self.reservation_sha256 for call in self.calls):
            raise SbxResultError("call usage receipts do not bind the run reservation")

    def to_dict(self) -> dict[str, object]:
        return {
            "aggregate_event_stream_sha256": self.aggregate_event_stream_sha256,
            "cache_write_input_tokens": self.cache_write_input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "calls": [call.to_dict() for call in self.calls],
            "exact": self.exact,
            "input_tokens": self.input_tokens,
            "kind": USAGE_KIND,
            "output_tokens": self.output_tokens,
            "provider_call_count": self.provider_call_count,
            "reasoning_tokens": self.reasoning_tokens,
            "reservation_sha256": self.reservation_sha256,
            "source": self.source,
            "total_tokens": self.total_tokens,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class SbxResultPlan:
    """Controller-fixed post-stop acceptance plan for exactly one sandbox."""

    binding: SbxRunBinding
    controller_uid: int
    controller_boot_sha256: str
    freshness_challenge_sha256: str
    verifier_identity_sha256: str
    verification_profile_sha256: str
    required_check_ids: tuple[str, ...]
    max_changed_files: int = 5
    max_changed_lines: int = 300
    forbidden_paths: tuple[str, ...] = SBX_RESULT_MANDATORY_FORBID_PATHS

    def __post_init__(self) -> None:
        if type(self.binding) is not SbxRunBinding:
            raise SbxResultError("result plan binding is invalid")
        _require_exact_int(
            self.controller_uid, minimum=0, maximum=2**31 - 1, label="controller UID"
        )
        for value, label in (
            (self.controller_boot_sha256, "controller boot digest"),
            (self.freshness_challenge_sha256, "freshness challenge digest"),
            (self.verifier_identity_sha256, "verifier identity digest"),
            (self.verification_profile_sha256, "verification profile digest"),
        ):
            _require_hex(value, _HEX64, label)
        if (
            type(self.required_check_ids) is not tuple
            or not self.required_check_ids
            or len(self.required_check_ids) > 32
            or tuple(sorted(set(self.required_check_ids))) != self.required_check_ids
            or any(
                type(item) is not str or _CHECK_ID.fullmatch(item) is None
                for item in self.required_check_ids
            )
        ):
            raise SbxResultError("required check registry is not exact, unique, and sorted")
        _require_exact_int(
            self.max_changed_files,
            minimum=1,
            maximum=MAX_PATCH_FILES,
            label="controller changed-file cap",
        )
        _require_exact_int(
            self.max_changed_lines,
            minimum=1,
            maximum=MAX_CHANGED_LINES,
            label="controller changed-line cap",
        )
        if (
            type(self.forbidden_paths) is not tuple
            or not self.forbidden_paths
            or len(self.forbidden_paths) > MAX_FORBIDDEN_PATHS
            or any(not _valid_policy_pattern(pattern) for pattern in self.forbidden_paths)
        ):
            raise SbxResultError("forbidden-path registry is invalid")
        if not set(SBX_RESULT_MANDATORY_FORBID_PATHS).issubset(self.forbidden_paths):
            raise SbxResultError("forbidden-path registry weakens the mandatory baseline")


def _valid_policy_pattern(pattern: object) -> bool:
    if type(pattern) is not str or not pattern:
        return False
    try:
        encoded = pattern.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= MAX_PATH_BYTES
        and not pattern.startswith(("/", "-"))
        and "\\" not in pattern
        and "\x00" not in pattern
        and ".." not in PurePosixPath(pattern).parts
        and unicodedata.normalize("NFC", pattern) == pattern
    )


@dataclass(frozen=True)
class DescriptorIdentity:
    """Pure representation of one no-follow filesystem identity observation."""

    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    permissions: int
    link_count: int
    kind: str

    def __post_init__(self) -> None:
        _require_exact_int(self.device, minimum=0, maximum=2**63 - 1, label="device ID")
        _require_exact_int(self.inode, minimum=1, maximum=2**63 - 1, label="inode")
        _require_exact_int(self.owner_uid, minimum=0, maximum=2**31 - 1, label="owner UID")
        _require_exact_int(self.owner_gid, minimum=0, maximum=2**31 - 1, label="owner GID")
        _require_exact_int(self.permissions, minimum=0, maximum=0o7777, label="permissions")
        _require_exact_int(self.link_count, minimum=1, maximum=2**31 - 1, label="link count")
        if self.kind != "directory":
            raise SbxResultError("descriptor identity is not a directory")

    def to_dict(self) -> dict[str, object]:
        return {
            "device": self.device,
            "inode": self.inode,
            "kind": self.kind,
            "link_count": self.link_count,
            "owner_gid": self.owner_gid,
            "owner_uid": self.owner_uid,
            "permissions": self.permissions,
        }


@dataclass(frozen=True)
class StopCleanupEvidence:
    """Future identity-bound cleanup authority; v0.35 does not provide it.

    Command return codes and final name absence remain observations, not
    destruction attestation.  The two attestation digests model evidence that
    a future independent adapter must add before this fixture target contract
    could become a live authority.
    """

    binding_sha256: str
    controller_boot_sha256: str
    stop_observed_monotonic_ns: int
    cleanup_observed_monotonic_ns: int
    identity_attestation_sha256: str
    destruction_attestation_sha256: str
    stop_command_sha256: str
    remove_command_sha256: str
    final_list_sha256: str
    stop_returncode: int
    remove_returncode: int
    stop_acknowledged: bool
    removal_acknowledged: bool
    exact_name_absent: bool
    sandbox_instance_absent: bool
    identity_authority_independent: bool
    destruction_authority_independent: bool
    uncertainty_reason: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_sha256, "cleanup binding digest"),
            (self.controller_boot_sha256, "cleanup controller boot digest"),
            (self.identity_attestation_sha256, "future identity attestation digest"),
            (self.destruction_attestation_sha256, "future destruction attestation digest"),
            (self.stop_command_sha256, "stop-command observation digest"),
            (self.remove_command_sha256, "remove-command observation digest"),
            (self.final_list_sha256, "final-list observation digest"),
        ):
            _require_hex(value, _HEX64, label)
        _require_exact_int(
            self.stop_observed_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="stop observation time",
        )
        _require_exact_int(
            self.cleanup_observed_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="cleanup observation time",
        )
        _require_exact_int(
            self.stop_returncode, minimum=-255, maximum=255, label="stop return code"
        )
        _require_exact_int(
            self.remove_returncode, minimum=-255, maximum=255, label="remove return code"
        )
        for label, value in (
            ("stop acknowledgement", self.stop_acknowledged),
            ("removal acknowledgement", self.removal_acknowledged),
            ("exact-name absence", self.exact_name_absent),
            ("sandbox-instance absence", self.sandbox_instance_absent),
            ("independent identity authority", self.identity_authority_independent),
            ("independent destruction authority", self.destruction_authority_independent),
        ):
            _require_bool(value, label)
        if self.uncertainty_reason is not None and (
            type(self.uncertainty_reason) is not str
            or not self.uncertainty_reason
            or len(self.uncertainty_reason) > 256
            or any(character in self.uncertainty_reason for character in "\r\n\0")
        ):
            raise SbxResultError("cleanup uncertainty reason is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "binding_sha256": self.binding_sha256,
            "cleanup_observed_monotonic_ns": self.cleanup_observed_monotonic_ns,
            "controller_boot_sha256": self.controller_boot_sha256,
            "destruction_attestation_sha256": self.destruction_attestation_sha256,
            "destruction_authority_independent": self.destruction_authority_independent,
            "exact_name_absent": self.exact_name_absent,
            "final_list_sha256": self.final_list_sha256,
            "identity_attestation_sha256": self.identity_attestation_sha256,
            "identity_authority_independent": self.identity_authority_independent,
            "kind": CLEANUP_KIND,
            "remove_command_sha256": self.remove_command_sha256,
            "remove_returncode": self.remove_returncode,
            "removal_acknowledged": self.removal_acknowledged,
            "sandbox_instance_absent": self.sandbox_instance_absent,
            "stop_acknowledged": self.stop_acknowledged,
            "stop_command_sha256": self.stop_command_sha256,
            "stop_observed_monotonic_ns": self.stop_observed_monotonic_ns,
            "stop_returncode": self.stop_returncode,
            "uncertainty_reason": self.uncertainty_reason,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class RunningCaptureEvidence:
    """Opaque fixed-patch capture while the exact worker sandbox still runs.

    Docker's documented ``sbx cp`` is transport only.  The future adapter must
    select the one workspace-relative patch name, omit ``-L``, use no generic
    or issue-derived path, and verify the controller-owned destination through
    a retained private-root descriptor. The workspace is never trusted to
    supply usage or a result document. Patch bytes remain unparsed until after
    cleanup succeeds.
    """

    binding_sha256: str
    controller_boot_sha256: str
    capture_started_monotonic_ns: int
    capture_finished_monotonic_ns: int
    capture_command_sha256: str
    capture_output_sha256: str
    patch_sha256: str
    patch_bytes: int
    root_at_open: DescriptorIdentity
    root_descriptor_after: DescriptorIdentity
    root_entry_after: DescriptorIdentity
    parent_at_open: DescriptorIdentity
    parent_after: DescriptorIdentity
    transport: str
    remote_relative_paths: tuple[str, ...]
    artifact_names: tuple[str, ...]
    cp_options: tuple[str, ...]
    destination_quota_bytes: int
    capture_deadline_ms: int
    opened_nofollow: bool
    descriptor_cloexec: bool
    fixed_cp_used: bool
    follow_links: bool
    generic_cp_used: bool
    issue_controlled_path_used: bool
    sandbox_running_before: bool
    sandbox_running_after: bool
    destination_regular_files: bool
    destination_unaliased_files: bool
    destination_quota_enforced: bool
    capture_deadline_enforced: bool
    capture_process_reaped: bool
    bytes_unparsed: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_sha256, "capture binding digest"),
            (self.controller_boot_sha256, "capture controller boot digest"),
            (self.capture_command_sha256, "capture-command digest"),
            (self.capture_output_sha256, "capture-output digest"),
            (self.patch_sha256, "captured patch digest"),
        ):
            _require_hex(value, _HEX64, label)
        _require_exact_int(
            self.capture_started_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="capture start time",
        )
        _require_exact_int(
            self.capture_finished_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="capture finish time",
        )
        _require_exact_int(
            self.patch_bytes, minimum=1, maximum=MAX_PATCH_BYTES, label="patch byte count"
        )
        if self.destination_quota_bytes != MAX_CAPTURE_BYTES:
            raise SbxResultError("capture destination quota is not the fixed byte cap")
        if self.capture_deadline_ms != FIXED_CAPTURE_DEADLINE_MS:
            raise SbxResultError("capture deadline is not fixed")
        for identity in (
            self.root_at_open,
            self.root_descriptor_after,
            self.root_entry_after,
            self.parent_at_open,
            self.parent_after,
        ):
            if type(identity) is not DescriptorIdentity:
                raise SbxResultError("capture descriptor identity is invalid")
        if self.transport != "sbx-cp-v0.35-fixed-files":
            raise SbxResultError("capture transport is not fixed sbx cp")
        if self.remote_relative_paths != (".leftovers-export/canonical.patch",):
            raise SbxResultError("capture source name is not the controller-fixed patch")
        if self.artifact_names != ("canonical.patch",):
            raise SbxResultError("capture destination name is not the fixed patch")
        if self.cp_options != ():
            raise SbxResultError(
                "capture options are not empty; -L and generic options are forbidden"
            )
        for label, value in (
            ("no-follow open", self.opened_nofollow),
            ("close-on-exec descriptor", self.descriptor_cloexec),
            ("fixed sbx cp use", self.fixed_cp_used),
            ("symlink following", self.follow_links),
            ("generic sbx cp use", self.generic_cp_used),
            ("issue-controlled capture path", self.issue_controlled_path_used),
            ("running state before capture", self.sandbox_running_before),
            ("running state after capture", self.sandbox_running_after),
            ("regular destination files", self.destination_regular_files),
            ("unaliased destination files", self.destination_unaliased_files),
            ("capture destination quota", self.destination_quota_enforced),
            ("capture deadline", self.capture_deadline_enforced),
            ("capture process reap", self.capture_process_reaped),
            ("opaque unparsed bytes", self.bytes_unparsed),
        ):
            _require_bool(value, label)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_names": list(self.artifact_names),
            "binding_sha256": self.binding_sha256,
            "bytes_unparsed": self.bytes_unparsed,
            "capture_command_sha256": self.capture_command_sha256,
            "capture_deadline_enforced": self.capture_deadline_enforced,
            "capture_deadline_ms": self.capture_deadline_ms,
            "capture_finished_monotonic_ns": self.capture_finished_monotonic_ns,
            "capture_output_sha256": self.capture_output_sha256,
            "capture_process_reaped": self.capture_process_reaped,
            "capture_started_monotonic_ns": self.capture_started_monotonic_ns,
            "controller_boot_sha256": self.controller_boot_sha256,
            "cp_options": list(self.cp_options),
            "descriptor_cloexec": self.descriptor_cloexec,
            "destination_regular_files": self.destination_regular_files,
            "destination_quota_bytes": self.destination_quota_bytes,
            "destination_quota_enforced": self.destination_quota_enforced,
            "destination_unaliased_files": self.destination_unaliased_files,
            "fixed_cp_used": self.fixed_cp_used,
            "follow_links": self.follow_links,
            "generic_cp_used": self.generic_cp_used,
            "issue_controlled_path_used": self.issue_controlled_path_used,
            "kind": CAPTURE_KIND,
            "opened_nofollow": self.opened_nofollow,
            "parent_after": self.parent_after.to_dict(),
            "parent_at_open": self.parent_at_open.to_dict(),
            "patch_bytes": self.patch_bytes,
            "patch_sha256": self.patch_sha256,
            "remote_relative_paths": list(self.remote_relative_paths),
            "root_at_open": self.root_at_open.to_dict(),
            "root_descriptor_after": self.root_descriptor_after.to_dict(),
            "root_entry_after": self.root_entry_after.to_dict(),
            "sandbox_running_after": self.sandbox_running_after,
            "sandbox_running_before": self.sandbox_running_before,
            "transport": self.transport,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class ControllerResultEvidence:
    """Controller-owned result document built after independent verification.

    The running workspace cannot author or export these bytes. The controller
    constructs them from its exact three-call JSONL usage receipt plus the
    independently verified patch summary in a separate private root.
    """

    binding_sha256: str
    controller_boot_sha256: str
    freshness_challenge_sha256: str
    constructed_monotonic_ns: int
    result_sha256: str
    result_bytes: int
    patch_sha256: str
    source_usage_sha256: str
    source_event_stream_sha256: str
    root_at_open: DescriptorIdentity
    root_descriptor_after: DescriptorIdentity
    root_entry_after: DescriptorIdentity
    parent_at_open: DescriptorIdentity
    parent_after: DescriptorIdentity
    artifact_name: str
    opened_nofollow: bool
    descriptor_cloexec: bool
    controller_constructed: bool
    constructed_from_exact_usage: bool
    workspace_result_bytes_used: bool
    result_regular_file: bool
    result_unaliased_file: bool
    result_root_removed: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_sha256, "controller-result binding digest"),
            (self.controller_boot_sha256, "controller-result boot digest"),
            (self.freshness_challenge_sha256, "controller-result challenge digest"),
            (self.result_sha256, "controller result digest"),
            (self.patch_sha256, "controller-result patch digest"),
            (self.source_usage_sha256, "controller-result source usage digest"),
            (self.source_event_stream_sha256, "controller-result event-stream digest"),
        ):
            _require_hex(value, _HEX64, label)
        _require_exact_int(
            self.constructed_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="controller-result construction time",
        )
        _require_exact_int(
            self.result_bytes,
            minimum=1,
            maximum=MAX_RESULT_BYTES,
            label="controller-result byte count",
        )
        for identity in (
            self.root_at_open,
            self.root_descriptor_after,
            self.root_entry_after,
            self.parent_at_open,
            self.parent_after,
        ):
            if type(identity) is not DescriptorIdentity:
                raise SbxResultError("controller-result descriptor identity is invalid")
        if self.artifact_name != "result.json":
            raise SbxResultError("controller-result artifact name is not fixed")
        for label, value in (
            ("controller-result no-follow open", self.opened_nofollow),
            ("controller-result close-on-exec descriptor", self.descriptor_cloexec),
            ("controller result construction", self.controller_constructed),
            ("exact-usage result construction", self.constructed_from_exact_usage),
            ("workspace result-byte use", self.workspace_result_bytes_used),
            ("controller-result regular file", self.result_regular_file),
            ("controller-result unaliased file", self.result_unaliased_file),
            ("controller-result root cleanup", self.result_root_removed),
        ):
            _require_bool(value, label)

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_name": self.artifact_name,
            "binding_sha256": self.binding_sha256,
            "constructed_from_exact_usage": self.constructed_from_exact_usage,
            "constructed_monotonic_ns": self.constructed_monotonic_ns,
            "controller_boot_sha256": self.controller_boot_sha256,
            "controller_constructed": self.controller_constructed,
            "descriptor_cloexec": self.descriptor_cloexec,
            "freshness_challenge_sha256": self.freshness_challenge_sha256,
            "kind": CONTROLLER_RESULT_KIND,
            "opened_nofollow": self.opened_nofollow,
            "parent_after": self.parent_after.to_dict(),
            "parent_at_open": self.parent_at_open.to_dict(),
            "patch_sha256": self.patch_sha256,
            "result_bytes": self.result_bytes,
            "result_regular_file": self.result_regular_file,
            "result_root_removed": self.result_root_removed,
            "result_sha256": self.result_sha256,
            "result_unaliased_file": self.result_unaliased_file,
            "root_at_open": self.root_at_open.to_dict(),
            "root_descriptor_after": self.root_descriptor_after.to_dict(),
            "root_entry_after": self.root_entry_after.to_dict(),
            "source_event_stream_sha256": self.source_event_stream_sha256,
            "source_usage_sha256": self.source_usage_sha256,
            "workspace_result_bytes_used": self.workspace_result_bytes_used,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class VerifierCheckReceipt:
    check_id: str
    exit_code: int | None
    timed_out: bool
    truncated: bool
    output_sha256: str

    def __post_init__(self) -> None:
        if type(self.check_id) is not str or _CHECK_ID.fullmatch(self.check_id) is None:
            raise SbxResultError("verifier check ID is invalid")
        if self.exit_code is not None:
            _require_exact_int(
                self.exit_code, minimum=-255, maximum=255, label="verifier check exit code"
            )
        _require_bool(self.timed_out, "verifier check timeout")
        _require_bool(self.truncated, "verifier check truncation")
        if self.timed_out and self.exit_code is not None:
            raise SbxResultError("timed-out verifier check has an exit code")
        if not self.timed_out and self.exit_code is None:
            raise SbxResultError("completed verifier check lacks an exit code")
        _require_hex(self.output_sha256, _HEX64, "verifier check output digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "exit_code": self.exit_code,
            "output_sha256": self.output_sha256,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class IndependentVerifierReceipt:
    """Post-cleanup parsing and checks in a fresh independent sandbox."""

    binding_sha256: str
    controller_boot_sha256: str
    freshness_challenge_sha256: str
    verifier_identity_sha256: str
    verification_profile_sha256: str
    parse_started_monotonic_ns: int
    verified_monotonic_ns: int
    capture_sha256: str
    cleanup_sha256: str
    applied_patch_sha256: str
    inspected_patch_sha256: str
    inspected_diff_sha256: str
    source_manifest_sha256: str
    policy_sha256: str
    base_sha: str
    changed_paths: tuple[str, ...]
    changed_lines: int
    checks: tuple[VerifierCheckReceipt, ...]
    parse_root_descriptor: DescriptorIdentity
    parse_root_entry: DescriptorIdentity
    verifier_sandbox_uuid: str
    verifier_sandbox_generation: int
    verifier_instance_attestation_sha256: str
    verifier_cleanup_attestation_sha256: str
    independent_domain: bool
    fresh_verifier_sandbox: bool
    worker_mount_absent: bool
    network_denied: bool
    credentials_absent: bool
    reconstructed_source: bool
    policy_allowed: bool
    unresolved_review: bool
    capture_root_removed: bool
    verification_sandbox_removed: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_sha256, "verifier binding digest"),
            (self.controller_boot_sha256, "verifier boot digest"),
            (self.freshness_challenge_sha256, "verifier freshness challenge"),
            (self.verifier_identity_sha256, "verifier identity digest"),
            (self.verification_profile_sha256, "verification profile digest"),
            (self.capture_sha256, "verified capture digest"),
            (self.cleanup_sha256, "verified cleanup digest"),
            (self.applied_patch_sha256, "applied patch digest"),
            (self.inspected_patch_sha256, "inspected patch digest"),
            (self.inspected_diff_sha256, "inspected diff digest"),
            (self.source_manifest_sha256, "verified source manifest digest"),
            (self.policy_sha256, "verified policy digest"),
            (self.verifier_instance_attestation_sha256, "verifier instance attestation"),
            (self.verifier_cleanup_attestation_sha256, "verifier cleanup attestation"),
        ):
            _require_hex(value, _HEX64, label)
        _require_hex(self.base_sha, _HEX40_OR_64, "verifier base SHA")
        _require_exact_int(
            self.parse_started_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="post-cleanup parse start time",
        )
        _require_exact_int(
            self.verified_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="verifier observation time",
        )
        if (
            type(self.changed_paths) is not tuple
            or not self.changed_paths
            or len(self.changed_paths) > MAX_PATCH_FILES
            or tuple(sorted(set(self.changed_paths))) != self.changed_paths
        ):
            raise SbxResultError("verifier changed-path evidence is invalid")
        for path in self.changed_paths:
            _normal_patch_path(path)
        _require_exact_int(
            self.changed_lines,
            minimum=1,
            maximum=MAX_CHANGED_LINES,
            label="verifier changed-line count",
        )
        if (
            type(self.checks) is not tuple
            or not self.checks
            or len(self.checks) > 32
            or any(type(check) is not VerifierCheckReceipt for check in self.checks)
        ):
            raise SbxResultError("verifier check evidence is invalid")
        if (
            type(self.parse_root_descriptor) is not DescriptorIdentity
            or type(self.parse_root_entry) is not DescriptorIdentity
        ):
            raise SbxResultError("verifier parse-root identity is invalid")
        try:
            verifier_uuid = uuid.UUID(self.verifier_sandbox_uuid)
        except (AttributeError, TypeError, ValueError) as exc:
            raise SbxResultError("verifier sandbox UUID is invalid") from exc
        if str(verifier_uuid) != self.verifier_sandbox_uuid or verifier_uuid.int == 0:
            raise SbxResultError("verifier sandbox UUID is not canonical and nonzero")
        _require_exact_int(
            self.verifier_sandbox_generation,
            minimum=1,
            maximum=2**63 - 1,
            label="verifier sandbox generation",
        )
        for label, value in (
            ("independent verifier domain", self.independent_domain),
            ("fresh verifier sandbox", self.fresh_verifier_sandbox),
            ("worker mount absence", self.worker_mount_absent),
            ("verifier network denial", self.network_denied),
            ("verifier credential absence", self.credentials_absent),
            ("reconstructed source", self.reconstructed_source),
            ("policy result", self.policy_allowed),
            ("unresolved review", self.unresolved_review),
            ("capture-root cleanup", self.capture_root_removed),
            ("verification-sandbox cleanup", self.verification_sandbox_removed),
        ):
            _require_bool(value, label)

    def to_dict(self) -> dict[str, object]:
        return {
            "applied_patch_sha256": self.applied_patch_sha256,
            "base_sha": self.base_sha,
            "binding_sha256": self.binding_sha256,
            "changed_lines": self.changed_lines,
            "changed_paths": list(self.changed_paths),
            "checks": [check.to_dict() for check in self.checks],
            "cleanup_sha256": self.cleanup_sha256,
            "controller_boot_sha256": self.controller_boot_sha256,
            "capture_root_removed": self.capture_root_removed,
            "capture_sha256": self.capture_sha256,
            "credentials_absent": self.credentials_absent,
            "freshness_challenge_sha256": self.freshness_challenge_sha256,
            "fresh_verifier_sandbox": self.fresh_verifier_sandbox,
            "independent_domain": self.independent_domain,
            "inspected_diff_sha256": self.inspected_diff_sha256,
            "inspected_patch_sha256": self.inspected_patch_sha256,
            "kind": VERIFIER_KIND,
            "network_denied": self.network_denied,
            "parse_root_descriptor": self.parse_root_descriptor.to_dict(),
            "parse_root_entry": self.parse_root_entry.to_dict(),
            "parse_started_monotonic_ns": self.parse_started_monotonic_ns,
            "policy_allowed": self.policy_allowed,
            "policy_sha256": self.policy_sha256,
            "reconstructed_source": self.reconstructed_source,
            "source_manifest_sha256": self.source_manifest_sha256,
            "unresolved_review": self.unresolved_review,
            "verification_profile_sha256": self.verification_profile_sha256,
            "verification_sandbox_removed": self.verification_sandbox_removed,
            "verified_monotonic_ns": self.verified_monotonic_ns,
            "verifier_identity_sha256": self.verifier_identity_sha256,
            "verifier_cleanup_attestation_sha256": self.verifier_cleanup_attestation_sha256,
            "verifier_instance_attestation_sha256": self.verifier_instance_attestation_sha256,
            "verifier_sandbox_generation": self.verifier_sandbox_generation,
            "verifier_sandbox_uuid": self.verifier_sandbox_uuid,
            "worker_mount_absent": self.worker_mount_absent,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class FreshBaseRecheck:
    """Immediate controller-side remote read before producing a handoff."""

    binding_sha256: str
    controller_boot_sha256: str
    freshness_challenge_sha256: str
    verifier_sha256: str
    controller_result_sha256: str
    observed_monotonic_ns: int
    repository: str
    issue_number: int
    observed_base_sha: str
    remote_read_receipt_sha256: str
    issue_open: bool
    assignment_clear: bool
    linked_or_open_pr_absent: bool

    def __post_init__(self) -> None:
        for value, label in (
            (self.binding_sha256, "base-recheck binding digest"),
            (self.controller_boot_sha256, "base-recheck boot digest"),
            (self.freshness_challenge_sha256, "base-recheck challenge digest"),
            (self.verifier_sha256, "base-recheck verifier digest"),
            (self.controller_result_sha256, "base-recheck controller-result digest"),
            (self.remote_read_receipt_sha256, "remote-read receipt digest"),
        ):
            _require_hex(value, _HEX64, label)
        _require_exact_int(
            self.observed_monotonic_ns,
            minimum=1,
            maximum=2**63 - 1,
            label="base-recheck observation time",
        )
        if type(self.repository) is not str or _REPOSITORY.fullmatch(self.repository) is None:
            raise SbxResultError("base-recheck repository identity is invalid")
        _require_exact_int(
            self.issue_number, minimum=1, maximum=2**31 - 1, label="base-recheck issue"
        )
        _require_hex(self.observed_base_sha, _HEX40_OR_64, "fresh base SHA")
        for label, value in (
            ("fresh issue-open state", self.issue_open),
            ("fresh assignment state", self.assignment_clear),
            ("fresh linked-PR state", self.linked_or_open_pr_absent),
        ):
            _require_bool(value, label)

    def to_dict(self) -> dict[str, object]:
        return {
            "assignment_clear": self.assignment_clear,
            "binding_sha256": self.binding_sha256,
            "controller_boot_sha256": self.controller_boot_sha256,
            "controller_result_sha256": self.controller_result_sha256,
            "freshness_challenge_sha256": self.freshness_challenge_sha256,
            "issue_number": self.issue_number,
            "issue_open": self.issue_open,
            "kind": BASE_RECHECK_KIND,
            "linked_or_open_pr_absent": self.linked_or_open_pr_absent,
            "observed_base_sha": self.observed_base_sha,
            "observed_monotonic_ns": self.observed_monotonic_ns,
            "remote_read_receipt_sha256": self.remote_read_receipt_sha256,
            "repository": self.repository,
            "verifier_sha256": self.verifier_sha256,
        }

    @property
    def sha256(self) -> str:
        return _sha256(_canonical_json(self.to_dict()))


@dataclass(frozen=True)
class PatchSummary:
    sha256: str
    paths: tuple[str, ...]
    changed_lines: int
    byte_count: int


_HANDOFF_SEAL = object()


@dataclass(frozen=True, init=False)
class CapabilityFreeSbxHandoff:
    """Bounded immutable data only; this type cannot call a publisher."""

    kind: str
    binding: SbxRunBinding
    canonical_patch: bytes
    patch_sha256: str
    result_sha256: str
    usage: ExactUsageReceipt
    cleanup_sha256: str
    capture_sha256: str
    verifier_sha256: str
    controller_result_sha256: str
    base_recheck_sha256: str
    changed_paths: tuple[str, ...]
    changed_lines: int
    _seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        kind: str,
        binding: SbxRunBinding,
        canonical_patch: bytes,
        patch_sha256: str,
        result_sha256: str,
        usage: ExactUsageReceipt,
        cleanup_sha256: str,
        capture_sha256: str,
        verifier_sha256: str,
        controller_result_sha256: str,
        base_recheck_sha256: str,
        changed_paths: tuple[str, ...],
        changed_lines: int,
        seal: object,
    ) -> None:
        if seal is not _HANDOFF_SEAL:
            raise SbxResultError("sbx handoff requires verified in-module construction")
        for name, value in (
            ("kind", kind),
            ("binding", binding),
            ("canonical_patch", canonical_patch),
            ("patch_sha256", patch_sha256),
            ("result_sha256", result_sha256),
            ("usage", usage),
            ("cleanup_sha256", cleanup_sha256),
            ("capture_sha256", capture_sha256),
            ("verifier_sha256", verifier_sha256),
            ("controller_result_sha256", controller_result_sha256),
            ("base_recheck_sha256", base_recheck_sha256),
            ("changed_paths", changed_paths),
            ("changed_lines", changed_lines),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_seal", seal)
        self.__post_init__()

    def __post_init__(self) -> None:
        if self.kind != HANDOFF_KIND:
            raise SbxResultError("handoff kind is invalid")
        if type(self.binding) is not SbxRunBinding or type(self.usage) is not ExactUsageReceipt:
            raise SbxResultError("handoff typed evidence is invalid")
        if (
            type(self.canonical_patch) is not bytes
            or _sha256(self.canonical_patch) != self.patch_sha256
        ):
            raise SbxResultError("handoff patch bytes do not match")
        summary = inspect_canonical_patch(
            self.canonical_patch,
            forbidden_paths=SBX_RESULT_MANDATORY_FORBID_PATHS,
        )
        if summary.paths != self.changed_paths or summary.changed_lines != self.changed_lines:
            raise SbxResultError("handoff patch summary does not match its bytes")
        if _usage_from_dict(self.usage.to_dict()) != self.usage:
            raise SbxResultError("handoff usage is not an exact revalidated receipt")
        for value, label in (
            (self.patch_sha256, "handoff patch digest"),
            (self.result_sha256, "handoff result digest"),
            (self.cleanup_sha256, "handoff cleanup digest"),
            (self.capture_sha256, "handoff capture digest"),
            (self.verifier_sha256, "handoff verifier digest"),
            (self.controller_result_sha256, "handoff controller-result digest"),
            (self.base_recheck_sha256, "handoff base-recheck digest"),
        ):
            _require_hex(value, _HEX64, label)


def _normal_patch_path(path: str) -> str:
    if (
        type(path) is not str
        or not path
        or _SAFE_PATH.fullmatch(path) is None
        or unicodedata.normalize("NFC", path) != path
    ):
        raise SbxResultError("patch path is not in the canonical path alphabet")
    encoded = path.encode("utf-8")
    parts = path.split("/")
    if (
        len(encoded) > MAX_PATH_BYTES
        or len(parts) > MAX_PATH_DEPTH
        or any(not part or part in {".", ".."} for part in parts)
        or ".git" in parts
    ):
        raise SbxResultError("patch path escapes or exceeds its bound")
    return path


def _forbidden_path(path: str, patterns: tuple[str, ...]) -> bool:
    if path == ".git" or path.startswith(".git/"):
        return True
    if any(
        fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)
        for pattern in patterns
    ):
        return True
    basename = PurePosixPath(path).name
    return (
        basename in _DEPENDENCY_FILES
        or any(fnmatch.fnmatchcase(basename, pattern) for pattern in _DEPENDENCY_FILE_PATTERNS)
        or any(
            fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)
            for pattern in _DEPENDENCY_PATH_PATTERNS
        )
    )


def _parse_range(raw_start: bytes, raw_count: bytes | None) -> tuple[int, int]:
    try:
        start = int(raw_start)
        count = 1 if raw_count is None else int(raw_count)
    except ValueError as exc:
        raise SbxResultError("patch hunk range is not a bounded integer") from exc
    if start > 2**31 - 1 or count > 2**31 - 1:
        raise SbxResultError("patch hunk range exceeds its integer cap")
    if raw_count is not None and count == 1:
        raise SbxResultError("patch hunk uses a non-canonical explicit count of one")
    if count == 0:
        if raw_count is None:
            raise SbxResultError("zero-length hunk range must be explicit")
    elif start == 0:
        raise SbxResultError("nonempty hunk range starts at zero")
    return start, count


def inspect_canonical_patch(patch: bytes, *, forbidden_paths: tuple[str, ...]) -> PatchSummary:
    """Parse a deliberately narrow canonical textual Git patch without Git.

    Only ordinary 100644 additions, deletions, and same-path modifications are
    admitted.  Rename/copy metadata, binary bodies, symlinks, submodules,
    executable modes, quoted paths, combined diffs, and no-newline markers are
    outside this contract and fail closed.
    """

    if type(patch) is not bytes or not patch or len(patch) > MAX_PATCH_BYTES:
        raise SbxResultError("canonical patch exceeds its byte cap")
    if type(forbidden_paths) is not tuple or any(
        not _valid_policy_pattern(pattern) for pattern in forbidden_paths
    ):
        raise SbxResultError("patch forbidden-path policy is invalid")
    if b"\x00" in patch or b"\r" in patch or not patch.endswith(b"\n"):
        raise SbxResultError("canonical patch framing is invalid")
    try:
        text = patch.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SbxResultError("canonical patch is not UTF-8") from exc
    if unicodedata.normalize("NFC", text) != text or any(
        ord(character) < 32 and character not in {"\n", "\t"} for character in text
    ):
        raise SbxResultError("canonical patch text is not normalized")
    lines = patch.splitlines(keepends=True)
    if any(not line.endswith(b"\n") or len(line) > MAX_PATCH_LINE_BYTES for line in lines):
        raise SbxResultError("canonical patch contains an overlong or unterminated line")

    index = 0
    paths: list[str] = []
    changed_lines = 0
    while index < len(lines):
        header = _DIFF_HEADER.fullmatch(lines[index])
        if header is None:
            raise SbxResultError("patch section lacks a canonical diff header")
        old_path = _normal_patch_path(header.group(1).decode("ascii"))
        new_path = _normal_patch_path(header.group(2).decode("ascii"))
        if old_path != new_path:
            raise SbxResultError("rename and copy patches are forbidden")
        path = old_path
        if paths and path <= paths[-1]:
            raise SbxResultError("patch paths are duplicated or not canonically sorted")
        if _forbidden_path(path, forbidden_paths):
            raise SbxResultError("patch touches a forbidden or dependency path")
        paths.append(path)
        if len(paths) > MAX_PATCH_FILES:
            raise SbxResultError("canonical patch exceeds its file cap")
        index += 1
        if index >= len(lines):
            raise SbxResultError("patch section is truncated")

        change_kind = "modify"
        if lines[index].startswith(b"new file mode "):
            if lines[index] != b"new file mode 100644\n":
                raise SbxResultError("patch adds an unsafe file mode")
            change_kind = "add"
            index += 1
        elif lines[index].startswith(b"deleted file mode "):
            if lines[index] != b"deleted file mode 100644\n":
                raise SbxResultError("patch deletes an unsafe file mode")
            change_kind = "delete"
            index += 1
        elif lines[index].startswith((b"old mode ", b"new mode ")):
            raise SbxResultError("patch mode changes are forbidden")
        if index >= len(lines):
            raise SbxResultError("patch section is truncated before index metadata")
        index_header = _INDEX_HEADER.fullmatch(lines[index])
        if index_header is None:
            raise SbxResultError("patch index metadata is not canonical text-mode metadata")
        old_hash, new_hash, mode = index_header.groups()
        if len(old_hash) != len(new_hash):
            raise SbxResultError("patch index hash widths differ")
        old_zero = not old_hash.strip(b"0")
        new_zero = not new_hash.strip(b"0")
        if change_kind == "add":
            valid_index = old_zero and not new_zero and mode is None
        elif change_kind == "delete":
            valid_index = not old_zero and new_zero and mode is None
        else:
            valid_index = (
                not old_zero and not new_zero and old_hash != new_hash and mode == b"100644"
            )
        if not valid_index:
            raise SbxResultError("patch index metadata contradicts its change kind")
        index += 1

        expected_old = (
            b"--- /dev/null\n" if change_kind == "add" else b"--- a/" + old_path.encode() + b"\n"
        )
        expected_new = (
            b"+++ /dev/null\n" if change_kind == "delete" else b"+++ b/" + new_path.encode() + b"\n"
        )
        if (
            index + 1 >= len(lines)
            or lines[index] != expected_old
            or lines[index + 1] != expected_new
        ):
            raise SbxResultError("patch file headers do not bind the section path")
        index += 2

        hunk_count = 0
        previous_old_end = 0
        previous_new_end = 0
        file_additions = 0
        file_deletions = 0
        while index < len(lines) and not lines[index].startswith(b"diff --git "):
            hunk = _HUNK_HEADER.fullmatch(lines[index])
            if hunk is None:
                raise SbxResultError("patch contains unsupported metadata or malformed hunk")
            old_start, old_count = _parse_range(hunk.group(1), hunk.group(2))
            new_start, new_count = _parse_range(hunk.group(3), hunk.group(4))
            if old_start < previous_old_end or new_start < previous_new_end:
                raise SbxResultError("patch hunks overlap or are not ordered")
            previous_old_end = old_start + old_count
            previous_new_end = new_start + new_count
            index += 1
            consumed_old = 0
            consumed_new = 0
            hunk_changes = 0
            while consumed_old < old_count or consumed_new < new_count:
                if index >= len(lines):
                    raise SbxResultError("patch hunk body is truncated")
                line = lines[index]
                prefix = line[:1]
                if prefix == b" ":
                    consumed_old += 1
                    consumed_new += 1
                elif prefix == b"-":
                    consumed_old += 1
                    file_deletions += 1
                    hunk_changes += 1
                elif prefix == b"+":
                    consumed_new += 1
                    file_additions += 1
                    hunk_changes += 1
                else:
                    raise SbxResultError("patch hunk has an unsupported body marker")
                if consumed_old > old_count or consumed_new > new_count:
                    raise SbxResultError("patch hunk body exceeds its declared ranges")
                index += 1
            if hunk_changes == 0:
                raise SbxResultError("patch hunk contains no changed line")
            changed_lines += hunk_changes
            if changed_lines > MAX_CHANGED_LINES:
                raise SbxResultError("canonical patch exceeds its changed-line cap")
            hunk_count += 1
        if hunk_count == 0:
            raise SbxResultError("patch section has no unified hunk")
        if change_kind == "add" and (
            hunk_count != 1 or file_deletions or not file_additions or previous_old_end != 0
        ):
            raise SbxResultError("new-file patch has contradictory hunk content")
        if change_kind == "delete" and (
            hunk_count != 1 or file_additions or not file_deletions or previous_new_end != 0
        ):
            raise SbxResultError("deleted-file patch has contradictory hunk content")

    return PatchSummary(
        sha256=_sha256(patch),
        paths=tuple(paths),
        changed_lines=changed_lines,
        byte_count=len(patch),
    )


def encode_fixture_result(
    plan: SbxResultPlan,
    *,
    patch: bytes,
    usage: ExactUsageReceipt,
    fixture_capability: FixtureSbxResultCapability,
) -> bytes:
    """Build canonical fixture bytes; the output conveys no authority."""

    _require_fixture_capability(fixture_capability)
    if type(plan) is not SbxResultPlan or type(usage) is not ExactUsageReceipt:
        raise SbxResultError("fixture result inputs are not exact typed evidence")
    summary = inspect_canonical_patch(patch, forbidden_paths=plan.forbidden_paths)
    _enforce_plan_patch_limits(plan, summary)
    if usage.total_tokens > plan.binding.total_token_cap:
        raise SbxResultError("exact usage exceeds the controller token cap")
    return _canonical_json(
        {
            "binding": plan.binding.to_dict(),
            "kind": RESULT_KIND,
            "limits": {
                "max_changed_files": plan.max_changed_files,
                "max_changed_lines": plan.max_changed_lines,
            },
            "patch": {
                "byte_count": summary.byte_count,
                "changed_lines": summary.changed_lines,
                "paths": list(summary.paths),
                "sha256": summary.sha256,
            },
            "usage": usage.to_dict(),
        }
    )


def _require_fixture_capability(capability: FixtureSbxResultCapability) -> None:
    if capability is not _FIXTURE_CAPABILITY:
        raise SbxResultError("explicit fixture sbx-result capability is required")


def _call_usage_from_dict(value: object) -> ExactCallUsage:
    call = _exact_keys(
        value,
        frozenset(
            {
                "cache_write_input_tokens",
                "cached_input_tokens",
                "call_index",
                "event_stream_sha256",
                "exact",
                "input_tokens",
                "output_tokens",
                "reasoning_tokens",
                "reservation_sha256",
                "source",
                "stage",
                "thread_id",
                "total_tokens",
            }
        ),
        "per-call usage receipt",
    )
    try:
        stage = ExecutionStage(call["stage"])
    except (TypeError, ValueError) as exc:
        raise SbxResultError("per-call usage stage is invalid") from exc
    return ExactCallUsage(
        stage=stage,
        call_index=call["call_index"],  # type: ignore[arg-type]
        input_tokens=call["input_tokens"],  # type: ignore[arg-type]
        output_tokens=call["output_tokens"],  # type: ignore[arg-type]
        cached_input_tokens=call["cached_input_tokens"],  # type: ignore[arg-type]
        cache_write_input_tokens=call["cache_write_input_tokens"],  # type: ignore[arg-type]
        reasoning_tokens=call["reasoning_tokens"],  # type: ignore[arg-type]
        total_tokens=call["total_tokens"],  # type: ignore[arg-type]
        source=call["source"],  # type: ignore[arg-type]
        exact=call["exact"],  # type: ignore[arg-type]
        event_stream_sha256=call["event_stream_sha256"],  # type: ignore[arg-type]
        thread_id=call["thread_id"],  # type: ignore[arg-type]
        reservation_sha256=call["reservation_sha256"],  # type: ignore[arg-type]
    )


def _usage_from_dict(value: object) -> ExactUsageReceipt:
    usage = _exact_keys(
        value,
        frozenset(
            {
                "aggregate_event_stream_sha256",
                "cache_write_input_tokens",
                "cached_input_tokens",
                "calls",
                "exact",
                "input_tokens",
                "kind",
                "output_tokens",
                "provider_call_count",
                "reasoning_tokens",
                "reservation_sha256",
                "source",
                "total_tokens",
            }
        ),
        "usage receipt",
    )
    if usage["kind"] != USAGE_KIND:
        raise SbxResultError("usage receipt kind is invalid")
    raw_calls = usage["calls"]
    if type(raw_calls) is not list:
        raise SbxResultError("usage calls are not an exact JSON array")
    return ExactUsageReceipt(
        calls=tuple(_call_usage_from_dict(call) for call in raw_calls),
        input_tokens=usage["input_tokens"],  # type: ignore[arg-type]
        output_tokens=usage["output_tokens"],  # type: ignore[arg-type]
        cached_input_tokens=usage["cached_input_tokens"],  # type: ignore[arg-type]
        cache_write_input_tokens=usage["cache_write_input_tokens"],  # type: ignore[arg-type]
        reasoning_tokens=usage["reasoning_tokens"],  # type: ignore[arg-type]
        total_tokens=usage["total_tokens"],  # type: ignore[arg-type]
        source=usage["source"],  # type: ignore[arg-type]
        exact=usage["exact"],  # type: ignore[arg-type]
        provider_call_count=usage["provider_call_count"],  # type: ignore[arg-type]
        aggregate_event_stream_sha256=usage["aggregate_event_stream_sha256"],  # type: ignore[arg-type]
        reservation_sha256=usage["reservation_sha256"],  # type: ignore[arg-type]
    )


def _validate_result_document(
    plan: SbxResultPlan,
    *,
    result_document: bytes,
    patch_summary: PatchSummary,
) -> tuple[str, ExactUsageReceipt]:
    document = _exact_keys(
        _parse_canonical_json(result_document),
        frozenset({"binding", "kind", "limits", "patch", "usage"}),
        "result document",
    )
    if document["kind"] != RESULT_KIND:
        raise SbxResultError("result document kind is invalid")
    binding = _exact_keys(document["binding"], frozenset(plan.binding.to_dict()), "result binding")
    if binding != plan.binding.to_dict():
        raise SbxResultError("result document binding does not match the controller plan")
    limits = _exact_keys(
        document["limits"],
        frozenset({"max_changed_files", "max_changed_lines"}),
        "result patch limits",
    )
    if limits != {
        "max_changed_files": plan.max_changed_files,
        "max_changed_lines": plan.max_changed_lines,
    }:
        raise SbxResultError("result document patch limits do not match the controller plan")
    patch = _exact_keys(
        document["patch"],
        frozenset({"byte_count", "changed_lines", "paths", "sha256"}),
        "result patch summary",
    )
    expected_patch = {
        "byte_count": patch_summary.byte_count,
        "changed_lines": patch_summary.changed_lines,
        "paths": list(patch_summary.paths),
        "sha256": patch_summary.sha256,
    }
    if patch != expected_patch:
        raise SbxResultError("result patch summary does not match canonical patch bytes")
    usage = _usage_from_dict(document["usage"])
    if usage.total_tokens > plan.binding.total_token_cap:
        raise SbxResultError("exact usage exceeds the controller token cap")
    return _sha256(result_document), usage


def _enforce_plan_patch_limits(plan: SbxResultPlan, summary: PatchSummary) -> None:
    if len(summary.paths) > plan.max_changed_files:
        raise SbxResultError("canonical patch exceeds the controller changed-file cap")
    if summary.changed_lines > plan.max_changed_lines:
        raise SbxResultError("canonical patch exceeds the controller changed-line cap")


def _require_cleanup_complete(plan: SbxResultPlan, cleanup: StopCleanupEvidence) -> None:
    if cleanup.binding_sha256 != plan.binding.sha256:
        raise SbxCleanupPending("cleanup evidence does not identify the planned sandbox generation")
    if cleanup.controller_boot_sha256 != plan.controller_boot_sha256:
        raise SbxCleanupPending("cleanup evidence crosses an untrusted controller boot")
    complete = (
        cleanup.stop_returncode == 0,
        cleanup.remove_returncode == 0,
        cleanup.stop_acknowledged,
        cleanup.removal_acknowledged,
        cleanup.exact_name_absent,
        cleanup.sandbox_instance_absent,
        cleanup.identity_authority_independent,
        cleanup.destruction_authority_independent,
    )
    if (
        cleanup.uncertainty_reason is not None
        or not all(complete)
        or cleanup.cleanup_observed_monotonic_ns <= cleanup.stop_observed_monotonic_ns
    ):
        raise SbxCleanupPending("sandbox stop or cleanup is failed, ambiguous, or unproven")


def _require_auxiliary_cleanup_complete(
    *,
    capture: RunningCaptureEvidence,
    verifier: IndependentVerifierReceipt,
    controller_result: ControllerResultEvidence,
) -> None:
    """Give every temporary-process/root cleanup failure priority over parsing."""

    if not capture.capture_process_reaped:
        raise SbxCleanupPending("fixed sbx cp capture process cleanup is unproven")
    if not verifier.capture_root_removed or not verifier.verification_sandbox_removed:
        raise SbxCleanupPending("capture-root or verifier-sandbox cleanup is unproven")
    if not controller_result.result_root_removed:
        raise SbxCleanupPending("controller-result root cleanup is unproven")


def _validate_capture(
    plan: SbxResultPlan,
    *,
    capture: RunningCaptureEvidence,
    cleanup: StopCleanupEvidence,
    patch: bytes,
) -> None:
    if capture.binding_sha256 != plan.binding.sha256:
        raise SbxResultError("capture evidence is bound to another sandbox generation")
    if capture.controller_boot_sha256 != plan.controller_boot_sha256:
        raise SbxResultError("capture evidence crosses an untrusted controller boot")
    if not (
        capture.capture_started_monotonic_ns
        < capture.capture_finished_monotonic_ns
        < cleanup.stop_observed_monotonic_ns
    ):
        raise SbxResultError("opaque capture is not proven complete before sandbox stop")
    if not capture.capture_process_reaped:
        raise SbxCleanupPending("fixed sbx cp capture process cleanup is unproven")
    if (
        not capture.opened_nofollow
        or not capture.descriptor_cloexec
        or not capture.fixed_cp_used
        or capture.follow_links
        or capture.generic_cp_used
        or capture.issue_controlled_path_used
        or not capture.sandbox_running_before
        or not capture.sandbox_running_after
        or not capture.destination_regular_files
        or not capture.destination_unaliased_files
        or not capture.destination_quota_enforced
        or not capture.capture_deadline_enforced
        or not capture.bytes_unparsed
    ):
        raise SbxResultError("capture used an unsafe, generic, followed-link, or parsed channel")
    root = capture.root_at_open
    if root.owner_uid != plan.controller_uid or root.permissions != 0o700:
        raise SbxResultError("capture root is not exactly controller-owned and private")
    if not (
        capture.root_descriptor_after == root
        and capture.root_entry_after == root
        and capture.parent_after == capture.parent_at_open
    ):
        raise SbxResultError("capture root or parent descriptor identity changed")
    if type(patch) is not bytes or not patch or len(patch) > MAX_PATCH_BYTES:
        raise SbxResultError("captured patch bytes exceed their exact bound")
    if capture.patch_sha256 != _sha256(patch) or capture.patch_bytes != len(patch):
        raise SbxResultError("capture receipt does not bind the exact bounded patch")


def _require_verifier_admission(
    plan: SbxResultPlan,
    *,
    verifier: IndependentVerifierReceipt,
    cleanup: StopCleanupEvidence,
    capture: RunningCaptureEvidence,
) -> None:
    """Require a fresh post-cleanup verifier before any patch parser is reachable."""

    preparse_bindings = (
        verifier.binding_sha256 == plan.binding.sha256,
        verifier.controller_boot_sha256 == plan.controller_boot_sha256,
        verifier.freshness_challenge_sha256 == plan.freshness_challenge_sha256,
        verifier.verifier_identity_sha256 == plan.verifier_identity_sha256,
        verifier.verification_profile_sha256 == plan.verification_profile_sha256,
        verifier.capture_sha256 == capture.sha256,
        verifier.cleanup_sha256 == cleanup.sha256,
        verifier.source_manifest_sha256 == plan.binding.source_manifest_sha256,
        verifier.policy_sha256 == plan.binding.policy_sha256,
        verifier.base_sha == plan.binding.base_sha,
    )
    if not all(preparse_bindings):
        raise SbxResultError("independent verifier receipt has a substituted binding")
    if not (
        cleanup.cleanup_observed_monotonic_ns
        < verifier.parse_started_monotonic_ns
        < verifier.verified_monotonic_ns
    ):
        raise SbxResultError("parsing or independent verification occurred before cleanup")
    if (
        verifier.parse_root_descriptor != capture.root_at_open
        or verifier.parse_root_entry != capture.root_at_open
    ):
        raise SbxResultError("capture root was not descriptor-stable through post-cleanup parsing")
    if verifier.verifier_sandbox_uuid == plan.binding.daemon_sandbox_uuid:
        raise SbxResultError("verification reused the worker sandbox instance")
    if (
        not verifier.independent_domain
        or not verifier.fresh_verifier_sandbox
        or not verifier.worker_mount_absent
        or not verifier.network_denied
        or not verifier.credentials_absent
        or not verifier.reconstructed_source
        or not verifier.policy_allowed
        or verifier.unresolved_review
    ):
        raise SbxResultError("independent verifier did not prove policy-clean reconstructed output")
    if tuple(check.check_id for check in verifier.checks) != plan.required_check_ids:
        raise SbxResultError("independent verifier check registry does not match the plan")
    if any(check.exit_code != 0 or check.timed_out or check.truncated for check in verifier.checks):
        raise SbxResultError("an independent verifier check did not succeed exactly")


def _validate_verifier(
    plan: SbxResultPlan,
    *,
    verifier: IndependentVerifierReceipt,
    cleanup: StopCleanupEvidence,
    capture: RunningCaptureEvidence,
    patch_summary: PatchSummary,
) -> None:
    if not verifier.capture_root_removed or not verifier.verification_sandbox_removed:
        raise SbxCleanupPending("capture-root or verifier-sandbox cleanup is unproven")
    _require_verifier_admission(
        plan,
        verifier=verifier,
        cleanup=cleanup,
        capture=capture,
    )
    patch_bindings = (
        verifier.applied_patch_sha256 == patch_summary.sha256,
        verifier.inspected_patch_sha256 == patch_summary.sha256,
        verifier.changed_paths == patch_summary.paths,
        verifier.changed_lines == patch_summary.changed_lines,
    )
    if not all(patch_bindings):
        raise SbxResultError("independent verifier receipt has a substituted binding")


def _require_controller_result_admission(
    plan: SbxResultPlan,
    *,
    controller_result: ControllerResultEvidence,
    verifier: IndependentVerifierReceipt,
    result_document: bytes,
    patch_summary: PatchSummary,
) -> None:
    """Require controller-only provenance before parsing controller result JSON."""

    if not controller_result.result_root_removed:
        raise SbxCleanupPending("controller-result root cleanup is unproven")
    if (
        type(result_document) is not bytes
        or not result_document
        or len(result_document) > MAX_RESULT_BYTES
    ):
        raise SbxResultError("controller result document exceeds its byte cap")
    if (
        controller_result.binding_sha256 != plan.binding.sha256
        or controller_result.controller_boot_sha256 != plan.controller_boot_sha256
        or controller_result.freshness_challenge_sha256 != plan.freshness_challenge_sha256
        or controller_result.result_sha256 != _sha256(result_document)
        or controller_result.result_bytes != len(result_document)
        or controller_result.patch_sha256 != patch_summary.sha256
    ):
        raise SbxResultError("controller-result evidence has a substituted binding")
    if controller_result.constructed_monotonic_ns <= verifier.verified_monotonic_ns:
        raise SbxResultError("controller result was not constructed after independent verification")
    root = controller_result.root_at_open
    if root.owner_uid != plan.controller_uid or root.permissions != 0o700:
        raise SbxResultError("controller-result root is not controller-owned and private")
    if not (
        controller_result.root_descriptor_after == root
        and controller_result.root_entry_after == root
        and controller_result.parent_after == controller_result.parent_at_open
    ):
        raise SbxResultError("controller-result root or parent descriptor identity changed")
    if (
        not controller_result.opened_nofollow
        or not controller_result.descriptor_cloexec
        or not controller_result.controller_constructed
        or not controller_result.constructed_from_exact_usage
        or controller_result.workspace_result_bytes_used
        or not controller_result.result_regular_file
        or not controller_result.result_unaliased_file
    ):
        raise SbxResultError("result document did not use the controller-only construction path")


def _validate_controller_result(
    plan: SbxResultPlan,
    *,
    controller_result: ControllerResultEvidence,
    verifier: IndependentVerifierReceipt,
    result_document: bytes,
    result_sha256: str,
    usage: ExactUsageReceipt,
    patch_summary: PatchSummary,
) -> None:
    _require_controller_result_admission(
        plan,
        controller_result=controller_result,
        verifier=verifier,
        result_document=result_document,
        patch_summary=patch_summary,
    )
    if (
        controller_result.result_sha256 != result_sha256
        or controller_result.source_usage_sha256 != usage.sha256
        or controller_result.source_event_stream_sha256 != usage.aggregate_event_stream_sha256
    ):
        raise SbxResultError("controller result does not bind exact controller-parsed JSONL usage")


def _validate_fresh_base(
    plan: SbxResultPlan,
    *,
    verifier: IndependentVerifierReceipt,
    controller_result: ControllerResultEvidence,
    base_recheck: FreshBaseRecheck,
    handoff_observed_monotonic_ns: int,
) -> None:
    _require_exact_int(
        handoff_observed_monotonic_ns,
        minimum=1,
        maximum=2**63 - 1,
        label="handoff observation time",
    )
    if (
        base_recheck.binding_sha256 != plan.binding.sha256
        or base_recheck.controller_boot_sha256 != plan.controller_boot_sha256
        or base_recheck.freshness_challenge_sha256 != plan.freshness_challenge_sha256
        or base_recheck.verifier_sha256 != verifier.sha256
        or base_recheck.controller_result_sha256 != controller_result.sha256
        or base_recheck.repository != plan.binding.repository
        or base_recheck.issue_number != plan.binding.issue_number
    ):
        raise SbxResultError("fresh base recheck is bound to another planned contribution")
    if base_recheck.observed_base_sha != plan.binding.base_sha:
        raise SbxResultError("base moved before capability-free handoff")
    if (
        not base_recheck.issue_open
        or not base_recheck.assignment_clear
        or not base_recheck.linked_or_open_pr_absent
    ):
        raise SbxResultError("fresh issue collision recheck does not permit handoff")
    if not (
        controller_result.constructed_monotonic_ns
        < base_recheck.observed_monotonic_ns
        <= handoff_observed_monotonic_ns
    ):
        raise SbxResultError("fresh base recheck is not ordered after verification")
    if handoff_observed_monotonic_ns - base_recheck.observed_monotonic_ns > MAX_FRESH_BASE_AGE_NS:
        raise SbxResultError("base recheck is stale before capability-free handoff")


def verify_sbx_result(*_args: object, **_kwargs: object) -> Never:
    """Reject production before path, executor, artifact, or daemon inspection."""

    raise SbxResultDisabled(
        "Docker Sandbox result verification is source-disabled before paths or executors"
    )


def verify_sbx_result_fixture(
    plan: SbxResultPlan,
    *,
    result_document: bytes,
    patch: bytes,
    cleanup: StopCleanupEvidence,
    capture: RunningCaptureEvidence,
    verifier: IndependentVerifierReceipt,
    controller_result: ControllerResultEvidence,
    base_recheck: FreshBaseRecheck,
    handoff_observed_monotonic_ns: int,
    fixture_capability: FixtureSbxResultCapability,
) -> CapabilityFreeSbxHandoff:
    """Validate a pure fixture evidence chain and return bounded inert data."""

    _require_fixture_capability(fixture_capability)
    for value, expected, label in (
        (plan, SbxResultPlan, "result plan"),
        (cleanup, StopCleanupEvidence, "cleanup evidence"),
        (capture, RunningCaptureEvidence, "capture evidence"),
        (verifier, IndependentVerifierReceipt, "verifier receipt"),
        (controller_result, ControllerResultEvidence, "controller-result evidence"),
        (base_recheck, FreshBaseRecheck, "base recheck"),
    ):
        if type(value) is not expected:
            raise SbxResultError(f"{label} is not an exact typed fixture value")

    # Cleanup has priority: malformed output must never hide an unremoved or
    # ambiguously identified sandbox generation.
    _require_cleanup_complete(plan, cleanup)
    _require_auxiliary_cleanup_complete(
        capture=capture,
        verifier=verifier,
        controller_result=controller_result,
    )
    # ``sbx cp`` supplied opaque bytes while the worker was running. Validate
    # only its fixed transport/root binding here; parsing begins below and is
    # therefore unreachable until cleanup is proven.
    _validate_capture(
        plan,
        capture=capture,
        cleanup=cleanup,
        patch=patch,
    )
    _require_verifier_admission(
        plan,
        verifier=verifier,
        cleanup=cleanup,
        capture=capture,
    )
    patch_summary = inspect_canonical_patch(patch, forbidden_paths=plan.forbidden_paths)
    _enforce_plan_patch_limits(plan, patch_summary)
    _validate_verifier(
        plan,
        verifier=verifier,
        cleanup=cleanup,
        capture=capture,
        patch_summary=patch_summary,
    )
    # The workspace cannot supply result or usage bytes. Only after the fresh
    # verifier succeeds may the controller parse its own canonical document,
    # constructed from independently captured Codex JSONL receipts.
    _require_controller_result_admission(
        plan,
        controller_result=controller_result,
        verifier=verifier,
        result_document=result_document,
        patch_summary=patch_summary,
    )
    result_sha256, usage = _validate_result_document(
        plan,
        result_document=result_document,
        patch_summary=patch_summary,
    )
    _validate_controller_result(
        plan,
        controller_result=controller_result,
        verifier=verifier,
        result_document=result_document,
        result_sha256=result_sha256,
        usage=usage,
        patch_summary=patch_summary,
    )
    _validate_fresh_base(
        plan,
        verifier=verifier,
        controller_result=controller_result,
        base_recheck=base_recheck,
        handoff_observed_monotonic_ns=handoff_observed_monotonic_ns,
    )
    return CapabilityFreeSbxHandoff(
        kind=HANDOFF_KIND,
        binding=plan.binding,
        canonical_patch=patch,
        patch_sha256=patch_summary.sha256,
        result_sha256=result_sha256,
        usage=usage,
        cleanup_sha256=cleanup.sha256,
        capture_sha256=capture.sha256,
        verifier_sha256=verifier.sha256,
        controller_result_sha256=controller_result.sha256,
        base_recheck_sha256=base_recheck.sha256,
        changed_paths=patch_summary.paths,
        changed_lines=patch_summary.changed_lines,
        seal=_HANDOFF_SEAL,
    )
