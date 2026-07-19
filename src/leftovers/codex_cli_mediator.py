"""Hard-disabled Codex CLI mediation boundary for the future strict-VM worker.

This is deliberately *not* a general-purpose Codex wrapper.  It has no mode
that accepts a command, environment, workspace, tool configuration, prompt
path, or credential path from an issue or model response.  The executable
path, exact digest, version, model, effort, and argv are controller-owned.

The current Codex CLI documentation/configuration surface does not provide a
reviewable proof that every model tool surface can be disabled while retaining
subscription authentication.  Accordingly ``PRODUCTION_CODEX_MEDIATION_ENABLED``
is permanently false in this release and ``mediate`` fails before it creates a
ledger, temporary directory, or subprocess.  The parser and ledger below are
implemented now so a future separately reviewed broker has a narrow contract
rather than inheriting a host-agent adapter.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from .model_mediator import (
    ACTION_BATCH_SCHEMA_VERSION,
    MAX_TOKEN_COMPONENT,
    MediationDisabled,
    MediationReceipt,
    MediationRequest,
    MediationResult,
    MediatorValidationError,
    ReportedTokenCounts,
    canonical_json_bytes,
    validate_action_batch,
    validate_mediation_request,
    validate_proposed_patch,
    validate_reported_token_counts,
)

PRODUCTION_CODEX_MEDIATION_ENABLED: Final = False
"""Release gate.  Never toggle this from configuration or an environment variable."""

ZERO_TOOL_CONFIGURATION_PROVEN: Final = False
"""No reviewed Codex CLI contract currently proves all model tools are absent."""

PROVIDER: Final = "openai-codex-cli"
MODEL: Final = "gpt-5.6-terra"
REASONING_EFFORT: Final = "high"
ENVELOPE_SCHEMA_VERSION: Final = 1
LEDGER_SCHEMA_VERSION: Final = 2
MAX_ENVELOPE_BYTES: Final = 262_144
MAX_EVENT_STREAM_BYTES: Final = 1_048_576
MAX_EVENT_LINE_BYTES: Final = 262_144
MAX_EVENT_COUNT: Final = 2_048
MAX_LEDGER_LINE_BYTES: Final = 4_096
MAX_LEDGER_EVENTS: Final = 129
PASSIVE_ITEM_TYPES: Final = frozenset({"agent_message", "reasoning"})
DISABLED_MODEL_FEATURES: Final = (
    "apps",
    "artifact",
    "auth_elicitation",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "chronicle",
    "code_mode",
    "code_mode_host",
    "computer_use",
    "default_mode_request_user_input",
    "enable_mcp_apps",
    "goals",
    "hooks",
    "image_generation",
    "in_app_browser",
    "memories",
    "multi_agent",
    "multi_agent_v2",
    "network_proxy",
    "plugins",
    "remote_plugin",
    "request_permissions_tool",
    "shell_snapshot",
    "shell_tool",
    "skill_mcp_dependency_install",
    "skill_search",
    "standalone_web_search",
    "tool_call_mcp_elicitation",
    "tool_suggest",
    "unified_exec",
    "workspace_dependencies",
)
_RUN_ID = re.compile(r"[a-f0-9]{32}")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?")
_EVENT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


class CodexMediatorError(RuntimeError):
    """A malformed provider boundary or local accounting failure."""


class CodexMediatorDisabled(MediationDisabled):
    """The only allowed result of attempting a live Codex subscription call."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_load(raw: bytes, *, maximum_bytes: int) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > maximum_bytes:
        raise CodexMediatorError("provider record is empty, mutable, or oversized")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CodexMediatorError("provider record contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_float=lambda _value: (_ for _ in ()).throw(CodexMediatorError("float forbidden")),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CodexMediatorError("constant forbidden")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CodexMediatorError("provider record is not canonical JSON") from exc
    if canonical_json_bytes(value) != raw:
        raise CodexMediatorError("provider record JSON is not canonical")
    return value


def _exact_object(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise CodexMediatorError(f"{name} has missing or unknown fields")
    return value


def _bounded_int(value: Any, *, lower: int, upper: int, name: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise CodexMediatorError(f"{name} is outside its bounds")
    return value


def _utc(value: datetime, name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CodexMediatorError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _framed_output_sha256(action_batch: bytes, patch: bytes | None) -> str:
    digest = hashlib.sha256(b"LEFTOVERS_MEDIATION_OUTPUT_V1\0")
    digest.update(len(action_batch).to_bytes(8, "big"))
    digest.update(action_batch)
    patch_bytes = b"" if patch is None else patch
    digest.update(len(patch_bytes).to_bytes(8, "big"))
    digest.update(patch_bytes)
    return digest.hexdigest()


@dataclass(frozen=True)
class CodexCliIdentity:
    """An immutable, externally reviewed CLI identity; never discover it via PATH."""

    executable: Path
    sha256: str
    version: str

    def validate(self) -> None:
        if not self.executable.is_absolute():
            raise CodexMediatorError("Codex executable must be an absolute controller path")
        if _SHA256.fullmatch(self.sha256) is None:
            raise CodexMediatorError("Codex executable digest must be exact lowercase SHA-256")
        if _VERSION.fullmatch(self.version) is None:
            raise CodexMediatorError("Codex CLI version must be an exact pinned version")


@dataclass(frozen=True)
class ProviderEnvelope:
    """Untrusted provider data before the mediator derives a strict action batch."""

    actions: tuple[dict[str, Any], ...]
    patch: bytes | None
    raw_sha256: str


@dataclass(frozen=True)
class CodexEventEvidence:
    """CLI-authored usage evidence retained for future broker authorization."""

    usage: ReportedTokenCounts
    cache_write_input_tokens: int
    stream_sha256: str
    thread_id: str


@dataclass(frozen=True)
class LedgerReservation:
    run_id: str
    call_index: int
    reserved_tokens: int
    request_sha256: str
    reservation_id: str


def _controller_path(path: Path, name: str) -> str:
    if not isinstance(path, Path) or not path.is_absolute():
        raise CodexMediatorError(f"{name} must be an absolute controller path")
    text = str(path)
    if text != os.path.abspath(text) or text != os.path.normpath(text):
        raise CodexMediatorError(f"{name} must be a normalized controller path")
    if not text or "\0" in text or "\n" in text or "\r" in text:
        raise CodexMediatorError(f"{name} contains forbidden characters")
    return text


def fixed_codex_argv(
    identity: CodexCliIdentity,
    *,
    private_cwd: Path,
    output_schema: Path,
    output_last_message: Path,
) -> tuple[str, ...]:
    """Return the only contemplated argv shape, never a runnable authorization.

    These controls are intentionally redundant.  They are not considered proof
    that Codex exposes no tools; ``assert_live_invocation_permitted`` rejects
    before this argv can be passed to ``Popen`` until such proof exists.
    """

    identity.validate()
    cwd = _controller_path(private_cwd, "private cwd")
    schema = _controller_path(output_schema, "output schema")
    result = _controller_path(output_last_message, "output message")
    if output_last_message.parent != private_cwd:
        raise CodexMediatorError("output message must be directly inside the private cwd")
    argv = [
        str(identity.executable),
        "exec",
        "--strict-config",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--model",
        MODEL,
        "--skip-git-repo-check",
        "-c",
        f'model_reasoning_effort="{REASONING_EFFORT}"',
        "-c",
        'model_verbosity="low"',
        "-c",
        'approval_policy="never"',
        "-c",
        "allow_login_shell=false",
        "-c",
        'shell_environment_policy.inherit="none"',
        "-c",
        "analytics.enabled=false",
    ]
    for feature in DISABLED_MODEL_FEATURES:
        argv.extend(("--disable", feature))
    argv.extend(
        (
            "--sandbox",
            "read-only",
            "--cd",
            cwd,
            "--color",
            "never",
            "--json",
            "--output-schema",
            schema,
            "--output-last-message",
            result,
            "-",
        )
    )
    return tuple(argv)


def assert_live_invocation_permitted(identity: CodexCliIdentity) -> None:
    """Fail before process, disk, credential, or environment handling."""

    identity.validate()
    if not PRODUCTION_CODEX_MEDIATION_ENABLED:
        raise CodexMediatorDisabled("Codex CLI mediation is hard-disabled in this release")
    if not ZERO_TOOL_CONFIGURATION_PROVEN:
        raise CodexMediatorDisabled(
            "Codex CLI tool-disable configuration is not proven; refusing provider launch"
        )
    raise AssertionError("a reviewed implementation must replace this final release gate")


def parse_provider_envelope(raw: bytes, request: MediationRequest) -> ProviderEnvelope:
    """Parse a non-authoritative provider envelope without granting it authority."""

    validate_mediation_request(request)
    value = _canonical_load(
        raw,
        maximum_bytes=min(MAX_ENVELOPE_BYTES, request.limits.max_response_bytes),
    )
    top = _exact_object(
        value,
        {
            "schema_version",
            "run_id",
            "round",
            "stage",
            "provider",
            "model",
            "reasoning_effort",
            "input_sha256",
            "actions",
            "patch",
        },
        "provider envelope",
    )
    if top["schema_version"] != ENVELOPE_SCHEMA_VERSION:
        raise CodexMediatorError("provider envelope schema version is unsupported")
    for field, expected in (
        ("run_id", request.run_id),
        ("round", request.round),
        ("stage", request.stage.value),
        ("provider", PROVIDER),
        ("model", MODEL),
        ("reasoning_effort", REASONING_EFFORT),
        ("input_sha256", _sha256(request.input_bytes)),
    ):
        if top[field] != expected:
            raise CodexMediatorError(f"provider envelope {field} does not bind to the request")
    if (
        request.provider != PROVIDER
        or request.model != MODEL
        or request.reasoning_effort != REASONING_EFFORT
    ):
        raise CodexMediatorError("Codex mediator request identity is not fixed")
    if type(top["actions"]) is not list or not top["actions"]:
        raise CodexMediatorError("provider envelope actions must be a non-empty list")
    if any(type(action) is not dict for action in top["actions"]):
        raise CodexMediatorError("provider envelope action is not an object")
    patch_value = top["patch"]
    if patch_value is None:
        patch = None
    elif type(patch_value) is str:
        try:
            patch = patch_value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CodexMediatorError("provider patch is not valid Unicode") from exc
    else:
        raise CodexMediatorError("provider patch must be text or null")
    return ProviderEnvelope(
        actions=tuple(dict(action) for action in top["actions"]),
        patch=patch,
        raw_sha256=_sha256(raw),
    )


def _event_json(raw_line: bytes) -> dict[str, Any]:
    """Parse one CLI-authored JSONL record without accepting duplicate keys."""

    if not raw_line or len(raw_line) > MAX_EVENT_LINE_BYTES:
        raise CodexMediatorError("Codex event line is empty or oversized")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CodexMediatorError("Codex event contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw_line.decode("utf-8"),
            object_pairs_hook=unique,
            parse_float=lambda _value: (_ for _ in ()).throw(
                CodexMediatorError("Codex event float is forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CodexMediatorError("Codex event constant is forbidden")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CodexMediatorError("Codex event stream is malformed JSONL") from exc
    if type(value) is not dict:
        raise CodexMediatorError("Codex event must be an object")
    return value


def parse_codex_event_evidence(raw: bytes, request: MediationRequest) -> CodexEventEvidence:
    """Derive exact usage from the CLI event channel and reject every tool item.

    This stream is emitted by the pinned CLI process, not by the model's final
    structured response.  It still grants no authority: unknown events, tool
    items, failures, missing reasoning accounting, and non-terminal data all
    fail closed.  Passing this parser is necessary but is not proof that an
    unreported tool surface cannot exist, so the live release gate remains off.
    """

    validate_mediation_request(request)
    if type(raw) is not bytes or not raw or len(raw) > MAX_EVENT_STREAM_BYTES:
        raise CodexMediatorError("Codex event stream is empty, mutable, or oversized")
    if not raw.endswith(b"\n"):
        raise CodexMediatorError("Codex event stream has a partial final record")
    lines = raw.splitlines()
    if not lines or len(lines) > MAX_EVENT_COUNT:
        raise CodexMediatorError("Codex event count is outside its bounds")

    state = "before_thread"
    completed_agent_message = False
    active_items: dict[str, str] = {}
    usage: ReportedTokenCounts | None = None
    observed_thread_id: str | None = None
    for index, raw_line in enumerate(lines):
        event = _event_json(raw_line)
        event_type = event.get("type")
        if type(event_type) is not str:
            raise CodexMediatorError("Codex event type is missing or invalid")
        if event_type in {"error", "turn.failed"}:
            raise CodexMediatorError("Codex event stream reported failure")
        if event_type == "thread.started":
            if state != "before_thread":
                raise CodexMediatorError("Codex thread event is out of order or duplicated")
            _exact_object(event, {"type", "thread_id"}, "Codex thread event")
            thread_id = event.get("thread_id")
            if type(thread_id) is not str or _EVENT_ID.fullmatch(thread_id) is None:
                raise CodexMediatorError("Codex thread identity is invalid")
            observed_thread_id = thread_id
            state = "before_turn"
            continue
        if event_type == "turn.started":
            if state != "before_turn":
                raise CodexMediatorError("Codex turn start is out of order or duplicated")
            _exact_object(event, {"type"}, "Codex turn-start event")
            state = "in_turn"
            continue
        if event_type in {"item.started", "item.updated", "item.completed"}:
            if state != "in_turn":
                raise CodexMediatorError("Codex item event is outside the active turn")
            _exact_object(event, {"type", "item"}, "Codex item event")
            item = event.get("item")
            if type(item) is not dict or set(item) != {"id", "type", "text"}:
                raise CodexMediatorError("Codex passive item fields are not exact")
            item_id = item.get("id")
            item_type = item.get("type")
            if (
                type(item_id) is not str
                or _EVENT_ID.fullmatch(item_id) is None
                or item_type not in PASSIVE_ITEM_TYPES
                or type(item.get("text")) is not str
            ):
                raise CodexMediatorError("Codex emitted a forbidden or unknown tool item")
            if event_type == "item.started":
                if item_id in active_items:
                    raise CodexMediatorError("Codex item start is duplicated")
                active_items[item_id] = item_type
                continue
            active_type = active_items.get(item_id)
            if event_type == "item.updated" and active_type != item_type:
                raise CodexMediatorError("Codex item lifecycle is not bound to one passive item")
            if event_type == "item.completed" and active_type not in {None, item_type}:
                raise CodexMediatorError("Codex item lifecycle is not bound to one passive item")
            if event_type == "item.completed":
                active_items.pop(item_id, None)
            if event_type == "item.completed" and item_type == "agent_message":
                completed_agent_message = True
            continue
        if event_type == "turn.completed":
            if state != "in_turn" or index != len(lines) - 1 or usage is not None:
                raise CodexMediatorError("Codex turn completion is out of order or duplicated")
            if not completed_agent_message:
                raise CodexMediatorError("Codex turn completed without an agent message")
            if active_items:
                raise CodexMediatorError("Codex turn completed with unfinished items")
            terminal = _exact_object(event, {"type", "usage"}, "Codex completion event")
            usage_value = terminal["usage"]
            if type(usage_value) is not dict:
                raise CodexMediatorError("Codex completion usage is not an object")
            required = {
                "input_tokens",
                "output_tokens",
                "cached_input_tokens",
                "cache_write_input_tokens",
                "reasoning_output_tokens",
            }
            usage_fields = frozenset(usage_value)
            if usage_fields not in {
                frozenset(required),
                frozenset({*required, "total_tokens"}),
            }:
                raise CodexMediatorError("Codex completion usage has missing or unknown fields")
            input_tokens = _bounded_int(
                usage_value["input_tokens"],
                lower=0,
                upper=MAX_TOKEN_COMPONENT,
                name="input_tokens",
            )
            output_tokens = _bounded_int(
                usage_value["output_tokens"],
                lower=0,
                upper=MAX_TOKEN_COMPONENT,
                name="output_tokens",
            )
            total_tokens = input_tokens + output_tokens
            if "total_tokens" in usage_value and usage_value["total_tokens"] != total_tokens:
                raise CodexMediatorError("Codex completion total tokens do not reconcile")
            cached_input_tokens = _bounded_int(
                usage_value["cached_input_tokens"],
                lower=0,
                upper=MAX_TOKEN_COMPONENT,
                name="cached_input_tokens",
            )
            cache_write_input_tokens = _bounded_int(
                usage_value["cache_write_input_tokens"],
                lower=0,
                upper=MAX_TOKEN_COMPONENT,
                name="cache_write_input_tokens",
            )
            if cache_write_input_tokens > input_tokens:
                raise CodexMediatorError("Codex cache-write input exceeds total input")
            usage = ReportedTokenCounts(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_input_tokens=cached_input_tokens,
                reasoning_tokens=_bounded_int(
                    usage_value["reasoning_output_tokens"],
                    lower=0,
                    upper=MAX_TOKEN_COMPONENT,
                    name="reasoning_output_tokens",
                ),
                total_tokens=total_tokens,
                source="provider",
                exact=True,
            )
            try:
                validate_reported_token_counts(usage, request.limits, fixture=False)
            except MediatorValidationError as exc:
                raise CodexMediatorError("Codex completion usage is invalid") from exc
            state = "complete"
            continue
        raise CodexMediatorError("Codex emitted an unknown event type")
    if state != "complete" or usage is None or observed_thread_id is None:
        raise CodexMediatorError("Codex event stream lacks one terminal usage receipt")
    return CodexEventEvidence(
        usage=usage,
        cache_write_input_tokens=cache_write_input_tokens,
        stream_sha256=_sha256(raw),
        thread_id=observed_thread_id,
    )


def parse_codex_event_usage(raw: bytes, request: MediationRequest) -> ReportedTokenCounts:
    """Return diagnostic counts; authorization must retain the full evidence object."""

    return parse_codex_event_evidence(raw, request).usage


def derive_mediation_result(
    raw: bytes,
    request: MediationRequest,
    *,
    event_evidence: CodexEventEvidence,
    started_at: datetime,
    finished_at: datetime,
) -> MediationResult:
    """Convert an envelope to the existing strict action protocol.

    The provider never supplies an apply-patch digest.  The mediator derives it
    from the separately bounded patch then inserts it into a fresh canonical
    action batch before the common validator sees it.
    """

    start = _utc(started_at, "started_at")
    finish = _utc(finished_at, "finished_at")
    validate_mediation_request(request, now=start)
    if finish < start or finish >= request.deadline_at.astimezone(UTC):
        raise CodexMediatorError("provider response timing is invalid or missed its deadline")
    if (
        type(event_evidence) is not CodexEventEvidence
        or _SHA256.fullmatch(event_evidence.stream_sha256) is None
        or _EVENT_ID.fullmatch(event_evidence.thread_id) is None
    ):
        raise CodexMediatorError("provider event evidence identity is invalid")
    usage = event_evidence.usage
    try:
        validate_reported_token_counts(usage, request.limits, fixture=False)
    except MediatorValidationError as exc:
        raise CodexMediatorError("external provider usage is invalid") from exc
    envelope = parse_provider_envelope(raw, request)
    patch = envelope.patch
    if patch is not None and (
        not patch or len(patch) > request.limits.max_patch_bytes or b"\0" in patch
    ):
        raise CodexMediatorError("provider patch is empty, oversized, or contains NUL")
    patch_sha256 = None if patch is None else _sha256(patch)
    derived_actions: list[dict[str, Any]] = []
    for action in envelope.actions:
        copy = dict(action)
        if copy.get("type") == "apply_patch":
            if set(copy) != {"id", "type"}:
                raise CodexMediatorError("provider apply_patch intent has unknown authority fields")
            if patch_sha256 is None:
                raise CodexMediatorError("apply_patch intent requires provider patch text")
            copy["patch_sha256"] = patch_sha256
        derived_actions.append(copy)
    action_bytes = canonical_json_bytes(
        {
            "schema_version": ACTION_BATCH_SCHEMA_VERSION,
            "run_id": request.run_id,
            "round": request.round,
            "stage": request.stage.value,
            "provider": PROVIDER,
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "actions": derived_actions,
        },
        reject_controls=True,
    )
    validated_patch, validated_patch_sha256 = validate_proposed_patch(
        patch,
        request,
        action_batch_bytes=len(action_bytes),
    )
    try:
        batch = validate_action_batch(
            action_bytes,
            request,
            proposed_patch_sha256=validated_patch_sha256,
        )
    except MediatorValidationError as exc:
        raise CodexMediatorError("derived strict action batch is invalid") from exc
    receipt = MediationReceipt(
        schema_version=ACTION_BATCH_SCHEMA_VERSION,
        run_id=request.run_id,
        round=request.round,
        stage=request.stage,
        provider=PROVIDER,
        model=MODEL,
        reasoning_effort=REASONING_EFFORT,
        input_sha256=_sha256(request.input_bytes),
        action_batch_sha256=_sha256(action_bytes),
        patch_sha256=validated_patch_sha256,
        output_sha256=_framed_output_sha256(action_bytes, validated_patch),
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cached_input_tokens=usage.cached_input_tokens,
        reasoning_tokens=usage.reasoning_tokens,
        total_tokens=usage.total_tokens,
        usage_source="provider",
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
        started_at=start,
        finished_at=finish,
    )
    return MediationResult(batch=batch, patch=validated_patch, receipt=receipt)


class CodexTokenLedger:
    """A private, fsynced, hash-chained reservation ledger for exactly one run.

    A reserve is intentionally charged at the requested total cap until a
    matching exact provider receipt settles it.  Thus a crash after provider
    launch cannot make the next process assume the capacity was unused.
    """

    def __init__(self, state_root: Path, run_id: str, *, run_token_cap: int) -> None:
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise CodexMediatorError("ledger state root must be an absolute controller path")
        if _RUN_ID.fullmatch(run_id) is None:
            raise CodexMediatorError("ledger run_id is invalid")
        if type(run_token_cap) is not int or not 1 <= run_token_cap <= MAX_TOKEN_COMPONENT:
            raise CodexMediatorError("ledger run token cap is invalid")
        self._state_root = state_root
        self._run_id = run_id
        self._run_token_cap = run_token_cap

    @property
    def path(self) -> Path:
        return self._state_root / "codex-mediator-ledgers" / f"{self._run_id}.jsonl"

    def _ensure_parent(self) -> None:
        try:
            root_stat = self._state_root.lstat()
        except OSError as exc:
            raise CodexMediatorError("ledger state root must already exist") from exc
        if (
            self._state_root.is_symlink()
            or not stat.S_ISDIR(root_stat.st_mode)
            or str(self._state_root.resolve(strict=True)) != str(self._state_root)
        ):
            raise CodexMediatorError("ledger state root is unsafe")
        mode = stat.S_IMODE(root_stat.st_mode)
        if root_stat.st_uid != os.getuid() or mode & 0o077:
            raise CodexMediatorError("ledger state root must be owner-private")
        directory = self.path.parent
        try:
            directory.mkdir(mode=0o700)
            parent_descriptor = os.open(
                self._state_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise CodexMediatorError("ledger directory could not be created safely") from exc
        directory_stat = directory.lstat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.getuid()
            or stat.S_IMODE(directory_stat.st_mode) & 0o077
            or str(directory.resolve(strict=True)) != str(directory)
        ):
            raise CodexMediatorError("ledger directory is unsafe")

    @staticmethod
    def _check_private_regular(descriptor: int) -> None:
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_uid != os.getuid()
            or identity.st_nlink != 1
            or stat.S_IMODE(identity.st_mode) != 0o600
        ):
            raise CodexMediatorError(
                "ledger file is not an owner-private, non-hardlinked regular file"
            )

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        unsigned = dict(event)
        unsigned.pop("event_sha256", None)
        return _sha256(canonical_json_bytes(unsigned))

    def _read_locked(self, descriptor: int) -> list[dict[str, Any]]:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_LEDGER_LINE_BYTES * MAX_LEDGER_EVENTS:
                raise CodexMediatorError("ledger exceeds its bounded recovery size")
        raw = b"".join(chunks)
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise CodexMediatorError("ledger has a partial record")
        lines = raw.splitlines()
        if len(lines) > MAX_LEDGER_EVENTS:
            raise CodexMediatorError("ledger event count exceeds its recovery cap")
        previous = "0" * 64
        events: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            if not line or len(line) > MAX_LEDGER_LINE_BYTES:
                raise CodexMediatorError("ledger record is malformed or oversized")
            event = _canonical_load(line, maximum_bytes=MAX_LEDGER_LINE_BYTES)
            if type(event) is not dict:
                raise CodexMediatorError("ledger event is not an object")
            if (
                event.get("schema_version") != LEDGER_SCHEMA_VERSION
                or event.get("run_id") != self._run_id
            ):
                raise CodexMediatorError("ledger identity does not match")
            if index == 0:
                event = _exact_object(
                    event,
                    {
                        "schema_version",
                        "event",
                        "run_id",
                        "run_token_cap",
                        "call_cap",
                        "provider",
                        "model",
                        "reasoning_effort",
                        "prev_sha256",
                        "event_sha256",
                    },
                    "ledger genesis",
                )
                if (
                    event["event"] != "genesis"
                    or event["run_token_cap"] != self._run_token_cap
                    or event["provider"] != PROVIDER
                    or event["model"] != MODEL
                    or event["reasoning_effort"] != REASONING_EFFORT
                ):
                    raise CodexMediatorError("ledger genesis policy does not match")
                _bounded_int(event["call_cap"], lower=1, upper=64, name="ledger call_cap")
            else:
                event = _exact_object(
                    event,
                    {
                        "schema_version",
                        "event",
                        "run_id",
                        "call_index",
                        "tokens",
                        "request_sha256",
                        "receipt_sha256",
                        "prev_sha256",
                        "event_sha256",
                    },
                    "ledger event",
                )
                if event["event"] not in {"reserve", "settle"}:
                    raise CodexMediatorError("ledger event is not allowlisted")
                _bounded_int(event["call_index"], lower=1, upper=64, name="ledger call_index")
                _bounded_int(
                    event["tokens"], lower=0, upper=MAX_TOKEN_COMPONENT, name="ledger tokens"
                )
                for key in ("request_sha256", "receipt_sha256"):
                    if type(event[key]) is not str or _SHA256.fullmatch(event[key]) is None:
                        raise CodexMediatorError(f"ledger {key} is invalid")
                if (event["event"] == "reserve") != (event["receipt_sha256"] == "0" * 64):
                    raise CodexMediatorError("ledger receipt identity does not match its event")
            for key in ("prev_sha256", "event_sha256"):
                if type(event[key]) is not str or _SHA256.fullmatch(event[key]) is None:
                    raise CodexMediatorError(f"ledger {key} is invalid")
            if event["prev_sha256"] != previous or event["event_sha256"] != self._event_hash(event):
                raise CodexMediatorError(f"ledger hash chain is invalid at record {index}")
            previous = event["event_sha256"]
            events.append(event)
        return events

    def _append_locked(self, descriptor: int, event: dict[str, Any]) -> None:
        line = canonical_json_bytes(event) + b"\n"
        if len(line) > MAX_LEDGER_LINE_BYTES:
            raise CodexMediatorError("ledger event exceeds bounded atomic record size")
        os.lseek(descriptor, 0, os.SEEK_END)
        pending = memoryview(line)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise CodexMediatorError("ledger write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)

    @staticmethod
    def _accounting(events: list[dict[str, Any]]) -> tuple[dict[int, dict[str, Any]], int]:
        if not events or events[0].get("event") != "genesis":
            raise CodexMediatorError("ledger is missing its immutable genesis record")
        reserves: dict[int, dict[str, Any]] = {}
        settlements: dict[int, dict[str, Any]] = {}
        for event in events[1:]:
            index = event["call_index"]
            if event["event"] == "reserve":
                if index in reserves:
                    raise CodexMediatorError("ledger has a duplicate reservation")
                reserves[index] = event
            else:
                if index not in reserves or index in settlements:
                    raise CodexMediatorError("ledger settlement lacks one reservation")
                if event["request_sha256"] != reserves[index]["request_sha256"]:
                    raise CodexMediatorError("ledger settlement changed request identity")
                if event["tokens"] > reserves[index]["tokens"]:
                    raise CodexMediatorError("ledger settlement exceeds reservation")
                settlements[index] = event
        charged = sum(
            settlements.get(index, reservation)["tokens"] for index, reservation in reserves.items()
        )
        return reserves, charged

    def reserve(self, request: MediationRequest) -> LedgerReservation:
        validate_mediation_request(request)
        if request.run_id != self._run_id:
            raise CodexMediatorError("reservation request is not bound to this run")
        if (
            request.provider != PROVIDER
            or request.model != MODEL
            or request.reasoning_effort != REASONING_EFFORT
        ):
            raise CodexMediatorError("reservation mediator identity is not fixed")
        if request.limits.total_token_cap > self._run_token_cap:
            raise CodexMediatorError("call token cap exceeds the run cap")
        self._ensure_parent()
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            self._check_private_regular(descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            events = self._read_locked(descriptor)
            if not events:
                if request.limits.call_index != 1:
                    raise CodexMediatorError("first ledger reservation must use call index one")
                genesis = {
                    "schema_version": LEDGER_SCHEMA_VERSION,
                    "event": "genesis",
                    "run_id": self._run_id,
                    "run_token_cap": self._run_token_cap,
                    "call_cap": request.limits.call_cap,
                    "provider": PROVIDER,
                    "model": MODEL,
                    "reasoning_effort": REASONING_EFFORT,
                    "prev_sha256": "0" * 64,
                }
                genesis["event_sha256"] = self._event_hash(genesis)
                self._append_locked(descriptor, genesis)
                events.append(genesis)
            elif events[0]["call_cap"] != request.limits.call_cap:
                raise CodexMediatorError("reservation call cap changed from ledger genesis")
            reserves, charged = self._accounting(events)
            if (
                request.limits.call_index != len(reserves) + 1
                or len(reserves) >= request.limits.call_cap
            ):
                raise CodexMediatorError(
                    "provider call index is not a contiguous admitted sequence"
                )
            if charged + request.limits.total_token_cap > self._run_token_cap:
                raise CodexMediatorError("conservative token reservation exceeds run cap")
            request_sha256 = _sha256(request.input_bytes)
            previous = events[-1]["event_sha256"] if events else "0" * 64
            event = {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "event": "reserve",
                "run_id": self._run_id,
                "call_index": request.limits.call_index,
                "tokens": request.limits.total_token_cap,
                "request_sha256": request_sha256,
                "receipt_sha256": "0" * 64,
                "prev_sha256": previous,
            }
            event["event_sha256"] = self._event_hash(event)
            self._append_locked(descriptor, event)
            return LedgerReservation(
                run_id=self._run_id,
                call_index=request.limits.call_index,
                reserved_tokens=request.limits.total_token_cap,
                request_sha256=request_sha256,
                reservation_id=event["event_sha256"],
            )
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def settle(self, reservation: LedgerReservation, result: MediationResult) -> None:
        if type(reservation) is not LedgerReservation or reservation.run_id != self._run_id:
            raise CodexMediatorError("settlement reservation is not bound to this run")
        if type(result) is not MediationResult or result.receipt.run_id != self._run_id:
            raise CodexMediatorError("settlement result is not bound to this run")
        if result.receipt.call_index != reservation.call_index:
            raise CodexMediatorError("settlement call index is not bound to reservation")
        if result.receipt.input_sha256 != reservation.request_sha256:
            raise CodexMediatorError("settlement request hash is not bound to reservation")
        if result.receipt.total_tokens > reservation.reserved_tokens:
            raise CodexMediatorError("provider usage exceeds the conservative reservation")
        if _SHA256.fullmatch(reservation.reservation_id) is None:
            raise CodexMediatorError("settlement reservation identity is invalid")
        self._ensure_parent()
        descriptor = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
        try:
            self._check_private_regular(descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            events = self._read_locked(descriptor)
            reserves, _charged = self._accounting(events)
            stored = reserves.get(reservation.call_index)
            if stored is None or stored["request_sha256"] != reservation.request_sha256:
                raise CodexMediatorError("settlement has no matching persisted reservation")
            if stored["tokens"] != reservation.reserved_tokens:
                raise CodexMediatorError("settlement changed the persisted reservation cap")
            if stored["event_sha256"] != reservation.reservation_id:
                raise CodexMediatorError("settlement changed the persisted reservation identity")
            if any(
                event["event"] == "settle" and event["call_index"] == reservation.call_index
                for event in events
            ):
                raise CodexMediatorError("settlement is already recorded")
            previous = events[-1]["event_sha256"] if events else "0" * 64
            event = {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "event": "settle",
                "run_id": self._run_id,
                "call_index": reservation.call_index,
                "tokens": result.receipt.total_tokens,
                "request_sha256": reservation.request_sha256,
                "receipt_sha256": _sha256(canonical_json_bytes(result.receipt.to_dict())),
                "prev_sha256": previous,
            }
            event["event_sha256"] = self._event_hash(event)
            self._append_locked(descriptor, event)
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


class CodexCliMediator:
    """Production-shaped facade that cannot launch Codex in this release."""

    production_capable: Final = False

    def __init__(self, identity: CodexCliIdentity, *, state_root: Path, run_token_cap: int) -> None:
        identity.validate()
        if not isinstance(state_root, Path) or not state_root.is_absolute():
            raise CodexMediatorError("mediator state root must be an absolute controller path")
        if type(run_token_cap) is not int or not 1 <= run_token_cap <= MAX_TOKEN_COMPONENT:
            raise CodexMediatorError("mediator run token cap is invalid")
        self.identity = identity
        self.state_root = state_root
        self.run_token_cap = run_token_cap

    def mediate(self, request: MediationRequest) -> MediationResult:
        del request
        assert_live_invocation_permitted(self.identity)
        raise AssertionError("unreachable: release gate must reject before provider launch")
