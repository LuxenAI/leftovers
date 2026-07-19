"""Dependency-free sealed transfer records for the future strict-VM worker.

The format deliberately transports data only.  It cannot select a VM command,
mount, environment, network, or model credential.  LFRQ is a sealed request
file with a fixed 4KiB header and variable 512-byte-aligned payload.  LFRS is
an untrusted, bounded tail region of a fixed-size scratch disk; its footer is
written last by the guest and is parsed with ``pread`` only after shutdown.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
import stat
import struct
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .model_mediator import (
    ActionBatch,
    FinishAction,
    MediationLimits,
    MediationRequest,
    MediationResult,
    MediationStage,
    MediatorValidationError,
    RunCheckAction,
    validate_action_batch,
    validate_mediation_result,
)


class BundleError(RuntimeError):
    """A sealed request or untrusted tail result violates its binary contract."""


REQUEST_MAGIC = b"LFRQ"
RESULT_MAGIC = b"LFRS"
FORMAT_VERSION = 1
HEADER_BYTES = 4_096
ALIGNMENT = 512
MAX_SECTIONS = 16
MAX_REQUEST_BYTES = 256 * 1_024 * 1_024
MIN_SCRATCH_BYTES = 64 * 1_024 * 1_024
MAX_SCRATCH_BYTES = 4 * 1_024 * 1_024 * 1_024
MIN_RESULT_TAIL_BYTES = 1 * 1_024 * 1_024
MAX_RESULT_TAIL_BYTES = 64 * 1_024 * 1_024
COPY_CHUNK_BYTES = 64 * 1_024

REQUEST_SECTION_TYPES = frozenset(
    {
        "manifest",
        "source_capsule",
        "task",
        "policy",
        "check_registry",
        "mediation",
        "cumulative_patch",
        "proposed_patch",
        "action_batch",
        "prior_observations",
    }
)
REQUIRED_REQUEST_SECTION_TYPES = frozenset(
    {
        "manifest",
        "source_capsule",
        "task",
        "policy",
        "check_registry",
        "mediation",
        "action_batch",
    }
)
RESULT_SECTION_TYPES = frozenset(
    {"guest_receipt", "observations", "canonical_patch", "checks", "stage_result"}
)
REQUIRED_RESULT_SECTION_TYPES = RESULT_SECTION_TYPES
REQUEST_JSON_CAPS = {
    "manifest": 64 * 1_024,
    "task": 64 * 1_024,
    "policy": 64 * 1_024,
    "check_registry": 64 * 1_024,
    "mediation": 64 * 1_024,
    "action_batch": 256 * 1_024,
    "prior_observations": 128 * 1_024,
}
REQUEST_RAW_CAPS = {
    "source_capsule": 128 * 1_024 * 1_024,
    "cumulative_patch": 8 * 1_024 * 1_024,
    "proposed_patch": 256 * 1_024,
}
RESULT_JSON_CAPS = {
    "guest_receipt": 64 * 1_024,
    "observations": 256 * 1_024,
    "checks": 256 * 1_024,
    "stage_result": 128 * 1_024,
}
RESULT_RAW_CAPS = {"canonical_patch": 8 * 1_024 * 1_024}
STAGES = frozenset({"planning", "implementation", "review", "final_verify"})

_RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
_CURATED_CHECK_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_RESULT_STATUS = frozenset({"complete", "blocked", "failed"})
_OBSERVATION_STATUS = frozenset({"complete", "blocked", "failed"})
_MAX_RESULT_TAIL_TEXT_BYTES = 16 * 1_024
_MAX_RESULT_SUMMARY_BYTES = 4 * 1_024
FIXTURE_USAGE_EVIDENCE_SHA256 = hashlib.sha256(b"LEFTOVERS_FIXTURE_USAGE_EVIDENCE_V1\0").hexdigest()
_GUEST_ISOLATION_EVIDENCE = {
    "schema_version": 1,
    "network": "absent",
    "host_shares": 0,
    "credential_files": 0,
    "uid": 65534,
    "no_new_privs": True,
    "seccomp": True,
    "landlock": True,
    "cgroup_v2": True,
    "pid1": True,
    "root_read_only": True,
}
# magic, version, header bytes, section count, reserved, total bytes, payload digest,
# run id, round, stage, completion marker.  The marker is zero for LFRQ.
_PREFIX = struct.Struct("<4sHHHHQ32s64sI32s32s")
_SECTION = struct.Struct("<16sQQ32s")
_TABLE_END = _PREFIX.size + MAX_SECTIONS * _SECTION.size


def _align(value: int) -> int:
    return (value + ALIGNMENT - 1) & ~(ALIGNMENT - 1)


_PAYLOAD_START = _align(_TABLE_END)


@dataclass(frozen=True)
class BundleBinding:
    run_id: str
    round: int
    stage: str


@dataclass(frozen=True)
class SectionReference:
    section_type: str
    offset: int
    length: int
    sha256: str


@dataclass(frozen=True)
class ParsedBundle:
    binding: BundleBinding
    sections: dict[str, Any]
    raw_sections: dict[str, SectionReference]
    sha256: str
    fixture_authorization: bool = False


@dataclass(frozen=True)
class TailResult:
    binding: BundleBinding
    sections: dict[str, Any]
    raw_sections: dict[str, SectionReference]
    completion_marker: str
    sha256: str


@dataclass(frozen=True)
class GuestObservation:
    action_id: str
    status: str
    truncated: bool
    tail: str


@dataclass(frozen=True)
class GuestCheck:
    check_id: str
    exit_code: int | None
    timed_out: bool
    truncated: bool
    tail: str


@dataclass(frozen=True)
class VerifiedGuestResult:
    """Typed semantic result accepted from an already-stopped guest only."""

    run_id: str
    round: int
    stage: str
    request_sha256: str
    guest_policy_sha256: str
    status: str
    summary: str
    action_ids: tuple[str, ...]
    observations: tuple[GuestObservation, ...]
    checks: tuple[GuestCheck, ...]
    canonical_patch_sha256: str | None
    cumulative_patch_sha256: str | None


@dataclass(frozen=True)
class CuratedCheck:
    """A controller-owned check ID to fixed argv mapping.

    This object is data only.  It has no subprocess implementation in this
    module, and it deliberately cannot carry a working directory, shell, or
    environment selected by a model or repository.
    """

    check_id: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class MediationAuthorization:
    """Controller-issued, digest-bound data accepted by the strict VM path.

    ``fixture`` is intentionally explicit.  Fixture authorizations are for
    offline protocol tests only and the production controller rejects them.
    A future broker authorization requires an independently reviewed issuer;
    this data shape alone is not a cryptographic attestation.
    """

    policy: dict[str, Any]
    check_registry: dict[str, Any]
    action_batch: dict[str, Any]
    proposed_patch: bytes | None
    receipt: dict[str, Any]
    fixture: bool


@dataclass(frozen=True)
class BrokerSealedAuthorization:
    """Reserved opaque broker handoff type; verification is not implemented.

    Deliberately exposing a data class does not confer authority.  A future
    dedicated broker must supply an authenticated, non-caller-forgeable
    envelope and an independently reviewed verifier before this type can cross
    the request-builder boundary.
    """

    sealed_receipt: bytes


@dataclass(frozen=True)
class _Identity:
    dev: int
    ino: int
    uid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _identity(info: os.stat_result) -> _Identity:
    return _Identity(
        info.st_dev,
        info.st_ino,
        info.st_uid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _validate_binding(run_id: str, round: int, stage: str) -> BundleBinding:
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        raise BundleError("run_id must be exactly 32 lowercase hex characters")
    if type(round) is not int or not 0 <= round <= 1_000_000:
        raise BundleError("round must be an integer between 0 and 1000000")
    if stage not in STAGES:
        raise BundleError("stage is not permitted")
    return BundleBinding(run_id, round, stage)


def _encode_fixed(value: str, size: int, label: str) -> bytes:
    raw = value.encode("ascii")
    if len(raw) > size:
        raise BundleError(f"{label} is too long")
    return raw + b"\0" * (size - len(raw))


def _decode_fixed(raw: bytes, label: str) -> str:
    head, separator, tail = raw.partition(b"\0")
    if separator and any(tail):
        raise BundleError(f"{label} has nonzero reserved bytes")
    try:
        return head.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BundleError(f"{label} is not ASCII") from exc


def _validate_json_complexity(value: Any) -> None:
    nodes = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 4_096 or depth > 20:
            raise BundleError("JSON exceeds complexity limits")
        if isinstance(item, dict):
            if len(item) > 256 or any(not isinstance(key, str) or len(key) > 256 for key in item):
                raise BundleError("JSON object exceeds shape limits")
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 1_024:
                raise BundleError("JSON array exceeds shape limits")
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str) and len(item) > 65_536:
            raise BundleError("JSON string exceeds shape limits")
        elif type(item) is int and not -(2**63) <= item <= 2**63 - 1:
            raise BundleError("JSON integer exceeds signed 64-bit range")
        elif isinstance(item, float):
            raise BundleError("JSON may not contain floating-point values")

    walk(value, 0)


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _canonical_json(value: Any, maximum: int) -> bytes:
    _validate_json_complexity(value)
    try:
        raw = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BundleError("JSON value cannot be canonicalized") from exc
    if not 0 < len(raw) <= maximum:
        raise BundleError("JSON section exceeds its byte cap")
    return raw


def _validate_action_policy(value: Any) -> tuple[str, str, str, frozenset[str], int]:
    """Parse the controller-owned action policy with no extensible authority fields."""

    expected = {
        "schema_version",
        "provider",
        "model",
        "reasoning_effort",
        "allowed_check_ids",
        "max_actions",
    }
    if type(value) is not dict or set(value) != expected or value.get("schema_version") != 1:
        raise BundleError("policy must be the exact strict action-policy object")
    provider = value["provider"]
    model = value["model"]
    effort = value["reasoning_effort"]
    checks = value["allowed_check_ids"]
    max_actions = value["max_actions"]
    if (
        type(provider) is not str
        or type(model) is not str
        or type(effort) is not str
        or type(checks) is not list
        or type(max_actions) is not int
        or not 1 <= max_actions <= 32
        or len(checks) > 32
        or checks != sorted(checks)
        or len(checks) != len(set(checks))
        or any(
            type(check) is not str or _CURATED_CHECK_ID.fullmatch(check) is None for check in checks
        )
    ):
        raise BundleError("policy action identity, checks, or limits are invalid")
    return provider, model, effort, frozenset(checks), max_actions


def _validate_fixed_argv(value: Any, *, check_id: str) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= 32:
        raise BundleError("check registry argv is outside its fixed bounds")
    argv: list[str] = []
    forbidden = {"sh", "bash", "zsh", "dash", "fish", "env", "sudo", "doas"}
    total = 0
    for index, item in enumerate(value):
        if type(item) is not str or not item or "\x00" in item or _contains_control(item):
            raise BundleError("check registry argv contains unsafe text")
        try:
            length = len(item.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise BundleError("check registry argv is not UTF-8") from exc
        if length > 512:
            raise BundleError("check registry argv component exceeds its byte cap")
        total += length
        if total > 4096:
            raise BundleError("check registry argv exceeds its aggregate byte cap")
        if index == 0 and item.rsplit("/", 1)[-1] in forbidden:
            raise BundleError("check registry may not invoke a shell or privilege wrapper")
        argv.append(item)
    if check_id != check_id.casefold():
        raise BundleError("check registry ID is not canonical")
    return tuple(argv)


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_check_registry(
    value: Any, *, allowed_check_ids: frozenset[str]
) -> dict[str, tuple[str, ...]]:
    expected = {"schema_version", "checks"}
    if type(value) is not dict or set(value) != expected or value.get("schema_version") != 1:
        raise BundleError("check_registry must be the exact strict registry object")
    checks = value["checks"]
    if type(checks) is not list or len(checks) != len(allowed_check_ids):
        raise BundleError("check_registry does not exactly cover the policy check IDs")
    parsed: dict[str, tuple[str, ...]] = {}
    prior = ""
    for item in checks:
        if type(item) is not dict or set(item) != {"check_id", "argv"}:
            raise BundleError("check_registry entry has unknown authority fields")
        check_id = item["check_id"]
        if type(check_id) is not str or _CURATED_CHECK_ID.fullmatch(check_id) is None:
            raise BundleError("check_registry check ID is invalid")
        if check_id <= prior or check_id in parsed:
            raise BundleError("check_registry entries must be sorted and unique")
        parsed[check_id] = _validate_fixed_argv(item["argv"], check_id=check_id)
        prior = check_id
    if frozenset(parsed) != allowed_check_ids:
        raise BundleError("check_registry does not exactly match the policy check IDs")
    return parsed


def curated_check_registry(checks: tuple[CuratedCheck, ...]) -> dict[str, Any]:
    """Canonicalize controller-curated checks before receipt issuance."""

    if type(checks) is not tuple or any(type(item) is not CuratedCheck for item in checks):
        raise BundleError("curated checks must be an immutable CuratedCheck tuple")
    value = {
        "schema_version": 1,
        "checks": [
            {"check_id": item.check_id, "argv": list(item.argv)}
            for item in sorted(checks, key=lambda item: item.check_id)
        ],
    }
    _validate_check_registry(value, allowed_check_ids=frozenset(item.check_id for item in checks))
    return value


def _receipt_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(dict(value), REQUEST_JSON_CAPS["mediation"])).hexdigest()


def authorize_mediation_result(
    request: MediationRequest,
    result: MediationResult,
    *,
    policy: Mapping[str, Any],
    curated_checks: tuple[CuratedCheck, ...],
    token_ledger_reservation_id: str,
    provider_usage_evidence_sha256: str,
    fixture: bool = False,
) -> MediationAuthorization:
    """Issue the only authorization shape accepted by a strict-VM LFRQ build.

    A raw action document is never an authorization.  The controller must
    supply a re-validated mediator result, its exact policy and a curated
    check-to-argv registry.  Production issuer identity/signing remains a
    separate release gate; this helper accepts fixture authority only when the
    caller says so explicitly.
    """

    if not fixture:
        raise BundleError("broker attestation verification is not implemented")
    raw_action = validate_mediation_result(result, request)
    if not isinstance(policy, Mapping):
        raise BundleError("controller policy must be a mapping")
    canonical_policy = json.loads(_canonical_json(dict(policy), REQUEST_JSON_CAPS["policy"]))
    provider, model, effort, allowed_checks, max_actions = _validate_action_policy(canonical_policy)
    if (
        provider != request.provider
        or model != request.model
        or effort != request.reasoning_effort
        or max_actions != request.limits.max_actions
        or allowed_checks != request.allowed_check_ids
    ):
        raise BundleError("controller policy does not exactly bind the mediation request")
    registry = curated_check_registry(curated_checks)
    _validate_check_registry(registry, allowed_check_ids=allowed_checks)
    if (
        type(token_ledger_reservation_id) is not str
        or _SHA256.fullmatch(token_ledger_reservation_id) is None
    ):
        raise BundleError("token ledger reservation identity must be a SHA-256 digest")
    if (
        type(provider_usage_evidence_sha256) is not str
        or _SHA256.fullmatch(provider_usage_evidence_sha256) is None
    ):
        raise BundleError("provider usage evidence identity must be a SHA-256 digest")
    if fixture and provider_usage_evidence_sha256 != FIXTURE_USAGE_EVIDENCE_SHA256:
        raise BundleError("fixture authorization must use deterministic usage evidence")
    if result.receipt.usage_source != ("fixture" if fixture else "provider"):
        raise BundleError("mediation receipt source does not match authorization authority")
    receipt = result.receipt.to_dict()
    receipt.update(
        {
            "authority": "fixture" if fixture else "broker",
            "policy_sha256": hashlib.sha256(
                _canonical_json(canonical_policy, REQUEST_JSON_CAPS["policy"])
            ).hexdigest(),
            "check_registry_sha256": hashlib.sha256(
                _canonical_json(registry, REQUEST_JSON_CAPS["check_registry"])
            ).hexdigest(),
            "token_ledger_reservation_id": token_ledger_reservation_id,
            "provider_usage_evidence_sha256": provider_usage_evidence_sha256,
        }
    )
    canonical_receipt = json.loads(_canonical_json(receipt, REQUEST_JSON_CAPS["mediation"]))
    action_batch = json.loads(raw_action)
    return MediationAuthorization(
        policy=canonical_policy,
        check_registry=registry,
        action_batch=action_batch,
        proposed_patch=result.patch,
        receipt=canonical_receipt,
        fixture=fixture,
    )


def _validate_mediation_receipt(
    binding: BundleBinding,
    sections: Mapping[str, Any],
    raw_sections: Mapping[str, SectionReference],
    *,
    fixture_authorization: bool,
) -> None:
    """Verify the sealed receipt, policy, registry, patch, and action batch agree."""

    policy = sections.get("policy")
    provider, model, effort, allowed_checks, max_actions = _validate_action_policy(policy)
    registry = sections.get("check_registry")
    _validate_check_registry(registry, allowed_check_ids=allowed_checks)
    action_value = sections.get("action_batch")
    action_raw = _canonical_json(action_value, REQUEST_JSON_CAPS["action_batch"])
    proposed = raw_sections.get("proposed_patch")
    receipt = sections.get("mediation")
    if type(receipt) is not dict:
        raise BundleError("mediation receipt must be an object")
    expected = {
        "schema_version",
        "run_id",
        "round",
        "stage",
        "provider",
        "model",
        "reasoning_effort",
        "input_sha256",
        "action_batch_sha256",
        "patch_sha256",
        "output_sha256",
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "reasoning_tokens",
        "total_tokens",
        "usage_source",
        "exact_usage",
        "max_response_bytes",
        "max_patch_bytes",
        "max_actions",
        "input_token_cap",
        "output_token_cap",
        "total_token_cap",
        "call_index",
        "call_cap",
        "deadline_at",
        "started_at",
        "finished_at",
        "authority",
        "policy_sha256",
        "check_registry_sha256",
        "token_ledger_reservation_id",
        "provider_usage_evidence_sha256",
    }
    if set(receipt) != expected or receipt.get("schema_version") != 1:
        raise BundleError("mediation receipt must have the exact controller-issued shape")
    if receipt["authority"] == "fixture":
        if not fixture_authorization or receipt.get("usage_source") != "fixture":
            raise BundleError("fixture mediation authorization is not enabled for this build")
    elif receipt["authority"] == "broker" and receipt.get("usage_source") == "provider":
        raise BundleError("broker attestation verification is not implemented")
    else:
        raise BundleError("mediation receipt authority is not accepted")
    identity = {
        "run_id": binding.run_id,
        "round": binding.round,
        "stage": binding.stage,
        "provider": provider,
        "model": model,
        "reasoning_effort": effort,
        "max_actions": max_actions,
    }
    if any(receipt.get(key) != value for key, value in identity.items()):
        raise BundleError("mediation receipt identity does not exactly bind the LFRQ")
    digests = {
        "action_batch_sha256": hashlib.sha256(action_raw).hexdigest(),
        "policy_sha256": hashlib.sha256(
            _canonical_json(policy, REQUEST_JSON_CAPS["policy"])
        ).hexdigest(),
        "check_registry_sha256": hashlib.sha256(
            _canonical_json(registry, REQUEST_JSON_CAPS["check_registry"])
        ).hexdigest(),
        "patch_sha256": None if proposed is None else proposed.sha256,
    }
    if any(receipt.get(key) != value for key, value in digests.items()):
        raise BundleError("mediation receipt digest does not bind the LFRQ data")
    reservation = receipt.get("token_ledger_reservation_id")
    if type(reservation) is not str or _SHA256.fullmatch(reservation) is None:
        raise BundleError("mediation receipt token ledger reservation identity is invalid")
    for name in (
        "input_sha256",
        "action_batch_sha256",
        "output_sha256",
        "policy_sha256",
        "check_registry_sha256",
        "token_ledger_reservation_id",
        "provider_usage_evidence_sha256",
    ):
        if type(receipt.get(name)) is not str or _SHA256.fullmatch(receipt[name]) is None:
            raise BundleError("mediation receipt digest field is invalid")
    if receipt.get("patch_sha256") is not None and (
        type(receipt["patch_sha256"]) is not str
        or _SHA256.fullmatch(receipt["patch_sha256"]) is None
    ):
        raise BundleError("mediation receipt patch digest is invalid")


def build_authorized_request_bundle(
    path: Path,
    *,
    run_id: str,
    round: int,
    stage: str,
    manifest: Mapping[str, Any],
    source_capsule: Path,
    task: Mapping[str, Any],
    authorization: MediationAuthorization | BrokerSealedAuthorization,
    cumulative_patch: bytes | str | Path | None = None,
    prior_observations: Mapping[str, Any] | None = None,
) -> ParsedBundle:
    """Build an LFRQ only from a controller-issued mediation authorization.

    The public strict-worker path uses this entry point rather than accepting
    an independently supplied policy, action batch, proposed patch, or check
    registry.  The low-level serializer remains available for binary parser
    tests, but it rejects missing receipt authority by default.
    """

    if type(authorization) is BrokerSealedAuthorization:
        raise BundleError("broker attestation verification is not implemented")
    if type(authorization) is not MediationAuthorization or not authorization.fixture:
        raise BundleError("strict VM request requires explicit fixture authorization")
    sections: dict[str, Any] = {
        "manifest": dict(manifest),
        "source_capsule": Path(source_capsule),
        "task": dict(task),
        "policy": dict(authorization.policy),
        "check_registry": dict(authorization.check_registry),
        "mediation": dict(authorization.receipt),
        "action_batch": dict(authorization.action_batch),
    }
    if authorization.proposed_patch is not None:
        sections["proposed_patch"] = authorization.proposed_patch
    if cumulative_patch is not None:
        sections["cumulative_patch"] = cumulative_patch
    if prior_observations is not None:
        sections["prior_observations"] = dict(prior_observations)
    return build_request_bundle(
        path,
        run_id=run_id,
        round=round,
        stage=stage,
        sections=sections,
        fixture_authorization=authorization.fixture,
    )


def _validate_action_document(
    binding: BundleBinding,
    sections: Mapping[str, Any],
    raw_sections: Mapping[str, SectionReference],
) -> ActionBatch:
    """Re-run the mediator grammar before an action document reaches the guest."""

    provider, model, effort, allowed_checks, max_actions = _validate_action_policy(
        sections.get("policy")
    )
    action_value = sections.get("action_batch")
    action_raw = _canonical_json(action_value, REQUEST_JSON_CAPS["action_batch"])
    proposed = raw_sections.get("proposed_patch")
    try:
        request = MediationRequest(
            run_id=binding.run_id,
            round=binding.round,
            stage=MediationStage(binding.stage),
            provider=provider,
            model=model,
            reasoning_effort=effort,
            input_bytes=b"{}",
            allowed_check_ids=allowed_checks,
            limits=MediationLimits(
                max_response_bytes=256 * 1_024,
                max_patch_bytes=256 * 1_024,
                max_actions=max_actions,
                input_token_cap=1,
                output_token_cap=1,
                total_token_cap=2,
                call_index=1,
                call_cap=1,
            ),
            deadline_at=datetime.now(UTC) + timedelta(minutes=1),
        )
        return validate_action_batch(
            action_raw,
            request,
            proposed_patch_sha256=None if proposed is None else proposed.sha256,
        )
    except (MediatorValidationError, ValueError) as exc:
        raise BundleError("action_batch violates the strict mediated action grammar") from exc


def _validate_request_stage_sections(
    binding: BundleBinding,
    sections: Mapping[str, Any],
    raw_sections: Mapping[str, SectionReference],
    *,
    fixture_authorization: bool,
) -> None:
    if binding.stage == "final_verify" and "cumulative_patch" not in raw_sections:
        raise BundleError("final_verify requires the frozen cumulative_patch")
    _validate_mediation_receipt(
        binding,
        sections,
        raw_sections,
        fixture_authorization=fixture_authorization,
    )
    _validate_action_document(binding, sections, raw_sections)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _parse_canonical_json(raw: bytes, maximum: int) -> Any:
    if not 0 < len(raw) <= maximum:
        raise BundleError("JSON section exceeds its byte cap")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BundleError("section is not valid UTF-8 JSON") from exc
    _validate_json_complexity(value)
    if _canonical_json(value, maximum) != raw:
        raise BundleError("JSON section is not canonical")
    return value


def _safe_parent(path: Path) -> None:
    try:
        info = path.parent.lstat()
    except OSError as exc:
        raise BundleError("record parent is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise BundleError("record parent is not private and owner-controlled")


def _open_exact(path: Path, *, size: int, mode: int) -> tuple[int, _Identity]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise BundleError("record is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != mode
        or before.st_nlink != 1
        or before.st_size != size
    ):
        raise BundleError("record ownership, mode, links, or exact size is unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BundleError("record cannot be opened without following links") from exc
    identity = _identity(os.fstat(descriptor))
    if identity != _identity(before):
        os.close(descriptor)
        raise BundleError("record identity changed while opening")
    return descriptor, identity


def _verify_identity(descriptor: int, expected: _Identity) -> None:
    if _identity(os.fstat(descriptor)) != expected:
        raise BundleError("record identity changed while reading")


def _pread_exact(descriptor: int, length: int, offset: int) -> bytes:
    if length < 0 or offset < 0:
        raise BundleError("record range is invalid")
    raw = os.pread(descriptor, length, offset)
    if len(raw) != length:
        raise BundleError("record is truncated")
    return raw


def _hash_range(
    descriptor: int, start: int, end: int, *, require_zero_gaps: list[tuple[int, int]]
) -> bytes:
    digest = hashlib.sha256()
    gap_index = 0
    offset = start
    while offset < end:
        length = min(COPY_CHUNK_BYTES, end - offset)
        raw = _pread_exact(descriptor, length, offset)
        digest.update(raw)
        while gap_index < len(require_zero_gaps):
            gap_start, gap_end = require_zero_gaps[gap_index]
            if gap_end <= offset:
                gap_index += 1
                continue
            overlap_start = max(offset, gap_start)
            overlap_end = min(offset + length, gap_end)
            if overlap_start < overlap_end and any(
                raw[overlap_start - offset : overlap_end - offset]
            ):
                raise BundleError("record has nonzero alignment gap or padding")
            if gap_end > offset + length:
                break
            gap_index += 1
        offset += length
    return digest.digest()


def _hash_plain_range(descriptor: int, start: int, end: int) -> bytes:
    """Hash an exact on-disk region without retaining it in memory."""

    return _hash_range(descriptor, start, end, require_zero_gaps=[])


def _copy_file(
    source: Path,
    target_descriptor: int,
    target_offset: int,
    maximum: int,
    *,
    utf8: bool,
) -> tuple[int, bytes]:
    try:
        source_info = source.lstat()
    except OSError as exc:
        raise BundleError("raw section source is unavailable") from exc
    if (
        not stat.S_ISREG(source_info.st_mode)
        or source_info.st_uid != os.getuid()
        or source_info.st_nlink != 1
        or stat.S_IMODE(source_info.st_mode) & 0o077
        or source_info.st_size <= 0
        or source_info.st_size > maximum
    ):
        raise BundleError("raw section source is unsafe or exceeds its byte cap")
    try:
        source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BundleError("raw section source cannot be opened safely") from exc
    before = _identity(os.fstat(source_descriptor))
    if before != _identity(source_info):
        os.close(source_descriptor)
        raise BundleError("raw section source identity changed while opening")
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")() if utf8 else None
    written = 0
    try:
        while True:
            raw = os.read(source_descriptor, COPY_CHUNK_BYTES)
            if not raw:
                break
            written += len(raw)
            if written > maximum:
                raise BundleError("raw section source exceeds its byte cap")
            if decoder is not None:
                try:
                    decoder.decode(raw)
                except UnicodeDecodeError as exc:
                    raise BundleError("raw patch is not valid UTF-8") from exc
            digest.update(raw)
            view = memoryview(raw)
            while view:
                count = os.pwrite(target_descriptor, view, target_offset)
                if count <= 0:
                    raise BundleError("record payload write made no progress")
                view = view[count:]
                target_offset += count
        if decoder is not None:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError as exc:
                raise BundleError("raw patch is not valid UTF-8") from exc
        if written != before.size or _identity(os.fstat(source_descriptor)) != before:
            raise BundleError("raw section source identity changed while reading")
    finally:
        os.close(source_descriptor)
    return written, digest.digest()


def _raw_from_value(
    value: Any, maximum: int, *, utf8: bool
) -> tuple[bytes | Path, int, bytes | None]:
    if isinstance(value, Path):
        return value, -1, None
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        raise BundleError("raw section must be bytes, text, or a Path")
    if not 0 < len(raw) <= maximum:
        raise BundleError("raw section exceeds its byte cap")
    if utf8:
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError("raw patch is not valid UTF-8") from exc
    return raw, len(raw), hashlib.sha256(raw).digest()


def _canonical_patch(value: Any, *, allow_empty: bool) -> bytes:
    """Return a bounded UTF-8 patch without interpreting it as JSON or code."""

    if isinstance(value, Path):
        raise BundleError("tail test helper requires an in-memory canonical patch")
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BundleError("raw patch is not valid UTF-8") from exc
    elif isinstance(value, bytes):
        raw = value
    else:
        raise BundleError("canonical patch must be text or bytes")
    if (not allow_empty and not raw) or len(raw) > RESULT_RAW_CAPS["canonical_patch"]:
        raise BundleError("canonical patch exceeds its byte cap")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleError("raw patch is not valid UTF-8") from exc
    return raw


def _write_all(descriptor: int, raw: bytes, offset: int) -> None:
    view = memoryview(raw)
    while view:
        count = os.pwrite(descriptor, view, offset)
        if count <= 0:
            raise BundleError("record write made no progress")
        offset += count
        view = view[count:]


def _pack_header(
    magic: bytes,
    binding: BundleBinding,
    total_size: int,
    payload_digest: bytes,
    records: list[tuple[str, int, int, bytes]],
    completion_marker: bytes,
) -> bytes:
    if len(records) > MAX_SECTIONS or len(payload_digest) != 32 or len(completion_marker) != 32:
        raise BundleError("record header inputs are invalid")
    header = bytearray(HEADER_BYTES)
    _PREFIX.pack_into(
        header,
        0,
        magic,
        FORMAT_VERSION,
        HEADER_BYTES,
        len(records),
        0,
        total_size,
        payload_digest,
        _encode_fixed(binding.run_id, 64, "run_id"),
        binding.round,
        _encode_fixed(binding.stage, 32, "stage"),
        completion_marker,
    )
    for index, (section_type, offset, length, digest) in enumerate(records):
        _SECTION.pack_into(
            header,
            _PREFIX.size + index * _SECTION.size,
            _encode_fixed(section_type, 16, "section type"),
            offset,
            length,
            digest,
        )
    return bytes(header)


def _marker(
    magic: bytes,
    binding: BundleBinding,
    total_size: int,
    payload_digest: bytes,
    records: list[tuple[str, int, int, bytes]],
) -> bytes:
    digest = hashlib.sha256()
    digest.update(magic)
    digest.update(struct.pack("<HQ", FORMAT_VERSION, total_size))
    digest.update(_encode_fixed(binding.run_id, 64, "run_id"))
    digest.update(struct.pack("<I", binding.round))
    digest.update(_encode_fixed(binding.stage, 32, "stage"))
    digest.update(payload_digest)
    for section_type, offset, length, section_digest in records:
        digest.update(_encode_fixed(section_type, 16, "section type"))
        digest.update(struct.pack("<QQ", offset, length))
        digest.update(section_digest)
    return digest.digest()


def _parse_header(
    raw: bytes,
    *,
    magic: bytes,
    total_size: int,
    expected: BundleBinding,
    allowed_types: frozenset[str],
    required_types: frozenset[str],
    caps: Mapping[str, int],
    payload_start: int,
    payload_end: int,
    require_marker: bool,
) -> tuple[list[tuple[str, int, int, bytes]], bytes, bytes]:
    if len(raw) != HEADER_BYTES:
        raise BundleError("record header is truncated")
    try:
        fields = _PREFIX.unpack_from(raw)
    except struct.error as exc:
        raise BundleError("record header is malformed") from exc
    (
        observed_magic,
        version,
        header_bytes,
        count,
        reserved,
        declared_size,
        payload_digest,
        encoded_run_id,
        round_number,
        encoded_stage,
        completion_marker,
    ) = fields
    if (
        observed_magic != magic
        or version != FORMAT_VERSION
        or header_bytes != HEADER_BYTES
        or reserved != 0
        or declared_size != total_size
        or (not require_marker and any(completion_marker))
    ):
        raise BundleError("record header fields are invalid")
    binding = _validate_binding(
        _decode_fixed(encoded_run_id, "run_id"), round_number, _decode_fixed(encoded_stage, "stage")
    )
    if binding != expected or not 0 < count <= MAX_SECTIONS:
        raise BundleError("record binding or section count is invalid")
    records: list[tuple[str, int, int, bytes]] = []
    ranges: list[tuple[int, int]] = []
    names: set[str] = set()
    previous_type = ""
    previous_offset = -1
    for index in range(count):
        position = _PREFIX.size + index * _SECTION.size
        type_raw, offset, length, section_digest = _SECTION.unpack_from(raw, position)
        section_type = _decode_fixed(type_raw, "section type")
        if section_type not in allowed_types or section_type in names:
            raise BundleError("record contains an unknown or duplicate section type")
        if section_type <= previous_type or offset < previous_offset:
            raise BundleError("record section table is not in canonical order")
        if length < 0 or length > caps[section_type] or offset % ALIGNMENT:
            raise BundleError("record section length or alignment is invalid")
        if length == 0 and section_type not in {"canonical_patch"}:
            raise BundleError("record section length or alignment is invalid")
        end = offset + length
        if end < offset or offset < payload_start or end > payload_end:
            raise BundleError("record section is outside the bounded payload region")
        names.add(section_type)
        previous_type = section_type
        previous_offset = offset
        records.append((section_type, offset, length, section_digest))
        ranges.append((offset, end))
    if not required_types.issubset(names):
        raise BundleError("record omits a required section type")
    if any(raw[_PREFIX.size + count * _SECTION.size : _TABLE_END]) or any(
        raw[_TABLE_END:HEADER_BYTES]
    ):
        raise BundleError("record has nonzero reserved header bytes")
    ordered = sorted(ranges)
    for previous, current in zip(ordered, ordered[1:], strict=False):
        if previous[1] > current[0]:
            raise BundleError("record sections overlap")
    if require_marker and completion_marker != _marker(
        magic, expected, total_size, payload_digest, records
    ):
        raise BundleError("tail completion marker does not match its header")
    return records, payload_digest, completion_marker


def _record_for(
    records: list[tuple[str, int, int, bytes]], name: str
) -> tuple[str, int, int, bytes]:
    for record in records:
        if record[0] == name:
            return record
    raise BundleError("record omits a required section type")


def _gaps(
    start: int, end: int, records: list[tuple[str, int, int, bytes]]
) -> list[tuple[int, int]]:
    cursor = start
    gaps: list[tuple[int, int]] = []
    for _, offset, length, _ in sorted(records, key=lambda item: item[1]):
        if cursor < offset:
            gaps.append((cursor, offset))
        cursor = offset + length
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def _stream_section_hash(descriptor: int, offset: int, length: int) -> bytes:
    digest = hashlib.sha256()
    cursor = offset
    end = offset + length
    while cursor < end:
        raw = _pread_exact(descriptor, min(COPY_CHUNK_BYTES, end - cursor), cursor)
        digest.update(raw)
        cursor += len(raw)
    return digest.digest()


def _read_json_section(descriptor: int, offset: int, length: int, maximum: int) -> Any:
    # JSON sections have intentionally small per-type caps; raw capsules and patches never use this.
    return _parse_canonical_json(_pread_exact(descriptor, length, offset), maximum)


def _validate_utf8_section(descriptor: int, offset: int, length: int) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")()
    cursor = offset
    end = offset + length
    try:
        while cursor < end:
            raw = _pread_exact(descriptor, min(COPY_CHUNK_BYTES, end - cursor), cursor)
            decoder.decode(raw)
            cursor += len(raw)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise BundleError("raw patch is not valid UTF-8") from exc


def build_request_bundle(
    path: Path,
    *,
    run_id: str,
    round: int,
    stage: str,
    sections: Mapping[str, Any],
    fixture_authorization: bool = False,
) -> ParsedBundle:
    """Build a sealed 0400 LFRQ request without loading an opaque capsule into RAM.

    ``source_capsule`` should be a :class:`~pathlib.Path`; it is streamed with
    a bounded buffer.  ``cumulative_patch`` may also be a Path for streaming.
    """

    binding = _validate_binding(run_id, round, stage)
    if not isinstance(sections, Mapping) or not REQUIRED_REQUEST_SECTION_TYPES.issubset(sections):
        raise BundleError("request omits a required section type")
    if any(name not in REQUEST_SECTION_TYPES for name in sections) or len(sections) > MAX_SECTIONS:
        raise BundleError("request contains an unknown section type")
    if not isinstance(sections["source_capsule"], Path):
        raise BundleError("source_capsule must be a streamed Path")
    prepared: list[tuple[str, bytes | Path, int, bytes | None, bool]] = []
    for section_type in sorted(sections):
        if section_type in REQUEST_JSON_CAPS:
            raw = _canonical_json(sections[section_type], REQUEST_JSON_CAPS[section_type])
            prepared.append((section_type, raw, len(raw), hashlib.sha256(raw).digest(), False))
        else:
            if section_type == "proposed_patch" and isinstance(sections[section_type], Path):
                raise BundleError("proposed_patch must be bounded in-memory mediator bytes")
            raw, length, digest = _raw_from_value(
                sections[section_type],
                REQUEST_RAW_CAPS[section_type],
                utf8=section_type in {"cumulative_patch", "proposed_patch"},
            )
            if isinstance(raw, Path):
                try:
                    size = raw.lstat().st_size
                except OSError as exc:
                    raise BundleError("raw section source is unavailable") from exc
                if not 0 < size <= REQUEST_RAW_CAPS[section_type]:
                    raise BundleError("raw section source exceeds its byte cap")
                length = size
            prepared.append(
                (
                    section_type,
                    raw,
                    length,
                    digest,
                    section_type in {"cumulative_patch", "proposed_patch"},
                )
            )
    provisional_raw_sections = {
        section_type: SectionReference(
            section_type,
            0,
            length,
            "0" * 64 if digest is None else digest.hex(),
        )
        for section_type, _raw, length, digest, _utf8 in prepared
        if section_type in REQUEST_RAW_CAPS
    }
    _validate_request_stage_sections(
        binding,
        sections,
        provisional_raw_sections,
        fixture_authorization=fixture_authorization,
    )
    cursor = HEADER_BYTES
    layout: list[tuple[str, int, int, bytes | Path, bytes | None, bool]] = []
    for section_type, source, length, digest, utf8 in prepared:
        cursor = _align(cursor)
        layout.append((section_type, cursor, length, source, digest, utf8))
        cursor += length
    total_size = _align(cursor)
    if total_size > MAX_REQUEST_BYTES:
        raise BundleError("request total size exceeds 256MiB cap")
    _safe_parent(path)
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise BundleError("request output cannot be created safely") from exc
    try:
        os.ftruncate(descriptor, total_size)
        records: list[tuple[str, int, int, bytes]] = []
        for section_type, offset, length, source, digest, utf8 in layout:
            if isinstance(source, Path):
                observed_length, observed_digest = _copy_file(
                    source, descriptor, offset, REQUEST_RAW_CAPS[section_type], utf8=utf8
                )
                if observed_length != length:
                    raise BundleError("raw section source size changed while copying")
                digest = observed_digest
            else:
                _write_all(descriptor, source, offset)
            assert digest is not None
            records.append((section_type, offset, length, digest))
        payload_digest = _hash_range(
            descriptor,
            HEADER_BYTES,
            total_size,
            require_zero_gaps=_gaps(HEADER_BYTES, total_size, records),
        )
        header = _pack_header(
            REQUEST_MAGIC, binding, total_size, payload_digest, records, b"\0" * 32
        )
        _write_all(descriptor, header, 0)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        with suppress(OSError):
            path.unlink()
        raise
    os.close(descriptor)
    return parse_request_bundle(
        path,
        run_id=run_id,
        round=round,
        stage=stage,
        fixture_authorization=fixture_authorization,
    )


def parse_request_bundle(
    path: Path,
    *,
    run_id: str,
    round: int,
    stage: str,
    fixture_authorization: bool = False,
) -> ParsedBundle:
    """Validate a sealed variable-size LFRQ request with streaming raw checks."""

    binding = _validate_binding(run_id, round, stage)
    try:
        requested_size = path.lstat().st_size
    except OSError as exc:
        raise BundleError("request is unavailable") from exc
    if not HEADER_BYTES <= requested_size <= MAX_REQUEST_BYTES or requested_size % ALIGNMENT:
        raise BundleError("request exact size is outside aligned bounds")
    descriptor, identity = _open_exact(path, size=requested_size, mode=0o400)
    try:
        header = _pread_exact(descriptor, HEADER_BYTES, 0)
        records, payload_digest, _ = _parse_header(
            header,
            magic=REQUEST_MAGIC,
            total_size=requested_size,
            expected=binding,
            allowed_types=REQUEST_SECTION_TYPES,
            required_types=REQUIRED_REQUEST_SECTION_TYPES,
            caps={**REQUEST_JSON_CAPS, **REQUEST_RAW_CAPS},
            payload_start=HEADER_BYTES,
            payload_end=requested_size,
            require_marker=False,
        )
        if (
            _hash_range(
                descriptor,
                HEADER_BYTES,
                requested_size,
                require_zero_gaps=_gaps(HEADER_BYTES, requested_size, records),
            )
            != payload_digest
        ):
            raise BundleError("request whole-payload SHA-256 does not match")
        sections: dict[str, Any] = {}
        raw_sections: dict[str, SectionReference] = {}
        for section_type, offset, length, digest in records:
            if _stream_section_hash(descriptor, offset, length) != digest:
                raise BundleError("request section hash does not match")
            if section_type in REQUEST_JSON_CAPS:
                sections[section_type] = _read_json_section(
                    descriptor, offset, length, REQUEST_JSON_CAPS[section_type]
                )
            else:
                if section_type in {"cumulative_patch", "proposed_patch"}:
                    _validate_utf8_section(descriptor, offset, length)
                raw_sections[section_type] = SectionReference(
                    section_type, offset, length, digest.hex()
                )
        _validate_request_stage_sections(
            binding,
            sections,
            raw_sections,
            fixture_authorization=fixture_authorization,
        )
        whole_request_sha256 = _hash_plain_range(descriptor, 0, requested_size).hex()
        _verify_identity(descriptor, identity)
    finally:
        os.close(descriptor)
    return ParsedBundle(
        binding,
        sections,
        raw_sections,
        whole_request_sha256,
        fixture_authorization=fixture_authorization,
    )


def _read_bounded_raw_section(descriptor: int, offset: int, length: int) -> bytes:
    """Return one explicitly permitted raw patch, never an opaque capsule."""

    chunks: list[bytes] = []
    cursor = offset
    end = offset + length
    while cursor < end:
        raw = _pread_exact(descriptor, min(COPY_CHUNK_BYTES, end - cursor), cursor)
        chunks.append(raw)
        cursor += len(raw)
    return b"".join(chunks)


def read_raw_section(
    path: Path,
    parsed: ParsedBundle | TailResult,
    section_type: str,
    *,
    scratch_size: int | None = None,
    tail_region_bytes: int | None = None,
) -> bytes:
    """Reopen and revalidate one bounded UTF-8 patch without mounting a record.

    Only the controller-consumable cumulative request patch and guest canonical
    result patch are readable.  The opaque source capsule remains stream-only.
    """

    if isinstance(parsed, ParsedBundle):
        if section_type != "cumulative_patch":
            raise BundleError("only cumulative_patch can be read from an LFRQ request")
        try:
            size = path.lstat().st_size
        except OSError as exc:
            raise BundleError("request is unavailable") from exc
        if not HEADER_BYTES <= size <= MAX_REQUEST_BYTES or size % ALIGNMENT:
            raise BundleError("request exact size is outside aligned bounds")
        descriptor, identity = _open_exact(path, size=size, mode=0o400)
        header_offset = 0
        payload_start = HEADER_BYTES
        payload_end = size
        magic = REQUEST_MAGIC
        allowed_types = REQUEST_SECTION_TYPES
        required_types = REQUIRED_REQUEST_SECTION_TYPES
        caps: Mapping[str, int] = {**REQUEST_JSON_CAPS, **REQUEST_RAW_CAPS}
        expected_sha256 = parsed.sha256
        expected_reference = parsed.raw_sections.get(section_type)
    elif isinstance(parsed, TailResult):
        if section_type != "canonical_patch":
            raise BundleError("only canonical_patch can be read from an LFRS result")
        if scratch_size is None or tail_region_bytes is None:
            raise BundleError("scratch size and tail region are required for an LFRS read")
        if (
            type(scratch_size) is not int
            or not MIN_SCRATCH_BYTES <= scratch_size <= MAX_SCRATCH_BYTES
            or scratch_size % ALIGNMENT
            or type(tail_region_bytes) is not int
            or not MIN_RESULT_TAIL_BYTES <= tail_region_bytes <= MAX_RESULT_TAIL_BYTES
            or tail_region_bytes % ALIGNMENT
            or tail_region_bytes + HEADER_BYTES > scratch_size
        ):
            raise BundleError("scratch or tail-region size is outside aligned bounds")
        descriptor, identity = _open_exact(path, size=scratch_size, mode=0o600)
        header_offset = scratch_size - HEADER_BYTES
        payload_start = scratch_size - tail_region_bytes
        payload_end = header_offset
        magic = RESULT_MAGIC
        allowed_types = RESULT_SECTION_TYPES
        required_types = REQUIRED_RESULT_SECTION_TYPES
        caps = {**RESULT_JSON_CAPS, **RESULT_RAW_CAPS}
        expected_sha256 = parsed.sha256
        expected_reference = parsed.raw_sections.get(section_type)
    else:
        raise BundleError("raw section reader requires a parsed LFRQ or LFRS record")
    if expected_reference is None:
        os.close(descriptor)
        raise BundleError("requested raw patch is absent")
    try:
        header = _pread_exact(descriptor, HEADER_BYTES, header_offset)
        records, payload_digest, _marker_value = _parse_header(
            header,
            magic=magic,
            total_size=size if isinstance(parsed, ParsedBundle) else scratch_size,
            expected=parsed.binding,
            allowed_types=allowed_types,
            required_types=required_types,
            caps=caps,
            payload_start=payload_start,
            payload_end=payload_end,
            require_marker=isinstance(parsed, TailResult),
        )
        if (
            _hash_range(
                descriptor,
                payload_start,
                payload_end,
                require_zero_gaps=_gaps(payload_start, payload_end, records),
            )
            != payload_digest
        ):
            raise BundleError("record whole-payload SHA-256 does not match")
        actual = _record_for(records, section_type)
        observed_reference = SectionReference(actual[0], actual[1], actual[2], actual[3].hex())
        if observed_reference != expected_reference:
            raise BundleError("raw patch reference does not match the parsed record")
        if actual[2] > caps[section_type]:
            raise BundleError("raw patch exceeds its byte cap")
        raw = _read_bounded_raw_section(descriptor, actual[1], actual[2])
        if hashlib.sha256(raw).digest() != actual[3]:
            raise BundleError("raw patch section hash does not match")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError("raw patch is not valid UTF-8") from exc
        whole_start = 0 if isinstance(parsed, ParsedBundle) else payload_start
        whole_end = size if isinstance(parsed, ParsedBundle) else scratch_size
        if _hash_plain_range(descriptor, whole_start, whole_end).hex() != expected_sha256:
            raise BundleError("record identity does not match the parsed whole-record SHA-256")
        _verify_identity(descriptor, identity)
        return raw
    finally:
        os.close(descriptor)


def build_tail_result(
    path: Path,
    *,
    scratch_size: int,
    tail_region_bytes: int,
    run_id: str,
    round: int,
    stage: str,
    sections: Mapping[str, Any],
) -> TailResult:
    """Guest/test helper that writes an LFRS footer last into a new 0600 scratch file."""

    binding = _validate_binding(run_id, round, stage)
    if (
        type(scratch_size) is not int
        or not MIN_SCRATCH_BYTES <= scratch_size <= MAX_SCRATCH_BYTES
        or scratch_size % ALIGNMENT
        or type(tail_region_bytes) is not int
        or not MIN_RESULT_TAIL_BYTES <= tail_region_bytes <= MAX_RESULT_TAIL_BYTES
        or tail_region_bytes % ALIGNMENT
        or tail_region_bytes + HEADER_BYTES > scratch_size
    ):
        raise BundleError("scratch or tail-region size is outside aligned bounds")
    if not isinstance(sections, Mapping) or set(sections) != REQUIRED_RESULT_SECTION_TYPES:
        raise BundleError("result sections must be exactly the required strict set")
    prepared: list[tuple[str, bytes]] = []
    for section_type in sorted(sections):
        if section_type in RESULT_JSON_CAPS:
            raw = _canonical_json(sections[section_type], RESULT_JSON_CAPS[section_type])
        else:
            raw = _canonical_patch(
                sections[section_type], allow_empty=binding.stage != "implementation"
            )
            if binding.stage != "implementation" and raw:
                raise BundleError("read-only stages may not return a model patch")
        prepared.append((section_type, raw))
    footer_offset = scratch_size - HEADER_BYTES
    region_start = scratch_size - tail_region_bytes
    cursor = region_start
    records: list[tuple[str, int, int, bytes]] = []
    for section_type, raw in prepared:
        cursor = _align(cursor)
        if cursor + len(raw) > footer_offset:
            raise BundleError("tail result sections exceed their reserved region")
        records.append((section_type, cursor, len(raw), hashlib.sha256(raw).digest()))
        cursor += len(raw)
    _safe_parent(path)
    succeeded = False
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise BundleError("scratch output cannot be created safely") from exc
    try:
        os.ftruncate(descriptor, scratch_size)
        for (_, offset, _length, _digest), (_, raw) in zip(records, prepared, strict=True):
            _write_all(descriptor, raw, offset)
        payload_digest = _hash_range(
            descriptor,
            region_start,
            footer_offset,
            require_zero_gaps=_gaps(region_start, footer_offset, records),
        )
        marker = _marker(RESULT_MAGIC, binding, scratch_size, payload_digest, records)
        footer = _pack_header(RESULT_MAGIC, binding, scratch_size, payload_digest, records, marker)
        _write_all(descriptor, footer, footer_offset)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        succeeded = True
    finally:
        os.close(descriptor)
        if not succeeded:
            with suppress(OSError):
                path.unlink()
    return extract_tail_result(
        path,
        scratch_size=scratch_size,
        tail_region_bytes=tail_region_bytes,
        run_id=run_id,
        round=round,
        stage=stage,
    )


def extract_tail_result(
    path: Path,
    *,
    scratch_size: int,
    tail_region_bytes: int,
    run_id: str,
    round: int,
    stage: str,
) -> TailResult:
    """Parse a bounded LFRS tail with no mount, no extraction, and no execution."""

    binding = _validate_binding(run_id, round, stage)
    if (
        type(scratch_size) is not int
        or not MIN_SCRATCH_BYTES <= scratch_size <= MAX_SCRATCH_BYTES
        or scratch_size % ALIGNMENT
        or type(tail_region_bytes) is not int
        or not MIN_RESULT_TAIL_BYTES <= tail_region_bytes <= MAX_RESULT_TAIL_BYTES
        or tail_region_bytes % ALIGNMENT
        or tail_region_bytes + HEADER_BYTES > scratch_size
    ):
        raise BundleError("scratch or tail-region size is outside aligned bounds")
    descriptor, identity = _open_exact(path, size=scratch_size, mode=0o600)
    try:
        footer_offset = scratch_size - HEADER_BYTES
        region_start = scratch_size - tail_region_bytes
        footer = _pread_exact(descriptor, HEADER_BYTES, footer_offset)
        records, payload_digest, marker = _parse_header(
            footer,
            magic=RESULT_MAGIC,
            total_size=scratch_size,
            expected=binding,
            allowed_types=RESULT_SECTION_TYPES,
            required_types=REQUIRED_RESULT_SECTION_TYPES,
            caps={**RESULT_JSON_CAPS, **RESULT_RAW_CAPS},
            payload_start=region_start,
            payload_end=footer_offset,
            require_marker=True,
        )
        if (
            _hash_range(
                descriptor,
                region_start,
                footer_offset,
                require_zero_gaps=_gaps(region_start, footer_offset, records),
            )
            != payload_digest
        ):
            raise BundleError("tail whole-region SHA-256 does not match")
        sections: dict[str, Any] = {}
        raw_sections: dict[str, SectionReference] = {}
        for section_type, offset, length, digest in records:
            if _stream_section_hash(descriptor, offset, length) != digest:
                raise BundleError("tail section hash does not match")
            if section_type in RESULT_JSON_CAPS:
                sections[section_type] = _read_json_section(
                    descriptor, offset, length, RESULT_JSON_CAPS[section_type]
                )
            else:
                _validate_utf8_section(descriptor, offset, length)
                if binding.stage != "implementation" and length:
                    raise BundleError("read-only stages may not return a model patch")
                raw_sections[section_type] = SectionReference(
                    section_type, offset, length, digest.hex()
                )
        whole_tail_sha256 = _hash_plain_range(descriptor, region_start, scratch_size).hex()
        _verify_identity(descriptor, identity)
    finally:
        os.close(descriptor)
    return TailResult(
        binding,
        sections,
        raw_sections,
        marker.hex(),
        whole_tail_sha256,
    )


def _result_exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise BundleError(f"guest result {label} fields are not exact")
    return value


def _result_text(value: Any, *, maximum: int, label: str, allow_empty: bool = True) -> str:
    if type(value) is not str:
        raise BundleError(f"guest result {label} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BundleError(f"guest result {label} is not valid Unicode") from exc
    if (not allow_empty and not encoded) or len(encoded) > maximum or "\0" in value:
        raise BundleError(f"guest result {label} is outside its byte bounds")
    return value


def _result_digest(value: Any, label: str, *, allow_none: bool) -> str | None:
    if value is None and allow_none:
        return None
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BundleError(f"guest result {label} is not a SHA-256 digest")
    return value


def _result_boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise BundleError(f"guest result {label} must be boolean")
    return value


def _result_integer(value: Any, *, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise BundleError(f"guest result {label} is outside its integer bounds")
    return value


def _validated_guest_receipt(
    value: Any,
    *,
    binding: BundleBinding,
    request_sha256: str,
    guest_policy_sha256: str,
) -> None:
    receipt = _result_exact_object(
        value,
        {
            "schema_version",
            "run_id",
            "round",
            "stage",
            "request_sha256",
            "guest_policy_sha256",
            "isolation",
        },
        "guest_receipt",
    )
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["run_id"] != binding.run_id
        or type(receipt["round"]) is not int
        or receipt["round"] != binding.round
        or receipt["stage"] != binding.stage
        or receipt["request_sha256"] != request_sha256
        or receipt["guest_policy_sha256"] != guest_policy_sha256
    ):
        raise BundleError("guest result guest_receipt does not bind this epoch")
    isolation = _result_exact_object(
        receipt["isolation"], set(_GUEST_ISOLATION_EVIDENCE), "guest_receipt.isolation"
    )
    for key, expected in _GUEST_ISOLATION_EVIDENCE.items():
        if type(isolation[key]) is not type(expected) or isolation[key] != expected:
            raise BundleError("guest result isolation evidence is not the fixed strict profile")


def _validated_observations(
    value: Any,
    *,
    expected_action_ids: tuple[str, ...],
    maximum_bytes: int,
) -> tuple[GuestObservation, ...]:
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= RESULT_JSON_CAPS["observations"]:
        raise BundleError("guest observation byte cap is invalid")
    # This binds the configured cap to the exact canonical bytes received from
    # the guest, rather than trusting a guest-supplied length field.
    try:
        _canonical_json(value, maximum_bytes)
    except BundleError as exc:
        raise BundleError("guest result exceeds the configured observation byte cap") from exc
    if type(value) is not list or len(value) != len(expected_action_ids):
        raise BundleError("guest result observations do not match expected action count")
    observations: list[GuestObservation] = []
    for index, item in enumerate(value):
        observation = _result_exact_object(
            item, {"action_id", "status", "truncated", "tail"}, "observation"
        )
        action_id = observation["action_id"]
        if type(action_id) is not str or action_id != expected_action_ids[index]:
            raise BundleError("guest result observation action IDs are not exact")
        status = observation["status"]
        if type(status) is not str or status not in _OBSERVATION_STATUS:
            raise BundleError("guest result observation status is invalid")
        truncated = _result_boolean(observation["truncated"], "observation.truncated")
        tail = _result_text(
            observation["tail"], maximum=_MAX_RESULT_TAIL_TEXT_BYTES, label="observation.tail"
        )
        observations.append(GuestObservation(action_id, status, truncated, tail))
    if len({item.action_id for item in observations}) != len(observations):
        raise BundleError("guest result observation action IDs are duplicated")
    return tuple(observations)


def _validated_checks(value: Any, *, expected_check_ids: tuple[str, ...]) -> tuple[GuestCheck, ...]:
    if type(value) is not list or len(value) != len(expected_check_ids):
        raise BundleError("guest result checks do not match expected curated checks")
    checks: list[GuestCheck] = []
    for index, item in enumerate(value):
        check = _result_exact_object(
            item, {"check_id", "exit", "timed_out", "truncated", "tail"}, "check"
        )
        check_id = check["check_id"]
        if type(check_id) is not str or check_id != expected_check_ids[index]:
            raise BundleError("guest result check IDs are not exact")
        timed_out = _result_boolean(check["timed_out"], "check.timed_out")
        exit_value = check["exit"]
        if timed_out:
            if exit_value is not None:
                raise BundleError("timed-out guest check must not report an exit code")
            exit_code = None
        else:
            exit_code = _result_integer(exit_value, minimum=-255, maximum=255, label="check.exit")
        truncated = _result_boolean(check["truncated"], "check.truncated")
        tail = _result_text(check["tail"], maximum=_MAX_RESULT_TAIL_TEXT_BYTES, label="check.tail")
        checks.append(GuestCheck(check_id, exit_code, timed_out, truncated, tail))
    if len({item.check_id for item in checks}) != len(checks):
        raise BundleError("guest result check IDs are duplicated")
    return tuple(checks)


def validate_guest_result(
    result: TailResult,
    request: ParsedBundle,
    *,
    guest_policy_sha256: str,
    max_observation_bytes: int,
) -> VerifiedGuestResult:
    """Bind a stopped guest's LFRS record to its sealed mediated request.

    This is deliberately a semantic validator, separate from the LFRS parser.
    The parser establishes byte-level integrity; this function establishes that
    every claim refers to controller-selected actions, checks, policy, request,
    and patch genesis.  It never reads, mounts, or executes guest data.
    """

    if not isinstance(result, TailResult) or not isinstance(request, ParsedBundle):
        raise BundleError("guest result validator requires parsed sealed records")
    _validate_request_stage_sections(
        request.binding,
        request.sections,
        request.raw_sections,
        fixture_authorization=request.fixture_authorization,
    )
    if result.binding != request.binding:
        raise BundleError("guest result and request bindings do not match")
    if type(guest_policy_sha256) is not str or _SHA256.fullmatch(guest_policy_sha256) is None:
        raise BundleError("guest policy digest is invalid")
    manifest = request.sections.get("manifest")
    if type(manifest) is not dict or manifest.get("guest_policy_sha256") != guest_policy_sha256:
        raise BundleError("sealed request does not bind the guest policy digest")
    action_batch = _validate_action_document(
        request.binding, request.sections, request.raw_sections
    )
    finish_actions = [action for action in action_batch.actions if isinstance(action, FinishAction)]
    if len(finish_actions) != 1:  # Defensive: the mediator grammar already enforces this.
        raise BundleError("sealed action batch does not have one final finish action")
    expected_status = finish_actions[0].status
    action_ids = tuple(action.action_id for action in action_batch.actions)
    observation_ids = action_ids
    expected_checks = tuple(
        action.check_id for action in action_batch.actions if isinstance(action, RunCheckAction)
    )
    proposed = request.raw_sections.get("proposed_patch")
    previous_cumulative = request.raw_sections.get("cumulative_patch")
    patch = result.raw_sections.get("canonical_patch")
    if patch is None:
        raise BundleError("guest result omits canonical_patch")
    canonical_patch_sha256 = patch.sha256 if patch.length else None

    _validated_guest_receipt(
        result.sections.get("guest_receipt"),
        binding=result.binding,
        request_sha256=request.sha256,
        guest_policy_sha256=guest_policy_sha256,
    )
    observations = _validated_observations(
        result.sections.get("observations"),
        expected_action_ids=observation_ids,
        maximum_bytes=max_observation_bytes,
    )
    checks = _validated_checks(result.sections.get("checks"), expected_check_ids=expected_checks)
    stage_result = _result_exact_object(
        result.sections.get("stage_result"),
        {"status", "summary", "action_ids", "cumulative_patch_sha256"},
        "stage_result",
    )
    status = stage_result["status"]
    if type(status) is not str or status not in _RESULT_STATUS or status != expected_status:
        raise BundleError("guest result status does not match the mediated finish action")
    summary = _result_text(
        stage_result["summary"],
        maximum=_MAX_RESULT_SUMMARY_BYTES,
        label="stage_result.summary",
        allow_empty=False,
    )
    action_id_value = stage_result["action_ids"]
    if (
        type(action_id_value) is not list
        or tuple(action_id_value) != action_ids
        or any(type(item) is not str for item in action_id_value)
    ):
        raise BundleError("guest result stage_result action IDs are not exact")
    cumulative_patch_sha256 = _result_digest(
        stage_result["cumulative_patch_sha256"],
        "stage_result.cumulative_patch_sha256",
        allow_none=True,
    )

    if result.binding.stage == "implementation":
        if status == "complete":
            if (
                proposed is None
                or canonical_patch_sha256 is None
                or canonical_patch_sha256 != proposed.sha256
            ):
                raise BundleError(
                    "successful implementation requires one matching proposed/canonical patch"
                )
            expected_cumulative = canonical_patch_sha256
        else:
            if canonical_patch_sha256 is not None:
                raise BundleError(
                    "blocked or failed implementation must return an empty canonical patch"
                )
            expected_cumulative = (
                None if previous_cumulative is None else previous_cumulative.sha256
            )
    else:
        if canonical_patch_sha256 is not None:
            raise BundleError("planning, review, and final verification may not return a patch")
        expected_cumulative = None if previous_cumulative is None else previous_cumulative.sha256
    if cumulative_patch_sha256 != expected_cumulative:
        raise BundleError("guest result cumulative patch digest does not match the stage contract")
    if status == "complete" and any(item.status != "complete" for item in observations):
        raise BundleError("successful stage contains a non-complete action observation")
    if (
        result.binding.stage == "final_verify"
        and status == "complete"
        and any(item.exit_code != 0 or item.timed_out or item.truncated for item in checks)
    ):
        raise BundleError("successful final verification requires every curated check to succeed")
    return VerifiedGuestResult(
        run_id=result.binding.run_id,
        round=result.binding.round,
        stage=result.binding.stage,
        request_sha256=request.sha256,
        guest_policy_sha256=guest_policy_sha256,
        status=status,
        summary=summary,
        action_ids=action_ids,
        observations=observations,
        checks=checks,
        canonical_patch_sha256=canonical_patch_sha256,
        cumulative_patch_sha256=cumulative_patch_sha256,
    )
