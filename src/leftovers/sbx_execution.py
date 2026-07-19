"""Pure contract for a future Docker Sandboxes Codex execution boundary.

This module deliberately contains no filesystem, subprocess, network, Docker,
Git, credential, or clock access.  It models the minimum evidence a future
privileged ``sbx`` adapter would have to provide before Leftovers could even
describe a Codex invocation.  Production remains source-disabled before any
argument is inspected.

The fixture API is intentionally explicit and non-authoritative.  It permits
canonical-schema and binding tests without creating a sandbox or teaching the
controller a generic command, environment, template, kit, profile, port, or
extra-workspace surface.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from .sbx import controller_sandbox_name

SBX_EXECUTION_ENABLED: Final = False
"""Release gate; configuration and environment variables cannot change it."""

INSPECTION_SCHEMA_VERSION: Final = 1
SBX_BINARY: Final = "/opt/homebrew/Caskroom/sbx/0.35.0/bin/sbx"
SBX_VERSION: Final = "v0.35.0"
SBX_REVISION: Final = "01e01520456e4126a9653471e7072e4d9b280321"
SBX_SHA256: Final = "b046dce135756ee14a72e88165c90b07d10e2d48b86cd089adee5acc2abf2d01"
AGENT: Final = "codex"
MODEL: Final = "gpt-5.6-terra"
REASONING_EFFORT: Final = "high"
SBX_EXEC_ID_TARGETING_DOCUMENTED: Final = False
SBX_EXEC_NAME_BINDING_ATOMIC: Final = False
SBX_V035_IN_VM_RUNTIME_ATTESTATION_DOCUMENTED: Final = False
"""Official v0.35 evidence does not expose the in-VM facts modeled below."""

CPU_CAP: Final = 2
MEMORY_CAP_BYTES: Final = 4 * 1024 * 1024 * 1024
CREATE_TIMEOUT_SECONDS: Final = 5 * 60
CLEANUP_TIMEOUT_SECONDS: Final = 2 * 60
LIFECYCLE_TIMEOUT_SECONDS: Final = 45 * 60
MAX_INSPECTION_BYTES: Final = 16 * 1024
MAX_DAEMON_GENERATION: Final = (1 << 63) - 1
CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE: Final = 4_096
"""Local reserve charged before one conservative token unit per UTF-8 input byte."""
TOKEN_CAPS_PROVIDER_ENFORCED: Final = False
"""The provider is not assumed to stop a call when a local token cap is reached."""
TOKEN_CAPS_REQUIRE_POST_CALL_RECEIPT: Final = True
"""A future adapter must reject usage receipts that exceed the admitted caps."""

POLICY_MODE: Final = "locked-down-openai-only"
CLONE_MODE: Final = "private-clone"
SOURCE_MOUNT_MODE: Final = "read-only"
WORKSPACE_MODE: Final = "private-read-write"
OPENAI_CAPABILITY_NAME: Final = "openai"
OPENAI_CAPABILITY_SCOPE: Final = "global"
OPENAI_CAPABILITY_TYPE: Final = "service"
AUTH_MODE: Final = "proxy-managed-openai-only"
MAX_CODEX_EXECUTABLE_BYTES: Final = 512 * 1024 * 1024

_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_SANDBOX_NAME = re.compile(r"leftovers-[a-f0-9]{24}\Z")
_UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\Z")
_CODEX_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?\Z")
_USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


class SbxExecutionError(RuntimeError):
    """The future execution contract is malformed or lacks authority."""


class SbxExecutionDisabled(SbxExecutionError):
    """The source-level release gate rejected a production entry."""


class ExecutionStage(StrEnum):
    PLANNING = "planning"
    IMPLEMENTATION = "implementation"
    VERIFICATION = "verification"


@dataclass(frozen=True, slots=True)
class StageLimits:
    """One immutable, controller-owned model-call envelope.

    Token values are conservative local admission limits and bounds checked
    against a separately validated post-call usage receipt.  They are not a
    provider-enforced hard stop and cannot prevent provider-side overrun.
    """

    stage: ExecutionStage
    call_index: int
    timeout_seconds: int
    input_token_cap: int
    output_token_cap: int
    total_token_cap: int
    combined_output_bytes: int


STAGE_LIMITS: Final = (
    StageLimits(ExecutionStage.PLANNING, 0, 6 * 60, 8_000, 2_000, 10_000, 32 * 1024),
    StageLimits(
        ExecutionStage.IMPLEMENTATION,
        1,
        20 * 60,
        25_000,
        10_000,
        35_000,
        64 * 1024,
    ),
    StageLimits(ExecutionStage.VERIFICATION, 2, 8 * 60, 8_000, 2_000, 10_000, 32 * 1024),
)
RUN_TOKEN_CAP: Final = sum(item.total_token_cap for item in STAGE_LIMITS)
MAX_MODEL_CALLS: Final = len(STAGE_LIMITS)
_LIMIT_BY_STAGE: Final = {item.stage: item for item in STAGE_LIMITS}
MAX_STDIN_BYTES: Final = (
    max(item.input_token_cap for item in STAGE_LIMITS)
    - CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE
)


@dataclass(frozen=True, slots=True)
class SbxCliIdentity:
    binary: str = SBX_BINARY
    version: str = SBX_VERSION
    revision: str = SBX_REVISION
    sha256: str = SBX_SHA256

    def __post_init__(self) -> None:
        if (
            type(self.binary) is not str
            or self.binary != SBX_BINARY
            or type(self.version) is not str
            or self.version != SBX_VERSION
            or type(self.revision) is not str
            or self.revision != SBX_REVISION
            or type(self.sha256) is not str
            or self.sha256 != SBX_SHA256
        ):
            raise SbxExecutionError("sbx CLI identity is not the exact pinned release")


PINNED_SBX_IDENTITY: Final = SbxCliIdentity()


def _sandbox_name(run_id: str) -> str:
    if type(run_id) is not str or _HEX32.fullmatch(run_id) is None:
        raise SbxExecutionError("controller run ID is invalid")
    return controller_sandbox_name(run_id)


@dataclass(frozen=True, slots=True)
class ControllerSandboxIdentity:
    """A name deterministically derived from one controller-generated run ID."""

    run_id: str
    name: str

    def __post_init__(self) -> None:
        expected = _sandbox_name(self.run_id)
        if type(self.name) is not str or self.name != expected:
            raise SbxExecutionError("sandbox name is not controller-derived")


def derive_controller_sandbox_identity(run_id: str) -> ControllerSandboxIdentity:
    """Create the only accepted controller-side sandbox identity."""

    return ControllerSandboxIdentity(run_id, _sandbox_name(run_id))


def _absolute_guest_path(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or value == "/"
        or len(value.encode("utf-8")) > 512
        or "\0" in value
        or "\n" in value
        or "\r" in value
        or posixpath.normpath(value) != value
    ):
        raise SbxExecutionError(f"{label} is not a canonical absolute in-VM path")
    return value


def _paths_overlap(first: str, second: str) -> bool:
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _descriptor_integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= (1 << 63) - 1:
        raise SbxExecutionError(f"in-VM Codex executable {label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class InVmRuntimeExpectation:
    """Future-adapter requirements, never current Docker v0.35 evidence.

    The executable facts must eventually come from one stable descriptor (and
    be revalidated across launch), while identity, groups, capabilities,
    ``CODEX_HOME``, authentication, and extension-loading facts must come from
    a separately reviewed in-guest adapter.  Official v0.35 inspection does
    not expose any of that evidence.
    """

    codex_executable_path: str
    codex_executable_sha256: str
    codex_version: str
    codex_executable_device: int
    codex_executable_inode: int
    codex_executable_owner_uid: int
    codex_executable_owner_gid: int
    codex_executable_mode: int
    codex_executable_link_count: int
    codex_executable_size_bytes: int
    codex_executable_mtime_ns: int
    codex_executable_ctime_ns: int
    user_name: str
    user_uid: int
    user_gid: int
    supplemental_gids: tuple[int, ...]
    linux_capabilities: tuple[str, ...]
    private_clone_workdir: str
    codex_home: str
    auth_mode: str
    user_config_loaded: bool
    repository_rules_loaded: bool
    hooks_loaded: bool

    def __post_init__(self) -> None:
        executable = _absolute_guest_path(self.codex_executable_path, "Codex executable")
        workdir = _absolute_guest_path(self.private_clone_workdir, "private clone workdir")
        codex_home = _absolute_guest_path(self.codex_home, "CODEX_HOME")
        if _paths_overlap(executable, workdir):
            raise SbxExecutionError("Codex executable must be outside the private clone")
        if _paths_overlap(codex_home, workdir):
            raise SbxExecutionError("CODEX_HOME must be outside the private clone")
        if (
            type(self.codex_executable_sha256) is not str
            or _HEX64.fullmatch(self.codex_executable_sha256) is None
        ):
            raise SbxExecutionError("in-VM Codex executable digest is invalid")
        if (
            type(self.codex_version) is not str
            or _CODEX_VERSION.fullmatch(self.codex_version) is None
        ):
            raise SbxExecutionError("in-VM Codex version is invalid")
        _descriptor_integer(self.codex_executable_device, "device", minimum=1)
        _descriptor_integer(self.codex_executable_inode, "inode", minimum=1)
        if self.codex_executable_owner_uid != 0 or type(self.codex_executable_owner_uid) is not int:
            raise SbxExecutionError("in-VM Codex executable owner UID must be root")
        if self.codex_executable_owner_gid != 0 or type(self.codex_executable_owner_gid) is not int:
            raise SbxExecutionError("in-VM Codex executable owner GID must be root")
        mode = _descriptor_integer(self.codex_executable_mode, "mode")
        if mode & 0o170000 != 0o100000 or mode & 0o111 == 0 or mode & 0o022 or mode & 0o7000:
            raise SbxExecutionError(
                "in-VM Codex executable must be a non-writable, non-special executable regular file"
            )
        if (
            type(self.codex_executable_link_count) is not int
            or self.codex_executable_link_count != 1
        ):
            raise SbxExecutionError("in-VM Codex executable link count must be one")
        size = _descriptor_integer(self.codex_executable_size_bytes, "size", minimum=1)
        if size > MAX_CODEX_EXECUTABLE_BYTES:
            raise SbxExecutionError("in-VM Codex executable is oversized")
        _descriptor_integer(self.codex_executable_mtime_ns, "mtime")
        _descriptor_integer(self.codex_executable_ctime_ns, "ctime")
        if (
            type(self.user_name) is not str
            or _USER_NAME.fullmatch(self.user_name) is None
            or self.user_name == "root"
        ):
            raise SbxExecutionError("in-VM execution user is invalid or privileged")
        if type(self.user_uid) is not int or not 1 <= self.user_uid <= 2**31 - 1:
            raise SbxExecutionError("in-VM execution UID is invalid or privileged")
        if type(self.user_gid) is not int or not 1 <= self.user_gid <= 2**31 - 1:
            raise SbxExecutionError("in-VM execution GID is invalid or privileged")
        if type(self.supplemental_gids) is not tuple or self.supplemental_gids:
            raise SbxExecutionError("in-VM supplemental groups must be exactly empty")
        if type(self.linux_capabilities) is not tuple or self.linux_capabilities:
            raise SbxExecutionError("in-VM Linux capability set must be exactly empty")
        if not workdir.startswith(f"/home/{self.user_name}/"):
            raise SbxExecutionError("private clone workdir is not owned by the execution user")
        if codex_home != f"/home/{self.user_name}/.codex":
            raise SbxExecutionError("CODEX_HOME is not the exact execution-user path")
        if type(self.auth_mode) is not str or self.auth_mode != AUTH_MODE:
            raise SbxExecutionError("in-VM authentication mode is not proxy-managed OpenAI only")
        for value, label in (
            (self.user_config_loaded, "user config"),
            (self.repository_rules_loaded, "repository rules"),
            (self.hooks_loaded, "hooks"),
        ):
            if type(value) is not bool or value:
                raise SbxExecutionError(f"in-VM {label} must be exactly disabled")


def _validate_runtime_expectation(value: object) -> InVmRuntimeExpectation:
    if type(value) is not InVmRuntimeExpectation:
        raise SbxExecutionError("inspection runtime expectation is invalid")
    return InVmRuntimeExpectation(
        codex_executable_path=value.codex_executable_path,
        codex_executable_sha256=value.codex_executable_sha256,
        codex_version=value.codex_version,
        codex_executable_device=value.codex_executable_device,
        codex_executable_inode=value.codex_executable_inode,
        codex_executable_owner_uid=value.codex_executable_owner_uid,
        codex_executable_owner_gid=value.codex_executable_owner_gid,
        codex_executable_mode=value.codex_executable_mode,
        codex_executable_link_count=value.codex_executable_link_count,
        codex_executable_size_bytes=value.codex_executable_size_bytes,
        codex_executable_mtime_ns=value.codex_executable_mtime_ns,
        codex_executable_ctime_ns=value.codex_executable_ctime_ns,
        user_name=value.user_name,
        user_uid=value.user_uid,
        user_gid=value.user_gid,
        supplemental_gids=value.supplemental_gids,
        linux_capabilities=value.linux_capabilities,
        private_clone_workdir=value.private_clone_workdir,
        codex_home=value.codex_home,
        auth_mode=value.auth_mode,
        user_config_loaded=value.user_config_loaded,
        repository_rules_loaded=value.repository_rules_loaded,
        hooks_loaded=value.hooks_loaded,
    )


@dataclass(frozen=True, slots=True)
class InspectionExpectation:
    """Controller bindings the daemon inspection must repeat exactly."""

    controller: ControllerSandboxIdentity
    runtime: InVmRuntimeExpectation
    policy_epoch_sha256: str
    secret_epoch_sha256: str

    def __post_init__(self) -> None:
        if type(self.controller) is not ControllerSandboxIdentity:
            raise SbxExecutionError("inspection controller identity is invalid")
        if self.controller.name != _sandbox_name(self.controller.run_id):
            raise SbxExecutionError("inspection controller identity is not derived")
        _validate_runtime_expectation(self.runtime)
        if (
            type(self.policy_epoch_sha256) is not str
            or _HEX64.fullmatch(self.policy_epoch_sha256) is None
        ):
            raise SbxExecutionError("policy epoch digest is invalid")
        if (
            type(self.secret_epoch_sha256) is not str
            or _HEX64.fullmatch(self.secret_epoch_sha256) is None
        ):
            raise SbxExecutionError("secret epoch digest is invalid")
        if self.policy_epoch_sha256 == self.secret_epoch_sha256:
            raise SbxExecutionError("policy and secret epochs must be domain-separated")


_FIXTURE_CAPABILITY_SECRET = object()
_FIXTURE_ATTESTATION_SEAL = object()


class FixtureSbxExecutionCapability:
    """Explicit authority for pure, non-production contract tests only."""

    __slots__ = ("_secret",)

    def __init__(self, secret: object) -> None:
        if secret is not _FIXTURE_CAPABILITY_SECRET:
            raise SbxExecutionError("fixture sbx execution capability is not constructible")
        self._secret = secret


_FIXTURE_CAPABILITY = FixtureSbxExecutionCapability(_FIXTURE_CAPABILITY_SECRET)


def fixture_sbx_execution_capability() -> FixtureSbxExecutionCapability:
    """Return the singleton fixture capability; it cannot open the source gate."""

    return _FIXTURE_CAPABILITY


def _require_fixture_capability(capability: object) -> None:
    if (
        type(capability) is not FixtureSbxExecutionCapability
        or capability is not _FIXTURE_CAPABILITY
        or capability._secret is not _FIXTURE_CAPABILITY_SECRET
    ):
        raise SbxExecutionError("fixture sbx execution capability is invalid")


@dataclass(frozen=True, slots=True, init=False)
class DaemonSandboxIdentity:
    """Opaque identity sealed by an inspection adapter, never by a caller."""

    opaque_uuid: str
    generation: int
    controller_name: str
    _seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        opaque_uuid: str,
        generation: int,
        controller_name: str,
        seal: object,
    ) -> None:
        if seal is not _FIXTURE_ATTESTATION_SEAL:
            raise SbxExecutionError("daemon sandbox identity requires adapter authority")
        _validate_daemon_identity_values(opaque_uuid, generation, controller_name)
        object.__setattr__(self, "opaque_uuid", opaque_uuid)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "controller_name", controller_name)
        object.__setattr__(self, "_seal", seal)


@dataclass(frozen=True, slots=True, init=False)
class SbxInspectionAttestation:
    """Canonical daemon observation sealed by the fixture inspection adapter."""

    controller: ControllerSandboxIdentity
    daemon: DaemonSandboxIdentity
    runtime: InVmRuntimeExpectation
    policy_epoch_sha256: str
    secret_epoch_sha256: str
    canonical_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        controller: ControllerSandboxIdentity,
        daemon: DaemonSandboxIdentity,
        runtime: InVmRuntimeExpectation,
        policy_epoch_sha256: str,
        secret_epoch_sha256: str,
        canonical_sha256: str,
        seal: object,
    ) -> None:
        if seal is not _FIXTURE_ATTESTATION_SEAL:
            raise SbxExecutionError("sandbox inspection requires adapter authority")
        object.__setattr__(self, "controller", controller)
        object.__setattr__(self, "daemon", daemon)
        object.__setattr__(self, "runtime", runtime)
        object.__setattr__(self, "policy_epoch_sha256", policy_epoch_sha256)
        object.__setattr__(self, "secret_epoch_sha256", secret_epoch_sha256)
        object.__setattr__(self, "canonical_sha256", canonical_sha256)
        object.__setattr__(self, "_seal", seal)
        _validate_attestation(self)


def _validate_daemon_identity_values(
    opaque_uuid: object, generation: object, controller_name: object
) -> None:
    if type(opaque_uuid) is not str or _UUID.fullmatch(opaque_uuid) is None:
        raise SbxExecutionError("daemon sandbox UUID is not canonical and opaque")
    if opaque_uuid == "00000000-0000-0000-0000-000000000000":
        raise SbxExecutionError("daemon sandbox UUID must not be nil")
    if type(generation) is not int or not 1 <= generation <= MAX_DAEMON_GENERATION:
        raise SbxExecutionError("daemon sandbox generation is invalid")
    if type(controller_name) is not str or _SANDBOX_NAME.fullmatch(controller_name) is None:
        raise SbxExecutionError("daemon controller name is invalid")


def _validate_attestation(attestation: object) -> SbxInspectionAttestation:
    if type(attestation) is not SbxInspectionAttestation:
        raise SbxExecutionError("sandbox inspection attestation has an invalid type")
    try:
        seal = attestation._seal
        daemon_seal = attestation.daemon._seal
    except AttributeError as exc:
        raise SbxExecutionError("sandbox inspection attestation is unsealed") from exc
    if seal is not _FIXTURE_ATTESTATION_SEAL or daemon_seal is not _FIXTURE_ATTESTATION_SEAL:
        raise SbxExecutionError("sandbox inspection attestation is unsealed")
    if type(attestation.controller) is not ControllerSandboxIdentity:
        raise SbxExecutionError("sandbox inspection controller identity is invalid")
    runtime = _validate_runtime_expectation(attestation.runtime)
    expected_name = _sandbox_name(attestation.controller.run_id)
    if (
        attestation.controller.name != expected_name
        or attestation.daemon.controller_name != expected_name
    ):
        raise SbxExecutionError("daemon identity does not bind the controller sandbox")
    _validate_daemon_identity_values(
        attestation.daemon.opaque_uuid,
        attestation.daemon.generation,
        attestation.daemon.controller_name,
    )
    if (
        type(attestation.policy_epoch_sha256) is not str
        or _HEX64.fullmatch(attestation.policy_epoch_sha256) is None
    ):
        raise SbxExecutionError("attested policy epoch is invalid")
    if (
        type(attestation.secret_epoch_sha256) is not str
        or _HEX64.fullmatch(attestation.secret_epoch_sha256) is None
    ):
        raise SbxExecutionError("attested secret epoch is invalid")
    if attestation.policy_epoch_sha256 == attestation.secret_epoch_sha256:
        raise SbxExecutionError("attested epochs are not domain-separated")
    if (
        type(attestation.canonical_sha256) is not str
        or _HEX64.fullmatch(attestation.canonical_sha256) is None
    ):
        raise SbxExecutionError("inspection canonical digest is invalid")
    expected_raw = _inspection_document(
        InspectionExpectation(
            attestation.controller,
            runtime,
            attestation.policy_epoch_sha256,
            attestation.secret_epoch_sha256,
        ),
        daemon_uuid=attestation.daemon.opaque_uuid,
        generation=attestation.daemon.generation,
    )
    if hashlib.sha256(expected_raw).hexdigest() != attestation.canonical_sha256:
        raise SbxExecutionError("inspection fields do not bind the canonical daemon document")
    return attestation


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise SbxExecutionError("inspection is not representable as canonical JSON") from exc


def _parse_canonical_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INSPECTION_BYTES:
        raise SbxExecutionError("inspection bytes are empty, mutable, or oversized")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SbxExecutionError("inspection contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_float(_value: str) -> object:
        raise SbxExecutionError("inspection JSON floats are forbidden")

    def reject_constant(_value: str) -> object:
        raise SbxExecutionError("inspection JSON constants are forbidden")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SbxExecutionError("inspection is not canonical JSON") from exc
    if type(value) is not dict or _canonical_json(value) != raw:
        raise SbxExecutionError("inspection is not canonical JSON")
    return value


def _exact_object(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        raise SbxExecutionError(f"{label} has missing or unknown fields")
    return value


def _expect_exact(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise SbxExecutionError(f"inspection {label} is not the fixed value")


def parse_fixture_inspection_attestation(
    capability: FixtureSbxExecutionCapability,
    raw: bytes,
    expectation: InspectionExpectation,
) -> SbxInspectionAttestation:
    """Parse one exact inspection document without granting production authority."""

    _require_fixture_capability(capability)
    if type(expectation) is not InspectionExpectation:
        raise SbxExecutionError("inspection expectation has an invalid type")
    expectation = InspectionExpectation(
        expectation.controller,
        expectation.runtime,
        expectation.policy_epoch_sha256,
        expectation.secret_epoch_sha256,
    )
    top = _exact_object(
        _parse_canonical_json(raw),
        frozenset(
            {
                "credential_proxy",
                "mounts",
                "network_policy",
                "ports",
                "resource_caps",
                "runtime",
                "sandbox",
                "sbx_identity",
                "schema_version",
            }
        ),
        "inspection",
    )
    _expect_exact(top["schema_version"], INSPECTION_SCHEMA_VERSION, "schema version")

    identity = _exact_object(
        top["sbx_identity"],
        frozenset({"binary", "revision", "sha256", "version"}),
        "sbx identity",
    )
    for field_name, expected in (
        ("binary", SBX_BINARY),
        ("version", SBX_VERSION),
        ("revision", SBX_REVISION),
        ("sha256", SBX_SHA256),
    ):
        _expect_exact(identity[field_name], expected, f"sbx {field_name}")

    sandbox = _exact_object(
        top["sandbox"],
        frozenset({"controller_name", "daemon_uuid", "generation"}),
        "sandbox identity",
    )
    _expect_exact(
        sandbox["controller_name"], expectation.controller.name, "controller sandbox name"
    )
    _validate_daemon_identity_values(
        sandbox["daemon_uuid"], sandbox["generation"], sandbox["controller_name"]
    )

    runtime = _exact_object(
        top["runtime"],
        frozenset(
            {
                "agent",
                "auth_mode",
                "codex_executable_ctime_ns",
                "codex_executable_device",
                "codex_executable_inode",
                "codex_executable_link_count",
                "codex_executable_mode",
                "codex_executable_mtime_ns",
                "codex_executable_owner_gid",
                "codex_executable_owner_uid",
                "codex_executable_path",
                "codex_executable_sha256",
                "codex_executable_size_bytes",
                "codex_home",
                "codex_version",
                "hooks_loaded",
                "linux_capabilities",
                "model",
                "private_clone_workdir",
                "reasoning_effort",
                "repository_rules_loaded",
                "supplemental_gids",
                "user_config_loaded",
                "user_gid",
                "user_name",
                "user_uid",
            }
        ),
        "runtime",
    )
    for field_name, expected in (
        ("agent", AGENT),
        ("auth_mode", expectation.runtime.auth_mode),
        ("codex_executable_ctime_ns", expectation.runtime.codex_executable_ctime_ns),
        ("codex_executable_device", expectation.runtime.codex_executable_device),
        ("codex_executable_inode", expectation.runtime.codex_executable_inode),
        ("codex_executable_link_count", expectation.runtime.codex_executable_link_count),
        ("codex_executable_mode", expectation.runtime.codex_executable_mode),
        ("codex_executable_mtime_ns", expectation.runtime.codex_executable_mtime_ns),
        ("codex_executable_owner_gid", expectation.runtime.codex_executable_owner_gid),
        ("codex_executable_owner_uid", expectation.runtime.codex_executable_owner_uid),
        ("codex_executable_path", expectation.runtime.codex_executable_path),
        ("codex_executable_sha256", expectation.runtime.codex_executable_sha256),
        ("codex_executable_size_bytes", expectation.runtime.codex_executable_size_bytes),
        ("codex_home", expectation.runtime.codex_home),
        ("codex_version", expectation.runtime.codex_version),
        ("hooks_loaded", expectation.runtime.hooks_loaded),
        ("linux_capabilities", list(expectation.runtime.linux_capabilities)),
        ("model", MODEL),
        ("private_clone_workdir", expectation.runtime.private_clone_workdir),
        ("reasoning_effort", REASONING_EFFORT),
        ("repository_rules_loaded", expectation.runtime.repository_rules_loaded),
        ("supplemental_gids", list(expectation.runtime.supplemental_gids)),
        ("user_config_loaded", expectation.runtime.user_config_loaded),
        ("user_gid", expectation.runtime.user_gid),
        ("user_name", expectation.runtime.user_name),
        ("user_uid", expectation.runtime.user_uid),
    ):
        _expect_exact(runtime[field_name], expected, f"runtime {field_name}")

    mounts = _exact_object(
        top["mounts"],
        frozenset({"clone_mode", "source_mode", "workspace_count", "workspace_mode"}),
        "mounts",
    )
    for field_name, expected in (
        ("clone_mode", CLONE_MODE),
        ("source_mode", SOURCE_MOUNT_MODE),
        ("workspace_mode", WORKSPACE_MODE),
        ("workspace_count", 1),
    ):
        _expect_exact(mounts[field_name], expected, f"mount {field_name}")

    policy = _exact_object(
        top["network_policy"],
        frozenset({"epoch_sha256", "mode"}),
        "network policy",
    )
    _expect_exact(policy["mode"], POLICY_MODE, "network policy mode")
    _expect_exact(
        policy["epoch_sha256"],
        expectation.policy_epoch_sha256,
        "network policy epoch",
    )

    credential = _exact_object(
        top["credential_proxy"],
        frozenset(
            {
                "environment_bytes_present",
                "epoch_sha256",
                "github_capability_present",
                "service_capability",
                "ssh_agent_present",
            }
        ),
        "credential proxy",
    )
    _expect_exact(credential["epoch_sha256"], expectation.secret_epoch_sha256, "secret epoch")
    service = _exact_object(
        credential["service_capability"],
        frozenset({"name", "scope", "type"}),
        "credential service capability",
    )
    for field_name, expected in (
        ("name", OPENAI_CAPABILITY_NAME),
        ("scope", OPENAI_CAPABILITY_SCOPE),
        ("type", OPENAI_CAPABILITY_TYPE),
    ):
        _expect_exact(service[field_name], expected, f"credential service {field_name}")
    for field_name in (
        "environment_bytes_present",
        "github_capability_present",
        "ssh_agent_present",
    ):
        _expect_exact(credential[field_name], False, f"credential {field_name}")

    _expect_exact(top["ports"], [], "published ports")
    resources = _exact_object(
        top["resource_caps"], frozenset({"cpus", "memory_bytes"}), "resource caps"
    )
    _expect_exact(resources["cpus"], CPU_CAP, "CPU cap")
    _expect_exact(resources["memory_bytes"], MEMORY_CAP_BYTES, "memory cap")

    daemon = DaemonSandboxIdentity(
        sandbox["daemon_uuid"],
        sandbox["generation"],
        sandbox["controller_name"],
        _FIXTURE_ATTESTATION_SEAL,
    )
    return SbxInspectionAttestation(
        expectation.controller,
        daemon,
        expectation.runtime,
        expectation.policy_epoch_sha256,
        expectation.secret_epoch_sha256,
        hashlib.sha256(raw).hexdigest(),
        _FIXTURE_ATTESTATION_SEAL,
    )


def canonical_fixture_inspection_document(
    capability: FixtureSbxExecutionCapability,
    expectation: InspectionExpectation,
    *,
    daemon_uuid: str,
    generation: int,
) -> bytes:
    """Render exact synthetic daemon bytes for fixture-only tests."""

    _require_fixture_capability(capability)
    if type(expectation) is not InspectionExpectation:
        raise SbxExecutionError("inspection expectation has an invalid type")
    expectation = InspectionExpectation(
        expectation.controller,
        expectation.runtime,
        expectation.policy_epoch_sha256,
        expectation.secret_epoch_sha256,
    )
    _validate_daemon_identity_values(daemon_uuid, generation, expectation.controller.name)
    return _inspection_document(expectation, daemon_uuid=daemon_uuid, generation=generation)


def _inspection_document(
    expectation: InspectionExpectation,
    *,
    daemon_uuid: str,
    generation: int,
) -> bytes:
    return _canonical_json(
        {
            "credential_proxy": {
                "environment_bytes_present": False,
                "epoch_sha256": expectation.secret_epoch_sha256,
                "github_capability_present": False,
                "service_capability": {
                    "name": OPENAI_CAPABILITY_NAME,
                    "scope": OPENAI_CAPABILITY_SCOPE,
                    "type": OPENAI_CAPABILITY_TYPE,
                },
                "ssh_agent_present": False,
            },
            "mounts": {
                "clone_mode": CLONE_MODE,
                "source_mode": SOURCE_MOUNT_MODE,
                "workspace_count": 1,
                "workspace_mode": WORKSPACE_MODE,
            },
            "network_policy": {
                "epoch_sha256": expectation.policy_epoch_sha256,
                "mode": POLICY_MODE,
            },
            "ports": [],
            "resource_caps": {"cpus": CPU_CAP, "memory_bytes": MEMORY_CAP_BYTES},
            "runtime": {
                "agent": AGENT,
                "auth_mode": expectation.runtime.auth_mode,
                "codex_executable_ctime_ns": expectation.runtime.codex_executable_ctime_ns,
                "codex_executable_device": expectation.runtime.codex_executable_device,
                "codex_executable_inode": expectation.runtime.codex_executable_inode,
                "codex_executable_link_count": expectation.runtime.codex_executable_link_count,
                "codex_executable_mode": expectation.runtime.codex_executable_mode,
                "codex_executable_mtime_ns": expectation.runtime.codex_executable_mtime_ns,
                "codex_executable_owner_gid": expectation.runtime.codex_executable_owner_gid,
                "codex_executable_owner_uid": expectation.runtime.codex_executable_owner_uid,
                "codex_executable_path": expectation.runtime.codex_executable_path,
                "codex_executable_sha256": expectation.runtime.codex_executable_sha256,
                "codex_executable_size_bytes": expectation.runtime.codex_executable_size_bytes,
                "codex_home": expectation.runtime.codex_home,
                "codex_version": expectation.runtime.codex_version,
                "hooks_loaded": expectation.runtime.hooks_loaded,
                "linux_capabilities": list(expectation.runtime.linux_capabilities),
                "model": MODEL,
                "private_clone_workdir": expectation.runtime.private_clone_workdir,
                "reasoning_effort": REASONING_EFFORT,
                "repository_rules_loaded": expectation.runtime.repository_rules_loaded,
                "supplemental_gids": list(expectation.runtime.supplemental_gids),
                "user_config_loaded": expectation.runtime.user_config_loaded,
                "user_gid": expectation.runtime.user_gid,
                "user_name": expectation.runtime.user_name,
                "user_uid": expectation.runtime.user_uid,
            },
            "sandbox": {
                "controller_name": expectation.controller.name,
                "daemon_uuid": daemon_uuid,
                "generation": generation,
            },
            "sbx_identity": {
                "binary": SBX_BINARY,
                "revision": SBX_REVISION,
                "sha256": SBX_SHA256,
                "version": SBX_VERSION,
            },
            "schema_version": INSPECTION_SCHEMA_VERSION,
        }
    )


def _utc(value: datetime, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise SbxExecutionError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def fixed_sbx_codex_argv(attestation: SbxInspectionAttestation) -> tuple[str, ...]:
    """Return the sole contemplated non-creating argv; never live authority.

    Docker v0.35 ``sbx exec`` fails when the name is absent but automatically
    starts a stopped sandbox.  It does not document targeting the daemon
    UUID/generation.  The non-atomic name lookup therefore leaves a stale- or
    replacement-instance race as an explicit activation blocker even though
    both opaque values are mandatory inspection evidence.
    """

    verified = _validate_attestation(attestation)
    return (
        SBX_BINARY,
        "exec",
        "-i",
        "--user",
        f"{verified.runtime.user_uid}:{verified.runtime.user_gid}",
        "--workdir",
        verified.runtime.private_clone_workdir,
        verified.controller.name,
        verified.runtime.codex_executable_path,
        "exec",
        "--strict-config",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--disable",
        "hooks",
        "--model",
        MODEL,
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
        "--sandbox",
        "workspace-write",
        "--color",
        "never",
        "--json",
        "-",
    )


@dataclass(frozen=True, slots=True, init=False)
class SbxExecutionPlan:
    """One sealed, stdin-only, bounded model-call plan for an attested sandbox."""

    inspection: SbxInspectionAttestation
    stage: ExecutionStage
    call_index: int
    stdin_bytes: bytes
    stdin_sha256: str
    run_started_at: datetime
    call_started_at: datetime
    call_deadline_at: datetime
    cleanup_must_start_by: datetime
    lifecycle_deadline_at: datetime
    _seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        inspection: SbxInspectionAttestation,
        stage: ExecutionStage,
        stdin_bytes: bytes,
        run_started_at: datetime,
        call_started_at: datetime,
        seal: object,
    ) -> None:
        if seal is not _FIXTURE_ATTESTATION_SEAL:
            raise SbxExecutionError("sbx execution plan requires adapter authority")
        if type(stage) is not ExecutionStage:
            raise SbxExecutionError("execution stage is invalid")
        limits = _LIMIT_BY_STAGE[stage]
        run_start = _utc(run_started_at, "run start")
        call_start = _utc(call_started_at, "call start")
        if call_start < run_start:
            raise SbxExecutionError("call starts before its run")
        lifecycle_deadline = run_start + timedelta(seconds=LIFECYCLE_TIMEOUT_SECONDS)
        cleanup_start = lifecycle_deadline - timedelta(seconds=CLEANUP_TIMEOUT_SECONDS)
        if call_start >= cleanup_start:
            raise SbxExecutionError("call starts inside the cleanup reserve")
        call_deadline = min(call_start + timedelta(seconds=limits.timeout_seconds), cleanup_start)
        stdin = _validate_stdin(stdin_bytes, limits)
        object.__setattr__(self, "inspection", _validate_attestation(inspection))
        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "call_index", limits.call_index)
        object.__setattr__(self, "stdin_bytes", stdin)
        object.__setattr__(self, "stdin_sha256", hashlib.sha256(stdin).hexdigest())
        object.__setattr__(self, "run_started_at", run_start)
        object.__setattr__(self, "call_started_at", call_start)
        object.__setattr__(self, "call_deadline_at", call_deadline)
        object.__setattr__(self, "cleanup_must_start_by", cleanup_start)
        object.__setattr__(self, "lifecycle_deadline_at", lifecycle_deadline)
        object.__setattr__(self, "_seal", seal)
        validate_fixture_execution_plan(self)

    @property
    def limits(self) -> StageLimits:
        return _LIMIT_BY_STAGE[self.stage]

    @property
    def stdin_byte_cap(self) -> int:
        return _stage_stdin_byte_cap(self.limits)

    @property
    def conservative_input_token_admission(self) -> int:
        return CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE + len(self.stdin_bytes)

    @property
    def argv(self) -> tuple[str, ...]:
        return fixed_sbx_codex_argv(self.inspection)

    @property
    def model(self) -> str:
        return MODEL

    @property
    def reasoning_effort(self) -> str:
        return REASONING_EFFORT

    @property
    def attestation_sha256(self) -> str:
        value = {
            "argv": list(self.argv),
            "call_deadline_at": _timestamp(self.call_deadline_at),
            "call_index": self.call_index,
            "call_started_at": _timestamp(self.call_started_at),
            "cleanup_must_start_by": _timestamp(self.cleanup_must_start_by),
            "inspection_sha256": self.inspection.canonical_sha256,
            "lifecycle_deadline_at": _timestamp(self.lifecycle_deadline_at),
            "limits": {
                "combined_output_bytes": self.limits.combined_output_bytes,
                "controller_context_token_reserve": CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE,
                "input_token_cap": self.limits.input_token_cap,
                "output_token_cap": self.limits.output_token_cap,
                "stdin_byte_cap": self.stdin_byte_cap,
                "timeout_seconds": self.limits.timeout_seconds,
                "total_token_cap": self.limits.total_token_cap,
            },
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "run_started_at": _timestamp(self.run_started_at),
            "stage": self.stage.value,
            "stdin_bytes_length": len(self.stdin_bytes),
            "stdin_sha256": self.stdin_sha256,
            "conservative_input_token_admission": self.conservative_input_token_admission,
        }
        return hashlib.sha256(_canonical_json(value)).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _stage_stdin_byte_cap(limits: StageLimits) -> int:
    cap = limits.input_token_cap - CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE
    if cap <= 0 or cap > MAX_STDIN_BYTES:
        raise SbxExecutionError("stage input cap cannot cover the controller context reserve")
    return cap


def _validate_stdin(value: object, limits: StageLimits) -> bytes:
    if type(value) is not bytes or not value:
        raise SbxExecutionError("stdin plan is empty or mutable")
    if len(value) > MAX_STDIN_BYTES or len(value) > _stage_stdin_byte_cap(limits):
        raise SbxExecutionError("stdin plan exceeds its stage input-token admission cap")
    if b"\0" in value or not value.endswith(b"\n"):
        raise SbxExecutionError("stdin plan has unsafe framing")
    try:
        value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SbxExecutionError("stdin plan is not UTF-8") from exc
    return value


def build_fixture_execution_plan(
    capability: FixtureSbxExecutionCapability,
    inspection: SbxInspectionAttestation,
    *,
    stage: ExecutionStage,
    stdin_bytes: bytes,
    run_started_at: datetime,
    call_started_at: datetime,
) -> SbxExecutionPlan:
    """Build a pure fixture plan with no process, path, clock, or provider access."""

    _require_fixture_capability(capability)
    return SbxExecutionPlan(
        inspection,
        stage,
        stdin_bytes,
        run_started_at,
        call_started_at,
        _FIXTURE_ATTESTATION_SEAL,
    )


def validate_fixture_execution_plan(plan: object) -> SbxExecutionPlan:
    """Revalidate every stored field after adversarial in-process mutation."""

    if type(plan) is not SbxExecutionPlan:
        raise SbxExecutionError("sbx execution plan has an invalid type")
    try:
        seal = plan._seal
    except AttributeError as exc:
        raise SbxExecutionError("sbx execution plan is unsealed") from exc
    if seal is not _FIXTURE_ATTESTATION_SEAL:
        raise SbxExecutionError("sbx execution plan is unsealed")
    _validate_attestation(plan.inspection)
    if type(plan.stage) is not ExecutionStage:
        raise SbxExecutionError("execution plan stage is invalid")
    limits = _LIMIT_BY_STAGE[plan.stage]
    if type(plan.call_index) is not int or plan.call_index != limits.call_index:
        raise SbxExecutionError("execution call index is not fixed for its stage")
    stdin = _validate_stdin(plan.stdin_bytes, limits)
    if plan.stdin_sha256 != hashlib.sha256(stdin).hexdigest():
        raise SbxExecutionError("execution stdin digest does not bind its bytes")
    run_start = _utc(plan.run_started_at, "run start")
    call_start = _utc(plan.call_started_at, "call start")
    expected_lifecycle = run_start + timedelta(seconds=LIFECYCLE_TIMEOUT_SECONDS)
    expected_cleanup = expected_lifecycle - timedelta(seconds=CLEANUP_TIMEOUT_SECONDS)
    if call_start < run_start or call_start >= expected_cleanup:
        raise SbxExecutionError("execution call time is outside its lifecycle")
    expected_call = min(call_start + timedelta(seconds=limits.timeout_seconds), expected_cleanup)
    if (
        plan.lifecycle_deadline_at != expected_lifecycle
        or plan.cleanup_must_start_by != expected_cleanup
        or plan.call_deadline_at != expected_call
    ):
        raise SbxExecutionError("execution deadlines are not controller-derived")
    if plan.model != MODEL or plan.reasoning_effort != REASONING_EFFORT:
        raise SbxExecutionError("execution model identity is not fixed")
    argv = plan.argv
    if argv != fixed_sbx_codex_argv(plan.inspection):
        raise SbxExecutionError("execution argv is not fixed")
    forbidden = frozenset(
        {
            "run",
            "-d",
            "-e",
            "-t",
            "--clone",
            "--cpus",
            "--dangerously-bypass-approvals-and-sandbox",
            "--detach",
            "--detach-keys",
            "--env",
            "--env-file",
            "--kit",
            "--memory",
            "--name",
            "--port",
            "--privileged",
            "--profile",
            "--template",
            "--tty",
        }
    )
    if argv[1] != "exec" or not forbidden.isdisjoint(argv):
        raise SbxExecutionError("execution argv contains a forbidden authority surface")
    return plan


def execute_live_sbx_plan(*_args: object, **_kwargs: object) -> None:
    """Production entrypoint that rejects before inspecting arguments or doing I/O."""

    if not SBX_EXECUTION_ENABLED:
        raise SbxExecutionDisabled(
            "Docker Sandboxes Codex execution is source-disabled before inspection or I/O"
        )
    raise AssertionError("a reviewed daemon adapter must replace the final source gate")
