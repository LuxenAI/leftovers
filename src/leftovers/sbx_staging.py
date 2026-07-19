"""Pure contract for disposable, controller-side Docker Sandbox staging clones.

This module deliberately has no filesystem, subprocess, Git, network, Docker,
or credential access.  ``prepare_live_sbx_staging_clone`` is source-disabled *before*
it reads an argument.  The fixture surface only validates evidence supplied by
a future reviewed controller.

GitHub reads in this design are controller-side HTTPS fetches of one immutable
commit into a newly initialized, owner-private disposable repository.  No
GitHub credential is passed to the VM.  In particular, Docker Sandboxes clone
mode must never receive an everyday checkout, a mount of one, or a clone that
shares its objects, links, or ancestry with one.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .sbx import controller_sandbox_name

SBX_STAGING_ENABLED: Final = False
"""Release gate; configuration and fixture authority cannot enable this."""

STAGING_ROOT: Final = "/private/tmp/leftovers-sbx-staging"
GIT_BINARY: Final = "/usr/bin/git"
GIT_PATH: Final = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_TRACKED_PATHS: Final = 2_048
MAX_TRACKED_PATH_BYTES: Final = 240
MAX_TRACKED_PATH_DEPTH: Final = 32

_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_GIT_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
_SLUG = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\Z"
)
_REMOTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}\Z")


class SbxStagingError(RuntimeError):
    """Staging evidence does not prove an isolated disposable clone."""


class SbxStagingDisabled(SbxStagingError):
    """The public live entry is source-disabled before argument inspection."""


class StagingState(StrEnum):
    READY = "ready"
    CLEANED = "cleaned"
    CLEANUP_PENDING = "cleanup_pending"


def _require(value: object, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise SbxStagingError(f"{label} is invalid")
    return value


def _public_repository(value: object) -> str:
    """Accept one canonical public GitHub owner/name slug, never a URL/ref."""

    slug = _require(value, _SLUG, "public GitHub repository")
    owner, name = slug.split("/")
    if owner in {".", ".."} or name in {".", ".."}:
        raise SbxStagingError("public GitHub repository is invalid")
    return slug


def _absolute(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        or posixpath.normpath(value) != value
        or len(value.encode("utf-8")) > 512
    ):
        raise SbxStagingError(f"{label} is not a canonical absolute path")
    return value


def _under(path: str, parent: str) -> bool:
    return path.startswith(parent + "/")


def _canonical_sha256(value: object) -> str:
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SbxStagingError("staging value cannot be canonically hashed") from exc
    return hashlib.sha256(raw).hexdigest()


def _identity(value: object, label: str, *, allow_directory: bool = True) -> DescriptorIdentity:
    if type(value) is not DescriptorIdentity:
        raise SbxStagingError(f"{label} descriptor identity is invalid")
    if not allow_directory and value.kind != "file":
        raise SbxStagingError(f"{label} must identify a regular file")
    return value


@dataclass(frozen=True, slots=True)
class DescriptorIdentity:
    """A no-follow descriptor identity gathered by a future controller."""

    device: int
    inode: int
    owner_uid: int
    mode: int
    kind: str = "directory"
    link_count: int = 1

    def __post_init__(self) -> None:
        if any(
            type(item) is not int for item in (self.device, self.inode, self.owner_uid, self.mode)
        ):
            raise SbxStagingError("descriptor identity contains a non-integer")
        if self.device <= 0 or self.inode <= 0 or self.owner_uid < 0:
            raise SbxStagingError("descriptor identity integer is invalid")
        if self.kind not in {"directory", "file"}:
            raise SbxStagingError("descriptor kind is invalid")
        if self.mode != (0o700 if self.kind == "directory" else 0o600):
            raise SbxStagingError("descriptor mode is not owner-private")
        if type(self.link_count) is not int or self.link_count != 1:
            raise SbxStagingError("descriptor link count must be exactly one")


@dataclass(frozen=True, slots=True)
class PrivateStagingRoot:
    """The only accepted parent for a disposable staging clone."""

    path: str
    owner_uid: int
    identity: DescriptorIdentity

    def __post_init__(self) -> None:
        path = _absolute(self.path, "staging root")
        if path != STAGING_ROOT:
            raise SbxStagingError("staging root is not the fixed private temporary root")
        if type(self.owner_uid) is not int or self.owner_uid < 0:
            raise SbxStagingError("staging owner UID is invalid")
        identity = _identity(self.identity, "staging root")
        if identity.owner_uid != self.owner_uid:
            raise SbxStagingError("staging root owner does not match descriptor")


@dataclass(frozen=True, slots=True)
class RemoteEvidence:
    name: str
    fetch_url: str
    push_url: str

    def __post_init__(self) -> None:
        _require(self.name, _REMOTE, "remote name")
        for value, label in (
            (self.fetch_url, "remote fetch URL"),
            (self.push_url, "remote push URL"),
        ):
            if type(value) is not str or "\x00" in value or "\n" in value or "\r" in value:
                raise SbxStagingError(f"{label} is invalid")


@dataclass(frozen=True, slots=True)
class CleanCloneEvidence:
    """Controller-observed properties of the newly created normal clone."""

    path: str
    identity: DescriptorIdentity
    root_identity: DescriptorIdentity
    run_directory_path: str
    run_directory_identity: DescriptorIdentity
    marker_identity: DescriptorIdentity
    marker_sha256: str
    base_sha_observed: str
    source_manifest_sha256: str
    tracked_paths: tuple[str, ...]
    untracked_paths: tuple[str, ...]
    ignored_paths: tuple[str, ...]
    remotes: tuple[RemoteEvidence, ...]
    is_normal_clone: bool
    has_symlink: bool
    has_hardlink: bool
    has_alternates: bool
    has_shared_object_store: bool

    def __post_init__(self) -> None:
        _absolute(self.path, "clone path")
        _identity(self.identity, "clone")
        _identity(self.root_identity, "clone root parent")
        _absolute(self.run_directory_path, "clone run directory")
        _identity(self.run_directory_identity, "clone run directory")
        _identity(self.marker_identity, "clone marker", allow_directory=False)
        _require(self.marker_sha256, _HEX64, "clone marker digest")
        _require(self.base_sha_observed, _GIT_SHA, "observed base SHA")
        _require(self.source_manifest_sha256, _HEX64, "source manifest digest")
        if (
            type(self.tracked_paths) is not tuple
            or not self.tracked_paths
            or len(self.tracked_paths) > MAX_TRACKED_PATHS
        ):
            raise SbxStagingError("tracked paths are absent or exceed their bound")
        if self.tracked_paths != tuple(sorted(self.tracked_paths)) or len(
            set(self.tracked_paths)
        ) != len(self.tracked_paths):
            raise SbxStagingError("tracked paths are not exact and sorted")
        for path in self.tracked_paths:
            try:
                encoded = path.encode("utf-8")
            except (AttributeError, UnicodeEncodeError) as exc:
                raise SbxStagingError("tracked path is not canonical UTF-8") from exc
            parts = path.split("/")
            if (
                type(path) is not str
                or not path
                or path.startswith("/")
                or "\\" in path
                or "\x00" in path
                or unicodedata.normalize("NFC", path) != path
                or len(encoded) > MAX_TRACKED_PATH_BYTES
                or len(parts) > MAX_TRACKED_PATH_DEPTH
                or any(part in {"", ".", "..", ".git"} for part in parts)
                or any(ord(character) < 32 or ord(character) == 127 for character in path)
            ):
                raise SbxStagingError("tracked path is unsafe")
        if self.untracked_paths or self.ignored_paths:
            raise SbxStagingError("clone is not tracked-only clean")
        if type(self.remotes) is not tuple or any(
            type(item) is not RemoteEvidence for item in self.remotes
        ):
            raise SbxStagingError("clone remote evidence is invalid")
        if not all(
            type(flag) is bool
            for flag in (
                self.is_normal_clone,
                self.has_symlink,
                self.has_hardlink,
                self.has_alternates,
                self.has_shared_object_store,
            )
        ):
            raise SbxStagingError("clone topology evidence is invalid")


def _origin_url(slug: str) -> str:
    return f"https://github.com/{slug}.git"


def _git_env(root: PrivateStagingRoot) -> tuple[tuple[str, str], ...]:
    """Fixed Git environment; no host credential/configuration is inherited."""

    return (
        ("PATH", GIT_PATH),
        ("HOME", root.path + "/git-home"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_ASKPASS", "/bin/false"),
        ("GIT_SSH_COMMAND", "/bin/false"),
        ("GIT_LFS_SKIP_SMUDGE", "1"),
    )


def _git_prefix() -> tuple[str, ...]:
    return (
        GIT_BINARY,
        "-c",
        "credential.helper=",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.attributesfile=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
    )


def staging_marker_sha256(
    *,
    run_id: str,
    sandbox_name: str,
    repository: str,
    base_sha: str,
    source_manifest_sha256: str,
    clone_path: str,
) -> str:
    """Digest the exact controller marker content for one disposable run."""

    return _canonical_sha256(
        {
            "base_sha": _require(base_sha, _GIT_SHA, "marker base SHA"),
            "clone_path": _absolute(clone_path, "marker clone path"),
            "kind": "leftovers.sbx.staging-marker.v1",
            "repository": _public_repository(repository),
            "run_id": _require(run_id, _HEX32, "marker run ID"),
            "sandbox_name": sandbox_name,
            "source_manifest_sha256": _require(
                source_manifest_sha256, _HEX64, "marker source manifest"
            ),
        }
    )


@dataclass(frozen=True, slots=True)
class SbxStagingPlan:
    """Exact argv-only future lifecycle for one private staging clone.

    The controller must execute the GitHub HTTPS fetch.  Only the staged clone
    may subsequently be named by a Docker Sandbox clone/provision adapter.
    """

    run_id: str
    sandbox_name: str
    repository: str
    base_sha: str
    source_manifest_sha256: str
    root: PrivateStagingRoot
    clone: CleanCloneEvidence
    git_env: tuple[tuple[str, str], ...]
    init_argv: tuple[str, ...]
    remote_add_argv: tuple[str, ...]
    fetch_argv: tuple[str, ...]
    checkout_argv: tuple[str, ...]
    origin_remove_argv: tuple[str, ...]
    status_argv: tuple[str, ...]
    remote_list_argv: tuple[str, ...]
    sandbox_remote_name: str

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "run ID")
        expected_name = controller_sandbox_name(self.run_id)
        if self.sandbox_name != expected_name:
            raise SbxStagingError("sandbox name is not bound to the run ID")
        _public_repository(self.repository)
        _require(self.base_sha, _GIT_SHA, "base SHA")
        _require(self.source_manifest_sha256, _HEX64, "source manifest digest")
        if type(self.root) is not PrivateStagingRoot or type(self.clone) is not CleanCloneEvidence:
            raise SbxStagingError("staging plan evidence is invalid")
        expected_clone = f"{self.root.path}/run-{self.run_id}/clone"
        expected_run_directory = f"{self.root.path}/run-{self.run_id}"
        if self.clone.path != expected_clone:
            raise SbxStagingError("clone path is not the exact disposable run child")
        if (
            self.clone.root_identity != self.root.identity
            or self.clone.run_directory_path != expected_run_directory
            or self.clone.identity == self.clone.run_directory_identity
            or self.clone.run_directory_identity.owner_uid != self.root.owner_uid
        ):
            raise SbxStagingError("clone parent chain is not the exact private run directory")
        if self.clone.base_sha_observed != self.base_sha:
            raise SbxStagingError("staged base SHA drifted")
        if self.clone.source_manifest_sha256 != self.source_manifest_sha256:
            raise SbxStagingError("staged source manifest drifted")
        if not self.clone.is_normal_clone or any(
            (
                self.clone.has_symlink,
                self.clone.has_hardlink,
                self.clone.has_alternates,
                self.clone.has_shared_object_store,
            )
        ):
            raise SbxStagingError("clone is not an isolated normal clone")
        expected_marker = staging_marker_sha256(
            run_id=self.run_id,
            sandbox_name=self.sandbox_name,
            repository=self.repository,
            base_sha=self.base_sha,
            source_manifest_sha256=self.source_manifest_sha256,
            clone_path=self.clone.path,
        )
        if self.clone.marker_sha256 != expected_marker:
            raise SbxStagingError("staging marker does not bind the exact run")
        if self.clone.remotes != ():
            raise SbxStagingError("pre-sbx remotes must be exactly empty")
        expected_env = _git_env(self.root)
        if self.git_env != expected_env:
            raise SbxStagingError("Git environment is not fixed and isolated")
        prefix = _git_prefix()
        clone = self.clone.path
        origin = _origin_url(self.repository)
        expected = (
            prefix + ("init", "--quiet", clone),
            prefix + ("-C", clone, "remote", "add", "origin", origin),
            prefix + ("-C", clone, "fetch", "--no-tags", "--depth=1", "origin", self.base_sha),
            prefix + ("-C", clone, "checkout", "--detach", "--force", self.base_sha),
            prefix + ("-C", clone, "remote", "remove", "origin"),
            prefix
            + ("-C", clone, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"),
            prefix + ("-C", clone, "remote", "-v"),
        )
        if (
            self.init_argv,
            self.remote_add_argv,
            self.fetch_argv,
            self.checkout_argv,
            self.origin_remove_argv,
            self.status_argv,
            self.remote_list_argv,
        ) != expected:
            raise SbxStagingError("Git argv is not the fixed controller staging sequence")
        remote = "sandbox-" + self.sandbox_name
        if self.sandbox_remote_name != remote:
            raise SbxStagingError("sandbox remote is not bound to the sandbox name")

    @property
    def sha256(self) -> str:
        return _canonical_sha256(
            {
                "base_sha": self.base_sha,
                "clone_path": self.clone.path,
                "clone_run_directory": self.clone.run_directory_path,
                "git_env": list(self.git_env),
                "git_sequence": [
                    list(self.init_argv),
                    list(self.remote_add_argv),
                    list(self.fetch_argv),
                    list(self.checkout_argv),
                    list(self.origin_remove_argv),
                    list(self.status_argv),
                    list(self.remote_list_argv),
                ],
                "marker_sha256": self.clone.marker_sha256,
                "repository": self.repository,
                "run_id": self.run_id,
                "sandbox_name": self.sandbox_name,
                "sandbox_remote_name": self.sandbox_remote_name,
                "source_manifest_sha256": self.source_manifest_sha256,
            }
        )


@dataclass(frozen=True, slots=True)
class StagingProvisionBinding:
    """Typed handoff for future sbx daemon/provision/cycle adapters."""

    run_id: str
    sandbox_name: str
    repository: str
    staged_clone_path: str
    staging_plan_sha256: str
    clone_identity: DescriptorIdentity
    run_directory_identity: DescriptorIdentity
    base_sha: str
    source_manifest_sha256: str

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "provision run ID")
        if self.sandbox_name != controller_sandbox_name(self.run_id):
            raise SbxStagingError("provision sandbox binding is invalid")
        _public_repository(self.repository)
        _absolute(self.staged_clone_path, "provision clone path")
        _require(self.staging_plan_sha256, _HEX64, "provision staging-plan digest")
        _identity(self.clone_identity, "provision clone")
        _identity(self.run_directory_identity, "provision run directory")
        _require(self.base_sha, _GIT_SHA, "provision base SHA")
        _require(self.source_manifest_sha256, _HEX64, "provision source manifest digest")


@dataclass(frozen=True, slots=True)
class StagingCleanupObservation:
    """No-follow post-stop evidence a future cleanup adapter must supply."""

    run_id: str
    sandbox_name: str
    sandbox_destruction_attestation_sha256: str
    clone_identity_before: DescriptorIdentity
    run_directory_identity_before: DescriptorIdentity
    root_identity_before: DescriptorIdentity
    marker_identity_before: DescriptorIdentity
    marker_sha256_before: str
    root_identity_after: DescriptorIdentity | None
    sandbox_destruction_proven: bool
    sandbox_remote_absent: bool
    no_labeled_containers: bool
    clone_removed: bool
    run_directory_removed: bool
    removal_target_was_exact_run_directory: bool
    marker_matched: bool
    parent_chain_matched: bool

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "cleanup run ID")
        if self.sandbox_name != controller_sandbox_name(self.run_id):
            raise SbxStagingError("cleanup sandbox binding is invalid")
        _require(
            self.sandbox_destruction_attestation_sha256,
            _HEX64,
            "sandbox destruction attestation",
        )
        _identity(self.clone_identity_before, "cleanup clone")
        _identity(self.run_directory_identity_before, "cleanup run directory")
        _identity(self.root_identity_before, "cleanup root")
        _identity(self.marker_identity_before, "cleanup marker", allow_directory=False)
        _require(self.marker_sha256_before, _HEX64, "cleanup marker digest")
        if self.root_identity_after is not None:
            _identity(self.root_identity_after, "post-cleanup root")
        if not all(
            type(flag) is bool
            for flag in (
                self.sandbox_destruction_proven,
                self.sandbox_remote_absent,
                self.no_labeled_containers,
                self.clone_removed,
                self.run_directory_removed,
                self.removal_target_was_exact_run_directory,
                self.marker_matched,
                self.parent_chain_matched,
            )
        ):
            raise SbxStagingError("cleanup observation flag is invalid")


@dataclass(frozen=True, slots=True)
class StagingCleanupReceipt:
    run_id: str
    sandbox_name: str
    state: StagingState
    sandbox_destruction_proven: bool
    clone_removed: bool
    run_directory_removed: bool
    sandbox_remote_absent: bool
    no_labeled_containers: bool
    root_identity_preserved: bool
    reason: str | None

    def __post_init__(self) -> None:
        _require(self.run_id, _HEX32, "cleanup receipt run ID")
        if self.sandbox_name != controller_sandbox_name(self.run_id):
            raise SbxStagingError("cleanup receipt sandbox binding is invalid")
        if type(self.state) is not StagingState or not all(
            type(flag) is bool
            for flag in (
                self.sandbox_destruction_proven,
                self.clone_removed,
                self.run_directory_removed,
                self.sandbox_remote_absent,
                self.no_labeled_containers,
                self.root_identity_preserved,
            )
        ):
            raise SbxStagingError("cleanup receipt is invalid")
        if self.state is StagingState.CLEANED:
            if (
                not all(
                    (
                        self.clone_removed,
                        self.run_directory_removed,
                        self.sandbox_destruction_proven,
                        self.sandbox_remote_absent,
                        self.no_labeled_containers,
                        self.root_identity_preserved,
                    )
                )
                or self.reason is not None
            ):
                raise SbxStagingError("cleaned receipt lacks complete proof")
        elif self.state is StagingState.CLEANUP_PENDING:
            if not isinstance(self.reason, str) or not self.reason:
                raise SbxStagingError("cleanup_pending receipt requires a reason")
        else:
            raise SbxStagingError("cleanup receipt cannot be ready")


class FixtureSbxStagingCapability:
    __slots__ = ("_secret",)

    def __init__(self, secret: object) -> None:
        if secret is not _FIXTURE_SECRET:
            raise SbxStagingError("fixture staging capability is not constructible")
        self._secret = secret


_FIXTURE_SECRET = object()
_FIXTURE_CAPABILITY = FixtureSbxStagingCapability(_FIXTURE_SECRET)


def fixture_sbx_staging_capability() -> FixtureSbxStagingCapability:
    """Return the singleton non-authoritative fake-plan capability."""

    return _FIXTURE_CAPABILITY


def _require_capability(capability: object) -> None:
    if (
        type(capability) is not FixtureSbxStagingCapability
        or capability is not _FIXTURE_CAPABILITY
        or capability._secret is not _FIXTURE_SECRET
    ):
        raise SbxStagingError("fixture staging capability is invalid")


def build_fixture_staging_plan(
    capability: FixtureSbxStagingCapability,
    *,
    run_id: str,
    repository: str,
    base_sha: str,
    source_manifest_sha256: str,
    root: PrivateStagingRoot,
    clone: CleanCloneEvidence,
) -> SbxStagingPlan:
    """Build one exact fixture plan; it performs neither Git nor filesystem I/O."""

    _require_capability(capability)
    name = controller_sandbox_name(run_id)
    prefix = _git_prefix()
    path = clone.path
    origin = _origin_url(repository)
    return SbxStagingPlan(
        run_id=run_id,
        sandbox_name=name,
        repository=repository,
        base_sha=base_sha,
        source_manifest_sha256=source_manifest_sha256,
        root=root,
        clone=clone,
        git_env=_git_env(root),
        init_argv=prefix + ("init", "--quiet", path),
        remote_add_argv=prefix + ("-C", path, "remote", "add", "origin", origin),
        fetch_argv=prefix + ("-C", path, "fetch", "--no-tags", "--depth=1", "origin", base_sha),
        checkout_argv=prefix + ("-C", path, "checkout", "--detach", "--force", base_sha),
        origin_remove_argv=prefix + ("-C", path, "remote", "remove", "origin"),
        status_argv=prefix
        + ("-C", path, "status", "--porcelain=v1", "--untracked-files=all", "--ignored"),
        remote_list_argv=prefix + ("-C", path, "remote", "-v"),
        sandbox_remote_name="sandbox-" + name,
    )


def validate_fixture_staging_plan(
    capability: FixtureSbxStagingCapability, plan: SbxStagingPlan
) -> StagingProvisionBinding:
    """Validate an exact plan and return the only future provision/cycle binding."""

    _require_capability(capability)
    if type(plan) is not SbxStagingPlan:
        raise SbxStagingError("staging plan is invalid")
    # Re-enter construction so mutated/forged frozen objects cannot bypass the
    # complete exact-argv and evidence invariants in ``__post_init__``.
    SbxStagingPlan(**{field: getattr(plan, field) for field in plan.__dataclass_fields__})
    return StagingProvisionBinding(
        run_id=plan.run_id,
        sandbox_name=plan.sandbox_name,
        repository=plan.repository,
        staged_clone_path=plan.clone.path,
        staging_plan_sha256=plan.sha256,
        clone_identity=plan.clone.identity,
        run_directory_identity=plan.clone.run_directory_identity,
        base_sha=plan.base_sha,
        source_manifest_sha256=plan.source_manifest_sha256,
    )


def fixture_staging_cleanup_receipt(
    capability: FixtureSbxStagingCapability,
    plan: SbxStagingPlan,
    observation: StagingCleanupObservation,
) -> StagingCleanupReceipt:
    """Classify exact cleanup evidence; every ambiguity is cleanup_pending."""

    _require_capability(capability)
    binding = validate_fixture_staging_plan(capability, plan)
    if observation.run_id != binding.run_id or observation.sandbox_name != binding.sandbox_name:
        raise SbxStagingError("cleanup observation does not bind the staging plan")
    expected_clone = plan.clone.identity
    expected_run_directory = plan.clone.run_directory_identity
    expected_root = plan.root.identity
    complete = (
        observation.sandbox_destruction_proven
        and observation.clone_identity_before == expected_clone
        and observation.run_directory_identity_before == expected_run_directory
        and observation.root_identity_before == expected_root
        and observation.marker_identity_before == plan.clone.marker_identity
        and observation.marker_sha256_before == plan.clone.marker_sha256
        and observation.root_identity_after == expected_root
        and observation.sandbox_remote_absent
        and observation.no_labeled_containers
        and observation.clone_removed
        and observation.run_directory_removed
        and observation.removal_target_was_exact_run_directory
        and observation.marker_matched
        and observation.parent_chain_matched
    )
    if complete:
        return StagingCleanupReceipt(
            binding.run_id,
            binding.sandbox_name,
            StagingState.CLEANED,
            True,
            True,
            True,
            True,
            True,
            True,
            None,
        )
    return StagingCleanupReceipt(
        binding.run_id,
        binding.sandbox_name,
        StagingState.CLEANUP_PENDING,
        observation.sandbox_destruction_proven,
        observation.clone_removed,
        observation.run_directory_removed,
        observation.sandbox_remote_absent,
        observation.no_labeled_containers,
        observation.root_identity_after == expected_root,
        "cleanup proof is incomplete or staging root identity changed",
    )


def prepare_live_sbx_staging_clone(*_args: object, **_kwargs: object) -> None:
    """Production surface: deny before paths, URLs, credentials, or argv are read."""

    raise SbxStagingDisabled(
        "Docker Sandbox disposable staging is source-disabled before argument inspection or I/O"
    )
