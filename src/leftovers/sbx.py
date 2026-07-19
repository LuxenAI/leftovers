"""Fail-closed boundary for Docker Sandboxes (``sbx``) clone sandboxes.

This module intentionally does *not* turn Docker Sandboxes into a production
execution backend.  Docker Sandboxes provide a useful VM boundary, but their
CLI and credential proxy are external authority.  The public boundary below is
therefore source-disabled.  It exists to make the proposed controller contract
small and adversarially testable before it is wired into orchestration:

* controller-derived names and fixed ``sbx create --clone`` argv only;
* clean host environment and an inspectable clean Git-clone input;
* exact binary/version/revision/digest admission before a create;
* no generic ``exec``, ``cp``, login, policy, port, or reset interface; and
* exact-name cleanup whose receipt is ``cleanup_pending`` on any uncertainty.

The fixture capability is deliberately not a credential and cannot enable the
source gate.  It is only a type barrier for deterministic unit tests with a
fake command executor.  Production integration must add independently reviewed
live attestation, result extraction, model mediation, and post-stop validation.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

# A release gate, not configuration.  No caller, TOML value, or environment
# variable can activate this module by accident.
DOCKER_SANDBOX_EXECUTION_ENABLED = False

MAX_CLI_OUTPUT_BYTES = 64 * 1024
MAX_IDENTITY_OUTPUT_BYTES = 4 * 1024
MAX_SOURCE_FILE_BYTES = 1 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILES = 2_048
MAX_SOURCE_DEPTH = 32
MAX_SOURCE_PATH_BYTES = 240
_NAME = re.compile(r"leftovers-[a-f0-9]{24}\Z")
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")
_REVISION = re.compile(r"[a-f0-9]{7,64}\Z")
_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")
_MEMORY = re.compile(r"[1-9][0-9]{0,3}[mMgG]\Z")
_SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\..*)?|\.npmrc|\.netrc|\.pypirc|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)|credentials(?:\..*)?|auth\.json|"
    r".*\.(?:pem|p12|pfx|key))\Z",
    re.IGNORECASE,
)
_SECRET_PATTERNS = (
    re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)(?:github_pat|ghp|gho|ghu|ghs)_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?i)AKIA[0-9A-Z]{16}"),
    re.compile(
        rb"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?"
        rb"[A-Za-z0-9_./+=-]{20,}"
    ),
)
_DENIED_ENV_EXACT = frozenset(
    {
        "SSH_AUTH_SOCK",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "CODEX_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }
)
_DENIED_ENV_PREFIXES = (
    "GITHUB_",
    "GH_",
    "GIT_",
    "DOCKER_",
    "COMPOSE_",
    "REGISTRY_",
    "OPENAI_",
    "ANTHROPIC_",
    "CODEX_",
    "AWS_",
    "SSH_",
)


class SbxError(RuntimeError):
    """An sbx boundary precondition or receipt is unsafe."""


class SbxExecutionDisabled(SbxError):
    """The source-level production gate rejected before command execution."""


class SbxAdmissionError(SbxError):
    """The controller cannot prove that sandbox creation is safe."""


class SbxCleanupPending(SbxError):
    """Exact-name sandbox cleanup could not be proven."""


class FixtureSbxCapability:
    """Explicit, non-production capability for fake-executor lifecycle tests."""

    __slots__ = ("_identity",)

    def __init__(self, identity: object) -> None:
        if identity is not _FIXTURE_CAPABILITY_IDENTITY:
            raise SbxError("fixture sbx capability is not constructible")
        self._identity = identity


_FIXTURE_CAPABILITY_IDENTITY = object()
_FIXTURE_CAPABILITY = FixtureSbxCapability(_FIXTURE_CAPABILITY_IDENTITY)


def fixture_sbx_capability() -> FixtureSbxCapability:
    """Return the singleton test-only capability.

    This is not an activation capability: ``SbxBoundary`` remains disabled.
    """

    return _FIXTURE_CAPABILITY


@dataclass(frozen=True)
class SbxIdentity:
    """Pinned identity of the host-owned CLI executable."""

    binary: Path
    version: str
    revision: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.binary.is_absolute() or self.binary.name != "sbx":
            raise ValueError("sbx binary must be an absolute file named sbx")
        if _VERSION.fullmatch(self.version) is None:
            raise ValueError("sbx version is invalid")
        if _REVISION.fullmatch(self.revision) is None:
            raise ValueError("sbx revision is invalid")
        if _HEX64.fullmatch(self.sha256) is None:
            raise ValueError("sbx binary SHA-256 is invalid")


@dataclass(frozen=True)
class GitCloneInput:
    """Controller-collected evidence for one normal, clean Git clone."""

    root: Path
    tracked_paths: tuple[str, ...]
    untracked_paths: tuple[str, ...]


@dataclass(frozen=True)
class SbxCommandResult:
    """Bounded result supplied by an injected executor."""

    returncode: int
    stdout: bytes
    stderr: bytes = b""
    timed_out: bool = False
    output_truncated: bool = False

    def __post_init__(self) -> None:
        if type(self.returncode) is not int:
            raise ValueError("command return code must be an integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("command output must be bytes")


CommandExecutor = Callable[[tuple[str, ...], Mapping[str, str], float, int], SbxCommandResult]


@dataclass(frozen=True)
class SbxCleanupReceipt:
    name: str
    state: str
    stop_returncode: int | None
    remove_returncode: int | None
    final_absent: bool


@dataclass(frozen=True)
class SbxProvisionReceipt:
    name: str
    create_argv: tuple[str, ...]
    identity: SbxIdentity


def controller_sandbox_name(run_nonce: str) -> str:
    """Derive the only allowed sandbox name from controller-only entropy."""

    if not isinstance(run_nonce, str) or not run_nonce or len(run_nonce) > 256:
        raise SbxAdmissionError("controller run nonce is invalid")
    try:
        raw = run_nonce.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SbxAdmissionError("controller run nonce must be ASCII") from exc
    return "leftovers-" + hashlib.sha256(b"leftovers-sbx-v1\x00" + raw).hexdigest()[:24]


def _require_name(name: str) -> str:
    if not isinstance(name, str) or _NAME.fullmatch(name) is None:
        raise SbxAdmissionError("sandbox name is not controller-derived")
    return name


def _host_environment(ambient: Mapping[str, str]) -> dict[str, str]:
    """Reject credential/routing ambient state, then return the exact CLI env."""

    for key, value in ambient.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise SbxAdmissionError("host environment has a non-string entry")
        upper = key.upper()
        if (
            upper in _DENIED_ENV_EXACT
            or upper.startswith(_DENIED_ENV_PREFIXES)
            or upper.endswith("_PROXY")
            or upper.endswith("_TOKEN")
            or upper.endswith("_API_KEY")
        ):
            raise SbxAdmissionError(f"forbidden ambient environment variable: {key}")
    # The v0.35 macOS binary panics when HOME is absent, before it can report a
    # normal error.  HOME is controller authority needed by the host CLI; it is
    # not an extra workspace and Docker documents that host user-agent config
    # is not copied into the sandbox.  Everything else remains explicit and
    # empty so SSH/proxy/provider/GitHub authority cannot be inherited.
    home = ambient.get("HOME")
    if not isinstance(home, str) or not home.startswith("/") or "\x00" in home:
        raise SbxAdmissionError("HOME must be a canonical absolute controller path")
    if Path(home) != Path(home).resolve():
        raise SbxAdmissionError("HOME must be a canonical absolute controller path")
    return {"HOME": home, "SBX_NO_TELEMETRY": "1"}


def _normal_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or unicodedata.normalize("NFC", value) != value:
        raise SbxAdmissionError("tracked path is not a normal relative path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SbxAdmissionError("tracked path is not valid UTF-8") from exc
    parts = value.split("/")
    if (
        len(encoded) > MAX_SOURCE_PATH_BYTES
        or len(parts) > MAX_SOURCE_DEPTH
        or value.startswith("/")
        or "\\" in value
        or any(not part or part in {".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SbxAdmissionError("tracked path is not a normal relative path")
    if ".git" in parts:
        raise SbxAdmissionError("Git control paths cannot be mounted into sbx")
    return value


def _source_file_bytes(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SbxAdmissionError("tracked source file cannot be opened safely") from exc
    identity = (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_uid,
        expected.st_gid,
        expected.st_size,
        expected.st_nlink,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    )
    try:
        held = os.fstat(descriptor)
        if (
            held.st_dev,
            held.st_ino,
            held.st_mode,
            held.st_uid,
            held.st_gid,
            held.st_size,
            held.st_nlink,
            held.st_mtime_ns,
            held.st_ctime_ns,
        ) != identity:
            raise SbxAdmissionError("tracked source file changed before scanning")
        content = bytearray()
        while len(content) <= MAX_SOURCE_FILE_BYTES:
            block = os.read(descriptor, min(128 * 1024, MAX_SOURCE_FILE_BYTES + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) != expected.st_size or len(content) > MAX_SOURCE_FILE_BYTES:
            raise SbxAdmissionError("tracked source file changed or exceeded its bound")
        after_held = os.fstat(descriptor)
        try:
            after_path = path.lstat()
        except OSError as exc:
            raise SbxAdmissionError("tracked source path changed while scanning") from exc
        for observed in (after_held, after_path):
            if (
                observed.st_dev,
                observed.st_ino,
                observed.st_mode,
                observed.st_uid,
                observed.st_gid,
                observed.st_size,
                observed.st_nlink,
                observed.st_mtime_ns,
                observed.st_ctime_ns,
            ) != identity:
                raise SbxAdmissionError("tracked source file changed while scanning")
        return bytes(content)
    finally:
        os.close(descriptor)


def _enumerate_worktree_files(root: Path) -> tuple[str, ...]:
    files: list[str] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path == root:
            directories[:] = [name for name in directories if name != ".git"]
        for name in sorted(directories):
            relative = (current_path / name).relative_to(root).as_posix()
            _normal_relative_path(relative)
            try:
                entry = (current_path / name).lstat()
            except OSError as exc:
                raise SbxAdmissionError("source directory cannot be inspected") from exc
            if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
                raise SbxAdmissionError("source directories must be real directories")
            if entry.st_uid != os.getuid() or stat.S_IMODE(entry.st_mode) & 0o022:
                raise SbxAdmissionError(
                    "source directories must be current-user-owned and non-writable by others"
                )
        for name in sorted(filenames):
            relative = _normal_relative_path((current_path / name).relative_to(root).as_posix())
            files.append(relative)
            if len(files) > MAX_SOURCE_FILES:
                raise SbxAdmissionError("tracked source file count exceeds its bound")
    return tuple(sorted(files))


def validate_clone_input(clone: GitCloneInput) -> Path:
    """Require a tracked-only, secret-free normal clone before ``--clone``.

    The caller must collect tracked/untracked evidence using its hardened Git
    controller.  This function deliberately does not run Git or accept a
    generated archive; it validates a narrow, read-only clone mount contract.
    """

    root = clone.root
    if not root.is_absolute() or root != root.resolve():
        raise SbxAdmissionError("clone root must be a canonical absolute directory")
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise SbxAdmissionError("clone root cannot be inspected") from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) & 0o077
    ):
        raise SbxAdmissionError("clone root must be a real directory")
    git_dir = root / ".git"
    try:
        git_stat = git_dir.lstat()
    except OSError as exc:
        raise SbxAdmissionError("clone lacks a normal .git directory") from exc
    if (
        stat.S_ISLNK(git_stat.st_mode)
        or not stat.S_ISDIR(git_stat.st_mode)
        or git_stat.st_uid != os.getuid()
        or stat.S_IMODE(git_stat.st_mode) & 0o022
    ):
        raise SbxAdmissionError("clone .git must be a directory, not a worktree link")
    if clone.untracked_paths:
        raise SbxAdmissionError("clone contains untracked or ignored input")
    if not clone.tracked_paths:
        raise SbxAdmissionError("clone has no tracked input")
    normalized_tracked = tuple(_normal_relative_path(value) for value in clone.tracked_paths)
    if len(normalized_tracked) > MAX_SOURCE_FILES:
        raise SbxAdmissionError("clone tracked path count exceeds its bound")
    if tuple(sorted(normalized_tracked)) != _enumerate_worktree_files(root):
        raise SbxAdmissionError("tracked manifest does not exactly cover the staged worktree")
    total = 0
    seen: set[str] = set()
    for relative in normalized_tracked:
        if relative in seen:
            raise SbxAdmissionError("clone tracked path list contains a duplicate")
        seen.add(relative)
        if _SENSITIVE_PATH.search(relative) is not None:
            raise SbxAdmissionError("clone contains a sensitive tracked filename")
        path = root / relative
        try:
            entry = path.lstat()
        except OSError as exc:
            raise SbxAdmissionError("tracked path cannot be inspected") from exc
        if (
            stat.S_ISLNK(entry.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or entry.st_uid != os.getuid()
            or entry.st_nlink != 1
            or stat.S_IMODE(entry.st_mode) & 0o022
        ):
            raise SbxAdmissionError("tracked input must contain regular non-symlink files")
        if entry.st_size > MAX_SOURCE_FILE_BYTES:
            raise SbxAdmissionError("tracked source file exceeds sandbox input bound")
        total += entry.st_size
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise SbxAdmissionError("tracked source total exceeds sandbox input bound")
        content = _source_file_bytes(path, entry)
        if any(pattern.search(content) is not None for pattern in _SECRET_PATTERNS):
            raise SbxAdmissionError("tracked source appears to contain a secret")
    try:
        final_root = root.lstat()
    except OSError as exc:
        raise SbxAdmissionError("clone root changed while scanning") from exc
    if (final_root.st_dev, final_root.st_ino, final_root.st_mtime_ns, final_root.st_ctime_ns) != (
        root_stat.st_dev,
        root_stat.st_ino,
        root_stat.st_mtime_ns,
        root_stat.st_ctime_ns,
    ):
        raise SbxAdmissionError("clone root changed while scanning")
    return root


def _parse_identity(raw: bytes, *, binary: Path, sha256: str) -> SbxIdentity:
    if not raw or len(raw) > MAX_IDENTITY_OUTPUT_BYTES:
        raise SbxAdmissionError("sbx identity output is absent or oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SbxAdmissionError("sbx identity output is not UTF-8") from exc
    match = re.fullmatch(
        r"sbx version: (v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?) "
        r"([a-f0-9]{7,64})\r?\n?",
        text,
    )
    if match is None:
        raise SbxAdmissionError("sbx identity output has an unexpected schema")
    try:
        return SbxIdentity(binary, match.group(1), match.group(2), sha256)
    except ValueError as exc:
        raise SbxAdmissionError("sbx identity output is invalid") from exc


def _parse_sandbox_names(raw: bytes) -> frozenset[str]:
    if len(raw) > MAX_CLI_OUTPUT_BYTES:
        raise SbxAdmissionError("sbx quiet-list output is oversized")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SbxAdmissionError("sbx quiet-list output is not UTF-8") from exc
    names: set[str] = set()
    for name in lines:
        if (
            not name
            or len(name) > 128
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}", name) is None
        ):
            raise SbxAdmissionError("sbx quiet-list item has an unexpected shape")
        if name in names:
            raise SbxAdmissionError("sbx list output contains duplicate names")
        names.add(name)
    return frozenset(names)


class SbxBoundary:
    """Source-disabled production facade.  It performs no command I/O."""

    def provision(self, *_args: object, **_kwargs: object) -> SbxProvisionReceipt:
        raise SbxExecutionDisabled(
            "Docker Sandboxes execution is source-disabled pending live boundary evidence"
        )


class FixtureSbxBoundary:
    """Deterministic fake-executor implementation of the proposed lifecycle."""

    def __init__(
        self,
        capability: FixtureSbxCapability,
        *,
        expected_identity: SbxIdentity,
        observed_binary_sha256: str,
        executor: CommandExecutor,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = MAX_CLI_OUTPUT_BYTES,
    ) -> None:
        if capability is not _FIXTURE_CAPABILITY:
            raise SbxError("fixture sbx capability is invalid")
        if type(timeout_seconds) not in (int, float) or timeout_seconds <= 0:
            raise ValueError("sbx command timeout must be positive")
        if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_CLI_OUTPUT_BYTES:
            raise ValueError("sbx output bound is invalid")
        if _HEX64.fullmatch(observed_binary_sha256) is None:
            raise ValueError("observed sbx binary SHA-256 is invalid")
        self._identity = expected_identity
        self._observed_binary_sha256 = observed_binary_sha256
        self._executor = executor
        self._timeout = float(timeout_seconds)
        self._max_output = max_output_bytes

    def _invoke(
        self, argv: tuple[str, ...], env: Mapping[str, str], *, identity: bool = False
    ) -> SbxCommandResult:
        if not argv or argv[0] != str(self._identity.binary):
            raise SbxAdmissionError("sbx argv does not use the pinned binary")
        result = self._executor(
            argv, env, self._timeout, MAX_IDENTITY_OUTPUT_BYTES if identity else self._max_output
        )
        if not isinstance(result, SbxCommandResult):
            raise SbxAdmissionError("sbx executor returned an invalid result")
        cap = MAX_IDENTITY_OUTPUT_BYTES if identity else self._max_output
        if (
            result.timed_out
            or result.output_truncated
            or len(result.stdout) > cap
            or len(result.stderr) > cap
        ):
            raise SbxAdmissionError("sbx command timed out or exceeded its output bound")
        return result

    def _admit(self, env: Mapping[str, str]) -> None:
        # The controller obtains this evidence from an independently reviewed,
        # no-follow digest operation before constructing this boundary.  The
        # command executor is intentionally never asked to run a shell or an
        # arbitrary hash command.
        if self._observed_binary_sha256 != self._identity.sha256:
            raise SbxAdmissionError("sbx binary SHA-256 identity mismatch")
        probe = self._invoke((str(self._identity.binary), "version"), env, identity=True)
        if probe.returncode != 0:
            raise SbxAdmissionError("sbx identity probe failed")
        observed = _parse_identity(
            probe.stdout, binary=self._identity.binary, sha256=self._identity.sha256
        )
        if observed != self._identity:
            raise SbxAdmissionError("sbx binary/version/revision identity mismatch")

    def _list(self, env: Mapping[str, str]) -> frozenset[str]:
        result = self._invoke((str(self._identity.binary), "ls", "--quiet"), env)
        if result.returncode != 0:
            raise SbxAdmissionError("sbx list failed; sandbox state is unknown")
        return _parse_sandbox_names(result.stdout)

    def provision(
        self, *, run_nonce: str, clone: GitCloneInput, ambient: Mapping[str, str]
    ) -> SbxProvisionReceipt:
        """Create one named private clone sandbox with no caller-provided args."""

        name = controller_sandbox_name(run_nonce)
        env = _host_environment(ambient)
        self._admit(env)
        names = self._list(env)
        if name in names:
            raise SbxAdmissionError("controller-derived sandbox name already exists")
        root = validate_clone_input(clone)
        # This is the complete create surface.  Never add agent-owned argv,
        # template/profile/kit/port flags, another workspace, or a shell.
        argv = (
            str(self._identity.binary),
            "create",
            "--clone",
            "--name",
            name,
            "--cpus",
            "2",
            "--memory",
            "4g",
            "codex",
            str(root),
        )
        result = self._invoke(argv, env)
        if result.returncode != 0:
            raise SbxAdmissionError("sbx create failed")
        return SbxProvisionReceipt(name, argv, self._identity)

    def cleanup(self, *, name: str, ambient: Mapping[str, str]) -> SbxCleanupReceipt:
        """Stop, remove, and prove absence of exactly one controller-owned name."""

        _require_name(name)
        env = _host_environment(ambient)
        stop_code: int | None = None
        remove_code: int | None = None
        errors: list[str] = []
        try:
            stop = self._invoke((str(self._identity.binary), "stop", name), env)
            stop_code = stop.returncode
            if stop.returncode != 0:
                errors.append("stop failed")
        except SbxAdmissionError:
            errors.append("stop ambiguous")
        try:
            remove = self._invoke((str(self._identity.binary), "rm", "--force", name), env)
            remove_code = remove.returncode
            if remove.returncode != 0:
                errors.append("remove failed")
        except SbxAdmissionError:
            errors.append("remove ambiguous")
        absent = False
        try:
            absent = name not in self._list(env)
        except SbxAdmissionError:
            errors.append("final list ambiguous")
        receipt = SbxCleanupReceipt(
            name=name,
            state="cleaned" if absent and not errors else "cleanup_pending",
            stop_returncode=stop_code,
            remove_returncode=remove_code,
            final_absent=absent,
        )
        if receipt.state != "cleaned":
            raise SbxCleanupPending("; ".join(errors) or "cleanup absence is unproven")
        return receipt
