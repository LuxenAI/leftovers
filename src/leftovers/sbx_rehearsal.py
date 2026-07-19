"""Non-production compatibility rehearsal for Docker Sandboxes.

This module deliberately proves only a very small, disposable ``sbx``
contract.  It never starts an AI agent, never creates a network policy or a
secret, and never passes a GitHub/SSH/provider credential to a sandbox.  It is
not wired into ``leftovers run`` and is not production-isolation evidence.

The real value of the rehearsal is negative evidence: before an execution
backend is considered, the controller can demonstrate that its exact ``sbx``
installation has the expected identity and policy, that clone mode is private,
and that one named sandbox can be removed and proven absent again.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .sbx import (
    MAX_CLI_OUTPUT_BYTES,
    SbxAdmissionError,
    SbxCommandResult,
    SbxIdentity,
    _host_environment,
    _parse_identity,
    _parse_sandbox_names,
    controller_sandbox_name,
)

_MAX_DOCTOR_OUTPUT: Final = 16 * 1024
_MAX_ENV_OUTPUT: Final = 64 * 1024
_STREAM_CHUNK_BYTES: Final = 8 * 1024
_TERMINATE_GRACE_SECONDS: Final = 1.0
_FIXTURE_PREFIX: Final = "leftovers-sbx-rehearsal-"
_FIXTURE_SENTINEL: Final = ".leftovers-sbx-fixture"
_VM_MARKER: Final = ".leftovers-vm-only-marker"
_OPENAI_ALLOW: Final = (
    "https://api.openai.com",
    "https://openai.com",
    "https://chatgpt.com",
    "https://www.chatgpt.com",
)
_NETWORK_DENY: Final = (
    "http://api.openai.com",
    "https://api.openai.com:8443",
    "https://api.github.com",
    "https://github.com",
    "https://raw.githubusercontent.com",
    "https://gist.github.com",
    "https://objects.githubusercontent.com",
    "https://copilot.github.com",
    "https://api.githubcopilot.com",
    "https://registry.npmjs.org",
    "https://pypi.org",
    "https://crates.io",
    "https://rubygems.org",
    "https://repo1.maven.org",
    "https://registry-1.docker.io",
    "https://evil.example",
    "https://example.invalid",
    "https://127.0.0.1",
    "https://[::1]",
    "https://169.254.169.254",
    "https://metadata.google.internal",
)
_SECRET_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ALLOWED_SANDBOX_ENV_KEYS: Final = frozenset(
    {
        "HOME",
        "HOSTNAME",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "PATH",
        "PWD",
        "SHELL",
        "SHLVL",
        "TERM",
        "USER",
        "_",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    }
)
_DENIED_ENV_EXACT: Final = frozenset(
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
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "CODEX_API_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }
)
_DENIED_ENV_PREFIXES: Final = (
    "SSH_",
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
)


class SbxRehearsalError(RuntimeError):
    """The non-production ``sbx`` compatibility contract was not proven."""


class SbxRehearsalCleanupPending(SbxRehearsalError):
    """A sandbox or fixture boundary is ambiguous and must be retained."""


CommandExecutor = Callable[[tuple[str, ...], Mapping[str, str], float, int], SbxCommandResult]
FixtureBuilder = Callable[[Path, str], Path]
BinaryDigest = Callable[[Path], str]


@dataclass(frozen=True)
class SbxDoctorReceipt:
    """Credential-free facts established by read-only CLI probes."""

    identity: SbxIdentity
    sandbox_names: frozenset[str]
    openai_secret_configured: bool
    github_secret_configured: bool


@dataclass(frozen=True)
class SbxRehearsalReceipt:
    """A bounded, non-production lifecycle result.

    ``fixture_path`` is retained whenever cleanup is not proven.  Callers must
    treat ``cleanup_pending`` as a hard stop rather than deleting it broadly.
    """

    state: str
    doctor: SbxDoctorReceipt
    name: str | None
    fixture_path: Path | None
    final_absent: bool


def _default_digest(path: Path) -> str:
    """Hash one normal, non-symlink executable without retaining its bytes."""

    try:
        entry = path.lstat()
    except OSError as exc:
        raise SbxRehearsalError("pinned sbx binary cannot be inspected") from exc
    if (
        stat.S_ISLNK(entry.st_mode)
        or not stat.S_ISREG(entry.st_mode)
        or entry.st_nlink != 1
        or entry.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(entry.st_mode) & 0o022
    ):
        raise SbxRehearsalError("pinned sbx binary must be a single-link regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SbxRehearsalError(
            "pinned sbx binary cannot be opened without following links"
        ) from exc
    try:
        held = os.fstat(fd)
        identity = (
            entry.st_dev,
            entry.st_ino,
            entry.st_mode,
            entry.st_uid,
            entry.st_gid,
            entry.st_size,
            entry.st_nlink,
            entry.st_mtime_ns,
            entry.st_ctime_ns,
        )
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
            raise SbxRehearsalError("pinned sbx binary changed while hashing")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 128 * 1024)
            if not block:
                break
            digest.update(block)
        after_held = os.fstat(fd)
        try:
            after_path = path.lstat()
        except OSError as exc:
            raise SbxRehearsalError("pinned sbx binary path changed while hashing") from exc
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
                raise SbxRehearsalError("pinned sbx binary changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _subprocess_executor(
    argv: tuple[str, ...], env: Mapping[str, str], timeout: float, cap: int
) -> SbxCommandResult:
    """Run a fixed argv with bounded streaming capture and session cleanup.

    The public probe accepts an injected executor so unit tests never execute
    ``sbx``.  This conservative default is intentionally not a general shell
    runner: no ``cwd``, stdin, shell, inherited environment, or extra fds are
    accepted.
    """

    if type(timeout) not in (int, float) or timeout <= 0 or type(cap) is not int or cap < 1:
        raise ValueError("subprocess executor requires a positive timeout and output cap")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            close_fds=True,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        return SbxCommandResult(-1, b"", str(exc).encode("utf-8", "replace")[:cap])
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen invariant
        _terminate_session(process)
        return SbxCommandResult(-1, b"", b"pipe allocation failed", timed_out=True)

    streams = {"stdout": process.stdout, "stderr": process.stderr}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = False
    output_truncated = False
    reaped = False
    selector = selectors.DefaultSelector()
    try:
        for label, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = time.monotonic() + float(timeout)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                # ``select`` can wake spuriously; only the monotonic deadline
                # decides whether an idle descendant-held pipe is a timeout.
                continue
            for key, _mask in events:
                label = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), _STREAM_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                except OSError:
                    timed_out = True
                    break
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                captured_total = len(captured["stdout"]) + len(captured["stderr"])
                available = cap - captured_total
                if len(chunk) > available:
                    if available > 0:
                        captured[label].extend(chunk[:available])
                    output_truncated = True
                    break
                captured[label].extend(chunk)
            if timed_out or output_truncated:
                break
        if not timed_out and not output_truncated:
            # EOF is not process completion: a child can close both capture
            # pipes and continue running forever.  Keep the original monotonic
            # deadline authoritative for the direct child too.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out = True
        # Always reconcile the whole session.  Even a normally exited direct
        # child may have left same-session descendants that closed the capture
        # pipes.  No command result is returned while that group is live.
        _terminate_session(process)
        reaped = True
    finally:
        # A timeout or overflow may leave descendants holding the write end of
        # a pipe.  Closing controller FDs and the selector is unconditional;
        # no descriptor keeps the caller alive after this function returns.
        try:
            if not reaped:
                _terminate_session(process)
        finally:
            for stream in streams.values():
                with suppress(KeyError, ValueError):
                    selector.unregister(stream)
                with suppress(OSError):
                    stream.close()
            selector.close()
    return SbxCommandResult(
        process.returncode if process.returncode is not None else -1,
        bytes(captured["stdout"]),
        bytes(captured["stderr"]),
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


def _terminate_session(process: subprocess.Popen[bytes]) -> None:
    """TERM then KILL one process session and reap its direct child.

    ``start_new_session=True`` makes the direct child's PID its process-group
    ID.  A descendant that retains a capture pipe is therefore stopped before
    the parent process is reaped.  Failure to find the group is benign only
    after the direct child has already exited.
    """

    def group_alive() -> bool:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
            else:
                return False
            raise SbxRehearsalError("cannot inspect the rehearsal process group") from exc
        return True

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        try:
            process.wait(timeout=0.05)
        except subprocess.TimeoutExpired:
            raise SbxRehearsalError("cannot terminate the rehearsal process group") from exc
    deadline = time.monotonic() + _TERMINATE_GRACE_SECONDS
    while group_alive() and time.monotonic() < deadline:
        time.sleep(0.02)
    if group_alive():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                raise SbxRehearsalError("cannot kill the rehearsal process group") from exc
        kill_deadline = time.monotonic() + _TERMINATE_GRACE_SECONDS
        while group_alive() and time.monotonic() < kill_deadline:
            time.sleep(0.02)
        if group_alive():
            raise SbxRehearsalError("rehearsal process group cleanup is unproven")
    # Reap the direct child even when a descendant kept the group alive after
    # the leader exited. No caller proceeds while the leader is a zombie.
    process.wait(timeout=_TERMINATE_GRACE_SECONDS)


def _private_root_identity(private_root: Path) -> tuple[int, int, int, int, int]:
    """Require one canonical owner-private directory for rehearsal state."""

    if not private_root.is_absolute() or private_root != private_root.resolve():
        raise SbxRehearsalError("private fixture root must be a canonical absolute path")
    try:
        entry = private_root.lstat()
    except OSError as exc:
        raise SbxRehearsalError("private fixture root cannot be inspected") from exc
    if (
        stat.S_ISLNK(entry.st_mode)
        or not stat.S_ISDIR(entry.st_mode)
        or entry.st_uid != os.getuid()
        or stat.S_IMODE(entry.st_mode) != 0o700
    ):
        raise SbxRehearsalError("private fixture root must be an owner-only real directory")
    return (entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid, entry.st_gid)


def _git_fixture(private_root: Path, name: str) -> Path:
    """Create a controller-owned normal Git clone input under ``private_root``."""

    root_identity = _private_root_identity(private_root)
    fixture = private_root / (_FIXTURE_PREFIX + name)
    if fixture.exists() or fixture.is_symlink():
        raise SbxRehearsalError("controller fixture path already exists")
    fixture.mkdir(mode=0o700)
    git_env = {"HOME": str(fixture), "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"}
    commands = (
        ("/usr/bin/git", "init", "--initial-branch=main", str(fixture)),
        ("/usr/bin/git", "-C", str(fixture), "config", "user.name", "Leftovers Rehearsal"),
        ("/usr/bin/git", "-C", str(fixture), "config", "user.email", "leftovers-rehearsal@invalid"),
    )
    try:
        for argv in commands:
            completed = subprocess.run(
                argv,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=git_env,
                close_fds=True,
                shell=False,
                timeout=20,
            )
            if completed.returncode != 0:
                raise SbxRehearsalError("controller could not initialize Git fixture")
        (fixture / "README.md").write_text(
            "Leftovers Docker Sandboxes rehearsal fixture\n", encoding="utf-8"
        )
        (fixture / _FIXTURE_SENTINEL).write_text(name + "\n", encoding="ascii")
        for argv in (
            ("/usr/bin/git", "-C", str(fixture), "add", "--", "README.md", _FIXTURE_SENTINEL),
            (
                "/usr/bin/git",
                "-C",
                str(fixture),
                "commit",
                "--no-gpg-sign",
                "-m",
                "leftovers sbx rehearsal fixture",
            ),
            (
                "/usr/bin/git",
                "-C",
                str(fixture),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ),
        ):
            completed = subprocess.run(
                argv,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=git_env,
                close_fds=True,
                shell=False,
                timeout=20,
            )
            if completed.returncode != 0:
                raise SbxRehearsalError("controller could not seal Git fixture")
            if argv[-1] == "--untracked-files=all" and completed.stdout:
                raise SbxRehearsalError("controller Git fixture is not tracked-only")
        if _private_root_identity(private_root) != root_identity:
            raise SbxRehearsalError("private fixture root changed during setup")
    except BaseException:
        # Fixture setup precedes an sbx create.  It is safe to remove only the
        # direct, sentinel-marked child we just made.
        _remove_fixture(fixture, private_root, name)
        raise
    return fixture


def _remove_fixture(fixture: Path, private_root: Path, name: str) -> None:
    """Remove one marker-checked child through an owner-private root FD."""

    if fixture.parent != private_root or fixture.name != _FIXTURE_PREFIX + name:
        raise SbxRehearsalError("fixture cleanup path escaped its private root")
    root_identity = _private_root_identity(private_root)
    if not shutil.rmtree.avoids_symlink_attacks:
        raise SbxRehearsalError("fixture cleanup lacks descriptor-relative symlink protection")
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(private_root, root_flags)
    except OSError as exc:
        raise SbxRehearsalError("fixture cleanup cannot open its private root") from exc
    fixture_fd = -1
    sentinel_fd = -1
    try:
        held_root = os.fstat(root_fd)
        if (
            held_root.st_dev,
            held_root.st_ino,
            held_root.st_mode,
            held_root.st_uid,
            held_root.st_gid,
        ) != root_identity:
            raise SbxRehearsalError("private fixture root changed before cleanup")
        try:
            fixture_fd = os.open(fixture.name, root_flags, dir_fd=root_fd)
            path_entry = os.stat(fixture.name, dir_fd=root_fd, follow_symlinks=False)
        except OSError as exc:
            raise SbxRehearsalError("fixture cleanup cannot hold its marked child") from exc
        held_entry = os.fstat(fixture_fd)
        child_identity = (
            held_entry.st_dev,
            held_entry.st_ino,
            held_entry.st_mode,
            held_entry.st_uid,
            held_entry.st_gid,
        )
        if (
            path_entry.st_dev,
            path_entry.st_ino,
            path_entry.st_mode,
            path_entry.st_uid,
            path_entry.st_gid,
        ) != child_identity or held_entry.st_uid != os.getuid():
            raise SbxRehearsalError("fixture cleanup child identity is unstable")
        sentinel_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            sentinel_fd = os.open(_FIXTURE_SENTINEL, sentinel_flags, dir_fd=fixture_fd)
            sentinel_entry = os.fstat(sentinel_fd)
            sentinel = os.read(sentinel_fd, 512)
            sentinel_extra = os.read(sentinel_fd, 1)
        except OSError as exc:
            raise SbxRehearsalError("fixture cleanup cannot verify its marker") from exc
        if (
            not stat.S_ISREG(sentinel_entry.st_mode)
            or sentinel_entry.st_uid != os.getuid()
            or sentinel_entry.st_nlink != 1
            or stat.S_IMODE(sentinel_entry.st_mode) & 0o022
            or sentinel != (name + "\n").encode("ascii")
            or sentinel_extra
        ):
            raise SbxRehearsalError("fixture cleanup ownership marker is invalid")
        current_entry = os.stat(fixture.name, dir_fd=root_fd, follow_symlinks=False)
        if (
            current_entry.st_dev,
            current_entry.st_ino,
            current_entry.st_mode,
            current_entry.st_uid,
            current_entry.st_gid,
        ) != child_identity:
            raise SbxRehearsalError("fixture cleanup child changed before removal")
        shutil.rmtree(fixture.name, dir_fd=root_fd)
        try:
            os.stat(fixture.name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SbxRehearsalError("fixture cleanup absence is ambiguous") from exc
        else:
            raise SbxRehearsalError("fixture cleanup absence is unproven")
    finally:
        if sentinel_fd >= 0:
            os.close(sentinel_fd)
        if fixture_fd >= 0:
            os.close(fixture_fd)
        os.close(root_fd)


def _parse_policy(raw: bytes) -> bool:
    if not raw or len(raw) > _MAX_DOCTOR_OUTPUT:
        raise SbxRehearsalError("network policy output is absent or oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbxRehearsalError("network policy output is not canonical JSON") from exc
    if (
        not isinstance(value, dict)
        or type(value.get("allowed")) is not bool
        or value.get("action") != "net:connect:tcp"
        or value.get("type") != "network"
        or len(value) > 16
        or any(not isinstance(key, str) or len(key) > 64 for key in value)
    ):
        raise SbxRehearsalError("network policy JSON does not state one boolean decision")
    return value["allowed"]


def _parse_secret_inventory(raw: bytes) -> frozenset[tuple[str, str, str]]:
    """Read bounded secret metadata while discarding masked value columns."""

    if len(raw) > _MAX_DOCTOR_OUTPUT:
        raise SbxRehearsalError("global secret list is oversized")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SbxRehearsalError("global secret list is not UTF-8") from exc
    if not lines:
        raise SbxRehearsalError("global secret list has no table header")
    header = lines[0].split()
    if header != ["SCOPE", "TYPE", "NAME", "SECRET"]:
        raise SbxRehearsalError("secret list has an unexpected table schema")
    inventory: set[tuple[str, str, str]] = set()
    for line in lines[1:]:
        columns = line.split()
        if (
            len(columns) != 4
            or not columns[0]
            or len(columns[0]) > 160
            or re.fullmatch(r"[a-z][a-z-]{0,31}", columns[1]) is None
            or _SECRET_NAME.fullmatch(columns[2]) is None
            or not columns[3]
            or len(columns[3]) > 512
        ):
            raise SbxRehearsalError("secret list contains invalid metadata")
        item = (columns[0], columns[1].lower(), columns[2].lower())
        if item in inventory:
            raise SbxRehearsalError("secret list contains duplicate metadata")
        inventory.add(item)
    return frozenset(inventory)


def _parse_env_keys(raw: bytes) -> frozenset[str]:
    if not raw or len(raw) > _MAX_ENV_OUTPUT or not raw.endswith(b"\0"):
        raise SbxRehearsalError("sandbox environment output is absent, oversized, or malformed")
    keys: set[str] = set()
    for entry in raw[:-1].split(b"\0"):
        try:
            key, value = entry.split(b"=", 1)
            key_text = key.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SbxRehearsalError("sandbox environment contains a malformed variable") from exc
        if (
            _ENV_KEY.fullmatch(key_text) is None
            or key_text in keys
            or key_text not in _ALLOWED_SANDBOX_ENV_KEYS
            or len(value) > 4_096
            or b"\n" in value
            or b"\r" in value
        ):
            raise SbxRehearsalError("sandbox environment contains an invalid variable name")
        upper = key_text.upper()
        if (
            upper in _DENIED_ENV_EXACT
            or upper.startswith(_DENIED_ENV_PREFIXES)
            or upper.endswith("_PROXY")
            or upper.endswith("_TOKEN")
            or upper.endswith("_API_KEY")
        ):
            raise SbxRehearsalError(f"sandbox inherited forbidden authority: {key_text}")
        keys.add(key_text)
    return frozenset(keys)


class SbxCompatibilityProbe:
    """Read-only doctor plus explicit, no-agent clone lifecycle rehearsal."""

    def __init__(
        self,
        *,
        expected_identity: SbxIdentity,
        ambient: Mapping[str, str],
        executor: CommandExecutor | None = None,
        binary_digest: BinaryDigest | None = None,
        fixture_builder: FixtureBuilder | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        if expected_identity.version != "v0.35.0":
            raise ValueError("the compatibility rehearsal is pinned to sbx v0.35.0")
        if type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 120:
            raise ValueError("sbx rehearsal timeout must be between one and 120 seconds")
        self._identity = expected_identity
        self._ambient = dict(ambient)
        self._executor = executor if executor is not None else _subprocess_executor
        self._binary_digest = binary_digest if binary_digest is not None else _default_digest
        self._fixture_builder = fixture_builder if fixture_builder is not None else _git_fixture
        self._timeout = float(timeout_seconds)

    def _invoke(
        self, argv: tuple[str, ...], env: Mapping[str, str], *, cap: int = MAX_CLI_OUTPUT_BYTES
    ) -> SbxCommandResult:
        if not argv or argv[0] != str(self._identity.binary):
            raise SbxRehearsalError("rehearsal attempted an unpinned sbx binary")
        try:
            result = self._executor(argv, env, self._timeout, cap)
        except BaseException as exc:
            raise SbxRehearsalError("sbx command executor failed") from exc
        if not isinstance(result, SbxCommandResult):
            raise SbxRehearsalError("sbx command executor returned an invalid result")
        if (
            result.timed_out
            or result.output_truncated
            or len(result.stdout) > cap
            or len(result.stderr) > cap
        ):
            raise SbxRehearsalError("sbx command timed out or exceeded its output bound")
        return result

    def _assert_binary_identity(self) -> None:
        try:
            observed_digest = self._binary_digest(self._identity.binary)
        except BaseException as exc:
            if isinstance(exc, SbxRehearsalError):
                raise
            raise SbxRehearsalError("sbx binary digest could not be established") from exc
        if observed_digest != self._identity.sha256:
            raise SbxRehearsalError("pinned sbx binary digest mismatch")

    def doctor(self) -> SbxDoctorReceipt:
        """Verify identity, authentication/state, policy, and secret metadata."""

        env = _host_environment(self._ambient)
        self._assert_binary_identity()
        version = self._invoke((str(self._identity.binary), "version"), env, cap=_MAX_DOCTOR_OUTPUT)
        if version.returncode != 0:
            raise SbxRehearsalError("sbx version probe failed")
        try:
            observed_identity = _parse_identity(
                version.stdout, binary=self._identity.binary, sha256=self._identity.sha256
            )
        except SbxAdmissionError as exc:
            raise SbxRehearsalError("sbx version output is invalid") from exc
        if observed_identity != self._identity:
            raise SbxRehearsalError("sbx version/revision identity mismatch")
        self._assert_binary_identity()
        listed = self._invoke((str(self._identity.binary), "ls", "--quiet"), env)
        if listed.returncode != 0:
            raise SbxRehearsalError("sbx authentication or sandbox state is unavailable")
        try:
            names = _parse_sandbox_names(listed.stdout)
        except SbxAdmissionError as exc:
            raise SbxRehearsalError("sbx sandbox listing is malformed") from exc
        for target in _OPENAI_ALLOW:
            result = self._invoke(
                (str(self._identity.binary), "policy", "check", "network", "--json", target),
                env,
                cap=_MAX_DOCTOR_OUTPUT,
            )
            if result.returncode != 0 or not _parse_policy(result.stdout):
                raise SbxRehearsalError("required OpenAI network target is not explicitly allowed")
        for target in _NETWORK_DENY:
            result = self._invoke(
                (str(self._identity.binary), "policy", "check", "network", "--json", target),
                env,
                cap=_MAX_DOCTOR_OUTPUT,
            )
            if result.returncode == 0 or _parse_policy(result.stdout):
                raise SbxRehearsalError(
                    "GitHub, package, or arbitrary network target is not denied"
                )
        secrets = self._invoke(
            (str(self._identity.binary), "secret", "ls", "--global"), env, cap=_MAX_DOCTOR_OUTPUT
        )
        if secrets.returncode != 0:
            raise SbxRehearsalError("global secret metadata is unavailable")
        inventory = _parse_secret_inventory(secrets.stdout)
        if inventory != frozenset({("(global)", "service", "openai")}):
            raise SbxRehearsalError(
                "global secret inventory must contain only the OpenAI service credential"
            )
        return SbxDoctorReceipt(self._identity, names, True, False)

    @staticmethod
    def _listed_names(raw: bytes) -> frozenset[str]:
        try:
            return _parse_sandbox_names(raw)
        except SbxAdmissionError as exc:
            raise SbxRehearsalError("sbx sandbox listing is malformed") from exc

    def rehearse(
        self,
        *,
        private_temp_root: Path,
        run_nonce: str,
        execute: bool = False,
    ) -> SbxRehearsalReceipt:
        """Optionally create and remove one private clone VM without an agent.

        ``execute=False`` is a doctor-only result.  ``execute=True`` is the
        explicit operator action required before any local fixture or sandbox
        state is created.
        """

        if type(execute) is not bool:
            raise ValueError("execute must be an explicit boolean")
        doctor = self.doctor()
        if not execute:
            return SbxRehearsalReceipt("doctor_only", doctor, None, None, False)
        root_identity = _private_root_identity(private_temp_root)
        name = controller_sandbox_name(run_nonce)
        if name in doctor.sandbox_names:
            raise SbxRehearsalError(
                "controller-derived rehearsal sandbox already exists; choose a fresh run ID"
            )
        scoped_secrets = self._invoke(
            (str(self._identity.binary), "secret", "ls", name),
            _host_environment(self._ambient),
            cap=_MAX_DOCTOR_OUTPUT,
        )
        if scoped_secrets.returncode != 0:
            raise SbxRehearsalError("sandbox-scoped secret metadata is unavailable")
        scoped_inventory = _parse_secret_inventory(scoped_secrets.stdout)
        if scoped_inventory - {("(global)", "service", "openai")}:
            raise SbxRehearsalError("fresh rehearsal name has additional scoped secret authority")
        fixture = self._fixture_builder(private_temp_root, name)
        if fixture.parent != private_temp_root or fixture.name != _FIXTURE_PREFIX + name:
            raise SbxRehearsalError("fixture builder returned a path outside the private root")
        if _private_root_identity(private_temp_root) != root_identity:
            raise SbxRehearsalError("private fixture root changed before sandbox creation")
        env = _host_environment(self._ambient)
        create_attempted = False
        created = False
        ambiguous = False
        failure: SbxRehearsalError | None = None
        final_absent = False
        try:
            create_attempted = True
            self._assert_binary_identity()
            create = self._invoke(
                (
                    str(self._identity.binary),
                    "create",
                    "--clone",
                    "--name",
                    name,
                    "--cpus",
                    "1",
                    "--memory",
                    "1g",
                    "shell",
                    str(fixture),
                ),
                env,
            )
            if create.returncode != 0:
                raise SbxRehearsalError("sbx create failed")
            self._assert_binary_identity()
            created = True
            listed = self._invoke((str(self._identity.binary), "ls", "--quiet"), env)
            try:
                listed_names = self._listed_names(listed.stdout)
            except SbxRehearsalError:
                ambiguous = True
                raise
            if listed.returncode != 0 or name not in listed_names:
                ambiguous = True
                raise SbxRehearsalError(
                    "created sandbox is not exactly present in the state listing"
                )
            ports = self._invoke(
                (str(self._identity.binary), "ports", name, "--json"), env, cap=_MAX_DOCTOR_OUTPUT
            )
            if ports.returncode != 0:
                ambiguous = True
                raise SbxRehearsalError("sandbox ports cannot be inspected")
            try:
                port_value = json.loads(ports.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                ambiguous = True
                raise SbxRehearsalError("sandbox ports output is not JSON") from exc
            if port_value != []:
                ambiguous = True
                raise SbxRehearsalError("sandbox exposes one or more ports")
            sandbox_env = self._invoke(
                (str(self._identity.binary), "exec", name, "env", "-0"), env, cap=_MAX_ENV_OUTPUT
            )
            if sandbox_env.returncode != 0:
                ambiguous = True
                raise SbxRehearsalError("sandbox environment cannot be inspected")
            try:
                _parse_env_keys(sandbox_env.stdout)
            except SbxRehearsalError:
                ambiguous = True
                raise
            source_probe = "/run/sandbox/source/.leftovers-source-write-probe"
            source_sentinel = fixture / _FIXTURE_SENTINEL
            try:
                before_sentinel = source_sentinel.read_bytes()
            except OSError as exc:
                ambiguous = True
                raise SbxRehearsalError("host source sentinel cannot be read safely") from exc
            source_write = self._invoke(
                (str(self._identity.binary), "exec", name, "touch", source_probe), env
            )
            if source_write.returncode == 0:
                ambiguous = True
                raise SbxRehearsalError("sandbox unexpectedly wrote to the source mount")
            host_source_probe = fixture / ".leftovers-source-write-probe"
            try:
                host_source_probe.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                ambiguous = True
                raise SbxRehearsalError("host source write probe is ambiguous") from exc
            else:
                ambiguous = True
                raise SbxRehearsalError("source mount write attempt reached the host fixture")
            try:
                sentinel_unchanged = source_sentinel.read_bytes() == before_sentinel
            except OSError as exc:
                ambiguous = True
                raise SbxRehearsalError("host source sentinel cannot be re-read safely") from exc
            if not sentinel_unchanged:
                ambiguous = True
                raise SbxRehearsalError("source mount write attempt changed the host fixture")
            clone_writable = self._invoke(
                (str(self._identity.binary), "exec", name, "test", "-w", str(fixture)), env
            )
            if clone_writable.returncode != 0:
                ambiguous = True
                raise SbxRehearsalError("private same-path clone was not writable")
            marker = str(fixture / _VM_MARKER)
            write_marker = self._invoke(
                (str(self._identity.binary), "exec", name, "touch", marker), env
            )
            if write_marker.returncode != 0:
                ambiguous = True
                raise SbxRehearsalError("sandbox could not write its private clone marker")
            if (fixture / _VM_MARKER).exists() or (fixture / _VM_MARKER).is_symlink():
                ambiguous = True
                raise SbxRehearsalError("sandbox marker escaped into the host fixture")
        except SbxRehearsalError as exc:
            failure = exc
        finally:
            if created:
                try:
                    self._assert_binary_identity()
                except SbxRehearsalError:
                    ambiguous = True
                else:
                    for argv in (
                        (str(self._identity.binary), "stop", name),
                        (str(self._identity.binary), "rm", "--force", name),
                    ):
                        try:
                            self._assert_binary_identity()
                        except SbxRehearsalError:
                            ambiguous = True
                            break
                        try:
                            result = self._invoke(argv, env)
                        except SbxRehearsalError:
                            ambiguous = True
                            continue
                        if result.returncode != 0:
                            ambiguous = True
                try:
                    self._assert_binary_identity()
                    listed = self._invoke((str(self._identity.binary), "ls", "--quiet"), env)
                    final_absent = listed.returncode == 0 and name not in self._listed_names(
                        listed.stdout
                    )
                    if not final_absent:
                        ambiguous = True
                except SbxRehearsalError:
                    ambiguous = True
            elif create_attempted:
                # A failed, timed-out, or output-truncated create has no
                # creation-correlated sandbox identity.  Name-only teardown
                # could destroy a foreign sandbox that won a race after the
                # preflight list, so retain the fixture and require operator
                # reconciliation without issuing stop/rm.
                ambiguous = True
        if ambiguous:
            raise SbxRehearsalCleanupPending(
                f"cleanup_pending for {name}; fixture retained at {fixture}"
            ) from failure
        if failure is not None:
            try:
                _remove_fixture(fixture, private_temp_root, name)
            except SbxRehearsalError as exc:
                raise SbxRehearsalCleanupPending(
                    f"cleanup_pending for {name}; fixture retained at {fixture}"
                ) from exc
            raise failure
        try:
            _remove_fixture(fixture, private_temp_root, name)
        except SbxRehearsalError as exc:
            raise SbxRehearsalCleanupPending(
                f"cleanup_pending for {name}; fixture retained at {fixture}"
            ) from exc
        return SbxRehearsalReceipt("rehearsed", doctor, name, None, final_absent)
