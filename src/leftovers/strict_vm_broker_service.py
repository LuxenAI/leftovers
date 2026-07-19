"""Descriptor-owned service primitives for the still-disabled strict-VM broker.

Nothing in this module starts a listener, changes credentials, or invokes the
VM launcher.  It is deliberately useful only to a *future*, separately
installed daemon after that daemon has proved its launchd identity and service
account.  Keeping the operating-system-facing pieces here makes their
properties executable and reviewable without accidentally turning the Python
controller into that daemon.

In particular, a controller supplies protocol bytes only.  It never supplies a
filesystem path, an argv vector, an environment, a resource limit, or a launch
identity.  ``STRICT_VM_BROKER_SERVICE_ENABLED`` is a source release gate, not
a configuration setting.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import re
import stat
import struct
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from .strict_vm_broker import (
    BROKER_FRAME_MAGIC,
    BROKER_PROTOCOL_VERSION,
    MAX_FRAME_BYTES,
    BrokerAuthorizationError,
    BrokerInstallation,
    BrokerProtocolError,
    BrokerReply,
    BrokerUnavailableError,
    StrictVMBrokerAdmission,
    encode_frame,
    peer_from_socket,
)

# These are deliberately independent source gates.  A future review must not
# enable the daemon merely by adding a launchd plist or a configuration value.
STRICT_VM_BROKER_SERVICE_ENABLED = False
STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED = False
STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED = False
STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED = False

_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_FRAME_HEADER = struct.Struct("<4sHHI32s")
_MAX_IO_ATTEMPTS = 4_096
_MAX_LAUNCHER_BYTES = 64 * 1_024 * 1_024
_REQUEST_NAME = "request.lfrq"


class BrokerServiceError(RuntimeError):
    """The future service boundary or its private storage is unsafe."""


class BrokerStorageError(BrokerServiceError):
    """Descriptor-relative storage cannot be proved safe or cleaned up."""


class BrokerCleanupError(BrokerStorageError):
    """A run-owned descriptor tree could not be removed exactly."""


class BrokerCancellationError(BrokerServiceError):
    """The bounded protocol exchange was cancelled before an acknowledgement."""


_FIXTURE_CAPABILITY_SECRET = object()


class FixtureBrokerServiceCapability:
    """Explicit non-production authority for synthetic broker rehearsals.

    Production orchestration must never accept this type.  It carries no
    service, filesystem, launch, provider, or publication authority and is
    issued only by the deliberately named fixture factory below.
    """

    __slots__ = ("_secret",)

    def __init__(self, secret: object) -> None:
        if secret is not _FIXTURE_CAPABILITY_SECRET:
            raise BrokerUnavailableError("fixture broker capability cannot be caller-constructed")
        self._secret = secret


def issue_fixture_broker_service_capability() -> FixtureBrokerServiceCapability:
    """Issue an explicit in-process test capability with no production authority."""

    return FixtureBrokerServiceCapability(_FIXTURE_CAPABILITY_SECRET)


def _require_fixture_capability(capability: FixtureBrokerServiceCapability) -> None:
    if (
        type(capability) is not FixtureBrokerServiceCapability
        or getattr(capability, "_secret", None) is not _FIXTURE_CAPABILITY_SECRET
    ):
        raise BrokerUnavailableError("explicit fixture broker capability is required")


def _require_production_service_enabled() -> None:
    """Reject before any peer, durable-state, descriptor, or verifier access."""

    if not (
        STRICT_VM_BROKER_SERVICE_ENABLED
        and STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED
        and STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED
        and STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED
    ):
        raise BrokerUnavailableError("strict VM broker production service is source-disabled")


class UnixSocket(Protocol):
    """Minimal connected Unix socket surface used by the bounded dispatcher."""

    def recv(self, size: int) -> bytes: ...

    def send(self, data: bytes) -> int: ...

    def getpeereid(self) -> tuple[int, int]: ...


class ControllerCodeSignatureVerifier(Protocol):
    """Darwin-only identity verifier kept outside controller-controlled bytes.

    A production implementation must derive the audit-token/process identity
    from the connected peer, ask Security.framework for the designated
    requirement, and compare it to this installation binding.  UID alone does
    not distinguish hostile code sharing the controller account.
    """

    def verify(self, connection: UnixSocket, binding: ControllerCodeSignatureBinding) -> bool: ...


class DurableBrokerAcknowledgement(Protocol):
    """Broker-private journal+witness transaction required before any reply.

    The implementation must commit the request/reply binding and a matching
    rollback witness durably before returning.  An error means the connection
    receives no acknowledgement; callers may retry but must then encounter
    the durable replay state.  Controller bytes never select this object.
    """

    def commit_before_ack(self, request_frame: bytes, reply: BrokerReply) -> None: ...


@dataclass(frozen=True)
class ControllerCodeSignatureBinding:
    """Installed controller identity, never accepted in a broker frame."""

    team_identifier: str
    designated_requirement_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.team_identifier, str)
            or not 1 <= len(self.team_identifier) <= 64
            or not self.team_identifier.isascii()
            or _HEX32.fullmatch(self.designated_requirement_sha256[:32]) is None
            or len(self.designated_requirement_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.designated_requirement_sha256)
        ):
            raise BrokerServiceError("controller code-signature binding is malformed")


@dataclass(frozen=True)
class FixedBrokerResourcePolicy:
    """The only launcher resource profile; controller frames cannot tune it."""

    memory_bytes: int = 2 * 1_024 * 1_024 * 1_024
    virtual_cpus: int = 2
    wall_clock_seconds: int = 30 * 60
    request_bytes: int = 256 * 1_024 * 1_024
    scratch_bytes: int = 2 * 1_024 * 1_024 * 1_024

    def __post_init__(self) -> None:
        if (
            self.memory_bytes != 2 * 1_024 * 1_024 * 1_024
            or self.virtual_cpus != 2
            or self.wall_clock_seconds != 30 * 60
            or self.request_bytes != 256 * 1_024 * 1_024
            or self.scratch_bytes != 2 * 1_024 * 1_024 * 1_024
        ):
            raise BrokerServiceError(
                "strict VM resource policy must be the installed fixed profile"
            )


_FIXED_RESOURCE_POLICY = FixedBrokerResourcePolicy()


@dataclass(frozen=True)
class FixedLauncherPlan:
    """Private launch data derived only from installed state and a broker run."""

    launcher_sha256: str
    argv: tuple[str, str, str]
    environment: tuple[()]
    resource_policy: FixedBrokerResourcePolicy


def _require_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or _HEX32.fullmatch(run_id) is None:
        raise BrokerStorageError("broker run identity is malformed")
    return run_id


def _fd_is_private_directory(fd: int, expected_uid: int) -> None:
    if type(fd) is not int or fd < 0:
        raise BrokerStorageError("broker directory descriptor is invalid")
    try:
        details = os.fstat(fd)
    except OSError as exc:
        raise BrokerStorageError("broker directory descriptor is unavailable") from exc
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != expected_uid
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_nlink < 2
    ):
        raise BrokerStorageError("broker private directory identity or mode is unsafe")


def _write_all(fd: int, value: bytes) -> None:
    offset = 0
    attempts = 0
    while offset < len(value):
        attempts += 1
        if attempts > _MAX_IO_ATTEMPTS:
            raise BrokerStorageError("bounded broker write did not make progress")
        try:
            written = os.write(fd, value[offset:])
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrokerStorageError("broker descriptor write failed") from exc
        if written <= 0:
            raise BrokerStorageError("broker descriptor write made no progress")
        offset += written


def verify_fixture_fixed_launcher_descriptor(
    launcher_fd: int,
    *,
    launcher_owner_uid: int,
    expected_sha256: str,
    capability: FixtureBrokerServiceCapability,
) -> None:
    """Fixture-check a pre-opened immutable launcher without accepting a path.

    The future daemon must obtain this descriptor from its root-owned
    installation before consulting any controller input.  A descriptor makes a
    path swap irrelevant; metadata is checked before and after the bounded
    digest so a concurrent replacement/modification is a hard failure.
    """

    _require_fixture_capability(capability)
    if (
        type(launcher_fd) is not int
        or launcher_fd < 0
        or type(launcher_owner_uid) is not int
        or launcher_owner_uid < 0
        or not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
    ):
        raise BrokerStorageError("installed launcher descriptor contract is malformed")
    try:
        before = os.fstat(launcher_fd)
        before_fd_flags = fcntl.fcntl(launcher_fd, fcntl.F_GETFD)
    except OSError as exc:
        raise BrokerStorageError("installed launcher descriptor is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != launcher_owner_uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o222
        or not before_fd_flags & fcntl.FD_CLOEXEC
        or not 0 < before.st_size <= _MAX_LAUNCHER_BYTES
    ):
        raise BrokerStorageError("installed launcher identity or permissions are unsafe")
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        try:
            chunk = os.pread(launcher_fd, min(64 * 1_024, before.st_size - offset), offset)
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrokerStorageError(
                "installed launcher cannot be read through its descriptor"
            ) from exc
        if not chunk:
            raise BrokerStorageError("installed launcher changed while being rehashed")
        digest.update(chunk)
        offset += len(chunk)
    try:
        after = os.fstat(launcher_fd)
        after_fd_flags = fcntl.fcntl(launcher_fd, fcntl.F_GETFD)
    except OSError as exc:
        raise BrokerStorageError("installed launcher descriptor disappeared") from exc
    if (
        after_fd_flags != before_fd_flags
        or not after_fd_flags & fcntl.FD_CLOEXEC
        or (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        or not hmac.compare_digest(digest.hexdigest(), expected_sha256)
    ):
        raise BrokerStorageError("installed launcher digest is not the fixed installation identity")


class FixturePrivateRunRoot:
    """A duplicated broker-owned ``runs`` directory descriptor.

    Its constructor receives a descriptor from the (future) dedicated daemon,
    never a path from a controller.  Every child operation uses ``dir_fd`` and
    ``O_NOFOLLOW``.  The class owns only descriptors it has duplicated or
    created and never recursively deletes a directory.
    """

    def __init__(
        self,
        runs_fd: int,
        *,
        broker_uid: int,
        capability: FixtureBrokerServiceCapability,
    ) -> None:
        _require_fixture_capability(capability)
        _fd_is_private_directory(runs_fd, broker_uid)
        try:
            self._runs_fd = os.dup(runs_fd)
        except OSError as exc:
            raise BrokerStorageError("cannot duplicate broker runs descriptor") from exc
        self._broker_uid = broker_uid
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            os.close(self._runs_fd)
            self._closed = True

    def __enter__(self) -> FixturePrivateRunRoot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def create_run(self, run_id: str) -> FixturePrivateRunWorkspace:
        """Create exactly one broker-generated, empty `0700` child directory."""

        if self._closed:
            raise BrokerStorageError("broker runs descriptor is closed")
        run_id = _require_run_id(run_id)
        try:
            os.mkdir(run_id, 0o700, dir_fd=self._runs_fd)
        except FileExistsError as exc:
            raise BrokerStorageError("broker run ID collision or replay") from exc
        except OSError as exc:
            raise BrokerStorageError("broker run directory creation failed") from exc
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            run_fd = os.open(run_id, flags, dir_fd=self._runs_fd)
            _fd_is_private_directory(run_fd, self._broker_uid)
            details = os.fstat(run_fd)
            return FixturePrivateRunWorkspace(
                self, run_id, run_fd, run_dev=details.st_dev, run_ino=details.st_ino
            )
        except Exception:
            # This is exact rollback of the just-created, still-empty child;
            # never recurse or sweep a directory chosen by another party.
            with suppress(OSError):
                os.rmdir(run_id, dir_fd=self._runs_fd)
            raise

    def _open_verified_run(self, run_id: str, run_dev: int, run_ino: int) -> int:
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(run_id, flags, dir_fd=self._runs_fd)
            details = os.fstat(fd)
        except OSError as exc:
            raise BrokerCleanupError("broker run directory cannot be reopened safely") from exc
        if (
            not stat.S_ISDIR(details.st_mode)
            or details.st_uid != self._broker_uid
            or stat.S_IMODE(details.st_mode) != 0o700
            or (details.st_dev, details.st_ino) != (run_dev, run_ino)
        ):
            os.close(fd)
            raise BrokerCleanupError("broker run directory identity changed before cleanup")
        return fd

    def _remove_run_directory(self, run_id: str, run_dev: int, run_ino: int) -> None:
        verified_fd = self._open_verified_run(run_id, run_dev, run_ino)
        try:
            os.rmdir(run_id, dir_fd=self._runs_fd)
        except OSError as exc:
            raise BrokerCleanupError(
                "broker run directory is not empty or cannot be removed"
            ) from exc
        finally:
            os.close(verified_fd)


class FixturePrivateRunWorkspace:
    """One exact run directory with a bounded, immutable request file."""

    def __init__(
        self,
        root: FixturePrivateRunRoot,
        run_id: str,
        run_fd: int,
        *,
        run_dev: int,
        run_ino: int,
    ) -> None:
        self._root = root
        self.run_id = _require_run_id(run_id)
        self._run_fd = run_fd
        self._run_dev = run_dev
        self._run_ino = run_ino
        self._request_written = False
        self._closed = False

    def write_request(self, request: bytes, expected_sha256: str) -> None:
        """Create one no-follow request file, fsync it, and bind its digest."""

        if self._closed or self._request_written:
            raise BrokerStorageError("broker request is already final or workspace is closed")
        if not isinstance(request, bytes) or not 0 < len(request) <= 256 * 1_024 * 1_024:
            raise BrokerStorageError("broker request is outside its fixed bounds")
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise BrokerStorageError("broker request digest is malformed")
        observed = hashlib.sha256(request).hexdigest()
        if not hmac.compare_digest(observed, expected_sha256):
            raise BrokerStorageError("broker request digest does not bind supplied bytes")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = -1
        try:
            fd = os.open(_REQUEST_NAME, flags, 0o600, dir_fd=self._run_fd)
            _write_all(fd, request)
            os.fsync(fd)
            details = os.fstat(fd)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != self._root._broker_uid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size != len(request)
            ):
                raise BrokerStorageError("broker request file identity is unsafe")
            self._request_written = True
            os.fsync(self._run_fd)
        except FileExistsError as exc:
            raise BrokerStorageError("broker request name collision") from exc
        except OSError as exc:
            raise BrokerStorageError("broker request storage failed") from exc
        finally:
            if fd >= 0:
                os.close(fd)

    def cleanup(self) -> None:
        """Remove only the exact file and exact child this object created."""

        if self._closed:
            return
        failure: Exception | None = None
        identity_fd = -1
        try:
            identity_fd = self._root._open_verified_run(self.run_id, self._run_dev, self._run_ino)
            held = os.fstat(self._run_fd)
            reopened = os.fstat(identity_fd)
            if (held.st_dev, held.st_ino) != (self._run_dev, self._run_ino) or (
                reopened.st_dev,
                reopened.st_ino,
            ) != (self._run_dev, self._run_ino):
                raise BrokerCleanupError("broker held run descriptor identity changed")
        except (BrokerCleanupError, OSError) as exc:
            failure = (
                exc
                if isinstance(exc, BrokerCleanupError)
                else BrokerCleanupError("broker run descriptor cannot be verified")
            )
            if failure is not exc:
                failure.__cause__ = exc
        finally:
            if identity_fd >= 0:
                os.close(identity_fd)
        if failure is None and self._request_written:
            try:
                os.unlink(_REQUEST_NAME, dir_fd=self._run_fd)
            except OSError as exc:
                failure = BrokerCleanupError("broker request cannot be removed")
                failure.__cause__ = exc
        try:
            os.close(self._run_fd)
        except OSError as exc:
            if failure is None:
                failure = BrokerCleanupError("broker run descriptor cannot be closed")
                failure.__cause__ = exc
        self._closed = True
        if failure is None:
            try:
                self._root._remove_run_directory(self.run_id, self._run_dev, self._run_ino)
            except BrokerCleanupError as exc:
                failure = exc
        if failure is not None:
            raise failure


def fixture_recv_bounded_frame(
    connection: UnixSocket,
    *,
    capability: FixtureBrokerServiceCapability,
    cancelled: Callable[[], bool] | None = None,
) -> bytes:
    """Fixture-read exactly one bounded frame without a stream suffix.

    The caller must close a cancelled connection.  This helper avoids a
    partially-read frame being treated as an acknowledgement and caps every
    individual receive request.
    """

    _require_fixture_capability(capability)

    def receive_exact(size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        attempts = 0
        while remaining:
            attempts += 1
            if attempts > _MAX_IO_ATTEMPTS:
                raise BrokerProtocolError("broker peer did not make bounded read progress")
            if cancelled is not None and cancelled():
                raise BrokerCancellationError("broker protocol exchange was cancelled")
            try:
                chunk = connection.recv(remaining)
            except InterruptedError:
                continue
            except OSError as exc:
                raise BrokerProtocolError("broker peer read failed") from exc
            if not isinstance(chunk, bytes) or not chunk:
                raise BrokerProtocolError("broker frame is truncated")
            if len(chunk) > remaining:
                raise BrokerProtocolError("broker peer exceeded bounded receive request")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    header = receive_exact(_FRAME_HEADER.size)
    try:
        magic, version, reserved, length, _digest = _FRAME_HEADER.unpack(header)
    except struct.error as exc:
        raise BrokerProtocolError("broker frame header is invalid") from exc
    if (
        magic != BROKER_FRAME_MAGIC
        or version != BROKER_PROTOCOL_VERSION
        or reserved != 0
        or not 0 < length <= MAX_FRAME_BYTES
    ):
        raise BrokerProtocolError("broker frame header is invalid")
    return header + receive_exact(length)


def _fixture_send_bounded_frame(connection: UnixSocket, payload: dict[str, object]) -> None:
    """Send exactly one canonical bounded reply with cancellation-safe progress."""

    frame = encode_frame(payload)
    offset = 0
    attempts = 0
    while offset < len(frame):
        attempts += 1
        if attempts > _MAX_IO_ATTEMPTS:
            raise BrokerProtocolError("broker peer did not make bounded write progress")
        try:
            written = connection.send(frame[offset:])
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrokerProtocolError("broker peer write failed") from exc
        if type(written) is not int or written <= 0 or written > len(frame) - offset:
            raise BrokerProtocolError("broker peer write made invalid progress")
        offset += written


class StrictVMBrokerServiceCore:
    """Production entrypoint that rejects before inspecting any dependency."""

    def __init__(
        self,
        installation: BrokerInstallation,
        *,
        signature_binding: ControllerCodeSignatureBinding,
        signature_verifier: ControllerCodeSignatureVerifier,
        durable_acknowledgement: DurableBrokerAcknowledgement,
        resource_policy: FixedBrokerResourcePolicy = _FIXED_RESOURCE_POLICY,
    ) -> None:
        del (
            installation,
            signature_binding,
            signature_verifier,
            durable_acknowledgement,
            resource_policy,
        )
        _require_production_service_enabled()
        raise BrokerUnavailableError("strict VM broker production service is not implemented")

    def dispatch_once(
        self, connection: UnixSocket, *, now_ns: int, cancelled: Callable[[], bool] | None = None
    ) -> BrokerReply:
        """Reject before reading peer identity, frame bytes, or durable state."""

        del self, connection, now_ns, cancelled
        _require_production_service_enabled()
        raise BrokerUnavailableError("strict VM broker production dispatch is not implemented")

    def fixed_launcher_plan(self, run_id: str) -> FixedLauncherPlan:
        """Reject before reading installation, run, filesystem, or launcher state."""

        del self, run_id
        _require_production_service_enabled()
        raise BrokerUnavailableError("strict VM broker production launcher is not implemented")


class FixtureStrictVMBrokerServiceCore:
    """Explicitly non-production dispatcher for bounded synthetic rehearsals."""

    def __init__(
        self,
        installation: BrokerInstallation,
        *,
        capability: FixtureBrokerServiceCapability,
        signature_binding: ControllerCodeSignatureBinding,
        signature_verifier: ControllerCodeSignatureVerifier,
        durable_acknowledgement: DurableBrokerAcknowledgement,
        resource_policy: FixedBrokerResourcePolicy = _FIXED_RESOURCE_POLICY,
    ) -> None:
        _require_fixture_capability(capability)
        self._fixture_capability = capability
        self._installation = installation
        self._signature_binding = signature_binding
        self._signature_verifier = signature_verifier
        self._durable_acknowledgement = durable_acknowledgement
        self._resource_policy = resource_policy
        self._admission = StrictVMBrokerAdmission(installation)
        self._poisoned = False

    def dispatch_once(
        self, connection: UnixSocket, *, now_ns: int, cancelled: Callable[[], bool] | None = None
    ) -> BrokerReply:
        """Authenticate a live Unix peer before parsing one bounded frame."""

        if self._poisoned:
            raise BrokerUnavailableError(
                "broker journal state is uncertain after a failed acknowledgement"
            )
        peer = peer_from_socket(connection)
        if peer.uid != self._installation.controller_uid:
            raise BrokerAuthorizationError("broker peer UID is not the installed controller UID")
        try:
            verified = self._signature_verifier.verify(connection, self._signature_binding)
        except Exception as exc:
            raise BrokerAuthorizationError("controller code-signature verification failed") from exc
        if verified is not True:
            raise BrokerAuthorizationError("controller code-signature binding is not satisfied")
        frame = fixture_recv_bounded_frame(
            connection, capability=self._fixture_capability, cancelled=cancelled
        )
        reply = self._admission.handle(frame, peer, now_ns=now_ns)
        try:
            self._durable_acknowledgement.commit_before_ack(frame, reply)
        except Exception as exc:
            # Admission state may have changed in memory while the durable
            # transaction's outcome is unknown. Do not accept another frame
            # until a separately reviewed daemon restart/recovery decides the
            # replay state from its witness.
            self._poisoned = True
            raise BrokerServiceError("journal+witness acknowledgement was not durable") from exc
        _fixture_send_bounded_frame(connection, reply.payload())
        return reply

    def fixed_launcher_plan(self, run_id: str) -> FixedLauncherPlan:
        """Always deny launcher construction until all release gates are evidenced."""

        _require_fixture_capability(self._fixture_capability)
        _require_run_id(run_id)
        identity = self._installation.boot_identity
        return FixedLauncherPlan(
            identity.launcher_sha256,
            (str(self._installation.launcher_path), "--run", "<broker-private-manifest>"),
            (),
            self._resource_policy,
        )


def ensure_service_activation_is_impossible() -> None:
    """Defensive import-time assertion used by adversarial tests and review."""

    if (
        STRICT_VM_BROKER_SERVICE_ENABLED
        or STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED
        or STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED
        or STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED
    ):
        raise BrokerServiceError("strict VM broker source gate was weakened")


ensure_service_activation_is_impossible()
