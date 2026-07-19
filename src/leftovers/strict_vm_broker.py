"""Fail-closed protocol scaffold for a dedicated strict-VM launch broker.

The strict-VM controller must not own the directory passed to
``strict-vm-launcher``.  Otherwise another process under the controller's UID
can replace a request, manifest, or scratch name after the controller verifies
it but before Virtualization.framework opens it.  A future installed broker
will run under a distinct service account, own its run directory, and accept
only this small framed protocol over a Unix-domain socket.

This module deliberately implements *no* listener, filesystem write, launcher
subprocess, host-service installation, or privilege transition.  It is a
testable admission contract only.  ``STRICT_VM_BROKER_ENABLED`` is a release
gate, not a configuration option; all attempts to start the service fail
before opening a socket.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

# Do not change this without a separately reviewed launchd installation,
# credential-mediated controller authorization, and live adversarial evidence.
STRICT_VM_BROKER_ENABLED = False

BROKER_PROTOCOL_VERSION = 1
BROKER_FRAME_MAGIC = b"LVB1"
MAX_FRAME_BYTES = 128 * 1_024
MAX_CHUNK_BYTES = 64 * 1_024
MAX_REQUEST_BYTES = 256 * 1_024 * 1_024
MAX_REQUEST_CHUNKS = MAX_REQUEST_BYTES // MAX_CHUNK_BYTES
ALLOCATION_TTL_NS = 120 * 1_000_000_000
MAX_PENDING_ALLOCATIONS = 16
MAX_REPLAY_GUARDS = 1_024
_FRAME = struct.Struct("<4sHHI32s")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ALLOCATION_OPERATIONS = frozenset({"allocate", "append_request"})


class StrictVMBrokerError(RuntimeError):
    """A broker frame or local trust-boundary condition is unsafe."""


class BrokerProtocolError(StrictVMBrokerError):
    """A peer supplied malformed, replayed, or non-canonical protocol data."""


class BrokerAuthorizationError(StrictVMBrokerError):
    """The Unix-socket peer is not the designated controller account."""


class BrokerUnavailableError(StrictVMBrokerError):
    """The deliberately uninstalled broker cannot be started."""


@dataclass(frozen=True)
class BrokerPeer:
    """Kernel-reported peer identity; never accept this structure from JSON."""

    uid: int
    gid: int


class PeerSocket(Protocol):
    """The Darwin subset needed to obtain a connected Unix peer identity."""

    def getpeereid(self) -> tuple[int, int]: ...


@dataclass(frozen=True)
class ImmutableBootIdentity:
    """The broker's installed, hash-pinned launch/boot artifact set."""

    launcher_sha256: str
    kernel_sha256: str
    initrd_sha256: str
    root_disk_sha256: str
    guest_policy_sha256: str
    launcher_version: str = "0.3.0-proof"

    def __post_init__(self) -> None:
        if self.launcher_version != "0.3.0-proof" or not all(
            _HEX64.fullmatch(value)
            for value in (
                self.launcher_sha256,
                self.kernel_sha256,
                self.initrd_sha256,
                self.root_disk_sha256,
                self.guest_policy_sha256,
            )
        ):
            raise StrictVMBrokerError("immutable boot identity is malformed")


@dataclass(frozen=True)
class BrokerInstallation:
    """Privileged installation inputs, never fields from a controller frame."""

    service_root: Path
    launcher_path: Path
    controller_uid: int
    broker_uid: int
    boot_identity: ImmutableBootIdentity

    def __post_init__(self) -> None:
        for path, label in ((self.service_root, "service root"), (self.launcher_path, "launcher")):
            if not path.is_absolute() or any(component in {".", ".."} for component in path.parts):
                raise StrictVMBrokerError(f"broker {label} must be an absolute installed path")
        if (
            type(self.controller_uid) is not int
            or type(self.broker_uid) is not int
            or self.controller_uid < 0
            or self.broker_uid < 0
            or self.controller_uid == self.broker_uid
        ):
            raise StrictVMBrokerError("controller and broker must be distinct valid UIDs")


@dataclass(frozen=True)
class BrokerAllocation:
    """Opaque authority returned to the controller for one bounded upload."""

    allocation_id: str
    lease_token: str
    run_id: str
    expires_at_ns: int


@dataclass(frozen=True)
class BrokerReply:
    """Protocol reply containing no local path, argv, mount, or host detail."""

    operation: str
    allocation_id: str
    lease_token: str | None
    run_id: str
    request_sha256: str | None
    request_bytes: int | None

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": BROKER_PROTOCOL_VERSION,
            "operation": self.operation,
            "allocation_id": self.allocation_id,
            "lease_token": self.lease_token,
            "run_id": self.run_id,
            "request_sha256": self.request_sha256,
            "request_bytes": self.request_bytes,
        }


@dataclass
class _PendingAllocation:
    allocation: BrokerAllocation
    peer: BrokerPeer
    request_id: str
    next_sequence: int
    total_bytes: int
    digest: Any


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _canonical_json(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BrokerProtocolError("broker frame cannot be canonicalized") from exc


def _strict_payload(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise BrokerProtocolError("broker frame payload is empty or oversized")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BrokerProtocolError("broker frame payload is not strict JSON") from exc
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise BrokerProtocolError("broker frame payload is not a canonical object")
    return value


def encode_frame(payload: dict[str, Any]) -> bytes:
    """Encode one canonical, integrity-bound protocol frame for a test client."""

    raw = _canonical_json(payload)
    if not 0 < len(raw) <= MAX_FRAME_BYTES:
        raise BrokerProtocolError("broker frame payload is empty or oversized")
    return (
        _FRAME.pack(
            BROKER_FRAME_MAGIC,
            BROKER_PROTOCOL_VERSION,
            0,
            len(raw),
            hashlib.sha256(raw).digest(),
        )
        + raw
    )


def decode_frame(raw: bytes) -> dict[str, Any]:
    """Reject truncated, concatenated, version-skewed, or altered frames."""

    if len(raw) < _FRAME.size:
        raise BrokerProtocolError("broker frame is truncated")
    magic, version, reserved, length, digest = _FRAME.unpack(raw[: _FRAME.size])
    if (
        magic != BROKER_FRAME_MAGIC
        or version != BROKER_PROTOCOL_VERSION
        or reserved != 0
        or not 0 < length <= MAX_FRAME_BYTES
        or len(raw) != _FRAME.size + length
    ):
        raise BrokerProtocolError("broker frame header is invalid")
    payload = raw[_FRAME.size :]
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), digest):
        raise BrokerProtocolError("broker frame digest does not match")
    return _strict_payload(payload)


def peer_from_socket(connection: PeerSocket) -> BrokerPeer:
    """Read Darwin ``getpeereid`` data; protocol JSON never names a peer UID."""

    try:
        uid, gid = connection.getpeereid()
    except (AttributeError, OSError) as exc:
        raise BrokerAuthorizationError("kernel peer credentials are unavailable") from exc
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise BrokerAuthorizationError("kernel peer credentials are invalid")
    return BrokerPeer(uid=uid, gid=gid)


def _require_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX32.fullmatch(value) is None:
        raise BrokerProtocolError(f"{label} must be exactly 32 lowercase hex characters")
    return value


def _decode_chunk(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((MAX_CHUNK_BYTES + 2) // 3):
        raise BrokerProtocolError("request chunk encoding is invalid")
    try:
        chunk = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise BrokerProtocolError("request chunk encoding is invalid") from exc
    if len(chunk) > MAX_CHUNK_BYTES or base64.b64encode(chunk).decode("ascii") != value:
        raise BrokerProtocolError("request chunk is not canonical or exceeds its cap")
    return chunk


class StrictVMBrokerAdmission:
    """In-memory model of the broker's authenticated bounded upload protocol.

    It is intentionally insufficient to launch anything. A future broker must
    stream accepted bytes through a broker-owned directory descriptor, build its
    own manifest, rehash immutable boot artifacts, and invoke the one fixed
    launcher argv. This state machine proves the controller cannot provide a
    host path, argv, or prechosen run-directory name to that future service.
    """

    def __init__(self, installation: BrokerInstallation) -> None:
        self.installation = installation
        self._pending: dict[str, _PendingAllocation] = {}
        self._replay_guards: dict[str, int] = {}

    def _require_peer(self, peer: BrokerPeer) -> None:
        if peer.uid != self.installation.controller_uid:
            raise BrokerAuthorizationError("broker peer UID is not the installed controller UID")

    @staticmethod
    def _now(now_ns: int | None) -> int:
        observed = time.monotonic_ns() if now_ns is None else now_ns
        if type(observed) is not int or observed < 0:
            raise BrokerProtocolError("broker monotonic timestamp is invalid")
        return observed

    def _prune_expired(self, now_ns: int) -> None:
        for allocation_id, state in tuple(self._pending.items()):
            if now_ns > state.allocation.expires_at_ns:
                del self._pending[allocation_id]
        for request_id, expires_at_ns in tuple(self._replay_guards.items()):
            if now_ns > expires_at_ns:
                del self._replay_guards[request_id]

    def _allocate(self, payload: dict[str, Any], peer: BrokerPeer, now_ns: int) -> BrokerReply:
        if set(payload) != {"schema_version", "operation", "request_id"}:
            raise BrokerProtocolError("allocate request fields are not exact")
        request_id = _require_hex(payload["request_id"], "request_id")
        if request_id in self._replay_guards:
            raise BrokerProtocolError("broker allocation request was already accepted")
        if (
            len(self._pending) >= MAX_PENDING_ALLOCATIONS
            or len(self._replay_guards) >= MAX_REPLAY_GUARDS
        ):
            raise BrokerProtocolError("broker allocation capacity is exhausted")
        allocation = BrokerAllocation(
            allocation_id=secrets.token_hex(16),
            lease_token=secrets.token_hex(16),
            run_id=secrets.token_hex(16),
            expires_at_ns=now_ns + ALLOCATION_TTL_NS,
        )
        self._pending[allocation.allocation_id] = _PendingAllocation(
            allocation=allocation,
            peer=peer,
            request_id=request_id,
            next_sequence=0,
            total_bytes=0,
            digest=hashlib.sha256(),
        )
        self._replay_guards[request_id] = allocation.expires_at_ns
        return BrokerReply(
            operation="allocated",
            allocation_id=allocation.allocation_id,
            lease_token=allocation.lease_token,
            run_id=allocation.run_id,
            request_sha256=None,
            request_bytes=None,
        )

    def _broker_run_directory(self, allocation: BrokerAllocation) -> Path:
        """Derive the sole future run location from broker-only installation state."""

        return self.installation.service_root / "runs" / allocation.run_id

    def _append(self, payload: dict[str, Any], peer: BrokerPeer, now_ns: int) -> BrokerReply:
        fields = {
            "schema_version",
            "operation",
            "request_id",
            "allocation_id",
            "lease_token",
            "sequence",
            "chunk_b64",
            "final",
            "request_sha256",
        }
        if set(payload) != fields:
            raise BrokerProtocolError("append request fields are not exact")
        request_id = _require_hex(payload["request_id"], "request_id")
        allocation_id = _require_hex(payload["allocation_id"], "allocation_id")
        lease_token = _require_hex(payload["lease_token"], "lease_token")
        state = self._pending.get(allocation_id)
        if state is None:
            raise BrokerProtocolError("broker allocation is absent, consumed, or expired")
        if state.peer != peer or not hmac.compare_digest(state.allocation.lease_token, lease_token):
            raise BrokerAuthorizationError("broker allocation does not belong to this peer")
        if not hmac.compare_digest(state.request_id, request_id):
            raise BrokerAuthorizationError("broker append does not bind to its allocation request")
        if now_ns > state.allocation.expires_at_ns:
            del self._pending[allocation_id]
            raise BrokerProtocolError("broker allocation is stale")
        if type(payload["sequence"]) is not int or payload["sequence"] != state.next_sequence:
            raise BrokerProtocolError("broker request chunk sequence is invalid")
        if state.next_sequence >= MAX_REQUEST_CHUNKS:
            del self._pending[allocation_id]
            raise BrokerProtocolError("broker request exceeds its chunk-count cap")
        if type(payload["final"]) is not bool:
            raise BrokerProtocolError("broker request final marker is invalid")
        chunk = _decode_chunk(payload["chunk_b64"])
        final = payload["final"]
        expected = payload["request_sha256"]
        if final:
            if not isinstance(expected, str) or _HEX64.fullmatch(expected) is None:
                raise BrokerProtocolError("final request digest is invalid")
            if state.total_bytes + len(chunk) == 0:
                del self._pending[allocation_id]
                raise BrokerProtocolError("final broker request may not be empty")
        elif expected is not None:
            raise BrokerProtocolError("non-final chunk may not name a request digest")
        if state.total_bytes + len(chunk) > MAX_REQUEST_BYTES:
            del self._pending[allocation_id]
            raise BrokerProtocolError("broker request exceeds its total byte cap")
        candidate_digest = state.digest.copy()
        candidate_digest.update(chunk)
        if final and not hmac.compare_digest(candidate_digest.hexdigest(), expected):
            del self._pending[allocation_id]
            raise BrokerProtocolError("final request digest does not match uploaded bytes")
        state.digest = candidate_digest
        state.total_bytes += len(chunk)
        state.next_sequence += 1
        if not final:
            return BrokerReply(
                operation="accepted",
                allocation_id=allocation_id,
                lease_token=None,
                run_id=state.allocation.run_id,
                request_sha256=None,
                request_bytes=None,
            )
        observed = state.digest.hexdigest()
        del self._pending[allocation_id]
        # The future service will stream the bytes to this derived location via
        # directory descriptors. Do not return it to the controller or create
        # it in this hard-disabled in-memory scaffold.
        self._broker_run_directory(state.allocation)
        return BrokerReply(
            operation="staged",
            allocation_id=allocation_id,
            lease_token=None,
            run_id=state.allocation.run_id,
            request_sha256=observed,
            request_bytes=state.total_bytes,
        )

    def handle(self, frame: bytes, peer: BrokerPeer, *, now_ns: int | None = None) -> BrokerReply:
        """Authenticate then accept exactly one allocation or upload frame."""

        self._require_peer(peer)
        payload = decode_frame(frame)
        if payload.get("schema_version") != BROKER_PROTOCOL_VERSION:
            raise BrokerProtocolError("broker protocol version is invalid")
        operation = payload.get("operation")
        if operation not in _ALLOCATION_OPERATIONS:
            raise BrokerProtocolError("broker operation is not permitted")
        observed_now = self._now(now_ns)
        self._prune_expired(observed_now)
        if operation == "allocate":
            return self._allocate(payload, peer, observed_now)
        return self._append(payload, peer, observed_now)

    def fixed_launcher_argv(self, allocation_id: str) -> tuple[str, ...]:
        """There is deliberately no launch capability in this scaffold."""

        del allocation_id
        raise BrokerUnavailableError(
            "strict VM broker is not installed or authorized to construct launcher argv"
        )


class StrictVMBrokerService:
    """Placeholder for the separately installed dedicated-account launch daemon."""

    def __init__(self, installation: BrokerInstallation) -> None:
        self.installation = installation

    def start(self) -> None:
        """Fail before opening a socket, creating a directory, or changing privileges."""

        if not STRICT_VM_BROKER_ENABLED:
            raise BrokerUnavailableError("strict VM broker service is hard-disabled")
        raise BrokerUnavailableError("strict VM broker service has no installed implementation")
