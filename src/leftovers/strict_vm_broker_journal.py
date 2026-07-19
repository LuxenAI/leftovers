"""Durable-state model for the hard-disabled dedicated strict-VM broker.

This module deliberately contains no socket, path, directory, subprocess, or
service implementation.  It describes the *only* durable state a future
dedicated-UID broker may need to persist.  A real installation must provide a
root-owned, descriptor-relative, no-follow journal sink whose ``append`` is
durable before it returns.  Passing ordinary paths to this module is
impossible by design.

The model is conservative across a crash: incomplete uploads are quarantined,
not resumed.  Their request IDs and any reservation remain consumed, so a torn
or rolled-back controller exchange cannot be replayed into a new epoch.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
from dataclasses import dataclass
from typing import Any, Protocol

from .strict_vm_broker import (
    ALLOCATION_TTL_NS,
    MAX_PENDING_ALLOCATIONS,
    MAX_REPLAY_GUARDS,
    BrokerAllocation,
    BrokerAuthorizationError,
    BrokerInstallation,
    BrokerPeer,
    BrokerUnavailableError,
    StrictVMBrokerError,
)

JOURNAL_VERSION = 1
MAX_JOURNAL_RECORD_BYTES = 32 * 1_024
MAX_JOURNAL_RECORDS = 8_192
MAX_DURABLE_ALLOCATIONS = MAX_PENDING_ALLOCATIONS
MAX_DURABLE_REPLAY_GUARDS = MAX_REPLAY_GUARDS
MAX_TOKEN_RESERVATIONS = 256
MAX_RESERVED_TOKENS = 1_000_000
MAX_TOKEN_RESERVATION_TOKENS = 100_000
LFRQ_HEADER_BYTES = 4_096
LFRQ_MAX_BYTES = 256 * 1_024 * 1_024
_LFRQ_PREFIX = struct.Struct("<4sHHHHQ32s64sI32s32s")
_LFRQ_SECTION = struct.Struct("<16sQQ32s")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_JOURNAL_TYPES = frozenset(
    {
        "genesis",
        "allocation",
        "append",
        "staged",
        "quarantined",
        "token_reserved",
        "token_settled",
    }
)


class BrokerJournalError(StrictVMBrokerError):
    """Durable broker state is malformed, incomplete, or not trustworthy."""


class BrokerJournalRollbackError(BrokerJournalError):
    """A journal prefix, genesis, or monotonic epoch could have been rolled back."""


@dataclass(frozen=True)
class BrokerPrivateRootContract:
    """Non-path contract for the root-owned, broker-private persistence tree.

    The service installer—not a controller frame or this Python scaffold—must
    prove it with directory descriptors.  Keeping a path out of this value is
    intentional: a controller must never nominate a journal/run directory.
    """

    broker_uid: int
    directory_mode: int = 0o700
    require_descriptor_relative: bool = True
    require_nofollow: bool = True
    require_identity_verification: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.broker_uid) is not int
            or self.broker_uid < 0
            or self.directory_mode != 0o700
            or not self.require_descriptor_relative
            or not self.require_nofollow
            or not self.require_identity_verification
        ):
            raise BrokerJournalError("broker private-root contract is weakened or malformed")


class DescriptorRelativeLFRQ(Protocol):
    """A staged request opened relative to a broker-owned directory descriptor.

    The production adapter must prove all three booleans from the descriptor
    acquisition operation.  This protocol intentionally has no pathname field.
    """

    size: int
    opened_relative_to_private_root: bool
    opened_nofollow: bool
    identity_verified: bool

    def pread_exact(self, size: int, offset: int) -> bytes: ...


@dataclass(frozen=True)
class JournalRecord:
    """One canonical, hash-linked, already-fsynced journal record."""

    sequence: int
    previous_sha256: str
    kind: str
    body: dict[str, Any]
    sha256: str
    raw: bytes


@dataclass(frozen=True)
class BrokerJournalAnchor:
    """Root-owned rollback witness, updated atomically with the append log.

    A hash chain alone detects a modified record but cannot distinguish a valid
    older prefix from the newest log.  Recovery therefore requires this
    separately durable witness from the broker's private installation.
    """

    record_count: int
    head_sha256: str
    genesis_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.record_count) is not int
            or self.record_count <= 0
            or _HEX64.fullmatch(self.head_sha256) is None
            or _HEX64.fullmatch(self.genesis_sha256) is None
        ):
            raise BrokerJournalError("journal rollback witness is malformed")


class BrokerJournalSink(Protocol):
    """Future broker-owned atomic commit primitive for journal and witness.

    ``commit_fsynced`` must durably publish *both* the next record and the
    matching root-owned rollback witness as one crash-consistent commit before
    it returns.  A simple append followed by a separate anchor write does not
    meet this contract: a crash between them permanently wedges recovery.

    A production implementation belongs in the separately reviewed launchd
    service. It must use broker-owned descriptor-relative storage and must not
    accept a caller-selected file name or ``Path`` from this package.
    """

    def commit_fsynced(self, record: bytes, anchor: BrokerJournalAnchor) -> None: ...


@dataclass(frozen=True)
class DurableAllocation:
    """A recovered allocation; incomplete entries are deliberately unusable."""

    allocation: BrokerAllocation
    peer: BrokerPeer
    request_id: str
    next_sequence: int
    total_bytes: int
    chunk_chain_sha256: str
    state: str
    request_sha256: str | None = None


@dataclass(frozen=True)
class TokenReservation:
    """Conservative token reservation bound to an allocation and LFRQ digest."""

    reservation_id: str
    allocation_id: str
    request_sha256: str
    tokens: int
    state: str


@dataclass(frozen=True)
class UnverifiedLFRQHeaderObservation:
    """Descriptor-shaped header observation, explicitly not LFRQ validation.

    It exists only so the disabled admission path can bind an opaque allocation
    to a claimed internal run ID before refusing to proceed.  It does not
    authenticate a request, verify its payload, or authorize a VM epoch.
    """

    run_id: str
    round: int
    stage: str
    total_size: int
    unverified_mediation_authority: str
    unverified_mediation_reservation_id: str | None


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
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BrokerJournalError("journal value is not canonicalizable") from exc


def _strict_json(raw: bytes, *, cap: int) -> dict[str, Any]:
    if not 0 < len(raw) <= cap:
        raise BrokerJournalError("canonical JSON is empty or exceeds its cap")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise BrokerJournalError("canonical JSON is malformed") from exc
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise BrokerJournalError("canonical JSON is not exact")
    return value


def _require_hex(value: Any, label: str, *, size: int = 64) -> str:
    expression = _HEX64 if size == 64 else _HEX32
    if type(value) is not str or expression.fullmatch(value) is None:
        raise BrokerJournalError(f"{label} is not a lowercase SHA/opaque identifier")
    return value


def _installation_binding(installation: BrokerInstallation) -> dict[str, Any]:
    """Canonical genesis body binding the installed service and boot artifacts."""

    identity = installation.boot_identity
    private_root = BrokerPrivateRootContract(installation.broker_uid)
    return {
        "broker_uid": installation.broker_uid,
        "boot": {
            "guest_policy_sha256": identity.guest_policy_sha256,
            "initrd_sha256": identity.initrd_sha256,
            "kernel_sha256": identity.kernel_sha256,
            "launcher_sha256": identity.launcher_sha256,
            "launcher_version": identity.launcher_version,
            "root_disk_sha256": identity.root_disk_sha256,
        },
        "controller_uid": installation.controller_uid,
        "private_root": {
            "directory_mode": private_root.directory_mode,
            "identity_verified": private_root.require_identity_verification,
            "no_follow": private_root.require_nofollow,
            "relative_descriptors": private_root.require_descriptor_relative,
        },
        # Paths are intentionally excluded: they are deployment details and
        # never authority supplied by the controller.
        "schema_version": JOURNAL_VERSION,
    }


def journal_genesis_sha256(installation: BrokerInstallation) -> str:
    return hashlib.sha256(_canonical_json(_installation_binding(installation))).hexdigest()


def _record_bytes(
    *, sequence: int, previous_sha256: str, kind: str, body: dict[str, Any]
) -> tuple[bytes, str]:
    if type(sequence) is not int or sequence < 0 or kind not in _JOURNAL_TYPES:
        raise BrokerJournalError("journal record identity is invalid")
    _require_hex(previous_sha256, "journal previous hash")
    unsigned = {
        "body": body,
        "kind": kind,
        "previous_sha256": previous_sha256,
        "schema_version": JOURNAL_VERSION,
        "sequence": sequence,
    }
    digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    record = dict(unsigned)
    record["sha256"] = digest
    raw = _canonical_json(record)
    if len(raw) > MAX_JOURNAL_RECORD_BYTES:
        raise BrokerJournalError("journal record exceeds its byte cap")
    return raw, digest


def _decode_record(raw: bytes) -> JournalRecord:
    value = _strict_json(raw, cap=MAX_JOURNAL_RECORD_BYTES)
    if set(value) != {
        "body",
        "kind",
        "previous_sha256",
        "schema_version",
        "sequence",
        "sha256",
    }:
        raise BrokerJournalError("journal record fields are not exact")
    if value["schema_version"] != JOURNAL_VERSION or not isinstance(value["body"], dict):
        raise BrokerJournalError("journal record version or body is invalid")
    _require_hex(value["previous_sha256"], "journal previous hash")
    _require_hex(value["sha256"], "journal record hash")
    expected_raw, expected_hash = _record_bytes(
        sequence=value["sequence"],
        previous_sha256=value["previous_sha256"],
        kind=value["kind"],
        body=value["body"],
    )
    if expected_raw != raw or not hmac.compare_digest(expected_hash, value["sha256"]):
        raise BrokerJournalError("journal record hash does not match canonical content")
    return JournalRecord(
        value["sequence"],
        value["previous_sha256"],
        value["kind"],
        value["body"],
        value["sha256"],
        raw,
    )


class DurableBrokerJournal:
    """Fsync-before-ack journal model with deterministic restart recovery.

    It does not know how to open storage.  ``BrokerJournalSink`` is deliberately
    narrower than a file-like object so a future implementation cannot be
    tempted to accept caller paths, truncate, rename, or rewrite the journal.
    """

    def __init__(self, installation: BrokerInstallation, sink: BrokerJournalSink) -> None:
        self.installation = installation
        self._sink = sink
        self.records: list[JournalRecord] = []
        self.allocations: dict[str, DurableAllocation] = {}
        self.replay_guards: dict[str, int] = {}
        self.reservations: dict[str, TokenReservation] = {}
        self._last_monotonic_ns = -1

    @classmethod
    def create(
        cls, installation: BrokerInstallation, sink: BrokerJournalSink
    ) -> DurableBrokerJournal:
        journal = cls(installation, sink)
        journal._append("genesis", {"installation_sha256": journal_genesis_sha256(installation)})
        return journal

    @classmethod
    def recover(
        cls,
        installation: BrokerInstallation,
        sink: BrokerJournalSink,
        records: tuple[bytes, ...],
        anchor: BrokerJournalAnchor,
    ) -> DurableBrokerJournal:
        """Recover exactly one complete chain; torn suffixes and prefix rollback fail closed."""

        if not records or len(records) > MAX_JOURNAL_RECORDS:
            raise BrokerJournalRollbackError("journal is absent, empty, or exceeds its record cap")
        if anchor.genesis_sha256 != journal_genesis_sha256(installation):
            raise BrokerJournalRollbackError(
                "journal witness does not bind this installation/boot set"
            )
        if len(records) != anchor.record_count:
            raise BrokerJournalRollbackError(
                "journal length differs from its durable rollback witness"
            )
        journal = cls(installation, sink)
        previous = "0" * 64
        for expected_sequence, raw in enumerate(records):
            record = _decode_record(raw)
            if record.sequence != expected_sequence or record.previous_sha256 != previous:
                raise BrokerJournalRollbackError("journal sequence or chain linkage is invalid")
            if expected_sequence == 0:
                expected = {"installation_sha256": journal_genesis_sha256(installation)}
                if record.kind != "genesis" or record.body != expected:
                    raise BrokerJournalRollbackError(
                        "journal genesis does not bind this installation/boot set"
                    )
            journal._apply(record)
            journal.records.append(record)
            previous = record.sha256
        if previous != anchor.head_sha256:
            raise BrokerJournalRollbackError(
                "journal head differs from its durable rollback witness"
            )
        # A service restart must never continue a partially streamed request.
        # Its data may have been torn or its staged file may have been replaced;
        # preserve the request ID/reservation while making reuse impossible.
        for allocation in tuple(journal.allocations.values()):
            if allocation.state == "uploading":
                journal.quarantine(allocation.allocation.allocation_id, reason="restart")
        return journal

    @property
    def head_sha256(self) -> str:
        return "0" * 64 if not self.records else self.records[-1].sha256

    def snapshot(self) -> tuple[bytes, ...]:
        """Return canonical records for an external root-owned, read-only replay source."""

        return tuple(record.raw for record in self.records)

    @property
    def anchor(self) -> BrokerJournalAnchor:
        """Model the separately fsynced private rollback witness after an append."""

        return BrokerJournalAnchor(
            len(self.records), self.head_sha256, journal_genesis_sha256(self.installation)
        )

    def _append(self, kind: str, body: dict[str, Any]) -> JournalRecord:
        if len(self.records) >= MAX_JOURNAL_RECORDS:
            raise BrokerJournalError("journal record cap is exhausted")
        raw, digest = _record_bytes(
            sequence=len(self.records), previous_sha256=self.head_sha256, kind=kind, body=body
        )
        record = JournalRecord(len(self.records), self.head_sha256, kind, body, digest, raw)
        # Validate a candidate state before touching durable storage.  The
        # journal is append-only, so persisting a semantically invalid record
        # would otherwise permanently wedge future recovery.
        preview = DurableBrokerJournal(self.installation, self._sink)
        preview.allocations = self.allocations.copy()
        preview.replay_guards = self.replay_guards.copy()
        preview.reservations = self.reservations.copy()
        preview._last_monotonic_ns = self._last_monotonic_ns
        preview._apply(record)
        next_anchor = BrokerJournalAnchor(
            len(self.records) + 1, digest, journal_genesis_sha256(self.installation)
        )
        # The service may update in-memory authority only after its dedicated
        # sink confirms an atomic durable journal+witness commit. A failure is
        # a hard failure with no in-memory authority mutation.
        try:
            self._sink.commit_fsynced(raw, next_anchor)
        except Exception as exc:
            raise BrokerJournalError("journal+witness commit was not durably acknowledged") from exc
        self._apply(record)
        self.records.append(record)
        return record

    def _apply(self, record: JournalRecord) -> None:
        body = record.body
        if record.kind == "genesis":
            return
        if record.kind == "allocation":
            self._apply_allocation(body)
        elif record.kind == "append":
            self._apply_append(body)
        elif record.kind == "staged":
            self._apply_staged(body)
        elif record.kind == "quarantined":
            self._apply_quarantined(body)
        elif record.kind == "token_reserved":
            self._apply_token_reserved(body)
        elif record.kind == "token_settled":
            self._apply_token_settled(body)
        else:  # guarded by _record_bytes, retained for defensive replay.
            raise BrokerJournalError("journal event type is unsupported")

    def _apply_allocation(self, body: dict[str, Any]) -> None:
        required = {
            "allocation_id",
            "expires_at_ns",
            "lease_token",
            "observed_at_ns",
            "peer_gid",
            "peer_uid",
            "request_id",
            "run_id",
        }
        if set(body) != required or len(self.allocations) >= MAX_DURABLE_ALLOCATIONS:
            raise BrokerJournalError("journal allocation body is invalid or exceeds its cap")
        for key in ("allocation_id", "lease_token", "request_id", "run_id"):
            _require_hex(body[key], key, size=32)
        if (
            type(body["expires_at_ns"]) is not int
            or body["expires_at_ns"] < 0
            or type(body["observed_at_ns"]) is not int
            or body["observed_at_ns"] < 0
            or body["observed_at_ns"] < self._last_monotonic_ns
            or type(body["peer_uid"]) is not int
            or type(body["peer_gid"]) is not int
            or body["peer_uid"] < 0
            or body["peer_gid"] < 0
            or body["peer_uid"] != self.installation.controller_uid
            or body["request_id"] in self.replay_guards
            or body["allocation_id"] in self.allocations
        ):
            raise BrokerJournalError("journal allocation identity is invalid")
        allocation = BrokerAllocation(
            body["allocation_id"], body["lease_token"], body["run_id"], body["expires_at_ns"]
        )
        self.allocations[allocation.allocation_id] = DurableAllocation(
            allocation,
            BrokerPeer(body["peer_uid"], body["peer_gid"]),
            body["request_id"],
            0,
            0,
            hashlib.sha256(b"").hexdigest(),
            "uploading",
        )
        if len(self.replay_guards) >= MAX_DURABLE_REPLAY_GUARDS:
            raise BrokerJournalError("journal replay-guard cap is exhausted")
        self.replay_guards[body["request_id"]] = body["expires_at_ns"]
        self._last_monotonic_ns = body["observed_at_ns"]

    def _apply_append(self, body: dict[str, Any]) -> None:
        required = {
            "allocation_id",
            "chunk_sha256",
            "next_sequence",
            "observed_at_ns",
            "total_bytes",
        }
        if set(body) != required:
            raise BrokerJournalError("journal append body is invalid")
        allocation_id = _require_hex(body["allocation_id"], "allocation_id", size=32)
        state = self.allocations.get(allocation_id)
        if state is None or state.state != "uploading":
            raise BrokerJournalError("journal append references a non-uploading allocation")
        _require_hex(body["chunk_sha256"], "chunk hash")
        if (
            type(body["next_sequence"]) is not int
            or type(body["total_bytes"]) is not int
            or type(body["observed_at_ns"]) is not int
            or body["observed_at_ns"] < 0
            or body["observed_at_ns"] < self._last_monotonic_ns
            or body["next_sequence"] != state.next_sequence + 1
            or body["next_sequence"] > LFRQ_MAX_BYTES // (64 * 1_024)
            or body["total_bytes"] <= state.total_bytes
            or body["total_bytes"] > LFRQ_MAX_BYTES
            or body["total_bytes"] - state.total_bytes > 64 * 1_024
        ):
            raise BrokerJournalError("journal append counters are invalid")
        chain = hashlib.sha256(
            bytes.fromhex(state.chunk_chain_sha256)
            + bytes.fromhex(body["chunk_sha256"])
            + body["total_bytes"].to_bytes(8, "little")
        ).hexdigest()
        self.allocations[allocation_id] = DurableAllocation(
            state.allocation,
            state.peer,
            state.request_id,
            body["next_sequence"],
            body["total_bytes"],
            chain,
            "uploading",
        )
        self._last_monotonic_ns = body["observed_at_ns"]

    def _apply_staged(self, body: dict[str, Any]) -> None:
        required = {"allocation_id", "request_sha256", "total_bytes"}
        if set(body) != required:
            raise BrokerJournalError("journal staged body is invalid")
        allocation_id = _require_hex(body["allocation_id"], "allocation_id", size=32)
        state = self.allocations.get(allocation_id)
        if state is None or state.state != "uploading":
            raise BrokerJournalError("journal staged event references an invalid allocation")
        _require_hex(body["request_sha256"], "request digest")
        if (
            type(body["total_bytes"]) is not int
            or body["total_bytes"] != state.total_bytes
            or not state.total_bytes
        ):
            raise BrokerJournalError("journal staged request size is invalid")
        self.allocations[allocation_id] = DurableAllocation(
            state.allocation,
            state.peer,
            state.request_id,
            state.next_sequence,
            state.total_bytes,
            state.chunk_chain_sha256,
            "staged",
            body["request_sha256"],
        )

    def _apply_quarantined(self, body: dict[str, Any]) -> None:
        if set(body) != {"allocation_id", "reason"} or body["reason"] not in {
            "restart",
            "invalid",
            "expired",
        }:
            raise BrokerJournalError("journal quarantine body is invalid")
        allocation_id = _require_hex(body["allocation_id"], "allocation_id", size=32)
        state = self.allocations.get(allocation_id)
        if state is None or state.state not in {"uploading", "staged"}:
            raise BrokerJournalError("journal quarantine references an invalid allocation")
        self.allocations[allocation_id] = DurableAllocation(
            state.allocation,
            state.peer,
            state.request_id,
            state.next_sequence,
            state.total_bytes,
            state.chunk_chain_sha256,
            "quarantined",
            state.request_sha256,
        )

    def _apply_token_reserved(self, body: dict[str, Any]) -> None:
        required = {"allocation_id", "request_sha256", "reservation_id", "tokens"}
        if set(body) != required or len(self.reservations) >= MAX_TOKEN_RESERVATIONS:
            raise BrokerJournalError("journal token reservation body is invalid or exceeds its cap")
        reservation_id = _require_hex(body["reservation_id"], "reservation id")
        allocation_id = _require_hex(body["allocation_id"], "allocation_id", size=32)
        request_sha256 = _require_hex(body["request_sha256"], "request digest")
        allocation = self.allocations.get(allocation_id)
        if (
            allocation is None
            or allocation.state != "staged"
            or allocation.request_sha256 != request_sha256
            or reservation_id in self.reservations
            or type(body["tokens"]) is not int
            or not 0 < body["tokens"] <= MAX_TOKEN_RESERVATION_TOKENS
            or self.reserved_tokens + body["tokens"] > MAX_RESERVED_TOKENS
        ):
            raise BrokerJournalError("journal token reservation is not admissible")
        self.reservations[reservation_id] = TokenReservation(
            reservation_id, allocation_id, request_sha256, body["tokens"], "reserved"
        )

    def _apply_token_settled(self, body: dict[str, Any]) -> None:
        if set(body) != {"reservation_id"}:
            raise BrokerJournalError("journal token settlement body is invalid")
        reservation_id = _require_hex(body["reservation_id"], "reservation id")
        reservation = self.reservations.get(reservation_id)
        if reservation is None or reservation.state != "reserved":
            raise BrokerJournalError("journal token settlement is invalid")
        self.reservations[reservation_id] = TokenReservation(
            reservation.reservation_id,
            reservation.allocation_id,
            reservation.request_sha256,
            reservation.tokens,
            "settled",
        )

    @property
    def reserved_tokens(self) -> int:
        return sum(item.tokens for item in self.reservations.values() if item.state == "reserved")

    def allocate(self, peer: BrokerPeer, request_id: str, now_ns: int) -> BrokerAllocation:
        """Persist a broker-generated allocation before returning it to a peer."""

        if peer.uid != self.installation.controller_uid or peer.uid < 0 or peer.gid < 0:
            raise BrokerAuthorizationError("journal peer is not the installed controller")
        _require_hex(request_id, "request id", size=32)
        if type(now_ns) is not int or now_ns < 0 or now_ns < self._last_monotonic_ns:
            raise BrokerJournalRollbackError(
                "broker monotonic epoch regressed; replay safety is unknown"
            )
        if request_id in self.replay_guards or len(self.allocations) >= MAX_DURABLE_ALLOCATIONS:
            raise BrokerJournalError(
                "allocation request is replayed or allocation capacity is exhausted"
            )
        # Import locally to avoid exposing random/token generation as a controller input.
        import secrets

        allocation = BrokerAllocation(
            secrets.token_hex(16),
            secrets.token_hex(16),
            secrets.token_hex(16),
            now_ns + ALLOCATION_TTL_NS,
        )
        self._append(
            "allocation",
            {
                "allocation_id": allocation.allocation_id,
                "expires_at_ns": allocation.expires_at_ns,
                "lease_token": allocation.lease_token,
                "observed_at_ns": now_ns,
                "peer_gid": peer.gid,
                "peer_uid": peer.uid,
                "request_id": request_id,
                "run_id": allocation.run_id,
            },
        )
        self._last_monotonic_ns = now_ns
        return allocation

    def append_chunk(
        self,
        allocation_id: str,
        lease_token: str,
        peer: BrokerPeer,
        chunk: bytes,
        *,
        sequence: int,
        now_ns: int,
    ) -> None:
        """Durably record an accepted chunk's digest; the future service stores bytes separately."""

        allocation_id = _require_hex(allocation_id, "allocation id", size=32)
        _require_hex(lease_token, "lease token", size=32)
        state = self.allocations.get(allocation_id)
        if state is None or state.state != "uploading":
            raise BrokerJournalError("allocation is absent or no longer uploadable")
        if peer != state.peer or not hmac.compare_digest(lease_token, state.allocation.lease_token):
            raise BrokerAuthorizationError("allocation does not belong to this peer")
        if (
            type(sequence) is not int
            or sequence != state.next_sequence
            or type(now_ns) is not int
            or now_ns < self._last_monotonic_ns
            or now_ns > state.allocation.expires_at_ns
            or not isinstance(chunk, bytes)
            or not chunk
            or len(chunk) > 64 * 1_024
            or state.total_bytes + len(chunk) > LFRQ_MAX_BYTES
        ):
            raise BrokerJournalError("chunk is not admissible for this allocation")
        self._append(
            "append",
            {
                "allocation_id": allocation_id,
                "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                "next_sequence": state.next_sequence + 1,
                "observed_at_ns": now_ns,
                "total_bytes": state.total_bytes + len(chunk),
            },
        )
        self._last_monotonic_ns = now_ns

    def validate_and_stage_lfrq(self, allocation_id: str, reader: DescriptorRelativeLFRQ) -> None:
        """Model the required pre-stage descriptor inspection and fail closed.

        The only non-fixture authority type is ``broker``, and no verifier for
        it exists.  Fixture authority is likewise prohibited from a broker
        epoch.  Consequently this method always refuses after binding the
        header; it is present to make bypassing the required inspection
        impossible in a future service integration.
        """

        allocation_id = _require_hex(allocation_id, "allocation id", size=32)
        allocation = self.allocations.get(allocation_id)
        if allocation is None or allocation.state != "uploading":
            raise BrokerJournalError("allocation cannot accept a staged LFRQ")
        observation = observe_unverified_lfrq_header(reader, allocation)
        del observation
        raise BrokerUnavailableError("LFRQ attestation verification is not implemented")

    def quarantine(self, allocation_id: str, *, reason: str) -> None:
        allocation_id = _require_hex(allocation_id, "allocation id", size=32)
        self._append("quarantined", {"allocation_id": allocation_id, "reason": reason})

    def reserve_tokens(
        self, allocation_id: str, request_sha256: str, reservation_id: str, tokens: int
    ) -> None:
        """Record conservative, non-replayable token capacity after staging.

        This does not accept model output or authorize a VM.  A future broker
        must derive ``reservation_id`` from independently verified provider
        evidence, not from an untrusted controller string.
        """

        self._append(
            "token_reserved",
            {
                "allocation_id": allocation_id,
                "request_sha256": request_sha256,
                "reservation_id": reservation_id,
                "tokens": tokens,
            },
        )

    def settle_tokens(self, reservation_id: str) -> None:
        self._append("token_settled", {"reservation_id": reservation_id})


def _decode_fixed(raw: bytes, label: str) -> str:
    if not raw or b"\0" not in raw:
        raise BrokerJournalError(f"LFRQ {label} fixed field is malformed")
    content, padding = raw.split(b"\0", 1)
    if not content or any(padding):
        raise BrokerJournalError(f"LFRQ {label} padding is malformed")
    try:
        return content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BrokerJournalError(f"LFRQ {label} is not ASCII") from exc


def observe_unverified_lfrq_header(
    reader: DescriptorRelativeLFRQ, allocation: DurableAllocation
) -> UnverifiedLFRQHeaderObservation:
    """Observe an unverified LFRQ header only; never use it for admission.

    The caller cannot pass a pathname.  The required production adapter must
    obtain the descriptor with a broker-owned directory descriptor, ``O_NOFOLLOW``
    and a post-open identity check; otherwise this model refuses it.  This is
    deliberately incomplete header observation, not a substitute for the
    complete ``vm_bundle`` parser once it gains a descriptor-native entry
    point. It does not verify payload, section-table canonicality, or authority.
    """

    if not (
        getattr(reader, "opened_relative_to_private_root", False) is True
        and getattr(reader, "opened_nofollow", False) is True
        and getattr(reader, "identity_verified", False) is True
    ):
        raise BrokerUnavailableError("descriptor-relative no-follow LFRQ proof is unavailable")
    size = getattr(reader, "size", None)
    if type(size) is not int or not LFRQ_HEADER_BYTES <= size <= LFRQ_MAX_BYTES or size % 512:
        raise BrokerJournalError("staged LFRQ size is outside exact bounds")
    header = reader.pread_exact(LFRQ_HEADER_BYTES, 0)
    if not isinstance(header, bytes) or len(header) != LFRQ_HEADER_BYTES:
        raise BrokerJournalError("staged LFRQ header is unavailable")
    try:
        (
            magic,
            version,
            header_bytes,
            count,
            reserved,
            total,
            _payload,
            run_raw,
            round_value,
            stage_raw,
            marker,
        ) = _LFRQ_PREFIX.unpack(header[: _LFRQ_PREFIX.size])
    except struct.error as exc:
        raise BrokerJournalError("staged LFRQ prefix is malformed") from exc
    if (
        magic != b"LFRQ"
        or version != 1
        or header_bytes != LFRQ_HEADER_BYTES
        or not 1 <= count <= 16
        or reserved != 0
        or total != size
        or marker != b"\0" * 32
    ):
        raise BrokerJournalError("staged LFRQ prefix does not meet the fixed contract")
    run_id = _decode_fixed(run_raw, "run id")
    if run_id != allocation.allocation.run_id:
        raise BrokerAuthorizationError("staged LFRQ run ID does not match broker allocation")
    stage = _decode_fixed(stage_raw, "stage")
    if stage not in {"planning", "implementation", "review", "final_verify"} or round_value < 0:
        raise BrokerJournalError("staged LFRQ binding is invalid")
    mediation: tuple[int, int, bytes] | None = None
    seen: set[str] = set()
    for index in range(count):
        start = _LFRQ_PREFIX.size + index * _LFRQ_SECTION.size
        raw_name, offset, length, digest = _LFRQ_SECTION.unpack(
            header[start : start + _LFRQ_SECTION.size]
        )
        name = _decode_fixed(raw_name, "section type")
        if name in seen or offset < LFRQ_HEADER_BYTES or length <= 0 or offset + length > total:
            raise BrokerJournalError("staged LFRQ section table is invalid")
        seen.add(name)
        if name == "mediation":
            if length > 64 * 1_024:
                raise BrokerJournalError("staged LFRQ mediation section exceeds its cap")
            mediation = (offset, length, digest)
    if mediation is None:
        raise BrokerJournalError("staged LFRQ omits mediation data")
    offset, length, digest = mediation
    raw_mediation = reader.pread_exact(length, offset)
    if not isinstance(raw_mediation, bytes) or len(raw_mediation) != length:
        raise BrokerJournalError("staged LFRQ mediation section is unavailable")
    if not hmac.compare_digest(hashlib.sha256(raw_mediation).digest(), digest):
        raise BrokerJournalError("staged LFRQ mediation digest does not match")
    mediation_value = _strict_json(raw_mediation, cap=64 * 1_024)
    authority = mediation_value.get("authority")
    reservation_id = mediation_value.get("token_ledger_reservation_id")
    if authority == "broker":
        # This must remain a failure until a separately reviewed, non-caller
        # forgeable broker-attestation verifier exists.
        raise BrokerUnavailableError("broker-shaped mediation authorization has no verifier")
    if authority != "fixture":
        raise BrokerJournalError("staged LFRQ mediation authority is invalid")
    if reservation_id is not None and (
        type(reservation_id) is not str or _HEX64.fullmatch(reservation_id) is None
    ):
        raise BrokerJournalError("staged LFRQ reservation identity is invalid")
    return UnverifiedLFRQHeaderObservation(
        run_id, round_value, stage, total, authority, reservation_id
    )
