"""Durable-state model for the hard-disabled dedicated strict-VM broker.

This module deliberately contains no socket, path, directory, subprocess, or
service implementation.  It describes the *only* durable state a future
dedicated-UID broker may need to persist.  It does not assume that two files
(an append log and a rollback witness) can be committed atomically: ordinary
filesystems cannot make that promise.  Instead, every commit writes a complete
self-validating state image to the inactive one of two broker-owned slots.
Recovery chooses the newest complete slot and ignores a torn or cross-file
mismatched peer.  Passing ordinary paths to this module is impossible by
design.

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
from .vm_bundle import (
    BundleError,
    DescriptorRequestIdentity,
    ParsedBundle,
    parse_request_bundle_descriptor,
)

JOURNAL_VERSION = 1
MAX_JOURNAL_RECORD_BYTES = 32 * 1_024
# Each alternating slot contains a complete image, not an unbounded append
# file.  Keep the pure recovery model deliberately small until a reviewed
# compaction protocol and native storage backend exist.
MAX_SLOT_RECORDS = 128
MAX_SLOT_IMAGE_BYTES = 4 * 1_024 * 1_024
MAX_DURABLE_ALLOCATIONS = MAX_PENDING_ALLOCATIONS
MAX_DURABLE_REPLAY_GUARDS = MAX_REPLAY_GUARDS
MAX_TOKEN_RESERVATIONS = 256
MAX_RESERVED_TOKENS = 1_000_000
MAX_TOKEN_RESERVATION_TOKENS = 100_000
LFRQ_HEADER_BYTES = 4_096
LFRQ_MAX_BYTES = 256 * 1_024 * 1_024
STRICT_VM_BROKER_DESCRIPTOR_ADMISSION_ENABLED = False
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
        "boot_rollover",
        "token_reserved",
        "token_settled",
    }
)


class BrokerJournalError(StrictVMBrokerError):
    """Durable broker state is malformed, incomplete, or not trustworthy."""


class BrokerJournalRollbackError(BrokerJournalError):
    """A journal prefix, genesis, or monotonic epoch could have been rolled back."""


@dataclass(frozen=True)
class BrokerBootSessionEvidence:
    """Digest supplied by a future native adapter for one host boot session.

    This pure Python value is intentionally not authority: callers can create
    it in tests, and no production broker path reaches this model.  A future
    dedicated-UID native adapter must derive it from an OS-backed boot session
    identity and bind it before the source-disabled service is ever enabled.
    """

    sha256: str

    def __post_init__(self) -> None:
        _require_hex(self.sha256, "broker boot-session digest")


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


class RetainedLFRQDescriptor(Protocol):
    """A no-follow FD retained by the future broker after private-dir open.

    This interface has no pathname and requires the adapter to carry the
    complete ``fstat`` snapshot captured immediately after descriptor-relative
    ``O_NOFOLLOW`` acquisition.  The parser independently rechecks every
    identity member through that descriptor before and after bounded reads.
    """

    descriptor: int
    identity: DescriptorRequestIdentity
    opened_relative_to_private_root: bool
    opened_nofollow: bool


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
    """The chain boundary embedded inside one durable slot image.

    Keeping this witness in the same verified image as the records avoids an
    impossible cross-file atomicity claim.  It detects torn/crossed slot
    contents, but cannot stop a compromised broker or storage administrator
    from rolling *both* slots back; that needs a separate root/external anchor.
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


@dataclass(frozen=True)
class BrokerJournalSlot:
    """One whole durable journal image for the alternating two-slot protocol.

    ``slot_sha256`` covers the generation, embedded anchor, and all canonical
    records.  It is corruption detection, not a signature or rollback anchor.
    The deliberately pure model does not prescribe an on-disk encoding.
    """

    generation: int
    records: tuple[bytes, ...]
    anchor: BrokerJournalAnchor
    slot_sha256: str


class BrokerJournalSink(Protocol):
    """Source-disabled two-slot storage contract for a future broker service.

    The adapter reads both complete slot images and writes/fsyncs only the
    inactive slot.  It must never overwrite the active slot in place.  A write
    exception is ambiguous: the image might have reached durable storage after
    the error, so the current process must recover before serving another
    request.  The adapter is not implemented here and accepts no caller path.
    """

    def read_slots(self) -> tuple[object | None, object | None]: ...

    def write_slot_fsynced(self, slot_index: int, slot: BrokerJournalSlot) -> None: ...


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


@dataclass(frozen=True)
class BrokerLFRQAdmissionBinding:
    """Controller identity the future broker must match before it can launch.

    This is deliberately a data-only expectation sourced from the broker's
    attested durable state.  A Python caller can construct one for tests, but
    cannot turn it into authority: public broker admission remains
    source-disabled before it reads a descriptor.
    """

    run_id: str
    round: int
    stage: str
    repository: str
    issue_number: int
    base_sha: str
    manifest_sha256: str
    task_sha256: str
    policy_sha256: str
    check_registry_sha256: str
    action_batch_sha256: str
    mediation_receipt_sha256: str
    proposed_patch_sha256: str | None
    reservation_id: str
    reservation_tokens: int
    boot_session_sha256: str

    def __post_init__(self) -> None:
        if (
            _HEX32.fullmatch(self.run_id) is None
            or type(self.round) is not int
            or not 0 <= self.round <= 1_000_000
            or self.stage not in {"planning", "implementation", "review", "final_verify"}
            or type(self.repository) is not str
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}",
                self.repository,
            )
            is None
            or type(self.issue_number) is not int
            or self.issue_number <= 0
            or re.fullmatch(r"[0-9a-f]{40}", self.base_sha) is None
            or any(
                _HEX64.fullmatch(value) is None
                for value in (
                    self.manifest_sha256,
                    self.task_sha256,
                    self.policy_sha256,
                    self.check_registry_sha256,
                    self.action_batch_sha256,
                    self.mediation_receipt_sha256,
                    self.reservation_id,
                    self.boot_session_sha256,
                )
            )
            or type(self.reservation_tokens) is not int
            or not 1 <= self.reservation_tokens <= MAX_TOKEN_RESERVATION_TOKENS
            or (
                self.proposed_patch_sha256 is not None
                and _HEX64.fullmatch(self.proposed_patch_sha256) is None
            )
        ):
            raise BrokerJournalError("broker LFRQ admission binding is malformed")


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


def _slot_sha256(generation: int, records: tuple[bytes, ...], anchor: BrokerJournalAnchor) -> str:
    """Return a streaming, length-prefixed integrity digest for one slot image."""

    if type(generation) is not int or generation < 0:
        raise BrokerJournalError("journal slot generation is invalid")
    if type(anchor) is not BrokerJournalAnchor:
        raise BrokerJournalError("journal slot anchor type is invalid")
    if type(records) is not tuple or not records or len(records) > MAX_SLOT_RECORDS:
        raise BrokerJournalError("journal slot records are absent or exceed their cap")
    digest = hashlib.sha256()
    digest.update(b"leftovers.strict-vm-broker.slot.v1\0")
    digest.update(generation.to_bytes(8, "big", signed=False))
    digest.update(anchor.record_count.to_bytes(8, "big", signed=False))
    digest.update(bytes.fromhex(anchor.head_sha256))
    digest.update(bytes.fromhex(anchor.genesis_sha256))
    total_bytes = 0
    for raw in records:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JOURNAL_RECORD_BYTES:
            raise BrokerJournalError("journal slot contains an invalid record image")
        total_bytes += len(raw)
        if total_bytes > MAX_SLOT_IMAGE_BYTES:
            raise BrokerJournalError("journal slot image exceeds its byte cap")
        digest.update(len(raw).to_bytes(8, "big", signed=False))
        digest.update(raw)
    return digest.hexdigest()


def _make_slot(
    generation: int, records: tuple[bytes, ...], installation: BrokerInstallation
) -> BrokerJournalSlot:
    """Build a complete slot image only after the candidate chain is valid."""

    decoded = _validate_slot_records(installation, records)
    anchor = BrokerJournalAnchor(
        len(decoded), decoded[-1].sha256, journal_genesis_sha256(installation)
    )
    return BrokerJournalSlot(generation, records, anchor, _slot_sha256(generation, records, anchor))


def _validate_slot_records(
    installation: BrokerInstallation, records: tuple[bytes, ...]
) -> tuple[JournalRecord, ...]:
    """Validate one complete hash chain without trusting any separate witness."""

    if not records or len(records) > MAX_SLOT_RECORDS:
        raise BrokerJournalRollbackError("journal slot is absent, empty, or exceeds its record cap")
    decoded: list[JournalRecord] = []
    previous = "0" * 64
    total_bytes = 0
    for expected_sequence, raw in enumerate(records):
        if not isinstance(raw, bytes):
            raise BrokerJournalError("journal slot record type is invalid")
        total_bytes += len(raw)
        if total_bytes > MAX_SLOT_IMAGE_BYTES:
            raise BrokerJournalRollbackError("journal slot image exceeds its byte cap")
        record = _decode_record(raw)
        if record.sequence != expected_sequence or record.previous_sha256 != previous:
            raise BrokerJournalRollbackError("journal sequence or chain linkage is invalid")
        if expected_sequence == 0:
            if (
                record.kind != "genesis"
                or set(record.body) != {"boot_session_sha256", "installation_sha256"}
                or record.body.get("installation_sha256") != journal_genesis_sha256(installation)
            ):
                raise BrokerJournalRollbackError(
                    "journal genesis does not bind this installation/boot set"
                )
            _require_hex(record.body.get("boot_session_sha256"), "journal boot-session digest")
        decoded.append(record)
        previous = record.sha256
    return tuple(decoded)


class DurableBrokerJournal:
    """Two-slot, fsync-before-reply journal model with deterministic recovery.

    The model writes a *whole candidate chain* to the inactive slot rather than
    pretending an append log and a separate witness have atomic cross-file
    durability.  It does not know how to open storage.  ``BrokerJournalSink``
    is deliberately narrower than a file-like object so a future implementation
    cannot be tempted to accept caller paths, truncate, rename, or rewrite the
    active slot in place.
    """

    def __init__(
        self,
        installation: BrokerInstallation,
        sink: BrokerJournalSink,
        boot_session: BrokerBootSessionEvidence,
    ) -> None:
        self.installation = installation
        self._sink = sink
        self._boot_session = boot_session
        self.records: list[JournalRecord] = []
        self.allocations: dict[str, DurableAllocation] = {}
        self.replay_guards: dict[str, int] = {}
        self.reservations: dict[str, TokenReservation] = {}
        self._last_monotonic_ns = -1
        self._active_slot_index: int | None = None
        self._generation = -1
        self._recovery_required = False

    @classmethod
    def create(
        cls,
        installation: BrokerInstallation,
        sink: BrokerJournalSink,
        *,
        boot_session: BrokerBootSessionEvidence,
    ) -> DurableBrokerJournal:
        slots = cls._read_slots(sink)
        if any(slot is not None for slot in slots):
            raise BrokerJournalError("refusing to initialize nonempty broker slot storage")
        journal = cls(installation, sink, boot_session)
        journal._append(
            "genesis",
            {
                "boot_session_sha256": boot_session.sha256,
                "installation_sha256": journal_genesis_sha256(installation),
            },
        )
        return journal

    @classmethod
    def recover(
        cls,
        installation: BrokerInstallation,
        sink: BrokerJournalSink,
        *,
        boot_session: BrokerBootSessionEvidence,
        now_ns: int,
    ) -> DurableBrokerJournal:
        """Recover the newest complete slot; ignore an incomplete peer slot.

        A valid but older slot is recoverable when its peer is torn, witness-ahead,
        or journal-ahead.  If both are invalid, recovery fails closed.  This
        cannot detect rollback of *both* slots by a compromised broker/storage
        authority; an external/root anchor remains a separate requirement.
        """

        candidates: list[tuple[int, int, DurableBrokerJournal, BrokerJournalSlot]] = []
        for index, slot in enumerate(cls._read_slots(sink)):
            if slot is None:
                continue
            try:
                candidate = cls._from_slot(installation, sink, slot, boot_session)
            except BrokerJournalError:
                continue
            candidates.append((candidate._generation, index, candidate, slot))
        if not candidates:
            raise BrokerJournalRollbackError("no complete broker journal slot is recoverable")
        candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
        generation, index, journal, selected = candidates[0]
        for other_generation, _other_index, _other_journal, other in candidates[1:]:
            if other_generation == generation and other.slot_sha256 != selected.slot_sha256:
                raise BrokerJournalRollbackError("broker slots fork at one generation")
            if abs(other_generation - generation) > 1:
                raise BrokerJournalRollbackError("broker slot generations have an impossible gap")
        journal._active_slot_index = index
        journal._generation = generation
        if type(now_ns) is not int or now_ns < 0:
            raise BrokerJournalRollbackError("new boot monotonic epoch is invalid")
        if journal._boot_session.sha256 != boot_session.sha256:
            # The native supplied session digest changed, so monotonic time may
            # restart.  First persist quarantine for every pending request in
            # the old epoch, then persist the new session boundary. Replay and
            # reservation state remains conservative and is never cleared.
            for allocation in tuple(journal.allocations.values()):
                if allocation.state in {"uploading", "staged"}:
                    journal.quarantine(allocation.allocation.allocation_id, reason="boot_rollover")
            journal._append(
                "boot_rollover",
                {
                    "boot_session_sha256": boot_session.sha256,
                    "observed_at_ns": now_ns,
                },
            )
        # On same-boot recovery, a zero-byte allocation has no staged request
        # to tear and may be replayed exactly. Any partially uploaded request
        # (and every staged request) is quarantined instead of resumed.
        for allocation in tuple(journal.allocations.values()):
            if allocation.state == "staged" or (
                allocation.state == "uploading" and allocation.total_bytes > 0
            ):
                journal.quarantine(allocation.allocation.allocation_id, reason="restart")
        return journal

    @staticmethod
    def _read_slots(sink: BrokerJournalSink) -> tuple[object | None, object | None]:
        try:
            slots = sink.read_slots()
        except Exception as exc:
            raise BrokerJournalError("broker slot storage cannot be read") from exc
        if type(slots) is not tuple or len(slots) != 2:
            raise BrokerJournalError("broker slot storage did not return exactly two slots")
        return slots

    @classmethod
    def _from_slot(
        cls,
        installation: BrokerInstallation,
        sink: BrokerJournalSink,
        raw_slot: object,
        boot_session: BrokerBootSessionEvidence,
    ) -> DurableBrokerJournal:
        if type(raw_slot) is not BrokerJournalSlot:
            raise BrokerJournalError("broker slot image type is invalid")
        slot = raw_slot
        if type(slot.anchor) is not BrokerJournalAnchor:
            raise BrokerJournalError("broker slot anchor type is invalid")
        if (
            type(slot.generation) is not int
            or slot.generation < 0
            or type(slot.slot_sha256) is not str
            or _HEX64.fullmatch(slot.slot_sha256) is None
            or slot.anchor.genesis_sha256 != journal_genesis_sha256(installation)
            or _slot_sha256(slot.generation, slot.records, slot.anchor) != slot.slot_sha256
        ):
            raise BrokerJournalRollbackError(
                "broker slot integrity or installation binding is invalid"
            )
        records = _validate_slot_records(installation, slot.records)
        if (
            slot.anchor.record_count != len(records)
            or slot.anchor.head_sha256 != records[-1].sha256
        ):
            raise BrokerJournalRollbackError("broker slot journal and embedded witness disagree")
        journal = cls(installation, sink, boot_session)
        for record in records:
            journal._apply(record)
            journal.records.append(record)
        journal._generation = slot.generation
        return journal

    @property
    def head_sha256(self) -> str:
        return "0" * 64 if not self.records else self.records[-1].sha256

    def snapshot(self) -> tuple[bytes, ...]:
        """Return the bounded canonical records in the current in-memory slot image."""

        return tuple(record.raw for record in self.records)

    @property
    def slot_snapshot(self) -> BrokerJournalSlot:
        """Return the current complete slot image for deterministic fixture inspection."""

        if self._generation < 0:
            raise BrokerJournalError("broker journal has no durable slot")
        return _make_slot(self._generation, self.snapshot(), self.installation)

    @property
    def recovery_required(self) -> bool:
        """Whether an ambiguous write error requires restart recovery before use."""

        return self._recovery_required

    @property
    def boot_session_sha256(self) -> str:
        """Return the latest durably recorded boot session digest."""

        return self._boot_session.sha256

    @property
    def anchor(self) -> BrokerJournalAnchor:
        """Return the chain boundary embedded in the current slot image."""

        return BrokerJournalAnchor(
            len(self.records), self.head_sha256, journal_genesis_sha256(self.installation)
        )

    def _append(self, kind: str, body: dict[str, Any]) -> JournalRecord:
        if self._recovery_required:
            raise BrokerJournalError(
                "broker journal requires recovery after an ambiguous slot write"
            )
        if len(self.records) >= MAX_SLOT_RECORDS:
            raise BrokerJournalError("broker slot history cap is exhausted")
        raw, digest = _record_bytes(
            sequence=len(self.records), previous_sha256=self.head_sha256, kind=kind, body=body
        )
        record = JournalRecord(len(self.records), self.head_sha256, kind, body, digest, raw)
        # Validate a candidate state before touching durable storage.  The
        # journal is append-only, so persisting a semantically invalid record
        # would otherwise permanently wedge future recovery.
        preview = DurableBrokerJournal(self.installation, self._sink, self._boot_session)
        preview.allocations = self.allocations.copy()
        preview.replay_guards = self.replay_guards.copy()
        preview.reservations = self.reservations.copy()
        preview._last_monotonic_ns = self._last_monotonic_ns
        preview._apply(record)
        next_records = self.snapshot() + (raw,)
        next_generation = self._generation + 1
        next_slot = _make_slot(next_generation, next_records, self.installation)
        target_slot = 0 if self._active_slot_index != 0 else 1
        # The service may update in-memory authority only after its dedicated
        # sink confirms the inactive, whole state image.  An error is
        # ambiguous: a later crash recovery may discover that the write made
        # durable progress, so this live instance must serve nothing further.
        try:
            self._sink.write_slot_fsynced(target_slot, next_slot)
        except Exception as exc:
            self._recovery_required = True
            raise BrokerJournalError("broker slot commit was not durably acknowledged") from exc
        self._apply(record)
        self.records.append(record)
        self._active_slot_index = target_slot
        self._generation = next_generation
        return record

    def _ensure_usable(self) -> None:
        if self._recovery_required:
            raise BrokerJournalError(
                "broker journal requires recovery after an ambiguous slot write"
            )

    def _apply(self, record: JournalRecord) -> None:
        body = record.body
        if record.kind == "genesis":
            self._apply_genesis(body)
        elif record.kind == "allocation":
            self._apply_allocation(body)
        elif record.kind == "append":
            self._apply_append(body)
        elif record.kind == "staged":
            self._apply_staged(body)
        elif record.kind == "quarantined":
            self._apply_quarantined(body)
        elif record.kind == "boot_rollover":
            self._apply_boot_rollover(body)
        elif record.kind == "token_reserved":
            self._apply_token_reserved(body)
        elif record.kind == "token_settled":
            self._apply_token_settled(body)
        else:  # guarded by _record_bytes, retained for defensive replay.
            raise BrokerJournalError("journal event type is unsupported")

    def _apply_genesis(self, body: dict[str, Any]) -> None:
        if set(body) != {"boot_session_sha256", "installation_sha256"}:
            raise BrokerJournalError("journal genesis body is invalid")
        if body["installation_sha256"] != journal_genesis_sha256(self.installation):
            raise BrokerJournalRollbackError("journal genesis installation binding is invalid")
        self._boot_session = BrokerBootSessionEvidence(
            _require_hex(body["boot_session_sha256"], "journal boot-session digest")
        )

    def _apply_boot_rollover(self, body: dict[str, Any]) -> None:
        if set(body) != {"boot_session_sha256", "observed_at_ns"}:
            raise BrokerJournalError("journal boot rollover body is invalid")
        next_session = BrokerBootSessionEvidence(
            _require_hex(body["boot_session_sha256"], "journal boot-session digest")
        )
        if (
            next_session.sha256 == self._boot_session.sha256
            or type(body["observed_at_ns"]) is not int
            or body["observed_at_ns"] < 0
        ):
            raise BrokerJournalError("journal boot rollover is invalid")
        self._boot_session = next_session
        self._last_monotonic_ns = body["observed_at_ns"]

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
            "boot_rollover",
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

        self._ensure_usable()
        if peer.uid != self.installation.controller_uid or peer.uid < 0 or peer.gid < 0:
            raise BrokerAuthorizationError("journal peer is not the installed controller")
        _require_hex(request_id, "request id", size=32)
        if type(now_ns) is not int or now_ns < 0:
            raise BrokerJournalRollbackError("broker monotonic epoch is invalid")
        # Allocation is an idempotent request/reply operation.  If the slot
        # reached durable storage just before a crash but the reply was lost,
        # the same installed peer can recover the exact broker-generated value
        # without creating a second epoch or wedging the durable prefix.
        for state in self.allocations.values():
            if state.request_id == request_id:
                if state.peer != peer:
                    raise BrokerAuthorizationError("allocation replay peer does not match")
                if (
                    state.state == "uploading"
                    and state.total_bytes == 0
                    and now_ns <= state.allocation.expires_at_ns
                ):
                    return state.allocation
                raise BrokerJournalError("allocation replay is no longer safely resumable")
        if now_ns < self._last_monotonic_ns:
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

        self._ensure_usable()
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
        """Deny public admission before observing a descriptor or controller bytes.

        A future daemon may use :func:`inspect_complete_lfrq_admission_contract`
        only after an independently reviewed installation/peer attestation and
        an atomic staged-plus-token-reservation commit are available.
        """

        del self, allocation_id, reader
        if not STRICT_VM_BROKER_DESCRIPTOR_ADMISSION_ENABLED:
            raise BrokerUnavailableError(
                "descriptor admission lacks installed broker peer/launchd attestation "
                "and atomic staged-plus-token-reservation evidence"
            )
        raise BrokerUnavailableError("strict VM descriptor admission is not implemented")

    def quarantine(self, allocation_id: str, *, reason: str) -> None:
        self._ensure_usable()
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

        self._ensure_usable()
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
        self._ensure_usable()
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


def inspect_complete_lfrq_admission_contract(
    journal: DurableBrokerJournal,
    allocation_id: str,
    request: RetainedLFRQDescriptor,
    *,
    binding: BrokerLFRQAdmissionBinding,
    observed_monotonic_ns: int,
    boot_session: BrokerBootSessionEvidence,
) -> ParsedBundle:
    """Validate every descriptor-bound LFRQ field without granting admission.

    This is the complete *pure* contract a future broker must satisfy after
    its own source gate and OS-backed peer/installation attestation have
    passed.  It never writes the journal, chooses a launcher, or returns a
    launch capability.  In particular, fixture mediation is rejected by the
    descriptor parser and a broker-shaped receipt remains structurally checked
    only; an installed non-caller-forgeable attestation verifier is still
    required before this inspection may be used for production admission.
    """

    if not isinstance(journal, DurableBrokerJournal):
        raise BrokerJournalError("complete LFRQ inspection requires a broker journal")
    allocation_id = _require_hex(allocation_id, "allocation id", size=32)
    if (
        type(observed_monotonic_ns) is not int
        or observed_monotonic_ns < 0
        or type(boot_session) is not BrokerBootSessionEvidence
        or not hmac.compare_digest(boot_session.sha256, binding.boot_session_sha256)
        or not hmac.compare_digest(boot_session.sha256, journal.boot_session_sha256)
    ):
        raise BrokerAuthorizationError("broker observation time or boot session is invalid")
    allocation = journal.allocations.get(allocation_id)
    if allocation is None or allocation.state != "staged":
        raise BrokerJournalError("LFRQ allocation is not durably staged")
    if (
        observed_monotonic_ns < journal._last_monotonic_ns
        or observed_monotonic_ns > allocation.allocation.expires_at_ns
    ):
        raise BrokerAuthorizationError(
            "broker LFRQ allocation is expired or monotonic time regressed"
        )
    if (
        getattr(request, "opened_relative_to_private_root", None) is not True
        or getattr(request, "opened_nofollow", None) is not True
        or type(getattr(request, "descriptor", None)) is not int
        or not isinstance(getattr(request, "identity", None), DescriptorRequestIdentity)
    ):
        raise BrokerUnavailableError("retained descriptor-native LFRQ proof is unavailable")
    if binding.run_id != allocation.allocation.run_id:
        raise BrokerAuthorizationError("broker LFRQ binding does not match allocation run ID")
    try:
        parsed = parse_request_bundle_descriptor(
            request.descriptor,
            identity=request.identity,
            expected_uid=journal.installation.broker_uid,
            run_id=binding.run_id,
            round=binding.round,
            stage=binding.stage,
        )
    except BundleError as exc:
        raise BrokerJournalError("complete staged LFRQ is invalid") from exc
    if (
        allocation.request_sha256 != parsed.sha256
        or allocation.total_bytes != request.identity.size
    ):
        raise BrokerAuthorizationError("staged LFRQ does not match its durable allocation")
    reservation = journal.reservations.get(binding.reservation_id)
    if (
        reservation is None
        or reservation.state != "reserved"
        or reservation.allocation_id != allocation_id
        or reservation.request_sha256 != parsed.sha256
        or reservation.tokens != binding.reservation_tokens
    ):
        raise BrokerAuthorizationError("LFRQ has no matching durable token reservation")

    task = parsed.sections.get("task")
    target = task.get("trusted", {}).get("target") if type(task) is dict else None
    if type(target) is not dict or (
        target.get("repository"),
        target.get("issue_number"),
        target.get("base_sha"),
    ) != (binding.repository, binding.issue_number, binding.base_sha):
        raise BrokerAuthorizationError("LFRQ repository, issue, or base SHA binding is invalid")
    mediation = parsed.sections.get("mediation")
    if type(mediation) is not dict or (
        mediation.get("authority"),
        mediation.get("token_ledger_reservation_id"),
    ) != ("broker", binding.reservation_id):
        raise BrokerAuthorizationError("LFRQ broker mediation identity is invalid")
    if any(
        type(mediation.get(name)) is not int or mediation[name] > reservation.tokens
        for name in (
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "reasoning_tokens",
            "total_tokens",
            "input_token_cap",
            "output_token_cap",
            "total_token_cap",
        )
    ):
        raise BrokerAuthorizationError("LFRQ mediation usage or caps exceed reserved tokens")
    values = {
        "manifest_sha256": _section_sha256(parsed.sections.get("manifest")),
        "task_sha256": _section_sha256(task),
        "policy_sha256": _section_sha256(parsed.sections.get("policy")),
        "check_registry_sha256": _section_sha256(parsed.sections.get("check_registry")),
        "action_batch_sha256": _section_sha256(parsed.sections.get("action_batch")),
        "mediation_receipt_sha256": _section_sha256(mediation),
        "proposed_patch_sha256": _raw_section_sha256(parsed, "proposed_patch"),
    }
    expected = {
        "manifest_sha256": binding.manifest_sha256,
        "task_sha256": binding.task_sha256,
        "policy_sha256": binding.policy_sha256,
        "check_registry_sha256": binding.check_registry_sha256,
        "action_batch_sha256": binding.action_batch_sha256,
        "mediation_receipt_sha256": binding.mediation_receipt_sha256,
        "proposed_patch_sha256": binding.proposed_patch_sha256,
    }
    if any(not _same_optional_digest(values[name], expected[name]) for name in expected):
        raise BrokerAuthorizationError(
            "LFRQ section identities do not match durable broker binding"
        )
    return parsed


def _section_sha256(value: Any) -> str:
    try:
        return hashlib.sha256(_canonical_json(value)).hexdigest()
    except BrokerJournalError:
        raise
    except Exception as exc:  # defensive boundary around untrusted parsed JSON
        raise BrokerJournalError("LFRQ section cannot be canonically bound") from exc


def _raw_section_sha256(parsed: ParsedBundle, section_type: str) -> str | None:
    section = parsed.raw_sections.get(section_type)
    return None if section is None else section.sha256


def _same_optional_digest(observed: object, expected: object) -> bool:
    """Constant-time compare only two same-typed, validated digest values."""

    if observed is None or expected is None:
        return observed is None and expected is None
    if type(observed) is not str or type(expected) is not str:
        return False
    return hmac.compare_digest(observed, expected)
