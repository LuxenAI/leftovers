"""Descriptor-relative two-slot storage for the source-disabled broker journal.

This module deliberately accepts a *pre-opened* private-root descriptor, never
a path. Its executable implementation is fixture-capability-only while the
real broker service remains disabled. The two files are complete binary slot
images: raw canonical journal records stay length-prefixed, so persistence does
not add a JSON or base64 copy of the already-canonical records.

An unreadable slot is represented by a non-``None`` sentinel. That distinction
is important: an empty slot is safe for journal initialization, whereas a torn
or corrupt slot must make initialization refuse and may only be ignored during
recovery when the other slot is independently valid.
"""

from __future__ import annotations

import fcntl
import os
import stat
import struct
from dataclasses import dataclass

from .strict_vm_broker import BrokerUnavailableError
from .strict_vm_broker_journal import (
    MAX_JOURNAL_RECORD_BYTES,
    MAX_SLOT_IMAGE_BYTES,
    MAX_SLOT_RECORDS,
    BrokerJournalAnchor,
    BrokerJournalError,
    BrokerJournalSlot,
    _decode_record,
    _slot_sha256,
)

STRICT_VM_BROKER_JOURNAL_STORAGE_ENABLED = False

_SLOT_MAGIC = b"LVBRSLOT"
_SLOT_VERSION = 1
_HEADER = struct.Struct(">8sHHQI32sQ32s32s")
_RECORD_LENGTH = struct.Struct(">I")
_SLOT_NAMES = ("journal.slot0", "journal.slot1")
_TEMP_NAMES = ("journal.slot0.tmp", "journal.slot1.tmp")
_IO_CHUNK_BYTES = 64 * 1_024
_MAX_WIRE_SLOT_BYTES = (
    MAX_SLOT_IMAGE_BYTES + _HEADER.size + (MAX_SLOT_RECORDS * _RECORD_LENGTH.size)
)
_MAX_IO_ATTEMPTS = 4_096
_FIXTURE_CAPABILITY_SECRET = object()


class BrokerJournalStorageError(RuntimeError):
    """The broker-private storage boundary cannot be proved safe."""


class BrokerJournalStorageAmbiguousError(BrokerJournalStorageError):
    """A write may have reached durable storage; restart recovery is required."""


class FixtureBrokerJournalStorageCapability:
    """Explicit in-process authority for storage tests, never production use."""

    __slots__ = ("_secret",)

    def __init__(self, secret: object) -> None:
        if secret is not _FIXTURE_CAPABILITY_SECRET:
            raise BrokerUnavailableError("fixture journal storage capability cannot be forged")
        self._secret = secret


def issue_fixture_broker_journal_storage_capability() -> FixtureBrokerJournalStorageCapability:
    """Issue a fixture-only capability with no daemon, path, or service authority."""

    return FixtureBrokerJournalStorageCapability(_FIXTURE_CAPABILITY_SECRET)


def _require_fixture_capability(capability: FixtureBrokerJournalStorageCapability) -> None:
    if (
        type(capability) is not FixtureBrokerJournalStorageCapability
        or getattr(capability, "_secret", None) is not _FIXTURE_CAPABILITY_SECRET
    ):
        raise BrokerUnavailableError("explicit fixture journal storage capability is required")


def _require_production_storage_enabled() -> None:
    if not STRICT_VM_BROKER_JOURNAL_STORAGE_ENABLED:
        raise BrokerUnavailableError("strict VM broker journal storage is source-disabled")


@dataclass(frozen=True)
class UnreadableBrokerJournalSlot:
    """A present slot that must never be confused with an absent slot."""

    slot_index: int


def _fd_cloexec(fd: int) -> bool:
    try:
        return bool(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
    except OSError as exc:
        raise BrokerJournalStorageError("broker storage descriptor is unavailable") from exc


def _private_root_identity(
    fd: int, broker_uid: int, *, require_cloexec: bool = True
) -> tuple[int, int, int, int]:
    if type(fd) is not int or fd < 0 or type(broker_uid) is not int or broker_uid < 0:
        raise BrokerJournalStorageError("broker storage root descriptor is malformed")
    try:
        details = os.fstat(fd)
        volume = os.fstatvfs(fd)
    except OSError as exc:
        raise BrokerJournalStorageError("broker storage root descriptor is unavailable") from exc
    local_flag = getattr(os, "ST_LOCAL", None)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != broker_uid
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_nlink < 2
        or (require_cloexec and not _fd_cloexec(fd))
        or (local_flag is not None and not volume.f_flag & local_flag)
    ):
        raise BrokerJournalStorageError("broker storage private root is unsafe")
    # Directory link counts are not stable on every supported filesystem when
    # ordinary children are created, so require a sane count but do not bind it.
    return (details.st_dev, details.st_ino, details.st_mode, details.st_uid)


def _regular_file_identity(details: os.stat_result, broker_uid: int) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != broker_uid
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_nlink != 1
        or details.st_size < 0
        or details.st_size > _MAX_WIRE_SLOT_BYTES
    ):
        raise BrokerJournalStorageError("broker slot file identity is unsafe")
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _same_file_across_rename(before: tuple[int, ...], after: tuple[int, ...]) -> bool:
    """Compare an inode identity while allowing rename to advance ctime only."""

    return before[:7] == after[:7] and after[7] >= before[7]


def _write_all(fd: int, value: bytes) -> None:
    offset = 0
    attempts = 0
    while offset < len(value):
        attempts += 1
        if attempts > _MAX_IO_ATTEMPTS:
            raise BrokerJournalStorageError("broker slot write did not make bounded progress")
        try:
            written = os.write(fd, value[offset : offset + _IO_CHUNK_BYTES])
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrokerJournalStorageError("broker slot descriptor write failed") from exc
        if (
            type(written) is not int
            or written <= 0
            or written > min(_IO_CHUNK_BYTES, len(value) - offset)
        ):
            raise BrokerJournalStorageError("broker slot descriptor write made invalid progress")
        offset += written


def _read_exact(fd: int, size: int) -> bytes:
    if type(size) is not int or size < 0 or size > _MAX_WIRE_SLOT_BYTES:
        raise BrokerJournalStorageError("broker slot read bound is invalid")
    chunks: list[bytes] = []
    remaining = size
    attempts = 0
    while remaining:
        attempts += 1
        if attempts > _MAX_IO_ATTEMPTS:
            raise BrokerJournalStorageError("broker slot read did not make bounded progress")
        try:
            chunk = os.read(fd, min(remaining, _IO_CHUNK_BYTES))
        except InterruptedError:
            continue
        except OSError as exc:
            raise BrokerJournalStorageError("broker slot descriptor read failed") from exc
        if not isinstance(chunk, bytes) or not chunk or len(chunk) > remaining:
            raise BrokerJournalStorageError("broker slot image is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_slot(slot: BrokerJournalSlot) -> None:
    if type(slot) is not BrokerJournalSlot or type(slot.anchor) is not BrokerJournalAnchor:
        raise BrokerJournalStorageError("broker slot value is malformed")
    if (
        type(slot.generation) is not int
        or slot.generation < 0
        or type(slot.records) is not tuple
        or not 1 <= len(slot.records) <= MAX_SLOT_RECORDS
        or slot.anchor.record_count != len(slot.records)
    ):
        raise BrokerJournalStorageError("broker slot shape exceeds fixed bounds")
    total_bytes = 0
    previous = "0" * 64
    for expected_sequence, raw in enumerate(slot.records):
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_JOURNAL_RECORD_BYTES:
            raise BrokerJournalStorageError("broker slot record exceeds fixed bounds")
        total_bytes += len(raw)
        if total_bytes > MAX_SLOT_IMAGE_BYTES:
            raise BrokerJournalStorageError("broker slot image exceeds fixed bounds")
        try:
            decoded = _decode_record(raw)
        except BrokerJournalError as exc:
            raise BrokerJournalStorageError("broker slot record is not canonical") from exc
        if decoded.sequence != expected_sequence or decoded.previous_sha256 != previous:
            raise BrokerJournalStorageError("broker slot record chain is malformed")
        previous = decoded.sha256
    if slot.anchor.head_sha256 != previous:
        raise BrokerJournalStorageError("broker slot embedded anchor is malformed")
    try:
        expected = _slot_sha256(slot.generation, slot.records, slot.anchor)
    except BrokerJournalError as exc:
        raise BrokerJournalStorageError("broker slot integrity digest is malformed") from exc
    if expected != slot.slot_sha256:
        raise BrokerJournalStorageError("broker slot integrity digest does not match")


def _encode_header(slot: BrokerJournalSlot) -> bytes:
    try:
        return _HEADER.pack(
            _SLOT_MAGIC,
            _SLOT_VERSION,
            0,
            slot.generation,
            len(slot.records),
            bytes.fromhex(slot.slot_sha256),
            slot.anchor.record_count,
            bytes.fromhex(slot.anchor.head_sha256),
            bytes.fromhex(slot.anchor.genesis_sha256),
        )
    except (ValueError, struct.error) as exc:
        raise BrokerJournalStorageError("broker slot binary header is malformed") from exc


def _decode_slot(fd: int, details: os.stat_result, broker_uid: int) -> BrokerJournalSlot:
    before = _regular_file_identity(details, broker_uid)
    if details.st_size < _HEADER.size:
        raise BrokerJournalStorageError("broker slot image is truncated")
    header = _read_exact(fd, _HEADER.size)
    try:
        (
            magic,
            version,
            reserved,
            generation,
            record_count,
            slot_sha256,
            anchor_count,
            anchor_head,
            anchor_genesis,
        ) = _HEADER.unpack(header)
    except struct.error as exc:
        raise BrokerJournalStorageError("broker slot header is malformed") from exc
    if (
        magic != _SLOT_MAGIC
        or version != _SLOT_VERSION
        or reserved != 0
        or not 1 <= record_count <= MAX_SLOT_RECORDS
        or anchor_count != record_count
    ):
        raise BrokerJournalStorageError("broker slot header fields are invalid")
    records: list[bytes] = []
    total_record_bytes = 0
    for _ in range(record_count):
        raw_length = _read_exact(fd, _RECORD_LENGTH.size)
        (length,) = _RECORD_LENGTH.unpack(raw_length)
        if not 1 <= length <= MAX_JOURNAL_RECORD_BYTES:
            raise BrokerJournalStorageError("broker slot record length is outside bounds")
        total_record_bytes += length
        if total_record_bytes > MAX_SLOT_IMAGE_BYTES:
            raise BrokerJournalStorageError("broker slot image exceeds fixed bounds")
        records.append(_read_exact(fd, length))
    expected_size = _HEADER.size + (record_count * _RECORD_LENGTH.size) + total_record_bytes
    if expected_size != details.st_size:
        raise BrokerJournalStorageError("broker slot image has trailing or missing bytes")
    try:
        after = os.fstat(fd)
    except OSError as exc:
        raise BrokerJournalStorageError("broker slot descriptor disappeared while reading") from exc
    if _regular_file_identity(after, broker_uid) != before:
        raise BrokerJournalStorageError("broker slot identity changed while reading")
    try:
        slot = BrokerJournalSlot(
            generation,
            tuple(records),
            BrokerJournalAnchor(anchor_count, anchor_head.hex(), anchor_genesis.hex()),
            slot_sha256.hex(),
        )
    except BrokerJournalError as exc:
        raise BrokerJournalStorageError("broker slot anchor is malformed") from exc
    _validate_slot(slot)
    return slot


class StrictVMBrokerJournalStorage:
    """Production construction point that rejects before inspecting an FD."""

    def __init__(self, *_: object, **__: object) -> None:
        _require_production_storage_enabled()
        raise BrokerUnavailableError("strict VM broker journal storage is unimplemented")


class FixtureBrokerJournalStorage:
    """Capability-gated descriptor-native ``BrokerJournalSink`` implementation."""

    def __init__(
        self,
        private_root_fd: int,
        *,
        broker_uid: int,
        capability: FixtureBrokerJournalStorageCapability,
    ) -> None:
        _require_fixture_capability(capability)
        _private_root_identity(private_root_fd, broker_uid, require_cloexec=False)
        retained_fd = -1
        try:
            retained_fd = os.dup(private_root_fd)
            os.set_inheritable(retained_fd, False)
            self._root_identity = _private_root_identity(retained_fd, broker_uid)
        except Exception as exc:
            close_error: OSError | None = None
            if retained_fd >= 0:
                closing_fd = retained_fd
                retained_fd = -1
                try:
                    os.close(closing_fd)
                except OSError as cleanup_exc:
                    close_error = cleanup_exc
            if close_error is not None:
                raise BrokerJournalStorageError(
                    "failed broker storage constructor cleanup close is ambiguous"
                ) from close_error
            if isinstance(exc, BrokerJournalStorageError):
                raise
            raise BrokerJournalStorageError("cannot retain broker storage root descriptor") from exc
        self._root_fd = retained_fd
        self._broker_uid = broker_uid
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            # POSIX close errors, especially EINTR, do not prove whether the
            # descriptor remains open. Poison our reference first so this
            # object can never reuse a possibly closed/reassigned descriptor.
            retained_fd = self._root_fd
            self._root_fd = -1
            self._closed = True
            try:
                os.close(retained_fd)
            except OSError as exc:
                raise BrokerJournalStorageError(
                    "broker storage root descriptor cannot close"
                ) from exc

    def __enter__(self) -> FixtureBrokerJournalStorage:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_open_root(self) -> None:
        if self._closed:
            raise BrokerJournalStorageError("broker storage root descriptor is closed")
        if _private_root_identity(self._root_fd, self._broker_uid) != self._root_identity:
            raise BrokerJournalStorageError("broker storage root identity changed")

    @staticmethod
    def _require_slot_index(slot_index: int) -> int:
        if type(slot_index) is not int or slot_index not in (0, 1):
            raise BrokerJournalStorageError("broker slot index is invalid")
        return slot_index

    def read_slots(self) -> tuple[object | None, object | None]:
        """Return absent, valid, or explicit unreadable values for exactly two slots."""

        self._require_open_root()
        slots = tuple(self._read_one(index) for index in range(2))
        self._require_open_root()
        return slots  # type: ignore[return-value]

    def _read_one(self, slot_index: int) -> BrokerJournalSlot | UnreadableBrokerJournalSlot | None:
        name = _SLOT_NAMES[slot_index]
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        fd = -1
        try:
            fd = os.open(name, flags, dir_fd=self._root_fd)
        except FileNotFoundError:
            return None
        except OSError:
            return UnreadableBrokerJournalSlot(slot_index)
        result: BrokerJournalSlot | UnreadableBrokerJournalSlot = UnreadableBrokerJournalSlot(
            slot_index
        )
        close_error: OSError | None = None
        try:
            try:
                result = _decode_slot(fd, os.fstat(fd), self._broker_uid)
            except (BrokerJournalStorageError, OSError):
                result = UnreadableBrokerJournalSlot(slot_index)
        finally:
            # Poison before close: if close is ambiguous, no code below can
            # reuse the numeric FD and no decoded slot is published as valid.
            closing_fd = fd
            fd = -1
            try:
                os.close(closing_fd)
            except OSError as exc:
                close_error = exc
        if close_error is not None:
            return UnreadableBrokerJournalSlot(slot_index)
        return result

    @staticmethod
    def _prove_name_absent(root_fd: int, name: str) -> None:
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise BrokerJournalStorageError("broker stale temp absence cannot be proved") from exc
        raise BrokerJournalStorageError("broker stale temp reappeared after unlink")

    def recover_fixture_stale_temps(self) -> None:
        """Remove only descriptor-proved crash remnants at the two fixed temp names.

        This fixture-only method is intentionally separate from reads and
        writes. A caller must invoke it during restart recovery, before journal
        service resumes. Once unlink is attempted, any error is ambiguous and
        the process must remain stopped; it may retry only through a fresh
        recovery pass.
        """

        self._require_open_root()
        for temp_name in _TEMP_NAMES:
            self._recover_one_stale_temp(temp_name)
        self._require_open_root()

    def _recover_one_stale_temp(self, temp_name: str) -> None:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        fd = -1
        unlink_attempted = False
        try:
            try:
                fd = os.open(temp_name, flags, dir_fd=self._root_fd)
            except FileNotFoundError:
                self._require_open_root()
                return
            except OSError as exc:
                raise BrokerJournalStorageError(
                    "broker stale temp cannot be opened without following"
                ) from exc

            before_details = os.fstat(fd)
            before_identity = _regular_file_identity(before_details, self._broker_uid)
            if not _fd_cloexec(fd):
                raise BrokerJournalStorageError("broker stale temp descriptor is inheritable")
            if _regular_file_identity(os.fstat(fd), self._broker_uid) != before_identity:
                raise BrokerJournalStorageError("broker stale temp identity changed before unlink")

            unlink_attempted = True
            os.unlink(temp_name, dir_fd=self._root_fd)
            after_unlink = os.fstat(fd)
            if (
                after_unlink.st_dev,
                after_unlink.st_ino,
                after_unlink.st_mode,
                after_unlink.st_uid,
                after_unlink.st_size,
                after_unlink.st_mtime_ns,
            ) != (
                before_details.st_dev,
                before_details.st_ino,
                before_details.st_mode,
                before_details.st_uid,
                before_details.st_size,
                before_details.st_mtime_ns,
            ) or after_unlink.st_nlink != 0:
                raise BrokerJournalStorageError(
                    "broker stale temp descriptor does not prove exact unlink"
                )
            self._prove_name_absent(self._root_fd, temp_name)
            self._require_open_root()
            os.fsync(self._root_fd)
            self._require_open_root()
            self._prove_name_absent(self._root_fd, temp_name)
        except BrokerJournalStorageError as exc:
            if unlink_attempted:
                raise BrokerJournalStorageAmbiguousError(
                    "broker stale temp recovery outcome is ambiguous"
                ) from exc
            raise
        except OSError as exc:
            if unlink_attempted:
                raise BrokerJournalStorageAmbiguousError(
                    "broker stale temp recovery outcome is ambiguous"
                ) from exc
            raise BrokerJournalStorageError("broker stale temp inspection failed") from exc
        finally:
            if fd >= 0:
                closing_fd = fd
                fd = -1
                try:
                    os.close(closing_fd)
                except OSError as exc:
                    if unlink_attempted:
                        raise BrokerJournalStorageAmbiguousError(
                            "broker stale temp recovery outcome is ambiguous"
                        ) from exc
                    raise BrokerJournalStorageError(
                        "broker stale temp descriptor cannot close"
                    ) from exc

    def write_slot_fsynced(self, slot_index: int, slot: BrokerJournalSlot) -> None:
        """Replace one exact slot; every post-temp failure is ambiguity requiring recovery."""

        slot_index = self._require_slot_index(slot_index)
        self._require_open_root()
        _validate_slot(slot)
        temp_name = _TEMP_NAMES[slot_index]
        slot_name = _SLOT_NAMES[slot_index]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = -1
        destination_fd = -1
        created = False
        try:
            fd = os.open(temp_name, flags, 0o600, dir_fd=self._root_fd)
            created = True
            _write_all(fd, _encode_header(slot))
            for raw in slot.records:
                _write_all(fd, _RECORD_LENGTH.pack(len(raw)))
                _write_all(fd, raw)
            os.fsync(fd)
            written_identity = _regular_file_identity(os.fstat(fd), self._broker_uid)
            expected_size = (
                _HEADER.size
                + (len(slot.records) * _RECORD_LENGTH.size)
                + sum(len(raw) for raw in slot.records)
            )
            if written_identity[5] != expected_size:
                raise BrokerJournalStorageError("broker temporary slot size changed while writing")
            os.replace(temp_name, slot_name, src_dir_fd=self._root_fd, dst_dir_fd=self._root_fd)
            renamed_identity = _regular_file_identity(os.fstat(fd), self._broker_uid)
            if not _same_file_across_rename(written_identity, renamed_identity):
                raise BrokerJournalStorageError(
                    "broker fsynced temp identity changed across rename"
                )
            self._prove_name_absent(self._root_fd, temp_name)
            self._require_open_root()
            os.fsync(self._root_fd)
            self._require_open_root()
            self._prove_name_absent(self._root_fd, temp_name)

            read_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
            destination_fd = os.open(slot_name, read_flags, dir_fd=self._root_fd)
            destination_details = os.fstat(destination_fd)
            destination_identity = _regular_file_identity(destination_details, self._broker_uid)
            if destination_identity != renamed_identity or not _fd_cloexec(destination_fd):
                raise BrokerJournalStorageError(
                    "broker destination does not resolve to the fsynced temp inode"
                )
            if _decode_slot(destination_fd, destination_details, self._broker_uid) != slot:
                raise BrokerJournalStorageError(
                    "broker destination content does not match the committed slot"
                )
            if (
                _regular_file_identity(os.fstat(fd), self._broker_uid) != destination_identity
                or _regular_file_identity(os.fstat(destination_fd), self._broker_uid)
                != destination_identity
            ):
                raise BrokerJournalStorageError(
                    "broker destination identity changed during commit proof"
                )
            self._prove_name_absent(self._root_fd, temp_name)
            self._require_open_root()
        except FileExistsError as exc:
            if not created:
                raise BrokerJournalStorageError("broker slot temp name already exists") from exc
            raise BrokerJournalStorageAmbiguousError(
                "broker slot commit outcome is ambiguous"
            ) from exc
        except (BrokerJournalStorageError, OSError) as exc:
            if created:
                raise BrokerJournalStorageAmbiguousError(
                    "broker slot commit outcome is ambiguous"
                ) from exc
            raise BrokerJournalStorageError("broker slot cannot create exclusive temp") from exc
        finally:
            close_error: OSError | None = None
            if destination_fd >= 0:
                closing_destination_fd = destination_fd
                destination_fd = -1
                try:
                    os.close(closing_destination_fd)
                except OSError as exc:
                    close_error = exc
            if fd >= 0:
                closing_fd = fd
                fd = -1
                try:
                    os.close(closing_fd)
                except OSError as exc:
                    if close_error is None:
                        close_error = exc
            if close_error is not None:
                raise BrokerJournalStorageAmbiguousError(
                    "broker slot descriptor close outcome is ambiguous"
                ) from close_error
