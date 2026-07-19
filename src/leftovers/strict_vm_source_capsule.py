"""Canonical LFSC v1 source capsules for the source-disabled strict VM.

LFSC (Leftovers File Source Capsule) is deliberately not an archive format and
does not extract anything.  It is a small, sequential regular-file manifest:
the fixed header authenticates the exact padded payload and each entry
authenticates its own bytes.  The only construction surface accepts a
pre-opened private input-directory descriptor and a pre-opened output-file
descriptor.  Production construction is source-gated; fixtures need an
unforgeable in-process capability.

This is a contract for a future guest parser, not guest execution, GitHub
archive ingestion, or a general-purpose filesystem copier.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import struct
import unicodedata
from dataclasses import dataclass

STRICT_VM_SOURCE_CAPSULE_PACKING_ENABLED = False

LFSC_MAGIC = b"LFSC"
LFSC_VERSION = 1
LFSC_ALIGNMENT = 8
MAX_FILES = 2_048
MAX_TREE_DEPTH = 32
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_CONTENT_BYTES = 32 * 1024 * 1024
MAX_PATH_BYTES = 240
IO_CHUNK_BYTES = 64 * 1024
MAX_IO_ATTEMPTS = 4_096
INPUT_ROOT_MODE = 0o700
INPUT_FILE_MODES = frozenset({0o600, 0o700})
CAPSULE_FILE_MODE = 0o600
CAPSULE_MODES = frozenset({0o644, 0o755})

# magic, version, header length, flags, file count, content bytes, payload
# bytes, payload digest, canonical-entry-list digest, zero reserved bytes.
_HEADER = struct.Struct(">4sHHIIQQ32s32s64s")
# UTF-8 path length, canonical mode, zero reserved word, content length, digest.
_ENTRY = struct.Struct(">HHIQ32s")
_FIXTURE_SECRET = object()


class SourceCapsuleError(RuntimeError):
    """A descriptor or LFSC v1 byte stream is unsafe or non-canonical."""


class SourceCapsuleUnavailableError(SourceCapsuleError):
    """The source-disabled production packing surface was requested."""


class FixtureSourceCapsuleCapability:
    """Unforgeable in-process authority for deterministic LFSC fixtures only."""

    __slots__ = ("_secret",)

    def __init__(self, secret: object) -> None:
        if secret is not _FIXTURE_SECRET:
            raise SourceCapsuleUnavailableError(
                "source capsule fixture capability cannot be forged"
            )
        self._secret = secret


def issue_fixture_source_capsule_capability() -> FixtureSourceCapsuleCapability:
    """Return the explicit test-only capability; it grants no VM authority."""

    return FixtureSourceCapsuleCapability(_FIXTURE_SECRET)


def _require_fixture_capability(capability: FixtureSourceCapsuleCapability) -> None:
    if (
        type(capability) is not FixtureSourceCapsuleCapability
        or getattr(capability, "_secret", None) is not _FIXTURE_SECRET
    ):
        raise SourceCapsuleUnavailableError(
            "explicit source capsule fixture capability is required"
        )


@dataclass(frozen=True)
class LFSCFile:
    """One validated manifest entry; data is never retained or extracted."""

    path: str
    mode: int
    size: int
    sha256: str


@dataclass(frozen=True)
class LFSCValidation:
    """Descriptor-derived LFSC facts suitable for a future guest parser."""

    file_count: int
    content_bytes: int
    payload_bytes: int
    payload_sha256: str
    manifest_sha256: str
    files: tuple[LFSCFile, ...]


def _set_cloexec(fd: int) -> None:
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
    except OSError as exc:
        raise SourceCapsuleError("capsule descriptor cannot be made close-on-exec") from exc


def _close_descriptors(descriptors: tuple[tuple[int, str], ...]) -> None:
    """Close every poisoned local descriptor and report the first failure."""

    first_failure: tuple[str, OSError] | None = None
    for fd, label in descriptors:
        try:
            os.close(fd)
        except OSError as exc:
            if first_failure is None:
                first_failure = (label, exc)
    if first_failure is not None:
        label, cause = first_failure
        raise SourceCapsuleError(f"{label} descriptor close could not be proven") from cause


def _dup_cloexec(fd: int) -> int:
    if type(fd) is not int or fd < 0:
        raise SourceCapsuleError("capsule descriptor is malformed")
    try:
        duplicate = os.dup(fd)
    except OSError as exc:
        raise SourceCapsuleError("capsule descriptor is unavailable") from exc
    try:
        _set_cloexec(duplicate)
    except SourceCapsuleError:
        owned_duplicate = duplicate
        duplicate = -1
        _close_descriptors(((owned_duplicate, "duplicated capsule"),))
        raise
    return duplicate


def _stat_identity(details: os.stat_result) -> tuple[int, ...]:
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


def _expected_uid(expected_uid: int | None) -> int:
    if expected_uid is None:
        return os.getuid()
    if type(expected_uid) is not int or expected_uid < 0:
        raise SourceCapsuleError("capsule expected owner is malformed")
    return expected_uid


def _private_directory(fd: int, owner_uid: int) -> tuple[int, ...]:
    try:
        details = os.fstat(fd)
    except OSError as exc:
        raise SourceCapsuleError("private source root descriptor is unavailable") from exc
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != owner_uid
        or stat.S_IMODE(details.st_mode) != INPUT_ROOT_MODE
        or details.st_nlink < 2
    ):
        raise SourceCapsuleError("private source root descriptor is unsafe")
    return _stat_identity(details)


def _capsule_regular_file(fd: int, owner_uid: int, *, empty: bool) -> tuple[int, ...]:
    try:
        details = os.fstat(fd)
    except OSError as exc:
        raise SourceCapsuleError("capsule file descriptor is unavailable") from exc
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != owner_uid
        or stat.S_IMODE(details.st_mode) != CAPSULE_FILE_MODE
        or details.st_nlink != 1
        or details.st_size < 0
        or (empty and details.st_size != 0)
    ):
        raise SourceCapsuleError("capsule file descriptor is unsafe")
    return _stat_identity(details)


def _same_except_size(before: tuple[int, ...], after: tuple[int, ...]) -> bool:
    return before[:5] == after[:5]


def _padding(size: int) -> int:
    return (-size) % LFSC_ALIGNMENT


def _check_component(component: str) -> None:
    if (
        not component
        or component in {".", "..", ".git"}
        or "/" in component
        or "\\" in component
        or unicodedata.normalize("NFC", component) != component
        or any(ord(character) < 32 or ord(character) == 127 for character in component)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in component)
    ):
        raise SourceCapsuleError("source path component is unsafe")


def _canonical_path(parts: tuple[str, ...]) -> tuple[str, bytes]:
    if not parts or len(parts) > MAX_TREE_DEPTH:
        raise SourceCapsuleError("source path depth exceeds LFSC v1 bounds")
    for component in parts:
        _check_component(component)
    value = "/".join(parts)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise SourceCapsuleError("source path is not UTF-8") from exc
    if not 0 < len(encoded) <= MAX_PATH_BYTES:
        raise SourceCapsuleError("source path exceeds LFSC v1 bounds")
    return value, encoded


def _component_order_key(path: str) -> tuple[bytes, ...]:
    """Canonical depth-first order, comparing each component as raw UTF-8."""

    return tuple(component.encode("utf-8", "strict") for component in path.split("/"))


def _canonical_mode(input_mode: int) -> int:
    mode = stat.S_IMODE(input_mode)
    if mode not in INPUT_FILE_MODES:
        raise SourceCapsuleError("source file mode is not an LFSC v1 input mode")
    return 0o755 if mode == 0o700 else 0o644


def _read_exact(fd: int, size: int, *, label: str) -> bytes:
    if type(size) is not int or size < 0:
        raise SourceCapsuleError("capsule read bound is malformed")
    chunks: list[bytes] = []
    remaining = size
    attempts = 0
    while remaining:
        attempts += 1
        if attempts > MAX_IO_ATTEMPTS:
            raise SourceCapsuleError(f"{label} read stalled")
        try:
            chunk = os.read(fd, min(remaining, IO_CHUNK_BYTES))
        except InterruptedError:
            continue
        except OSError as exc:
            raise SourceCapsuleError(f"{label} read failed") from exc
        if not isinstance(chunk, bytes) or not chunk or len(chunk) > remaining:
            raise SourceCapsuleError(f"{label} is truncated or stalled")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(fd: int, value: bytes, *, offset: int | None = None) -> None:
    written_total = 0
    attempts = 0
    while written_total < len(value):
        attempts += 1
        if attempts > MAX_IO_ATTEMPTS:
            raise SourceCapsuleError("capsule write stalled")
        chunk = value[written_total : written_total + IO_CHUNK_BYTES]
        try:
            written = (
                os.write(fd, chunk)
                if offset is None
                else os.pwrite(fd, chunk, offset + written_total)
            )
        except InterruptedError:
            continue
        except OSError as exc:
            raise SourceCapsuleError("capsule write failed") from exc
        if type(written) is not int or written <= 0 or written > len(chunk):
            raise SourceCapsuleError("capsule write stalled")
        written_total += written


def _write_payload(fd: int, digest: hashlib._Hash, value: bytes) -> None:
    _write_all(fd, value)
    digest.update(value)


def _require_stable_file(fd: int, before: tuple[int, ...], owner_uid: int) -> tuple[int, ...]:
    try:
        after_details = os.fstat(fd)
    except OSError as exc:
        raise SourceCapsuleError("source file disappeared during capsule packing") from exc
    after = _stat_identity(after_details)
    if (
        before != after
        or not stat.S_ISREG(after_details.st_mode)
        or after_details.st_uid != owner_uid
        or after_details.st_nlink != 1
        or stat.S_IMODE(after_details.st_mode) not in INPUT_FILE_MODES
    ):
        raise SourceCapsuleError("source file mutated during capsule packing")
    return after


def _list_directory(fd: int, owner_uid: int) -> list[os.DirEntry[str]]:
    before = _private_directory(fd, owner_uid)
    try:
        with os.scandir(fd) as entries:
            listed = list(entries)
    except OSError as exc:
        raise SourceCapsuleError("source directory cannot be enumerated") from exc
    try:
        after = _stat_identity(os.fstat(fd))
    except OSError as exc:
        raise SourceCapsuleError("source directory disappeared during enumeration") from exc
    if before != after:
        raise SourceCapsuleError("source directory mutated during enumeration")
    return sorted(listed, key=lambda entry: entry.name.encode("utf-8", "surrogatepass"))


def _read_file_to_payload(
    directory_fd: int,
    name: str,
    parts: tuple[str, ...],
    output_fd: int,
    payload_digest: hashlib._Hash,
    manifest_digest: hashlib._Hash,
    owner_uid: int,
    output_identity: tuple[int, int],
) -> tuple[int, int]:
    _path, path_bytes = _canonical_path(parts)
    file_fd: int | None = None
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise SourceCapsuleError("source file cannot be opened without following links") from exc
    try:
        before_details = os.fstat(file_fd)
        before = _stat_identity(before_details)
        if (
            not stat.S_ISREG(before_details.st_mode)
            or before_details.st_uid != owner_uid
            or before_details.st_nlink != 1
            or before_details.st_size < 0
            or before_details.st_size > MAX_FILE_BYTES
        ):
            raise SourceCapsuleError("source tree contains an unsafe regular file")
        if (before_details.st_dev, before_details.st_ino) == output_identity:
            raise SourceCapsuleError("capsule output aliases a source-tree file")
        mode = _canonical_mode(before_details.st_mode)
        content_digest = hashlib.sha256()
        # Hash the bounded file once, then rewind and stream it directly to
        # the capsule.  Retaining a 1 MiB file in memory would violate the
        # point of bounded chunked I/O.
        remaining = before_details.st_size
        attempts = 0
        while remaining:
            attempts += 1
            if attempts > MAX_IO_ATTEMPTS:
                raise SourceCapsuleError("source file read stalled")
            try:
                chunk = os.read(file_fd, min(remaining, IO_CHUNK_BYTES))
            except InterruptedError:
                continue
            except OSError as exc:
                raise SourceCapsuleError("source file read failed") from exc
            if not isinstance(chunk, bytes) or not chunk or len(chunk) > remaining:
                raise SourceCapsuleError("source file is truncated or stalled")
            content_digest.update(chunk)
            remaining -= len(chunk)
        _require_stable_file(file_fd, before, owner_uid)
        digest = content_digest.digest()
        entry = _ENTRY.pack(len(path_bytes), mode, 0, before_details.st_size, digest)
        manifest_digest.update(entry + path_bytes)
        _write_payload(output_fd, payload_digest, entry)
        _write_payload(output_fd, payload_digest, path_bytes)
        path_padding = b"\0" * _padding(len(path_bytes))
        if path_padding:
            _write_payload(output_fd, payload_digest, path_padding)
        try:
            os.lseek(file_fd, 0, os.SEEK_SET)
        except OSError as exc:
            raise SourceCapsuleError("source file is not seekable") from exc
        remaining = before_details.st_size
        second_digest = hashlib.sha256()
        attempts = 0
        while remaining:
            attempts += 1
            if attempts > MAX_IO_ATTEMPTS:
                raise SourceCapsuleError("source file read stalled")
            try:
                chunk = os.read(file_fd, min(remaining, IO_CHUNK_BYTES))
            except InterruptedError:
                continue
            except OSError as exc:
                raise SourceCapsuleError("source file read failed") from exc
            if not isinstance(chunk, bytes) or not chunk or len(chunk) > remaining:
                raise SourceCapsuleError("source file is truncated or stalled")
            second_digest.update(chunk)
            _write_payload(output_fd, payload_digest, chunk)
            remaining -= len(chunk)
        if second_digest.digest() != digest:
            raise SourceCapsuleError("source file changed between capsule reads")
        _require_stable_file(file_fd, before, owner_uid)
        content_padding = b"\0" * _padding(before_details.st_size)
        if content_padding:
            _write_payload(output_fd, payload_digest, content_padding)
        return before_details.st_size, 1
    finally:
        if file_fd is not None:
            owned_file_fd = file_fd
            file_fd = None
            _close_descriptors(((owned_file_fd, "source file"),))


def _reject_output_alias(
    directory_fd: int,
    owner_uid: int,
    output_identity: tuple[int, int],
) -> None:
    """Preflight a descriptor tree so an in-tree output remains untouched."""

    before = _private_directory(directory_fd, owner_uid)
    for entry in _list_directory(directory_fd, owner_uid):
        try:
            details = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise SourceCapsuleError(
                "source entry cannot be inspected for output aliasing"
            ) from exc
        if stat.S_ISREG(details.st_mode):
            if (details.st_dev, details.st_ino) == output_identity:
                raise SourceCapsuleError("capsule output aliases a source-tree file")
            continue
        if not stat.S_ISDIR(details.st_mode):
            continue
        child_fd: int | None = None
        try:
            child_fd = os.open(
                entry.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise SourceCapsuleError(
                "source directory cannot be opened for alias preflight"
            ) from exc
        try:
            _reject_output_alias(child_fd, owner_uid, output_identity)
        finally:
            if child_fd is not None:
                owned_child_fd = child_fd
                child_fd = None
                _close_descriptors(((owned_child_fd, "source alias-preflight directory"),))
    try:
        after = _stat_identity(os.fstat(directory_fd))
    except OSError as exc:
        raise SourceCapsuleError("source directory disappeared during alias preflight") from exc
    if before != after:
        raise SourceCapsuleError("source directory mutated during alias preflight")


def _pack_directory(
    directory_fd: int,
    parts: tuple[str, ...],
    output_fd: int,
    payload_digest: hashlib._Hash,
    manifest_digest: hashlib._Hash,
    owner_uid: int,
    output_identity: tuple[int, int],
) -> tuple[int, int]:
    before = _private_directory(directory_fd, owner_uid)
    total_bytes = 0
    total_files = 0
    for entry in _list_directory(directory_fd, owner_uid):
        try:
            name = entry.name
            _check_component(name)
            child_parts = parts + (name,)
            _canonical_path(child_parts)
            entry_details = entry.stat(follow_symlinks=False)
        except (OSError, UnicodeError) as exc:
            raise SourceCapsuleError("source directory entry is unreadable") from exc
        if stat.S_ISDIR(entry_details.st_mode):
            child_fd: int | None = None
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise SourceCapsuleError("source directory cannot be opened safely") from exc
            try:
                child_bytes, child_files = _pack_directory(
                    child_fd,
                    child_parts,
                    output_fd,
                    payload_digest,
                    manifest_digest,
                    owner_uid,
                    output_identity,
                )
            finally:
                if child_fd is not None:
                    owned_child_fd = child_fd
                    child_fd = None
                    _close_descriptors(((owned_child_fd, "source directory"),))
            total_bytes += child_bytes
            total_files += child_files
        elif stat.S_ISREG(entry_details.st_mode):
            file_bytes, file_count = _read_file_to_payload(
                directory_fd,
                name,
                child_parts,
                output_fd,
                payload_digest,
                manifest_digest,
                owner_uid,
                output_identity,
            )
            total_bytes += file_bytes
            total_files += file_count
        else:
            raise SourceCapsuleError("source tree contains a non-regular-file type")
        if total_files > MAX_FILES or total_bytes > MAX_CONTENT_BYTES:
            raise SourceCapsuleError("source tree exceeds LFSC v1 bounds")
    try:
        after = _stat_identity(os.fstat(directory_fd))
    except OSError as exc:
        raise SourceCapsuleError("source directory disappeared during capsule packing") from exc
    if before != after:
        raise SourceCapsuleError("source directory mutated during capsule packing")
    return total_bytes, total_files


def pack_lfsc_v1_fixture(
    input_root_fd: int,
    output_fd: int,
    *,
    capability: FixtureSourceCapsuleCapability,
    owner_uid: int | None = None,
) -> LFSCValidation:
    """Pack an LFSC v1 fixture from descriptors only; never accepts paths."""

    _require_fixture_capability(capability)
    uid = _expected_uid(owner_uid)
    source_fd: int | None = None
    capsule_fd: int | None = None
    try:
        source_fd = _dup_cloexec(input_root_fd)
        capsule_fd = _dup_cloexec(output_fd)
        source_before = _private_directory(source_fd, uid)
        output_before = _capsule_regular_file(capsule_fd, uid, empty=True)
        output_identity = (output_before[0], output_before[1])
        _reject_output_alias(source_fd, uid, output_identity)
        try:
            if os.lseek(capsule_fd, 0, os.SEEK_CUR) != 0:
                raise SourceCapsuleError("capsule output descriptor must start at offset zero")
        except OSError as exc:
            raise SourceCapsuleError("capsule output descriptor is not seekable") from exc
        _write_all(capsule_fd, b"\0" * _HEADER.size)
        payload_digest = hashlib.sha256()
        manifest_digest = hashlib.sha256()
        content_bytes, file_count = _pack_directory(
            source_fd,
            (),
            capsule_fd,
            payload_digest,
            manifest_digest,
            uid,
            output_identity,
        )
        try:
            source_after = _stat_identity(os.fstat(source_fd))
        except OSError as exc:
            raise SourceCapsuleError("private source root disappeared during packing") from exc
        if source_before != source_after:
            raise SourceCapsuleError("private source root mutated during capsule packing")
        payload_bytes = os.lseek(capsule_fd, 0, os.SEEK_CUR) - _HEADER.size
        if payload_bytes < 0:
            raise SourceCapsuleError("capsule output offset is malformed")
        # Payload is durable before the complete, digest-bearing header exists.
        try:
            os.fsync(capsule_fd)
        except OSError as exc:
            raise SourceCapsuleError("capsule payload fsync failed") from exc
        header = _HEADER.pack(
            LFSC_MAGIC,
            LFSC_VERSION,
            _HEADER.size,
            0,
            file_count,
            content_bytes,
            payload_bytes,
            payload_digest.digest(),
            manifest_digest.digest(),
            b"\0" * 64,
        )
        _write_all(capsule_fd, header, offset=0)
        try:
            os.fsync(capsule_fd)
        except OSError as exc:
            raise SourceCapsuleError("complete capsule header fsync failed") from exc
        after = _capsule_regular_file(capsule_fd, uid, empty=False)
        expected_size = _HEADER.size + payload_bytes
        if not _same_except_size(output_before, after) or after[5] != expected_size:
            raise SourceCapsuleError("capsule output mutated during packing")
        return validate_lfsc_v1(capsule_fd, owner_uid=uid)
    finally:
        descriptors: list[tuple[int, str]] = []
        if capsule_fd is not None:
            owned_capsule_fd = capsule_fd
            capsule_fd = None
            descriptors.append((owned_capsule_fd, "capsule output"))
        if source_fd is not None:
            owned_source_fd = source_fd
            source_fd = None
            descriptors.append((owned_source_fd, "source root"))
        _close_descriptors(tuple(descriptors))


def pack_lfsc_v1(
    input_root_fd: int, output_fd: int, *, owner_uid: int | None = None
) -> LFSCValidation:
    """Production packing gate; deliberately refuses before descriptor access."""

    del input_root_fd, output_fd, owner_uid
    if not STRICT_VM_SOURCE_CAPSULE_PACKING_ENABLED:
        raise SourceCapsuleUnavailableError("strict VM LFSC packing is source-disabled")
    raise SourceCapsuleUnavailableError("production LFSC packing is not implemented")


def _decode_path(raw: bytes) -> tuple[str, tuple[bytes, ...]]:
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SourceCapsuleError("LFSC path is not UTF-8") from exc
    parts = tuple(path.split("/"))
    canonical, encoded = _canonical_path(parts)
    if canonical != path or encoded != raw:
        raise SourceCapsuleError("LFSC path is not canonical NFC")
    return path, _component_order_key(path)


def validate_lfsc_v1(capsule_fd: int, *, owner_uid: int | None = None) -> LFSCValidation:
    """Validate one descriptor-only LFSC v1 stream without extracting files."""

    uid = _expected_uid(owner_uid)
    fd: int | None = None
    try:
        fd = _dup_cloexec(capsule_fd)
        before = _capsule_regular_file(fd, uid, empty=False)
        max_wire_bytes = (
            _HEADER.size
            + MAX_CONTENT_BYTES
            + MAX_FILES * (_ENTRY.size + MAX_PATH_BYTES + (2 * (LFSC_ALIGNMENT - 1)))
        )
        if before[5] < _HEADER.size or before[5] > max_wire_bytes:
            raise SourceCapsuleError("LFSC capsule size exceeds fixed bounds")
        try:
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError as exc:
            raise SourceCapsuleError("LFSC descriptor is not seekable") from exc
        raw_header = _read_exact(fd, _HEADER.size, label="LFSC header")
        (
            magic,
            version,
            header_size,
            flags,
            file_count,
            content_bytes,
            payload_bytes,
            declared_payload_digest,
            declared_manifest_digest,
            reserved,
        ) = _HEADER.unpack(raw_header)
        if (
            magic != LFSC_MAGIC
            or version != LFSC_VERSION
            or header_size != _HEADER.size
            or flags != 0
            or file_count > MAX_FILES
            or content_bytes > MAX_CONTENT_BYTES
            or payload_bytes != before[5] - _HEADER.size
            or reserved != b"\0" * len(reserved)
            or declared_payload_digest == b"\0" * 32
            or declared_manifest_digest == b"\0" * 32
        ):
            raise SourceCapsuleError("LFSC fixed header is malformed or incomplete")
        payload_digest = hashlib.sha256()
        manifest_digest = hashlib.sha256()
        files: list[LFSCFile] = []
        previous_order_key: tuple[bytes, ...] | None = None
        remaining_payload = payload_bytes
        total_content = 0

        def consume(size: int, label: str) -> bytes:
            nonlocal remaining_payload
            if size < 0 or size > remaining_payload:
                raise SourceCapsuleError("LFSC entries overlap or exceed the declared payload")
            value = _read_exact(fd, size, label=label)
            payload_digest.update(value)
            remaining_payload -= size
            return value

        for _ in range(file_count):
            raw_entry = consume(_ENTRY.size, "LFSC entry")
            path_length, mode, entry_reserved, size, digest = _ENTRY.unpack(raw_entry)
            if (
                path_length == 0
                or path_length > MAX_PATH_BYTES
                or mode not in CAPSULE_MODES
                or entry_reserved != 0
                or size > MAX_FILE_BYTES
            ):
                raise SourceCapsuleError("LFSC entry header is malformed")
            raw_path = consume(path_length, "LFSC path")
            path, order_key = _decode_path(raw_path)
            if previous_order_key is not None and order_key <= previous_order_key:
                raise SourceCapsuleError("LFSC paths are reordered or duplicated")
            previous_order_key = order_key
            path_padding = consume(_padding(path_length), "LFSC path padding")
            if path_padding != b"\0" * len(path_padding):
                raise SourceCapsuleError("LFSC path padding is nonzero")
            content_hash = hashlib.sha256()
            remaining_file = size
            while remaining_file:
                chunk_size = min(remaining_file, IO_CHUNK_BYTES)
                chunk = consume(chunk_size, "LFSC file content")
                content_hash.update(chunk)
                remaining_file -= len(chunk)
            content_padding = consume(_padding(size), "LFSC content padding")
            if content_padding != b"\0" * len(content_padding):
                raise SourceCapsuleError("LFSC content padding is nonzero")
            if content_hash.digest() != digest:
                raise SourceCapsuleError("LFSC per-file digest drift")
            manifest_digest.update(raw_entry + raw_path)
            total_content += size
            if total_content > MAX_CONTENT_BYTES:
                raise SourceCapsuleError("LFSC content total exceeds fixed bounds")
            files.append(LFSCFile(path, mode, size, digest.hex()))
        if remaining_payload != 0 or total_content != content_bytes:
            raise SourceCapsuleError("LFSC payload has extra bytes, overlap, or incorrect totals")
        try:
            extra = os.read(fd, 1)
        except OSError as exc:
            raise SourceCapsuleError("LFSC extra-byte check failed") from exc
        if extra:
            raise SourceCapsuleError("LFSC capsule has trailing bytes")
        after = _capsule_regular_file(fd, uid, empty=False)
        if before != after:
            raise SourceCapsuleError("LFSC capsule mutated during validation")
        if payload_digest.digest() != declared_payload_digest:
            raise SourceCapsuleError("LFSC whole-payload digest drift")
        if manifest_digest.digest() != declared_manifest_digest:
            raise SourceCapsuleError("LFSC manifest digest drift")
        return LFSCValidation(
            file_count=file_count,
            content_bytes=content_bytes,
            payload_bytes=payload_bytes,
            payload_sha256=declared_payload_digest.hex(),
            manifest_sha256=declared_manifest_digest.hex(),
            files=tuple(files),
        )
    finally:
        if fd is not None:
            owned_fd = fd
            fd = None
            _close_descriptors(((owned_fd, "capsule validation"),))
