"""Fail-closed, restartable leases for strict-VM controller artifacts.

The guest never receives this directory.  A run directory is nevertheless
treated as hostile after a controller crash: cleanup trusts only an exact
marker, a hash-chained in-directory journal, and a root-level recovery ledger.
Deletion is name-by-name through directory descriptors; there is deliberately
no recursive cleanup primitive in this module.

After a successful run-directory deletion the sole intentional residue is one
canonical owner-read-only cleanup tombstone.  The controller must durably store
its returned receipt before calling :meth:`retire_cleanup_receipt`; that method
is the only permitted way to remove the tombstone and refuses while either the
run directory or its recovery ledger remains present.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class VMLeaseError(RuntimeError):
    """A strict-VM lease violates its controller contract."""


class VMCleanupPendingError(VMLeaseError):
    """Exact artifact or directory absence could not be proven."""

    def __init__(self, message: str, run_id: str, retained: tuple[str, ...]):
        super().__init__(message)
        self.run_id = run_id
        self.retained = retained


@dataclass(frozen=True)
class ArtifactIdentity:
    name: str
    role: str
    device: int
    inode: int
    uid: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str | None


@dataclass(frozen=True)
class VMCleanupReceipt:
    schema_version: int
    run_id: str
    artifacts_removed: tuple[str, ...]
    run_directory_removed: bool
    path_absence_proven: bool
    finished_at: str


_RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
_FILE_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_ROLE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MARKER = ".leftovers-strict-vm-lease.json"
_JOURNAL = ".leftovers-strict-vm-state.jsonl"
_RECOVERY_PREFIX = ".leftovers-strict-vm-recovery-"
_TOMBSTONE_PREFIX = ".leftovers-strict-vm-cleanup-"
_RESERVED = frozenset({_MARKER, _JOURNAL})
_MAX_ARTIFACT_BYTES = 4 * 1_024 * 1_024 * 1_024
_MAX_CONTROL_BYTES = 4 * 1_024 * 1_024
_HASH_CHUNK_BYTES = 64 * 1_024
_ZERO_HASH = "0" * 64


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _strict_json(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise VMLeaseError("lease JSON has duplicate keys")
            output[key] = value
        return output

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VMLeaseError("lease JSON is invalid") from exc
    if not isinstance(value, dict):
        raise VMLeaseError("lease JSON must be an object")
    return value


def _directory_identity(descriptor: int) -> tuple[int, int, int, int]:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        raise VMLeaseError("lease descriptor is not a directory")
    return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)


def _artifact_identity(
    name: str, role: str, info: os.stat_result, digest: str | None
) -> ArtifactIdentity:
    return ArtifactIdentity(
        name=name,
        role=role,
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        links=info.st_nlink,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
        sha256=digest,
    )


def _identity_payload(value: ArtifactIdentity) -> dict[str, Any]:
    return {
        "name": value.name,
        "role": value.role,
        "device": value.device,
        "inode": value.inode,
        "uid": value.uid,
        "mode": value.mode,
        "links": value.links,
        "size": value.size,
        "mtime_ns": value.mtime_ns,
        "ctime_ns": value.ctime_ns,
        "sha256": value.sha256,
    }


def _identity_from_payload(value: Any) -> ArtifactIdentity:
    if not isinstance(value, dict) or set(value) != {
        "name",
        "role",
        "device",
        "inode",
        "uid",
        "mode",
        "links",
        "size",
        "mtime_ns",
        "ctime_ns",
        "sha256",
    }:
        raise VMLeaseError("lease artifact journal payload is invalid")
    name = value["name"]
    role = value["role"]
    if _FILE_NAME.fullmatch(name) is None or name in _RESERVED or _ROLE.fullmatch(role) is None:
        raise VMLeaseError("lease artifact journal name or role is invalid")
    integers = ("device", "inode", "uid", "mode", "links", "size", "mtime_ns", "ctime_ns")
    if any(type(value[key]) is not int for key in integers):
        raise VMLeaseError("lease artifact journal integer is invalid")
    if (
        value["device"] < 0
        or value["inode"] < 1
        or value["uid"] != os.getuid()
        or value["mode"] not in {0o400, 0o600}
        or value["links"] != 1
        or not 1 <= value["size"] <= _MAX_ARTIFACT_BYTES
        or value["mtime_ns"] < 0
        or value["ctime_ns"] < 0
    ):
        raise VMLeaseError("lease artifact journal identity is unsafe")
    digest = value["sha256"]
    if value["mode"] == 0o400:
        if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
            raise VMLeaseError("sealed artifact requires SHA-256")
    elif digest is not None:
        raise VMLeaseError("mutable artifact cannot carry a SHA-256")
    return ArtifactIdentity(**value)


class StrictVMRunLease:
    """An owner-private lease with durable recovery of partial exact cleanup."""

    def __init__(self, root: Path, run_id: str):
        if _RUN_ID.fullmatch(run_id) is None:
            raise VMLeaseError("strict-VM run_id must be exactly 32 lowercase hex characters")
        root = Path(root)
        if not root.is_absolute() or root.resolve() != root:
            raise VMLeaseError("strict-VM lease root must be a canonical absolute path")
        try:
            root_info = root.lstat()
        except OSError as exc:
            raise VMLeaseError("strict-VM lease root is unavailable") from exc
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise VMLeaseError("strict-VM lease root must be an owner-private 0700 directory")
        self._expected_root_identity = (
            root_info.st_dev,
            root_info.st_ino,
            root_info.st_uid,
            0o700,
        )
        self.root = root
        self.run_id = run_id
        self.name = f"leftovers-vm-{run_id}"
        self.path = root / self.name
        self._recovery_name = f"{_RECOVERY_PREFIX}{run_id}.jsonl"
        self._tombstone_name = f"{_TOMBSTONE_PREFIX}{run_id}.json"
        self._root_descriptor: int | None = None
        self._run_descriptor: int | None = None
        self._run_identity: tuple[int, int, int, int] | None = None
        self._nonce: str | None = None
        self._artifacts: dict[str, ArtifactIdentity] = {}
        self._last_record_hash = _ZERO_HASH
        self._last_recovery_hash = _ZERO_HASH
        self._removal_intent = False
        self._poisoned = False
        self._resumed = False
        self._completed_receipt: VMCleanupReceipt | None = None

    def __enter__(self) -> StrictVMRunLease:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, traceback
        if self._run_descriptor is not None:
            if exc is None:
                self.cleanup()
            else:
                self.close()
        return False

    def _require_active(self) -> tuple[int, int]:
        if self._root_descriptor is None or self._run_descriptor is None:
            raise VMLeaseError("strict-VM lease is not active")
        return self._root_descriptor, self._run_descriptor

    def _require_unpoisoned(self) -> None:
        if self._poisoned:
            raise VMLeaseError("strict-VM lease journal is poisoned")

    def _fsync_run(self) -> None:
        _, run_descriptor = self._require_active()
        os.fsync(run_descriptor)

    def _fsync_root(self) -> None:
        root_descriptor, _ = self._require_active()
        os.fsync(root_descriptor)

    @staticmethod
    def _open_directory(parent: int, name: str) -> int:
        try:
            return os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
        except OSError as exc:
            raise VMLeaseError("lease directory cannot be opened safely") from exc

    def _write_new(self, name: str, raw: bytes, mode: int, *, root: bool = False) -> None:
        parent = self._root_descriptor if root else self._run_descriptor
        if parent is None:
            raise VMLeaseError("strict-VM lease is not active")
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent,
        )
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise VMLeaseError("lease file write made no progress")
                view = view[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)

    def _read_regular(
        self, parent: int, name: str, *, mode: int, cap: int
    ) -> tuple[bytes, os.stat_result]:
        try:
            descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        except OSError as exc:
            raise VMLeaseError("lease control file cannot be opened safely") from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != mode
                or before.st_nlink != 1
                or not 1 <= before.st_size <= cap
            ):
                raise VMLeaseError("lease control file identity is unsafe")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(descriptor, _HASH_CHUNK_BYTES)
                if not block:
                    break
                total += len(block)
                if total > cap:
                    raise VMLeaseError("lease control file exceeds byte cap")
                chunks.append(block)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                stat.S_IMODE(before.st_mode),
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise VMLeaseError("lease control file changed while reading")
            return b"".join(chunks), after
        finally:
            os.close(descriptor)

    def _append_chain(
        self,
        name: str,
        previous_hash: str,
        record: dict[str, Any],
        *,
        root: bool,
    ) -> str:
        parent = self._root_descriptor if root else self._run_descriptor
        if parent is None:
            raise VMLeaseError("strict-VM lease is not active")
        unsigned = {
            "at": _now(),
            "event": record["event"],
            "fields": record["fields"],
            "nonce": self._nonce,
            "previous_hash": previous_hash,
            "run_id": self.run_id,
            "run_device": self._run_identity[0] if self._run_identity else None,
            "run_inode": self._run_identity[1] if self._run_identity else None,
            "run_uid": self._run_identity[2] if self._run_identity else None,
            "run_mode": self._run_identity[3] if self._run_identity else None,
        }
        record_hash = hashlib.sha256(_canonical(unsigned)).hexdigest()
        raw = _canonical({**unsigned, "record_hash": record_hash}) + b"\n"
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent,
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) != 0o600
                    or opened.st_nlink != 1
                ):
                    raise VMLeaseError("lease journal identity is unsafe")
                view = memoryview(raw)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise VMLeaseError("lease journal write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)
            return record_hash
        except BaseException:
            self._poisoned = True
            raise

    def _record_recovery(self, event: str, **fields: Any) -> str:
        if _ROLE.fullmatch(event) is None:
            raise VMLeaseError("lease recovery event name is unsafe")
        result = self._append_chain(
            self._recovery_name,
            self._last_recovery_hash,
            {"event": event, "fields": fields},
            root=True,
        )
        self._last_recovery_hash = result
        return result

    def record(self, event: str, **fields: Any) -> str:
        if _ROLE.fullmatch(event) is None:
            raise VMLeaseError("lease event name is unsafe")
        self._require_unpoisoned()
        result = self._append_chain(
            _JOURNAL,
            self._last_record_hash,
            {"event": event, "fields": fields},
            root=False,
        )
        self._last_record_hash = result
        return result

    def _verify_marker(self) -> None:
        _, run_descriptor = self._require_active()
        raw, info = self._read_regular(run_descriptor, _MARKER, mode=0o400, cap=64 * 1024)
        if not raw.endswith(b"\n"):
            raise VMLeaseError("lease marker is not canonical")
        marker = _strict_json(raw[:-1])
        if _canonical(marker) + b"\n" != raw or set(marker) != {
            "schema_version",
            "run_id",
            "nonce",
            "directory_device",
            "directory_inode",
            "controller_uid",
            "created_at",
        }:
            raise VMLeaseError("lease marker is malformed")
        if (
            marker["schema_version"] != 1
            or marker["run_id"] != self.run_id
            or not isinstance(marker["nonce"], str)
            or re.fullmatch(r"[0-9a-f]{64}", marker["nonce"]) is None
            or type(marker["directory_device"]) is not int
            or type(marker["directory_inode"]) is not int
            or marker["controller_uid"] != os.getuid()
            or not isinstance(marker["created_at"], str)
            or self._run_identity is None
            or (marker["directory_device"], marker["directory_inode"]) != self._run_identity[:2]
        ):
            raise VMLeaseError("lease marker does not bind this run directory")
        if self._nonce is not None and marker["nonce"] != self._nonce:
            raise VMLeaseError("lease marker nonce changed")
        self._nonce = marker["nonce"]
        # Marker data is sealed: same-inode mutations must also be visible.
        if info.st_size != len(raw):
            raise VMLeaseError("lease marker changed while reading")

    def _verify_chain(
        self, raw: bytes, *, recovery: bool
    ) -> tuple[str, dict[str, ArtifactIdentity], set[str], bool, bool]:
        if not raw.endswith(b"\n"):
            raise VMLeaseError("lease journal has a partial record")
        previous = _ZERO_HASH
        artifacts: dict[str, ArtifactIdentity] = {}
        removed: set[str] = set()
        removal_intent = False
        completed = False
        records = raw.splitlines()
        if not records:
            raise VMLeaseError("lease journal is empty")
        for index, line in enumerate(records):
            value = _strict_json(line)
            if _canonical(value) != line or set(value) != {
                "at",
                "event",
                "fields",
                "nonce",
                "previous_hash",
                "record_hash",
                "run_id",
                "run_device",
                "run_inode",
                "run_uid",
                "run_mode",
            }:
                raise VMLeaseError("lease journal record is not canonical")
            unsigned = {key: value[key] for key in value if key != "record_hash"}
            if (
                not isinstance(value["at"], str)
                or _ROLE.fullmatch(value["event"]) is None
                or not isinstance(value["fields"], dict)
                or value["run_id"] != self.run_id
                or value["nonce"] != self._nonce
                or value["previous_hash"] != previous
                or not isinstance(value["record_hash"], str)
                or _HEX64.fullmatch(value["record_hash"]) is None
                or hashlib.sha256(_canonical(unsigned)).hexdigest() != value["record_hash"]
                or self._run_identity is None
                or (
                    value["run_device"],
                    value["run_inode"],
                    value["run_uid"],
                    value["run_mode"],
                )
                != self._run_identity
            ):
                raise VMLeaseError("lease journal chain or binding is invalid")
            event = value["event"]
            fields = value["fields"]
            if completed:
                raise VMLeaseError("lease journal has records after completion")
            if index == 0 and (
                (recovery and event != "lease_created")
                or (not recovery and event != "run_dir_created")
            ):
                raise VMLeaseError("lease journal has no creation record")
            if event in {"artifact_registered", "artifact_refreshed"}:
                identity = _identity_from_payload(fields.get("artifact"))
                if event == "artifact_registered" and identity.name in artifacts:
                    raise VMLeaseError("lease journal registers an artifact twice")
                if event == "artifact_refreshed" and identity.name not in artifacts:
                    raise VMLeaseError("lease journal refreshes an unknown artifact")
                artifacts[identity.name] = identity
            elif event == "artifact_absent":
                names = fields.get("artifacts")
                if (
                    not isinstance(names, list)
                    or any(not isinstance(name, str) for name in names)
                    or len(set(names)) != len(names)
                    or not set(names).issubset(artifacts)
                ):
                    raise VMLeaseError("lease journal deletion set is invalid")
                removed.update(names)
            elif event == "run_directory_removal_intent":
                if set(artifacts) != removed:
                    raise VMLeaseError("lease removal intent has live artifacts")
                removal_intent = True
            elif event == "cleanup_complete":
                names = fields.get("artifacts")
                if not removal_intent or not isinstance(names, list) or names != sorted(artifacts):
                    raise VMLeaseError("lease completion record is invalid")
                completed = True
            previous = value["record_hash"]
        return previous, artifacts, removed, removal_intent, completed

    def _verify_journal(self) -> tuple[dict[str, ArtifactIdentity], set[str]]:
        _, run_descriptor = self._require_active()
        raw, _ = self._read_regular(run_descriptor, _JOURNAL, mode=0o600, cap=_MAX_CONTROL_BYTES)
        head, artifacts, removed, _intent, _completed = self._verify_chain(raw, recovery=False)
        self._last_record_hash = head
        return artifacts, removed

    @staticmethod
    def _cross_check_journal_prefix(
        journal_artifacts: dict[str, ArtifactIdentity],
        recovery_artifacts: dict[str, ArtifactIdentity],
    ) -> None:
        for name, recorded in journal_artifacts.items():
            expected = recovery_artifacts.get(name)
            if expected is None:
                raise VMLeaseError("recovery ledger and run journal disagree")
            if recorded.mode == 0o400:
                if recorded != expected:
                    raise VMLeaseError("immutable journal artifact conflicts with recovery ledger")
                continue
            stable = ("name", "role", "device", "inode", "uid", "mode", "links", "size", "sha256")
            if (
                recorded.mode != 0o600
                or expected.mode != 0o600
                or any(getattr(recorded, field) != getattr(expected, field) for field in stable)
                or recorded.mtime_ns > expected.mtime_ns
                or recorded.ctime_ns > expected.ctime_ns
            ):
                raise VMLeaseError("mutable journal artifact is not a valid recovery prefix")

    def _reconcile_journal_prefix(
        self,
        journal_artifacts: dict[str, ArtifactIdentity],
        journal_removed: set[str],
        recovery_artifacts: dict[str, ArtifactIdentity],
        recovery_removed: set[str],
    ) -> None:
        """Extend a valid journal prefix to the authoritative root-ledger state."""

        self._cross_check_journal_prefix(journal_artifacts, recovery_artifacts)
        if not journal_removed.issubset(recovery_removed):
            raise VMLeaseError("run journal reports deletion absent from recovery ledger")
        for name in sorted(recovery_artifacts):
            recorded = journal_artifacts.get(name)
            expected = recovery_artifacts[name]
            if recorded is None:
                self.record("artifact_registered", artifact=_identity_payload(expected))
                continue
            if recorded == expected:
                continue
            stable = ("device", "inode", "uid", "mode", "links", "size", "sha256")
            if (
                recorded.mode != 0o600
                or expected.mode != 0o600
                or any(getattr(recorded, field) != getattr(expected, field) for field in stable)
            ):
                raise VMLeaseError("run journal artifact conflicts with recovery ledger")
            self.record("artifact_refreshed", artifact=_identity_payload(expected))
        for name in sorted(recovery_removed - journal_removed):
            self.record("artifact_absent", artifacts=[name])

    def _verify_recovery(self) -> tuple[dict[str, ArtifactIdentity], set[str], bool, bool]:
        root_descriptor = self._root_descriptor
        if root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        raw, _ = self._read_regular(
            root_descriptor, self._recovery_name, mode=0o600, cap=_MAX_CONTROL_BYTES
        )
        head, artifacts, removed, intent, completed = self._verify_chain(raw, recovery=True)
        self._last_recovery_hash = head
        return artifacts, removed, intent, completed

    def acquire(self) -> StrictVMRunLease:
        if self._root_descriptor is not None or self._run_descriptor is not None:
            raise VMLeaseError("strict-VM lease cannot be acquired in its current state")
        created = False
        try:
            self._root_descriptor = self._open_directory_parent()
            os.mkdir(self.name, 0o700, dir_fd=self._root_descriptor)
            created = True
            self._run_descriptor = self._open_directory(self._root_descriptor, self.name)
            self._run_identity = _directory_identity(self._run_descriptor)
            if self._run_identity[2:] != (os.getuid(), 0o700):
                raise VMLeaseError("strict-VM run directory identity is unsafe")
            self._nonce = secrets.token_hex(32)
            marker = {
                "schema_version": 1,
                "run_id": self.run_id,
                "nonce": self._nonce,
                "directory_device": self._run_identity[0],
                "directory_inode": self._run_identity[1],
                "controller_uid": os.getuid(),
                "created_at": _now(),
            }
            self._write_new(_MARKER, _canonical(marker) + b"\n", 0o400)
            self._write_new(self._recovery_name, b"", 0o600, root=True)
            self._record_recovery("lease_created")
            self._write_new(_JOURNAL, b"", 0o600)
            self.record("run_dir_created")
            return self
        except BaseException as setup_error:
            # A marker with a valid recovery ledger is intentionally retained.
            # Before that point, remove only exact control names we created.
            cleanup_error: BaseException | None = None
            if created and self._last_recovery_hash == _ZERO_HASH:
                try:
                    if self._run_descriptor is not None:
                        for control in (_JOURNAL, _MARKER):
                            with suppress(FileNotFoundError):
                                os.unlink(control, dir_fd=self._run_descriptor)
                        os.fsync(self._run_descriptor)
                        os.close(self._run_descriptor)
                        self._run_descriptor = None
                    os.rmdir(self.name, dir_fd=self._root_descriptor)
                    os.fsync(self._root_descriptor)
                except BaseException as exc:
                    cleanup_error = exc
            with suppress(VMLeaseError):
                self.close()
            if cleanup_error is not None or (created and self._last_recovery_hash != _ZERO_HASH):
                raise VMCleanupPendingError(
                    "strict-VM lease setup could not prove exact resource absence",
                    self.run_id,
                    (self.name,),
                ) from (cleanup_error or setup_error)
            raise setup_error

    def _open_directory_parent(self) -> int:
        try:
            descriptor = os.open(
                self.root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise VMLeaseError("strict-VM lease root cannot be opened safely") from exc
        if _directory_identity(descriptor) != self._expected_root_identity:
            os.close(descriptor)
            raise VMLeaseError("strict-VM lease root identity changed while opening")
        return descriptor

    @classmethod
    def resume_cleanup(cls, root: Path, run_id: str) -> VMCleanupReceipt:
        """Reopen exactly one marker-bound run and finish its exact cleanup."""

        lease = cls(root, run_id)
        receipt = lease._resume()
        if receipt is not None:
            return receipt
        return lease.cleanup()

    @classmethod
    def retire_cleanup_receipt(cls, root: Path, run_id: str) -> VMCleanupReceipt:
        """Explicitly consume the sole bounded completion tombstone for one run.

        Call this only after the returned receipt has been durably persisted by
        the controller.  It refuses to remove the receipt while either the run
        directory or recovery ledger remains present.
        """

        lease = cls(root, run_id)
        try:
            lease._root_descriptor = lease._open_directory_parent()
            lease._prove_run_absent()
            lease._prove_root_name_absent(lease._recovery_name, label="recovery ledger")
            receipt = lease._read_cleanup_tombstone()
            os.unlink(lease._tombstone_name, dir_fd=lease._root_descriptor)
            os.fsync(lease._root_descriptor)
            lease._prove_root_name_absent(lease._tombstone_name, label="cleanup tombstone")
            lease.close()
            return receipt
        except BaseException:
            with suppress(VMLeaseError):
                lease.close()
            raise

    def _bootstrap_recovery_identity(self) -> None:
        """Load the nonce and exact run identity from the root-only ledger."""

        if self._root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        raw, _ = self._read_regular(
            self._root_descriptor, self._recovery_name, mode=0o600, cap=_MAX_CONTROL_BYTES
        )
        lines = raw.splitlines()
        if not lines:
            raise VMLeaseError("recovery ledger is empty")
        first = _strict_json(lines[0])
        nonce = first.get("nonce")
        values = ("run_device", "run_inode", "run_uid", "run_mode")
        if (
            not isinstance(nonce, str)
            or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
            or any(type(first.get(key)) is not int for key in values)
            or first["run_uid"] != os.getuid()
            or first["run_mode"] != 0o700
            or first["run_device"] < 0
            or first["run_inode"] < 1
        ):
            raise VMLeaseError("recovery ledger identity is invalid")
        self._nonce = nonce
        self._run_identity = (
            first["run_device"],
            first["run_inode"],
            first["run_uid"],
            first["run_mode"],
        )

    def _prove_run_absent(self) -> None:
        if self._root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        try:
            os.stat(self.name, dir_fd=self._root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise VMLeaseError("strict-VM run directory absence is unproven")

    def _prove_root_name_absent(self, name: str, *, label: str) -> None:
        if self._root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        try:
            os.stat(name, dir_fd=self._root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise VMLeaseError(f"strict-VM {label} absence is unproven")

    def _recovery_binding(self) -> tuple[str, str]:
        if self._root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        raw, _ = self._read_regular(
            self._root_descriptor, self._recovery_name, mode=0o600, cap=_MAX_CONTROL_BYTES
        )
        head, _artifacts, _removed, intent, completed = self._verify_chain(raw, recovery=True)
        if not intent or not completed:
            raise VMLeaseError("recovery ledger does not prove cleanup completion")
        self._last_recovery_hash = head
        return head, hashlib.sha256(raw).hexdigest()

    def _tombstone_payload(
        self,
        artifacts_removed: tuple[str, ...],
        recovery_head: str,
        recovery_sha256: str,
    ) -> dict[str, Any]:
        if self._nonce is None or self._run_identity is None:
            raise VMLeaseError("strict-VM cleanup tombstone has no run binding")
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "nonce": self._nonce,
            "run_device": self._run_identity[0],
            "run_inode": self._run_identity[1],
            "run_uid": self._run_identity[2],
            "run_mode": self._run_identity[3],
            "artifacts_removed": list(artifacts_removed),
            "recovery_head_sha256": recovery_head,
            "recovery_sha256": recovery_sha256,
            "finished_at": _now(),
        }

    def _read_cleanup_tombstone(
        self,
        *,
        expected_head: str | None = None,
        expected_recovery_sha256: str | None = None,
    ) -> VMCleanupReceipt:
        if self._root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        raw, _ = self._read_regular(
            self._root_descriptor, self._tombstone_name, mode=0o400, cap=64 * 1024
        )
        if not raw.endswith(b"\n"):
            raise VMLeaseError("cleanup tombstone is not canonical")
        value = _strict_json(raw[:-1])
        expected = {
            "schema_version",
            "run_id",
            "nonce",
            "run_device",
            "run_inode",
            "run_uid",
            "run_mode",
            "artifacts_removed",
            "recovery_head_sha256",
            "recovery_sha256",
            "finished_at",
        }
        if _canonical(value) + b"\n" != raw or set(value) != expected:
            raise VMLeaseError("cleanup tombstone payload is invalid")
        integers = ("run_device", "run_inode", "run_uid", "run_mode")
        artifacts = value["artifacts_removed"]
        if (
            value["schema_version"] != 1
            or value["run_id"] != self.run_id
            or not isinstance(value["nonce"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["nonce"]) is None
            or any(type(value[key]) is not int for key in integers)
            or value["run_uid"] != os.getuid()
            or value["run_mode"] != 0o700
            or value["run_device"] < 0
            or value["run_inode"] < 1
            or not isinstance(artifacts, list)
            or artifacts != sorted(set(artifacts))
            or any(_FILE_NAME.fullmatch(name) is None for name in artifacts)
            or not isinstance(value["recovery_head_sha256"], str)
            or _HEX64.fullmatch(value["recovery_head_sha256"]) is None
            or not isinstance(value["recovery_sha256"], str)
            or _HEX64.fullmatch(value["recovery_sha256"]) is None
            or not isinstance(value["finished_at"], str)
        ):
            raise VMLeaseError("cleanup tombstone fields are invalid")
        identity = (
            value["run_device"],
            value["run_inode"],
            value["run_uid"],
            value["run_mode"],
        )
        if self._nonce is not None and value["nonce"] != self._nonce:
            raise VMLeaseError("cleanup tombstone nonce conflicts with recovery ledger")
        if self._run_identity is not None and identity != self._run_identity:
            raise VMLeaseError("cleanup tombstone run identity conflicts with recovery ledger")
        if expected_head is not None and value["recovery_head_sha256"] != expected_head:
            raise VMLeaseError("cleanup tombstone recovery head conflicts with ledger")
        if (
            expected_recovery_sha256 is not None
            and value["recovery_sha256"] != expected_recovery_sha256
        ):
            raise VMLeaseError("cleanup tombstone recovery hash conflicts with ledger")
        self._nonce = value["nonce"]
        self._run_identity = identity
        return VMCleanupReceipt(1, self.run_id, tuple(artifacts), True, True, value["finished_at"])

    def _write_or_validate_cleanup_tombstone(
        self, artifacts_removed: tuple[str, ...]
    ) -> VMCleanupReceipt:
        recovery_head, recovery_sha256 = self._recovery_binding()
        payload = self._tombstone_payload(artifacts_removed, recovery_head, recovery_sha256)
        try:
            self._write_new(self._tombstone_name, _canonical(payload) + b"\n", 0o400, root=True)
        except FileExistsError:
            return self._read_cleanup_tombstone(
                expected_head=recovery_head, expected_recovery_sha256=recovery_sha256
            )
        return VMCleanupReceipt(
            1, self.run_id, artifacts_removed, True, True, payload["finished_at"]
        )

    def _retire_recovery_ledger(self, artifacts_removed: tuple[str, ...]) -> VMCleanupReceipt:
        if self._root_descriptor is None:
            raise VMLeaseError("strict-VM lease root is not active")
        self._prove_run_absent()
        receipt = self._write_or_validate_cleanup_tombstone(artifacts_removed)
        os.unlink(self._recovery_name, dir_fd=self._root_descriptor)
        os.fsync(self._root_descriptor)
        self._prove_run_absent()
        self._prove_root_name_absent(self._recovery_name, label="recovery ledger")
        self._completed_receipt = receipt
        self.close()
        return receipt

    def _resume(self) -> VMCleanupReceipt | None:
        if self._root_descriptor is not None or self._run_descriptor is not None:
            raise VMLeaseError("strict-VM lease cannot be resumed in its current state")
        try:
            self._resumed = True
            self._root_descriptor = self._open_directory_parent()
            try:
                self._run_descriptor = self._open_directory(self._root_descriptor, self.name)
            except VMLeaseError as exc:
                try:
                    self._prove_run_absent()
                except VMLeaseError:
                    raise exc from None
                try:
                    self._prove_root_name_absent(self._recovery_name, label="recovery ledger")
                except VMLeaseError:
                    pass
                else:
                    return self._read_cleanup_tombstone()
                self._bootstrap_recovery_identity()
                artifacts, _removed, intent, completed = self._verify_recovery()
                if not intent:
                    raise VMLeaseError("missing run directory has no removal intent") from exc
                if not completed:
                    self._record_recovery("cleanup_complete", artifacts=sorted(artifacts))
                return self._retire_recovery_ledger(tuple(sorted(artifacts)))
            self._run_identity = _directory_identity(self._run_descriptor)
            if self._run_identity[2:] != (os.getuid(), 0o700):
                raise VMLeaseError("strict-VM run directory identity is unsafe")
            # A marker is mandatory unless a previously verified root ledger
            # explicitly recorded the final rmdir intent.
            marker_present = _MARKER in os.listdir(self._run_descriptor)
            if marker_present:
                self._verify_marker()
            else:
                self._bootstrap_recovery_identity()
                if _directory_identity(self._run_descriptor) != self._run_identity:
                    raise VMLeaseError("recovery ledger does not bind this run directory")
            recovery_artifacts, removed, intent, _completed = self._verify_recovery()
            self._removal_intent = intent
            if not marker_present and not intent:
                raise VMLeaseError("lease marker is missing before removal intent")
            observed = set(os.listdir(self._run_descriptor))
            if _JOURNAL in observed:
                journal_info = os.stat(_JOURNAL, dir_fd=self._run_descriptor, follow_symlinks=False)
                early_setup = (
                    not recovery_artifacts
                    and not self._removal_intent
                    and stat.S_ISREG(journal_info.st_mode)
                    and journal_info.st_uid == os.getuid()
                    and stat.S_IMODE(journal_info.st_mode) == 0o600
                    and journal_info.st_nlink == 1
                    and journal_info.st_size == 0
                )
                if early_setup:
                    if observed - {_MARKER, _JOURNAL}:
                        raise VMLeaseError("early setup directory contains unknown entries")
                    self.record("run_dir_created")
                else:
                    journal_artifacts, journal_removed = self._verify_journal()
                    self._reconcile_journal_prefix(
                        journal_artifacts,
                        journal_removed,
                        recovery_artifacts,
                        removed,
                    )
            elif not self._removal_intent:
                if recovery_artifacts or observed - {_MARKER}:
                    raise VMLeaseError("lease journal is missing before removal intent")
                self._write_new(_JOURNAL, b"", 0o600)
                self.record("run_dir_created")
            self._artifacts = recovery_artifacts
        except BaseException:
            with suppress(VMLeaseError):
                self.close()
            raise

    def register_artifact(
        self,
        path: Path,
        *,
        role: str,
        mode: int,
        maximum_bytes: int = _MAX_ARTIFACT_BYTES,
        sha256: str | None = None,
    ) -> ArtifactIdentity:
        _, run_descriptor = self._require_active()
        self._require_unpoisoned()
        path = Path(path)
        if (
            path.parent != self.path
            or _FILE_NAME.fullmatch(path.name) is None
            or path.name in _RESERVED
            or path.name in self._artifacts
            or _ROLE.fullmatch(role) is None
            or mode not in {0o400, 0o600}
            or type(maximum_bytes) is not int
            or not 1 <= maximum_bytes <= _MAX_ARTIFACT_BYTES
            or (mode == 0o400 and (not isinstance(sha256, str) or _HEX64.fullmatch(sha256) is None))
            or (mode == 0o600 and sha256 is not None)
        ):
            raise VMLeaseError("artifact registration fields are unsafe")
        identity = self._validate_artifact(
            path.name, role, mode, maximum_bytes, sha256, sealed=mode == 0o400
        )
        self._record_recovery("artifact_registered", artifact=_identity_payload(identity))
        self.record("artifact_registered", artifact=_identity_payload(identity))
        self._artifacts[path.name] = identity
        return identity

    def _validate_artifact(
        self,
        name: str,
        role: str,
        mode: int,
        maximum_bytes: int,
        digest: str | None,
        *,
        sealed: bool,
        expected: ArtifactIdentity | None = None,
    ) -> ArtifactIdentity:
        _, run_descriptor = self._require_active()
        try:
            descriptor = os.open(
                name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=run_descriptor
            )
        except OSError as exc:
            raise VMLeaseError("artifact cannot be opened safely") from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != mode
                or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum_bytes
            ):
                raise VMLeaseError("artifact identity, mode, links, or size is unsafe")
            current = _artifact_identity(name, role, before, digest)
            if expected is not None:
                fields = ("device", "inode", "uid", "mode", "links", "size", "mtime_ns", "ctime_ns")
                if any(getattr(current, field) != getattr(expected, field) for field in fields):
                    raise VMLeaseError("registered artifact metadata changed before cleanup")
            if sealed:
                if digest is None:
                    raise VMLeaseError("sealed artifact requires SHA-256")
                hasher = hashlib.sha256()
                total = 0
                while True:
                    block = os.read(descriptor, _HASH_CHUNK_BYTES)
                    if not block:
                        break
                    total += len(block)
                    if total > maximum_bytes:
                        raise VMLeaseError("artifact exceeded its byte cap while hashing")
                    hasher.update(block)
                after = os.fstat(descriptor)
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_uid,
                    stat.S_IMODE(before.st_mode),
                    before.st_nlink,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_uid,
                    stat.S_IMODE(after.st_mode),
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) or hasher.hexdigest() != digest:
                    raise VMLeaseError("sealed artifact changed while hashing")
            return current
        finally:
            os.close(descriptor)

    def refresh_mutable_artifact(self, name: str) -> ArtifactIdentity:
        _, _ = self._require_active()
        self._require_unpoisoned()
        previous = self._artifacts.get(name)
        if previous is None or previous.mode != 0o600:
            raise VMLeaseError("mutable artifact is not a registered 0600 file")
        current = self._validate_artifact(
            name,
            previous.role,
            0o600,
            previous.size,
            None,
            sealed=False,
        )
        # Scratch may change timestamps and bytes, but never identity or size.
        if (
            current.device,
            current.inode,
            current.uid,
            current.mode,
            current.links,
            current.size,
        ) != (
            previous.device,
            previous.inode,
            previous.uid,
            previous.mode,
            previous.links,
            previous.size,
        ):
            raise VMLeaseError("mutable artifact identity changed beyond timestamps")
        self._record_recovery("artifact_refreshed", artifact=_identity_payload(current))
        self.record("artifact_refreshed", artifact=_identity_payload(current))
        self._artifacts[name] = current
        return current

    def _validate_cleanup_state(self, *, recovering: bool) -> list[str]:
        _, run_descriptor = self._require_active()
        if _directory_identity(run_descriptor) != self._run_identity:
            raise VMLeaseError("strict-VM run directory identity changed")
        observed = set(os.listdir(run_descriptor))
        controls = set() if self._removal_intent else {_MARKER, _JOURNAL}
        allowed = controls | set(self._artifacts)
        if not observed.issubset(allowed):
            raise VMLeaseError("strict-VM run directory contains unknown entries")
        if not self._removal_intent and not controls.issubset(observed):
            raise VMLeaseError("strict-VM control files are missing")
        present: list[str] = []
        for name, identity in self._artifacts.items():
            if name not in observed:
                if not recovering:
                    raise VMLeaseError("registered artifact is missing before cleanup")
                continue
            self._validate_artifact(
                name,
                identity.role,
                identity.mode,
                identity.size,
                identity.sha256,
                sealed=identity.mode == 0o400,
                expected=identity if identity.mode == 0o400 else None,
            )
            if identity.mode == 0o600:
                # Mutable file must retain every identity field except timestamps.
                info = os.stat(name, dir_fd=run_descriptor, follow_symlinks=False)
                current = _artifact_identity(name, identity.role, info, None)
                if (
                    current.device,
                    current.inode,
                    current.uid,
                    current.mode,
                    current.links,
                    current.size,
                ) != (
                    identity.device,
                    identity.inode,
                    identity.uid,
                    identity.mode,
                    identity.links,
                    identity.size,
                ):
                    raise VMLeaseError("mutable artifact identity changed before cleanup")
            present.append(name)
        return present

    def cleanup(self) -> VMCleanupReceipt:
        _, run_descriptor = self._require_active()
        removed: list[str] = []
        try:
            self._require_unpoisoned()
            recovery_artifacts, recovery_removed, intent, _completed = self._verify_recovery()
            if not self._removal_intent:
                self._verify_marker()
                journal_artifacts, journal_removed = self._verify_journal()
                self._reconcile_journal_prefix(
                    journal_artifacts,
                    journal_removed,
                    recovery_artifacts,
                    recovery_removed,
                )
            else:
                observed = set(os.listdir(run_descriptor))
                if _MARKER in observed:
                    self._verify_marker()
                if _JOURNAL in observed:
                    journal_artifacts, journal_removed = self._verify_journal()
                    self._reconcile_journal_prefix(
                        journal_artifacts,
                        journal_removed,
                        recovery_artifacts,
                        recovery_removed,
                    )
            self._artifacts = recovery_artifacts
            self._removal_intent = intent
            present = self._validate_cleanup_state(recovering=self._resumed)
            if self._removal_intent:
                if present:
                    raise VMLeaseError("directory-removal intent has live registered artifacts")
            else:
                if self._resumed:
                    for name in sorted(set(self._artifacts) - set(present)):
                        self._record_recovery("artifact_absent", artifacts=[name])
                        self.record("artifact_absent", artifacts=[name])
                self._record_recovery("cleanup_started", artifacts=sorted(self._artifacts))
                self.record("cleanup_started", artifacts=sorted(self._artifacts))
                for identity in sorted(
                    (self._artifacts[name] for name in present),
                    key=lambda value: (value.mode != 0o600, value.name),
                ):
                    os.unlink(identity.name, dir_fd=run_descriptor)
                    os.fsync(run_descriptor)
                    try:
                        os.stat(identity.name, dir_fd=run_descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise VMLeaseError("artifact unlink did not prove path absence")
                    removed.append(identity.name)
                    self._record_recovery("artifact_absent", artifacts=[identity.name])
                    self.record("artifact_absent", artifacts=[identity.name])
                # This root-level, fsynced intent makes it safe to remove the
                # in-directory marker only because restart recovery still has the
                # exact name, nonce, directory identity, and artifact register.
                self._record_recovery("run_directory_removal_intent")
                self.record("run_directory_removal_intent")
                self._removal_intent = True
            for control in (_JOURNAL, _MARKER):
                if control in os.listdir(run_descriptor):
                    os.unlink(control, dir_fd=run_descriptor)
                    os.fsync(run_descriptor)
            if os.listdir(run_descriptor):
                raise VMLeaseError("strict-VM run directory is not empty after exact cleanup")
            os.close(run_descriptor)
            self._run_descriptor = None
            root_descriptor = self._root_descriptor
            if root_descriptor is None:
                raise VMLeaseError("strict-VM root descriptor disappeared")
            os.rmdir(self.name, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            try:
                os.stat(self.name, dir_fd=root_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise VMLeaseError("strict-VM run directory absence is unproven")
            all_removed = tuple(sorted(self._artifacts))
            self._record_recovery("cleanup_complete", artifacts=list(all_removed))
            return self._retire_recovery_ledger(all_removed)
        except BaseException as exc:
            retained: tuple[str, ...]
            try:
                retained = tuple(sorted(os.listdir(run_descriptor)))
            except OSError:
                retained = (self.name,)
            with suppress(VMLeaseError):
                self.close()
            raise VMCleanupPendingError(
                "strict-VM cleanup could not prove exact resource absence", self.run_id, retained
            ) from exc

    def close(self) -> None:
        errors: list[OSError] = []
        for attribute in ("_run_descriptor", "_root_descriptor"):
            descriptor = getattr(self, attribute)
            if descriptor is not None:
                setattr(self, attribute, None)
                try:
                    os.close(descriptor)
                except OSError as exc:
                    errors.append(exc)
        if errors:
            raise VMLeaseError("strict-VM lease descriptor cleanup failed") from errors[0]
