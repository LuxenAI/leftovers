from __future__ import annotations

import fcntl
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from leftovers.strict_vm_broker import (
    BrokerInstallation,
    BrokerUnavailableError,
    ImmutableBootIdentity,
)
from leftovers.strict_vm_broker_journal import BrokerBootSessionEvidence, DurableBrokerJournal
from leftovers.strict_vm_broker_storage import (
    MAX_SLOT_IMAGE_BYTES,
    BrokerJournalStorageAmbiguousError,
    BrokerJournalStorageError,
    FixtureBrokerJournalStorage,
    FixtureBrokerJournalStorageCapability,
    StrictVMBrokerJournalStorage,
    UnreadableBrokerJournalSlot,
    issue_fixture_broker_journal_storage_capability,
)


class StrictVMBrokerStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "broker-private"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.capability = issue_fixture_broker_journal_storage_capability()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _storage(self) -> FixtureBrokerJournalStorage:
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            return FixtureBrokerJournalStorage(
                fd, broker_uid=os.getuid(), capability=self.capability
            )
        finally:
            os.close(fd)

    def _slot(self):
        with self._storage() as storage:
            journal = DurableBrokerJournal.create(
                BrokerInstallation(
                    service_root=self.root / "service",
                    launcher_path=self.root / "launcher",
                    controller_uid=os.getuid() + 1,
                    broker_uid=os.getuid(),
                    boot_identity=ImmutableBootIdentity(*(["a" * 64] * 5)),
                ),
                storage,
                boot_session=BrokerBootSessionEvidence("b" * 64),
            )
            return journal.slot_snapshot

    def test_binary_slot_round_trip_is_descriptor_relative_and_bounded(self) -> None:
        slot = self._slot()
        with self._storage() as storage:
            slots = storage.read_slots()
        self.assertEqual(slots, (slot, None))
        raw = (self.root / "journal.slot0").read_bytes()
        self.assertNotIn(b"base64", raw)
        self.assertLessEqual(len(raw), MAX_SLOT_IMAGE_BYTES + 1024)
        self.assertEqual(stat.S_IMODE((self.root / "journal.slot0").stat().st_mode), 0o600)

    def test_invalid_root_and_production_surface_reject_before_input_access(self) -> None:
        class _Exploding:
            def __getattribute__(self, name: str) -> object:
                raise AssertionError(f"storage gate accessed {name}")

        with self.assertRaises(BrokerUnavailableError):
            StrictVMBrokerJournalStorage(_Exploding())
        file_fd = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerJournalStorageError):
                FixtureBrokerJournalStorage(
                    file_fd, broker_uid=os.getuid(), capability=self.capability
                )
        finally:
            os.close(file_fd)
        os.chmod(self.root, 0o755)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerJournalStorageError):
                FixtureBrokerJournalStorage(fd, broker_uid=os.getuid(), capability=self.capability)
        finally:
            os.close(fd)

    def test_constructor_closes_duplicate_once_when_inheritability_setup_fails(self) -> None:
        private_root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        original_close = os.close
        duplicate_fd = os.dup(private_root_fd)
        close_calls: list[int] = []

        def close_duplicate(fd: int) -> None:
            close_calls.append(fd)
            original_close(fd)

        try:
            with (
                mock.patch("leftovers.strict_vm_broker_storage.os.dup", return_value=duplicate_fd),
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.set_inheritable",
                    side_effect=OSError("inheritable setup failure"),
                ),
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.close",
                    side_effect=close_duplicate,
                ),
                self.assertRaisesRegex(BrokerJournalStorageError, "cannot retain"),
            ):
                FixtureBrokerJournalStorage(
                    private_root_fd,
                    broker_uid=os.getuid(),
                    capability=self.capability,
                )
            self.assertEqual(close_calls, [duplicate_fd])
            with self.assertRaises(OSError):
                os.fstat(duplicate_fd)
        finally:
            original_close(private_root_fd)

    def test_constructor_cleanup_close_error_is_explicit_and_never_retried(self) -> None:
        private_root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        original_close = os.close
        duplicate_fd = os.dup(private_root_fd)
        close_calls = 0

        def close_then_report_error(fd: int) -> None:
            nonlocal close_calls
            self.assertEqual(fd, duplicate_fd)
            close_calls += 1
            original_close(fd)
            raise OSError("ambiguous cleanup close")

        try:
            with (
                mock.patch("leftovers.strict_vm_broker_storage.os.dup", return_value=duplicate_fd),
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.set_inheritable",
                    side_effect=OSError("inheritable setup failure"),
                ),
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.close",
                    side_effect=close_then_report_error,
                ),
                self.assertRaisesRegex(BrokerJournalStorageError, "cleanup close is ambiguous"),
            ):
                FixtureBrokerJournalStorage(
                    private_root_fd,
                    broker_uid=os.getuid(),
                    capability=self.capability,
                )
            self.assertEqual(close_calls, 1)
            with self.assertRaises(OSError):
                os.fstat(duplicate_fd)
        finally:
            original_close(private_root_fd)
        os.chmod(self.root, 0o700)
        forged = object.__new__(FixtureBrokerJournalStorageCapability)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerUnavailableError):
                FixtureBrokerJournalStorage(fd, broker_uid=os.getuid(), capability=forged)
        finally:
            os.close(fd)

    def test_symlink_hardlink_fifo_oversize_and_truncation_are_unreadable(self) -> None:
        slot = self._slot()
        outside = self.root.parent / "outside"
        outside.write_bytes(b"outside")
        slot_path = self.root / "journal.slot1"
        os.symlink(outside, slot_path)
        with self._storage() as storage:
            self.assertEqual(storage.read_slots()[1], UnreadableBrokerJournalSlot(1))
        slot_path.unlink()
        os.link(self.root / "journal.slot0", slot_path)
        with self._storage() as storage:
            self.assertEqual(storage.read_slots()[1], UnreadableBrokerJournalSlot(1))
        slot_path.unlink()
        os.mkfifo(slot_path, 0o600)
        with self._storage() as storage:
            self.assertEqual(storage.read_slots()[1], UnreadableBrokerJournalSlot(1))
        slot_path.unlink()
        slot_path.write_bytes(b"x")
        with slot_path.open("r+b") as handle:
            handle.truncate(MAX_SLOT_IMAGE_BYTES + 2048)
        os.chmod(slot_path, 0o600)
        with self._storage() as storage:
            self.assertEqual(storage.read_slots()[1], UnreadableBrokerJournalSlot(1))
        slot_path.unlink()
        with self._storage() as storage:
            storage.write_slot_fsynced(1, slot)
        with slot_path.open("r+b") as handle:
            handle.truncate(slot_path.stat().st_size - 1)
        with self._storage() as storage:
            self.assertEqual(storage.read_slots()[1], UnreadableBrokerJournalSlot(1))

    def test_preexisting_temp_refuses_without_replacing_a_slot(self) -> None:
        slot = self._slot()
        temp = self.root / "journal.slot1.tmp"
        temp.write_bytes(b"crash remnant")
        os.chmod(temp, 0o600)
        with (
            self._storage() as storage,
            self.assertRaisesRegex(BrokerJournalStorageError, "temp name"),
        ):
            storage.write_slot_fsynced(1, slot)
        self.assertTrue(temp.exists())
        self.assertFalse((self.root / "journal.slot1").exists())

    def test_fixture_recovery_removes_only_safe_stale_temps_and_is_idempotent(self) -> None:
        for index in range(2):
            temp = self.root / f"journal.slot{index}.tmp"
            temp.write_bytes(f"stale-{index}".encode())
            os.chmod(temp, 0o600)
        with self._storage() as storage:
            storage.recover_fixture_stale_temps()
            storage.recover_fixture_stale_temps()
        self.assertFalse((self.root / "journal.slot0.tmp").exists())
        self.assertFalse((self.root / "journal.slot1.tmp").exists())

    def test_fixture_recovery_rejects_unsafe_stale_temp_types_and_metadata(self) -> None:
        temp = self.root / "journal.slot0.tmp"
        outside = self.root.parent / "outside-temp"
        outside.write_bytes(b"outside")
        os.chmod(outside, 0o600)

        os.symlink(outside, temp)
        with self._storage() as storage, self.assertRaises(BrokerJournalStorageError):
            storage.recover_fixture_stale_temps()
        temp.unlink()

        os.link(outside, temp)
        with self._storage() as storage, self.assertRaises(BrokerJournalStorageError):
            storage.recover_fixture_stale_temps()
        temp.unlink()

        os.mkfifo(temp, 0o600)
        with self._storage() as storage, self.assertRaises(BrokerJournalStorageError):
            storage.recover_fixture_stale_temps()
        temp.unlink()

        temp.mkdir(mode=0o700)
        with self._storage() as storage, self.assertRaises(BrokerJournalStorageError):
            storage.recover_fixture_stale_temps()
        temp.rmdir()

        temp.write_bytes(b"wrong mode")
        os.chmod(temp, 0o644)
        with self._storage() as storage, self.assertRaises(BrokerJournalStorageError):
            storage.recover_fixture_stale_temps()
        temp.unlink()

        temp.write_bytes(b"x")
        os.chmod(temp, 0o600)
        with temp.open("r+b") as handle:
            handle.truncate(MAX_SLOT_IMAGE_BYTES + 2048)
        with self._storage() as storage, self.assertRaises(BrokerJournalStorageError):
            storage.recover_fixture_stale_temps()
        temp.unlink()

        temp.write_bytes(b"wrong owner observation")
        os.chmod(temp, 0o600)
        original_fstat = os.fstat

        def wrong_owner_fstat(fd: int):
            details = original_fstat(fd)
            if stat.S_ISREG(details.st_mode):
                return SimpleNamespace(
                    st_dev=details.st_dev,
                    st_ino=details.st_ino,
                    st_mode=details.st_mode,
                    st_uid=os.getuid() + 1,
                    st_nlink=details.st_nlink,
                    st_size=details.st_size,
                    st_mtime_ns=details.st_mtime_ns,
                    st_ctime_ns=details.st_ctime_ns,
                )
            return details

        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.fstat", side_effect=wrong_owner_fstat
            ),
            self.assertRaises(BrokerJournalStorageError),
        ):
            storage.recover_fixture_stale_temps()
        self.assertTrue(temp.exists())

    def test_fixture_recovery_fails_closed_on_unlink_fsync_and_reappearance(self) -> None:
        temp = self.root / "journal.slot0.tmp"
        temp.write_bytes(b"stale")
        os.chmod(temp, 0o600)
        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.unlink",
                side_effect=OSError("unlink failure"),
            ),
            self.assertRaises(BrokerJournalStorageAmbiguousError),
        ):
            storage.recover_fixture_stale_temps()
        self.assertTrue(temp.exists())

        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.fsync",
                side_effect=OSError("directory fsync failure"),
            ),
            self.assertRaises(BrokerJournalStorageAmbiguousError),
        ):
            storage.recover_fixture_stale_temps()
        self.assertFalse(temp.exists())

        temp.write_bytes(b"stale again")
        os.chmod(temp, 0o600)
        original_unlink = os.unlink

        def unlink_then_reappear(name: str, *, dir_fd: int) -> None:
            original_unlink(name, dir_fd=dir_fd)
            replacement_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
            os.close(replacement_fd)

        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.unlink", side_effect=unlink_then_reappear
            ),
            self.assertRaises(BrokerJournalStorageAmbiguousError),
        ):
            storage.recover_fixture_stale_temps()
        self.assertTrue(temp.exists())

    def test_fixture_recovery_rejects_post_unlink_root_identity_change(self) -> None:
        temp = self.root / "journal.slot0.tmp"
        temp.write_bytes(b"stale")
        os.chmod(temp, 0o600)
        original_unlink = os.unlink

        def unlink_then_change_root_mode(name: str, *, dir_fd: int) -> None:
            original_unlink(name, dir_fd=dir_fd)
            os.chmod(self.root, 0o755)

        try:
            with (
                self._storage() as storage,
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.unlink",
                    side_effect=unlink_then_change_root_mode,
                ),
                self.assertRaises(BrokerJournalStorageAmbiguousError),
            ):
                storage.recover_fixture_stale_temps()
        finally:
            os.chmod(self.root, 0o700)
        self.assertFalse(temp.exists())

    def test_write_fsync_rename_and_write_failures_are_explicitly_ambiguous(self) -> None:
        slot = self._slot()
        for target, replacement in (
            ("fsync", mock.Mock(side_effect=OSError("fsync failure"))),
            ("replace", mock.Mock(side_effect=OSError("rename failure"))),
            ("write", mock.Mock(side_effect=OSError("write failure"))),
        ):
            with (
                self.subTest(target=target),
                self._storage() as storage,
                mock.patch(f"leftovers.strict_vm_broker_storage.os.{target}", replacement),
                self.assertRaises(BrokerJournalStorageAmbiguousError),
            ):
                storage.write_slot_fsynced(1, slot)
            temp = self.root / "journal.slot1.tmp"
            if temp.exists():
                temp.unlink()

    def test_write_rejects_destination_replacement_and_temp_reappearance(self) -> None:
        slot = self._slot()
        original_replace = os.replace

        def replace_then_substitute(
            source: str,
            destination: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
        ) -> None:
            original_replace(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )
            original_replace(
                destination,
                "saved-fsynced-slot",
                src_dir_fd=dst_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )
            replacement_fd = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=dst_dir_fd,
            )
            os.write(replacement_fd, b"replacement")
            os.close(replacement_fd)

        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.replace",
                side_effect=replace_then_substitute,
            ),
            self.assertRaises(BrokerJournalStorageAmbiguousError),
        ):
            storage.write_slot_fsynced(1, slot)
        self.assertTrue((self.root / "saved-fsynced-slot").exists())

        (self.root / "journal.slot1").unlink()
        (self.root / "saved-fsynced-slot").unlink()

        def replace_then_reappear(
            source: str,
            destination: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
        ) -> None:
            original_replace(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )
            reappeared_fd = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=src_dir_fd,
            )
            os.close(reappeared_fd)

        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.replace",
                side_effect=replace_then_reappear,
            ),
            self.assertRaises(BrokerJournalStorageAmbiguousError),
        ):
            storage.write_slot_fsynced(1, slot)
        self.assertTrue((self.root / "journal.slot1.tmp").exists())

    def test_write_close_error_poisons_local_fd_without_double_close(self) -> None:
        slot = self._slot()
        original_open = os.open
        original_close = os.close
        temp_fd: int | None = None
        temp_close_calls = 0

        def capture_temp_open(name, flags, mode=0o777, *, dir_fd=None):
            nonlocal temp_fd
            opened = original_open(name, flags, mode, dir_fd=dir_fd)
            if name == "journal.slot1.tmp":
                temp_fd = opened
            return opened

        def fail_temp_close(fd: int) -> None:
            nonlocal temp_close_calls
            if fd == temp_fd:
                temp_close_calls += 1
                raise OSError("ambiguous temp close")
            original_close(fd)

        with (
            self._storage() as storage,
            mock.patch("leftovers.strict_vm_broker_storage.os.open", side_effect=capture_temp_open),
            mock.patch("leftovers.strict_vm_broker_storage.os.close", side_effect=fail_temp_close),
            self.assertRaisesRegex(BrokerJournalStorageAmbiguousError, "descriptor close"),
        ):
            storage.write_slot_fsynced(1, slot)
        self.assertIsNotNone(temp_fd)
        self.assertEqual(temp_close_calls, 1)
        original_close(temp_fd)

    def test_read_error_returns_unreadable_not_absent(self) -> None:
        self._slot()
        with (
            self._storage() as storage,
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.read", side_effect=OSError("read failure")
            ),
        ):
            self.assertEqual(storage.read_slots()[0], UnreadableBrokerJournalSlot(0))

    def test_read_close_error_returns_unreadable_and_never_reuses_slot_fd(self) -> None:
        self._slot()
        storage = self._storage()
        original_open = os.open
        original_close = os.close
        slot_fd: int | None = None
        slot_close_calls = 0

        def capture_slot_open(name, flags, mode=0o777, *, dir_fd=None):
            nonlocal slot_fd
            opened = original_open(name, flags, mode, dir_fd=dir_fd)
            if name == "journal.slot0":
                slot_fd = opened
            return opened

        def fail_slot_close(fd: int) -> None:
            nonlocal slot_close_calls
            if fd == slot_fd:
                slot_close_calls += 1
                raise OSError("ambiguous slot close")
            original_close(fd)

        try:
            with (
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.open",
                    side_effect=capture_slot_open,
                ),
                mock.patch(
                    "leftovers.strict_vm_broker_storage.os.close",
                    side_effect=fail_slot_close,
                ),
            ):
                self.assertEqual(storage.read_slots()[0], UnreadableBrokerJournalSlot(0))
            self.assertIsNotNone(slot_fd)
            self.assertEqual(slot_close_calls, 1)
            original_close(slot_fd)
        finally:
            storage.close()

    def test_retained_descriptor_is_noninheritable_and_writes_are_chunked(self) -> None:
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        os.set_inheritable(fd, True)
        try:
            storage = FixtureBrokerJournalStorage(
                fd, broker_uid=os.getuid(), capability=self.capability
            )
        finally:
            os.close(fd)
        try:
            self.assertTrue(fcntl.fcntl(storage._root_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            self.assertFalse(os.get_inheritable(storage._root_fd))
        finally:
            storage.close()
        writes: list[int] = []
        original_write = os.write

        def recording_write(target_fd: int, value: bytes) -> int:
            writes.append(len(value))
            return original_write(target_fd, value)

        slot = self._slot()
        with (
            self._storage() as storage,
            mock.patch("leftovers.strict_vm_broker_storage.os.write", side_effect=recording_write),
        ):
            storage.write_slot_fsynced(1, slot)
        self.assertTrue(writes)
        self.assertLessEqual(max(writes), 64 * 1024)

    def test_close_error_poisoned_retained_descriptor_before_reporting(self) -> None:
        storage = self._storage()
        retained_fd = storage._root_fd
        with (
            mock.patch(
                "leftovers.strict_vm_broker_storage.os.close",
                side_effect=OSError("ambiguous close failure"),
            ),
            self.assertRaises(BrokerJournalStorageError),
        ):
            storage.close()
        self.assertTrue(storage._closed)
        self.assertEqual(storage._root_fd, -1)
        with self.assertRaisesRegex(BrokerJournalStorageError, "closed"):
            storage.read_slots()
        os.close(retained_fd)
