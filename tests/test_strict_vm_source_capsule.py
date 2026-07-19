from __future__ import annotations

import fcntl
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leftovers.strict_vm_source_capsule import (  # noqa: PLC2701
    _ENTRY,
    _HEADER,
    CAPSULE_FILE_MODE,
    MAX_CONTENT_BYTES,
    SourceCapsuleError,
    SourceCapsuleUnavailableError,
    issue_fixture_source_capsule_capability,
    pack_lfsc_v1,
    pack_lfsc_v1_fixture,
    validate_lfsc_v1,
)


class StrictVMSourceCapsuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "private-source"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.capability = issue_fixture_source_capsule_capability()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _file(self, relative: str, content: bytes, mode: int = 0o600) -> None:
        target = self.root / relative
        target.parent.mkdir(mode=0o700, exist_ok=True)
        for directory in (target.parent,):
            os.chmod(directory, 0o700)
        target.write_bytes(content)
        os.chmod(target, mode)

    def _pack(self):
        capsule = self.base / "capsule.lfsc"
        capsule.unlink(missing_ok=True)
        capsule.touch(mode=CAPSULE_FILE_MODE)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        capsule_fd = os.open(capsule, os.O_RDWR | os.O_CLOEXEC)
        try:
            result = pack_lfsc_v1_fixture(root_fd, capsule_fd, capability=self.capability)
        finally:
            os.close(capsule_fd)
            os.close(root_fd)
        return capsule, result

    def _validate(self, capsule: Path):
        fd = os.open(capsule, os.O_RDONLY | os.O_CLOEXEC)
        try:
            return validate_lfsc_v1(fd)
        finally:
            os.close(fd)

    def test_round_trip_is_sorted_nfc_padded_and_descriptor_only(self) -> None:
        self._file("b.txt", b"b")
        self._file("a/run", b"#!/bin/true\n", 0o700)
        self._file("a/é.txt", b"accent")
        self._file("a.txt", b"component-boundary")
        capsule, packed = self._pack()
        validated = self._validate(capsule)
        self.assertEqual(packed, validated)
        self.assertEqual(
            [item.path for item in validated.files],
            ["a/run", "a/é.txt", "a.txt", "b.txt"],
        )
        self.assertEqual([item.mode for item in validated.files], [0o755, 0o644, 0o644, 0o644])
        raw = capsule.read_bytes()
        self.assertEqual(_HEADER.size, 160)
        self.assertEqual(len(raw), _HEADER.size + validated.payload_bytes)
        self.assertEqual(raw[:4], b"LFSC")
        check_fd = os.open(capsule, os.O_RDONLY | os.O_CLOEXEC)
        try:
            self.assertTrue(fcntl.fcntl(check_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        finally:
            os.close(check_fd)

    def test_production_packing_rejects_before_descriptor_access(self) -> None:
        class Exploding:
            def __int__(self) -> int:
                raise AssertionError("production gate touched descriptor")

        with self.assertRaises(SourceCapsuleUnavailableError):
            pack_lfsc_v1(Exploding(), Exploding())  # type: ignore[arg-type]

    def test_input_contract_rejects_hostile_types_paths_modes_and_hardlinks(self) -> None:
        self._file(".git/config", b"x")
        with self.assertRaisesRegex(SourceCapsuleError, "path component"):
            self._pack()
        (self.root / ".git").unlink() if (self.root / ".git").is_file() else None
        shutil.rmtree(self.root / ".git")
        self._file("link", b"x")
        os.link(self.root / "link", self.root / "hard")
        with self.assertRaisesRegex(SourceCapsuleError, "unsafe regular"):
            self._pack()
        (self.root / "hard").unlink()
        self._file("bad-mode", b"x", 0o644)
        with self.assertRaisesRegex(SourceCapsuleError, "input mode"):
            self._pack()
        (self.root / "bad-mode").unlink()
        os.mkfifo(self.root / "pipe", 0o600)
        with self.assertRaisesRegex(SourceCapsuleError, "non-regular"):
            self._pack()
        (self.root / "pipe").unlink()
        self._file("e\u0301", b"x")
        with self.assertRaisesRegex(SourceCapsuleError, "path component"):
            self._pack()

    def test_validator_rejects_truncation_digest_drift_extra_bytes_and_reordering(self) -> None:
        self._file("a", b"alpha")
        self._file("b", b"beta")
        capsule, _ = self._pack()
        raw = bytearray(capsule.read_bytes())
        for mutate, expected in (
            (lambda value: value.__delitem__(-1), "size|truncated|payload|header"),
            (lambda value: value.__setitem__(_HEADER.size + _ENTRY.size + 8, 0x78), "digest|path"),
            (lambda value: value.extend(b"x"), "size|extra|header"),
        ):
            changed = bytearray(raw)
            mutate(changed)
            capsule.write_bytes(changed)
            os.chmod(capsule, CAPSULE_FILE_MODE)
            with self.assertRaisesRegex(SourceCapsuleError, expected):
                self._validate(capsule)
        capsule.write_bytes(raw)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        first = _HEADER.size
        second = first + _ENTRY.size + 1 + 7 + 5 + 3
        swapped = bytearray(raw)
        swapped[first + _ENTRY.size], swapped[second + _ENTRY.size] = (
            swapped[second + _ENTRY.size],
            swapped[first + _ENTRY.size],
        )
        capsule.write_bytes(swapped)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        with self.assertRaisesRegex(SourceCapsuleError, "reordered|digest"):
            self._validate(capsule)

    def test_validator_rejects_nonzero_padding_and_stalled_io(self) -> None:
        self._file("a", b"a")
        capsule, _ = self._pack()
        raw = bytearray(capsule.read_bytes())
        raw[_HEADER.size + _ENTRY.size + 1] = 1
        capsule.write_bytes(raw)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        with self.assertRaisesRegex(SourceCapsuleError, "padding"):
            self._validate(capsule)
        capsule.write_bytes(bytes(raw))
        os.chmod(capsule, CAPSULE_FILE_MODE)
        with (
            mock.patch("leftovers.strict_vm_source_capsule.os.read", return_value=b""),
            self.assertRaisesRegex(SourceCapsuleError, "truncated|stalled"),
        ):
            self._validate(capsule)

    def test_caps_and_mutation_and_output_identity_fail_closed(self) -> None:
        self._file("a", b"a")
        capsule = self.base / "capsule.lfsc"
        capsule.touch(mode=CAPSULE_FILE_MODE)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        capsule_fd = os.open(capsule, os.O_RDWR | os.O_CLOEXEC)
        try:
            with (
                mock.patch(
                    "leftovers.strict_vm_source_capsule.os.fsync", side_effect=OSError("no")
                ),
                self.assertRaisesRegex(SourceCapsuleError, "fsync"),
            ):
                pack_lfsc_v1_fixture(root_fd, capsule_fd, capability=self.capability)
        finally:
            os.close(capsule_fd)
            os.close(root_fd)
        self._file("too-big", b"x" * (MAX_CONTENT_BYTES + 1))
        with self.assertRaisesRegex(SourceCapsuleError, "unsafe regular|exceeds"):
            self._pack()
        (self.root / "too-big").unlink()
        capsule, _ = self._pack()
        with (
            mock.patch(
                "leftovers.strict_vm_source_capsule.os.fstat",
                side_effect=lambda fd: os.stat_result((0,) * 10),
            ),
            self.assertRaises(SourceCapsuleError),
        ):
            self._validate(capsule)

    def test_read_write_stalls_and_source_mutation_fail_closed(self) -> None:
        self._file("a", b"content")
        with (
            mock.patch("leftovers.strict_vm_source_capsule.os.write", return_value=0),
            self.assertRaisesRegex(SourceCapsuleError, "write stalled"),
        ):
            self._pack()

        original_read = os.read
        changed = False

        def mutate_after_read(fd: int, size: int) -> bytes:
            nonlocal changed
            value = original_read(fd, size)
            if value and not changed:
                changed = True
                os.chmod(self.root / "a", 0o700)
            return value

        with (
            mock.patch("leftovers.strict_vm_source_capsule.os.read", side_effect=mutate_after_read),
            self.assertRaisesRegex(SourceCapsuleError, "mutated|changed"),
        ):
            self._pack()

    def test_output_inside_input_tree_is_rejected_before_writing(self) -> None:
        self._file("source", b"content")
        capsule = self.root / "capsule.lfsc"
        capsule.touch(mode=CAPSULE_FILE_MODE)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        capsule_fd = os.open(capsule, os.O_RDWR | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(SourceCapsuleError, "aliases"):
                pack_lfsc_v1_fixture(root_fd, capsule_fd, capability=self.capability)
        finally:
            os.close(capsule_fd)
            os.close(root_fd)
        self.assertEqual(capsule.read_bytes(), b"")

    def test_duplicate_acquisition_failures_close_every_acquired_fd(self) -> None:
        self._file("source", b"content")
        capsule = self.base / "dup-failure.lfsc"
        capsule.touch(mode=CAPSULE_FILE_MODE)
        os.chmod(capsule, CAPSULE_FILE_MODE)
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        capsule_fd = os.open(capsule, os.O_RDWR | os.O_CLOEXEC)
        original_dup = os.dup
        duplicated: list[int] = []

        def record_dup(fd: int) -> int:
            duplicate = original_dup(fd)
            duplicated.append(duplicate)
            return duplicate

        try:
            with (
                mock.patch(
                    "leftovers.strict_vm_source_capsule._set_cloexec",
                    side_effect=SourceCapsuleError("injected CLOEXEC failure"),
                ),
                mock.patch("leftovers.strict_vm_source_capsule.os.dup", side_effect=record_dup),
                self.assertRaisesRegex(SourceCapsuleError, "CLOEXEC"),
            ):
                pack_lfsc_v1_fixture(root_fd, capsule_fd, capability=self.capability)
            self.assertEqual(len(duplicated), 1)
            with self.assertRaises(OSError):
                os.fstat(duplicated[0])

            duplicated.clear()

            def fail_second_dup(fd: int) -> int:
                if duplicated:
                    raise OSError("injected second dup failure")
                return record_dup(fd)

            with (
                mock.patch(
                    "leftovers.strict_vm_source_capsule.os.dup",
                    side_effect=fail_second_dup,
                ),
                self.assertRaisesRegex(SourceCapsuleError, "unavailable"),
            ):
                pack_lfsc_v1_fixture(root_fd, capsule_fd, capability=self.capability)
            self.assertEqual(len(duplicated), 1)
            with self.assertRaises(OSError):
                os.fstat(duplicated[0])
        finally:
            os.close(capsule_fd)
            os.close(root_fd)

    def test_file_and_directory_close_failures_are_not_suppressed_or_retried(self) -> None:
        original_close = os.close

        self._file("file", b"content")
        file_identity = (self.root / "file").stat()
        failed_file_descriptors: list[int] = []

        def fail_file_close(fd: int) -> None:
            details = os.fstat(fd)
            matches = (details.st_dev, details.st_ino) == (
                file_identity.st_dev,
                file_identity.st_ino,
            )
            original_close(fd)
            if matches:
                failed_file_descriptors.append(fd)
                raise OSError("injected file close failure")

        with (
            mock.patch("leftovers.strict_vm_source_capsule.os.close", side_effect=fail_file_close),
            self.assertRaisesRegex(SourceCapsuleError, "source file descriptor close"),
        ):
            self._pack()
        self.assertEqual(len(failed_file_descriptors), 1)

        (self.root / "file").unlink()
        self._file("nested/file", b"content")
        directory_identity = (self.root / "nested").stat()
        matching_directory_closes: list[int] = []

        def fail_second_directory_close(fd: int) -> None:
            details = os.fstat(fd)
            matches = (details.st_dev, details.st_ino) == (
                directory_identity.st_dev,
                directory_identity.st_ino,
            )
            original_close(fd)
            if matches:
                matching_directory_closes.append(fd)
                if len(matching_directory_closes) == 2:
                    raise OSError("injected directory close failure")

        with (
            mock.patch(
                "leftovers.strict_vm_source_capsule.os.close",
                side_effect=fail_second_directory_close,
            ),
            self.assertRaisesRegex(SourceCapsuleError, "source directory descriptor close"),
        ):
            self._pack()
        self.assertEqual(len(matching_directory_closes), 2)

    def test_pack_and_validation_close_failures_fail_closed_once(self) -> None:
        self._file("file", b"content")
        original_dup = os.dup
        original_close = os.close
        duplicates: list[int] = []
        failed_closes: list[int] = []

        def record_dup(fd: int) -> int:
            duplicate = original_dup(fd)
            duplicates.append(duplicate)
            return duplicate

        def fail_source_root_close(fd: int) -> None:
            should_fail = bool(duplicates) and fd == duplicates[0]
            original_close(fd)
            if should_fail:
                failed_closes.append(fd)
                raise OSError("injected pack close failure")

        with (
            mock.patch("leftovers.strict_vm_source_capsule.os.dup", side_effect=record_dup),
            mock.patch(
                "leftovers.strict_vm_source_capsule.os.close",
                side_effect=fail_source_root_close,
            ),
            self.assertRaisesRegex(SourceCapsuleError, "source root descriptor close"),
        ):
            self._pack()
        self.assertEqual(failed_closes, duplicates[:1])

        capsule, _ = self._pack()
        validation_fd = os.open(capsule, os.O_RDONLY | os.O_CLOEXEC)
        duplicates.clear()
        failed_closes.clear()
        try:
            with (
                mock.patch("leftovers.strict_vm_source_capsule.os.dup", side_effect=record_dup),
                mock.patch(
                    "leftovers.strict_vm_source_capsule.os.close",
                    side_effect=fail_source_root_close,
                ),
                self.assertRaisesRegex(SourceCapsuleError, "capsule validation descriptor close"),
            ):
                validate_lfsc_v1(validation_fd)
            self.assertEqual(failed_closes, duplicates)
        finally:
            os.close(validation_fd)
