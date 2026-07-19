from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from leftovers.strict_vm_lease import (
    ArtifactIdentity,
    StrictVMRunLease,
    VMCleanupPendingError,
    VMLeaseError,
)


class StrictVMRunLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.run_id = "a" * 32

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lease(self) -> StrictVMRunLease:
        return StrictVMRunLease(self.root, self.run_id)

    def recovery_path(self) -> Path:
        return self.root / f".leftovers-strict-vm-recovery-{self.run_id}.jsonl"

    def tombstone_path(self) -> Path:
        return self.root / f".leftovers-strict-vm-cleanup-{self.run_id}.json"

    def test_constructor_does_not_acquire_or_create_controller_files(self) -> None:
        lease = self.lease()

        self.assertFalse(lease.path.exists())
        self.assertFalse(
            (self.root / f".leftovers-strict-vm-recovery-{self.run_id}.jsonl").exists()
        )
        self.assertIsNone(lease._root_descriptor)
        self.assertIsNone(lease._run_descriptor)

    def test_acquire_and_empty_cleanup_are_marker_bound_and_exact(self) -> None:
        lease = self.lease().acquire()
        self.assertEqual(lease.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (lease.path / ".leftovers-strict-vm-lease.json").stat().st_mode & 0o777, 0o400
        )
        self.assertEqual(
            (lease.path / ".leftovers-strict-vm-state.jsonl").stat().st_mode & 0o777, 0o600
        )

        receipt = lease.cleanup()

        self.assertTrue(receipt.run_directory_removed)
        self.assertTrue(receipt.path_absence_proven)
        self.assertEqual(receipt.artifacts_removed, ())
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())
        self.assertTrue(self.tombstone_path().exists())

    def test_registered_artifacts_are_hashed_and_removed_by_exact_name(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "round-000-request.raw"
        request.write_bytes(b"sealed-request")
        os.chmod(request, 0o400)
        digest = hashlib.sha256(request.read_bytes()).hexdigest()

        identity = lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            maximum_bytes=1024,
            sha256=digest,
        )
        self.assertEqual(identity.sha256, digest)

        receipt = lease.cleanup()
        self.assertEqual(receipt.artifacts_removed, (request.name,))
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_mutable_scratch_may_change_content_but_not_identity_or_size(self) -> None:
        lease = self.lease().acquire()
        scratch = lease.path / "round-000-scratch.raw"
        scratch.write_bytes(b"\0" * 4096)
        os.chmod(scratch, 0o600)
        original = lease.register_artifact(
            scratch,
            role="scratch",
            mode=0o600,
            maximum_bytes=4096,
        )
        descriptor = os.open(scratch, os.O_WRONLY)
        try:
            os.pwrite(descriptor, b"guest", 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        refreshed = lease.refresh_mutable_artifact(scratch.name)

        self.assertEqual(
            (refreshed.device, refreshed.inode, refreshed.size),
            (original.device, original.inode, original.size),
        )
        lease.cleanup()

    def test_unknown_file_blocks_cleanup_without_broad_deletion(self) -> None:
        lease = self.lease().acquire()
        unknown = lease.path / "guest-chosen-name"
        unknown.write_bytes(b"sentinel")

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence") as raised:
            lease.cleanup()

        self.assertIn(unknown.name, raised.exception.retained)
        self.assertEqual(unknown.read_bytes(), b"sentinel")
        self.assertTrue(lease.path.exists())

    def test_missing_registered_artifact_blocks_first_pass_cleanup(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            sha256=hashlib.sha256(b"request").hexdigest(),
        )
        request.unlink()

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"):
            lease.cleanup()

        self.assertTrue(lease.path.exists())

    def test_hardlink_and_identity_replacement_are_rejected(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        linked = lease.path / "linked.raw"
        os.link(request, linked)
        with self.assertRaisesRegex(VMLeaseError, "links"):
            lease.register_artifact(
                request,
                role="request",
                mode=0o400,
                sha256=hashlib.sha256(request.read_bytes()).hexdigest(),
            )
        linked.unlink()
        lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            sha256=hashlib.sha256(request.read_bytes()).hexdigest(),
        )
        request.unlink()
        request.write_bytes(b"replace")
        os.chmod(request, 0o400)

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"):
            lease.cleanup()

        self.assertTrue(request.exists())

    def test_control_file_replacement_blocks_cleanup(self) -> None:
        lease = self.lease().acquire()
        journal = lease.path / ".leftovers-strict-vm-state.jsonl"
        os.chmod(journal, 0o644)

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"):
            lease.cleanup()

        self.assertTrue(journal.exists())

    def test_journal_overwrite_poison_fails_closed(self) -> None:
        lease = self.lease().acquire()
        journal = lease.path / ".leftovers-strict-vm-state.jsonl"
        journal.write_bytes(b'{"forged":true}\n')
        os.chmod(journal, 0o600)

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"):
            lease.cleanup()

        self.assertTrue(lease.path.exists())
        self.assertTrue(journal.exists())

    def test_same_inode_same_size_sealed_mutation_blocks_cleanup(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"original")
        os.chmod(request, 0o400)
        lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            sha256=hashlib.sha256(b"original").hexdigest(),
        )
        os.chmod(request, 0o600)
        descriptor = os.open(request, os.O_WRONLY)
        try:
            os.pwrite(descriptor, b"forged!!", 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(request, 0o400)

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"):
            lease.cleanup()

        self.assertEqual(request.read_bytes(), b"forged!!")

    def test_unlink_failure_becomes_cleanup_pending_and_closes_descriptors(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            sha256=hashlib.sha256(request.read_bytes()).hexdigest(),
        )
        real_unlink = os.unlink

        def fail_artifact(path: object, *args: object, **kwargs: object) -> None:
            if path == request.name:
                raise OSError("injected unlink failure")
            real_unlink(path, *args, **kwargs)

        with (
            patch("leftovers.strict_vm_lease.os.unlink", side_effect=fail_artifact),
            self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"),
        ):
            lease.cleanup()

        self.assertIsNone(lease._run_descriptor)
        self.assertIsNone(lease._root_descriptor)
        self.assertTrue(request.exists())

    def test_partial_artifact_deletion_is_restart_recoverable(self) -> None:
        lease = self.lease().acquire()
        scratch = lease.path / "scratch.raw"
        scratch.write_bytes(b"x" * 64)
        os.chmod(scratch, 0o600)
        lease.register_artifact(scratch, role="scratch", mode=0o600, maximum_bytes=64)
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            sha256=hashlib.sha256(b"request").hexdigest(),
        )
        real_unlink = os.unlink

        def fail_request(path: object, *args: object, **kwargs: object) -> None:
            if path == request.name:
                raise OSError("injected request unlink failure")
            real_unlink(path, *args, **kwargs)

        with (
            patch("leftovers.strict_vm_lease.os.unlink", side_effect=fail_request),
            self.assertRaises(VMCleanupPendingError),
        ):
            lease.cleanup()

        self.assertFalse(scratch.exists())
        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertTrue(receipt.path_absence_proven)
        self.assertEqual(set(receipt.artifacts_removed), {scratch.name, request.name})
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_post_marker_removal_rmdir_failure_is_restart_recoverable(self) -> None:
        lease = self.lease().acquire()
        real_rmdir = os.rmdir

        def fail_run_rmdir(path: object, *args: object, **kwargs: object) -> None:
            if path == lease.name:
                raise OSError("injected rmdir failure")
            real_rmdir(path, *args, **kwargs)

        with (
            patch("leftovers.strict_vm_lease.os.rmdir", side_effect=fail_run_rmdir),
            self.assertRaises(VMCleanupPendingError),
        ):
            lease.cleanup()

        self.assertFalse((lease.path / ".leftovers-strict-vm-lease.json").exists())
        self.assertFalse((lease.path / ".leftovers-strict-vm-state.jsonl").exists())
        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertTrue(receipt.path_absence_proven)
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_rmdir_completed_before_ledger_retirement_is_recoverable(self) -> None:
        lease = self.lease().acquire()
        real_unlink = os.unlink

        def fail_ledger_unlink(path: object, *args: object, **kwargs: object) -> None:
            if path == self.recovery_path().name:
                raise OSError("injected ledger unlink failure")
            real_unlink(path, *args, **kwargs)

        with (
            patch("leftovers.strict_vm_lease.os.unlink", side_effect=fail_ledger_unlink),
            self.assertRaises(VMCleanupPendingError),
        ):
            lease.cleanup()

        self.assertFalse(lease.path.exists())
        self.assertTrue(self.recovery_path().exists())
        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertTrue(receipt.path_absence_proven)
        self.assertFalse(self.recovery_path().exists())

    def test_repeated_resume_uses_tombstone_until_explicit_retirement(self) -> None:
        lease = self.lease().acquire()
        lease.close()
        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertTrue(receipt.path_absence_proven)
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())
        self.assertTrue(self.tombstone_path().exists())

        repeated = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertEqual(repeated, receipt)
        self.assertTrue(self.tombstone_path().exists())

        retired = StrictVMRunLease.retire_cleanup_receipt(self.root, self.run_id)
        self.assertEqual(retired, receipt)
        self.assertFalse(self.tombstone_path().exists())

        with self.assertRaisesRegex(VMLeaseError, "cannot be opened safely"):
            StrictVMRunLease.resume_cleanup(self.root, self.run_id)

        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_tampered_cleanup_tombstone_blocks_resume_and_retirement(self) -> None:
        lease = self.lease().acquire()
        lease.cleanup()
        tombstone = self.tombstone_path()
        os.chmod(tombstone, 0o600)
        tombstone.write_bytes(b'{"forged":true}\n')
        os.chmod(tombstone, 0o400)

        with self.assertRaisesRegex(VMLeaseError, "tombstone"):
            StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        with self.assertRaisesRegex(VMLeaseError, "tombstone"):
            StrictVMRunLease.retire_cleanup_receipt(self.root, self.run_id)

        self.assertTrue(tombstone.exists())

    def test_journal_prefix_rejects_conflicting_immutable_and_future_mutable_identity(self) -> None:
        immutable = ArtifactIdentity(
            "request.raw", "request", 1, 2, os.getuid(), 0o400, 1, 7, 10, 10, "a" * 64
        )
        with self.assertRaisesRegex(VMLeaseError, "immutable"):
            StrictVMRunLease._cross_check_journal_prefix(
                {immutable.name: replace(immutable, inode=3)}, {immutable.name: immutable}
            )
        mutable = ArtifactIdentity(
            "scratch.raw", "scratch", 1, 4, os.getuid(), 0o600, 1, 7, 10, 10, None
        )
        with self.assertRaisesRegex(VMLeaseError, "mutable"):
            StrictVMRunLease._cross_check_journal_prefix(
                {mutable.name: replace(mutable, mtime_ns=11)}, {mutable.name: mutable}
            )

    def test_hash_valid_same_name_immutable_journal_conflict_blocks_cleanup(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        lease.register_artifact(
            request,
            role="request",
            mode=0o400,
            sha256=hashlib.sha256(b"request").hexdigest(),
        )
        journal = lease.path / ".leftovers-strict-vm-state.jsonl"
        records = [json.loads(line) for line in journal.read_text().splitlines()]
        previous = "0" * 64
        for record in records:
            if record["event"] == "artifact_registered":
                record["fields"]["artifact"]["inode"] += 1
            record["previous_hash"] = previous
            unsigned = {key: value for key, value in record.items() if key != "record_hash"}
            record["record_hash"] = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            previous = record["record_hash"]
        os.chmod(journal, 0o600)
        journal.write_text(
            "".join(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
                for record in records
            )
        )
        os.chmod(journal, 0o600)

        with self.assertRaisesRegex(VMCleanupPendingError, "exact resource absence"):
            lease.cleanup()

        self.assertTrue(request.exists())

    def test_active_cleanup_reconciles_root_ledger_ahead_of_journal(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        real_record = lease.record

        def fail_registration(event: str, **fields: object) -> str:
            if event == "artifact_registered":
                raise VMLeaseError("injected journal append failure")
            return real_record(event, **fields)

        with (
            patch.object(lease, "record", side_effect=fail_registration),
            self.assertRaisesRegex(VMLeaseError, "injected journal"),
        ):
            lease.register_artifact(
                request,
                role="request",
                mode=0o400,
                sha256=hashlib.sha256(b"request").hexdigest(),
            )

        receipt = lease.cleanup()
        self.assertEqual(receipt.artifacts_removed, (request.name,))
        self.assertTrue(self.tombstone_path().exists())

    def test_run_directory_swap_is_rejected_on_recovery(self) -> None:
        lease = self.lease().acquire()
        lease.close()
        moved = self.root / "moved-run"
        os.rename(lease.path, moved)
        lease.path.mkdir(mode=0o700)

        with self.assertRaisesRegex(VMLeaseError, "bind"):
            StrictVMRunLease.resume_cleanup(self.root, self.run_id)

        self.assertTrue(moved.exists())
        self.assertTrue(lease.path.exists())

    def test_setup_journal_failure_retains_recoverable_marker_bound_directory(self) -> None:
        lease = self.lease()
        with (
            patch.object(StrictVMRunLease, "record", side_effect=VMLeaseError("injected")),
            self.assertRaisesRegex(VMCleanupPendingError, "could not prove"),
        ):
            lease.acquire()
        self.assertTrue(lease.path.exists())
        self.assertTrue((lease.path / ".leftovers-strict-vm-lease.json").exists())
        self.assertIsNone(lease._run_descriptor)
        self.assertIsNone(lease._root_descriptor)

        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertTrue(receipt.path_absence_proven)
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_early_setup_missing_journal_is_reconciled_only_when_empty(self) -> None:
        lease = self.lease().acquire()
        journal = lease.path / ".leftovers-strict-vm-state.jsonl"
        journal.unlink()
        lease.close()

        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertTrue(receipt.path_absence_proven)
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_root_ledger_ahead_of_journal_is_resumable(self) -> None:
        lease = self.lease().acquire()
        request = lease.path / "request.raw"
        request.write_bytes(b"request")
        os.chmod(request, 0o400)
        real_record = lease.record

        def fail_only_registration(event: str, **fields: object) -> str:
            if event == "artifact_registered":
                raise VMLeaseError("injected journal append failure")
            return real_record(event, **fields)

        with (
            patch.object(lease, "record", side_effect=fail_only_registration),
            self.assertRaisesRegex(VMLeaseError, "injected journal"),
        ):
            lease.register_artifact(
                request,
                role="request",
                mode=0o400,
                sha256=hashlib.sha256(b"request").hexdigest(),
            )
        lease.close()

        receipt = StrictVMRunLease.resume_cleanup(self.root, self.run_id)
        self.assertEqual(receipt.artifacts_removed, (request.name,))
        self.assertFalse(lease.path.exists())
        self.assertFalse(self.recovery_path().exists())

    def test_exceptional_context_retains_directory_but_closes_descriptors(self) -> None:
        lease = self.lease()
        with self.assertRaisesRegex(RuntimeError, "fixture"), lease:
            raise RuntimeError("fixture")
        self.assertTrue(lease.path.exists())
        self.assertIsNone(lease._run_descriptor)
        self.assertIsNone(lease._root_descriptor)

    def test_root_and_run_identifiers_are_strict(self) -> None:
        os.chmod(self.root, 0o755)
        with self.assertRaisesRegex(VMLeaseError, "0700"):
            self.lease()
        os.chmod(self.root, 0o700)
        with self.assertRaisesRegex(VMLeaseError, "32 lowercase"):
            StrictVMRunLease(self.root, "not-a-run-id")


if __name__ == "__main__":
    unittest.main()
