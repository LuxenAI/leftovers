import json
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from leftovers.audit import AuditJournal
from leftovers.statefs import PrivateStateError, private_file
from leftovers.workspace import WorkspaceError, WorkspaceLease, reap_expired


class AuditWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root, ignore_errors=True))

    def test_audit_redacts_and_hash_chains(self) -> None:
        journal = AuditJournal(self.root / "state", "run")
        journal.append("one", token="ghp_abcdefghijklmnopqrstuvwxyz")
        journal.append("two", value="ok")
        records = [json.loads(line) for line in journal.path.read_text().splitlines()]
        self.assertNotIn("ghp_", journal.path.read_text())
        self.assertIn("[REDACTED]", journal.path.read_text())
        self.assertEqual(records[1]["previous_hash"], records[0]["record_hash"])
        self.assertEqual(stat.S_IMODE((self.root / "state").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(journal.path.stat().st_mode), 0o600)

    def test_private_state_file_refuses_a_symlink(self) -> None:
        target = self.root / "outside"
        target.write_text("do not touch")
        state = self.root / "state"
        state.mkdir()
        candidate = state / "audit.jsonl"
        candidate.symlink_to(target)
        with self.assertRaises(PrivateStateError):
            private_file(candidate)
        self.assertEqual(target.read_text(), "do not touch")

    def test_reaper_only_removes_expired_marked_directories(self) -> None:
        lease = WorkspaceLease(self.root, "old")
        lease.__enter__()
        assert lease.path is not None
        old_path = lease.path
        marker = old_path / ".leftovers-lease.json"
        data = json.loads(marker.read_text())
        data["created_at"] = (datetime.now(UTC) - timedelta(hours=5)).isoformat()
        marker.write_text(json.dumps(data))
        unmarked = self.root / "leftovers-keep"
        unmarked.mkdir()
        removed = reap_expired(self.root, 1)
        self.assertEqual(removed, [old_path])
        self.assertFalse(old_path.exists())
        self.assertTrue(unmarked.exists())

    def test_reaper_preserves_workspace_with_active_container_job(self) -> None:
        lease = WorkspaceLease(self.root, "active-run")
        lease.__enter__()
        assert lease.path is not None
        marker = lease.path / ".leftovers-lease.json"
        data = json.loads(marker.read_text())
        data["created_at"] = (datetime.now(UTC) - timedelta(hours=5)).isoformat()
        marker.write_text(json.dumps(data))
        self.assertEqual(
            reap_expired(self.root, 1, protected_run_ids={"active-run"}),
            [],
        )
        self.assertTrue(lease.path.exists())

    def test_lease_entry_removes_unmarked_directory_when_marker_write_fails(self) -> None:
        lease = WorkspaceLease(self.root, "marker-failure")
        with (
            mock.patch.object(Path, "write_text", side_effect=OSError("disk full")),
            self.assertRaisesRegex(OSError, "disk full"),
        ):
            lease.__enter__()

        self.assertIsNone(lease.path)
        self.assertIsNone(lease.repo_path)
        self.assertEqual(list(self.root.glob("leftovers-*")), [])

    def test_lease_entry_reports_unmarked_directory_when_cleanup_fails(self) -> None:
        lease = WorkspaceLease(self.root, "cleanup-failure")
        with (
            mock.patch.object(Path, "write_text", side_effect=OSError("disk full")),
            mock.patch("leftovers.workspace.shutil.rmtree", side_effect=OSError("busy")),
            self.assertRaisesRegex(WorkspaceError, "cleanup could not be proven"),
        ):
            lease.__enter__()

        self.assertIsNotNone(lease.path)
        assert lease.path is not None
        self.assertTrue(lease.path.exists())
        self.assertIsNone(lease.repo_path)


if __name__ == "__main__":
    unittest.main()
