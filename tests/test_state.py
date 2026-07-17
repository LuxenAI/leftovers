import tempfile
import unittest
from pathlib import Path

from leftovers.config import PublicationConfig
from leftovers.state import PublicationLedger, StatePolicyError


class PublicationLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root))

    def test_window_cap_is_atomic_and_run_reservation_is_idempotent(self) -> None:
        ledger = PublicationLedger(self.root)
        config = PublicationConfig(max_prs_per_window=1, repository_cooldown_days=0)
        ledger.reserve(
            run_id="run-1",
            window_key="daily:2026-07-17",
            repository="owner/one",
            issue_number=1,
            config=config,
        )
        ledger.reserve(
            run_id="run-1",
            window_key="daily:2026-07-17",
            repository="owner/one",
            issue_number=1,
            config=config,
        )
        with self.assertRaisesRegex(StatePolicyError, "cap"):
            ledger.reserve(
                run_id="run-2",
                window_key="daily:2026-07-17",
                repository="owner/two",
                issue_number=2,
                config=config,
            )

    def test_repository_cooldown_applies_across_budget_windows(self) -> None:
        ledger = PublicationLedger(self.root)
        config = PublicationConfig(max_prs_per_window=2, repository_cooldown_days=7)
        ledger.reserve(
            run_id="run-1",
            window_key="daily:2026-07-17",
            repository="owner/repo",
            issue_number=1,
            config=config,
        )
        with self.assertRaisesRegex(StatePolicyError, "cooldown"):
            ledger.reserve(
                run_id="run-2",
                window_key="daily:2026-07-18",
                repository="owner/repo",
                issue_number=2,
                config=config,
            )

    def test_read_only_preflight_reports_cap_and_repository_cooldown(self) -> None:
        ledger = PublicationLedger(self.root)
        config = PublicationConfig(max_prs_per_window=2, repository_cooldown_days=7)
        ledger.reserve(
            run_id="run-1",
            window_key="daily:2026-07-17",
            repository="owner/one",
            issue_number=1,
            config=config,
        )
        with self.assertRaisesRegex(StatePolicyError, "cooldown"):
            ledger.check_available(
                window_key="daily:2026-07-18",
                repository="owner/one",
                config=config,
            )
        ledger.check_available(
            window_key="daily:2026-07-18",
            repository="owner/two",
            config=config,
        )
        capped = PublicationConfig(max_prs_per_window=1, repository_cooldown_days=0)
        with self.assertRaisesRegex(StatePolicyError, "cap"):
            ledger.check_available(
                window_key="daily:2026-07-17",
                repository="owner/two",
                config=capped,
            )


if __name__ == "__main__":
    unittest.main()
