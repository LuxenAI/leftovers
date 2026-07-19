import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from leftovers.budget import BudgetError, BudgetGate, BudgetLedger, budget_window_key
from leftovers.config import BudgetConfig
from leftovers.models import BudgetSnapshot


class BudgetGateTests(unittest.TestCase):
    def test_unknown_environment_budget_fails_closed(self) -> None:
        config = BudgetConfig(source="environment", remaining_tokens_env="MISSING_LEFTOVERS_TEST")
        with patch.dict(os.environ, {}, clear=True):
            snapshot = BudgetGate(config).snapshot()
        allowed, reason = BudgetGate(config).can_start(snapshot, 10_000)
        self.assertFalse(allowed)
        self.assertIn("unknown", reason)

    def test_reserve_and_safety_multiplier_are_both_enforced(self) -> None:
        config = BudgetConfig(
            source="fixed",
            fixed_remaining_tokens=150_000,
            reserve_tokens=20_000,
            minimum_spendable_tokens=30_000,
            safety_multiplier=1.25,
        )
        with patch(
            "leftovers.budget.utc_now",
            return_value=datetime(2026, 7, 17, 12, tzinfo=UTC),
        ):
            snapshot = BudgetGate(config).snapshot()
        self.assertEqual(snapshot.spendable_tokens, 130_000)
        self.assertTrue(BudgetGate(config).can_start(snapshot, 80_000)[0])
        self.assertFalse(BudgetGate(config).can_start(snapshot, 120_000)[0])

    def test_negative_manual_budget_is_rejected(self) -> None:
        with self.assertRaises(BudgetError):
            BudgetGate(BudgetConfig()).snapshot(-1)

    def test_start_is_rejected_too_close_to_reset(self) -> None:
        config = BudgetConfig(
            source="fixed",
            fixed_remaining_tokens=150_000,
            reserve_tokens=20_000,
            minimum_spendable_tokens=30_000,
            safety_multiplier=1.0,
            max_run_seconds=3_600,
            reset_safety_seconds=300,
        )
        now = datetime(2026, 7, 17, 12, tzinfo=UTC)
        snapshot = BudgetSnapshot(
            source="test",
            remaining_tokens=150_000,
            reserve_tokens=20_000,
            spendable_tokens=130_000,
            confidence="test",
            observed_at=now,
            resets_at=now + timedelta(seconds=3_899),
        )
        allowed, reason = BudgetGate(config).can_start(snapshot, 80_000)
        self.assertFalse(allowed)
        self.assertIn("before reset", reason)

    def test_fractional_safety_reservation_rounds_up(self) -> None:
        config = BudgetConfig(
            source="fixed",
            fixed_remaining_tokens=1,
            reserve_tokens=0,
            minimum_spendable_tokens=1,
            safety_multiplier=1.1,
        )
        snapshot = BudgetGate(config).snapshot()
        allowed, reason = BudgetGate(config).can_start(snapshot, 1)
        self.assertFalse(allowed)
        self.assertIn("required 2", reason)


class BudgetLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root))
        self.config = BudgetConfig(
            source="fixed",
            fixed_remaining_tokens=120_000,
            reserve_tokens=20_000,
            minimum_spendable_tokens=30_000,
            safety_multiplier=1.0,
            window="daily",
            timezone="UTC",
        )

    @staticmethod
    def snapshot(observed_at: datetime) -> BudgetSnapshot:
        return BudgetSnapshot(
            source="test",
            remaining_tokens=120_000,
            reserve_tokens=20_000,
            spendable_tokens=100_000,
            confidence="test",
            observed_at=observed_at,
            resets_at=observed_at + timedelta(hours=12),
        )

    def test_reservation_is_idempotent_and_prevents_envelope_reuse(self) -> None:
        ledger = BudgetLedger(self.root, self.config)
        snapshot = self.snapshot(datetime(2026, 7, 17, 12, tzinfo=UTC))
        first = ledger.reserve("run-1", snapshot, 60_000, now=snapshot.observed_at)
        repeated = ledger.reserve("run-1", snapshot, 60_000, now=snapshot.observed_at)
        self.assertEqual(first, repeated)
        self.assertEqual(
            ledger.active_run_ids(now=snapshot.observed_at),
            {"run-1"},
        )
        self.assertEqual(ledger.reserved_tokens(first.window_key), 60_000)
        self.assertEqual(budget_window_key(self.config, snapshot.observed_at), first.window_key)
        with self.assertRaisesRegex(BudgetError, "unreserved tokens"):
            ledger.reserve("run-2", snapshot, 60_000, now=snapshot.observed_at)
        ledger.finish("run-1", "complete")
        self.assertEqual(ledger.active_run_ids(now=snapshot.observed_at), set())

    def test_crashed_reservation_expires_as_workspace_protection_only(self) -> None:
        ledger = BudgetLedger(self.root, self.config)
        snapshot = self.snapshot(datetime(2026, 7, 17, 12, tzinfo=UTC))
        reservation = ledger.reserve(
            "crashed-run",
            snapshot,
            60_000,
            now=snapshot.observed_at,
        )
        horizon = timedelta(
            seconds=(self.config.max_run_seconds + self.config.reset_safety_seconds + 7_200)
        )

        self.assertEqual(
            ledger.active_run_ids(now=snapshot.observed_at + horizon - timedelta(seconds=1)),
            {"crashed-run"},
        )
        self.assertEqual(
            ledger.active_run_ids(now=snapshot.observed_at + horizon + timedelta(seconds=1)),
            set(),
        )
        self.assertEqual(ledger.reserved_tokens(reservation.window_key), 60_000)

    def test_new_daily_window_gets_a_separate_envelope(self) -> None:
        ledger = BudgetLedger(self.root, self.config)
        first = self.snapshot(datetime(2026, 7, 17, 12, tzinfo=UTC))
        next_day = self.snapshot(datetime(2026, 7, 18, 12, tzinfo=UTC))
        self.assertNotEqual(
            ledger.window_key(first.observed_at),
            ledger.window_key(next_day.observed_at),
        )
        ledger.reserve("run-1", first, 60_000, now=first.observed_at)
        reservation = ledger.reserve("run-2", next_day, 60_000, now=next_day.observed_at)
        self.assertEqual(reservation.window_key, "daily:2026-07-18")

    def test_stale_or_cross_window_snapshot_is_rejected(self) -> None:
        ledger = BudgetLedger(self.root, self.config)
        snapshot = self.snapshot(datetime(2026, 7, 17, 23, 59, tzinfo=UTC))
        with self.assertRaisesRegex(BudgetError, "window changed"):
            ledger.reserve(
                "run-cross-reset",
                snapshot,
                1_000,
                now=datetime(2026, 7, 18, 0, 0, tzinfo=UTC),
            )
        with self.assertRaisesRegex(BudgetError, "stale"):
            ledger.reserve(
                "run-stale",
                snapshot,
                1_000,
                now=datetime(2026, 7, 17, 23, 50, tzinfo=UTC),
            )


if __name__ == "__main__":
    unittest.main()
