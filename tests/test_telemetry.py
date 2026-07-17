from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import tempfile
import threading
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from leftovers.telemetry import (
    DATABASE_NAME,
    SCHEMA_VERSION,
    TelemetryConflictError,
    TelemetryNotFoundError,
    TelemetryReader,
    TelemetryUnavailableError,
    TelemetryValidationError,
    TelemetryWriter,
)


@dataclass(frozen=True)
class ExampleUsage:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    reasoning_tokens: int
    total_tokens: int
    source: str
    exact: bool
    reported_at: datetime


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.state = self.root / "state"
        self.writer = TelemetryWriter(self.state)
        self.t0 = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)

    def start_run(
        self,
        run_id: str = "a" * 32,
        *,
        run_kind: str = "production",
    ) -> str:
        self.writer.start_run(run_id, run_kind=run_kind, started_at=self.t0)
        return run_id

    def start_model(
        self,
        run_id: str,
        *,
        invocation_id: str = "b" * 32,
        stage: str = "planning",
        attempt: int = 0,
        backend: str = "container",
        provider: str = "openai",
        model: str = "gpt-5",
        cap: int | None = 10_000,
    ) -> str:
        return self.writer.start_model_invocation(
            run_id,
            invocation_id=invocation_id,
            stage=stage,
            attempt=attempt,
            backend=backend,
            expected_provider=provider,
            expected_model=model,
            run_token_cap=cap,
            started_at=self.t0,
        )

    def exact_usage(self, total: int = 130) -> ExampleUsage:
        return ExampleUsage(
            input_tokens=total - 30,
            output_tokens=30,
            cached_input_tokens=20,
            reasoning_tokens=10,
            total_tokens=total,
            source="provider_response",
            exact=True,
            reported_at=self.t0 + timedelta(seconds=5),
        )

    def test_schema_permissions_and_read_only_reader(self) -> None:
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        database = self.state / DATABASE_NAME
        self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)
        entries_before = {path.name for path in self.state.iterdir()}
        bytes_before = database.read_bytes()
        modified_before = database.stat().st_mtime_ns
        reader = TelemetryReader(self.state)
        health = reader.health()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["database"]["schema_version"], SCHEMA_VERSION)
        self.assertTrue(health["database"]["query_only"])
        self.assertEqual({path.name for path in self.state.iterdir()}, entries_before)
        self.assertEqual(database.read_bytes(), bytes_before)
        self.assertEqual(database.stat().st_mtime_ns, modified_before)
        with reader._connect() as connection, self.assertRaises(sqlite3.OperationalError):
            connection.execute(
                "INSERT INTO runs (run_id, run_kind, started_at, updated_at, stage) "
                "VALUES ('forbidden', 'production', 'x', 'x', 'scheduled')"
            )

    def test_reader_does_not_create_a_missing_database(self) -> None:
        missing = self.root / "missing"
        missing.mkdir(mode=0o700)
        with self.assertRaisesRegex(TelemetryUnavailableError, "does not exist"):
            TelemetryReader(missing)
        self.assertEqual(list(missing.iterdir()), [])

    def test_reader_refuses_group_readable_database_and_symlink(self) -> None:
        path = self.state / DATABASE_NAME
        os.chmod(path, 0o640)
        with self.assertRaisesRegex(TelemetryUnavailableError, "owner-only"):
            TelemetryReader(self.state)
        os.chmod(path, 0o600)
        other = self.root / "other-state"
        other.mkdir(mode=0o700)
        (other / DATABASE_NAME).symlink_to(path)
        with self.assertRaisesRegex(TelemetryUnavailableError, "owner-only"):
            TelemetryReader(other)

    def test_run_lifecycle_is_safe_ordered_and_idempotent(self) -> None:
        run_id = self.start_run()
        self.assertEqual(
            self.writer.start_run(run_id, run_kind="production"),
            1,
        )
        with self.assertRaises(TelemetryConflictError):
            self.writer.start_run(run_id, run_kind="training")
        self.writer.transition_run(run_id, "discovering", occurred_at=self.t0)
        self.writer.set_run_target(
            run_id,
            repository="owner/repo",
            issue_number=17,
            score=88,
            occurred_at=self.t0,
        )
        self.writer.set_cleanup_status(
            run_id,
            "proven",
            containers_removed=True,
            workspace_removed=True,
            occurred_at=self.t0,
        )
        terminal_sequence = self.writer.finish_run(
            run_id,
            "complete",
            safe_status_code="dry_run_complete",
            cleanup_status="proven",
            finished_at=self.t0,
        )
        self.assertEqual(
            self.writer.finish_run(
                run_id,
                "complete",
                safe_status_code="dry_run_complete",
                cleanup_status="proven",
            ),
            terminal_sequence,
        )
        with self.assertRaises(TelemetryConflictError):
            self.writer.record_event(run_id, "verification")
        detail = TelemetryReader(self.state).get_run(run_id)
        self.assertEqual(
            [event["sequence"] for event in detail["events"]],
            list(range(1, terminal_sequence + 1)),
        )
        self.assertEqual(detail["run"]["repository"], "owner/repo")
        self.assertNotIn("message", detail["run"])

    def test_run_validation_rejects_unbounded_or_untrusted_fields(self) -> None:
        run_id = self.start_run()
        with self.assertRaises(TelemetryValidationError):
            self.writer.start_run("../escape")
        with self.assertRaises(TelemetryValidationError):
            self.writer.record_event(run_id, "arbitrary_model_event")
        with self.assertRaisesRegex(TelemetryValidationError, "non-allowlisted"):
            self.writer.record_event(run_id, "verification", detail={"prompt": "secret"})
        with self.assertRaisesRegex(TelemetryValidationError, "bounded printable"):
            self.writer.record_event(
                run_id,
                "verification",
                detail={"reason_code": "x" * 257},
            )
        with self.assertRaisesRegex(TelemetryValidationError, "canonical"):
            self.writer.finish_run(run_id, "complete", pr_url="https://attacker.test/pr/1")

    def test_model_checkin_heartbeat_exact_usage_and_summary(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        self.assertTrue(
            self.writer.heartbeat_model(
                invocation_id,
                source="controller",
                observed_at=self.t0 + timedelta(seconds=1),
            )
        )
        self.assertFalse(
            self.writer.heartbeat_model(
                invocation_id,
                source="controller",
                observed_at=self.t0 + timedelta(seconds=2),
            )
        )
        self.assertEqual(
            self.writer.record_model_checkin(
                invocation_id,
                observed_provider="openai",
                observed_model="gpt-5",
                source="broker_attested",
                checked_in_at=self.t0 + timedelta(seconds=3),
            ),
            "matched",
        )
        usage = self.exact_usage()
        self.assertEqual(
            self.writer.record_model_usage(invocation_id, "request-1", usage),
            "exact",
        )
        self.assertEqual(
            self.writer.record_model_usage(invocation_id, "request-1", usage),
            "exact",
        )
        self.assertEqual(
            self.writer.finish_model_invocation(
                invocation_id,
                "succeeded",
                exit_code=0,
                finished_at=self.t0 + timedelta(seconds=10),
            ),
            "exact",
        )
        self.writer.finish_run(run_id, "complete", finished_at=self.t0 + timedelta(seconds=11))
        reader = TelemetryReader(self.state)
        summary = reader.summary(now=self.t0 + timedelta(seconds=12))
        self.assertEqual(summary["tokens"]["known_used_tokens"], 130)
        self.assertIsNone(summary["tokens"]["estimated_reported_tokens"])
        self.assertEqual(summary["tokens"]["run_cap_tokens"], 10_000)
        self.assertEqual(summary["tokens"]["usage_coverage"], 1.0)
        model = reader.list_models(now=self.t0 + timedelta(seconds=12))["models"][0]
        self.assertEqual(model["identity_status"], "matched")
        self.assertEqual(model["heartbeat_status"], "not_applicable")
        self.assertEqual(model["known_used_tokens"], 130)

    def test_heartbeat_freshness_and_backward_time(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        reader = TelemetryReader(self.state)
        initial = reader.list_models(now=self.t0)["models"][0]
        self.assertEqual(initial["heartbeat_status"], "unknown")
        heartbeat = self.t0 + timedelta(seconds=10)
        self.writer.heartbeat_model(invocation_id, source="controller", observed_at=heartbeat)
        self.assertEqual(
            reader.list_models(now=heartbeat + timedelta(seconds=29))["models"][0][
                "heartbeat_status"
            ],
            "current",
        )
        self.assertEqual(
            reader.list_models(now=heartbeat + timedelta(seconds=31))["models"][0][
                "heartbeat_status"
            ],
            "stale",
        )
        with self.assertRaisesRegex(TelemetryConflictError, "backwards"):
            self.writer.heartbeat_model(
                invocation_id,
                source="controller",
                observed_at=heartbeat - timedelta(seconds=1),
            )

    def test_identity_mismatch_cannot_be_marked_successful(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        self.assertEqual(
            self.writer.record_model_checkin(
                invocation_id,
                observed_provider="openai",
                observed_model="gpt-4",
                source="adapter_reported",
            ),
            "mismatch",
        )
        with self.assertRaisesRegex(TelemetryConflictError, "cannot succeed"):
            self.writer.finish_model_invocation(invocation_id, "succeeded", exit_code=0)
        self.writer.finish_model_invocation(
            invocation_id,
            "failed",
            exit_code=3,
            failure_code="model_mismatch",
        )
        summary = TelemetryReader(self.state).summary()
        self.assertEqual(summary["models"]["identity_mismatches"], 1)
        self.assertEqual(summary["tokens"]["unknown_invocations"], 1)

    def test_usage_idempotency_rejects_conflicting_request(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        self.writer.record_model_usage(invocation_id, "request-1", self.exact_usage())
        with self.assertRaisesRegex(TelemetryConflictError, "different usage"):
            self.writer.record_model_usage(
                invocation_id,
                "request-1",
                self.exact_usage(total=999),
            )

    def test_usage_mapping_is_strict_and_bool_is_not_an_integer(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        base = {
            "input_tokens": 1,
            "output_tokens": 2,
            "cached_input_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 3,
            "source": "provider_response",
            "exact": True,
            "reported_at": self.t0,
        }
        with self.assertRaisesRegex(TelemetryValidationError, "non-allowlisted"):
            self.writer.record_model_usage(
                invocation_id,
                "unknown-field",
                {**base, "raw_response": "must not persist"},
            )
        with self.assertRaises(TelemetryValidationError):
            self.writer.record_model_usage(
                invocation_id,
                "bool-token",
                {**base, "total_tokens": True},
            )
        with self.assertRaisesRegex(TelemetryValidationError, "belongs in invocation"):
            self.writer.record_model_usage(
                invocation_id,
                "unavailable",
                {**base, "source": "unavailable"},
            )
        with self.assertRaisesRegex(TelemetryValidationError, "must equal"):
            self.writer.record_model_usage(
                invocation_id,
                "bad-total",
                {**base, "total_tokens": 4},
            )
        with self.assertRaisesRegex(TelemetryValidationError, "cached_input_tokens"):
            self.writer.record_model_usage(
                invocation_id,
                "bad-cache",
                {**base, "cached_input_tokens": 2},
            )
        with self.assertRaisesRegex(TelemetryValidationError, "marked exact"):
            self.writer.record_model_usage(
                invocation_id,
                "bad-estimate",
                {**base, "source": "estimated", "exact": True},
            )
        with self.assertRaisesRegex(TelemetryValidationError, "must be marked exact"):
            self.writer.record_model_usage(
                invocation_id,
                "bad-provider",
                {**base, "exact": False},
            )

    def test_exact_estimated_partial_and_unavailable_are_distinct(self) -> None:
        run_id = self.start_run()
        first = self.start_model(run_id, invocation_id="1" * 32)
        estimated = {
            "input_tokens": 10,
            "output_tokens": 5,
            "cached_input_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 15,
            "source": "estimated",
            "exact": False,
            "reported_at": self.t0,
        }
        self.assertEqual(
            self.writer.record_model_usage(first, "estimate", estimated),
            "estimated",
        )
        self.writer.finish_model_invocation(first, "succeeded", exit_code=0)
        second = self.start_model(
            run_id,
            invocation_id="2" * 32,
            stage="implementation",
        )
        self.assertEqual(
            self.writer.finish_model_invocation(second, "failed", exit_code=2),
            "unavailable",
        )
        third = self.start_model(
            run_id,
            invocation_id="3" * 32,
            stage="review",
        )
        self.writer.record_model_usage(third, "exact", self.exact_usage())
        self.assertEqual(
            self.writer.record_model_usage(third, "estimate", estimated),
            "partial",
        )
        self.writer.finish_model_invocation(third, "succeeded", exit_code=0)
        summary = TelemetryReader(self.state).summary()
        self.assertEqual(summary["tokens"]["known_used_tokens"], 130)
        self.assertEqual(summary["tokens"]["estimated_reported_tokens"], 30)
        self.assertEqual(summary["tokens"]["finished_invocations"], 3)
        self.assertEqual(summary["tokens"]["exact_invocations"], 0)
        self.assertEqual(summary["tokens"]["unknown_invocations"], 1)
        self.assertEqual(summary["tokens"]["usage_coverage"], 0.0)

    def test_production_and_training_usage_never_mix(self) -> None:
        production = self.start_run("a" * 32)
        with self.assertRaisesRegex(TelemetryValidationError, "training backend"):
            self.start_model(
                production,
                invocation_id="e" * 32,
                backend="training",
            )
        production_model = self.start_model(production, invocation_id="b" * 32)
        with self.assertRaisesRegex(TelemetryValidationError, "training runs"):
            self.writer.record_model_checkin(
                production_model,
                observed_provider="openai",
                observed_model="gpt-5",
                source="synthetic",
            )
        synthetic = {
            "input_tokens": 2,
            "output_tokens": 3,
            "cached_input_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 5,
            "source": "synthetic",
            "exact": True,
            "reported_at": self.t0,
        }
        with self.assertRaisesRegex(TelemetryValidationError, "training"):
            self.writer.record_model_usage(production_model, "synthetic", synthetic)
        self.writer.record_model_usage(production_model, "real", self.exact_usage())

        training = self.start_run("c" * 32, run_kind="training")
        training_model = self.start_model(
            training,
            invocation_id="d" * 32,
            backend="training",
            provider="leftovers",
            model="deterministic-training-v1",
        )
        self.writer.record_model_usage(training_model, "synthetic", synthetic)
        reader = TelemetryReader(self.state)
        self.assertEqual(reader.summary(run_kind="production")["tokens"]["known_used_tokens"], 130)
        self.assertEqual(reader.summary(run_kind="training")["tokens"]["known_used_tokens"], 5)
        self.assertEqual(len(reader.list_runs(run_kind="production")["runs"]), 1)
        self.assertEqual(len(reader.list_runs(run_kind="training")["runs"]), 1)
        with self.assertRaises(TelemetryNotFoundError):
            reader.get_run(training, run_kind="production")

    def test_budget_projection_preserves_exact_distinct_semantics(self) -> None:
        run_id = self.start_run()
        first = self.writer.record_budget_projection(
            "projection-1",
            run_kind="production",
            window_key="daily:2026-07-17",
            maximum_tokens=200_000,
            remaining_tokens=150_000,
            reserve_tokens=20_000,
            reserved_tokens=0,
            source="fixed-envelope",
            run_id=run_id,
            observed_at=self.t0,
        )
        self.assertEqual(first, 1)
        summary = TelemetryReader(self.state).summary()
        tokens = summary["tokens"]
        self.assertEqual(tokens["maximum_tokens"], 200_000)
        self.assertEqual(tokens["remaining_tokens"], 150_000)
        self.assertEqual(tokens["reserve_tokens"], 20_000)
        self.assertEqual(tokens["reserved_tokens"], 0)
        self.assertEqual(tokens["spendable_tokens"], 130_000)
        self.assertEqual(tokens["available_to_reserve_tokens"], 130_000)
        self.assertIsNone(tokens["known_used_tokens"])
        self.assertEqual(summary["budget"]["authority"], "non_authoritative_projection")
        run = TelemetryReader(self.state).get_run(run_id)["run"]
        self.assertEqual(run["budget_window_key"], "daily:2026-07-17")

        reserved = self.writer.record_budget_projection(
            "projection-2",
            run_kind="production",
            window_key="daily:2026-07-17",
            maximum_tokens=200_000,
            remaining_tokens=150_000,
            reserve_tokens=20_000,
            reserved_tokens=100_000,
            source="fixed-envelope",
            reservation_state="reserved",
            run_id=run_id,
            reservation_id="reservation-1",
            observed_at=self.t0 + timedelta(seconds=1),
        )
        self.assertEqual(reserved, 2)
        self.assertEqual(
            self.writer.record_budget_projection(
                "projection-2",
                run_kind="production",
                window_key="daily:2026-07-17",
                maximum_tokens=200_000,
                remaining_tokens=150_000,
                reserve_tokens=20_000,
                reserved_tokens=100_000,
                source="fixed-envelope",
                reservation_state="reserved",
                run_id=run_id,
                reservation_id="reservation-1",
            ),
            reserved,
        )
        tokens = TelemetryReader(self.state).summary()["tokens"]
        self.assertEqual(tokens["reserved_tokens"], 100_000)
        self.assertEqual(tokens["available_to_reserve_tokens"], 30_000)
        self.assertEqual(tokens["window"]["key"], "daily:2026-07-17")

        self.writer.record_budget_projection(
            "projection-3",
            run_kind="production",
            window_key="daily:2026-07-17",
            maximum_tokens=200_000,
            remaining_tokens=149_000,
            reserve_tokens=20_000,
            reserved_tokens=100_000,
            source="fixed-envelope",
            reservation_state="committed",
            run_id=run_id,
            reservation_id="reservation-1",
            observed_at=self.t0 + timedelta(seconds=2),
        )
        with self.assertRaisesRegex(TelemetryConflictError, "finalized"):
            self.writer.record_budget_projection(
                "projection-4",
                run_kind="production",
                window_key="daily:2026-07-17",
                maximum_tokens=200_000,
                remaining_tokens=149_000,
                reserve_tokens=20_000,
                reserved_tokens=0,
                source="fixed-envelope",
                reservation_state="released",
                reservation_id="reservation-1",
            )

    def test_summary_preserves_unknown_usage_when_no_final_receipt_exists(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        self.writer.record_budget_projection(
            "projection-no-receipt",
            run_kind="production",
            window_key="daily:2026-07-17",
            maximum_tokens=1_000,
            remaining_tokens=1_000,
            reserve_tokens=100,
            reserved_tokens=0,
            source="fixed-envelope",
            run_id=run_id,
            observed_at=self.t0,
        )
        self.writer.finish_model_invocation(invocation_id, "failed", exit_code=2)

        tokens = TelemetryReader(self.state).summary()["tokens"]

        self.assertIsNone(tokens["known_used_tokens"])
        self.assertIsNone(tokens["estimated_reported_tokens"])
        self.assertEqual(tokens["finished_invocations"], 1)
        self.assertEqual(tokens["exact_invocations"], 0)
        self.assertEqual(tokens["unknown_invocations"], 1)

    def test_unfinished_exact_receipt_does_not_inflate_usage_coverage(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        self.writer.record_budget_projection(
            "projection-active-exact",
            run_kind="production",
            window_key="daily:2026-07-17",
            maximum_tokens=1_000,
            remaining_tokens=900,
            reserve_tokens=100,
            reserved_tokens=0,
            source="fixed-envelope",
            run_id=run_id,
            observed_at=self.t0,
        )
        self.writer.record_model_usage(invocation_id, "active-receipt", self.exact_usage())

        tokens = TelemetryReader(self.state).summary()["tokens"]

        self.assertEqual(tokens["known_used_tokens"], 130)
        self.assertEqual(tokens["finished_invocations"], 0)
        self.assertEqual(tokens["exact_invocations"], 0)
        self.assertIsNone(tokens["usage_coverage"])
        self.assertEqual(tokens["usage_coverage_detail"]["status"], "unknown")

    def test_summary_usage_and_caps_follow_latest_budget_window(self) -> None:
        old_run = self.start_run("1" * 32)
        old_model = self.start_model(old_run, invocation_id="2" * 32, cap=4_000)
        self.writer.record_model_usage(old_model, "old-receipt", self.exact_usage(400))
        self.writer.finish_model_invocation(old_model, "succeeded", exit_code=0)
        self.writer.record_budget_projection(
            "old-window",
            run_kind="production",
            window_key="daily:2026-07-16",
            maximum_tokens=10_000,
            remaining_tokens=9_600,
            reserve_tokens=1_000,
            reserved_tokens=0,
            source="fixed-envelope",
            run_id=old_run,
            observed_at=self.t0,
        )

        current_run = self.start_run("3" * 32)
        current_model = self.start_model(
            current_run,
            invocation_id="4" * 32,
            cap=2_000,
        )
        self.writer.record_model_usage(
            current_model,
            "current-receipt",
            self.exact_usage(200),
        )
        self.writer.finish_model_invocation(current_model, "succeeded", exit_code=0)
        self.writer.record_budget_projection(
            "current-window",
            run_kind="production",
            window_key="daily:2026-07-17",
            maximum_tokens=10_000,
            remaining_tokens=9_800,
            reserve_tokens=1_000,
            reserved_tokens=0,
            source="fixed-envelope",
            run_id=current_run,
            observed_at=self.t0 + timedelta(days=1),
        )

        tokens = TelemetryReader(self.state).summary()["tokens"]

        self.assertEqual(tokens["window"]["key"], "daily:2026-07-17")
        self.assertEqual(tokens["known_used_tokens"], 200)
        self.assertEqual(tokens["run_cap_tokens"], 2_000)
        self.assertEqual(tokens["capped_runs"], 1)
        self.assertEqual(tokens["finished_invocations"], 1)
        self.assertEqual(tokens["exact_invocations"], 1)
        self.assertEqual(tokens["usage_coverage"], 1.0)

    def test_budget_projection_fails_closed_and_separates_training(self) -> None:
        with self.assertRaisesRegex(TelemetryValidationError, "exceed"):
            self.writer.record_budget_projection(
                "invalid",
                run_kind="production",
                window_key="daily:2026-07-17",
                maximum_tokens=10,
                remaining_tokens=11,
                reserve_tokens=0,
                reserved_tokens=0,
                source="fixed-envelope",
            )
        with self.assertRaisesRegex(TelemetryValidationError, "training"):
            self.writer.record_budget_projection(
                "synthetic-production",
                run_kind="production",
                window_key="daily:2026-07-17",
                maximum_tokens=10,
                remaining_tokens=10,
                reserve_tokens=0,
                reserved_tokens=0,
                source="synthetic",
            )
        self.writer.record_budget_projection(
            "synthetic-training",
            run_kind="training",
            window_key="training:2026-07-17",
            maximum_tokens=1_000,
            remaining_tokens=900,
            reserve_tokens=100,
            reserved_tokens=200,
            source="synthetic",
            observed_at=self.t0,
        )
        reader = TelemetryReader(self.state)
        production = reader.summary(run_kind="production")
        training = reader.summary(run_kind="training")
        self.assertIsNone(production["tokens"]["maximum_tokens"])
        self.assertEqual(training["tokens"]["maximum_tokens"], 1_000)
        self.assertEqual(training["tokens"]["available_to_reserve_tokens"], 600)

    def test_concurrent_events_receive_gapless_transactional_sequences(self) -> None:
        run_id = self.start_run()
        errors: list[BaseException] = []

        def append(index: int) -> None:
            try:
                self.writer.record_event(
                    run_id,
                    "verification",
                    detail={"repair_cycle": index},
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=append, args=(index,)) for index in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertEqual(errors, [])
        events = TelemetryReader(self.state).get_run(run_id)["events"]
        self.assertEqual([event["sequence"] for event in events], list(range(1, 26)))

    def test_writer_is_bound_to_its_controller_process(self) -> None:
        run_id = self.start_run()
        with (
            mock.patch("leftovers.telemetry.os.getpid", return_value=os.getpid() + 1),
            self.assertRaisesRegex(Exception, "controller process"),
        ):
            self.writer.record_event(run_id, "verification")

    def test_snapshot_is_safe_json_and_dashboard_friendly(self) -> None:
        run_id = self.start_run()
        invocation_id = self.start_model(run_id)
        self.writer.heartbeat_model(invocation_id, source="controller", observed_at=self.t0)
        reader = TelemetryReader(self.state)
        snapshot = reader.snapshot(now=self.t0 + timedelta(seconds=5))
        encoded = json.dumps(snapshot)
        self.assertNotIn(str(self.state), encoded)
        self.assertEqual(snapshot["schema_version"], SCHEMA_VERSION)
        self.assertEqual(snapshot["health"]["status"], "ok")
        self.assertEqual(snapshot["summary"]["tokens"]["unit"], "tokens")
        self.assertEqual(snapshot["models"][0]["heartbeat_status"], "current")

    def test_limits_and_schema_versions_fail_closed(self) -> None:
        self.start_run()
        reader = TelemetryReader(self.state)
        with self.assertRaises(TelemetryValidationError):
            reader.list_runs(limit=0)
        with self.assertRaises(TelemetryValidationError):
            reader.list_models(stale_after_seconds=0)
        with sqlite3.connect(self.state / DATABASE_NAME) as connection:
            connection.execute("PRAGMA user_version=999")
        with self.assertRaisesRegex(TelemetryUnavailableError, "schema version"):
            TelemetryReader(self.state)


if __name__ == "__main__":
    unittest.main()
