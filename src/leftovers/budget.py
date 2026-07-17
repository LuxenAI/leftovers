from __future__ import annotations

import math
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import time as datetime_time
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import BudgetConfig
from .models import BudgetSnapshot, utc_now
from .statefs import private_directory, private_file

_CONTROLLER_COMPLETION_GRACE_SECONDS = 7_200


class BudgetError(ValueError):
    """Raised when the configured budget source cannot produce a safe value."""


def budget_window_key(config: BudgetConfig, now: datetime) -> str:
    """Return the quota-window key without opening or mutating the budget ledger."""

    observed = now.astimezone(ZoneInfo(config.timezone))
    shifted = observed - timedelta(hours=config.reset_hour)
    if config.window == "daily":
        return f"daily:{shifted.date().isoformat()}"
    days_since_reset = (shifted.weekday() - config.reset_weekday) % 7
    start = shifted.date() - timedelta(days=days_since_reset)
    return f"weekly:{start.isoformat()}"


@dataclass
class BudgetGate:
    config: BudgetConfig

    def next_reset(self, observed_at: datetime) -> datetime:
        zone = ZoneInfo(self.config.timezone)
        local = observed_at.astimezone(zone)
        if self.config.window == "daily":
            reset_date = local.date()
            candidate = datetime.combine(
                reset_date,
                datetime_time(hour=self.config.reset_hour),
                tzinfo=zone,
            )
            if candidate <= local:
                candidate = datetime.combine(
                    reset_date + timedelta(days=1),
                    datetime_time(hour=self.config.reset_hour),
                    tzinfo=zone,
                )
        else:
            days_ahead = (self.config.reset_weekday - local.weekday()) % 7
            reset_date = local.date() + timedelta(days=days_ahead)
            candidate = datetime.combine(
                reset_date,
                datetime_time(hour=self.config.reset_hour),
                tzinfo=zone,
            )
            if candidate <= local:
                candidate = datetime.combine(
                    reset_date + timedelta(days=7),
                    datetime_time(hour=self.config.reset_hour),
                    tzinfo=zone,
                )
        return candidate.astimezone(observed_at.tzinfo)

    def snapshot(self, override_remaining: int | None = None) -> BudgetSnapshot:
        if override_remaining is not None:
            remaining = override_remaining
            source = "cli-override"
            confidence = "manual"
        elif self.config.source == "fixed":
            remaining = self.config.fixed_remaining_tokens
            source = "fixed-envelope"
            confidence = "configured"
        else:
            raw = os.environ.get(self.config.remaining_tokens_env)
            if raw is None or raw.strip() == "":
                remaining = None
            else:
                try:
                    remaining = int(raw)
                except ValueError as exc:
                    raise BudgetError(
                        f"{self.config.remaining_tokens_env} must be a non-negative integer"
                    ) from exc
            source = f"environment:{self.config.remaining_tokens_env}"
            confidence = "manual"
        if remaining is not None and remaining < 0:
            raise BudgetError("remaining token budget cannot be negative")
        if (
            remaining is not None
            and self.config.maximum_tokens is not None
            and remaining > self.config.maximum_tokens
        ):
            raise BudgetError("remaining token budget exceeds the configured maximum")
        spendable = (
            max(0, remaining - self.config.reserve_tokens) if remaining is not None else None
        )
        observed_at = utc_now()
        return BudgetSnapshot(
            source=source,
            remaining_tokens=remaining,
            reserve_tokens=self.config.reserve_tokens,
            spendable_tokens=spendable,
            confidence=confidence if remaining is not None else "unknown",
            observed_at=observed_at,
            resets_at=self.next_reset(observed_at),
            maximum_tokens=self.config.maximum_tokens,
        )

    def can_start(self, snapshot: BudgetSnapshot, estimated_tokens_p95: int) -> tuple[bool, str]:
        if snapshot.spendable_tokens is None:
            return (
                False,
                "remaining quota is unknown; provide an official adapter value or manual envelope",
            )
        required = max(
            self.config.minimum_spendable_tokens,
            math.ceil(estimated_tokens_p95 * self.config.safety_multiplier),
        )
        if snapshot.spendable_tokens < required:
            return (
                False,
                f"spendable quota {snapshot.spendable_tokens} is below required {required}",
            )
        if snapshot.resets_at is None:
            return False, "quota reset time is unknown"
        seconds_remaining = (snapshot.resets_at - snapshot.observed_at).total_seconds()
        required_horizon = self.config.max_run_seconds + self.config.reset_safety_seconds
        if seconds_remaining < required_horizon:
            return (
                False,
                f"only {int(seconds_remaining)}s remain before reset; {required_horizon}s required",
            )
        return True, f"spendable quota {snapshot.spendable_tokens} covers required {required}"


@dataclass(frozen=True)
class BudgetReservation:
    run_id: str
    window_key: str
    reserved_tokens: int
    remaining_after_reservation: int


class BudgetLedger:
    """Transactional local reservations prevent repeated runs from reusing one envelope."""

    def __init__(self, state_dir: Path, config: BudgetConfig):
        root = private_directory(state_dir)
        self.path = private_file(root / "budget.sqlite3")
        self.config = config
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reservations (
                    run_id TEXT PRIMARY KEY,
                    window_key TEXT NOT NULL,
                    reserved_tokens INTEGER NOT NULL CHECK (reserved_tokens >= 0),
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    finished_at TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def window_key(self, now: datetime | None = None) -> str:
        return budget_window_key(self.config, now or utc_now())

    def reserved_tokens(self, window_key: str) -> int:
        """Return capacity already consumed or held in one qualified window."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(SUM(reserved_tokens), 0) FROM reservations "
                "WHERE window_key = ? AND status != 'released'",
                (window_key,),
            ).fetchone()
        return int(row[0])

    def active_run_ids(self, *, now: datetime | None = None) -> set[str]:
        """Return recent reservations that may still have a live controller.

        A crashed controller keeps consuming quota conservatively, but its
        workspace becomes reapable after the configured run horizon plus reset
        and cleanup grace. Malformed and future-dated rows fail closed.
        """

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id, created_at FROM reservations WHERE status = 'reserved'"
            ).fetchall()
        current = now or utc_now()
        live_horizon = timedelta(
            seconds=(
                self.config.max_run_seconds
                + self.config.reset_safety_seconds
                + _CONTROLLER_COMPLETION_GRACE_SECONDS
            )
        )
        protected: set[str] = set()
        for run_id, raw_created_at in rows:
            try:
                created_at = datetime.fromisoformat(str(raw_created_at))
            except ValueError:
                protected.add(str(run_id))
                continue
            if created_at.tzinfo is None or created_at > current:
                protected.add(str(run_id))
                continue
            if current - created_at <= live_horizon:
                protected.add(str(run_id))
        return protected

    def reserve(
        self,
        run_id: str,
        snapshot: BudgetSnapshot,
        estimated_tokens_p95: int,
        *,
        now: datetime | None = None,
    ) -> BudgetReservation:
        if snapshot.spendable_tokens is None:
            raise BudgetError("cannot reserve an unknown quota")
        amount = math.ceil(estimated_tokens_p95 * self.config.safety_multiplier)
        window_key = self.window_key(snapshot.observed_at)
        current = now or utc_now()
        age_seconds = (current - snapshot.observed_at).total_seconds()
        if age_seconds < -60 or age_seconds > 300:
            raise BudgetError("quota snapshot is stale or future-dated")
        if self.window_key(current) != window_key:
            raise BudgetError("quota reset window changed after the snapshot was captured")
        if (
            snapshot.resets_at is None
            or (snapshot.resets_at - current).total_seconds()
            < self.config.max_run_seconds + self.config.reset_safety_seconds
        ):
            raise BudgetError("insufficient time remains to finish before the quota reset")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT window_key, reserved_tokens FROM reservations WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if existing:
                connection.execute("COMMIT")
                return BudgetReservation(
                    run_id=run_id,
                    window_key=str(existing[0]),
                    reserved_tokens=int(existing[1]),
                    remaining_after_reservation=max(
                        0, snapshot.spendable_tokens - int(existing[1])
                    ),
                )
            used = connection.execute(
                "SELECT COALESCE(SUM(reserved_tokens), 0) FROM reservations "
                "WHERE window_key = ? AND status != 'released'",
                (window_key,),
            ).fetchone()[0]
            available = max(0, snapshot.spendable_tokens - int(used))
            required = max(self.config.minimum_spendable_tokens, amount)
            if available < required:
                connection.execute("ROLLBACK")
                raise BudgetError(
                    f"window {window_key} has {available} unreserved tokens; {required} required"
                )
            connection.execute(
                "INSERT INTO reservations "
                "(run_id, window_key, reserved_tokens, status, created_at) "
                "VALUES (?, ?, ?, 'reserved', ?)",
                (run_id, window_key, amount, snapshot.observed_at.isoformat()),
            )
            connection.execute("COMMIT")
        return BudgetReservation(
            run_id=run_id,
            window_key=window_key,
            reserved_tokens=amount,
            remaining_after_reservation=available - amount,
        )

    def finish(self, run_id: str, status: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE reservations SET status = ?, finished_at = ? WHERE run_id = ?",
                (status, utc_now().isoformat(), run_id),
            )
