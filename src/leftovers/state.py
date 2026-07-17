from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from .config import PublicationConfig
from .models import utc_now
from .statefs import private_directory, private_file


class StatePolicyError(RuntimeError):
    pass


class PublicationLedger:
    """Atomic local output caps and repository cooldown reservations."""

    def __init__(self, state_dir: Path):
        root = private_directory(state_dir)
        self.path = private_file(root / "publications.sqlite3")
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS publication_slots (
                    run_id TEXT PRIMARY KEY,
                    window_key TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    issue_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    pr_url TEXT
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _assert_available(
        connection: sqlite3.Connection,
        *,
        window_key: str,
        repository: str,
        config: PublicationConfig,
        now: datetime,
    ) -> None:
        count = connection.execute(
            "SELECT COUNT(*) FROM publication_slots WHERE window_key = ? AND status != 'released'",
            (window_key,),
        ).fetchone()[0]
        if int(count) >= config.max_prs_per_window:
            raise StatePolicyError("publication cap for this budget window is exhausted")
        now_iso = now.isoformat()
        cooldown_cutoff = (now - timedelta(days=config.repository_cooldown_days)).isoformat()
        # Use the supplied instant as the upper bound so a malformed future record fails closed.
        recent = connection.execute(
            "SELECT 1 FROM publication_slots "
            "WHERE repository = ? AND created_at BETWEEN ? AND ? "
            "AND status != 'released' LIMIT 1",
            (repository, cooldown_cutoff, now_iso),
        ).fetchone()
        future = connection.execute(
            "SELECT 1 FROM publication_slots WHERE repository = ? AND created_at > ? "
            "AND status != 'released' LIMIT 1",
            (repository, now_iso),
        ).fetchone()
        if recent or future:
            raise StatePolicyError(
                f"repository {repository} is inside the configured publication cooldown"
            )

    def check_available(
        self,
        *,
        window_key: str,
        repository: str,
        config: PublicationConfig,
    ) -> None:
        now = utc_now()
        with self._connect() as connection:
            self._assert_available(
                connection,
                window_key=window_key,
                repository=repository,
                config=config,
                now=now,
            )

    def reserve(
        self,
        *,
        run_id: str,
        window_key: str,
        repository: str,
        issue_number: int,
        config: PublicationConfig,
    ) -> None:
        now = utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM publication_slots WHERE run_id = ?", (run_id,)
            ).fetchone():
                connection.execute("COMMIT")
                return
            try:
                self._assert_available(
                    connection,
                    window_key=window_key,
                    repository=repository,
                    config=config,
                    now=now,
                )
            except StatePolicyError:
                connection.execute("ROLLBACK")
                raise
            connection.execute(
                "INSERT INTO publication_slots "
                "(run_id, window_key, repository, issue_number, status, created_at) "
                "VALUES (?, ?, ?, ?, 'reserved', ?)",
                (run_id, window_key, repository, issue_number, now.isoformat()),
            )
            connection.execute("COMMIT")

    def finish(self, run_id: str, pr_url: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE publication_slots SET status = 'published', pr_url = ? WHERE run_id = ?",
                (pr_url, run_id),
            )
