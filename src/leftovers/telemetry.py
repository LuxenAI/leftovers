from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .statefs import private_directory, private_file

SCHEMA_VERSION = 1
DATABASE_NAME = "telemetry.sqlite3"

RUN_KINDS = frozenset({"production", "training"})
RUN_STAGES = frozenset(
    {
        "scheduled",
        "budget_check",
        "discovering",
        "scoring",
        "selected",
        "preflight",
        "sandbox_ready",
        "planning",
        "implementing",
        "verifying",
        "reviewing",
        "approved",
        "awaiting_approval",
        "publishing",
        "pr_open",
        "cleaning",
        "complete",
        "deferred",
        "skipped",
        "failed",
        "aborted",
        "cleanup_pending",
    }
)
TERMINAL_RUN_STAGES = frozenset(
    {"complete", "deferred", "skipped", "failed", "aborted", "cleanup_pending"}
)
EVENT_TYPES = frozenset(
    {
        "run_started",
        "state",
        "budget_observed",
        "budget_reserved",
        "candidate_selected",
        "sandbox_ready",
        "model_started",
        "model_checkin",
        "model_heartbeat",
        "model_usage",
        "model_finished",
        "verification",
        "review",
        "approval",
        "publication",
        "cleanup",
        "telemetry_degraded",
        "run_finished",
    }
)
MODEL_STAGES = frozenset({"planning", "implementation", "review"})
MODEL_BACKENDS = frozenset({"container", "host", "broker", "training"})
MODEL_STATES = frozenset(
    {"queued", "starting", "running", "succeeded", "failed", "timed_out", "cancelled"}
)
TERMINAL_MODEL_STATES = frozenset({"succeeded", "failed", "timed_out", "cancelled"})
IDENTITY_STATUSES = frozenset({"unknown", "matched", "mismatch"})
IDENTITY_SOURCES = frozenset({"adapter_reported", "broker_attested", "synthetic"})
HEARTBEAT_SOURCES = frozenset({"controller", "adapter", "broker", "synthetic"})
USAGE_STATUSES = frozenset({"pending", "exact", "estimated", "partial", "unavailable", "invalid"})
USAGE_SOURCES = frozenset(
    {
        "provider_response",
        "broker_attested",
        "adapter_reported",
        "estimated",
        "synthetic",
        "unavailable",
    }
)
CLEANUP_STATUSES = frozenset({"not_started", "pending", "proven", "failed"})
BUDGET_SOURCES = frozenset(
    {"fixed-envelope", "cli-override", "environment", "provider-adapter", "synthetic"}
)
BUDGET_RESERVATION_STATES = frozenset({"snapshot", "reserved", "released", "committed"})

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_MODEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,191}")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}")
_PR_URL = re.compile(
    r"https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}/pull/[1-9][0-9]*"
)
_WINDOW_KEY = re.compile(r"[a-z][a-z0-9_-]{0,31}:[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}")
_DETAIL_KEYS = frozenset(
    {
        "attempt",
        "cleanup_status",
        "confidence",
        "containers_removed",
        "exact",
        "failure_code",
        "identity_status",
        "issue_number",
        "reason_code",
        "remaining_after_reservation",
        "repair_cycle",
        "repository",
        "reserved_tokens",
        "score",
        "source",
        "state",
        "total_tokens",
        "usage_status",
        "window_key",
        "workspace_removed",
    }
)
_USAGE_FIELDS = frozenset(
    {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "reasoning_tokens",
        "total_tokens",
        "source",
        "exact",
        "reported_at",
    }
)
_MAX_TOKEN_COUNT = 1_000_000_000


class TelemetryError(RuntimeError):
    """Base class for telemetry failures."""


class TelemetryValidationError(TelemetryError, ValueError):
    """Raised when controller or adapter data violates the telemetry contract."""


class TelemetryConflictError(TelemetryError):
    """Raised when an idempotency key is reused with different data."""


class TelemetryNotFoundError(TelemetryError):
    """Raised when a requested run or model invocation does not exist."""


class TelemetryUnavailableError(TelemetryError):
    """Raised when the read-only telemetry database is absent or unsafe."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_text(value: datetime | str | None, field: str) -> str:
    if value is None:
        parsed = _utc_now()
    elif isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise TelemetryValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    else:
        raise TelemetryValidationError(f"{field} must be a timestamp")
    if parsed.tzinfo is None:
        raise TelemetryValidationError(f"{field} must include a timezone")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _choice(value: str, choices: frozenset[str], field: str) -> str:
    if value not in choices:
        raise TelemetryValidationError(f"{field} must be one of: {', '.join(sorted(choices))}")
    return value


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise TelemetryValidationError(f"{field} is not a safe identifier")
    return value


def _code(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise TelemetryValidationError(f"{field} is not a safe status code")
    return value


def _model_name(value: str, field: str) -> str:
    if not isinstance(value, str) or _MODEL_NAME.fullmatch(value) is None:
        raise TelemetryValidationError(f"{field} is not a safe provider/model identifier")
    return value


def _optional_count(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= _MAX_TOKEN_COUNT:
        raise TelemetryValidationError(
            f"{field} must be a non-negative integer no larger than {_MAX_TOKEN_COUNT}"
        )
    return value


def _required_count(value: Any, field: str) -> int:
    parsed = _optional_count(value, field)
    if parsed is None:
        raise TelemetryValidationError(f"{field} is required")
    return parsed


def _safe_detail(detail: Mapping[str, Any] | None) -> str:
    if detail is None:
        return "{}"
    unknown = sorted(set(detail) - _DETAIL_KEYS)
    if unknown:
        raise TelemetryValidationError(
            "telemetry detail contains non-allowlisted key(s): " + ", ".join(unknown)
        )
    cleaned: dict[str, str | int | bool | None] = {}
    for key, value in detail.items():
        if value is None or type(value) in {bool, int}:
            if type(value) is int and not -(10**12) <= value <= 10**12:
                raise TelemetryValidationError(f"telemetry detail {key} is out of range")
            cleaned[key] = value
            continue
        if (
            not isinstance(value, str)
            or len(value) > 256
            or any(ord(character) < 32 for character in value)
        ):
            raise TelemetryValidationError(
                f"telemetry detail {key} must be a bounded printable scalar"
            )
        cleaned[key] = value
    encoded = json.dumps(cleaned, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > 4_096:
        raise TelemetryValidationError("telemetry detail exceeds 4096 bytes")
    return encoded


def _safe_optional_text(value: str | None, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TelemetryValidationError(f"{field} must contain at most {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TelemetryValidationError(f"{field} may not contain control characters")
    return value


@contextmanager
def _close_connection(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    try:
        yield connection
    finally:
        connection.close()


class TelemetryWriter:
    """Controller-owned telemetry writer; never construct this in the dashboard process."""

    def __init__(self, state_dir: Path):
        self._owner_pid = os.getpid()
        self._owner_uid = os.getuid()
        root = private_directory(state_dir)
        self.path = private_file(root / DATABASE_NAME)
        self._initialize()
        os.chmod(self.path, 0o600)

    def _assert_owner(self) -> None:
        if os.getpid() != self._owner_pid or os.getuid() != self._owner_uid:
            raise TelemetryError("telemetry writer may only be used by its controller process")

    def _connect(self) -> sqlite3.Connection:
        self._assert_owner()
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        # Rollback-journal mode lets a `mode=ro` dashboard reader remain
        # physically read-only. WAL readers otherwise create -wal/-shm sidecars.
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with _close_connection(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            else:
                connection.execute("COMMIT")

    def _initialize(self) -> None:
        with _close_connection(self._connect()) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, SCHEMA_VERSION}:
                raise TelemetryError(
                    f"unsupported telemetry schema version {version}; expected {SCHEMA_VERSION}"
                )
            if version == SCHEMA_VERSION:
                return
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY,
                    run_kind TEXT NOT NULL CHECK (run_kind IN ('production', 'training')),
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    finished_at TEXT,
                    stage TEXT NOT NULL,
                    terminal INTEGER NOT NULL DEFAULT 0 CHECK (terminal IN (0, 1)),
                    repository TEXT,
                    issue_number INTEGER CHECK (issue_number IS NULL OR issue_number > 0),
                    score INTEGER CHECK (score IS NULL OR score BETWEEN 0 AND 100),
                    failure_code TEXT,
                    safe_status_code TEXT,
                    pr_url TEXT,
                    budget_window_key TEXT,
                    cleanup_status TEXT NOT NULL DEFAULT 'not_started'
                        CHECK (cleanup_status IN ('not_started', 'pending', 'proven', 'failed')),
                    last_event_sequence INTEGER NOT NULL DEFAULT 0
                        CHECK (last_event_sequence >= 0)
                );
                CREATE TABLE run_events (
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    detail_json TEXT NOT NULL DEFAULT '{}' CHECK (length(detail_json) <= 4096),
                    PRIMARY KEY (run_id, sequence)
                );
                CREATE TABLE model_invocations (
                    invocation_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    stage TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK (attempt BETWEEN 0 AND 100),
                    backend TEXT NOT NULL,
                    expected_provider TEXT NOT NULL,
                    expected_model TEXT NOT NULL,
                    observed_provider TEXT,
                    observed_model TEXT,
                    identity_status TEXT NOT NULL DEFAULT 'unknown'
                        CHECK (identity_status IN ('unknown', 'matched', 'mismatch')),
                    identity_source TEXT,
                    state TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    checked_in_at TEXT,
                    last_controller_heartbeat_at TEXT,
                    last_adapter_heartbeat_at TEXT,
                    finished_at TEXT,
                    exit_code INTEGER,
                    failure_code TEXT,
                    usage_status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (usage_status IN
                            ('pending', 'exact', 'estimated', 'partial', 'unavailable', 'invalid')),
                    run_token_cap INTEGER CHECK (run_token_cap IS NULL OR run_token_cap >= 0),
                    UNIQUE (run_id, stage, attempt)
                );
                CREATE TABLE model_usage (
                    invocation_id TEXT NOT NULL
                        REFERENCES model_invocations(invocation_id) ON DELETE CASCADE,
                    request_key TEXT NOT NULL,
                    reported_at TEXT NOT NULL,
                    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
                    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
                    cached_input_tokens INTEGER
                        CHECK (cached_input_tokens IS NULL OR cached_input_tokens >= 0),
                    reasoning_tokens INTEGER
                        CHECK (reasoning_tokens IS NULL OR reasoning_tokens >= 0),
                    total_tokens INTEGER NOT NULL CHECK (total_tokens >= 0),
                    source TEXT NOT NULL,
                    exact INTEGER NOT NULL CHECK (exact IN (0, 1)),
                    is_final INTEGER NOT NULL CHECK (is_final IN (0, 1)),
                    PRIMARY KEY (invocation_id, request_key)
                );
                CREATE TABLE budget_projections (
                    projection_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    projection_id TEXT NOT NULL UNIQUE,
                    run_kind TEXT NOT NULL CHECK (run_kind IN ('production', 'training')),
                    window_key TEXT NOT NULL,
                    run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL,
                    reservation_id TEXT,
                    reservation_state TEXT NOT NULL CHECK
                        (reservation_state IN ('snapshot', 'reserved', 'released', 'committed')),
                    maximum_tokens INTEGER CHECK
                        (maximum_tokens IS NULL OR maximum_tokens >= 0),
                    remaining_tokens INTEGER CHECK
                        (remaining_tokens IS NULL OR remaining_tokens >= 0),
                    reserve_tokens INTEGER NOT NULL CHECK (reserve_tokens >= 0),
                    reserved_tokens INTEGER NOT NULL CHECK (reserved_tokens >= 0),
                    observed_at TEXT NOT NULL,
                    source TEXT NOT NULL
                );
                CREATE INDEX run_events_time_idx ON run_events(occurred_at);
                CREATE INDEX model_invocations_run_idx ON model_invocations(run_id, started_at);
                CREATE INDEX model_usage_invocation_idx ON model_usage(invocation_id, reported_at);
                CREATE INDEX budget_projection_window_idx
                    ON budget_projections(run_kind, observed_at, projection_sequence);
                CREATE INDEX budget_projection_reservation_idx
                    ON budget_projections(reservation_id, projection_sequence);
                PRAGMA user_version=1;
                COMMIT;
                """
            )

    @staticmethod
    def _run(connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise TelemetryNotFoundError(f"telemetry run {run_id} does not exist")
        return row

    @staticmethod
    def _invocation(connection: sqlite3.Connection, invocation_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM model_invocations WHERE invocation_id = ?", (invocation_id,)
        ).fetchone()
        if row is None:
            raise TelemetryNotFoundError(
                f"telemetry model invocation {invocation_id} does not exist"
            )
        return row

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        occurred_at: str,
        stage: str,
        detail_json: str,
    ) -> int:
        row = TelemetryWriter._run(connection, run_id)
        sequence = int(row["last_event_sequence"]) + 1
        connection.execute(
            "INSERT INTO run_events "
            "(run_id, sequence, occurred_at, event_type, stage, detail_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, sequence, occurred_at, event_type, stage, detail_json),
        )
        connection.execute(
            "UPDATE runs SET last_event_sequence = ?, updated_at = ? WHERE run_id = ?",
            (sequence, occurred_at, run_id),
        )
        return sequence

    def start_run(
        self,
        run_id: str,
        *,
        run_kind: str = "production",
        stage: str = "scheduled",
        started_at: datetime | str | None = None,
        repository: str | None = None,
        issue_number: int | None = None,
        score: int | None = None,
        budget_window_key: str | None = None,
    ) -> int:
        run_id = _identifier(run_id, "run_id")
        run_kind = _choice(run_kind, RUN_KINDS, "run_kind")
        stage = _choice(stage, RUN_STAGES, "stage")
        timestamp = _utc_text(started_at, "started_at")
        if repository is not None and _REPOSITORY.fullmatch(repository) is None:
            raise TelemetryValidationError("repository must be a safe owner/name slug")
        if issue_number is not None and (type(issue_number) is not int or issue_number < 1):
            raise TelemetryValidationError("issue_number must be a positive integer")
        if score is not None and (type(score) is not int or not 0 <= score <= 100):
            raise TelemetryValidationError("score must be an integer from 0 to 100")
        budget_window_key = _safe_optional_text(budget_window_key, "budget_window_key", maximum=128)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is not None:
                comparable = (
                    existing["run_kind"],
                    existing["stage"],
                    existing["repository"],
                    existing["issue_number"],
                    existing["score"],
                    existing["budget_window_key"],
                )
                requested = (
                    run_kind,
                    stage,
                    repository,
                    issue_number,
                    score,
                    budget_window_key,
                )
                if comparable != requested:
                    raise TelemetryConflictError("run_id is already bound to different run data")
                return int(existing["last_event_sequence"])
            connection.execute(
                "INSERT INTO runs "
                "(run_id, run_kind, started_at, updated_at, stage, repository, issue_number, "
                "score, budget_window_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    run_kind,
                    timestamp,
                    timestamp,
                    stage,
                    repository,
                    issue_number,
                    score,
                    budget_window_key,
                ),
            )
            return self._append_event(
                connection,
                run_id=run_id,
                event_type="run_started",
                occurred_at=timestamp,
                stage=stage,
                detail_json="{}",
            )

    def record_event(
        self,
        run_id: str,
        event_type: str,
        *,
        stage: str | None = None,
        detail: Mapping[str, Any] | None = None,
        occurred_at: datetime | str | None = None,
    ) -> int:
        run_id = _identifier(run_id, "run_id")
        event_type = _choice(event_type, EVENT_TYPES, "event_type")
        if stage is not None:
            stage = _choice(stage, RUN_STAGES, "stage")
        timestamp = _utc_text(occurred_at, "occurred_at")
        detail_json = _safe_detail(detail)
        with self._transaction() as connection:
            run = self._run(connection, run_id)
            if bool(run["terminal"]):
                raise TelemetryConflictError("cannot append an event to a terminal run")
            return self._append_event(
                connection,
                run_id=run_id,
                event_type=event_type,
                occurred_at=timestamp,
                stage=stage or str(run["stage"]),
                detail_json=detail_json,
            )

    def transition_run(
        self,
        run_id: str,
        stage: str,
        *,
        detail: Mapping[str, Any] | None = None,
        occurred_at: datetime | str | None = None,
    ) -> int:
        run_id = _identifier(run_id, "run_id")
        stage = _choice(stage, RUN_STAGES, "stage")
        if stage in TERMINAL_RUN_STAGES:
            raise TelemetryValidationError("terminal stages must be recorded with finish_run")
        timestamp = _utc_text(occurred_at, "occurred_at")
        detail_json = _safe_detail(detail)
        with self._transaction() as connection:
            run = self._run(connection, run_id)
            if bool(run["terminal"]):
                raise TelemetryConflictError("cannot transition a terminal run")
            connection.execute(
                "UPDATE runs SET stage = ?, updated_at = ? WHERE run_id = ?",
                (stage, timestamp, run_id),
            )
            return self._append_event(
                connection,
                run_id=run_id,
                event_type="state",
                occurred_at=timestamp,
                stage=stage,
                detail_json=detail_json,
            )

    def set_run_target(
        self,
        run_id: str,
        *,
        repository: str,
        issue_number: int,
        score: int,
        occurred_at: datetime | str | None = None,
    ) -> int:
        run_id = _identifier(run_id, "run_id")
        if _REPOSITORY.fullmatch(repository) is None:
            raise TelemetryValidationError("repository must be a safe owner/name slug")
        if type(issue_number) is not int or issue_number < 1:
            raise TelemetryValidationError("issue_number must be a positive integer")
        if type(score) is not int or not 0 <= score <= 100:
            raise TelemetryValidationError("score must be an integer from 0 to 100")
        timestamp = _utc_text(occurred_at, "occurred_at")
        with self._transaction() as connection:
            run = self._run(connection, run_id)
            if bool(run["terminal"]):
                raise TelemetryConflictError("cannot select an issue for a terminal run")
            previous = (run["repository"], run["issue_number"], run["score"])
            target = (repository, issue_number, score)
            if any(item is not None for item in previous) and previous != target:
                raise TelemetryConflictError("run target is already bound to different data")
            connection.execute(
                "UPDATE runs SET repository = ?, issue_number = ?, score = ?, updated_at = ? "
                "WHERE run_id = ?",
                (repository, issue_number, score, timestamp, run_id),
            )
            return self._append_event(
                connection,
                run_id=run_id,
                event_type="candidate_selected",
                occurred_at=timestamp,
                stage=str(run["stage"]),
                detail_json=_safe_detail(
                    {"repository": repository, "issue_number": issue_number, "score": score}
                ),
            )

    def set_cleanup_status(
        self,
        run_id: str,
        cleanup_status: str,
        *,
        containers_removed: bool | None = None,
        workspace_removed: bool | None = None,
        occurred_at: datetime | str | None = None,
    ) -> int:
        run_id = _identifier(run_id, "run_id")
        cleanup_status = _choice(cleanup_status, CLEANUP_STATUSES, "cleanup_status")
        timestamp = _utc_text(occurred_at, "occurred_at")
        detail = {
            "cleanup_status": cleanup_status,
            "containers_removed": containers_removed,
            "workspace_removed": workspace_removed,
        }
        with self._transaction() as connection:
            run = self._run(connection, run_id)
            if bool(run["terminal"]):
                raise TelemetryConflictError("cannot update cleanup for a terminal run")
            connection.execute(
                "UPDATE runs SET cleanup_status = ?, updated_at = ? WHERE run_id = ?",
                (cleanup_status, timestamp, run_id),
            )
            return self._append_event(
                connection,
                run_id=run_id,
                event_type="cleanup",
                occurred_at=timestamp,
                stage=str(run["stage"]),
                detail_json=_safe_detail(detail),
            )

    def finish_run(
        self,
        run_id: str,
        stage: str,
        *,
        failure_code: str | None = None,
        safe_status_code: str | None = None,
        pr_url: str | None = None,
        cleanup_status: str | None = None,
        finished_at: datetime | str | None = None,
    ) -> int:
        run_id = _identifier(run_id, "run_id")
        stage = _choice(stage, TERMINAL_RUN_STAGES, "stage")
        failure_code = _code(failure_code, "failure_code")
        safe_status_code = _code(safe_status_code, "safe_status_code")
        if pr_url is not None and _PR_URL.fullmatch(pr_url) is None:
            raise TelemetryValidationError("pr_url must be a canonical github.com pull URL")
        if cleanup_status is not None:
            cleanup_status = _choice(cleanup_status, CLEANUP_STATUSES, "cleanup_status")
        timestamp = _utc_text(finished_at, "finished_at")
        with self._transaction() as connection:
            run = self._run(connection, run_id)
            final_cleanup = cleanup_status or str(run["cleanup_status"])
            requested = (stage, failure_code, safe_status_code, pr_url, final_cleanup)
            if bool(run["terminal"]):
                existing = (
                    run["stage"],
                    run["failure_code"],
                    run["safe_status_code"],
                    run["pr_url"],
                    run["cleanup_status"],
                )
                if existing != requested:
                    raise TelemetryConflictError(
                        "terminal run outcome conflicts with stored outcome"
                    )
                return int(run["last_event_sequence"])
            connection.execute(
                "UPDATE runs SET stage = ?, terminal = 1, finished_at = ?, updated_at = ?, "
                "failure_code = ?, safe_status_code = ?, pr_url = ?, cleanup_status = ? "
                "WHERE run_id = ?",
                (
                    stage,
                    timestamp,
                    timestamp,
                    failure_code,
                    safe_status_code,
                    pr_url,
                    final_cleanup,
                    run_id,
                ),
            )
            return self._append_event(
                connection,
                run_id=run_id,
                event_type="run_finished",
                occurred_at=timestamp,
                stage=stage,
                detail_json=_safe_detail(
                    {
                        "failure_code": failure_code,
                        "reason_code": safe_status_code,
                        "cleanup_status": final_cleanup,
                    }
                ),
            )

    def record_budget_projection(
        self,
        projection_id: str,
        *,
        run_kind: str,
        window_key: str,
        maximum_tokens: int | None,
        remaining_tokens: int | None,
        reserve_tokens: int,
        reserved_tokens: int,
        source: str,
        reservation_state: str = "snapshot",
        run_id: str | None = None,
        reservation_id: str | None = None,
        observed_at: datetime | str | None = None,
    ) -> int:
        """Record a non-authoritative, fully qualified budget observation.

        Every row contains the complete current projection. Reservation changes use a stable
        reservation ID and distinct projection IDs for the reserved and released/committed states.
        The admission ledger remains authoritative; this table exists only for monitoring.
        """

        projection_id = _identifier(projection_id, "projection_id")
        run_kind = _choice(run_kind, RUN_KINDS, "run_kind")
        if not isinstance(window_key, str) or _WINDOW_KEY.fullmatch(window_key) is None:
            raise TelemetryValidationError("window_key is not a safe qualified window key")
        maximum_tokens = _optional_count(maximum_tokens, "maximum_tokens")
        remaining_tokens = _optional_count(remaining_tokens, "remaining_tokens")
        reserve_tokens = _required_count(reserve_tokens, "reserve_tokens")
        reserved_tokens = _required_count(reserved_tokens, "reserved_tokens")
        if (
            maximum_tokens is not None
            and remaining_tokens is not None
            and remaining_tokens > maximum_tokens
        ):
            raise TelemetryValidationError("remaining_tokens cannot exceed maximum_tokens")
        source = _choice(source, BUDGET_SOURCES, "source")
        reservation_state = _choice(
            reservation_state, BUDGET_RESERVATION_STATES, "reservation_state"
        )
        run_id = _identifier(run_id, "run_id") if run_id is not None else None
        reservation_id = (
            _identifier(reservation_id, "reservation_id") if reservation_id is not None else None
        )
        if reservation_state == "snapshot" and reservation_id is not None:
            raise TelemetryValidationError("snapshot projections may not name a reservation")
        if reservation_state != "snapshot" and reservation_id is None:
            raise TelemetryValidationError("reservation changes require a stable reservation_id")
        if source == "synthetic" and run_kind != "training":
            raise TelemetryValidationError(
                "synthetic budget projections may only be recorded for training runs"
            )
        timestamp = _utc_text(observed_at, "observed_at")
        semantic = (
            run_kind,
            window_key,
            run_id,
            reservation_id,
            reservation_state,
            maximum_tokens,
            remaining_tokens,
            reserve_tokens,
            reserved_tokens,
            source,
        )
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM budget_projections WHERE projection_id = ?",
                (projection_id,),
            ).fetchone()
            if existing is not None:
                stored = (
                    existing["run_kind"],
                    existing["window_key"],
                    existing["run_id"],
                    existing["reservation_id"],
                    existing["reservation_state"],
                    existing["maximum_tokens"],
                    existing["remaining_tokens"],
                    existing["reserve_tokens"],
                    existing["reserved_tokens"],
                    existing["source"],
                )
                if stored != semantic:
                    raise TelemetryConflictError(
                        "budget projection ID is already bound to different data"
                    )
                return int(existing["projection_sequence"])
            if run_id is not None:
                run = self._run(connection, run_id)
                if run["run_kind"] != run_kind:
                    raise TelemetryConflictError(
                        "budget projection run kind does not match its run"
                    )
                existing_window = run["budget_window_key"]
                if existing_window is not None and existing_window != window_key:
                    raise TelemetryConflictError("budget projection window does not match its run")
                if existing_window is None:
                    connection.execute(
                        "UPDATE runs SET budget_window_key = ?, updated_at = ? WHERE run_id = ?",
                        (window_key, timestamp, run_id),
                    )
            if reservation_id is not None:
                prior = connection.execute(
                    "SELECT reservation_state FROM budget_projections "
                    "WHERE reservation_id = ? ORDER BY projection_sequence DESC LIMIT 1",
                    (reservation_id,),
                ).fetchone()
                if prior is None and reservation_state != "reserved":
                    raise TelemetryConflictError(
                        "a reservation must be observed as reserved before it is finalized"
                    )
                if prior is not None:
                    previous_state = str(prior["reservation_state"])
                    if previous_state != "reserved":
                        raise TelemetryConflictError(
                            "a finalized reservation cannot transition again"
                        )
                    if reservation_state not in {"released", "committed"}:
                        raise TelemetryConflictError(
                            "a reserved projection may only be released or committed"
                        )
            cursor = connection.execute(
                "INSERT INTO budget_projections "
                "(projection_id, run_kind, window_key, run_id, reservation_id, "
                "reservation_state, maximum_tokens, remaining_tokens, reserve_tokens, "
                "reserved_tokens, observed_at, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    projection_id,
                    run_kind,
                    window_key,
                    run_id,
                    reservation_id,
                    reservation_state,
                    maximum_tokens,
                    remaining_tokens,
                    reserve_tokens,
                    reserved_tokens,
                    timestamp,
                    source,
                ),
            )
            sequence = int(cursor.lastrowid)
            if run_id is not None:
                run = self._run(connection, run_id)
                event_type = (
                    "budget_observed" if reservation_state == "snapshot" else "budget_reserved"
                )
                self._append_event(
                    connection,
                    run_id=run_id,
                    event_type=event_type,
                    occurred_at=timestamp,
                    stage=str(run["stage"]),
                    detail_json=_safe_detail(
                        {
                            "window_key": window_key,
                            "reserved_tokens": reserved_tokens,
                            "source": source,
                            "state": reservation_state,
                        }
                    ),
                )
            return sequence

    def start_model_invocation(
        self,
        run_id: str,
        *,
        stage: str,
        attempt: int,
        backend: str,
        expected_provider: str,
        expected_model: str,
        run_token_cap: int | None = None,
        invocation_id: str | None = None,
        started_at: datetime | str | None = None,
    ) -> str:
        run_id = _identifier(run_id, "run_id")
        stage = _choice(stage, MODEL_STAGES, "stage")
        if type(attempt) is not int or not 0 <= attempt <= 100:
            raise TelemetryValidationError("attempt must be an integer from 0 to 100")
        backend = _choice(backend, MODEL_BACKENDS, "backend")
        expected_provider = _model_name(expected_provider, "expected_provider")
        expected_model = _model_name(expected_model, "expected_model")
        run_token_cap = _optional_count(run_token_cap, "run_token_cap")
        invocation_id = _identifier(invocation_id or uuid.uuid4().hex, "invocation_id")
        timestamp = _utc_text(started_at, "started_at")
        with self._transaction() as connection:
            run = self._run(connection, run_id)
            if bool(run["terminal"]):
                raise TelemetryConflictError("cannot start a model for a terminal run")
            if backend == "training" and run["run_kind"] != "training":
                raise TelemetryValidationError(
                    "the synthetic training backend may only be used by training runs"
                )
            existing = connection.execute(
                "SELECT * FROM model_invocations WHERE invocation_id = ? "
                "OR (run_id = ? AND stage = ? AND attempt = ?)",
                (invocation_id, run_id, stage, attempt),
            ).fetchone()
            if existing is not None:
                comparable = (
                    existing["invocation_id"],
                    existing["run_id"],
                    existing["stage"],
                    existing["attempt"],
                    existing["backend"],
                    existing["expected_provider"],
                    existing["expected_model"],
                    existing["run_token_cap"],
                )
                requested = (
                    invocation_id,
                    run_id,
                    stage,
                    attempt,
                    backend,
                    expected_provider,
                    expected_model,
                    run_token_cap,
                )
                if comparable != requested:
                    raise TelemetryConflictError(
                        "model invocation key is already bound to different data"
                    )
                return invocation_id
            connection.execute(
                "INSERT INTO model_invocations "
                "(invocation_id, run_id, stage, attempt, backend, expected_provider, "
                "expected_model, state, started_at, run_token_cap) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?)",
                (
                    invocation_id,
                    run_id,
                    stage,
                    attempt,
                    backend,
                    expected_provider,
                    expected_model,
                    timestamp,
                    run_token_cap,
                ),
            )
            self._append_event(
                connection,
                run_id=run_id,
                event_type="model_started",
                occurred_at=timestamp,
                stage=str(run["stage"]),
                detail_json=_safe_detail({"attempt": attempt, "state": "starting"}),
            )
        return invocation_id

    def record_model_checkin(
        self,
        invocation_id: str,
        *,
        observed_provider: str,
        observed_model: str,
        source: str,
        checked_in_at: datetime | str | None = None,
    ) -> str:
        invocation_id = _identifier(invocation_id, "invocation_id")
        observed_provider = _model_name(observed_provider, "observed_provider")
        observed_model = _model_name(observed_model, "observed_model")
        source = _choice(source, IDENTITY_SOURCES, "source")
        timestamp = _utc_text(checked_in_at, "checked_in_at")
        with self._transaction() as connection:
            invocation = self._invocation(connection, invocation_id)
            if invocation["state"] in TERMINAL_MODEL_STATES:
                raise TelemetryConflictError("cannot check in a terminal model invocation")
            run = self._run(connection, str(invocation["run_id"]))
            if source == "synthetic" and run["run_kind"] != "training":
                raise TelemetryValidationError(
                    "synthetic model check-ins may only be recorded for training runs"
                )
            identity_status = (
                "matched"
                if observed_provider == invocation["expected_provider"]
                and observed_model == invocation["expected_model"]
                else "mismatch"
            )
            if invocation["checked_in_at"] is not None:
                existing = (
                    invocation["observed_provider"],
                    invocation["observed_model"],
                    invocation["identity_source"],
                    invocation["identity_status"],
                )
                requested = (observed_provider, observed_model, source, identity_status)
                if existing != requested:
                    raise TelemetryConflictError("model check-in conflicts with stored identity")
                return identity_status
            connection.execute(
                "UPDATE model_invocations SET observed_provider = ?, observed_model = ?, "
                "identity_status = ?, identity_source = ?, checked_in_at = ?, state = 'running' "
                "WHERE invocation_id = ?",
                (
                    observed_provider,
                    observed_model,
                    identity_status,
                    source,
                    timestamp,
                    invocation_id,
                ),
            )
            self._append_event(
                connection,
                run_id=str(invocation["run_id"]),
                event_type="model_checkin",
                occurred_at=timestamp,
                stage=str(run["stage"]),
                detail_json=_safe_detail({"source": source, "identity_status": identity_status}),
            )
            return identity_status

    def heartbeat_model(
        self,
        invocation_id: str,
        *,
        source: str,
        observed_at: datetime | str | None = None,
    ) -> bool:
        invocation_id = _identifier(invocation_id, "invocation_id")
        source = _choice(source, HEARTBEAT_SOURCES, "source")
        timestamp = _utc_text(observed_at, "observed_at")
        column = (
            "last_controller_heartbeat_at"
            if source == "controller"
            else "last_adapter_heartbeat_at"
        )
        with self._transaction() as connection:
            invocation = self._invocation(connection, invocation_id)
            if invocation["state"] in TERMINAL_MODEL_STATES:
                raise TelemetryConflictError("cannot heartbeat a terminal model invocation")
            previous = invocation[column]
            if previous is not None and _parse_utc(timestamp) < _parse_utc(str(previous)):
                raise TelemetryConflictError("model heartbeat time moved backwards")
            if previous == timestamp:
                return False
            connection.execute(
                f"UPDATE model_invocations SET {column} = ?, state = 'running' "
                "WHERE invocation_id = ?",
                (timestamp, invocation_id),
            )
            should_emit = (
                previous is None
                or (_parse_utc(timestamp) - _parse_utc(str(previous))).total_seconds() >= 60
            )
            if should_emit:
                run = self._run(connection, str(invocation["run_id"]))
                self._append_event(
                    connection,
                    run_id=str(invocation["run_id"]),
                    event_type="model_heartbeat",
                    occurred_at=timestamp,
                    stage=str(run["stage"]),
                    detail_json=_safe_detail({"source": source, "state": "running"}),
                )
            return should_emit

    @staticmethod
    def _usage_mapping(usage: object) -> dict[str, Any]:
        if is_dataclass(usage) and not isinstance(usage, type):
            raw = asdict(usage)
        elif isinstance(usage, Mapping):
            raw = dict(usage)
        else:
            raise TelemetryValidationError("usage must be a dataclass or mapping")
        unknown = sorted(set(raw) - _USAGE_FIELDS)
        if unknown:
            raise TelemetryValidationError(
                "usage contains non-allowlisted field(s): " + ", ".join(unknown)
            )
        missing = sorted({"total_tokens", "source", "exact"} - set(raw))
        if missing:
            raise TelemetryValidationError("usage is missing field(s): " + ", ".join(missing))
        source = _choice(raw["source"], USAGE_SOURCES, "usage.source")
        if source == "unavailable":
            raise TelemetryValidationError(
                "unavailable usage belongs in invocation usage_status, not a numeric row"
            )
        if type(raw["exact"]) is not bool:
            raise TelemetryValidationError("usage.exact must be a boolean")
        component_fields = {
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
            "reasoning_tokens",
        }
        supplied_components = component_fields.intersection(raw)
        if supplied_components and supplied_components != component_fields:
            missing_components = sorted(component_fields - supplied_components)
            raise TelemetryValidationError(
                "usage component receipt is missing field(s): " + ", ".join(missing_components)
            )
        if supplied_components:
            input_tokens = _required_count(raw.get("input_tokens"), "usage.input_tokens")
            output_tokens = _required_count(raw.get("output_tokens"), "usage.output_tokens")
            cached_input_tokens = _required_count(
                raw.get("cached_input_tokens"), "usage.cached_input_tokens"
            )
            reasoning_tokens = _required_count(
                raw.get("reasoning_tokens"), "usage.reasoning_tokens"
            )
        else:
            # Aggregate-only safe mappings are accepted for projections that have already been
            # validated by the runner. A TokenUsage dataclass always carries all four components.
            input_tokens = None
            output_tokens = None
            cached_input_tokens = None
            reasoning_tokens = None
        total_tokens = _required_count(raw["total_tokens"], "usage.total_tokens")
        if cached_input_tokens is not None and cached_input_tokens > input_tokens:
            raise TelemetryValidationError("usage.cached_input_tokens exceeds input_tokens")
        if reasoning_tokens is not None and reasoning_tokens > output_tokens:
            raise TelemetryValidationError("usage.reasoning_tokens exceeds output_tokens")
        if input_tokens is not None and total_tokens != input_tokens + output_tokens:
            raise TelemetryValidationError(
                "usage.total_tokens must equal input_tokens plus output_tokens"
            )
        if source == "estimated" and raw["exact"]:
            raise TelemetryValidationError("estimated usage cannot be marked exact")
        if source in {"provider_response", "broker_attested"} and not raw["exact"]:
            raise TelemetryValidationError("provider-attested usage must be marked exact")
        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_input_tokens": cached_input_tokens,
            "reasoning_tokens": reasoning_tokens,
            "total_tokens": total_tokens,
            "source": source,
            "exact": raw["exact"],
            "reported_at": _utc_text(raw.get("reported_at"), "usage.reported_at"),
        }

    @staticmethod
    def _refresh_usage_status(connection: sqlite3.Connection, invocation_id: str) -> str:
        rows = connection.execute(
            "SELECT exact, is_final FROM model_usage WHERE invocation_id = ?",
            (invocation_id,),
        ).fetchall()
        if not rows:
            status = "pending"
        else:
            exact_final = any(bool(row["exact"]) and bool(row["is_final"]) for row in rows)
            estimated_final = any(not bool(row["exact"]) and bool(row["is_final"]) for row in rows)
            unfinished = any(not bool(row["is_final"]) for row in rows)
            if exact_final and not estimated_final and not unfinished:
                status = "exact"
            elif estimated_final and not exact_final and not unfinished:
                status = "estimated"
            else:
                status = "partial"
        connection.execute(
            "UPDATE model_invocations SET usage_status = ? WHERE invocation_id = ?",
            (status, invocation_id),
        )
        return status

    def record_model_usage(
        self,
        invocation_id: str,
        request_key: str,
        usage: object,
        *,
        is_final: bool = True,
    ) -> str:
        invocation_id = _identifier(invocation_id, "invocation_id")
        request_key = _identifier(request_key, "request_key")
        if type(is_final) is not bool:
            raise TelemetryValidationError("is_final must be a boolean")
        normalized = self._usage_mapping(usage)
        with self._transaction() as connection:
            invocation = self._invocation(connection, invocation_id)
            if invocation["state"] in TERMINAL_MODEL_STATES:
                raise TelemetryConflictError("cannot record usage for a terminal model invocation")
            run = self._run(connection, str(invocation["run_id"]))
            if normalized["source"] == "synthetic" and run["run_kind"] != "training":
                raise TelemetryValidationError(
                    "synthetic token usage may only be recorded for training runs"
                )
            existing = connection.execute(
                "SELECT * FROM model_usage WHERE invocation_id = ? AND request_key = ?",
                (invocation_id, request_key),
            ).fetchone()
            semantic = (
                normalized["input_tokens"],
                normalized["output_tokens"],
                normalized["cached_input_tokens"],
                normalized["reasoning_tokens"],
                normalized["total_tokens"],
                normalized["source"],
                int(normalized["exact"]),
                int(is_final),
            )
            if existing is not None:
                stored = (
                    existing["input_tokens"],
                    existing["output_tokens"],
                    existing["cached_input_tokens"],
                    existing["reasoning_tokens"],
                    existing["total_tokens"],
                    existing["source"],
                    existing["exact"],
                    existing["is_final"],
                )
                if stored != semantic:
                    raise TelemetryConflictError(
                        "model usage request key is already bound to different usage"
                    )
                return str(invocation["usage_status"])
            connection.execute(
                "INSERT INTO model_usage "
                "(invocation_id, request_key, reported_at, input_tokens, output_tokens, "
                "cached_input_tokens, reasoning_tokens, total_tokens, source, exact, is_final) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    invocation_id,
                    request_key,
                    normalized["reported_at"],
                    normalized["input_tokens"],
                    normalized["output_tokens"],
                    normalized["cached_input_tokens"],
                    normalized["reasoning_tokens"],
                    normalized["total_tokens"],
                    normalized["source"],
                    int(normalized["exact"]),
                    int(is_final),
                ),
            )
            status = self._refresh_usage_status(connection, invocation_id)
            self._append_event(
                connection,
                run_id=str(invocation["run_id"]),
                event_type="model_usage",
                occurred_at=str(normalized["reported_at"]),
                stage=str(run["stage"]),
                detail_json=_safe_detail(
                    {
                        "source": normalized["source"],
                        "total_tokens": normalized["total_tokens"],
                        "exact": normalized["exact"],
                        "usage_status": status,
                    }
                ),
            )
            return status

    def finish_model_invocation(
        self,
        invocation_id: str,
        state: str,
        *,
        exit_code: int | None = None,
        failure_code: str | None = None,
        finished_at: datetime | str | None = None,
    ) -> str:
        invocation_id = _identifier(invocation_id, "invocation_id")
        state = _choice(state, TERMINAL_MODEL_STATES, "state")
        if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
            raise TelemetryValidationError("exit_code must be an integer from -255 to 255")
        failure_code = _code(failure_code, "failure_code")
        timestamp = _utc_text(finished_at, "finished_at")
        with self._transaction() as connection:
            invocation = self._invocation(connection, invocation_id)
            current_state = str(invocation["state"])
            if current_state in TERMINAL_MODEL_STATES:
                existing = (current_state, invocation["exit_code"], invocation["failure_code"])
                requested = (state, exit_code, failure_code)
                if existing != requested:
                    raise TelemetryConflictError(
                        "terminal model outcome conflicts with stored outcome"
                    )
                return str(invocation["usage_status"])
            if state == "succeeded" and invocation["identity_status"] == "mismatch":
                raise TelemetryConflictError("a model identity mismatch cannot succeed")
            usage_status = str(invocation["usage_status"])
            if usage_status == "pending":
                usage_status = "unavailable"
            connection.execute(
                "UPDATE model_invocations SET state = ?, finished_at = ?, exit_code = ?, "
                "failure_code = ?, usage_status = ? WHERE invocation_id = ?",
                (state, timestamp, exit_code, failure_code, usage_status, invocation_id),
            )
            run = self._run(connection, str(invocation["run_id"]))
            self._append_event(
                connection,
                run_id=str(invocation["run_id"]),
                event_type="model_finished",
                occurred_at=timestamp,
                stage=str(run["stage"]),
                detail_json=_safe_detail(
                    {
                        "state": state,
                        "failure_code": failure_code,
                        "usage_status": usage_status,
                    }
                ),
            )
            return usage_status


class TelemetryReader:
    """Physically read-only dashboard view over safe telemetry projections."""

    def __init__(self, state_dir: Path):
        state = state_dir.expanduser()
        try:
            state_info = state.lstat()
        except FileNotFoundError as exc:
            raise TelemetryUnavailableError("telemetry state directory does not exist") from exc
        if (
            not stat.S_ISDIR(state_info.st_mode)
            or state_info.st_uid != os.getuid()
            or stat.S_IMODE(state_info.st_mode) & 0o077
        ):
            raise TelemetryUnavailableError(
                "telemetry state directory must be an owner-only regular directory"
            )
        self.path = state / DATABASE_NAME
        try:
            info = self.path.lstat()
        except FileNotFoundError as exc:
            raise TelemetryUnavailableError("telemetry database does not exist") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise TelemetryUnavailableError("telemetry database must be an owner-only regular file")
        with _close_connection(self._connect()) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != SCHEMA_VERSION:
                raise TelemetryUnavailableError(
                    f"unsupported telemetry schema version {version}; expected {SCHEMA_VERSION}"
                )

    def _connect(self) -> sqlite3.Connection:
        uri = f"file:{quote(str(self.path.resolve()), safe='/')}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
        except sqlite3.Error as exc:
            raise TelemetryUnavailableError("cannot open telemetry database read-only") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=1000")
        return connection

    @staticmethod
    def _limit(value: int) -> int:
        if type(value) is not int or not 1 <= value <= 200:
            raise TelemetryValidationError("limit must be an integer from 1 to 200")
        return value

    @staticmethod
    def _run_kind(value: str) -> str:
        return _choice(value, RUN_KINDS, "run_kind")

    @staticmethod
    def _envelope(run_kind: str | None = None) -> dict[str, Any]:
        envelope: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _utc_text(None, "generated_at"),
        }
        if run_kind is not None:
            envelope["run_kind"] = run_kind
        return envelope

    @staticmethod
    def _safe_run(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "run_kind": row["run_kind"],
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "finished_at": row["finished_at"],
            "stage": row["stage"],
            "terminal": bool(row["terminal"]),
            "repository": row["repository"],
            "issue_number": row["issue_number"],
            "score": row["score"],
            "failure_code": row["failure_code"],
            "safe_status_code": row["safe_status_code"],
            "pr_url": row["pr_url"],
            "budget_window_key": row["budget_window_key"],
            "cleanup_status": row["cleanup_status"],
            "last_event_sequence": row["last_event_sequence"],
        }

    @staticmethod
    def _heartbeat_status(row: sqlite3.Row, now: datetime, stale_after_seconds: int) -> str:
        if row["state"] in TERMINAL_MODEL_STATES:
            return "not_applicable"
        timestamps = [
            value
            for value in (
                row["last_controller_heartbeat_at"],
                row["last_adapter_heartbeat_at"],
            )
            if value is not None
        ]
        if not timestamps:
            return "unknown"
        latest = max(_parse_utc(str(value)) for value in timestamps)
        return "current" if (now - latest).total_seconds() <= stale_after_seconds else "stale"

    @staticmethod
    def _safe_model(row: sqlite3.Row, now: datetime, stale_after_seconds: int) -> dict[str, Any]:
        last_seen_values = [
            value
            for value in (
                row["last_controller_heartbeat_at"],
                row["last_adapter_heartbeat_at"],
            )
            if value is not None
        ]
        return {
            "invocation_id": row["invocation_id"],
            "run_id": row["run_id"],
            "stage": row["stage"],
            "attempt": row["attempt"],
            "backend": row["backend"],
            "expected_provider": row["expected_provider"],
            "expected_model": row["expected_model"],
            "observed_provider": row["observed_provider"],
            "observed_model": row["observed_model"],
            "identity_status": row["identity_status"],
            "identity_source": row["identity_source"],
            "state": row["state"],
            "started_at": row["started_at"],
            "checked_in_at": row["checked_in_at"],
            "last_seen_at": max(last_seen_values) if last_seen_values else None,
            "heartbeat_status": TelemetryReader._heartbeat_status(row, now, stale_after_seconds),
            "finished_at": row["finished_at"],
            "exit_code": row["exit_code"],
            "failure_code": row["failure_code"],
            "usage_status": row["usage_status"],
            "run_token_cap": row["run_token_cap"],
            "known_used_tokens": row["known_used_tokens"],
            "estimated_reported_tokens": row["estimated_reported_tokens"],
        }

    @staticmethod
    def _model_query(where: str) -> str:
        return (
            "SELECT mi.*, "
            "CASE WHEN SUM(CASE WHEN mu.exact = 1 AND mu.is_final = 1 THEN 1 ELSE 0 END) > 0 "
            "THEN SUM(CASE WHEN mu.exact = 1 AND mu.is_final = 1 "
            "THEN mu.total_tokens ELSE 0 END) END AS known_used_tokens, "
            "CASE WHEN SUM(CASE WHEN mu.exact = 0 AND mu.is_final = 1 THEN 1 ELSE 0 END) > 0 "
            "THEN SUM(CASE WHEN mu.exact = 0 AND mu.is_final = 1 "
            "THEN mu.total_tokens ELSE 0 END) END AS estimated_reported_tokens "
            "FROM model_invocations mi JOIN runs r ON r.run_id = mi.run_id "
            "LEFT JOIN model_usage mu ON mu.invocation_id = mi.invocation_id "
            f"WHERE {where} GROUP BY mi.invocation_id "
        )

    def list_runs(self, *, limit: int = 50, run_kind: str = "production") -> dict[str, Any]:
        limit = self._limit(limit)
        run_kind = self._run_kind(run_kind)
        with _close_connection(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM runs WHERE run_kind = ? "
                "ORDER BY started_at DESC, run_id DESC LIMIT ?",
                (run_kind, limit),
            ).fetchall()
        result = self._envelope(run_kind)
        result["runs"] = [self._safe_run(row) for row in rows]
        return result

    def list_models(
        self,
        *,
        limit: int = 50,
        run_kind: str = "production",
        now: datetime | None = None,
        stale_after_seconds: int = 30,
    ) -> dict[str, Any]:
        limit = self._limit(limit)
        run_kind = self._run_kind(run_kind)
        if not 1 <= stale_after_seconds <= 86_400:
            raise TelemetryValidationError("stale_after_seconds must be from 1 to 86400")
        observed = (now or _utc_now()).astimezone(UTC)
        query = self._model_query("r.run_kind = ?") + "ORDER BY mi.started_at DESC LIMIT ?"
        with _close_connection(self._connect()) as connection:
            rows = connection.execute(query, (run_kind, limit)).fetchall()
        result = self._envelope(run_kind)
        result["models"] = [self._safe_model(row, observed, stale_after_seconds) for row in rows]
        return result

    def summary(
        self,
        *,
        run_kind: str = "production",
        now: datetime | None = None,
        stale_after_seconds: int = 30,
    ) -> dict[str, Any]:
        run_kind = self._run_kind(run_kind)
        if not 1 <= stale_after_seconds <= 86_400:
            raise TelemetryValidationError("stale_after_seconds must be from 1 to 86400")
        observed = (now or _utc_now()).astimezone(UTC)
        with _close_connection(self._connect()) as connection:
            budget = connection.execute(
                "SELECT * FROM budget_projections WHERE run_kind = ? "
                "ORDER BY observed_at DESC, projection_sequence DESC LIMIT 1",
                (run_kind,),
            ).fetchone()
            usage_scope = "r.run_kind = ?"
            usage_parameters: tuple[Any, ...] = (run_kind,)
            if budget is not None:
                # A quota projection describes one concrete budget window. Token
                # receipts and run caps must use that same window; otherwise a
                # lifetime total would be compared with a daily or weekly limit.
                usage_scope += " AND r.budget_window_key = ?"
                usage_parameters = (run_kind, budget["window_key"])
            run_counts = connection.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN terminal = 0 THEN 1 ELSE 0 END) AS active, "
                "SUM(CASE WHEN terminal = 1 THEN 1 ELSE 0 END) AS terminal "
                "FROM runs WHERE run_kind = ?",
                (run_kind,),
            ).fetchone()
            usage = connection.execute(
                "SELECT "
                "SUM(CASE WHEN mu.exact = 1 AND mu.is_final = 1 "
                "THEN mu.total_tokens END) AS known, "
                "SUM(CASE WHEN mu.exact = 0 AND mu.is_final = 1 "
                "THEN mu.total_tokens END) AS estimated "
                "FROM model_usage mu "
                "JOIN model_invocations mi ON mi.invocation_id = mu.invocation_id "
                f"JOIN runs r ON r.run_id = mi.run_id WHERE {usage_scope}",
                usage_parameters,
            ).fetchone()
            invocation_counts = connection.execute(
                "SELECT "
                "SUM(CASE WHEN state IN ('succeeded','failed','timed_out','cancelled') "
                "THEN 1 ELSE 0 END) AS finished, "
                "SUM(CASE WHEN state IN ('succeeded','failed','timed_out','cancelled') "
                "AND usage_status = 'exact' THEN 1 ELSE 0 END) AS exact_count, "
                "SUM(CASE WHEN state IN ('succeeded','failed','timed_out','cancelled') "
                "AND usage_status IN ('unavailable','invalid') THEN 1 ELSE 0 END) "
                "AS unknown_count "
                "FROM model_invocations mi JOIN runs r ON r.run_id = mi.run_id "
                f"WHERE {usage_scope}",
                usage_parameters,
            ).fetchone()
            identity_counts = connection.execute(
                "SELECT SUM(CASE WHEN identity_status = 'mismatch' THEN 1 ELSE 0 END) "
                "AS mismatches FROM model_invocations mi "
                "JOIN runs r ON r.run_id = mi.run_id WHERE r.run_kind = ?",
                (run_kind,),
            ).fetchone()
            cap = connection.execute(
                "SELECT SUM(run_cap) AS total_cap, COUNT(*) AS capped_runs FROM ("
                "SELECT r.run_id, MAX(mi.run_token_cap) AS run_cap FROM runs r "
                "JOIN model_invocations mi ON mi.run_id = r.run_id "
                f"WHERE {usage_scope} AND mi.run_token_cap IS NOT NULL GROUP BY r.run_id)",
                usage_parameters,
            ).fetchone()
            latest = connection.execute(
                "SELECT MAX(e.occurred_at) FROM run_events e "
                "JOIN runs r ON r.run_id = e.run_id WHERE r.run_kind = ?",
                (run_kind,),
            ).fetchone()[0]
            active_rows = connection.execute(
                self._model_query(
                    "r.run_kind = ? AND mi.state NOT IN "
                    "('succeeded','failed','timed_out','cancelled')"
                ),
                (run_kind,),
            ).fetchall()
        finished = int(invocation_counts["finished"] or 0)
        exact_count = int(invocation_counts["exact_count"] or 0)
        coverage = exact_count / finished if finished else None
        if coverage is None:
            coverage_status = "unknown"
        elif coverage == 1:
            coverage_status = "complete"
        elif coverage == 0:
            coverage_status = "unavailable"
        else:
            coverage_status = "partial"
        if budget is None:
            maximum_tokens = None
            remaining_tokens = None
            reserve_tokens = None
            reserved_tokens = None
            spendable_tokens = None
            available_tokens = None
            budget_source = None
            budget_observed_at = None
            window_key = None
            reservation_state = None
        else:
            maximum_tokens = budget["maximum_tokens"]
            remaining_tokens = budget["remaining_tokens"]
            reserve_tokens = int(budget["reserve_tokens"])
            reserved_tokens = int(budget["reserved_tokens"])
            spendable_tokens = (
                max(0, int(remaining_tokens) - reserve_tokens)
                if remaining_tokens is not None
                else None
            )
            available_tokens = (
                max(0, spendable_tokens - reserved_tokens) if spendable_tokens is not None else None
            )
            budget_source = budget["source"]
            budget_observed_at = budget["observed_at"]
            window_key = budget["window_key"]
            reservation_state = budget["reservation_state"]
        stale = sum(
            self._heartbeat_status(row, observed, stale_after_seconds) == "stale"
            for row in active_rows
        )
        result = self._envelope(run_kind)
        result.update(
            {
                "latest_event_at": latest,
                "runs": {
                    "total": int(run_counts["total"] or 0),
                    "active": int(run_counts["active"] or 0),
                    "terminal": int(run_counts["terminal"] or 0),
                },
                "tokens": {
                    "scope": "leftovers_observed",
                    "unit": "tokens",
                    "maximum_tokens": maximum_tokens,
                    "remaining_tokens": remaining_tokens,
                    "reserve_tokens": reserve_tokens,
                    "reserved_tokens": reserved_tokens,
                    "spendable_tokens": spendable_tokens,
                    "available_to_reserve_tokens": available_tokens,
                    "known_used_tokens": (
                        int(usage["known"]) if usage["known"] is not None else None
                    ),
                    "estimated_reported_tokens": (
                        int(usage["estimated"]) if usage["estimated"] is not None else None
                    ),
                    "run_cap_tokens": (
                        int(cap["total_cap"]) if cap["total_cap"] is not None else None
                    ),
                    "capped_runs": int(cap["capped_runs"] or 0),
                    "finished_invocations": finished,
                    "exact_invocations": exact_count,
                    "unknown_invocations": int(invocation_counts["unknown_count"] or 0),
                    "usage_coverage": coverage,
                    "usage_coverage_detail": {
                        "status": coverage_status,
                        "percent": round(coverage * 100, 2) if coverage is not None else None,
                        "exact_invocations": exact_count,
                        "finished_invocations": finished,
                    },
                    "window": {
                        "kind": str(window_key).split(":", 1)[0] if window_key else None,
                        "key": window_key,
                        "resets_at": None,
                        "qualified": budget is not None,
                    },
                },
                "budget": {
                    "authority": "non_authoritative_projection",
                    "source": budget_source,
                    "observed_at": budget_observed_at,
                    "reservation_state": reservation_state,
                    "window_key": window_key,
                    "window": {
                        "kind": str(window_key).split(":", 1)[0] if window_key else None,
                        "key": window_key,
                        "resets_at": None,
                        "qualified": budget is not None,
                    },
                    "maximum_tokens": maximum_tokens,
                    "remaining_tokens": remaining_tokens,
                    "reserve_tokens": reserve_tokens,
                    "reserved_tokens": reserved_tokens,
                    "spendable_tokens": spendable_tokens,
                    "available_to_reserve_tokens": available_tokens,
                    "coverage": {
                        "status": coverage_status,
                        "percent": round(coverage * 100, 2) if coverage is not None else None,
                        "exact_invocations": exact_count,
                        "finished_invocations": finished,
                        "exact": coverage == 1 if coverage is not None else None,
                    },
                    "tokens": {
                        "scope": "leftovers_observed",
                        "unit": "tokens",
                        "known_used_tokens": (
                            int(usage["known"]) if usage["known"] is not None else None
                        ),
                        "estimated_reported_tokens": (
                            int(usage["estimated"]) if usage["estimated"] is not None else None
                        ),
                        "run_cap_tokens": (
                            int(cap["total_cap"]) if cap["total_cap"] is not None else None
                        ),
                        "exact_invocations": exact_count,
                        "finished_invocations": finished,
                    },
                },
                "models": {
                    "active": len(active_rows),
                    "stale": stale,
                    "identity_mismatches": int(identity_counts["mismatches"] or 0),
                },
            }
        )
        return result

    def get_run(self, run_id: str, *, run_kind: str = "production") -> dict[str, Any]:
        run_id = _identifier(run_id, "run_id")
        run_kind = self._run_kind(run_kind)
        with _close_connection(self._connect()) as connection:
            run = connection.execute(
                "SELECT * FROM runs WHERE run_id = ? AND run_kind = ?", (run_id, run_kind)
            ).fetchone()
            if run is None:
                raise TelemetryNotFoundError(f"telemetry run {run_id} does not exist")
            events = connection.execute(
                "SELECT sequence, occurred_at, event_type, stage, detail_json "
                "FROM run_events WHERE run_id = ? ORDER BY sequence LIMIT 200",
                (run_id,),
            ).fetchall()
            models = connection.execute(
                self._model_query("mi.run_id = ?") + "ORDER BY mi.started_at",
                (run_id,),
            ).fetchall()
        result = self._envelope(run_kind)
        result["run"] = self._safe_run(run)
        result["events"] = [
            {
                "sequence": row["sequence"],
                "occurred_at": row["occurred_at"],
                "event_type": row["event_type"],
                "stage": row["stage"],
                "detail": json.loads(row["detail_json"]),
            }
            for row in events
        ]
        observed = _utc_now()
        result["models"] = [self._safe_model(row, observed, 30) for row in models]
        return result

    def health(self) -> dict[str, Any]:
        with _close_connection(self._connect()) as connection:
            query_only = int(connection.execute("PRAGMA query_only").fetchone()[0])
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            quick_check = str(connection.execute("PRAGMA quick_check(1)").fetchone()[0])
            latest = connection.execute("SELECT MAX(occurred_at) FROM run_events").fetchone()[0]
        healthy = query_only == 1 and version == SCHEMA_VERSION and quick_check == "ok"
        status = "ok" if healthy else "degraded"
        result = self._envelope()
        result.update(
            {
                "status": status,
                "database": {
                    "readable": True,
                    "query_only": query_only == 1,
                    "schema_version": version,
                    "integrity": quick_check,
                },
                "latest_event_at": latest,
            }
        )
        return result

    def snapshot(
        self,
        *,
        limit: int = 20,
        run_kind: str = "production",
        now: datetime | None = None,
        stale_after_seconds: int = 30,
    ) -> dict[str, Any]:
        limit = self._limit(limit)
        run_kind = self._run_kind(run_kind)
        result = self._envelope(run_kind)
        result["health"] = self.health()
        result["summary"] = self.summary(
            run_kind=run_kind,
            now=now,
            stale_after_seconds=stale_after_seconds,
        )
        result["runs"] = self.list_runs(limit=limit, run_kind=run_kind)["runs"]
        result["models"] = self.list_models(
            limit=limit,
            run_kind=run_kind,
            now=now,
            stale_after_seconds=stale_after_seconds,
        )["models"]
        return result
