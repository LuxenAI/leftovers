from __future__ import annotations

import hashlib
import inspect
import ipaddress
import json
import re
import socket
import socketserver
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .audit import redact
from .models import RunStage
from .telemetry import TelemetryNotFoundError, TelemetryReader

_MISSING = object()
_NOT_FOUND = object()
_MAX_API_BYTES = 256 * 1024
_MAX_ASSET_BYTES = 512 * 1024
_MAX_REQUEST_TARGET = 2_048
_MAX_QUERY_BYTES = 256
_MAX_RUNS = 100
_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}")
_ISSUE_REF = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,9}")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}")
_TERMINAL_STAGES = {
    RunStage.COMPLETE.value,
    RunStage.DEFERRED.value,
    RunStage.SKIPPED.value,
    RunStage.FAILED.value,
    RunStage.ABORTED.value,
    RunStage.CLEANUP_PENDING.value,
}
_KNOWN_STAGES = {stage.value for stage in RunStage}
_SECURITY_HEADERS = (
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
)


class DashboardUnavailable(RuntimeError):
    """Raised when safe telemetry cannot be read into a dashboard response."""


def _mapping(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        converted = asdict(value)
        if isinstance(converted, Mapping):
            return converted
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, Mapping):
            return converted
    return {}


def _sequence(value: object) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return value
    return ()


def _first(source: Mapping[str, Any], *keys: str) -> object:
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def _safe_int(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 10**15 else None


def _safe_ratio(value: object, *, ratio: bool = False) -> float | None:
    if type(value) not in {int, float}:
        return None
    number = float(value)
    if ratio:
        number *= 100
    if not 0 <= number <= 100:
        return None
    return round(number, 2)


def _safe_text(value: object, *, maximum: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = redact(value, limit=maximum).strip()
    if (
        not cleaned
        or len(cleaned) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in cleaned)
    ):
        return None
    return cleaned


def _safe_name(value: object) -> str | None:
    text = _safe_text(value)
    return text if text is not None and _SAFE_NAME.fullmatch(text) else None


def _safe_timestamp(value: object) -> str | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value) <= 64:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _safe_enum(value: object, allowed: set[str], default: str = "unknown") -> str:
    return value if isinstance(value, str) and value in allowed else default


def _normalize_usage(source: Mapping[str, Any]) -> dict[str, Any]:
    usage = _mapping(_first(source, "usage", "token_usage"))
    total = _safe_int(_first(usage, "total_tokens", "known_used_tokens"))
    if total is None:
        total = _safe_int(_first(source, "total_tokens", "known_used_tokens"))
    raw_exact = _first(usage, "exact")
    exact = raw_exact if type(raw_exact) is bool else None
    usage_status = _first(source, "usage_status")
    if exact is None and usage_status == "exact":
        exact = True
    elif exact is None and usage_status in {"estimated", "partial"}:
        exact = False
    return {
        "total_tokens": total,
        "source": _safe_name(_first(usage, "source")),
        "exact": exact,
    }


def _normalize_run(value: object, *, implied_kind: str | None = None) -> dict[str, Any] | None:
    source = _mapping(value)
    run_id = _safe_text(_first(source, "run_id", "id"), maximum=64)
    if run_id is None or _RUN_ID.fullmatch(run_id) is None:
        return None
    raw_kind = _first(source, "run_kind", "kind") or implied_kind
    kind = _safe_enum(raw_kind, {"production", "training", "unclassified"})
    if kind == "unknown":
        kind = "unclassified"
    stage = _safe_enum(_first(source, "stage", "state"), _KNOWN_STAGES)
    issue_ref = _safe_text(_first(source, "issue_ref"), maximum=220)
    if issue_ref is None or _ISSUE_REF.fullmatch(issue_ref) is None:
        repository = _safe_text(_first(source, "repository"), maximum=140)
        issue_number = _safe_int(_first(source, "issue_number"))
        issue_ref = (
            f"{repository}#{issue_number}"
            if repository is not None
            and _REPOSITORY.fullmatch(repository)
            and issue_number is not None
            and issue_number > 0
            else None
        )
    return {
        "run_id": run_id,
        "kind": kind,
        "stage": stage,
        "issue_ref": issue_ref,
        "started_at": _safe_timestamp(_first(source, "started_at", "created_at")),
        "updated_at": _safe_timestamp(_first(source, "updated_at", "observed_at")),
        "finished_at": _safe_timestamp(_first(source, "finished_at", "completed_at")),
        "usage": _normalize_usage(source),
    }


def _normalize_runs(value: object, limit: int) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {
        "production": [],
        "training": [],
        "unclassified": [],
    }
    candidates: list[tuple[object, str | None]] = []
    if isinstance(value, Mapping):
        if "runs" in value:
            implied = _safe_enum(
                _first(value, "run_kind", "kind"),
                {"production", "training", "unclassified"},
            )
            implied = "unclassified" if implied == "unknown" else implied
            nested = value["runs"]
            if isinstance(nested, Mapping):
                for group in ("production", "training", "unclassified", "unknown"):
                    for item in _sequence(nested.get(group)):
                        candidates.append((item, "unclassified" if group == "unknown" else group))
            else:
                candidates.extend((item, implied) for item in _sequence(nested))
        else:
            for group in ("production", "training", "unclassified", "unknown"):
                for item in _sequence(value.get(group)):
                    candidates.append((item, "unclassified" if group == "unknown" else group))
    else:
        candidates.extend((item, None) for item in _sequence(value))
    seen: set[str] = set()
    for candidate, implied_kind in candidates[: _MAX_RUNS * 3]:
        normalized = _normalize_run(candidate, implied_kind=implied_kind)
        if normalized is None or normalized["run_id"] in seen:
            continue
        seen.add(normalized["run_id"])
        grouped[normalized["kind"]].append(normalized)
    for values in grouped.values():
        values.sort(
            key=lambda item: item["updated_at"] or item["finished_at"] or item["started_at"] or "",
            reverse=True,
        )
        del values[limit:]
    return grouped


def _normalize_model(value: object, *, implied_kind: str | None = None) -> dict[str, Any] | None:
    source = _mapping(value)
    expected_provider = _safe_name(_first(source, "expected_provider"))
    expected_model = _safe_name(_first(source, "expected_model"))
    observed_provider = _safe_name(_first(source, "observed_provider", "provider"))
    observed_model = _safe_name(_first(source, "observed_model", "model", "model_id"))
    provider = observed_provider or expected_provider
    model = observed_model or expected_model
    if provider is None and model is None:
        return None
    capabilities = []
    for capability in _sequence(_first(source, "capabilities"))[:32]:
        safe = _safe_name(capability)
        if safe is not None and safe not in capabilities:
            capabilities.append(safe)
    fresh_value = _first(source, "fresh")
    heartbeat_status = _safe_enum(
        _first(source, "heartbeat_status"),
        {"current", "stale", "unknown", "not_applicable"},
    )
    freshness = _safe_enum(_first(source, "freshness"), {"fresh", "stale", "unknown"})
    if freshness == "unknown" and type(fresh_value) is bool:
        freshness = "fresh" if fresh_value else "stale"
    if freshness == "unknown" and heartbeat_status in {"current", "stale"}:
        freshness = "fresh" if heartbeat_status == "current" else "stale"
    identity_status = _safe_enum(
        _first(source, "identity_status"), {"matched", "mismatch", "unknown"}
    )
    state = _safe_enum(
        _first(source, "state"),
        {"queued", "starting", "running", "succeeded", "failed", "timed_out", "cancelled"},
    )
    status = _safe_enum(
        _first(source, "status"),
        {"available", "ok", "degraded", "stale", "offline", "unknown"},
    )
    if identity_status == "mismatch":
        status = "degraded"
    elif heartbeat_status == "stale":
        status = "stale"
    elif state in {"failed", "timed_out", "cancelled"}:
        status = "offline"
    elif status == "unknown" and (heartbeat_status == "current" or state == "succeeded"):
        status = "ok"
    return {
        "invocation_id": _safe_text(_first(source, "invocation_id"), maximum=64),
        "provider": provider,
        "model": model,
        "expected_provider": expected_provider,
        "expected_model": expected_model,
        "observed_provider": observed_provider,
        "observed_model": observed_model,
        "identity_status": identity_status,
        "state": state,
        "stage": _safe_enum(_first(source, "stage"), {"planning", "implementation", "review"}),
        "adapter_version": _safe_name(_first(source, "adapter_version")),
        "capabilities": capabilities,
        "checked_in_at": _safe_timestamp(
            _first(source, "checked_in_at", "checkin_at", "last_checkin_at")
        ),
        "heartbeat_at": _safe_timestamp(
            _first(
                source,
                "heartbeat_at",
                "last_heartbeat_at",
                "last_seen_at",
                "observed_at",
            )
        ),
        "freshness": freshness,
        "heartbeat_status": heartbeat_status,
        "status": status,
        "usage": _normalize_usage(source),
        "estimated_reported_tokens": _safe_int(_first(source, "estimated_reported_tokens")),
        "run_token_cap": _safe_int(_first(source, "run_token_cap")),
        "run_id": (
            run_id
            if (run_id := _safe_text(_first(source, "run_id"), maximum=64)) is not None
            and _RUN_ID.fullmatch(run_id)
            else None
        ),
        "kind": _safe_enum(
            _first(source, "run_kind", "kind") or implied_kind,
            {"production", "training", "unclassified"},
        ),
    }


def _normalize_models(value: object, limit: int) -> list[dict[str, Any]]:
    result = []
    seen: set[tuple[str | None, str | None, str | None, str | None]] = set()
    candidates: list[tuple[object, str | None]] = []
    if isinstance(value, Mapping):
        if "models" in value:
            implied = _safe_enum(
                _first(value, "run_kind", "kind"),
                {"production", "training", "unclassified"},
            )
            implied = "unclassified" if implied == "unknown" else implied
            candidates.extend((item, implied) for item in _sequence(value["models"]))
        else:
            for group in ("production", "training", "unclassified"):
                candidates.extend((item, group) for item in _sequence(value.get(group)))
    else:
        candidates.extend((item, None) for item in _sequence(value))
    for candidate, implied_kind in candidates[: _MAX_RUNS * 2]:
        model = _normalize_model(candidate, implied_kind=implied_kind)
        if model is None:
            continue
        identity = (
            model["invocation_id"],
            model["provider"],
            model["model"],
            model["run_id"],
        )
        if identity in seen:
            continue
        seen.add(identity)
        result.append(model)
    result.sort(key=lambda item: (item["provider"] or "", item["model"] or ""))
    return result[:limit]


def _normalize_budget(value: object) -> dict[str, Any]:
    source = _mapping(value)
    budget = _mapping(source.get("budget")) or source
    tokens = _mapping(source.get("tokens")) or _mapping(budget.get("tokens")) or budget
    raw_window = tokens.get("window", budget.get("window"))
    window = _mapping(raw_window)
    if not window and isinstance(raw_window, str):
        window = {"kind": raw_window}
    raw_coverage = _first(tokens, "usage_coverage_detail", "coverage", "usage_coverage")
    if raw_coverage is None:
        raw_coverage = _first(budget, "coverage", "usage_coverage")
    coverage = _mapping(raw_coverage)
    if coverage:
        percent = _safe_ratio(_first(coverage, "percent", "percentage"))
        if percent is None:
            percent = _safe_ratio(_first(coverage, "ratio"), ratio=True)
    else:
        percent = _safe_ratio(raw_coverage, ratio=True)
    coverage_status = _safe_enum(
        _first(coverage, "status"), {"complete", "partial", "unknown", "unavailable"}
    )
    if coverage_status == "unknown" and percent is not None:
        coverage_status = "complete" if percent == 100 else "partial"
    exact_invocations = _safe_int(
        _first(coverage, "exact_invocations", "known_runs", "reported_runs")
    )
    if exact_invocations is None:
        exact_invocations = _safe_int(_first(tokens, "exact_invocations"))
    finished_invocations = _safe_int(_first(coverage, "finished_invocations", "total_runs"))
    if finished_invocations is None:
        finished_invocations = _safe_int(_first(tokens, "finished_invocations"))
    raw_exact = _first(coverage, "exact")
    coverage_exact = raw_exact if type(raw_exact) is bool else None
    if (
        coverage_exact is None
        and exact_invocations is not None
        and finished_invocations is not None
    ):
        coverage_exact = exact_invocations == finished_invocations
    return {
        "window": {
            "kind": _safe_enum(_first(window, "kind", "window"), {"daily", "weekly", "unknown"}),
            "key": _safe_text(_first(window, "key", "window_key"), maximum=128),
            "starts_at": _safe_timestamp(_first(window, "starts_at", "start_at")),
            "resets_at": _safe_timestamp(_first(window, "resets_at", "ends_at", "reset_at")),
            "qualified": (
                qualified
                if type(qualified := _first(window, "qualified", "is_qualified")) is bool
                else None
            ),
        },
        "maximum_tokens": _safe_int(
            _first(
                budget,
                "maximum_tokens",
                "max_tokens",
                "window_maximum_tokens",
                "qualified_maximum_tokens",
            )
        ),
        "remaining_tokens": _safe_int(_first(budget, "remaining_tokens")),
        "reserve_tokens": _safe_int(_first(budget, "reserve_tokens")),
        "reserved_tokens": _safe_int(_first(budget, "reserved_tokens")),
        "known_used_tokens": _safe_int(_first(tokens, "known_used_tokens", "used_tokens")),
        "spendable_tokens": _safe_int(_first(budget, "spendable_tokens")),
        "coverage": {
            "status": coverage_status,
            "percent": percent,
            "exact_invocations": exact_invocations,
            "finished_invocations": finished_invocations,
            "exact": coverage_exact,
        },
        "run_cap_tokens": _safe_int(_first(tokens, "run_cap_tokens")),
        "estimated_reported_tokens": _safe_int(_first(tokens, "estimated_reported_tokens")),
        "scope": _safe_name(_first(tokens, "scope")),
        "unit": _safe_name(_first(tokens, "unit")),
        "authority": _safe_name(_first(budget, "authority")),
    }


def _normalize_health(value: object) -> dict[str, Any]:
    source = _mapping(value)
    status = _safe_enum(
        _first(source, "status"), {"ok", "healthy", "degraded", "unavailable", "unknown"}
    )
    if status == "healthy":
        status = "ok"
    healthy = _first(source, "healthy")
    if status == "unknown" and type(healthy) is bool:
        status = "ok" if healthy else "degraded"
    components = []
    raw_components = source.get("components")
    if isinstance(raw_components, Mapping):
        raw_components = [
            {"name": name, "status": component_status}
            for name, component_status in raw_components.items()
        ]
    for component in _sequence(raw_components)[:32]:
        item = _mapping(component)
        name = _safe_name(_first(item, "name", "component"))
        if name is None:
            continue
        components.append(
            {
                "name": name,
                "status": _safe_enum(
                    _first(item, "status"),
                    {"ok", "degraded", "unavailable", "unknown"},
                ),
                "checked_at": _safe_timestamp(_first(item, "checked_at", "observed_at")),
            }
        )
    raw_database = _mapping(source.get("database"))
    database = {
        "readable": (
            readable if type(readable := _first(raw_database, "readable")) is bool else None
        ),
        "query_only": (
            query_only if type(query_only := _first(raw_database, "query_only")) is bool else None
        ),
        "schema_version": _safe_int(_first(raw_database, "schema_version")),
        "integrity": _safe_enum(_first(raw_database, "integrity"), {"ok", "degraded", "unknown"}),
    }
    if raw_database:
        components.extend(
            (
                {
                    "name": "database_readable",
                    "status": (
                        "ok"
                        if database["readable"] is True
                        else "unavailable"
                        if database["readable"] is False
                        else "unknown"
                    ),
                    "checked_at": None,
                },
                {
                    "name": "database_read_only",
                    "status": (
                        "ok"
                        if database["query_only"] is True
                        else "degraded"
                        if database["query_only"] is False
                        else "unknown"
                    ),
                    "checked_at": None,
                },
                {
                    "name": "database_integrity",
                    "status": database["integrity"],
                    "checked_at": None,
                },
            )
        )
    return {
        "status": status,
        "checked_at": _safe_timestamp(
            _first(source, "checked_at", "observed_at", "latest_event_at")
        ),
        "latest_event_at": _safe_timestamp(_first(source, "latest_event_at")),
        "database": database,
        "components": components,
    }


class DashboardDataAdapter:
    """Allowlist and normalize TelemetryReader output for the untrusted browser boundary."""

    def __init__(self, reader: TelemetryReader | object):
        self.reader = reader
        self._lock = threading.Lock()

    def _call_optional(self, name: str, **kwargs: object) -> object:
        target = getattr(self.reader, name, _MISSING)
        if target is _MISSING:
            return _MISSING
        if name == "snapshot" and isinstance(target, Mapping):
            return target
        if not callable(target):
            raise DashboardUnavailable("telemetry reader interface is invalid")
        try:
            signature = inspect.signature(target)
            accepted: dict[str, object] = {}
            positional: list[object] = []
            has_var_kwargs = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
            for key, value in kwargs.items():
                parameter = signature.parameters.get(key)
                if parameter is not None and parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
                    positional.append(value)
                elif has_var_kwargs or parameter is not None:
                    accepted[key] = value
            return target(*positional, **accepted)
        except TelemetryNotFoundError:
            return _NOT_FOUND
        except DashboardUnavailable:
            raise
        except Exception as exc:
            raise DashboardUnavailable("telemetry read failed") from exc

    def _supports_parameter(self, name: str, parameter_name: str) -> bool:
        target = getattr(self.reader, name, None)
        if not callable(target):
            return False
        try:
            signature = inspect.signature(target)
        except (TypeError, ValueError):
            return False
        return parameter_name in signature.parameters or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )

    @staticmethod
    def _wrapper_items(value: object, key: str) -> list[object]:
        source = _mapping(value)
        nested = source.get(key) if source else value
        return list(_sequence(nested))[:_MAX_RUNS]

    @staticmethod
    def _merge_kind_snapshots(production: object, training: object) -> Mapping[str, Any]:
        production_source = _mapping(production)
        training_source = _mapping(training)
        if not production_source or not training_source:
            raise DashboardUnavailable("telemetry snapshot is unavailable")
        production_runs = DashboardDataAdapter._wrapper_items(production_source, "runs")
        training_runs = DashboardDataAdapter._wrapper_items(training_source, "runs")
        production_models = DashboardDataAdapter._wrapper_items(production_source, "models")
        training_models = DashboardDataAdapter._wrapper_items(training_source, "models")
        return {
            "generated_at": _first(production_source, "generated_at", "observed_at"),
            "summary": _mapping(production_source.get("summary")) or production_source,
            "runs": {
                "production": production_runs,
                "training": training_runs,
            },
            "models": {
                "production": production_models,
                "training": training_models,
            },
            "health": production_source.get("health", {}),
        }

    def snapshot(self, *, limit: int = 24) -> dict[str, Any]:
        if not 1 <= limit <= _MAX_RUNS:
            raise ValueError("limit is out of range")
        with self._lock:
            direct = self._call_optional("snapshot", limit=limit, run_kind="production")
            if direct is not _MISSING:
                if self._supports_parameter("snapshot", "run_kind"):
                    training = self._call_optional("snapshot", limit=limit, run_kind="training")
                    source = self._merge_kind_snapshots(direct, training)
                else:
                    source = _mapping(direct)
                    if not source:
                        raise DashboardUnavailable("telemetry snapshot is unavailable")
            else:
                source_data: dict[str, Any] = {}
                found = False
                summary = self._call_optional("summary", run_kind="production")
                if summary is not _MISSING:
                    source_data["summary"] = summary
                    found = True
                for method, key in (("list_runs", "runs"), ("list_models", "models")):
                    production = self._call_optional(method, limit=limit, run_kind="production")
                    if production is _MISSING:
                        continue
                    found = True
                    if self._supports_parameter(method, "run_kind"):
                        training = self._call_optional(method, limit=limit, run_kind="training")
                        source_data[key] = {
                            "production": self._wrapper_items(production, key),
                            "training": self._wrapper_items(training, key),
                        }
                    else:
                        source_data[key] = production
                health = self._call_optional("health")
                if health is not _MISSING:
                    source_data["health"] = health
                    found = True
                if not found:
                    raise DashboardUnavailable("telemetry reader exposes no safe snapshot")
                source = source_data

            summary_source = _mapping(source.get("summary")) or source
            runs_source = source.get("runs", summary_source.get("runs", ()))
            models_source = source.get("models", summary_source.get("models", ()))
            health_source = source.get("health", summary_source.get("health", {}))
            runs = _normalize_runs(runs_source, limit)
            models = _normalize_models(models_source, limit)
            usage_by_run: dict[str, dict[str, Any]] = {}
            for model in models:
                model_run_id = model["run_id"]
                model_total = model["usage"]["total_tokens"]
                if model_run_id is None or model_total is None:
                    continue
                aggregate = usage_by_run.setdefault(
                    model_run_id,
                    {"total_tokens": 0, "source": "model_receipts", "exact": True},
                )
                aggregate["total_tokens"] += model_total
                if model["usage"]["exact"] is not True:
                    aggregate["exact"] = False
            for group in runs.values():
                for run in group:
                    if run["usage"]["total_tokens"] is None and run["run_id"] in usage_by_run:
                        run["usage"] = usage_by_run[run["run_id"]]
            active = _normalize_run(_first(summary_source, "active_run", "active"))
            if active is None:
                all_runs = runs["production"] + runs["training"] + runs["unclassified"]
                active = next(
                    (item for item in all_runs if item["stage"] not in _TERMINAL_STAGES), None
                )
            elif active["usage"]["total_tokens"] is None and active["run_id"] in usage_by_run:
                active["usage"] = usage_by_run[active["run_id"]]
            return {
                "version": 1,
                "generated_at": _safe_timestamp(
                    _first(summary_source, "latest_event_at")
                    or _first(health_source, "latest_event_at")
                    or _first(source, "generated_at", "observed_at")
                ),
                "budget": _normalize_budget(summary_source),
                "active_run": active,
                "runs": runs,
                "models": models,
                "health": _normalize_health(health_source),
            }

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        if _RUN_ID.fullmatch(run_id) is None:
            return None
        with self._lock:
            kinds = (
                ("production", "training")
                if self._supports_parameter("get_run", "run_kind")
                else ("unclassified",)
            )
            method_present = False
            for kind in kinds:
                direct = self._call_optional("get_run", run_id=run_id, run_kind=kind)
                if direct is _MISSING:
                    continue
                method_present = True
                if direct is _NOT_FOUND:
                    continue
                source = _mapping(direct)
                record = source.get("run") if "run" in source else direct
                if record is None:
                    continue
                normalized = _normalize_run(record, implied_kind=kind)
                if normalized is None or normalized["run_id"] != run_id:
                    raise DashboardUnavailable("telemetry run record is invalid")
                return normalized
            if method_present:
                return None
        snapshot = self.snapshot(limit=_MAX_RUNS)
        for group in snapshot["runs"].values():
            for run in group:
                if run["run_id"] == run_id:
                    return run
        return None


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def process_request(self, request: socket.socket, client_address: tuple[Any, ...]) -> None:
        # Bound slow/incomplete loopback clients so they cannot retain every
        # worker indefinitely. The dashboard is a local monitor, not a streaming
        # protocol, so five seconds is deliberately generous for one request.
        request.settimeout(5.0)
        if not self._request_slots.acquire(blocking=False):  # type: ignore[attr-defined]
            self._reject_overload(request)  # type: ignore[attr-defined]
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()  # type: ignore[attr-defined]
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[Any, ...]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()  # type: ignore[attr-defined]


class DashboardHTTPServer(_BoundedThreadingMixIn, HTTPServer):
    request_queue_size = 16
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        adapter: DashboardDataAdapter,
        *,
        max_workers: int = 4,
    ):
        if not 1 <= max_workers <= 32:
            raise ValueError("max_workers must be between 1 and 32")
        self.adapter = adapter
        self._request_slots = threading.BoundedSemaphore(max_workers)
        self.assets = _load_assets()
        super().__init__(server_address, DashboardRequestHandler)
        address, port = self.server_address[:2]
        self.authority = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

    def _reject_overload(self, request: socket.socket) -> None:
        body = b'{"error":"service unavailable"}'
        try:
            # Never let a client that connected without sending a request line
            # stall the accept loop while all workers are already occupied.
            request.setblocking(False)
            preview = request.recv(16, socket.MSG_PEEK)
            is_head = preview.startswith(b"HEAD ")
        except (BlockingIOError, OSError):
            is_head = False
        lines = [
            b"HTTP/1.1 503 Service Unavailable",
            b"Content-Type: application/json; charset=utf-8",
            b"Cache-Control: no-store",
            b"Connection: close",
            f"Content-Length: {len(body)}".encode(),
            *(f"{name}: {value}".encode() for name, value in _SECURITY_HEADERS),
            b"",
            b"" if is_head else body,
        ]
        with suppress(OSError):
            request.sendall(b"\r\n".join(lines))


class DashboardRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Leftovers-Dashboard"
    sys_version = ""

    @property
    def dashboard_server(self) -> DashboardHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: object) -> None:
        return

    def handle_expect_100(self) -> bool:
        self._send_error(HTTPStatus.EXPECTATION_FAILED, "request body is not accepted")
        return False

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(head=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(head=True)

    def do_POST(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_TRACE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_CONNECT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self.close_connection = True
        self._send_error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed", allow=True)

    def _request_is_local(self) -> bool:
        try:
            return ipaddress.ip_address(self.client_address[0].split("%", 1)[0]).is_loopback
        except ValueError:
            return False

    def _authority_is_valid(self) -> bool:
        hosts = self.headers.get_all("Host", failobj=[])
        if len(hosts) != 1 or hosts[0] != self.dashboard_server.authority:
            return False
        origins = self.headers.get_all("Origin", failobj=[])
        expected_origin = f"http://{self.dashboard_server.authority}"
        return len(origins) <= 1 and (not origins or origins[0] == expected_origin)

    def _parse_target(self) -> tuple[str, dict[str, list[str]]] | None:
        if len(self.path) > _MAX_REQUEST_TARGET or any(ord(char) < 32 for char in self.path):
            return None
        target = urlsplit(self.path)
        if target.scheme or target.netloc or target.fragment or "%" in target.path:
            return None
        if len(target.query) > _MAX_QUERY_BYTES:
            return None
        try:
            query = parse_qs(
                target.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
        except ValueError:
            return None
        if any(len(values) != 1 for values in query.values()):
            return None
        return target.path, query

    def _dispatch(self, *, head: bool) -> None:
        if not self._request_is_local():
            self._send_error(HTTPStatus.FORBIDDEN, "local requests only", head=head)
            return
        if not self._authority_is_valid():
            self._send_error(HTTPStatus.MISDIRECTED_REQUEST, "invalid host", head=head)
            return
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        transfer_encodings = self.headers.get_all("Transfer-Encoding", failobj=[])
        if (
            len(content_lengths) > 1
            or (content_lengths and content_lengths[0] != "0")
            or transfer_encodings
        ):
            self.close_connection = True
            self._send_error(HTTPStatus.BAD_REQUEST, "request body is not accepted", head=head)
            return
        parsed = self._parse_target()
        if parsed is None:
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid request target", head=head)
            return
        path, query = parsed
        if path in {"/", "/index.html"}:
            if query:
                self._send_error(HTTPStatus.BAD_REQUEST, "query not allowed", head=head)
                return
            self._send_asset("index.html", "text/html; charset=utf-8", head=head)
            return
        asset_types = {
            "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        if path in asset_types:
            if query:
                self._send_error(HTTPStatus.BAD_REQUEST, "query not allowed", head=head)
                return
            name, content_type = asset_types[path]
            self._send_asset(name, content_type, head=head)
            return
        if path.startswith("/api/v1/"):
            self._send_api(path, query, head=head)
            return
        self._send_error(HTTPStatus.NOT_FOUND, "not found", head=head)

    @staticmethod
    def _parse_limit(query: Mapping[str, list[str]], allowed: set[str]) -> int | None:
        if set(query) - allowed:
            return None
        raw_limit = query.get("limit", ["24"])[0]
        if not raw_limit.isascii() or not raw_limit.isdigit():
            return None
        limit = int(raw_limit)
        return limit if 1 <= limit <= _MAX_RUNS else None

    def _send_api(self, path: str, query: dict[str, list[str]], *, head: bool) -> None:
        limit = self._parse_limit(query, {"limit", "kind"})
        if limit is None:
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid query", head=head)
            return
        try:
            if path == "/api/v1/snapshot":
                if set(query) - {"limit"}:
                    self._send_error(HTTPStatus.BAD_REQUEST, "invalid query", head=head)
                    return
                payload = self.dashboard_server.adapter.snapshot(limit=limit)
            elif path == "/api/v1/summary":
                if set(query) - {"limit"}:
                    self._send_error(HTTPStatus.BAD_REQUEST, "invalid query", head=head)
                    return
                snapshot = self.dashboard_server.adapter.snapshot(limit=limit)
                payload = {
                    "version": snapshot["version"],
                    "generated_at": snapshot["generated_at"],
                    "budget": snapshot["budget"],
                    "active_run": snapshot["active_run"],
                }
            elif path == "/api/v1/runs":
                kind = query.get("kind", ["all"])[0]
                if kind not in {"all", "production", "training", "unclassified"}:
                    self._send_error(HTTPStatus.BAD_REQUEST, "invalid query", head=head)
                    return
                snapshot = self.dashboard_server.adapter.snapshot(limit=limit)
                groups = snapshot["runs"]
                payload = {
                    "version": snapshot["version"],
                    "runs": groups if kind == "all" else {kind: groups[kind]},
                }
            elif path == "/api/v1/models":
                if set(query) - {"limit"}:
                    self._send_error(HTTPStatus.BAD_REQUEST, "invalid query", head=head)
                    return
                snapshot = self.dashboard_server.adapter.snapshot(limit=limit)
                payload = {"version": snapshot["version"], "models": snapshot["models"]}
            elif path == "/api/v1/health":
                if query:
                    self._send_error(HTTPStatus.BAD_REQUEST, "invalid query", head=head)
                    return
                snapshot = self.dashboard_server.adapter.snapshot(limit=1)
                payload = {"version": snapshot["version"], "health": snapshot["health"]}
            else:
                match = re.fullmatch(r"/api/v1/runs/([A-Za-z0-9_-]{1,64})", path)
                if match is None or query:
                    self._send_error(HTTPStatus.NOT_FOUND, "not found", head=head)
                    return
                run = self.dashboard_server.adapter.get_run(match.group(1))
                if run is None:
                    self._send_error(HTTPStatus.NOT_FOUND, "not found", head=head)
                    return
                payload = {"version": 1, "run": run}
        except DashboardUnavailable:
            self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "service unavailable", head=head)
            return
        except Exception:
            self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "service unavailable", head=head)
            return
        try:
            self._send_json(HTTPStatus.OK, payload, head=head)
        except DashboardUnavailable:
            self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "service unavailable", head=head)

    def _send_asset(self, name: str, content_type: str, *, head: bool) -> None:
        body, etag = self.dashboard_server.assets[name]
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            etag=etag,
            cache_control="private, no-cache, max-age=0",
            head=head,
        )

    def _send_json(self, status: HTTPStatus, payload: object, *, head: bool) -> None:
        try:
            body = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise DashboardUnavailable("dashboard payload is not serializable") from exc
        if len(body) > _MAX_API_BYTES:
            self._send_error(HTTPStatus.SERVICE_UNAVAILABLE, "service unavailable", head=head)
            return
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            etag=_etag(body),
            cache_control="private, no-cache, max-age=0",
            head=head,
        )

    def _send_error(
        self,
        status: HTTPStatus,
        message: str,
        *,
        head: bool = False,
        allow: bool = False,
    ) -> None:
        body = json.dumps({"error": message}, separators=(",", ":")).encode()
        extra = (("Allow", "GET, HEAD"),) if allow else ()
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            cache_control="no-store",
            head=head,
            extra_headers=extra,
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        etag: str | None = None,
        cache_control: str,
        head: bool,
        extra_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        not_modified = (
            status is HTTPStatus.OK
            and etag is not None
            and self.headers.get("If-None-Match") == etag
        )
        self.send_response(HTTPStatus.NOT_MODIFIED if not_modified else status)
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Cache-Control", cache_control)
        if etag is not None:
            self.send_header("ETag", etag)
        for name, value in extra_headers:
            self.send_header(name, value)
        if not not_modified:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head and not not_modified:
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)


def _etag(body: bytes) -> str:
    return f'"sha256-{hashlib.sha256(body).hexdigest()}"'


def _load_assets() -> dict[str, tuple[bytes, str]]:
    assets: dict[str, tuple[bytes, str]] = {}
    root = files("leftovers.dashboard_assets")
    for name in ("index.html", "styles.css", "app.js"):
        body = root.joinpath(name).read_bytes()
        if not body or len(body) > _MAX_ASSET_BYTES:
            raise RuntimeError(f"dashboard asset {name} is missing or oversized")
        assets[name] = (body, _etag(body))
    return assets


def create_dashboard_server(
    reader: TelemetryReader | object,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    max_workers: int = 4,
) -> DashboardHTTPServer:
    """Create a loopback-only, read-only dashboard HTTP server."""

    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("dashboard host must be the literal loopback address 127.0.0.1 or ::1")
    if type(port) is not int or not 0 <= port <= 65_535:
        raise ValueError("dashboard port is out of range")
    server_type = DashboardHTTPServer
    if host == "::1":
        server_type = type(
            "IPv6DashboardHTTPServer",
            (DashboardHTTPServer,),
            {"address_family": socket.AF_INET6},
        )
    return server_type((host, port), DashboardDataAdapter(reader), max_workers=max_workers)


def serve_dashboard(
    reader: TelemetryReader | object,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    max_workers: int = 4,
) -> None:
    """Serve until interrupted; callers own lifecycle and signal handling."""

    with create_dashboard_server(reader, host=host, port=port, max_workers=max_workers) as server:
        server.serve_forever(poll_interval=0.25)
