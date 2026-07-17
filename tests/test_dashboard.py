from __future__ import annotations

import http.client
import json
import re
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from leftovers.dashboard import DashboardDataAdapter, create_dashboard_server
from leftovers.telemetry import TelemetryReader, TelemetryWriter

ASSET_ROOT = Path(__file__).parents[1] / "src" / "leftovers" / "dashboard_assets"


def _run(
    run_id: str,
    kind: str,
    stage: str,
    *,
    total_tokens: int | None = 1_200,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "run_kind": kind,
        "stage": stage,
        "issue_ref": "luxenai/leftovers#12",
        "started_at": "2026-07-17T16:00:00Z",
        "updated_at": "2026-07-17T16:05:00Z",
        "usage": {
            "total_tokens": total_tokens,
            "source": "provider_response",
            "exact": True,
            "input_tokens": 900,
            "output_tokens": 300,
            "raw_response": "NEVER_EXPOSE_RAW_RESPONSE",
        },
        "message": "NEVER_EXPOSE_MESSAGE",
        "diff": "NEVER_EXPOSE_DIFF",
    }


def _snapshot() -> dict[str, Any]:
    return {
        "generated_at": "2026-07-17T16:05:30Z",
        "budget": {
            "window": {
                "kind": "daily",
                "key": "2026-07-17",
                "starts_at": "2026-07-17T00:00:00Z",
                "resets_at": "2026-07-18T00:00:00Z",
                "qualified": True,
            },
            "maximum_tokens": 100_000,
            "remaining_tokens": 65_000,
            "reserve_tokens": 10_000,
            "reserved_tokens": 8_000,
            "known_used_tokens": 27_000,
            "spendable_tokens": 55_000,
            "coverage": {
                "status": "partial",
                "percent": 80,
                "exact_invocations": 4,
                "finished_invocations": 5,
                "exact": False,
            },
            "provider_token": "NEVER_EXPOSE_PROVIDER_TOKEN",
        },
        "active_run": _run("prod_active_01", "production", "implementing"),
        "runs": {
            "production": [
                _run("prod_active_01", "production", "implementing"),
                _run("prod_done_01", "production", "complete"),
            ],
            "training": [_run("train_done_01", "training", "complete", total_tokens=None)],
        },
        "models": [
            {
                "provider": "openai",
                "model": "gpt-5.6",
                "adapter_version": "1.2.0",
                "capabilities": ["planning", "coding"],
                "checked_in_at": "2026-07-17T16:00:00Z",
                "heartbeat_at": "2026-07-17T16:05:00Z",
                "freshness": "fresh",
                "status": "available",
                "run_id": "prod_active_01",
                "run_kind": "production",
                "credential": "NEVER_EXPOSE_CREDENTIAL",
            },
            {
                "provider": "synthetic",
                "model": "rehearsal-v1",
                "freshness": "stale",
                "status": "stale",
                "run_id": "train_done_01",
                "run_kind": "training",
            },
        ],
        "health": {
            "status": "degraded",
            "checked_at": "2026-07-17T16:05:00Z",
            "components": [
                {"name": "journal", "status": "ok", "detail": "NEVER_EXPOSE_DETAIL"},
                {"name": "model_checkin", "status": "degraded"},
            ],
            "error": "NEVER_EXPOSE_HEALTH_ERROR",
        },
        "journal": "NEVER_EXPOSE_JOURNAL",
        "prompt": "NEVER_EXPOSE_PROMPT",
    }


class SnapshotReader:
    def __init__(self) -> None:
        self.value = _snapshot()

    def snapshot(self, limit: int = 24) -> dict[str, Any]:
        return self.value


class PropertySnapshotReader:
    snapshot = _snapshot()


class MethodReader:
    def summary(self, run_kind: str = "production") -> dict[str, Any]:
        return {
            "run_kind": run_kind,
            "generated_at": "2026-07-17T16:05:30Z",
            "maximum_tokens": 80_000,
            "remaining_tokens": None,
            "reserve_tokens": 8_000,
            "known_used_tokens": 2_400,
            "usage_coverage": {"status": "complete", "ratio": 1.0},
            "window": {"kind": "weekly", "qualified": None},
        }

    def list_runs(self, limit: int = 50, run_kind: str = "production") -> dict[str, Any]:
        prefix = "prod" if run_kind == "production" else "train"
        return {
            "run_kind": run_kind,
            "runs": [_run(f"{prefix}_wrapped_01", run_kind, "complete")],
        }

    def list_models(self, limit: int = 50, run_kind: str = "production") -> dict[str, Any]:
        return {
            "run_kind": run_kind,
            "models": [
                {
                    "provider": "provider",
                    "model": f"model-{run_kind}",
                    "fresh": run_kind == "production",
                }
            ],
        }

    def get_run(self, run_id: str, run_kind: str = "production") -> dict[str, Any]:
        expected = "prod_wrapped_01" if run_kind == "production" else "train_wrapped_01"
        return {
            "run_kind": run_kind,
            "run": _run(run_id, run_kind, "complete") if run_id == expected else None,
            "events": [{"raw": "NEVER_EXPOSE_EVENT"}],
        }

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "components": {"telemetry": "ok"}}


class ActualShapeReader:
    def snapshot(self, *, limit: int = 20, run_kind: str = "production") -> dict[str, Any]:
        prefix = "prod" if run_kind == "production" else "train"
        return {
            "schema_version": 1,
            "generated_at": "2026-07-17T16:05:30Z",
            "run_kind": run_kind,
            "health": {
                "status": "ok",
                "generated_at": "2026-07-17T16:05:30Z",
                "database": {
                    "readable": True,
                    "query_only": True,
                    "schema_version": 1,
                    "integrity": "ok",
                },
            },
            "summary": {
                "run_kind": run_kind,
                "tokens": {
                    "scope": "leftovers_observed",
                    "unit": "tokens",
                    "maximum_tokens": 120_000,
                    "remaining_tokens": 70_000,
                    "reserve_tokens": 10_000,
                    "reserved_tokens": 5_000,
                    "spendable_tokens": 60_000,
                    "known_used_tokens": 35_000,
                    "estimated_reported_tokens": 900,
                    "run_cap_tokens": 40_000,
                    "usage_coverage_detail": {
                        "status": "partial",
                        "percent": 75.0,
                        "exact_invocations": 3,
                        "finished_invocations": 4,
                    },
                    "window": {
                        "kind": "daily",
                        "key": "daily:2026-07-17",
                        "resets_at": None,
                        "qualified": True,
                    },
                },
                "budget": {
                    "authority": "non_authoritative_projection",
                    "maximum_tokens": 120_000,
                    "remaining_tokens": 70_000,
                    "reserve_tokens": 10_000,
                    "reserved_tokens": 5_000,
                    "spendable_tokens": 60_000,
                },
            },
            "runs": [
                {
                    "run_id": f"{prefix}_actual_01",
                    "run_kind": run_kind,
                    "stage": "implementing" if run_kind == "production" else "complete",
                    "repository": "luxenai/leftovers",
                    "issue_number": 42,
                    "started_at": "2026-07-17T16:00:00Z",
                    "updated_at": "2026-07-17T16:05:00Z",
                }
            ],
            "models": [
                {
                    "invocation_id": f"{prefix}_model_01",
                    "run_id": f"{prefix}_actual_01",
                    "stage": "implementation",
                    "expected_provider": "openai",
                    "expected_model": "gpt-5.6",
                    "observed_provider": "openai",
                    "observed_model": "gpt-5.6",
                    "identity_status": "matched",
                    "state": "running" if run_kind == "production" else "succeeded",
                    "checked_in_at": "2026-07-17T16:00:01Z",
                    "last_seen_at": "2026-07-17T16:05:00Z",
                    "heartbeat_status": "current",
                    "usage_status": "exact",
                    "known_used_tokens": 1_500,
                    "estimated_reported_tokens": None,
                    "run_token_cap": 20_000,
                }
            ],
        }


class ExplodingReader:
    def snapshot(self, limit: int = 24) -> dict[str, Any]:
        raise RuntimeError("SUPER_SECRET_BACKEND_FAILURE")


class BlockingReader:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def snapshot(self, limit: int = 24) -> dict[str, Any]:
        self.entered.set()
        if not self.release.wait(timeout=3):
            raise RuntimeError("test timed out")
        return _snapshot()


@contextmanager
def running_server(reader: object, *, max_workers: int = 4):
    server = create_dashboard_server(reader, port=0, max_workers=max_workers)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    server: Any,
    method: str,
    path: str,
    *,
    host: str | None = None,
    origin: str | None = None,
) -> tuple[http.client.HTTPResponse, bytes]:
    address, port = server.server_address[:2]
    connection = http.client.HTTPConnection(address, port, timeout=3)
    connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    if host is not None:
        connection.putheader("Host", host)
    if origin is not None:
        connection.putheader("Origin", origin)
    connection.endheaders()
    response = connection.getresponse()
    body = response.read()
    connection.close()
    return response, body


class _IdParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name == "id" and value is not None:
                self.ids.add(value)


class DashboardAdapterTests(unittest.TestCase):
    def test_snapshot_normalizes_and_allowlists_fields(self) -> None:
        snapshot = DashboardDataAdapter(SnapshotReader()).snapshot()
        self.assertEqual(snapshot["budget"]["maximum_tokens"], 100_000)
        self.assertEqual(snapshot["budget"]["coverage"]["percent"], 80.0)
        self.assertEqual(snapshot["active_run"]["stage"], "implementing")
        self.assertEqual(len(snapshot["runs"]["production"]), 2)
        self.assertEqual(len(snapshot["runs"]["training"]), 1)
        self.assertEqual(snapshot["models"][0]["freshness"], "fresh")
        encoded = json.dumps(snapshot)
        for forbidden in (
            "NEVER_EXPOSE",
            "diff",
            "prompt",
            "credential",
            "raw_response",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_unknown_numeric_values_remain_null(self) -> None:
        reader = SnapshotReader()
        reader.value["budget"]["remaining_tokens"] = None
        reader.value["budget"]["known_used_tokens"] = "0"
        reader.value["budget"]["coverage"] = {}
        snapshot = DashboardDataAdapter(reader).snapshot()
        self.assertIsNone(snapshot["budget"]["remaining_tokens"])
        self.assertIsNone(snapshot["budget"]["known_used_tokens"])
        self.assertIsNone(snapshot["budget"]["coverage"]["percent"])
        self.assertEqual(snapshot["budget"]["coverage"]["status"], "unknown")

    def test_property_snapshot_is_supported(self) -> None:
        snapshot = DashboardDataAdapter(PropertySnapshotReader()).snapshot(limit=1)
        self.assertEqual(len(snapshot["runs"]["production"]), 1)

    def test_safe_methods_are_composed_for_both_run_kinds(self) -> None:
        adapter = DashboardDataAdapter(MethodReader())
        snapshot = adapter.snapshot()
        self.assertEqual(snapshot["budget"]["maximum_tokens"], 80_000)
        self.assertEqual(snapshot["budget"]["coverage"]["percent"], 100.0)
        self.assertEqual(snapshot["runs"]["production"][0]["run_id"], "prod_wrapped_01")
        self.assertEqual(snapshot["runs"]["training"][0]["run_id"], "train_wrapped_01")
        self.assertEqual(
            {model["kind"] for model in snapshot["models"]},
            {"production", "training"},
        )
        run = adapter.get_run("train_wrapped_01")
        self.assertIsNotNone(run)
        self.assertEqual(run["kind"], "training")
        self.assertNotIn("events", run)

    def test_actual_reader_shape_maps_budget_identity_health_and_issue(self) -> None:
        snapshot = DashboardDataAdapter(ActualShapeReader()).snapshot()
        budget = snapshot["budget"]
        self.assertEqual(budget["maximum_tokens"], 120_000)
        self.assertEqual(budget["known_used_tokens"], 35_000)
        self.assertEqual(budget["coverage"]["percent"], 75.0)
        self.assertEqual(budget["coverage"]["exact_invocations"], 3)
        self.assertEqual(budget["authority"], "non_authoritative_projection")
        self.assertEqual(
            snapshot["runs"]["production"][0]["issue_ref"],
            "luxenai/leftovers#42",
        )
        self.assertEqual(snapshot["runs"]["production"][0]["usage"]["total_tokens"], 1_500)
        self.assertEqual(snapshot["models"][0]["expected_model"], "gpt-5.6")
        self.assertEqual(snapshot["models"][0]["observed_model"], "gpt-5.6")
        self.assertEqual(snapshot["models"][0]["heartbeat_status"], "current")
        self.assertTrue(snapshot["health"]["database"]["query_only"])
        self.assertIn(
            "database_read_only",
            {component["name"] for component in snapshot["health"]["components"]},
        )

    def test_real_telemetry_reader_integration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            writer = TelemetryWriter(state_dir)
            writer.start_run(
                "prod_real_01",
                run_kind="production",
                stage="implementing",
                repository="luxenai/leftovers",
                issue_number=51,
            )
            writer.start_run(
                "train_real_01",
                run_kind="training",
                stage="scheduled",
                repository="luxenai/leftovers",
                issue_number=52,
            )
            writer.finish_run("train_real_01", "complete")
            writer.record_budget_projection(
                "projection_real_01",
                run_kind="production",
                window_key="daily:2026-07-17",
                maximum_tokens=100_000,
                remaining_tokens=70_000,
                reserve_tokens=10_000,
                reserved_tokens=5_000,
                source="environment",
                run_id="prod_real_01",
            )
            invocation_id = writer.start_model_invocation(
                "prod_real_01",
                stage="implementation",
                attempt=0,
                backend="container",
                expected_provider="openai",
                expected_model="gpt-5.6",
                run_token_cap=20_000,
                invocation_id="model_real_01",
            )
            writer.record_model_checkin(
                invocation_id,
                observed_provider="openai",
                observed_model="gpt-5.6",
                source="adapter_reported",
            )
            writer.heartbeat_model(invocation_id, source="controller")
            writer.record_model_usage(
                invocation_id,
                "request_real_01",
                {
                    "input_tokens": 2_000,
                    "output_tokens": 500,
                    "cached_input_tokens": 300,
                    "reasoning_tokens": 100,
                    "total_tokens": 2_500,
                    "source": "provider_response",
                    "exact": True,
                },
            )
            writer.finish_model_invocation(invocation_id, "succeeded", exit_code=0)

            adapter = DashboardDataAdapter(TelemetryReader(state_dir))
            snapshot = adapter.snapshot()
            repeated_snapshot = adapter.snapshot()

        self.assertEqual(snapshot, repeated_snapshot)
        self.assertEqual(snapshot["budget"]["maximum_tokens"], 100_000)
        self.assertEqual(snapshot["budget"]["known_used_tokens"], 2_500)
        self.assertEqual(snapshot["budget"]["coverage"]["status"], "complete")
        self.assertEqual(snapshot["runs"]["production"][0]["issue_ref"], "luxenai/leftovers#51")
        self.assertEqual(snapshot["runs"]["training"][0]["issue_ref"], "luxenai/leftovers#52")
        self.assertEqual(snapshot["models"][0]["identity_status"], "matched")
        self.assertEqual(snapshot["models"][0]["usage"]["total_tokens"], 2_500)
        self.assertTrue(snapshot["health"]["database"]["query_only"])

    def test_invalid_reader_fails_closed(self) -> None:
        with self.assertRaisesRegex(Exception, "telemetry read failed"):
            DashboardDataAdapter(ExplodingReader()).snapshot()
        with self.assertRaisesRegex(Exception, "no safe snapshot"):
            DashboardDataAdapter(object()).snapshot()


class DashboardHTTPTests(unittest.TestCase):
    def test_server_refuses_nonliteral_or_nonloopback_bindings(self) -> None:
        for host in ("localhost", "0.0.0.0", "example.test"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                create_dashboard_server(SnapshotReader(), host=host)
        with self.assertRaises(ValueError):
            create_dashboard_server(SnapshotReader(), max_workers=0)

    def test_snapshot_has_security_headers_and_no_cors(self) -> None:
        with running_server(SnapshotReader()) as server:
            response, body = request(
                server, "GET", "/api/v1/snapshot?limit=10", host=server.authority
            )
        self.assertEqual(response.status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
        self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))
        self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(response.getheader("Referrer-Policy"), "no-referrer")
        self.assertEqual(response.getheader("Cross-Origin-Resource-Policy"), "same-origin")
        self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))
        self.assertNotIn("NEVER_EXPOSE", body.decode())

    def test_exact_host_and_origin_are_enforced(self) -> None:
        with running_server(SnapshotReader()) as server:
            missing, _ = request(server, "GET", "/api/v1/health")
            wrong, _ = request(server, "GET", "/api/v1/health", host="evil.example")
            origin, _ = request(
                server,
                "GET",
                "/api/v1/health",
                host=server.authority,
                origin="https://evil.example",
            )
            correct, _ = request(
                server,
                "GET",
                "/api/v1/health",
                host=server.authority,
                origin=f"http://{server.authority}",
            )
        self.assertEqual(missing.status, 421)
        self.assertEqual(wrong.status, 421)
        self.assertEqual(origin.status, 421)
        self.assertEqual(correct.status, 200)

    def test_head_and_etag_revalidation(self) -> None:
        with running_server(SnapshotReader()) as server:
            head, head_body = request(server, "HEAD", "/", host=server.authority)
            first, first_body = request(server, "GET", "/api/v1/snapshot", host=server.authority)
            etag = first.getheader("ETag")
            address, port = server.server_address[:2]
            connection = http.client.HTTPConnection(address, port, timeout=3)
            connection.request(
                "GET",
                "/api/v1/snapshot",
                headers={"Host": server.authority, "If-None-Match": etag},
            )
            cached = connection.getresponse()
            cached_body = cached.read()
            connection.close()
        self.assertEqual(head.status, 200)
        self.assertEqual(head_body, b"")
        self.assertGreater(int(head.getheader("Content-Length")), 0)
        self.assertEqual(first.status, 200)
        self.assertTrue(first_body)
        self.assertRegex(etag, r'^"sha256-[0-9a-f]{64}"$')
        self.assertEqual(cached.status, 304)
        self.assertEqual(cached_body, b"")
        self.assertEqual(cached.getheader("ETag"), etag)
        self.assertIn("default-src 'none'", cached.getheader("Content-Security-Policy"))

    def test_routes_are_bounded_and_get_head_only(self) -> None:
        with running_server(SnapshotReader()) as server:
            post, _ = request(server, "POST", "/api/v1/health", host=server.authority)
            duplicate, _ = request(
                server, "GET", "/api/v1/runs?limit=1&limit=2", host=server.authority
            )
            too_many, _ = request(server, "GET", "/api/v1/runs?limit=101", host=server.authority)
            unknown, _ = request(server, "GET", "/api/v1/runs?sort=stage", host=server.authority)
            absolute, _ = request(
                server, "GET", "http://evil.example/api/v1/health", host=server.authority
            )
            encoded, _ = request(server, "GET", "/api/v1/runs/%2e%2e", host=server.authority)
            address, port = server.server_address[:2]
            connection = http.client.HTTPConnection(address, port, timeout=3)
            connection.request(
                "GET",
                "/api/v1/health",
                body=b"x",
                headers={"Host": server.authority, "Content-Type": "text/plain"},
            )
            body_request = connection.getresponse()
            body_request.read()
            connection.close()
        self.assertEqual(post.status, 405)
        self.assertEqual(post.getheader("Allow"), "GET, HEAD")
        self.assertEqual(duplicate.status, 400)
        self.assertEqual(too_many.status, 400)
        self.assertEqual(unknown.status, 400)
        self.assertEqual(absolute.status, 400)
        self.assertEqual(encoded.status, 400)
        self.assertEqual(body_request.status, 400)

    def test_summary_runs_models_health_and_run_routes(self) -> None:
        with running_server(SnapshotReader()) as server:
            summary, summary_body = request(server, "GET", "/api/v1/summary", host=server.authority)
            runs, runs_body = request(
                server,
                "GET",
                "/api/v1/runs?kind=training&limit=2",
                host=server.authority,
            )
            models, models_body = request(
                server, "GET", "/api/v1/models?limit=1", host=server.authority
            )
            health, health_body = request(server, "GET", "/api/v1/health", host=server.authority)
            detail, detail_body = request(
                server, "GET", "/api/v1/runs/train_done_01", host=server.authority
            )
            missing, _ = request(
                server, "GET", "/api/v1/runs/does_not_exist", host=server.authority
            )
        self.assertEqual(summary.status, 200)
        self.assertNotIn("runs", json.loads(summary_body))
        self.assertEqual(runs.status, 200)
        self.assertEqual(set(json.loads(runs_body)["runs"]), {"training"})
        self.assertEqual(models.status, 200)
        self.assertEqual(len(json.loads(models_body)["models"]), 1)
        self.assertEqual(health.status, 200)
        self.assertEqual(json.loads(health_body)["health"]["status"], "degraded")
        self.assertEqual(detail.status, 200)
        self.assertEqual(json.loads(detail_body)["run"]["run_id"], "train_done_01")
        self.assertEqual(missing.status, 404)

    def test_reader_failure_is_generic_503(self) -> None:
        with running_server(ExplodingReader()) as server:
            response, body = request(server, "GET", "/api/v1/snapshot", host=server.authority)
        self.assertEqual(response.status, 503)
        self.assertEqual(json.loads(body), {"error": "service unavailable"})
        self.assertNotIn(b"SUPER_SECRET", body)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")

    def test_concurrency_is_bounded_and_overload_returns_503(self) -> None:
        reader = BlockingReader()
        with running_server(reader, max_workers=1) as server:
            first_result: list[int] = []

            def first_request() -> None:
                response, _ = request(server, "GET", "/api/v1/snapshot", host=server.authority)
                first_result.append(response.status)

            thread = threading.Thread(target=first_request)
            thread.start()
            self.assertTrue(reader.entered.wait(timeout=1))
            overloaded, overloaded_body = request(
                server, "GET", "/api/v1/snapshot", host=server.authority
            )
            reader.release.set()
            thread.join(timeout=2)
        self.assertEqual(overloaded.status, 503)
        self.assertEqual(json.loads(overloaded_body), {"error": "service unavailable"})
        self.assertEqual(first_result, [200])

    def test_idle_overload_connection_cannot_stall_accept_loop(self) -> None:
        reader = BlockingReader()
        with running_server(reader, max_workers=1) as server:
            first_result: list[int] = []

            def first_request() -> None:
                response, _ = request(server, "GET", "/api/v1/snapshot", host=server.authority)
                first_result.append(response.status)

            thread = threading.Thread(target=first_request)
            thread.start()
            self.assertTrue(reader.entered.wait(timeout=1))
            address, port = server.server_address[:2]
            with socket.create_connection((address, port), timeout=1) as idle:
                idle.settimeout(1)
                rejection = idle.recv(4_096)
            overloaded, overloaded_body = request(
                server, "GET", "/api/v1/snapshot", host=server.authority
            )
            reader.release.set()
            thread.join(timeout=2)

        self.assertTrue(rejection.startswith(b"HTTP/1.1 503 Service Unavailable"))
        self.assertEqual(overloaded.status, 503)
        self.assertEqual(json.loads(overloaded_body), {"error": "service unavailable"})
        self.assertEqual(first_result, [200])


class DashboardAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (ASSET_ROOT / "index.html").read_text()
        cls.css = (ASSET_ROOT / "styles.css").read_text()
        cls.js = (ASSET_ROOT / "app.js").read_text()

    def test_assets_are_local_csp_compatible_and_dependency_free(self) -> None:
        self.assertNotRegex(self.html, r"<script(?![^>]*\bsrc=)[^>]*>")
        self.assertNotRegex(self.html, r"\sstyle=")
        self.assertNotIn("<svg", self.html.lower())
        self.assertNotRegex(self.html, r"https?://")
        self.assertNotRegex(self.css, r"@import|url\(")
        self.assertNotRegex(self.js, r"\b(?:eval|Function)\s*\(")
        self.assertNotIn("innerHTML", self.js)
        self.assertNotIn("document.write", self.js)
        self.assertNotIn("localStorage", self.js)
        self.assertNotIn("sessionStorage", self.js)
        self.assertNotIn(".style.", self.js)

    def test_javascript_references_existing_static_ids(self) -> None:
        parser = _IdParser()
        parser.feed(self.html)
        literal_references = set(re.findall(r'element\("([A-Za-z0-9_-]+)"\)', self.js))
        self.assertTrue(literal_references)
        self.assertEqual(literal_references - parser.ids, set())

    def test_required_operational_surfaces_are_present(self) -> None:
        for expected in (
            "metric-maximum",
            "metric-remaining",
            "metric-reserve",
            "metric-reserved",
            "metric-used",
            "metric-coverage",
            "active-stage",
            "models-list",
            "production-runs",
            "training-runs",
            "health-status",
        ):
            self.assertIn(f'id="{expected}"', self.html)
        self.assertIn("Unknown values are never treated as zero", self.html)
        self.assertIn('approved: "verify"', self.js)

    def test_responsive_and_accessibility_contract(self) -> None:
        self.assertIn('name="viewport"', self.html)
        self.assertIn('href="#main-content"', self.html)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn('<progress\n            id="usage-progress"', self.html)
        self.assertIn("min-width: 320px", self.css)
        self.assertIn("@media (min-width: 768px)", self.css)
        self.assertIn("1440px", self.css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.css)
        self.assertIn("@media (prefers-color-scheme: dark)", self.css)


if __name__ == "__main__":
    unittest.main()
