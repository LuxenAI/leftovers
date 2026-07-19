from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from leftovers.cli import _doctor, main
from leftovers.runner import RunnerCleanupError


class _FakeRehearsalReport:
    def __init__(self, *, success: bool = True):
        self.success = success

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "run_id": "training_test_01",
            "synthetic": True,
        }


class CliTests(unittest.TestCase):
    def test_doctor_never_treats_oci_rehearsal_as_strict_vm_readiness(self) -> None:
        config = SimpleNamespace(
            agent=SimpleNamespace(backend="container"),
            github=SimpleNamespace(token_env="LEFTOVERS_GITHUB_READ_TOKEN"),
            publication=SimpleNamespace(mode="dry-run"),
            sandbox=SimpleNamespace(
                runtime="docker",
                image="fixture@sha256:" + "a" * 64,
            ),
        )
        with (
            patch("leftovers.cli.shutil.which", return_value="/usr/bin/fixture"),
            patch("leftovers.cli.os.geteuid", return_value=501),
        ):
            ok, checks = _doctor(config)

        strict = next(check for check in checks if check["name"] == "strict_vm_execution")
        self.assertFalse(ok)
        self.assertFalse(strict["ok"])
        self.assertEqual(strict["severity"], "error")

    def test_cleanup_failure_has_machine_readable_nested_process_group(self) -> None:
        stderr = io.StringIO()
        with (
            patch(
                "leftovers.cli.load_config",
                side_effect=RunnerCleanupError("could not prove cleanup", 4242),
            ),
            redirect_stderr(stderr),
        ):
            status = main(["--config", "unused.toml", "validate"])

        self.assertEqual(status, 2)
        self.assertEqual(
            json.loads(stderr.getvalue()),
            {
                "error": "RunnerCleanupError",
                "message": "could not prove cleanup",
                "process_group": 4242,
            },
        )

    def test_cleanup_protects_container_and_reserved_controller_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = SimpleNamespace(
                agent=SimpleNamespace(backend="host"),
                budget=object(),
                sandbox=object(),
                state_dir=root / "state",
                temp_root=root / "workspaces",
            )
            runner = SimpleNamespace(
                active_job_ids=lambda: {"container-run"},
                reap_expired_containers=lambda: [],
                runtime_available=lambda: True,
            )
            ledger = SimpleNamespace(active_run_ids=lambda: {"reserved-run"})
            stdout = io.StringIO()
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch("leftovers.cli.AgentRunner", return_value=runner),
                patch("leftovers.cli.BudgetLedger", return_value=ledger),
                patch("leftovers.cli.reap_expired", return_value=[]) as reap,
                redirect_stdout(stdout),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "cleanup",
                        "--older-than-hours",
                        "1",
                    ]
                )

            self.assertEqual(status, 0)
            reap.assert_called_once_with(
                config.temp_root,
                1,
                protected_run_ids={"container-run", "reserved-run"},
            )

    def test_host_agent_cleanup_refuses_without_verification_runtime(self) -> None:
        config = SimpleNamespace(
            agent=SimpleNamespace(backend="host"),
            budget=object(),
            sandbox=object(),
            state_dir=Path("state"),
            temp_root=Path("workspaces"),
        )
        runner = SimpleNamespace(runtime_available=lambda: False)
        stderr = io.StringIO()
        with (
            patch("leftovers.cli.load_config", return_value=config),
            patch("leftovers.cli.AgentRunner", return_value=runner),
            patch("leftovers.cli.reap_expired") as reap,
            redirect_stderr(stderr),
        ):
            status = main(["--config", "unused.toml", "cleanup"])

        self.assertEqual(status, 2)
        reap.assert_not_called()
        self.assertIn("possibly mounted workspaces", stderr.getvalue())

    def test_dashboard_uses_read_only_reader_and_loopback_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = SimpleNamespace(state_dir=Path(directory) / "state")
            reader = object()
            stderr = io.StringIO()
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch("leftovers.cli.TelemetryReader", return_value=reader) as reader_type,
                patch("leftovers.cli.serve_dashboard", side_effect=KeyboardInterrupt) as serve,
                redirect_stderr(stderr),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "dashboard",
                        "--host",
                        "::1",
                        "--port",
                        "9001",
                        "--workers",
                        "7",
                    ]
                )

            self.assertEqual(status, 130)
            reader_type.assert_called_once_with(config.state_dir)
            serve.assert_called_once_with(reader, host="::1", port=9001, max_workers=7)
            startup = json.loads(stderr.getvalue())
            self.assertEqual(startup["dashboard"], "http://[::1]:9001/")
            self.assertTrue(startup["read_only"])

    def test_training_run_uses_unique_root_and_exports_exact_owner_only_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = SimpleNamespace(state_dir=base / "state")
            exported = base / "reports" / "training.json"
            stdout = io.StringIO()
            report = _FakeRehearsalReport()
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch("leftovers.cli.run_rehearsal", return_value=report) as run,
                redirect_stdout(stdout),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "training-run",
                        "--mode",
                        "process",
                        "--profile",
                        "none",
                        "--report",
                        str(exported),
                    ]
                )

            self.assertEqual(status, 0)
            root = run.call_args.args[0]
            self.assertEqual(root.parent, (config.state_dir / "rehearsals").resolve())
            self.assertRegex(root.name, r"^training-[0-9a-f]{32}$")
            self.assertEqual(run.call_args.kwargs["mode"], "process")
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload, json.loads(exported.read_text(encoding="utf-8")))
            self.assertEqual(payload["execution_profile"], "unsandboxed-process-supplemental")
            self.assertEqual(payload["profile_requested"], "none")
            self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(root.parent.stat().st_mode), 0o700)

    def test_unsuccessful_training_report_uses_nonzero_work_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = SimpleNamespace(state_dir=Path(directory) / "state")
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch(
                    "leftovers.cli.run_rehearsal",
                    return_value=_FakeRehearsalReport(success=False),
                ),
                redirect_stdout(io.StringIO()),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "training-run",
                        "--profile",
                        "none",
                    ]
                )
            self.assertEqual(status, 3)

    def test_seatbelt_profile_fails_closed_when_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = SimpleNamespace(state_dir=Path(directory) / "state")
            stderr = io.StringIO()
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch("leftovers.cli._seatbelt_available", return_value=False),
                patch("leftovers.cli.run_rehearsal") as run,
                redirect_stderr(stderr),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "training-run",
                        "--profile",
                        "seatbelt",
                    ]
                )
            self.assertEqual(status, 2)
            run.assert_not_called()
            error = json.loads(stderr.getvalue())
            self.assertEqual(error["error"], "RehearsalError")
            self.assertNotIn("traceback", stderr.getvalue().lower())

    def test_auto_profile_reexecutes_process_in_seatbelt_and_preserves_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = SimpleNamespace(state_dir=Path(directory) / "state")
            stdout = io.StringIO()
            child = SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "success": True,
                        "execution_profile": "macos-seatbelt-supplemental",
                        "profile_requested": "seatbelt",
                    }
                ),
                stderr="",
            )
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch("leftovers.cli._seatbelt_available", return_value=True),
                patch(
                    "leftovers.cli.seatbelt_argv", return_value=("sandbox-exec", "child")
                ) as wrapper,
                patch("leftovers.cli.subprocess.run", return_value=child) as execute,
                patch("leftovers.cli.run_rehearsal") as run,
                patch.dict(
                    "os.environ",
                    {
                        "PATH": "/usr/bin:/bin",
                        "CODEX_HOME": "/Users/example/.codex",
                        "LEFTOVERS_CODEX_BIN": "/Applications/Codex.app/codex",
                        "GITHUB_TOKEN": "github-secret",
                        "OPENAI_API_KEY": "provider-secret",
                        "AWS_SECRET_ACCESS_KEY": "cloud-secret",
                        "SSH_AUTH_SOCK": "/private/tmp/agent.sock",
                    },
                    clear=True,
                ),
                redirect_stdout(stdout),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "training-run",
                        "--mode",
                        "process",
                        "--profile",
                        "auto",
                    ]
                )

            self.assertEqual(status, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["execution_profile"], "macos-seatbelt-supplemental")
            self.assertEqual(payload["profile_requested"], "auto")
            self.assertIn("Seatbelt", payload["assurance"])
            self.assertIn("OCI", payload["assurance"])
            run.assert_not_called()
            wrapper.assert_called_once()
            self.assertEqual(execute.call_args.args[0], ["sandbox-exec", "child"])
            self.assertEqual(
                execute.call_args.kwargs["env"]["LEFTOVERS_REHEARSAL_SEATBELT_CHILD"],
                "1",
            )
            child_environment = execute.call_args.kwargs["env"]
            self.assertEqual(child_environment["HOME"], child_environment["TMPDIR"])
            for name in (
                "CODEX_HOME",
                "LEFTOVERS_CODEX_BIN",
                "GITHUB_TOKEN",
                "OPENAI_API_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "SSH_AUTH_SOCK",
            ):
                self.assertNotIn(name, child_environment)

    def test_internal_root_is_not_a_public_escape_hatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = SimpleNamespace(state_dir=Path(directory) / "state")
            stderr = io.StringIO()
            with (
                patch("leftovers.cli.load_config", return_value=config),
                patch.dict("os.environ", {}, clear=True),
                redirect_stderr(stderr),
            ):
                status = main(
                    [
                        "--config",
                        "unused.toml",
                        "training-run",
                        "--profile",
                        "none",
                        "--internal-root",
                        str(Path(directory) / "chosen"),
                    ]
                )
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(stderr.getvalue())["error"], "ConfigError")


if __name__ == "__main__":
    unittest.main()
