from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from leftovers.models import RunStage
from leftovers.rehearsal import (
    REHEARSAL_IMAGE,
    REHEARSAL_MODEL,
    REHEARSAL_PROVIDER,
    REHEARSAL_REPOSITORY,
    REHEARSAL_TEST_COMMAND,
    REHEARSAL_TOTAL_TOKENS,
    RehearsalError,
    RehearsalRunner,
    RehearsalWorkspaceLease,
    build_rehearsal_config,
    run_rehearsal,
    seatbelt_argv,
    verify_audit_journal,
)
from leftovers.telemetry import TelemetryReader

_CONTAINER_MODE = os.environ.get("LEFTOVERS_RUN_CONTAINER_REHEARSAL", "")


class RehearsalTests(unittest.TestCase):
    def test_controller_owned_fixture_has_no_remote_and_reproduces_bug(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with RehearsalWorkspaceLease(root, "fixture-run") as lease:
                workspace = lease.clone(REHEARSAL_REPOSITORY, "main")
                managed_path = lease.path
                remotes = subprocess.run(
                    ["git", "remote", "-v"],
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(remotes.returncode, 0)
                self.assertEqual(remotes.stdout, "")
                reproduction = subprocess.run(
                    list(REHEARSAL_TEST_COMMAND),
                    cwd=workspace,
                    env={
                        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                        "HOME": str(root / "test-home"),
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertNotEqual(reproduction.returncode, 0)
                self.assertIn("terminal escape", reproduction.stderr)
            assert managed_path is not None
            self.assertFalse(managed_path.exists())

    def test_process_rehearsal_runs_full_training_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_rehearsal(Path(directory), mode="process")

            self.assertTrue(report.success)
            self.assertEqual(report.outcome.stage, RunStage.COMPLETE)
            self.assertIsNone(report.outcome.failure_code)
            self.assertEqual(report.mode, "process")
            self.assertIn("supplemental-process-rehearsal", report.assurance)
            self.assertEqual(report.provider, REHEARSAL_PROVIDER)
            self.assertEqual(report.model, REHEARSAL_MODEL)
            self.assertEqual(report.total_tokens, REHEARSAL_TOTAL_TOKENS)
            self.assertLessEqual(report.total_tokens, report.maximum_tokens)
            self.assertEqual(
                tuple(usage.stage for usage in report.usage_by_stage),
                ("planning", "implementation", "review"),
            )
            self.assertTrue(all(usage.usage.exact for usage in report.usage_by_stage))
            self.assertTrue(
                all(usage.usage.source == "synthetic" for usage in report.usage_by_stage)
            )
            self.assertEqual(len(report.model_checkins), 3)
            self.assertTrue(all(check.ok for check in report.checks))
            self.assertIsNone(report.outcome.pr_url)
            self.assertIsNone(report.outcome.branch)
            self.assertNotEqual(report.state_dir.resolve(), report.temp_root.resolve())
            self.assertFalse(list(report.temp_root.glob("leftovers-*")))
            self.assertEqual(stat.S_IMODE(report.report_path.stat().st_mode), 0o600)

            stored = json.loads(report.report_path.read_text(encoding="utf-8"))
            self.assertTrue(stored["success"])
            self.assertEqual(stored["total_tokens"], REHEARSAL_TOTAL_TOKENS)
            records = verify_audit_journal(report.journal_path)
            self.assertIn("cleanup_receipt", {record["event"] for record in records})
            self.assertNotIn("published", {record["event"] for record in records})
            self.assertNotIn("telemetry_degraded", {record["event"] for record in records})

            snapshot = TelemetryReader(report.state_dir).snapshot(run_kind="training")
            summary = snapshot["summary"]
            self.assertEqual(summary["tokens"]["maximum_tokens"], 5_000)
            self.assertEqual(summary["tokens"]["known_used_tokens"], REHEARSAL_TOTAL_TOKENS)
            self.assertEqual(summary["tokens"]["usage_coverage"], 1.0)
            self.assertEqual(summary["budget"]["reservation_state"], "committed")
            self.assertEqual(len(snapshot["models"]), 3)
            self.assertTrue(
                all(model["identity_status"] == "matched" for model in snapshot["models"])
            )

    def test_audit_verifier_rejects_tampered_training_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_rehearsal(Path(directory), mode="process")
            lines = report.journal_path.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["payload"]["run_kind"] = "production"
            lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
            report.journal_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(RehearsalError, "record hash"):
                verify_audit_journal(report.journal_path)

    def test_container_modes_use_rehearsal_image_and_runner_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "repo"
            output = root / "out"
            (workspace / ".git").mkdir(parents=True)
            output.mkdir()
            for mode in ("docker", "podman"):
                with self.subTest(mode=mode):
                    config = build_rehearsal_config(root / mode, mode=mode)
                    runner = RehearsalRunner(config.sandbox, config.agent, mode=mode)
                    argv = runner._container_argv(
                        workspace,
                        output,
                        "rehearsal-run",
                        "implementation",
                        read_only_workspace=False,
                        command=config.agent.command,
                        pass_agent_environment=True,
                    )
                    joined = " ".join(argv)
                    self.assertEqual(argv[0], mode)
                    self.assertIn("--read-only", argv)
                    self.assertIn("--network none", joined)
                    self.assertIn("--cap-drop=ALL", argv)
                    self.assertIn("no-new-privileges=true", joined)
                    self.assertIn("/workspace/.git,ro", joined)
                    self.assertIn("LEFTOVERS_RESULT_PATH=/out/result.json", argv)
                    self.assertIn("LEFTOVERS_TELEMETRY_PATH=/out/telemetry.ndjson", argv)
                    self.assertIn("io.leftovers.job=rehearsal-run", argv)
                    self.assertIn(REHEARSAL_IMAGE, argv)
                    self.assertEqual(
                        argv[-3:],
                        ["/opt/leftovers/rehearsal_agent.py", "--mode", "container"],
                    )
            dockerfile = (
                Path(__file__).resolve().parents[1] / "sandbox" / "Rehearsal.Dockerfile"
            ).read_text(encoding="utf-8")
            self.assertIn("/opt/leftovers/rootfs-write-probe", dockerfile)
            self.assertIn("chmod 0666", dockerfile)

    def test_adapter_refuses_github_credential_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = Path(__file__).resolve().parents[1] / "scripts" / "rehearsal_agent.py"
            result = subprocess.run(
                [sys.executable, str(script), "--mode", "process"],
                cwd=root,
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": str(root),
                    "GITHUB_TOKEN": "test-sentinel",
                    "LEFTOVERS_STAGE": "planning",
                    "LEFTOVERS_RESULT_PATH": str(root / "result.json"),
                    "LEFTOVERS_TELEMETRY_PATH": str(root / "telemetry.ndjson"),
                },
                input='{"no_github_writes": true}',
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden worker environment names", result.stderr)
            self.assertNotIn("test-sentinel", result.stderr)
            self.assertFalse((root / "result.json").exists())
            self.assertFalse((root / "telemetry.ndjson").exists())

    def test_rehearsal_rejects_unsafe_input_and_nonempty_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RehearsalError, "unsafe"):
                build_rehearsal_config(root, mode="docker", image="bad image")
            (root / "occupied").write_text("do not reuse\n", encoding="utf-8")
            with self.assertRaisesRegex(RehearsalError, "new or empty"):
                run_rehearsal(root, mode="process")

    def test_seatbelt_wrapper_is_explicitly_supplemental_and_denies_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            workspaces = root / "workspaces"
            temporary = root / "tmp"
            with patch("leftovers.rehearsal.shutil.which", return_value="/usr/bin/sandbox-exec"):
                argv = seatbelt_argv(
                    root=root,
                    state_dir=state,
                    temp_root=workspaces,
                    tmp_dir=temporary,
                    command=("leftovers-rehearsal",),
                )
            self.assertEqual(argv[0], "/usr/bin/sandbox-exec")
            self.assertIn(f"ROOT_DIR={root}", argv)
            self.assertIn(f"STATE_DIR={state}", argv)
            self.assertIn(f"TEMP_ROOT={workspaces}", argv)
            self.assertIn(f"TMP_DIR={temporary}", argv)
            profile = argv[argv.index("-p") + 1]
            self.assertIn("(deny network*)", profile)
            self.assertIn('(subpath (param "TEMP_ROOT"))', profile)
            self.assertEqual(argv[-1], "leftovers-rehearsal")

    @unittest.skipUnless(
        _CONTAINER_MODE in {"docker", "podman"},
        "set LEFTOVERS_RUN_CONTAINER_REHEARSAL=docker|podman after building the image",
    )
    def test_live_oci_rehearsal(self) -> None:
        image = os.environ.get("LEFTOVERS_REHEARSAL_IMAGE", REHEARSAL_IMAGE)
        with tempfile.TemporaryDirectory() as directory:
            report = run_rehearsal(
                Path(directory),
                mode=_CONTAINER_MODE,  # type: ignore[arg-type]
                image=image,
            )
            self.assertTrue(report.success)
            self.assertEqual(report.assurance, "oci-container-rehearsal")
            self.assertTrue(all(check.ok for check in report.checks))


if __name__ == "__main__":
    unittest.main()
