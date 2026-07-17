import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from leftovers.config import AppConfig, load_config
from leftovers.github import FixtureIssueSource
from leftovers.models import AgentResult, CommandResult, FailureCode, RunOutcome, RunStage
from leftovers.orchestrator import ContributionOrchestrator, _mark_cleanup_pending
from leftovers.runner import AgentOutputError, AgentRunner
from leftovers.workspace import WorkspaceLease


def _passed_command() -> CommandResult:
    return CommandResult(("fixture",), 0, 0.01, "", "")


def _test_config(config: AppConfig, root: Path) -> AppConfig:
    now = datetime.now(UTC)
    budget = replace(
        config.budget,
        window="weekly",
        timezone="UTC",
        reset_weekday=(now.weekday() + 1) % 7,
        reset_hour=now.hour,
        max_run_seconds=60,
        reset_safety_seconds=0,
    )
    return replace(config, state_dir=root / "state", temp_root=root / "work", budget=budget)


class _FixtureRunner:
    cleanup_ok = True

    def runtime_available(self) -> bool:
        return True

    def run_agent(
        self,
        stage: str,
        workspace: Path,
        prompt: object,
        run_id: str,
        *,
        read_only_workspace: bool,
        deadline: float | None = None,
        telemetry_callback: object | None = None,
    ) -> AgentResult:
        del prompt, run_id, read_only_workspace, deadline, telemetry_callback
        if stage == "planning":
            payload = {
                "status": "planned",
                "acceptance_criteria": ["regression fixed"],
                "reproduction": {"argv": ["fixture"], "observed": "failed before patch"},
                "root_cause": [{"path": "fixture.txt", "evidence": "stale value"}],
                "steps": ["edit file"],
                "tests": [["fixture"]],
                "risks": [],
                "estimated_remaining_tokens": 1_000,
                "stop_conditions": ["scope expands"],
            }
            return AgentResult(stage, "planned", payload, _passed_command())
        if stage == "implementation":
            (workspace / "fixture.txt").write_text("after\n")
            payload = {
                "status": "implemented",
                "summary": "changed fixture",
                "changed_files": ["fixture.txt"],
                "commands": [],
                "acceptance_criteria": [
                    {"criterion": "regression fixed", "evidence": "fixture changed"}
                ],
                "remaining_risks": [],
            }
            return AgentResult(stage, "implemented", payload, _passed_command())
        if stage == "review":
            payload = {
                "verdict": "approve",
                "findings": [],
                "missing_verification": [],
                "pr_claims_supported": True,
            }
            return AgentResult(stage, "approve", payload, _passed_command())
        raise AssertionError(stage)

    def run_commands(self, *args: object, **kwargs: object) -> list[CommandResult]:
        return [_passed_command()]

    def cleanup_job(self, run_id: str) -> bool:
        del run_id
        return self.cleanup_ok


class _TestRepairRunner(_FixtureRunner):
    def __init__(self) -> None:
        self.test_attempts = 0
        self.implementation_attempts = 0

    def run_agent(self, stage: str, *args: object, **kwargs: object) -> AgentResult:
        if stage == "implementation":
            self.implementation_attempts += 1
        return super().run_agent(stage, *args, **kwargs)

    def run_commands(self, *args: object, **kwargs: object) -> list[CommandResult]:
        del args, kwargs
        self.test_attempts += 1
        if self.test_attempts == 1:
            return [CommandResult(("fixture",), 1, 0.01, "expected after", "failed")]
        return [_passed_command()]


class OrchestratorTests(unittest.TestCase):
    def test_host_agent_execute_preflight_still_requires_verification_runtime(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(load_config(project / "config/leftovers.example.toml"), root)
        config = replace(config, agent=replace(config.agent, backend="host"))
        runner = _FixtureRunner()

        with patch.object(runner, "runtime_available", return_value=False):
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=False)

        self.assertEqual(outcome.stage, RunStage.FAILED)
        self.assertEqual(outcome.failure_code, FailureCode.RUNTIME_UNAVAILABLE)
        self.assertFalse((root / "work").exists())

    def test_production_rejects_a_synthetic_usage_runner(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(load_config(project / "config/leftovers.example.toml"), root)
        runner = AgentRunner(config.sandbox, config.agent, allow_synthetic_usage=True)
        with self.assertRaisesRegex(ValueError, "only be enabled for a training"):
            ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            )

    def test_cleanup_failure_does_not_hide_partial_publication(self) -> None:
        outcome = RunOutcome(
            run_id="a" * 32,
            stage=RunStage.FAILED,
            failure_code=FailureCode.PUBLISH_PARTIAL,
            message="remote publication state is uncertain",
        )
        _mark_cleanup_pending(outcome, "cleanup could not be proven")
        self.assertEqual(outcome.stage, RunStage.CLEANUP_PENDING)
        self.assertEqual(outcome.failure_code, FailureCode.PUBLISH_PARTIAL)
        self.assertIn("remote publication state is uncertain", outcome.message)
        self.assertIn("cleanup could not be proven", outcome.message)

    def test_selection_run_is_read_only_and_picks_eligible_issue(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = load_config(project / "config/leftovers.example.toml")
        config = _test_config(config, root)
        source = FixtureIssueSource(project / "examples/issues.json")
        outcome = ContributionOrchestrator(config, source).run(execute_work=False, publish=False)
        self.assertEqual(outcome.stage, RunStage.SELECTED)
        self.assertEqual(outcome.issue_ref, "example/impactful-project#417")
        self.assertFalse((root / "work").exists())
        self.assertTrue(list((root / "state/runs").glob("*.jsonl")))

    def test_publish_flag_fails_fast_when_configuration_is_dry_run(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(
            load_config(project / "config/leftovers.example.toml"),
            root,
        )
        outcome = ContributionOrchestrator(
            config,
            FixtureIssueSource(project / "examples/issues.json"),
        ).run(execute_work=True, publish=True)
        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertIn("not draft-pr", outcome.message)
        self.assertFalse((root / "work").exists())

    def test_publish_preflight_skips_human_approval_before_agent_work(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(
            load_config(project / "config/leftovers.example.toml"),
            root,
        )
        config = replace(
            config,
            publication=replace(
                config.publication,
                mode="draft-pr",
                external_writes_acknowledged=True,
            ),
            repositories=(replace(config.repositories[0], require_human_approval=True),),
        )
        runner = _FixtureRunner()
        with patch.object(runner, "run_agent", wraps=runner.run_agent) as run_agent:
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=True)
        self.assertEqual(outcome.stage, RunStage.SKIPPED)
        self.assertIn("publication preflight", outcome.message)
        run_agent.assert_not_called()
        self.assertFalse((root / "work").exists())

    def test_complete_dry_run_executes_full_lifecycle_and_cleans_workspace(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = load_config(project / "config/leftovers.example.toml")
        config = _test_config(config, root)
        source = FixtureIssueSource(project / "examples/issues.json")

        def clone(lease: WorkspaceLease, slug: str, branch: str) -> Path:
            del slug, branch
            assert lease.repo_path is not None
            lease.repo_path.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Fixture"], cwd=lease.repo_path, check=True
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.test"],
                cwd=lease.repo_path,
                check=True,
            )
            (lease.repo_path / "fixture.txt").write_text("before\n")
            subprocess.run(["git", "add", "fixture.txt"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "fixture base"], cwd=lease.repo_path, check=True
            )
            return lease.repo_path

        with patch.object(WorkspaceLease, "clone", clone):
            outcome = ContributionOrchestrator(
                config,
                source,
                runner=_FixtureRunner(),
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.COMPLETE)
        self.assertEqual(outcome.failure_code, None)
        self.assertFalse(any((root / "work").glob("leftovers-*")))

    def test_controller_test_failure_gets_one_bounded_repair(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(
            load_config(project / "config/leftovers.example.toml"),
            root,
        )
        runner = _TestRepairRunner()

        def clone(lease: WorkspaceLease, slug: str, branch: str) -> Path:
            del slug, branch
            assert lease.repo_path is not None
            lease.repo_path.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Fixture"], cwd=lease.repo_path, check=True
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.test"],
                cwd=lease.repo_path,
                check=True,
            )
            (lease.repo_path / "fixture.txt").write_text("before\n")
            subprocess.run(["git", "add", "fixture.txt"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "fixture base"], cwd=lease.repo_path, check=True
            )
            return lease.repo_path

        with patch.object(WorkspaceLease, "clone", clone):
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.COMPLETE)
        self.assertEqual(runner.test_attempts, 2)
        self.assertEqual(runner.implementation_attempts, 2)
        self.assertFalse(any((root / "work").glob("leftovers-*")))

    def test_unproven_container_cleanup_retains_bound_workspace(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = load_config(project / "config/leftovers.example.toml")
        config = _test_config(config, root)
        runner = _FixtureRunner()
        runner.cleanup_ok = False

        def clone(lease: WorkspaceLease, slug: str, branch: str) -> Path:
            del slug, branch
            assert lease.repo_path is not None
            lease.repo_path.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Fixture"], cwd=lease.repo_path, check=True
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.test"],
                cwd=lease.repo_path,
                check=True,
            )
            (lease.repo_path / "fixture.txt").write_text("before\n")
            subprocess.run(["git", "add", "fixture.txt"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "fixture base"], cwd=lease.repo_path, check=True
            )
            return lease.repo_path

        with patch.object(WorkspaceLease, "clone", clone):
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.CLEANUP_PENDING)
        self.assertTrue(any((root / "work").glob("leftovers-*")))

    def test_malformed_agent_result_maps_to_invalid_output(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(
            load_config(project / "config/leftovers.example.toml"),
            root,
        )
        runner = _FixtureRunner()

        def clone(lease: WorkspaceLease, slug: str, branch: str) -> Path:
            del slug, branch
            assert lease.repo_path is not None
            lease.repo_path.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Fixture"], cwd=lease.repo_path, check=True
            )
            subprocess.run(
                ["git", "config", "user.email", "fixture@example.test"],
                cwd=lease.repo_path,
                check=True,
            )
            (lease.repo_path / "fixture.txt").write_text("before\n")
            subprocess.run(["git", "add", "fixture.txt"], cwd=lease.repo_path, check=True)
            subprocess.run(
                ["git", "commit", "-qm", "fixture base"], cwd=lease.repo_path, check=True
            )
            return lease.repo_path

        with (
            patch.object(WorkspaceLease, "clone", clone),
            patch.object(
                runner,
                "run_agent",
                side_effect=AgentOutputError("planning result is invalid"),
            ),
        ):
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.FAILED)
        self.assertEqual(outcome.failure_code, FailureCode.INVALID_OUTPUT)


if __name__ == "__main__":
    unittest.main()
