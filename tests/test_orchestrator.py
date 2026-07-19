import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from leftovers.config import AppConfig, load_config
from leftovers.github import FixtureIssueSource, GitHubClient
from leftovers.models import AgentResult, CommandResult, FailureCode, RunOutcome, RunStage
from leftovers.orchestrator import (
    ContributionOrchestrator,
    _mark_cleanup_pending,
    _training_rehearsal_component,
)
from leftovers.runner import AgentOutputError, AgentRunner, RunnerCleanupError
from leftovers.workspace import WorkspaceLease


def _passed_command() -> CommandResult:
    return CommandResult(("fixture",), 0, 0.01, "", "")


def _clone_fixture_repository(lease: WorkspaceLease, slug: str, branch: str) -> Path:
    del slug, branch
    assert lease.repo_path is not None
    lease.repo_path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=lease.repo_path, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=lease.repo_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.test"],
        cwd=lease.repo_path,
        check=True,
    )
    (lease.repo_path / "fixture.txt").write_text("before\n")
    subprocess.run(["git", "add", "fixture.txt"], cwd=lease.repo_path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture base"], cwd=lease.repo_path, check=True)
    return lease.repo_path


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
    return replace(
        config,
        state_dir=root / "state",
        temp_root=root / "work",
        budget=budget,
        sandbox=replace(config.sandbox, network="none", timeout_seconds=30),
        agent=replace(
            config.agent,
            provider="leftovers-rehearsal",
            model="deterministic-parser-fixture-v1",
            checkin_required=True,
            usage_reporting_required=True,
            timeout_seconds=30,
            max_repair_cycles=0,
            pass_environment=(),
        ),
        publication=replace(
            config.publication,
            mode="dry-run",
            external_writes_acknowledged=False,
        ),
    )


class _FixtureRunner:
    cleanup_ok = True

    def assert_production_isolation(self) -> str:
        return "fixture-strict-vm"

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


@_training_rehearsal_component("runner")
class _TrainingFixtureRunner(_FixtureRunner):
    """Explicit in-tree-only synthetic runner for rehearsal admission tests."""

    allow_synthetic_usage = True


@_training_rehearsal_component("runner")
class _TestRepairRunner(_TrainingFixtureRunner):
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


@_training_rehearsal_component("source")
class _TrainingFixtureIssueSource(FixtureIssueSource):
    """Explicit in-tree-only source fixture for rehearsal admission tests."""


@_training_rehearsal_component("lease_factory")
class _TrainingFixtureLease(WorkspaceLease):
    """Explicit in-tree-only lease fixture for rehearsal admission tests."""


class OrchestratorTests(unittest.TestCase):
    def test_training_attestation_rejects_a_forged_test_module_name(self) -> None:
        forged = type("ForgedTrainingRunner", (), {"__module__": "tests.forged"})
        with self.assertRaisesRegex(ValueError, "dedicated test components"):
            _training_rehearsal_component("runner")(forged)

    def test_runner_cleanup_failure_bypasses_failed_outcome_conversion(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(load_config(project / "config/leftovers.example.toml"), root)

        @_training_rehearsal_component("runner")
        class CleanupFailingRunner(_TrainingFixtureRunner):
            def run_agent(self, *args: object, **kwargs: object) -> AgentResult:
                del args, kwargs
                raise RunnerCleanupError("could not prove runner cleanup", 4242)

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
            self.assertRaisesRegex(RunnerCleanupError, "could not prove runner cleanup") as raised,
        ):
            ContributionOrchestrator(
                config,
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=CleanupFailingRunner(),
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
            ).run(execute_work=True, publish=False)
        self.assertEqual(raised.exception.process_group, 4242)

    def test_host_agent_is_rejected_before_budget_discovery_or_runtime(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(load_config(project / "config/leftovers.example.toml"), root)
        config = replace(config, agent=replace(config.agent, backend="host"))
        runner = _FixtureRunner()

        with (
            patch.object(runner, "runtime_available") as runtime_available,
            patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot,
            patch.object(
                ContributionOrchestrator,
                "scout",
                side_effect=AssertionError("discovery must not run"),
            ) as scout,
        ):
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=False)

        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertEqual(outcome.failure_code, FailureCode.POLICY_DENIED)
        self.assertIn("agent.backend=host", outcome.message)
        budget_snapshot.assert_not_called()
        scout.assert_not_called()
        runtime_available.assert_not_called()
        self.assertFalse((root / "work").exists())

    def test_network_and_environment_exposure_are_rejected_before_budget(self) -> None:
        project = Path(__file__).resolve().parents[1]
        base = load_config(project / "config/leftovers.example.toml")
        cases = {
            "sandbox bridge": (
                lambda config: replace(config, sandbox=replace(config.sandbox, network="bridge")),
                "sandbox.network must be none",
            ),
            "repository bridge": (
                lambda config: replace(
                    config,
                    repositories=(replace(config.repositories[0], network="bridge"),),
                ),
                "repository network overrides must be none",
            ),
            "host environment": (
                lambda config: replace(
                    config,
                    agent=replace(config.agent, pass_environment=("OPENAI_API_KEY",)),
                ),
                "agent.pass_environment must be empty",
            ),
        }
        for name, (mutate, expected) in cases.items():
            with self.subTest(name=name):
                root = Path(tempfile.mkdtemp())
                self.addCleanup(lambda path=root: __import__("shutil").rmtree(path))
                config = mutate(_test_config(base, root))
                runner = _FixtureRunner()
                with (
                    patch.object(runner, "assert_production_isolation") as assertion,
                    patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot,
                ):
                    outcome = ContributionOrchestrator(
                        config,
                        FixtureIssueSource(project / "examples/issues.json"),
                        runner=runner,
                    ).run(execute_work=True, publish=False)
                self.assertEqual(outcome.stage, RunStage.ABORTED)
                self.assertEqual(outcome.failure_code, FailureCode.POLICY_DENIED)
                self.assertIn(expected, outcome.message)
                assertion.assert_not_called()
                budget_snapshot.assert_not_called()
                self.assertFalse((root / "work").exists())

    def test_ordinary_container_runner_is_rejected_before_budget(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(load_config(project / "config/leftovers.example.toml"), root)
        runner = AgentRunner(config.sandbox, config.agent)

        with patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot:
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
            ).run(execute_work=True, publish=False)

        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertEqual(outcome.failure_code, FailureCode.POLICY_DENIED)
        self.assertIn("agent.backend must be strict-vm", outcome.message)
        budget_snapshot.assert_not_called()
        self.assertFalse((root / "work").exists())

    def test_custom_runner_cannot_self_attest_strict_isolation(self) -> None:
        project = Path(__file__).resolve().parents[1]
        base = load_config(project / "config/leftovers.example.toml")
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        config = _test_config(base, root)

        class FakeStrictRunner:
            def assert_production_isolation(self) -> str:
                raise AssertionError("runner self-attestation must never be consulted")

            def runtime_available(self) -> bool:
                raise AssertionError("runtime must not be consulted")

            def run_agent(self, *args: object, **kwargs: object) -> AgentResult:
                raise AssertionError("agent must not run")

        with (
            patch("leftovers.orchestrator.production_isolation_violations", return_value=()),
            patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot,
            patch.object(
                ContributionOrchestrator,
                "scout",
                side_effect=AssertionError("discovery must not run"),
            ) as scout,
            patch.object(
                WorkspaceLease, "clone", side_effect=AssertionError("workspace must not exist")
            ),
        ):
            outcome = ContributionOrchestrator(
                config,
                FixtureIssueSource(project / "examples/issues.json"),
                runner=FakeStrictRunner(),
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertEqual(outcome.failure_code, FailureCode.POLICY_DENIED)
        self.assertIn(
            "controller-owned strict whole-cycle VM capability is disabled", outcome.message
        )
        budget_snapshot.assert_not_called()
        scout.assert_not_called()
        self.assertFalse((root / "work").exists())

    def test_training_rejects_host_bridge_and_environment_before_budget(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(load_config(project / "config/leftovers.example.toml"), root)
        config = replace(
            config,
            sandbox=replace(config.sandbox, network="bridge"),
            agent=replace(
                config.agent,
                backend="host",
                pass_environment=("TRAINING_FIXTURE",),
            ),
        )
        runner = _TrainingFixtureRunner()

        with (
            patch.object(runner, "runtime_available") as runtime_available,
            patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot,
            patch.object(
                ContributionOrchestrator,
                "scout",
                side_effect=AssertionError("training discovery must not run"),
            ) as scout,
        ):
            outcome = ContributionOrchestrator(
                config,
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
            ).run(execute_work=True, publish=False)

        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertEqual(outcome.failure_code, FailureCode.POLICY_DENIED)
        self.assertIn("training sandbox.network must be none", outcome.message)
        self.assertIn("training agent.pass_environment must be empty", outcome.message)
        budget_snapshot.assert_not_called()
        scout.assert_not_called()
        runtime_available.assert_not_called()

    def test_training_rejects_generic_host_runner_default_lease_and_github_source(self) -> None:
        project = Path(__file__).resolve().parents[1]
        base = load_config(project / "config/leftovers.example.toml")
        cases = (
            (
                "generic host runner",
                lambda config: AgentRunner(
                    replace(config.sandbox, network="none"),
                    replace(config.agent, backend="host"),
                    allow_synthetic_usage=True,
                ),
                lambda config: _TrainingFixtureIssueSource(project / "examples/issues.json"),
                _TrainingFixtureLease,
                "attested deterministic rehearsal runner",
            ),
            (
                "default workspace lease",
                lambda config: _FixtureRunner(),
                lambda config: _TrainingFixtureIssueSource(project / "examples/issues.json"),
                WorkspaceLease,
                "attested deterministic rehearsal lease factory",
            ),
            (
                "GitHub source",
                lambda config: _FixtureRunner(),
                lambda config: GitHubClient(config.github),
                _TrainingFixtureLease,
                "attested deterministic rehearsal issue source",
            ),
        )
        for name, runner_factory, source_factory, lease_factory, expected in cases:
            with self.subTest(name=name):
                root = Path(tempfile.mkdtemp())
                self.addCleanup(lambda path=root: __import__("shutil").rmtree(path))
                config = _test_config(base, root)
                runner = runner_factory(config)
                with (
                    patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot,
                    patch.object(
                        ContributionOrchestrator,
                        "scout",
                        side_effect=AssertionError("training discovery must not run"),
                    ) as scout,
                ):
                    outcome = ContributionOrchestrator(
                        config,
                        source_factory(config),
                        runner=runner,
                        lease_factory=lease_factory,
                        run_kind="training",
                    ).run(execute_work=True, publish=False)
                self.assertEqual(outcome.stage, RunStage.ABORTED)
                self.assertEqual(outcome.failure_code, FailureCode.POLICY_DENIED)
                self.assertIn(expected, outcome.message)
                budget_snapshot.assert_not_called()
                scout.assert_not_called()
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

    def test_training_publish_is_rejected_before_any_publisher_call(self) -> None:
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
        runner = _TrainingFixtureRunner()

        class Publisher:
            def assert_authorized(self, publish_flag: bool) -> None:
                del publish_flag
                raise AssertionError("training must not consult a publisher")

        with patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot:
            outcome = ContributionOrchestrator(
                config,
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
                publisher=Publisher(),
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
            ).run(execute_work=True, publish=True)
        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertIn("training rehearsals can never publish", outcome.message)
        budget_snapshot.assert_not_called()
        self.assertFalse((root / "work").exists())
        records = [
            json.loads(line)
            for line in (root / "state" / "runs" / f"{outcome.run_id}.jsonl")
            .read_text()
            .splitlines()
        ]
        receipts = [record["payload"] for record in records if record["event"] == "cleanup_receipt"]
        self.assertEqual(
            receipts,
            [
                {
                    "containers_removed": True,
                    "local_workspace_removed": True,
                    "resources_acquired": False,
                }
            ],
        )

    def test_complete_dry_run_executes_full_lifecycle_and_cleans_workspace(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = load_config(project / "config/leftovers.example.toml")
        config = _test_config(config, root)

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
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=_TrainingFixtureRunner(),
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.COMPLETE)
        self.assertEqual(outcome.failure_code, None)
        self.assertFalse(any((root / "work").glob("leftovers-*")))

    def test_training_rejects_repair_cycles_before_budget(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = _test_config(
            load_config(project / "config/leftovers.example.toml"),
            root,
        )
        config = replace(config, agent=replace(config.agent, max_repair_cycles=1))
        with patch("leftovers.orchestrator.BudgetGate.snapshot") as budget_snapshot:
            outcome = ContributionOrchestrator(
                config,
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=_TestRepairRunner(),
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.ABORTED)
        self.assertIn("bounded deterministic rehearsal identity", outcome.message)
        budget_snapshot.assert_not_called()

    def test_unproven_container_cleanup_retains_bound_workspace(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        project = Path(__file__).resolve().parents[1]
        config = load_config(project / "config/leftovers.example.toml")
        config = _test_config(config, root)
        runner = _TrainingFixtureRunner()
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
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
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
        runner = _TrainingFixtureRunner()

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
                _TrainingFixtureIssueSource(project / "examples/issues.json"),
                runner=runner,
                lease_factory=_TrainingFixtureLease,
                run_kind="training",
            ).run(execute_work=True, publish=False)
        self.assertEqual(outcome.stage, RunStage.FAILED)
        self.assertEqual(outcome.failure_code, FailureCode.INVALID_OUTPUT)


if __name__ == "__main__":
    unittest.main()
