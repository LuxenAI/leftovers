import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from leftovers.config import AgentConfig, SandboxConfig
from leftovers.models import CommandResult
from leftovers.prompts import RenderedPrompt
from leftovers.runner import (
    AgentOutputError,
    AgentRunner,
    RunnerError,
    _AdapterTelemetryMonitor,
    _validate_agent_payload,
    _validate_json_complexity,
)


class RunnerTests(unittest.TestCase):
    def test_codex_cli_backend_converts_structured_output_and_usage(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        workspace.mkdir()
        subprocess = __import__("subprocess")
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(
                backend="codex-cli",
                command=("codex",),
                provider="openai-codex-cli",
                model="gpt-5.6-luna",
                checkin_required=True,
                usage_reporting_required=True,
            ),
        )
        result_payload = {
            "status": "implemented",
            "summary": "implemented fixture",
            "changed_files": ["example.py"],
            "commands": [],
            "acceptance_criteria": [{"criterion": "works", "evidence": "fixture"}],
            "remaining_risks": [],
            "reason": "",
        }
        captured: dict[str, object] = {}

        def fake_execute(argv: list[str], **kwargs: object) -> CommandResult:
            captured["argv"] = argv
            captured["env"] = kwargs["env"]
            result_path = Path(argv[argv.index("--output-last-message") + 1])
            result_path.write_text(json.dumps(result_payload))
            usage_event = {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 25,
                    "output_tokens": 20,
                    "reasoning_output_tokens": 5,
                },
            }
            return CommandResult(tuple(argv), 0, 0.01, json.dumps(usage_event), "")

        events: list[dict[str, object]] = []
        with (
            mock.patch("leftovers.runner.resolve_codex_executable", return_value="/usr/bin/codex"),
            mock.patch("leftovers.runner.execute", side_effect=fake_execute),
        ):
            result = runner.run_agent(
                "implementation",
                workspace,
                RenderedPrompt("implementation", "task", "0" * 64),
                "run-1",
                read_only_workspace=False,
                telemetry_callback=events.append,
            )
        self.assertEqual(result.status, "implemented")
        self.assertIsNotNone(result.usage)
        assert result.usage is not None
        self.assertEqual(result.usage.total_tokens, 120)
        self.assertEqual([event["type"] for event in events], ["checkin", "usage"])
        argv = captured["argv"]
        self.assertIsInstance(argv, list)
        self.assertIn('default_permissions="leftovers-write"', argv)
        environment = captured["env"]
        self.assertIsInstance(environment, dict)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("CODEX_ACCESS_TOKEN", environment)
        self.assertEqual(Path(environment["HOME"]).name, "codex-agent-home")

    def test_host_agent_git_config_mutation_is_rejected_before_controller_git(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        workspace.mkdir()
        subprocess = __import__("subprocess")
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)

        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",), backend="host"),
        )

        def mutate_config(*args: object, **kwargs: object) -> CommandResult:
            del args, kwargs
            subprocess.run(
                ["git", "config", "diff.evil.textconv", "touch /tmp/never-run"],
                cwd=workspace,
                check=True,
            )
            return CommandResult(("agent",), 0, 0.01, "", "")

        prompt = RenderedPrompt("implementation", "task", "0" * 64)
        with (
            mock.patch("leftovers.runner.execute", side_effect=mutate_config),
            self.assertRaisesRegex(RunnerError, "Git control metadata"),
        ):
            runner.run_agent(
                "implementation",
                workspace,
                prompt,
                "host-run",
                read_only_workspace=False,
            )

    def test_adapter_telemetry_requires_identity_and_exact_token_arithmetic(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        path = root / "telemetry.ndjson"
        observed_at = datetime.now(UTC).isoformat()
        events = [
            {
                "version": 1,
                "sequence": 1,
                "type": "checkin",
                "provider": "fixture",
                "model": "deterministic-v1",
                "adapter_version": "1.0.0",
                "capabilities": ["planning", "usage"],
                "observed_at": observed_at,
            },
            {
                "version": 1,
                "sequence": 2,
                "type": "heartbeat",
                "observed_at": observed_at,
            },
            {
                "version": 1,
                "sequence": 3,
                "type": "usage",
                "input_tokens": 120,
                "output_tokens": 30,
                "cached_input_tokens": 20,
                "reasoning_tokens": 10,
                "total_tokens": 150,
                "source": "synthetic",
                "exact": True,
                "final": True,
                "observed_at": observed_at,
            },
        ]
        import json

        path.write_text("\n".join(json.dumps(event) for event in events))
        agent = AgentConfig(
            command=("agent",),
            provider="fixture",
            model="deterministic-v1",
            checkin_required=True,
            usage_reporting_required=True,
        )
        monitor = _AdapterTelemetryMonitor(path, agent, None, allow_synthetic_usage=True)
        monitor.poll(final=True)
        self.assertIsNotNone(monitor.usage)
        assert monitor.usage is not None
        self.assertEqual(monitor.usage.total_tokens, 150)
        self.assertEqual(monitor.usage.source, "synthetic")

        with self.assertRaisesRegex(AgentOutputError, "explicit training run"):
            _AdapterTelemetryMonitor(path, agent, None).poll(final=True)

    def test_adapter_telemetry_fails_closed_on_model_mismatch_and_sequence_gap(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        path = root / "telemetry.ndjson"
        observed_at = datetime.now(UTC).isoformat()
        import json

        checkin = {
            "version": 1,
            "sequence": 1,
            "type": "checkin",
            "provider": "wrong-provider",
            "model": "deterministic-v1",
            "adapter_version": "1.0.0",
            "capabilities": [],
            "observed_at": observed_at,
        }
        path.write_text(json.dumps(checkin))
        agent = AgentConfig(
            command=("agent",),
            provider="fixture",
            model="deterministic-v1",
        )
        with self.assertRaisesRegex(AgentOutputError, "does not match"):
            _AdapterTelemetryMonitor(path, agent, None).poll(final=True)

        checkin["provider"] = "fixture"
        heartbeat = {
            "version": 1,
            "sequence": 3,
            "type": "heartbeat",
            "observed_at": observed_at,
        }
        path.write_text(json.dumps(checkin) + "\n" + json.dumps(heartbeat))
        with self.assertRaisesRegex(AgentOutputError, "sequence"):
            _AdapterTelemetryMonitor(path, agent, None).poll(final=True)

    def test_required_adapter_telemetry_cannot_be_silently_omitted(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        agent = AgentConfig(
            command=("agent",),
            checkin_required=True,
            usage_reporting_required=True,
        )
        monitor = _AdapterTelemetryMonitor(root / "missing.ndjson", agent, None)
        with self.assertRaisesRegex(AgentOutputError, "check-in"):
            monitor.poll(final=True)

    def test_planning_contract_requires_reproduction_and_root_cause(self) -> None:
        payload = {
            "status": "planned",
            "acceptance_criteria": ["fixed"],
            "steps": ["edit"],
            "tests": [["python", "-m", "pytest"]],
            "risks": [],
            "estimated_remaining_tokens": 1_000,
            "stop_conditions": ["scope expands"],
        }
        with self.assertRaisesRegex(AgentOutputError, "reproduction"):
            _validate_agent_payload("planning", payload)
        payload["reproduction"] = {"argv": ["python", "repro.py"], "observed": "failed"}
        with self.assertRaisesRegex(AgentOutputError, "root-cause"):
            _validate_agent_payload("planning", payload)

    def test_approving_review_refuses_any_remaining_finding(self) -> None:
        payload = {
            "verdict": "approve",
            "findings": [{"severity": "minor", "summary": "edge case", "evidence": "line 10"}],
            "missing_verification": [],
            "pr_claims_supported": True,
        }
        with self.assertRaisesRegex(AgentOutputError, "no unresolved findings"):
            _validate_agent_payload("review", payload)

    def test_review_finding_shape_is_strict(self) -> None:
        payload = {
            "verdict": "revise",
            "findings": ["looks wrong"],
            "missing_verification": [],
            "pr_claims_supported": False,
        }
        with self.assertRaisesRegex(AgentOutputError, "evidence shape"):
            _validate_agent_payload("review", payload)

    def test_agent_json_complexity_is_bounded(self) -> None:
        nested: object = "leaf"
        for _ in range(22):
            nested = {"child": nested}
        with self.assertRaisesRegex(AgentOutputError, "complexity"):
            _validate_json_complexity(nested)
        with self.assertRaisesRegex(AgentOutputError, "non-finite"):
            _validate_json_complexity({"value": float("nan")})

    def test_implementation_contract_requires_evidence(self) -> None:
        payload = {
            "status": "implemented",
            "summary": "changed parser",
            "changed_files": ["parser.py"],
            "commands": [],
            "acceptance_criteria": [],
            "remaining_risks": [],
        }
        with self.assertRaisesRegex(AgentOutputError, "acceptance evidence"):
            _validate_agent_payload("implementation", payload)

    def test_container_command_has_hardening_and_no_github_credential(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        output = root / "out"
        (workspace / ".git").mkdir(parents=True)
        output.mkdir()
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",), pass_environment=("OPENAI_API_KEY",)),
        )
        with mock.patch.dict(
            os.environ, {"OPENAI_API_KEY": "secret", "GITHUB_TOKEN": "must-not-pass"}
        ):
            argv = runner._container_argv(
                workspace,
                output,
                "1234567890abcdef",
                "implementation",
                read_only_workspace=False,
                command=("agent",),
                pass_agent_environment=True,
            )
        joined = " ".join(argv)
        for required in (
            "--read-only",
            "--network none",
            "--cap-drop=ALL",
            "no-new-privileges=true",
            "--pids-limit",
            "--memory",
            "/workspace/.git,ro",
        ):
            self.assertIn(required, joined)
        mounts = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--mount"]
        self.assertIn(f"type=bind,src={workspace.resolve()},dst=/workspace", mounts)
        self.assertIn(f"type=bind,src={output.resolve()},dst=/out", mounts)
        self.assertFalse(any(mount.endswith(",rw") for mount in mounts))
        self.assertIn("OPENAI_API_KEY", argv)
        self.assertIn("LEFTOVERS_TELEMETRY_PATH=/out/telemetry.ndjson", argv)
        self.assertNotIn("GITHUB_TOKEN", joined)
        self.assertNotIn("must-not-pass", joined)

    def test_non_agent_container_does_not_receive_agent_environment(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        output = root / "out"
        workspace.mkdir()
        output.mkdir()
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",), pass_environment=("OPENAI_API_KEY",)),
        )
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "secret"}):
            argv = runner._container_argv(
                workspace,
                output,
                "1234567890abcdef",
                "test-0",
                read_only_workspace=False,
                command=("python", "-m", "pytest"),
                pass_agent_environment=False,
            )
        self.assertNotIn("OPENAI_API_KEY", argv)
        self.assertNotIn("secret", " ".join(argv))

    def test_container_command_carries_cleanup_proof_labels(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        output = root / "out"
        workspace.mkdir()
        output.mkdir()
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",)),
        )
        argv = runner._container_argv(
            workspace,
            output,
            "run-123",
            "planning",
            read_only_workspace=True,
            command=("agent",),
        )
        joined = " ".join(argv)
        self.assertIn("io.leftovers.managed=true", joined)
        self.assertIn("io.leftovers.job=run-123", joined)
        self.assertIn("io.leftovers.stage=planning", joined)
        self.assertIn("io.leftovers.lease_expires=", joined)
        mounts = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--mount"]
        self.assertIn(f"type=bind,src={workspace.resolve()},dst=/workspace,ro", mounts)
        self.assertIn(f"type=bind,src={output.resolve()},dst=/out", mounts)

    def test_failed_container_execution_still_attempts_label_scoped_cleanup(self) -> None:
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",)),
        )
        with (
            mock.patch("leftovers.runner.execute", side_effect=OSError("boom")),
            mock.patch.object(runner, "_remove_container", return_value=True) as cleanup,
            self.assertRaisesRegex(OSError, "boom"),
        ):
            runner._execute_container(
                ["docker", "run"],
                run_id="run-123",
                stage="planning",
                stdin=None,
                timeout=1,
            )
        cleanup.assert_called_once_with("run-123", "planning")

    def test_cleanup_refuses_container_without_exact_ownership_labels(self) -> None:
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",)),
        )
        responses = [
            CompletedProcess([], 0, "abc123\n", ""),
            CompletedProcess(
                [],
                0,
                '[{"Config":{"Labels":{"io.leftovers.managed":"true",'
                '"io.leftovers.job":"another-run",'
                '"io.leftovers.stage":"planning"}}}]',
                "",
            ),
        ]
        with (
            mock.patch.object(runner, "runtime_available", return_value=True),
            mock.patch("leftovers.runner.subprocess.run", side_effect=responses) as run,
        ):
            self.assertFalse(runner._remove_container("run-123", "planning"))
        self.assertFalse(any(call.args[0][1:3] == ["rm", "-f"] for call in run.call_args_list))

    def test_host_agent_cleanup_still_removes_verification_containers(self) -> None:
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",), backend="host"),
        )
        labels = {
            "io.leftovers.managed": "true",
            "io.leftovers.job": "host-run",
            "io.leftovers.stage": "verification-0",
        }
        with (
            mock.patch.object(runner, "_containers_for_job", return_value=["container-1"]),
            mock.patch.object(runner, "_container_labels", return_value=labels),
            mock.patch.object(runner, "_remove_container", return_value=True) as remove,
        ):
            self.assertTrue(runner.cleanup_job("host-run"))

        remove.assert_called_once_with("host-run", "verification-0")

    def test_host_agent_active_jobs_fail_closed_without_container_runtime(self) -> None:
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",), backend="host"),
        )
        with (
            mock.patch.object(runner, "runtime_available", return_value=False),
            self.assertRaisesRegex(RunnerError, "runtime unavailable"),
        ):
            runner.active_job_ids()

    def test_reaper_removes_only_expired_labeled_containers(self) -> None:
        runner = AgentRunner(
            SandboxConfig(runtime="docker", image="image@sha256:abc"),
            AgentConfig(command=("agent",)),
        )
        responses = [
            CompletedProcess([], 0, "expired123\nactive456\n", ""),
            CompletedProcess(
                [],
                0,
                '[{"Config":{"Labels":{"io.leftovers.managed":"true",'
                '"io.leftovers.job":"run-expired",'
                '"io.leftovers.stage":"planning",'
                '"io.leftovers.lease_expires":"99"}}}]',
                "",
            ),
            CompletedProcess([], 0, "", ""),
            CompletedProcess(
                [],
                0,
                '[{"Config":{"Labels":{"io.leftovers.managed":"true",'
                '"io.leftovers.job":"run-active",'
                '"io.leftovers.stage":"planning",'
                '"io.leftovers.lease_expires":"101"}}}]',
                "",
            ),
            CompletedProcess([], 0, "active456\n", ""),
        ]
        with (
            mock.patch.object(runner, "runtime_available", return_value=True),
            mock.patch("leftovers.runner.subprocess.run", side_effect=responses) as run,
        ):
            self.assertEqual(runner.reap_expired_containers(now=100), ["expired123"])
        removal_calls = [
            call.args[0] for call in run.call_args_list if call.args[0][1:3] == ["rm", "-f"]
        ]
        self.assertEqual(removal_calls, [["docker", "rm", "-f", "expired123"]])


if __name__ == "__main__":
    unittest.main()
