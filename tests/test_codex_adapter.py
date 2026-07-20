import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from leftovers.codex_adapter import (
    CodexAdapterError,
    build_codex_argv,
    codex_process_environment,
    inspect_codex_cli,
    parse_codex_usage,
    stage_result_schema,
    validate_codex_workspace,
    write_stage_schema,
)


class CodexAdapterTests(unittest.TestCase):
    def test_cli_inspection_requires_current_version_login_and_model(self) -> None:
        probes = [
            CompletedProcess(["codex", "--version"], 0, "codex-cli 0.145.0-alpha.18\n", ""),
            CompletedProcess(["codex", "login", "status"], 0, "logged in\n", ""),
            CompletedProcess(
                ["codex", "debug", "models", "--bundled"],
                0,
                json.dumps({"models": [{"slug": "gpt-5.6-luna"}]}),
                "",
            ),
        ]
        with (
            mock.patch(
                "leftovers.codex_adapter.resolve_codex_executable",
                return_value="/bin/codex",
            ),
            mock.patch("leftovers.codex_adapter._run_codex_probe", side_effect=probes),
        ):
            inspection = inspect_codex_cli("codex", "gpt-5.6-luna")
        self.assertTrue(inspection.ready)
        self.assertEqual(inspection.version, "codex-cli 0.145.0-alpha.18")

    def test_controller_builds_least_privilege_argv(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        workspace.mkdir()
        argv = build_codex_argv(
            "/opt/codex/bin/codex",
            stage="implementation",
            workspace=workspace,
            schema_path=root / "schema.json",
            result_path=root / "result.json",
            model="gpt-5.6-luna",
            read_only_workspace=False,
        )
        joined = "\n".join(argv)
        self.assertNotIn("--sandbox", argv)
        self.assertIn("--ask-for-approval", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("project_doc_max_bytes=0", argv)
        self.assertIn("mcp_servers={}", argv)
        self.assertIn('web_search="disabled"', argv)
        self.assertIn('default_permissions="leftovers-write"', argv)
        self.assertIn('":workspace_roots"={"."="write"', joined)
        self.assertIn('".git"="read"', joined)
        self.assertIn('".agents"="deny"', joined)
        self.assertIn('".codex"="deny"', joined)
        self.assertIn('permissions.leftovers-write.network.enabled=false', argv)
        for feature in ("apps", "hooks", "multi_agent", "remote_plugin"):
            self.assertIn(feature, argv)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)
        self.assertEqual(argv[-1], "-")

    def test_stage_permissions_must_match_stage(self) -> None:
        with self.assertRaisesRegex(CodexAdapterError, "permission do not match"):
            build_codex_argv(
                "codex",
                stage="review",
                workspace=Path("/tmp/repo"),
                schema_path=Path("/tmp/schema"),
                result_path=Path("/tmp/result"),
                model="model",
                read_only_workspace=False,
            )

    def test_codex_process_environment_drops_all_ambient_credentials(self) -> None:
        source = {
            "HOME": "/home/operator",
            "PATH": "/usr/bin",
            "GITHUB_TOKEN": "github-secret",
            "GH_TOKEN": "gh-secret",
            "OPENAI_API_KEY": "api-secret",
            "CODEX_ACCESS_TOKEN": "codex-secret",
            "SSH_AUTH_SOCK": "/tmp/agent.sock",
            "AWS_SECRET_ACCESS_KEY": "cloud-secret",
        }
        with mock.patch.dict(os.environ, source, clear=True):
            environment = codex_process_environment()
        self.assertEqual(environment, {"HOME": "/home/operator", "PATH": "/usr/bin"})
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, source, clear=True):
                isolated = codex_process_environment(Path(directory))
        self.assertEqual(isolated["HOME"], str(Path(directory).resolve()))
        self.assertEqual(isolated["CODEX_HOME"], "/home/operator/.codex")
        self.assertNotIn("GITHUB_TOKEN", isolated)

    def test_repository_local_codex_skills_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            validate_codex_workspace(workspace)
            (workspace / ".agents" / "skills").mkdir(parents=True)
            with self.assertRaisesRegex(CodexAdapterError, "skills are refused"):
                validate_codex_workspace(workspace)

    def test_provider_usage_is_parsed_from_final_jsonl_event(self) -> None:
        output = "\n".join(
            [
                json.dumps({"type": "turn.started"}),
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {
                            "input_tokens": 100,
                            "cached_input_tokens": 40,
                            "output_tokens": 20,
                            "reasoning_output_tokens": 5,
                        },
                    }
                ),
            ]
        )
        usage = parse_codex_usage(output)
        self.assertEqual(usage.total_tokens, 120)
        self.assertEqual(usage.reasoning_tokens, 5)
        self.assertTrue(usage.exact)
        self.assertEqual(usage.source, "provider_response")

    def test_missing_or_invalid_provider_usage_fails_closed(self) -> None:
        with self.assertRaisesRegex(CodexAdapterError, "usage receipt"):
            parse_codex_usage('{"type":"turn.failed"}')
        with self.assertRaisesRegex(CodexAdapterError, "cached input"):
            parse_codex_usage(
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {
                            "input_tokens": 1,
                            "cached_input_tokens": 2,
                            "output_tokens": 1,
                        },
                    }
                )
            )

    def test_stage_schemas_are_closed_and_written_owner_only(self) -> None:
        for stage in ("planning", "implementation", "review"):
            with self.subTest(stage=stage):
                schema = stage_result_schema(stage)
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(set(schema["required"]), set(schema["properties"]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schema.json"
            write_stage_schema(path, "review")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text())["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
