from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "codex_adapter.py"
SPEC = importlib.util.spec_from_file_location("leftovers_test_codex_adapter", ADAPTER_PATH)
assert SPEC is not None and SPEC.loader is not None
codex_adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codex_adapter)


class CodexAdapterTests(unittest.TestCase):
    def test_stage_schemas_require_every_declared_object_property(self) -> None:
        def visit(value: object) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    self.assertEqual(set(value.get("required", [])), set(properties))
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        for schema_name in codex_adapter.SCHEMAS.values():
            visit(json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8")))

    def test_command_pins_terra_high_and_minimal_workspace_sandbox(self) -> None:
        command = codex_adapter._command(
            Path("/trusted/codex"),
            Path("/trusted/schema.json"),
            Path("/private/result.json"),
            "implementation",
        )
        self.assertEqual(command[:2], ["/trusted/codex", "exec"])
        self.assertIn("gpt-5.6-terra", command)
        self.assertIn('model_reasoning_effort="high"', command)
        self.assertIn('approval_policy="never"', command)
        self.assertIn("sandbox_workspace_write.network_access=false", command)
        self.assertIn('shell_environment_policy.inherit="none"', command)
        self.assertEqual(command[command.index("--sandbox") + 1], "workspace-write")
        self.assertIn("--ephemeral", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ignore-rules", command)
        self.assertNotIn("danger-full-access", command)

        review = codex_adapter._command(
            Path("/trusted/codex"),
            Path("/trusted/schema.json"),
            Path("/private/result.json"),
            "review",
        )
        self.assertEqual(review[review.index("--sandbox") + 1], "read-only")

    def test_version_gate_rejects_old_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "codex"
            binary.write_text("#!/bin/sh\necho 'codex-cli 0.142.4'\n", encoding="utf-8")
            binary.chmod(0o700)
            with self.assertRaisesRegex(codex_adapter.AdapterError, "too old"):
                codex_adapter._codex_version(binary)

    def test_usage_parser_requires_reconciled_final_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {
                            "input_tokens": 1200,
                            "cached_input_tokens": 800,
                            "output_tokens": 300,
                            "reasoning_output_tokens": 100,
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            usage = codex_adapter._usage_from_events(path)
        self.assertEqual(
            usage,
            {
                "input_tokens": 1200,
                "output_tokens": 300,
                "cached_input_tokens": 800,
                "reasoning_tokens": 100,
                "total_tokens": 1500,
            },
        )

    def test_usage_parser_bounds_each_jsonl_line_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_bytes(b"x" * (codex_adapter.MAX_JSONL_LINE_BYTES + 1))

            with self.assertRaisesRegex(codex_adapter.AdapterError, "oversized JSONL event"):
                codex_adapter._usage_from_events(path)

    def test_structured_result_rejects_oversized_and_linked_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized.json"
            with oversized.open("wb") as stream:
                stream.truncate(codex_adapter.MAX_RESULT_BYTES + 1)
            with self.assertRaisesRegex(codex_adapter.AdapterError, "empty or oversized"):
                codex_adapter._load_result(oversized)

            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(codex_adapter.AdapterError, "safe regular"):
                codex_adapter._load_result(linked)

    def test_fake_codex_end_to_end_writes_result_and_exact_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fake = root / "codex"
            fake.write_text(
                """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

if "--version" in sys.argv:
    print("codex-cli 0.145.0")
    raise SystemExit(0)

sys.stdin.read()
output = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
output.write_text(json.dumps({
    "status": "planned",
    "acceptance_criteria": ["focused fix"],
    "reproduction": {"argv": ["python3", "-m", "unittest"], "observed": "fails"},
    "root_cause": [{"path": "module.py", "evidence": "terminal branch drops data"}],
    "steps": ["preserve the terminal value"],
    "tests": [["python3", "-m", "unittest"]],
    "risks": [],
    "estimated_remaining_tokens": 1000,
    "stop_conditions": ["scope expands"]
}))
print(json.dumps({
    "type": "turn.completed",
    "usage": {
        "input_tokens": 100,
        "cached_input_tokens": 20,
        "output_tokens": 30,
        "reasoning_output_tokens": 10
    }
}))
""",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            result = root / "result.json"
            telemetry = root / "telemetry.ndjson"
            environment = {
                **os.environ,
                "LEFTOVERS_STAGE": "planning",
                "LEFTOVERS_RESULT_PATH": str(result),
                "LEFTOVERS_TELEMETRY_PATH": str(telemetry),
                "LEFTOVERS_CODEX_BIN": str(fake),
            }
            completed = subprocess.run(
                [sys.executable, str(ADAPTER_PATH)],
                input=b"Plan the bounded fixture fix.",
                capture_output=True,
                env=environment,
                cwd=ROOT,
                timeout=20,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(json.loads(result.read_text())["status"], "planned")
            events = [json.loads(line) for line in telemetry.read_text().splitlines()]
            self.assertEqual([event["type"] for event in events], ["checkin", "usage"])
            self.assertEqual(events[0]["model"], "gpt-5.6-terra")
            self.assertEqual(events[1]["total_tokens"], 130)
            self.assertTrue(events[1]["exact"])

    def test_stage_timeout_includes_a_blocked_prompt_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            fake = root / "codex"
            fake.write_text(
                """#!/usr/bin/env python3
import sys
import time
import signal

if "--version" in sys.argv:
    print("codex-cli 0.145.0")
    raise SystemExit(0)
signal.signal(signal.SIGINT, signal.SIG_IGN)
time.sleep(30)
""",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            result = root / "result.json"
            telemetry = root / "telemetry.ndjson"
            prompt = root / "prompt"
            prompt.write_bytes(b"x" * codex_adapter.MAX_PROMPT_BYTES)
            with prompt.open("rb") as stream:

                class BinaryInput:
                    buffer = stream

                started = time.monotonic()
                with (
                    patch.dict(
                        os.environ,
                        {
                            "LEFTOVERS_STAGE": "planning",
                            "LEFTOVERS_RESULT_PATH": str(result),
                            "LEFTOVERS_TELEMETRY_PATH": str(telemetry),
                            "LEFTOVERS_CODEX_BIN": str(fake),
                        },
                        clear=False,
                    ),
                    patch.object(codex_adapter, "STAGE_TIMEOUTS", {"planning": 1}),
                    patch.object(codex_adapter.sys, "stdin", BinaryInput()),
                    self.assertRaises(codex_adapter.AdapterError),
                ):
                    codex_adapter.main()

            self.assertLess(time.monotonic() - started, 6)
            self.assertFalse(result.exists())

    def test_fast_exit_still_rejects_oversized_events_and_diagnostics(self) -> None:
        cases = (
            (1, codex_adapter.MAX_EVENT_BYTES, "JSONL output exceeded"),
            (2, codex_adapter.MAX_DIAGNOSTIC_BYTES, "diagnostics exceeded"),
        )
        for descriptor, maximum_bytes, expected in cases:
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                os.chmod(root, 0o700)
                fake = root / "codex"
                fake.write_text(
                    f"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

if "--version" in sys.argv:
    print("codex-cli 0.145.0")
    raise SystemExit(0)

sys.stdin.read()
output = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
output.write_text("{{}}\\n")
if {descriptor} == 1:
    os.ftruncate(1, {maximum_bytes + 1})
else:
    print(json.dumps({{
        "type": "turn.completed",
        "usage": {{
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0
        }}
    }}))
    sys.stdout.flush()
    os.ftruncate(2, {maximum_bytes + 1})
""",
                    encoding="utf-8",
                )
                fake.chmod(0o700)
                result = root / "result.json"
                telemetry = root / "telemetry.ndjson"
                completed = subprocess.run(
                    [sys.executable, str(ADAPTER_PATH)],
                    input=b"Plan a bounded fixture.",
                    capture_output=True,
                    env={
                        **os.environ,
                        "LEFTOVERS_STAGE": "planning",
                        "LEFTOVERS_RESULT_PATH": str(result),
                        "LEFTOVERS_TELEMETRY_PATH": str(telemetry),
                        "LEFTOVERS_CODEX_BIN": str(fake),
                    },
                    cwd=ROOT,
                    timeout=20,
                    check=False,
                )

                self.assertEqual(completed.returncode, 2)
                self.assertIn(expected, completed.stderr.decode())
                self.assertFalse(result.exists())

    def test_stage_timeout_includes_stalled_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = root / "result.json"
            telemetry = root / "telemetry.ndjson"
            reader, writer = os.pipe()
            stream = os.fdopen(reader, "rb", buffering=0)

            class BinaryInput:
                buffer = stream

            try:
                started = time.monotonic()
                with (
                    patch.dict(
                        os.environ,
                        {
                            "LEFTOVERS_STAGE": "planning",
                            "LEFTOVERS_RESULT_PATH": str(result),
                            "LEFTOVERS_TELEMETRY_PATH": str(telemetry),
                        },
                        clear=False,
                    ),
                    patch.object(codex_adapter, "STAGE_TIMEOUTS", {"planning": 1}),
                    patch.object(codex_adapter.sys, "stdin", BinaryInput()),
                    self.assertRaisesRegex(codex_adapter.AdapterError, "hard time limit"),
                ):
                    codex_adapter.main()
                self.assertLess(time.monotonic() - started, 2)
                self.assertFalse(result.exists())
                self.assertFalse(telemetry.exists())
            finally:
                stream.close()
                os.close(writer)

    def test_output_parent_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chmod(root, 0o700)
            target = root / "target"
            target.mkdir(mode=0o700)
            nested = target / "nested"
            nested.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(codex_adapter.AdapterError, "symlinked ancestors"):
                codex_adapter._secure_new_file(link / "nested" / "result.json")

    def test_output_path_must_be_canonical_and_without_symlinked_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with self.assertRaisesRegex(codex_adapter.AdapterError, "unambiguous absolute"):
                codex_adapter._canonical_output_path(str(root / "subdir" / ".." / "result.json"))

            linked_root = root.parent / f"{root.name}-link"
            linked_root.symlink_to(root, target_is_directory=True)
            try:
                with self.assertRaisesRegex(codex_adapter.AdapterError, "unambiguous absolute"):
                    codex_adapter._canonical_output_path(str(linked_root / "result.json"))
            finally:
                linked_root.unlink()

    def test_main_rejects_ambiguous_environment_output_before_reading_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()

            class NoPrompt:
                pass

            with (
                patch.dict(
                    os.environ,
                    {
                        "LEFTOVERS_STAGE": "planning",
                        "LEFTOVERS_RESULT_PATH": str(root / "child" / ".." / "result.json"),
                        "LEFTOVERS_TELEMETRY_PATH": str(root / "telemetry.ndjson"),
                    },
                    clear=False,
                ),
                patch.object(codex_adapter.sys, "stdin", NoPrompt()),
                self.assertRaisesRegex(codex_adapter.AdapterError, "unambiguous absolute"),
            ):
                codex_adapter.main()

    def test_failure_detail_is_bounded_and_redacts_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            diagnostic = root / "diagnostic"
            events = root / "events"
            secret = "github_pat_" + "a" * 40
            diagnostic.write_text(f"provider failed with {secret}\n", encoding="utf-8")
            events.write_text("", encoding="utf-8")

            detail = codex_adapter._failure_detail(diagnostic, events)

        self.assertIn("provider failed", detail)
        self.assertIn("[REDACTED]", detail)
        self.assertNotIn(secret, detail)
        self.assertLessEqual(len(detail), 800)

    def test_cleanup_continues_after_process_group_termination_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = tuple(root / f"artifact-{index}" for index in range(3))
            descriptors = tuple(
                os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600) for path in paths
            )
            process = Mock()
            process.stdin = io.BytesIO(b"")
            with (
                patch.object(
                    codex_adapter,
                    "_terminate",
                    side_effect=codex_adapter.AdapterError("termination was unproven"),
                ),
                patch.object(codex_adapter, "_restore_cancellation_handlers") as restore,
                self.assertRaisesRegex(codex_adapter.AdapterError, "termination was unproven"),
            ):
                codex_adapter._cleanup_stage(
                    process=process,
                    process_group=4242,
                    deadline=time.monotonic() + 1,
                    descriptors=descriptors,
                    paths=paths,
                    previous_handlers={},
                )

            restore.assert_called_once_with({})
            self.assertTrue(process.stdin.closed)
            for descriptor, path in zip(descriptors, paths, strict=True):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
