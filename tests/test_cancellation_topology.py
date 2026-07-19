from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import suppress
from pathlib import Path
from unittest import mock

import leftovers.runner as runner
from leftovers.cancellation import install_cancellation_handlers
from leftovers.runner import execute

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "scripts" / "codex_adapter.py"


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


job = _load_script("leftovers_test_cancellation_macos_job", "macos_job.py")


@unittest.skipUnless(os.name == "posix", "process-group cancellation requires POSIX")
class CancellationTopologyTests(unittest.TestCase):
    def _private_root(self) -> Path:
        root = Path(tempfile.mkdtemp()).resolve()
        os.chmod(root, 0o700)
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        return root

    def _fake_codex(self, root: Path) -> Path:
        fake = root / "codex"
        fake.write_text(
            """#!/usr/bin/env python3
import os
import signal
import sys
import time
from pathlib import Path

if "--version" in sys.argv:
    print("codex-cli 0.145.0")
    raise SystemExit(0)

Path(os.environ["TEST_CODEX_PID_PATH"]).write_text(f"{os.getpid()} {os.getpgrp()}\\n")
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return fake

    def _adapter_environment(self, root: Path, fake: Path, pid_path: Path) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LEFTOVERS_STAGE": "planning",
            "LEFTOVERS_RESULT_PATH": str(root / "result.json"),
            "LEFTOVERS_TELEMETRY_PATH": str(root / "telemetry.ndjson"),
            "LEFTOVERS_CODEX_BIN": str(fake),
            "TEST_CODEX_PID_PATH": str(pid_path),
        }

    def _wait_for_pid_record(self, path: Path) -> tuple[int, int]:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.is_file():
                values = tuple(int(value) for value in path.read_text().split())
                self.assertEqual(len(values), 2)
                return values[0], values[1]
            time.sleep(0.02)
        self.fail("fake Codex did not start")

    def _wait_for_dead(self, pid: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError as exc:
                self.fail(f"could not inspect nested Codex process {pid}: {exc}")
            time.sleep(0.02)
        self.fail(f"nested Codex process {pid} remained live after cancellation")

    def test_wrapper_signal_cleans_runner_adapter_and_codex_descendants(self) -> None:
        root = self._private_root()
        pid_path = root / "codex.pid"
        fake = self._fake_codex(root)
        environment = self._adapter_environment(root, fake, pid_path)
        controller = root / "controller.py"
        controller.write_text(
            "\n".join(
                (
                    "from leftovers.cancellation import install_cancellation_handlers",
                    "from leftovers.runner import execute",
                    "install_cancellation_handlers()",
                    f"execute({json.dumps([sys.executable, str(ADAPTER_PATH)])}, cwd=None, "
                    f"env={environment!r}, stdin='bounded prompt', timeout=60, "
                    "max_output_bytes=65536)",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        controller_environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        process = subprocess.Popen(
            [sys.executable, str(controller)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=controller_environment,
            start_new_session=True,
        )
        self.addCleanup(self._kill_process_group, process)
        codex_pid, adapter_group = self._wait_for_pid_record(pid_path)
        self.assertNotEqual(codex_pid, adapter_group)
        self.assertNotEqual(adapter_group, process.pid)
        os.kill(adapter_group, 0)

        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)

        self.assertNotEqual(process.returncode, -signal.SIGTERM)
        self._wait_for_dead(codex_pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(adapter_group, 0)

    def test_runner_timeout_still_kills_the_adapter_owned_group(self) -> None:
        root = self._private_root()
        pid_path = root / "codex.pid"
        fake = self._fake_codex(root)
        result = execute(
            [sys.executable, str(ADAPTER_PATH)],
            cwd=None,
            env=self._adapter_environment(root, fake, pid_path),
            stdin="bounded prompt",
            timeout=1,
            max_output_bytes=65_536,
        )

        self.assertTrue(result.timed_out)
        codex_pid, _adapter_group = self._wait_for_pid_record(pid_path)
        self._wait_for_dead(codex_pid)

    def test_runner_owned_adapter_completes_without_killing_its_own_group(self) -> None:
        root = self._private_root()
        pid_path = root / "codex.pid"
        fake = root / "codex"
        fake.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

if "--version" in sys.argv:
    print("codex-cli 0.145.0")
    raise SystemExit(0)

Path(os.environ["TEST_CODEX_PID_PATH"]).write_text(f"{os.getpid()} {os.getpgrp()}\\n")
sys.stdin.read()
output = Path(sys.argv[sys.argv.index("--output-last-message") + 1])
output.write_text(json.dumps({
    "status": "planned",
    "acceptance_criteria": ["bounded"],
    "reproduction": {"argv": ["true"], "observed": "fixture"},
    "root_cause": [{"path": "fixture.py", "evidence": "fixture"}],
    "steps": ["verify"],
    "tests": [["true"]],
    "risks": [],
    "estimated_remaining_tokens": 1,
    "stop_conditions": ["scope expands"]
}))
print(json.dumps({"type": "turn.completed", "usage": {
    "input_tokens": 1, "cached_input_tokens": 0,
    "output_tokens": 1, "reasoning_output_tokens": 0
}}))
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        result_path = root / "result.json"
        telemetry_path = root / "telemetry.ndjson"
        result = execute(
            [sys.executable, str(ADAPTER_PATH)],
            cwd=None,
            env={
                **self._adapter_environment(root, fake, pid_path),
                "LEFTOVERS_RESULT_PATH": str(result_path),
                "LEFTOVERS_TELEMETRY_PATH": str(telemetry_path),
            },
            stdin="bounded prompt",
            timeout=10,
            max_output_bytes=65_536,
        )

        self.assertTrue(result.passed, result.stderr_tail)
        self.assertEqual(json.loads(result_path.read_text())["status"], "planned")
        self.assertEqual(
            [json.loads(line)["type"] for line in telemetry_path.read_text().splitlines()],
            ["checkin", "usage"],
        )
        _codex_pid, adapter_group = self._wait_for_pid_record(pid_path)
        with self.assertRaises(ProcessLookupError):
            os.killpg(adapter_group, 0)

    def test_direct_adapter_signal_cleans_its_separate_codex_session(self) -> None:
        root = self._private_root()
        pid_path = root / "codex.pid"
        fake = self._fake_codex(root)
        process = subprocess.Popen(
            [sys.executable, str(ADAPTER_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._adapter_environment(root, fake, pid_path),
        )
        self.addCleanup(self._kill_process, process)
        assert process.stdin is not None
        process.stdin.write(b"bounded prompt")
        process.stdin.close()
        codex_pid, codex_group = self._wait_for_pid_record(pid_path)
        self.assertEqual(codex_pid, codex_group)

        os.kill(process.pid, signal.SIGTERM)
        process.wait(timeout=10)

        self.assertNotEqual(process.returncode, -signal.SIGTERM)
        self._wait_for_dead(codex_pid)

    def test_direct_adapter_signal_during_version_probe_cleans_probe_session(self) -> None:
        root = self._private_root()
        pid_path = root / "probe.pid"
        fake = root / "codex"
        fake.write_text(
            """#!/usr/bin/env python3
import os
import signal
import sys
import time
from pathlib import Path

Path(os.environ["TEST_CODEX_PID_PATH"]).write_text(f"{os.getpid()} {os.getpgrp()}\\n")
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        process = subprocess.Popen(
            [sys.executable, str(ADAPTER_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._adapter_environment(root, fake, pid_path),
        )
        self.addCleanup(self._kill_process, process)
        assert process.stdin is not None
        process.stdin.write(b"bounded prompt")
        process.stdin.close()
        probe_pid, probe_group = self._wait_for_pid_record(pid_path)
        self.assertEqual(probe_pid, probe_group)

        os.kill(process.pid, signal.SIGTERM)
        process.wait(timeout=10)

        self.assertNotEqual(process.returncode, -signal.SIGTERM)
        self._wait_for_dead(probe_pid)

    def test_runner_timeout_cleans_blocked_version_probe_from_owned_group(self) -> None:
        root = self._private_root()
        pid_path = root / "probe.pid"
        fake = root / "codex"
        fake.write_text(
            """#!/usr/bin/env python3
import os
import signal
import time
from pathlib import Path

Path(os.environ["TEST_CODEX_PID_PATH"]).write_text(f"{os.getpid()} {os.getpgrp()}\\n")
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)

        result = execute(
            [sys.executable, str(ADAPTER_PATH)],
            cwd=None,
            env=self._adapter_environment(root, fake, pid_path),
            stdin="bounded prompt",
            timeout=1,
            max_output_bytes=65_536,
        )

        self.assertTrue(result.timed_out)
        probe_pid, runner_group = self._wait_for_pid_record(pid_path)
        self.assertNotEqual(probe_pid, runner_group)
        self._wait_for_dead(probe_pid)
        with self.assertRaises(ProcessLookupError):
            os.killpg(runner_group, 0)

    def test_macos_watchdog_reserves_grace_for_wrapper_cleanup(self) -> None:
        root = self._private_root()
        (root / "tmp").mkdir(mode=0o700)
        pid_path = root / "codex.pid"
        fake = self._fake_codex(root)
        environment = self._adapter_environment(root, fake, pid_path)
        controller = root / "controller.py"
        controller.write_text(
            "\n".join(
                (
                    "from leftovers.cancellation import install_cancellation_handlers",
                    "from leftovers.runner import execute",
                    "install_cancellation_handlers()",
                    f"execute({json.dumps([sys.executable, str(ADAPTER_PATH)])}, cwd=None, "
                    f"env={environment!r}, stdin='bounded prompt', timeout=60, "
                    "max_output_bytes=65536)",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        controller_environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        work_deadline = time.monotonic() + 0.6
        # The production job reserves 12 seconds after its work deadline.
        # Runner-owned teardown needs up to five seconds for SIGTERM plus two
        # seconds to confirm SIGKILL, so this regression preserves that real
        # ordering instead of killing the wrapper midway through its cleanup.
        supervisor = job._JobSupervisor(work_deadline, work_deadline + 12)
        supervisor.install(0.6)
        try:
            with self.assertRaisesRegex(job.JobError, "job-wide deadline expired"):
                job._run(
                    [sys.executable, str(controller)],
                    environment=controller_environment,
                    cwd=root,
                    timeout=60,
                    supervisor=supervisor,
                )
        finally:
            supervisor.close()

        codex_pid, adapter_group = self._wait_for_pid_record(pid_path)
        self._wait_for_dead(codex_pid)
        with self.assertRaises(ProcessLookupError):
            os.kill(adapter_group, 0)

    def test_deferred_wrapper_cancellation_cleans_child_created_during_spawn(self) -> None:
        root = self._private_root()
        pid_path = root / "child.pid"
        child = root / "child.py"
        child.write_text(
            "\n".join(
                (
                    "import os",
                    "import signal",
                    "import time",
                    "from pathlib import Path",
                    "Path(os.environ['TEST_CHILD_PID_PATH']).write_text(",
                    '    f"{os.getpid()} {os.getpgrp()}"',
                    ")",
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                    "while True:",
                    "    time.sleep(1)",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TEST_CHILD_PID_PATH": str(pid_path),
        }
        original_popen = runner.subprocess.Popen

        def spawn_then_signal(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = original_popen(*args, **kwargs)
            deadline = time.monotonic() + 2
            while not pid_path.is_file() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pid_path.is_file(), "child did not reach the spawn-registration window")
            os.kill(os.getpid(), signal.SIGTERM)
            return process

        restore = install_cancellation_handlers()
        try:
            with (
                mock.patch.object(runner.subprocess, "Popen", side_effect=spawn_then_signal),
                self.assertRaises(KeyboardInterrupt),
            ):
                execute(
                    [sys.executable, str(child)],
                    cwd=None,
                    env=environment,
                    stdin=None,
                    timeout=60,
                    max_output_bytes=65_536,
                )
        finally:
            restore()

        child_pid, _child_group = self._wait_for_pid_record(pid_path)
        self._wait_for_dead(child_pid)

    def test_runner_cleans_descendant_when_session_leader_exits_first(self) -> None:
        root = self._private_root()
        pid_path = root / "orphan.pid"
        child = root / "orphan.py"
        child.write_text(
            "\n".join(
                (
                    "import os",
                    "import signal",
                    "import time",
                    "from pathlib import Path",
                    "Path(os.environ['TEST_ORPHAN_PID_PATH']).write_text(",
                    '    f"{os.getpid()} {os.getpgrp()}"',
                    ")",
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                    "while True:",
                    "    time.sleep(1)",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        leader = root / "leader.py"
        leader.write_text(
            "\n".join(
                (
                    "import os",
                    "import subprocess",
                    "import sys",
                    "import time",
                    "from pathlib import Path",
                    "child = subprocess.Popen([sys.executable, os.environ['TEST_ORPHAN_CHILD']])",
                    "deadline = time.monotonic() + 5",
                    "while not Path(os.environ['TEST_ORPHAN_PID_PATH']).exists():",
                    "    if time.monotonic() >= deadline:",
                    "        raise RuntimeError('orphan did not start')",
                    "    time.sleep(0.01)",
                    "os._exit(0)",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TEST_ORPHAN_PID_PATH": str(pid_path),
            "TEST_ORPHAN_CHILD": str(child),
        }

        # A real process group proves that cleanup does not merely rely on the
        # Popen leader's return code.  Shorten only the test's grace window so
        # the SIGKILL escalation stays fast.
        with mock.patch.object(runner, "_TERMINATION_GRACE_SECONDS", 0.1):
            result = execute(
                [sys.executable, str(leader)],
                cwd=None,
                env=environment,
                stdin=None,
                timeout=10,
                max_output_bytes=65_536,
            )

        self.assertEqual(result.exit_code, 0)
        orphan_pid, orphan_group = self._wait_for_pid_record(pid_path)
        self.assertNotEqual(orphan_pid, orphan_group)
        self._wait_for_dead(orphan_pid)
        with self.assertRaises(ProcessLookupError):
            os.killpg(orphan_group, 0)

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)

    @staticmethod
    def _kill_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        with suppress(ProcessLookupError):
            os.kill(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
