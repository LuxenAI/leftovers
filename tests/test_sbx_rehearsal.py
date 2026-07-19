from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from leftovers.sbx import SbxAdmissionError, SbxCommandResult, SbxIdentity, controller_sandbox_name
from leftovers.sbx_rehearsal import (
    _NETWORK_DENY,
    _OPENAI_ALLOW,
    SbxCompatibilityProbe,
    SbxRehearsalCleanupPending,
    SbxRehearsalError,
    _default_digest,
    _subprocess_executor,
)

PINNED_SBX = "/opt/homebrew/Caskroom/sbx/0.35.0/bin/sbx"


class FakeExecutor:
    def __init__(self, results: list[SbxCommandResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[tuple[str, ...], dict[str, str], float, int]] = []

    def __call__(
        self, argv: tuple[str, ...], env: object, timeout: float, cap: int
    ) -> SbxCommandResult:
        self.calls.append((argv, dict(env), timeout, cap))
        if not self.results:
            raise AssertionError(f"unexpected sbx command: {argv}")
        return self.results.pop(0)


class SubprocessExecutorTests(unittest.TestCase):
    """These use the Python interpreter, never the real ``sbx`` binary."""

    def _run(self, source: str, *, timeout: float = 1.0, cap: int = 64) -> SbxCommandResult:
        return _subprocess_executor(
            (sys.executable, "-c", source),
            {"PATH": os.environ.get("PATH", "")},
            timeout,
            cap,
        )

    def test_stdout_and_stderr_overflow_are_bounded_and_fail_closed(self) -> None:
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                result = self._run(
                    f"import sys; sys.{stream}.write('x' * 8192); sys.{stream}.flush()",
                    cap=31,
                )
                self.assertTrue(result.output_truncated)
                self.assertFalse(result.timed_out)
                self.assertLessEqual(len(result.stdout), 31)
                self.assertLessEqual(len(result.stderr), 31)
                self.assertLessEqual(len(result.stdout) + len(result.stderr), 31)

    def test_timeout_terminates_and_reaps_the_direct_child(self) -> None:
        started = time.monotonic()
        result = self._run("import time; time.sleep(30)", timeout=0.05)
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 3.0)

    def test_closed_capture_pipes_cannot_bypass_the_deadline(self) -> None:
        started = time.monotonic()
        result = self._run(
            "import os, time; os.close(1); os.close(2); time.sleep(30)",
            timeout=0.05,
        )
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 3.0)

    def test_timeout_kills_same_session_descendant_holding_capture_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "descendant.pid"
            termination_file = Path(directory) / "descendant.terminated"
            child_source = (
                "import pathlib, signal, sys, time; "
                "path = pathlib.Path(sys.argv[1]); "
                "signal.signal(signal.SIGTERM, lambda *_: "
                "(path.write_text('terminated'), sys.exit(0))); "
                "time.sleep(30)"
            )
            source = (
                "import pathlib, subprocess, sys; "
                "child = subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[3]]); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid))"
            )
            result = _subprocess_executor(
                (
                    sys.executable,
                    "-c",
                    source,
                    str(pid_file),
                    child_source,
                    str(termination_file),
                ),
                {"PATH": os.environ.get("PATH", "")},
                1.0,
                64,
            )
            self.assertTrue(result.timed_out)
            self.assertTrue(pid_file.is_file())
            deadline = time.monotonic() + 1.0
            while not termination_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(termination_file.read_text(encoding="utf-8"), "terminated")

    def test_binary_digest_detects_mutation_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "sbx"
            binary.write_bytes(b"x" * (256 * 1024))
            binary.chmod(0o500)
            real_read = os.read
            mutated = False

            def mutating_read(descriptor: int, count: int) -> bytes:
                nonlocal mutated
                block = real_read(descriptor, count)
                if block and not mutated:
                    mutated = True
                    binary.chmod(0o700)
                    with binary.open("ab") as stream:
                        stream.write(b"changed")
                    binary.chmod(0o500)
                return block

            with (
                patch("leftovers.sbx_rehearsal.os.read", side_effect=mutating_read),
                self.assertRaises(SbxRehearsalError),
            ):
                _default_digest(binary)

    def test_normal_parent_exit_still_cleans_descendant_without_capture_pipes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "descendant.ready"
            termination_file = Path(directory) / "descendant.terminated"
            child_source = (
                "import pathlib, signal, sys, time; "
                "ready = pathlib.Path(sys.argv[1]); stopped = pathlib.Path(sys.argv[2]); "
                "signal.signal(signal.SIGTERM, lambda *_: "
                "(stopped.write_text('terminated'), sys.exit(0))); "
                "ready.write_text('ready'); time.sleep(30)"
            )
            parent_source = (
                "import pathlib, subprocess, sys, time; "
                "ready = pathlib.Path(sys.argv[1]); "
                "subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1], sys.argv[2]], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                "deadline = time.monotonic() + 2; "
                "\nwhile not ready.exists() and time.monotonic() < deadline: time.sleep(0.01); "
                "\nraise SystemExit(0 if ready.exists() else 2)"
            )
            result = _subprocess_executor(
                (
                    sys.executable,
                    "-c",
                    parent_source,
                    str(ready_file),
                    str(termination_file),
                    child_source,
                ),
                {"PATH": os.environ.get("PATH", "")},
                3.0,
                64,
            )
            self.assertEqual(result.returncode, 0)
            self.assertFalse(result.timed_out)
            deadline = time.monotonic() + 1.0
            while not termination_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(termination_file.read_text(encoding="utf-8"), "terminated")


class SbxCompatibilityProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp()).resolve()
        self.temp.chmod(0o700)
        self.addCleanup(lambda: __import__("shutil").rmtree(self.temp, ignore_errors=True))
        self.identity = SbxIdentity(
            Path(PINNED_SBX),
            "v0.35.0",
            "01e01520456e4126a9653471e7072e4d9b280321",
            "a" * 64,
        )
        self.ambient = {"HOME": str(Path.home()), "PATH": "/host-should-not-pass"}

    def _fixture(self, root: Path, name: str) -> Path:
        fixture = root / ("leftovers-sbx-rehearsal-" + name)
        fixture.mkdir()
        (fixture / ".git").mkdir()
        (fixture / ".leftovers-sbx-fixture").write_text(name + "\n", encoding="ascii")
        (fixture / "README.md").write_text("fixture\n", encoding="utf-8")
        return fixture

    def _doctor_results(self) -> list[SbxCommandResult]:
        return [
            SbxCommandResult(0, f"sbx version: v0.35.0 {self.identity.revision}\n".encode()),
            SbxCommandResult(0, b""),
            *[
                SbxCommandResult(
                    0,
                    b'{"action":"net:connect:tcp","allowed":true,"type":"network"}',
                )
                for _target in _OPENAI_ALLOW
            ],
            *[
                SbxCommandResult(
                    1,
                    b'{"action":"net:connect:tcp","allowed":false,"type":"network"}',
                )
                for _target in _NETWORK_DENY
            ],
            SbxCommandResult(
                0,
                b"SCOPE TYPE NAME SECRET\n(global) service openai redacted\n",
            ),
        ]

    def _probe(
        self, results: list[SbxCommandResult], *, digest: str | None = None
    ) -> tuple[SbxCompatibilityProbe, FakeExecutor]:
        executor = FakeExecutor(results)
        return (
            SbxCompatibilityProbe(
                expected_identity=self.identity,
                ambient=self.ambient,
                executor=executor,
                binary_digest=lambda _path: self.identity.sha256 if digest is None else digest,
                fixture_builder=self._fixture,
            ),
            executor,
        )

    def _rehearsal_results(self, *, final_list: bytes = b"") -> list[SbxCommandResult]:
        name = controller_sandbox_name("run-1")
        return self._doctor_results() + [
            SbxCommandResult(0, b"SCOPE TYPE NAME SECRET\n"),
            SbxCommandResult(0, b"created"),
            SbxCommandResult(0, f"{name}\n".encode()),
            SbxCommandResult(0, b"[]"),
            SbxCommandResult(0, b"HOME=/root\0PATH=/usr/bin\0"),
            SbxCommandResult(1, b"read-only"),
            SbxCommandResult(0, b""),
            SbxCommandResult(0, b""),
            SbxCommandResult(0, b""),
            SbxCommandResult(0, b""),
            SbxCommandResult(0, final_list),
        ]

    def test_doctor_pins_identity_uses_clean_env_and_checks_exact_policy_matrix(self) -> None:
        probe, executor = self._probe(self._doctor_results())
        receipt = probe.doctor()
        self.assertEqual(receipt.identity, self.identity)
        self.assertTrue(receipt.openai_secret_configured)
        self.assertFalse(receipt.github_secret_configured)
        self.assertEqual(
            [call[0] for call in executor.calls],
            [
                (PINNED_SBX, "version"),
                (PINNED_SBX, "ls", "--quiet"),
                *[
                    (PINNED_SBX, "policy", "check", "network", "--json", target)
                    for target in (*_OPENAI_ALLOW, *_NETWORK_DENY)
                ],
                (PINNED_SBX, "secret", "ls", "--global"),
            ],
        )
        for _argv, env, _timeout, _cap in executor.calls:
            self.assertEqual(env, {"HOME": str(Path.home()), "SBX_NO_TELEMETRY": "1"})

    def test_doctor_only_never_creates_a_fixture_or_sandbox(self) -> None:
        probe, executor = self._probe(self._doctor_results())
        receipt = probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=False)
        self.assertEqual(receipt.state, "doctor_only")
        self.assertIsNone(receipt.fixture_path)
        self.assertEqual(len(executor.calls), len(self._doctor_results()))
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_preexisting_derived_name_rejects_before_fixture_or_cleanup(self) -> None:
        name = controller_sandbox_name("run-1")
        results = self._doctor_results()
        results[1] = SbxCommandResult(0, f"{name}\n".encode())
        probe, executor = self._probe(results)

        with self.assertRaisesRegex(SbxRehearsalError, "already exists"):
            probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)

        self.assertEqual(len(executor.calls), len(results))
        self.assertFalse(any(call[0][1] in {"create", "stop", "rm"} for call in executor.calls))
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_explicit_rehearsal_rejects_nonprivate_root_before_fixture(self) -> None:
        self.temp.chmod(0o755)
        probe, executor = self._probe(self._doctor_results())

        with self.assertRaisesRegex(SbxRehearsalError, "owner-only"):
            probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)

        self.assertEqual(len(executor.calls), len(self._doctor_results()))
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_digest_version_list_policy_and_secret_fail_closed_before_execution(self) -> None:
        cases = (
            ("digest", self._doctor_results(), "b" * 64),
            ("version", [SbxCommandResult(0, b"sbx version: v0.35.1 badbad1\n")], None),
            ("auth", self._doctor_results()[:1] + [SbxCommandResult(1, b"auth")], None),
            (
                "policy",
                self._doctor_results()[:2] + [SbxCommandResult(0, b'{"allowed":false}')],
                None,
            ),
            (
                "secret",
                self._doctor_results()[:-1]
                + [
                    SbxCommandResult(
                        0,
                        b"SCOPE TYPE NAME SECRET\n(global) service github redacted\n",
                    )
                ],
                None,
            ),
        )
        for label, results, digest in cases:
            with self.subTest(label=label):
                probe, executor = self._probe(results, digest=digest)
                with self.assertRaises(SbxRehearsalError):
                    probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=False)
                self.assertFalse(any("create" in call[0] for call in executor.calls))
                self.assertEqual(list(self.temp.iterdir()), [])

    def test_ambient_authority_is_rejected_before_binary_probe(self) -> None:
        for variable in (
            "SSH_AUTH_SOCK",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "DOCKER_HOST",
            "HTTPS_PROXY",
            "GIT_CONFIG_GLOBAL",
        ):
            with self.subTest(variable=variable):
                executor = FakeExecutor(self._doctor_results())
                probe = SbxCompatibilityProbe(
                    expected_identity=self.identity,
                    ambient={"HOME": str(Path.home()), variable: "x"},
                    executor=executor,
                    binary_digest=lambda _path: self.identity.sha256,
                    fixture_builder=self._fixture,
                )
                with self.assertRaises(SbxAdmissionError):
                    probe.doctor()
                self.assertEqual(executor.calls, [])

    def test_explicit_rehearsal_uses_only_fixed_clone_lifecycle_and_removes_fixture(self) -> None:
        probe, executor = self._probe(self._rehearsal_results())
        receipt = probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)
        name = controller_sandbox_name("run-1")
        self.assertEqual(receipt.state, "rehearsed")
        self.assertTrue(receipt.final_absent)
        self.assertIsNone(receipt.fixture_path)
        fixture = self.temp / ("leftovers-sbx-rehearsal-" + name)
        self.assertFalse(fixture.exists())
        self.assertEqual(
            [call[0] for call in executor.calls[len(self._doctor_results()) :]],
            [
                (PINNED_SBX, "secret", "ls", name),
                (
                    PINNED_SBX,
                    "create",
                    "--clone",
                    "--name",
                    name,
                    "--cpus",
                    "1",
                    "--memory",
                    "1g",
                    "shell",
                    str(fixture),
                ),
                (PINNED_SBX, "ls", "--quiet"),
                (PINNED_SBX, "ports", name, "--json"),
                (PINNED_SBX, "exec", name, "env", "-0"),
                (
                    PINNED_SBX,
                    "exec",
                    name,
                    "touch",
                    "/run/sandbox/source/.leftovers-source-write-probe",
                ),
                (PINNED_SBX, "exec", name, "test", "-w", str(fixture)),
                (PINNED_SBX, "exec", name, "touch", str(fixture / ".leftovers-vm-only-marker")),
                (PINNED_SBX, "stop", name),
                (PINNED_SBX, "rm", "--force", name),
                (PINNED_SBX, "ls", "--quiet"),
            ],
        )
        self.assertTrue(
            all("--privileged" not in call[0] and "cp" not in call[0] for call in executor.calls)
        )

    def test_live_boundary_ambiguities_cleanup_and_preserve_fixture(self) -> None:
        name = controller_sandbox_name("run-1")
        cases = {
            "ports": self._doctor_results()
            + [
                SbxCommandResult(0, b"SCOPE TYPE NAME SECRET\n"),
                SbxCommandResult(0, b"created"),
                SbxCommandResult(0, f"{name}\n".encode()),
                SbxCommandResult(0, b'["1234"]'),
                SbxCommandResult(0, b""),
                SbxCommandResult(0, b""),
                SbxCommandResult(0, b""),
            ],
            "env": self._doctor_results()
            + [
                SbxCommandResult(0, b"SCOPE TYPE NAME SECRET\n"),
                SbxCommandResult(0, b"created"),
                SbxCommandResult(0, f"{name}\n".encode()),
                SbxCommandResult(0, b"[]"),
                SbxCommandResult(0, b"GITHUB_TOKEN=x\0"),
                SbxCommandResult(0, b""),
                SbxCommandResult(0, b""),
                SbxCommandResult(0, b""),
            ],
            "opaque-env": self._doctor_results()
            + [
                SbxCommandResult(0, b"SCOPE TYPE NAME SECRET\n"),
                SbxCommandResult(0, b"created"),
                SbxCommandResult(0, f"{name}\n".encode()),
                SbxCommandResult(0, b"[]"),
                SbxCommandResult(0, b"FOO=opaque-secret\0"),
                SbxCommandResult(0, b""),
                SbxCommandResult(0, b""),
                SbxCommandResult(0, b""),
            ],
            "final-list": self._rehearsal_results(final_list=f"{name}\n".encode()),
        }
        for label, results in cases.items():
            with self.subTest(label=label):
                root = self.temp / label
                root.mkdir(mode=0o700)
                probe, executor = self._probe(results)
                with self.assertRaises(SbxRehearsalCleanupPending):
                    probe.rehearse(private_temp_root=root, run_nonce="run-1", execute=True)
                fixture = root / ("leftovers-sbx-rehearsal-" + name)
                self.assertTrue(fixture.is_dir())
                self.assertEqual(
                    [call[0] for call in executor.calls[-3:]],
                    [
                        (PINNED_SBX, "stop", name),
                        (PINNED_SBX, "rm", "--force", name),
                        (PINNED_SBX, "ls", "--quiet"),
                    ],
                )

    def test_successful_source_write_probe_is_a_cleanup_pending_boundary_breach(self) -> None:
        results = self._rehearsal_results()
        source_write_index = len(self._doctor_results()) + 5
        results[source_write_index] = SbxCommandResult(0, b"")
        probe, executor = self._probe(results)
        with self.assertRaisesRegex(SbxRehearsalCleanupPending, "fixture retained"):
            probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)
        self.assertIn("touch", executor.calls[source_write_index][0])
        self.assertEqual(
            [call[0][1] for call in executor.calls[-3:]],
            ["stop", "rm", "ls"],
        )

    def test_create_failure_retains_fixture_without_name_only_teardown(self) -> None:
        probe, executor = self._probe(
            self._doctor_results()
            + [
                SbxCommandResult(0, b"SCOPE TYPE NAME SECRET\n"),
                SbxCommandResult(1, b"no"),
            ]
        )
        with self.assertRaisesRegex(SbxRehearsalCleanupPending, "fixture retained"):
            probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)
        self.assertEqual(len(executor.calls), len(self._doctor_results()) + 2)
        self.assertFalse(any(call[0][1] in {"stop", "rm"} for call in executor.calls))
        self.assertEqual(len(list(self.temp.iterdir())), 1)

    def test_ambiguous_create_timeout_never_uses_name_only_teardown(self) -> None:
        probe, executor = self._probe(
            self._doctor_results()
            + [
                SbxCommandResult(0, b"SCOPE TYPE NAME SECRET\n"),
                SbxCommandResult(-1, b"", timed_out=True),
            ]
        )
        with self.assertRaisesRegex(SbxRehearsalCleanupPending, "fixture retained"):
            probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)
        self.assertFalse(any(call[0][1] in {"stop", "rm"} for call in executor.calls))
        self.assertEqual(len(list(self.temp.iterdir())), 1)

    def test_scoped_or_additional_secret_authority_rejects_before_fixture(self) -> None:
        name = controller_sandbox_name("run-1")
        probe, executor = self._probe(
            self._doctor_results()
            + [
                SbxCommandResult(
                    0,
                    f"SCOPE TYPE NAME SECRET\n{name} service gh redacted\n".encode(),
                )
            ]
        )
        with self.assertRaisesRegex(SbxRehearsalError, "scoped secret authority"):
            probe.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=True)
        self.assertFalse(any(call[0][1] == "create" for call in executor.calls))
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_non_boolean_execute_rejects(self) -> None:
        good, _executor = self._probe(self._doctor_results())
        with self.assertRaises(ValueError):
            good.rehearse(private_temp_root=self.temp, run_nonce="run-1", execute=1)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
