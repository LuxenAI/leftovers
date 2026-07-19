from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leftovers.sbx import (
    DOCKER_SANDBOX_EXECUTION_ENABLED,
    FixtureSbxBoundary,
    GitCloneInput,
    SbxAdmissionError,
    SbxBoundary,
    SbxCleanupPending,
    SbxCommandResult,
    SbxExecutionDisabled,
    SbxIdentity,
    controller_sandbox_name,
    fixture_sbx_capability,
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


class SbxBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root))
        (self.root / ".git").mkdir()
        (self.root / "README.md").write_text("safe tracked source\n", encoding="utf-8")
        self.clone = GitCloneInput(self.root, ("README.md",), ())
        self.identity = SbxIdentity(
            Path(PINNED_SBX), "v0.35.0", "01e01520456e4126a9653471e7072e4d9b280321", "a" * 64
        )

    def _success_results(self, *, listed: list[object] | None = None) -> list[SbxCommandResult]:
        names = [] if listed is None else listed
        return [
            SbxCommandResult(
                0,
                f"sbx version: v0.35.0 {self.identity.revision}\n".encode(),
            ),
            SbxCommandResult(
                0,
                ("" if not names else "\n".join(str(item) for item in names) + "\n").encode(),
            ),
            SbxCommandResult(0, b"created"),
        ]

    def _boundary(self, results: list[SbxCommandResult]) -> tuple[FixtureSbxBoundary, FakeExecutor]:
        executor = FakeExecutor(results)
        return (
            FixtureSbxBoundary(
                fixture_sbx_capability(),
                expected_identity=self.identity,
                observed_binary_sha256=self.identity.sha256,
                executor=executor,
            ),
            executor,
        )

    def test_source_gate_cannot_be_activated_by_fixture_or_configuration(self) -> None:
        self.assertFalse(DOCKER_SANDBOX_EXECUTION_ENABLED)
        with self.assertRaises(SbxExecutionDisabled):
            SbxBoundary().provision(run_nonce="r", clone=self.clone, ambient={})

    def test_exact_controller_derived_name_is_stable_and_not_input_name(self) -> None:
        self.assertEqual(controller_sandbox_name("run-1"), controller_sandbox_name("run-1"))
        self.assertNotEqual(controller_sandbox_name("run-1"), controller_sandbox_name("run-2"))
        self.assertRegex(controller_sandbox_name("run-1"), r"^leftovers-[a-f0-9]{24}$")

    def test_fixed_clone_create_argv_and_clean_environment(self) -> None:
        boundary, executor = self._boundary(self._success_results())
        receipt = boundary.provision(
            run_nonce="run-1",
            clone=self.clone,
            ambient={"HOME": str(Path.home()), "PATH": "/bad"},
        )
        expected_name = controller_sandbox_name("run-1")
        self.assertEqual(
            receipt.create_argv,
            (
                PINNED_SBX,
                "create",
                "--clone",
                "--name",
                expected_name,
                "--cpus",
                "2",
                "--memory",
                "4g",
                "codex",
                str(self.root),
            ),
        )
        self.assertEqual(executor.calls[0][0], (PINNED_SBX, "version"))
        self.assertEqual(executor.calls[1][0], (PINNED_SBX, "ls", "--quiet"))
        self.assertEqual(
            executor.calls[2][1],
            {"HOME": str(Path.home()), "SBX_NO_TELEMETRY": "1"},
        )
        self.assertNotIn("--template", receipt.create_argv)
        self.assertNotIn("--profile", receipt.create_argv)
        self.assertNotIn("--kit", receipt.create_argv)
        self.assertNotIn("--port", receipt.create_argv)

    def test_credential_proxy_git_registry_and_docker_ambient_are_rejected_before_probe(
        self,
    ) -> None:
        for variable in (
            "SSH_AUTH_SOCK",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "DOCKER_HOST",
            "HTTPS_PROXY",
            "GIT_CONFIG_GLOBAL",
            "REGISTRY_TOKEN",
        ):
            boundary, executor = self._boundary(self._success_results())
            with (
                self.subTest(variable=variable),
                self.assertRaisesRegex(SbxAdmissionError, "forbidden ambient"),
            ):
                boundary.provision(
                    run_nonce="run-1",
                    clone=self.clone,
                    ambient={"HOME": str(Path.home()), variable: "x"},
                )
            self.assertEqual(executor.calls, [])

    def test_identity_mismatch_or_failure_prevents_list_and_create(self) -> None:
        for result in (
            SbxCommandResult(1, b"denied"),
            SbxCommandResult(
                0, b'{"version":"v0.35.1","revision":"01e01520456e4126a9653471e7072e4d9b280321"}'
            ),
            SbxCommandResult(0, b"{}"),
        ):
            boundary, executor = self._boundary([result])
            with self.assertRaises(SbxAdmissionError):
                boundary.provision(
                    run_nonce="run-1", clone=self.clone, ambient={"HOME": str(Path.home())}
                )
            self.assertEqual(len(executor.calls), 1)

    def test_binary_digest_mismatch_prevents_any_cli_command(self) -> None:
        executor = FakeExecutor(self._success_results())
        boundary = FixtureSbxBoundary(
            fixture_sbx_capability(),
            expected_identity=self.identity,
            observed_binary_sha256="b" * 64,
            executor=executor,
        )
        with self.assertRaisesRegex(SbxAdmissionError, "SHA-256"):
            boundary.provision(
                run_nonce="run-1", clone=self.clone, ambient={"HOME": str(Path.home())}
            )
        self.assertEqual(executor.calls, [])

    def test_list_auth_failure_malformed_names_duplicate_or_existing_name_prevents_create(
        self,
    ) -> None:
        name = controller_sandbox_name("run-1")
        for listed in (
            SbxCommandResult(1, b"auth failed"),
            SbxCommandResult(0, b"not a valid sandbox name\n"),
            SbxCommandResult(0, b"same\nsame\n"),
            SbxCommandResult(0, f"{name}\n".encode()),
        ):
            boundary, executor = self._boundary([self._success_results()[0], listed])
            with self.assertRaises(SbxAdmissionError):
                boundary.provision(
                    run_nonce="run-1", clone=self.clone, ambient={"HOME": str(Path.home())}
                )
            self.assertEqual(len(executor.calls), 2)

    def test_clone_rejects_untracked_secret_symlink_and_worktree_link_before_create(self) -> None:
        cases: list[GitCloneInput] = [
            GitCloneInput(self.root, ("README.md",), (".env",)),
            GitCloneInput(self.root, ("README.md", ".env"), ()),
        ]
        (self.root / "link").symlink_to("README.md")
        cases.append(GitCloneInput(self.root, ("link",), ()))
        for clone in cases:
            boundary, executor = self._boundary(self._success_results()[:2])
            with self.assertRaises(SbxAdmissionError):
                boundary.provision(
                    run_nonce="run-1", clone=clone, ambient={"HOME": str(Path.home())}
                )
            self.assertEqual(len(executor.calls), 2)

    def test_clone_manifest_cannot_omit_an_on_disk_file(self) -> None:
        (self.root / "omitted.txt").write_text("unlisted source\n", encoding="utf-8")
        boundary, executor = self._boundary(self._success_results()[:2])
        with self.assertRaisesRegex(SbxAdmissionError, "exactly cover"):
            boundary.provision(
                run_nonce="run-1",
                clone=self.clone,
                ambient={"HOME": str(Path.home())},
            )
        self.assertEqual(len(executor.calls), 2)

    def test_clone_rejects_hardlinked_source_even_when_manifest_is_complete(self) -> None:
        (self.root / "alias.md").hardlink_to(self.root / "README.md")
        clone = GitCloneInput(self.root, ("README.md", "alias.md"), ())
        boundary, executor = self._boundary(self._success_results()[:2])
        with self.assertRaisesRegex(SbxAdmissionError, "regular non-symlink"):
            boundary.provision(
                run_nonce="run-1",
                clone=clone,
                ambient={"HOME": str(Path.home())},
            )
        self.assertEqual(len(executor.calls), 2)

    def test_clone_rejects_group_or_other_writable_source_directory(self) -> None:
        source = self.root / "src"
        source.mkdir()
        source.chmod(0o777)
        (source / "module.py").write_text("value = 1\n", encoding="utf-8")
        clone = GitCloneInput(self.root, ("README.md", "src/module.py"), ())
        boundary, executor = self._boundary(self._success_results()[:2])
        with self.assertRaisesRegex(SbxAdmissionError, "source directories"):
            boundary.provision(
                run_nonce="run-1",
                clone=clone,
                ambient={"HOME": str(Path.home())},
            )
        self.assertEqual(len(executor.calls), 2)

    def test_output_timeout_and_truncation_prevent_create(self) -> None:
        for result in (
            SbxCommandResult(0, b"{}", timed_out=True),
            SbxCommandResult(0, b"{}", output_truncated=True),
            SbxCommandResult(0, b"x" * 4097),
        ):
            boundary, executor = self._boundary([result])
            with self.assertRaises(SbxAdmissionError):
                boundary.provision(
                    run_nonce="run-1", clone=self.clone, ambient={"HOME": str(Path.home())}
                )
            self.assertEqual(len(executor.calls), 1)

    def test_cleanup_uses_exact_name_stop_force_remove_and_final_absence(self) -> None:
        name = controller_sandbox_name("run-1")
        boundary, executor = self._boundary(
            [
                SbxCommandResult(0, b"stopped"),
                SbxCommandResult(0, b"removed"),
                SbxCommandResult(0, b""),
            ]
        )
        receipt = boundary.cleanup(name=name, ambient={"HOME": str(Path.home())})
        self.assertEqual(receipt.state, "cleaned")
        self.assertEqual(
            [call[0] for call in executor.calls],
            [
                (PINNED_SBX, "stop", name),
                (PINNED_SBX, "rm", "--force", name),
                (PINNED_SBX, "ls", "--quiet"),
            ],
        )

    def test_cleanup_failure_or_final_list_ambiguity_is_cleanup_pending(self) -> None:
        name = controller_sandbox_name("run-1")
        for results in (
            [
                SbxCommandResult(1, b"stop failed"),
                SbxCommandResult(0, b"removed"),
                SbxCommandResult(0, b""),
            ],
            [
                SbxCommandResult(0, b"stopped"),
                SbxCommandResult(0, b"removed"),
                SbxCommandResult(1, b"auth failed"),
            ],
            [
                SbxCommandResult(0, b"stopped"),
                SbxCommandResult(0, b"removed"),
                SbxCommandResult(0, f"{name}\n".encode()),
            ],
        ):
            boundary, executor = self._boundary(results)
            with self.assertRaises(SbxCleanupPending):
                boundary.cleanup(name=name, ambient={"HOME": str(Path.home())})
            self.assertEqual(len(executor.calls), 3)

    def test_standalone_wrapper_uses_a_private_temp_root_and_empty_environment(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts" / "sbx-rehearsal.sh"
        source = script.read_text(encoding="utf-8")
        self.assertIn("umask 077", source)
        self.assertIn("PATH=/usr/bin:/bin:/usr/sbin:/sbin", source)
        self.assertIn("/usr/bin/mktemp -d /private/tmp/leftovers-sbx-rehearsal.XXXXXX", source)
        self.assertIn("/usr/bin/dirname", source)
        self.assertIn(
            "PYTHON=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3", source
        )
        self.assertIn("env -i", source)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", source)
        self.assertIn('--private-temp-root "$PRIVATE_ROOT"', source)
        self.assertNotIn("GITHUB_TOKEN=", source)
        self.assertNotIn("SSH_AUTH_SOCK=", source)
        self.assertNotIn("command -v", source)
