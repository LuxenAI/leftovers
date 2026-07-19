from __future__ import annotations

import importlib.util
import io
import json
import os
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from leftovers.audit import AuditJournal
from leftovers.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


installer = _load_script("leftovers_test_installer", "install_macos.py")
job = _load_script("leftovers_test_macos_job", "macos_job.py")
uninstaller = _load_script("leftovers_test_uninstaller", "uninstall_macos.py")
sys.modules["uninstall_macos"] = uninstaller
status_reporter = _load_script("leftovers_test_status_macos", "status_macos.py")
builder = _load_script("leftovers_test_package_builder", "build_macos_package.py")


class MacOSPackageTests(unittest.TestCase):
    def private_root(self) -> Path:
        root = Path(tempfile.mkdtemp())
        os.chmod(root, 0o700)
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        return root

    def test_rendered_preview_config_is_valid_and_cannot_publish(self) -> None:
        root = self.private_root()
        adapter = root / "lib" / "codex_adapter.py"
        adapter.parent.mkdir(mode=0o700)
        adapter.write_text("# fixture\n", encoding="utf-8")
        config_path = installer._render_config(
            root,
            runtime="docker",
            adapter=adapter,
            force=True,
        )
        config = load_config(config_path)

        self.assertEqual(config.agent.model, "gpt-5.6-terra")
        self.assertEqual(config.agent.provider, "openai-codex-cli")
        self.assertEqual(config.agent.backend, "host")
        self.assertTrue(config.agent.checkin_required)
        self.assertTrue(config.agent.usage_reporting_required)
        self.assertEqual(config.agent.max_repair_cycles, 0)
        self.assertEqual(config.agent.estimated_tokens_p95, 50_000)
        self.assertEqual(config.budget.maximum_tokens, 65_000)
        self.assertEqual(config.budget.reserve_tokens, 10_000)
        self.assertEqual(config.policy.max_changed_files, 5)
        self.assertEqual(config.policy.max_changed_lines, 300)
        self.assertEqual(config.publication.mode, "dry-run")
        self.assertFalse(config.publication.external_writes_acknowledged)
        self.assertFalse(config.repositories[0].ai_contributions_allowed)
        self.assertEqual(config.repositories[0].test_commands, ())
        self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

    def test_install_root_rejects_symlinked_ancestor_and_outside_path(self) -> None:
        root = self.private_root()
        target = root / "redirect-target"
        target.mkdir(mode=0o700)
        (root / ".leftovers").symlink_to(target, target_is_directory=True)
        with (
            patch.object(installer, "ROOT", root),
            patch.object(installer, "MANAGED_BASE", root / ".leftovers"),
            self.assertRaisesRegex(installer.InstallError, "symlink"),
        ):
            installer._scoped_install_root(root / ".leftovers" / "install")
        with (
            patch.object(installer, "ROOT", root),
            patch.object(installer, "MANAGED_BASE", root / "managed"),
            self.assertRaisesRegex(installer.InstallError, "must stay beneath"),
        ):
            installer._scoped_install_root(root / "outside")

    def test_verified_oci_image_rewrites_config_to_immutable_id(self) -> None:
        root = self.private_root()
        adapter = root / "lib" / "codex_adapter.py"
        adapter.parent.mkdir(mode=0o700)
        adapter.write_text("# fixture\n", encoding="utf-8")
        config_path = installer._render_config(
            root,
            runtime="docker",
            adapter=adapter,
            force=True,
        )
        image_id = "sha256:" + "a" * 64
        installer._pin_config_image(config_path, image_id)

        self.assertEqual(load_config(config_path).sandbox.image, image_id)

    def test_existing_config_symlink_is_rejected(self) -> None:
        root = self.private_root()
        target = root / "outside.toml"
        target.write_text("version = 1\n", encoding="utf-8")
        (root / "config.toml").symlink_to(target)
        with self.assertRaisesRegex(installer.InstallError, "may not be a symlink"):
            installer._render_config(
                root,
                runtime="docker",
                adapter=root / "adapter.py",
                force=False,
            )

    def test_installer_refuses_to_overlap_active_job_lock(self) -> None:
        root = self.private_root()
        descriptor = installer._acquire_package_lock(root)
        self.addCleanup(lambda: os.close(descriptor))
        with self.assertRaisesRegex(installer.InstallError, "job is active"):
            installer._acquire_package_lock(root)

    def test_installer_refuses_to_overwrite_unresolved_cleanup_evidence(self) -> None:
        root = self.private_root()
        (root / installer.CLEANUP_PENDING_FILENAME).write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(installer.InstallError, "cleanup remains unresolved"):
            installer._acquire_package_lock(root)

    def test_zipapp_propagates_cli_failure_status(self) -> None:
        root = self.private_root()
        archive = installer._build_zipapp(root)
        adapter = root / "adapter.py"
        adapter.write_text("# fixture\n", encoding="utf-8")
        config = installer._render_config(
            root,
            runtime="docker",
            adapter=adapter,
            force=True,
        )
        completed = subprocess.run(
            [sys.executable, str(archive), "--config", str(config), "doctor"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn('"sandbox_runtime"', completed.stdout)

    def test_preview_admission_requires_manual_ai_policy_and_tests(self) -> None:
        base = {
            "publication": {"mode": "dry-run", "external_writes_acknowledged": False},
            "agent": {"backend": "host", "model": "gpt-5.6-terra"},
            "repositories": [
                {
                    "enabled": True,
                    "ai_contributions_allowed": False,
                    "test_commands": [],
                }
            ],
        }
        self.assertFalse(job._curated_preview_available(base))
        base["repositories"] = [
            {
                "enabled": True,
                "ai_contributions_allowed": True,
                "ai_policy_url": "https://github.com/owner/repo/blob/main/CONTRIBUTING.md",
                "ai_policy_checked_at": "2026-07-18",
                "test_commands": [["python3", "-m", "unittest"]],
            }
        ]
        self.assertTrue(job._curated_preview_available(base))
        base["publication"]["mode"] = "draft-pr"
        self.assertFalse(job._curated_preview_available(base))

    def test_oci_rehearsal_cannot_authorize_strict_execution(self) -> None:
        root = self.private_root()
        supervisor = job._JobSupervisor(time.monotonic() + 60)
        ok, reason = job._runtime_ready(
            {"sandbox": {"runtime": "docker", "image": "leftovers-sandbox:local-preview"}},
            {
                "assurance": "oci-rehearsal-verified-dry-run",
                "sandbox_image_id": "sha256:" + "a" * 64,
            },
            {"PATH": "/usr/bin:/bin"},
            root,
            time.monotonic() + 60,
            supervisor,
        )
        self.assertFalse(ok)
        self.assertIn("strict VM execution is disabled", reason)

    def test_preview_job_cannot_enable_host_or_oci_contribution_execution(self) -> None:
        self.assertFalse(job.STRICT_VM_EXECUTION_ENABLED)

    def test_github_token_is_captured_in_memory_without_job_temp_files(self) -> None:
        completed = Mock()
        completed.pid = 4242
        completed.poll.return_value = 0
        completed.returncode = 0
        completed.stdout = io.BytesIO(b"github_pat_" + b"a" * 32 + b"\n")
        with (
            patch.object(job.shutil, "which", return_value="/usr/local/bin/gh"),
            patch.object(job.subprocess, "Popen", return_value=completed) as popen,
            patch.object(job, "_terminate") as terminate,
            patch.object(job, "_run", side_effect=AssertionError("must not write token capture")),
        ):
            token = job._github_token(
                {"PATH": "/usr/local/bin:/usr/bin:/bin"},
                job._JobSupervisor(time.monotonic() + 60),
            )

        self.assertTrue(token.startswith("github_pat_"))
        self.assertEqual(popen.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        terminate.assert_called_once()

    def test_global_deadline_blocks_github_token_subprocess(self) -> None:
        supervisor = job._JobSupervisor(time.monotonic() - 0.01)
        with (
            patch.object(job.shutil, "which", return_value="/usr/local/bin/gh"),
            patch.object(job.subprocess, "Popen") as popen,
            self.assertRaisesRegex(job.JobError, "job-wide deadline expired"),
        ):
            job._github_token({"PATH": "/usr/local/bin:/usr/bin:/bin"}, supervisor)
        popen.assert_not_called()

    def test_termination_targets_process_group_after_leader_exits(self) -> None:
        process = Mock()
        process.pid = 4242
        process.poll.return_value = 0
        with (
            patch.object(job, "_process_group_is_alive", side_effect=[True, False, False]),
            patch.object(job.os, "killpg") as killpg,
        ):
            job._terminate(process, deadline=time.monotonic() + 10)

        killpg.assert_called_once_with(4242, job.signal.SIGTERM)

    def test_signal_handler_terminates_the_registered_process_group(self) -> None:
        process = Mock()
        supervisor = job._JobSupervisor(time.monotonic() + 60)
        supervisor.active_process = process
        with patch.object(job, "_terminate") as terminate:
            supervisor._on_signal(job.signal.SIGTERM, None)

        terminate.assert_called_once_with(process, deadline=supervisor.deadline)
        self.assertEqual(supervisor.stop_reason, "job received SIGTERM")

    def test_unproven_process_group_termination_persists_private_evidence(self) -> None:
        root = self.private_root()
        marker = root / job.CLEANUP_PENDING_FILENAME
        process = Mock()
        process.pid = 4242
        supervisor = job._JobSupervisor(
            time.monotonic() + 60,
            cleanup_pending_path=marker,
        )
        with (
            patch.object(job, "TERMINATION_GRACE_SECONDS", 0),
            patch.object(job, "KILL_CONFIRM_SECONDS", 0),
            patch.object(job, "_process_group_is_alive", return_value=True),
            patch.object(job, "_signal_process_group"),
            self.assertRaisesRegex(job.JobError, "could not be terminated after SIGKILL"),
        ):
            supervisor.terminate(process)

        evidence = json.loads(marker.read_bytes())
        self.assertEqual(evidence["state"], "cleanup_pending")
        self.assertEqual(evidence["pid"], 4242)
        self.assertEqual(evidence["pgid"], 4242)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_preview_cleanup_lease_exists_before_controller_result_and_blocks_new_work(
        self,
    ) -> None:
        root = self.private_root()
        config = {"state_dir": str(root / "state"), "temp_root": str(root / "workspaces")}
        evidence = job._start_preview_cleanup_lease(root, config)
        marker = root / job.CLEANUP_PENDING_FILENAME
        self.assertTrue(marker.exists())
        self.assertEqual(evidence["state"], "cleanup_in_progress")
        self.assertEqual(evidence["container_label"], f"io.leftovers.job={evidence['run_id']}")
        with self.assertRaisesRegex(job.JobError, "unresolved"):
            job._JobSupervisor(
                time.monotonic() + 30, cleanup_pending_path=marker
            ).assert_no_cleanup_pending()

    def test_preview_cleanup_lease_clears_only_after_matching_hash_chained_receipt(self) -> None:
        root = self.private_root()
        config = {"state_dir": str(root / "state"), "temp_root": str(root / "workspaces")}
        evidence = job._start_preview_cleanup_lease(root, config)
        journal = AuditJournal(Path(evidence["state_dir"]), evidence["run_id"])
        journal.append(
            "cleanup_receipt",
            containers_removed=True,
            local_workspace_removed=True,
            resources_acquired=True,
        )
        result = job.CommandResult(
            0,
            json.dumps(
                {"run_id": evidence["run_id"], "stage": "complete", "failure_code": None}
            ).encode(),
            b"",
        )
        payload = job._consume_preview_result(root, result, evidence)
        self.assertEqual(payload["stage"], "complete")
        self.assertFalse((root / job.CLEANUP_PENDING_FILENAME).exists())

    def test_no_candidate_receipt_clears_preview_lease_without_resources(self) -> None:
        root = self.private_root()
        config = {"state_dir": str(root / "state"), "temp_root": str(root / "workspaces")}
        evidence = job._start_preview_cleanup_lease(root, config)
        journal = AuditJournal(Path(evidence["state_dir"]), evidence["run_id"])
        journal.append(
            "cleanup_receipt",
            containers_removed=True,
            local_workspace_removed=True,
            resources_acquired=False,
        )
        result = job.CommandResult(
            0,
            json.dumps(
                {
                    "run_id": evidence["run_id"],
                    "stage": "skipped",
                    "failure_code": "no_candidate",
                }
            ).encode(),
            b"",
        )

        payload = job._consume_preview_result(root, result, evidence)

        self.assertEqual(payload["stage"], "skipped")
        self.assertFalse((root / job.CLEANUP_PENDING_FILENAME).exists())

    def test_process_cleanup_cannot_erase_a_v2_preview_lease(self) -> None:
        root = self.private_root()
        config = {"state_dir": str(root / "state"), "temp_root": str(root / "workspaces")}
        job._start_preview_cleanup_lease(root, config)
        marker = root / job.CLEANUP_PENDING_FILENAME
        process = Mock()
        process.pid = 4242
        supervisor = job._JobSupervisor(
            time.monotonic() + 60,
            cleanup_pending_path=marker,
        )

        supervisor._record_cleanup_pending(process, "outer cleanup was initially unproven")
        self.assertEqual(json.loads(marker.read_text())["state"], "cleanup_pending")
        supervisor._clear_cleanup_pending_if_owned(process)

        evidence = json.loads(marker.read_text())
        self.assertEqual(evidence["version"], 2)
        self.assertEqual(evidence["state"], "cleanup_pending")

    def test_nonzero_cleanup_pending_or_malformed_preview_result_retains_cleanup_lease(
        self,
    ) -> None:
        for result in (
            None,
            job.CommandResult(0, b"not-json", b""),
            job.CommandResult(0, b"x" * (job.MAX_CAPTURE_BYTES + 1), b""),
        ):
            root = self.private_root()
            config = {"state_dir": str(root / "state"), "temp_root": str(root / "workspaces")}
            lease = job._start_preview_cleanup_lease(root, config)
            if result is None:
                result = job.CommandResult(
                    3,
                    json.dumps(
                        {
                            "run_id": lease["run_id"],
                            "stage": "cleanup_pending",
                            "failure_code": "cleanup_failed",
                        }
                    ).encode(),
                    b"",
                )
            with self.assertRaises(job.JobError):
                job._consume_preview_result(root, result, lease)
            evidence = job._read_cleanup_evidence(root / job.CLEANUP_PENDING_FILENAME)
            self.assertEqual(evidence["state"], "cleanup_pending")
            self.assertEqual(evidence["source"], "controller-result")

    def test_cleanup_evidence_is_cleared_only_after_the_same_group_is_proven_dead(self) -> None:
        root = self.private_root()
        marker = root / job.CLEANUP_PENDING_FILENAME
        marker.write_text(
            json.dumps(
                {
                    "version": 1,
                    "state": "cleanup_pending",
                    "pid": 4242,
                    "pgid": 4242,
                    "observed_at": "2026-07-18T20:00:00Z",
                    "reason": "termination proof was unavailable",
                }
            ),
            encoding="utf-8",
        )
        os.chmod(marker, 0o600)
        process = Mock()
        process.pid = 4242
        supervisor = job._JobSupervisor(
            time.monotonic() + 60,
            cleanup_pending_path=marker,
        )
        with patch.object(job, "_process_group_is_alive", return_value=False):
            supervisor.terminate(process)

        self.assertFalse(marker.exists())

    def test_nested_runner_cleanup_error_marks_host_cleanup_pending_and_blocks_uninstall(
        self,
    ) -> None:
        base = self.private_root()
        managed = base / ".leftovers"
        managed.mkdir(mode=0o700)
        install_root = managed / "install"
        install_root.mkdir(mode=0o700)
        (install_root / "tmp").mkdir(mode=0o700)
        (install_root / "manifest.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "install_root": str(install_root),
                    "publication": "disabled",
                    "model": "gpt-5.6-terra",
                    "launch_label": None,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(install_root / "manifest.json", 0o600)
        supervisor = job._JobSupervisor(
            time.monotonic() + 30,
            cleanup_pending_path=install_root / job.CLEANUP_PENDING_FILENAME,
        )
        command = [
            sys.executable,
            "-c",
            (
                "import json, sys; "
                "print(json.dumps({'error': 'RunnerCleanupError', "
                "'process_group': 98765, "
                "'message': 'runner-owned process group could not be terminated'}), "
                "file=sys.stderr); sys.exit(2)"
            ),
        ]
        result = job._run(
            command,
            environment={"PATH": "/usr/bin:/bin"},
            cwd=install_root,
            timeout=10,
            supervisor=supervisor,
            propagate_runner_cleanup_failure=True,
        )
        self.assertEqual(result.returncode, 2)
        evidence = json.loads((install_root / job.CLEANUP_PENDING_FILENAME).read_bytes())
        self.assertEqual(evidence["source"], "nested-runner")
        self.assertEqual(evidence["pid"], 98765)
        self.assertEqual(evidence["pgid"], 98765)
        self.assertIn("RunnerCleanupError", evidence["reason"])
        with (
            patch.object(uninstaller, "ROOT", base),
            patch.object(uninstaller, "MANAGED_BASE", managed),
            patch.object(uninstaller.sys, "platform", "darwin"),
            self.assertRaisesRegex(
                uninstaller.UninstallError, "preview cleanup remains unresolved"
            ),
        ):
            uninstaller.main(["--install-root", str(install_root)])
        self.assertTrue(install_root.exists())

    def test_nested_runner_cleanup_payload_requires_a_positive_integer_group_id(self) -> None:
        for process_group in (None, False, 0, -1, "98765", 98.5):
            payload = json.dumps(
                {
                    "error": "RunnerCleanupError",
                    "process_group": process_group,
                    "message": "runner-owned process group could not be terminated",
                }
            ).encode()
            self.assertIsNone(job._runner_cleanup_failure(payload))

    def test_fast_exit_captures_are_size_checked_before_reading(self) -> None:
        for descriptor, label in ((1, "stdout"), (2, "stderr")):
            with self.subTest(label=label):
                root = self.private_root()
                (root / "tmp").mkdir(mode=0o700)
                supervisor = job._JobSupervisor(time.monotonic() + 30)
                command = [
                    sys.executable,
                    "-c",
                    f"import os; os.ftruncate({descriptor}, {job.MAX_CAPTURE_BYTES + 1})",
                ]

                with self.assertRaisesRegex(job.JobError, f"bounded command {label} exceeded"):
                    job._run(
                        command,
                        environment={"PATH": "/usr/bin:/bin"},
                        cwd=root,
                        timeout=10,
                        supervisor=supervisor,
                    )

                self.assertEqual(list((root / "tmp").iterdir()), [])

    def test_capture_cleanup_continues_when_group_termination_fails(self) -> None:
        root = self.private_root()
        (root / "tmp").mkdir(mode=0o700)
        supervisor = job._JobSupervisor(time.monotonic() + 30)
        created: list[tuple[int, str]] = []
        original_mkstemp = tempfile.mkstemp

        def tracked_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
            descriptor, name = original_mkstemp(*args, **kwargs)
            created.append((descriptor, name))
            return descriptor, name

        with (
            patch.object(job.tempfile, "mkstemp", side_effect=tracked_mkstemp),
            patch.object(
                supervisor,
                "terminate",
                side_effect=job.JobError("termination proof failed"),
            ),
            self.assertRaisesRegex(job.JobError, "termination proof failed"),
        ):
            job._run(
                [sys.executable, "-c", "pass"],
                environment={"PATH": "/usr/bin:/bin"},
                cwd=root,
                timeout=10,
                supervisor=supervisor,
            )

        self.assertEqual(len(created), 2)
        for descriptor, name in created:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertFalse(Path(name).exists())

    def test_private_json_reader_rejects_oversized_and_linked_files(self) -> None:
        root = self.private_root()
        oversized = root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(129)
        os.chmod(oversized, 0o600)
        with self.assertRaisesRegex(job.JobError, "private owner-controlled"):
            job._read_json_file(oversized, label="worker result", maximum_bytes=128)

        target = root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        os.chmod(target, 0o600)
        linked = root / "linked.json"
        linked.symlink_to(target)
        with self.assertRaisesRegex(job.JobError, "private owner-controlled"):
            job._read_json_file(linked, label="worker result")

    def test_cleanup_journal_rejects_an_oversized_jsonl_line(self) -> None:
        root = self.private_root()
        config = {"state_dir": str(root / "state"), "temp_root": str(root / "workspaces")}
        evidence = job._start_preview_cleanup_lease(root, config)
        journal = Path(evidence["state_dir"]) / "runs" / f"{evidence['run_id']}.jsonl"
        journal.parent.mkdir(parents=True, mode=0o700)
        journal.write_bytes(b"x" * (job.MAX_JOURNAL_LINE_BYTES + 1))
        os.chmod(journal, 0o600)

        self.assertFalse(
            job._verified_cleanup_receipt(
                root,
                evidence,
                {"run_id": evidence["run_id"], "stage": "complete"},
            )
        )

    def test_deadline_after_wrapper_exit_cannot_erase_nested_cleanup_evidence(self) -> None:
        root = self.private_root()
        (root / "tmp").mkdir(mode=0o700)
        marker = root / job.CLEANUP_PENDING_FILENAME
        supervisor = job._JobSupervisor(
            time.monotonic() + 30,
            cleanup_pending_path=marker,
        )
        command = [
            sys.executable,
            "-c",
            (
                "import json, sys; "
                "print(json.dumps({'error': 'RunnerCleanupError', "
                "'process_group': 97531, "
                "'message': 'runner-owned process group could not be terminated'}), "
                "file=sys.stderr); sys.exit(2)"
            ),
        ]

        def deadline_after_marker() -> None:
            if marker.exists():
                raise job.JobError("job-wide deadline expired")

        with (
            patch.object(supervisor, "check", side_effect=deadline_after_marker),
            self.assertRaisesRegex(job.JobError, "job-wide deadline expired"),
        ):
            job._run(
                command,
                environment={"PATH": "/usr/bin:/bin"},
                cwd=root,
                timeout=10,
                supervisor=supervisor,
                propagate_runner_cleanup_failure=True,
            )

        evidence = json.loads(marker.read_bytes())
        self.assertEqual(evidence["source"], "nested-runner")
        self.assertEqual(evidence["pgid"], 97531)

    def test_uninstaller_and_status_refuse_unproven_cleanup(self) -> None:
        base = self.private_root()
        managed = base / ".leftovers"
        managed.mkdir(mode=0o700)
        install_root = managed / "install"
        install_root.mkdir(mode=0o700)
        (install_root / "manifest.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "install_root": str(install_root),
                    "publication": "disabled",
                    "model": "gpt-5.6-terra",
                    "launch_label": None,
                }
            ),
            encoding="utf-8",
        )
        (install_root / uninstaller.CLEANUP_PENDING_FILENAME).write_text(
            json.dumps(
                {
                    "version": 2,
                    "state": "cleanup_in_progress",
                    "run_id": "a" * 32,
                    "container_label": "io.leftovers.job=" + "a" * 32,
                    "install_root": str(install_root),
                    "state_dir": str(install_root / "state"),
                    "workspace_root": str(install_root / "workspaces"),
                    "pid": 4242,
                    "pgid": 4242,
                    "observed_at": "2026-07-18T20:00:00Z",
                    "reason": "active child process group could not be terminated after SIGKILL",
                }
            ),
            encoding="utf-8",
        )
        os.chmod(install_root / "manifest.json", 0o600)
        os.chmod(install_root / uninstaller.CLEANUP_PENDING_FILENAME, 0o600)
        with (
            patch.object(uninstaller, "ROOT", base),
            patch.object(uninstaller, "MANAGED_BASE", managed),
            patch.object(uninstaller.sys, "platform", "darwin"),
            self.assertRaisesRegex(
                uninstaller.UninstallError, "preview cleanup remains unresolved"
            ),
        ):
            uninstaller.main(["--install-root", str(install_root)])

        output = io.StringIO()
        with (
            patch.object(uninstaller, "ROOT", base),
            patch.object(uninstaller, "MANAGED_BASE", managed),
            patch.object(status_reporter, "_launch_loaded", return_value=False),
            redirect_stdout(output),
        ):
            status = status_reporter.main(["--install-root", str(install_root)])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(report["job_state"], "cleanup-pending")
        self.assertEqual(report["cleanup_pending"]["state"], "cleanup_in_progress")
        self.assertEqual(report["cleanup_pending"]["pgid"], 4242)
        self.assertTrue(install_root.exists())

    def test_launchd_one_shot_is_private_nonpersistent_and_credential_free(self) -> None:
        root = self.private_root()
        for name in ("job.py", "codex", "rehearsal.py"):
            path = root / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o700)
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(Path.home()),
            "CODEX_HOME": str(Path.home() / ".codex"),
        }
        with (
            patch.object(installer.shutil, "which", return_value="/bin/launchctl"),
            patch.object(installer, "_run_checked", return_value="") as run_checked,
        ):
            label, plist_path = installer._launch_once(
                root,
                job=root / "job.py",
                codex=root / "codex",
                rehearsal=root / "rehearsal.py",
                environment=environment,
            )

        with plist_path.open("rb") as stream:
            payload = plistlib.load(stream)
        self.assertEqual(payload["Label"], label)
        self.assertTrue(payload["RunAtLoad"])
        self.assertFalse(payload["KeepAlive"])
        self.assertEqual(payload["ProcessType"], "Background")
        self.assertTrue(payload["LowPriorityIO"])
        self.assertEqual(Path(payload["WorkingDirectory"]), root)
        self.assertNotIn("GITHUB_TOKEN", str(payload))
        self.assertNotIn("GH_TOKEN", str(payload))
        self.assertNotIn("CODEX_HOME", str(payload))
        self.assertNotIn("LEFTOVERS_CODEX_BIN", str(payload))
        self.assertNotIn("EnvironmentVariables", payload)
        self.assertEqual(plist_path.stat().st_mode & 0o777, 0o600)
        bootstrap = run_checked.call_args.args[0]
        self.assertEqual(bootstrap[:2], ["/bin/launchctl", "bootstrap"])
        arguments = payload["ProgramArguments"]
        self.assertEqual(arguments[:2], ["/usr/bin/env", "-i"])
        self.assertIn(f"HOME={environment['HOME']}", arguments)
        self.assertIn(f"PATH={environment['PATH']}", arguments)
        self.assertIn(f"LEFTOVERS_REHEARSAL_AGENT={root / 'rehearsal.py'}", arguments)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", arguments)
        self.assertEqual(arguments[-2:], ["--launch-label", label])

    def test_launch_now_rejects_tcc_protected_user_folders(self) -> None:
        home = self.private_root() / "home"
        for name in ("Desktop", "Documents", "Downloads"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    installer.InstallError,
                    "protected user folder",
                ),
            ):
                installer._reject_tcc_protected_launch_root(
                    home / name / "Leftovers" / ".leftovers" / "install",
                    home=home,
                )

        installer._reject_tcc_protected_launch_root(
            home / "Developer" / "Leftovers" / ".leftovers" / "install",
            home=home,
        )

    def test_repeated_launch_removes_only_the_prior_manifest_bound_service_and_plist(
        self,
    ) -> None:
        root = self.private_root()
        launchd = root / "launchd"
        launchd.mkdir(mode=0o700)
        old_label = f"dev.leftovers.once.{os.getuid()}.20260718210000.1234"
        old_plist = launchd / f"{old_label}.plist"
        old_plist.write_bytes(plistlib.dumps({"Label": old_label}))
        os.chmod(old_plist, 0o600)
        unrelated = launchd / "unrelated.plist"
        unrelated.write_bytes(plistlib.dumps({"Label": "unrelated"}))
        os.chmod(unrelated, 0o600)
        manifest = {
            "version": 1,
            "install_root": str(root),
            "publication": "disabled",
            "model": "gpt-5.6-terra",
            "launch_label": old_label,
            "launch_plist": str(old_plist),
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        os.chmod(root / "manifest.json", 0o600)
        launchctl_results = [
            Mock(returncode=0, stdout=b"", stderr=b""),
            Mock(returncode=0, stdout=b"", stderr=b""),
            Mock(
                returncode=1,
                stdout=b"",
                stderr=b"Could not find service",
            ),
        ]
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
        package_lock = installer._acquire_package_lock(root)
        self.addCleanup(os.close, package_lock)
        with (
            patch.object(installer.shutil, "which", return_value="/bin/launchctl"),
            patch.object(
                installer.subprocess,
                "run",
                side_effect=launchctl_results,
            ) as launchctl,
        ):
            self.assertTrue(
                installer._cleanup_previous_launch(
                    root,
                    environment,
                    lock_descriptor=package_lock,
                )
            )

        service = f"gui/{os.getuid()}/{old_label}"
        self.assertEqual(
            [call.args[0] for call in launchctl.call_args_list],
            [
                ["/bin/launchctl", "print", service],
                ["/bin/launchctl", "bootout", service],
                ["/bin/launchctl", "print", service],
            ],
        )
        self.assertFalse(old_plist.exists())
        self.assertTrue(unrelated.exists())

        for name in ("job.py", "codex", "rehearsal.py"):
            path = root / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o700)
        with (
            patch.object(installer.shutil, "which", return_value="/bin/launchctl"),
            patch.object(installer, "_run_checked", return_value=""),
        ):
            new_label, new_plist = installer._launch_once(
                root,
                job=root / "job.py",
                codex=root / "codex",
                rehearsal=root / "rehearsal.py",
                environment=environment,
            )
        self.assertNotEqual(new_label, old_label)
        self.assertTrue(new_plist.exists())
        self.assertTrue(unrelated.exists())

    def test_launch_transaction_persists_binding_and_cleanup_pending_on_unload_failure(
        self,
    ) -> None:
        root = self.private_root()
        launchd = root / "launchd"
        launchd.mkdir(mode=0o700)
        label = f"dev.leftovers.once.{os.getuid()}.20260718210100.2345"
        plist_path = launchd / f"{label}.plist"
        plist_path.write_bytes(plistlib.dumps({"Label": label}))
        os.chmod(plist_path, 0o600)
        manifest = {
            "version": 1,
            "install_root": str(root),
            "publication": "disabled",
            "model": "gpt-5.6-terra",
            "launch_label": None,
            "launch_plist": None,
            "launch_behavior": "none",
        }
        original_write = installer._write_manifest
        writes = 0

        def fail_final_write(path: Path, value: dict[str, object]) -> None:
            nonlocal writes
            writes += 1
            if writes == 1:
                original_write(path, value)
                return
            raise installer.InstallError("synthetic final manifest failure")

        environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
        package_lock = installer._acquire_package_lock(root)
        self.addCleanup(os.close, package_lock)
        with (
            patch.object(
                installer,
                "_prepare_launch_once",
                return_value=(label, plist_path, "/bin/launchctl"),
            ),
            patch.object(installer, "_bootstrap_launch", return_value=None),
            patch.object(installer, "_write_manifest", side_effect=fail_final_write),
            patch.object(installer.shutil, "which", return_value="/bin/launchctl"),
            patch.object(
                installer.subprocess,
                "run",
                side_effect=[
                    Mock(returncode=0, stdout=b"", stderr=b""),
                    Mock(returncode=1, stdout=b"", stderr=b"synthetic bootout failure"),
                ],
            ),
            self.assertRaisesRegex(installer.InstallError, "cleanup-pending evidence"),
        ):
            installer._bind_launched_job(
                root,
                job=root / "job.py",
                codex=root / "codex",
                rehearsal=root / "rehearsal.py",
                environment=environment,
                manifest=manifest,
                lock_descriptor=package_lock,
            )

        persisted = json.loads((root / "manifest.json").read_bytes())
        self.assertEqual(persisted["launch_label"], label)
        self.assertEqual(persisted["launch_plist"], str(plist_path))
        self.assertEqual(persisted["launch_behavior"], "pending-bootstrap")
        evidence = json.loads((root / installer.CLEANUP_PENDING_FILENAME).read_bytes())
        self.assertEqual(evidence["source"], "launchd-transaction")
        self.assertEqual(evidence["launch_label"], label)
        self.assertEqual(evidence["launch_plist"], str(plist_path))
        self.assertEqual(
            uninstaller._cleanup_pending_evidence(root)["launch_label"],
            label,
        )
        self.assertEqual(
            job._read_cleanup_evidence(root / installer.CLEANUP_PENDING_FILENAME)["launch_label"],
            label,
        )
        self.assertTrue(plist_path.exists())

    def test_absent_prior_service_is_confirmed_before_its_exact_plist_is_removed(
        self,
    ) -> None:
        root = self.private_root()
        launchd = root / "launchd"
        launchd.mkdir(mode=0o700)
        label = f"dev.leftovers.once.{os.getuid()}.20260718210115.2377"
        plist_path = launchd / f"{label}.plist"
        plist_path.write_bytes(plistlib.dumps({"Label": label}))
        os.chmod(plist_path, 0o600)
        missing = b"Could not find service"
        with (
            patch.object(installer.shutil, "which", return_value="/bin/launchctl"),
            patch.object(
                installer.subprocess,
                "run",
                side_effect=[
                    Mock(returncode=113, stdout=b"", stderr=missing),
                    Mock(returncode=3, stdout=b"", stderr=b"No such process"),
                    Mock(returncode=113, stdout=b"", stderr=missing),
                ],
            ) as launchctl,
        ):
            unloaded = installer._cleanup_launch_binding(
                root,
                {"launch_label": label, "launch_plist": str(plist_path)},
                {"PATH": "/usr/bin:/bin"},
            )
        self.assertFalse(unloaded)
        self.assertFalse(plist_path.exists())
        self.assertEqual(launchctl.call_args_list[1].args[0][1], "bootout")

    def test_reinstall_refuses_an_out_of_binding_launch_plist_without_remote_action(
        self,
    ) -> None:
        root = self.private_root()
        label = f"dev.leftovers.once.{os.getuid()}.20260718210130.2399"
        outside = root / "outside.plist"
        outside.write_bytes(plistlib.dumps({"Label": label}))
        os.chmod(outside, 0o600)
        (root / "manifest.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "install_root": str(root),
                    "publication": "disabled",
                    "model": "gpt-5.6-terra",
                    "launch_label": label,
                    "launch_plist": str(outside),
                }
            ),
            encoding="utf-8",
        )
        os.chmod(root / "manifest.json", 0o600)
        package_lock = installer._acquire_package_lock(root)
        self.addCleanup(os.close, package_lock)
        with (
            patch.object(installer.subprocess, "run") as launchctl,
            self.assertRaisesRegex(installer.InstallError, "exact managed binding"),
        ):
            installer._cleanup_previous_launch(
                root,
                {"PATH": "/usr/bin:/bin"},
                lock_descriptor=package_lock,
            )
        launchctl.assert_not_called()
        self.assertTrue(outside.exists())

    def test_shared_lock_serializes_launch_handoff_reinstall_and_uninstall(self) -> None:
        root = self.private_root()
        installer_lock = installer._acquire_package_lock(root)
        label = f"dev.leftovers.once.{os.getuid()}.20260718210200.3456"
        with self.assertRaisesRegex(installer.InstallError, "job is active"):
            installer._acquire_package_lock(root)
        with (
            patch.object(uninstaller.time, "monotonic", side_effect=[0.0, 16.0]),
            patch.object(uninstaller.time, "sleep", return_value=None),
            self.assertRaisesRegex(uninstaller.UninstallError, "detached job is still active"),
        ):
            uninstaller._acquire_job_lock(root)

        released = threading.Event()

        def release_installer() -> None:
            time.sleep(0.05)
            os.close(installer_lock)
            released.set()

        thread = threading.Thread(target=release_installer)
        thread.start()
        job_lock = job._acquire_job_lock(root, label)
        thread.join(timeout=2)
        self.assertTrue(released.is_set())
        self.assertIsNotNone(job_lock)
        assert job_lock is not None
        try:
            with self.assertRaisesRegex(installer.InstallError, "job is active"):
                installer._acquire_package_lock(root)
        finally:
            os.close(job_lock)

    def test_uninstaller_unloads_only_the_manifest_bound_service_before_root_removal(
        self,
    ) -> None:
        base = self.private_root()
        managed = base / ".leftovers"
        managed.mkdir(mode=0o700)
        install_root = managed / "install"
        install_root.mkdir(mode=0o700)
        launchd = install_root / "launchd"
        launchd.mkdir(mode=0o700)
        label = f"dev.leftovers.once.{os.getuid()}.20260718210300.4567"
        plist_path = launchd / f"{label}.plist"
        plist_path.write_bytes(plistlib.dumps({"Label": label}))
        os.chmod(plist_path, 0o600)
        (install_root / "manifest.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "install_root": str(install_root),
                    "publication": "disabled",
                    "model": "gpt-5.6-terra",
                    "launch_label": label,
                    "launch_plist": str(plist_path),
                }
            ),
            encoding="utf-8",
        )
        os.chmod(install_root / "manifest.json", 0o600)
        fake_launchctl = base / "launchctl"
        fake_launchctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_launchctl.chmod(0o700)
        service = f"gui/{os.getuid()}/{label}"
        output = io.StringIO()
        with (
            patch.object(uninstaller, "ROOT", base),
            patch.object(uninstaller, "MANAGED_BASE", managed),
            patch.object(uninstaller, "LAUNCHCTL_PATH", fake_launchctl),
            patch.object(uninstaller.sys, "platform", "darwin"),
            patch.object(
                uninstaller.subprocess,
                "run",
                side_effect=[
                    Mock(returncode=0, stdout=b"", stderr=b""),
                    Mock(returncode=0, stdout=b"", stderr=b""),
                    Mock(
                        returncode=1,
                        stdout=b"",
                        stderr=b"Could not find service",
                    ),
                ],
            ) as launchctl,
            redirect_stdout(output),
        ):
            status = uninstaller.main(["--install-root", str(install_root)])

        self.assertEqual(status, 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["launch_service_unloaded"])
        self.assertFalse(install_root.exists())
        self.assertEqual(
            [call.args[0] for call in launchctl.call_args_list],
            [
                [str(fake_launchctl), "print", service],
                [str(fake_launchctl), "bootout", service],
                [str(fake_launchctl), "print", service],
            ],
        )

    def test_uninstaller_reads_manifest_and_cleanup_marker_without_following_links(
        self,
    ) -> None:
        root = self.private_root()
        target = root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        os.chmod(target, 0o600)
        (root / "manifest.json").symlink_to(target)
        with self.assertRaisesRegex(uninstaller.UninstallError, "safe regular file"):
            uninstaller._read_manifest(root)

        (root / "manifest.json").unlink()
        marker = root / uninstaller.CLEANUP_PENDING_FILENAME
        with marker.open("wb") as stream:
            stream.truncate(8_193)
        os.chmod(marker, 0o600)
        with self.assertRaisesRegex(uninstaller.UninstallError, "owner-controlled"):
            uninstaller._cleanup_pending_evidence(root)

    def test_uninstaller_removes_only_manifest_bound_private_root(self) -> None:
        base = self.private_root()
        managed = base / ".leftovers"
        managed.mkdir(mode=0o700)
        install_root = managed / "install"
        install_root.mkdir(mode=0o700)
        (install_root / "manifest.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "install_root": str(install_root),
                    "publication": "disabled",
                    "model": "gpt-5.6-terra",
                    "launch_label": None,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(install_root / "manifest.json", 0o600)
        with (
            patch.object(uninstaller, "ROOT", base),
            patch.object(uninstaller, "MANAGED_BASE", managed),
            patch.object(uninstaller.sys, "platform", "darwin"),
        ):
            status = uninstaller.main(["--install-root", str(install_root)])

        self.assertEqual(status, 0)
        self.assertFalse(install_root.exists())
        self.assertTrue(managed.exists())

    def test_uninstaller_rejects_root_outside_managed_base(self) -> None:
        base = self.private_root()
        managed = base / ".leftovers"
        managed.mkdir(mode=0o700)
        outside = base / "outside"
        outside.mkdir(mode=0o700)
        with (
            patch.object(uninstaller, "ROOT", base),
            patch.object(uninstaller, "MANAGED_BASE", managed),
            self.assertRaisesRegex(uninstaller.UninstallError, "escapes"),
        ):
            uninstaller._validated_root(outside)

    def test_portable_archive_is_reproducible_and_build_verified(self) -> None:
        root = self.private_root()
        first = root / "first.tar.gz"
        second = root / "second.tar.gz"
        first_result = builder.build(first)
        second_result = builder.build(second)

        self.assertTrue(first_result["verified"])
        self.assertEqual(first_result["sha256"], second_result["sha256"])
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)
        with tarfile.open(first, "r:gz") as archive:
            prefix = builder.PACKAGE_NAME
            names = {member.name for member in archive.getmembers()}
            self.assertIn(f"{prefix}/PACKAGE-MANIFEST.json", names)
            self.assertIn(f"{prefix}/scripts/install-macos.sh", names)
            self.assertIn(f"{prefix}/scripts/uninstall-macos.sh", names)
            self.assertIn(f"{prefix}/vm/strict_vm_launcher.swift", names)
            self.assertIn(f"{prefix}/vm/strict-vm.entitlements.plist", names)
            self.assertIn(f"{prefix}/vm/check.sh", names)
            self.assertIn(f"{prefix}/vm/smoke_init.sh", names)
            manifest_stream = archive.extractfile(f"{prefix}/PACKAGE-MANIFEST.json")
            assert manifest_stream is not None
            manifest = json.load(manifest_stream)
        self.assertEqual(manifest["publication_default"], "disabled")
        self.assertEqual(manifest["entrypoint"], "scripts/install-macos.sh")
        modes = {entry["path"]: entry["mode"] for entry in manifest["files"]}
        self.assertEqual(modes["vm/check.sh"], "0700")
        self.assertEqual(modes["vm/smoke_init.sh"], "0700")
        self.assertEqual(modes["vm/strict_vm_launcher.swift"], "0600")
        self.assertEqual(modes["vm/strict-vm.entitlements.plist"], "0600")


if __name__ == "__main__":
    unittest.main()
