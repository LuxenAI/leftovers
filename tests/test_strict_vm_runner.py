from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
import tempfile
import textwrap
import types
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from leftovers.config import StrictVMConfig
from leftovers.model_mediator import (
    FixtureMediator,
    FixtureTurn,
    MediationLimits,
    MediationRequest,
    MediationStage,
    ReportedTokenCounts,
    canonical_json_bytes,
)
from leftovers.strict_vm_runner import (
    STRICT_VM_EXECUTION_ENABLED,
    StrictVMLaunchError,
    StrictVMOneEpochController,
    StrictVMOutputOverflow,
    StrictVMReadiness,
    StrictVMReadinessError,
    StrictVMReceiptError,
    StrictVMRunnerError,
    _drain_launcher,
    _read_pinned_policy,
    _stop_group,
    _validate_guest_policy,
    verify_static_readiness,
)
from leftovers.vm_bundle import (
    FIXTURE_USAGE_EVIDENCE_SHA256,
    MIN_RESULT_TAIL_BYTES,
    MIN_SCRATCH_BYTES,
    BundleError,
    authorize_mediation_result,
)


class StrictVMOneEpochControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.lease_root = self.root / "leases"
        self.lease_root.mkdir(mode=0o700)
        self.boot = self.root / "boot"
        self.boot.mkdir(mode=0o700)
        self.kernel = self.boot / "kernel"
        self.initrd = self.boot / "initrd"
        self.root_disk = self.boot / "root.raw"
        self.kernel.write_bytes(b"kernel")
        self.initrd.write_bytes(b"initrd")
        self.root_disk.write_bytes(b"\0" * (1 << 20))
        self.guest_policy = self.boot / "guest-policy.json"
        self.write_guest_policy()
        for path in (self.kernel, self.initrd, self.root_disk):
            os.chmod(path, 0o400)
        os.chmod(self.guest_policy, 0o400)
        os.chmod(self.boot, 0o500)
        self.source = self.root / "source.tar.gz"
        self.source.write_bytes(b"opaque-source-capsule")
        os.chmod(self.source, 0o600)
        self.audit = self.root / "launcher-audit.json"
        self.run_id = "f" * 32

    def tearDown(self) -> None:
        os.chmod(self.boot, 0o700)
        self.temporary.cleanup()

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_guest_policy(self, *, root_disk_sha256: str | None = None) -> None:
        value = {
            "boot_artifacts": {
                "initrd_sha256": self.digest(self.initrd),
                "kernel_sha256": self.digest(self.kernel),
                "root_disk_sha256": root_disk_sha256 or self.digest(self.root_disk),
            },
            "execution_mode": "reject-all-actions",
            "profile": "leftovers-guest-rejection-only-v1",
            "schema_version": 1,
        }
        self.guest_policy.write_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

    def launcher(self, behavior: str = "good") -> Path:
        path = self.root / f"launcher-{behavior}.py"
        source_root = Path(__file__).resolve().parents[1] / "src"
        path.write_text(
            textwrap.dedent(
                f"""\
                #!{sys.executable}
                import hashlib
                import json
                import os
                import sys
                from datetime import UTC, datetime
                sys.path.insert(0, {str(source_root)!r})
                from leftovers.vm_bundle import build_tail_result

                behavior = {behavior!r}
                manifest_path = sys.argv[2]
                manifest = json.loads(open(manifest_path, encoding="utf-8").read())
                audit = {str(self.audit)!r}
                with open(audit, "w", encoding="utf-8") as handle:
                    json.dump({{"argv": sys.argv, "env": dict(os.environ)}}, handle, sort_keys=True)
                if behavior == "flood":
                    sys.stdout.write("x" * (70 * 1024))
                    raise SystemExit(0)
                if behavior == "failed":
                    print(json.dumps({{"status": "failed"}}))
                    raise SystemExit(1)
                scratch = manifest["scratch_disk"]["path"]
                request = manifest["request_disk"]
                patch = "diff --git a/a b/a\\n"
                patch_sha256 = hashlib.sha256(patch.encode("utf-8")).hexdigest()
                guest_policy_sha256 = manifest["guest_policy_sha256"]
                if behavior == "bad_guest_result":
                    guest_policy_sha256 = "0" * 64
                build_tail_result(
                    __import__("pathlib").Path(scratch),
                    scratch_size=manifest["scratch_disk"]["size_bytes"],
                    tail_region_bytes={MIN_RESULT_TAIL_BYTES},
                    run_id=manifest["run_id"],
                    round=0,
                    stage="implementation",
                    sections={{
                        "guest_receipt": {{
                            "schema_version": 1,
                            "run_id": manifest["run_id"],
                            "round": 0,
                            "stage": "implementation",
                            "request_sha256": request["sha256"],
                            "guest_policy_sha256": guest_policy_sha256,
                            "isolation": {{
                                "schema_version": 1, "network": "absent", "host_shares": 0,
                                "credential_files": 0, "uid": 65534, "no_new_privs": True,
                                "seccomp": True, "landlock": True, "cgroup_v2": True,
                                "pid1": True, "root_read_only": True,
                            }},
                        }},
                        "observations": [{{
                            "action_id": "patch", "status": "complete",
                            "truncated": False, "tail": "",
                        }}, {{
                            "action_id": "finish", "status": "complete",
                            "truncated": False, "tail": "",
                        }}],
                        "canonical_patch": patch,
                        "checks": [],
                        "stage_result": {{
                            "status": "complete", "summary": "bounded fixture",
                            "action_ids": ["patch", "finish"],
                            "cumulative_patch_sha256": patch_sha256,
                        }},
                    }},
                )
                observed_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                )
                receipt = {{
                    "schema_version": 2,
                    "launcher_version": "0.3.0-proof",
                    "manifest_sha256": hashlib.sha256(open(manifest_path, "rb").read()).hexdigest(),
                    "run_id": manifest["run_id"],
                    "mode": "run",
                    "status": "guest_stopped",
                    "started_at": observed_at,
                    "finished_at": observed_at,
                    "config_validated": True,
                    "stop_reason": "guest_shutdown",
                    "limits": {{
                        "cpu_count": manifest["cpu_count"],
                        "memory_bytes": manifest["memory_bytes"],
                        "wall_time_seconds": manifest["wall_time_seconds"],
                        "scratch_bytes": manifest["scratch_disk"]["size_bytes"],
                    }},
                    "artifacts": {{
                        "kernel_sha256": manifest["kernel"]["sha256"],
                        "initrd_sha256": manifest["initrd"]["sha256"],
                        "root_disk_sha256": manifest["root_disk"]["sha256"],
                        "request_disk_sha256": request["sha256"],
                    }},
                    "devices": {{
                        "platform": "generic", "boot_loader": "linux",
                        "network_devices": 0, "socket_devices": 0, "directory_shares": 0,
                        "serial_ports": 0, "console_devices": 0, "graphics_devices": 0,
                        "audio_devices": 0, "usb_controllers": 0, "keyboards": 0,
                        "pointing_devices": 0, "entropy_devices": 0,
                        "memory_balloon_devices": 0,
                        "storage_devices": [
                            {{"role": "root", "kind": "virtio-block", "read_only": True,
                              "size_bytes": os.path.getsize(manifest["root_disk"]["path"])}},
                            {{"role": "scratch", "kind": "virtio-block", "read_only": False,
                              "size_bytes": manifest["scratch_disk"]["size_bytes"]}},
                            {{"role": "request", "kind": "virtio-block", "read_only": True,
                              "size_bytes": os.path.getsize(request["path"])}},
                        ],
                    }},
                    "scratch_retained": True,
                    "error_code": None,
                }}
                if behavior == "unknown":
                    receipt["unexpected"] = True
                if behavior == "mismatch":
                    receipt["run_id"] = "0" * 32
                if behavior == "duplicate":
                    print('{{"run_id":"one","run_id":"two"}}')
                    raise SystemExit(0)
                if behavior == "noncanonical":
                    print(json.dumps(receipt))
                else:
                    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
                """
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o500)
        return path

    def config(self, behavior: str = "good") -> StrictVMConfig:
        launcher = self.launcher(behavior)
        return StrictVMConfig(
            enabled=True,
            launcher_path=str(launcher),
            launcher_sha256=self.digest(launcher),
            boot_artifact_directory=str(self.boot),
            kernel_path=str(self.kernel),
            kernel_sha256=self.digest(self.kernel),
            initrd_path=str(self.initrd),
            initrd_sha256=self.digest(self.initrd),
            root_disk_path=str(self.root_disk),
            root_disk_sha256=self.digest(self.root_disk),
            guest_policy_path=str(self.guest_policy),
            cpu_count=1,
            memory_bytes=512 << 20,
            scratch_bytes=MIN_SCRATCH_BYTES,
            wall_time_seconds=30,
            max_rounds=1,
            max_request_bytes=4 << 20,
            result_region_bytes=MIN_RESULT_TAIL_BYTES,
            max_observation_bytes=1024,
        )

    def execute_epoch(self, behavior: str = "good"):
        controller = StrictVMOneEpochController(self.config(behavior), self.lease_root)
        readiness = StrictVMReadiness(
            launcher_sha256="1" * 64,
            kernel_sha256=self.digest(self.kernel),
            initrd_sha256=self.digest(self.initrd),
            root_disk_sha256=self.digest(self.root_disk),
            root_disk_bytes=self.root_disk.stat().st_size,
            guest_policy_sha256=self.digest(self.guest_policy),
        )
        with (
            mock.patch("leftovers.strict_vm_runner.STRICT_VM_EXECUTION_ENABLED", True),
            mock.patch(
                "leftovers.strict_vm_runner.verify_static_readiness", return_value=readiness
            ),
        ):
            return controller.run_epoch(
                run_id=self.run_id,
                round=0,
                stage="implementation",
                source_capsule=self.source,
                task={"issue": 1},
                authorization=self.fixture_authorization(self.run_id),
            )

    @staticmethod
    def action_policy() -> dict[str, object]:
        return {
            "schema_version": 1,
            "provider": "fixture",
            "model": "terra-fixture",
            "reasoning_effort": "high",
            "allowed_check_ids": [],
            "max_actions": 8,
        }

    def action_batch(self, patch_sha256: str, run_id: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "run_id": run_id,
            "round": 0,
            "stage": "implementation",
            "provider": "fixture",
            "model": "terra-fixture",
            "reasoning_effort": "high",
            "actions": [
                {"id": "patch", "type": "apply_patch", "patch_sha256": patch_sha256},
                {
                    "id": "finish",
                    "type": "finish",
                    "status": "complete",
                    "summary": "bounded fixture",
                },
            ],
        }

    def fixture_authorization(self, run_id: str):
        proposed_patch = b"diff --git a/a b/a\n"
        request = MediationRequest(
            run_id=run_id,
            round=0,
            stage=MediationStage.IMPLEMENTATION,
            provider="fixture",
            model="terra-fixture",
            reasoning_effort="high",
            input_bytes=canonical_json_bytes({"fixture": "strict-vm"}),
            allowed_check_ids=frozenset(),
            limits=MediationLimits(
                max_response_bytes=256 * 1024,
                max_patch_bytes=256 * 1024,
                max_actions=8,
                input_token_cap=100,
                output_token_cap=100,
                total_token_cap=200,
                call_index=1,
                call_cap=1,
            ),
            deadline_at=datetime.now(UTC) + timedelta(minutes=2),
        )
        raw = canonical_json_bytes(
            self.action_batch(hashlib.sha256(proposed_patch).hexdigest(), run_id)
        )
        result = FixtureMediator(
            (
                FixtureTurn(
                    raw,
                    ReportedTokenCounts(10, 5, 0, 0, 15, "fixture", True),
                    proposed_patch,
                ),
            )
        ).mediate(request)
        return authorize_mediation_result(
            request,
            result,
            policy=self.action_policy(),
            curated_checks=(),
            token_ledger_reservation_id="d" * 64,
            provider_usage_evidence_sha256=FIXTURE_USAGE_EVIDENCE_SHA256,
            fixture=True,
        )

    def test_success_uses_fixed_empty_environment_argv_and_exact_cleanup(self) -> None:
        result = self.execute_epoch()
        self.assertFalse(STRICT_VM_EXECUTION_ENABLED)
        self.assertEqual(result.canonical_patch, b"diff --git a/a b/a\n")
        self.assertTrue(result.cleanup.path_absence_proven)
        self.assertFalse((self.lease_root / f"leftovers-vm-{self.run_id}").exists())
        audit = json.loads(self.audit.read_text(encoding="utf-8"))
        self.assertEqual(audit["argv"][1], "--run")
        self.assertTrue(audit["argv"][2].endswith("/manifest.json"))
        # ``subprocess`` receives env={} exactly. CPython may synthesize this
        # locale marker on macOS; no inherited PATH, HOME, or credentials pass.
        self.assertTrue(set(audit["env"]).issubset({"LC_CTYPE"}))

    def test_constructor_has_no_lease_side_effect(self) -> None:
        StrictVMOneEpochController(self.config(), self.lease_root)
        self.assertEqual(list(self.lease_root.iterdir()), [])

    def test_execution_gate_fails_before_readiness_or_lease_creation(self) -> None:
        controller = StrictVMOneEpochController(self.config(), self.lease_root)
        with (
            mock.patch(
                "leftovers.strict_vm_runner.verify_static_readiness",
                side_effect=AssertionError("readiness must not run"),
            ),
            self.assertRaisesRegex(StrictVMRunnerError, "hard-disabled"),
        ):
            controller.run_epoch(
                run_id=self.run_id,
                round=0,
                stage="implementation",
                source_capsule=self.source,
                task={"issue": 1},
                authorization=self.fixture_authorization(self.run_id),
            )
        self.assertEqual(list(self.lease_root.iterdir()), [])

    def test_success_never_probes_or_signals_a_reaped_process_group(self) -> None:
        launcher = self.root / "single-process-launcher.py"
        launcher.write_text(
            f"#!{sys.executable}\nimport sys\nsys.stdout.write('ok')\n",
            encoding="utf-8",
        )
        os.chmod(launcher, 0o500)
        manifest = self.root / "unused-manifest"
        manifest.write_text("fixture", encoding="utf-8")
        with mock.patch(
            "leftovers.strict_vm_runner._group_alive",
            side_effect=AssertionError("post-reap PGID probe"),
        ):
            returncode, stdout, stderr = _drain_launcher(str(launcher), manifest, timeout_seconds=2)
        self.assertEqual((returncode, stdout, stderr), (0, b"ok", b""))

    def test_stop_group_does_not_probe_a_group_after_reaping_its_leader(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        # The leader exits after SIGTERM while its pre-reap zombie still makes
        # Linux killpg(..., 0) report a live group.
        process.poll.side_effect = (None, None, 0)
        with mock.patch("leftovers.strict_vm_runner.os.killpg") as killpg:
            self.assertTrue(_stop_group(process))
        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(12345, 0),
                mock.call(12345, signal.SIGTERM),
                mock.call(12345, 0),
            ],
        )

    def test_output_flood_retains_the_lease_after_launch(self) -> None:
        with self.assertRaises(StrictVMOutputOverflow):
            self.execute_epoch("flood")
        retained = self.lease_root / f"leftovers-vm-{self.run_id}"
        self.assertTrue(retained.exists())
        self.assertTrue((retained / "request.raw").exists())

    def test_unknown_or_mismatched_receipt_retains_the_lease(self) -> None:
        for behavior in ("unknown", "mismatch", "duplicate", "noncanonical"):
            with self.subTest(behavior=behavior):
                initial = {
                    "unknown": "e",
                    "mismatch": "d",
                    "duplicate": "c",
                    "noncanonical": "b",
                }[behavior]
                run_id = initial * 32
                controller = StrictVMOneEpochController(self.config(behavior), self.lease_root)
                readiness = StrictVMReadiness(
                    launcher_sha256="1" * 64,
                    kernel_sha256=self.digest(self.kernel),
                    initrd_sha256=self.digest(self.initrd),
                    root_disk_sha256=self.digest(self.root_disk),
                    root_disk_bytes=self.root_disk.stat().st_size,
                    guest_policy_sha256=self.digest(self.guest_policy),
                )
                with (
                    mock.patch("leftovers.strict_vm_runner.STRICT_VM_EXECUTION_ENABLED", True),
                    mock.patch(
                        "leftovers.strict_vm_runner.verify_static_readiness",
                        return_value=readiness,
                    ),
                    self.assertRaises(StrictVMReceiptError),
                ):
                    controller.run_epoch(
                        run_id=run_id,
                        round=0,
                        stage="implementation",
                        source_capsule=self.source,
                        task={"issue": 1},
                        authorization=self.fixture_authorization(run_id),
                    )
                self.assertTrue((self.lease_root / f"leftovers-vm-{run_id}").exists())

    def test_nonzero_launcher_exit_retains_the_lease(self) -> None:
        with self.assertRaises(StrictVMLaunchError):
            self.execute_epoch("failed")
        self.assertTrue((self.lease_root / f"leftovers-vm-{self.run_id}").exists())

    def test_stopped_guest_result_must_satisfy_the_typed_contract_before_cleanup(self) -> None:
        with self.assertRaisesRegex(BundleError, "does not bind this epoch"):
            self.execute_epoch("bad_guest_result")
        self.assertFalse((self.lease_root / f"leftovers-vm-{self.run_id}").exists())

    def test_guest_policy_is_canonical_and_binds_the_exact_boot_digests(self) -> None:
        raw = self.guest_policy.read_bytes()
        _validate_guest_policy(
            raw,
            kernel_sha256=self.digest(self.kernel),
            initrd_sha256=self.digest(self.initrd),
            root_disk_sha256=self.digest(self.root_disk),
        )
        with self.assertRaisesRegex(StrictVMReadinessError, "bound to the pinned boot"):
            _validate_guest_policy(
                raw,
                kernel_sha256=self.digest(self.kernel),
                initrd_sha256=self.digest(self.initrd),
                root_disk_sha256="0" * 64,
            )
        with self.assertRaisesRegex(StrictVMReadinessError, "not canonical"):
            _validate_guest_policy(
                raw + b"\n",
                kernel_sha256=self.digest(self.kernel),
                initrd_sha256=self.digest(self.initrd),
                root_disk_sha256=self.digest(self.root_disk),
            )

    def test_guest_policy_reader_rejects_a_symlink_mutable_mode_or_ctime_change(self) -> None:
        symlink = self.boot / "policy-link.json"
        os.chmod(self.boot, 0o700)
        try:
            symlink.symlink_to(self.guest_policy)
        finally:
            os.chmod(self.boot, 0o500)
        with self.assertRaisesRegex(StrictVMReadinessError, "permissions are unsafe"):
            _read_pinned_policy(symlink, expected_owner=os.geteuid())
        os.chmod(self.guest_policy, 0o600)
        with self.assertRaisesRegex(StrictVMReadinessError, "permissions are unsafe"):
            _read_pinned_policy(self.guest_policy, expected_owner=os.geteuid())
        os.chmod(self.guest_policy, 0o400)
        # The descriptor is intentionally not retained: this is only a stable
        # stat fixture for a post-read identity-change simulation.
        descriptor = os.open(self.guest_policy, os.O_RDONLY)
        try:
            first = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        changed = types.SimpleNamespace(
            st_dev=first.st_dev,
            st_ino=first.st_ino,
            st_uid=first.st_uid,
            st_mode=first.st_mode,
            st_nlink=first.st_nlink,
            st_size=first.st_size,
            st_mtime_ns=first.st_mtime_ns,
            st_ctime_ns=first.st_ctime_ns + 1,
        )
        with (
            mock.patch("leftovers.strict_vm_runner.os.fstat", side_effect=[first, changed]),
            self.assertRaisesRegex(StrictVMReadinessError, "changed while reading"),
        ):
            _read_pinned_policy(self.guest_policy, expected_owner=os.geteuid())

    def test_static_readiness_derives_policy_digest_instead_of_reading_one_from_config(
        self,
    ) -> None:
        config = self.config()
        os.chmod(config.launcher_path, 0o555)
        with (
            mock.patch("leftovers.strict_vm_runner.sys.platform", "darwin"),
            mock.patch("leftovers.strict_vm_runner.platform.machine", return_value="arm64"),
            mock.patch("leftovers.strict_vm_runner.os.geteuid", return_value=os.geteuid() + 1),
            mock.patch("leftovers.strict_vm_runner._require_immutable_ancestors"),
        ):
            readiness = verify_static_readiness(config)
        self.assertEqual(readiness.guest_policy_sha256, self.digest(self.guest_policy))
        self.assertNotIn("guest_policy_sha256", config.__dict__)

    def test_readiness_rejects_boot_artifact_mutation_before_creating_a_lease(self) -> None:
        os.chmod(self.boot, 0o700)
        with (
            mock.patch("leftovers.strict_vm_runner.STRICT_VM_EXECUTION_ENABLED", True),
            mock.patch("leftovers.strict_vm_runner.sys.platform", "darwin"),
            mock.patch("leftovers.strict_vm_runner.platform.machine", return_value="arm64"),
            self.assertRaisesRegex(Exception, "immutable|non-controller"),
        ):
            StrictVMOneEpochController(self.config(), self.lease_root).run_epoch(
                run_id=self.run_id,
                round=0,
                stage="implementation",
                source_capsule=self.source,
                task={"issue": 1},
                authorization=self.fixture_authorization(self.run_id),
            )
        self.assertEqual(list(self.lease_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
