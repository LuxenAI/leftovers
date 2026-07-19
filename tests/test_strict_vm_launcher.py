from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "vm" / "strict_vm_launcher.swift"
CHECK_SCRIPT = ROOT / "vm" / "check.sh"
SMOKE_INIT = ROOT / "vm" / "smoke_init.sh"
ENTITLEMENTS = ROOT / "vm" / "strict-vm.entitlements.plist"


class StrictVMLauncherSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_manifest_cannot_supply_commands_or_devices(self) -> None:
        manifest_source = self.source.split("private struct Manifest: Decodable", 1)[1].split(
            "private struct LimitsReceipt", 1
        )[0]
        self.assertNotIn("let command", manifest_source)
        self.assertNotIn("let environment", manifest_source)
        self.assertNotIn("let network", manifest_source)
        for host_execution_api in (
            "Process(",
            "NSTask",
            "posix_spawn",
            "execve(",
            "system(",
            "popen(",
        ):
            self.assertNotIn(host_execution_api, self.source)
        self.assertIn('code: "manifest_unknown_field"', self.source)

    def test_manifest_v2_separates_immutable_boot_and_private_run_domains(self) -> None:
        self.assertIn('case bootArtifactDirectory = "boot_artifact_directory"', self.source)
        self.assertNotIn('case artifactDirectory = "artifact_directory"', self.source)
        self.assertIn("private let manifestSchemaVersion = 2", self.source)
        self.assertIn("private let receiptSchemaVersion = 2", self.source)
        self.assertIn("value.st_uid != geteuid()", self.source)
        self.assertIn("#if LEFTOVERS_TESTING", self.source)
        self.assertIn("boot_artifact_directory must have no write permission bits", self.source)
        self.assertIn("requirePinnedBootAncestors", self.source)
        self.assertIn("manifest must be sealed mode 0400", self.source)
        self.assertIn("request_disk must be named request.raw", self.source)

    def test_production_owner_guard_is_not_relaxed_by_testing_exception(self) -> None:
        section = self.source.split("private func requireImmutableBootDirectory", 1)[1].split(
            "private func requireDirectChild", 1
        )[0]
        testing_branch, production_branch = section.split("#else", 1)
        self.assertNotIn("value.st_uid != geteuid()", testing_branch)
        self.assertIn("value.st_uid != geteuid()", production_branch.split("#endif", 1)[0])

    def test_device_graph_explicitly_omits_host_escape_surfaces(self) -> None:
        for assignment in (
            "configuration.networkDevices = []",
            "configuration.socketDevices = []",
            "configuration.directorySharingDevices = []",
            "configuration.serialPorts = []",
            "configuration.consoleDevices = []",
            "configuration.graphicsDevices = []",
            "configuration.audioDevices = []",
            "configuration.usbControllers = []",
            "configuration.keyboards = []",
            "configuration.pointingDevices = []",
        ):
            self.assertIn(assignment, self.source)
        self.assertNotIn("VZVirtioNetworkDeviceConfiguration", self.source)
        self.assertNotIn("VZVirtioSocketDeviceConfiguration", self.source)
        self.assertNotIn("VZVirtioFileSystemDeviceConfiguration", self.source)

    def test_only_bounded_disk_devices_are_constructed(self) -> None:
        self.assertIn('role: "root", readOnly: true', self.source)
        self.assertIn('role: "scratch", readOnly: false', self.source)
        self.assertIn('role: "request", readOnly: true', self.source)
        self.assertIn("configuration.storageDevices = storage", self.source)
        self.assertIn("F_PREALLOCATE", self.source)
        self.assertIn("4 * gib", self.source)

    def test_host_resources_have_fail_closed_bounds(self) -> None:
        for token in (
            "setrlimit(RLIMIT_CORE",
            "setrlimit(RLIMIT_NOFILE",
            "maximumHostFileDescriptors",
            "hostFreeSpaceReserve",
            "requireScratchCapacity",
            "maximumScratchPreparationSeconds",
            'code: "artifact_hash_timeout"',
            'code: "scratch_cleanup_unproven"',
        ):
            self.assertIn(token, self.source)

    def test_manifest_parser_requires_one_canonical_json_object(self) -> None:
        self.assertIn("JSONSerialization.data(", self.source)
        self.assertIn(".sortedKeys, .withoutEscapingSlashes", self.source)
        self.assertIn('code: "manifest_canonical"', self.source)
        self.assertIn("no duplicate keys", self.source)

    def test_stop_deadline_and_signal_lifecycle_are_independent_of_can_stop(self) -> None:
        controller = self.source.split("private final class VMController", 1)[1].split(
            "private func usageFailure", 1
        )[0]
        self.assertIn("private var stopInFlight = false", controller)
        self.assertIn("private var stopDeadlineTimer", controller)
        self.assertIn("deadline.schedule(deadline: .now() + .seconds(10))", controller)
        self.assertIn("self?.enforceStopDeadline()", controller)
        self.assertLess(
            controller.index("private func enforceStopDeadline"),
            controller.index("private func tryStop"),
        )
        self.assertIn("guard !stopInFlight else { return }", controller)
        self.assertIn(
            "if requestedStopReason != nil {\n            finishRequestedStop()", controller
        )
        self.assertIn("let cancellation = SignalCancellation()", self.source)
        self.assertIn("pthread_sigmask(SIG_BLOCK", self.source)
        self.assertIn("pthread_sigmask(SIG_UNBLOCK", self.source)
        self.assertLess(
            self.source.index("cancellation.install()"), self.source.index("let run = try prepare")
        )

    def test_scratch_and_read_only_inputs_are_revalidated_at_boundaries(self) -> None:
        self.assertIn("st_ctimespec", self.source)
        self.assertIn("private func revalidateVMStartInputs", self.source)
        self.assertIn("private func revalidateScratchAfterStop", self.source)
        self.assertIn("try controller.run { try revalidateVMStartInputs(run) }", self.source)
        self.assertIn("try revalidateScratchAfterStop(run)", self.source)
        self.assertIn("fchmod(descriptor, S_IRUSR | S_IWUSR)", self.source)
        self.assertIn("try fsyncRunDirectory(runDirectory)", self.source)

    def test_boot_contract_is_initramfs_only_and_internal(self) -> None:
        self.assertIn('"console=hvc0"', self.source)
        self.assertIn('"rdinit=/init"', self.source)
        self.assertIn('"panic=-1"', self.source)
        self.assertNotIn('"root=/dev/vda"', self.source)
        self.assertIn("bootLoader.commandLine =", self.source)

    def test_receipt_attests_validation_and_exact_device_counts(self) -> None:
        for field in (
            'case configValidated = "config_validated"',
            'case networkDevices = "network_devices"',
            'case socketDevices = "socket_devices"',
            'case directoryShares = "directory_shares"',
            'case pointingDevices = "pointing_devices"',
            'case entropyDevices = "entropy_devices"',
            'case memoryBalloonDevices = "memory_balloon_devices"',
            'case storageDevices = "storage_devices"',
            'case scratchRetained = "scratch_retained"',
            'case manifestSHA256 = "manifest_sha256"',
        ):
            self.assertIn(field, self.source)
        self.assertIn("try configuration.validate()", self.source)


@unittest.skipUnless(
    sys.platform == "darwin" and platform.machine() == "arm64",
    "Virtualization.framework launcher is macOS/Apple-silicon only",
)
class StrictVMLauncherBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leftovers-vm-test-")
        cls.work = Path(cls.temporary.name).resolve()
        cls.binary = cls.work / "strict-vm-launcher"
        environment = os.environ.copy()
        environment["CLANG_MODULE_CACHE_PATH"] = str(cls.work / "clang-cache")
        environment["SWIFT_MODULE_CACHE_PATH"] = str(cls.work / "swift-cache")
        subprocess.run(
            [
                "/usr/bin/swiftc",
                "-D",
                "LEFTOVERS_TESTING",
                "-target",
                "arm64-apple-macos26.0",
                "-framework",
                "CryptoKit",
                "-framework",
                "Virtualization",
                str(SOURCE),
                "-o",
                str(cls.binary),
            ],
            check=True,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
        )
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--entitlements",
                str(ENTITLEMENTS),
                str(cls.binary),
            ],
            check=True,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def run_launcher(
        self, manifest: dict[str, object], *, mode: int = 0o400
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700, exist_ok=True)
        run.chmod(0o700)
        path = run / f"manifest-{len(list(run.glob('manifest-*.json')))}.json"
        path.write_text(
            json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        path.chmod(mode)
        self.last_manifest_path = path
        return self.invoke_launcher(path)

    def invoke_launcher(
        self, path: Path, *, environment: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        result = subprocess.run(
            [str(self.binary), "--check", str(path)],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        receipt = json.loads(result.stdout)
        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "launcher_version",
                "manifest_sha256",
                "run_id",
                "mode",
                "status",
                "started_at",
                "finished_at",
                "config_validated",
                "stop_reason",
                "limits",
                "artifacts",
                "devices",
                "scratch_retained",
                "error_code",
            },
        )
        return result, receipt

    def minimal_manifest(self) -> dict[str, object]:
        case = self.work / self._testMethodName
        return {
            "schema_version": 2,
            "run_id": "a" * 32,
            "boot_artifact_directory": str(case / "boot"),
            "run_directory": str(case / "run"),
            "kernel": {"path": str(case / "boot" / "kernel"), "sha256": "0" * 64},
            "initrd": {"path": str(case / "boot" / "initrd"), "sha256": "0" * 64},
            "root_disk": {"path": str(case / "boot" / "root.raw"), "sha256": "0" * 64},
            "scratch_disk": {
                "path": str(case / "run" / "scratch.raw"),
                "size_bytes": 64 * 1024 * 1024,
            },
            "cpu_count": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "wall_time_seconds": 30,
        }

    def provision_boot_artifacts(
        self, manifest: dict[str, object], *, kernel_mode: int = 0o400
    ) -> dict[str, bytes]:
        boot = Path(str(manifest["boot_artifact_directory"]))
        boot.mkdir(parents=True, mode=0o700, exist_ok=True)
        boot.chmod(0o700)
        payloads = {
            "kernel": b"kernel",
            "initrd": b"initrd",
            "root.raw": b"\0" * (1024 * 1024),
        }
        for field, name in (("kernel", "kernel"), ("initrd", "initrd"), ("root_disk", "root.raw")):
            path = boot / name
            payload = payloads[name]
            path.write_bytes(payload)
            path.chmod(kernel_mode if field == "kernel" else 0o400)
            manifest[field] = {
                "path": str(path),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        boot.chmod(0o500)
        return payloads

    def test_unknown_command_field_is_rejected_before_any_resource_creation(self) -> None:
        manifest = self.minimal_manifest()
        manifest["command"] = ["/bin/sh", "-c", "touch /tmp/escaped"]
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["error_code"], "manifest_unknown_field", result.stderr)
        self.assertFalse((self.work / "run" / "scratch.raw").exists())

    def test_duplicate_or_noncanonical_manifest_json_is_rejected_before_resources(self) -> None:
        manifest = self.minimal_manifest()
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        canonical = json.dumps(manifest, separators=(",", ":"), sort_keys=True)
        duplicated = canonical[:-1] + ',"run_id":"' + ("b" * 32) + '"}'
        path = run / "manifest-duplicate.json"
        path.write_text(duplicated, encoding="utf-8")
        path.chmod(0o400)
        result, receipt = self.invoke_launcher(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "manifest_canonical", result.stderr)
        self.assertFalse((run / "scratch.raw").exists())

    def test_run_id_must_be_exact_lowercase_hex(self) -> None:
        manifest = self.minimal_manifest()
        manifest["run_id"] = "not-a-32-hex-run-id"
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "run_id", result.stderr)

    def test_unknown_nested_artifact_field_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        assert isinstance(manifest["kernel"], dict)
        manifest["kernel"]["mount"] = "/Users/example"
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "manifest_unknown_field", result.stderr)

    def test_old_artifact_directory_field_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        manifest["artifact_directory"] = manifest["boot_artifact_directory"]
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "manifest_unknown_field", result.stderr)

    def test_writable_manifest_is_rejected(self) -> None:
        result, receipt = self.run_launcher(self.minimal_manifest(), mode=0o600)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "manifest_permissions", result.stderr)

    def test_hard_linked_manifest_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        original = run / "hardlink-original.json"
        linked = run / "hardlink-second.json"
        original.write_text(
            json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8"
        )
        original.chmod(0o400)
        os.link(original, linked)
        result, receipt = self.invoke_launcher(linked)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "manifest_links", result.stderr)

    def test_symlinked_manifest_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        original = run / "symlink-original.json"
        linked = run / "symlink-second.json"
        original.write_text(
            json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8"
        )
        original.chmod(0o400)
        linked.symlink_to(original)
        result, receipt = self.invoke_launcher(linked)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "path_symlink", result.stderr)

    def test_resource_limit_is_rejected_before_paths_are_opened(self) -> None:
        manifest = self.minimal_manifest()
        manifest["cpu_count"] = 5
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "cpu_limit", result.stderr)
        self.assertFalse(receipt["config_validated"])

    def test_hash_mismatch_fails_closed_without_a_scratch_disk(self) -> None:
        manifest = self.minimal_manifest()
        boot = Path(str(manifest["boot_artifact_directory"]))
        run = Path(str(manifest["run_directory"]))
        boot.mkdir(parents=True, mode=0o700)
        kernel = boot / "kernel"
        kernel.write_bytes(b"not-a-kernel")
        kernel.chmod(0o400)
        boot.chmod(0o500)
        manifest["kernel"] = {
            "path": str(kernel),
            "sha256": hashlib.sha256(b"different").hexdigest(),
        }
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "artifact_hash_mismatch", result.stderr)
        self.assertFalse((run / "scratch.raw").exists())

    def test_manifest_must_be_a_sealed_direct_child_of_run_directory(self) -> None:
        manifest = self.minimal_manifest()
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        outside = run.parent / "outside-manifest.json"
        outside.write_text(
            json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8"
        )
        outside.chmod(0o400)
        result, receipt = self.invoke_launcher(outside)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "path_scope", result.stderr)

    def test_writable_boot_directory_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest)
        Path(str(manifest["boot_artifact_directory"])).chmod(0o700)
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "boot_directory_permissions", result.stderr)

    def test_owner_writable_boot_artifact_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest, kernel_mode=0o600)
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "artifact_permissions", result.stderr)

    def test_boot_artifact_outside_immutable_boot_directory_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest)
        outside = Path(str(manifest["boot_artifact_directory"])).parent / "outside-kernel"
        payload = b"kernel"
        outside.write_bytes(payload)
        outside.chmod(0o400)
        manifest["kernel"] = {
            "path": str(outside),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "path_scope", result.stderr)

    def test_request_outside_run_directory_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest)
        outside = Path(str(manifest["run_directory"])).parent / "outside"
        outside.mkdir(mode=0o700)
        request = outside / "request.raw"
        payload = b"r" * 512
        request.write_bytes(payload)
        request.chmod(0o400)
        manifest["request_disk"] = {
            "path": str(request),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "path_scope", result.stderr)

    def test_writable_request_is_rejected(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest)
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        request = run / "request.raw"
        payload = b"r" * 512
        request.write_bytes(payload)
        request.chmod(0o600)
        manifest["request_disk"] = {
            "path": str(request),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        result, receipt = self.run_launcher(manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt["error_code"], "artifact_permissions", result.stderr)

    def test_valid_v2_manifest_hash_is_bound_before_configuration(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest)
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        request = run / "request.raw"
        payload = b"r" * 512
        request.write_bytes(payload)
        request.chmod(0o400)
        request_digest = hashlib.sha256(payload).hexdigest()
        manifest["request_disk"] = {"path": str(request), "sha256": request_digest}
        result, receipt = self.run_launcher(manifest)
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["launcher_version"], "0.3.0-proof")
        self.assertEqual(
            receipt["manifest_sha256"],
            hashlib.sha256(self.last_manifest_path.read_bytes()).hexdigest(),
        )
        if result.returncode == 0:
            self.assertEqual(
                receipt["artifacts"]["request_disk_sha256"],  # type: ignore[index]
                request_digest,
            )
        else:
            self.assertEqual(receipt["error_code"], "vz_configuration", result.stderr)
        self.assertFalse((run / "scratch.raw").exists())

    def test_cleanup_failure_is_reported_as_retained_not_absent(self) -> None:
        manifest = self.minimal_manifest()
        self.provision_boot_artifacts(manifest)
        run = Path(str(manifest["run_directory"]))
        run.mkdir(parents=True, mode=0o700)
        path = run / "manifest-cleanup-failure.json"
        path.write_text(
            json.dumps(manifest, separators=(",", ":"), sort_keys=True), encoding="utf-8"
        )
        path.chmod(0o400)
        environment = os.environ.copy()
        environment["LEFTOVERS_TEST_FORCE_SCRATCH_CLEANUP_FAILURE"] = "1"
        result, receipt = self.invoke_launcher(path, environment=environment)
        scratch = run / "scratch.raw"
        try:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(receipt["error_code"], "scratch_cleanup_unproven", result.stderr)
            self.assertTrue(receipt["scratch_retained"])
            self.assertTrue(scratch.is_file())
            scratch_stat = scratch.stat()
            self.assertEqual(scratch_stat.st_mode & 0o777, 0o600)
            self.assertEqual(scratch_stat.st_nlink, 1)
            self.assertEqual(scratch_stat.st_size, 64 * 1024 * 1024)
        finally:
            scratch.unlink(missing_ok=True)


class StrictVMLauncherBuildTests(unittest.TestCase):
    def test_production_check_does_not_enable_testing_relaxations(self) -> None:
        self.assertNotIn("LEFTOVERS_TESTING", CHECK_SCRIPT.read_text(encoding="utf-8"))

    def test_check_script_has_valid_posix_shell_syntax(self) -> None:
        result = subprocess.run(
            ["/bin/sh", "-n", str(CHECK_SCRIPT)],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(
        sys.platform == "darwin" and platform.machine() == "arm64",
        "Virtualization.framework launcher is macOS/Apple-silicon only",
    )
    def test_build_and_entitlement_signature(self) -> None:
        result = subprocess.run(
            ["/bin/sh", str(CHECK_SCRIPT)],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("entitlement signature verified", result.stdout)


class StrictVMSmokeInitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SMOKE_INIT.read_text(encoding="utf-8")

    def test_smoke_init_has_valid_posix_shell_syntax(self) -> None:
        result = subprocess.run(
            ["/bin/sh", "-n", str(SMOKE_INIT)],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_smoke_init_uses_fixed_busybox_and_no_network_clients(self) -> None:
        self.assertTrue(self.source.startswith("#!/bin/busybox sh\n"))
        self.assertIn("BB=/bin/busybox", self.source)
        for forbidden in (
            "$PATH",
            "curl ",
            "wget ",
            " nc ",
            "telnet ",
            "ssh ",
            "scp ",
            "ifconfig ",
            "udhcpc ",
            "dhcpcd ",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_smoke_init_mounts_only_guest_pseudo_filesystems(self) -> None:
        self.assertIn("$BB mount -t proc proc /proc", self.source)
        self.assertIn("$BB mount -t sysfs sysfs /sys", self.source)
        self.assertIn("$BB mount -t devtmpfs devtmpfs /dev", self.source)
        self.assertEqual(self.source.count("$BB mount "), 3)
        self.assertNotIn("9p", self.source)
        self.assertNotIn("virtiofs", self.source.lower())

    def test_smoke_init_writes_receipt_only_to_bounded_scratch_disk(self) -> None:
        self.assertIn("root_read_only=", self.source)
        self.assertIn("scratch_read_only=", self.source)
        self.assertIn("of=/dev/vdb bs=4096 count=1 conv=sync", self.source)
        self.assertNotIn("of=/dev/vda", self.source)
        self.assertNotIn("of=/dev/vdc", self.source)
        self.assertIn("complete=true", self.source)
        self.assertIn("$BB poweroff -f", self.source)


if __name__ == "__main__":
    unittest.main()
