from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUEST = ROOT / "vm" / "guest"


def release_module() -> object:
    spec = importlib.util.spec_from_file_location(
        "leftovers_guest_release_test", GUEST / "release.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StrictVmGuestScaffoldTests(unittest.TestCase):
    def test_pinned_official_sources_are_exact_and_documented(self) -> None:
        lock = json.loads((GUEST / "SOURCES.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["schema_version"], 2)
        self.assertEqual(lock["recorded_at"], "2026-07-19T00:26:00Z")
        sources = {entry["name"]: entry for entry in lock["sources"]}
        self.assertEqual(sources["buildroot"]["ref"], "refs/tags/2026.05.1")
        self.assertEqual(
            sources["buildroot"]["tag_object"], "de1f9260590a53a7cd8a59addc47c96ecd09f983"
        )
        self.assertEqual(
            sources["linux-stable"]["tag_object"],
            "669dc96e243e422e7404bb98be00d527bafc0a96",
        )
        for entry in sources.values():
            self.assertEqual(entry["hash_algorithm"], "git-sha1")
            self.assertRegex(entry["tag_object"], r"^[0-9a-f]{40}$")
            self.assertTrue(entry["repository"].startswith("https://"))
            self.assertEqual(entry["tag_verification"]["method"], "git-verify-tag")
            self.assertTrue(entry["tag_verification"]["required"])

    def test_source_lock_validator_is_offline_and_passes(self) -> None:
        completed = subprocess.run(
            ["python3", str(GUEST / "verify-sources.py")],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(completed.stdout.strip(), "strict guest source lock is valid")

    def test_defconfig_and_kernel_policy_have_required_defense_layers(self) -> None:
        defconfig = (GUEST / "configs" / "leftovers_strict_vm_defconfig").read_text(
            encoding="utf-8"
        )
        kernel = (GUEST / "board" / "leftovers" / "linux.fragment").read_text(encoding="utf-8")
        self.assertIn(
            'BR2_LINUX_KERNEL_CUSTOM_REPO_VERSION="669dc96e243e422e7404bb98be00d527bafc0a96"',
            defconfig,
        )
        self.assertIn("BR2_TARGET_ROOTFS_CPIO=y", defconfig)
        self.assertIn("BR2_TARGET_ROOTFS_EXT2=y", defconfig)
        self.assertIn("BR2_LINUX_KERNEL_USE_DEFCONFIG=y", defconfig)
        self.assertIn("BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES", defconfig)
        for setting in (
            "CONFIG_CGROUPS=y",
            "CONFIG_CGROUP_PIDS=y",
            "CONFIG_MEMCG=y",
            "CONFIG_SECCOMP_FILTER=y",
            "CONFIG_SECURITY_LANDLOCK=y",
            "CONFIG_NET=n",
            "CONFIG_UNIX=n",
            "CONFIG_MODULES=n",
            "CONFIG_USER_NS=n",
        ):
            self.assertIn(setting, kernel)

    def test_supervisor_is_rejection_only_without_a_private_wire_protocol(self) -> None:
        source_path = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_supervisor.c"
        )
        source = source_path.read_text(encoding="utf-8")
        for required in (
            "getpid() != 1",
            "memory.max",
            "memory.swap.max",
            "pids.max",
            "cpu.max",
            "PR_SET_NO_NEW_PRIVS",
            "PR_CAPBSET_DROP",
            "SYS_landlock_restrict_self",
            "SECCOMP_MODE_FILTER",
            "cgroup.subtree_control",
            "leftovers.request=/dev/vdc",
            "leftovers.scratch=/dev/vdb",
            "drop_capability_bounding_set_while_privileged",
            "worker_identity_and_capabilities_are_safe",
            "There is intentionally no LFRQ parser and no LFRS writer here",
        ):
            self.assertIn(required, source)
        self.assertNotRegex(source, r"\b(system|popen|execlp|execvp)\s*\(")
        for forbidden in ("LFR_HEADER_BYTES", "emit_lfrs", "FIXED_CHECKS", "open_beneath"):
            self.assertNotIn(forbidden, source)

    def test_early_init_performs_a_read_only_vda_pivot_without_a_shell(self) -> None:
        source = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "early_init.c"
        ).read_text(encoding="utf-8")
        self.assertIn('mount("/dev/vda", "/newroot", "ext4", MS_RDONLY', source)
        self.assertIn("SYS_pivot_root", source)
        self.assertIn("execve(argv[0], argv, environment)", source)
        self.assertNotRegex(source, r"\b(system|popen|execlp|execvp)\s*\(")

    def test_worker_boundary_order_is_privileged_drop_then_identity_then_no_new_privs(self) -> None:
        source_path = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_supervisor.c"
        )
        source = source_path.read_text(encoding="utf-8")
        start = source.index("static int rejection_only_worker")
        end = source.index("static void power_off")
        function = source[start:end]
        self.assertLess(
            function.index("drop_capability_bounding_set_while_privileged"),
            function.index("setgroups"),
        )
        self.assertLess(
            function.index("setuid"),
            function.index("worker_identity_and_capabilities_are_safe"),
        )
        self.assertLess(
            function.index("worker_identity_and_capabilities_are_safe"),
            function.index("install_network_denial_seccomp"),
        )
        self.assertLess(
            function.index("install_network_denial_seccomp"),
            function.index("landlock_restrict_worker"),
        )

    def test_static_check_is_offline_and_passes(self) -> None:
        completed = subprocess.run(
            ["sh", str(GUEST / "check-static.sh")],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertRegex(completed.stdout, re.compile(r"static policy checks passed"))

    def test_container_release_script_and_workflow_are_fail_closed(self) -> None:
        script = (GUEST / "ci" / "build-in-container.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "guest-build.yml").read_text(encoding="utf-8")
        self.assertIn('python3 "$guest/release.py" release-readiness', script)
        self.assertIn("LINUX_OVERRIDE_SRCDIR = /work/sources/linux-stable", script)
        self.assertIn("exit 78", script)
        self.assertIn("--network none", workflow)
        self.assertIn("--read-only --cap-drop ALL --cpus=2", workflow)
        self.assertIn("--memory=2g --memory-swap=2g --pids-limit=256", workflow)
        self.assertIn("type=tmpfs", workflow)
        self.assertIn("o=size=6g,nosuid,nodev", workflow)
        self.assertNotIn("o=size=6g,nosuid,nodev,noexec", workflow)
        self.assertIn("/tmp:rw,noexec,nosuid,size=64m", workflow)
        self.assertIn("docker volume rm --force", workflow)
        self.assertNotIn("${{ steps.builder.outputs.image }}", workflow)
        self.assertIn('python3 "$guest/release.py" verify-remote', script)
        self.assertIn("git_safe()", script)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", script)
        self.assertIn("source_field buildroot repository", script)
        self.assertNotIn("git clone --no-checkout https://", script)
        self.assertNotRegex(workflow, r"uses:\s+[^@\s]+@(?![0-9a-f]{40}(?:\s|$))")

    def test_clean_tag_checkout_rejects_dirty_or_moved_head(self) -> None:
        module = release_module()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "source"
            git_home = Path(temporary) / "git-home"
            git_home.mkdir()

            def git(*arguments: str) -> None:
                completed = subprocess.run(
                    ["git", "-C", str(repository), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Guest Test")
            (repository / "input.txt").write_text("clean\n", encoding="utf-8")
            git("add", "input.txt")
            git("commit", "-qm", "initial")
            git("tag", "-am", "v1", "v1")
            git("config", "core.hooksPath", "/untrusted/hooks")
            self.assertEqual(
                module.checked_git(
                    repository, ["config", "--get", "core.hooksPath"], git_home=git_home
                ).strip(),
                "/dev/null",
            )
            self.assertRegex(
                module.verify_clean_tag_checkout(repository, "refs/tags/v1", git_home),
                r"^[0-9a-f]{40}$",
            )
            (repository / "untracked.txt").write_text("untracked\n", encoding="utf-8")
            with self.assertRaises(module.ReleaseError):
                module.verify_clean_tag_checkout(repository, "refs/tags/v1", git_home)
            (repository / "untracked.txt").unlink()
            (repository / "input.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(module.ReleaseError):
                module.verify_clean_tag_checkout(repository, "refs/tags/v1", git_home)
            git("add", "input.txt")
            with self.assertRaises(module.ReleaseError):
                module.verify_clean_tag_checkout(repository, "refs/tags/v1", git_home)
            git("commit", "-qm", "moved head")
            with self.assertRaises(module.ReleaseError):
                module.verify_clean_tag_checkout(repository, "refs/tags/v1", git_home)

    def test_build_lock_rejects_shell_image_references_and_keyring_traversal(self) -> None:
        lock = json.loads((GUEST / "BUILD.lock.json").read_text(encoding="utf-8"))
        lock["builder_image"] = {
            "reference": "registry.example/x';id;#@sha256:" + "a" * 64,
            "status": "CONFIGURED",
        }
        lock["provenance"] = {
            "required": True,
            "status": "CONFIGURED",
            "verifier": {"argv": ["verify"], "id": "leftovers-provenance-v1", "sha256": "b" * 64},
        }
        lock["reproducibility"] = {"required": True, "source_date_epoch": 1, "status": "CONFIGURED"}
        lock["trusted_keyring"] = {
            "path": "vm/guest/../../outside",
            "sha256": "c" * 64,
            "status": "CONFIGURED",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "BUILD.lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            completed = subprocess.run(
                ["python3", str(GUEST / "release.py"), "validate-locks", "--build-lock", str(path)],
                check=False,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("trusted keyring path", completed.stderr)
        lock["trusted_keyring"]["path"] = "vm/guest/trusted-keys"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "BUILD.lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            completed = subprocess.run(
                ["python3", str(GUEST / "release.py"), "validate-locks", "--build-lock", str(path)],
                check=False,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("builder image", completed.stderr)

    def test_release_pipeline_fails_closed_until_trust_roots_are_configured(self) -> None:
        completed = subprocess.run(
            ["python3", str(GUEST / "release.py"), "release-readiness"],
            check=False,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("intentionally unconfigured", completed.stderr)

    def test_configured_roots_still_fail_without_an_implemented_pinned_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            guest = workspace / "vm" / "guest"
            keys = guest / "trusted-keys"
            keys.mkdir(parents=True)
            (keys / "upstream.asc").write_text("public test key only\n", encoding="utf-8")
            source_lock = json.loads((GUEST / "SOURCES.lock.json").read_text(encoding="utf-8"))
            for source in source_lock["sources"]:
                source["tag_verification"].update(
                    status="CONFIGURED", expected_signer_fingerprint="A" * 40
                )
            source_lock_path = guest / "SOURCES.lock.json"
            source_lock_path.write_text(json.dumps(source_lock), encoding="utf-8")
            key_data = (keys / "upstream.asc").read_bytes()
            keyring_digest = hashlib.sha256(
                b"upstream.asc\\0" + str(len(key_data)).encode("ascii") + b"\\0" + key_data + b"\\0"
            ).hexdigest()
            build_lock = {
                "schema_version": 1,
                "builder_image": {
                    "reference": "registry.example/guest@sha256:" + "b" * 64,
                    "status": "CONFIGURED",
                },
                "provenance": {
                    "required": True,
                    "status": "CONFIGURED",
                    "verifier": {
                        "argv": ["leftovers-provenance-verify", "verify"],
                        "id": "leftovers-provenance-v1",
                        "sha256": "a" * 64,
                    },
                },
                "reproducibility": {
                    "required": True,
                    "source_date_epoch": 1,
                    "status": "CONFIGURED",
                },
                "trusted_keyring": {
                    "path": "vm/guest/trusted-keys",
                    "sha256": keyring_digest,
                    "status": "CONFIGURED",
                },
            }
            build_lock_path = guest / "BUILD.lock.json"
            build_lock_path.write_text(json.dumps(build_lock), encoding="utf-8")
            completed = subprocess.run(
                [
                    "python3",
                    str(GUEST / "release.py"),
                    "release-readiness",
                    "--workspace",
                    str(workspace),
                    "--sources-lock",
                    str(source_lock_path),
                    "--build-lock",
                    str(build_lock_path),
                ],
                check=False,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("not implemented in the fixed registry", completed.stderr)

    def test_readme_states_disabled_status_and_live_blockers(self) -> None:
        readme = (GUEST / "README.md").read_text(encoding="utf-8")
        self.assertIn("not a guest image", readme)
        self.assertIn("fails closed", readme)
        self.assertIn("leftovers.request=/dev/vdc", readme)
        self.assertIn("leaves scratch without a host-acceptable footer", readme)
        self.assertIn("It has not been built or boot-tested", readme)
        self.assertIn("Until then, this is mechanically verifiable source policy only", readme)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
