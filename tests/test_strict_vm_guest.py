from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
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

    def test_supervisor_compiles_a_source_only_fail_closed_interpreter(self) -> None:
        source_path = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_supervisor.c"
        )
        source = source_path.read_text(encoding="utf-8")
        interpreter = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_interpreter.c"
        ).read_text(encoding="utf-8")
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
            "close_all_inherited_descriptors",
            "descriptor_table_is_empty",
            "RLIMIT_NOFILE",
            "RLIMIT_FSIZE",
            "RLIMIT_CORE",
            "RLIMIT_CPU",
            "setitimer",
            "block_device_inventory_is_exact",
            "limited_device_node_inventory_is_exact",
            'mount(\n            "tmpfs",\n            "/dev"',
            "make_limited_block_node",
            "BLKROGET",
            "LANDLOCK_ACCESS_FS_TRUNCATE",
            "LANDLOCK_CREATE_RULESET_VERSION",
            '#include "guest_interpreter.c"',
            "if (false)",
        ):
            self.assertIn(required, source)
        for required in (
            "LFR_HEADER_BYTES",
            "LFR_MAX_REQUEST_BYTES",
            "LFR_MAX_ACTIONS",
            "LFR_MAX_TREE_DEPTH",
            "LFR_MAX_REPOSITORY_BYTES",
            "lfr_parse_request",
            "lfr_parse_action_batch",
            "lfr_parse_one_action",
            "lfr_hash_range",
            "lfr_open_beneath",
            "RESOLVE_BENEATH",
            "RESOLVE_NO_MAGICLINKS",
            "RESOLVE_NO_SYMLINKS",
            "RESOLVE_NO_XDEV",
            "O_NOFOLLOW",
            "BLKGETSIZE64",
            "repo-tree-safety-v1",
            "repo-root-regular-v1",
            "lfr_apply_exact_controller_patch",
            "lfr_emit_bounded_result",
            "LPATCH/1",
        ):
            self.assertIn(required, interpreter)
        self.assertNotRegex(source, r"\b(system|popen|execlp|execvp|execve)\s*\(")
        self.assertNotRegex(interpreter, r"\b(system|popen|execlp|execvp|execve)\s*\(")
        self.assertNotIn("lfr_json_contains_exact", interpreter)
        self.assertNotIn("lfr_hex_digest_present", interpreter)
        self.assertIn("return false; /* no implicit partial write", interpreter)
        self.assertIn("No completion marker is written here", interpreter)
        limited_inventory = source[
            source.index("static bool limited_device_node_inventory_is_exact") : source.index(
                "static bool make_limited_block_node"
            )
        ]
        self.assertIn('"vdb"', limited_inventory)
        self.assertIn('"vdc"', limited_inventory)
        self.assertNotIn('"vda"', limited_inventory)
        device_setup = source[
            source.index("static bool required_devices_are_exact_and_minimal") : source.index(
                "static bool drop_capability_bounding_set_while_privileged"
            )
        ]
        self.assertEqual(device_setup.count("make_limited_block_node("), 2)
        self.assertIn("MS_NOSUID | MS_NOEXEC", device_setup)

    def test_compiled_guest_action_parser_rejects_ambiguous_authority(self) -> None:
        from leftovers.model_mediator import canonical_json_bytes

        clang = shutil.which("clang")
        if clang is None:
            self.skipTest("clang is unavailable for the source-only guest parser test")
        run_id = "a" * 32
        patch_digest = hashlib.sha256(b"patch").hexdigest()

        def document(stage: str, actions: list[dict[str, object]]) -> bytes:
            return canonical_json_bytes(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "round": 0,
                    "stage": stage,
                    "provider": "openai-codex-cli",
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "high",
                    "actions": actions,
                },
                reject_controls=True,
            )

        finish = {"id": "finish", "type": "finish", "status": "complete", "summary": "ok"}
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            header = temporary_path / "linux" / "fs.h"
            header.parent.mkdir()
            header.write_text(
                "#ifndef LEFTOVERS_TEST_LINUX_FS_H\n"
                "#define LEFTOVERS_TEST_LINUX_FS_H\n"
                "#define BLKGETSIZE64 0x80081272\n"
                "#define BLKROGET 0x125e\n"
                "#endif\n",
                encoding="ascii",
            )
            binary = temporary_path / "guest-action-parser"
            source = (
                GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_interpreter.c"
            )
            compiled = subprocess.run(
                [
                    clang,
                    "-std=c11",
                    "-D_GNU_SOURCE",
                    "-DLFR_ACTION_PARSER_TEST",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wno-deprecated-declarations",
                    "-Wformat=2",
                    "-Wformat-security",
                    "-Wshadow",
                    "-Wconversion",
                    "-Wstrict-prototypes",
                    f"-I{temporary_path}",
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=False,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)

            def parse(
                raw: bytes, stage: str, patch: str = "-"
            ) -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(
                    [str(binary), run_id, stage, "0", patch],
                    input=raw,
                    check=False,
                    cwd=ROOT,
                    capture_output=True,
                )

            valid_patch = document(
                "implementation",
                [
                    {"id": "patch", "type": "apply_patch", "patch_sha256": patch_digest},
                    finish,
                ],
            )
            completed = parse(valid_patch, "implementation", patch_digest)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stdout, b"actions=2 patches=1 checks=0\n")

            valid_check = document(
                "final_verify",
                [
                    {"id": "check", "type": "run_check", "check_id": "repo-tree-safety-v1"},
                    finish,
                ],
            )
            completed = parse(valid_check, "final_verify")
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stdout, b"actions=2 patches=0 checks=1\n")

            quoted_summary = document(
                "planning",
                [
                    {
                        "id": "finish",
                        "type": "finish",
                        "status": "complete",
                        "summary": 'quoted "type":"run_check" and repo-tree-safety-v1',
                    }
                ],
            )
            completed = parse(quoted_summary, "planning")
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(completed.stdout, b"actions=1 patches=0 checks=0\n")

            unicode_summary = document(
                "planning",
                [
                    {
                        "id": "finish",
                        "type": "finish",
                        "status": "complete",
                        "summary": "NFC café, snowman \u2603, rocket \U0001f680",
                    }
                ],
            )
            for character in ("é", "☃", "🚀"):
                self.assertIn(character.encode(), unicode_summary)
            self.assertNotIn(b"\\u2603", unicode_summary)
            self.assertEqual(parse(unicode_summary, "planning").returncode, 0)

            from leftovers import vm_bundle

            section_payloads = {
                name: (b"capsule" if name == "source_capsule" else b"{}")
                for name in vm_bundle.REQUIRED_REQUEST_SECTION_TYPES
            }
            section_payloads.update(cumulative_patch=b"frozen patch\n", prior_obs=b"{}")
            request_bytes = bytearray(vm_bundle.HEADER_BYTES)
            cursor = vm_bundle.HEADER_BYTES
            records: list[tuple[str, int, int, bytes]] = []
            for name, payload in sorted(section_payloads.items()):
                cursor = (cursor + vm_bundle.ALIGNMENT - 1) & ~(vm_bundle.ALIGNMENT - 1)
                end = cursor + len(payload)
                if end > len(request_bytes):
                    request_bytes.extend(b"\0" * (end - len(request_bytes)))
                request_bytes[cursor:end] = payload
                records.append((name, cursor, len(payload), hashlib.sha256(payload).digest()))
                cursor = end
            total = (cursor + vm_bundle.ALIGNMENT - 1) & ~(vm_bundle.ALIGNMENT - 1)
            request_bytes.extend(b"\0" * (total - len(request_bytes)))
            request_bytes[: vm_bundle.HEADER_BYTES] = vm_bundle._pack_header(  # type: ignore[attr-defined]
                vm_bundle.REQUEST_MAGIC,
                vm_bundle.BundleBinding(run_id, 0, "final_verify"),
                total,
                hashlib.sha256(request_bytes[vm_bundle.HEADER_BYTES :]).digest(),
                records,
                b"\0" * 32,
            )
            request_path = temporary_path / "request.raw"
            request_path.write_bytes(request_bytes)
            request_parse = subprocess.run(
                [str(binary), "--request", str(request_path)],
                check=False,
                cwd=ROOT,
                capture_output=True,
            )
            self.assertEqual(request_parse.returncode, 0, request_parse.stderr.decode())

            duplicate_top = quoted_summary.replace(
                b'"stage":"planning"}', b'"stage":"planning","stage":"planning"}'
            )
            duplicate_action = quoted_summary.replace(
                b'"id":"finish"', b'"id":"finish","id":"shadow"'
            )
            unknown_top = quoted_summary.replace(
                b'"stage":"planning"}', b'"stage":"planning","unexpected":true}'
            )
            unknown_action = quoted_summary.replace(
                b'"id":"finish"', b'"extra":false,"id":"finish"'
            )
            escaped_type = valid_check.replace(b'"run_check"', b'"run_\\u0063heck"')
            escaped_check = valid_check.replace(
                b'"repo-tree-safety-v1"', b'"repo-tree-safety-v\\u0031"'
            )
            escaped_unicode = unicode_summary.replace("☃".encode(), b"\\u2603")
            malformed_utf8 = unicode_summary.replace("☃".encode(), b"\xe2\x28\xa1")
            overlong_utf8 = unicode_summary.replace("☃".encode(), b"\xc0\xaf")
            utf8_control = unicode_summary.replace("☃".encode(), b"\xc2\x85")
            escaped_control = quoted_summary.replace(b"quoted ", b"quoted\\n")
            unknown_check = valid_check.replace(b'"repo-tree-safety-v1"', b'"repository-selected"')
            wrong_digest = valid_patch.replace(patch_digest.encode(), b"0" * 64)
            unknown_type = valid_check.replace(b'"run_check"', b'"read_file"')
            wrong_model = quoted_summary.replace(b'"gpt-5.6-terra"', b'"gpt-5.6-sol"')
            noncanonical_whitespace = quoted_summary.replace(b',"model"', b', "model"', 1)
            wrong_action_order = valid_check.replace(
                b'{"check_id":"repo-tree-safety-v1","id":"check","type":"run_check"}',
                b'{"id":"check","check_id":"repo-tree-safety-v1","type":"run_check"}',
            )
            finish_before_check = document(
                "final_verify",
                [
                    finish,
                    {"id": "check", "type": "run_check", "check_id": "repo-tree-safety-v1"},
                ],
            )
            duplicate_ids = document(
                "final_verify",
                [
                    {
                        "id": "same",
                        "type": "run_check",
                        "check_id": "repo-tree-safety-v1",
                    },
                    {
                        "id": "same",
                        "type": "run_check",
                        "check_id": "repo-root-regular-v1",
                    },
                    finish,
                ],
            )
            duplicate_checks = document(
                "final_verify",
                [
                    {
                        "id": "checkone",
                        "type": "run_check",
                        "check_id": "repo-tree-safety-v1",
                    },
                    {
                        "id": "checktwo",
                        "type": "run_check",
                        "check_id": "repo-tree-safety-v1",
                    },
                    finish,
                ],
            )
            wrong_order = json.dumps(
                {
                    "actions": [finish],
                    "provider": "openai-codex-cli",
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "high",
                    "round": 0,
                    "run_id": run_id,
                    "schema_version": 1,
                    "stage": "planning",
                },
                separators=(",", ":"),
            ).encode("ascii")
            too_many = document(
                "final_verify",
                [
                    {
                        "id": f"check{index}",
                        "type": "run_check",
                        "check_id": "repo-tree-safety-v1",
                    }
                    for index in range(33)
                ]
                + [finish],
            )
            for hostile, stage, patch in (
                (duplicate_top, "planning", "-"),
                (duplicate_action, "planning", "-"),
                (unknown_top, "planning", "-"),
                (unknown_action, "planning", "-"),
                (escaped_type, "final_verify", "-"),
                (escaped_check, "final_verify", "-"),
                (escaped_unicode, "planning", "-"),
                (malformed_utf8, "planning", "-"),
                (overlong_utf8, "planning", "-"),
                (utf8_control, "planning", "-"),
                (escaped_control, "planning", "-"),
                (unknown_check, "final_verify", "-"),
                (wrong_digest, "implementation", patch_digest),
                (unknown_type, "final_verify", "-"),
                (wrong_model, "planning", "-"),
                (noncanonical_whitespace, "planning", "-"),
                (wrong_action_order, "final_verify", "-"),
                (finish_before_check, "final_verify", "-"),
                (duplicate_ids, "final_verify", "-"),
                (duplicate_checks, "final_verify", "-"),
                (wrong_order, "planning", "-"),
                (too_many, "final_verify", "-"),
            ):
                with self.subTest(hostile=hostile[:80]):
                    self.assertNotEqual(parse(hostile, stage, patch).returncode, 0)

            shallow = temporary_path / "shallow-tree"
            shallow.mkdir()
            cursor = shallow
            for index in range(4):
                cursor = cursor / f"d{index}"
                cursor.mkdir()
            (cursor / "regular.txt").write_text("safe", encoding="ascii")
            self.assertEqual(
                subprocess.run(
                    [str(binary), "--tree", str(shallow)],
                    check=False,
                    cwd=ROOT,
                    capture_output=True,
                ).returncode,
                0,
            )

            too_deep = temporary_path / "too-deep-tree"
            too_deep.mkdir()
            cursor = too_deep
            for index in range(33):
                cursor = cursor / f"d{index}"
                cursor.mkdir()
            self.assertNotEqual(
                subprocess.run(
                    [str(binary), "--tree", str(too_deep)],
                    check=False,
                    cwd=ROOT,
                    capture_output=True,
                ).returncode,
                0,
            )

    def test_guest_interpreter_source_matches_host_framing_bounds(self) -> None:
        from leftovers import vm_bundle

        interpreter = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_interpreter.c"
        ).read_text(encoding="utf-8")
        self.assertEqual(vm_bundle.HEADER_BYTES, 4096)
        self.assertEqual(vm_bundle.ALIGNMENT, 512)
        self.assertEqual(vm_bundle.MAX_SECTIONS, 16)
        self.assertEqual(vm_bundle.MAX_REQUEST_BYTES, 256 * 1024 * 1024)
        self.assertEqual(vm_bundle.MIN_SCRATCH_BYTES, 64 * 1024 * 1024)
        self.assertEqual(vm_bundle.MAX_RESULT_TAIL_BYTES, 64 * 1024 * 1024)
        self.assertIn("prior_obs", vm_bundle.REQUEST_SECTION_TYPES)
        self.assertNotIn("prior_observations", vm_bundle.REQUEST_SECTION_TYPES)
        self.assertTrue(
            all(len(name.encode("ascii")) <= 16 for name in vm_bundle.REQUEST_SECTION_TYPES)
        )
        for definition in (
            "#define LFR_HEADER_BYTES 4096U",
            "#define LFR_ALIGNMENT 512U",
            "#define LFR_MAX_SECTIONS 16U",
            "#define LFR_MAX_REQUEST_BYTES (256U * 1024U * 1024U)",
            "#define LFR_MIN_SCRATCH_BYTES (64U * 1024U * 1024U)",
            "#define LFR_MAX_TAIL_BYTES (64U * 1024U * 1024U)",
        ):
            self.assertIn(definition, interpreter)
        self.assertIn('memcmp(header, "LFRQ", 4U)', interpreter)
        self.assertIn('memcpy(footer, "LFRS", 4U)', interpreter)
        self.assertIn("lfr_range_is_zero", interpreter)
        self.assertIn("section->offset < prior_end", interpreter)
        self.assertIn("section->length > request->total_bytes - section->offset", interpreter)
        self.assertIn("S_ISBLK(status.st_mode)", interpreter)
        self.assertIn("BLKGETSIZE64", interpreter)
        self.assertIn("BLKROGET", interpreter)
        self.assertIn('strcmp(name, "prior_obs")', interpreter)

    def test_host_lfrq_header_parser_rejects_padding_and_overlapping_sections(self) -> None:
        """Keep the independently implemented guest table checks aligned to host framing."""
        from leftovers import vm_bundle

        binding = vm_bundle.BundleBinding("a" * 32, 0, "planning")
        payload_end = vm_bundle.HEADER_BYTES + len(vm_bundle.REQUIRED_REQUEST_SECTION_TYPES) * 512
        records = [
            (name, vm_bundle.HEADER_BYTES + index * 512, 1, hashlib.sha256(name.encode()).digest())
            for index, name in enumerate(sorted(vm_bundle.REQUIRED_REQUEST_SECTION_TYPES))
        ]
        header = vm_bundle._pack_header(  # type: ignore[attr-defined]
            vm_bundle.REQUEST_MAGIC,
            binding,
            payload_end,
            hashlib.sha256(b"host-parser-test").digest(),
            records,
            b"\0" * 32,
        )
        parsed, _payload, _marker = vm_bundle._parse_header(  # type: ignore[attr-defined]
            header,
            magic=vm_bundle.REQUEST_MAGIC,
            total_size=payload_end,
            expected=binding,
            allowed_types=vm_bundle.REQUEST_SECTION_TYPES,
            required_types=vm_bundle.REQUIRED_REQUEST_SECTION_TYPES,
            caps={**vm_bundle.REQUEST_JSON_CAPS, **vm_bundle.REQUEST_RAW_CAPS},
            payload_start=vm_bundle.HEADER_BYTES,
            payload_end=payload_end,
            require_marker=False,
        )
        self.assertEqual(parsed, records)
        padded = bytearray(header)
        padded[-1] = 1
        with self.assertRaises(vm_bundle.BundleError):
            vm_bundle._parse_header(  # type: ignore[attr-defined]
                bytes(padded),
                magic=vm_bundle.REQUEST_MAGIC,
                total_size=payload_end,
                expected=binding,
                allowed_types=vm_bundle.REQUEST_SECTION_TYPES,
                required_types=vm_bundle.REQUIRED_REQUEST_SECTION_TYPES,
                caps={**vm_bundle.REQUEST_JSON_CAPS, **vm_bundle.REQUEST_RAW_CAPS},
                payload_start=vm_bundle.HEADER_BYTES,
                payload_end=payload_end,
                require_marker=False,
            )
        overlapping = list(records)
        overlapping[1] = (overlapping[1][0], overlapping[0][1], 1, overlapping[1][3])
        overlap_header = vm_bundle._pack_header(  # type: ignore[attr-defined]
            vm_bundle.REQUEST_MAGIC,
            binding,
            payload_end,
            hashlib.sha256(b"host-parser-test").digest(),
            overlapping,
            b"\0" * 32,
        )
        with self.assertRaises(vm_bundle.BundleError):
            vm_bundle._parse_header(  # type: ignore[attr-defined]
                overlap_header,
                magic=vm_bundle.REQUEST_MAGIC,
                total_size=payload_end,
                expected=binding,
                allowed_types=vm_bundle.REQUEST_SECTION_TYPES,
                required_types=vm_bundle.REQUIRED_REQUEST_SECTION_TYPES,
                caps={**vm_bundle.REQUEST_JSON_CAPS, **vm_bundle.REQUEST_RAW_CAPS},
                payload_start=vm_bundle.HEADER_BYTES,
                payload_end=payload_end,
                require_marker=False,
            )

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
            function.index("descriptor_table_is_empty"),
            function.index("configure_worker_resource_limits"),
        )
        self.assertLess(
            function.index("configure_worker_resource_limits"),
            function.index("arm_worker_wall_timer"),
        )
        self.assertLess(
            function.index("arm_worker_wall_timer"),
            function.index("drop_capability_bounding_set_while_privileged"),
        )
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
        main = source[source.index("int main(void)") :]
        self.assertLess(
            main.index("close_all_inherited_descriptors"),
            main.index("mount_boundary_filesystems"),
        )
        self.assertLess(
            main.index("required_devices_are_exact_and_minimal"),
            main.index("fork"),
        )
        self.assertEqual(source.count("entry = readdir(directory);"), 3)
        self.assertGreaterEqual(source.count("if (errno != 0)"), 3)
        interpreter = (
            GUEST / "package" / "leftovers-guest-supervisor" / "src" / "guest_interpreter.c"
        ).read_text(encoding="utf-8")
        tree_scan = interpreter[
            interpreter.index("static bool lfr_repository_tree_safe_at") : interpreter.index(
                "static int lfr_run_fixed_check"
            )
        ]
        self.assertIn("errno = 0;", tree_scan)
        self.assertIn("if (errno != 0)", tree_scan)

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
        self.assertIn("call site is statically unreachable", readme)
        self.assertIn("patch application fails closed", readme)
        self.assertIn("host extraction rejects it", readme)
        self.assertIn("It has not been built or boot-tested", readme)
        self.assertIn("Until then, this is mechanically verifiable source policy only", readme)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
