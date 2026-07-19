import tempfile
import textwrap
import unittest
from pathlib import Path

from leftovers.config import ConfigError, load_config, production_isolation_violations

BASE = """
version = 1
[budget]
source = "fixed"
fixed_remaining_tokens = 100000
[agent]
backend = "container"
command = ["agent"]
[publication]
mode = "dry-run"
[[repositories]]
slug = "owner/repo"
ai_contributions_allowed = true
ai_policy_url = "https://github.com/owner/repo/blob/main/CONTRIBUTING.md"
ai_policy_checked_at = "2026-07-17"
test_commands = [["python", "-m", "unittest"]]
"""


def strict_vm_config() -> str:
    digest = "a" * 64
    return BASE.replace(
        'backend = "container"\ncommand = ["agent"]',
        'backend = "strict-vm"\ncommand = []\npass_environment = []',
    ).replace(
        "[publication]",
        f"""
[strict_vm]
enabled = true
launcher_path = "/trusted/bin/strict-vm-launcher"
launcher_sha256 = "{digest}"
boot_artifact_directory = "/trusted/boot"
kernel_path = "/trusted/boot/kernel"
kernel_sha256 = "{digest}"
initrd_path = "/trusted/boot/initrd"
initrd_sha256 = "{digest}"
root_disk_path = "/trusted/boot/root.raw"
root_disk_sha256 = "{digest}"
guest_policy_path = "/trusted/boot/guest-policy.json"

[mediator]
backend = "fixture"
model = "gpt-5.6-terra"
reasoning_effort = "high"

[publication]""",
    )


def sbx_config() -> str:
    return BASE.replace(
        'backend = "container"\ncommand = ["agent"]',
        'backend = "sbx"\ncommand = []\nprovider = "openai-codex-cli"\n'
        'model = "gpt-5.6-terra"\ncheckin_required = true\n'
        "usage_reporting_required = true\nestimated_tokens_p50 = 40000\n"
        "estimated_tokens_p95 = 50000\nmax_repair_cycles = 0\npass_environment = []",
    ).replace(
        "[publication]",
        """
[sbx]
binary_path = "/opt/homebrew/Caskroom/sbx/0.35.0/bin/sbx"
binary_sha256 = "b046dce135756ee14a72e88165c90b07d10e2d48b86cd089adee5acc2abf2d01"
version = "v0.35.0"
revision = "01e01520456e4126a9653471e7072e4d9b280321"
agent = "codex"
clone_mode_required = true
cpus = 2
memory = "4g"
create_timeout_seconds = 300
stage_timeout_seconds = 1200
cleanup_timeout_seconds = 120
max_output_bytes = 65536
network_policy = "locked-down-openai-only"
reasoning_effort = "high"

[publication]""",
    )


class ConfigTests(unittest.TestCase):
    def write(self, content: str) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "config.toml"
        path.write_text(textwrap.dedent(content))
        self.addCleanup(lambda: __import__("shutil").rmtree(directory))
        return path

    def test_minimal_config_loads(self) -> None:
        config = load_config(self.write(BASE))
        self.assertEqual(config.repositories[0].slug, "owner/repo")
        self.assertEqual(config.github.api_version, "2026-03-10")

    def test_strict_vm_staging_config_is_typed_with_fixture_mediator(self) -> None:
        config = load_config(self.write(strict_vm_config()))
        self.assertTrue(config.strict_vm.enabled)
        self.assertEqual(config.agent.backend, "strict-vm")
        self.assertEqual(config.agent.command, ())
        self.assertEqual(config.mediator.model, "gpt-5.6-terra")
        self.assertEqual(config.mediator.backend, "fixture")
        self.assertIn(
            "agent.backend must be sbx for unattended production",
            production_isolation_violations(config),
        )

    def test_sbx_staging_config_is_typed_but_production_remains_source_disabled(self) -> None:
        config = load_config(self.write(sbx_config()))
        self.assertEqual(config.agent.backend, "sbx")
        self.assertEqual(config.sbx.version, "v0.35.0")
        self.assertEqual(config.sbx.agent, "codex")
        self.assertEqual(config.mediator.max_calls, 3)
        self.assertEqual(config.mediator.total_token_cap, 55_000)
        self.assertIn(
            "Docker Sandboxes production execution is disabled pending live clone, policy, "
            "credential, result-extraction, and cleanup evidence",
            production_isolation_violations(config),
        )

    def test_sbx_mediator_limits_are_the_exact_three_stage_contract(self) -> None:
        cases = (
            ("max_calls = 3", "max_calls = 4"),
            ("per_call_timeout_seconds = 1200", "per_call_timeout_seconds = 1199"),
            ("max_prompt_bytes = 20904", "max_prompt_bytes = 20905"),
            ("max_response_bytes = 65536", "max_response_bytes = 65535"),
            ("total_token_cap = 55000", "total_token_cap = 55001"),
        )
        mediator = """
[mediator]
backend = "disabled"
provider = "openai-subscription"
model = "gpt-5.6-terra"
reasoning_effort = "high"
max_calls = 3
per_call_timeout_seconds = 1200
max_prompt_bytes = 20904
max_response_bytes = 65536
total_token_cap = 55000

"""
        source = sbx_config().replace("[publication]", mediator + "[publication]")
        for original, replacement in cases:
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ConfigError, "exact three-stage Terra-high"),
            ):
                load_config(self.write(source.replace(original, replacement)))

    def test_sbx_has_no_configurable_authority_surfaces(self) -> None:
        for field, value in (
            ("template", '"mutable:latest"'),
            ("kit", '"github"'),
            ("profile", '"balanced"'),
            ("extra_workspace", '"/Users"'),
            ("ports", '["0.0.0.0:8080"]'),
            ("secret", '"github"'),
        ):
            with self.subTest(field=field):
                unsafe = sbx_config().replace("[sbx]", f"[sbx]\n{field} = {value}")
                with self.assertRaisesRegex(ConfigError, "unknown key"):
                    load_config(self.write(unsafe))

    def test_sbx_requires_exact_identity_clone_and_terra_high(self) -> None:
        cases = (
            (
                'binary_sha256 = "b046dce135756ee14a72e88165c90b07d10e2d48b86cd089'
                'adee5acc2abf2d01"',
                "",
                "pinned sbx identity",
            ),
            ('version = "v0.35.0"', 'version = "0.35"', "exact stable version"),
            ("clone_mode_required = true", "clone_mode_required = false", "may not be disabled"),
            ('model = "gpt-5.6-terra"', 'model = "other"', "gpt-5.6-terra"),
            ('reasoning_effort = "high"', 'reasoning_effort = "medium"', "must be high"),
        )
        for original, replacement, expected in cases:
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ConfigError, expected),
            ):
                load_config(self.write(sbx_config().replace(original, replacement)))

    def test_sbx_requires_the_exact_reviewed_resource_and_agent_profiles(self) -> None:
        cases = (
            ("cpus = 2", "cpus = 3", "exact reviewed v0.35"),
            ('memory = "4g"', 'memory = "3g"', "exact reviewed v0.35"),
            ("create_timeout_seconds = 300", "create_timeout_seconds = 301", "exact reviewed"),
            ("checkin_required = true", "checkin_required = false", "agent safeguards"),
            (
                "usage_reporting_required = true",
                "usage_reporting_required = false",
                "agent safeguards",
            ),
            ("max_repair_cycles = 0", "max_repair_cycles = 1", "agent safeguards"),
            ("estimated_tokens_p95 = 50000", "estimated_tokens_p95 = 55001", "agent safeguards"),
        )
        for original, replacement, expected in cases:
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ConfigError, expected),
            ):
                load_config(self.write(sbx_config().replace(original, replacement)))

    def test_strict_vm_has_no_configurable_command_endpoint_or_environment(self) -> None:
        for section, field, value in (
            ("strict_vm", "command", '["sh"]'),
            ("strict_vm", "mount", '"/Users"'),
            ("mediator", "endpoint", '"https://example.test"'),
            ("mediator", "command", '["codex"]'),
        ):
            with self.subTest(section=section, field=field):
                marker = f"[{section}]"
                unsafe = strict_vm_config().replace(marker, f"{marker}\n{field} = {value}")
                with self.assertRaisesRegex(ConfigError, "unknown key"):
                    load_config(self.write(unsafe))

    def test_strict_vm_requires_all_pinned_artifact_identities(self) -> None:
        unsafe = strict_vm_config().replace('launcher_sha256 = "' + "a" * 64 + '"\n', "")
        with self.assertRaisesRegex(ConfigError, "launcher_sha256"):
            load_config(self.write(unsafe))

    def test_strict_vm_paths_are_canonical_and_boot_artifacts_are_direct_children(self) -> None:
        cases = (
            (
                'launcher_path = "/trusted/bin/strict-vm-launcher"',
                'launcher_path = "relative/launcher"',
                "canonical absolute path",
            ),
            (
                'kernel_path = "/trusted/boot/kernel"',
                'kernel_path = "/trusted/other/kernel"',
                "direct child",
            ),
            (
                'guest_policy_path = "/trusted/boot/guest-policy.json"',
                'guest_policy_path = "/trusted/other/guest-policy.json"',
                "direct child",
            ),
            (
                'root_disk_sha256 = "' + "a" * 64 + '"',
                'root_disk_sha256 = "' + "A" * 64 + '"',
                "lowercase SHA-256",
            ),
        )
        for original, replacement, expected in cases:
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ConfigError, expected),
            ):
                load_config(self.write(strict_vm_config().replace(original, replacement)))

    def test_strict_vm_refuses_a_config_supplied_guest_policy_digest(self) -> None:
        unsafe = strict_vm_config().replace(
            'guest_policy_path = "/trusted/boot/guest-policy.json"',
            'guest_policy_path = "/trusted/boot/guest-policy.json"\n'
            'guest_policy_sha256 = "' + "a" * 64 + '"',
        )
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            load_config(self.write(unsafe))

    def test_strict_vm_limits_are_bounded_independently(self) -> None:
        cases = (
            ("cpu_count = 2", "cpu_count = 5", "hardware limits"),
            ("memory_bytes = 2147483648", "memory_bytes = 536870913", "hardware limits"),
            ("max_rounds = 8", "max_rounds = 33", "protocol limits"),
            ("max_actions_per_round = 24", "max_actions_per_round = 33", "protocol limits"),
            (
                "max_observation_bytes = 262144",
                "max_observation_bytes = 262145",
                "protocol limits",
            ),
            (
                "result_region_bytes = 16777216",
                "result_region_bytes = 4294967296",
                "protocol limits",
            ),
        )
        source = strict_vm_config().replace(
            'guest_policy_path = "/trusted/boot/guest-policy.json"',
            'guest_policy_path = "/trusted/boot/guest-policy.json"\n'
            "cpu_count = 2\nmemory_bytes = 2147483648\nmax_rounds = 8\n"
            "max_actions_per_round = 24\nmax_observation_bytes = 262144\n"
            "result_region_bytes = 16777216",
        )
        for original, replacement, expected in cases:
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ConfigError, expected),
            ):
                load_config(self.write(source.replace(original, replacement)))

    def test_enabled_strict_vm_requires_the_exact_installed_resource_profile(self) -> None:
        source = strict_vm_config().replace(
            'guest_policy_path = "/trusted/boot/guest-policy.json"',
            'guest_policy_path = "/trusted/boot/guest-policy.json"\n'
            "cpu_count = 2\nmemory_bytes = 2147483648\n"
            "scratch_bytes = 2147483648\nwall_time_seconds = 1800",
        )
        for original, replacement in (
            ("cpu_count = 2", "cpu_count = 1"),
            ("memory_bytes = 2147483648", "memory_bytes = 1073741824"),
            ("scratch_bytes = 2147483648", "scratch_bytes = 1073741824"),
            ("wall_time_seconds = 1800", "wall_time_seconds = 900"),
        ):
            with (
                self.subTest(replacement=replacement),
                self.assertRaisesRegex(ConfigError, "exact installed resource profile"),
            ):
                load_config(self.write(source.replace(original, replacement)))

    def test_mediator_reasoning_effort_matches_runtime_grammar(self) -> None:
        unsafe = strict_vm_config().replace(
            'reasoning_effort = "high"', 'reasoning_effort = "xhigh"'
        )
        with self.assertRaisesRegex(ConfigError, "reasoning_effort is unsupported"):
            load_config(self.write(unsafe))

    def test_unknown_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            load_config(self.write(BASE + "\n[github]\ntyop = true\n"))

    def test_github_write_credentials_cannot_enter_worker(self) -> None:
        unsafe = BASE.replace(
            'command = ["agent"]',
            'command = ["agent"]\npass_environment = ["GH_TOKEN"]',
        )
        with self.assertRaisesRegex(ConfigError, "may not receive GitHub"):
            load_config(self.write(unsafe))

    def test_non_draft_publication_is_rejected(self) -> None:
        unsafe = BASE.replace('mode = "dry-run"', 'mode = "draft-pr"\ndraft = false')
        with self.assertRaisesRegex(ConfigError, "only publishes draft"):
            load_config(self.write(unsafe))

    def test_string_boolean_is_not_coerced(self) -> None:
        unsafe = BASE.replace('mode = "dry-run"', 'mode = "dry-run"\ndraft = "false"')
        with self.assertRaisesRegex(ConfigError, "publication.draft has type str"):
            load_config(self.write(unsafe))

    def test_negative_budget_values_are_rejected(self) -> None:
        unsafe = BASE.replace("fixed_remaining_tokens = 100000", "fixed_remaining_tokens = -1")
        with self.assertRaisesRegex(ConfigError, "cannot be negative"):
            load_config(self.write(unsafe))

    def test_invalid_budget_reset_ranges_are_rejected(self) -> None:
        unsafe = BASE.replace(
            "fixed_remaining_tokens = 100000",
            "fixed_remaining_tokens = 100000\nreset_hour = 24",
        )
        with self.assertRaisesRegex(ConfigError, "reset_hour"):
            load_config(self.write(unsafe))

    def test_unsafe_image_reference_is_rejected(self) -> None:
        unsafe = BASE.replace(
            "[agent]",
            '[sandbox]\nimage = "image;--privileged"\n\n[agent]',
        )
        with self.assertRaisesRegex(ConfigError, "safe OCI image"):
            load_config(self.write(unsafe))

    def test_invalid_sandbox_network_is_rejected(self) -> None:
        unsafe = BASE.replace(
            "[agent]",
            '[sandbox]\nnetwork = "host"\n\n[agent]',
        )
        with self.assertRaisesRegex(ConfigError, "network must be none or bridge"):
            load_config(self.write(unsafe))

    def test_sandbox_byte_sizes_use_bounded_unambiguous_units(self) -> None:
        valid = BASE.replace(
            "[agent]",
            '[sandbox]\nmemory = "8g"\ntmpfs_size = "1024m"\n\n[agent]',
        )
        config = load_config(self.write(valid))
        self.assertEqual(config.sandbox.memory, "8g")
        self.assertEqual(config.sandbox.tmpfs_size, "1024m")

        invalid_values = (
            ("memory", "4GiB", "positive integer byte size"),
            ("memory", "0g", "positive integer byte size"),
            ("memory", "32m", "conservative byte-size bounds"),
            ("memory", "9999999999g", "conservative byte-size bounds"),
            ("tmpfs_size", "0", "positive integer byte size"),
            ("tmpfs_size", "9g", "conservative byte-size bounds"),
        )
        for field, value, expected in invalid_values:
            with self.subTest(field=field, value=value):
                unsafe = BASE.replace(
                    "[agent]",
                    f'[sandbox]\n{field} = "{value}"\n\n[agent]',
                )
                with self.assertRaisesRegex(ConfigError, expected):
                    load_config(self.write(unsafe))

    def test_tmpfs_may_not_exceed_memory_limit(self) -> None:
        unsafe = BASE.replace(
            "[agent]",
            '[sandbox]\nmemory = "128m"\ntmpfs_size = "256m"\n\n[agent]',
        )
        with self.assertRaisesRegex(ConfigError, "may not exceed"):
            load_config(self.write(unsafe))

    def test_custom_github_token_environment_cannot_enter_worker(self) -> None:
        unsafe = BASE.replace(
            "[budget]",
            '[github]\ntoken_env = "LEFTOVERS_GITHUB_READ_TOKEN"\n\n[budget]',
        ).replace(
            'command = ["agent"]',
            'command = ["agent"]\npass_environment = ["LEFTOVERS_GITHUB_READ_TOKEN"]',
        )
        with self.assertRaisesRegex(ConfigError, "may not receive GitHub"):
            load_config(self.write(unsafe))

    def test_runtime_control_environment_cannot_enter_worker(self) -> None:
        for variable in ("DOCKER_HOST", "CONTAINER_HOST", "PODMAN_CONNECTIONS_CONF", "KUBECONFIG"):
            with self.subTest(variable=variable):
                unsafe = BASE.replace(
                    'command = ["agent"]',
                    f'command = ["agent"]\npass_environment = ["{variable}"]',
                )
                with self.assertRaisesRegex(ConfigError, "runtime-control"):
                    load_config(self.write(unsafe))

    def test_non_finite_budget_multiplier_is_rejected(self) -> None:
        unsafe = BASE.replace(
            "fixed_remaining_tokens = 100000",
            "fixed_remaining_tokens = 100000\nsafety_multiplier = nan",
        )
        with self.assertRaisesRegex(ConfigError, "between 1 and 3"):
            load_config(self.write(unsafe))

    def test_unsafe_branch_prefix_is_rejected(self) -> None:
        unsafe = BASE.replace('mode = "dry-run"', 'mode = "dry-run"\nbranch_prefix = "bad ref"')
        with self.assertRaisesRegex(ConfigError, "Git ref"):
            load_config(self.write(unsafe))

    def test_safety_invariants_cannot_be_disabled(self) -> None:
        unsafe = BASE.replace(
            "[agent]",
            "[policy]\nrequire_unassigned = false\n\n[agent]",
        )
        with self.assertRaisesRegex(ConfigError, "may not be disabled"):
            load_config(self.write(unsafe))

    def test_unrecognized_allowed_license_is_rejected(self) -> None:
        unsafe = BASE.replace(
            'test_commands = [["python", "-m", "unittest"]]',
            'test_commands = [["python", "-m", "unittest"]]\nallowed_licenses = ["NOASSERTION"]',
        )
        with self.assertRaisesRegex(ConfigError, "unrecognized SPDX"):
            load_config(self.write(unsafe))

    def test_draft_publication_requires_explicit_license_allowlist(self) -> None:
        digest = "a" * 64
        unsafe = (
            BASE.replace(
                "[agent]",
                f'[sandbox]\nimage = "leftovers@sha256:{digest}"\n\n[agent]',
            )
            .replace(
                'mode = "dry-run"',
                'mode = "draft-pr"\nexpected_login = "leftovers-bot"\nexpected_user_id = 1',
            )
            .replace(
                'test_commands = [["python", "-m", "unittest"]]',
                'test_commands = [["python", "-m", "unittest"]]\nallow_labels = ["help wanted"]',
            )
        )
        with self.assertRaisesRegex(ConfigError, "explicit allowed_licenses"):
            load_config(self.write(unsafe))


if __name__ == "__main__":
    unittest.main()
