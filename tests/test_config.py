import tempfile
import textwrap
import unittest
from pathlib import Path

from leftovers.config import ConfigError, load_config

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
