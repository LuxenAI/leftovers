import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from leftovers.codex_adapter import CodexCliInspection
from leftovers.config import ConfigError, load_config
from leftovers.onboarding import CodexSetupInputs, parse_argv_json, setup_codex


class OnboardingTests(unittest.TestCase):
    def inputs(self) -> CodexSetupInputs:
        return CodexSetupInputs(
            repository="owner/repo",
            ai_policy_url="https://github.com/owner/repo/blob/main/CONTRIBUTING.md",
            ai_policy_reviewed=True,
            test_commands=(("python", "-m", "unittest"),),
            allowed_licenses=("MIT",),
            allow_labels=("help wanted",),
            default_branch="main",
            model="gpt-5.6-luna",
            allocated_tokens=150_000,
            reserve_tokens=20_000,
            window="daily",
            timezone="America/Phoenix",
            runtime="docker",
        )

    def test_setup_writes_valid_owner_only_dry_run_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config" / "leftovers.toml"
            inspection = CodexCliInspection(
                "/Applications/ChatGPT.app/Contents/Resources/codex",
                "codex-cli 0.145.0",
                True,
                True,
                True,
            )
            with (
                mock.patch("leftovers.onboarding.inspect_codex_cli", return_value=inspection),
                mock.patch("leftovers.onboarding.shutil.which", return_value="/usr/bin/tool"),
                mock.patch("leftovers.onboarding._gh_authenticated", return_value=True),
                mock.patch("leftovers.onboarding.container_image_available", return_value=True),
                mock.patch.dict("os.environ", {"GITHUB_TOKEN": "read-only-test-token"}),
            ):
                status, report = setup_codex(target, self.inputs())
            self.assertEqual(status, 0)
            self.assertTrue(report["ready"])
            self.assertFalse(report["publication_enabled"])
            self.assertFalse(report["packages_installed"])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            config = load_config(target)
            self.assertEqual(config.agent.backend, "codex-cli")
            self.assertEqual(config.agent.command, (inspection.executable,))
            self.assertEqual(config.publication.mode, "dry-run")
            self.assertTrue(config.repositories[0].require_human_approval)

    def test_setup_refuses_overwrite_and_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "leftovers.toml"
            target.write_text("keep")
            inspection = CodexCliInspection("/usr/bin/codex", "codex-cli 1.0.0", True, True, True)
            with (
                mock.patch("leftovers.onboarding.inspect_codex_cli", return_value=inspection),
                self.assertRaisesRegex(ConfigError, "refusing to overwrite"),
            ):
                setup_codex(target, self.inputs())
            self.assertEqual(target.read_text(), "keep")
            target.unlink()
            outside = Path(directory) / "outside"
            outside.write_text("keep")
            target.symlink_to(outside)
            with (
                mock.patch("leftovers.onboarding.inspect_codex_cli", return_value=inspection),
                self.assertRaisesRegex(ConfigError, "refusing to overwrite"),
            ):
                setup_codex(target, self.inputs())
            self.assertEqual(outside.read_text(), "keep")

    def test_setup_requires_policy_test_license_and_real_budget_confirmation(self) -> None:
        unsafe = self.inputs()
        for replacement, message in (
            ({"ai_policy_reviewed": False}, "policy was reviewed"),
            ({"test_commands": ()}, "test command"),
            ({"allowed_licenses": ()}, "SPDX"),
            ({"allocated_tokens": 100_000}, "at least 100000"),
        ):
            with self.subTest(message=message):
                values = {**unsafe.__dict__, **replacement}
                with self.assertRaisesRegex(ConfigError, message):
                    setup_codex(Path("unused"), CodexSetupInputs(**values))

    def test_test_commands_are_strict_json_argv_arrays(self) -> None:
        self.assertEqual(
            parse_argv_json('["python","-m","pytest","-q"]'),
            ("python", "-m", "pytest", "-q"),
        )
        for unsafe in ('"python -m pytest"', "[]", '["sh", 2]', '["sh", ""]'):
            with self.subTest(unsafe=unsafe), self.assertRaises(ConfigError):
                parse_argv_json(unsafe)


if __name__ == "__main__":
    unittest.main()
