from __future__ import annotations

import plistlib
import stat
import subprocess
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
RUN_CYCLE = ROOT / "scripts" / "run-cycle.sh"
LAUNCHD = ROOT / "schedules" / "launchd"
SYSTEMD = ROOT / "schedules" / "systemd"
PLACEHOLDER_ROOT = "/ABSOLUTE/PATH/TO/Leftovers"


def _parse_systemd_unit(path: Path) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    current_section: str | None = None
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            if not current_section:
                raise AssertionError(f"{path}:{line_number}: empty section")
            continue
        if current_section is None or "=" not in line:
            raise AssertionError(f"{path}:{line_number}: malformed unit directive")
        key, value = line.split("=", 1)
        if not key:
            raise AssertionError(f"{path}:{line_number}: empty unit directive")
        sections[current_section][key].append(value)
    return {section: dict(directives) for section, directives in sections.items()}


class SchedulerRegressionTests(unittest.TestCase):
    def test_container_test_stage_includes_scheduler_assets(self) -> None:
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            "COPY --chown=leftovers:leftovers schedules /app/schedules",
            dockerfile,
        )

    def test_run_cycle_has_valid_posix_shell_syntax_and_safety_contract(self) -> None:
        syntax = subprocess.run(
            ["/bin/sh", "-n", str(RUN_CYCLE)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertTrue(RUN_CYCLE.stat().st_mode & stat.S_IXUSR)

        script = RUN_CYCLE.read_text(encoding="utf-8")
        required_fragments = (
            "set -eu",
            "umask 077",
            "scheduler environment must be a regular, non-symlink file",
            "scheduler environment must be owned by the current user",
            "scheduler environment permissions must be 0600 or 0400",
            "LEFTOVERS_PYTHON must be an absolute path",
            "fcntl.LOCK_EX | fcntl.LOCK_NB",
            (
                'arguments = [sys.executable, "-m", "leftovers", "--config", '
                'config, "run", "--execute"]'
            ),
            'if publish:\n    arguments.append("--publish")',
            "os.execve(sys.executable, arguments, environment)",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        self.assertNotIn("eval ", script)
        self.assertNotIn("shell=True", script)

    def test_launchd_examples_parse_and_preserve_critical_settings(self) -> None:
        expectations = {
            "daily": {
                "label": "dev.leftovers.daily",
                "calendar": {"Hour": 22, "Minute": 30},
            },
            "weekly": {
                "label": "dev.leftovers.weekly",
                "calendar": {"Weekday": 6, "Hour": 22, "Minute": 0},
            },
        }
        for cadence, expected in expectations.items():
            with self.subTest(cadence=cadence):
                path = LAUNCHD / f"dev.leftovers.{cadence}.plist.example"
                with path.open("rb") as stream:
                    payload = plistlib.load(stream)

                self.assertEqual(payload["Label"], expected["label"])
                self.assertEqual(
                    payload["ProgramArguments"],
                    ["/bin/sh", f"{PLACEHOLDER_ROOT}/scripts/run-cycle.sh"],
                )
                self.assertEqual(payload["WorkingDirectory"], PLACEHOLDER_ROOT)
                self.assertEqual(payload["StartCalendarInterval"], expected["calendar"])
                self.assertEqual(
                    payload["EnvironmentVariables"],
                    {
                        "LEFTOVERS_ENV_FILE": (f"{PLACEHOLDER_ROOT}/.leftovers/scheduler.env"),
                        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                    },
                )
                self.assertEqual(
                    payload["StandardOutPath"],
                    f"{PLACEHOLDER_ROOT}/.leftovers/scheduler.out.log",
                )
                self.assertEqual(
                    payload["StandardErrorPath"],
                    f"{PLACEHOLDER_ROOT}/.leftovers/scheduler.err.log",
                )
                self.assertNotIn("RunAtLoad", payload)
                self.assertNotIn("KeepAlive", payload)
                self._assert_no_embedded_credential_names(path.read_text(encoding="utf-8"))

    def test_systemd_service_parses_and_preserves_hardening(self) -> None:
        path = SYSTEMD / "leftovers.service"
        unit = _parse_systemd_unit(path)

        self.assertEqual(unit["Unit"]["After"], ["network-online.target"])
        self.assertEqual(unit["Unit"]["Wants"], ["network-online.target"])
        service = unit["Service"]
        self.assertEqual(service["Type"], ["oneshot"])
        self.assertEqual(service["WorkingDirectory"], [PLACEHOLDER_ROOT])
        self.assertEqual(service["ExecStart"], [f"{PLACEHOLDER_ROOT}/scripts/run-cycle.sh"])
        self.assertCountEqual(
            service["Environment"],
            [
                f"LEFTOVERS_ENV_FILE={PLACEHOLDER_ROOT}/.leftovers/scheduler.env",
                "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            ],
        )
        self.assertEqual(service["NoNewPrivileges"], ["true"])
        self.assertEqual(service["PrivateTmp"], ["true"])
        self.assertEqual(service["ProtectSystem"], ["strict"])
        self.assertEqual(service["ProtectHome"], ["read-only"])
        self.assertEqual(service["ReadWritePaths"], [f"{PLACEHOLDER_ROOT}/.leftovers"])
        self.assertEqual(service["UMask"], ["0077"])
        self._assert_no_embedded_credential_names(path.read_text(encoding="utf-8"))

    def test_systemd_timers_parse_and_preserve_cadence(self) -> None:
        expectations = {
            "daily": {
                "calendar": "*-*-* 22:30:00",
                "delay": "5m",
            },
            "weekly": {
                "calendar": "Fri *-*-* 22:00:00",
                "delay": "10m",
            },
        }
        for cadence, expected in expectations.items():
            with self.subTest(cadence=cadence):
                path = SYSTEMD / f"leftovers-{cadence}.timer"
                unit = _parse_systemd_unit(path)
                timer = unit["Timer"]
                self.assertEqual(timer["OnCalendar"], [expected["calendar"]])
                self.assertEqual(timer["Persistent"], ["true"])
                self.assertEqual(timer["RandomizedDelaySec"], [expected["delay"]])
                self.assertEqual(timer["Unit"], ["leftovers.service"])
                self.assertEqual(unit["Install"]["WantedBy"], ["timers.target"])
                self._assert_no_embedded_credential_names(path.read_text(encoding="utf-8"))

    def _assert_no_embedded_credential_names(self, text: str) -> None:
        for name in ("GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK"):
            self.assertNotIn(name, text)


if __name__ == "__main__":
    unittest.main()
