from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "leftovers_test_log_bounds_installer",
    ROOT / "scripts" / "install_macos.py",
)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


class MacOSLaunchLogBoundsTests(unittest.TestCase):
    def test_each_one_shot_replaces_prior_log_growth_with_an_empty_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            log = root / "job.stdout.log"
            log.write_bytes(b"x" * (2 << 20))
            log.chmod(0o644)

            installer._prepare_launch_log(log)

            info = log.lstat()
            self.assertEqual(info.st_size, 0)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)

    def test_symlinked_launch_log_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            target = root / "target"
            target.write_bytes(b"retain")
            link = root / "job.stderr.log"
            link.symlink_to(target)

            with self.assertRaisesRegex(installer.InstallError, "not a safe regular file"):
                installer._prepare_launch_log(link)

            self.assertEqual(target.read_bytes(), b"retain")


if __name__ == "__main__":
    unittest.main()
