from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = _load_script("leftovers_test_integrity_builder", "build_macos_package.py")
verifier = _load_script("leftovers_test_integrity_verifier", "verify_macos_package.py")


class PackageIntegrityTests(unittest.TestCase):
    def private_root(self) -> Path:
        root = Path(tempfile.mkdtemp())
        os.chmod(root, 0o700)
        self.addCleanup(shutil.rmtree, root)
        return root

    def extracted_package(self) -> tuple[Path, Path]:
        temporary = self.private_root()
        archive_path = temporary / "package.tar.gz"
        builder.build(archive_path)
        extracted = temporary / "extracted"
        extracted.mkdir(mode=0o700)
        previous_umask = os.umask(0o077)
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                archive.extractall(extracted, filter="data")
        finally:
            os.umask(previous_umask)
        return archive_path, extracted / builder.PACKAGE_NAME

    def test_verifies_extracted_payload_and_optional_external_archive_digest(self) -> None:
        archive_path, package_root = self.extracted_package()
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        self.assertTrue((package_root / "scripts" / "verify_macos_package.py").is_file())

        result = verifier.verify(
            package_root,
            archive=archive_path,
            archive_sha256=digest,
        )

        self.assertEqual(result["internal_consistency"], "verified")
        self.assertEqual(result["external_archive_sha256"], digest)
        self.assertEqual(result["archive_tree_binding"], "verified")
        self.assertEqual(result["authenticity"], "bound-to-supplied-archive-digest")

    def test_trusted_archive_cannot_be_paired_with_a_different_consistent_root(self) -> None:
        archive_path, package_root = self.extracted_package()
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        readme = package_root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"locally replaced\n")
        manifest_path = package_root / "PACKAGE-MANIFEST.json"
        manifest = json.loads(manifest_path.read_bytes())
        entry = next(item for item in manifest["files"] if item["path"] == "README.md")
        payload = readme.read_bytes()
        entry["bytes"] = len(payload)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)

        self.assertEqual(verifier.verify(package_root)["internal_consistency"], "verified")
        with self.assertRaisesRegex(
            verifier.PackageVerificationError,
            "external archive member mismatch",
        ):
            verifier.verify(
                package_root,
                archive=archive_path,
                archive_sha256=digest,
            )

    def test_hardened_umask_extraction_preserves_verifiable_owner_only_modes(self) -> None:
        temporary = self.private_root()
        archive_path = temporary / "package.tar.gz"
        builder.build(archive_path)
        extracted = temporary / "hardened-extraction"
        extracted.mkdir(mode=0o700)
        tar = shutil.which("tar")
        if tar is None:
            self.skipTest("tar is unavailable")
        completed = subprocess.run(
            [tar, "-xzf", str(archive_path), "-C", str(extracted)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            preexec_fn=lambda: os.umask(0o077),
            timeout=20,
            check=False,
        )
        diagnostic = (completed.stdout + completed.stderr).decode(errors="replace")
        self.assertEqual(completed.returncode, 0, diagnostic)
        package_root = extracted / builder.PACKAGE_NAME

        result = verifier.verify(package_root)

        self.assertEqual(result["internal_consistency"], "verified")
        self.assertEqual((package_root / "PACKAGE-MANIFEST.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            (package_root / "scripts" / "install-macos.sh").stat().st_mode & 0o777,
            0o700,
        )
        self.assertEqual((package_root / "vm" / "check.sh").stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (package_root / "vm" / "smoke_init.sh").stat().st_mode & 0o777,
            0o700,
        )
        self.assertEqual(
            (package_root / "vm" / "strict_vm_launcher.swift").stat().st_mode & 0o777,
            0o600,
        )

    def test_extracted_source_timestamps_can_build_the_installed_zipapp(self) -> None:
        _, package_root = self.extracted_package()
        output = package_root.parent / "leftovers.pyz"

        zipapp.create_archive(
            package_root / "src",
            output,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )

        self.assertTrue(output.is_file())

    def test_status_wrapper_does_not_pollute_verified_source_with_bytecode(self) -> None:
        _, package_root = self.extracted_package()
        install_root = (package_root / ".leftovers" / "install").resolve()
        install_root.mkdir(parents=True, mode=0o700)
        install_root.parent.chmod(0o700)
        manifest = install_root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "installed_at": "2026-07-18T00:00:00Z",
                    "install_root": str(install_root),
                    "publication": "disabled",
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "high",
                    "launch_label": None,
                }
            ),
            encoding="utf-8",
        )
        manifest.chmod(0o600)

        completed = subprocess.run(
            [str(package_root / "scripts" / "status-macos.sh")],
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LEFTOVERS_INSTALL_PYTHON": sys.executable,
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=20,
            check=False,
        )

        diagnostic = (completed.stdout + completed.stderr).decode(errors="replace")
        self.assertEqual(completed.returncode, 0, diagnostic)
        self.assertFalse((package_root / "scripts" / "__pycache__").exists())
        self.assertEqual(verifier.verify(package_root)["internal_consistency"], "verified")

    def test_rejects_missing_and_extra_payloads_before_installation(self) -> None:
        _, package_root = self.extracted_package()
        (package_root / "README.md").unlink()
        with self.assertRaisesRegex(verifier.PackageVerificationError, "missing manifest payload"):
            verifier.verify(package_root)

        _, package_root = self.extracted_package()
        (package_root / "unexpected.txt").write_text("not packaged\n", encoding="utf-8")
        with self.assertRaisesRegex(verifier.PackageVerificationError, "extra payload"):
            verifier.verify(package_root)

        _, package_root = self.extracted_package()
        (package_root / "unexpected-directory").mkdir(mode=0o700)
        with self.assertRaisesRegex(verifier.PackageVerificationError, "extra directory"):
            verifier.verify(package_root)

    def test_rejects_permissive_or_nonprivate_package_directories(self) -> None:
        _, package_root = self.extracted_package()
        package_root.chmod(0o755)
        with self.assertRaisesRegex(verifier.PackageVerificationError, "0700 directory"):
            verifier.verify(package_root)

        _, package_root = self.extracted_package()
        (package_root / "docs").chmod(0o755)
        with self.assertRaisesRegex(verifier.PackageVerificationError, "current-user-owned 0700"):
            verifier.verify(package_root)

    def test_reinstall_allows_only_the_exact_owner_private_state_directory(self) -> None:
        _, package_root = self.extracted_package()
        managed_state = package_root / ".leftovers"
        managed_state.mkdir(mode=0o700)
        install_state = managed_state / "install"
        install_state.mkdir(mode=0o700)
        (install_state / "manifest.json").write_text("{}\n", encoding="utf-8")

        result = verifier.verify(package_root)

        self.assertEqual(result["internal_consistency"], "verified")
        managed_state.chmod(0o755)
        with self.assertRaisesRegex(verifier.PackageVerificationError, "managed-state directory"):
            verifier.verify(package_root)

        managed_state.chmod(0o700)
        shutil.rmtree(managed_state)
        managed_state.symlink_to(package_root / "docs", target_is_directory=True)
        with self.assertRaisesRegex(verifier.PackageVerificationError, "symlink payload"):
            verifier.verify(package_root)

    def test_rejects_tampered_or_symlink_payloads_before_installation(self) -> None:
        _, package_root = self.extracted_package()
        with (package_root / "README.md").open("ab") as stream:
            stream.write(b"tampered\n")
        with self.assertRaisesRegex(verifier.PackageVerificationError, "digest or size mismatch"):
            verifier.verify(package_root)

        _, package_root = self.extracted_package()
        (package_root / "scripts" / "unexpected-link").symlink_to("install-macos.sh")
        with self.assertRaisesRegex(verifier.PackageVerificationError, "symlink payload"):
            verifier.verify(package_root)

    def test_rejects_oversized_manifest_before_decoding(self) -> None:
        _, package_root = self.extracted_package()
        manifest = package_root / "PACKAGE-MANIFEST.json"
        manifest.write_bytes(b" " * (verifier.MAX_MANIFEST_BYTES + 1))
        manifest.chmod(0o600)
        with self.assertRaisesRegex(verifier.PackageVerificationError, "size bound"):
            verifier.verify(package_root)

    def test_rejects_external_archive_digest_mismatch(self) -> None:
        archive_path, package_root = self.extracted_package()
        with self.assertRaisesRegex(verifier.PackageVerificationError, "does not match"):
            verifier.verify(package_root, archive=archive_path, archive_sha256="0" * 64)

    def test_source_checkout_entrypoint_skips_transfer_manifest_verifier(self) -> None:
        temporary = self.private_root()
        fake_python = temporary / "python3"
        fake_python.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
        fake_python.chmod(0o700)
        fake_git = temporary / "git"
        fake_git.write_text(
            "#!/bin/sh\nprintf '%s\\n' " + shlex.quote(str(ROOT)) + "\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o700)
        completed = subprocess.run(
            [str(ROOT / "scripts" / "install-macos.sh"), "--launch-now"],
            env={
                **os.environ,
                "LEFTOVERS_INSTALL_PYTHON": str(fake_python),
                "LEFTOVERS_INSTALL_GIT": str(fake_git),
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(str(ROOT / "scripts" / "install_macos.py"), completed.stdout)
        self.assertNotIn("verify_macos_package.py", completed.stdout)


if __name__ == "__main__":
    unittest.main()
