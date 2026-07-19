from __future__ import annotations

import platform
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "vm" / "broker" / "NativeBrokerTrustAdapter.swift"
CHECK = ROOT / "vm" / "broker" / "check.sh"
README = ROOT / "vm" / "broker" / "README.md"
FLAG_PROBE = ROOT / "vm" / "broker" / "SecurityFlagValues.c"


class NativeBrokerTrustAdapterSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_source_gate_precedes_manifest_account_security_and_xpc_access(self) -> None:
        verifier = self.source.split("private func verifyConnectedPeer", 1)[1].split(
            "private func selfCheck", 1
        )[0]
        self.assertLess(
            verifier.index("guard nativeBrokerTrustAdapterEnabled else"),
            verifier.index("acquireRootOwnedManifestDescriptor"),
        )
        self.assertIn("nativeBrokerTrustAdapterEnabled = false", self.source)
        self.assertIn("SecCodeCreateWithXPCMessage", self.source)
        self.assertNotIn("xpc_connection_create_mach_service", self.source)
        self.assertNotIn("xpc_main(", self.source)
        self.assertNotIn("launchctl", self.source)
        self.assertNotIn("JSONSerialization", self.source)
        self.assertNotIn("JSONDecoder", self.source)

    def test_identity_contract_rejects_pid_path_and_unpinned_values(self) -> None:
        self.assertNotIn("xpc_connection_get_pid", self.source)
        self.assertNotIn("proc_pidpath", self.source)
        self.assertIn("SecRequirementCopyData", self.source)
        self.assertIn("SecRequirementCreateWithData", self.source)
        self.assertIn("kSecCodeInfoTeamIdentifier", self.source)
        self.assertIn("kSecCodeInfoIdentifier", self.source)
        self.assertIn("kSecCodeInfoCdHashes", self.source)
        self.assertIn("kSecCodeInfoCertificates", self.source)
        self.assertIn("kSecCodeInfoEntitlementsDict", self.source)
        self.assertIn("getTaskAllowEntitlement", self.source)
        self.assertIn("debuggerEntitlement", self.source)

    def test_entitlement_map_and_every_observed_cdhash_must_be_exact(self) -> None:
        self.assertIn("let exactEntitlements: [String: Bool]", self.source)
        self.assertIn(
            "Set(entitlements?.keys ?? Dictionary<String, Any>().keys) == expectedEntitlementKeys",
            self.source,
        )
        self.assertIn("for (name, value) in expected.exactEntitlements", self.source)
        self.assertIn("!expected.allowedCDHashes.isEmpty && hashes?.isEmpty == false", self.source)
        self.assertIn(
            "hashes?.allSatisfy({ expected.allowedCDHashes.contains($0) }) == true",
            self.source,
        )
        self.assertNotIn("hashes?.contains(where:", self.source)

    def test_manifest_contract_is_descriptor_relative_and_fixed(self) -> None:
        self.assertIn(
            "openat(directory, manifestFilename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)",
            self.source,
        )
        self.assertIn("before == after && ancestorsBefore == ancestorsAfter", self.source)
        self.assertIn("value.st_uid == 0", self.source)
        system_policy = self.source.split("private func requireStableRootOwnedSystemDirectory", 1)[
            1
        ].split("private func requireImmutableInstallDirectory", 1)[0]
        install_policy = self.source.split("private func requireImmutableInstallDirectory", 1)[
            1
        ].split("private func validateAncestorDescriptors", 1)[0]
        self.assertIn("(value.st_mode & 0o022) == 0", system_policy)
        self.assertNotIn("UF_IMMUTABLE", system_policy)
        self.assertIn("(value.st_mode & 0o222) == 0", install_policy)
        self.assertIn("value.st_flags & UInt32(UF_IMMUTABLE | SF_IMMUTABLE)", install_policy)
        self.assertIn('stableSystemAncestorComponents = ["private", "var", "db"]', self.source)
        self.assertIn('immutableInstallSubtreeComponents = ["leftovers", "strict-vm"]', self.source)
        self.assertIn("validateAncestorDescriptors(directories)", self.source)
        self.assertIn("(beforeStat.st_mode & 0o7777) == 0o444", self.source)
        self.assertIn("beforeStat.st_nlink == 1", self.source)

    def test_acl_iteration_accepts_only_exact_empty_and_rejects_errors(self) -> None:
        acl_policy = self.source.split("private func requireNoExtendedACL", 1)[1].split(
            "private func closeAllChecked", 1
        )[0]
        self.assertIn("let entryResult = acl_get_entry", acl_policy)
        self.assertIn("switch entryResult", acl_policy)
        self.assertIn("case 0:\n        return", acl_policy)
        self.assertIn("case 1:", acl_policy)
        self.assertIn("default:", acl_policy)
        self.assertIn("could not enumerate extended ACL", acl_policy)
        self.assertNotIn("if acl_get_entry", acl_policy)

    def test_descriptor_close_is_explicit_poisoned_and_fail_closed(self) -> None:
        owner = self.source.split("private final class OwnedDescriptor", 1)[1].split(
            "private final class ManifestDescriptor", 1
        )[0]
        checked_close = owner.split("func closeChecked", 1)[1].split("deinit", 1)[0]
        self.assertLess(
            checked_close.index("self.descriptor = nil"),
            checked_close.index("Darwin.close(descriptor)"),
        )
        self.assertIn("throw TrustAdapterError.descriptorCloseFailed", checked_close)
        self.assertEqual(owner.count("_ = Darwin.close(descriptor)"), 1)

        close_all = self.source.split("private func closeAllChecked", 1)[1].split(
            "private func closeAcquisitionDescriptors", 1
        )[0]
        self.assertLess(
            close_all.index("descriptors.removeAll(keepingCapacity: false)"),
            close_all.index("for descriptor in closing.reversed()"),
        )
        self.assertIn("if firstError == nil { firstError = error }", close_all)
        self.assertNotIn("defer { directories.forEach", self.source)
        self.assertNotIn("_ = close(manifest)", self.source)

        manifest_scope = self.source.split("private final class ManifestDescriptor", 1)[1].split(
            "private struct ExactCodeIdentity", 1
        )[0]
        self.assertIn("func withOpenDescriptor", manifest_scope)
        self.assertIn("try ownedDescriptor.closeChecked()", manifest_scope)
        verifier = self.source.split("private func verifyConnectedPeer", 1)[1].split(
            "private func selfCheck", 1
        )[0]
        self.assertIn("try descriptor.withOpenDescriptor", verifier)

    def test_fixed_system_launchdaemon_constants_and_account_contract(self) -> None:
        self.assertIn('systemLaunchDaemonDomain = "system"', self.source)
        self.assertIn('brokerMachService = "ai.luxenai.leftovers.strict-vm-broker"', self.source)
        self.assertIn(
            'brokerLaunchDaemonName = "ai.luxenai.leftovers.strict-vm-broker.plist"',
            self.source,
        )
        self.assertIn('brokerNonLoginShell = "/usr/bin/false"', self.source)
        self.assertIn('home == "/var/empty"', self.source)
        self.assertIn("getgrouplist", self.source)

    def test_readme_records_official_sdk_boundary_and_missing_api(self) -> None:
        text = README.read_text(encoding="utf-8")
        self.assertIn("SecCodeCreateWithXPCMessage", text)
        self.assertIn("xpc_connection_get_audit_token", text)
        self.assertIn("CS_DEBUGGED", text)

    def test_security_flag_values_are_pinned_to_sdk_declarations(self) -> None:
        probe = FLAG_PROBE.read_text(encoding="utf-8")
        for symbol in (
            "kSecCSDefaultFlags",
            "kSecCSCheckAllArchitectures",
            "kSecCSStrictValidate",
            "kSecCSNoNetworkAccess",
            "kSecCSSigningInformation",
            "kSecCSRequirementInformation",
        ):
            self.assertIn(f"_Static_assert({symbol}", probe)
        check = CHECK.read_text(encoding="utf-8")
        self.assertIn('"$HERE/SecurityFlagValues.c"', check)
        self.assertIn(
            "strictOfflineSecCSFlags = SecCSFlags(rawValue: (1 << 0) | (1 << 4) | (1 << 29))",
            self.source,
        )
        self.assertIn("let flags = SecCSFlags(rawValue: (1 << 1) | (1 << 2))", self.source)


@unittest.skipUnless(
    sys.platform == "darwin" and platform.machine() == "arm64",
    "native broker adapter check is macOS/Apple-silicon only",
)
class NativeBrokerTrustAdapterCheckTests(unittest.TestCase):
    def test_compile_and_rejection_only_self_check(self) -> None:
        result = subprocess.run(
            ["sh", str(CHECK)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("rejection-only self-check passed", result.stdout)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
