from __future__ import annotations

import copy
import hashlib
import unittest

from leftovers.strict_vm_broker import BROKER_PROTOCOL_VERSION, ImmutableBootIdentity
from leftovers.strict_vm_broker_installation import (
    DEBUG_ENTITLEMENT,
    GET_TASK_ALLOW_ENTITLEMENT,
    SYSTEM_LAUNCHD_DOMAIN,
    XPC_AUDIT_TOKEN_SOURCE,
    BootArtifactLayout,
    BrokerInstallationManifest,
    BrokerInstallationPolicyError,
    BrokerInstallationUnavailable,
    BrokerSelfCodeEvidence,
    DedicatedBrokerAccountEvidence,
    DescriptorSnapshot,
    EntitlementValue,
    ImmutableAncestorEvidence,
    ManifestDescriptorEvidence,
    RootOwnedManifestMetadata,
    XPCPeerEvidence,
    static_system_launchdaemon_plist_fixture,
    validate_broker_self_code_evidence,
    validate_dedicated_broker_account_evidence,
    validate_root_owned_manifest,
    validate_system_launchdaemon_plist_policy,
    validate_xpc_peer_evidence,
    verify_installed_xpc_peer,
)
from leftovers.strict_vm_broker_service import FixedBrokerResourcePolicy


class _PathOnlyPeer:
    pid = 42
    path = "/Applications/Leftovers.app"


class _NeverAccessAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def load_root_owned_manifest(
        self,
    ) -> tuple[BrokerInstallationManifest, RootOwnedManifestMetadata]:
        self.calls += 1
        raise AssertionError("source-disabled verifier accessed native install data")

    def collect_xpc_peer_evidence(self, connection: object) -> XPCPeerEvidence:
        del connection
        self.calls += 1
        raise AssertionError("source-disabled verifier accessed native XPC data")


class StrictVMBrokerInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker_requirement = b"designated requirement: broker v1"
        self.controller_requirement = b"designated requirement: controller v1"
        self.manifest = BrokerInstallationManifest(
            broker_uid=311,
            broker_gid=311,
            controller_uid=501,
            broker_account="leftovers-broker",
            broker_group="leftovers-broker",
            controller_account="leftovers-controller",
            team_identifier="ABCDE12345",
            broker_signing_identifier="ai.luxenai.leftovers.strict-vm-broker",
            controller_signing_identifier="ai.luxenai.leftovers.controller",
            broker_requirement=self.broker_requirement,
            broker_requirement_sha256=hashlib.sha256(self.broker_requirement).hexdigest(),
            controller_requirement=self.controller_requirement,
            controller_requirement_sha256=hashlib.sha256(self.controller_requirement).hexdigest(),
            allowed_broker_cdhashes=("d" * 40,),
            allowed_controller_cdhashes=("a" * 40, "b" * 40),
            required_client_entitlement="ai.luxenai.leftovers.strict-vm-client",
            boot_identity=ImmutableBootIdentity(*(["c" * 64] * 5)),
            boot_artifact_layout=BootArtifactLayout(),
            resource_profile=FixedBrokerResourcePolicy(),
            protocol_version=BROKER_PROTOCOL_VERSION,
        )

    def _evidence(self, **changes: object) -> XPCPeerEvidence:
        values: dict[str, object] = {
            "source": XPC_AUDIT_TOKEN_SOURCE,
            "audit_token": b"a" * 32,
            "audit_token_uid": self.manifest.controller_uid,
            "audit_token_pid": 123,
            "team_identifier": self.manifest.team_identifier,
            "signing_identifier": self.manifest.controller_signing_identifier,
            "designated_requirement": self.controller_requirement,
            "designated_requirement_sha256": self.manifest.controller_requirement_sha256,
            "cdhash": "a" * 40,
            "client_entitlements": (
                EntitlementValue(self.manifest.required_client_entitlement, True),
            ),
            "is_ad_hoc_signed": False,
            "is_debugged": False,
        }
        values.update(changes)
        return XPCPeerEvidence(**values)

    def _manifest_metadata(self, **changes: object) -> RootOwnedManifestMetadata:
        snapshot = DescriptorSnapshot(1, 2, len(self.manifest.canonical_bytes), 3, 4)
        ancestor = ImmutableAncestorEvidence(1, 3, 0, 0o555, True, True, True, False, True)
        values: dict[str, object] = {
            "opened_nofollow": True,
            "is_regular_file": True,
            "owner_uid": 0,
            "mode": 0o444,
            "nlink": 1,
            "is_local_volume": True,
            "has_nontrivial_write_acl": False,
            "before": snapshot,
            "after": snapshot,
            "ancestors_before": (ancestor,),
            "ancestors_after": (ancestor,),
        }
        values.update(changes)
        return RootOwnedManifestMetadata(ManifestDescriptorEvidence(**values), self.manifest.sha256)

    def _broker_self_evidence(self, **changes: object) -> BrokerSelfCodeEvidence:
        values: dict[str, object] = {
            "team_identifier": self.manifest.team_identifier,
            "signing_identifier": self.manifest.broker_signing_identifier,
            "designated_requirement": self.broker_requirement,
            "designated_requirement_sha256": self.manifest.broker_requirement_sha256,
            "cdhash": "d" * 40,
            "is_ad_hoc_signed": False,
            "is_debugged": False,
        }
        values.update(changes)
        return BrokerSelfCodeEvidence(**values)

    def _broker_account_evidence(self, **changes: object) -> DedicatedBrokerAccountEvidence:
        values: dict[str, object] = {
            "uid": self.manifest.broker_uid,
            "gid": self.manifest.broker_gid,
            "account": self.manifest.broker_account,
            "group": self.manifest.broker_group,
            "login_shell": "/usr/bin/false",
            "has_no_home_directory": True,
            "supplemental_gids": (),
        }
        values.update(changes)
        return DedicatedBrokerAccountEvidence(**values)

    def test_canonical_manifest_round_trip_and_root_owned_binding(self) -> None:
        parsed = BrokerInstallationManifest.from_mapping(self.manifest.to_mapping())
        self.assertEqual(parsed, self.manifest)
        self.assertEqual(parsed.canonical_bytes, self.manifest.canonical_bytes)
        validate_root_owned_manifest(
            self.manifest,
            self._manifest_metadata(),
        )
        with self.assertRaises(BrokerInstallationPolicyError):
            validate_root_owned_manifest(
                self.manifest,
                RootOwnedManifestMetadata(self._manifest_metadata().descriptor, "0" * 64),
            )

    def test_manifest_rejects_unknown_and_noncanonical_identity_fields(self) -> None:
        malformed = copy.deepcopy(self.manifest.to_mapping())
        malformed["unexpected"] = True
        with self.assertRaises(BrokerInstallationPolicyError):
            BrokerInstallationManifest.from_mapping(malformed)
        malformed = self.manifest.to_mapping()
        malformed["manifest_owner_uid"] = 501
        with self.assertRaises(BrokerInstallationPolicyError):
            BrokerInstallationManifest.from_mapping(malformed)
        malformed = self.manifest.to_mapping()
        malformed["allowed_controller_cdhashes"] = ["b" * 40, "a" * 40]
        with self.assertRaises(BrokerInstallationPolicyError):
            BrokerInstallationManifest.from_mapping(malformed)
        malformed = self.manifest.to_mapping()
        malformed["boot_artifact_layout"]["launcher"] = "/tmp/launcher"
        with self.assertRaises(BrokerInstallationPolicyError):
            BrokerInstallationManifest.from_mapping(malformed)
        malformed = self.manifest.to_mapping()
        malformed["broker_executable_name"] = "/tmp/broker"
        with self.assertRaises(BrokerInstallationPolicyError):
            BrokerInstallationManifest.from_mapping(malformed)

    def test_xpc_peer_requires_exact_audit_token_bound_identity(self) -> None:
        validate_xpc_peer_evidence(self.manifest, self._evidence())
        with self.assertRaises(BrokerInstallationPolicyError):
            validate_xpc_peer_evidence(self.manifest, _PathOnlyPeer())  # type: ignore[arg-type]
        for change in (
            {"audit_token_uid": 502},
            {"team_identifier": "ZZZZZ99999"},
            {"signing_identifier": "ai.luxenai.other"},
            {
                "designated_requirement": b"different requirement",
                "designated_requirement_sha256": hashlib.sha256(
                    b"different requirement"
                ).hexdigest(),
            },
            {"cdhash": "c" * 40},
            {"client_entitlements": ()},
            {
                "client_entitlements": (
                    EntitlementValue(self.manifest.required_client_entitlement, True),
                    EntitlementValue(GET_TASK_ALLOW_ENTITLEMENT, True),
                )
            },
            {
                "client_entitlements": (
                    EntitlementValue(self.manifest.required_client_entitlement, True),
                    EntitlementValue(DEBUG_ENTITLEMENT, True),
                )
            },
            {"is_ad_hoc_signed": True},
            {"is_debugged": True},
        ):
            with self.subTest(change=change), self.assertRaises(BrokerInstallationPolicyError):
                validate_xpc_peer_evidence(self.manifest, self._evidence(**change))

    def test_manifest_descriptor_requires_stable_nofollow_regular_file_and_immutable_tree(
        self,
    ) -> None:
        for changes in (
            {"opened_nofollow": False},
            {"is_regular_file": False},
            {"mode": 0o644},
            {"nlink": 2},
            {"is_local_volume": False},
            {"has_nontrivial_write_acl": True},
            {"after": DescriptorSnapshot(1, 2, len(self.manifest.canonical_bytes) + 1, 3, 4)},
        ):
            with self.subTest(changes=changes), self.assertRaises(BrokerInstallationPolicyError):
                self._manifest_metadata(**changes)
        with self.assertRaises(BrokerInstallationPolicyError):
            ImmutableAncestorEvidence(1, 3, 0, 0o555, True, True, True, False, False)

    def test_broker_self_signing_and_dedicated_runtime_account_are_exact(self) -> None:
        validate_broker_self_code_evidence(self.manifest, self._broker_self_evidence())
        validate_dedicated_broker_account_evidence(self.manifest, self._broker_account_evidence())
        for changes in (
            {"cdhash": "e" * 40},
            {"is_ad_hoc_signed": True},
            {"is_debugged": True},
        ):
            with (
                self.subTest(self_changes=changes),
                self.assertRaises(BrokerInstallationPolicyError),
            ):
                validate_broker_self_code_evidence(
                    self.manifest, self._broker_self_evidence(**changes)
                )
        for changes in (
            {"uid": 312},
            {"gid": 312},
            {"login_shell": "/bin/zsh"},
            {"has_no_home_directory": False},
            {"supplemental_gids": (20,)},
        ):
            with (
                self.subTest(account_changes=changes),
                self.assertRaises(BrokerInstallationPolicyError),
            ):
                validate_dedicated_broker_account_evidence(
                    self.manifest, self._broker_account_evidence(**changes)
                )

    def test_launchdaemon_policy_is_system_only_exact_and_has_no_ambiguous_fields(self) -> None:
        fixture = static_system_launchdaemon_plist_fixture(self.manifest)
        validate_system_launchdaemon_plist_policy(SYSTEM_LAUNCHD_DOMAIN, fixture, self.manifest)
        for domain, edit in (
            ("user/501", {}),
            (SYSTEM_LAUNCHD_DOMAIN, {"Umask": 0o022}),
            (SYSTEM_LAUNCHD_DOMAIN, {"UserName": "root"}),
            (SYSTEM_LAUNCHD_DOMAIN, {"ProgramArguments": ["/bin/sh", "-c", "id"]}),
            (SYSTEM_LAUNCHD_DOMAIN, {"EnvironmentVariables": {"PATH": "/tmp"}}),
            (SYSTEM_LAUNCHD_DOMAIN, {"Sockets": {"unreviewed": True}}),
            (SYSTEM_LAUNCHD_DOMAIN, {"KeepAlive": True}),
        ):
            unsafe = copy.deepcopy(fixture)
            unsafe.update(edit)
            with (
                self.subTest(domain=domain, edit=edit),
                self.assertRaises(BrokerInstallationPolicyError),
            ):
                validate_system_launchdaemon_plist_policy(domain, unsafe, self.manifest)

    def test_public_native_verifier_fails_before_adapter_or_path_access(self) -> None:
        adapter = _NeverAccessAdapter()
        with self.assertRaises(BrokerInstallationUnavailable):
            verify_installed_xpc_peer(adapter, object())
        self.assertEqual(adapter.calls, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
