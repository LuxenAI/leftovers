"""Source-disabled contracts for a future macOS strict-VM broker install.

This module neither writes a plist nor reads an installed path.  Its manifest,
peer, and launchd-policy values are deliberately pure data so a later native,
privileged implementation has a small, reviewable acceptance contract.  The
public native-verification entry point is source-disabled before it can consult
an adapter, a path, a socket, or a process.

Nothing returned by the pure validators is launch or broker authority.  Python
callers can construct every value in this module; only a separately reviewed
native adapter, root-owned installation, and live evidence could eventually
make the same checks meaningful.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .strict_vm_broker import BROKER_PROTOCOL_VERSION, ImmutableBootIdentity
from .strict_vm_broker_service import FixedBrokerResourcePolicy

# A plist, configuration file, fixture, or caller cannot enable this gate.
STRICT_VM_BROKER_INSTALLATION_ENABLED = False
STRICT_VM_BROKER_NATIVE_TRUST_ADAPTER_VERIFIED = False

INSTALLATION_MANIFEST_SCHEMA_VERSION = 1
XPC_AUDIT_TOKEN_SOURCE = "xpc-audit-token-security-framework-v1"
SYSTEM_LAUNCHD_DOMAIN = "system"
STRICT_VM_BROKER_LABEL = "ai.luxenai.leftovers.strict-vm-broker"
STRICT_VM_BROKER_MACH_SERVICE = "ai.luxenai.leftovers.strict-vm-broker"
STRICT_VM_BROKER_EXECUTABLE_NAME = "leftovers-strict-vm-broker"
STRICT_VM_BROKER_PLIST_NAME = "ai.luxenai.leftovers.strict-vm-broker.plist"
STRICT_VM_BROKER_PROGRAM_ARGUMENTS = (
    f"/Library/PrivilegedHelperTools/{STRICT_VM_BROKER_EXECUTABLE_NAME}",
    "--serve",
)
DEDICATED_BROKER_NONLOGIN_SHELL = "/usr/bin/false"
GET_TASK_ALLOW_ENTITLEMENT = "com.apple.security.get-task-allow"
DEBUG_ENTITLEMENT = "com.apple.security.cs.debugger"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ACCOUNT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_SIGNING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z")
_ENTITLEMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{2,127}\Z")
_MANIFEST_KEYS = frozenset(
    {
        "allowed_controller_cdhashes",
        "allowed_broker_cdhashes",
        "boot_artifact_layout",
        "boot_identity",
        "broker_account",
        "broker_group",
        "broker_requirement_b64",
        "broker_requirement_sha256",
        "broker_executable_name",
        "broker_signing_identifier",
        "broker_uid",
        "broker_gid",
        "controller_account",
        "controller_requirement_b64",
        "controller_requirement_sha256",
        "controller_signing_identifier",
        "controller_uid",
        "manifest_mode",
        "manifest_owner_uid",
        "mach_service_name",
        "launchdaemon_plist_name",
        "protocol_version",
        "required_client_entitlement",
        "resource_profile",
        "schema_version",
        "team_identifier",
    }
)
_BOOT_LAYOUT_KEYS = frozenset({"guest_policy", "initrd", "kernel", "launcher", "root_disk"})
_BOOT_IDENTITY_KEYS = frozenset(
    {
        "guest_policy_sha256",
        "initrd_sha256",
        "kernel_sha256",
        "launcher_sha256",
        "launcher_version",
        "root_disk_sha256",
    }
)
_RESOURCE_KEYS = frozenset(
    {
        "memory_bytes",
        "request_bytes",
        "scratch_bytes",
        "virtual_cpus",
        "wall_clock_seconds",
    }
)
_LAUNCHD_KEYS = frozenset(
    {"Label", "MachServices", "ProcessType", "ProgramArguments", "Umask", "UserName", "GroupName"}
)
_FIXED_BOOT_ARTIFACT_LAYOUT = {
    "launcher": "strict-vm-launcher",
    "kernel": "vmlinuz",
    "initrd": "initramfs.cpio.gz",
    "root_disk": "rootfs.img",
    "guest_policy": "guest-policy.json",
}


class BrokerInstallationPolicyError(RuntimeError):
    """A future broker install, peer, or launchd policy is not exact enough."""


class BrokerInstallationUnavailable(BrokerInstallationPolicyError):
    """The native installation verifier remains deliberately source-disabled."""


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise BrokerInstallationPolicyError(f"{label} must be lowercase SHA-256")
    return value


def _account(value: object, label: str) -> str:
    if (
        type(value) is not str
        or _ACCOUNT.fullmatch(value) is None
        or value in {"root", "wheel", "staff"}
    ):
        raise BrokerInstallationPolicyError(f"{label} is not a dedicated account identity")
    return value


def _canonical_json(value: dict[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "ascii"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BrokerInstallationPolicyError(
            "installation manifest cannot be canonicalized"
        ) from exc


def _require_requirement(value: object, digest: object, label: str) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= 64 * 1024:
        raise BrokerInstallationPolicyError(f"{label} requirement bytes are invalid")
    if hashlib.sha256(value).hexdigest() != _hex64(digest, f"{label} requirement digest"):
        raise BrokerInstallationPolicyError(f"{label} requirement digest does not bind its bytes")
    return value


@dataclass(frozen=True)
class BootArtifactLayout:
    """Fixed relative artifact names, bound to roles rather than caller paths."""

    launcher: str = _FIXED_BOOT_ARTIFACT_LAYOUT["launcher"]
    kernel: str = _FIXED_BOOT_ARTIFACT_LAYOUT["kernel"]
    initrd: str = _FIXED_BOOT_ARTIFACT_LAYOUT["initrd"]
    root_disk: str = _FIXED_BOOT_ARTIFACT_LAYOUT["root_disk"]
    guest_policy: str = _FIXED_BOOT_ARTIFACT_LAYOUT["guest_policy"]

    def __post_init__(self) -> None:
        mapping = self.to_mapping()
        if mapping != _FIXED_BOOT_ARTIFACT_LAYOUT:
            raise BrokerInstallationPolicyError(
                "boot artifact roles or relative names are not fixed"
            )
        if any("/" in value or value in {"", ".", ".."} for value in mapping.values()):
            raise BrokerInstallationPolicyError(
                "boot artifact names must be fixed relative basenames"
            )

    def to_mapping(self) -> dict[str, str]:
        return {
            "launcher": self.launcher,
            "kernel": self.kernel,
            "initrd": self.initrd,
            "root_disk": self.root_disk,
            "guest_policy": self.guest_policy,
        }


@dataclass(frozen=True)
class BrokerInstallationManifest:
    """Canonical root-owned policy data; never a controller-supplied capability."""

    broker_uid: int
    broker_gid: int
    controller_uid: int
    broker_account: str
    broker_group: str
    controller_account: str
    team_identifier: str
    broker_signing_identifier: str
    controller_signing_identifier: str
    broker_requirement: bytes
    broker_requirement_sha256: str
    controller_requirement: bytes
    controller_requirement_sha256: str
    allowed_broker_cdhashes: tuple[str, ...]
    allowed_controller_cdhashes: tuple[str, ...]
    required_client_entitlement: str
    boot_identity: ImmutableBootIdentity
    boot_artifact_layout: BootArtifactLayout
    resource_profile: FixedBrokerResourcePolicy
    broker_executable_name: str = STRICT_VM_BROKER_EXECUTABLE_NAME
    launchdaemon_plist_name: str = STRICT_VM_BROKER_PLIST_NAME
    mach_service_name: str = STRICT_VM_BROKER_MACH_SERVICE
    manifest_owner_uid: int = 0
    manifest_mode: int = 0o444
    schema_version: int = INSTALLATION_MANIFEST_SCHEMA_VERSION
    protocol_version: int = BROKER_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.broker_uid) is not int
            or type(self.broker_gid) is not int
            or type(self.controller_uid) is not int
            or self.broker_uid <= 0
            or self.broker_gid <= 0
            or self.controller_uid <= 0
            or self.broker_uid == self.controller_uid
            or self.manifest_owner_uid != 0
            or self.manifest_mode != 0o444
            or self.schema_version != INSTALLATION_MANIFEST_SCHEMA_VERSION
            or self.protocol_version != BROKER_PROTOCOL_VERSION
        ):
            raise BrokerInstallationPolicyError(
                "installation manifest identity or version is invalid"
            )
        _account(self.broker_account, "broker account")
        _account(self.broker_group, "broker group")
        _account(self.controller_account, "controller account")
        if self.broker_account == self.controller_account:
            raise BrokerInstallationPolicyError("broker and controller accounts must be distinct")
        if (
            type(self.team_identifier) is not str
            or not re.fullmatch(r"[A-Z0-9]{10}", self.team_identifier)
            or type(self.broker_signing_identifier) is not str
            or _SIGNING_ID.fullmatch(self.broker_signing_identifier) is None
            or type(self.controller_signing_identifier) is not str
            or _SIGNING_ID.fullmatch(self.controller_signing_identifier) is None
            or type(self.required_client_entitlement) is not str
            or _ENTITLEMENT.fullmatch(self.required_client_entitlement) is None
        ):
            raise BrokerInstallationPolicyError("installation code-signing identity is invalid")
        _require_requirement(self.broker_requirement, self.broker_requirement_sha256, "broker")
        _require_requirement(
            self.controller_requirement, self.controller_requirement_sha256, "controller"
        )
        if (
            type(self.allowed_broker_cdhashes) is not tuple
            or not self.allowed_broker_cdhashes
            or tuple(sorted(set(self.allowed_broker_cdhashes))) != self.allowed_broker_cdhashes
            or any(_HEX40.fullmatch(value) is None for value in self.allowed_broker_cdhashes)
            or type(self.allowed_controller_cdhashes) is not tuple
            or not self.allowed_controller_cdhashes
            or tuple(sorted(set(self.allowed_controller_cdhashes)))
            != self.allowed_controller_cdhashes
            or any(_HEX40.fullmatch(value) is None for value in self.allowed_controller_cdhashes)
            or type(self.boot_identity) is not ImmutableBootIdentity
            or type(self.boot_artifact_layout) is not BootArtifactLayout
            or type(self.resource_profile) is not FixedBrokerResourcePolicy
            or self.broker_executable_name != STRICT_VM_BROKER_EXECUTABLE_NAME
            or self.launchdaemon_plist_name != STRICT_VM_BROKER_PLIST_NAME
            or self.mach_service_name != STRICT_VM_BROKER_MACH_SERVICE
        ):
            raise BrokerInstallationPolicyError("installation immutable identity is invalid")

    def to_mapping(self) -> dict[str, object]:
        """Return the only canonical, serializable representation of this policy."""

        return {
            "allowed_broker_cdhashes": list(self.allowed_broker_cdhashes),
            "allowed_controller_cdhashes": list(self.allowed_controller_cdhashes),
            "boot_artifact_layout": self.boot_artifact_layout.to_mapping(),
            "boot_identity": {
                "guest_policy_sha256": self.boot_identity.guest_policy_sha256,
                "initrd_sha256": self.boot_identity.initrd_sha256,
                "kernel_sha256": self.boot_identity.kernel_sha256,
                "launcher_sha256": self.boot_identity.launcher_sha256,
                "launcher_version": self.boot_identity.launcher_version,
                "root_disk_sha256": self.boot_identity.root_disk_sha256,
            },
            "broker_account": self.broker_account,
            "broker_executable_name": self.broker_executable_name,
            "broker_group": self.broker_group,
            "broker_requirement_b64": base64.b64encode(self.broker_requirement).decode("ascii"),
            "broker_requirement_sha256": self.broker_requirement_sha256,
            "broker_signing_identifier": self.broker_signing_identifier,
            "broker_uid": self.broker_uid,
            "broker_gid": self.broker_gid,
            "controller_account": self.controller_account,
            "controller_requirement_b64": base64.b64encode(self.controller_requirement).decode(
                "ascii"
            ),
            "controller_requirement_sha256": self.controller_requirement_sha256,
            "controller_signing_identifier": self.controller_signing_identifier,
            "controller_uid": self.controller_uid,
            "launchdaemon_plist_name": self.launchdaemon_plist_name,
            "mach_service_name": self.mach_service_name,
            "manifest_mode": self.manifest_mode,
            "manifest_owner_uid": self.manifest_owner_uid,
            "protocol_version": self.protocol_version,
            "required_client_entitlement": self.required_client_entitlement,
            "resource_profile": {
                "memory_bytes": self.resource_profile.memory_bytes,
                "request_bytes": self.resource_profile.request_bytes,
                "scratch_bytes": self.resource_profile.scratch_bytes,
                "virtual_cpus": self.resource_profile.virtual_cpus,
                "wall_clock_seconds": self.resource_profile.wall_clock_seconds,
            },
            "schema_version": self.schema_version,
            "team_identifier": self.team_identifier,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_mapping())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @classmethod
    def from_mapping(cls, value: object) -> BrokerInstallationManifest:
        """Parse an exact manifest mapping; unknown fields fail closed."""

        if type(value) is not dict or frozenset(value) != _MANIFEST_KEYS:
            raise BrokerInstallationPolicyError("installation manifest fields are not exact")
        boot = value["boot_identity"]
        boot_layout = value["boot_artifact_layout"]
        resource = value["resource_profile"]
        if type(boot) is not dict or frozenset(boot) != _BOOT_IDENTITY_KEYS:
            raise BrokerInstallationPolicyError("boot identity fields are not exact")
        if type(boot_layout) is not dict or frozenset(boot_layout) != _BOOT_LAYOUT_KEYS:
            raise BrokerInstallationPolicyError("boot artifact layout fields are not exact")
        if type(resource) is not dict or frozenset(resource) != _RESOURCE_KEYS:
            raise BrokerInstallationPolicyError("resource profile fields are not exact")
        try:
            broker_requirement = base64.b64decode(value["broker_requirement_b64"], validate=True)
            controller_requirement = base64.b64decode(
                value["controller_requirement_b64"], validate=True
            )
        except (TypeError, ValueError) as exc:
            raise BrokerInstallationPolicyError(
                "installation requirement encoding is invalid"
            ) from exc
        allowed_broker = value["allowed_broker_cdhashes"]
        allowed_controller = value["allowed_controller_cdhashes"]
        if (
            type(allowed_broker) is not list
            or type(allowed_controller) is not list
            or any(type(item) is not str for item in allowed_broker + allowed_controller)
        ):
            raise BrokerInstallationPolicyError("allowed controller CDHashes are invalid")
        return cls(
            broker_uid=value["broker_uid"],
            broker_gid=value["broker_gid"],
            controller_uid=value["controller_uid"],
            broker_account=value["broker_account"],
            broker_group=value["broker_group"],
            controller_account=value["controller_account"],
            team_identifier=value["team_identifier"],
            broker_signing_identifier=value["broker_signing_identifier"],
            controller_signing_identifier=value["controller_signing_identifier"],
            broker_requirement=broker_requirement,
            broker_requirement_sha256=value["broker_requirement_sha256"],
            controller_requirement=controller_requirement,
            controller_requirement_sha256=value["controller_requirement_sha256"],
            allowed_broker_cdhashes=tuple(allowed_broker),
            allowed_controller_cdhashes=tuple(allowed_controller),
            required_client_entitlement=value["required_client_entitlement"],
            boot_identity=ImmutableBootIdentity(**boot),
            boot_artifact_layout=BootArtifactLayout(**boot_layout),
            resource_profile=FixedBrokerResourcePolicy(**resource),
            broker_executable_name=value["broker_executable_name"],
            launchdaemon_plist_name=value["launchdaemon_plist_name"],
            mach_service_name=value["mach_service_name"],
            manifest_owner_uid=value["manifest_owner_uid"],
            manifest_mode=value["manifest_mode"],
            schema_version=value["schema_version"],
            protocol_version=value["protocol_version"],
        )


@dataclass(frozen=True)
class DescriptorSnapshot:
    """Stable descriptor identity observed immediately before and after a read."""

    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    def __post_init__(self) -> None:
        if (
            type(self.device) is not int
            or type(self.inode) is not int
            or type(self.size) is not int
            or type(self.mtime_ns) is not int
            or type(self.ctime_ns) is not int
            or self.device <= 0
            or self.inode <= 0
            or not 1 <= self.size <= 1024 * 1024
            or self.mtime_ns <= 0
            or self.ctime_ns <= 0
        ):
            raise BrokerInstallationPolicyError("manifest descriptor snapshot is invalid")


@dataclass(frozen=True)
class ImmutableAncestorEvidence:
    """One descriptor-derived directory fact in the root-to-parent chain."""

    device: int
    inode: int
    owner_uid: int
    mode: int
    is_directory: bool
    is_local_volume: bool
    opened_nofollow: bool
    has_nontrivial_write_acl: bool
    immutable: bool

    def __post_init__(self) -> None:
        if (
            type(self.device) is not int
            or type(self.inode) is not int
            or self.device <= 0
            or self.inode <= 0
            or self.owner_uid != 0
            or type(self.mode) is not int
            or self.mode & 0o222
            or self.is_directory is not True
            or self.is_local_volume is not True
            or self.opened_nofollow is not True
            or self.has_nontrivial_write_acl is not False
            or self.immutable is not True
        ):
            raise BrokerInstallationPolicyError(
                "manifest ancestor tree is not immutable and root-owned"
            )


@dataclass(frozen=True)
class ManifestDescriptorEvidence:
    """No-follow regular-file and immutable-ancestor evidence from native code."""

    opened_nofollow: bool
    is_regular_file: bool
    owner_uid: int
    mode: int
    nlink: int
    is_local_volume: bool
    has_nontrivial_write_acl: bool
    before: DescriptorSnapshot
    after: DescriptorSnapshot
    ancestors_before: tuple[ImmutableAncestorEvidence, ...]
    ancestors_after: tuple[ImmutableAncestorEvidence, ...]

    def __post_init__(self) -> None:
        if (
            self.opened_nofollow is not True
            or self.is_regular_file is not True
            or self.owner_uid != 0
            or self.mode != 0o444
            or self.nlink != 1
            or self.is_local_volume is not True
            or self.has_nontrivial_write_acl is not False
            or type(self.before) is not DescriptorSnapshot
            or type(self.after) is not DescriptorSnapshot
            or self.before != self.after
            or type(self.ancestors_before) is not tuple
            or not self.ancestors_before
            or self.ancestors_before != self.ancestors_after
            or any(type(item) is not ImmutableAncestorEvidence for item in self.ancestors_before)
        ):
            raise BrokerInstallationPolicyError(
                "manifest descriptor evidence is unsafe or unstable"
            )


@dataclass(frozen=True)
class RootOwnedManifestMetadata:
    """Facts a future adapter derives from an opened, revalidated install descriptor."""

    descriptor: ManifestDescriptorEvidence
    manifest_sha256: str

    def __post_init__(self) -> None:
        if type(self.descriptor) is not ManifestDescriptorEvidence:
            raise BrokerInstallationPolicyError("installed manifest descriptor evidence is invalid")
        _hex64(self.manifest_sha256, "installed manifest digest")


def validate_root_owned_manifest(
    manifest: BrokerInstallationManifest, metadata: RootOwnedManifestMetadata
) -> None:
    """Validate static manifest bytes against descriptor-derived metadata only."""

    if (
        type(manifest) is not BrokerInstallationManifest
        or type(metadata) is not RootOwnedManifestMetadata
    ):
        raise BrokerInstallationPolicyError("installation manifest evidence has an invalid type")
    if metadata.manifest_sha256 != manifest.sha256:
        raise BrokerInstallationPolicyError(
            "installed manifest digest does not bind canonical policy"
        )


@dataclass(frozen=True)
class EntitlementValue:
    """One boolean entitlement value reported by Security.framework."""

    name: str
    value: bool

    def __post_init__(self) -> None:
        if type(self.name) is not str or _ENTITLEMENT.fullmatch(self.name) is None:
            raise BrokerInstallationPolicyError("entitlement name is malformed")
        if type(self.value) is not bool:
            raise BrokerInstallationPolicyError("entitlement value must be boolean")


@dataclass(frozen=True)
class BrokerSelfCodeEvidence:
    """Broker signing facts obtained before a controller peer is inspected."""

    team_identifier: str
    signing_identifier: str
    designated_requirement: bytes
    designated_requirement_sha256: str
    cdhash: str
    is_ad_hoc_signed: bool
    is_debugged: bool

    def __post_init__(self) -> None:
        if (
            type(self.team_identifier) is not str
            or not re.fullmatch(r"[A-Z0-9]{10}", self.team_identifier)
            or type(self.signing_identifier) is not str
            or _SIGNING_ID.fullmatch(self.signing_identifier) is None
            or _HEX40.fullmatch(self.cdhash) is None
            or type(self.is_ad_hoc_signed) is not bool
            or type(self.is_debugged) is not bool
        ):
            raise BrokerInstallationPolicyError("broker self code-signing evidence is malformed")
        _require_requirement(
            self.designated_requirement,
            self.designated_requirement_sha256,
            "broker self designated",
        )


@dataclass(frozen=True)
class DedicatedBrokerAccountEvidence:
    """Directory-service facts; account spelling alone is never a trust signal."""

    uid: int
    gid: int
    account: str
    group: str
    login_shell: str
    has_no_home_directory: bool
    supplemental_gids: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self.uid) is not int
            or type(self.gid) is not int
            or self.uid <= 0
            or self.gid <= 0
            or _account(self.account, "broker runtime account") != self.account
            or _account(self.group, "broker runtime group") != self.group
            or self.login_shell != DEDICATED_BROKER_NONLOGIN_SHELL
            or self.has_no_home_directory is not True
            or type(self.supplemental_gids) is not tuple
            or self.supplemental_gids != ()
        ):
            raise BrokerInstallationPolicyError("broker dedicated-account evidence is invalid")


def validate_broker_self_code_evidence(
    manifest: BrokerInstallationManifest, evidence: BrokerSelfCodeEvidence
) -> None:
    """Validate broker self identity before collecting any client/XPC evidence."""

    if (
        type(manifest) is not BrokerInstallationManifest
        or type(evidence) is not BrokerSelfCodeEvidence
    ):
        raise BrokerInstallationPolicyError("broker self signing evidence has an invalid type")
    if (
        evidence.team_identifier != manifest.team_identifier
        or evidence.signing_identifier != manifest.broker_signing_identifier
        or evidence.designated_requirement != manifest.broker_requirement
        or evidence.designated_requirement_sha256 != manifest.broker_requirement_sha256
        or evidence.cdhash not in manifest.allowed_broker_cdhashes
        or evidence.is_ad_hoc_signed
        or evidence.is_debugged
    ):
        raise BrokerInstallationPolicyError(
            "broker self does not exactly match installed trust policy"
        )


def validate_dedicated_broker_account_evidence(
    manifest: BrokerInstallationManifest, evidence: DedicatedBrokerAccountEvidence
) -> None:
    """Validate runtime UID/GID and non-login/no-home/no-groups constraints."""

    if (
        type(manifest) is not BrokerInstallationManifest
        or type(evidence) is not DedicatedBrokerAccountEvidence
    ):
        raise BrokerInstallationPolicyError("broker account evidence has an invalid type")
    if (
        evidence.uid != manifest.broker_uid
        or evidence.gid != manifest.broker_gid
        or evidence.account != manifest.broker_account
        or evidence.group != manifest.broker_group
    ):
        raise BrokerInstallationPolicyError(
            "broker runtime account does not match installation policy"
        )


@dataclass(frozen=True)
class XPCPeerEvidence:
    """Security.framework facts derived from an XPC audit token by native code.

    A PID, executable path, uid, or a caller-provided digest alone is never
    this type of evidence.  The pure form is test data only until a native
    adapter collects it from the connected XPC peer.
    """

    source: str
    audit_token: bytes
    audit_token_uid: int
    audit_token_pid: int
    team_identifier: str
    signing_identifier: str
    designated_requirement: bytes
    designated_requirement_sha256: str
    cdhash: str
    client_entitlements: tuple[EntitlementValue, ...]
    is_ad_hoc_signed: bool
    is_debugged: bool

    def __post_init__(self) -> None:
        entitlement_names = (
            tuple(item.name for item in self.client_entitlements)
            if type(self.client_entitlements) is tuple
            and all(type(item) is EntitlementValue for item in self.client_entitlements)
            else ()
        )
        if (
            self.source != XPC_AUDIT_TOKEN_SOURCE
            or type(self.audit_token) is not bytes
            or len(self.audit_token) != 32
            or type(self.audit_token_uid) is not int
            or self.audit_token_uid <= 0
            or type(self.audit_token_pid) is not int
            or self.audit_token_pid <= 0
            or type(self.team_identifier) is not str
            or not re.fullmatch(r"[A-Z0-9]{10}", self.team_identifier)
            or type(self.signing_identifier) is not str
            or _SIGNING_ID.fullmatch(self.signing_identifier) is None
            or _HEX40.fullmatch(self.cdhash) is None
            or type(self.client_entitlements) is not tuple
            or any(type(item) is not EntitlementValue for item in self.client_entitlements)
            or entitlement_names != tuple(sorted(set(entitlement_names)))
            or type(self.is_ad_hoc_signed) is not bool
            or type(self.is_debugged) is not bool
        ):
            raise BrokerInstallationPolicyError("XPC audit-token evidence is malformed")
        _require_requirement(
            self.designated_requirement,
            self.designated_requirement_sha256,
            "XPC peer designated",
        )


def validate_xpc_peer_evidence(
    manifest: BrokerInstallationManifest, evidence: XPCPeerEvidence
) -> None:
    """Check exact static binding; success does not confer broker authority."""

    if type(manifest) is not BrokerInstallationManifest or type(evidence) is not XPCPeerEvidence:
        raise BrokerInstallationPolicyError("peer evidence must be audit-token/XPC-derived")
    if (
        evidence.audit_token_uid != manifest.controller_uid
        or evidence.team_identifier != manifest.team_identifier
        or evidence.signing_identifier != manifest.controller_signing_identifier
        or evidence.designated_requirement != manifest.controller_requirement
        or evidence.designated_requirement_sha256 != manifest.controller_requirement_sha256
        or evidence.cdhash not in manifest.allowed_controller_cdhashes
        or EntitlementValue(manifest.required_client_entitlement, True)
        not in evidence.client_entitlements
        or any(
            entitlement.name in {GET_TASK_ALLOW_ENTITLEMENT, DEBUG_ENTITLEMENT}
            for entitlement in evidence.client_entitlements
        )
        or evidence.is_ad_hoc_signed
        or evidence.is_debugged
    ):
        raise BrokerInstallationPolicyError(
            "XPC peer does not exactly match installed trust policy"
        )


def static_system_launchdaemon_plist_fixture(
    manifest: BrokerInstallationManifest,
) -> dict[str, object]:
    """Return an in-memory policy fixture only; never write or install it."""

    if type(manifest) is not BrokerInstallationManifest:
        raise BrokerInstallationPolicyError(
            "launchd fixture requires an exact installation manifest"
        )
    return {
        "Label": STRICT_VM_BROKER_LABEL,
        "MachServices": {manifest.mach_service_name: True},
        "ProcessType": "Background",
        "ProgramArguments": list(STRICT_VM_BROKER_PROGRAM_ARGUMENTS),
        "Umask": 0o077,
        "UserName": manifest.broker_account,
        "GroupName": manifest.broker_group,
    }


def validate_system_launchdaemon_plist_policy(
    domain: object, plist: object, manifest: BrokerInstallationManifest
) -> None:
    """Validate the exact static system-daemon plist shape without installing it."""

    if type(manifest) is not BrokerInstallationManifest:
        raise BrokerInstallationPolicyError(
            "launchd policy requires an exact installation manifest"
        )
    if (
        domain != SYSTEM_LAUNCHD_DOMAIN
        or type(plist) is not dict
        or frozenset(plist) != _LAUNCHD_KEYS
    ):
        raise BrokerInstallationPolicyError("launchd policy is not an exact system-domain daemon")
    if (
        plist["Label"] != STRICT_VM_BROKER_LABEL
        or plist["UserName"] != manifest.broker_account
        or plist["GroupName"] != manifest.broker_group
        or plist["Umask"] != 0o077
        or plist["ProcessType"] != "Background"
        or type(plist["ProgramArguments"]) is not list
        or tuple(plist["ProgramArguments"]) != STRICT_VM_BROKER_PROGRAM_ARGUMENTS
        or type(plist["MachServices"]) is not dict
        or plist["MachServices"] != {manifest.mach_service_name: True}
    ):
        raise BrokerInstallationPolicyError("launchd policy weakens the dedicated broker contract")


class NativeBrokerTrustAdapter(Protocol):
    """Future privileged adapter; it must use descriptors and audit tokens, not paths/PIDs."""

    def load_root_owned_manifest(
        self,
    ) -> tuple[BrokerInstallationManifest, RootOwnedManifestMetadata]: ...

    def collect_dedicated_broker_account_evidence(self) -> DedicatedBrokerAccountEvidence: ...

    def collect_broker_self_code_evidence(self) -> BrokerSelfCodeEvidence: ...

    def collect_xpc_peer_evidence(self, connection: object) -> XPCPeerEvidence: ...


def _require_native_verifier_enabled() -> None:
    if not (
        STRICT_VM_BROKER_INSTALLATION_ENABLED and STRICT_VM_BROKER_NATIVE_TRUST_ADAPTER_VERIFIED
    ):
        raise BrokerInstallationUnavailable(
            "strict VM broker installation verifier is source-disabled"
        )


def verify_installed_xpc_peer(adapter: NativeBrokerTrustAdapter, connection: object) -> None:
    """Future live entry point; reject before any adapter, path, or XPC access today."""

    _require_native_verifier_enabled()
    manifest, metadata = adapter.load_root_owned_manifest()
    validate_root_owned_manifest(manifest, metadata)
    validate_dedicated_broker_account_evidence(
        manifest, adapter.collect_dedicated_broker_account_evidence()
    )
    validate_broker_self_code_evidence(manifest, adapter.collect_broker_self_code_evidence())
    validate_xpc_peer_evidence(manifest, adapter.collect_xpc_peer_evidence(connection))


def ensure_installation_activation_is_impossible() -> None:
    """Defensive import-time assertion for the non-authoritative scaffold."""

    if STRICT_VM_BROKER_INSTALLATION_ENABLED or STRICT_VM_BROKER_NATIVE_TRUST_ADAPTER_VERIFIED:
        raise BrokerInstallationPolicyError("strict VM broker installation gate was weakened")


ensure_installation_activation_is_impossible()
