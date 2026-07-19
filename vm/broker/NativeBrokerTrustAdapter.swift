// Native strict-VM broker trust adapter scaffold.
//
// This file is intentionally source-disabled.  It does not install a
// LaunchDaemon, create a listener, bind a Mach service, or accept a PID, path,
// or caller-provided digest as identity.  The only executable command is the
// rejection-only `--self-check` harness at the bottom of this file.

import Darwin
import Foundation
import Security
import XPC

private let nativeBrokerTrustAdapterEnabled = false
// `SecCSFlags` defaults to zero. The local SDK exposes the C enum values but
// not every spelling as a Swift global, so retain the documented bit values
// here: CheckAllArchitectures (1<<0), StrictValidate (1<<4), and
// NoNetworkAccess (1<<29).
private let defaultSecCSFlags = SecCSFlags(rawValue: 0)
private let strictOfflineSecCSFlags = SecCSFlags(rawValue: (1 << 0) | (1 << 4) | (1 << 29))

// These names are installation policy, not configuration.  A future reviewed
// installer must materialize the exact system-domain LaunchDaemon separately.
private let systemLaunchDaemonDomain = "system"
private let brokerLabel = "ai.luxenai.leftovers.strict-vm-broker"
private let brokerMachService = "ai.luxenai.leftovers.strict-vm-broker"
private let brokerExecutableName = "leftovers-strict-vm-broker"
private let brokerLaunchDaemonName = "ai.luxenai.leftovers.strict-vm-broker.plist"
private let brokerProgramArguments = [
    "/Library/PrivilegedHelperTools/leftovers-strict-vm-broker",
    "--serve",
]
// The ordinary macOS system ancestors are root-controlled but are not required
// to carry immutable flags.  Only the dedicated installation subtree is both
// non-writable and immutable.
private let stableSystemAncestorComponents = ["private", "var", "db"]
private let immutableInstallSubtreeComponents = ["leftovers", "strict-vm"]
private let manifestFilename = "broker-installation-manifest.json"
private let brokerNonLoginShell = "/usr/bin/false"
private let getTaskAllowEntitlement = "com.apple.security.get-task-allow"
private let debuggerEntitlement = "com.apple.security.cs.debugger"

private enum TrustAdapterError: Error, CustomStringConvertible {
    case sourceDisabled
    case invalidManifestDescriptor(String)
    case unstableManifestDescriptor
    case invalidBrokerIdentity(String)
    case invalidPeerIdentity(String)
    case unsupportedSDKCapability(String)
    case descriptorUnavailable
    case descriptorCloseFailed

    var description: String {
        switch self {
        case .sourceDisabled:
            return "native broker trust adapter is source-disabled"
        case let .invalidManifestDescriptor(message), let .invalidBrokerIdentity(message),
             let .invalidPeerIdentity(message), let .unsupportedSDKCapability(message):
            return message
        case .unstableManifestDescriptor:
            return "manifest descriptor or immutable ancestor chain changed during acquisition"
        case .descriptorUnavailable:
            return "owned descriptor is already closed or unavailable"
        case .descriptorCloseFailed:
            return "owned descriptor close failed after ownership was poisoned"
        }
    }
}

private struct DescriptorSnapshot: Equatable {
    let device: dev_t
    let inode: ino_t
    let size: off_t
    let modification: timespec
    let change: timespec

    init(_ value: stat) {
        device = value.st_dev
        inode = value.st_ino
        size = value.st_size
        modification = value.st_mtimespec
        change = value.st_ctimespec
    }

    static func == (lhs: DescriptorSnapshot, rhs: DescriptorSnapshot) -> Bool {
        lhs.device == rhs.device && lhs.inode == rhs.inode && lhs.size == rhs.size
            && lhs.modification.tv_sec == rhs.modification.tv_sec
            && lhs.modification.tv_nsec == rhs.modification.tv_nsec
            && lhs.change.tv_sec == rhs.change.tv_sec
            && lhs.change.tv_nsec == rhs.change.tv_nsec
    }
}

private final class OwnedDescriptor {
    private var descriptor: Int32?

    init(_ descriptor: Int32) {
        self.descriptor = descriptor
    }

    func borrow() throws -> Int32 {
        guard let descriptor else { throw TrustAdapterError.descriptorUnavailable }
        return descriptor
    }

    func closeChecked() throws {
        guard let descriptor else { throw TrustAdapterError.descriptorUnavailable }
        // Poison before close. A failing close must never leave a reusable
        // integer that could later refer to an unrelated kernel object.
        self.descriptor = nil
        guard Darwin.close(descriptor) == 0 else {
            throw TrustAdapterError.descriptorCloseFailed
        }
    }

    deinit {
        // Unavoidable nonthrowing fallback for abandoned error paths. Normal
        // acquisition and verification use closeChecked() and propagate errors.
        if let descriptor {
            self.descriptor = nil
            _ = Darwin.close(descriptor)
        }
    }
}

private final class ManifestDescriptor {
    private let ownedDescriptor: OwnedDescriptor
    let bytes: Data
    let before: DescriptorSnapshot
    let after: DescriptorSnapshot
    let ancestorsBefore: [DescriptorSnapshot]
    let ancestorsAfter: [DescriptorSnapshot]

    init(
        ownedDescriptor: OwnedDescriptor,
        bytes: Data,
        before: DescriptorSnapshot,
        after: DescriptorSnapshot,
        ancestorsBefore: [DescriptorSnapshot],
        ancestorsAfter: [DescriptorSnapshot]
    ) {
        self.ownedDescriptor = ownedDescriptor
        self.bytes = bytes
        self.before = before
        self.after = after
        self.ancestorsBefore = ancestorsBefore
        self.ancestorsAfter = ancestorsAfter
    }

    func withOpenDescriptor<T>(_ body: (Int32) throws -> T) throws -> T {
        let descriptor = try ownedDescriptor.borrow()
        let bodyResult: Result<T, Error>
        do {
            bodyResult = .success(try body(descriptor))
        } catch {
            bodyResult = .failure(error)
        }
        // Close is attempted exactly once, after the body, and a close failure
        // takes precedence because resource disposition is then unproven.
        try ownedDescriptor.closeChecked()
        return try bodyResult.get()
    }
}

private struct ExactCodeIdentity {
    let teamIdentifier: String
    let signingIdentifier: String
    let designatedRequirement: Data
    let allowedCDHashes: Set<Data>
    let exactEntitlements: [String: Bool]
}

private struct ExactRuntimeAccount {
    let uid: uid_t
    let gid: gid_t
    let account: String
    let group: String
}

private struct ImmutableManifestPolicy {
    let brokerIdentity: ExactCodeIdentity
    let controllerIdentity: ExactCodeIdentity
    let brokerAccount: ExactRuntimeAccount
}

private func require(_ condition: Bool, _ error: TrustAdapterError) throws {
    guard condition else { throw error }
}

private func fstatSnapshot(_ descriptor: Int32) throws -> (stat, DescriptorSnapshot) {
    var value = stat()
    guard fstat(descriptor, &value) == 0 else {
        throw TrustAdapterError.invalidManifestDescriptor("fstat failed")
    }
    return (value, DescriptorSnapshot(value))
}

private func requireLocalVolume(_ descriptor: Int32) throws {
    var filesystem = statfs()
    guard fstatfs(descriptor, &filesystem) == 0, (filesystem.f_flags & UInt32(MNT_LOCAL)) != 0 else {
        throw TrustAdapterError.invalidManifestDescriptor("manifest must be on a local volume")
    }
}

private func requireNoExtendedACL(_ descriptor: Int32) throws {
    // `acl_get_fd_np` is an SDK-declared descriptor API.  A non-empty extended
    // ACL is fail-closed; an absent ACL is the only accepted no-ACL result.
    errno = 0
    guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
        guard errno == ENOATTR else {
            throw TrustAdapterError.invalidManifestDescriptor("could not prove ACL absence")
        }
        return
    }
    var entry: acl_entry_t?
    let entryResult = acl_get_entry(acl, 0, &entry)
    guard acl_free(UnsafeMutableRawPointer(acl)) == 0 else {
        throw TrustAdapterError.invalidManifestDescriptor("could not release ACL evidence")
    }
    switch entryResult {
    case 0:
        return
    case 1:
        throw TrustAdapterError.invalidManifestDescriptor("manifest or ancestor has an extended ACL")
    default:
        throw TrustAdapterError.invalidManifestDescriptor("could not enumerate extended ACL")
    }
}

private func closeAllChecked(_ descriptors: inout [OwnedDescriptor]) throws {
    // Remove the owners from the live set before the first syscall, then try
    // every descriptor exactly once even if an earlier close fails.
    let closing = descriptors
    descriptors.removeAll(keepingCapacity: false)
    var firstError: Error?
    for descriptor in closing.reversed() {
        do {
            try descriptor.closeChecked()
        } catch {
            if firstError == nil { firstError = error }
        }
    }
    if let firstError { throw firstError }
}

private func closeAcquisitionDescriptors(
    manifest: OwnedDescriptor?,
    directories: inout [OwnedDescriptor]
) throws {
    var firstError: Error?
    if let manifest {
        do {
            try manifest.closeChecked()
        } catch {
            firstError = error
        }
    }
    do {
        try closeAllChecked(&directories)
    } catch {
        if firstError == nil { firstError = error }
    }
    if let firstError { throw firstError }
}

private func requireRootOwnedDirectoryFacts(
    _ descriptor: Int32
) throws -> (stat, DescriptorSnapshot) {
    let (value, snapshot) = try fstatSnapshot(descriptor)
    try require((value.st_mode & 0o170000) == 0o040000,
                .invalidManifestDescriptor("ancestor is not a directory"))
    try require(value.st_uid == 0, .invalidManifestDescriptor("ancestor is not root-owned"))
    try requireLocalVolume(descriptor)
    try requireNoExtendedACL(descriptor)
    return (value, snapshot)
}

private func requireStableRootOwnedSystemDirectory(_ descriptor: Int32) throws -> DescriptorSnapshot {
    let (value, snapshot) = try requireRootOwnedDirectoryFacts(descriptor)
    try require((value.st_mode & 0o022) == 0,
                .invalidManifestDescriptor("system ancestor is group/other writable"))
    return snapshot
}

private func requireImmutableInstallDirectory(_ descriptor: Int32) throws -> DescriptorSnapshot {
    let (value, snapshot) = try requireRootOwnedDirectoryFacts(descriptor)
    try require((value.st_mode & 0o222) == 0,
                .invalidManifestDescriptor("dedicated install ancestor is writable"))
    try require((value.st_flags & UInt32(UF_IMMUTABLE | SF_IMMUTABLE)) != 0,
                .invalidManifestDescriptor("dedicated install ancestor is not immutable"))
    return snapshot
}

private func validateAncestorDescriptors(
    _ directories: [OwnedDescriptor]
) throws -> [DescriptorSnapshot] {
    let systemDescriptorCount = 1 + stableSystemAncestorComponents.count
    let expectedCount = systemDescriptorCount + immutableInstallSubtreeComponents.count
    try require(directories.count == expectedCount,
                .invalidManifestDescriptor("manifest ancestor chain has unexpected depth"))
    return try directories.enumerated().map { index, ownedDescriptor in
        let descriptor = try ownedDescriptor.borrow()
        if index < systemDescriptorCount {
            return try requireStableRootOwnedSystemDirectory(descriptor)
        }
        return try requireImmutableInstallDirectory(descriptor)
    }
}

private func readBounded(_ descriptor: Int32, maximumBytes: Int) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let count = read(descriptor, &buffer, buffer.count)
        guard count >= 0 else { throw TrustAdapterError.invalidManifestDescriptor("manifest read failed") }
        if count == 0 { return result }
        try require(result.count + count <= maximumBytes,
                    .invalidManifestDescriptor("manifest exceeds fixed bound"))
        result.append(buffer, count: count)
    }
}

// This is deliberately not reachable from the command-line harness.  It uses
// a fixed root and descriptor-relative `openat` calls so no caller supplies a
// manifest pathname and no path component can be followed as a symlink.
private func acquireRootOwnedManifestDescriptor() throws -> ManifestDescriptor {
    var directories: [OwnedDescriptor] = []
    var manifestOwner: OwnedDescriptor?
    var ancestorsBefore: [DescriptorSnapshot] = []
    do {
        let root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard root >= 0 else {
            throw TrustAdapterError.invalidManifestDescriptor("cannot open root")
        }
        let rootOwner = OwnedDescriptor(root)
        directories.append(rootOwner)
        ancestorsBefore.append(try requireStableRootOwnedSystemDirectory(root))
        for component in stableSystemAncestorComponents {
            guard let directoryOwner = directories.last else {
                throw TrustAdapterError.invalidManifestDescriptor("manifest ancestor chain is empty")
            }
            let directory = try directoryOwner.borrow()
            let next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else {
                throw TrustAdapterError.invalidManifestDescriptor("cannot no-follow open manifest ancestor")
            }
            directories.append(OwnedDescriptor(next))
            ancestorsBefore.append(try requireStableRootOwnedSystemDirectory(next))
        }
        for component in immutableInstallSubtreeComponents {
            guard let directoryOwner = directories.last else {
                throw TrustAdapterError.invalidManifestDescriptor("manifest ancestor chain is empty")
            }
            let directory = try directoryOwner.borrow()
            let next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else {
                throw TrustAdapterError.invalidManifestDescriptor("cannot no-follow open install ancestor")
            }
            directories.append(OwnedDescriptor(next))
            ancestorsBefore.append(try requireImmutableInstallDirectory(next))
        }

        guard let directoryOwner = directories.last else {
            throw TrustAdapterError.invalidManifestDescriptor("manifest ancestor chain is empty")
        }
        let directory = try directoryOwner.borrow()
        let manifest = openat(directory, manifestFilename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard manifest >= 0 else {
            throw TrustAdapterError.invalidManifestDescriptor("cannot no-follow open fixed manifest")
        }
        let owner = OwnedDescriptor(manifest)
        manifestOwner = owner
        let (beforeStat, before) = try fstatSnapshot(manifest)
        try require((beforeStat.st_mode & 0o170000) == 0o100000,
                    .invalidManifestDescriptor("manifest is not regular"))
        try require(beforeStat.st_uid == 0, .invalidManifestDescriptor("manifest is not root-owned"))
        try require((beforeStat.st_mode & 0o7777) == 0o444,
                    .invalidManifestDescriptor("manifest mode is not exactly 0444"))
        try require(beforeStat.st_nlink == 1, .invalidManifestDescriptor("manifest has multiple links"))
        try requireLocalVolume(manifest)
        try requireNoExtendedACL(manifest)
        let bytes = try readBounded(manifest, maximumBytes: 1_048_576)
        let (_, after) = try fstatSnapshot(manifest)
        // Revalidate the same retained no-follow descriptors only after the
        // complete read; a pathname re-stat is not accepted as this evidence.
        let ancestorsAfter = try validateAncestorDescriptors(directories)
        try require(before == after && ancestorsBefore == ancestorsAfter, .unstableManifestDescriptor)
        try closeAllChecked(&directories)
        return ManifestDescriptor(
            ownedDescriptor: owner, bytes: bytes, before: before, after: after,
            ancestorsBefore: ancestorsBefore, ancestorsAfter: ancestorsAfter
        )
    } catch {
        let operationError = error
        do {
            try closeAcquisitionDescriptors(manifest: manifestOwner, directories: &directories)
        } catch {
            throw error
        }
        throw operationError
    }
}

private func staticCodeFor(_ code: SecCode) throws -> SecStaticCode {
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, defaultSecCSFlags, &staticCode) == errSecSuccess,
          let staticCode else {
        throw TrustAdapterError.invalidBrokerIdentity("could not derive static code from SecCode")
    }
    return staticCode
}

private func requirementBytes(_ code: SecCode) throws -> Data {
    let staticCode = try staticCodeFor(code)
    var requirement: SecRequirement?
    guard SecCodeCopyDesignatedRequirement(staticCode, defaultSecCSFlags, &requirement) == errSecSuccess,
          let requirement else {
        throw TrustAdapterError.invalidBrokerIdentity("could not extract designated requirement")
    }
    var bytes: CFData?
    guard SecRequirementCopyData(requirement, defaultSecCSFlags, &bytes) == errSecSuccess,
          let bytes else {
        throw TrustAdapterError.invalidBrokerIdentity("could not serialize designated requirement")
    }
    return bytes as Data
}

private func exactSigningInformation(_ code: SecCode) throws -> NSDictionary {
    let staticCode = try staticCodeFor(code)
    var information: CFDictionary?
    // SigningInformation (1<<1) and RequirementInformation (1<<2) are the
    // documented flags required for certificate/team and requirement entries.
    let flags = SecCSFlags(rawValue: (1 << 1) | (1 << 2))
    guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess, let information else {
        throw TrustAdapterError.invalidBrokerIdentity("could not obtain code-signing information")
    }
    return information as NSDictionary
}

private func requireExactCodeIdentity(_ code: SecCode, expected: ExactCodeIdentity, peer: Bool) throws {
    var expectedRequirement: SecRequirement?
    guard SecRequirementCreateWithData(expected.designatedRequirement as CFData,
                                       defaultSecCSFlags, &expectedRequirement) == errSecSuccess,
          let expectedRequirement else {
        throw TrustAdapterError.invalidBrokerIdentity("installed requirement bytes are invalid")
    }
    guard SecCodeCheckValidity(code, strictOfflineSecCSFlags, expectedRequirement) == errSecSuccess else {
        if peer {
            throw TrustAdapterError.invalidPeerIdentity("Security.framework rejected peer code")
        }
        throw TrustAdapterError.invalidBrokerIdentity("Security.framework rejected broker code")
    }
    let information = try exactSigningInformation(code)
    let team = information.object(forKey: kSecCodeInfoTeamIdentifier) as? String
    let identifier = information.object(forKey: kSecCodeInfoIdentifier) as? String
    let hashes = information.object(forKey: kSecCodeInfoCdHashes) as? [Data]
    // The SDK documents certificates as absent for ad-hoc code.  Require a
    // non-empty chain in addition to the exact requirement and CDHash policy.
    let certificates = information.object(forKey: kSecCodeInfoCertificates) as? [Any]
    let entitlements = information.object(forKey: kSecCodeInfoEntitlementsDict) as? [String: Any]
    let actualRequirement = try requirementBytes(code)
    let identityError: TrustAdapterError = peer
        ? .invalidPeerIdentity("code-signing identity does not exactly match manifest")
        : .invalidBrokerIdentity("code-signing identity does not exactly match manifest")
    try require(team == expected.teamIdentifier && identifier == expected.signingIdentifier,
                identityError)
    try require(actualRequirement == expected.designatedRequirement, identityError)
    try require(
        !expected.allowedCDHashes.isEmpty && hashes?.isEmpty == false
            && hashes?.allSatisfy({ expected.allowedCDHashes.contains($0) }) == true,
        identityError
    )
    try require(certificates?.isEmpty == false, identityError)
    let expectedEntitlementKeys = Set(expected.exactEntitlements.keys)
    try require(
        !expectedEntitlementKeys.contains(getTaskAllowEntitlement)
            && !expectedEntitlementKeys.contains(debuggerEntitlement)
            && Set(entitlements?.keys ?? Dictionary<String, Any>().keys) == expectedEntitlementKeys,
        identityError
    )
    for (name, value) in expected.exactEntitlements {
        try require((entitlements?[name] as? Bool) == value, identityError)
    }
    // The forbidden entitlements are rejected even when represented as false:
    // their presence means the installed signature is not the exact policy.
    try require(entitlements?[getTaskAllowEntitlement] == nil && entitlements?[debuggerEntitlement] == nil,
                identityError)
}

private func requireExactBrokerAccount(_ expected: ExactRuntimeAccount) throws {
    let uid = geteuid()
    let gid = getegid()
    try require(uid == expected.uid && gid == expected.gid,
                .invalidBrokerIdentity("runtime UID/GID do not match dedicated broker account"))
    guard let account = getpwuid(uid), let group = getgrgid(gid),
          let accountName = String(validatingUTF8: account.pointee.pw_name),
          let groupName = String(validatingUTF8: group.pointee.gr_name),
          let shell = String(validatingUTF8: account.pointee.pw_shell),
          let home = String(validatingUTF8: account.pointee.pw_dir) else {
        throw TrustAdapterError.invalidBrokerIdentity("cannot resolve dedicated broker account")
    }
    try require(accountName == expected.account && groupName == expected.group,
                .invalidBrokerIdentity("runtime account or group name does not match manifest"))
    try require(shell == brokerNonLoginShell && home == "/var/empty",
                .invalidBrokerIdentity("broker account has login shell or home directory"))
    var groups = [Int32](repeating: 0, count: 1)
    var groupCount: Int32 = 1
    guard getgrouplist(accountName, Int32(gid), &groups, &groupCount) != -1,
          groupCount == 1, groups[0] == Int32(gid) else {
        throw TrustAdapterError.invalidBrokerIdentity("broker account has supplemental groups")
    }
}

private func validateBrokerSelf(_ policy: ImmutableManifestPolicy) throws {
    var selfCode: SecCode?
    guard SecCodeCopySelf(defaultSecCSFlags, &selfCode) == errSecSuccess, let selfCode else {
        throw TrustAdapterError.invalidBrokerIdentity("could not acquire broker SecCode")
    }
    try requireExactCodeIdentity(selfCode, expected: policy.brokerIdentity, peer: false)
    try requireExactBrokerAccount(policy.brokerAccount)
}

private func validateConnectedXPCPeer(_ message: xpc_object_t, policy: ImmutableManifestPolicy) throws {
    // This public SDK call derives the SecCode from the connected message's
    // XPC audit token.  It deliberately does not use PID, executable path, or
    // a caller-provided audit-token digest as identity.
    var peer: SecCode?
    guard SecCodeCreateWithXPCMessage(message, defaultSecCSFlags, &peer) == errSecSuccess,
          let peer else {
        throw TrustAdapterError.invalidPeerIdentity("could not derive peer SecCode from XPC audit token")
    }
    try requireExactCodeIdentity(peer, expected: policy.controllerIdentity, peer: true)
}

private func verifyConnectedPeer(_ message: xpc_object_t) throws {
    // The gate is deliberately before manifest, account, Security.framework,
    // and XPC access.  No Python configuration, plist, or executable flag can
    // alter this source constant.
    guard nativeBrokerTrustAdapterEnabled else { throw TrustAdapterError.sourceDisabled }
    let descriptor = try acquireRootOwnedManifestDescriptor()
    try descriptor.withOpenDescriptor { _ in
        // Parsing and canonical-manifest binding are deliberately absent.
        throw TrustAdapterError.unsupportedSDKCapability(
            "activation requires a reviewed canonical manifest parser and installation procedure"
        )
    }
}

private func selfCheck() -> Int32 {
    do {
        // Passing a nil/invalid XPC object would be unsafe.  The source gate is
        // tested without constructing, connecting, or reading any XPC peer.
        guard nativeBrokerTrustAdapterEnabled else { throw TrustAdapterError.sourceDisabled }
        return 70
    } catch TrustAdapterError.sourceDisabled {
        fputs("source_disabled: native broker trust adapter rejects before manifest, account, Security, or XPC access\n", stderr)
        return 78
    } catch {
        fputs("unexpected self-check result: \(error)\n", stderr)
        return 70
    }
}

if CommandLine.arguments.dropFirst() == ["--self-check"] {
    exit(selfCheck())
}
fputs("usage: NativeBrokerTrustAdapter --self-check\n", stderr)
exit(64)
