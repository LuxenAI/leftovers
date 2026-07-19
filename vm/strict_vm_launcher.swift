import CryptoKit
import Darwin
import Foundation
import Virtualization

private let launcherVersion = "0.3.0-proof"
private let manifestSchemaVersion = 2
private let receiptSchemaVersion = 2
private let mib: UInt64 = 1_048_576
private let gib: UInt64 = 1_073_741_824
private let hostFreeSpaceReserve = gib
private let maximumHostFileDescriptors: rlim_t = 256
private let maximumScratchPreparationSeconds = 60.0
private let productionCPUCount = 2
private let productionMemoryBytes = 2 * gib
private let productionScratchBytes = 2 * gib
private let productionWallTimeSeconds = 30 * 60
private let fixedKernelCommandLine = [
    "console=hvc0",
    "rdinit=/init",
    "panic=-1",
    "leftovers.scratch=/dev/vdb",
].joined(separator: " ")

private struct ArtifactSpec: Decodable {
    let path: String
    let sha256: String
}

private struct ScratchSpec: Decodable {
    let path: String
    let sizeBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case path
        case sizeBytes = "size_bytes"
    }
}

private struct Manifest: Decodable {
    let schemaVersion: Int
    let runID: String
    let bootArtifactDirectory: String
    let runDirectory: String
    let kernel: ArtifactSpec
    let initrd: ArtifactSpec
    let rootDisk: ArtifactSpec
    let requestDisk: ArtifactSpec?
    let scratchDisk: ScratchSpec
    let cpuCount: Int
    let memoryBytes: UInt64
    let wallTimeSeconds: Int

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case runID = "run_id"
        case bootArtifactDirectory = "boot_artifact_directory"
        case runDirectory = "run_directory"
        case kernel
        case initrd
        case rootDisk = "root_disk"
        case requestDisk = "request_disk"
        case scratchDisk = "scratch_disk"
        case cpuCount = "cpu_count"
        case memoryBytes = "memory_bytes"
        case wallTimeSeconds = "wall_time_seconds"
    }
}

private struct LimitsReceipt: Encodable {
    let cpuCount: Int
    let memoryBytes: UInt64
    let wallTimeSeconds: Int
    let scratchBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case cpuCount = "cpu_count"
        case memoryBytes = "memory_bytes"
        case wallTimeSeconds = "wall_time_seconds"
        case scratchBytes = "scratch_bytes"
    }
}

private struct ArtifactReceipt: Encodable {
    let kernelSHA256: String
    let initrdSHA256: String
    let rootDiskSHA256: String
    let requestDiskSHA256: String?

    enum CodingKeys: String, CodingKey {
        case kernelSHA256 = "kernel_sha256"
        case initrdSHA256 = "initrd_sha256"
        case rootDiskSHA256 = "root_disk_sha256"
        case requestDiskSHA256 = "request_disk_sha256"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kernelSHA256, forKey: .kernelSHA256)
        try container.encode(initrdSHA256, forKey: .initrdSHA256)
        try container.encode(rootDiskSHA256, forKey: .rootDiskSHA256)
        if let requestDiskSHA256 {
            try container.encode(requestDiskSHA256, forKey: .requestDiskSHA256)
        } else {
            try container.encodeNil(forKey: .requestDiskSHA256)
        }
    }
}

private struct StorageDeviceReceipt: Encodable {
    let role: String
    let kind: String
    let readOnly: Bool
    let sizeBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case role
        case kind
        case readOnly = "read_only"
        case sizeBytes = "size_bytes"
    }
}

private struct DeviceReceipt: Encodable {
    let platform: String
    let bootLoader: String
    let networkDevices: Int
    let socketDevices: Int
    let directoryShares: Int
    let serialPorts: Int
    let consoleDevices: Int
    let graphicsDevices: Int
    let audioDevices: Int
    let usbControllers: Int
    let keyboards: Int
    let pointingDevices: Int
    let entropyDevices: Int
    let memoryBalloonDevices: Int
    let storageDevices: [StorageDeviceReceipt]

    enum CodingKeys: String, CodingKey {
        case platform
        case bootLoader = "boot_loader"
        case networkDevices = "network_devices"
        case socketDevices = "socket_devices"
        case directoryShares = "directory_shares"
        case serialPorts = "serial_ports"
        case consoleDevices = "console_devices"
        case graphicsDevices = "graphics_devices"
        case audioDevices = "audio_devices"
        case usbControllers = "usb_controllers"
        case keyboards
        case pointingDevices = "pointing_devices"
        case entropyDevices = "entropy_devices"
        case memoryBalloonDevices = "memory_balloon_devices"
        case storageDevices = "storage_devices"
    }
}

private struct Receipt: Encodable {
    let schemaVersion: Int
    let launcherVersion: String
    let manifestSHA256: String?
    let runID: String?
    let mode: String
    let status: String
    let startedAt: String?
    let finishedAt: String
    let configValidated: Bool
    let stopReason: String?
    let limits: LimitsReceipt?
    let artifacts: ArtifactReceipt?
    let devices: DeviceReceipt?
    let scratchRetained: Bool
    let errorCode: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case launcherVersion = "launcher_version"
        case manifestSHA256 = "manifest_sha256"
        case runID = "run_id"
        case mode
        case status
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case configValidated = "config_validated"
        case stopReason = "stop_reason"
        case limits
        case artifacts
        case devices
        case scratchRetained = "scratch_retained"
        case errorCode = "error_code"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(launcherVersion, forKey: .launcherVersion)
        try container.encode(mode, forKey: .mode)
        try container.encode(status, forKey: .status)
        try container.encode(finishedAt, forKey: .finishedAt)
        try container.encode(configValidated, forKey: .configValidated)
        try container.encode(scratchRetained, forKey: .scratchRetained)
        if let manifestSHA256 {
            try container.encode(manifestSHA256, forKey: .manifestSHA256)
        } else {
            try container.encodeNil(forKey: .manifestSHA256)
        }
        if let runID {
            try container.encode(runID, forKey: .runID)
        } else {
            try container.encodeNil(forKey: .runID)
        }
        if let startedAt {
            try container.encode(startedAt, forKey: .startedAt)
        } else {
            try container.encodeNil(forKey: .startedAt)
        }
        if let stopReason {
            try container.encode(stopReason, forKey: .stopReason)
        } else {
            try container.encodeNil(forKey: .stopReason)
        }
        if let limits {
            try container.encode(limits, forKey: .limits)
        } else {
            try container.encodeNil(forKey: .limits)
        }
        if let artifacts {
            try container.encode(artifacts, forKey: .artifacts)
        } else {
            try container.encodeNil(forKey: .artifacts)
        }
        if let devices {
            try container.encode(devices, forKey: .devices)
        } else {
            try container.encodeNil(forKey: .devices)
        }
        if let errorCode {
            try container.encode(errorCode, forKey: .errorCode)
        } else {
            try container.encodeNil(forKey: .errorCode)
        }
    }
}

private struct LaunchFailure: Error, CustomStringConvertible {
    let code: String
    let detail: String
    let scratchRetained: Bool

    init(code: String, detail: String, scratchRetained: Bool = false) {
        self.code = code
        self.detail = detail
        self.scratchRetained = scratchRetained
    }

    var description: String { "\(code): \(detail)" }
}

private struct VerifiedArtifact {
    let url: URL
    let sha256: String
    let sizeBytes: UInt64
    let identity: stat
}

private struct PreparedScratch {
    let url: URL
    // Scratch contents and timestamps are deliberately guest-mutable. Its inode, ownership,
    // mode, link count, and size are not.
    let identity: stat
}

private struct LoadedManifest {
    let manifest: Manifest
    let sha256: String
}

private struct BootArtifactDirectory {
    let url: URL
    let owner: uid_t
}

private struct PreparedRun {
    let manifest: Manifest
    let kernel: VerifiedArtifact
    let initrd: VerifiedArtifact
    let rootDisk: VerifiedArtifact
    let requestDisk: VerifiedArtifact?
    let scratch: PreparedScratch
}

private struct ConfigurationBundle {
    let configuration: VZVirtualMachineConfiguration
    let devices: DeviceReceipt
}

private struct StopOutcome {
    let status: String
    let reason: String
    let startedAt: String?
    let errorCode: String?
}

private final class SignalCancellation {
    private let lock = NSLock()
    private var receivedSignal: Int32?
    private var sources: [DispatchSourceSignal] = []

    func install() throws {
        guard sources.isEmpty else { return }
        let signalNumbers: [Int32] = [SIGTERM, SIGINT, SIGHUP]
        var signalSet = sigset_t()
        guard sigemptyset(&signalSet) == 0,
              signalNumbers.allSatisfy({ sigaddset(&signalSet, $0) == 0 }),
              pthread_sigmask(SIG_BLOCK, &signalSet, nil) == 0
        else {
            throw LaunchFailure(code: "signal_install", detail: "cannot block termination signals")
        }
        var unblocked = false
        defer {
            if !unblocked {
                _ = pthread_sigmask(SIG_UNBLOCK, &signalSet, nil)
            }
        }
        for signalNumber in signalNumbers {
            Darwin.signal(signalNumber, SIG_IGN)
            let source = DispatchSource.makeSignalSource(
                signal: signalNumber,
                queue: DispatchQueue.global(qos: .userInitiated)
            )
            source.setEventHandler { [weak self] in
                self?.record(signalNumber)
            }
            source.resume()
            sources.append(source)
        }
        guard pthread_sigmask(SIG_UNBLOCK, &signalSet, nil) == 0 else {
            throw LaunchFailure(code: "signal_install", detail: "cannot unblock termination signals")
        }
        unblocked = true
    }

    func reason() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return receivedSignal.map { "signal_\($0)" }
    }

    func checkpoint(_ phase: String) throws {
        if let reason = reason() {
            throw LaunchFailure(
                code: "cancelled",
                detail: "launcher received \(reason) before \(phase)"
            )
        }
    }

    private func record(_ signalNumber: Int32) {
        lock.lock()
        if receivedSignal == nil { receivedSignal = signalNumber }
        lock.unlock()
    }
}

private func applyHostProcessLimits() throws {
#if !LEFTOVERS_TESTING
    guard geteuid() != 0 else {
        throw LaunchFailure(code: "launcher_root", detail: "production launcher must run as a non-root user")
    }
#endif
    _ = umask(S_IRWXG | S_IRWXO)
    var coreLimit = rlimit(rlim_cur: 0, rlim_max: 0)
    guard setrlimit(RLIMIT_CORE, &coreLimit) == 0 else {
        throw LaunchFailure(code: "host_core_limit", detail: "cannot disable launcher core dumps")
    }
    var currentFiles = rlimit()
    guard getrlimit(RLIMIT_NOFILE, &currentFiles) == 0 else {
        throw LaunchFailure(code: "host_nofile_limit", detail: "cannot inspect file descriptor limit")
    }
    let boundedFiles = min(currentFiles.rlim_max, maximumHostFileDescriptors)
    guard boundedFiles >= 64 else {
        throw LaunchFailure(code: "host_nofile_limit", detail: "host file descriptor limit is too low")
    }
    var fileLimit = rlimit(rlim_cur: boundedFiles, rlim_max: boundedFiles)
    guard setrlimit(RLIMIT_NOFILE, &fileLimit) == 0 else {
        throw LaunchFailure(code: "host_nofile_limit", detail: "cannot bound file descriptors")
    }
}

private func timestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
}

private func emit(_ receipt: Receipt) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    guard let data = try? encoder.encode(receipt) else {
        FileHandle.standardError.write(Data("receipt_encoding_failed\n".utf8))
        return
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

private func exactKeys(
    _ object: Any,
    allowed: Set<String>,
    required: Set<String>,
    context: String
) throws -> [String: Any] {
    guard let dictionary = object as? [String: Any] else {
        throw LaunchFailure(code: "manifest_shape", detail: "\(context) must be an object")
    }
    let keys = Set(dictionary.keys)
    let unknown = keys.subtracting(allowed).sorted()
    if !unknown.isEmpty {
        throw LaunchFailure(
            code: "manifest_unknown_field",
            detail: "\(context) contains unknown fields: \(unknown.joined(separator: ","))"
        )
    }
    let missing = required.subtracting(keys).sorted()
    if !missing.isEmpty {
        throw LaunchFailure(
            code: "manifest_missing_field",
            detail: "\(context) is missing fields: \(missing.joined(separator: ","))"
        )
    }
    return dictionary
}

private func rejectUnknownManifestFields(_ data: Data) throws {
    let object: Any
    do {
        object = try JSONSerialization.jsonObject(with: data, options: [])
    } catch {
        throw LaunchFailure(code: "manifest_json", detail: "invalid JSON")
    }
    let top = try exactKeys(
        object,
        allowed: [
            "schema_version", "run_id", "boot_artifact_directory", "run_directory", "kernel",
            "initrd", "root_disk", "request_disk", "scratch_disk", "cpu_count",
            "memory_bytes", "wall_time_seconds",
        ],
        required: [
            "schema_version", "run_id", "boot_artifact_directory", "run_directory", "kernel",
            "initrd", "root_disk", "scratch_disk", "cpu_count", "memory_bytes",
            "wall_time_seconds",
        ],
        context: "manifest"
    )
    let artifactAllowed: Set<String> = ["path", "sha256"]
    for key in ["kernel", "initrd", "root_disk"] {
        _ = try exactKeys(
            top[key] as Any,
            allowed: artifactAllowed,
            required: artifactAllowed,
            context: key
        )
    }
    if let request = top["request_disk"] {
        _ = try exactKeys(
            request,
            allowed: artifactAllowed,
            required: artifactAllowed,
            context: "request_disk"
        )
    }
    _ = try exactKeys(
        top["scratch_disk"] as Any,
        allowed: ["path", "size_bytes"],
        required: ["path", "size_bytes"],
        context: "scratch_disk"
    )
    let canonical: Data
    do {
        canonical = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    } catch {
        throw LaunchFailure(code: "manifest_json", detail: "manifest cannot be canonicalized")
    }
    guard data == canonical else {
        // Parsing duplicate keys loses the earlier value. Requiring the unique canonical form
        // rejects that ambiguity along with whitespace and key-order variants.
        throw LaunchFailure(
            code: "manifest_canonical",
            detail: "manifest must be canonical JSON with no duplicate keys"
        )
    }
}

private func checkedAbsoluteURL(_ path: String, role: String) throws -> URL {
    guard path.utf8.count <= 1024, path.hasPrefix("/") else {
        throw LaunchFailure(code: "path_invalid", detail: "\(role) path must be a bounded absolute path")
    }
    if path.contains("\u{0}") {
        throw LaunchFailure(code: "path_invalid", detail: "\(role) path contains NUL")
    }
    guard path != "/", !path.hasSuffix("/"), !path.contains("//") else {
        throw LaunchFailure(code: "path_noncanonical", detail: "\(role) path must be canonical")
    }
    let components = path.split(separator: "/", omittingEmptySubsequences: false)
    guard components.first == "", components.dropFirst().allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
        throw LaunchFailure(code: "path_noncanonical", detail: "\(role) path must be canonical")
    }
    return URL(fileURLWithPath: path)
}

private func lstatValue(_ path: String, role: String) throws -> stat {
    var value = stat()
    guard lstat(path, &value) == 0 else {
        throw LaunchFailure(code: "path_lstat", detail: "cannot inspect \(role)")
    }
    return value
}

private func requireNoSymlinkComponents(_ url: URL, role: String) throws {
    let parts = url.pathComponents
    var current = "/"
    for part in parts where part != "/" {
        current = URL(fileURLWithPath: current).appendingPathComponent(part).path
        let value = try lstatValue(current, role: role)
        if (value.st_mode & S_IFMT) == S_IFLNK {
            throw LaunchFailure(code: "path_symlink", detail: "\(role) path contains a symlink")
        }
    }
}

private func sameFileIdentity(_ first: stat, _ second: stat) -> Bool {
    first.st_dev == second.st_dev && first.st_ino == second.st_ino
        && first.st_size == second.st_size
        && first.st_nlink == second.st_nlink
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
        && first.st_mtimespec.tv_sec == second.st_mtimespec.tv_sec
        && first.st_mtimespec.tv_nsec == second.st_mtimespec.tv_nsec
        && first.st_ctimespec.tv_sec == second.st_ctimespec.tv_sec
        && first.st_ctimespec.tv_nsec == second.st_ctimespec.tv_nsec
}

private func sameScratchIdentity(_ first: stat, _ second: stat) -> Bool {
    (first.st_mode & S_IFMT) == S_IFREG
        && (second.st_mode & S_IFMT) == S_IFREG
        && first.st_dev == second.st_dev
        && first.st_ino == second.st_ino
        && first.st_size == second.st_size
        && first.st_nlink == second.st_nlink
        && first.st_uid == second.st_uid
        && first.st_mode == second.st_mode
}

private func loadManifest(path: String) throws -> LoadedManifest {
    let url = try checkedAbsoluteURL(path, role: "manifest")
    try requireNoSymlinkComponents(url, role: "manifest")
    let pathValue = try lstatValue(url.path, role: "manifest")
    guard (pathValue.st_mode & S_IFMT) == S_IFREG else {
        throw LaunchFailure(code: "manifest_type", detail: "manifest must be a regular file")
    }
    guard pathValue.st_nlink == 1 else {
        throw LaunchFailure(code: "manifest_links", detail: "manifest must have exactly one hard link")
    }
    guard pathValue.st_uid == geteuid() else {
        throw LaunchFailure(code: "manifest_owner", detail: "manifest is not owned by the launcher user")
    }
    guard (pathValue.st_mode & mode_t(0o7777)) == mode_t(0o400) else {
        throw LaunchFailure(code: "manifest_permissions", detail: "manifest must be sealed mode 0400")
    }
    guard pathValue.st_size > 0, pathValue.st_size <= 64 * 1024 else {
        throw LaunchFailure(code: "manifest_size", detail: "manifest must be 1 byte through 64 KiB")
    }
    var filesystem = statfs()
    guard statfs(url.path, &filesystem) == 0,
          (UInt32(filesystem.f_flags) & UInt32(MNT_LOCAL)) != 0
    else {
        throw LaunchFailure(code: "manifest_filesystem", detail: "manifest must be on a local filesystem")
    }
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw LaunchFailure(code: "manifest_open", detail: "cannot securely open manifest")
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer { try? handle.close() }
    var openedValue = stat()
    guard fstat(descriptor, &openedValue) == 0, sameFileIdentity(pathValue, openedValue) else {
        throw LaunchFailure(code: "manifest_changed", detail: "manifest changed before open")
    }
    let data: Data
    do {
        data = try handle.read(upToCount: 64 * 1024 + 1) ?? Data()
    } catch {
        throw LaunchFailure(code: "manifest_read", detail: "cannot read manifest")
    }
    guard !data.isEmpty, data.count <= 64 * 1024 else {
        throw LaunchFailure(code: "manifest_size", detail: "manifest must be 1 byte through 64 KiB")
    }
    var afterValue = stat()
    guard fstat(descriptor, &afterValue) == 0, sameFileIdentity(openedValue, afterValue),
          Int64(data.count) == afterValue.st_size
    else {
        throw LaunchFailure(code: "manifest_changed", detail: "manifest changed while reading")
    }
    try rejectUnknownManifestFields(data)
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let decoded: Manifest
    do {
        decoded = try JSONDecoder().decode(Manifest.self, from: data)
    } catch {
        throw LaunchFailure(code: "manifest_decode", detail: "manifest types are invalid")
    }
    let runDirectory = try checkedAbsoluteURL(decoded.runDirectory, role: "run_directory")
    try requirePrivateRunDirectory(runDirectory)
    try requireDirectChild(url, of: runDirectory, role: "manifest")
    return LoadedManifest(manifest: decoded, sha256: digest)
}

private func requireLocalVolume(_ url: URL, role: String) throws {
    var filesystem = statfs()
    guard statfs(url.path, &filesystem) == 0 else {
        throw LaunchFailure(code: "directory_statfs", detail: "cannot inspect \(role) filesystem")
    }
    guard (UInt32(filesystem.f_flags) & UInt32(MNT_LOCAL)) != 0 else {
        throw LaunchFailure(code: "directory_remote", detail: "\(role) must be on a local filesystem")
    }
}

private func requirePrivateRunDirectory(_ url: URL) throws {
    let role = "run_directory"
    try requireNoSymlinkComponents(url, role: role)
    let value = try lstatValue(url.path, role: role)
    guard (value.st_mode & S_IFMT) == S_IFDIR else {
        throw LaunchFailure(code: "directory_type", detail: "\(role) is not a directory")
    }
    guard value.st_uid == geteuid() else {
        throw LaunchFailure(code: "directory_owner", detail: "\(role) is not owned by the launcher user")
    }
    guard (value.st_mode & mode_t(0o7777)) == mode_t(0o700) else {
        throw LaunchFailure(code: "directory_permissions", detail: "run_directory must be private mode 0700")
    }
    try requireLocalVolume(url, role: role)
}

private func requirePinnedBootAncestors(_ url: URL, allowedOwner: uid_t) throws {
#if !LEFTOVERS_TESTING
    var current = "/"
    for part in url.pathComponents where part != "/" {
        current = URL(fileURLWithPath: current).appendingPathComponent(part).path
        let value = try lstatValue(current, role: "boot_artifact_directory")
        guard (value.st_mode & S_IFMT) == S_IFDIR else {
            throw LaunchFailure(
                code: "boot_path_type",
                detail: "boot_artifact_directory ancestors must be directories"
            )
        }
        guard value.st_uid == 0 || value.st_uid == allowedOwner else {
            throw LaunchFailure(
                code: "boot_path_owner",
                detail: "boot_artifact_directory ancestors must be owned by root or the pinned boot owner"
            )
        }
        guard (value.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0
        else {
            throw LaunchFailure(
                code: "boot_path_permissions",
                detail: "boot_artifact_directory ancestors must have no write permission bits"
            )
        }
    }
#endif
}

private func requireImmutableBootDirectory(_ url: URL) throws -> BootArtifactDirectory {
    let role = "boot_artifact_directory"
    try requireNoSymlinkComponents(url, role: role)
    let value = try lstatValue(url.path, role: role)
    guard (value.st_mode & S_IFMT) == S_IFDIR else {
        throw LaunchFailure(code: "directory_type", detail: "boot_artifact_directory is not a directory")
    }
#if LEFTOVERS_TESTING
    // Behavior tests cannot create root-owned fixtures. The testing build permits same-euid
    // fixtures only when the directory and its files have every write bit removed.
#else
    guard value.st_uid != geteuid() else {
        throw LaunchFailure(
            code: "boot_directory_owner",
            detail: "production boot_artifact_directory must be owned by root or a dedicated non-launcher account"
        )
    }
#endif
    guard (value.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0 else {
        throw LaunchFailure(
            code: "boot_directory_permissions",
            detail: "boot_artifact_directory must have no write permission bits"
        )
    }
    try requirePinnedBootAncestors(url, allowedOwner: value.st_uid)
    try requireLocalVolume(url, role: role)
    return BootArtifactDirectory(url: url, owner: value.st_uid)
}

private func requireDirectChild(_ file: URL, of directory: URL, role: String) throws {
    guard file.deletingLastPathComponent().path == directory.path else {
        throw LaunchFailure(code: "path_scope", detail: "\(role) must be a direct child of its controlled directory")
    }
}

private func requireSeparatedDirectories(_ first: URL, _ second: URL) throws {
    let firstPrefix = first.path + "/"
    let secondPrefix = second.path + "/"
    guard first.path != second.path,
          !first.path.hasPrefix(secondPrefix),
          !second.path.hasPrefix(firstPrefix)
    else {
        throw LaunchFailure(
            code: "directory_separation",
            detail: "boot artifact and run directories must be disjoint"
        )
    }
}

private func validSHA256(_ value: String) -> Bool {
    value.count == 64 && value.allSatisfy { character in
        character >= "0" && character <= "9" || character >= "a" && character <= "f"
    }
}

private func hashFile(_ url: URL, role: String, expected: stat) throws -> String {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw LaunchFailure(code: "artifact_open", detail: "cannot securely open \(role)")
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer { try? handle.close() }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0, sameFileIdentity(expected, opened) else {
        throw LaunchFailure(code: "artifact_changed", detail: "\(role) changed before open")
    }
    let sizeMiB = max(1.0, Double(opened.st_size) / Double(mib))
    let hashDeadline = ProcessInfo.processInfo.systemUptime + min(300.0, max(30.0, sizeMiB / 16.0))
    var hasher = SHA256()
    do {
        while let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty {
            guard ProcessInfo.processInfo.systemUptime <= hashDeadline else {
                throw LaunchFailure(code: "artifact_hash_timeout", detail: "\(role) hashing exceeded its deadline")
            }
            hasher.update(data: chunk)
        }
    } catch let failure as LaunchFailure {
        throw failure
    } catch {
        throw LaunchFailure(code: "artifact_read", detail: "cannot hash \(role)")
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0, sameFileIdentity(opened, after) else {
        throw LaunchFailure(code: "artifact_changed", detail: "\(role) changed while hashing")
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

private func verifyArtifact(
    _ spec: ArtifactSpec,
    role: String,
    in controlledDirectory: URL,
    expectedOwner: uid_t,
    exactPermissions: mode_t?,
    requireNoWriteBits: Bool,
    minimumBytes: UInt64,
    maximumBytes: UInt64,
    requireBlockMultiple: Bool
) throws -> VerifiedArtifact {
    guard validSHA256(spec.sha256) else {
        throw LaunchFailure(code: "artifact_hash_format", detail: "\(role) SHA-256 must be lowercase hexadecimal")
    }
    let url = try checkedAbsoluteURL(spec.path, role: role)
    try requireDirectChild(url, of: controlledDirectory, role: role)
    try requireNoSymlinkComponents(url, role: role)
    let before = try lstatValue(url.path, role: role)
    guard (before.st_mode & S_IFMT) == S_IFREG else {
        throw LaunchFailure(code: "artifact_type", detail: "\(role) must be a regular file")
    }
    guard before.st_nlink == 1 else {
        throw LaunchFailure(code: "artifact_links", detail: "\(role) must have exactly one hard link")
    }
    guard before.st_uid == expectedOwner else {
        throw LaunchFailure(code: "artifact_owner", detail: "\(role) has an untrusted owner")
    }
    if let exactPermissions {
        guard (before.st_mode & mode_t(0o7777)) == exactPermissions else {
            throw LaunchFailure(
                code: "artifact_permissions",
                detail: "\(role) must be sealed mode \(String(exactPermissions, radix: 8))"
            )
        }
    }
    if requireNoWriteBits {
        guard (before.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0 else {
            throw LaunchFailure(code: "artifact_permissions", detail: "\(role) must have no write permission bits")
        }
    }
    let size = UInt64(before.st_size)
    guard size >= minimumBytes, size <= maximumBytes else {
        throw LaunchFailure(code: "artifact_size", detail: "\(role) is outside its size bounds")
    }
    if requireBlockMultiple, size % 512 != 0 {
        throw LaunchFailure(code: "artifact_alignment", detail: "\(role) size must be a multiple of 512")
    }
    let digest = try hashFile(url, role: role, expected: before)
    guard digest == spec.sha256 else {
        throw LaunchFailure(code: "artifact_hash_mismatch", detail: "\(role) SHA-256 mismatch")
    }
    let after = try lstatValue(url.path, role: role)
    guard sameFileIdentity(before, after) else {
        throw LaunchFailure(code: "artifact_changed", detail: "\(role) changed during verification")
    }
    return VerifiedArtifact(url: url, sha256: digest, sizeBytes: size, identity: after)
}

private func revalidateReadOnlyInput(_ artifact: VerifiedArtifact, role: String) throws {
    try requireNoSymlinkComponents(artifact.url, role: role)
    let pathValue = try lstatValue(artifact.url.path, role: role)
    guard sameFileIdentity(artifact.identity, pathValue) else {
        throw LaunchFailure(code: "artifact_changed", detail: "\(role) changed before VM start")
    }
    let descriptor = open(artifact.url.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw LaunchFailure(code: "artifact_open", detail: "cannot securely reopen \(role)")
    }
    defer { _ = close(descriptor) }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0, sameFileIdentity(artifact.identity, opened) else {
        throw LaunchFailure(code: "artifact_changed", detail: "\(role) changed before VM start")
    }
}

private func revalidateScratch(
    _ scratch: PreparedScratch,
    role: String,
    runDirectory: URL,
    requireSync: Bool
) throws {
    try requireNoSymlinkComponents(scratch.url, role: role)
    let pathValue = try lstatValue(scratch.url.path, role: role)
    guard sameScratchIdentity(scratch.identity, pathValue) else {
        throw LaunchFailure(code: "scratch_identity", detail: "scratch disk identity changed \(role)")
    }
    let descriptor = open(scratch.url.path, O_RDWR | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw LaunchFailure(code: "scratch_open", detail: "cannot securely reopen scratch disk")
    }
    defer { _ = close(descriptor) }
    var opened = stat()
    guard fstat(descriptor, &opened) == 0, sameScratchIdentity(scratch.identity, opened) else {
        throw LaunchFailure(code: "scratch_identity", detail: "scratch disk changed \(role)")
    }
    if requireSync {
        guard fsync(descriptor) == 0 else {
            throw LaunchFailure(code: "scratch_fsync", detail: "cannot fsync scratch disk after guest stop")
        }
        try fsyncRunDirectory(runDirectory)
    }
}

private func revalidateVMStartInputs(_ run: PreparedRun) throws {
    if let request = run.requestDisk {
        try revalidateReadOnlyInput(request, role: "request_disk")
    }
    let runDirectory = try checkedAbsoluteURL(run.manifest.runDirectory, role: "run_directory")
    try revalidateScratch(run.scratch, role: "before VM start", runDirectory: runDirectory, requireSync: false)
}

private func revalidateScratchAfterStop(_ run: PreparedRun) throws {
    let runDirectory = try checkedAbsoluteURL(run.manifest.runDirectory, role: "run_directory")
    try revalidateScratch(run.scratch, role: "after guest stop", runDirectory: runDirectory, requireSync: true)
}

private func validateManifestValues(_ manifest: Manifest, mode: String) throws {
    guard manifest.schemaVersion == manifestSchemaVersion else {
        throw LaunchFailure(code: "schema_version", detail: "unsupported manifest schema")
    }
    let runIDPattern = try! NSRegularExpression(pattern: "^[a-f0-9]{32}$")
    let runIDRange = NSRange(manifest.runID.startIndex..., in: manifest.runID)
    guard runIDPattern.firstMatch(in: manifest.runID, range: runIDRange) != nil else {
        throw LaunchFailure(code: "run_id", detail: "run_id must be exactly 32 lowercase hexadecimal characters")
    }
    guard (1...4).contains(manifest.cpuCount) else {
        throw LaunchFailure(code: "cpu_limit", detail: "cpu_count must be between 1 and 4")
    }
    guard manifest.memoryBytes >= 512 * mib, manifest.memoryBytes <= 4 * gib,
          manifest.memoryBytes % mib == 0
    else {
        throw LaunchFailure(code: "memory_limit", detail: "memory_bytes must be 512 MiB through 4 GiB and MiB-aligned")
    }
    guard (30...3_600).contains(manifest.wallTimeSeconds) else {
        throw LaunchFailure(code: "wall_limit", detail: "wall_time_seconds must be between 30 and 3600")
    }
    guard manifest.scratchDisk.sizeBytes >= 64 * mib,
          manifest.scratchDisk.sizeBytes <= 4 * gib,
          manifest.scratchDisk.sizeBytes % mib == 0
    else {
        throw LaunchFailure(code: "scratch_limit", detail: "scratch size must be 64 MiB through 4 GiB and MiB-aligned")
    }
    if mode == "run" {
        guard manifest.requestDisk != nil else {
            throw LaunchFailure(
                code: "request_required",
                detail: "run mode requires the sealed read-only request disk"
            )
        }
        guard manifest.cpuCount == productionCPUCount,
              manifest.memoryBytes == productionMemoryBytes,
              manifest.scratchDisk.sizeBytes == productionScratchBytes,
              manifest.wallTimeSeconds == productionWallTimeSeconds
        else {
            throw LaunchFailure(
                code: "production_resource_profile",
                detail: "run mode requires the exact installed resource profile"
            )
        }
    }
}

private func scratchPathIsAbsent(_ url: URL) -> Bool {
    var value = stat()
    guard lstat(url.path, &value) != 0 else { return false }
    return errno == ENOENT
}

private func fsyncRunDirectory(_ runDirectory: URL) throws {
    let descriptor = open(runDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw LaunchFailure(code: "run_directory_open", detail: "cannot securely open run_directory")
    }
    defer { _ = close(descriptor) }
    var value = stat()
    guard fstat(descriptor, &value) == 0,
          (value.st_mode & S_IFMT) == S_IFDIR,
          value.st_uid == geteuid(),
          (value.st_mode & mode_t(0o7777)) == mode_t(0o700)
    else {
        throw LaunchFailure(code: "run_directory_changed", detail: "run_directory changed while in use")
    }
    guard fsync(descriptor) == 0 else {
        throw LaunchFailure(code: "run_directory_fsync", detail: "cannot fsync run_directory")
    }
}

private func removeScratchAndProveAbsent(
    _ url: URL,
    expectedIdentity: stat?,
    in runDirectory: URL
) -> Bool {
#if LEFTOVERS_TESTING
    if ProcessInfo.processInfo.environment["LEFTOVERS_TEST_FORCE_SCRATCH_CLEANUP_FAILURE"] == "1" {
        return false
    }
#endif
    var current = stat()
    if lstat(url.path, &current) == 0 {
        guard let expectedIdentity, sameScratchIdentity(expectedIdentity, current) else {
            return false
        }
        if unlink(url.path) != 0 { return false }
    } else if errno != ENOENT {
        return false
    }
    do {
        try fsyncRunDirectory(runDirectory)
    } catch {
        return false
    }
    return scratchPathIsAbsent(url)
}

private func requireScratchCapacity(_ sizeBytes: UInt64, in runDirectory: URL) throws {
    var filesystem = statfs()
    guard statfs(runDirectory.path, &filesystem) == 0, filesystem.f_bsize > 0 else {
        throw LaunchFailure(code: "scratch_capacity", detail: "cannot inspect scratch filesystem capacity")
    }
    let blockSize = UInt64(filesystem.f_bsize)
    let availableBlocks = UInt64(filesystem.f_bavail)
    guard availableBlocks <= UInt64.max / blockSize else {
        throw LaunchFailure(code: "scratch_capacity", detail: "scratch filesystem capacity overflow")
    }
    let availableBytes = availableBlocks * blockSize
    guard sizeBytes <= UInt64.max - hostFreeSpaceReserve,
          availableBytes >= sizeBytes + hostFreeSpaceReserve
    else {
        throw LaunchFailure(
            code: "scratch_capacity",
            detail: "scratch filesystem cannot preserve the fixed host free-space reserve"
        )
    }
}

private func createReservedScratch(
    _ spec: ScratchSpec,
    in runDirectory: URL,
    cancellation: SignalCancellation
) throws -> PreparedScratch {
    try cancellation.checkpoint("scratch creation")
    let url = try checkedAbsoluteURL(spec.path, role: "scratch_disk")
    try requireDirectChild(url, of: runDirectory, role: "scratch_disk")
    var value = stat()
    if lstat(url.path, &value) == 0 || errno != ENOENT {
        throw LaunchFailure(code: "scratch_exists", detail: "scratch disk must not already exist")
    }
    try requireScratchCapacity(spec.sizeBytes, in: runDirectory)
    try cancellation.checkpoint("scratch allocation")
    let descriptor = open(url.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else {
        throw LaunchFailure(code: "scratch_create", detail: "cannot create scratch disk")
    }
    var descriptorOpen = true
    var createdIdentity: stat?
    let preparationDeadline = ProcessInfo.processInfo.systemUptime + maximumScratchPreparationSeconds
    do {
        guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 else {
            throw LaunchFailure(code: "scratch_permissions", detail: "cannot seal scratch disk mode")
        }
        var created = stat()
        guard fstat(descriptor, &created) == 0,
              (created.st_mode & S_IFMT) == S_IFREG,
              created.st_nlink == 1,
              created.st_uid == geteuid(),
              (created.st_mode & mode_t(0o7777)) == mode_t(0o600)
        else {
            throw LaunchFailure(code: "scratch_identity", detail: "new scratch disk identity is unsafe")
        }
        createdIdentity = created
        var allocation = fstore_t(
            fst_flags: UInt32(F_ALLOCATECONTIG),
            fst_posmode: F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: off_t(spec.sizeBytes),
            fst_bytesalloc: 0
        )
        if fcntl(descriptor, F_PREALLOCATE, &allocation) == -1 {
            allocation.fst_flags = UInt32(F_ALLOCATEALL)
            guard fcntl(descriptor, F_PREALLOCATE, &allocation) != -1 else {
                throw LaunchFailure(code: "scratch_reserve", detail: "cannot reserve bounded scratch capacity")
            }
        }
        try cancellation.checkpoint("scratch reservation")
        guard ftruncate(descriptor, off_t(spec.sizeBytes)) == 0, fsync(descriptor) == 0 else {
            throw LaunchFailure(code: "scratch_resize", detail: "cannot finalize scratch disk")
        }
        var finalized = stat()
        guard fstat(descriptor, &finalized) == 0,
              (finalized.st_mode & S_IFMT) == S_IFREG,
              finalized.st_nlink == 1,
              finalized.st_uid == geteuid(),
              (finalized.st_mode & mode_t(0o7777)) == mode_t(0o600),
              UInt64(finalized.st_size) == spec.sizeBytes
        else {
            throw LaunchFailure(code: "scratch_identity", detail: "new scratch disk identity is unsafe")
        }
        guard ProcessInfo.processInfo.systemUptime <= preparationDeadline else {
            throw LaunchFailure(
                code: "scratch_reserve_timeout",
                detail: "scratch preparation exceeded its deadline"
            )
        }
        let closeResult = close(descriptor)
        descriptorOpen = false
        guard closeResult == 0 else {
            throw LaunchFailure(code: "scratch_close", detail: "cannot close finalized scratch disk")
        }
        try fsyncRunDirectory(runDirectory)
        let afterClose = try lstatValue(url.path, role: "scratch_disk")
        guard sameFileIdentity(finalized, afterClose) else {
            throw LaunchFailure(code: "scratch_changed", detail: "scratch disk changed before VM start")
        }
        try cancellation.checkpoint("VM configuration")
        return PreparedScratch(url: url, identity: finalized)
    } catch {
        if descriptorOpen { _ = close(descriptor) }
        guard removeScratchAndProveAbsent(
            url,
            expectedIdentity: createdIdentity,
            in: runDirectory
        ) else {
            throw LaunchFailure(
                code: "scratch_cleanup_unproven",
                detail: "scratch creation failed and path absence could not be proven",
                scratchRetained: true
            )
        }
        throw error
    }
}

private func prepare(
    _ manifest: Manifest,
    mode: String,
    cancellation: SignalCancellation
) throws -> PreparedRun {
    try cancellation.checkpoint("manifest preparation")
    try validateManifestValues(manifest, mode: mode)
    let bootArtifactDirectory = try checkedAbsoluteURL(
        manifest.bootArtifactDirectory,
        role: "boot_artifact_directory"
    )
    let runDirectory = try checkedAbsoluteURL(manifest.runDirectory, role: "run_directory")
    let bootDirectory = try requireImmutableBootDirectory(bootArtifactDirectory)
    try requirePrivateRunDirectory(runDirectory)
    try requireSeparatedDirectories(bootArtifactDirectory, runDirectory)
    try cancellation.checkpoint("boot artifact verification")
    let kernel = try verifyArtifact(
        manifest.kernel,
        role: "kernel",
        in: bootDirectory.url,
        expectedOwner: bootDirectory.owner,
        exactPermissions: nil,
        requireNoWriteBits: true,
        minimumBytes: 1,
        maximumBytes: 128 * mib,
        requireBlockMultiple: false
    )
    let initrd = try verifyArtifact(
        manifest.initrd,
        role: "initrd",
        in: bootDirectory.url,
        expectedOwner: bootDirectory.owner,
        exactPermissions: nil,
        requireNoWriteBits: true,
        minimumBytes: 1,
        maximumBytes: 512 * mib,
        requireBlockMultiple: false
    )
    let rootDisk = try verifyArtifact(
        manifest.rootDisk,
        role: "root_disk",
        in: bootDirectory.url,
        expectedOwner: bootDirectory.owner,
        exactPermissions: nil,
        requireNoWriteBits: true,
        minimumBytes: mib,
        maximumBytes: 16 * gib,
        requireBlockMultiple: true
    )
    let requestDisk: VerifiedArtifact?
    if let spec = manifest.requestDisk {
        let requestURL = try checkedAbsoluteURL(spec.path, role: "request_disk")
        guard requestURL.lastPathComponent == "request.raw" else {
            throw LaunchFailure(code: "path_name", detail: "request_disk must be named request.raw")
        }
        requestDisk = try verifyArtifact(
            spec,
            role: "request_disk",
            in: runDirectory,
            expectedOwner: geteuid(),
            exactPermissions: mode_t(0o400),
            requireNoWriteBits: true,
            minimumBytes: 512,
            maximumBytes: 256 * mib,
            requireBlockMultiple: true
        )
    } else {
        requestDisk = nil
    }
    let scratch = try createReservedScratch(
        manifest.scratchDisk,
        in: runDirectory,
        cancellation: cancellation
    )
    return PreparedRun(
        manifest: manifest,
        kernel: kernel,
        initrd: initrd,
        rootDisk: rootDisk,
        requestDisk: requestDisk,
        scratch: scratch
    )
}

private func blockDevice(
    url: URL,
    role: String,
    readOnly: Bool
) throws -> VZVirtioBlockDeviceConfiguration {
    let attachment = try VZDiskImageStorageDeviceAttachment(
        url: url,
        readOnly: readOnly,
        cachingMode: .uncached,
        synchronizationMode: readOnly ? .full : .fsync
    )
    let device = VZVirtioBlockDeviceConfiguration(attachment: attachment)
    device.blockDeviceIdentifier = "leftovers-\(role)"
    return device
}

private func buildConfiguration(_ run: PreparedRun) throws -> ConfigurationBundle {
    let configuration = VZVirtualMachineConfiguration()
    let bootLoader = VZLinuxBootLoader(kernelURL: run.kernel.url)
    bootLoader.initialRamdiskURL = run.initrd.url
    bootLoader.commandLine = run.requestDisk == nil
        ? fixedKernelCommandLine
        : fixedKernelCommandLine + " leftovers.request=/dev/vdc"
    configuration.bootLoader = bootLoader
    configuration.cpuCount = run.manifest.cpuCount
    configuration.memorySize = run.manifest.memoryBytes

    let root = try blockDevice(url: run.rootDisk.url, role: "root", readOnly: true)
    let scratch = try blockDevice(url: run.scratch.url, role: "scratch", readOnly: false)
    var storage: [VZStorageDeviceConfiguration] = [root, scratch]
    var storageReceipt = [
        StorageDeviceReceipt(
            role: "root",
            kind: "virtio-block",
            readOnly: true,
            sizeBytes: run.rootDisk.sizeBytes
        ),
        StorageDeviceReceipt(
            role: "scratch",
            kind: "virtio-block",
            readOnly: false,
            sizeBytes: run.manifest.scratchDisk.sizeBytes
        ),
    ]
    if let request = run.requestDisk {
        storage.append(try blockDevice(url: request.url, role: "request", readOnly: true))
        storageReceipt.append(
            StorageDeviceReceipt(
                role: "request",
                kind: "virtio-block",
                readOnly: true,
                sizeBytes: request.sizeBytes
            )
        )
    }
    configuration.storageDevices = storage

    // These empty arrays are the security boundary: the manifest cannot add devices.
    configuration.networkDevices = []
    configuration.socketDevices = []
    configuration.directorySharingDevices = []
    configuration.serialPorts = []
    configuration.consoleDevices = []
    configuration.graphicsDevices = []
    configuration.audioDevices = []
    configuration.usbControllers = []
    configuration.keyboards = []
    configuration.pointingDevices = []
    configuration.entropyDevices = []
    configuration.memoryBalloonDevices = []

    do {
        try configuration.validate()
    } catch {
        let diagnostic = String(error.localizedDescription.prefix(500))
        throw LaunchFailure(
            code: "vz_configuration",
            detail: "Virtualization configuration did not validate: \(diagnostic)"
        )
    }

    return ConfigurationBundle(
        configuration: configuration,
        devices: DeviceReceipt(
            platform: "generic",
            bootLoader: "linux",
            networkDevices: configuration.networkDevices.count,
            socketDevices: configuration.socketDevices.count,
            directoryShares: configuration.directorySharingDevices.count,
            serialPorts: configuration.serialPorts.count,
            consoleDevices: configuration.consoleDevices.count,
            graphicsDevices: configuration.graphicsDevices.count,
            audioDevices: configuration.audioDevices.count,
            usbControllers: configuration.usbControllers.count,
            keyboards: configuration.keyboards.count,
            pointingDevices: configuration.pointingDevices.count,
            entropyDevices: configuration.entropyDevices.count,
            memoryBalloonDevices: configuration.memoryBalloonDevices.count,
            storageDevices: storageReceipt
        )
    )
}

private final class VMController: NSObject, VZVirtualMachineDelegate {
    private let virtualMachine: VZVirtualMachine
    private let wallTimeSeconds: Int
    private let cancellation: SignalCancellation
    private var timer: DispatchSourceTimer?
    private var cancellationPoll: DispatchSourceTimer?
    private var stopPoll: DispatchSourceTimer?
    private var stopDeadlineTimer: DispatchSourceTimer?
    private var requestedStopReason: String?
    private var stopInFlight = false
    private(set) var finished = false
    private(set) var outcome: StopOutcome?
    private var startedAt: String?

    init(
        configuration: VZVirtualMachineConfiguration,
        wallTimeSeconds: Int,
        cancellation: SignalCancellation
    ) {
        self.virtualMachine = VZVirtualMachine(configuration: configuration)
        self.wallTimeSeconds = wallTimeSeconds
        self.cancellation = cancellation
        super.init()
        self.virtualMachine.delegate = self
    }

    func run(preStart: () throws -> Void) throws -> StopOutcome {
        try cancellation.checkpoint("VM start")
        try preStart()
        try cancellation.checkpoint("VM start")
        let wallTimer = DispatchSource.makeTimerSource(queue: .main)
        wallTimer.schedule(deadline: .now() + .seconds(wallTimeSeconds), leeway: .seconds(1))
        wallTimer.setEventHandler { [weak self] in self?.requestStop(reason: "wall_timeout") }
        wallTimer.resume()
        timer = wallTimer

        let signalTimer = DispatchSource.makeTimerSource(queue: .main)
        signalTimer.schedule(deadline: .now(), repeating: .milliseconds(50))
        signalTimer.setEventHandler { [weak self] in
            guard let self, let reason = self.cancellation.reason() else { return }
            self.requestStop(reason: reason)
        }
        signalTimer.resume()
        cancellationPoll = signalTimer

        virtualMachine.start { [weak self] result in
            guard let self else { return }
            switch result {
            case .success:
                self.startedAt = timestamp()
                if self.requestedStopReason != nil { self.tryStop() }
            case let .failure(error):
                let nsError = error as NSError
                let diagnostic = String(nsError.localizedDescription.prefix(500))
                FileHandle.standardError.write(
                    Data("strict-vm-launcher: VM start failed: \(diagnostic)\n".utf8)
                )
                self.finish(
                    status: "failed",
                    reason: "start_failed",
                    errorCode: "vz_start_\(nsError.code)"
                )
            }
        }

        while !finished {
            _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.1))
        }
        return outcome ?? StopOutcome(
            status: "failed",
            reason: "missing_outcome",
            startedAt: startedAt,
            errorCode: "internal_state"
        )
    }

    private func requestStop(reason: String) {
        guard !finished else { return }
        if requestedStopReason == nil {
            requestedStopReason = reason
            let deadline = DispatchSource.makeTimerSource(queue: .main)
            deadline.schedule(deadline: .now() + .seconds(10))
            deadline.setEventHandler { [weak self] in
                self?.enforceStopDeadline()
            }
            deadline.resume()
            stopDeadlineTimer = deadline
        }
        tryStop()
    }

    private func enforceStopDeadline() {
        guard !finished, requestedStopReason != nil else { return }
        finish(status: "failed", reason: "stop_unproven", errorCode: "vz_stop_deadline")
    }

    private func statusForRequestedStop() -> String {
        requestedStopReason == "wall_timeout" ? "timed_out" : "interrupted"
    }

    private func finishRequestedStop() {
        guard let reason = requestedStopReason else { return }
        finish(status: statusForRequestedStop(), reason: reason, errorCode: nil)
    }

    private func tryStop() {
        guard !finished, requestedStopReason != nil else { return }
        if virtualMachine.state == .stopped {
            finishRequestedStop()
            return
        }
        guard !stopInFlight else { return }
        if virtualMachine.canStop {
            stopInFlight = true
            virtualMachine.stop { [weak self] error in
                guard let self else { return }
                self.stopInFlight = false
                if let error {
                    self.finish(
                        status: "failed",
                        reason: "stop_unproven",
                        errorCode: "vz_stop_\(String(describing: type(of: error)))"
                    )
                } else if self.virtualMachine.state != .stopped {
                    self.tryStop()
                } else {
                    self.finishRequestedStop()
                }
            }
            return
        }
        if stopPoll == nil {
            let poll = DispatchSource.makeTimerSource(queue: .main)
            poll.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
            poll.setEventHandler { [weak self] in self?.tryStop() }
            poll.resume()
            stopPoll = poll
        }
    }

    private func finish(status: String, reason: String, errorCode: String?) {
        guard !finished else { return }
        timer?.cancel()
        cancellationPoll?.cancel()
        stopPoll?.cancel()
        stopDeadlineTimer?.cancel()
        outcome = StopOutcome(
            status: status,
            reason: reason,
            startedAt: startedAt,
            errorCode: errorCode
        )
        finished = true
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        guard virtualMachine.state == .stopped else {
            finish(status: "failed", reason: "stop_unproven", errorCode: "vz_guest_stop_state")
            return
        }
        if requestedStopReason != nil {
            finishRequestedStop()
        } else {
            finish(status: "guest_stopped", reason: "guest_shutdown", errorCode: nil)
        }
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        finish(
            status: "failed",
            reason: "guest_error",
            errorCode: "vz_guest_\(String(describing: type(of: error)))"
        )
    }
}

private func usageFailure() -> Never {
    emit(
        Receipt(
            schemaVersion: receiptSchemaVersion,
            launcherVersion: launcherVersion,
            manifestSHA256: nil,
            runID: nil,
            mode: "unknown",
            status: "failed",
            startedAt: nil,
            finishedAt: timestamp(),
            configValidated: false,
            stopReason: nil,
            limits: nil,
            artifacts: nil,
            devices: nil,
            scratchRetained: false,
            errorCode: "usage"
        )
    )
    exit(64)
}

private func main() -> Int32 {
    guard ProcessInfo.processInfo.arguments.count == 3 else { usageFailure() }
    let modeArgument = ProcessInfo.processInfo.arguments[1]
    guard modeArgument == "--check" || modeArgument == "--run" else { usageFailure() }
    let mode = modeArgument == "--check" ? "check" : "run"
    var manifest: Manifest?
    var manifestSHA256: String?
    var prepared: PreparedRun?
    var configurationBundle: ConfigurationBundle?
    var runOutcome: StopOutcome?
    var scratchRetained = false
    let cancellation = SignalCancellation()

    do {
        try cancellation.install()
        try cancellation.checkpoint("launcher setup")
        try applyHostProcessLimits()
        let loaded = try loadManifest(path: ProcessInfo.processInfo.arguments[2])
        manifest = loaded.manifest
        manifestSHA256 = loaded.sha256
        try cancellation.checkpoint("manifest loading")
        let run = try prepare(loaded.manifest, mode: mode, cancellation: cancellation)
        prepared = run
        try cancellation.checkpoint("VM configuration")
        let bundle = try buildConfiguration(run)
        configurationBundle = bundle

        let limits = LimitsReceipt(
            cpuCount: loaded.manifest.cpuCount,
            memoryBytes: loaded.manifest.memoryBytes,
            wallTimeSeconds: loaded.manifest.wallTimeSeconds,
            scratchBytes: loaded.manifest.scratchDisk.sizeBytes
        )
        let artifacts = ArtifactReceipt(
            kernelSHA256: run.kernel.sha256,
            initrdSHA256: run.initrd.sha256,
            rootDiskSHA256: run.rootDisk.sha256,
            requestDiskSHA256: run.requestDisk?.sha256
        )
        if mode == "check" {
            let runDirectory = try checkedAbsoluteURL(run.manifest.runDirectory, role: "run_directory")
            guard removeScratchAndProveAbsent(
                run.scratch.url,
                expectedIdentity: run.scratch.identity,
                in: runDirectory
            ) else {
                scratchRetained = true
                throw LaunchFailure(
                    code: "scratch_cleanup_unproven",
                    detail: "check-mode scratch absence could not be proven",
                    scratchRetained: true
                )
            }
            prepared = nil
            emit(
                Receipt(
                    schemaVersion: receiptSchemaVersion,
                    launcherVersion: launcherVersion,
                    manifestSHA256: loaded.sha256,
                    runID: loaded.manifest.runID,
                    mode: mode,
                    status: "validated",
                    startedAt: nil,
                    finishedAt: timestamp(),
                    configValidated: true,
                    stopReason: nil,
                    limits: limits,
                    artifacts: artifacts,
                    devices: bundle.devices,
                    scratchRetained: false,
                    errorCode: nil
                )
            )
            return 0
        }

        let controller = VMController(
            configuration: bundle.configuration,
            wallTimeSeconds: loaded.manifest.wallTimeSeconds,
            cancellation: cancellation
        )
        let outcome = try controller.run { try revalidateVMStartInputs(run) }
        runOutcome = outcome
        scratchRetained = outcome.startedAt != nil
        if outcome.startedAt != nil {
            try revalidateScratchAfterStop(run)
        }
        if !scratchRetained {
            let runDirectory = try checkedAbsoluteURL(run.manifest.runDirectory, role: "run_directory")
            guard removeScratchAndProveAbsent(
                run.scratch.url,
                expectedIdentity: run.scratch.identity,
                in: runDirectory
            ) else {
                scratchRetained = true
                throw LaunchFailure(
                    code: "scratch_cleanup_unproven",
                    detail: "failed-start scratch absence could not be proven",
                    scratchRetained: true
                )
            }
            prepared = nil
        }
        emit(
            Receipt(
                schemaVersion: receiptSchemaVersion,
                launcherVersion: launcherVersion,
                manifestSHA256: loaded.sha256,
                runID: loaded.manifest.runID,
                mode: mode,
                status: outcome.status,
                startedAt: outcome.startedAt,
                finishedAt: timestamp(),
                configValidated: true,
                stopReason: outcome.reason,
                limits: limits,
                artifacts: artifacts,
                devices: bundle.devices,
                scratchRetained: scratchRetained,
                errorCode: outcome.errorCode
            )
        )
        return outcome.status == "guest_stopped" ? 0 : 1
    } catch let failure as LaunchFailure {
        scratchRetained = scratchRetained || failure.scratchRetained
        var errorCode = failure.code
        if let scratch = prepared?.scratch, !scratchRetained {
            let runDirectory = try? checkedAbsoluteURL(
                prepared?.manifest.runDirectory ?? "",
                role: "run_directory"
            )
            if let runDirectory,
               removeScratchAndProveAbsent(
                   scratch.url,
                   expectedIdentity: scratch.identity,
                   in: runDirectory
               ) {
                prepared = nil
            } else {
                scratchRetained = true
                errorCode = "scratch_cleanup_unproven"
            }
        }
        emit(
            Receipt(
                schemaVersion: receiptSchemaVersion,
                launcherVersion: launcherVersion,
                manifestSHA256: manifestSHA256,
                runID: manifest?.runID,
                mode: mode,
                status: "failed",
                startedAt: runOutcome?.startedAt,
                finishedAt: timestamp(),
                configValidated: configurationBundle != nil,
                stopReason: runOutcome?.reason,
                limits: nil,
                artifacts: nil,
                devices: configurationBundle?.devices,
                scratchRetained: scratchRetained,
                errorCode: errorCode
            )
        )
        FileHandle.standardError.write(Data("strict-vm-launcher: \(failure)\n".utf8))
        return 1
    } catch {
        if let scratch = prepared?.scratch, !scratchRetained {
            let runDirectory = try? checkedAbsoluteURL(
                prepared?.manifest.runDirectory ?? "",
                role: "run_directory"
            )
            if let runDirectory,
               removeScratchAndProveAbsent(
                   scratch.url,
                   expectedIdentity: scratch.identity,
                   in: runDirectory
               ) {
                prepared = nil
            } else {
                scratchRetained = true
            }
        }
        emit(
            Receipt(
                schemaVersion: receiptSchemaVersion,
                launcherVersion: launcherVersion,
                manifestSHA256: manifestSHA256,
                runID: manifest?.runID,
                mode: mode,
                status: "failed",
                startedAt: runOutcome?.startedAt,
                finishedAt: timestamp(),
                configValidated: false,
                stopReason: runOutcome?.reason,
                limits: nil,
                artifacts: nil,
                devices: nil,
                scratchRetained: scratchRetained,
                errorCode: scratchRetained ? "scratch_cleanup_unproven" : "unexpected"
            )
        )
        FileHandle.standardError.write(Data("strict-vm-launcher: unexpected failure\n".utf8))
        return 1
    }
}

exit(main())
