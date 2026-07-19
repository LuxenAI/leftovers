# Strict macOS VM launcher proof

This directory contains a bounded proof-of-design for a future high-assurance Leftovers execution
profile on Apple silicon. It deliberately fails closed. It is not yet connected to the production
orchestrator, does not include a guest image, and is not evidence that an online coding agent can
run safely tonight.

The launcher is one macOS process per VM run. It constructs the complete
`VZVirtualMachineConfiguration` internally and accepts only an exact, operator-generated JSON
manifest. The manifest cannot provide commands, environment variables, network settings, mounts,
device types, or host paths outside the immutable boot and private per-run trust domains.

## Fixed boundary

The virtual hardware graph contains:

- a direct Linux kernel and initramfs boot using the fixed command line
  `console=hvc0 rdinit=/init panic=-1 leftovers.scratch=/dev/vdb`;
- one hash-pinned, read-only root disk;
- one newly created, physically preallocated writable scratch disk, bounded to 64 MiB through
  4 GiB;
- optionally one hash-pinned, read-only request disk; and
- zero network, socket, shared-directory, serial, console, graphics, audio, USB, keyboard,
  pointing, balloon, or entropy devices.

The root disk remains an attached read-only artifact; the initramfs supplies `/init`. A request
disk is the only guest input channel. Guest output must be written to the bounded scratch disk and
must only be extracted after the VM has stopped. No host directory is shared with the guest.

CPU count is restricted to 1 through 4, memory to 512 MiB through 4 GiB, and VM wall time to 30
through 3,600 seconds. The scratch file is created with `O_EXCL | O_NOFOLLOW`, preallocated before
start, and never silently reused. Kernel, initramfs, root, and request artifacts must be regular,
non-symlink, size-bounded files. Kernel, initramfs, and root are direct children of an immutable
local boot directory owned by root or a dedicated account other than the launcher. The directory
and boot files have no write permission bits, each boot file has exactly one hard link, and the
production launcher refuses to run as root. `request.raw` and the manifest are launcher-owned,
single-link, sealed mode `0400` direct children of the private mode `0700` per-run directory. Their
lowercase SHA-256 values are recomputed before `VZVirtualMachineConfiguration.validate()`.
All files are opened with `O_NOFOLLOW`; file-descriptor identity is compared before and after reads.

`SIGTERM`, `SIGINT`, and `SIGHUP` request a destructive Virtualization.framework stop. The launcher
allows at most ten additional seconds to prove that stop. A missing or failed stop proof produces
`stop_unproven`, never success. A run that actually started retains the scratch disk for a separate
verifier; check mode and failed starts remove it. The caller must treat an absent receipt, a
`scratch_retained` result it cannot verify, or a forced `SIGKILL` as `cleanup_pending`.

## Manifest v2

Every path must be absolute and canonical. Boot files must be direct children of
`boot_artifact_directory`. The optional `request.raw`, sealed manifest itself, and not-yet-existing
scratch path must be direct children of `run_directory`. The two directories must be disjoint,
contain no symlink component, and live on local filesystems. Production requires a non-root launcher
and a root- or dedicated-account-owned immutable boot directory reached only through path components
that the launcher, group, and other users cannot rewrite; only a binary compiled with
`LEFTOVERS_TESTING` may use same-launcher-owned, no-write-bit boot fixtures.

```json
{
  "schema_version": 2,
  "run_id": "2026-07-18-a1",
  "boot_artifact_directory": "/private/var/leftovers/boot",
  "run_directory": "/private/var/leftovers/runs/2026-07-18-a1",
  "kernel": {
    "path": "/private/var/leftovers/boot/vmlinux",
    "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS"
  },
  "initrd": {
    "path": "/private/var/leftovers/boot/leftovers-initramfs.cpio.gz",
    "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS"
  },
  "root_disk": {
    "path": "/private/var/leftovers/boot/root.raw",
    "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS"
  },
  "request_disk": {
    "path": "/private/var/leftovers/runs/2026-07-18-a1/request.raw",
    "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS"
  },
  "scratch_disk": {
    "path": "/private/var/leftovers/runs/2026-07-18-a1/scratch.raw",
    "size_bytes": 1073741824
  },
  "cpu_count": 2,
  "memory_bytes": 2147483648,
  "wall_time_seconds": 1800
}
```

`request_disk` is optional. All unknown fields are rejected recursively, including a seemingly
benign extra field. There is intentionally no compatibility escape hatch.

The only supported invocations are:

```sh
strict-vm-launcher --check /absolute/path/manifest.json
strict-vm-launcher --run /absolute/path/manifest.json
```

Both write one sorted schema-v2 JSON receipt to standard output. The receipt binds the exact sealed
manifest bytes with `manifest_sha256` and records the validated artifact hashes, limits, stop result,
scratch disposition, and exact device counts, including `network_devices: 0`. It is a launcher
assertion, not a cryptographic third-party attestation.

## Build check

On Apple silicon with macOS 26 and Xcode command-line tools:

```sh
sh vm/check.sh
PYTHONPATH=src python3 -m unittest tests.test_strict_vm_launcher -v
```

The check compiles with Swift and Virtualization.framework in a private temporary directory, adds
an ad-hoc signature carrying only the virtualization entitlement, verifies it, then removes the
binary. A distributable build needs a reviewed build pipeline, stable code signing identity,
launcher hash pinning, and release provenance; the ad-hoc signature is only a local compile check.

## Diagnostic smoke fixture

`smoke_init.sh` is a diagnostic initramfs `/init`, not a production guest. It mounts only guest
`proc`, `sysfs`, and `devtmpfs`, loads Alpine's fixed `virtio_blk` module, waits a bounded five
seconds for the launcher-declared block devices, and writes one padded 4 KiB text receipt to the
scratch disk. It starts no network client, receives no credential, repository, command, environment,
host share, or model access, and then powers the guest off. The repository and transfer package do
not include a kernel, initramfs binary, root image, or request image.

On 2026-07-18, the historical v0.2.0 manifest/receipt-v1 proof launcher was compiled and ad-hoc
signed on an Apple-silicon Mac, then booted with a manually assembled Alpine 3.24.1 diagnostic
initramfs. The launcher reported a
validated graph with zero network, socket, share, serial, console, graphics, audio, USB, keyboard,
pointing, entropy, and balloon devices; the guest reported only `lo`, a read-only root, a writable
64 MiB scratch disk, PID 1, and two virtio devices before a guest-initiated shutdown. The exact
source hashes, launcher receipt, guest scratch receipt, and limitations are recorded in
`vm/evidence/2026-07-18-live-smoke.json`. That record and its hashes are preserved unchanged. Tests
verify it as an immutable historical v1 record and confirm that the current v2 receipt schema rejects
it; it is not evidence for, and is deliberately not bound to, the current v0.3.0 v2 launcher source.

That observation proves one v1 fixture run, not the current v2 trust-domain separation, a reusable
image build, production mediation path, or escape-proof system. The current receipt schema rejects
unsafe semantic combinations, but any future controller must also compare the expected manifest,
launcher identity, source provenance, run ID, and scratch contents; schema success alone is not
attestation.

## Sealed mediation authorization (protocol scaffold)

An LFRQ now carries a canonical `mediation` receipt and a `check_registry` alongside its action
batch. The receipt binds the run/round/stage, provider/model/effort, canonical action-batch and
patch digests, exact action policy digest, exact check-ID-to-fixed-argv registry digest, token-ledger
reservation identity, and the digest of independently parsed provider-usage evidence. The parser
revalidates those bindings before both request construction and guest-result interpretation. Raw
action data without an authorization is rejected. Offline fixtures are a separate explicit mode and
use a deterministic fixture usage-evidence digest; they are not broker authority.

This is a protocol guard, not a signature scheme or execution approval. The current builder rejects
every `broker` authorization—including an in-process object with plausible hashes—because no opaque
broker attestation verifier exists. A future broker must own the receipt issuer and registry state
under a distinct account, retain the exact usage-event bytes whose digest it records, and prove that
its fixed argv mapping cannot be changed by repository or model input. Production strict-VM
execution remains disabled.

## Deliberate blockers and limitations

- No reviewed production kernel, reproducible initramfs/root image, restricted non-root worker, or
  result extractor is supplied. The diagnostic `smoke_init.sh` does not satisfy those requirements.
  A real run must remain disabled until those artifacts are reproducibly built, hash-pinned, and
  adversarially tested.
- The zero-NIC, zero-socket VM cannot contact an online model provider. The existing host Codex
  adapter must not be placed behind this label. Enabling Terra requires a separately designed,
  narrowly authenticated and audited mediation channel; simply adding NAT, a virtual socket, host
  credentials, or `CODEX_HOME` would violate this profile.
- Virtualization.framework bounds VM CPU and memory, but guest process/PID, file, and syscall limits
  still require a reviewed `/init` with cgroup v2, seccomp, Landlock, a non-root worker, and a
  read-only guest policy. Those controls are not proved by this launcher alone.
- Trust-domain separation and hash checking narrow artifact substitution, but a privileged boot-
  artifact owner can still replace files. Protected ownership, immutable release provenance, a
  pinned launcher identity, and an external controller are still required.
- Scratch output is untrusted. A separate verifier must read only fixed bounded regions through
  no-follow descriptors, never mount it or invoke a filesystem/archive parser, enforce exact
  type/count/size/hash rules, produce a canonical result bundle, and erase the run directory only
  after a marker-checked cleanup receipt. That verifier is not implemented here.
- This reduces the attack surface; it cannot prove that macOS, Virtualization.framework, the CPU,
  or the guest kernel has no escape vulnerability. “Absolutely escape-proof” is not an honest
  security claim. A dedicated machine remains the stronger boundary for hostile workloads.

Until the guest image, offline adversarial tests, result handoff, external cleanup verification,
and authenticated model mediation all exist, this code is a fail-closed design artifact—not an
authorization to execute untrusted repository work.
