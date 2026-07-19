# Strict VM Linux guest scaffold

This is a reproducible-input **source scaffold**, not a guest image or a reproducible guest build, and not an authorization to run an
issue, a test, a model, or a PR workflow.  It remains behind the repository's disabled strict-VM
execution gate.  No artifact from this directory has been built or booted.
Every unimplemented or malformed path fails closed by powering off or by leaving no host-acceptable
result record.

## Scope and trust boundary

The future boot chain is deliberately split:

```text
immutable Buildroot + Linux source pins
  -> reviewed aarch64 kernel + read-only root.ext2 + initramfs
  -> minimal early PID 1, read-only vda mount, and pivot into root.ext2
  -> fail-closed PID 1 supervisor (this tree)
  -> source-only, release-disabled bounded action interpreter
```

The launcher must attach the root image read-only, have no NIC, share, socket, or interactive device,
and pass exactly one `leftovers.request=/dev/vdc` plus exactly one
`leftovers.scratch=/dev/vdb` on its fixed kernel command line. The current launcher appends the
request parameter when a request disk is present and uses `vdb` for scratch. The supervisor rejects
an absent, duplicate, malformed, unknown `leftovers.*`, or differently pinned device argument; it
never infers a device order.

There is no host filesystem mount, host process launcher, credential, broker socket, network client,
shell, package manager, archive extractor, arbitrary argv field, or model provider in this guest.
The request and scratch block devices are the only proposed data channels. A future mediator remains
outside the VM and must never give the guest its credentials. The interpreter source opens only those
descriptors and a pre-prepared scratch repository directory descriptor; it never opens a host path,
looks up credentials, consults an environment variable, or accepts an argv. It is compiled but its
call site is statically unreachable in the release guest. No built image has exercised it.
The source parser accepts either a regular test fixture or the real read-only block request, deriving
the latter's exact extent with `BLKGETSIZE64` and independently requiring `BLKROGET`. The unactivated
wire name for the public `prior_observations` API argument is the bounded 9-byte `prior_obs`; every
section name fits the fixed 16-byte table field, including exact-width `cumulative_patch`.

## Future LFSC v1 source capsule contract

The old opaque-archive idea is replaced by the source-disabled **LFSC v1** regular-file capsule
defined in `src/leftovers/strict_vm_source_capsule.py`. A future guest parser receives only a
pre-opened capsule descriptor, never a host pathname, and validates without extraction: a fixed
big-endian header, length-prefixed UTF-8 NFC relative paths in canonical depth-first component order,
fixed canonical file modes (`0644` or `0755`), per-file SHA-256, whole-payload SHA-256, and zero
alignment padding. Component order compares each path component's raw UTF-8 bytes; it is deliberately
not flat serialized-path ordering, so `a/x` precedes the sibling file `a.txt`.
It rejects absolute/dot/control/`.git` components, duplicates or reordering, truncation/overlap/trailing
bytes, digest drift, and nonzero padding. The source-side fixture packer accepts only an owner-private
`0700` directory descriptor containing owner-private single-link regular `0600`/`0700` files and a
pre-opened owner-private single-link `0600` output descriptor. It uses no caller paths, chunked I/O,
close-on-exec descriptors, pre/post `fstat` checks, directory-mutation detection, explicit close-error
handling, and fsyncs payload bytes before it writes the complete digest-bearing header. A descriptor
preflight rejects an output inode anywhere in the source tree before writing the incomplete header;
the streaming pass checks the inode again before reading file content. The fixed bounds match the
guest's source tree contract: 2,048 files, depth 32, 240-byte paths, 1 MiB/file, and 32 MiB total
content.

Packing remains fixture-capability-only and production-source-gated. LFSC does not parse GitHub
archives, extract guest files, execute anything, contact a provider, launch a VM, or authorize a write.

## Reproducible inputs

[`SOURCES.lock.json`](SOURCES.lock.json) records the official Buildroot `2026.05.1` release tag
(`de1f9260590a53a7cd8a59addc47c96ecd09f983`, released 2026-07-15) and Linux stable `v6.12.87`
(`669dc96e243e422e7404bb98be00d527bafc0a96`, released 2026-05-08).  Those are immutable Git object
hashes, recorded after `git ls-remote --refs` on 2026-07-19T00:26:00Z.  Before a build, a release
pipeline must verify the signed upstream tags, resolve those exact objects, build in a disposable
Linux CI environment, and produce a signed provenance statement binding the source lock, Buildroot
defconfig, kernel config, compiler, and boot artifact SHA-256 values.  This checkout deliberately
does not download the 5–150 MiB source/toolchain inputs or build them on the host.

`python3 vm/guest/verify-sources.py` validates the lock structure without network access. The
container builder's `release.py verify-remote` checks only the two lock-derived, fixed official
HTTPS tag names with `git ls-remote --refs` immediately before its shallow tag fetch. It then checks
the local exact tag objects and signatures, requires `HEAD` to equal the tag's commit, and rejects
index, tracked, or untracked checkout dirt. Git verification uses an isolated home, disabled global
and system configuration, no hooks/credential helper/fsmonitor, and a fixed OpenPGP program. The
remote object check complements, but does not replace, upstream signed-tag verification.

## Container-only release candidate pipeline

[`BUILD.lock.json`](BUILD.lock.json) starts deliberately **UNCONFIGURED**. It has no builder image
digest, public-key trust-root digest, expected upstream signing identities, reproducibility epoch, or
provenance verifier. Therefore `make guest-release-preflight` and the manually dispatched
[`strict-guest-candidate`](../../.github/workflows/guest-build.yml) workflow fail before pulling an
image, cloning a source, or building anything. This is intentional: a source hash and a modelled
JSON receipt are not substitutes for verified upstream signatures or release provenance.

To prepare a reviewed release candidate, maintainers must make a separately reviewed source change
that pins all of the following in `BUILD.lock.json` and `SOURCES.lock.json`:

1. a digest-only builder-image reference (`registry/name@sha256:...`),
2. a minimal public OpenPGP keyring in `trusted-keys/` and its canonical tree digest,
3. the exact 40-character expected signer fingerprint for each upstream tag,
4. a stable `SOURCE_DATE_EPOCH`, and
5. the independently reviewed provenance-verifier registry ID, binary SHA-256, and fixed argv.

There is intentionally **no registered provenance verifier in this source tree**. Even a
syntactically complete lock therefore fails `release-readiness`; a future verifier must be
implemented, pinned in the small in-code registry, exercised, and independently reviewed before
the candidate builder can run.

When a verifier exists, the manual workflow will perform a temporary networked fetch phase inside
that image, verify the exact signed tags with `git verify-tag`, and use Buildroot's documented
`LINUX_OVERRIDE_SRCDIR` mechanism. It uses a bounded (6 GiB) tmpfs Docker volume that is explicitly
removed and re-checked, and each container has fixed CPU, memory, swap, PID, read-only-root, and
capability limits. The work volume is `nosuid,nodev` but intentionally executable because Buildroot
must run its generated host tools; the separate `/tmp` tmpfs remains `noexec`. The compile phase is
a fresh `--network none` container. Its output is only a
**self-asserted, unsigned candidate**: the JSON files currently omit the resolved source commits,
download hashes, Buildroot `.config`, kernel `.config`, source-signature transcript, keyring digest,
actual builder execution identity, complete toolchain/package inventory, build log, and a signed
provenance statement. It exits with status 78 and cannot become a boot artifact until an external,
pinned verifier checks a signature and a separate reproducibility build matches every digest.

`release.py compare-candidates --left <candidate-a> --right <candidate-b>` is only a deterministic
comparison helper. It accepts byte-identical canonical policy and artifact manifests; it cannot
establish reproducible execution, make a signature claim, upload an artifact, change the strict-VM
execution gate, or copy a candidate into the host boot-artifact directory.

The Buildroot external-tree convention is intentional: after source verification, a disposable CI
job would invoke:

```sh
make BR2_EXTERNAL=/absolute/path/to/Leftovers/vm/guest \
  O=/isolated/output leftovers_strict_vm_defconfig
make O=/isolated/output
```

That command is documentation, not an approved local deployment command.  It must run only in a
reviewed build container/VM with a fresh clone at the recorded commit, verified tag signatures, and
an output directory outside a user home/credential tree.  The generated `rootfs.ext2` is a candidate
read-only root disk; `rootfs.cpio.gz` is a candidate initramfs. The package installs a small compiled
`/init` in the initramfs. It waits only for `/dev/vda`, mounts it read-only, performs `pivot_root`,
detaches the old initramfs root, and `execve`s the statically linked supervisor from the mounted root.
This design avoids treating a full Buildroot cpio as the final root filesystem. It has not been built or boot-tested; any early-init or pivot failure powers off rather than falling back to a shell. Their names, SHA-256 digests, mode, owner, and signature must be incorporated into the host boot-artifact manifest before launch.

The release builder must also create one canonical, mode-`0400`, non-symlink
`guest-policy.json` next to those three boot files. It is a controller-verifiable source artifact,
not guest-provided output and not a configurable digest. Its exact compact JSON form is:

```json
{"boot_artifacts":{"initrd_sha256":"<64 lowercase hex>","kernel_sha256":"<64 lowercase hex>","root_disk_sha256":"<64 lowercase hex>"},"execution_mode":"reject-all-actions","profile":"leftovers-guest-rejection-only-v1","schema_version":1}
```

The host opens the artifact with no-follow semantics, requires the immutable boot-artifact owner
and exact mode, rejects non-canonical JSON, derives its SHA-256 itself, and compares the three
embedded hashes to the independently opened boot files. The derived digest is then placed in the
sealed request/manifest and must match any later result receipt. This binds the policy to a specific
guest boot image while the supervisor remains rejection-only; it is not a substitute for signed
build provenance or live boot evidence.

## Supervisor policy

`leftovers-early-init` is the initramfs `/init`; `leftovers-guest-supervisor` becomes PID 1 only
after the read-only root pivot. The supervisor receives no arguments. Before forking a worker it
verifies the root is read-only; mounts guest-only `proc`, `sysfs`, `devtmpfs`, cgroup v2, and bounded
`tmpfs` volumes; enables `cpu`, `memory`, and `pids` in the parent cgroup; writes and re-reads
`memory.max=384 MiB`, `memory.swap.max=0`, `pids.max=64`, and `cpu.max=50000 100000`; and requires
the exact raw-device arguments above. It first closes every inherited descriptor with `close_range`
and audits `/proc/self/fd`. It validates exactly the `vda`, `vdb`, and `vdc` kernel block inventory,
verifies root and request are kernel-reported read-only while scratch is writable, and rejects
aliased device identities. It then hides devtmpfs beneath a 64 KiB `nosuid,noexec` tmpfs, recreates
only mode-0600 `vdb` and mode-0400 `vdc` for UID/GID 65534, and rechecks both device identities,
read-only states, modes, owners, and the exact two-entry `/dev` inventory. The root node and every
character device are absent from the worker-visible mount.

The worker is moved into that cgroup while privileged, drops its capability bounding set, clears
keep-caps, calls `setgroups`, sets UID/GID 65534, verifies all effective/permitted/inheritable/bounding
capability sets are zero, then sets `no_new_privs`, applies a Landlock ruleset with no filesystem path
whitelist, and installs a seccomp filter denying network syscall entry points. Before that drop it
sets and reads back exact `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, `RLIMIT_CORE`, and `RLIMIT_CPU` values and
arms a non-repeating wall timer with the default fatal `SIGALRM` disposition. Landlock ABI 3 or newer
is required and `LANDLOCK_ACCESS_FS_TRUNCATE` is handled explicitly. The kernel config
independently removes the network stack, module loading, user/PID/network namespaces, BPF syscall,
core dumps, and kexec. These controls are defense in depth; they are not a claim of escape-proofing.

The controller's only wire format is implemented in
[`src/leftovers/vm_bundle.py`](../../src/leftovers/vm_bundle.py): a sealed 4,096-byte request header
and a fixed tail-region result footer. `guest_interpreter.c` independently checks the bounded LFRQ
header/table, byte caps, alignment, zero padding, whole-payload and per-section SHA-256 values,
required section names, and an independent exact action-batch parser before it considers an action.
That parser accepts only the canonical sorted top-level schema bound to the fixed provider, Terra
model, high effort, LFRQ run/round/stage, and one to 32 actions. Each action has an exact sorted field
set; duplicate/unknown/reordered keys, duplicate IDs/checks, escaped authority strings, escaped
Unicode spellings, malformed or overlong UTF-8, stage-inappropriate actions, unknown checks, and
patch-digest substitution fail. The non-authoritative finish summary accepts only strict
shortest-form raw UTF-8 plus canonical quote/backslash escapes, matching the host's
`canonical_json_bytes` output (which uses `ensure_ascii=False`); authority fields remain unescaped
ASCII. Host validation additionally requires NFC before sealing; summary text carries no guest
authority.
The exact descriptor, block, and repository inventory scans also distinguish clean `readdir` EOF
from an I/O error; incomplete enumeration is rejection, never an exact-inventory receipt.
Quoted summary text can never be reinterpreted as an action. The interpreter uses
descriptor-relative `openat2` with
`RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV`, rejects absolute/dot
paths, symlinks, hard-linked regular files, devices, FIFOs, sockets, over-large files, excessive
file counts, repository trees deeper than 32 directories, and excessive repository bytes. It has no
shell, PATH lookup, archive extractor, network API, credential lookup, or model client.

The only candidate action types are one controller-digest-bound patch and the two in-process fixed
checks `repo-tree-safety-v1` and `repo-root-regular-v1`; no action contains or selects a command
string. The current controller still emits unified-diff patch bytes while the guest source reserves
a replacement-only `LPATCH/1` record. Consequently patch application fails closed and no edit can
occur. The footer writer similarly emits only a bounded diagnostic LFRS header with no completion
marker, so host extraction rejects it. Host tests compile and execute the pure parser against quoted
action substrings, duplicate/unknown/reordered fields, Unicode escapes, excessive action counts,
unknown checks, and digest substitution; this is not guest-runtime proof. Activating writes requires
one reviewed scratch-image layout, a complete shared patch grammar, a semantic five-section LFRS
writer, parser fuzzing, and live VM evidence. The source is a hardening component, not evidence that
the guest can safely execute work.

Linux documents that `no_new_privs` prevents `execve` privilege gain, Landlock restricts filesystem
access for unprivileged processes, and cgroup v2 provides hierarchical resource controllers.  See
[no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html),
[Landlock](https://docs.kernel.org/userspace-api/landlock.html), and
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Static validation and remaining gates

Run only the no-download policy inspection locally:

```sh
sh vm/guest/check-static.sh
PYTHONPATH=src python3 -m unittest tests.test_strict_vm_guest -v
make guest-lock-check
```

Before enabling the strict runner, all of the following must be complete and independently reviewed:

1. Build and sign the pinned guest artifacts in isolated CI, then pin their SHA-256s and ownership in
   the launcher manifest.
2. Build and boot-test the early-init vda pivot plus exact vdb/vdc device contract against the current
   launcher, including absent-request failure and duplicate-argument rejection.
3. Fuzz and live-test the existing 4 KiB request-header parser, then implement the semantic
   tail-footer parser plus bounded, descriptor-only result extraction; prove malformed headers,
   partial writes, stale scratch disks, and duplicate records fail closed.
4. Complete the shared replacement-patch grammar and semantic LFRS writer, then test every allowed
   action in a disposable VM. The checked-in interpreter is source-only and remains disabled.
   Activation must also pre-open and bind the three intended descriptors before installing a
   reviewed Landlock policy; the current no-rule policy and empty descriptor table intentionally
   make the source-only interpreter unusable. The guest must validate or cryptographically bind the
   request-specific policy, check registry, mediation receipt, action cap, and check allowlist rather
   than relying only on its hard-coded global bounds.
5. Run live escape, network, cgroup exhaustion, fork bomb, file/inode, symlink, archive, timeout,
   crash/restart, and cleanup adversarial tests on the exact signed artifacts.
6. Integrate the credential-isolating model mediator and whole-cycle result verifier without exposing
   a host credential, directory share, runtime socket, or general egress.

Until then, this is mechanically verifiable source policy only.
