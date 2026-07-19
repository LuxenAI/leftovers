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
  -> rejection-only PID 1 supervisor (this tree)
  -> non-root worker with no request parser or result writer
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
outside the VM and must never give the guest its credentials. This scaffold opens neither device and
does not parse a request or emit a result.

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
the exact raw-device arguments above.

The worker is moved into that cgroup while privileged, drops its capability bounding set, clears
keep-caps, calls `setgroups`, sets UID/GID 65534, verifies all effective/permitted/inheritable/bounding
capability sets are zero, then sets `no_new_privs`, applies a Landlock ruleset with no filesystem path
whitelist, and installs a seccomp filter denying network syscall entry points. The kernel config
independently removes the network stack, module loading, user/PID/network namespaces, BPF syscall,
core dumps, and kexec. These controls are defense in depth; they are not a claim of escape-proofing.

The controller's only wire format is implemented in
[`src/leftovers/vm_bundle.py`](../../src/leftovers/vm_bundle.py): a sealed 4,096-byte request header
and a fixed tail-region result footer. This scaffold deliberately implements neither parser nor
writer. It leaves scratch without a host-acceptable footer, so bounded host extraction rejects it.
There is no archive extractor, path resolver, shell, Python runtime, package manager, fixed check
registry, or executable action interpreter. A future implementation must use the controller format
unchanged, fuzz its total parser, use descriptor-relative `openat2` with
`RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS`, reject hard links/devices/symlinks and
path traversal, and execute only controller-owned fixed argv arrays.

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
3. Implement and fuzz the existing 4 KiB-header/tail-footer parser plus bounded, descriptor-only
   result extraction; prove malformed headers, partial writes, stale scratch disks, and duplicate
   records fail closed.
4. Add a narrow action interpreter, safe archive/path handling, and controller-owned fixed checks;
   then test every allowed action in a disposable VM.
5. Run live escape, network, cgroup exhaustion, fork bomb, file/inode, symlink, archive, timeout,
   crash/restart, and cleanup adversarial tests on the exact signed artifacts.
6. Integrate the credential-isolating model mediator and whole-cycle result verifier without exposing
   a host credential, directory share, runtime socket, or general egress.

Until then, this is mechanically verifiable source policy only.
