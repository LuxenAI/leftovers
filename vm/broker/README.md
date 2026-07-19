# Source-disabled native macOS broker trust adapter

`NativeBrokerTrustAdapter.swift` is a compile-checked outline of the native
trust boundary that the Python contracts in
`src/leftovers/strict_vm_broker_installation.py` cannot provide. It is not a
broker service. It cannot install or load a LaunchDaemon, register or bind a
Mach service, create an XPC listener, launch a VM, or enable a Python gate.

The only runnable interface is:

```sh
sh vm/broker/check.sh
```

That command compiles the Swift source against the locally installed macOS SDK,
then invokes `--self-check`. The program exits `78` after proving its source
gate rejects *before* manifest, account, Security.framework, or XPC access.
The check fails if compilation or that ordering proof fails.

## Fixed policy surface

The source fixes, rather than accepts as input:

- the System LaunchDaemon domain, broker label/Mach service, executable/plist
  names, and `ProgramArguments` (`--serve`);
- a root-owned manifest directory and filename;
- descriptor-relative `openat(..., O_NOFOLLOW)` acquisition, local-volume,
  regular-file, root owner, exact `0444`, one-link, ACL, fstat-before/after,
  and retained-ancestor requirements. The ordinary `/`, `/private`,
  `/private/var`, and `/private/var/db` descriptors must remain local,
  root-owned, ACL-free, and not group/other writable; the fixed
  `leftovers/strict-vm` install subtree must additionally have no write bits
  and carry a user- or system-immutable flag;
- Security.framework extraction and comparison of exact designated-requirement
  bytes, Team ID, signing ID, a nonempty observed CDHash set wholly contained
  in the manifest rotation allowlist, and the exact entitlement key/value map;
- dedicated runtime UID/GID, account/group, `/usr/bin/false`, `/var/empty`,
  and no-supplemental-groups facts; and
- `SecCodeCreateWithXPCMessage`, the public SDK API that derives a peer
  `SecCode` from the connected XPC message audit token, never a PID, path, or
  caller-supplied digest.

The inactive implementation has no manifest parser or installation procedure,
so it cannot accidentally treat a configuration file or test fixture as
authority. A later activation must make the parser, root-owned install,
descriptor retention/revalidation, account creation, and live XPC adversarial
tests separately reviewable.

Descriptor owners poison their stored integer before calling `close(2)`.
Acquisition removes the complete retained-directory set from live ownership,
attempts every close exactly once, and fails the operation if any close fails;
the manifest's explicit `withOpenDescriptor` scope likewise propagates close
failure before returning its body result. `deinit` cannot throw, so
`OwnedDescriptor` retains one best-effort, poison-before-close fallback solely
for abandoned objects. Normal acquisition and verification do not rely on it.

## SDK evidence and residual blockers

The local Xcode 26.5 macOS SDK declares the APIs used here in:

- `Security.framework/Headers/SecCode.h`: `SecCodeCopySelf`,
  `SecCodeCopySigningInformation`, `SecCodeCopyGuestWithAttributes`, and
  `SecCodeCreateWithXPCMessage`;
- `Security.framework/Headers/SecRequirement.h`: stable designated-requirement
  byte extraction/reconstruction; and
- `usr/include/{sys/acl.h,sys/fcntl.h,sys/mount.h}`: descriptor ACL,
  `openat`, and local-volume primitives.

`SecurityFlagValues.c` compile-time assertions bind every numeric
`SecCSFlags` literal used by the Swift importer workaround to those official
SDK declarations. `check.sh` fails if either that C probe or the Swift source
does not compile.

`xpc_connection_get_audit_token` is **not** declared by that SDK. This adapter
does not fake or dynamically look up that private/non-SDK symbol. Instead it
uses the SDK-declared `SecCodeCreateWithXPCMessage` path. Direct connection-
token extraction, if later considered necessary, is a blocking SDK capability
gap and must make the integration check fail until an official declaration is
available.

Likewise, the public headers available here do not expose an independently
verifiable `CS_DEBUGGED` code-status constant. The scaffold rejects the
debugger entitlement when present, but a future requirement to prove live
debug-state needs a separately documented official API; it must not be
approximated with PID/path inspection.
