# Dedicated strict-VM broker (unimplemented release gate)

`leftovers.strict_vm_broker` defines a narrow, **hard-disabled** protocol for the missing host
trust boundary between a controller account and the immutable strict-VM launcher.
`leftovers.strict_vm_broker_service` now makes parts of the future service boundary executable only
through explicitly fixture-named APIs and an issued `FixtureBrokerServiceCapability`:
descriptor-relative request storage, bounded one-frame Unix-socket I/O, a Darwin
peer/signature-verification interface, fixed resource policy, and exact run cleanup. The public
production `StrictVMBrokerServiceCore` constructor, dispatcher, and launcher-plan method all check
the source gates before inspecting a peer, dependency, descriptor, or durable state, then remain
unimplemented. The module does not bind a socket, create a run directory in production, invoke the
launcher, install a service, or change any host permissions.

The need is specific: a controller-owned `0700` directory is not enough when the controller and
an attacker can run as the same macOS UID. The attacker can race an apparently sealed request or
scratch path between validation and the launcher opening it. A production broker therefore must be
installed under a distinct dedicated service UID, own the service root and every run directory, and
admit only a separately approved controller UID through Darwin `getpeereid` credentials.

`getpeereid` distinguishes Unix users, not malicious processes sharing the approved controller UID.
That is intentional: the dedicated broker removes their ability to replace broker-owned filesystem
paths, while the still-missing controller authorization receipt must bind any accepted request to the
mediator's allowed actions and checks. The protocol alone is not authorization to run arbitrary input.

The new code-signature interface makes that remaining gap explicit. A production Darwin verifier
must obtain the connected peer's audit-token/process identity, verify its Security.framework
designated requirement, and bind it to an installed Team ID plus requirement digest. It must do so
before reading controller-provided frame bytes. The current Python code provides no implementation
of that verifier and does not treat a boolean, UID, executable path, or controller-supplied hash as
such evidence.

## Prepared protocol, not an execution interface

The framed Unix-socket protocol is integrity-bound and canonical. It allows only two operations:

1. `allocate` returns a broker-generated opaque allocation ID, lease token, and 32-hex run ID.
   The controller never names a directory.
2. `append_request` streams canonical base64 chunks capped at 64 KiB. The broker binds the sequence,
   peer, allocation request ID, monotonic 120-second lifetime, 4,096-chunk and total 256 MiB caps,
   nonempty final payload, and final SHA-256 before
   considering the request staged. The broker retains accepted allocation request IDs for that
   lifetime and caps pending/replay state, so a replay cannot create unbounded concurrent epochs.

Frames have no `path`, `argv`, command, mount, environment, network, credential, boot-artifact, or
publish-target field. Unknown fields and unknown operations are rejected. Replay, stale allocation,
wrong peer credentials, noncanonical JSON/base64, invalid digest, out-of-order chunk, oversized
frame, and concatenated/truncated frame all fail closed.

The broker installation itself contains the immutable launcher and boot identity. A future service
must build its own manifest using descriptor-relative creation in a broker-owned run directory,
rehash its immutable launch/boot artifacts through pre-opened descriptors (with immutable owner,
single-link identity, `FD_CLOEXEC`, and no writable mode bits), and invoke only:

```text
<installed strict-vm-launcher> --run <broker-generated manifest path>
```

That argv is intentionally unavailable from the scaffold. The controller cannot ask the broker to
run an arbitrary executable or path.

Fixture-only `FixturePrivateRunRoot` accepts only a broker-owned `runs` directory descriptor whose
owner and exact `0700` mode are checked. It creates the broker-generated `run_id` child using
`mkdirat`, opens it with `O_NOFOLLOW`, and writes only `request.lfrq` with
`O_CREAT|O_EXCL|O_NOFOLLOW`, exact `0600` mode, digest binding, and `fsync`. Cleanup records the
created directory's device/inode, reopens the name relative to the private root, and compares both
the reopened and held descriptor identities before unlinking or removing anything. A rename plus
same-name replacement present at either identity check fails closed without touching either request
tree. Portable POSIX `rmdir` remains a name operation: a hostile same-UID process can still race a
replacement after the final check. The fixture is therefore not cleanup authority; production
requires a distinct-UID, exclusive broker-owned root. Cleanup never recurses or sweeps a
controller-named path. These primitives are unavailable without the fixture capability and are not
wired to a listener while the release gates are false.

The fixture dispatcher reads one bounded canonical frame, asks Darwin `getpeereid`, verifies the
installed controller signature binding, then parses the frame. It performs no inherited-environment
forwarding and its launcher-plan fixture has fixed memory, vCPU, request, scratch, and wall-clock
limits. Cancellation during a partial frame yields no reply. It also requires a broker-private
`DurableBrokerAcknowledgement` transaction to persist the request/reply binding in a complete,
fsynced inactive journal slot before sending any reply; an ambiguous slot write produces no
acknowledgement and requires recovery. That interface is deliberately not a live journal/service
implementation. Production does not fall
through to this fixture dispatcher. All four source gates remain false:
`STRICT_VM_BROKER_SERVICE_ENABLED`, dedicated-UID evidence, code-signature evidence, and live
cleanup evidence.

## Activation blockers

`STRICT_VM_BROKER_ENABLED` is a source-level `False`, and `StrictVMBrokerService.start()` fails
before a socket or directory is created. Do not enable it from configuration. Separate review must
first provide all of the following:

- a signed, root-owned launchd installation and a dedicated non-controller broker UID;
- a socket permission/ACL design, a Security.framework audit-token/designated-requirement verifier,
  and live `getpeereid` tests, including same-UID race attempts;
- descriptor-relative, no-follow request/manifest/scratch creation plus exact cleanup/recovery;
- immutable boot-artifact provenance and rehashing immediately before launcher use;
- mediation-receipt binding to the accepted request and independently verified post-stop result;
- broker-owned durable replay/allocation and token-ledger journals that survive daemon restart;
- a source-disabled, descriptor-relative two-slot journal backend with crash, torn-write,
  journal-ahead, witness-ahead, disk-full/sync-failure, and lost-reply recovery evidence;
- a separate root/external rollback anchor: two local broker slots cannot detect a compromised
  broker or storage authority rolling both slots back;
- parsing the staged LFRQ through a no-follow descriptor and requiring its internal run ID and
  broker-attested authorization to match the broker-generated allocation;
- live adversarial VM resource, escape, crash, and cleanup evidence with remote writes disabled.

## Durable-state model

`leftovers.strict_vm_broker_journal` adds a second, also non-runnable model for the broker's
private persistence boundary. It accepts no file path, run directory, command, or argv. It does
**not** claim that an append log and a separate witness can be atomically committed across files.
Instead, its future broker-owned storage contract reads two complete slot images and writes/fsyncs
only the inactive slot. Each image embeds the canonical record chain, its count/head/genesis
boundary, generation, and a digest over all of them. Recovery validates both independently and
selects the newest complete image; it can discard a torn/corrupt slot, a journal-ahead slot with a
stale embedded witness, or a witness-ahead slot with stale records without wedging a valid prefix.
The digest is streamed over length-prefixed records rather than hex-encoding an entire image in
memory. The model limits a slot to 128 records and 4 MiB; it deliberately has no compaction or
storage backend. An invalid pair, a two-generation gap larger than one, or two different valid
images at the same generation fails closed.

A failed slot write is deliberately ambiguous: storage may have become durable just before it
returned an error. The live broker therefore returns no acknowledgement and enters
`recovery_required`; it must serve nothing else until restart recovery chooses a verified slot. A
same-boot allocation is idempotent by its installed-peer/request-ID pair **only** while it has zero
accepted bytes and has not expired. This lets a crash after durable allocation commit but before
reply return the exact persisted value without a second run. A partially uploaded, staged,
quarantined, or expired allocation is never returned as a fresh idempotent allocation. This is a
pure state-machine contract, not a filesystem backend or live durability proof.

Two broker-owned slots are crash consistency and controller-UID isolation machinery, **not**
rollback resistance against a compromised broker or storage administrator: an attacker who can
replace both with a valid older pair is outside this model. A distinct root/external monotonic
authority is a separate activation blocker. Every canonical record remains hash-chained; genesis
binds the installed broker/controller UID pair, mandatory `0700` private-root contract, and
immutable launcher/kernel/initrd/root-disk/guest-policy identity.

Recovery requires a `BrokerBootSessionEvidence` digest from the future native adapter. The current
Python representation is caller-constructible fixture data and cannot authorize anything. With the
same digest it retains an untouched zero-byte allocation but quarantines every partial/staged
request. With a changed digest it first durably quarantines all pending work, preserves request IDs
and token reservations conservatively, then records a boot-rollover event and begins a new monotonic
epoch. The model otherwise rejects a regressed monotonic epoch rather than trusting reboot/restart
time. A live adapter that derives and attests this OS boot-session identity remains an activation
blocker.

The future filesystem adapter must open staged LFRQ bytes **relative to a broker-owned directory
descriptor**, with no-follow semantics and post-open identity verification. The model accepts only
that descriptor-shaped reader; it has no `Path` constructor. Its sole exposed helper is named
`observe_unverified_lfrq_header`: it binds a claimed internal run ID before the admission path
unconditionally refuses, but it does not validate payload data, a complete section table, a request
digest, or authorization. A `broker` mediation authority is still rejected because no unforgeable
broker-attestation verifier exists. Fixture authority is never an executable broker admission either.
Request staging is unavailable until `vm_bundle` gains a descriptor-native full parser.

The current in-memory replay guard is still only a protocol model. Restarting a future daemon must
never clear accepted request IDs or token reservations, and `getpeereid` alone cannot distinguish a
legitimate controller from a malicious process running under the same approved controller UID.
Production therefore also needs an unforgeable mediator/broker capability or a code-signature-bound
IPC design; caller-constructed hashes are not authorization.

## macOS installation and XPC peer contract

`leftovers.strict_vm_broker_installation` is a separate, source-disabled pure contract for the
missing installation boundary. It does not create a plist, read a path, bind an XPC service, or
change accounts. Its canonical root-owned manifest binds the distinct broker/controller UIDs and
account names and UID/GID, Team ID, broker/controller signing identifiers, stable
designated-requirement bytes and SHA-256 values, ordered broker/controller CDHash sets, the
required client entitlement, broker protocol/schema versions, immutable
launcher/kernel/initrd/root-disk/guest-policy digests, fixed relative boot-artifact role names,
the exact broker executable/plist/Mach-service identity, and the exact fixed resource profile.
Unknown manifest fields, a non-root owner/mode, duplicate or reordered CDHashes, a substituted
requirement digest, an absolute/caller-selected boot name, and any non-exact identity/profile fail
closed.

Before accepting its canonical digest, a future native adapter must collect no-follow descriptor
evidence for a regular, root-owned `0444`, single-link manifest on a local volume: stable
device/inode/size/mtime/ctime before and after the read, no nontrivial write ACL, and an identical
root-to-parent ancestor chain of no-follow, local, root-owned, non-writable, immutable directories
without write ACLs. The Python structures model those required facts but do not inspect a path or
prove them. A pathname, `stat` snapshot without stable re-observation, symlink, hard link, writable
ancestor, network volume, or ACL ambiguity must fail in the future native adapter.

The manifest is intentionally **not authority**: every Python value remains caller-constructible.
The future privileged native adapter must obtain it through an already-open root-owned descriptor,
verify its canonical digest, then obtain controller identity from a connected XPC audit token and
Security.framework. Before it even obtains peer data, that adapter must prove the broker's own Team
ID, signing ID, requirement bytes/digest, allowed broker CDHash, and non-ad-hoc/non-debug state;
then it must prove a distinct runtime account with exact UID/GID/account/group, `/usr/bin/false`
shell, no home directory, and no supplemental groups. Account spelling, including a leading
underscore convention, is not itself trusted or prescribed by this contract.

The pure peer validator requires XPC audit-token-derived evidence and exact UID, Team ID, signing
ID, requirement bytes/digest, allowed controller CDHash, and entitlement values. It requires the
installed client entitlement to be explicitly `true` and rejects either `get-task-allow` or the
debugger entitlement even if represented as `false`; PID-only, path-only, ad-hoc, debugged,
wrong-ID, missing-entitlement, and wrong-CDHash forms are rejected. `verify_installed_xpc_peer()`
is source-disabled before it can consult an adapter, path, or XPC connection. It cannot be enabled
by TOML, a plist, or a fixture.

The same module provides only an in-memory static plist fixture and validates a narrowly fixed
System LaunchDaemon shape: system domain, dedicated `UserName`/`GroupName`, `Umask` `077`, one
fixed Mach service, fixed `ProgramArguments`, and no extra fields. This rejects environment,
socket, or keepalive ambiguity. A future macOS implementation still needs a separately reviewed
root-owned installation procedure, XPC/audit-token adapter, code-signature API integration,
descriptor-stable install verification, and live same-UID adversarial evidence. No pure contract
can establish those runtime facts or make the VM absolutely escape-proof.

Descriptor retention narrows pathname races but cannot remove the final same-UID name-removal race
inside this fixture. The future distinct-UID/exclusive-root service boundary is mandatory, and even
that does not make Virtualization.framework or any host absolutely escape-proof.
