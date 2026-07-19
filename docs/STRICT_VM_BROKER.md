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
`DurableBrokerAcknowledgement` transaction to persist the request/reply binding and its root-owned
journal witness before sending any reply; a failed witness produces no acknowledgement. That
interface is deliberately not a live journal/service implementation. Production does not fall
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
- a root-owned, fsync-confirmed rollback witness updated with every journal append, with crash,
  torn-write, valid-prefix rollback, and storage-backend recovery evidence;
- parsing the staged LFRQ through a no-follow descriptor and requiring its internal run ID and
  broker-attested authorization to match the broker-generated allocation;
- live adversarial VM resource, escape, crash, and cleanup evidence with remote writes disabled.

## Durable-state model

`leftovers.strict_vm_broker_journal` adds a second, also non-runnable model for the broker's
private persistence boundary. It accepts no file path, run directory, command, or argv. Its only
storage interface is a future broker-owned `commit_fsynced(record, next_anchor)` primitive. It must
make the record and matching root-owned rollback witness durable as one crash-consistent commit
before returning; a separate append followed by an anchor write is inadequate. Every canonical record
is hash-chained; the genesis record binds the installed broker/controller UID pair, the mandatory
`0700` private-root contract, and the immutable launcher/kernel/initrd/root-disk/guest-policy
identity. A separate root-owned rollback witness must carry the exact record count, genesis digest,
and head digest. Recovery rejects a missing/torn chain, a substituted boot identity, or a valid old
prefix that disagrees with that witness.

Recovery retains allocation request IDs, token reservations, and the persisted monotonic floor before
a new allocation is admitted. An incomplete upload is appended as
`quarantined` on restart rather than resumed: the staged file might be torn or replaced, so its lease
is not reusable. Token reservations are bounded, linked to the staged request digest, and remain
reserved until a later separately authorized settlement. The model explicitly rejects a regressed
monotonic epoch rather than treating reboot/restart time as trustworthy.

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

Descriptor retention narrows pathname races but cannot remove the final same-UID name-removal race
inside this fixture. The future distinct-UID/exclusive-root service boundary is mandatory, and even
that does not make Virtualization.framework or any host absolutely escape-proof.
