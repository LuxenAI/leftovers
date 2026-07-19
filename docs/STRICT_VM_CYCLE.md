# Strict-VM whole-cycle verifier (unimplemented release gate)

`leftovers.strict_vm_cycle` is a pure, hard-disabled state machine for the evidence a future
strict-VM contribution cycle would need. It has no dependency on Git, filesystem access,
subprocesses, networking, a provider, the VM launcher, or `publisher.py`. It cannot clone a
repository, call Codex, boot a VM, or publish a pull request.

`STRICT_VM_WHOLE_CYCLE_CAPABILITY` is source-level `False`; `disabled_live_cycle()` rejects before
any admission or backend work. The module is intentionally limited to deterministic offline tests
and the validation of externally collected evidence.

## Required evidence sequence

1. A controller-curated `CyclePlan` fixes one run, repository/issue, base ref/SHA, policy digest,
   exact check IDs, rounds, token cap, and UTC deadline.
2. `MediatorReceipt` and `StoppedGuestReceipt` must bind the same run, round, request digest,
   action batch digest, and canonical UTF-8 patch digest. The guest result is accepted only after
   a launcher stop proof and bounded post-stop result extraction.
3. If cleanup is not proven, the only state is `cleanup_pending`. It has no path to publisher
   approval; another controller must recover and prove cleanup independently.
4. `leftovers.strict_vm_poststop` is the separate, source-disabled implementation boundary for a
   future trusted host verifier. It accepts only the three descriptor-read, bounded, canonical
   post-stop artifacts (`result.json`, `cleanup.json`, and `canonical.patch`) after both stop flags
   are true. It rejects symlinks, hard-link aliases, replacement during reading, duplicate or deep
   JSON, any mismatch among run/epoch/request/mediator/patch identities, and a cleanup frame that
   does not prove the stopped VM resources were removed.
   The public `verify_post_stop()` has no injected-executor parameter and checks its source gate
   before inspecting any argument or path. Only the explicitly named
   `verify_post_stop_fixture()` accepts the singleton non-production fixture capability and runs
   this scaffold.
5. The fixture post-stop verifier creates a fresh disposable controller-owned Git checkout with
   global, system, hook, credential, and fsmonitor configuration disabled. It checks the planned
   base SHA before cloning and immediately after the fixed fixture check registry; it applies the
   exact patch through a fixed Git argv, independently inspects raw paths/modes and a binary diff, rejects
   escapes, forbidden paths, secret-like values, unsafe modes, oversized changes, and removes the
   clone before returning its non-authoritative receipt. A guest's claimed checks are never enough.
6. Every check must be an exact controller-registry ID and a predeclared argv tuple. The default
   executor refuses to run because an unreviewed host command is not evidence of offline execution.
   No production OS-isolated executor is supplied. Injected fixture executors and the bounded
   process helper are non-authoritative; production checks require a separately reviewed OS/VM
   boundary that denies both network access and access outside the verification clone. That
   boundary must also prove its process unit is empty after every check: process-group cleanup
   alone cannot observe a detached child that closes the capture pipes before its parent exits.
7. The host must observe the planned base SHA during re-verification and recheck it immediately
   before handoff. Any moved base, patch drift, policy-digest mismatch, failed/timed/truncated check,
   or unresolved review finding is rejected.

The scaffold can then use `create_fixture_publisher_handoff()` to produce a small, explicitly
non-authoritative `FixturePublisherHandoff` for negative-path tests. It contains the
target/base/patch/policy/check identities, but no model/guest receipt, host path, command,
credential, publisher object, or write capability. Its inputs and output are ordinary
caller-constructible Python data and must never be treated as production authorization.
`create_publisher_handoff()` always fails closed pending broker-attested, rollback-resistant
evidence. `publisher.py` remains separately responsible for its own current authorization and
remote preflight checks.

The current `vm_bundle` fixture authorization and low-level `fixture_authorization` flag are also
caller-constructible test inputs. The source-disabled epoch rejects before using them, but they must
be replaced by a separate non-production capability/type before any execution gate can be reviewed
for activation; a Boolean fixture marker is not broker authority.

## Synthetic wiring rehearsal

`leftovers.strict_vm_synthetic_rehearsal` joins the currently executable *contracts* once without
activating any of their authorities. It creates only deterministic fixture bytes in an empty,
owner-private directory, validates a non-executing pinned Codex invocation plan, validates a
synthetic provider envelope/event stream, stages an opaque digest-bound request through the
descriptor-relative broker storage primitive, reads three bounded post-stop artifacts through the
no-follow reader, and feeds receipts into the pure cycle state machine.

Caller-supplied schema and guest-source fixtures must be unaliased regular files and are opened
nonblocking/no-follow, capped before allocation, and rechecked by device/inode/size/time after the
read. The fixture root is opened relative to a retained, verified parent descriptor; its exact
basename-to-inode binding and every child directory stay open through cleanup. New directories are
registered immediately after `mkdir`, and new leaves immediately after their exclusive open, so a
later validation, write, or fsync failure cannot silently orphan an untracked child. Broker staging
uses the retained no-follow `broker-runs` descriptor rather than reopening its pathname. Cleanup
attempts every saved leaf and directory, reports all failures, and never recursively sweeps a caller
path; after child cleanup the root pathname binding is rechecked before success. A cleanup failure
takes precedence while retaining the primary operation error as its cause.

This remains fixture hardening, not a production filesystem authority. POSIX stat-then-unlink or
stat-then-rmdir is not atomic against a hostile process with the same UID. If a directory identity
cannot be observed after `mkdir`, cleanup refuses to guess and reports `cleanup unproven`; it does
not remove an unbound name. Production requires an exclusive service-owned root (and a distinct
service identity) so same-UID substitution cannot race those final name-removal operations.

It does not call the provider, launch a VM, invoke Git or a check, contact GitHub, import the
publisher, or make the compiled guest interpreter reachable. The post-stop host verification is
also deliberately not claimed: the rehearsal only exercises its descriptor artifact reader and
receipt shape; `verify_post_stop()` remains the separate future boundary that requires a reviewed
OS-isolated executor and broker authority; it currently rejects before I/O. The resulting handoff
is the existing fixture-only, capability-free value. Every production gate is asserted false before
the rehearsal begins and remains false afterward. Its private fixture directory is empty again
before success returns.

## Activation blockers

This verifier does **not** complete a production backend. Before any gate could be reviewed for
activation, Leftovers still needs a broker-owned strict-VM run directory, an authenticated
credential-isolating no-tool model mediator, a compiled guest action interpreter, trusted
host-side patch application/check execution, a platform-reviewed network- and filesystem-isolated
check executor with descendant-emptiness evidence, an exclusive service-owned verification mount
whose cleanup cannot race an inode replacement, durable cleanup recovery, and live adversarial
escape/resource/cleanup evidence with remote writes disabled. Even with those proofs, it must not
claim absolute escape-proofing.
