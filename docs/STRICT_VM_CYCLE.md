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
4. A trusted host verifier, outside this scaffold, must apply the exact canonical patch in a
   fresh controller-owned checkout, compute the independent diff digest, enforce the frozen policy,
   execute every fixed curated check, and resolve every review finding. Its result is represented by
   `IndependentHostReceipt`; a guest's claimed checks are never enough.
5. The host must observe the planned base SHA during re-verification and recheck it immediately
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

## Activation blockers

This verifier does **not** complete a production backend. Before any gate could be reviewed for
activation, Leftovers still needs a broker-owned strict-VM run directory, an authenticated
credential-isolating no-tool model mediator, a compiled guest action interpreter, trusted
host-side patch application/check execution, durable cleanup recovery, and live adversarial
escape/resource/cleanup evidence with remote writes disabled. Even with those proofs, it must not
claim absolute escape-proofing.
