# Agent protocol

## Inputs and authority

Each prompt contains two source-tagged JSON envelopes:

- `trusted_task_envelope`: immutable target identity, base SHA, change limits, forbidden paths, and
  operator-curated verification commands;
- `untrusted_sources`: issue content, repository instruction files, prior model output, diffs, and
  command records.

The prompt is defense in depth. Enforcement belongs to the controller and runtime broker; words in a
prompt never grant a capability.

## Stages

### Planning

The repository is read-only. The agent returns `planned`, `blocked`, or `failed`, with acceptance
criteria, reproduction evidence, root-cause evidence, ordered steps, tests, risks, remaining budget,
and stop conditions.

### Implementation

The repository is writable but `.git` is read-only in the container profile. The agent follows only
the approved plan and returns `implemented`, `blocked`, or `failed`. Its command claims are advisory;
controller-captured verification is authoritative.

### Verification and review

The controller runs only repository-manifest argv arrays offline. A fresh review context receives the
frozen diff and captured results, returning `approve`, `revise`, or `abandon`. `revise` can loop only
up to `agent.max_repair_cycles`; any remaining finding fails the run.

### Draft-PR text

The unattended execution path does not ask a model to write publishable copy. After approval, the
controller deterministically renders the title and body from the issue number, canonical diff
statistics and file list, controller-captured check ordinals/exit status, independent-review status,
and a fixed AI-assistance disclosure. Local command argv and free-form logs are excluded from the
public body. It bounds and sanitizes those fields before the publisher receives them.

The repository retains a `pr-writer` prompt/result schema as a legacy or non-publishing experiment.
Its free-form output is not part of the run path and cannot be supplied to the publisher.

## Output and telemetry transport

The runner sets `LEFTOVERS_RESULT_PATH` and `LEFTOVERS_TELEMETRY_PATH`. Every stage must write one
strict result JSON object; stdout is non-authoritative and bounded/redacted. When configured, the
adapter also appends protocol-v1 NDJSON telemetry: one identity check-in, ordered heartbeats, and at
most one final usage receipt. The runner bounds and validates both transports before accepting them.
Schemas under [`schemas`](schemas) document the contracts. A missing, malformed, stale, reordered, or
identity-mismatched required record fails the stage.

Usage evidence is explicitly qualified as provider response, broker-attested, adapter-reported,
estimated, synthetic, or unavailable. Adapter-reported identity is not cryptographic attestation.
Controller heartbeats show process supervision; they do not prove the provider/model is responsive.
See [`docs/TELEMETRY.md`](docs/TELEMETRY.md) for dashboard aggregation semantics.

## Failure codes

Stable codes include `budget_exhausted`, `policy_denied`, `no_candidate`, `no_reproduction`,
`test_failed`, `review_rejected`, `upstream_moved`, `rate_limited`, `auth_failed`, `publish_partial`,
`cleanup_failed`, `runtime_unavailable`, `agent_failed`, and `invalid_output`.

No model can convert a failure into a publication. A future resume implementation must reconcile by
`run_id + repository + issue + base_sha` before making any remote mutation.
