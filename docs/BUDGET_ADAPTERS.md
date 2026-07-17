# Budget adapters

## Contract

A budget snapshot must provide:

```json
{
  "remaining_tokens": 150000,
  "spendable_tokens": 130000,
  "reserve_tokens": 20000,
  "confidence": "manual",
  "source": "fixed-envelope",
  "observed_at": "2026-07-17T16:00:00Z",
  "resets_at": "2026-07-18T00:00:00Z"
}
```

Start only when:

```text
spendable >= max(minimum_spendable, estimated_tokens_p95 * safety_multiplier)
```

Token estimates must include planning, implementation, review, repair loops, and tool output. Draft
PR text is controller-rendered and consumes no model budget. `spendable_tokens` is calculated after
subtracting `reserve_tokens`; do not add the reserve again when evaluating the start condition.

The snapshot must be fresh, fall inside the current configured reset window, and leave at least
`budget.max_run_seconds + budget.reset_safety_seconds` before `resets_at`. The controller applies the
same `max_run_seconds` as a monotonic run-wide deadline to agent and verification stages. This bounds
local work near reset; it still cannot cancel a provider request that ignores its own timeout.

This is admission accounting, not a hard usage limiter. The runner does not observe provider billing
in real time and cannot terminate a request exactly at the reserved token count. The planning-stage
estimate check is another fail-closed estimate, not metering. Configure a provider-side maximum or
an external broker cutoff whenever the provider exposes one, and keep the reserve large enough for
uncertainty.

## Stateful reservations

An execute run reserves `estimated_tokens_p95 * safety_multiplier` in
`<state_dir>/budget.sqlite3` before creating a workspace. The SQLite transaction sums every
non-released reservation in the configured daily or weekly window, using `budget.timezone`,
`reset_hour`, and (for weekly windows) `reset_weekday`. This prevents two scheduler invocations from
treating one fixed/manual snapshot as independently spendable.

Reservation rejects snapshots observed more than five minutes ago, snapshots from a different reset
window, and windows whose remaining horizon is shorter than the configured run deadline plus safety
margin. This check is repeated transactionally so a long discovery phase cannot race the reset.

Reservations are deliberately conservative in v0.1: completion, dry-run failure, and partial
publication all retain the reservation for that window. There is no automatic reconciliation to
actual provider usage and no automatic release command. Inspect the hash-chained run journal and the
ledger before any manual database recovery; never delete the state file merely to force another run.
Each invocation selects and attempts at most one issue.

## Shipped sources

### Fixed envelope

`budget.source = "fixed"` is an explicit allocation, not a reading of the provider account. It is
appropriate for a schedule that intentionally permits up to a known daily/weekly amount.

### Environment/manual snapshot

`budget.source = "environment"` reads a non-secret integer from
`budget.remaining_tokens_env`. Populate it from a person or a provider's supported usage/quota API.
`--remaining-tokens` overrides it for one run.

Missing, malformed, or negative values fail closed.

## Not supported

- Scraping a consumer account's web UI.
- Treating RPM/TPM/message limits as prepaid remaining tokens.
- Assuming API billing consumes a ChatGPT/Codex/Claude subscription allowance.
- Inferring exact remaining quota from local transcripts or tokenizers.
- Driving the balance to zero. Retries, caching, tool calls, and provider accounting are uncertain.

An official-provider adapter should be added only when supported documentation defines scope,
latency, reset semantics, and units. It must never request a broader credential than the model client
already needs.
