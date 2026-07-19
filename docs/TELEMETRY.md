# Telemetry and dashboard semantics

Leftovers exposes a local, read-only operations dashboard. Its purpose is observability, not control:
the dashboard cannot start work, change policy, release a reservation, publish a pull request, or
modify state. Budget and publication ledgers remain authoritative even when telemetry is unavailable.

## Metrics that must not be conflated

The UI and API keep these values separate:

- **Window maximum** is an explicit provider-reported ceiling or operator allocation. It is unknown
  when `budget.maximum_tokens` is not configured; it is never inferred from another field.
- **Provider remaining** is the latest quota snapshot supplied by the configured adapter, environment,
  or manual override.
- **Reserve floor** is the amount intentionally withheld from Leftovers.
- **Spendable** is `max(0, provider remaining - reserve floor)`.
- **Reserved** is local admission capacity held by non-released run reservations in the current
  reset window. A reservation is not model usage.
- **Known used** is the sum of accepted model usage receipts. Unknown or missing usage is `null`,
  never zero.
- **Coverage** reports how many finished invocations have exact usage. Training usage is always
  isolated from production totals and labeled `synthetic`.

Planning estimates are safety inputs, not bills. Post-hoc adapter reports cannot enforce a hard
provider limit. A hard token ceiling requires a provider request limit or a credential-holding broker
outside the worker that can stop inference before the cap is exceeded.

## Model check-in protocol

Every agent invocation receives `LEFTOVERS_TELEMETRY_PATH`. An adapter can append protocol-v1 NDJSON
events described by [`schemas/adapter-telemetry.schema.json`](../schemas/adapter-telemetry.schema.json):

1. exactly one `checkin`, as sequence 1, with provider, model, adapter version, capabilities, and a
   timezone-aware timestamp;
2. zero or more ordered `heartbeat` events; and
3. at most one final `usage` receipt with normalized non-negative token counts and an evidence source.

The runner bounds file size, line size, event count, JSON complexity, timestamps, sequences, and
integer ranges. A reported provider/model mismatch is fatal. When `agent.checkin_required` or
`agent.usage_reporting_required` is enabled, an omitted record is also fatal. A check-in written by
the worker is `adapter_reported`, not cryptographic model attestation; `broker_attested` is reserved
for an external broker boundary.

Usage sources are:

- `broker_attested` — exact receipt from an external credential-holding broker;
- `provider_response` — exact usage from a provider response;
- `adapter_reported` — adapter assertion without a stronger trust boundary;
- `estimated` — explicitly inexact;
- `synthetic` — deterministic rehearsal data; and
- `unavailable` — no numeric usage was accepted.

## Telemetry storage

`telemetry.sqlite3` is a safe-field projection. It stores run identifiers, bounded state codes,
stage transitions, model invocation lifecycle, qualified usage, cleanup status, and timestamps. It
does not store issue bodies, prompts, diffs, repository files, command output, arbitrary exception
text, credentials, or filesystem paths.

The controller writer uses short rollback-journal transactions, foreign keys, and monotonic per-run
event sequences. Dashboard readers open SQLite in read-only query mode and never migrate or create
files.
Telemetry failure is fail-closed for the dashboard but cannot grant work or publication authority.
The redacted hash-chained audit journal remains the security record.

## HTTP boundary

`leftovers dashboard` binds to a literal loopback address only. It rejects wildcard and non-loopback
binds, unexpected `Host` or `Origin` headers, mutation methods, oversized targets, unrecognized
routes, and unsafe query values. Responses have no CORS opt-in, are `no-store`, and include a strict
same-origin Content Security Policy plus clickjacking, referrer, MIME-sniffing, opener, resource, and
permissions protections.

The API exposes only bounded, allowlisted projections:

- `/api/v1/summary`
- `/api/v1/runs`
- `/api/v1/runs/<run-id>`
- `/api/v1/models`
- `/api/v1/health`

Use SSH port forwarding for remote viewing rather than binding the dashboard to a LAN or public
interface. Run it without GitHub or provider credentials.

Exact launch command:

```sh
PYTHONPATH=src python3 -m leftovers --config config/leftovers.toml \
  dashboard --host 127.0.0.1 --port 8765 --workers 4
```

The database must already exist and pass ownership, mode, schema-version, and integrity checks. The
command never creates or migrates it. Host is restricted to `127.0.0.1` or `::1`, port to
`1..65535`, and workers to `1..32`. This repository intentionally does not include a public hosting
path: the UI has no login/TLS layer and displays private operational metadata.

## Rehearsal data

`leftovers training-run` creates a controller-owned local Git fixture and can never publish. Its
budget ledger, telemetry, and workspaces live under separate rehearsal subdirectories. The
deterministic adapter exercises planning, implementation, offline verification, independent review,
approval, model check-in, synthetic usage, and proven cleanup.

Process-mode rehearsal is supplemental. For sandboxed local QA it must be wrapped in an
operating-system sandbox; `--profile none` is an explicitly unwrapped diagnostic used only to
exercise contract and lifecycle behavior. Container mode is the stronger deterministic rehearsal:
it uses the real runner, read-only root filesystem, no network, dropped capabilities, read-only
planning/review mounts, read-only `.git` during implementation, resource limits, ownership labels,
and label-scoped cleanup. It still shares the host kernel and is not production-isolation evidence.
Synthetic rehearsal usage never appears in production totals.

Build and execute the OCI rehearsal with:

```sh
make rehearsal-image
PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml \
  training-run --mode docker --image leftovers-rehearsal:local \
  --profile auto --report .leftovers/rehearsal-report.json
```

Every invocation uses a new root under `<state_dir>/rehearsals/`. `--profile auto` resolves to
`oci-container` for Docker/Podman, `macos-seatbelt-supplemental` for process mode when the macOS
wrapper is present, or `unsandboxed-process-supplemental` otherwise. The resolved value is included
in stdout and the optional owner-only report. A process pass proves contract/lifecycle behavior only.
