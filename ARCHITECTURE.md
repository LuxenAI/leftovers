# Architecture

## Design objective

Leftovers is a bounded contribution control plane. A scheduler may wake it near a daily or weekly
quota reset, but work begins only when a supported budget adapter or a deliberate local envelope says
there is enough spendable capacity and enough time remains before reset for the configured run-wide
deadline plus safety margin. Quota changes analysis depth; global and per-repository PR caps must
remain small.

The local budget gate and SQLite reservations are conservative admission accounting. They do not
meter provider calls, impose a hard token ceiling, or replace a supported provider-side cutoff.

## Trust zones

1. **Controller:** trusted configuration, budget policy, state machine, scoring, and audit journal.
2. **Discovery:** read-only GitHub REST/GraphQL access. It cannot mutate GitHub.
3. **Acquisition:** obtains one public repository at an immutable base revision without executing it.
4. **Worker:** agent edits one ephemeral workspace; it has no GitHub write credential.
5. **Verifier/reviewer:** runs curated commands offline and reviews a frozen diff in a fresh context.
6. **Publisher:** deterministic controller code that briefly accesses the user's authenticated `gh`
   identity after all gates pass.
7. **Audit store:** controller-write-only redacted records with a SHA-256 hash chain.
8. **Telemetry projection:** controller-written safe fields in a separate SQLite database. It is
   non-authoritative and omits prompts, diffs, logs, credentials, paths, and arbitrary errors.
9. **Dashboard:** physically read-only telemetry reader and loopback HTTP server. It has no command,
   budget-ledger, publication-ledger, or GitHub mutation interface.

The existing local Docker/Podman and host-agent paths are rehearsal-only. Production admission
rejects them before budget, discovery, or acquisition. Docker Sandboxes (`sbx`) is the active
integration candidate, but its boundary facade is source-disabled and its compatibility rehearsal
is shell-only: it performs no provider or Terra/high call. The custom
Virtualization.framework launcher is archival source-disabled research, not an operator activation
path. Neither candidate changes the non-overridable production gate.

## Lifecycle

```text
scheduled -> budget_check -> discovering -> scoring -> selected -> preflight
          -> sandbox_ready -> planning -> implementing -> verifying -> reviewing
          -> approved -> publishing -> pr_open -> cleaning -> complete
```

Alternate outcomes are:

- `deferred`: unknown/insufficient quota or a temporary upstream/rate condition;
- `skipped`: no eligible candidate;
- `aborted`: a policy, scope, integrity, or upstream-state violation;
- `failed`: agent, command, or publication failure;
- `cleanup_pending`: local disposal could not be proven.

Any run that creates a workspace enters cleanup from a `finally` path. A published PR is not complete
until every exactly labeled run container is removed and verified absent, followed by marker-checked
workspace deletion. If container cleanup cannot be proven, the bound workspace is retained.

Every production and training run is tagged at creation. Model invocations record expected and
adapter-observed identities, lifecycle timestamps, controller/adapter heartbeats, and qualified
usage receipts. Training uses a separate controller-owned fixture, synthetic usage, unique state and
workspace roots, and a publisher-free issue source. Its admission requires exact attestations for
the fixture runner, issue source, and lease factory; it also requires the fixed deterministic model
identity, no network or environment forwarding, no repair loop, and dry-run publication. UI grouping
never makes synthetic usage part of production quota totals.

## Candidate policy and scoring

Hard gates run before model judgment: allowlisted active licensed repository, current AI/bot policy
explicitly approved by the curator, issue open/unassigned/unlocked, no open linked/cross-referenced
PR, allowed labels, denied labels absent, recognized test commands, and score over threshold.

For an explicitly publishing run, selection also performs a read-only local publication preflight.
Candidates requiring per-PR human approval or already inside the publication cap/cooldown are skipped
before quota is reserved or an agent runs. The cap/cooldown is still transactionally rechecked and
reserved immediately before remote writes; preflight is an efficiency filter, not authorization.

Signals are normalized to `0..1`:

```text
base =
    0.28 * repository_impact
  + 0.22 * urgency
  + 0.15 * user_demand
  + 0.15 * maintainer_signal
  + 0.12 * tractability
  + 0.08 * neglect

penalty =
    0.20 * technical_risk
  + 0.12 * collision_risk
  + 0.08 * scope_uncertainty

score = round(100 * clamp(base - penalty, 0, 1))
```

Repository importance is curated and blended with capped log-stars; stars are never the sole impact
signal. Every score retains its components and reasons in the journal.

## Execution boundary

The production preflight rejects `agent.backend = "host"`, non-empty `agent.pass_environment`, any
global or repository bridge network, and the stock `AgentRunner`. The rehearsal runner still
constructs OCI arguments itself; agent/model output cannot add mounts, environment, image, network,
privileges, or runtime flags. Its profile uses a read-only root, network `none` by default, all
capabilities dropped, no-new-privileges, bounded CPU/RAM/PIDs/files, tmpfs, an arbitrary host UID, no
ports/devices/socket, and a read-only nested `.git` mount.

Planning and review mount the rehearsal workspace read-only. Implementation mounts only the
repository writable. Training cannot exercise a bridge override: an attempted override is rejected
before budget, discovery, workspace creation, or runtime inspection.

The active `sbx` candidate is intentionally narrower than an execution backend. Its probe pins the
CLI identity; checks one exact global `service/openai` secret inventory; samples a fixed OpenAI-allow
and non-OpenAI-deny network canary matrix; creates one clone-mode shell sandbox; and checks ports,
observed environment names, fixed clone-write canaries, and exact-name cleanup. Those finite checks
and the name-based lifecycle are useful
negative evidence, not an attestation of the complete daemon, policy, proxy, or credential boundary.
`SbxBoundary.provision()` remains source-disabled before command I/O, and `leftovers run --execute`
still denies before budget or discovery. A future activation must satisfy the full strict evidence
contract, including credential isolation, bounded post-stop extraction, fresh verification, and
proven cleanup.

The archival strict-VM manifest contains boot artifacts and resource limits only. Manifest v2 separates
root- or dedicated-account-owned immutable boot files from a launcher-owned private per-run directory
containing the sealed manifest, optional read-only request disk, and fresh preallocated writable
scratch disk. Hardware is fixed in code with zero network/socket/share/interactive devices, and
receipt v2 binds the exact manifest SHA-256. The manifest has no command or environment field. See
[`vm/README.md`](vm/README.md). The current one-epoch controller is source-disabled and accepts only
explicit fixture authorization; broker-shaped authorization is rejected because no verifier exists.
Its guest source rejects every action and emits no acceptable result. A future whole-cycle runner
must put acquisition, Git parsing, fixed check execution, and canonical diff generation inside that
boundary, while a separate dedicated-UID broker owns every launcher path and durable token/replay
ledger. A caller-supplied string or hash is never sufficient authority.

## Integrity and publication

After implementation, the controller includes untracked files in a canonical Git diff, enforces
file/line/byte/path/lock/binary/secret limits, runs configured tests, and asks a fresh agent context to
review the evidence. An approval bundle freezes the base SHA, patch SHA-256, policy hash, run ID, and
30-minute expiry.

Immediately before publishing, the controller rechecks the issue for closure, assignment, and linked
PRs, then verifies the upstream base SHA is unchanged. The publisher validates the patch hash again,
resolves the authenticated login and immutable user ID against configured expected values, creates a
controller-authored commit, and receives only controller-rendered title/body text built from the issue
number, canonical diff statistics/files, captured check ordinals/exit status, review status, and
fixed AI disclosure. Public text excludes local command argv. It then reconciles a personal fork and
a same-commit issue branch or existing PR, requiring the exact controller-rendered title/body when a
PR already exists. It rejects mismatched remote state, otherwise opens a draft PR, and reads the new
PR back to verify the approved head, base, draft state, canonical URL, title, and body. Free-form model
copy is never published, and the agent never holds the publisher token.

## Retention

Successful runs remove verified run-labeled containers before deleting local workspaces. The audit
retains bounded/redacted state transitions,
scores, prompt hashes, command summaries, policy results, approval hashes, PR URL, and cleanup
receipt. Failed patches are not retained by default. Open PR branches remain remotely until review
finishes; local disposability and remote reviewability are different constraints.

`telemetry.sqlite3` is a rebuildable safe-field projection alongside the authoritative budget,
publication, and journal state. Its writer is controller-bound; dashboard connections use SQLite
`mode=ro` plus `query_only`. A telemetry failure can degrade visibility but cannot relax a gate. The
HTTP view binds only to `127.0.0.1` or `::1`, applies bounded request concurrency and response sizes,
and exposes no public hosting mode because the project does not implement dashboard authentication.
