# Operations

## Portable macOS preview bundle

For a one-shot, no-publish preview on macOS, use the repository-local installer:

```sh
./scripts/install-macos.sh --force-config --scout
```

It runs from a non-root account and requires Python 3.11+, Git, `sandbox-exec`, a saved login in a
Codex CLI `0.144.5+`, and an authenticated `gh` CLI for read-only repository scouting. The foreground
job completes without the Codex desktop app/chat. The current installer still verifies the
configured CLI identity for package compatibility, but any launchd job receives no
`CODEX_HOME` or Codex binary path and does not invoke the model.

The installer creates only owner-private files under `.leftovers/install`. It validates a dry-run
configuration, performs a synthetic Seatbelt rehearsal, then runs the job. The job writes:

- `.leftovers/install/reports/repository-candidates.json` — read-only nominations only;
- `.leftovers/install/reports/seatbelt-rehearsal.json` — installer synthetic workflow evidence;
- `.leftovers/install/reports/job-summary.json` — start/stop reason and any failure-closed error;
- `.leftovers/install/cleanup-pending.json` — present only while execute cleanup is active or
  unproven; and
- `.leftovers/install/logs/job.stdout.log` and `job.stderr.log` — one-shot launch diagnostics when
  launchd is used from a non-protected checkout.

The full job has one 45-minute lifecycle
envelope across GitHub-token lookup and scouting. Host and OCI contribution execution are denied at
build time in the job and again by the production orchestrator before budget or discovery. Legacy
cleanup-lease verification remains tested for safe reconciliation, but the scout-only path acquires
no worker resource. The job reuses the successful installer rehearsal rather than repeating it.
Inspect it with `./scripts/status-macos.sh`. `--launch-now` is accepted only when the checkout is
outside macOS-protected Desktop, Documents, and Downloads folders; never grant Full Disk Access to
bypass that fail-closed check. After saving required evidence, run `./scripts/uninstall-macos.sh`;
that helper bootouts only a manifest-recorded label and removes only the exact repository-local
install root.

Repository discovery does not add an allowlist entry, enable AI contributions, start an execution,
or publish. The bundled configuration has a placeholder repository, but even a curated repository
cannot bypass the strict-VM gate. Docker/Podman availability does not change that status. Successful
read-only scouting and a supplemental Seatbelt rehearsal are the only expected outcomes. See
[`MACOS_PACKAGE.md`](MACOS_PACKAGE.md) and [`../vm/README.md`](../vm/README.md).

## First activation

1. Create `config/leftovers.toml` from the example.
2. Curate a small repository allowlist and record current licenses, contribution rules, AI policy,
   default branch, forbidden paths, and exact offline checks. If AI contributions are allowed, record
   the policy's HTTPS source and the date it was actually checked.
3. Build a provider-specific rehearsal image from `sandbox/Dockerfile` without credentials.
4. Run `validate`, `doctor`, fixture scout, the OCI training cycle, and live scout. `doctor` must
   continue to fail its strict-VM execution check until the guest integration is complete.
5. Inspect audit journals and confirm every temporary workspace is gone.
6. Only after a separately reviewed strict runner has an integrated guest, narrow model mediator,
   bounded result extractor, and live escape/resource/cleanup evidence, enable `draft-pr`, set the
   standing acknowledgement, and use a dedicated public-only contributor identity. Record the exact
   `publication.expected_login` and immutable numeric
   `publication.expected_user_id`; a mismatch must stop publication. Keep per-window and
   per-repository output caps small.

## Deterministic training cycle

Build and run the deterministic shared-kernel Docker rehearsal before connecting a provider adapter:

```sh
make rehearsal-image
PYTHONPATH=src python3 -m leftovers --config config/leftovers.example.toml \
  training-run --mode docker --image leftovers-rehearsal:local \
  --profile auto --report .leftovers/rehearsal-report.json
```

For Podman, build with `RUNTIME=podman` and pass `--mode podman`. Each invocation generates a unique
owner-only root below `<state_dir>/rehearsals/`; `--report` is an optional owner-only copy of the
exact stdout JSON. Exit status `0` requires every evidence check to pass, `3` means the cycle
completed with failed checks, and `2` means configuration/runtime/contract failure.

The fixture is local, has no Git remote, never supplies a GitHub token, and never calls the
publisher. A successful OCI result proves the real runner observed its root-filesystem, network,
mount, identity, usage, audit-chain, and cleanup assertions for this deterministic fixture. It does
not prove that arbitrary hostile native code is safe on a shared host kernel.

When no runtime exists, `make training-run-process` exercises the functional control flow. On macOS,
`--profile auto` re-executes it under the supplemental Seatbelt profile when `sandbox-exec` exists;
`--profile seatbelt` fails closed if that wrapper is unavailable. `--profile none` explicitly skips
the outer wrapper. The JSON `execution_profile` is authoritative about which path ran. Never present
a process-mode pass as OCI evidence.

## Read-only operations dashboard

Production runs project allowlisted telemetry fields into `<state_dir>/telemetry.sqlite3`. After that
file exists, launch the local viewer without GitHub or provider credentials:

```sh
PYTHONPATH=src python3 -m leftovers --config config/leftovers.toml \
  dashboard --host 127.0.0.1 --port 8765 --workers 4
```

The command prints its loopback URL to stderr and blocks until interrupted. `--host` accepts only
`127.0.0.1` or `::1`; port is `1..65535` and workers is `1..32`. There is deliberately no wildcard,
LAN, or public-hosting flag. The server has no authentication/TLS and operational quota/model
metadata is private. Use an authenticated SSH port forward bound to the remote loopback socket if an
operator needs remote viewing.

The dashboard is not a control plane: it cannot create a run, change policy, mutate either ledger,
release capacity, or publish. A missing, unsafe, corrupt, or unsupported telemetry database makes it
fail closed while normal budget and publication enforcement remain unchanged. Rehearsal telemetry
is stored inside that rehearsal's isolated state root; to inspect it interactively, use a reviewed
config copy whose `state_dir` points at the report's `state_dir`. Do not merge its synthetic totals
into production accounting.

## Daily and weekly schedules

`scripts/run-cycle.sh` is the single scheduler entrypoint. It holds a nonblocking kernel advisory
lock for the complete process lifetime and requests execute-only dry runs. In the current release,
those invocations are negative admission tests rather than contribution attempts. Once a strict
runner is integrated, each admitted invocation may select and attempt at most one issue. The budget
ledger prevents later invocations from reusing the same configured window, while publication caps
and repository cooldowns independently bound draft PR output.

In the current release, a production scheduler reaches the strict-isolation preflight and returns
`policy_denied` before budget/discovery. Do not install the daily/weekly execute schedules expecting
contribution work until a strict VM runner replaces the stock runner. The separate macOS preview
installer remains the supported read-only scouting path.

The wrapper reads `.leftovers/scheduler.env` when present, or the exact path in
`LEFTOVERS_ENV_FILE`. It accepts literal `KEY=value` lines only: no quote processing, variable
expansion, or shell commands. The file must be a regular non-symlink, owned by the scheduler user,
and mode `0600` or `0400` (no execute, special, group, or other bits). An explicitly configured
missing file is fatal. Set
`LEFTOVERS_PUBLISH=1` only after the activation checklist; it causes the wrapper to pass the explicit
`--publish` capability. `LEFTOVERS_LOCK_FILE` may override the default
`.leftovers/run.lock` path.

The lock file must be a regular non-symlink owned by the scheduler user and is tightened to mode
`0600`. A concurrent lock holder causes a clean no-op. The kernel releases the lock automatically on
normal exit, `SIGKILL`, failed `exec`, or machine restart, so there is no stale PID recovery state.

Examples are provided for:

- macOS launchd: `schedules/launchd/dev.leftovers.daily.plist.example` at 22:30 local time;
- systemd: `schedules/systemd/leftovers-daily.timer` at 22:30 daily;
- systemd: `schedules/systemd/leftovers-weekly.timer` at 22:00 Fridays.

Do not run the service as root. The reset timing of an AI plan may be rolling rather than midnight;
configure the schedule and budget envelope from the provider's supported information. Choose either
the daily or weekly timer unless the budget configuration intentionally accounts for both schedules.
Leave enough pre-reset time for `budget.max_run_seconds + budget.reset_safety_seconds`; the budget
gate rejects later starts.

### Install on macOS with launchd

Run from the repository root. These commands install the dry-run daily example; substitute the
weekly plist filename to use the weekly schedule.

```sh
umask 077
ROOT=$(pwd -P)
PYTHON=$(command -v python3)
mkdir -p "$ROOT/.leftovers" "$HOME/Library/LaunchAgents"
chmod 700 "$ROOT/.leftovers"
test -e "$ROOT/.leftovers/scheduler.env" || \
  install -m 600 schedules/scheduler.env.example "$ROOT/.leftovers/scheduler.env"
sed -e "s|/ABSOLUTE/PATH/TO/Leftovers|$ROOT|g" \
    -e "s|/ABSOLUTE/PATH/TO/python3|$PYTHON|g" \
    "$ROOT/.leftovers/scheduler.env" > "$ROOT/.leftovers/scheduler.env.new"
mv "$ROOT/.leftovers/scheduler.env.new" "$ROOT/.leftovers/scheduler.env"
chmod 600 "$ROOT/.leftovers/scheduler.env"
sed "s|/ABSOLUTE/PATH/TO/Leftovers|$ROOT|g" \
  schedules/launchd/dev.leftovers.daily.plist.example \
  > "$HOME/Library/LaunchAgents/dev.leftovers.daily.plist"
chmod 600 "$HOME/Library/LaunchAgents/dev.leftovers.daily.plist"
plutil -lint "$HOME/Library/LaunchAgents/dev.leftovers.daily.plist"
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/dev.leftovers.daily.plist"
launchctl print "gui/$(id -u)/dev.leftovers.daily"
```

The `sed` pass leaves no placeholders in the private environment file. Edit that file directly to
set the curated config path, read-plane/provider credentials, or `LEFTOVERS_PUBLISH`; do not place
secrets in the plist. The publisher uses the separately authenticated `gh` identity. To replace an
already-loaded agent before running `bootstrap` again:

```sh
launchctl bootout "gui/$(id -u)/dev.leftovers.daily"
```

### Install as a systemd user timer

Run from the repository root. These commands install the dry-run daily example without root; use the
weekly timer filename instead if desired.

```sh
umask 077
ROOT=$(pwd -P)
PYTHON=$(command -v python3)
mkdir -p "$ROOT/.leftovers" "$HOME/.config/systemd/user"
chmod 700 "$ROOT/.leftovers"
test -e "$ROOT/.leftovers/scheduler.env" || \
  install -m 600 schedules/scheduler.env.example "$ROOT/.leftovers/scheduler.env"
sed -e "s|/ABSOLUTE/PATH/TO/Leftovers|$ROOT|g" \
    -e "s|/ABSOLUTE/PATH/TO/python3|$PYTHON|g" \
    "$ROOT/.leftovers/scheduler.env" > "$ROOT/.leftovers/scheduler.env.new"
mv "$ROOT/.leftovers/scheduler.env.new" "$ROOT/.leftovers/scheduler.env"
chmod 600 "$ROOT/.leftovers/scheduler.env"
sed "s|/ABSOLUTE/PATH/TO/Leftovers|$ROOT|g" \
  schedules/systemd/leftovers.service \
  > "$HOME/.config/systemd/user/leftovers.service"
install -m 644 schedules/systemd/leftovers-daily.timer \
  "$HOME/.config/systemd/user/leftovers-daily.timer"
systemctl --user daemon-reload
systemctl --user enable --now leftovers-daily.timer
systemctl --user list-timers leftovers-daily.timer
```

Edit the private environment file directly after installation. This performs one immediate smoke run
and then shows its log:

```sh
systemctl --user start leftovers.service
journalctl --user-unit leftovers.service
```

A logged-out user manager may require distribution-specific lingering setup, which is intentionally
not enabled by this repository.

## Failure handling

- `deferred`: wait for the next window; do not bypass the reserve.
- `no_candidate`: normal; do not lower policy just to consume quota.
- `runtime_unavailable`: for an OCI rehearsal, install/configure a container runtime separately;
  Leftovers never installs host packages. A container runtime does not satisfy the strict VM
  production requirement.
- `test_failed` or `review_rejected`: retain audit evidence, not the workspace; reconsider next run.
- `upstream_moved`: rediscover and reverify from the new base.
- `publish_partial`: stop automatic writes. Inspect the contributor fork for
  `<branch_prefix>/issue-N`, check for a draft PR, compare the run journal and approval hash, and
  inspect `publications.sqlite3`. v0.1 has no automatic resume/release path; do not simply rerun.
- `cleanup_pending`: stop new jobs. Run `leftovers cleanup` only with the configured runtime
  available; it verifies and removes expired, exactly labeled containers before examining marked
  workspaces. For the portable bundle, also inspect `.leftovers/install/cleanup-pending.json` and its
  exact run ID/container label. Never use global prune or delete a possibly mounted workspace first;
  delete the marker only after reconciliation proves both container and workspace cleanup.

When cleanup and an earlier failure both occur, `stage` is `cleanup_pending` while the primary
`failure_code` (especially `publish_partial`) is preserved and the message reports both conditions.
Reconcile the remote publication state before treating local cleanup as the only incident.

For the default 24-hour expiry threshold:

```sh
PYTHONPATH=src python3 -m leftovers --config config/leftovers.toml \
  cleanup --older-than-hours 24
```

A failed execute run retains its conservative budget reservation for the configured window. A
reserved publication slot likewise retains the window count and repository cooldown after a partial
write. These fail-closed records are intentional; manual state surgery without remote and journal
reconciliation can duplicate work.

Budget reservations decide whether work may start, but they are not provider-enforced token ceilings
and do not meter live inference. A provider-side maximum or external broker cutoff remains necessary
when strict spend control is required.

## Audit and retention

Journals live in `<state_dir>/runs/<run_id>.jsonl`. Each line names the prior record hash. The
controller verifies ownership and tightens state directories to `0700` and state files to `0600`;
keep the scheduler account and enclosing storage private too. Apply an external retention policy
(suggested: command logs 7 days, run metadata 30 days). The local code intentionally does not delete
audit evidence automatically.

The two SQLite control files under `<state_dir>` are operational state, not disposable caches:

- `budget.sqlite3`: token-envelope reservations keyed by reset window;
- `publications.sqlite3`: publication slots, PR URLs, and repository cooldown history.

Back them up with the journals and restrict all three to the scheduler user.

`telemetry.sqlite3` is a separate non-authoritative observability projection. Backing it up is
optional; never restore it in place of either control ledger or the hash-chained journals.
