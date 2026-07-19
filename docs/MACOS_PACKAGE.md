# Portable macOS preview package

The macOS package is a small, repository-local, headless **scout-only preview** installation. It is
designed to prepare conservative nominations without leaving a recurring agent, a system-wide
package, or a GitHub write credential in a coding sandbox. It does not currently invoke a model or
consume the dormant local token envelope.

It is not a “run arbitrary GitHub issues tonight” switch. It performs a read-only repository-supply
scan and a synthetic workflow rehearsal only. Host and OCI contribution execution are explicitly
disabled; curation or a container runtime cannot bypass that gate.

## Safe first installation

From the root of a trusted Leftovers checkout, as the normal macOS user:

```sh
./scripts/install-macos.sh --force-config --scout
```

Do not run it with `sudo`. The command creates `.leftovers/install` with owner-only permissions,
builds a dependency-free `leftovers.pyz`, copies the controller-owned adapter and schemas, renders a
dry-run configuration, validates it, runs a Seatbelt rehearsal, performs one bounded read-only scan,
and exits. It does not depend on the Codex chat or desktop app process. The scout receives no Codex
credential directory or binary path and does not install a long-lived agent in
`~/Library/LaunchAgents`.

For checkouts outside macOS-protected Desktop, Documents, and Downloads folders, `--launch-now` may
instead submit a private one-shot plist with `RunAtLoad = true`, `KeepAlive = false`, `Nice = 10`,
and `LowPriorityIO = true`. A LaunchAgent cannot safely open a bundle or its logs under those
protected folders without broader privacy authority. The installer therefore rejects that layout
before mutation; do not grant Full Disk Access to bypass the check. `--launch-now` starts
immediately and is not a clock-time scheduler.

## Prerequisites

- macOS, a persistent non-virtualenv Python 3.11 or newer, and Git;
- a non-root user account;
- a Codex CLI at `0.144.5` or newer that supports `gpt-5.6-terra`; the installer checks the ChatGPT
  app bundle, Codex app bundle, `LEFTOVERS_CODEX_BIN`, then `PATH`;
- a saved, valid CLI login for that account. The desktop app/chat does not need to keep running, but
  the CLI binary and its saved login must remain available;
- an authenticated `gh` CLI for the read-only GitHub scan. Its existing token is read into memory
  only and is never written to the install root or passed to a worker; and
- optionally, Docker or Podman for the deterministic OCI rehearsal only.

The installer does not install Python, Codex, GitHub CLI, Docker, Podman, or any system package. It
fails closed if a required local prerequisite is missing. The current development Mac has no Docker
or Podman, so the package currently operates in the supplemental scout/rehearsal profile only.
`sandbox-exec` is required for the default rehearsal; `--skip-rehearsal` permits an OCI-only setup
but labels the package unverified until `--verify-oci` succeeds.

To build a reproducible source bundle for transfer to another prepared Mac:

```sh
make macos-package
```

The result under `.leftovers/dist/` contains a deterministic `PACKAGE-MANIFEST.json` with the
SHA-256, size, and owner-only mode (`0600`, or `0700` for installer scripts) of every member. The
builder reopens and verifies the archive before reporting success. When run from the extracted
transfer bundle, the installer also verifies the
extracted tree before it performs any installer action: every manifest member must have the
recorded hash, size, and mode, and missing, extra, special, or symlink payloads are rejected. When
run directly from this development repository, it instead requires that the directory be the root
of a Git checkout; a checkout contains intentionally unbundled development files and therefore
cannot be compared to the transfer manifest.

After the first extracted-bundle install, later reinstall, relaunch, or `--verify-oci` invocations
continue to verify every source member. The verifier excludes only the exact root-level
`.leftovers` mutable-state directory, and only when it is a real, current-user-owned `0700`
directory; any symlink, permissive mode, or extra source payload still fails closed.
Reinstallation also refuses to overwrite an unresolved cleanup marker.

That manifest alone proves **internal consistency**, not archive authenticity: an attacker who can
replace the manifest can replace the payload with it. Before extracting a transferred archive,
obtain its SHA-256 from an independently trusted release channel and compare it with a trusted local
tool:

```sh
shasum -a 256 leftovers-macos-preview-v0.2.0.tar.gz
```

Extract into a persistent owner-private directory. A normal `umask 022` extraction creates `0755`
directories and is deliberately rejected by the verifier:

```sh
install -d -m 700 "$HOME/Leftovers-0.2.0"
(umask 077; tar -xzf leftovers-macos-preview-v0.2.0.tar.gz -C "$HOME/Leftovers-0.2.0")
cd "$HOME/Leftovers-0.2.0/leftovers-macos-preview-v0.2.0"
```

You can have the installer compare the same externally supplied value again. In that mode it reads
the bounded archive once, verifies the supplied digest, validates every archive member, and requires
the extracted manifest and payload to match that exact archive. Both values are required; the
digest's provenance remains your responsibility:

```sh
LEFTOVERS_PACKAGE_ARCHIVE=/path/to/leftovers-macos-preview-v0.2.0.tar.gz \
LEFTOVERS_PACKAGE_ARCHIVE_SHA256=trusted_lowercase_sha256 \
./scripts/install-macos.sh --force-config --scout
```

The extracted root and every source directory must be current-user-owned `0700`; files must be
current-user-owned, single-link regular files with the manifest-declared `0600` or `0700` mode.
This blocks cross-user replacement during verification. A hostile process running as the same user
can still race ordinary filesystem operations, so a dedicated non-admin account remains the stronger
installation boundary.

## What the scout job does

The job takes an advisory lock and gives its read-only lifecycle one 45-minute envelope. Legacy
execute-cleanup reconciliation remains covered by tests, but the active job never admits a worker,
creates a contribution workspace, or starts Codex. It first uses the existing GitHub CLI token for a serial,
read-only `repo-scout` request (a small scan of 12 repositories with at most 7 nominations). It
verifies and reuses the installer rehearsal rather than repeating it. It reports its result without
starting the model.

The rendered configuration retains a dormant 65,000-token envelope, 10,000-token reserve,
50,000-token P95 estimate, and zero repair cycles for future integration tests. The scout-only job
does not reserve or consume that envelope. These values are local accounting, not a way to read or
enforce a consumer-plan balance.

The candidate report is:

```text
.leftovers/install/reports/repository-candidates.json
```

It contains `mode: "read-only-nomination"` and `execution_authorized: false`. Nominees are selected
for issue pressure and maintainer activity, but neither the installer nor the job auto-adds one to
the allowlist. Other evidence is stored in:

```text
.leftovers/install/reports/seatbelt-rehearsal.json
.leftovers/install/reports/job-summary.json
.leftovers/install/cleanup-pending.json
.leftovers/install/logs/job.stdout.log
.leftovers/install/logs/job.stderr.log
```

`cleanup-pending.json` is absent during ordinary scouting and after a fully proven preview cleanup.
If status reports `cleanup-pending`, preserve the file and reconcile its exact run ID, container
label, journal, runtime state, and workspace before manually removing the marker. Leftovers does not
guess that a released process lock means a daemon-owned container is gone.

If the read-only GitHub login is unavailable, the job records a failure-closed error in
`job-summary.json`; it does not fall back to scraping a browser or another credential source.

## Curation remains read-only research

The rendered `.leftovers/install/config.toml` starts with the placeholder
`leftovers/curate-before-use`. It has no allowed license, no tests, no recorded AI policy, and
`ai_contributions_allowed = false`; that is intentional.

Use the checklist in [`REPOSITORY_CURATION.md`](REPOSITORY_CURATION.md) to evaluate nominations, but
do not interpret curation as execution authorization. The current job stops at scouting regardless
of repository fields or runtime availability. It has no reachable path to invoke
`leftovers run --execute`, create a fork, push a branch, comment, or open a pull request.

## Codex Terra/high adapter test fixture

`scripts/codex_adapter.py` is copied into the package and is intentionally fixed to
`gpt-5.6-terra` with `high` reasoning effort. It runs non-interactive, ephemeral `codex exec` stages
with strict structured output and hard per-stage limits: 6 minutes (planning), 20 minutes
(implementation), and 8 minutes (review). It disables inherited user configuration, interactive
approval, plugins/tools, workspace network access, and shell-environment inheritance; it collects a
bounded JSONL usage receipt.

This is an adapter test fixture, not a production isolation boundary. Production rejects its host
backend, and launchd receives neither `CODEX_HOME` nor `LEFTOVERS_CODEX_BIN`. For the strict VM
design and its still-missing guest/model mediation, see [`vm/README.md`](../vm/README.md) and
[`SECURITY.md`](../SECURITY.md).

## Assurance and verification

`manifest.json` records the selected Codex binary/version, fixed model/reasoning effort, runtime
availability, assurance label, report paths, and optional one-shot launch label. Inspect it and the reports
after the job completes:

```sh
cat .leftovers/install/manifest.json
cat .leftovers/install/reports/job-summary.json
```

An installation without an OCI runtime is correctly labeled
`seatbelt-supplemental-scout-only`. An OCI rehearsal is labeled
`oci-rehearsal-verified-scout-only`. Neither is a VM or production-sandbox claim.

On a separately prepared Mac with Docker or Podman, this optional command verifies only the OCI
rehearsal:

```sh
./scripts/install-macos.sh --verify-oci
```

It builds the reviewed sandbox and rehearsal images locally and runs the deterministic OCI rehearsal.
It records the sandbox image's immutable ID in both `config.toml` and `manifest.json`. That command
does not enable a repository, model run, or pull request. A successful report is rehearsal evidence,
not proof that hostile native code is safe on a shared host kernel.

Inspect the result without opening Codex:

```sh
./scripts/status-macos.sh
```

## Footprint and removal

The package keeps its mutable state, reports, reset-per-launch logs, schemas, launcher, and any
one-shot plist beneath `.leftovers/install`. Installation verifies the existing Codex CLI identity/login for
compatibility, while the scout reads only the existing GitHub CLI credential for scouting;
it receives no Codex path. `--verify-oci` writes rehearsal images to the selected runtime's global
image store. When `--launch-now` is used, its launchd registration remains loaded until bootout or
logout even after the one-shot process exits.

After the job is finished and required evidence has been saved, remove the package with:

```sh
./scripts/uninstall-macos.sh
```

The uninstaller validates every path component, the owner-private manifest, the exact install-root
identity, the current user in the recorded launch label, and the advisory job lock. It unloads only
that recorded service and deletes only the manifest-bound `.leftovers/install` subtree. It refuses
paths outside this repository's `.leftovers` directory and reports `outside_paths_removed: []`. It
also refuses removal while either cleanup-in-progress or cleanup-pending evidence exists; reconcile
the recorded run and prove runtime/workspace cleanup first.
