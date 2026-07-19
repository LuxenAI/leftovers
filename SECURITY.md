# Security model

## Threats

Assume hostile issue bodies, comments, repositories, Git metadata, tests, build scripts, dependency
hooks, model output, logs, and archives. Primary risks are host compromise, credential theft, prompt
injection, supply-chain execution, hidden patch content, resource exhaustion, spam/reputation damage,
and partial publication or cleanup failures.

## Enforced in v0.1

- Repository allowlist and exact `owner/name` GitHub HTTPS acquisition.
- No submodule recursion, LFS smudge, interactive credentials, external Git protocol, or hooks during
  shallow clone.
- Worker configuration rejects GitHub credential environment variables.
- Unattended production admission runs before budget, discovery, clone, or model work. It rejects
  host agents, every non-empty environment pass-through, bridge networking (including repository
  overrides), and the stock Docker/Podman runner.
- OCI rehearsal flags drop capabilities and network, use a read-only root, no-new-privileges,
  validated CPU/RAM/PID/file/tmpfs limits, and a read-only `.git` overlay.
- Planning/review workspaces are read-only.
- All configured commands are argv arrays and use `shell=False`.
- Hard issue gates block security/legal/credential/design/collision work.
- Patch gates inspect both sides of renames and block configured sensitive paths, workflow/license
  files, dependency manifests/lockfiles, binaries, any touched symlink or Git submodule link,
  executable-bit changes, invalid UTF-8, large diffs, and common credential signatures.
- Verification runs offline; fresh review must approve.
- Draft-PR title/body text is controller-rendered from bounded verified evidence and fixed disclosure;
  free-form model copy is not published. Existing-PR recovery and post-create readback require that
  exact title/body text as well as the approved head, base, draft state, and canonical URL.
- Approval bundle expiration and patch hash are rechecked before publication; the committed
  `base_sha..HEAD` diff must exactly equal the frozen approved patch before any remote mutation.
- GitHub issue/base state is rechecked before publication.
- Publisher uses an isolated Git HOME, disabled hooks/credential helpers, an ephemeral askpass script,
  and a token held only in its subprocess environment.
- Publisher identity must match configured expected login and immutable GitHub user ID before writes.
- Container removal requires exact managed/job/stage labels and a post-removal absence check;
  workspace deletion runs only afterward and requires a managed marker, expected prefix, and
  descendant-path proof.
- The controller refuses execute runs as root. State directories/files are ownership-checked and
  tightened to `0700`/`0600` without following final-component symlinks.
- Audit text is ANSI-stripped, redacted, bounded, and hash-chained.
- Telemetry stores only allowlisted identifiers, state codes, counts, and timestamps; it excludes
  issue bodies, prompts, diffs, command output, arbitrary exceptions, paths, and credentials.
- Dashboard readers open telemetry physically read-only and the HTTP server accepts only loopback
  clients and literal loopback binds, rejects mutation methods and unexpected Host/Origin values,
  bounds concurrency/requests/responses, and sends a restrictive CSP and related security headers.
- The deterministic training fixture has no Git remote or publisher path. Its OCI mode uses the real
  hardened runner and must prove label-scoped container and marker-scoped workspace cleanup. Generic
  callers cannot label a run as training to bypass production admission: training rejects publication
  before consulting a publisher and admits only attested fixture runner/source/lease classes with the
  fixed synthetic identity, no network (including repository overrides), and no environment forwarding.
- `repo-scout` and the portable macOS job perform GitHub reads only. A nomination is emitted with
  `execution_authorized: false`; it cannot mutate configuration, enable a repository, invoke the
  publisher, or send GitHub credentials to the worker.
- The portable macOS bundle rejects symlinked or out-of-repository roots and uses an owner-private
  manifest, a one-shot low-priority launchd job, private reports/logs, and a kernel lock. Its
  template hard-disables external writes. The host Codex adapter never invokes `--publish` and
  configuration validation rejects it for draft PRs. Its guarded uninstaller validates the
  manifest and job lock before removing only that exact root. Termination propagates from the
  launchd wrapper through controller cleanup to the adapter-owned Codex process group. Before OCI
  execution, a durable owner-private cleanup lease is created and can be cleared only by a matching
  hash-chained receipt proving container and workspace removal; unresolved evidence blocks later
  jobs, reinstall, and uninstall even after the process lock is released. On Linux, the runner
  temporarily enables child-subreaper behavior around its one owned session, reaps only children in
  that exact process group, and restores the prior setting; an unavailable or unprovable reap remains
  a cleanup failure.
- Worker results, telemetry, Codex JSONL/diagnostics, job captures, generated configuration,
  manifests, and cleanup journals are lstat-checked and read through no-follow descriptors with
  total-file and per-line limits. Final post-exit checks cover workers that write oversized files
  between monitor ticks. Cleanup continues closing descriptors, removing temporary files, and
  restoring handlers even when process termination proof fails.
- The macOS launchd job has a compile-time execution deny gate, receives neither `CODEX_HOME` nor a
  Codex binary path, and truncates its private one-shot logs before each launch.
- `vm/strict_vm_launcher.swift` is a fail-closed boundary proof: its exact manifest cannot supply a
  command, environment, network, mount, or device. Manifest v2 requires immutable boot artifacts
  owned outside the non-root launcher account, sealed manifest/request inputs in a private per-run
  directory, one fresh preallocated scratch disk, and zero NIC/socket/share or interactive devices;
  receipt v2 binds the exact manifest SHA-256 and exhaustive device graph. The strict controller
  derives (rather than accepts from TOML) the digest of an immutable canonical `guest-policy.json`;
  that rejection-only policy must name the exact pinned kernel, initrd, and root-disk digests.

## Known assurance gaps

Do not describe these as solved:

- A local Docker/Podman container shares the host kernel, so it is rehearsal-only. The strict VM
  launcher, one-epoch controller, typed request/result parser, cleanup lease, and guest source
  scaffold exist, but every execution/mediator/broker/orchestrator gate remains source-disabled.
  The guest is rejection-only, unbuilt, and unbooted; no production issue execution is authorized.
- The current orchestrator still clones and inspects a host-visible checkout. A complete strict
  runner must move acquisition, Git parsing, model/tool execution, verification, and diff creation
  into guest-owned disks and return only a bounded canonical bundle after shutdown.
- The strict launcher bounds VM memory/CPU/time and physically reserves the scratch cap. Guest
  source requires non-root execution, cgroup-v2 memory/PID/CPU limits, seccomp, Landlock, read-only
  policy, and no core dumps, but those controls have only static tests. Reproducible build, boot,
  pressure, inode/file-count, and adversarial evidence is still missing.
- The zero-NIC VM has no model access. A hard-disabled Codex parser and ledger scaffold separates
  model output from CLI usage, but there is no authenticated provider process or durable broker
  authority. The existing host Codex adapter cannot be relabeled as that mediator.
- Controller-owned paths and hash chains do not resist another process under the same UID. The
  hard-disabled broker protocol closes caller path/argv selection, and its separate journal model
  specifies fsync-before-ack records, boot-bound genesis, rollback witnesses, replay/token recovery,
  and restart quarantine. Neither is an implementation: the dedicated-UID launchd service,
  descriptor-relative storage backend, root-owned rollback witness, full descriptor-native LFRQ
  parser, and unforgeable mediator authorization are still absent.
- Agent provider authentication is deployment-specific. Baking credentials into an image is unsafe.
  Prefer a model/tool broker or a provider CLI whose own sandbox keeps credentials outside tool
  reach. The host backend is lower assurance. In particular, the bundled Codex adapter uses the
  logged-in host CLI's saved subscription authentication: it must not be treated as a credential
  boundary for hostile code and is dry-run-only.
- Secret regexes are not proof of absence. Production should add a dedicated scanner and entropy/
  historical-secret checks.
- Sensitive-issue label and text matching is a conservative gate, not semantic proof that an issue
  is non-security or non-legal. Repository allowlists, maintainer-signal labels, the worker stop
  contract, and human curation remain required.
- Approval bundles are integrity hashes within a trusted controller, not externally signed
  attestations.
- Publication does not have a general resume protocol. Fork creation has bounded readiness checks,
  but a push or PR-creation failure remains `publish_partial` and requires operator reconciliation;
  local ledgers prevent an automatic retry from compounding an uncertain remote state.
- The dashboard has no authentication or TLS and is therefore intentionally loopback-only. Do not
  reverse-proxy or publicly host it; use an authenticated SSH loopback forward when remote viewing is
  required.
- Process-mode and OCI rehearsals are functional evidence, not production sandbox claims. The
  optional macOS Seatbelt wrapper broadly permits reads and is only supplemental.
- The portable macOS package is not a strict-VM provisioner. It always stops after scouting and its
  synthetic rehearsal; installing Docker/Podman or curating a repository does not enable model work.

## High-assurance deployment requirements

Before enabling production, complete the guest and controller integration described in
[`vm/README.md`](vm/README.md): reproducible signed boot artifacts, non-root cgroup/seccomp/Landlock
guest policy, in-guest acquisition and verification, no-general-egress model mediation, bounded
post-stop result extraction, adversarial escape/resource tests, and cleanup receipts. Keep the
publisher outside the guest with a just-in-time token. Never expose a host runtime socket or run an
untrusted repository Dockerfile against it.

Those controls can reduce attack surface and bound damage; they cannot prove that macOS,
Virtualization.framework, the CPU, or the guest kernel contains no exploitable escape. Do not
describe this project as completely isolated or absolutely escape-proof, even after integration.

## Reporting

Before this project is published, configure a private vulnerability-reporting channel or GitHub
private vulnerability reporting. Do not open a public issue for a suspected credential leak or
exploitable sandbox escape.
