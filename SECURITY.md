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
- Runtime flags drop capabilities and network, use a read-only root, no-new-privileges, CPU/RAM/PID/
  file/tmpfs limits, and a read-only `.git` overlay.
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
- The first-party Codex CLI dry-run backend accepts no user CLI flags or environment pass-through,
  disables automatic instruction/config/rule/hook/app/network surfaces, uses stage-specific
  least-privilege permission profiles, and converts only closed-schema output and bounded usage
  telemetry. Repository-local Codex skills are refused, execution uses an empty isolated home, and
  ambient GitHub, provider-token, SSH-agent, and cloud credentials are not forwarded.
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
  hardened runner and must prove label-scoped container and marker-scoped workspace cleanup.

## Known assurance gaps

Do not describe these as solved:

- A local Docker/Podman container shares the host kernel. Intentionally hostile native code requires
  a disposable VM/microVM backend, which v0.1 does not provision. Runtime rootlessness is
  operator-provided and reported as unverified rather than portably proven by the controller.
- The current checkout is a host-visible bind-mounted tree. A high-assurance backend should acquire
  into an isolated volume, inspect file types/path collisions without trusting worker Git state, and
  produce a canonical tree bundle from pristine baseline and worker volumes.
- The local runner does not enforce a portable disk quota or custom seccomp/AppArmor profile.
- Setup networking is coarse (`none` or `bridge`), not domain-allowlisted. Keep it `none` unless a
  human accepts the supply-chain/exfiltration risk.
- Agent provider authentication is deployment-specific. Baking credentials into an image is unsafe.
  Prefer a model/tool broker or a provider CLI whose own sandbox keeps credentials outside tool
  reach. Host and Codex CLI backends are lower assurance and cannot publish.
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
- Process-mode rehearsal is functional evidence, not a production sandbox claim. The optional macOS
  Seatbelt wrapper broadly permits reads and is only supplemental; OCI mode remains the required
  local production-faithful proof.

## High-assurance deployment requirements

Use a fresh VM/microVM per job, rootless runtime inside it, pinned image digests, immutable dependency
bundles fetched without lifecycle scripts, a no-egress worker, canonical lstat-based tree comparison,
a fresh verifier volume, signed/expiring approval attestation, just-in-time publisher token, encrypted
audit storage, and a periodic label-scoped reaper. Never expose the host runtime socket or run an
untrusted repository Dockerfile against it.

## Reporting

Before this project is published, configure a private vulnerability-reporting channel or GitHub
private vulnerability reporting. Do not open a public issue for a suspected credential leak or
exploitable sandbox escape.
