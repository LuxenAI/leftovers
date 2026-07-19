# Docker Sandboxes execution boundary

Docker Sandboxes (`sbx`) is the active isolation-integration **candidate** for Leftovers. The custom
Virtualization.framework work under `vm/` is archival, source-disabled research; it is retained for
review, not an operator activation path. Neither status authorizes production contribution execution.

Docker documents a microVM per sandbox, a private filesystem and Docker daemon, and policy-mediated
networking. Leftovers still treats the `sbx` CLI, daemon, credential proxy, template, and Git bridge
as external authority that must be verified rather than assumed safe. Docker documents that the
agent user is non-root but has `sudo`; the hypervisor, rather than the in-guest Unix account, is the
host-isolation boundary. Leftovers therefore does not treat a non-root username as containment:

- [Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/)
- [clone-mode usage](https://docs.docker.com/ai/sandboxes/usage/)
- [architecture](https://docs.docker.com/ai/sandboxes/architecture/)
- [isolation model](https://docs.docker.com/ai/sandboxes/security/isolation/)
- [security defaults](https://docs.docker.com/ai/sandboxes/security/defaults/)
- [credential behavior](https://docs.docker.com/ai/sandboxes/security/credentials/)
- [local network policy](https://docs.docker.com/ai/sandboxes/governance/local/)
- [`sbx exec` reference](https://docs.docker.com/reference/cli/sbx/exec/)

## Boundary Leftovers enforces

Leftovers never points `sbx` at the operator's everyday checkout or a host worktree. Direct-mount
mode is forbidden: it exposes the host working tree for live agent writes. A future contribution run
must:

1. create an owner-private, disposable, controller-owned staging clone from a controller-enumerated
   tracked-file input, with no ignored or untracked `.env`, credential, key, socket, or
   user-configuration payload. Clone mode mounts the Git root read-only but includes untracked and
   ignored files, so a normal host checkout is not an acceptable input;
2. require the expected digest/version/revision for `sbx` v0.35.0 with `create --clone`, one
   workspace, and the future fixed `openai-codex-cli` / `gpt-5.6-terra` / `high` intent, with
   explicit CPU, memory, wall-time, and output bounds;
   clone mode also creates a host `sandbox-<name>` Git remote, so that remote must exist only in
   the disposable staging clone and `sbx rm` must remove it before the clone is deleted;
3. pass only `HOME` (required by the macOS CLI) and `SBX_NO_TELEMETRY=1` to the host CLI, while
   rejecting SSH-agent, GitHub, provider, Git, registry, runtime, and proxy variables;
4. eventually attest the effective Locked Down policy. Local `sbx policy` administration is a
   network-rule interface; filesystem mount decisions are made at creation time and are not emitted
   by the policy log. A snapshot can change, and organization governance can replace local and kit
   rules entirely. The current rehearsal checks a finite fixed allow/deny canary set only; it is not
   an exact policy attestation and cannot prove the absence of another egress path;
5. require the global secret inventory to equal exactly one entry: `(global)`, `service`, `openai`.
   Any additional global secret, any missing/renamed OpenAI service secret, or any additional scoped
   secret fails the rehearsal. Registry, GitHub, and SSH credentials are forbidden. The coding agent
   never receives `gh`, a PAT, an SSH signing capability, or publisher authority; and
6. use `sbx exec` and `sbx cp` only through fixed controller-owned argv arrays. `sbx run --name` is
   forbidden because Docker documents that it creates the named sandbox when it is absent.
   `sbx exec` also starts a stopped sandbox automatically and addresses it by name in the documented
   interface, so an earlier UUID/generation observation is not an atomic execute authorization. A
   future adapter must additionally prove exact `UID:GID`, empty supplemental groups and effective
   capabilities, a canonical minimal `CODEX_HOME`, disabled user configuration/rules/hooks, and a
   descriptor-stable Codex executable identity immediately across launch. `sbx cp` is transport,
   not attestation, and `-L` is forbidden. Capture only a bounded opaque patch while the sandbox is
   running, stop and remove the sandbox, and parse the patch only after cleanup is proven. Semantic
   output and exact per-stage usage must instead come from controller-captured Codex JSONL bound to
   the run; a result file written by repository code cannot assert its own usage. Docker documents
   no generic post-stop export or machine-verifiable destruction receipt. Repository code and test
   commands must execute in a separate fresh sandbox, never on the host or in the publisher
   checkout; and
7. stop and remove exactly the controller-derived sandbox name, then prove that name absent before
   deleting the marked staging clone. No `sbx reset`, `rm --all`, global prune, broad prefix
   deletion, kit, template, profile, privileged exec, extra workspace, or port-publication command
   is available.

The publisher remains separate. Only `publisher.py`, after deterministic issue, diff, test, review,
assignment, linked-PR, and base-SHA gates, may use host GitHub credentials to open a draft PR.

The future Terra/high intent is deliberately economical: the typed source-disabled sbx plan proposes
2 CPUs, 4 GiB, a 5-minute create cap, planning/implementation/verification call caps of 6/20/8
minutes, a 2-minute cleanup reserve, and 32/64/32 KiB combined-output caps. Those three calls have
10,000/35,000/10,000 local token envelopes and a 55,000-token aggregate ceiling; each stage is
admitted exactly once in order. The current shell rehearsal instead fixes 1 CPU/1 GiB and consumes
only the pinned identity plus a bounded per-command timeout from `[sbx]`; the other values are not
yet runtime-enforced or attested. The wider controller retains conservative token admission,
including a reserve and P95 safety multiplier. These are local safeguards checked before a call and
against controller-captured post-call usage, not a provider-enforced quota ceiling, and they do not
authorize a provider call.

Docker's Codex template documents a default invocation with
`--dangerously-bypass-approvals-and-sandbox`. That default cannot be the Leftovers production
invocation. Until a separately reviewed, exact Codex argv contract is live-attested, neither
`sbx run codex` nor a successful OpenAI OAuth flow enables a coding-agent run.

The OpenAI service credential proxy hides the raw token from the VM, but Docker's public contract
does not establish process-scoped authorization inside the sandbox. A repository subprocess may be
able to reuse the same proxy capability or sentinel and spend quota. Leftovers therefore treats a
configured OpenAI service secret as necessary authentication, not credential-isolating model
mediation; production remains blocked until a narrow mediator can bind each of the three admitted
calls to controller-owned input, output, identity, and exact usage evidence.

## Compatibility rehearsal

The repository now includes a no-agent compatibility probe. Its read-only phase verifies the exact
binary digest/version/revision, `sbx` authentication and state listing, a finite network-policy canary
matrix, and secret metadata. Its explicit phase creates a tracked-only local fixture and one
1-CPU/1-GiB `shell` sandbox, exercises fixed source-mount and private-clone write canaries, checks a
strict allowlist of observed environment-variable names, confirms there are no published ports, and
then performs exact-name teardown. A failed source-mount write or clean `env -0` does not prove that
all daemon mounts, proxy capabilities, or credential paths are absent.

The explicit phase runs only fixed shell commands used for these checks (`env`, `touch`, and `test`).
It does not start an AI agent, call a provider, invoke Codex, or make a Terra/high inference request.
The `--execute` flag authorizes a disposable shell-sandbox lifecycle, not `leftovers run --execute`.

Run the read-only phase:

```sh
./scripts/sbx-rehearsal.sh
```

Run the disposable lifecycle only after the read-only checks pass:

```sh
./scripts/sbx-rehearsal.sh --execute
```

The wrapper requires Python 3.11+, resolves the repository itself, and invokes Leftovers under a
fresh environment containing only `HOME`, a fixed command path, and `PYTHONPATH`. It does not depend
on the Codex desktop app or this task remaining open.

Any timeout, output overflow, malformed policy/list/secret response, inherited credential, exposed
port, host-write observation, failed stop/remove, or unproven final absence is failure. A failed or
ambiguous create retains the marked fixture and deliberately issues no name-only `stop`/`rm`. After a
successful create, teardown is still name-based; `stop`, `rm`, and observed absence are weaker than a
destruction receipt or proof that every descendant has stopped. `sbx ls --json` has a stable
per-sandbox ID in v0.35.0 and `sbx inspect --json` is available, but Docker does not document a
machine-readable schema for either response or a deletion receipt. They are diagnostic observations,
not production ownership, policy-binding, cleanup, or result-extraction attestations.

## One-time host preparation

Do not run these commands with `sudo`, and do not import a GitHub secret into Docker Sandboxes.

```sh
brew trust docker/tap
brew install docker/tap/sbx
sbx login
sbx policy init deny-all
sbx policy allow network \
  "api.openai.com:443,openai.com:443,chatgpt.com:443,www.chatgpt.com:443"
sbx secret set -g openai --oauth
./scripts/sbx-rehearsal.sh --execute
```

`sbx policy init deny-all` is a one-time initialization command. If policy is already initialized,
inspect it with `sbx policy ls --wide --include-inactive`; do not use `sbx policy reset` merely to
make this sequence repeatable. The explicit allow rule is required because Locked Down blocks
provider traffic by default. If organization governance is active, local rules are inactive: obtain
the equivalent organization policy instead of assuming the local command took effect. The probe
requires the exact global OpenAI service-secret inventory described above, not merely the absence of
a GitHub secret. Removing or renaming a pre-existing secret can change other Docker Sandbox
workflows, so make that a deliberate operator decision or use a dedicated macOS account for
Leftovers.

## Current machine status

As inspected on 2026-07-19, the installed CLI is:

```text
version:  v0.35.0
revision: 01e01520456e4126a9653471e7072e4d9b280321
sha256:   b046dce135756ee14a72e88165c90b07d10e2d48b86cd089adee5acc2abf2d01
binary:   /opt/homebrew/Caskroom/sbx/0.35.0/bin/sbx
```

The read-only probe currently stops at `sbx authentication or sandbox state is unavailable`: the
installed `sbx` receives Keychain error `-50` for `sbx ls`, and secret/policy inspection is therefore
unavailable too. No sandbox was created. Run `sbx login` from a normal Terminal session, complete the
host-side OpenAI OAuth flow, initialize Locked Down policy, add the explicit allow rule above, and
rerun the read-only probe.

## Release status

The compatibility probe is not an AI-agent run and does not authorize production. `leftovers run
--execute` remains source-disabled before budget reservation, discovery, cloning, model invocation,
or publication. It cannot be enabled by TOML, the installed `sbx` CLI, a successful rehearsal, or
the Terra/high intent. Activation requires the separately reviewed strict evidence contract: live
clone isolation, an attested effective policy rather than finite canaries, credential isolation,
descriptor-stable binary execution, sandbox UUID/generation ownership, bounded result extraction,
fresh-sandbox verification, descendant-empty resource evidence, token receipts, crash recovery,
exact cleanup, and publisher separation. The existing macOS package remains a detached, read-only
scout so it can continue finding issue-rich, PR-constrained repositories without spending model
quota or writing to GitHub.

No software can honestly guarantee that a hypervisor, daemon, proxy, or host kernel has no exploitable
bug. Here, "sandboxed" means the concrete, tested boundaries above and a fail-closed response whenever
one cannot be proved.
