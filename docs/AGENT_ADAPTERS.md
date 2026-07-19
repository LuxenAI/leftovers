# Agent adapters

Leftovers defines a provider-neutral process contract. The stock sandbox image supplies the
rehearsal environment only. Container or host adapters cannot currently pass production admission.
Docker Sandboxes is the active integration candidate, but its present rehearsal is shell-only and
does not run an adapter, Codex, a provider call, or Terra/high inference; its execution facade is
source-disabled. A future deployment must satisfy the separately reviewed strict evidence contract
before it can publish.

For deterministic adapter testing, the repository also ships `scripts/codex_adapter.py`: a
**host-agent, rehearsal-only** adapter for the headless Codex CLI. It pins the model to
`gpt-5.6-terra` and reasoning effort to `high`; it is not a general OpenAI API adapter and it does not
turn a consumer subscription into a measurable token balance.

## Bundled Codex host-preview adapter

The adapter remains selected in the macOS package template for schema/config compatibility. It requires a
saved Codex CLI login and a Codex CLI at version `0.144.5` or newer. The desktop app/chat does not
need to remain running after installation; the CLI binary and its existing saved authentication must
remain available to the logged-in user.

For each planning, implementation, or review stage it runs `codex exec` with an ephemeral session,
strict config, ignored user/rule files, disabled plugins and interactive tools, no inherited shell
environment, `approval_policy = "never"`, disabled workspace network access, a strict JSON schema,
and a bounded JSONL usage receipt. Hard limits are 6 minutes for planning, 20 minutes for
implementation, and 8 minutes for review. The adapter enforces private output paths, bounded
prompt/events/diagnostics, process-group termination, and exact token arithmetic before reporting
usage to the controller.

Those controls are useful for tests, not a substitute for a separate trust boundary:

- The Codex process runs on the host and uses the host's saved subscription authentication.
- The adapter cannot receive GitHub credentials and cannot push, comment, fork, or open a PR.
- Configuration validation rejects host-agent use for `draft-pr` publication. The portable macOS
  bundle always renders `publication.mode = "dry-run"` and `external_writes_acknowledged = false`.
- The macOS launchd job does not receive `CODEX_HOME` or `LEFTOVERS_CODEX_BIN`, has a hard execution
  deny gate, and never invokes `run --execute` or `--publish`.
- The production orchestrator rejects host backends before budget, discovery, clone, or model work.

Use it only with the limits in [`MACOS_PACKAGE.md`](MACOS_PACKAGE.md) and the risk model in
[`../SECURITY.md`](../SECURITY.md). A production implementation still needs a narrow model mediator
that keeps provider credentials outside untrusted repository code and the full strict evidence
contract; a no-agent sbx rehearsal is not an adapter authorization.

## Process contract

`agent.command` is an argv array, never a shell string. The controller invokes that command for
planning, implementation, and independent-review stages. The adapter must:

1. read the complete prompt from standard input;
2. use `LEFTOVERS_STAGE` only to select the matching strict result shape;
3. write exactly one UTF-8 JSON object to `LEFTOVERS_RESULT_PATH` (inside a container this is
   `/out/result.json`);
4. when telemetry is required, append one check-in, ordered heartbeats, and at most one final usage
   receipt to `LEFTOVERS_TELEMETRY_PATH` (inside a container `/out/telemetry.ndjson`);
5. exit zero only after the result and final telemetry records are fully written; and
6. keep stdout/stderr diagnostic-only and within `agent.max_output_bytes`.

The required fields and status values are documented in [`PROTOCOL.md`](../PROTOCOL.md), enforced by
the Python runner, and summarized in
[`schemas/agent-result.schema.json`](../schemas/agent-result.schema.json). That schema retains a
legacy `pr-writer` shape, but unattended execution does not invoke it or publish its text. The
controller ignores an adapter's claims about tests and runs only the operator-curated command arrays
itself.

Telemetry is protocol input, not free-form logging. The strict shape is in
[`schemas/adapter-telemetry.schema.json`](../schemas/adapter-telemetry.schema.json); identity must
exactly match the configured provider/model, sequence numbers must be contiguous, timestamps must be
fresh and timezone-aware, and usage arithmetic must reconcile. Do not place prompts, responses,
credentials, paths, logs, or exceptions in this channel. See [`TELEMETRY.md`](TELEMETRY.md) for
qualification and dashboard semantics.

## OCI rehearsal adapter checklist

- Derive from `sandbox/Dockerfile`, add one reviewed executable, and set `agent.command` to it.
- Pin the final image by immutable digest before rehearsal; `latest` is a development warning.
- Ensure the image is already present locally. The runner uses `--pull=never`.
- Do not install or invoke `gh`, mount the runtime socket, mount host credential directories, or add
  GitHub credentials to `agent.pass_environment`.
- Smoke-test planning, implementation, and review result shapes against the runner before using a
  live repository.
- Keep repository setup/test commands separate from the adapter; those stages never inherit the
  adapter's pass-through environment.

## Provider credentials and networking

The container runner passes only names explicitly listed in `agent.pass_environment`, and config
validation rejects GitHub tokens, SSH-agent sockets, and runtime sockets. That allowlist does not make
a direct provider secret safe: the coding agent can execute untrusted repository code in the same
container, and a networked stage could expose the secret.

The archival strict-VM research has no NIC or socket, so it does not provide a generic external
broker. Any future mediator must keep credentials outside the worker, expose only bounded inference
semantics, and avoid general egress or a host-command channel. A provider CLI on the host cannot
satisfy that boundary merely because its tool subprocesses use a sandbox. Production also rejects
direct provider environment variables and every bridge-network override.

[`CODEX_CLI_MEDIATOR.md`](CODEX_CLI_MEDIATOR.md) records a separate hard-disabled Codex
subscription mediator protocol: canonical provider envelopes, controller-derived patch digests,
exact usage arithmetic, and crash-conservative hash-chained token reservations. It does **not**
make the CLI runnable. Activation requires official version-pinned proof that every model tool
surface is disabled and a credential topology that never reaches the VM guest.

Do not claim autonomous operation until the strict source-disabled execution boundary, narrow
credential-isolating model mediator, bounded result extractor, chosen adapter, and cleanup path are
integrated and exercised with live adversarial evidence and no remote write. Adapter, OCI, or sbx
rehearsal checks alone do not authorize production.
