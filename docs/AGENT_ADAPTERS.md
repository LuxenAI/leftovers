# Agent adapters

Leftovers defines a provider-neutral process contract and ships one first-party execute-only
integration for Codex CLI. Anthropic, local-model, and other providers still require a deployment to
build and review its own adapter. The stock sandbox image supplies the execution environment only.

## First-party Codex CLI backend

`agent.backend = "codex-cli"` invokes only the configured Codex executable; extra user-supplied
arguments and `pass_environment` entries are rejected. The controller selects the model and builds
all noninteractive, structured-output, permission, feature-disable, and result-path arguments.
Planning and review are read-only; implementation can write only the temporary workspace. Model-run
commands have no network and do not inherit the Codex process environment.

The Codex process receives only the small host environment needed to find its saved login. GitHub,
OpenAI API, Codex access-token, SSH-agent, cloud, and arbitrary variables are not forwarded. User
config and automatic project instruction injection are disabled, as are project rules, hooks, apps,
web search, subagents, and remote plugins. Exact final usage is converted from Codex JSONL into the
normal adapter telemetry protocol. The execution uses an empty isolated `HOME`, denies `.agents` and
`.codex` reads, and refuses a repository-local `.agents/skills` tree so repository skills cannot
become a higher-priority instruction channel.

This backend requires Codex CLI 0.145.0 or newer and a model present in its bundled catalog. It is a
lower-assurance host process and is rejected in `draft-pr` mode. Use `leftovers setup codex` and see
[`CODEX_CLI.md`](CODEX_CLI.md) for activation and limitations.

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

## Container adapter checklist

- Derive from `sandbox/Dockerfile`, add one reviewed executable, and set `agent.command` to it.
- Pin the final image by immutable digest before unattended use; `latest` is a development warning.
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

For higher assurance, use an external model/tool broker that keeps provider credentials outside the
worker and exposes only the minimum inference operation. A provider CLI on the host may keep its
credential outside the repository container, but `host` and `codex-cli` are lower-assurance profiles
and cannot be used with draft publication. Direct provider credentials plus bridge networking
should be limited to curated, explicitly risk-accepted dry runs; `network = "none"` cannot reach a
hosted model API from a generic container adapter.

Do not claim autonomous operation until the chosen adapter, credential topology, image digest,
network policy, and all stage outputs have been exercised in execute-only runs with no remote write.
