# Agent adapters

Leftovers v0.1 defines a provider-neutral process contract; it does **not** ship a runnable OpenAI,
Anthropic, local-model, or other provider adapter. The stock sandbox image supplies the execution
environment only. A deployment must build and review its own adapter before `run --execute` can
complete.

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
credential outside the repository container, but `agent.backend = "host"` is the lower-assurance
profile and cannot be used with v0.1 draft publication. Direct provider credentials plus bridge
networking should be limited to curated, explicitly risk-accepted dry runs; `network = "none"`
cannot reach a hosted model API.

Do not claim autonomous operation until the chosen adapter, credential topology, image digest,
network policy, and all stage outputs have been exercised in execute-only runs with no remote write.
