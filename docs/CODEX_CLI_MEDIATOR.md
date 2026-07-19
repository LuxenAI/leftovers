# Strict Codex CLI mediator (unimplemented release gate)

`leftovers.codex_cli_mediator` is a narrow, **hard-disabled** future boundary for a Codex
subscription provider. It is not the older `scripts/codex_adapter.py` host-preview adapter and it
does not enable `leftovers run --execute`.

The contemplated provider identity is exact: `openai-codex-cli`, `gpt-5.6-terra`, and `high`.
The controller would pin an absolute executable path, expected SHA-256, and an asserted exact
version label; live activation must independently prove the code-signature/dependency identity. It
would invoke an empty private working directory with an empty environment, no inherited
configuration/rules, no extra host directories, a new session, a monotonic deadline, bounded
stdin/stdout/stderr/events, and process-group termination proof. The fixed argv is deliberately
not configurable. Repository text and prompts remain untrusted input data.

That invocation is not authorized today. The Codex CLI configuration surface has not been
independently proven to remove every model tool capability (shell/code, app, browser, plugins,
MCP, memory, multi-agent, and other tools) while retaining subscription authentication. In
particular, a private `HOME`/`CODEX_HOME` needed to ignore user configuration also cannot be
assumed to retain an authenticated subscription. `PRODUCTION_CODEX_MEDIATION_ENABLED` and
`ZERO_TOOL_CONFIGURATION_PROVEN` are both compile-time `False`, and `mediate()` rejects before it
creates a ledger, temporary directory, subprocess, environment, or credential lookup. Do not flip
either value in a deployment configuration.

`verify_codex_cli_identity()` and `prepare_codex_invocation_plan()` now implement the
**non-executing** portion of this contract. The executable and output schema are opened with
`O_NOFOLLOW | O_NONBLOCK`, streamed through bounded SHA-256 calculations (rather than copied into
memory), and bound to stable device/inode/owner/mode/size/time metadata. Hard links, symlinks, writable
ancestors, mutable modes, wrong digests, special-file substitution, and replacement between
verification passes are rejected.
The invocation directory must already be an exact owner-only `0700` directory with trusted
ancestors and no entries; the only result name is `result.json`. The resulting plan has an empty
environment, fixed argv, bounded event/diagnostic limits, stdin prompt digest, schema digest,
deadline, complete validated file/directory metadata, request/limit binding, and an attestation
digest. It contains no provider credential and does not start a process. Empty environment is not
credential isolation: a future same-UID process could still resolve its account home, read other
host files, or contact Keychain/login services, so a dedicated service identity and OS capability
boundary remain mandatory.

The untrusted request JSON is length-and-digest-bound, then base64 encoded so request strings cannot
spoof the trusted framing delimiters. Before a plan is returned, a deliberately conservative
one-token-per-framed-byte estimate plus a 16,384-token provider-context reserve must fit the input
cap, and that estimate plus the full output cap must fit the total reservation. The reserve is
based on the observed CLI overhead with safety margin; it is an admission backstop, not a supported
provider quota API or proof that a future CLI version cannot add more context. A pinned tokenizer
and renewed version-specific evidence remain activation requirements. Codex-specific request bytes
are additionally capped at 1,500,000 so base64 expansion plus trusted framing always fits the
2,100,000-byte provider-prompt cap; the shared mediator's larger generic input ceiling does not
silently become a non-composable Codex limit.

This is still not a descriptor-to-exec authority. A future dedicated broker must revalidate the
same executable identity immediately before a descriptor-safe spawn, hold the private directory
by descriptor, capture output without unbounded buffering, enforce termination, and durably bind
the observation to its reply. `revalidate_codex_invocation_plan()` currently rebuilds and compares
the executable, schema, private-directory, argv, prompt, request, token, and deadline bindings,
including schema device/inode/owner/mode/size/time metadata. The plan attestation independently
hashes its actual argv, environment, stdin bytes, executable path, cwd, schema path, and result path
as well as the declared verification fields, so replacing a stored launch field changes the digest.
That detects stale-plan reuse but is still path-based and cannot replace a descriptor-safe spawn
critical section. The current Codex app
installation under `/Applications` is also ineligible for this high-assurance path because
`/Applications` is group-writable on this host; activation would require a separately provisioned,
root-owned immutable CLI location or an equivalently reviewed platform code-signature policy. No
installer performs that provisioning.

## Data contract prepared for a future reviewed broker

The only accepted model-authored output is the canonical JSON
[`codex-provider-envelope.schema.json`](../schemas/codex-provider-envelope.schema.json). It binds
the run, round, stage, exact model identity, and input digest; it carries an optional UTF-8 patch,
and intent-only actions. It cannot supply token usage or an apply-patch digest. The mediator
derives the patch SHA-256 itself, adds it to a newly canonical strict action batch, and sends that
batch through the existing allowlisted action validator. Thus the provider cannot choose an argv,
check command, host path, network, mount, credential, or publishing target.

Token accounting is a separate trust channel. `parse_codex_event_evidence()` accepts only a
bounded, complete CLI JSONL lifecycle with exact event fields and a bound item-ID state machine. It
rejects unknown/failure events and every item type except passive reasoning or agent messages, and
derives exact counts from the single terminal `turn.completed` record. Reasoning usage is mandatory
and totals must reconcile. The retained evidence includes the full stream SHA-256 and CLI thread
identity; the future broker authorization must bind that digest to the same semantic output and
ledger reservation. A model-authored response that adds a `usage` field is rejected as unknown.
This event check is necessary evidence, not a claim that the CLI cannot have an unreported tool
surface; the zero-tool production gate therefore remains closed.

The synthetic live record
[`2026-07-19-codex-zero-tool-probe.json`](../vm/evidence/2026-07-19-codex-zero-tool-probe.json)
pins Codex `0.145.0-alpha.18` and its executable SHA-256. One Terra/high turn in an empty private
read-only cwd returned `PROBE_OK`, emitted no tool item, and reported 11,794 total tokens. It also
showed that this CLI emits an atomic `item.completed` agent message and a separate
`cache_write_input_tokens` usage field; both are now part of the strict parser contract. This was
one real subscription call and is deliberately labeled observation rather than activation proof.

Before a future provider launch, `CodexTokenLedger.reserve()` would append and `fsync` a
hash-chained reservation under a private state root. Its immutable genesis record pins the run cap,
call cap, provider, model, and reasoning effort; each returned reservation identity is the persisted
event hash. It charges the whole requested total-token cap until a matching exact usage receipt
settles it. A crash after reservation is intentionally charged conservatively. Entries contain only
hashes and counts, never prompts, response text, patches, paths, diagnostics, or credentials.

This ledger is not yet an authority boundary. Another process under the same UID can delete or
roll back the entire state root and recompute an unkeyed chain. Production must move the ledger and
its durable anchor under the dedicated broker/service account; the local implementation is only a
bounded recovery and accounting contract.

The mediator/controller must not write a request, manifest, or scratch path that the strict-VM
launcher later opens. That same-UID race is reserved for a separately installed dedicated service
account described in [`STRICT_VM_BROKER.md`](STRICT_VM_BROKER.md). The broker protocol is also
hard-disabled and does not provide a path, argv, socket listener, or launcher invocation today.

## Activation evidence required

The parser and receipt types may be integrated only behind hard-disabled gates. Do not enable a
provider, broker authorization, strict VM epoch, or orchestrator path until a separate security
review supplies all of the following:

1. Official, version-pinned CLI evidence that the exact argv/config disables every model tool
   surface and ignores all user/project rules and extensions. The contemplated argv uses
   `--strict-config`, `--ephemeral`, `--ignore-user-config`, `--ignore-rules`, a read-only private
   cwd, an empty inherited shell environment, explicit feature disables, a controller-owned output
   schema/result path, and stdin-only prompting; none of those flags is treated as sufficient proof.
2. A credential broker that can authenticate the CLI without exposing user config, keychain access,
   a token, or a socket to the strict-VM guest or repository code.
3. Live tests proving private cwd/environment, capability absence, output/event limits, monotonic
   timeout, complete process-group cleanup, exact usage parsing, crash-reservation recovery, and
   no secrets in receipts.
4. A reviewed whole-cycle strict-VM integration with no remote writes, followed by adversarial
   escape/resource/cleanup evidence.

Until then the supported terminal command remains the scout-only command documented in the README:

```sh
./scripts/install-macos.sh --force-config --scout
```
