# Codex CLI backend

Leftovers includes a controller-owned `codex-cli` backend for execute-only dry runs using an
operator's saved Codex CLI login. It is the shortest supported path from a ChatGPT Codex plan to a
locally verified candidate patch. It is not a plan-balance scraper, shared quota pool, remote worker,
or automatic PR publisher.

## Prerequisites

- Python 3.11 or newer, Git, and Leftovers;
- Codex CLI 0.145.0 or newer;
- a saved Codex login (`codex login`, then `codex login status`);
- a read-only public-repository token in `GITHUB_TOKEN` for live scouting;
- Docker or Podman plus a locally built `leftovers-sandbox:latest` image for offline test execution
  and cleanup proof; and
- `gh` only for a future, separately reviewed publication path.

ChatGPT sign-in uses included subscription access when the account and workspace support it. API-key
login uses separately billed API usage. Leftovers does not pass `OPENAI_API_KEY`, `CODEX_API_KEY`,
`CODEX_ACCESS_TOKEN`, GitHub credentials, SSH agent sockets, or arbitrary environment values into
the agent process. Prefer OS keyring credential storage and treat file-based `auth.json` as a
password. See the official [Codex authentication](https://learn.chatgpt.com/docs/auth) documentation.

## Guided setup

For an interactive owner-only configuration wizard:

```sh
leftovers --config config/leftovers.toml setup codex
```

The wizard asks for one allowlisted `owner/name` repository, a reviewed SPDX license, an HTTPS
source showing that AI-assisted contributions are permitted, one or more offline test argv arrays,
and an explicit daily or weekly token envelope. It writes a new mode-`0600` config in `dry-run` mode
and refuses to overwrite any existing file or symlink.

A non-interactive example is:

```sh
leftovers --config config/leftovers.toml setup codex \
  --repository owner/project \
  --ai-policy-url https://github.com/owner/project/blob/main/CONTRIBUTING.md \
  --ai-policy-reviewed \
  --allowed-license MIT \
  --test-command-json '["python","-m","pytest","-q"]' \
  --allocated-tokens 150000
```

Setup only diagnoses prerequisites. It does not install host packages, copy a token, log in on the
operator's behalf, build the sandbox image, enable publication, or install a scheduler. Review every
generated repository field before running a live scout.

## Execution boundary

For each model stage, Leftovers constructs `codex exec` arguments itself and uses ephemeral,
noninteractive, strict structured output. The adapter:

- selects the configured model explicitly;
- disables approval prompts while keeping a least-privilege permission profile;
- grants model-run commands only minimal runtime reads and the temporary repository;
- keeps planning/review read-only and grants workspace write only during implementation;
- disables model-command network, web search, user config, automatic `AGENTS.md` injection,
  execution rules, hooks, apps, memories, goals, subagents, remote plugins, and shell snapshots;
- uses an empty isolated `HOME` for repository execution while retaining only `CODEX_HOME` for the
  CLI's own saved authentication;
- denies `.agents`, `.codex`, common `.env`, PEM, and key-file reads inside the workspace, and
  refuses repositories that contain a discoverable `.agents/skills` tree;
- captures exact final usage from Codex JSONL and validates it through the existing telemetry
  protocol; and
- writes the final JSON through a closed, stage-specific schema outside the model's workspace.

The controller then checks Git metadata and the canonical diff, runs only operator-curated offline
commands inside the hardened container, performs a fresh review, and proves label-scoped container
cleanup before deleting the workspace. The coding process never receives GitHub publication
credentials. The official [`codex exec`](https://learn.chatgpt.com/docs/developer-commands?surface=cli#cli-codex-exec)
and [permission profiles](https://learn.chatgpt.com/docs/permissions) documentation describe the
underlying Codex controls.

## Activation

Run these in order:

```sh
leftovers --config config/leftovers.toml validate
leftovers --config config/leftovers.toml doctor
leftovers --config config/leftovers.toml scout
leftovers --config config/leftovers.toml run --execute
```

Inspect the hash-chained journal and cleanup receipt after every execute-only run. Complete at least
three successful dry runs before considering any publication work.

## Limits

- Codex still runs as a local process under the operator account. Permission profiles materially
  reduce model-command access, but this is not equivalent to a disposable VM/microVM.
- A container runtime remains mandatory because setup and verification commands do not run on the
  host.
- The configured token envelope is local admission control. It is not an exact view of remaining
  ChatGPT plan allowance and cannot force a provider-side cutoff.
- `codex-cli` is rejected in `draft-pr` mode. Publication remains a separate future hardening step.
- The selected model must remain available in the installed Codex CLI's bundled catalog; `doctor`
  fails closed when the CLI, login, version, or model check fails.
