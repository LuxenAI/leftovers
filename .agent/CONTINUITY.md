# Project continuity

## 2026-07-18: guided Codex CLI dry-run backend

- Added a first-party `codex-cli` backend so an operator's saved ChatGPT Codex login can power
  planning, implementation, and review without copying credentials into a repository container.
- The controller owns every Codex argument. Configuration may name only the Codex executable and
  model; extra CLI arguments and environment pass-through are rejected.
- Codex 0.145.0 or newer is required because the adapter uses permission profiles and a fixed set of
  current feature-disable controls. Model-run commands receive only minimal runtime reads and the
  temporary workspace, with network disabled and credential-like workspace files denied. User
  config, project instruction injection, rules, hooks, apps, web search, subagents, and shell
  snapshots are disabled for each run. Repository-local Codex skills are refused and execution uses
  an empty isolated `HOME`; only `CODEX_HOME` remains visible to the CLI process for saved auth.
- Planning and review receive a read-only workspace. Implementation receives workspace write.
  Leftovers still performs its own Git metadata checks, canonical diff gates, offline container
  verification, independent review, telemetry validation, and cleanup proof.
- `leftovers setup codex` creates a new mode-0600 dry-run config only after the operator confirms the
  repository AI policy, SPDX license, offline test argv, and quota envelope. It detects but does not
  install Python, Git, Codex, `gh`, or Docker/Podman, and it does not install a scheduler.
- The Codex CLI backend remains lower assurance than a fresh VM/microVM and is intentionally blocked
  from `draft-pr` mode. A later publication PR should add a sealed approval/resume boundary before
  reconsidering that restriction.
