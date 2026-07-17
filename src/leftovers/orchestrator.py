from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .audit import AuditJournal
from .budget import BudgetError, BudgetGate, BudgetLedger, budget_window_key
from .config import AppConfig, RepositoryConfig
from .github import GitHubClient, GitHubError, IssueSource
from .models import (
    FailureCode,
    RankedCandidate,
    RunOutcome,
    RunStage,
    utc_now,
)
from .policy import (
    DiffInspection,
    candidate_gate,
    controller_git_env,
    controller_git_prefix,
    diff_gate,
    inspect_diff,
    unsafe_git_configuration,
)
from .prompts import render_prompt
from .publisher import GhPublisher, PublicationError, create_approval_bundle
from .runner import AgentOutputError, AgentRunner, RunnerError
from .scoring import score_issue
from .state import PublicationLedger, StatePolicyError
from .telemetry import TERMINAL_RUN_STAGES, TelemetryWriter
from .workspace import WorkspaceError, WorkspaceLease


class RunAbort(RuntimeError):
    def __init__(self, code: FailureCode, message: str, stage: RunStage = RunStage.ABORTED):
        super().__init__(message)
        self.code = code
        self.stage = stage


def _mark_cleanup_pending(outcome: RunOutcome, cleanup_message: str) -> None:
    """Record cleanup failure without hiding a more urgent primary failure."""
    previous_code = outcome.failure_code
    previous_message = outcome.message
    outcome.stage = RunStage.CLEANUP_PENDING
    if previous_code is None:
        outcome.failure_code = FailureCode.CLEANUP_FAILED
        outcome.message = cleanup_message
        return
    outcome.message = (
        f"{previous_message}; additionally, {cleanup_message}"
        if previous_message
        else cleanup_message
    )


def rank_candidates(config: AppConfig, source: IssueSource) -> list[RankedCandidate]:
    issues = source.discover(
        config.repositories, config.discovery.query, config.discovery.per_repo_limit
    )[: config.discovery.max_candidates]
    repositories = {repo.slug: repo for repo in config.repositories}
    ranked: list[RankedCandidate] = []
    for issue in issues:
        repository = repositories[issue.repo.slug]
        score = score_issue(issue, repository, config.scoring)
        failures = candidate_gate(
            issue,
            score,
            repository,
            config.policy,
            config.scoring.minimum_score,
        )
        ranked.append(
            RankedCandidate(
                issue=issue,
                score=score,
                eligible=not failures,
                gate_failures=failures,
                estimated_tokens_p50=config.agent.estimated_tokens_p50,
                estimated_tokens_p95=config.agent.estimated_tokens_p95,
            )
        )
    return sorted(ranked, key=lambda candidate: candidate.score.total, reverse=True)


def ranked_to_dict(candidate: RankedCandidate) -> dict[str, Any]:
    return {
        "issue": {
            "ref": candidate.issue.ref,
            "url": candidate.issue.url,
            "title": candidate.issue.title,
            "labels": list(candidate.issue.labels),
            "assignees": list(candidate.issue.assignees),
            "state": candidate.issue.state,
            "has_open_linked_pr": candidate.issue.has_open_linked_pr,
        },
        "eligible": candidate.eligible,
        "gate_failures": list(candidate.gate_failures),
        "score": candidate.score.to_dict(),
        "estimated_tokens_p50": candidate.estimated_tokens_p50,
        "estimated_tokens_p95": candidate.estimated_tokens_p95,
    }


def _git(workspace: Path, *args: str) -> str:
    dangerous_config = unsafe_git_configuration(workspace)
    if dangerous_config:
        raise RunAbort(
            FailureCode.POLICY_DENIED,
            "repository contains unsafe local Git configuration: " + ", ".join(dangerous_config),
        )
    result = subprocess.run(
        [*controller_git_prefix(), *args],
        cwd=workspace,
        text=True,
        capture_output=True,
        timeout=60,
        env=controller_git_env(workspace),
    )
    if result.returncode != 0:
        raise RunAbort(FailureCode.AGENT_FAILED, f"git {args[0]} failed: {result.stderr[-1000:]}")
    return result.stdout.strip()


def _repository_context(workspace: Path, maximum_bytes: int = 200_000) -> dict[str, str]:
    names = (
        "AGENTS.md",
        "CONTRIBUTING.md",
        "CONTRIBUTING.rst",
        ".github/CONTRIBUTING.md",
        "README.md",
        "SECURITY.md",
    )
    context: dict[str, str] = {}
    remaining = maximum_bytes
    root = workspace.resolve()
    for name in names:
        path = workspace / name
        if remaining <= 0 or path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
            raw = path.read_bytes()[:remaining]
        except (OSError, ValueError):
            continue
        text = raw.decode("utf-8", errors="replace")
        context[name] = text
        remaining -= len(raw)
    return context


def _task_envelopes(
    *,
    candidate: RankedCandidate,
    repository: RepositoryConfig,
    config: AppConfig,
    base_sha: str,
    repository_context: dict[str, str],
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    issue = candidate.issue
    trusted = {
        "target": {
            "repository": issue.repo.slug,
            "issue_number": issue.number,
            "issue_node_id": issue.node_id,
            "base_sha": base_sha,
        },
        "limits": {
            "max_changed_files": min(
                repository.max_changed_files or config.policy.max_changed_files,
                config.policy.max_changed_files,
            ),
            "max_changed_lines": min(
                repository.max_changed_lines or config.policy.max_changed_lines,
                config.policy.max_changed_lines,
            ),
            "forbid_paths": [*config.policy.forbid_paths, *repository.forbid_paths],
            "forbid_dependency_changes": config.policy.forbid_dependency_changes,
            "no_github_writes": True,
        },
        "configured_verification_commands": [list(command) for command in repository.test_commands],
    }
    untrusted: dict[str, Any] = {
        "issue": {
            "ref": issue.ref,
            "url": issue.url,
            "title": issue.title,
            "body": issue.body[:50_000],
            "labels": list(issue.labels),
        },
        "repository_instruction_files": repository_context,
    }
    if prior:
        untrusted.update(prior)
    return {"trusted": trusted, "untrusted": untrusted}


def _markdown_code(value: str) -> str:
    clean = re.sub(r"[\x00-\x1f\x7f]", " ", value).replace("`", "'")
    return f"`{clean}`"


def _render_pr_copy(
    candidate: RankedCandidate,
    diff: DiffInspection,
    tests: list[Any],
) -> tuple[str, str]:
    """Render publishable text only from controller-observed, bounded facts."""
    issue = candidate.issue
    clean_issue_title = re.sub(r"[\x00-\x1f\x7f]+", " ", issue.title).strip()
    title = f"Address #{issue.number}: {clean_issue_title}"
    changed_files = "\n".join(f"- {_markdown_code(path)}" for path in diff.files)
    verification = "\n".join(
        f"- Configured check {index} — exit {result.exit_code}"
        for index, result in enumerate(tests, start=1)
    )
    body = f"""## Summary

This draft proposes a focused change related to #{issue.number}.

- Files changed: {len(diff.files)}
- Lines changed: {diff.changed_lines} (+{diff.added_lines}/-{diff.deleted_lines})

## Changed files

{changed_files}

## Verification

{verification}

## Review status

The frozen patch and the captured checks passed an independent automated review. Maintainer review
is still required; this pull request remains a draft.

Related to #{issue.number}.

## Disclosure

Prepared with AI assistance under the repository policy recorded by Leftovers. The title, scope,
verification list, and disclosure in this body were rendered by deterministic controller code.
"""
    return title[:240], body[:60_000]


def _bounded_test_failures(results: list[Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for ordinal, result in enumerate(results, start=1):
        if result.passed:
            continue
        failures.append(
            {
                "configured_check_ordinal": ordinal,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "stdout_tail": result.stdout_tail[-4_000:],
                "stderr_tail": result.stderr_tail[-4_000:],
            }
        )
        if len(failures) == 4:
            break
    return failures


class _RunTelemetry:
    """Best-effort safe-field projection; it never controls admission or publication."""

    def __init__(
        self,
        config: AppConfig,
        run_id: str,
        run_kind: str,
        journal: AuditJournal,
    ) -> None:
        self.config = config
        self.run_id = run_id
        self.run_kind = run_kind
        self.journal = journal
        self.writer: TelemetryWriter | None = None
        self.degraded = False
        self.attempts: dict[str, int] = {}
        self.cleanup_status = "not_started"
        try:
            self.writer = TelemetryWriter(config.state_dir)
            self.writer.start_run(run_id, run_kind=run_kind)
        except Exception as exc:  # telemetry is deliberately non-authoritative
            self._degrade("start_run", exc)

    def _degrade(self, operation: str, error: Exception) -> None:
        if self.degraded:
            return
        self.degraded = True
        with suppress(OSError):
            self.journal.append(
                "telemetry_degraded",
                reason_code="telemetry_write_failed",
                operation=operation,
                error_type=type(error).__name__,
            )

    def _safe(self, operation: str, *args: Any, **kwargs: Any) -> Any:
        if self.writer is None:
            return None
        try:
            return getattr(self.writer, operation)(*args, **kwargs)
        except Exception as exc:  # telemetry cannot change the security outcome
            self._degrade(operation, exc)
            return None

    def transition(self, stage: RunStage | str, **detail: Any) -> None:
        value = stage.value if isinstance(stage, RunStage) else stage
        if value not in TERMINAL_RUN_STAGES:
            self._safe("transition_run", self.run_id, value, detail=detail or None)

    def event(self, event_type: str, *, stage: RunStage | str, **detail: Any) -> None:
        value = stage.value if isinstance(stage, RunStage) else stage
        self._safe(
            "record_event",
            self.run_id,
            event_type,
            stage=value,
            detail=detail or None,
        )

    def set_target(self, candidate: RankedCandidate) -> None:
        self._safe(
            "set_run_target",
            self.run_id,
            repository=candidate.issue.repo.slug,
            issue_number=candidate.issue.number,
            score=candidate.score.total,
        )

    def record_budget(
        self,
        snapshot: Any,
        *,
        window_key: str,
        reserved_tokens: int,
        reservation_state: str,
    ) -> None:
        if self.run_kind == "training":
            source = "synthetic"
        elif snapshot.source.startswith("environment:"):
            source = "environment"
        elif snapshot.source in {"fixed-envelope", "cli-override"}:
            source = snapshot.source
        else:
            source = "provider-adapter"
        reservation_id = self.run_id if reservation_state != "snapshot" else None
        self._safe(
            "record_budget_projection",
            f"{self.run_id}:budget:{reservation_state}",
            run_kind=self.run_kind,
            window_key=window_key,
            maximum_tokens=snapshot.maximum_tokens,
            remaining_tokens=snapshot.remaining_tokens,
            reserve_tokens=snapshot.reserve_tokens,
            reserved_tokens=reserved_tokens,
            source=source,
            reservation_state=reservation_state,
            run_id=self.run_id,
            reservation_id=reservation_id,
            observed_at=snapshot.observed_at,
        )

    def start_invocation(self, stage: str, run_token_cap: int | None) -> tuple[str | None, int]:
        attempt = self.attempts.get(stage, 0) + 1
        self.attempts[stage] = attempt
        invocation_id = self._safe(
            "start_model_invocation",
            self.run_id,
            stage=stage,
            attempt=attempt,
            backend="training" if self.run_kind == "training" else self.config.agent.backend,
            expected_provider=self.config.agent.provider,
            expected_model=self.config.agent.model,
            run_token_cap=run_token_cap,
        )
        return invocation_id if isinstance(invocation_id, str) else None, attempt

    def model_event(self, invocation_id: str | None, event: dict[str, Any]) -> None:
        if invocation_id is None:
            return
        event_type = event.get("type")
        observed_at = event.get("observed_at")
        if event_type == "controller_heartbeat":
            self._safe(
                "heartbeat_model",
                invocation_id,
                source="controller",
                observed_at=observed_at,
            )
        elif event_type == "checkin":
            self._safe(
                "record_model_checkin",
                invocation_id,
                observed_provider=event.get("provider"),
                observed_model=event.get("model"),
                source="synthetic" if self.run_kind == "training" else "adapter_reported",
                checked_in_at=observed_at,
            )
        elif event_type == "heartbeat":
            self._safe(
                "heartbeat_model",
                invocation_id,
                source="adapter",
                observed_at=observed_at,
            )

    def finish_invocation(
        self,
        invocation_id: str | None,
        *,
        stage: str,
        attempt: int,
        result: Any | None = None,
        failure_code: str | None = None,
    ) -> None:
        if invocation_id is None:
            return
        if result is not None and result.usage is not None:
            self._safe(
                "record_model_usage",
                invocation_id,
                f"{stage}:{attempt}:final",
                result.usage,
                is_final=True,
            )
        self._safe(
            "finish_model_invocation",
            invocation_id,
            "succeeded" if result is not None else "failed",
            exit_code=result.command.exit_code if result is not None else None,
            failure_code=failure_code,
        )

    def cleanup(self, *, containers_removed: bool, workspace_removed: bool) -> None:
        proven = containers_removed and workspace_removed
        self.cleanup_status = "proven" if proven else "failed"
        self._safe(
            "set_cleanup_status",
            self.run_id,
            self.cleanup_status,
            containers_removed=containers_removed,
            workspace_removed=workspace_removed,
        )

    def finish(self, outcome: RunOutcome, *, selection_only: bool) -> None:
        stage = outcome.stage.value
        status_code: str | None = None
        if stage == RunStage.SELECTED.value and selection_only:
            self.transition(RunStage.SELECTED)
            stage = RunStage.COMPLETE.value
            status_code = "selection_only"
        elif stage not in TERMINAL_RUN_STAGES:
            stage = RunStage.FAILED.value
            status_code = "incomplete_lifecycle"
        cleanup_status = (
            "failed" if outcome.stage == RunStage.CLEANUP_PENDING else self.cleanup_status
        )
        self._safe(
            "finish_run",
            self.run_id,
            stage,
            failure_code=outcome.failure_code.value if outcome.failure_code else None,
            safe_status_code=status_code,
            pr_url=outcome.pr_url,
            cleanup_status=cleanup_status,
        )


class ContributionOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        source: IssueSource,
        *,
        runner: AgentRunner | None = None,
        publisher: GhPublisher | None = None,
        lease_factory: Callable[[Path, str], WorkspaceLease] | None = None,
        run_kind: str = "production",
    ):
        if run_kind not in {"production", "training"}:
            raise ValueError("run_kind must be production or training")
        self.config = config
        self.source = source
        self.runner = runner or AgentRunner(config.sandbox, config.agent)
        if run_kind != "training" and getattr(self.runner, "allow_synthetic_usage", False):
            raise ValueError("synthetic usage may only be enabled for a training orchestrator")
        self.publisher = publisher or GhPublisher(config.publication)
        self.lease_factory = lease_factory or WorkspaceLease
        self.run_kind = run_kind

    def scout(self) -> list[RankedCandidate]:
        return rank_candidates(self.config, self.source)

    def _run_agent(
        self,
        telemetry: _RunTelemetry,
        stage: str,
        workspace: Path,
        prompt: Any,
        run_id: str,
        *,
        read_only_workspace: bool,
        deadline: float | None,
        run_token_cap: int,
    ) -> Any:
        invocation_id, attempt = telemetry.start_invocation(stage, run_token_cap)
        try:
            result = self.runner.run_agent(
                stage,
                workspace,
                prompt,
                run_id,
                read_only_workspace=read_only_workspace,
                deadline=deadline,
                telemetry_callback=lambda event: telemetry.model_event(invocation_id, event),
            )
        except BaseException:
            telemetry.finish_invocation(
                invocation_id,
                stage=stage,
                attempt=attempt,
                failure_code="agent_invocation_failed",
            )
            raise
        telemetry.finish_invocation(
            invocation_id,
            stage=stage,
            attempt=attempt,
            result=result,
        )
        return result

    def run(
        self,
        *,
        execute_work: bool,
        publish: bool,
        remaining_tokens: int | None = None,
    ) -> RunOutcome:
        run_id = uuid.uuid4().hex
        outcome = RunOutcome(run_id=run_id, stage=RunStage.SCHEDULED)
        journal = AuditJournal(self.config.state_dir, run_id)
        telemetry = _RunTelemetry(self.config, run_id, self.run_kind, journal)
        journal.append(
            "state",
            stage=RunStage.SCHEDULED,
            run_kind=self.run_kind,
            provider=self.config.agent.provider,
            model=self.config.agent.model,
        )
        try:
            return self._run_cycle(
                run_id=run_id,
                outcome=outcome,
                journal=journal,
                telemetry=telemetry,
                execute_work=execute_work,
                publish=publish,
                remaining_tokens=remaining_tokens,
            )
        except (
            RunnerError,
            WorkspaceError,
            PublicationError,
            GitHubError,
            OSError,
            sqlite3.Error,
            subprocess.SubprocessError,
        ) as exc:
            publication_uncertain = outcome.stage in {
                RunStage.PUBLISHING,
                RunStage.PR_OPEN,
            }
            outcome.stage = RunStage.FAILED
            if publication_uncertain or isinstance(exc, PublicationError):
                outcome.failure_code = FailureCode.PUBLISH_PARTIAL
            elif isinstance(exc, GitHubError):
                outcome.failure_code = (
                    FailureCode.RATE_LIMITED if exc.retryable else FailureCode.AUTH_FAILED
                )
            elif isinstance(exc, AgentOutputError):
                outcome.failure_code = FailureCode.INVALID_OUTPUT
            elif isinstance(exc, RunnerError) and "not installed" in str(exc):
                outcome.failure_code = FailureCode.RUNTIME_UNAVAILABLE
            else:
                outcome.failure_code = FailureCode.AGENT_FAILED
            outcome.message = str(exc)
            journal.append("failed", failure_code=outcome.failure_code, reason=str(exc))
            return outcome
        finally:
            telemetry.finish(outcome, selection_only=not execute_work)

    def _run_cycle(
        self,
        *,
        run_id: str,
        outcome: RunOutcome,
        journal: AuditJournal,
        telemetry: _RunTelemetry,
        execute_work: bool,
        publish: bool,
        remaining_tokens: int | None,
    ) -> RunOutcome:
        if publish:
            if not execute_work:
                outcome.stage = RunStage.ABORTED
                outcome.failure_code = FailureCode.POLICY_DENIED
                outcome.message = "publication requires execution"
                journal.append("aborted", reason=outcome.message)
                return outcome
            try:
                self.publisher.assert_authorized(True)
            except PublicationError as exc:
                outcome.stage = RunStage.ABORTED
                outcome.failure_code = FailureCode.POLICY_DENIED
                outcome.message = str(exc)
                journal.append("aborted", reason=outcome.message)
                return outcome
        if execute_work and getattr(os, "geteuid", lambda: 1)() == 0:
            outcome.stage = RunStage.ABORTED
            outcome.failure_code = FailureCode.POLICY_DENIED
            outcome.message = "controller execution as root is forbidden"
            journal.append("aborted", reason=outcome.message)
            return outcome
        try:
            snapshot = BudgetGate(self.config.budget).snapshot(remaining_tokens)
        except BudgetError as exc:
            outcome.stage = RunStage.DEFERRED
            outcome.failure_code = FailureCode.BUDGET_EXHAUSTED
            outcome.message = str(exc)
            journal.append("deferred", reason=outcome.message)
            return outcome
        outcome.stage = RunStage.BUDGET_CHECK
        telemetry.transition(outcome.stage)
        journal.append("budget", snapshot=snapshot)
        window_key = budget_window_key(self.config.budget, snapshot.observed_at)
        try:
            ledger = BudgetLedger(self.config.state_dir, self.config.budget)
            reserved_before = ledger.reserved_tokens(window_key)
        except (OSError, sqlite3.Error) as exc:
            outcome.stage = RunStage.FAILED
            outcome.failure_code = FailureCode.AGENT_FAILED
            outcome.message = f"budget ledger unavailable: {exc}"
            journal.append("failed", failure_code=outcome.failure_code, reason=outcome.message)
            return outcome
        telemetry.record_budget(
            snapshot,
            window_key=window_key,
            reserved_tokens=reserved_before,
            reservation_state="snapshot",
        )
        can_start, reason = BudgetGate(self.config.budget).can_start(
            snapshot, self.config.agent.estimated_tokens_p95
        )
        if not can_start:
            outcome.stage = RunStage.DEFERRED
            outcome.failure_code = FailureCode.BUDGET_EXHAUSTED
            outcome.message = reason
            journal.append("deferred", reason=reason)
            return outcome

        outcome.stage = RunStage.DISCOVERING
        telemetry.transition(outcome.stage)
        journal.append("state", stage=outcome.stage)
        try:
            ranked = self.scout()
        except GitHubError as exc:
            outcome.stage = RunStage.DEFERRED if exc.retryable else RunStage.FAILED
            outcome.failure_code = (
                FailureCode.RATE_LIMITED if exc.retryable else FailureCode.AGENT_FAILED
            )
            outcome.message = str(exc)
            journal.append("github_read_failed", reason=outcome.message)
            return outcome
        journal.append("candidates", candidates=[ranked_to_dict(item) for item in ranked])
        publication_ledger: PublicationLedger | None = None
        eligible_candidates = [item for item in ranked if item.eligible]
        if publish:
            publication_ledger = PublicationLedger(self.config.state_dir)
            publication_window = window_key
            selected = None
            repositories = {repo.slug: repo for repo in self.config.repositories}
            for candidate in eligible_candidates:
                repository = repositories[candidate.issue.repo.slug]
                if repository.require_human_approval:
                    journal.append(
                        "publication_preflight_denied",
                        issue_ref=candidate.issue.ref,
                        reason="repository requires per-PR human approval",
                    )
                    continue
                try:
                    publication_ledger.check_available(
                        window_key=publication_window,
                        repository=repository.slug,
                        config=self.config.publication,
                    )
                except StatePolicyError as exc:
                    journal.append(
                        "publication_preflight_denied",
                        issue_ref=candidate.issue.ref,
                        reason=str(exc),
                    )
                    continue
                selected = candidate
                break
        else:
            selected = next(iter(eligible_candidates), None)
        if selected is None:
            outcome.stage = RunStage.SKIPPED
            outcome.failure_code = FailureCode.NO_CANDIDATE
            outcome.message = (
                "no candidate passed deterministic policy and publication preflight gates"
                if publish
                else "no candidate passed deterministic policy gates"
            )
            journal.append("skipped", reason=outcome.message)
            return outcome
        outcome.issue_ref = selected.issue.ref
        outcome.score = selected.score.total
        outcome.stage = RunStage.SELECTED
        telemetry.set_target(selected)
        telemetry.transition(outcome.stage)
        journal.append("selected", candidate=ranked_to_dict(selected))
        if not execute_work:
            outcome.message = (
                "candidate selected; rerun with --execute to create a disposable workspace"
            )
            return outcome

        repository = next(
            repo for repo in self.config.repositories if repo.slug == selected.issue.repo.slug
        )
        if not repository.test_commands:
            outcome.stage = RunStage.ABORTED
            outcome.failure_code = FailureCode.POLICY_DENIED
            outcome.message = "repository has no operator-curated verification command"
            journal.append("aborted", reason=outcome.message)
            return outcome

        if not self.runner.runtime_available():
            outcome.stage = RunStage.FAILED
            outcome.failure_code = FailureCode.RUNTIME_UNAVAILABLE
            outcome.message = f"{self.config.sandbox.runtime} is not installed or not on PATH"
            journal.append("failed", failure_code=outcome.failure_code, reason=outcome.message)
            return outcome

        try:
            reservation = ledger.reserve(run_id, snapshot, self.config.agent.estimated_tokens_p95)
        except BudgetError as exc:
            outcome.stage = RunStage.DEFERRED
            outcome.failure_code = FailureCode.BUDGET_EXHAUSTED
            outcome.message = str(exc)
            journal.append("deferred", reason=outcome.message)
            return outcome
        journal.append("budget_reserved", reservation=reservation)
        telemetry.record_budget(
            snapshot,
            window_key=window_key,
            reserved_tokens=ledger.reserved_tokens(window_key),
            reservation_state="reserved",
        )
        if snapshot.resets_at is None:
            outcome.stage = RunStage.DEFERRED
            outcome.failure_code = FailureCode.BUDGET_EXHAUSTED
            outcome.message = "quota reset time is unknown"
            journal.append("deferred", reason=outcome.message)
            return outcome
        seconds_until_reset = (snapshot.resets_at - utc_now()).total_seconds()
        run_seconds = min(
            self.config.budget.max_run_seconds,
            int(seconds_until_reset - self.config.budget.reset_safety_seconds),
        )
        if run_seconds < 1:
            outcome.stage = RunStage.DEFERRED
            outcome.failure_code = FailureCode.BUDGET_EXHAUSTED
            outcome.message = "quota-window deadline expired before execution"
            journal.append("deferred", reason=outcome.message)
            return outcome
        run_deadline = time.monotonic() + run_seconds

        lease = self.lease_factory(self.config.temp_root, run_id)
        cleanup_needed = False
        try:
            lease.__enter__()
            cleanup_needed = True
            outcome.stage = RunStage.PREFLIGHT
            telemetry.transition(outcome.stage)
            journal.append("state", stage=outcome.stage)
            branch = repository.default_branch or selected.issue.repo.default_branch
            workspace = lease.clone(repository.slug, branch)
            base_sha = _git(workspace, "rev-parse", "HEAD")
            context = _repository_context(workspace)
            outcome.stage = RunStage.SANDBOX_READY
            telemetry.transition(outcome.stage)
            telemetry.event("sandbox_ready", stage=outcome.stage)
            journal.append("sandbox_ready", base_sha=base_sha, context_files=sorted(context))

            envelope = _task_envelopes(
                candidate=selected,
                repository=repository,
                config=self.config,
                base_sha=base_sha,
                repository_context=context,
            )
            outcome.stage = RunStage.PLANNING
            telemetry.transition(outcome.stage)
            planning_prompt = render_prompt("planning", envelope)
            journal.append("prompt", stage="planning", sha256=planning_prompt.sha256)
            plan = self._run_agent(
                telemetry,
                "planning",
                workspace,
                planning_prompt,
                run_id,
                read_only_workspace=True,
                deadline=run_deadline,
                run_token_cap=reservation.reserved_tokens,
            )
            journal.append(
                "agent_result", stage="planning", status=plan.status, payload=plan.payload
            )
            if plan.status != "planned":
                raise RunAbort(
                    FailureCode.NO_REPRODUCTION,
                    "planning agent could not produce a safe plan",
                )
            planned_remaining = plan.payload.get("estimated_remaining_tokens")
            if (
                isinstance(planned_remaining, int)
                and planned_remaining > reservation.reserved_tokens
            ):
                raise RunAbort(
                    FailureCode.BUDGET_EXHAUSTED,
                    "planning estimate exceeds the reserved quota envelope",
                    RunStage.DEFERRED,
                )

            implementation_envelope = _task_envelopes(
                candidate=selected,
                repository=repository,
                config=self.config,
                base_sha=base_sha,
                repository_context=context,
                prior={"approved_plan": plan.payload},
            )
            outcome.stage = RunStage.IMPLEMENTING
            telemetry.transition(outcome.stage)
            implementation_prompt = render_prompt("implementation", implementation_envelope)
            journal.append("prompt", stage="implementation", sha256=implementation_prompt.sha256)
            implementation = self._run_agent(
                telemetry,
                "implementation",
                workspace,
                implementation_prompt,
                run_id,
                read_only_workspace=False,
                deadline=run_deadline,
                run_token_cap=reservation.reserved_tokens,
            )
            journal.append(
                "agent_result",
                stage="implementation",
                status=implementation.status,
                payload=implementation.payload,
            )
            if implementation.status != "implemented":
                raise RunAbort(FailureCode.AGENT_FAILED, "implementation agent did not finish")

            review_payload: dict[str, Any] | None = None
            diff = None
            for repair_cycle in range(self.config.agent.max_repair_cycles + 1):
                diff = inspect_diff(workspace, self.config.policy.max_patch_bytes)
                failures = diff_gate(diff, repository, self.config.policy)
                journal.append(
                    "diff_gate",
                    files=diff.files,
                    changed_lines=diff.changed_lines,
                    failures=failures,
                )
                if failures:
                    raise RunAbort(FailureCode.POLICY_DENIED, "; ".join(failures))

                outcome.stage = RunStage.VERIFYING
                telemetry.transition(outcome.stage, repair_cycle=repair_cycle)
                if repository.setup_commands and repair_cycle == 0:
                    setup_results = self.runner.run_commands(
                        workspace,
                        repository.setup_commands,
                        run_id,
                        stage="setup",
                        network=repository.network or self.config.sandbox.network,
                        deadline=run_deadline,
                    )
                    journal.append("setup_results", results=setup_results)
                    if any(not result.passed for result in setup_results):
                        raise RunAbort(FailureCode.TEST_FAILED, "sandbox setup command failed")
                test_results = self.runner.run_commands(
                    workspace,
                    repository.test_commands,
                    run_id,
                    stage=f"verify-{repair_cycle}",
                    network="none",
                    deadline=run_deadline,
                )
                outcome.tests = test_results
                telemetry.event(
                    "verification",
                    stage=outcome.stage,
                    repair_cycle=repair_cycle,
                    state=(
                        "failed" if any(not result.passed for result in test_results) else "passed"
                    ),
                )
                journal.append("test_results", results=test_results)
                tests_failed = any(not result.passed for result in test_results)
                post_test_diff = inspect_diff(workspace, self.config.policy.max_patch_bytes)
                post_test_failures = diff_gate(post_test_diff, repository, self.config.policy)
                if post_test_failures:
                    raise RunAbort(
                        FailureCode.POLICY_DENIED,
                        "verification mutated policy-sensitive content: "
                        + "; ".join(post_test_failures),
                    )
                if post_test_diff != diff or _git(workspace, "rev-parse", "HEAD") != base_sha:
                    raise RunAbort(
                        FailureCode.POLICY_DENIED,
                        "verification changed the approved candidate patch or Git base",
                    )
                diff = post_test_diff
                if tests_failed:
                    repair_limit_hit = repair_cycle >= self.config.agent.max_repair_cycles
                    if repair_limit_hit:
                        raise RunAbort(
                            FailureCode.TEST_FAILED,
                            "required verification command failed after the repair budget",
                        )
                    repair_envelope = _task_envelopes(
                        candidate=selected,
                        repository=repository,
                        config=self.config,
                        base_sha=base_sha,
                        repository_context=context,
                        prior={
                            "approved_plan": plan.payload,
                            "previous_implementation_report": implementation.payload,
                            "controller_test_failures_to_repair": _bounded_test_failures(
                                test_results
                            ),
                        },
                    )
                    repair_prompt = render_prompt("implementation", repair_envelope)
                    outcome.stage = RunStage.IMPLEMENTING
                    telemetry.transition(
                        outcome.stage,
                        repair_cycle=repair_cycle + 1,
                    )
                    journal.append(
                        "state",
                        stage=outcome.stage,
                        repair_cycle=repair_cycle + 1,
                        repair_reason="controller_test_failure",
                    )
                    journal.append(
                        "prompt",
                        stage=f"implementation-test-repair-{repair_cycle + 1}",
                        sha256=repair_prompt.sha256,
                    )
                    implementation = self._run_agent(
                        telemetry,
                        "implementation",
                        workspace,
                        repair_prompt,
                        run_id,
                        read_only_workspace=False,
                        deadline=run_deadline,
                        run_token_cap=reservation.reserved_tokens,
                    )
                    journal.append(
                        "agent_result",
                        stage=f"implementation-test-repair-{repair_cycle + 1}",
                        status=implementation.status,
                        payload=implementation.payload,
                    )
                    if implementation.status != "implemented":
                        raise RunAbort(
                            FailureCode.AGENT_FAILED,
                            "test-repair agent did not finish",
                        )
                    continue

                outcome.stage = RunStage.REVIEWING
                telemetry.transition(outcome.stage, repair_cycle=repair_cycle)
                review_envelope = _task_envelopes(
                    candidate=selected,
                    repository=repository,
                    config=self.config,
                    base_sha=base_sha,
                    repository_context=context,
                    prior={
                        "approved_plan": plan.payload,
                        "implementation_report": implementation.payload,
                        "canonical_diff": diff.patch,
                        "captured_tests": [asdict(result) for result in test_results],
                    },
                )
                review_prompt = render_prompt("review", review_envelope)
                journal.append("prompt", stage="review", sha256=review_prompt.sha256)
                review = self._run_agent(
                    telemetry,
                    "review",
                    workspace,
                    review_prompt,
                    run_id,
                    read_only_workspace=True,
                    deadline=run_deadline,
                    run_token_cap=reservation.reserved_tokens,
                )
                review_payload = review.payload
                telemetry.event(
                    "review",
                    stage=outcome.stage,
                    state=review.status,
                    repair_cycle=repair_cycle,
                )
                journal.append(
                    "agent_result",
                    stage="review",
                    status=review.status,
                    payload=review.payload,
                )
                supported = review.payload.get("pr_claims_supported") is True
                missing = review.payload.get("missing_verification") or []
                findings = review.payload.get("findings") or []
                if review.status == "approve" and supported and not missing and not findings:
                    break
                repair_limit_hit = repair_cycle >= self.config.agent.max_repair_cycles
                if review.status == "abandon" or repair_limit_hit:
                    raise RunAbort(
                        FailureCode.REVIEW_REJECTED,
                        "independent review rejected the patch",
                    )

                repair_envelope = _task_envelopes(
                    candidate=selected,
                    repository=repository,
                    config=self.config,
                    base_sha=base_sha,
                    repository_context=context,
                    prior={
                        "approved_plan": plan.payload,
                        "review_findings_to_repair": review.payload,
                    },
                )
                repair_prompt = render_prompt("implementation", repair_envelope)
                outcome.stage = RunStage.IMPLEMENTING
                telemetry.transition(
                    outcome.stage,
                    repair_cycle=repair_cycle + 1,
                )
                journal.append(
                    "state",
                    stage=outcome.stage,
                    repair_cycle=repair_cycle + 1,
                )
                journal.append(
                    "prompt",
                    stage=f"implementation-repair-{repair_cycle + 1}",
                    sha256=repair_prompt.sha256,
                )
                implementation = self._run_agent(
                    telemetry,
                    "implementation",
                    workspace,
                    repair_prompt,
                    run_id,
                    read_only_workspace=False,
                    deadline=run_deadline,
                    run_token_cap=reservation.reserved_tokens,
                )
                journal.append(
                    "agent_result",
                    stage=f"implementation-repair-{repair_cycle + 1}",
                    status=implementation.status,
                    payload=implementation.payload,
                )
                if implementation.status != "implemented":
                    raise RunAbort(FailureCode.AGENT_FAILED, "repair agent did not finish")

            assert diff is not None and review_payload is not None
            title, body = _render_pr_copy(selected, diff, outcome.tests)
            journal.append("pr_copy", title=title, body=body)

            final_diff = inspect_diff(workspace, self.config.policy.max_patch_bytes)
            if final_diff != diff or _git(workspace, "rev-parse", "HEAD") != base_sha:
                raise RunAbort(
                    FailureCode.POLICY_DENIED,
                    "workspace changed after independent verification",
                )
            diff = final_diff

            policy_document = {
                "policy": asdict(self.config.policy),
                "repository": asdict(repository),
                "review": review_payload,
            }
            approval = create_approval_bundle(
                run_id=run_id,
                issue=selected.issue,
                base_sha=base_sha,
                base_ref=branch,
                diff=diff,
                policy_document=policy_document,
            )
            telemetry.transition("approved")
            telemetry.event("approval", stage="approved", state="approved")
            journal.append("approved", approval=approval)

            should_publish = publish and self.config.publication.mode == "draft-pr"
            if should_publish:
                if repository.require_human_approval:
                    raise RunAbort(
                        FailureCode.POLICY_DENIED,
                        "repository policy requires a human approval not present in this "
                        "unattended run",
                    )
                if not isinstance(self.source, GitHubClient):
                    raise RunAbort(FailureCode.POLICY_DENIED, "fixture sources cannot publish")
                fresh_issue = self.source.refresh_issue(selected.issue)
                if fresh_issue is None or fresh_issue.updated_at != selected.issue.updated_at:
                    raise RunAbort(
                        FailureCode.UPSTREAM_MOVED,
                        "issue changed or closed after selection",
                    )
                fresh_score = score_issue(fresh_issue, repository, self.config.scoring)
                fresh_failures = candidate_gate(
                    fresh_issue,
                    fresh_score,
                    repository,
                    self.config.policy,
                    self.config.scoring.minimum_score,
                )
                if fresh_failures:
                    raise RunAbort(
                        FailureCode.UPSTREAM_MOVED,
                        "fresh issue/repository policy gate failed: " + "; ".join(fresh_failures),
                    )
                if self.source.branch_head(repository.slug, branch) != base_sha:
                    raise RunAbort(
                        FailureCode.UPSTREAM_MOVED,
                        "upstream base branch moved after verification",
                    )
                publication_ledger = publication_ledger or PublicationLedger(self.config.state_dir)
                try:
                    publication_ledger.reserve(
                        run_id=run_id,
                        window_key=reservation.window_key,
                        repository=repository.slug,
                        issue_number=selected.issue.number,
                        config=self.config.publication,
                    )
                except StatePolicyError as exc:
                    raise RunAbort(FailureCode.POLICY_DENIED, str(exc)) from exc
                journal.append(
                    "publication_slot_reserved",
                    repository=repository.slug,
                    window_key=reservation.window_key,
                )
                outcome.stage = RunStage.PUBLISHING
                telemetry.transition(outcome.stage)
                journal.append("state", stage=outcome.stage)
                published = self.publisher.publish(
                    publish_flag=publish,
                    workspace=workspace,
                    issue=selected.issue,
                    diff=diff,
                    approval=approval,
                    title=title,
                    body=body,
                    base_branch=branch,
                )
                outcome.pr_url = published.pr_url
                outcome.branch = published.branch
                outcome.stage = RunStage.PR_OPEN
                telemetry.transition(outcome.stage)
                telemetry.event("publication", stage=outcome.stage, state="published")
                outcome.message = "verified patch published as a draft PR"
                publication_ledger.finish(run_id, published.pr_url)
                journal.append("published", result=published)
            else:
                outcome.stage = RunStage.COMPLETE
                outcome.message = "verified dry run completed; no remote write was attempted"
                journal.append("dry_run_complete", approval=approval)
        except RunAbort as exc:
            outcome.stage = exc.stage
            outcome.failure_code = exc.code
            outcome.message = str(exc)
            journal.append("aborted", failure_code=exc.code, reason=str(exc))
        except (
            RunnerError,
            WorkspaceError,
            PublicationError,
            GitHubError,
            OSError,
            sqlite3.Error,
            subprocess.SubprocessError,
        ) as exc:
            publication_uncertain = outcome.stage in {
                RunStage.PUBLISHING,
                RunStage.PR_OPEN,
            }
            outcome.stage = RunStage.FAILED
            if publication_uncertain or isinstance(exc, PublicationError):
                outcome.failure_code = FailureCode.PUBLISH_PARTIAL
            elif isinstance(exc, GitHubError):
                outcome.failure_code = (
                    FailureCode.RATE_LIMITED if exc.retryable else FailureCode.AUTH_FAILED
                )
            elif isinstance(exc, AgentOutputError):
                outcome.failure_code = FailureCode.INVALID_OUTPUT
            elif isinstance(exc, RunnerError) and "not installed" in str(exc):
                outcome.failure_code = FailureCode.RUNTIME_UNAVAILABLE
            else:
                outcome.failure_code = FailureCode.AGENT_FAILED
            outcome.message = str(exc)
            journal.append("failed", failure_code=outcome.failure_code, reason=str(exc))
        finally:
            if lease.path is not None:
                cleanup_needed = True
            if cleanup_needed:
                outcome_before_cleanup = outcome.stage
                telemetry.transition(RunStage.CLEANING)
                try:
                    container_cleanup_proven = self.runner.cleanup_job(run_id)
                except (OSError, RunnerError):
                    container_cleanup_proven = False
                workspace_cleanup_proven = False
                cleanup_error = "workspace retained until container cleanup can be proven"
                if container_cleanup_proven:
                    try:
                        lease.cleanup()
                        workspace_cleanup_proven = True
                    except (OSError, WorkspaceError) as exc:
                        cleanup_error = str(exc)
                else:
                    workspace_cleanup_proven = False
                if container_cleanup_proven and workspace_cleanup_proven:
                    if outcome_before_cleanup == RunStage.PR_OPEN:
                        outcome.stage = RunStage.COMPLETE
                else:
                    reasons = []
                    if not container_cleanup_proven:
                        reasons.append(
                            "container cleanup receipt unavailable; bound workspace retained"
                        )
                    if not workspace_cleanup_proven:
                        reasons.append(f"workspace cleanup failed: {cleanup_error}")
                    _mark_cleanup_pending(
                        outcome,
                        "cleanup could not be proven: " + "; ".join(reasons),
                    )
                telemetry.cleanup(
                    containers_removed=container_cleanup_proven,
                    workspace_removed=workspace_cleanup_proven,
                )
                try:
                    journal.append("state", stage=RunStage.CLEANING)
                    if container_cleanup_proven and workspace_cleanup_proven:
                        journal.append(
                            "cleanup_receipt",
                            containers_removed=True,
                            local_workspace_removed=True,
                        )
                    else:
                        journal.append("cleanup_failed", reason=outcome.message)
                except OSError:
                    # Cleanup already ran; an unavailable audit sink must not undo it.
                    pass
            ledger_finished = False
            try:
                ledger.finish(run_id, outcome.stage.value)
                ledger_finished = True
            except (OSError, sqlite3.Error):
                pass
            if ledger_finished:
                try:
                    reserved_now = ledger.reserved_tokens(window_key)
                except (OSError, sqlite3.Error):
                    reserved_now = None
                if reserved_now is not None:
                    telemetry.record_budget(
                        snapshot,
                        window_key=window_key,
                        reserved_tokens=reserved_now,
                        reservation_state="committed",
                    )
            # The reservation remains conservative when reconciliation cannot be recorded.
        return outcome
