"""Deterministic end-to-end rehearsal for the Leftovers control plane.

The rehearsal never discovers or clones a remote repository and can never publish. Container mode
exercises the production ``AgentRunner`` boundary with a purpose-built image. Process mode exercises
the same result/telemetry contracts as supplemental local QA; it is not an OCI isolation claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from .config import (
    AgentConfig,
    AppConfig,
    BudgetConfig,
    DiscoveryConfig,
    GitHubConfig,
    PolicyConfig,
    PublicationConfig,
    RepositoryConfig,
    SandboxConfig,
    ScoringConfig,
)
from .models import IssueCandidate, RepositoryMetadata, RunOutcome, RunStage, TokenUsage
from .orchestrator import ContributionOrchestrator
from .runner import AgentRunner, CommandResult, RunnerError, execute
from .statefs import private_directory, private_file
from .workspace import WorkspaceError, WorkspaceLease

REHEARSAL_REPOSITORY = "leftovers-fixture/parser"
REHEARSAL_PROVIDER = "leftovers-rehearsal"
REHEARSAL_MODEL = "deterministic-parser-fixture-v1"
REHEARSAL_IMAGE = "leftovers-rehearsal:local"
REHEARSAL_TEST_COMMAND = ("python3", "-m", "unittest", "-q", "test_parser.py")
REHEARSAL_TOTAL_TOKENS = 750
_SAFE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,254}")

_PARSER_SOURCE = '''\
def decode_escaped(value: str) -> str:
    """Decode backslash escapes while preserving ordinary characters."""
    decoded: list[str] = []
    escaping = False
    for character in value:
        if escaping:
            decoded.append(character)
            escaping = False
        elif character == "\\\\":
            escaping = True
        else:
            decoded.append(character)
    return "".join(decoded)
'''

_TEST_SOURCE = """\
import unittest

from parser import decode_escaped


class ParserTests(unittest.TestCase):
    def test_decode_preserves_terminal_escape(self) -> None:
        terminal = "path" + chr(92)
        self.assertEqual(
            decode_escaped(terminal),
            terminal,
            "terminal escape must be preserved",
        )

    def test_decode_keeps_existing_escape_behavior(self) -> None:
        self.assertEqual(decode_escaped("a\\\\b"), "ab")


if __name__ == "__main__":
    unittest.main()
"""

_README_SOURCE = """# Parser rehearsal fixture

This controller-owned repository exists only to exercise Leftovers without network access or a
GitHub write. The intentionally buggy parser loses a terminal escape character.
"""

_AGENTS_SOURCE = """# Rehearsal fixture instructions

Change only `parser.py`. Preserve a terminal escape character and run the configured offline test.
Never use the network, credentials, Git remotes, dependency installers, or publication tools.
"""

_SEATBELT_PROFILE = """\
(version 1)
(allow default)
(deny network*)
(deny file-write*
  (require-not
    (require-any
      (literal (param "ROOT_DIR"))
      (subpath (param "STATE_DIR"))
      (subpath (param "TEMP_ROOT"))
      (subpath (param "TMP_DIR"))
      (literal "/dev/null")
      (literal "/dev/zero")
      (literal "/dev/random")
      (literal "/dev/urandom"))))
"""


class RehearsalError(RuntimeError):
    pass


@dataclass(frozen=True)
class RehearsalCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class StageUsage:
    stage: str
    usage: TokenUsage

    def to_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, **self.usage.to_dict()}


@dataclass(frozen=True)
class RehearsalReport:
    success: bool
    run_id: str
    mode: str
    assurance: str
    synthetic: bool
    provider: str
    model: str
    total_tokens: int
    maximum_tokens: int
    remaining_tokens: int
    outcome: RunOutcome
    state_dir: Path
    temp_root: Path
    journal_path: Path
    report_path: Path
    model_checkins: tuple[dict[str, Any], ...]
    usage_by_stage: tuple[StageUsage, ...]
    audit_events: tuple[str, ...]
    checks: tuple[RehearsalCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "run_id": self.run_id,
            "mode": self.mode,
            "assurance": self.assurance,
            "synthetic": self.synthetic,
            "provider": self.provider,
            "model": self.model,
            "total_tokens": self.total_tokens,
            "maximum_tokens": self.maximum_tokens,
            "remaining_tokens": self.remaining_tokens,
            "outcome": self.outcome.to_dict(),
            "state_dir": str(self.state_dir),
            "temp_root": str(self.temp_root),
            "journal_path": str(self.journal_path),
            "report_path": str(self.report_path),
            "model_checkins": list(self.model_checkins),
            "usage_by_stage": [item.to_dict() for item in self.usage_by_stage],
            "audit_events": list(self.audit_events),
            "checks": [asdict(check) for check in self.checks],
        }


@dataclass(frozen=True)
class RehearsalIssueSource:
    """In-memory issue source with no network-capable methods."""

    observed_at: datetime

    def discover(
        self,
        repositories: tuple[RepositoryConfig, ...],
        query: str,
        per_repo_limit: int,
    ) -> list[IssueCandidate]:
        del query
        if per_repo_limit < 1 or not any(
            repository.enabled and repository.slug == REHEARSAL_REPOSITORY
            for repository in repositories
        ):
            return []
        metadata = RepositoryMetadata(
            slug=REHEARSAL_REPOSITORY,
            stars=50_000,
            archived=False,
            disabled=False,
            license_spdx="Apache-2.0",
            default_branch="main",
            pushed_at=self.observed_at - timedelta(days=1),
            open_issues=1,
            forking_allowed=True,
            pull_requests_enabled=True,
            pull_request_creation_policy="ALL",
        )
        return [
            IssueCandidate(
                repo=metadata,
                number=1,
                node_id="rehearsal:parser#1",
                title="Parser loses a terminal escape character",
                body=(
                    "Steps to reproduce, expected output, and a focused offline test are provided. "
                    "Preserve the final escape without changing ordinary escape decoding."
                ),
                url="https://github.com/leftovers-fixture/parser/issues/1",
                labels=("bug", "help wanted"),
                created_at=self.observed_at - timedelta(days=120),
                updated_at=self.observed_at - timedelta(days=2),
                comments=5,
                reactions=8,
                assignees=(),
                locked=False,
                author_association="MEMBER",
                has_open_linked_pr=False,
                has_recent_claim=False,
                state="open",
            )
        ]


class RehearsalWorkspaceLease(WorkspaceLease):
    """Materialize a fixed local Git repository instead of cloning a remote URL."""

    def clone(self, slug: str, branch: str) -> Path:
        if slug != REHEARSAL_REPOSITORY or branch != "main":
            raise WorkspaceError(
                "rehearsal checkout identity does not match the controller fixture"
            )
        if self.path is None or self.repo_path is None:
            raise WorkspaceError("rehearsal workspace lease is not active")
        if self.repo_path.exists():
            raise WorkspaceError("rehearsal repository path already exists")
        git = shutil.which("git")
        if not git:
            raise WorkspaceError("git is required for the local rehearsal fixture")
        self.repo_path.mkdir(mode=0o700)
        files = {
            "parser.py": _PARSER_SOURCE,
            "test_parser.py": _TEST_SOURCE,
            "README.md": _README_SOURCE,
            "AGENTS.md": _AGENTS_SOURCE,
        }
        for name, content in files.items():
            (self.repo_path / name).write_text(content, encoding="utf-8")
        home = self.path / "fixture-git-home"
        home.mkdir(mode=0o700)
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Leftovers Rehearsal",
            "GIT_AUTHOR_EMAIL": "rehearsal@localhost.invalid",
            "GIT_COMMITTER_NAME": "Leftovers Rehearsal",
            "GIT_COMMITTER_EMAIL": "rehearsal@localhost.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        }
        commands = (
            (git, "init", "-q", "-b", "main"),
            (git, "add", "--", *files),
            (
                git,
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "deterministic rehearsal fixture",
            ),
        )
        for command in commands:
            result = subprocess.run(
                list(command),
                cwd=self.repo_path,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise WorkspaceError(f"local rehearsal Git setup failed: {result.stderr[-1_000:]}")
        return self.repo_path


class RehearsalRunner(AgentRunner):
    """Real AgentRunner with bounded recording and a process-only verification fallback."""

    def __init__(self, sandbox: SandboxConfig, agent: AgentConfig, *, mode: str):
        super().__init__(sandbox, agent, allow_synthetic_usage=True)
        self.mode = mode
        self.telemetry_events: list[dict[str, Any]] = []
        self.stage_usage: list[StageUsage] = []

    def runtime_available(self) -> bool:
        if self.mode == "process":
            return True
        return super().runtime_available()

    def cleanup_job(self, run_id: str) -> bool:
        if self.mode == "process":
            return True
        return super().cleanup_job(run_id)

    def run_agent(
        self,
        stage: str,
        workspace: Path,
        prompt: Any,
        run_id: str,
        *,
        read_only_workspace: bool,
        deadline: float | None = None,
        telemetry_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> Any:
        def record(event: dict[str, Any]) -> None:
            self.telemetry_events.append({"stage": stage, **event})
            if telemetry_callback is not None:
                telemetry_callback(event)

        result = super().run_agent(
            stage,
            workspace,
            prompt,
            run_id,
            read_only_workspace=read_only_workspace,
            deadline=deadline,
            telemetry_callback=record,
        )
        if result.usage is not None:
            self.stage_usage.append(StageUsage(stage=stage, usage=result.usage))
        return result

    def run_commands(
        self,
        workspace: Path,
        commands: tuple[tuple[str, ...], ...],
        run_id: str,
        *,
        stage: str,
        network: str = "none",
        deadline: float | None = None,
    ) -> list[CommandResult]:
        if self.mode != "process":
            return super().run_commands(
                workspace,
                commands,
                run_id,
                stage=stage,
                network=network,
                deadline=deadline,
            )
        if network != "none" or any(command != REHEARSAL_TEST_COMMAND for command in commands):
            raise RunnerError(
                "process rehearsal only permits its fixed offline verification command"
            )
        home = workspace.parent / "process-verifier-home"
        home.mkdir(mode=0o700, exist_ok=True)
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "CI": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        results: list[CommandResult] = []
        for command in commands:
            timeout = self.sandbox.timeout_seconds
            if deadline is not None:
                remaining = int(deadline - time.monotonic())
                if remaining < 1:
                    raise RunnerError("run-wide quota-window deadline is exhausted")
                timeout = min(timeout, remaining)
            result = execute(
                list(command),
                cwd=workspace,
                env=environment,
                stdin=None,
                timeout=timeout,
                max_output_bytes=self.agent.max_output_bytes,
            )
            results.append(result)
            if not result.passed:
                break
        return results

    def remaining_containers(self, run_id: str) -> list[str] | None:
        if self.mode == "process":
            return []
        return self._containers_for_job(run_id)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def build_rehearsal_config(
    root: Path,
    *,
    mode: Literal["docker", "podman", "process"] = "process",
    image: str = REHEARSAL_IMAGE,
) -> AppConfig:
    if mode not in {"docker", "podman", "process"}:
        raise RehearsalError("rehearsal mode must be docker, podman, or process")
    if _SAFE_IMAGE.fullmatch(image) is None:
        raise RehearsalError("rehearsal image reference is unsafe")
    root = root.expanduser().resolve()
    now = datetime.now(UTC)
    if mode == "process":
        script = _project_root() / "scripts" / "rehearsal_agent.py"
        if script.is_symlink() or not script.is_file():
            raise RehearsalError("controller-owned rehearsal adapter is missing or unsafe")
        backend = "host"
        command = (sys.executable, str(script), "--mode", "process")
        runtime = "docker"
    else:
        backend = "container"
        command = ("python3", "/opt/leftovers/rehearsal_agent.py", "--mode", "container")
        runtime = mode
    return AppConfig(
        version=1,
        state_dir=root / "state",
        temp_root=root / "workspaces",
        github=GitHubConfig(token_env="LEFTOVERS_REHEARSAL_GITHUB_TOKEN"),
        budget=BudgetConfig(
            source="fixed",
            fixed_remaining_tokens=5_000,
            maximum_tokens=5_000,
            reserve_tokens=1_000,
            minimum_spendable_tokens=1_000,
            safety_multiplier=1.0,
            window="weekly",
            timezone="UTC",
            reset_hour=now.hour,
            reset_weekday=(now.weekday() + 1) % 7,
            max_run_seconds=60,
            reset_safety_seconds=0,
        ),
        discovery=DiscoveryConfig(query="rehearsal fixture", per_repo_limit=1, max_candidates=1),
        scoring=ScoringConfig(minimum_score=1),
        policy=PolicyConfig(
            max_changed_files=2,
            max_changed_lines=20,
            max_patch_bytes=20_000,
            ai_policy_max_age_days=365,
        ),
        sandbox=SandboxConfig(
            runtime=runtime,
            image=image,
            network="none",
            memory="512m",
            cpus=1.0,
            pids_limit=64,
            timeout_seconds=30,
            tmpfs_size="64m",
        ),
        agent=AgentConfig(
            backend=backend,
            command=command,
            provider=REHEARSAL_PROVIDER,
            model=REHEARSAL_MODEL,
            checkin_required=True,
            usage_reporting_required=True,
            checkin_timeout_seconds=5,
            heartbeat_timeout_seconds=15,
            timeout_seconds=30,
            max_output_bytes=65_536,
            estimated_tokens_p50=750,
            estimated_tokens_p95=1_000,
            max_repair_cycles=0,
            pass_environment=(),
        ),
        publication=PublicationConfig(mode="dry-run", external_writes_acknowledged=False),
        repositories=(
            RepositoryConfig(
                slug=REHEARSAL_REPOSITORY,
                enabled=True,
                importance=1.0,
                default_branch="main",
                allowed_licenses=("Apache-2.0",),
                allow_labels=("help wanted",),
                deny_labels=(),
                test_commands=(REHEARSAL_TEST_COMMAND,),
                setup_commands=(),
                forbid_paths=(),
                max_changed_files=1,
                max_changed_lines=10,
                network="none",
                require_human_approval=False,
                ai_contributions_allowed=True,
                ai_policy_url=("https://github.com/leftovers-fixture/parser/blob/main/AGENTS.md"),
                ai_policy_checked_at=now.date().isoformat(),
            ),
        ),
    )


def verify_audit_journal(path: Path) -> tuple[dict[str, Any], ...]:
    """Recompute every record hash and chain link before trusting rehearsal evidence."""
    if path.is_symlink() or not path.is_file():
        raise RehearsalError("rehearsal audit journal is missing or unsafe")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 10_000_000:
        raise RehearsalError("rehearsal audit journal has an unsafe shape")
    raw_lines = path.read_bytes().splitlines()
    if not raw_lines or len(raw_lines) > 1_024:
        raise RehearsalError("rehearsal audit journal has an invalid record count")
    expected_previous = "0" * 64
    records: list[dict[str, Any]] = []
    for raw_line in raw_lines:
        if not raw_line or len(raw_line) > 1_000_000:
            raise RehearsalError("rehearsal audit journal has an invalid line")
        try:
            record = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RehearsalError("rehearsal audit journal contains invalid JSON") from exc
        if not isinstance(record, dict) or set(record) != {
            "at",
            "event",
            "payload",
            "previous_hash",
            "record_hash",
        }:
            raise RehearsalError("rehearsal audit journal record shape is invalid")
        if record["previous_hash"] != expected_previous:
            raise RehearsalError("rehearsal audit journal chain link is invalid")
        claimed = record["record_hash"]
        unsigned = {key: value for key, value in record.items() if key != "record_hash"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
        calculated = hashlib.sha256(canonical.encode()).hexdigest()
        if not isinstance(claimed, str) or claimed != calculated:
            raise RehearsalError("rehearsal audit journal record hash is invalid")
        expected_previous = claimed
        records.append(record)
    return tuple(records)


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    target = private_file(path)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise RehearsalError("rehearsal report destination is unsafe")
        payload = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise OSError("rehearsal report write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _check(name: str, ok: bool, detail: str) -> RehearsalCheck:
    return RehearsalCheck(name=name, ok=bool(ok), detail=detail)


def run_rehearsal(
    root: Path,
    *,
    mode: Literal["docker", "podman", "process"] = "process",
    image: str = REHEARSAL_IMAGE,
) -> RehearsalReport:
    """Run one deterministic training cycle and return independently checked evidence."""
    expanded = root.expanduser()
    if expanded.is_symlink() or (
        expanded.exists() and (not expanded.is_dir() or any(expanded.iterdir()))
    ):
        raise RehearsalError("rehearsal root must be a new or empty non-symlink directory")
    root = private_directory(expanded)
    config = build_rehearsal_config(root, mode=mode, image=image)
    if config.state_dir.resolve() == config.temp_root.resolve():
        raise RehearsalError("rehearsal state and workspace roots must be distinct")
    runner = RehearsalRunner(config.sandbox, config.agent, mode=mode)
    if mode in {"docker", "podman"} and not runner.runtime_available():
        raise RehearsalError(f"{mode} is unavailable for the container rehearsal")
    source = RehearsalIssueSource(datetime.now(UTC))
    outcome = ContributionOrchestrator(
        config,
        source,
        runner=runner,
        lease_factory=RehearsalWorkspaceLease,
        run_kind="training",
    ).run(execute_work=True, publish=False)

    journal_path = config.state_dir / "runs" / f"{outcome.run_id}.jsonl"
    audit_error: str | None = None
    try:
        records = verify_audit_journal(journal_path)
    except RehearsalError as exc:
        records = ()
        audit_error = str(exc)
    event_names = tuple(str(record.get("event", "")) for record in records)
    agent_records = [record for record in records if record.get("event") == "agent_result"]
    agent_stages = tuple(
        str(record.get("payload", {}).get("stage", "")) for record in agent_records
    )
    expected_agent_stages = ("planning", "implementation", "review")
    assertions = [
        record.get("payload", {}).get("payload", {}).get("rehearsal_assertions", {})
        for record in agent_records
    ]
    checkins = tuple(event for event in runner.telemetry_events if event.get("type") == "checkin")
    usages = tuple(runner.stage_usage)
    total_tokens = sum(item.usage.total_tokens for item in usages)
    maximum_tokens = config.budget.maximum_tokens or 0
    remaining_containers = runner.remaining_containers(outcome.run_id)
    initial_states = [
        record
        for record in records
        if record.get("event") == "state" and record.get("payload", {}).get("stage") == "scheduled"
    ]
    forbidden_remote_events = {
        "publication_slot_reserved",
        "published",
        "publication_preflight_denied",
    }
    checks = (
        _check(
            "outcome_complete",
            outcome.stage == RunStage.COMPLETE and outcome.failure_code is None,
            f"stage={outcome.stage.value}, failure={outcome.failure_code}",
        ),
        _check(
            "audit_chain",
            audit_error is None,
            audit_error or f"verified {len(records)} chained records",
        ),
        _check(
            "training_identity",
            len(initial_states) == 1
            and initial_states[0]["payload"].get("run_kind") == "training"
            and initial_states[0]["payload"].get("provider") == REHEARSAL_PROVIDER
            and initial_states[0]["payload"].get("model") == REHEARSAL_MODEL,
            "scheduled record is bound to the deterministic training identity",
        ),
        _check(
            "full_agent_lifecycle",
            agent_stages == expected_agent_stages,
            f"agent stage order={agent_stages}",
        ),
        _check(
            "offline_verification",
            bool(outcome.tests) and all(result.passed for result in outcome.tests),
            "controller-captured fixed test command passed",
        ),
        _check(
            "approval",
            "approved" in event_names and "dry_run_complete" in event_names,
            "approval bundle was created and retained as a dry run",
        ),
        _check(
            "no_remote_write",
            not forbidden_remote_events.intersection(event_names)
            and outcome.pr_url is None
            and outcome.branch is None,
            "fixture source and dry-run mode produced no publication event",
        ),
        _check(
            "model_checkins",
            len(checkins) == 3
            and tuple(event.get("stage") for event in checkins) == expected_agent_stages
            and all(
                event.get("provider") == REHEARSAL_PROVIDER
                and event.get("model") == REHEARSAL_MODEL
                for event in checkins
            ),
            f"received {len(checkins)} deterministic model check-ins",
        ),
        _check(
            "synthetic_exact_usage",
            len(usages) == 3
            and tuple(item.stage for item in usages) == expected_agent_stages
            and all(item.usage.source == "synthetic" and item.usage.exact for item in usages)
            and total_tokens == REHEARSAL_TOTAL_TOKENS,
            f"synthetic exact total={total_tokens}",
        ),
        _check(
            "maximum_usage",
            0 <= total_tokens <= maximum_tokens,
            f"synthetic total={total_tokens}, configured maximum={maximum_tokens}",
        ),
        _check(
            "worker_boundary",
            bool(assertions)
            and all(
                isinstance(stage_assertions, dict)
                and stage_assertions
                and all(value is True for value in stage_assertions.values())
                for stage_assertions in assertions
            ),
            (
                "OCI isolation probes passed"
                if mode in {"docker", "podman"}
                else "process mode is explicitly marked supplemental"
            ),
        ),
        _check(
            "container_cleanup",
            remaining_containers == [],
            (
                "no run-labeled containers remain"
                if remaining_containers == []
                else "container absence could not be proven"
            ),
        ),
        _check(
            "workspace_cleanup",
            "cleanup_receipt" in event_names and not list(config.temp_root.glob("leftovers-*")),
            "cleanup receipt exists and no managed workspace remains",
        ),
        _check(
            "separate_state_and_temp",
            config.state_dir.resolve() != config.temp_root.resolve(),
            "state and workspaces use separate roots",
        ),
    )
    assurance = (
        "oci-container-rehearsal"
        if mode in {"docker", "podman"}
        else "supplemental-process-rehearsal; use Seatbelt externally on macOS"
    )
    report_path = config.state_dir / "training" / f"{outcome.run_id}.json"
    report = RehearsalReport(
        success=all(check.ok for check in checks),
        run_id=outcome.run_id,
        mode=mode,
        assurance=assurance,
        synthetic=True,
        provider=REHEARSAL_PROVIDER,
        model=REHEARSAL_MODEL,
        total_tokens=total_tokens,
        maximum_tokens=maximum_tokens,
        remaining_tokens=max(0, maximum_tokens - total_tokens),
        outcome=outcome,
        state_dir=config.state_dir,
        temp_root=config.temp_root,
        journal_path=journal_path,
        report_path=report_path,
        model_checkins=checkins,
        usage_by_stage=usages,
        audit_events=event_names,
        checks=checks,
    )
    _write_private_json(report_path, report.to_dict())
    return report


def seatbelt_argv(
    *,
    root: Path,
    state_dir: Path,
    temp_root: Path,
    tmp_dir: Path,
    command: tuple[str, ...],
) -> tuple[str, ...]:
    """Build a parameterized macOS Seatbelt wrapper for supplemental process QA.

    The profile permits broad reads and is therefore not suitable for arbitrary repositories or
    provider credentials. It is intentionally limited to this deterministic fixture.
    """
    if not command or shutil.which("sandbox-exec") is None:
        raise RehearsalError("sandbox-exec and a non-empty command are required")
    paths = {
        "ROOT_DIR": root,
        "STATE_DIR": state_dir,
        "TEMP_ROOT": temp_root,
        "TMP_DIR": tmp_dir,
    }
    parameters: list[str] = []
    for name, path in paths.items():
        resolved = path.expanduser().resolve()
        if not resolved.is_absolute() or "\x00" in str(resolved) or "\n" in str(resolved):
            raise RehearsalError(f"unsafe Seatbelt path parameter: {name}")
        parameters.extend(("-D", f"{name}={resolved}"))
    return (
        "/usr/bin/sandbox-exec",
        *parameters,
        "-p",
        _SEATBELT_PROFILE,
        *command,
    )
