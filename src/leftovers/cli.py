from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from .audit import redact
from .budget import BudgetLedger
from .config import AppConfig, ConfigError, load_config
from .dashboard import DashboardUnavailable, serve_dashboard
from .github import (
    FixtureIssueSource,
    GitHubClient,
    GitHubError,
    RepositorySupplyCriteria,
)
from .models import RunStage
from .orchestrator import ContributionOrchestrator, ranked_to_dict
from .publisher import GhPublisher, PublicationError
from .rehearsal import (
    REHEARSAL_IMAGE,
    RehearsalError,
    _controller_command,
    run_rehearsal,
    seatbelt_argv,
)
from .runner import AgentRunner, RunnerCleanupError, RunnerError
from .sbx import SbxIdentity
from .sbx_rehearsal import SbxCompatibilityProbe, SbxRehearsalError
from .statefs import PrivateStateError, private_directory
from .telemetry import TelemetryError, TelemetryReader
from .workspace import WorkspaceError, reap_expired

_SEATBELT_CHILD = "LEFTOVERS_REHEARSAL_SEATBELT_CHILD"
_RUN_ID = __import__("re").compile(r"[a-f0-9]{32}")


def _bounded_integer(minimum: int, maximum: int, label: str) -> Any:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{label} must be an integer") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"{label} must be between {minimum} and {maximum}")
        return parsed

    return parse


def _bounded_float(minimum: float, maximum: float, label: str) -> Any:
    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{label} must be a number") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"{label} must be between {minimum:g} and {maximum:g}")
        return parsed

    return parse


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leftovers",
        description=(
            "Turn deliberately allocated agent quota into careful open-source contributions."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/leftovers.toml"),
        help="TOML configuration path (default: config/leftovers.toml)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate configuration and exit")
    subparsers.add_parser("doctor", help="check local runtime prerequisites without remote writes")

    sbx_rehearsal = subparsers.add_parser(
        "sbx-rehearsal",
        help="verify the pinned Docker Sandboxes boundary without starting an AI agent",
    )
    sbx_rehearsal.add_argument(
        "--execute",
        action="store_true",
        help="create and remove one controller-owned shell sandbox after read-only checks",
    )
    sbx_rehearsal.add_argument(
        "--private-temp-root",
        type=Path,
        help="owner-private root for the disposable tracked-only fixture",
    )
    sbx_rehearsal.add_argument(
        "--run-id",
        help="controller-owned 32-character hexadecimal rehearsal identity",
    )

    scout = subparsers.add_parser("scout", help="discover, gate, score, and rank issues read-only")
    scout.add_argument("--fixture", type=Path, help="read issues from a local JSON fixture")
    scout.add_argument("--eligible-only", action="store_true")

    repo_scout = subparsers.add_parser(
        "repo-scout",
        help="nominate issue-rich, PR-constrained repositories for manual curation",
    )
    repo_scout.add_argument(
        "--min-stars", type=_bounded_integer(1, 100_000, "minimum stars"), default=100
    )
    repo_scout.add_argument(
        "--max-stars", type=_bounded_integer(1, 1_000_000, "maximum stars"), default=3_000
    )
    repo_scout.add_argument(
        "--min-open-issues",
        type=_bounded_integer(1, 10_000, "minimum open issues"),
        default=30,
    )
    repo_scout.add_argument(
        "--max-open-issues",
        type=_bounded_integer(1, 10_000, "maximum open issues"),
        default=200,
    )
    repo_scout.add_argument(
        "--max-open-prs",
        type=_bounded_integer(0, 10_000, "maximum open PRs"),
        default=12,
    )
    repo_scout.add_argument(
        "--min-ratio",
        type=_bounded_float(1, 1_000, "minimum issue-to-PR ratio"),
        default=8.0,
    )
    repo_scout.add_argument(
        "--pushed-within-days",
        type=_bounded_integer(1, 365, "activity window"),
        default=90,
    )
    repo_scout.add_argument(
        "--fresh-issue-days",
        type=_bounded_integer(1, 365, "fresh issue window"),
        default=180,
    )
    repo_scout.add_argument(
        "--min-fresh-invited-issues",
        type=_bounded_integer(1, 100, "minimum fresh invited issues"),
        default=3,
    )
    repo_scout.add_argument(
        "--min-recent-human-activity",
        type=_bounded_integer(0, 100, "minimum recent human activity"),
        default=2,
    )
    repo_scout.add_argument(
        "--scan",
        type=_bounded_integer(1, 50, "repository scan limit"),
        default=25,
    )
    repo_scout.add_argument(
        "--limit",
        type=_bounded_integer(1, 50, "result limit"),
        default=10,
    )

    run = subparsers.add_parser("run", help="run one bounded contribution cycle")
    run.add_argument(
        "--fixture", type=Path, help="use a local issue fixture; publication is disabled"
    )
    run.add_argument(
        "--execute",
        action="store_true",
        help="clone and invoke the configured agent (otherwise selection-only)",
    )
    run.add_argument(
        "--publish",
        action="store_true",
        help="authorize the configured publisher for this run; implies --execute",
    )
    run.add_argument(
        "--remaining-tokens",
        type=int,
        help="manual remaining-quota snapshot for this run",
    )
    run.add_argument(
        "--run-id",
        help="controller-owned 32-character hexadecimal run identity (advanced use)",
    )

    cleanup = subparsers.add_parser("cleanup", help="reap expired, exactly-marked local workspaces")
    cleanup.add_argument("--older-than-hours", type=int, default=24)

    dashboard = subparsers.add_parser(
        "dashboard", help="serve the read-only operations dashboard on loopback"
    )
    dashboard.add_argument(
        "--host",
        choices=("127.0.0.1", "::1"),
        default="127.0.0.1",
        help="literal loopback bind address (default: 127.0.0.1)",
    )
    dashboard.add_argument(
        "--port",
        type=_bounded_integer(1, 65_535, "port"),
        default=8765,
        help="loopback TCP port (default: 8765)",
    )
    dashboard.add_argument(
        "--workers",
        type=_bounded_integer(1, 32, "workers"),
        default=4,
        help="maximum concurrent request workers (default: 4)",
    )

    training = subparsers.add_parser(
        "training-run",
        help="run the deterministic no-publish contribution rehearsal",
    )
    training.add_argument(
        "--mode",
        choices=("process", "docker", "podman"),
        default="process",
        help="worker execution mode (default: process)",
    )
    training.add_argument(
        "--image",
        default=REHEARSAL_IMAGE,
        help=f"rehearsal image for Docker/Podman (default: {REHEARSAL_IMAGE})",
    )
    training.add_argument(
        "--profile",
        choices=("auto", "seatbelt", "none"),
        default="auto",
        help=(
            "outer process isolation: auto selects macOS Seatbelt when available; "
            "container modes always use the OCI profile"
        ),
    )
    training.add_argument(
        "--report",
        type=Path,
        help="write the exact JSON result to an owner-only file",
    )
    training.add_argument("--internal-root", type=Path, help=argparse.SUPPRESS)
    return parser


def _source(config: AppConfig, fixture: Path | None) -> FixtureIssueSource | GitHubClient:
    return FixtureIssueSource(fixture.resolve()) if fixture else GitHubClient(config.github)


def _doctor(config: AppConfig) -> tuple[bool, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, severity: str = "error") -> None:
        checks.append({"name": name, "ok": ok, "severity": severity, "detail": detail})

    add("git", shutil.which("git") is not None, "git is required for ephemeral checkouts")
    add(
        "non_root_controller",
        getattr(os, "geteuid", lambda: 1)() != 0,
        "controller execution as root is forbidden",
    )
    gh_present = shutil.which("gh") is not None
    add(
        "gh",
        gh_present or config.publication.mode == "dry-run",
        "gh is required only for draft-PR publication",
    )
    runtime_present = shutil.which(config.sandbox.runtime) is not None
    add(
        "sandbox_runtime",
        runtime_present,
        f"{config.sandbox.runtime} is required only for OCI rehearsal and verification stages",
    )
    sbx_config = getattr(config, "sbx", None)
    sbx_binary = getattr(sbx_config, "binary_path", "")
    sbx_present = bool(sbx_binary) and Path(sbx_binary).is_file()
    add(
        "sbx_runtime",
        sbx_present,
        "the exact configured Docker Sandboxes binary is required for the compatibility probe",
        severity="warning" if config.agent.backend != "sbx" else "error",
    )
    add(
        "sbx_execution",
        False,
        "production execution is disabled until clone mode, policy, credential isolation, "
        "bounded result extraction, and exact cleanup are live-attested together",
    )
    add(
        "pinned_image",
        "@sha256:" in config.sandbox.image,
        "production/VM profiles should pin the sandbox image by digest",
        severity="warning",
    )
    add(
        "agent_backend",
        config.agent.backend == "sbx",
        "unattended production requires the source-gated sbx backend; "
        "host/OCI remain rehearsal-only",
        severity="warning",
    )
    add(
        "sandbox_policy_boundary",
        False,
        "effective sbx network, secret, port, clone, and cleanup policy "
        "needs an explicit rehearsal",
        severity="warning",
    )
    add(
        "github_read_token",
        bool(os.environ.get(config.github.token_env)),
        f"{config.github.token_env} is required for repository-control eligibility; "
        "without it live candidates fail closed",
        severity="warning",
    )
    add(
        "publication_default",
        config.publication.mode == "dry-run",
        "new installations should remain dry-run until reviewed",
        severity="warning",
    )
    if config.publication.mode == "draft-pr" and shutil.which("gh") is not None:
        try:
            login, user_id = GhPublisher(config.publication)._identity()
            identity_ok = (
                login.casefold() == (config.publication.expected_login or "").casefold()
                and user_id == config.publication.expected_user_id
            )
            identity_detail = (
                "authenticated github.com identity matches configured login and immutable id"
                if identity_ok
                else "authenticated github.com identity does not match publication pins"
            )
        except PublicationError as exc:
            identity_ok = False
            identity_detail = f"could not verify github.com publisher identity: {exc}"
        add("publisher_identity", identity_ok, identity_detail)
    errors = [check for check in checks if not check["ok"] and check["severity"] == "error"]
    return not errors, checks


def _write_json_report(path: Path, value: dict[str, Any]) -> None:
    expanded = path.expanduser()
    parent = expanded.parent
    if parent.is_symlink():
        raise PrivateStateError("training report parent may not be a symlink")
    if not parent.exists():
        parent = private_directory(parent)
    else:
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise PrivateStateError("training report parent must be owner-controlled")
        parent = parent.resolve()
    target = parent / expanded.name
    if target.is_symlink():
        raise PrivateStateError("training report destination may not be a symlink")
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(target, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        descriptor = os.open(target, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise PrivateStateError("training report destination is unsafe")
        os.fchmod(descriptor, 0o600)
        os.ftruncate(descriptor, 0)
        payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise OSError("training report write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _seatbelt_available() -> bool:
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def _training_root(config: AppConfig, internal_root: Path | None) -> Path:
    if internal_root is not None:
        if os.environ.get(_SEATBELT_CHILD) != "1":
            raise ConfigError("--internal-root is reserved for the Seatbelt child process")
        return internal_root.expanduser()
    parent = private_directory(config.state_dir / "rehearsals")
    return parent / f"training-{uuid.uuid4().hex}"


def _seatbelt_child_environment(root: Path) -> dict[str, str]:
    """Build a minimal child environment with no host credential locations or values."""

    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(root),
        "TMPDIR": str(root),
        "PYTHONDONTWRITEBYTECODE": "1",
        _SEATBELT_CHILD: "1",
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _training_payload(args: argparse.Namespace, config: AppConfig) -> tuple[int, dict[str, Any]]:
    root = _training_root(config, args.internal_root)
    if args.mode in {"docker", "podman"}:
        if args.profile == "seatbelt":
            raise ConfigError("--profile seatbelt is only valid with --mode process")
        resolved_profile = "oci-container"
    elif args.profile == "seatbelt":
        if not _seatbelt_available():
            raise RehearsalError("macOS sandbox-exec is required for --profile seatbelt")
        resolved_profile = "macos-seatbelt-supplemental"
    elif args.profile == "auto" and _seatbelt_available():
        resolved_profile = "macos-seatbelt-supplemental"
    else:
        resolved_profile = "unsandboxed-process-supplemental"

    should_reexec = (
        resolved_profile == "macos-seatbelt-supplemental" and os.environ.get(_SEATBELT_CHILD) != "1"
    )
    if should_reexec:
        # Python resolves its temporary directory before the child can create the rehearsal root.
        # Create the otherwise-empty owner-only root outside Seatbelt so TMPDIR is usable at
        # startup.
        root = private_directory(root)
        command = (
            *_controller_command(),
            "--config",
            str(args.config),
            "training-run",
            "--mode",
            "process",
            "--image",
            args.image,
            "--profile",
            "seatbelt",
            "--internal-root",
            str(root),
        )
        environment = _seatbelt_child_environment(root)
        wrapped = seatbelt_argv(
            root=root,
            state_dir=root / "state",
            temp_root=root / "workspaces",
            tmp_dir=root,
            command=command,
        )
        try:
            completed = subprocess.run(
                list(wrapped),
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RehearsalError("Seatbelt rehearsal exceeded its 180-second limit") from exc
        if completed.returncode != 0:
            detail = ""
            try:
                child_error = json.loads(completed.stderr)
            except json.JSONDecodeError:
                child_error = None
            if isinstance(child_error, dict) and isinstance(child_error.get("message"), str):
                detail = f": {redact(child_error['message'], limit=500)}"
            raise RehearsalError(
                f"Seatbelt rehearsal failed with exit status {completed.returncode}{detail}"
            )
        try:
            child_payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RehearsalError("Seatbelt rehearsal returned invalid JSON") from exc
        if not isinstance(child_payload, dict) or type(child_payload.get("success")) is not bool:
            raise RehearsalError("Seatbelt rehearsal returned an invalid result shape")
        child_payload["profile_requested"] = args.profile
        child_payload["assurance"] = (
            "supplemental macOS Seatbelt process rehearsal; host and OCI profiles are "
            "rehearsal-only and cannot authorize production execution"
        )
        return (0 if child_payload["success"] else 3), child_payload

    report = run_rehearsal(root, mode=args.mode, image=args.image)
    payload = report.to_dict()
    payload["execution_profile"] = resolved_profile
    payload["profile_requested"] = args.profile
    return (0 if report.success else 3), payload


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "validate":
            print(json.dumps({"valid": True, "config": str(args.config.resolve())}, indent=2))
            return 0
        if args.command == "doctor":
            ok, checks = _doctor(config)
            print(json.dumps({"ok": ok, "checks": checks}, indent=2))
            return 0 if ok else 2
        if args.command == "sbx-rehearsal":
            if getattr(os, "geteuid", lambda: 1)() == 0:
                raise SbxRehearsalError("Docker Sandboxes rehearsal must not run as root")
            if args.run_id is not None and _RUN_ID.fullmatch(args.run_id) is None:
                raise ConfigError("--run-id must be exactly 32 lowercase hexadecimal characters")
            try:
                identity = SbxIdentity(
                    Path(config.sbx.binary_path),
                    config.sbx.version,
                    config.sbx.revision,
                    config.sbx.binary_sha256,
                )
            except ValueError as exc:
                raise ConfigError("[sbx] does not contain a valid pinned CLI identity") from exc
            private_root = private_directory(
                args.private_temp_root
                if args.private_temp_root is not None
                else config.temp_root / "sbx-rehearsal"
            )
            receipt = SbxCompatibilityProbe(
                expected_identity=identity,
                ambient=os.environ,
                timeout_seconds=min(config.sbx.cleanup_timeout_seconds, 120),
            ).rehearse(
                private_temp_root=private_root,
                run_nonce=args.run_id or uuid.uuid4().hex,
                execute=args.execute,
            )
            print(
                json.dumps(
                    {
                        "state": receipt.state,
                        "production_execution_authorized": False,
                        "ai_agent_started": False,
                        "sandbox_name": receipt.name,
                        "fixture_path": str(receipt.fixture_path) if receipt.fixture_path else None,
                        "final_absent": receipt.final_absent,
                        "sbx": {
                            "binary": str(receipt.doctor.identity.binary),
                            "version": receipt.doctor.identity.version,
                            "revision": receipt.doctor.identity.revision,
                            "sha256": receipt.doctor.identity.sha256,
                        },
                        "preexisting_sandbox_count": len(receipt.doctor.sandbox_names),
                        "openai_secret_configured": receipt.doctor.openai_secret_configured,
                        "github_secret_configured": receipt.doctor.github_secret_configured,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "cleanup":
            runner = AgentRunner(config.sandbox, config.agent)
            if not runner.runtime_available():
                raise RunnerError(
                    "container runtime unavailable; refusing to delete possibly mounted workspaces"
                )
            removed_containers = runner.reap_expired_containers()
            active_jobs = runner.active_job_ids()
            active_jobs.update(BudgetLedger(config.state_dir, config.budget).active_run_ids())
            removed_workspaces = reap_expired(
                config.temp_root,
                args.older_than_hours,
                protected_run_ids=active_jobs,
            )
            print(
                json.dumps(
                    {
                        "removed_workspaces": [str(path) for path in removed_workspaces],
                        "removed_containers": removed_containers,
                        "container_runtime_available": runner.runtime_available(),
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "dashboard":
            reader = TelemetryReader(config.state_dir)
            authority = f"[{args.host}]" if ":" in args.host else args.host
            startup = {
                "dashboard": f"http://{authority}:{args.port}/",
                "read_only": True,
                "state_dir": str(config.state_dir),
            }
            print(json.dumps(startup, sort_keys=True), file=sys.stderr, flush=True)
            try:
                serve_dashboard(
                    reader,
                    host=args.host,
                    port=args.port,
                    max_workers=args.workers,
                )
            except KeyboardInterrupt:
                return 130
            return 0
        if args.command == "training-run":
            status, payload = _training_payload(args, config)
            if args.report is not None:
                _write_json_report(args.report, payload)
            print(json.dumps(payload, indent=2, sort_keys=True))
            return status
        if args.command == "scout":
            source = _source(config, args.fixture)
            ranked = ContributionOrchestrator(config, source).scout()
            if args.eligible_only:
                ranked = [candidate for candidate in ranked if candidate.eligible]
            print(json.dumps({"candidates": [ranked_to_dict(item) for item in ranked]}, indent=2))
            return 0
        if args.command == "repo-scout":
            if args.max_stars < args.min_stars:
                raise ConfigError("--max-stars cannot be less than --min-stars")
            if args.max_open_issues < args.min_open_issues:
                raise ConfigError("--max-open-issues cannot be less than --min-open-issues")
            if args.limit > args.scan:
                raise ConfigError("--limit cannot exceed --scan")
            criteria = RepositorySupplyCriteria(
                min_stars=args.min_stars,
                max_stars=args.max_stars,
                min_open_issues=args.min_open_issues,
                max_open_issues=args.max_open_issues,
                max_open_prs=args.max_open_prs,
                min_issue_pr_ratio=args.min_ratio,
                pushed_within_days=args.pushed_within_days,
                fresh_issue_days=args.fresh_issue_days,
                min_fresh_invited_issues=args.min_fresh_invited_issues,
                min_recent_human_activity=args.min_recent_human_activity,
                scan_limit=args.scan,
                result_limit=args.limit,
            )
            candidates = GitHubClient(config.github).discover_repository_supply(criteria)
            print(
                json.dumps(
                    {
                        "mode": "read-only-nomination",
                        "execution_authorized": False,
                        "criteria": {
                            "min_stars": criteria.min_stars,
                            "max_stars": criteria.max_stars,
                            "min_open_issues": criteria.min_open_issues,
                            "max_open_issues": criteria.max_open_issues,
                            "max_open_prs": criteria.max_open_prs,
                            "min_issue_pr_ratio": criteria.min_issue_pr_ratio,
                            "pushed_within_days": criteria.pushed_within_days,
                            "fresh_issue_days": criteria.fresh_issue_days,
                            "min_fresh_invited_issues": criteria.min_fresh_invited_issues,
                            "min_recent_human_activity": criteria.min_recent_human_activity,
                            "scan_limit": criteria.scan_limit,
                            "result_limit": criteria.result_limit,
                        },
                        "candidates": [candidate.to_dict() for candidate in candidates],
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "run":
            if args.publish and args.fixture:
                raise ConfigError("--publish cannot be used with --fixture")
            if args.run_id is not None and _RUN_ID.fullmatch(args.run_id) is None:
                raise ConfigError("--run-id must be exactly 32 lowercase hexadecimal characters")
            source = _source(config, args.fixture)
            outcome = ContributionOrchestrator(config, source).run(
                execute_work=args.execute or args.publish,
                publish=args.publish,
                remaining_tokens=args.remaining_tokens,
                run_id=args.run_id,
            )
            print(json.dumps(outcome.to_dict(), indent=2))
            successful = {RunStage.COMPLETE, RunStage.SELECTED, RunStage.SKIPPED}
            return 0 if outcome.stage in successful else 3
        raise AssertionError("unreachable command")
    except RunnerCleanupError as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": str(exc),
                    "process_group": exc.process_group,
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 2
    except (
        ConfigError,
        DashboardUnavailable,
        GitHubError,
        PrivateStateError,
        RehearsalError,
        SbxRehearsalError,
        RunnerError,
        TelemetryError,
        WorkspaceError,
        OSError,
    ) as exc:
        error = {"error": type(exc).__name__, "message": str(exc)}
        print(json.dumps(error, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
