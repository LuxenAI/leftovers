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
from .codex_adapter import inspect_codex_cli
from .config import AppConfig, ConfigError, load_config
from .dashboard import DashboardUnavailable, serve_dashboard
from .github import FixtureIssueSource, GitHubClient, GitHubError
from .models import RunStage
from .onboarding import (
    DEFAULT_CODEX_MODEL,
    CodexSetupInputs,
    container_image_available,
    parse_argv_json,
    setup_codex,
)
from .orchestrator import ContributionOrchestrator, ranked_to_dict
from .publisher import GhPublisher, PublicationError
from .rehearsal import (
    REHEARSAL_IMAGE,
    RehearsalError,
    run_rehearsal,
    seatbelt_argv,
)
from .runner import AgentRunner, RunnerError
from .statefs import PrivateStateError, private_directory
from .telemetry import TelemetryError, TelemetryReader
from .workspace import WorkspaceError, reap_expired

_SEATBELT_CHILD = "LEFTOVERS_REHEARSAL_SEATBELT_CHILD"


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
    setup = subparsers.add_parser(
        "setup", help="create a new dry-run configuration with guided prerequisite checks"
    )
    setup.add_argument("provider", choices=("codex",))
    setup.add_argument("--repository", help="allowlisted GitHub repository as owner/name")
    setup.add_argument("--ai-policy-url", help="reviewed HTTPS AI-contribution policy URL")
    setup.add_argument(
        "--ai-policy-reviewed",
        action="store_true",
        help="confirm that the policy URL was reviewed and currently permits AI assistance",
    )
    setup.add_argument(
        "--test-command-json",
        action="append",
        default=[],
        help='reviewed offline test argv as JSON, for example ["python","-m","pytest","-q"]',
    )
    setup.add_argument(
        "--allowed-license",
        action="append",
        default=[],
        help="reviewed SPDX license identifier; repeat when needed",
    )
    setup.add_argument(
        "--allow-label",
        action="append",
        default=[],
        help="maintainer-signal issue label; defaults to help wanted and good first issue",
    )
    setup.add_argument("--default-branch", default="main")
    setup.add_argument("--model", default=DEFAULT_CODEX_MODEL)
    setup.add_argument(
        "--allocated-tokens",
        type=_bounded_integer(100_000, 10_000_000, "allocated tokens"),
        help="explicit daily or weekly token envelope allocated to Leftovers",
    )
    setup.add_argument(
        "--reserve-tokens",
        type=_bounded_integer(0, 9_900_000, "reserve tokens"),
        default=20_000,
    )
    setup.add_argument("--window", choices=("daily", "weekly"), default="daily")
    setup.add_argument("--timezone", default="America/Phoenix")
    setup.add_argument("--runtime", choices=("docker", "podman"), default="docker")
    subparsers.add_parser("validate", help="validate configuration and exit")
    subparsers.add_parser("doctor", help="check local runtime prerequisites without remote writes")

    scout = subparsers.add_parser("scout", help="discover, gate, score, and rank issues read-only")
    scout.add_argument("--fixture", type=Path, help="read issues from a local JSON fixture")
    scout.add_argument("--eligible-only", action="store_true")

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


def _prompt_required(value: str | None, label: str) -> str:
    if value and value.strip():
        return value.strip()
    if not sys.stdin.isatty():
        raise ConfigError(f"setup requires --{label.replace('_', '-')}")
    response = input(f"{label.replace('_', ' ').capitalize()}: ").strip()
    if not response:
        raise ConfigError(f"setup requires {label.replace('_', ' ')}")
    return response


def _setup_inputs(args: argparse.Namespace) -> CodexSetupInputs:
    repository = _prompt_required(args.repository, "repository")
    ai_policy_url = _prompt_required(args.ai_policy_url, "ai_policy_url")
    reviewed = args.ai_policy_reviewed
    if not reviewed and sys.stdin.isatty():
        answer = input(
            "Have you reviewed that policy and confirmed AI-assisted contributions are allowed? "
            "[y/N]: "
        ).strip()
        reviewed = answer.casefold() in {"y", "yes"}
    raw_commands = list(args.test_command_json)
    if not raw_commands and sys.stdin.isatty():
        raw_commands.append(
            input('Offline test argv JSON (for example ["python","-m","pytest","-q"]): ')
        )
    commands = tuple(parse_argv_json(value) for value in raw_commands)
    licenses = list(args.allowed_license)
    if not licenses and sys.stdin.isatty():
        licenses = [
            item.strip()
            for item in input("Reviewed SPDX license identifier(s), comma-separated: ").split(",")
            if item.strip()
        ]
    allocated_tokens = args.allocated_tokens
    if allocated_tokens is None and sys.stdin.isatty():
        raw_tokens = input("Token envelope allocated to Leftovers [150000]: ").strip() or "150000"
        try:
            allocated_tokens = int(raw_tokens)
        except ValueError as exc:
            raise ConfigError("allocated tokens must be an integer") from exc
    if allocated_tokens is None:
        raise ConfigError("setup requires --allocated-tokens")
    labels = tuple(args.allow_label or ("help wanted", "good first issue"))
    return CodexSetupInputs(
        repository=repository,
        ai_policy_url=ai_policy_url,
        ai_policy_reviewed=reviewed,
        test_commands=commands,
        allowed_licenses=tuple(licenses),
        allow_labels=labels,
        default_branch=args.default_branch,
        model=args.model,
        allocated_tokens=allocated_tokens,
        reserve_tokens=args.reserve_tokens,
        window=args.window,
        timezone=args.timezone,
        runtime=args.runtime,
    )


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
        f"{config.sandbox.runtime} is required for container-agent and verification stages",
    )
    add(
        "sandbox_image",
        runtime_present
        and container_image_available(config.sandbox.runtime, config.sandbox.image),
        f"configured image {config.sandbox.image} must already exist locally",
    )
    add(
        "pinned_image",
        "@sha256:" in config.sandbox.image,
        "production/VM profiles should pin the sandbox image by digest",
        severity="warning",
    )
    add(
        "agent_backend",
        config.agent.backend == "container",
        "host and Codex CLI agents remain dry-run, lower-assurance profiles",
        severity="warning",
    )
    if config.agent.backend == "codex-cli":
        inspection = inspect_codex_cli(config.agent.command[0], config.agent.model)
        add(
            "codex_cli",
            inspection.executable is not None,
            "Codex CLI must be installed at the configured path",
        )
        add(
            "codex_version",
            inspection.version_supported,
            "Codex CLI 0.145.0 or newer is required by the hardened adapter",
        )
        add(
            "codex_login",
            inspection.authenticated,
            "Codex CLI must report an active saved login",
        )
        add(
            "codex_model",
            inspection.model_available,
            f"configured model {config.agent.model} must exist in the bundled model catalog",
        )
    add(
        "rootless_runtime",
        False,
        "rootless/runtime-VM isolation is operator-provided and not portably auto-verified",
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
            sys.executable,
            "-m",
            "leftovers",
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
        environment = os.environ.copy()
        environment[_SEATBELT_CHILD] = "1"
        environment["TMPDIR"] = str(root)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
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
            "supplemental macOS Seatbelt process rehearsal; "
            "the OCI container rehearsal remains authoritative"
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
        if args.command == "setup":
            if args.provider != "codex":
                raise ConfigError("unsupported setup provider")
            status, payload = setup_codex(args.config, _setup_inputs(args))
            print(json.dumps(payload, indent=2, sort_keys=True))
            return status
        config = load_config(args.config)
        if args.command == "validate":
            print(json.dumps({"valid": True, "config": str(args.config.resolve())}, indent=2))
            return 0
        if args.command == "doctor":
            ok, checks = _doctor(config)
            print(json.dumps({"ok": ok, "checks": checks}, indent=2))
            return 0 if ok else 2
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
        if args.command == "run":
            if args.publish and args.fixture:
                raise ConfigError("--publish cannot be used with --fixture")
            source = _source(config, args.fixture)
            outcome = ContributionOrchestrator(config, source).run(
                execute_work=args.execute or args.publish,
                publish=args.publish,
                remaining_tokens=args.remaining_tokens,
            )
            print(json.dumps(outcome.to_dict(), indent=2))
            successful = {RunStage.COMPLETE, RunStage.SELECTED, RunStage.SKIPPED}
            return 0 if outcome.stage in successful else 3
        raise AssertionError("unreachable command")
    except (
        ConfigError,
        DashboardUnavailable,
        GitHubError,
        PrivateStateError,
        RehearsalError,
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
