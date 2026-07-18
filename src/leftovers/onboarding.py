from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .codex_adapter import CODEX_PROVIDER, inspect_codex_cli
from .config import ConfigError, load_config


DEFAULT_CODEX_MODEL = "gpt-5.6-luna"


@dataclass(frozen=True)
class CodexSetupInputs:
    repository: str
    ai_policy_url: str
    ai_policy_reviewed: bool
    test_commands: tuple[tuple[str, ...], ...]
    allowed_licenses: tuple[str, ...]
    allow_labels: tuple[str, ...]
    default_branch: str
    model: str
    allocated_tokens: int
    reserve_tokens: int
    window: str
    timezone: str
    runtime: str


def parse_argv_json(value: str) -> tuple[str, ...]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ConfigError("test commands must be JSON argv arrays") from exc
    if (
        not isinstance(payload, list)
        or not payload
        or len(payload) > 64
        or any(
            not isinstance(argument, str)
            or not argument
            or len(argument) > 4_096
            or "\0" in argument
            for argument in payload
        )
    ):
        raise ConfigError("each test command must be a non-empty JSON string array")
    return tuple(payload)


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _toml_strings(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _toml_commands(commands: tuple[tuple[str, ...], ...]) -> str:
    return "[" + ", ".join(_toml_strings(command) for command in commands) + "]"


def _validate_inputs(inputs: CodexSetupInputs) -> None:
    if not inputs.ai_policy_reviewed:
        raise ConfigError(
            "setup requires an explicit confirmation that the repository AI policy was reviewed"
        )
    if not inputs.test_commands:
        raise ConfigError("setup requires at least one operator-reviewed test command")
    if not inputs.allowed_licenses:
        raise ConfigError("setup requires at least one reviewed SPDX license identifier")
    if not inputs.allow_labels:
        raise ConfigError("setup requires at least one maintainer-signal issue label")
    if inputs.window not in {"daily", "weekly"}:
        raise ConfigError("setup window must be daily or weekly")
    if inputs.runtime not in {"docker", "podman"}:
        raise ConfigError("setup runtime must be docker or podman")
    if inputs.allocated_tokens < 1 or inputs.reserve_tokens < 0:
        raise ConfigError("allocated and reserve token values must be positive")
    if inputs.allocated_tokens - inputs.reserve_tokens < 100_000:
        raise ConfigError(
            "allocated tokens must leave at least 100000 after reserve for the default P95 gate"
        )


def render_codex_config(inputs: CodexSetupInputs, codex_executable: str) -> str:
    _validate_inputs(inputs)
    checked_at = datetime.now(UTC).date().isoformat()
    policy_forbid_paths = _toml_strings(
        (
            ".github/workflows/**",
            "SECURITY.md",
            "CODEOWNERS",
            ".gitmodules",
            ".gitattributes",
            "**/*.pem",
            "**/*.key",
        )
    )
    return f'''version = 1
state_dir = ".leftovers/state"
temp_root = ".leftovers/workspaces"

[github]
api_url = "https://api.github.com"
token_env = "GITHUB_TOKEN"
api_version = "2026-03-10"
request_timeout_seconds = 20
max_read_requests_per_run = 500

[budget]
source = "fixed"
fixed_remaining_tokens = {inputs.allocated_tokens}
maximum_tokens = {inputs.allocated_tokens}
reserve_tokens = {inputs.reserve_tokens}
minimum_spendable_tokens = 30000
safety_multiplier = 1.25
window = {_toml_string(inputs.window)}
timezone = {_toml_string(inputs.timezone)}
reset_hour = 0
reset_weekday = 0
max_run_seconds = 3600
reset_safety_seconds = 300

[discovery]
query = {_toml_string(f'is:issue is:open no:assignee -linked:pr label:"{inputs.allow_labels[0]}"')}
per_repo_limit = 20
max_candidates = 100

[scoring]
minimum_score = 55
repository_impact_weight = 0.28
urgency_weight = 0.22
user_demand_weight = 0.15
maintainer_signal_weight = 0.15
tractability_weight = 0.12
neglect_weight = 0.08
technical_risk_penalty = 0.20
collision_risk_penalty = 0.12
scope_uncertainty_penalty = 0.08

[policy]
require_unassigned = true
require_no_open_linked_pr = true
require_license = true
max_changed_files = 20
max_changed_lines = 1200
max_patch_bytes = 1000000
ai_policy_max_age_days = 90
deny_labels = ["security", "vulnerability", "legal", "needs-design", "breaking-change", "wontfix"]
forbid_paths = {policy_forbid_paths}
forbid_dependency_changes = true

[sandbox]
runtime = {_toml_string(inputs.runtime)}
image = "leftovers-sandbox:latest"
network = "none"
memory = "4g"
cpus = 2.0
pids_limit = 256
timeout_seconds = 1800
tmpfs_size = "512m"

[agent]
backend = "codex-cli"
command = [{_toml_string(codex_executable)}]
provider = "{CODEX_PROVIDER}"
model = {_toml_string(inputs.model)}
checkin_required = true
usage_reporting_required = true
checkin_timeout_seconds = 30
heartbeat_timeout_seconds = 120
timeout_seconds = 3600
max_output_bytes = 65536
estimated_tokens_p50 = 40000
estimated_tokens_p95 = 80000
max_repair_cycles = 1
pass_environment = []

[publication]
mode = "dry-run"
external_writes_acknowledged = false
require_cli_flag = true
draft = true
fork = true
branch_prefix = "leftovers"
disclose_ai_assistance = true
max_prs_per_window = 1
max_open_prs_per_repository = 1
repository_cooldown_days = 7

[[repositories]]
slug = {_toml_string(inputs.repository)}
enabled = true
importance = 0.5
default_branch = {_toml_string(inputs.default_branch)}
allowed_licenses = {_toml_strings(inputs.allowed_licenses)}
allow_labels = {_toml_strings(inputs.allow_labels)}
deny_labels = ["needs maintainer decision"]
setup_commands = []
test_commands = {_toml_commands(inputs.test_commands)}
forbid_paths = ["infra/**", "releases/**"]
max_changed_files = 12
max_changed_lines = 600
network = "none"
require_human_approval = true
ai_contributions_allowed = true
ai_policy_url = {_toml_string(inputs.ai_policy_url)}
ai_policy_checked_at = {_toml_string(checked_at)}
'''


def _write_new_config(path: Path, content: str) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink() or expanded.exists():
        raise ConfigError(f"refusing to overwrite existing setup config: {expanded}")
    parent = expanded.parent
    if parent.is_symlink():
        raise ConfigError(f"setup config parent may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid():
        raise ConfigError("setup config parent is not an owner-controlled directory")
    parent = parent.resolve()
    target = parent / expanded.name
    descriptor, temporary_name = tempfile.mkstemp(prefix=".leftovers-setup-", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        pending = memoryview(content.encode("utf-8"))
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise ConfigError("setup config write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        load_config(temporary)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise ConfigError(f"refusing to overwrite existing setup config: {target}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ConfigError("created setup config failed ownership and file-type verification")
    os.chmod(target, 0o600)
    return target


def _gh_authenticated(executable: str | None) -> bool:
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [executable, "auth", "status", "--hostname", "github.com"],
            env={name: os.environ[name] for name in ("HOME", "PATH") if name in os.environ},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def container_image_available(runtime: str, image: str = "leftovers-sandbox:latest") -> bool:
    executable = shutil.which(runtime)
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [executable, "image", "inspect", image],
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def setup_codex(path: Path, inputs: CodexSetupInputs) -> tuple[int, dict[str, object]]:
    _validate_inputs(inputs)
    codex = inspect_codex_cli("codex", inputs.model)
    configured_executable = codex.executable or "codex"
    config_path = _write_new_config(path, render_codex_config(inputs, configured_executable))
    git_present = shutil.which("git") is not None
    runtime_present = shutil.which(inputs.runtime) is not None
    image_present = runtime_present and container_image_available(inputs.runtime)
    gh = shutil.which("gh")
    gh_authenticated = _gh_authenticated(gh)
    github_read_token = bool(os.environ.get("GITHUB_TOKEN"))
    checks = [
        {
            "name": "python",
            "ok": sys.version_info >= (3, 11),
            "severity": "error",
            "detail": "Python 3.11 or newer is required",
        },
        {
            "name": "git",
            "ok": git_present,
            "severity": "error",
            "detail": "Git is required for temporary repository acquisition",
        },
        {
            "name": "container_runtime",
            "ok": runtime_present,
            "severity": "error",
            "detail": f"{inputs.runtime} is required for offline verification and cleanup proof",
        },
        {
            "name": "sandbox_image",
            "ok": image_present,
            "severity": "error",
            "detail": "leftovers-sandbox:latest must be built locally before execute runs",
        },
        {
            "name": "codex_cli",
            "ok": codex.executable is not None,
            "severity": "error",
            "detail": "Codex CLI must be installed and available on PATH",
        },
        {
            "name": "codex_version",
            "ok": codex.version_supported,
            "severity": "error",
            "detail": "Codex CLI 0.145.0 or newer is required by the hardened adapter",
        },
        {
            "name": "codex_login",
            "ok": codex.authenticated,
            "severity": "error",
            "detail": "Codex CLI must have an active saved login; run codex login",
        },
        {
            "name": "codex_model",
            "ok": codex.model_available,
            "severity": "error",
            "detail": f"configured model {inputs.model} must exist in the bundled catalog",
        },
        {
            "name": "github_read_token",
            "ok": github_read_token,
            "severity": "error",
            "detail": "GITHUB_TOKEN must contain a read-only public-repository token for scouting",
        },
        {
            "name": "github_cli",
            "ok": gh is not None,
            "severity": "warning",
            "detail": "gh is needed only after a later publication review",
        },
        {
            "name": "github_login",
            "ok": gh_authenticated,
            "severity": "warning",
            "detail": "gh authentication is needed only after a later publication review",
        },
    ]
    errors = [check for check in checks if not check["ok"] and check["severity"] == "error"]
    next_steps = [
        f"leftovers --config {config_path} validate",
        f"leftovers --config {config_path} doctor",
        f"leftovers --config {config_path} scout",
    ]
    if not codex.authenticated:
        next_steps.insert(0, "codex login")
    if not image_present:
        next_steps.insert(0, "make sandbox-image")
    if not github_read_token:
        next_steps.insert(0, "set GITHUB_TOKEN to a read-only public-repository token")
    return (0 if not errors else 3), {
        "configured": True,
        "ready": not errors,
        "config": str(config_path),
        "mode": "dry-run",
        "checks": checks,
        "next_steps": next_steps,
        "publication_enabled": False,
        "packages_installed": False,
        "scheduler_installed": False,
    }
