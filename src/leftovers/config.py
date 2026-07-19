from __future__ import annotations

import math
import os
import re
import tempfile
import tomllib
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

# Unattended agents may add repository-specific exclusions, but they may never
# relax this workflow/infrastructure/security baseline through TOML overrides.
MANDATORY_FORBID_PATHS: tuple[str, ...] = (
    ".github/workflows/**",
    ".github/actions/**",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    ".circleci/**",
    ".buildkite/**",
    ".azure-pipelines/**",
    "Jenkinsfile",
    "Jenkinsfile.*",
    "**/Jenkinsfile",
    "**/Jenkinsfile.*",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    "bitbucket-pipelines.yaml",
    ".travis.yml",
    ".travis.yaml",
    ".drone.yml",
    ".drone.yaml",
    ".woodpecker.yml",
    ".woodpecker.yaml",
    "appveyor.yml",
    "appveyor.yaml",
    "infra/**",
    "**/infra/**",
    "infrastructure/**",
    "**/infrastructure/**",
    "terraform/**",
    "**/terraform/**",
    "*.tf",
    "**/*.tf",
    "*.tf.json",
    "**/*.tf.json",
    "*.tfvars",
    "**/*.tfvars",
    "k8s/**",
    "**/k8s/**",
    "kubernetes/**",
    "**/kubernetes/**",
    "helm/**",
    "**/helm/**",
    "charts/**",
    "**/charts/**",
    "ansible/**",
    "**/ansible/**",
    "cloudformation/**",
    "**/cloudformation/**",
    "deploy/**",
    "**/deploy/**",
    "deployment/**",
    "**/deployment/**",
    "scripts/deploy*",
    "**/scripts/deploy*",
    "scripts/release*",
    "**/scripts/release*",
    ".devcontainer/**",
    "**/.devcontainer/**",
    "Pulumi.yaml",
    "Pulumi.*.yaml",
    "**/Pulumi.yaml",
    "**/Pulumi.*.yaml",
    "cdk.json",
    "**/cdk.json",
    "serverless.yml",
    "serverless.yaml",
    "**/serverless.yml",
    "**/serverless.yaml",
    "samconfig.toml",
    "**/samconfig.toml",
    "Dockerfile",
    "Dockerfile.*",
    "**/Dockerfile",
    "**/Dockerfile.*",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "**/docker-compose*.yml",
    "**/docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    "**/compose*.yml",
    "**/compose*.yaml",
    "SECURITY.md",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    "LICENSE*",
    "**/LICENSE*",
    "COPYING*",
    "**/COPYING*",
    "NOTICE*",
    "**/NOTICE*",
    ".gitmodules",
    ".gitattributes",
    "*.pem",
    "*.key",
    "**/*.pem",
    "**/*.key",
)


class ConfigError(ValueError):
    """Raised when configuration is ambiguous or unsafe."""


@dataclass(frozen=True)
class GitHubConfig:
    api_url: str = "https://api.github.com"
    token_env: str = "GITHUB_TOKEN"
    api_version: str = "2026-03-10"
    request_timeout_seconds: int = 20
    max_read_requests_per_run: int = 500


@dataclass(frozen=True)
class BudgetConfig:
    source: str = "environment"
    remaining_tokens_env: str = "LEFTOVERS_REMAINING_TOKENS"
    fixed_remaining_tokens: int | None = None
    maximum_tokens: int | None = None
    reserve_tokens: int = 20_000
    minimum_spendable_tokens: int = 30_000
    safety_multiplier: float = 1.25
    window: str = "daily"
    timezone: str = "UTC"
    reset_hour: int = 0
    reset_weekday: int = 0
    max_run_seconds: int = 3_600
    reset_safety_seconds: int = 300


@dataclass(frozen=True)
class DiscoveryConfig:
    query: str = 'is:issue is:open no:assignee -linked:pr label:"help wanted"'
    per_repo_limit: int = 20
    max_candidates: int = 100


@dataclass(frozen=True)
class ScoringConfig:
    minimum_score: int = 55
    repository_impact_weight: float = 0.28
    urgency_weight: float = 0.22
    user_demand_weight: float = 0.15
    maintainer_signal_weight: float = 0.15
    tractability_weight: float = 0.12
    neglect_weight: float = 0.08
    technical_risk_penalty: float = 0.20
    collision_risk_penalty: float = 0.12
    scope_uncertainty_penalty: float = 0.08


@dataclass(frozen=True)
class PolicyConfig:
    require_unassigned: bool = True
    require_no_open_linked_pr: bool = True
    require_license: bool = True
    max_changed_files: int = 20
    max_changed_lines: int = 1_200
    max_patch_bytes: int = 1_000_000
    ai_policy_max_age_days: int = 90
    deny_labels: tuple[str, ...] = (
        "security",
        "vulnerability",
        "credentials",
        "authentication",
        "authorization",
        "cryptography",
        "infrastructure",
        "abuse",
        "release",
        "legal",
        "needs-design",
        "breaking-change",
        "wontfix",
    )
    forbid_paths: tuple[str, ...] = MANDATORY_FORBID_PATHS
    forbid_dependency_changes: bool = True


@dataclass(frozen=True)
class SandboxConfig:
    runtime: str = "docker"
    image: str = "leftovers-sandbox:latest"
    network: str = "none"
    memory: str = "4g"
    cpus: float = 2.0
    pids_limit: int = 256
    timeout_seconds: int = 1_800
    tmpfs_size: str = "512m"


@dataclass(frozen=True)
class AgentConfig:
    backend: str = "container"
    command: tuple[str, ...] = ()
    provider: str = "unconfigured"
    model: str = "unconfigured"
    checkin_required: bool = False
    usage_reporting_required: bool = False
    checkin_timeout_seconds: int = 30
    heartbeat_timeout_seconds: int = 120
    timeout_seconds: int = 3_600
    max_output_bytes: int = 65_536
    estimated_tokens_p50: int = 40_000
    estimated_tokens_p95: int = 80_000
    max_repair_cycles: int = 1
    pass_environment: tuple[str, ...] = ()


@dataclass(frozen=True)
class StrictVMConfig:
    """Pinned, bounded inputs for the future whole-cycle VM backend.

    These values describe controller-owned artifacts and limits only.  There is
    intentionally no command, environment, network, mount, endpoint, or
    publication field in this section.
    """

    enabled: bool = False
    profile: str = "darwin-vz-offline-v2"
    launcher_path: str = ""
    launcher_sha256: str = ""
    boot_artifact_directory: str = ""
    kernel_path: str = ""
    kernel_sha256: str = ""
    initrd_path: str = ""
    initrd_sha256: str = ""
    root_disk_path: str = ""
    root_disk_sha256: str = ""
    # This is an immutable canonical JSON artifact, not an operator-supplied
    # digest.  The strict runner derives its digest only after validating that
    # it binds the exact pinned boot artifacts.
    guest_policy_path: str = ""
    cpu_count: int = 2
    memory_bytes: int = 2_147_483_648
    scratch_bytes: int = 2_147_483_648
    wall_time_seconds: int = 1_800
    max_rounds: int = 8
    max_actions_per_round: int = 24
    max_request_bytes: int = 268_435_456
    result_region_bytes: int = 16_777_216
    max_observation_bytes: int = 262_144


@dataclass(frozen=True)
class MediatorConfig:
    """Inference-only mediator identity and quotas.

    No executable or endpoint is configurable here.  A concrete built-in
    implementation must be separately reviewed before ``backend`` can grow a
    production value.
    """

    backend: str = "disabled"
    provider: str = "openai-subscription"
    model: str = "gpt-5.6-terra"
    reasoning_effort: str = "high"
    max_calls: int = 12
    per_call_timeout_seconds: int = 360
    max_prompt_bytes: int = 262_144
    max_response_bytes: int = 65_536
    total_token_cap: int = 65_000


@dataclass(frozen=True)
class PublicationConfig:
    mode: str = "dry-run"
    external_writes_acknowledged: bool = False
    require_cli_flag: bool = True
    draft: bool = True
    fork: bool = True
    branch_prefix: str = "leftovers"
    disclose_ai_assistance: bool = True
    max_prs_per_window: int = 1
    max_open_prs_per_repository: int = 1
    repository_cooldown_days: int = 7
    expected_login: str | None = None
    expected_user_id: int | None = None


@dataclass(frozen=True)
class RepositoryConfig:
    slug: str
    enabled: bool = True
    importance: float = 0.5
    default_branch: str | None = None
    allowed_licenses: tuple[str, ...] = ()
    allow_labels: tuple[str, ...] = ()
    deny_labels: tuple[str, ...] = ()
    test_commands: tuple[tuple[str, ...], ...] = ()
    setup_commands: tuple[tuple[str, ...], ...] = ()
    forbid_paths: tuple[str, ...] = ()
    max_changed_files: int | None = None
    max_changed_lines: int | None = None
    network: str | None = None
    require_human_approval: bool = False
    ai_contributions_allowed: bool | None = None
    ai_policy_url: str | None = None
    ai_policy_checked_at: str | None = None


@dataclass(frozen=True)
class AppConfig:
    version: int
    state_dir: Path
    temp_root: Path
    github: GitHubConfig
    budget: BudgetConfig
    discovery: DiscoveryConfig
    scoring: ScoringConfig
    policy: PolicyConfig
    sandbox: SandboxConfig
    agent: AgentConfig
    publication: PublicationConfig
    strict_vm: StrictVMConfig = field(default_factory=StrictVMConfig)
    mediator: MediatorConfig = field(default_factory=MediatorConfig)
    repositories: tuple[RepositoryConfig, ...] = field(default_factory=tuple)


def production_isolation_violations(config: AppConfig) -> tuple[str, ...]:
    """Return configuration choices forbidden for unattended production work.

    Host agents, networked workers, and ambient host environment forwarding are
    still loadable so explicitly labeled training and rehearsal workflows keep
    working.  The production orchestrator applies these stricter invariants
    before budget admission, discovery, or resource acquisition.
    """

    violations: list[str] = []
    if config.agent.backend == "host":
        violations.append("agent.backend=host executes the model on the host")
    if config.sandbox.network != "none":
        violations.append("sandbox.network must be none")
    networked_repositories = sorted(
        repository.slug
        for repository in config.repositories
        if repository.enabled and repository.network not in {None, "none"}
    )
    if networked_repositories:
        violations.append(
            "repository network overrides must be none: " + ", ".join(networked_repositories)
        )
    if config.agent.pass_environment:
        violations.append("agent.pass_environment must be empty")
    if config.agent.backend != "strict-vm":
        violations.append("agent.backend must be strict-vm for unattended production")
    if not config.strict_vm.enabled:
        violations.append("strict_vm.enabled must be true for unattended production")
    if config.mediator.backend != "inference-only-v1":
        violations.append("no credential-isolating inference-only mediator is implemented")
    return tuple(violations)


_SECTIONS = {
    "version",
    "state_dir",
    "temp_root",
    "github",
    "budget",
    "discovery",
    "scoring",
    "policy",
    "sandbox",
    "agent",
    "strict_vm",
    "mediator",
    "publication",
    "repositories",
}
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REPOSITORY_SLUG = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}"
)
_PINNED_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]*@sha256:[0-9a-fA-F]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BYTE_SIZE = re.compile(r"([1-9][0-9]{0,9})([bkmg]?)")
_BYTE_SIZE_MULTIPLIERS = {
    "": 1,
    "b": 1,
    "k": 1 << 10,
    "m": 1 << 20,
    "g": 1 << 30,
}


def _bounded_byte_size(value: str, where: str, minimum: int, maximum: int) -> int:
    """Parse the small, unambiguous byte-size subset accepted by Leftovers."""

    match = _BYTE_SIZE.fullmatch(value)
    if match is None:
        raise ConfigError(
            f"{where} must be a positive integer byte size with an optional b, k, m, or g suffix"
        )
    size = int(match.group(1)) * _BYTE_SIZE_MULTIPLIERS[match.group(2)]
    if not minimum <= size <= maximum:
        raise ConfigError(f"{where} is outside conservative byte-size bounds")
    return size


def _safe_git_ref(value: str) -> bool:
    forbidden = ("..", "@{", "\\", "~", "^", ":", "?", "*", "[", "//")
    return bool(
        value
        and len(value) <= 200
        and not value.startswith(("-", ".", "/"))
        and not value.endswith(("/", ".", ".lock"))
        and not any(token in value for token in forbidden)
        and not any(character.isspace() for character in value)
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _safe_absolute_config_path(value: str) -> bool:
    """Recognize a lexical, canonical absolute path without touching the host."""

    if not value or len(value.encode("utf-8")) > 1_024 or "\0" in value:
        return False
    path = Path(value)
    return (
        path.is_absolute()
        and value == str(path)
        and value != "/"
        and "//" not in value
        and all(part not in {"", ".", ".."} for part in path.parts[1:])
    )


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigError(f"unknown key(s) in {where}: {', '.join(unknown)}")


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a table")
    return value


def _tuple_strings(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{where} must be an array of strings")
    return tuple(value)


def _commands(value: Any, where: str) -> tuple[tuple[str, ...], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{where} must be an array of argv arrays")
    if len(value) > 10:
        raise ConfigError(f"{where} may contain at most 10 commands")
    commands: list[tuple[str, ...]] = []
    for command in value:
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(arg, str) for arg in command)
        ):
            raise ConfigError(f"each command in {where} must be a non-empty string array")
        if len(command) > 64 or any(
            len(argument) > 4_096 or "\0" in argument for argument in command
        ):
            raise ConfigError(f"a command in {where} exceeds the argv safety limits")
        commands.append(tuple(command))
    return tuple(commands)


def _make(section_type: type[Any], raw: dict[str, Any], where: str) -> Any:
    allowed = set(section_type.__dataclass_fields__)
    _reject_unknown(raw, allowed, where)
    hints = get_type_hints(section_type)
    for key, value in raw.items():
        if not _matches_type(value, hints[key]):
            raise ConfigError(
                f"{where}.{key} has type {type(value).__name__}; expected {hints[key]}"
            )
    try:
        return section_type(**raw)
    except TypeError as exc:
        raise ConfigError(f"invalid {where}: {exc}") from exc


def _matches_type(value: Any, annotation: Any) -> bool:
    origin = get_origin(annotation)
    if origin in {Union, types.UnionType}:
        return any(_matches_type(value, member) for member in get_args(annotation))
    if origin is tuple:
        arguments = get_args(annotation)
        if not isinstance(value, tuple):
            return False
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return all(_matches_type(item, arguments[0]) for item in value)
        return len(value) == len(arguments) and all(
            _matches_type(item, expected) for item, expected in zip(value, arguments, strict=True)
        )
    if annotation is bool:
        return type(value) is bool
    if annotation is int:
        return type(value) is int
    if annotation is float:
        return type(value) in {int, float}
    if annotation is str:
        return isinstance(value, str)
    if annotation is type(None):
        return value is None
    return isinstance(value, annotation)


def _repository(raw: dict[str, Any], index: int) -> RepositoryConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"repositories[{index}] must be a table")
    allowed = set(RepositoryConfig.__dataclass_fields__)
    _reject_unknown(raw, allowed, f"repositories[{index}]")
    if (
        "slug" not in raw
        or not isinstance(raw["slug"], str)
        or _REPOSITORY_SLUG.fullmatch(raw["slug"]) is None
        or raw["slug"].endswith(("/.", "/.."))
    ):
        raise ConfigError(f"repositories[{index}].slug must be 'owner/name'")
    values = dict(raw)
    for key in ("allowed_licenses", "allow_labels", "deny_labels", "forbid_paths"):
        values[key] = _tuple_strings(values.get(key), f"repositories[{index}].{key}")
    for key in ("test_commands", "setup_commands"):
        values[key] = _commands(values.get(key), f"repositories[{index}].{key}")
    repo = _make(RepositoryConfig, values, f"repositories[{index}]")
    if not 0 <= repo.importance <= 1:
        raise ConfigError(f"repositories[{index}].importance must be between 0 and 1")
    return repo


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {config_path}: {exc}") from exc
    _reject_unknown(data, _SECTIONS, "root")
    version = data.get("version")
    if type(version) is not int or version != 1:
        raise ConfigError("version must be 1")

    github_raw = _section(data, "github")
    budget_raw = _section(data, "budget")
    discovery_raw = _section(data, "discovery")
    scoring_raw = _section(data, "scoring")
    policy_raw = _section(data, "policy")
    sandbox_raw = _section(data, "sandbox")
    agent_raw = _section(data, "agent")
    strict_vm_raw = _section(data, "strict_vm")
    mediator_raw = _section(data, "mediator")
    publication_raw = _section(data, "publication")

    policy_raw = dict(policy_raw)
    for key in ("deny_labels", "forbid_paths"):
        if key in policy_raw:
            policy_raw[key] = _tuple_strings(policy_raw[key], f"policy.{key}")
    baseline_policy = PolicyConfig()
    if "deny_labels" in policy_raw:
        policy_raw["deny_labels"] = tuple(
            dict.fromkeys((*baseline_policy.deny_labels, *policy_raw["deny_labels"]))
        )
    if "forbid_paths" in policy_raw:
        policy_raw["forbid_paths"] = tuple(
            dict.fromkeys((*baseline_policy.forbid_paths, *policy_raw["forbid_paths"]))
        )
    agent_raw = dict(agent_raw)
    for key in ("command", "pass_environment"):
        if key in agent_raw:
            agent_raw[key] = _tuple_strings(agent_raw[key], f"agent.{key}")

    raw_repositories = data.get("repositories", [])
    if not isinstance(raw_repositories, list):
        raise ConfigError("repositories must be an array of tables")
    repositories = tuple(_repository(raw, i) for i, raw in enumerate(raw_repositories))
    enabled = [repo.slug for repo in repositories if repo.enabled]
    if not enabled:
        raise ConfigError("at least one repository must be enabled")
    if len(enabled) != len(set(enabled)):
        raise ConfigError("enabled repository slugs must be unique")

    state_default = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    state_value = data.get("state_dir", state_default / "leftovers")
    temp_value = data.get("temp_root", tempfile.gettempdir())
    if not isinstance(state_value, str | Path) or not isinstance(temp_value, str | Path):
        raise ConfigError("state_dir and temp_root must be paths")
    state_dir = Path(state_value).expanduser()
    temp_root = Path(temp_value).expanduser()

    config = AppConfig(
        version=version,
        state_dir=state_dir,
        temp_root=temp_root,
        github=_make(GitHubConfig, github_raw, "github"),
        budget=_make(BudgetConfig, budget_raw, "budget"),
        discovery=_make(DiscoveryConfig, discovery_raw, "discovery"),
        scoring=_make(ScoringConfig, scoring_raw, "scoring"),
        policy=_make(PolicyConfig, policy_raw, "policy"),
        sandbox=_make(SandboxConfig, sandbox_raw, "sandbox"),
        agent=_make(AgentConfig, agent_raw, "agent"),
        strict_vm=_make(StrictVMConfig, strict_vm_raw, "strict_vm"),
        mediator=_make(MediatorConfig, mediator_raw, "mediator"),
        publication=_make(PublicationConfig, publication_raw, "publication"),
        repositories=repositories,
    )
    _validate(config)
    return config


def _validate(config: AppConfig) -> None:
    if config.github.api_url != "https://api.github.com":
        raise ConfigError("v1 only supports https://api.github.com")
    if _ENVIRONMENT_NAME.fullmatch(config.github.token_env) is None:
        raise ConfigError("github.token_env must be an environment variable name")
    if not 1 <= config.github.request_timeout_seconds <= 60:
        raise ConfigError("github.request_timeout_seconds must be between 1 and 60")
    if not 1 <= config.github.max_read_requests_per_run <= 1_000:
        raise ConfigError("github.max_read_requests_per_run must be between 1 and 1000")
    if config.budget.source not in {"environment", "fixed"}:
        raise ConfigError("budget.source must be environment or fixed")
    if config.budget.source == "fixed" and config.budget.fixed_remaining_tokens is None:
        raise ConfigError("budget.fixed_remaining_tokens is required for the fixed source")
    if config.budget.reserve_tokens < 0 or config.budget.minimum_spendable_tokens < 0:
        raise ConfigError("budget reserve and minimum values cannot be negative")
    if (
        config.budget.fixed_remaining_tokens is not None
        and config.budget.fixed_remaining_tokens < 0
    ):
        raise ConfigError("budget.fixed_remaining_tokens cannot be negative")
    if config.budget.maximum_tokens is not None and config.budget.maximum_tokens < 1:
        raise ConfigError("budget.maximum_tokens must be positive when configured")
    if (
        config.budget.fixed_remaining_tokens is not None
        and config.budget.maximum_tokens is not None
        and config.budget.fixed_remaining_tokens > config.budget.maximum_tokens
    ):
        raise ConfigError("budget.fixed_remaining_tokens cannot exceed budget.maximum_tokens")
    if not math.isfinite(config.budget.safety_multiplier) or not (
        1 <= config.budget.safety_multiplier <= 3
    ):
        raise ConfigError("budget.safety_multiplier must be between 1 and 3")
    if _ENVIRONMENT_NAME.fullmatch(config.budget.remaining_tokens_env) is None:
        raise ConfigError("budget.remaining_tokens_env must be an environment variable name")
    if config.budget.window not in {"daily", "weekly"}:
        raise ConfigError("budget.window must be daily or weekly")
    if not 0 <= config.budget.reset_hour <= 23:
        raise ConfigError("budget.reset_hour must be between 0 and 23")
    if not 0 <= config.budget.reset_weekday <= 6:
        raise ConfigError("budget.reset_weekday must be between 0 and 6")
    if not 60 <= config.budget.max_run_seconds <= 7_200:
        raise ConfigError("budget.max_run_seconds must be between 60 and 7200")
    if not 0 <= config.budget.reset_safety_seconds <= 3_600:
        raise ConfigError("budget.reset_safety_seconds must be between 0 and 3600")
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(config.budget.timezone)
    except (ImportError, KeyError) as exc:
        raise ConfigError(f"unknown budget.timezone: {config.budget.timezone}") from exc
    if not 1 <= config.discovery.per_repo_limit <= 100:
        raise ConfigError("discovery.per_repo_limit must be between 1 and 100")
    if not 1 <= config.discovery.max_candidates <= 500:
        raise ConfigError("discovery.max_candidates must be between 1 and 500")
    if not config.discovery.query.strip() or len(config.discovery.query) > 1_000:
        raise ConfigError("discovery.query must contain at most 1000 characters")
    if any(ord(character) < 32 for character in config.discovery.query):
        raise ConfigError("discovery.query may not contain control characters")
    if config.sandbox.runtime not in {"docker", "podman"}:
        raise ConfigError("sandbox.runtime must be docker or podman")
    if config.sandbox.network not in {"none", "bridge"}:
        raise ConfigError("sandbox.network must be none or bridge")
    memory_bytes = _bounded_byte_size(
        config.sandbox.memory,
        "sandbox.memory",
        64 << 20,
        64 << 30,
    )
    tmpfs_bytes = _bounded_byte_size(
        config.sandbox.tmpfs_size,
        "sandbox.tmpfs_size",
        1 << 20,
        8 << 30,
    )
    if tmpfs_bytes > memory_bytes:
        raise ConfigError("sandbox.tmpfs_size may not exceed sandbox.memory")
    if config.sandbox.cpus <= 0 or config.sandbox.pids_limit < 1:
        raise ConfigError("sandbox CPU and PID limits must be positive")
    if config.sandbox.timeout_seconds < 1:
        raise ConfigError("sandbox.timeout_seconds must be positive")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,254}", config.sandbox.image):
        raise ConfigError("sandbox.image is not a safe OCI image reference")
    if "@sha256:" in config.sandbox.image and _PINNED_IMAGE.fullmatch(config.sandbox.image) is None:
        raise ConfigError("sandbox.image has an invalid SHA-256 digest")
    if not (
        0 < config.sandbox.cpus <= 64
        and 1 <= config.sandbox.pids_limit <= 4_096
        and 1 <= config.sandbox.timeout_seconds <= 7_200
    ):
        raise ConfigError("sandbox resource limits are outside conservative bounds")
    if config.agent.backend not in {"container", "host", "strict-vm"}:
        raise ConfigError("agent.backend must be container, host, or strict-vm")
    if config.agent.backend == "strict-vm":
        if config.agent.command:
            raise ConfigError("strict-vm agents cannot accept a configurable command")
        if config.agent.pass_environment:
            raise ConfigError("strict-vm agents cannot inherit host environment variables")
        if not config.strict_vm.enabled:
            raise ConfigError("agent.backend=strict-vm requires strict_vm.enabled=true")
    else:
        if not config.agent.command:
            raise ConfigError("agent.command must be a non-empty argv array")
        if not config.agent.command[0].strip():
            raise ConfigError("agent.command executable may not be empty")
    for field_name, value in (
        ("provider", config.agent.provider),
        ("model", config.agent.model),
    ):
        if (
            not value.strip()
            or len(value) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ConfigError(f"agent.{field_name} must be a bounded printable identifier")
    if len(config.agent.command) > 64 or any(
        len(argument) > 4_096 or "\0" in argument for argument in config.agent.command
    ):
        raise ConfigError("agent.command exceeds the argv safety limits")
    if any(_ENVIRONMENT_NAME.fullmatch(name) is None for name in config.agent.pass_environment):
        raise ConfigError("agent.pass_environment contains an invalid variable name")
    if (
        config.agent.timeout_seconds < 1
        or config.agent.max_output_bytes < 1
        or config.agent.estimated_tokens_p50 < 1
        or config.agent.estimated_tokens_p95 < config.agent.estimated_tokens_p50
        or config.agent.max_repair_cycles < 0
        or config.agent.checkin_timeout_seconds < 1
        or config.agent.heartbeat_timeout_seconds < config.agent.checkin_timeout_seconds
    ):
        raise ConfigError("agent limits and token estimates are invalid")
    if (
        config.agent.timeout_seconds > 14_400
        or config.agent.max_output_bytes > 1_000_000
        or config.agent.estimated_tokens_p95 > 10_000_000
        or config.agent.max_repair_cycles > 3
        or config.agent.checkin_timeout_seconds > 3_600
        or config.agent.heartbeat_timeout_seconds > 7_200
    ):
        raise ConfigError("agent limits exceed conservative upper bounds")
    forbidden_env = {
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITHUB_PAT",
        "SSH_AUTH_SOCK",
        config.github.token_env,
    }
    exposed = forbidden_env.intersection(config.agent.pass_environment)
    exposed.update(
        name
        for name in config.agent.pass_environment
        if name.startswith(("DOCKER_", "CONTAINER_", "PODMAN_", "KUBE"))
    )
    if exposed:
        raise ConfigError(
            "the coding agent may not receive GitHub or runtime-control credentials: "
            + ", ".join(sorted(exposed))
        )
    strict = config.strict_vm
    if strict.profile != "darwin-vz-offline-v2":
        raise ConfigError("strict_vm.profile must be darwin-vz-offline-v2")
    strict_paths = {
        "launcher_path": strict.launcher_path,
        "boot_artifact_directory": strict.boot_artifact_directory,
        "kernel_path": strict.kernel_path,
        "initrd_path": strict.initrd_path,
        "root_disk_path": strict.root_disk_path,
        "guest_policy_path": strict.guest_policy_path,
    }
    strict_digests = {
        "launcher_sha256": strict.launcher_sha256,
        "kernel_sha256": strict.kernel_sha256,
        "initrd_sha256": strict.initrd_sha256,
        "root_disk_sha256": strict.root_disk_sha256,
    }
    if strict.enabled:
        if config.agent.backend != "strict-vm":
            raise ConfigError("strict_vm.enabled=true requires agent.backend=strict-vm")
        missing = sorted(
            name for name, value in (*strict_paths.items(), *strict_digests.items()) if not value
        )
        if missing:
            raise ConfigError(
                "enabled strict_vm requires pinned paths and digests: " + ", ".join(missing)
            )
    for name, value in strict_paths.items():
        if value and not _safe_absolute_config_path(value):
            raise ConfigError(f"strict_vm.{name} must be a canonical absolute path")
    for name, value in strict_digests.items():
        if value and _SHA256.fullmatch(value) is None:
            raise ConfigError(f"strict_vm.{name} must be lowercase SHA-256")
    if strict.boot_artifact_directory:
        boot_directory = Path(strict.boot_artifact_directory)
        for name in ("kernel_path", "initrd_path", "root_disk_path", "guest_policy_path"):
            value = getattr(strict, name)
            if value and Path(value).parent != boot_directory:
                raise ConfigError(
                    f"strict_vm.{name} must be a direct child of boot_artifact_directory"
                )
    if not (
        1 <= strict.cpu_count <= 4
        and 512 << 20 <= strict.memory_bytes <= 4 << 30
        and strict.memory_bytes % (1 << 20) == 0
        and 64 << 20 <= strict.scratch_bytes <= 4 << 30
        and strict.scratch_bytes % (1 << 20) == 0
        and 30 <= strict.wall_time_seconds <= 3_600
    ):
        raise ConfigError("strict_vm hardware limits are outside launcher bounds")
    if not (
        1 <= strict.max_rounds <= 32
        and 1 <= strict.max_actions_per_round <= 32
        and 4_096 <= strict.max_request_bytes <= 256 << 20
        and strict.max_request_bytes % 512 == 0
        and 1 << 20 <= strict.result_region_bytes <= 64 << 20
        and strict.result_region_bytes % 4_096 == 0
        and strict.result_region_bytes < strict.scratch_bytes
        and 1_024 <= strict.max_observation_bytes <= 256 << 10
        and strict.max_observation_bytes < strict.result_region_bytes
    ):
        raise ConfigError("strict_vm protocol limits are outside conservative bounds")
    if config.mediator.backend not in {"disabled", "fixture"}:
        raise ConfigError(
            "mediator.backend has no reviewed production implementation; use disabled or fixture"
        )
    for name, value in (
        ("provider", config.mediator.provider),
        ("model", config.mediator.model),
        ("reasoning_effort", config.mediator.reasoning_effort),
    ):
        if (
            not value.strip()
            or len(value) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ConfigError(f"mediator.{name} must be a bounded printable identifier")
    if config.mediator.reasoning_effort not in {"low", "medium", "high"}:
        raise ConfigError("mediator.reasoning_effort is unsupported")
    if not (
        1 <= config.mediator.max_calls <= 64
        and 1 <= config.mediator.per_call_timeout_seconds <= 1_800
        and 1_024 <= config.mediator.max_prompt_bytes <= 4 << 20
        and 1_024 <= config.mediator.max_response_bytes <= 1 << 20
        and 1 <= config.mediator.total_token_cap <= 10_000_000
    ):
        raise ConfigError("mediator limits are outside conservative bounds")
    if config.mediator.backend == "fixture" and config.agent.backend != "strict-vm":
        raise ConfigError("the fixture mediator is only valid with agent.backend=strict-vm")
    if config.publication.mode not in {"dry-run", "draft-pr"}:
        raise ConfigError("publication.mode must be dry-run or draft-pr")
    if not config.publication.require_cli_flag:
        raise ConfigError("v1 requires publication.require_cli_flag = true")
    if config.publication.mode == "draft-pr" and not config.publication.draft:
        raise ConfigError("v1 only publishes draft PRs")
    if config.publication.mode == "draft-pr" and config.agent.backend not in {
        "container",
        "strict-vm",
    }:
        raise ConfigError("draft publication requires a container or strict-vm agent backend")
    if (
        config.publication.mode == "draft-pr"
        and _PINNED_IMAGE.fullmatch(config.sandbox.image) is None
    ):
        raise ConfigError("draft publication requires sandbox.image pinned by SHA-256 digest")
    if not _safe_git_ref(f"{config.publication.branch_prefix}/issue-1"):
        raise ConfigError("publication.branch_prefix is not a safe Git ref prefix")
    if (
        config.publication.expected_login is not None
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
            config.publication.expected_login,
        )
        is None
    ):
        raise ConfigError("publication.expected_login is not a valid GitHub login")
    if config.publication.expected_user_id is not None and config.publication.expected_user_id < 1:
        raise ConfigError("publication.expected_user_id must be positive")
    if config.publication.mode == "draft-pr" and (
        not config.publication.expected_login or config.publication.expected_user_id is None
    ):
        raise ConfigError("draft publication requires an expected GitHub login and user id")
    if (
        config.publication.max_prs_per_window < 1
        or config.publication.max_open_prs_per_repository < 1
        or config.publication.repository_cooldown_days < 0
        or config.publication.max_prs_per_window > 5
        or config.publication.max_open_prs_per_repository > 100
        or config.publication.repository_cooldown_days > 365
    ):
        raise ConfigError("publication caps or cooldown are outside conservative bounds")
    if not (
        config.policy.require_unassigned
        and config.policy.require_no_open_linked_pr
        and config.policy.require_license
        and config.policy.forbid_dependency_changes
        and config.publication.disclose_ai_assistance
    ):
        raise ConfigError("v1 safety and AI-disclosure invariants may not be disabled")
    if not 0 <= config.scoring.minimum_score <= 100:
        raise ConfigError("scoring.minimum_score must be between 0 and 100")
    scoring_weights = (
        config.scoring.repository_impact_weight,
        config.scoring.urgency_weight,
        config.scoring.user_demand_weight,
        config.scoring.maintainer_signal_weight,
        config.scoring.tractability_weight,
        config.scoring.neglect_weight,
        config.scoring.technical_risk_penalty,
        config.scoring.collision_risk_penalty,
        config.scoring.scope_uncertainty_penalty,
    )
    if any(not 0 <= weight <= 1 for weight in scoring_weights):
        raise ConfigError("scoring weights and penalties must be between 0 and 1")
    if (
        config.policy.max_changed_files < 1
        or config.policy.max_changed_lines < 1
        or config.policy.max_patch_bytes < 1
        or config.policy.ai_policy_max_age_days < 1
        or config.policy.max_changed_files > 100
        or config.policy.max_changed_lines > 10_000
        or config.policy.max_patch_bytes > 10_000_000
        or config.policy.ai_policy_max_age_days > 365
    ):
        raise ConfigError("change limits are outside conservative bounds")
    for index, repository in enumerate(config.repositories):
        if repository.network not in {None, "none", "bridge"}:
            raise ConfigError(f"repositories[{index}].network must be none or bridge")
        if repository.max_changed_files is not None and repository.max_changed_files < 1:
            raise ConfigError(f"repositories[{index}].max_changed_files must be positive")
        if repository.max_changed_lines is not None and repository.max_changed_lines < 1:
            raise ConfigError(f"repositories[{index}].max_changed_lines must be positive")
        if repository.default_branch is not None and not _safe_git_ref(repository.default_branch):
            raise ConfigError(f"repositories[{index}].default_branch is not a safe Git ref")
        if config.publication.mode == "draft-pr" and not repository.allow_labels:
            raise ConfigError(
                f"repositories[{index}] needs maintainer-signal allow_labels for draft publication"
            )
        if any(value in {"NOASSERTION", "OTHER"} for value in repository.allowed_licenses):
            raise ConfigError(
                f"repositories[{index}].allowed_licenses contains an unrecognized SPDX value"
            )
        if config.publication.mode == "draft-pr" and not repository.allowed_licenses:
            raise ConfigError(
                f"repositories[{index}] needs an explicit allowed_licenses list "
                "for draft publication"
            )
        if repository.ai_contributions_allowed is True:
            if not repository.ai_policy_url or not repository.ai_policy_url.startswith("https://"):
                raise ConfigError(
                    f"repositories[{index}] requires an HTTPS ai_policy_url when AI is allowed"
                )
            if not repository.ai_policy_checked_at:
                raise ConfigError(
                    f"repositories[{index}] requires ai_policy_checked_at when AI is allowed"
                )
