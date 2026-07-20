from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import TokenUsage, utc_now


CODEX_PROVIDER = "openai-codex-cli"
CODEX_ADAPTER_VERSION = "leftovers-codex-cli-v1"
MIN_CODEX_VERSION = (0, 145, 0)
_MAX_MODEL_CATALOG_BYTES = 2_000_000
_CODEX_VERSION = re.compile(r"\bcodex-cli\s+(\d+)\.(\d+)\.(\d+)")
_DISABLED_FEATURES = (
    "apps",
    "goals",
    "hooks",
    "memories",
    "multi_agent",
    "remote_plugin",
    "shell_snapshot",
)


class CodexAdapterError(RuntimeError):
    pass


@dataclass(frozen=True)
class CodexCliInspection:
    executable: str | None
    version: str | None
    version_supported: bool
    authenticated: bool
    model_available: bool

    @property
    def ready(self) -> bool:
        return bool(
            self.executable
            and self.version_supported
            and self.authenticated
            and self.model_available
        )


def resolve_codex_executable(value: str = "codex") -> str | None:
    candidate = shutil.which(value)
    if candidate is None:
        return None
    return str(Path(candidate).resolve())


def codex_process_environment(isolated_home: Path | None = None) -> dict[str, str]:
    """Keep login discovery available without forwarding ambient worker credentials."""
    allowed = {
        "CODEX_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "PATH",
        "SHELL",
        "TMPDIR",
        "USER",
    }
    environment = {name: value for name, value in os.environ.items() if name in allowed}
    if isolated_home is not None:
        actual_home = os.environ.get("HOME")
        codex_home = os.environ.get("CODEX_HOME")
        if codex_home is None and actual_home:
            codex_home = str(Path(actual_home) / ".codex")
        if not codex_home:
            raise CodexAdapterError("Codex auth home could not be determined")
        environment["CODEX_HOME"] = codex_home
        environment["HOME"] = str(isolated_home.resolve())
    return environment


def validate_codex_workspace(workspace: Path) -> None:
    """Reject repository skill discovery that would outrank the untrusted-source contract."""
    agents = workspace / ".agents"
    try:
        agents_info = agents.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(agents_info.st_mode) or not stat.S_ISDIR(agents_info.st_mode):
        raise CodexAdapterError("repository .agents path is not a real directory")
    skills = agents / "skills"
    try:
        skills.lstat()
    except FileNotFoundError:
        return
    raise CodexAdapterError("repository-local Codex skills are refused in unattended runs")


def _run_codex_probe(argv: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            env=codex_process_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CodexAdapterError(f"Codex CLI probe failed: {type(exc).__name__}") from exc


def inspect_codex_cli(executable: str, model: str) -> CodexCliInspection:
    resolved = resolve_codex_executable(executable)
    if resolved is None:
        return CodexCliInspection(None, None, False, False, False)

    try:
        version_result = _run_codex_probe([resolved, "--version"])
    except CodexAdapterError:
        return CodexCliInspection(resolved, None, False, False, False)
    version_text = version_result.stdout.strip()
    match = _CODEX_VERSION.search(version_text)
    parsed = tuple(int(part) for part in match.groups()) if match else None
    version_supported = bool(
        version_result.returncode == 0 and parsed is not None and parsed >= MIN_CODEX_VERSION
    )

    try:
        login_result = _run_codex_probe([resolved, "login", "status"])
    except CodexAdapterError:
        authenticated = False
    else:
        authenticated = login_result.returncode == 0

    model_available = False
    try:
        models_result = _run_codex_probe([resolved, "debug", "models", "--bundled"])
    except CodexAdapterError:
        models_result = None
    if models_result is not None and models_result.returncode == 0 and (
        len(models_result.stdout.encode("utf-8")) <= _MAX_MODEL_CATALOG_BYTES
    ):
        try:
            payload = json.loads(models_result.stdout)
        except (json.JSONDecodeError, RecursionError):
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("models"), list):
            model_available = any(
                isinstance(item, dict) and item.get("slug") == model
                for item in payload["models"]
            )

    return CodexCliInspection(
        executable=resolved,
        version=version_text or None,
        version_supported=version_supported,
        authenticated=authenticated,
        model_available=model_available,
    )


def _string_schema(*, minimum: int = 0, maximum: int = 8_192) -> dict[str, Any]:
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def _string_array(*, minimum: int = 0) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": minimum,
        "maxItems": 128,
        "items": _string_schema(minimum=1, maximum=4_096),
    }


def stage_result_schema(stage: str) -> dict[str, Any]:
    string = _string_schema(maximum=8_192)
    nonempty = _string_schema(minimum=1, maximum=8_192)
    argv = {
        "type": "array",
        "maxItems": 64,
        "items": _string_schema(maximum=4_096),
    }
    if stage == "planning":
        properties: dict[str, Any] = {
            "status": {"type": "string", "enum": ["planned", "blocked", "failed"]},
            "acceptance_criteria": _string_array(),
            "reproduction": {
                "type": "object",
                "properties": {"argv": argv, "observed": string},
                "required": ["argv", "observed"],
                "additionalProperties": False,
            },
            "root_cause": {
                "type": "array",
                "maxItems": 128,
                "items": {
                    "type": "object",
                    "properties": {"path": string, "evidence": string},
                    "required": ["path", "evidence"],
                    "additionalProperties": False,
                },
            },
            "steps": _string_array(),
            "tests": {"type": "array", "maxItems": 64, "items": argv},
            "risks": _string_array(),
            "estimated_remaining_tokens": {
                "type": "integer",
                "minimum": 0,
                "maximum": 1_000_000_000,
            },
            "stop_conditions": _string_array(),
            "reason": string,
        }
    elif stage == "implementation":
        properties = {
            "status": {"type": "string", "enum": ["implemented", "blocked", "failed"]},
            "summary": string,
            "changed_files": _string_array(),
            "commands": {
                "type": "array",
                "maxItems": 128,
                "items": {
                    "type": "object",
                    "properties": {
                        "argv": argv,
                        "exit_code": {"type": "integer"},
                        "summary": string,
                    },
                    "required": ["argv", "exit_code", "summary"],
                    "additionalProperties": False,
                },
            },
            "acceptance_criteria": {
                "type": "array",
                "maxItems": 128,
                "items": {
                    "type": "object",
                    "properties": {"criterion": string, "evidence": string},
                    "required": ["criterion", "evidence"],
                    "additionalProperties": False,
                },
            },
            "remaining_risks": _string_array(),
            "reason": string,
        }
    elif stage == "review":
        properties = {
            "verdict": {"type": "string", "enum": ["approve", "revise", "abandon"]},
            "findings": {
                "type": "array",
                "maxItems": 128,
                "items": {
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["blocker", "major", "minor"],
                        },
                        "summary": nonempty,
                        "evidence": nonempty,
                        "path": {"type": ["string", "null"], "maxLength": 4_096},
                    },
                    "required": ["severity", "summary", "evidence", "path"],
                    "additionalProperties": False,
                },
            },
            "missing_verification": _string_array(),
            "pr_claims_supported": {"type": "boolean"},
        }
    else:
        raise CodexAdapterError(f"unsupported Codex stage: {stage}")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def write_stage_schema(path: Path, stage: str) -> None:
    encoded = (json.dumps(stage_result_schema(stage), sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise CodexAdapterError("Codex output schema is not an owner-controlled regular file")
        os.fchmod(descriptor, 0o600)
        pending = memoryview(encoded)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise CodexAdapterError("Codex output schema write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _permission_config(profile: str, access: str) -> str:
    workspace_rules = (
        '{"."="'
        + access
        + '",".git"="read",".agents"="deny",".codex"="deny",'
        + '".env"="deny",".env.*"="deny","*.env"="deny",'
        + '"*/*.env"="deny","*/*/*.env"="deny","**/*.pem"="deny",'
        + '"**/*.key"="deny"}'
    )
    return (
        f'permissions.{profile}.filesystem={{glob_scan_max_depth=3,":minimal"="read",'
        f'":workspace_roots"={workspace_rules}}}'
    )


def build_codex_argv(
    executable: str,
    *,
    stage: str,
    workspace: Path,
    schema_path: Path,
    result_path: Path,
    model: str,
    read_only_workspace: bool,
) -> list[str]:
    if stage not in {"planning", "implementation", "review"}:
        raise CodexAdapterError(f"unsupported Codex stage: {stage}")
    if read_only_workspace != (stage != "implementation"):
        raise CodexAdapterError("Codex stage and workspace permission do not match")
    profile = "leftovers-read" if read_only_workspace else "leftovers-write"
    access = "read" if read_only_workspace else "write"
    argv = [
        executable,
        "--ask-for-approval",
        "never",
        "--cd",
        str(workspace.resolve()),
        "--model",
        model,
        "--config",
        f'default_permissions="{profile}"',
        "--config",
        _permission_config(profile, access),
        "--config",
        f"permissions.{profile}.network.enabled=false",
        "--config",
        "project_doc_max_bytes=0",
        "--config",
        "project_doc_fallback_filenames=[]",
        "--config",
        "mcp_servers={}",
        "--config",
        'web_search="disabled"',
        "--config",
        "check_for_update_on_startup=false",
        "--config",
        'shell_environment_policy.inherit="none"',
        "--config",
        'shell_environment_policy.set={CI="1"}',
    ]
    for feature in _DISABLED_FEATURES:
        argv.extend(["--disable", feature])
    argv.extend(
        [
            "exec",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--json",
            "--color",
            "never",
            "--output-schema",
            str(schema_path.resolve()),
            "--output-last-message",
            str(result_path.resolve()),
            "-",
        ]
    )
    return argv


def parse_codex_usage(output: str) -> TokenUsage:
    latest: dict[str, Any] | None = None
    for line in output.splitlines():
        if not line.startswith("{") or len(line) > 65_536:
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            continue
        if (
            isinstance(event, dict)
            and event.get("type") == "turn.completed"
            and isinstance(event.get("usage"), dict)
        ):
            latest = event["usage"]
    if latest is None:
        raise CodexAdapterError("Codex JSONL did not contain a final usage receipt")
    values = {
        "input_tokens": latest.get("input_tokens"),
        "cached_input_tokens": latest.get("cached_input_tokens", 0),
        "output_tokens": latest.get("output_tokens"),
        "reasoning_tokens": latest.get(
            "reasoning_output_tokens", latest.get("reasoning_tokens", 0)
        ),
    }
    if any(type(value) is not int or not 0 <= value <= 1_000_000_000 for value in values.values()):
        raise CodexAdapterError("Codex JSONL usage values are invalid")
    if values["cached_input_tokens"] > values["input_tokens"]:
        raise CodexAdapterError("Codex cached input usage exceeds input usage")
    if values["reasoning_tokens"] > values["output_tokens"]:
        raise CodexAdapterError("Codex reasoning usage exceeds output usage")
    return TokenUsage(
        **values,
        total_tokens=values["input_tokens"] + values["output_tokens"],
        source="provider_response",
        exact=True,
        reported_at=utc_now(),
    )
