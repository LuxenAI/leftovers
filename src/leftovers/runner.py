from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import redact
from .config import AgentConfig, SandboxConfig
from .models import AgentResult, CommandResult, TokenUsage, isoformat, utc_now
from .prompts import RenderedPrompt


class RunnerError(RuntimeError):
    pass


class AgentOutputError(RunnerError):
    """Raised when an agent exits successfully but violates its result contract."""

    pass


_TELEMETRY_SOURCES = {
    "provider_response",
    "broker_attested",
    "adapter_reported",
    "estimated",
    "synthetic",
}
_TELEMETRY_MAX_BYTES = 65_536
_TELEMETRY_MAX_LINE_BYTES = 4_096
_TELEMETRY_MAX_EVENTS = 1_024


def _parse_observed_at(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise AgentOutputError("adapter telemetry observed_at must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AgentOutputError("adapter telemetry observed_at is invalid") from exc
    if parsed.tzinfo is None:
        raise AgentOutputError("adapter telemetry observed_at must include a timezone")
    observed = parsed.astimezone(UTC)
    now = utc_now()
    age = (now - observed).total_seconds()
    if age < -60 or age > 86_400:
        raise AgentOutputError("adapter telemetry observed_at is outside the accepted clock range")
    return observed


class _AdapterTelemetryMonitor:
    """Incrementally validates bounded, append-only adapter telemetry NDJSON."""

    def __init__(
        self,
        path: Path,
        agent: AgentConfig,
        callback: Callable[[dict[str, Any]], None] | None,
        *,
        allow_synthetic_usage: bool = False,
    ):
        self.path = path
        self.agent = agent
        self.callback = callback
        self.allow_synthetic_usage = allow_synthetic_usage
        self.offset = 0
        self.buffer = b""
        self.sequence = 0
        self.events = 0
        self.file_identity: tuple[int, int] | None = None
        self.started_monotonic = time.monotonic()
        self.checkin_at: datetime | None = None
        self.last_adapter_heartbeat_at: datetime | None = None
        self.usage: TokenUsage | None = None

    def _emit(self, event: dict[str, Any]) -> None:
        if self.callback is not None:
            self.callback(event)

    @staticmethod
    def _require_keys(event: dict[str, Any], required: set[str]) -> None:
        if set(event) != required:
            raise AgentOutputError("adapter telemetry event has unexpected fields")

    def _validate_sequence(self, event: dict[str, Any]) -> None:
        sequence = event.get("sequence")
        if type(sequence) is not int or sequence != self.sequence + 1:
            raise AgentOutputError("adapter telemetry sequence is not contiguous")
        self.sequence = sequence
        self.events += 1
        if self.events > _TELEMETRY_MAX_EVENTS:
            raise AgentOutputError("adapter telemetry exceeds the event count limit")

    def _consume(self, raw_line: bytes) -> None:
        if not raw_line or len(raw_line) > _TELEMETRY_MAX_LINE_BYTES:
            raise AgentOutputError("adapter telemetry line is empty or oversized")
        try:
            event = json.loads(raw_line, parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise AgentOutputError("adapter telemetry line is not strict JSON") from exc
        if not isinstance(event, dict):
            raise AgentOutputError("adapter telemetry event must be an object")
        _validate_json_complexity(event)
        self._validate_sequence(event)
        if event.get("version") != 1 or not isinstance(event.get("type"), str):
            raise AgentOutputError("adapter telemetry protocol version or event type is invalid")
        event_type = event["type"]
        if self.sequence == 1 and event_type != "checkin":
            raise AgentOutputError("adapter telemetry must begin with a model check-in")
        if event_type == "checkin":
            self._require_keys(
                event,
                {
                    "version",
                    "sequence",
                    "type",
                    "provider",
                    "model",
                    "adapter_version",
                    "capabilities",
                    "observed_at",
                },
            )
            if self.checkin_at is not None:
                raise AgentOutputError("adapter emitted more than one model check-in")
            for key in ("provider", "model", "adapter_version"):
                value = event[key]
                if (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value) > 128
                    or any(ord(character) < 32 or ord(character) == 127 for character in value)
                ):
                    raise AgentOutputError(f"adapter telemetry {key} is invalid")
            capabilities = event["capabilities"]
            if (
                not isinstance(capabilities, list)
                or len(capabilities) > 32
                or any(
                    not isinstance(item, str)
                    or not item
                    or len(item) > 64
                    or any(ord(character) < 32 or ord(character) == 127 for character in item)
                    for item in capabilities
                )
            ):
                raise AgentOutputError("adapter telemetry capabilities are invalid")
            if event["provider"] != self.agent.provider or event["model"] != self.agent.model:
                raise AgentOutputError("adapter model check-in does not match configured identity")
            self.checkin_at = _parse_observed_at(event["observed_at"])
            self.last_adapter_heartbeat_at = self.checkin_at
        elif event_type == "heartbeat":
            self._require_keys(
                event,
                {"version", "sequence", "type", "observed_at"},
            )
            if self.checkin_at is None:
                raise AgentOutputError("adapter heartbeat arrived before model check-in")
            observed = _parse_observed_at(event["observed_at"])
            if self.last_adapter_heartbeat_at and observed < self.last_adapter_heartbeat_at:
                raise AgentOutputError("adapter heartbeat timestamps moved backwards")
            self.last_adapter_heartbeat_at = observed
        elif event_type == "usage":
            self._require_keys(
                event,
                {
                    "version",
                    "sequence",
                    "type",
                    "input_tokens",
                    "output_tokens",
                    "cached_input_tokens",
                    "reasoning_tokens",
                    "total_tokens",
                    "source",
                    "exact",
                    "final",
                    "observed_at",
                },
            )
            if self.checkin_at is None:
                raise AgentOutputError("adapter usage arrived before model check-in")
            if self.usage is not None:
                raise AgentOutputError("adapter emitted more than one final usage receipt")
            values = {
                key: event[key]
                for key in (
                    "input_tokens",
                    "output_tokens",
                    "cached_input_tokens",
                    "reasoning_tokens",
                    "total_tokens",
                )
            }
            if any(
                type(value) is not int or not 0 <= value <= 1_000_000_000
                for value in values.values()
            ):
                raise AgentOutputError("adapter token usage values are invalid")
            if values["cached_input_tokens"] > values["input_tokens"]:
                raise AgentOutputError("cached input tokens exceed input tokens")
            if values["reasoning_tokens"] > values["output_tokens"]:
                raise AgentOutputError("reasoning tokens exceed output tokens")
            if values["total_tokens"] != values["input_tokens"] + values["output_tokens"]:
                raise AgentOutputError("adapter total tokens do not equal input plus output")
            source = event["source"]
            exact = event["exact"]
            if (
                source not in _TELEMETRY_SOURCES
                or type(exact) is not bool
                or event["final"] is not True
            ):
                raise AgentOutputError("adapter usage source, exactness, or finality is invalid")
            if source == "synthetic" and not self.allow_synthetic_usage:
                raise AgentOutputError(
                    "synthetic adapter usage is permitted only in an explicit training run"
                )
            if source == "estimated" and exact:
                raise AgentOutputError("estimated usage cannot be marked exact")
            if source in {"provider_response", "broker_attested"} and not exact:
                raise AgentOutputError("provider-attested usage must be marked exact")
            observed = _parse_observed_at(event["observed_at"])
            self.usage = TokenUsage(
                **values,
                source=source,
                exact=exact,
                reported_at=observed,
            )
        else:
            raise AgentOutputError("adapter telemetry event type is unsupported")
        self._emit(event)

    def poll(self, *, final: bool = False) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AgentOutputError("adapter telemetry must be a single-link regular file")
            identity = (info.st_dev, info.st_ino)
            if self.file_identity is None:
                self.file_identity = identity
            elif identity != self.file_identity:
                raise AgentOutputError("adapter telemetry file identity changed during execution")
            if info.st_size < self.offset:
                raise AgentOutputError("adapter telemetry was truncated during execution")
            if info.st_size > _TELEMETRY_MAX_BYTES:
                raise AgentOutputError("adapter telemetry exceeds the byte limit")
            descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.lseek(descriptor, self.offset, os.SEEK_SET)
                chunk = os.read(descriptor, _TELEMETRY_MAX_BYTES - self.offset + 1)
            finally:
                os.close(descriptor)
            self.offset += len(chunk)
            self.buffer += chunk
            lines = self.buffer.split(b"\n")
            self.buffer = lines.pop()
            for line in lines:
                self._consume(line)
        if final and self.buffer:
            pending = self.buffer
            self.buffer = b""
            self._consume(pending)
        elapsed = time.monotonic() - self.started_monotonic
        if (
            self.agent.checkin_required
            and self.checkin_at is None
            and (final or elapsed > self.agent.checkin_timeout_seconds)
        ):
            raise AgentOutputError("required adapter model check-in was not received")
        if self.checkin_at is not None and not final:
            latest = self.last_adapter_heartbeat_at or self.checkin_at
            age = (utc_now() - latest).total_seconds()
            if age > self.agent.heartbeat_timeout_seconds:
                raise AgentOutputError("adapter model heartbeat became stale")
        if final and self.agent.usage_reporting_required and self.usage is None:
            raise AgentOutputError("required adapter usage receipt was not received")


def _validate_json_complexity(value: object) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > 5_000 or depth > 20:
            raise AgentOutputError("agent result exceeds JSON complexity limits")
        if isinstance(item, dict):
            if len(item) > 100 or any(not isinstance(key, str) for key in item):
                raise AgentOutputError("agent result object exceeds shape limits")
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 1_000:
                raise AgentOutputError("agent result array exceeds shape limits")
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise AgentOutputError("agent result contains a non-finite number")

    visit(value, 0)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _effective_timeout(configured: int, deadline: float | None) -> int:
    if deadline is None:
        return configured
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RunnerError("run-wide quota-window deadline is exhausted")
    return min(configured, remaining)


def _bounded(value: str, maximum: int) -> str:
    if len(value) <= maximum:
        return value
    return "[TRUNCATED]\n" + value[-maximum:]


def execute(
    argv: list[str],
    *,
    cwd: Path | None,
    env: dict[str, str],
    stdin: str | None,
    timeout: int,
    max_output_bytes: int,
    on_tick: Callable[[], None] | None = None,
    tick_seconds: float = 0.5,
) -> CommandResult:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
    )
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()

    def drain(stream: Any, target: bytearray) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            target.extend(chunk)
            overflow = len(target) - max_output_bytes
            if overflow > 0:
                del target[:overflow]

    stdout_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout_buffer), daemon=True
    )
    stderr_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr_buffer), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    def write_stdin() -> None:
        if stdin is None or process.stdin is None:
            return
        try:
            process.stdin.write(stdin.encode())
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    stdin_thread = threading.Thread(target=write_stdin, daemon=True)
    stdin_thread.start()
    timed_out = False
    callback_error: Exception | None = None
    deadline = started + timeout
    try:
        while process.poll() is None:
            if on_tick is not None:
                try:
                    on_tick()
                except Exception as exc:
                    callback_error = exc
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                break
            try:
                process.wait(timeout=min(tick_seconds, remaining))
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    stdin_thread.join(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()
    stdout = stdout_buffer.decode("utf-8", errors="replace")
    stderr = stderr_buffer.decode("utf-8", errors="replace")
    if callback_error is not None:
        raise callback_error
    return CommandResult(
        argv=tuple(argv),
        exit_code=process.returncode if not timed_out else 124,
        duration_seconds=round(time.monotonic() - started, 3),
        stdout_tail=redact(_bounded(stdout, max_output_bytes), limit=max_output_bytes),
        stderr_tail=redact(_bounded(stderr, max_output_bytes), limit=max_output_bytes),
        timed_out=timed_out,
    )


@dataclass
class AgentRunner:
    sandbox: SandboxConfig
    agent: AgentConfig
    allow_synthetic_usage: bool = False

    def runtime_available(self) -> bool:
        return shutil.which(self.sandbox.runtime) is not None

    def _output(self, workspace: Path, stage: str) -> tuple[Path, Path, Path]:
        output_dir = workspace.parent / "agent-output" / stage
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return output_dir, output_dir / "result.json", output_dir / "telemetry.ndjson"

    def _container_argv(
        self,
        workspace: Path,
        output_dir: Path,
        run_id: str,
        stage: str,
        *,
        read_only_workspace: bool,
        command: tuple[str, ...],
        network: str | None = None,
        pass_agent_environment: bool = False,
    ) -> list[str]:
        workspace_mode = "ro" if read_only_workspace else "rw"
        name = f"leftovers-{run_id[:12]}-{stage}".replace("_", "-")[:63]
        lease_expires = (
            int(time.time()) + max(self.agent.timeout_seconds, self.sandbox.timeout_seconds) + 300
        )
        argv = [
            self.sandbox.runtime,
            "run",
            "--rm",
            "--name",
            name,
            "--init",
            "--label",
            "io.leftovers.managed=true",
            "--label",
            f"io.leftovers.job={run_id}",
            "--label",
            f"io.leftovers.stage={stage}",
            "--label",
            f"io.leftovers.lease_expires={lease_expires}",
            "--read-only",
            "--network",
            network or self.sandbox.network,
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--pids-limit",
            str(self.sandbox.pids_limit),
            "--cpus",
            str(self.sandbox.cpus),
            "--memory",
            self.sandbox.memory,
            "--memory-swap",
            self.sandbox.memory,
            "--ulimit",
            "nofile=4096:4096",
            "--ulimit",
            "core=0:0",
            "--shm-size",
            "64m",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,size={self.sandbox.tmpfs_size},mode=1777",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--workdir",
            "/workspace",
            "--mount",
            f"type=bind,src={workspace.resolve()},dst=/workspace,{workspace_mode}",
            "--mount",
            f"type=bind,src={output_dir.resolve()},dst=/out,rw",
            "--env",
            "CI=1",
            "--env",
            "HOME=/tmp",
            "--env",
            f"LEFTOVERS_STAGE={stage}",
            "--env",
            "LEFTOVERS_RESULT_PATH=/out/result.json",
            "--env",
            "LEFTOVERS_TELEMETRY_PATH=/out/telemetry.ndjson",
        ]
        git_dir = workspace / ".git"
        if not read_only_workspace and git_dir.exists():
            argv.extend(["--mount", f"type=bind,src={git_dir.resolve()},dst=/workspace/.git,ro"])
        if pass_agent_environment:
            for name_from_host in self.agent.pass_environment:
                if name_from_host in os.environ:
                    argv.extend(["--env", name_from_host])
        argv.extend(["--pull=never", "-i", self.sandbox.image, *command])
        return argv

    def _execute_container(
        self,
        argv: list[str],
        *,
        run_id: str,
        stage: str,
        stdin: str | None,
        timeout: int,
        on_tick: Callable[[], None] | None = None,
    ) -> CommandResult:
        try:
            result = execute(
                argv,
                cwd=None,
                env=self._runtime_env(),
                stdin=stdin,
                timeout=timeout,
                max_output_bytes=self.agent.max_output_bytes,
                on_tick=on_tick,
            )
        except BaseException as exc:
            if not self._remove_container(run_id, stage):
                raise RunnerError(
                    f"container cleanup could not be proven for {stage} after failure"
                ) from exc
            raise
        if not self._remove_container(run_id, stage):
            raise RunnerError(f"container cleanup could not be proven for {stage}")
        return result

    def _runtime_env(self) -> dict[str, str]:
        env = dict(os.environ)
        for secret_name in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"):
            env.pop(secret_name, None)
        return env

    @staticmethod
    def _host_readonly_fingerprint(workspace: Path) -> str:
        from .policy import (
            controller_git_env,
            controller_git_prefix,
            inspect_diff,
            unsafe_git_configuration,
        )

        dangerous_config = unsafe_git_configuration(workspace)
        if dangerous_config:
            raise RunnerError(
                "repository contains unsafe local Git configuration: " + ", ".join(dangerous_config)
            )

        head = subprocess.run(
            [*controller_git_prefix(), "rev-parse", "HEAD"],
            cwd=workspace,
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
            env=controller_git_env(workspace),
        ).stdout
        config_path = workspace / ".git/config"
        config_bytes = config_path.read_bytes() if config_path.is_file() else b""
        diff = inspect_diff(workspace, 10_000_000)
        value = head.encode() + config_bytes + diff.patch.encode() + str(diff.files).encode()
        return hashlib.sha256(value).hexdigest()

    def run_agent(
        self,
        stage: str,
        workspace: Path,
        prompt: RenderedPrompt,
        run_id: str,
        *,
        read_only_workspace: bool,
        deadline: float | None = None,
        telemetry_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> AgentResult:
        output_dir, result_path, telemetry_path = self._output(workspace, stage)
        for stale_path in (result_path, telemetry_path):
            if stale_path.exists():
                stale_path.unlink()
        monitor = _AdapterTelemetryMonitor(
            telemetry_path,
            self.agent,
            telemetry_callback,
            allow_synthetic_usage=self.allow_synthetic_usage,
        )

        def telemetry_tick() -> None:
            if telemetry_callback is not None:
                telemetry_callback(
                    {
                        "version": 1,
                        "type": "controller_heartbeat",
                        "observed_at": isoformat(utc_now()),
                    }
                )
            monitor.poll()

        if self.agent.backend == "container":
            if not self.runtime_available():
                raise RunnerError(f"{self.sandbox.runtime} is not installed or not on PATH")
            prompt_text = prompt.text.replace("{{LEFTOVERS_RESULT_PATH}}", "/out/result.json")
            argv = self._container_argv(
                workspace,
                output_dir,
                run_id,
                stage,
                read_only_workspace=read_only_workspace,
                command=self.agent.command,
                pass_agent_environment=True,
            )
            command_result = self._execute_container(
                argv,
                run_id=run_id,
                stage=stage,
                stdin=prompt_text,
                timeout=_effective_timeout(self.agent.timeout_seconds, deadline),
                on_tick=telemetry_tick,
            )
        else:
            config_path = workspace / ".git/config"
            local_config_before = config_path.read_bytes()
            before = self._host_readonly_fingerprint(workspace) if read_only_workspace else None
            prompt_text = prompt.text.replace("{{LEFTOVERS_RESULT_PATH}}", str(result_path))
            env_names = {"PATH", "LANG", "LC_ALL", "TMPDIR"}.union(self.agent.pass_environment)
            host_env = {name: value for name, value in os.environ.items() if name in env_names}
            for secret_name in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PAT"):
                host_env.pop(secret_name, None)
            host_env["LEFTOVERS_STAGE"] = stage
            host_env["LEFTOVERS_RESULT_PATH"] = str(result_path)
            host_env["LEFTOVERS_TELEMETRY_PATH"] = str(telemetry_path)
            isolated_home = workspace.parent / "host-agent-home"
            isolated_home.mkdir(mode=0o700, exist_ok=True)
            host_env["HOME"] = str(isolated_home)
            command_result = execute(
                list(self.agent.command),
                cwd=workspace,
                env=host_env,
                stdin=prompt_text,
                timeout=_effective_timeout(self.agent.timeout_seconds, deadline),
                max_output_bytes=self.agent.max_output_bytes,
                on_tick=telemetry_tick,
            )
            if not config_path.is_file() or config_path.read_bytes() != local_config_before:
                raise RunnerError(f"host agent modified Git control metadata during {stage}")
            from .policy import unsafe_git_configuration

            dangerous_config = unsafe_git_configuration(workspace)
            if dangerous_config:
                raise RunnerError(
                    "repository contains unsafe local Git configuration: "
                    + ", ".join(dangerous_config)
                )
            if before is not None and self._host_readonly_fingerprint(workspace) != before:
                raise RunnerError(f"host agent modified the workspace during read-only {stage}")
        if not command_result.passed:
            raise RunnerError(
                f"agent {stage} command failed with exit {command_result.exit_code}: "
                f"{command_result.stderr_tail[-1000:]}"
            )
        monitor.poll(final=True)
        try:
            result_stat = result_path.lstat()
        except FileNotFoundError as exc:
            raise AgentOutputError(f"agent {stage} did not write {result_path}") from exc
        if not stat.S_ISREG(result_stat.st_mode):
            raise AgentOutputError(f"agent {stage} result must be a regular file")
        if result_stat.st_nlink != 1:
            raise AgentOutputError(f"agent {stage} result may not be hard-linked")
        if not result_path.is_file():
            raise AgentOutputError(f"agent {stage} did not write {result_path}")
        if result_stat.st_size > self.agent.max_output_bytes:
            raise AgentOutputError(f"agent {stage} result exceeds configured output limit")
        try:
            descriptor = os.open(result_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                raw_result = os.read(descriptor, self.agent.max_output_bytes + 1)
            finally:
                os.close(descriptor)
            payload = json.loads(raw_result, parse_constant=_reject_json_constant)
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise AgentOutputError(f"agent {stage} result is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise AgentOutputError(f"agent {stage} result must be a JSON object")
        _validate_json_complexity(payload)
        status = _validate_agent_payload(stage, payload)
        return AgentResult(
            stage=stage,
            status=status,
            payload=payload,
            command=command_result,
            usage=monitor.usage,
        )

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
        if not self.runtime_available():
            raise RunnerError(f"{self.sandbox.runtime} is not installed or not on PATH")
        output_dir = workspace.parent / "command-output" / stage
        output_dir.mkdir(parents=True, exist_ok=True)
        results: list[CommandResult] = []
        for index, command in enumerate(commands):
            argv = self._container_argv(
                workspace,
                output_dir,
                run_id,
                f"{stage}-{index}",
                read_only_workspace=False,
                command=command,
                network=network,
                pass_agent_environment=False,
            )
            command_stage = f"{stage}-{index}"
            result = self._execute_container(
                argv,
                run_id=run_id,
                stage=command_stage,
                stdin=None,
                timeout=_effective_timeout(self.sandbox.timeout_seconds, deadline),
            )
            results.append(result)
            if not result.passed:
                break
        return results

    def _containers_for_job(self, run_id: str) -> list[str] | None:
        if not self.runtime_available():
            return None
        try:
            result = subprocess.run(
                [
                    self.sandbox.runtime,
                    "ps",
                    "-aq",
                    "--filter",
                    "label=io.leftovers.managed=true",
                    "--filter",
                    f"label=io.leftovers.job={run_id}",
                ],
                text=True,
                capture_output=True,
                timeout=20,
                env=self._runtime_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        identifiers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if any(
            not identifier.isascii() or not identifier.isalnum() or len(identifier) > 128
            for identifier in identifiers
        ):
            return None
        return identifiers

    def _container_labels(self, identifier: str) -> dict[str, str] | None:
        try:
            result = subprocess.run(
                [self.sandbox.runtime, "inspect", identifier],
                text=True,
                capture_output=True,
                timeout=20,
                env=self._runtime_env(),
            )
            if result.returncode != 0 or len(result.stdout) > 1_000_000:
                return None
            payload = json.loads(result.stdout)
            labels = payload[0]["Config"]["Labels"]
        except (
            OSError,
            subprocess.TimeoutExpired,
            json.JSONDecodeError,
            IndexError,
            KeyError,
            TypeError,
        ):
            return None
        if not isinstance(labels, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
        ):
            return None
        return labels

    def _remove_container(self, run_id: str, stage: str) -> bool:
        identifiers = self._containers_for_job(run_id)
        if identifiers is None:
            return False
        matching: list[str] = []
        for identifier in identifiers:
            labels = self._container_labels(identifier)
            if labels is None:
                return False
            if (
                labels.get("io.leftovers.managed") != "true"
                or labels.get("io.leftovers.job") != run_id
            ):
                return False
            if labels.get("io.leftovers.stage") == stage:
                matching.append(identifier)
        for identifier in matching:
            try:
                result = subprocess.run(
                    [self.sandbox.runtime, "rm", "-f", identifier],
                    text=True,
                    capture_output=True,
                    timeout=20,
                    env=self._runtime_env(),
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            if result.returncode != 0:
                return False
        remaining = self._containers_for_job(run_id)
        if remaining is None:
            return False
        for identifier in remaining:
            labels = self._container_labels(identifier)
            if labels is None or labels.get("io.leftovers.stage") == stage:
                return False
        return True

    def cleanup_job(self, run_id: str) -> bool:
        """Remove only containers whose immutable labels prove ownership by this run."""
        identifiers = self._containers_for_job(run_id)
        if identifiers is None:
            return False
        stages: set[str] = set()
        for identifier in identifiers:
            labels = self._container_labels(identifier)
            if (
                labels is None
                or labels.get("io.leftovers.managed") != "true"
                or labels.get("io.leftovers.job") != run_id
                or not labels.get("io.leftovers.stage")
            ):
                return False
            stages.add(labels["io.leftovers.stage"])
        return all(self._remove_container(run_id, stage) for stage in sorted(stages))

    def reap_expired_containers(self, now: int | None = None) -> list[str]:
        """Reap crash leftovers only after managed and expiry labels are verified."""
        if not self.runtime_available():
            return []
        try:
            result = subprocess.run(
                [
                    self.sandbox.runtime,
                    "ps",
                    "-aq",
                    "--filter",
                    "label=io.leftovers.managed=true",
                ],
                text=True,
                capture_output=True,
                timeout=20,
                env=self._runtime_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError("could not enumerate managed containers") from exc
        if result.returncode != 0:
            raise RunnerError("could not enumerate managed containers")
        identifiers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if any(
            not identifier.isascii() or not identifier.isalnum() or len(identifier) > 128
            for identifier in identifiers
        ):
            raise RunnerError("container runtime returned an invalid identifier")
        cutoff = now if now is not None else int(time.time())
        removed: list[str] = []
        for identifier in identifiers:
            labels = self._container_labels(identifier)
            if labels is None or labels.get("io.leftovers.managed") != "true":
                raise RunnerError("managed-container labels could not be verified")
            job = labels.get("io.leftovers.job", "")
            stage = labels.get("io.leftovers.stage", "")
            raw_expiry = labels.get("io.leftovers.lease_expires", "")
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", job) is None
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", stage) is None
                or not raw_expiry.isascii()
                or not raw_expiry.isdigit()
            ):
                raise RunnerError("managed-container ownership labels are incomplete")
            if int(raw_expiry) > cutoff:
                continue
            try:
                removal = subprocess.run(
                    [self.sandbox.runtime, "rm", "-f", identifier],
                    text=True,
                    capture_output=True,
                    timeout=20,
                    env=self._runtime_env(),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RunnerError(
                    f"could not remove expired managed container {identifier}"
                ) from exc
            if removal.returncode != 0:
                raise RunnerError(f"could not remove expired managed container {identifier}")
            removed.append(identifier)
        if removed:
            try:
                remaining = subprocess.run(
                    [
                        self.sandbox.runtime,
                        "ps",
                        "-aq",
                        "--filter",
                        "label=io.leftovers.managed=true",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=20,
                    env=self._runtime_env(),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RunnerError("could not verify expired-container cleanup") from exc
            remaining_ids = {line.strip() for line in remaining.stdout.splitlines() if line.strip()}
            if remaining.returncode != 0 or remaining_ids.intersection(removed):
                raise RunnerError("expired-container cleanup could not be proven")
        return removed

    def active_job_ids(self) -> set[str]:
        """Return run IDs for every remaining managed container, failing on ambiguity."""
        if not self.runtime_available():
            raise RunnerError("container runtime unavailable while checking active jobs")
        try:
            result = subprocess.run(
                [
                    self.sandbox.runtime,
                    "ps",
                    "-aq",
                    "--filter",
                    "label=io.leftovers.managed=true",
                ],
                text=True,
                capture_output=True,
                timeout=20,
                env=self._runtime_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError("could not enumerate active managed containers") from exc
        if result.returncode != 0:
            raise RunnerError("could not enumerate active managed containers")
        jobs: set[str] = set()
        for identifier in (line.strip() for line in result.stdout.splitlines() if line.strip()):
            if not identifier.isascii() or not identifier.isalnum() or len(identifier) > 128:
                raise RunnerError("container runtime returned an invalid identifier")
            labels = self._container_labels(identifier)
            if labels is None or labels.get("io.leftovers.managed") != "true":
                raise RunnerError("active managed-container labels could not be verified")
            job = labels.get("io.leftovers.job", "")
            stage = labels.get("io.leftovers.stage", "")
            expiry = labels.get("io.leftovers.lease_expires", "")
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", job) is None
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", stage) is None
                or not expiry.isascii()
                or not expiry.isdigit()
            ):
                raise RunnerError("active managed-container ownership labels are incomplete")
            jobs.add(job)
        return jobs


def _validate_agent_payload(stage: str, payload: dict[str, Any]) -> str:
    def nonempty_text(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def string_list(value: object, *, allow_empty: bool) -> bool:
        return (
            isinstance(value, list)
            and (allow_empty or bool(value))
            and all(nonempty_text(item) for item in value)
        )

    if stage == "planning":
        status = payload.get("status")
        if status not in {"planned", "blocked", "failed"}:
            raise AgentOutputError("planning result status must be planned, blocked, or failed")
        if status == "planned":
            for key in ("acceptance_criteria", "steps", "stop_conditions"):
                if not string_list(payload.get(key), allow_empty=False):
                    raise AgentOutputError(f"planning result requires non-empty {key} evidence")
            if not string_list(payload.get("risks"), allow_empty=True):
                raise AgentOutputError("planning risks must be a string array")
            tests = payload.get("tests")
            if (
                not isinstance(tests, list)
                or not tests
                or any(not string_list(command, allow_empty=False) for command in tests)
            ):
                raise AgentOutputError("planning result requires non-empty test argv arrays")
            reproduction = payload.get("reproduction")
            if (
                not isinstance(reproduction, dict)
                or not string_list(reproduction.get("argv"), allow_empty=False)
                or not nonempty_text(reproduction.get("observed"))
            ):
                raise AgentOutputError("planned work requires concrete reproduction evidence")
            root_cause = payload.get("root_cause")
            if (
                not isinstance(root_cause, list)
                or not root_cause
                or any(
                    not isinstance(finding, dict)
                    or not nonempty_text(finding.get("path"))
                    or not nonempty_text(finding.get("evidence"))
                    for finding in root_cause
                )
            ):
                raise AgentOutputError("planned work requires concrete root-cause evidence")
            estimate = payload.get("estimated_remaining_tokens")
            if type(estimate) is not int or estimate < 0:
                raise AgentOutputError("planning result has an invalid token estimate")
        elif not nonempty_text(payload.get("reason")):
            raise AgentOutputError("blocked or failed planning results require a reason")
        return status
    if stage == "implementation":
        status = payload.get("status")
        if status not in {"implemented", "blocked", "failed"}:
            raise AgentOutputError("implementation status must be implemented, blocked, or failed")
        if status == "implemented":
            if not nonempty_text(payload.get("summary")):
                raise AgentOutputError("implementation result requires a summary")
            if not string_list(payload.get("changed_files"), allow_empty=False):
                raise AgentOutputError("implementation result requires changed file claims")
            commands = payload.get("commands")
            if not isinstance(commands, list) or any(
                not isinstance(command, dict)
                or not string_list(command.get("argv"), allow_empty=False)
                or type(command.get("exit_code")) is not int
                or not nonempty_text(command.get("summary"))
                for command in commands
            ):
                raise AgentOutputError("implementation command evidence has an invalid shape")
            acceptance = payload.get("acceptance_criteria")
            if (
                not isinstance(acceptance, list)
                or not acceptance
                or any(
                    not isinstance(item, dict)
                    or not nonempty_text(item.get("criterion"))
                    or not nonempty_text(item.get("evidence"))
                    for item in acceptance
                )
            ):
                raise AgentOutputError("implementation acceptance evidence has an invalid shape")
            if not string_list(payload.get("remaining_risks"), allow_empty=True):
                raise AgentOutputError("implementation risks must be a string array")
        elif not nonempty_text(payload.get("reason")):
            raise AgentOutputError("blocked or failed implementation results require a reason")
        return status
    if stage == "review":
        verdict = payload.get("verdict")
        if verdict not in {"approve", "revise", "abandon"}:
            raise AgentOutputError("review verdict must be approve, revise, or abandon")
        findings = payload.get("findings")
        missing = payload.get("missing_verification")
        if not isinstance(findings, list) or not string_list(missing, allow_empty=True):
            raise AgentOutputError(
                "review result requires findings and missing_verification arrays"
            )
        if any(
            not isinstance(finding, dict)
            or finding.get("severity") not in {"blocker", "major", "minor"}
            or not nonempty_text(finding.get("summary"))
            or not nonempty_text(finding.get("evidence"))
            or (
                "path" in finding
                and finding.get("path") is not None
                and not nonempty_text(finding.get("path"))
            )
            for finding in findings
        ):
            raise AgentOutputError("review findings have an invalid evidence shape")
        if type(payload.get("pr_claims_supported")) is not bool:
            raise AgentOutputError("review result requires a boolean pr_claims_supported")
        if verdict == "approve" and (
            findings or missing or payload["pr_claims_supported"] is not True
        ):
            raise AgentOutputError("an approving review must have no unresolved findings")
        if verdict != "approve" and not findings and not missing:
            raise AgentOutputError("a non-approving review requires actionable evidence")
        return verdict
    if stage == "pr-writer":
        title = payload.get("title")
        body = payload.get("body")
        if not isinstance(title, str) or not title.strip() or len(title) > 240:
            raise AgentOutputError(
                "PR writer title must be a non-empty string of at most 240 characters"
            )
        if not isinstance(body, str) or not body.strip() or len(body) > 60_000:
            raise AgentOutputError("PR writer result must contain string title and body")
        return "written"
    raise AgentOutputError(f"unsupported agent stage: {stage}")
