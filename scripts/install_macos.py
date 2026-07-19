#!/usr/bin/env python3
"""Install a self-contained Leftovers preview bundle under the repository state directory."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import zipapp
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANAGED_BASE = ROOT / ".leftovers"
DEFAULT_INSTALL_ROOT = ROOT / ".leftovers" / "install"
MINIMUM_CODEX_VERSION = (0, 144, 5)
COMMAND_PATH = (
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:"
    "/Applications/Docker.app/Contents/Resources/bin:/opt/podman/bin"
)
CODEX_CANDIDATES = (
    Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
    Path("/Applications/Codex.app/Contents/Resources/codex"),
)
STAGE_SCHEMAS = (
    "codex-planning.schema.json",
    "codex-implementation.schema.json",
    "codex-review.schema.json",
)
CLEANUP_PENDING_FILENAME = "cleanup-pending.json"
LAUNCH_LABEL = re.compile(r"dev\.leftovers\.once\.(\d+)\.\d{14}\.\d+")
MAX_MANIFEST_BYTES = 1_000_000
MAX_LAUNCH_PLIST_BYTES = 1_000_000
MAX_LAUNCHCTL_OUTPUT_BYTES = 65_536


class InstallError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install the headless, dry-run Leftovers macOS bundle"
    )
    parser.add_argument("--install-root", type=Path, default=DEFAULT_INSTALL_ROOT)
    parser.add_argument("--runtime", choices=("auto", "docker", "podman"), default="auto")
    parser.add_argument("--force-config", action="store_true")
    parser.add_argument("--skip-rehearsal", action="store_true")
    parser.add_argument("--scout", action="store_true")
    parser.add_argument("--verify-oci", action="store_true")
    parser.add_argument("--launch-now", action="store_true")
    return parser


def _lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _reject_symlink_components(path: Path, *, boundary: Path) -> None:
    """Reject existing symlinks from ``boundary`` through ``path`` without following them."""

    path = _lexical_path(path)
    boundary = _lexical_path(boundary)
    try:
        relative = path.relative_to(boundary)
    except ValueError as exc:
        raise InstallError(f"managed path escapes its repository boundary: {path}") from exc
    current = boundary
    components = (Path("."), *relative.parts)
    for component in components:
        if component != Path("."):
            current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode):
            raise InstallError(f"managed path component may not be a symlink: {current}")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise InstallError(f"managed path component is not a directory: {current}")


def _scoped_install_root(path: Path) -> Path:
    candidate = _lexical_path(path)
    base = _lexical_path(MANAGED_BASE)
    if candidate == base:
        raise InstallError("install root must be a child of the repository .leftovers directory")
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise InstallError(
            "install root must stay beneath this repository's .leftovers directory"
        ) from exc
    _reject_symlink_components(candidate, boundary=ROOT)
    return candidate


def _reject_tcc_protected_launch_root(path: Path, *, home: Path | None = None) -> None:
    """Fail before launchd hits macOS protected-folder policy.

    A user-launched Terminal process may have access to Desktop, Documents, or
    Downloads while an independently spawned LaunchAgent does not.  Asking for
    Full Disk Access would expand authority far beyond this preview, so keep the
    package in-place and require the bounded foreground ``--scout`` path there.
    """

    candidate = _lexical_path(path)
    user_home = _lexical_path(home or Path.home())
    for name in ("Desktop", "Documents", "Downloads"):
        protected = user_home / name
        if candidate == protected or protected in candidate.parents:
            raise InstallError(
                "--launch-now cannot safely run from a macOS protected user folder; "
                "use --scout from Terminal and do not grant Full Disk Access"
            )


def _private_directory(path: Path) -> Path:
    path = _lexical_path(path)
    if path == _lexical_path(ROOT) or _lexical_path(ROOT) in path.parents:
        _reject_symlink_components(path, boundary=ROOT)
    if path.is_symlink():
        raise InstallError(f"managed directory may not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise InstallError(f"managed directory is not owner-controlled: {path}")
    os.chmod(path, 0o700)
    return path.resolve()


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    parent = _private_directory(path.parent)
    target = parent / path.name
    if target.is_symlink():
        raise InstallError(f"managed file may not be a symlink: {target}")
    if target.exists():
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise InstallError(f"managed file is not owner-controlled: {target}")
    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise InstallError(f"temporary install path already exists: {temporary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise InstallError("install write made no progress")
            pending = pending[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)


def _version(binary: Path) -> tuple[int, int, int] | None:
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"codex-cli\s+(\d+)\.(\d+)\.(\d+)", completed.stdout)
    if completed.returncode != 0 or match is None:
        return None
    return tuple(int(value) for value in match.groups())


def _find_codex() -> tuple[Path, tuple[int, int, int]]:
    configured = os.environ.get("LEFTOVERS_CODEX_BIN")
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend(CODEX_CANDIDATES)
    discovered = shutil.which("codex")
    if discovered:
        candidates.append(Path(discovered))
    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in seen or not os.access(resolved, os.X_OK):
            continue
        seen.add(resolved)
        version = _version(resolved)
        if version is not None and version >= MINIMUM_CODEX_VERSION:
            return resolved, version
    required = ".".join(str(value) for value in MINIMUM_CODEX_VERSION)
    raise InstallError(
        f"Codex CLI {required} or newer is required; install/update Codex before continuing"
    )


def _choose_runtime(requested: str) -> tuple[str, Path | None]:
    if requested != "auto":
        discovered = shutil.which(requested, path=COMMAND_PATH)
        return requested, Path(discovered).resolve() if discovered else None
    for name in ("docker", "podman"):
        discovered = shutil.which(name, path=COMMAND_PATH)
        if discovered:
            return name, Path(discovered).resolve()
    return "docker", None


def _python_supported() -> None:
    if sys.hexversion < 0x030B0000:
        raise InstallError("Python 3.11 or newer is required")
    if sys.platform != "darwin":
        raise InstallError("this installer is for macOS; use the OCI/systemd package elsewhere")
    if getattr(os, "geteuid", lambda: 1)() == 0:
        raise InstallError("Leftovers may not be installed or run as root")
    executable = Path(sys.executable)
    try:
        executable = executable.resolve(strict=True)
    except OSError as exc:
        raise InstallError("the active Python interpreter is not a persistent file") from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise InstallError("the active Python interpreter is not executable")
    temporary_roots = (
        Path("/tmp"),
        Path("/private/tmp"),
        Path(os.environ.get("TMPDIR", "/tmp")),
    )
    if any(root == executable or root in executable.parents for root in temporary_roots):
        raise InstallError("the installer may not embed a temporary Python interpreter")
    if sys.prefix != sys.base_prefix and os.environ.get("LEFTOVERS_ALLOW_VENV") != "1":
        raise InstallError(
            "run the installer with a persistent system, Homebrew, framework, or pyenv Python; "
            "temporary virtual environments are rejected"
        )
    if shutil.which("git", path=COMMAND_PATH) is None:
        raise InstallError("required macOS command is missing: git")


def _check_codex_login(codex: Path) -> None:
    try:
        completed = subprocess.run(
            [str(codex), "login", "status"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("could not verify the saved Codex CLI login") from exc
    if completed.returncode != 0:
        raise InstallError("a saved Codex CLI login is required")


def _check_github_read_access(environment: dict[str, str]) -> None:
    gh = shutil.which("gh", path=environment["PATH"])
    if gh is None:
        raise InstallError("GitHub CLI is required for --scout and --launch-now")
    try:
        completed = subprocess.run(
            [gh, "auth", "token"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("could not inspect the saved GitHub CLI authentication") from exc
    token = completed.stdout.strip()
    if (
        completed.returncode != 0
        or not 20 <= len(token) <= 512
        or re.fullmatch(rb"[A-Za-z0-9_.-]+", token) is None
    ):
        raise InstallError("a valid saved GitHub CLI token is required for read-only scouting")


def _build_zipapp(install_root: Path) -> Path:
    destination = install_root / "bin" / "leftovers.pyz"
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    _private_directory(destination.parent)
    if temporary.exists() or temporary.is_symlink():
        raise InstallError(f"temporary zipapp path already exists: {temporary}")

    def include(path: Path) -> bool:
        return "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}

    try:
        zipapp.create_archive(
            ROOT / "src",
            target=temporary,
            interpreter="/usr/bin/env python3",
            filter=include,
            compressed=True,
        )
        os.chmod(temporary, 0o700)
        os.replace(temporary, destination)
    except (OSError, zipapp.ZipAppError) as exc:
        raise InstallError(f"could not build the Leftovers zipapp: {exc}") from exc
    return destination


def _copy_runtime_files(install_root: Path) -> tuple[Path, Path, Path]:
    adapter = install_root / "lib" / "codex_adapter.py"
    rehearsal = install_root / "lib" / "rehearsal_agent.py"
    job = install_root / "lib" / "macos_job.py"
    for source, destination in (
        (ROOT / "scripts" / "codex_adapter.py", adapter),
        (ROOT / "scripts" / "rehearsal_agent.py", rehearsal),
        (ROOT / "scripts" / "macos_job.py", job),
    ):
        _atomic_write(destination, source.read_bytes(), 0o500)
    for schema_name in STAGE_SCHEMAS:
        source = ROOT / "schemas" / schema_name
        _atomic_write(install_root / "schemas" / schema_name, source.read_bytes(), 0o400)
    return adapter, rehearsal, job


def _toml_value(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def _render_config(
    install_root: Path,
    *,
    runtime: str,
    adapter: Path,
    force: bool,
) -> Path:
    destination = install_root / "config.toml"
    if destination.exists() and not force:
        if destination.is_symlink():
            raise InstallError("generated configuration may not be a symlink")
        info = destination.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= 1_000_000
        ):
            raise InstallError("generated configuration is not a private owner-controlled file")
        return destination
    template = (ROOT / "config" / "macos-preview.template.toml").read_text(encoding="utf-8")
    replacements = {
        "__STATE_DIR__": _toml_value(install_root / "state"),
        "__TEMP_ROOT__": _toml_value(install_root / "workspaces"),
        "__RUNTIME__": runtime,
        "__PYTHON__": _toml_value(Path(sys.executable).resolve()),
        "__ADAPTER__": _toml_value(adapter),
    }
    rendered = template
    for marker, value in replacements.items():
        rendered = rendered.replace(marker, value)
    if "__" in rendered:
        raise InstallError("unresolved marker remains in the generated configuration")
    _atomic_write(destination, rendered.encode(), 0o600)
    return destination


def _install_wrapper(
    install_root: Path,
    *,
    archive: Path,
    config: Path,
    rehearsal: Path,
) -> Path:
    wrapper = install_root / "bin" / "leftovers"
    lines = (
        "#!/bin/sh",
        "set -eu",
        "umask 077",
        f"export LEFTOVERS_REHEARSAL_AGENT={shlex.quote(str(rehearsal))}",
        f"export LEFTOVERS_LAUNCHER={shlex.quote(str(wrapper))}",
        (
            f"exec {shlex.quote(str(Path(sys.executable).resolve()))} "
            f'{shlex.quote(str(archive))} --config {shlex.quote(str(config))} "$@"'
        ),
        "",
    )
    _atomic_write(wrapper, "\n".join(lines).encode(), 0o700)
    return wrapper


def _run_checked(command: list[str], environment: dict[str, str], timeout: int) -> str:
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=environment,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError(f"install verification could not run {command[0]}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1:] or ["no diagnostic"]
        raise InstallError(f"install verification failed: {detail[0][:300]}")
    return completed.stdout


def _image_id(runtime: Path, image: str, environment: dict[str, str]) -> str:
    raw = _run_checked(
        [str(runtime), "image", "inspect", image],
        environment,
        30,
    )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InstallError("OCI runtime returned malformed image metadata") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise InstallError("OCI runtime returned an unexpected image metadata shape")
    identity = payload[0].get("Id", payload[0].get("ID"))
    if not isinstance(identity, str):
        raise InstallError("OCI runtime omitted the worker image identity")
    normalized = identity.casefold()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", normalized) is None:
        raise InstallError("OCI runtime returned an invalid worker image identity")
    return normalized


def _pin_config_image(config: Path, image_id: str) -> None:
    text = config.read_text(encoding="utf-8")
    replacement = f'image = "{image_id}"'
    pattern = re.compile(
        r'^image = "(?:leftovers-sandbox:local-preview|sha256:[0-9a-f]{64})"$',
        re.MULTILINE,
    )
    rendered, count = pattern.subn(replacement, text)
    if count != 1:
        raise InstallError("generated config worker image cannot be pinned safely")
    _atomic_write(config, rendered.encode(), 0o600)


def _verify_oci(
    runtime: Path,
    install_root: Path,
    config: Path,
    environment: dict[str, str],
) -> tuple[Path, str]:
    _run_checked(
        [
            str(runtime),
            "build",
            "--file",
            str(ROOT / "sandbox" / "Dockerfile"),
            "--tag",
            "leftovers-sandbox:local-preview",
            str(ROOT),
        ],
        environment,
        900,
    )
    _run_checked(
        [
            str(runtime),
            "build",
            "--build-arg",
            "BASE_IMAGE=leftovers-sandbox:local-preview",
            "--file",
            str(ROOT / "sandbox" / "Rehearsal.Dockerfile"),
            "--tag",
            "leftovers-rehearsal:local",
            str(ROOT),
        ],
        environment,
        900,
    )
    report = install_root / "reports" / "oci-rehearsal.json"
    wrapper = install_root / "bin" / "leftovers"
    _run_checked(
        [
            str(wrapper),
            "training-run",
            "--mode",
            runtime.name,
            "--profile",
            "auto",
            "--report",
            str(report),
        ],
        environment,
        300,
    )
    image_id = _image_id(runtime, "leftovers-sandbox:local-preview", environment)
    _pin_config_image(config, image_id)
    return report, image_id


def _prepare_launch_once(
    install_root: Path,
    *,
    job: Path,
    codex: Path,
    rehearsal: Path,
    environment: dict[str, str],
) -> tuple[str, Path, str]:
    launchctl = shutil.which("launchctl")
    if launchctl is None:
        raise InstallError("launchctl is required for --launch-now")
    timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    label = f"dev.leftovers.once.{os.getuid()}.{timestamp}.{os.getpid()}"
    plist_path = install_root / "launchd" / f"{label}.plist"
    logs = _private_directory(install_root / "logs")
    stdout_log = logs / "job.stdout.log"
    stderr_log = logs / "job.stderr.log"
    _prepare_launch_log(stdout_log)
    _prepare_launch_log(stderr_log)
    payload: dict[str, Any] = {
        "Label": label,
        "ProgramArguments": [
            "/usr/bin/env",
            "-i",
            f"HOME={environment['HOME']}",
            f"PATH={environment['PATH']}",
            f"LEFTOVERS_REHEARSAL_AGENT={rehearsal}",
            "PYTHONDONTWRITEBYTECODE=1",
            str(Path(sys.executable).resolve()),
            str(job),
            "--install-root",
            str(install_root),
            "--launch-label",
            label,
        ],
        "WorkingDirectory": str(install_root),
        "RunAtLoad": True,
        "KeepAlive": False,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
        "ThrottleInterval": 60,
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
    }
    _atomic_write(plist_path, plistlib.dumps(payload, sort_keys=True), 0o600)
    return label, plist_path, launchctl


def _bootstrap_launch(
    launchctl: str,
    plist_path: Path,
    environment: dict[str, str],
) -> None:
    domain = f"gui/{os.getuid()}"
    _run_checked([launchctl, "bootstrap", domain, str(plist_path)], environment, 30)


def _launch_once(
    install_root: Path,
    *,
    job: Path,
    codex: Path,
    rehearsal: Path,
    environment: dict[str, str],
) -> tuple[str, Path]:
    label, plist_path, launchctl = _prepare_launch_once(
        install_root,
        job=job,
        codex=codex,
        rehearsal=rehearsal,
        environment=environment,
    )
    try:
        _bootstrap_launch(launchctl, plist_path, environment)
    except InstallError as exc:
        binding = {"launch_label": label, "launch_plist": str(plist_path)}
        try:
            _cleanup_launch_binding(install_root, binding, environment)
        except InstallError as cleanup_exc:
            raise InstallError(
                "launchd bootstrap failed and exact launch cleanup could not be proven"
            ) from cleanup_exc
        raise exc
    return label, plist_path


def _write_manifest(install_root: Path, manifest: dict[str, Any]) -> None:
    _atomic_write(
        install_root / "manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
        0o600,
    )


def _read_existing_manifest(install_root: Path) -> dict[str, Any] | None:
    """Read an existing install manifest through a bounded, no-follow descriptor."""

    path = install_root / "manifest.json"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallError("existing install manifest is not a safe regular file") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= MAX_MANIFEST_BYTES
        ):
            raise InstallError("existing install manifest is not a private owner-controlled file")
        payload = bytearray()
        while len(payload) <= MAX_MANIFEST_BYTES:
            chunk = os.read(descriptor, min(65_536, MAX_MANIFEST_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_MANIFEST_BYTES:
            raise InstallError("existing install manifest exceeds its byte limit")
    finally:
        os.close(descriptor)
    try:
        manifest = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("existing install manifest contains invalid JSON") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 1
        or manifest.get("install_root") != str(install_root)
        or manifest.get("publication") != "disabled"
        or manifest.get("model") != "gpt-5.6-terra"
    ):
        raise InstallError("existing install manifest does not bind this exact install root")
    return manifest


def _launch_binding(install_root: Path, manifest: dict[str, Any]) -> tuple[str, Path] | None:
    label = manifest.get("launch_label")
    recorded_plist = manifest.get("launch_plist")
    if label is None and recorded_plist is None:
        return None
    if not isinstance(label, str) or not isinstance(recorded_plist, str):
        raise InstallError("install manifest contains an incomplete launchd binding")
    match = LAUNCH_LABEL.fullmatch(label)
    if match is None or int(match.group(1)) != os.getuid():
        raise InstallError("install manifest launch label is outside this user identity")
    expected = install_root / "launchd" / f"{label}.plist"
    if recorded_plist != str(expected):
        raise InstallError("install manifest launch plist is outside its exact managed binding")
    _reject_symlink_components(expected, boundary=install_root)
    return label, expected


def _validate_launch_plist(path: Path, label: str) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InstallError("tracked launch plist is not a safe regular file") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= MAX_LAUNCH_PLIST_BYTES
        ):
            raise InstallError("tracked launch plist is not a private owner-controlled file")
        payload = bytearray()
        while len(payload) <= MAX_LAUNCH_PLIST_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_LAUNCH_PLIST_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_LAUNCH_PLIST_BYTES:
            raise InstallError("tracked launch plist exceeds its byte limit")
    finally:
        os.close(descriptor)
    try:
        value = plistlib.loads(payload)
    except (ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise InstallError("tracked launch plist is invalid") from exc
    if not isinstance(value, dict) or value.get("Label") != label:
        raise InstallError("tracked launch plist does not match its manifest label")
    return True


def _launchctl_result(
    command: list[str], environment: dict[str, str], timeout: int
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=environment,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("launchctl cleanup could not be proven") from exc


def _launchctl_reports_missing(result: subprocess.CompletedProcess[bytes]) -> bool:
    if result.returncode == 0:
        return False
    stdout = result.stdout if isinstance(result.stdout, bytes) else b""
    stderr = result.stderr if isinstance(result.stderr, bytes) else b""
    if len(stdout) > MAX_LAUNCHCTL_OUTPUT_BYTES or len(stderr) > MAX_LAUNCHCTL_OUTPUT_BYTES:
        raise InstallError("launchctl cleanup output exceeded its byte limit")
    diagnostic = (stdout + b"\n" + stderr).decode("utf-8", errors="replace").lower()
    return any(
        marker in diagnostic
        for marker in ("could not find service", "service not found", "no such process")
    )


def _cleanup_launch_binding(
    install_root: Path,
    manifest: dict[str, Any],
    environment: dict[str, str],
) -> bool:
    """Unload and unlink only the exact launch binding recorded in ``manifest``."""

    binding = _launch_binding(install_root, manifest)
    if binding is None:
        return False
    label, plist_path = binding
    plist_exists = _validate_launch_plist(plist_path, label)
    launchctl = shutil.which("launchctl", path=environment["PATH"])
    if launchctl is None:
        raise InstallError("launchctl is required to clean a tracked launchd binding")
    service = f"gui/{os.getuid()}/{label}"
    inspected = _launchctl_result(
        [launchctl, "print", service],
        environment,
        15,
    )
    inspected_missing = _launchctl_reports_missing(inspected)
    removed = _launchctl_result(
        [launchctl, "bootout", service],
        environment,
        30,
    )
    removed_missing = _launchctl_reports_missing(removed)
    if removed.returncode != 0 and not (inspected_missing and removed_missing):
        raise InstallError("the tracked launchd service could not be unloaded")
    verified = _launchctl_result(
        [launchctl, "print", service],
        environment,
        15,
    )
    if verified.returncode == 0:
        raise InstallError("the tracked launchd service remained loaded after bootout")
    if not _launchctl_reports_missing(verified):
        raise InstallError("launchctl did not prove the tracked service is absent")
    unloaded = inspected.returncode == 0 or removed.returncode == 0
    if plist_exists:
        try:
            plist_path.unlink()
        except OSError as exc:
            raise InstallError("the exact tracked launch plist could not be removed") from exc
    return unloaded


def _assert_package_lock(install_root: Path, descriptor: int) -> None:
    try:
        descriptor_info = os.fstat(descriptor)
        path_info = (install_root / "job.lock").lstat()
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError) as exc:
        raise InstallError("package mutation lock is not held by this installer") from exc
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or descriptor_info.st_uid != os.getuid()
        or descriptor_info.st_nlink != 1
        or (descriptor_info.st_dev, descriptor_info.st_ino) != (path_info.st_dev, path_info.st_ino)
    ):
        raise InstallError("package mutation lock does not bind the exact install root")


def _cleanup_previous_launch(
    install_root: Path,
    environment: dict[str, str],
    *,
    lock_descriptor: int,
) -> bool:
    _assert_package_lock(install_root, lock_descriptor)
    manifest = _read_existing_manifest(install_root)
    if manifest is None:
        return False
    return _cleanup_launch_binding(install_root, manifest, environment)


def _record_launch_cleanup_pending(
    install_root: Path,
    *,
    label: str,
    plist_path: Path,
    reason: str,
) -> None:
    evidence = {
        "version": 1,
        "state": "cleanup_pending",
        "pid": os.getpid(),
        "pgid": os.getpgrp(),
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "reason": reason[:500],
        "source": "launchd-transaction",
        "launch_label": label,
        "launch_plist": str(plist_path),
    }
    _atomic_write(
        install_root / CLEANUP_PENDING_FILENAME,
        (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode(),
        0o600,
    )


def _cleanup_submitted_launch_or_mark_pending(
    install_root: Path,
    *,
    label: str,
    plist_path: Path,
    environment: dict[str, str],
    reason: str,
) -> None:
    binding = {"launch_label": label, "launch_plist": str(plist_path)}
    try:
        _cleanup_launch_binding(install_root, binding, environment)
    except InstallError as cleanup_exc:
        try:
            _record_launch_cleanup_pending(
                install_root,
                label=label,
                plist_path=plist_path,
                reason=f"{reason}; {cleanup_exc}",
            )
        except InstallError as marker_exc:
            raise InstallError(
                "launch cleanup could not be proven and cleanup-pending evidence "
                "could not be written"
            ) from marker_exc
        raise InstallError(
            "launch cleanup could not be proven; cleanup-pending evidence was retained"
        ) from cleanup_exc


def _bind_launched_job(
    install_root: Path,
    *,
    job: Path,
    codex: Path,
    rehearsal: Path,
    environment: dict[str, str],
    manifest: dict[str, Any],
    lock_descriptor: int,
) -> tuple[str, Path]:
    """Bootstrap and persist one launch while the caller holds ``job.lock``."""

    _assert_package_lock(install_root, lock_descriptor)
    label, plist_path, launchctl = _prepare_launch_once(
        install_root,
        job=job,
        codex=codex,
        rehearsal=rehearsal,
        environment=environment,
    )
    manifest["launch_label"] = label
    manifest["launch_plist"] = str(plist_path)
    manifest["launch_behavior"] = "pending-bootstrap"
    try:
        _write_manifest(install_root, manifest)
    except InstallError as exc:
        try:
            if _validate_launch_plist(plist_path, label):
                plist_path.unlink()
        except (InstallError, OSError) as cleanup_exc:
            raise InstallError(
                "pending launch manifest write failed and its plist could not be removed"
            ) from cleanup_exc
        raise exc
    try:
        _bootstrap_launch(launchctl, plist_path, environment)
    except InstallError as exc:
        _cleanup_submitted_launch_or_mark_pending(
            install_root,
            label=label,
            plist_path=plist_path,
            environment=environment,
            reason="launchd bootstrap failed",
        )
        raise exc
    manifest["launch_behavior"] = "immediate-one-shot-fire-and-forget"
    try:
        _write_manifest(install_root, manifest)
    except InstallError as exc:
        _cleanup_submitted_launch_or_mark_pending(
            install_root,
            label=label,
            plist_path=plist_path,
            environment=environment,
            reason="final launch manifest write failed",
        )
        raise exc
    return label, plist_path


def _prepare_launch_log(path: Path) -> None:
    """Create a fresh owner-only launchd log without following a prior link.

    The JSON job summary and hash-chained run journal are the durable evidence.
    Reusing append-only launchd paths without truncation would permit an
    otherwise healthy sequence of one-shot jobs to consume host disk forever.
    """

    parent = _private_directory(path.parent)
    target = parent / path.name
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as exc:
        raise InstallError(f"launch log is not a safe regular file: {target}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise InstallError(f"launch log is not owner-controlled: {target}")
        # Each one-shot starts with an empty log.  The job itself emits only a
        # bounded JSON summary; child command output is captured separately.
        os.ftruncate(descriptor, 0)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _acquire_package_lock(install_root: Path) -> int:
    path = install_root / "job.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        os.close(descriptor)
        raise InstallError("package lock is not a single-link owner-controlled file")
    os.fchmod(descriptor, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise InstallError("a detached Leftovers job is active; reinstall later") from None
    cleanup_evidence = install_root / CLEANUP_PENDING_FILENAME
    if cleanup_evidence.exists() or cleanup_evidence.is_symlink():
        os.close(descriptor)
        raise InstallError(
            "a prior preview cleanup remains unresolved; refusing to reinstall over its evidence"
        )
    return descriptor


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _python_supported()
    install_root_path = _scoped_install_root(args.install_root)
    if args.launch_now:
        _reject_tcc_protected_launch_root(install_root_path)
    codex, codex_version = _find_codex()
    _check_codex_login(codex)
    runtime_name, runtime_path = _choose_runtime(args.runtime)
    base_environment = {
        "PATH": COMMAND_PATH,
        "HOME": str(Path.home()),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if args.scout or args.launch_now:
        _check_github_read_access(base_environment)
    if not args.skip_rehearsal and shutil.which("sandbox-exec", path=COMMAND_PATH) is None:
        raise InstallError("sandbox-exec is required unless --skip-rehearsal is selected")

    install_root = _private_directory(install_root_path)
    _private_directory(install_root.parent)
    package_lock = _acquire_package_lock(install_root)
    _cleanup_previous_launch(
        install_root,
        base_environment,
        lock_descriptor=package_lock,
    )
    for name in ("bin", "lib", "schemas", "state", "workspaces", "reports", "logs"):
        _private_directory(install_root / name)
    archive = _build_zipapp(install_root)
    adapter, rehearsal, job = _copy_runtime_files(install_root)
    config = _render_config(
        install_root,
        runtime=runtime_name,
        adapter=adapter,
        force=args.force_config,
    )
    wrapper = _install_wrapper(
        install_root,
        archive=archive,
        config=config,
        rehearsal=rehearsal,
    )
    environment = {
        **base_environment,
        "LEFTOVERS_REHEARSAL_AGENT": str(rehearsal),
        "TMPDIR": str(_private_directory(install_root / "tmp")),
    }
    _run_checked([str(wrapper), "validate"], environment, 30)
    rehearsal_report: Path | None = None
    if not args.skip_rehearsal:
        rehearsal_report = install_root / "reports" / "seatbelt-rehearsal.json"
        _run_checked(
            [
                str(wrapper),
                "training-run",
                "--mode",
                "process",
                "--profile",
                "seatbelt",
                "--report",
                str(rehearsal_report),
            ],
            environment,
            300,
        )
    oci_report: Path | None = None
    sandbox_image_id: str | None = None
    if args.verify_oci:
        if runtime_path is None:
            raise InstallError("--verify-oci requires Docker or Podman on PATH")
        oci_report, sandbox_image_id = _verify_oci(
            runtime_path,
            install_root,
            config,
            environment,
        )
        _run_checked([str(wrapper), "validate"], environment, 30)

    installed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if oci_report:
        assurance = "oci-rehearsal-verified-scout-only"
    elif rehearsal_report:
        assurance = "seatbelt-supplemental-scout-only"
    else:
        assurance = "unverified-scout-only"
    manifest: dict[str, Any] = {
        "version": 1,
        "installed_at": installed_at,
        "install_root": str(install_root),
        "command": str(wrapper),
        "config": str(config),
        "codex_binary": str(codex),
        "codex_version": ".".join(str(value) for value in codex_version),
        "codex_login_verified": True,
        "model": "gpt-5.6-terra",
        "reasoning_effort": "high",
        "runtime": runtime_name,
        "runtime_binary": str(runtime_path) if runtime_path else None,
        "runtime_available": runtime_path is not None,
        "sandbox_image_id": sandbox_image_id,
        "publication": "disabled",
        "assurance": assurance,
        "seatbelt_report": str(rehearsal_report) if rehearsal_report else None,
        "oci_report": str(oci_report) if oci_report else None,
        "launch_label": None,
        "launch_plist": None,
        "launch_behavior": "none",
        "notes": [
            "repository discovery never auto-enables an execution target",
            "host and ordinary OCI contribution execution are production-gated off",
            "strict VM guest execution requires a separate live-attested integration",
            "the bundled Codex adapter is retained for tests and cannot be launched by this job",
        ],
    }
    _write_manifest(install_root, manifest)

    if args.launch_now:
        _bind_launched_job(
            install_root,
            job=job,
            codex=codex,
            rehearsal=rehearsal,
            environment=environment,
            manifest=manifest,
            lock_descriptor=package_lock,
        )
    # This is the handoff point.  A launchd child carrying the bound label may
    # wait briefly on this same lock, but it cannot read mutable package state
    # until bootstrap and the final manifest commit have both completed.
    os.close(package_lock)

    if args.scout and not args.launch_now:
        _run_checked(
            [
                str(Path(sys.executable).resolve()),
                str(job),
                "--install-root",
                str(install_root),
                "--scout-only",
            ],
            environment,
            300,
        )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InstallError as exc:
        print(json.dumps({"error": "InstallError", "message": str(exc)}), file=sys.stderr)
        raise SystemExit(2) from None
