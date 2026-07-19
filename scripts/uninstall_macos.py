#!/usr/bin/env python3
"""Remove only a manifest-bound Leftovers macOS preview installation."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANAGED_BASE = ROOT / ".leftovers"
DEFAULT_INSTALL_ROOT = MANAGED_BASE / "install"
LAUNCH_LABEL = re.compile(r"dev\.leftovers\.once\.(\d+)\.\d{14}\.\d+")
CLEANUP_PENDING_FILENAME = "cleanup-pending.json"
MAX_LAUNCH_PLIST_BYTES = 1_000_000
LAUNCHCTL_PATH = Path("/bin/launchctl")
MAX_LAUNCHCTL_OUTPUT_BYTES = 65_536


class UninstallError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Remove a repository-local Leftovers macOS preview bundle"
    )
    parser.add_argument("--install-root", type=Path, default=DEFAULT_INSTALL_ROOT)
    return parser


def _lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _validated_root(path: Path) -> Path:
    root = _lexical_path(path)
    base = _lexical_path(MANAGED_BASE)
    if root == base:
        raise UninstallError("refusing to remove the repository .leftovers directory itself")
    try:
        root.relative_to(base)
    except ValueError as exc:
        raise UninstallError("install root escapes this repository's .leftovers directory") from exc
    current = _lexical_path(ROOT)
    for component in root.relative_to(current).parts:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise UninstallError(f"install root does not exist: {root}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise UninstallError(f"install path component may not be a symlink: {current}")
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise UninstallError("install root is not a private owner-controlled directory")
    return root


def _read_private_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    missing_ok: bool = False,
) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise UninstallError(f"{label} is missing") from None
    except OSError as exc:
        raise UninstallError(f"{label} is not a safe regular file") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= maximum_bytes
        ):
            raise UninstallError(f"{label} is not a private owner-controlled file")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if not payload or len(payload) > maximum_bytes:
            raise UninstallError(f"{label} exceeds its bounded read contract")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _read_manifest(root: Path) -> dict[str, Any]:
    payload = _read_private_file(
        root / "manifest.json",
        label="install manifest",
        maximum_bytes=1_000_000,
    )
    assert payload is not None
    try:
        manifest = json.loads(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UninstallError("install manifest contains invalid JSON") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 1
        or manifest.get("install_root") != str(root)
        or manifest.get("publication") != "disabled"
        or manifest.get("model") != "gpt-5.6-terra"
    ):
        raise UninstallError("install manifest does not authorize removal of this exact root")
    return manifest


def _cleanup_pending_evidence(root: Path) -> dict[str, Any] | None:
    """Return an actionable unproven-cleanup marker, rejecting unsafe variants."""

    path = root / CLEANUP_PENDING_FILENAME
    payload = _read_private_file(
        path,
        label="cleanup-pending evidence",
        maximum_bytes=8_192,
        missing_ok=True,
    )
    if payload is None:
        return None
    try:
        value = json.loads(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UninstallError("cleanup-pending evidence contains invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("version") not in {1, 2}
        or value.get("state") not in {"cleanup_in_progress", "cleanup_pending"}
        or type(value.get("pid")) is not int
        or value["pid"] <= 0
        or type(value.get("pgid")) is not int
        or value["pgid"] <= 0
        or not isinstance(value.get("observed_at"), str)
        or not value["observed_at"]
        or not isinstance(value.get("reason"), str)
        or not value["reason"]
    ):
        raise UninstallError("cleanup-pending evidence has an invalid shape")
    if value["version"] == 2:
        run_id = value.get("run_id")
        if (
            not isinstance(run_id, str)
            or re.fullmatch(r"[a-f0-9]{32}", run_id) is None
            or value.get("container_label") != f"io.leftovers.job={run_id}"
            or not all(
                isinstance(value.get(name), str) and value[name]
                for name in ("install_root", "state_dir", "workspace_root")
            )
        ):
            raise UninstallError("cleanup-pending evidence has an invalid preview lease context")
    return value


def _refuse_unproven_cleanup(root: Path) -> None:
    evidence = _cleanup_pending_evidence(root)
    if evidence is None:
        return
    raise UninstallError(
        "refusing removal: a prior preview cleanup remains unresolved "
        f"(state={evidence['state']}, run_id={evidence.get('run_id', 'unknown')}, "
        f"observed_at={evidence['observed_at']}); "
        f"inspect {root / CLEANUP_PENDING_FILENAME} and resolve it before retrying"
    )


def _launch_binding(root: Path, manifest: dict[str, Any]) -> tuple[str, Path] | None:
    label = manifest.get("launch_label")
    recorded_plist = manifest.get("launch_plist")
    if label is None and recorded_plist is None:
        return None
    if not isinstance(label, str) or not isinstance(recorded_plist, str):
        raise UninstallError("install manifest contains an incomplete launchd binding")
    match = LAUNCH_LABEL.fullmatch(label)
    if match is None or int(match.group(1)) != os.getuid():
        raise UninstallError("install manifest launch label is outside this user identity")
    expected = root / "launchd" / f"{label}.plist"
    if recorded_plist != str(expected):
        raise UninstallError("install manifest launch plist is outside its exact managed binding")
    current = root
    for component in expected.relative_to(root).parts:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode):
            raise UninstallError(f"tracked launch path component may not be a symlink: {current}")
    return label, expected


def _validate_launch_plist(path: Path, label: str) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise UninstallError("tracked launch plist is not a safe regular file") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= MAX_LAUNCH_PLIST_BYTES
        ):
            raise UninstallError("tracked launch plist is not a private owner-controlled file")
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
            raise UninstallError("tracked launch plist exceeds its byte limit")
    finally:
        os.close(descriptor)
    try:
        value = plistlib.loads(payload)
    except (ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise UninstallError("tracked launch plist is invalid") from exc
    if not isinstance(value, dict) or value.get("Label") != label:
        raise UninstallError("tracked launch plist does not match its manifest label")
    return True


def _launchctl_result(command: list[str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UninstallError("launchctl cleanup could not be proven") from exc
    if (
        len(result.stdout) > MAX_LAUNCHCTL_OUTPUT_BYTES
        or len(result.stderr) > MAX_LAUNCHCTL_OUTPUT_BYTES
    ):
        raise UninstallError("launchctl cleanup output exceeded its byte limit")
    return result


def _launchctl_reports_missing(result: subprocess.CompletedProcess[bytes]) -> bool:
    if result.returncode == 0:
        return False
    diagnostic = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace").lower()
    return any(
        marker in diagnostic
        for marker in ("could not find service", "service not found", "no such process")
    )


def _bootout(root: Path, manifest: dict[str, Any]) -> bool:
    binding = _launch_binding(root, manifest)
    if binding is None:
        return False
    label, plist_path = binding
    plist_exists = _validate_launch_plist(plist_path, label)
    launchctl = LAUNCHCTL_PATH
    if not launchctl.is_file() or not os.access(launchctl, os.X_OK):
        raise UninstallError("launchctl is unavailable; refusing incomplete cleanup")
    service = f"gui/{os.getuid()}/{label}"
    inspected = _launchctl_result([str(launchctl), "print", service], 15)
    inspected_missing = _launchctl_reports_missing(inspected)
    removed = _launchctl_result([str(launchctl), "bootout", service], 30)
    removed_missing = _launchctl_reports_missing(removed)
    if removed.returncode != 0 and not (inspected_missing and removed_missing):
        raise UninstallError("the recorded one-shot launchd service could not be unloaded")
    verified = _launchctl_result([str(launchctl), "print", service], 15)
    if verified.returncode == 0:
        raise UninstallError("the recorded one-shot launchd service remained loaded")
    if not _launchctl_reports_missing(verified):
        raise UninstallError("launchctl did not prove the recorded service is absent")
    unloaded = inspected.returncode == 0 or removed.returncode == 0
    if plist_exists:
        try:
            plist_path.unlink()
        except OSError as exc:
            raise UninstallError("the exact tracked launch plist could not be removed") from exc
    return unloaded


def _acquire_job_lock(root: Path) -> int:
    path = root / "job.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        os.close(descriptor)
        raise UninstallError("job lock is not a single-link owner-controlled file")
    os.fchmod(descriptor, 0o600)
    deadline = time.monotonic() + 15
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(descriptor)
                raise UninstallError(
                    "the detached job is still active; try cleanup again later"
                ) from None
            time.sleep(0.25)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if sys.platform != "darwin":
        raise UninstallError("this cleanup helper is for macOS")
    if getattr(os, "geteuid", lambda: 1)() == 0:
        raise UninstallError("do not run the Leftovers cleanup helper as root")
    root = _validated_root(args.install_root)
    descriptor = _acquire_job_lock(root)
    try:
        manifest = _read_manifest(root)
        _refuse_unproven_cleanup(root)
        launch_removed = _bootout(root, manifest)
        shutil.rmtree(root)
    except OSError as exc:
        raise UninstallError(f"could not remove the exact install root: {exc}") from exc
    finally:
        os.close(descriptor)
    print(
        json.dumps(
            {
                "removed": True,
                "install_root": str(root),
                "launch_service_unloaded": launch_removed,
                "outside_paths_removed": [],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UninstallError as exc:
        print(json.dumps({"error": "UninstallError", "message": str(exc)}))
        raise SystemExit(2) from None
