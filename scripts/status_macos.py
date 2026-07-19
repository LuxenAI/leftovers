#!/usr/bin/env python3
"""Report the bounded state of a repository-local Leftovers macOS package."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from uninstall_macos import (
    DEFAULT_INSTALL_ROOT,
    LAUNCH_LABEL,
    UninstallError,
    _cleanup_pending_evidence,
    _read_manifest,
    _validated_root,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect the Leftovers macOS preview bundle")
    parser.add_argument("--install-root", type=Path, default=DEFAULT_INSTALL_ROOT)
    return parser


def _summary(root: Path) -> dict[str, Any] | None:
    path = root / "reports" / "job-summary.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 2_000_000:
        return None
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _current_summary(summary: dict[str, Any] | None, installed_at: object) -> bool:
    if summary is None or not isinstance(installed_at, str):
        return False
    started_at = summary.get("started_at")
    if not isinstance(started_at, str):
        return False
    try:
        installed = datetime.fromisoformat(installed_at.replace("Z", "+00:00"))
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return started >= installed


def _launch_loaded(label: object) -> bool:
    if not isinstance(label, str):
        return False
    match = LAUNCH_LABEL.fullmatch(label)
    if match is None or int(match.group(1)) != os.getuid():
        return False
    completed = subprocess.run(
        ["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    return completed.returncode == 0


def main(argv: list[str] | None = None) -> int:
    root = _validated_root(_parser().parse_args(argv).install_root)
    manifest = _read_manifest(root)
    summary = _summary(root)
    cleanup_pending = _cleanup_pending_evidence(root)
    summary_is_current = _current_summary(summary, manifest.get("installed_at"))
    launch_loaded = _launch_loaded(manifest.get("launch_label"))
    if cleanup_pending is not None:
        job_state = "cleanup-pending"
    elif summary_is_current:
        job_state = "finished"
    elif launch_loaded:
        job_state = "submitted-or-running"
    else:
        job_state = "not-run-for-current-install"
    output = {
        "installed": True,
        "install_root": str(root),
        "model": manifest["model"],
        "reasoning_effort": manifest.get("reasoning_effort"),
        "assurance": manifest.get("assurance"),
        "publication": manifest["publication"],
        "runtime": manifest.get("runtime"),
        "runtime_available_at_install": manifest.get("runtime_available"),
        "sandbox_image_id": manifest.get("sandbox_image_id"),
        "launch_behavior": manifest.get("launch_behavior"),
        "launch_service_loaded": launch_loaded,
        "job_state": job_state,
        "cleanup_pending": cleanup_pending,
        "job_summary": summary if summary_is_current else None,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return (
        0
        if cleanup_pending is None and (not summary_is_current or not summary.get("errors"))
        else 2
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UninstallError as exc:
        print(json.dumps({"error": "StatusError", "message": str(exc)}))
        raise SystemExit(2) from None
