#!/usr/bin/env python3
"""Verify the installed wheel, console entry point, and required package data."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

import leftovers

EXPECTED_PACKAGE_DATA = (
    "prompt_templates/implementation.md",
    "prompt_templates/planning.md",
    "prompt_templates/pr-writer.md",
    "prompt_templates/review.md",
    "prompt_templates/system.md",
    "dashboard_assets/index.html",
    "dashboard_assets/styles.css",
    "dashboard_assets/app.js",
)


def main() -> int:
    installed = distribution("leftovers-agent")
    entry_points = [
        entry_point
        for entry_point in installed.entry_points
        if entry_point.group == "console_scripts" and entry_point.name == "leftovers"
    ]
    if len(entry_points) != 1 or entry_points[0].value != "leftovers.cli:main":
        raise SystemExit("installed wheel does not expose the expected leftovers console script")

    package_root = Path(leftovers.__file__).resolve().parent
    assets: dict[str, dict[str, object]] = {}
    for relative_name in EXPECTED_PACKAGE_DATA:
        path = package_root / relative_name
        if not path.is_file():
            raise SystemExit(f"installed wheel is missing package data: {relative_name}")
        content = path.read_bytes()
        if not content:
            raise SystemExit(f"installed package data is empty: {relative_name}")
        assets[relative_name] = {
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    executable = Path(sys.executable).with_name("leftovers")
    result = subprocess.run(
        [str(executable), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "HOME": "/nonexistent",
            "PATH": str(executable.parent),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    if result.returncode != 0 or "usage: leftovers" not in result.stdout:
        raise SystemExit("installed leftovers console script did not render help successfully")

    print(
        json.dumps(
            {
                "assets": assets,
                "console_script": str(executable),
                "distribution": installed.metadata["Name"],
                "version": installed.version,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
