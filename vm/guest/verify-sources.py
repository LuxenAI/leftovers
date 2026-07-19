#!/usr/bin/env python3
"""Verify the immutable source lock without downloading source trees.

`--verify-remote` is for a disposable release builder only. It asks each
official Git remote for exactly the recorded tag object and rejects a different
object ID before Buildroot is allowed to fetch source.  It deliberately does
not claim signed-tag verification: that requires the separately pinned public
keyring and ``release.py verify-checkouts``.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HEX40 = re.compile(r"^[0-9a-f]{40}$")


def load_lock(path: Path) -> list[dict[str, str]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != 2 or not isinstance(value.get("sources"), list):
        raise ValueError("unsupported source lock")
    sources = value["sources"]
    if len(sources) != 2 or {entry.get("name") for entry in sources} != {
        "buildroot",
        "linux-stable",
    }:
        raise ValueError("source lock must contain exactly Buildroot and linux-stable")
    for entry in sources:
        if entry.get("hash_algorithm") != "git-sha1" or not HEX40.fullmatch(
            entry.get("tag_object", "")
        ):
            raise ValueError(f"invalid immutable object ID for {entry.get('name', 'unknown')}")
        if not entry.get("repository", "").startswith("https://"):
            raise ValueError(f"non-HTTPS repository for {entry['name']}")
        if not entry.get("ref", "").startswith("refs/tags/"):
            raise ValueError(f"non-tag source reference for {entry['name']}")
    return sources


def remote_object(repository: str, ref: str) -> str:
    completed = subprocess.run(
        ["git", "ls-remote", "--refs", repository, ref],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ValueError(f"remote lookup failed for {repository}: {completed.stderr.strip()}")
    lines = completed.stdout.strip().splitlines()
    if len(lines) != 1:
        raise ValueError(f"expected one exact remote tag record for {ref}")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != ref or not HEX40.fullmatch(fields[0]):
        raise ValueError(f"malformed remote tag record for {ref}")
    return fields[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-remote", action="store_true")
    args = parser.parse_args()
    sources = load_lock(Path(__file__).with_name("SOURCES.lock.json"))
    if args.verify_remote:
        for source in sources:
            actual = remote_object(source["repository"], source["ref"])
            if actual != source["tag_object"]:
                raise ValueError(f"source substitution for {source['name']}")
    print("strict guest source lock is valid")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"strict guest source verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
