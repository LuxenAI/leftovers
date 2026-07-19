#!/usr/bin/env python3
"""Fail-closed provenance helpers for the strict-VM guest release builder.

This program deliberately does not fetch, compile, invoke a container runtime,
or verify a signature by assertion.  It validates immutable inputs and creates
canonical *candidate* boot metadata after a separately provisioned disposable
builder has performed the real work.  ``release-readiness`` rejects the
repository's intentionally unconfigured trust roots.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
# Deliberately narrower than the full OCI grammar: release builders do not need
# uppercase names, tags, registry ports, or shell-significant characters.  The
# value is eventually passed to Docker as an argv element, but a strict grammar
# prevents a later workflow edit from turning a lock-file field into shell text.
IMAGE_REFERENCE = re.compile(
    r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?:/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)+"
    r"@sha256:[0-9a-f]{64}\Z"
)
FIXED_KEYRING_PATH = "vm/guest/trusted-keys"
OFFICIAL_SOURCE_REPOSITORIES = {
    "buildroot": "https://gitlab.com/buildroot.org/buildroot.git",
    "linux-stable": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
}
# No verifier is registered yet.  A future implementation must add an exact
# reviewed identifier, executable digest, and fixed argv here *and* invoke it
# before any candidate can be promoted.  Until then, readiness remains false.
PROVENANCE_VERIFIER_REGISTRY: dict[str, tuple[str, tuple[str, ...]]] = {}
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_KEYRING_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = {
    "kernel": 512 * 1024 * 1024,
    "initrd": 512 * 1024 * 1024,
    "root_disk": 4 * 1024 * 1024 * 1024,
}
SAFE_GIT_CONFIG = (
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.autocrlf=false",
    "credential.helper=",
    "gpg.format=openpgp",
    "gpg.program=/usr/bin/gpg",
    "gpg.openpgp.program=/usr/bin/gpg",
)


class ReleaseError(ValueError):
    """A release input is absent, ambiguous, mutable, or not independently pinned."""


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ReleaseError(f"non-finite JSON value: {value}")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ReleaseError("value cannot be canonicalized as JSON") from error


def _stable_regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    """Read one bounded regular file without following its final path component."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ReleaseError(f"cannot open {label} {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise ReleaseError(f"unsafe {label} {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise ReleaseError(f"truncated {label} {path}")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise ReleaseError(f"changed while reading {label} {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_json(path: Path, *, canonical: bool = False) -> tuple[Any, bytes]:
    try:
        raw = _stable_regular_bytes(path, MAX_JSON_BYTES, "JSON file")
        value = json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReleaseError) as error:
        raise ReleaseError(f"invalid JSON file {path}") from error
    encoded = canonical_json(value)
    if canonical and raw != encoded:
        raise ReleaseError(f"JSON file is not canonical: {path}")
    return value, encoded


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ReleaseError(f"{label} fields are not exact")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ReleaseError(f"{label} is not a lowercase SHA-256 digest")
    return value


def require_beneath(path: Path, root: Path, label: str) -> Path:
    """Resolve a caller path once and require it to remain below a fixed root."""
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=False)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise ReleaseError(f"{label} escapes its allowed root") from error
    return resolved_path


def source_lock(path: Path) -> tuple[dict[str, Any], bytes]:
    value, encoded = read_json(path)
    lock = require_keys(
        value, {"schema_version", "recorded_at", "verification", "sources"}, "source lock"
    )
    if (
        lock["schema_version"] != 2
        or not isinstance(lock["recorded_at"], str)
        or not isinstance(lock["verification"], str)
    ):
        raise ReleaseError("unsupported source lock")
    sources = lock["sources"]
    if not isinstance(sources, list) or len(sources) != 2:
        raise ReleaseError("source lock must contain exactly two sources")
    expected = {"buildroot", "linux-stable"}
    seen: set[str] = set()
    for entry in sources:
        item = require_keys(
            entry,
            {
                "name",
                "purpose",
                "repository",
                "ref",
                "tag_object",
                "hash_algorithm",
                "release_date",
                "release_page",
                "tag_verification",
            },
            "source entry",
        )
        name = item["name"]
        if not isinstance(name, str) or name not in expected or name in seen:
            raise ReleaseError("source names are not exact")
        seen.add(name)
        if (
            item["hash_algorithm"] != "git-sha1"
            or item["repository"] != OFFICIAL_SOURCE_REPOSITORIES[name]
            or not isinstance(item["ref"], str)
            or not item["ref"].startswith("refs/tags/")
            or not isinstance(item["tag_object"], str)
            or HEX40.fullmatch(item["tag_object"]) is None
        ):
            raise ReleaseError(f"source lock entry is unsafe: {name}")
        verification = require_keys(
            item["tag_verification"],
            {"required", "method", "trusted_keyring", "expected_signer_fingerprint", "status"},
            "tag verification",
        )
        if (
            verification["required"] is not True
            or verification["method"] != "git-verify-tag"
            or verification["trusted_keyring"] != "BUILD.lock.json:trusted_keyring"
            or verification["status"] not in {"UNCONFIGURED", "CONFIGURED"}
            or (
                verification["expected_signer_fingerprint"] is not None
                and (
                    not isinstance(verification["expected_signer_fingerprint"], str)
                    or FINGERPRINT.fullmatch(verification["expected_signer_fingerprint"]) is None
                )
            )
        ):
            raise ReleaseError(f"tag verification policy is unsafe: {name}")
    if seen != expected:
        raise ReleaseError("source lock names are incomplete")
    return lock, encoded


def build_lock(path: Path) -> tuple[dict[str, Any], bytes]:
    value, encoded = read_json(path)
    lock = require_keys(
        value,
        {"schema_version", "builder_image", "provenance", "reproducibility", "trusted_keyring"},
        "build lock",
    )
    if lock["schema_version"] != 1:
        raise ReleaseError("unsupported build lock")
    builder = require_keys(lock["builder_image"], {"reference", "status"}, "builder image")
    provenance = require_keys(
        lock["provenance"], {"required", "status", "verifier"}, "provenance policy"
    )
    reproducibility = require_keys(
        lock["reproducibility"],
        {"required", "source_date_epoch", "status"},
        "reproducibility policy",
    )
    keyring = require_keys(lock["trusted_keyring"], {"path", "sha256", "status"}, "trusted keyring")
    for label, item in (
        ("builder image", builder),
        ("provenance", provenance),
        ("reproducibility", reproducibility),
        ("trusted keyring", keyring),
    ):
        if item["status"] not in {"UNCONFIGURED", "CONFIGURED"}:
            raise ReleaseError(f"invalid {label} status")
    if provenance["required"] is not True or reproducibility["required"] is not True:
        raise ReleaseError("provenance and reproducibility must be required")
    if keyring["path"] != FIXED_KEYRING_PATH:
        raise ReleaseError("trusted keyring path is not the fixed guest keyring")
    if keyring["sha256"] is not None:
        require_digest(keyring["sha256"], "trusted keyring digest")
    if builder["reference"] is not None and (
        not isinstance(builder["reference"], str)
        or IMAGE_REFERENCE.fullmatch(builder["reference"]) is None
    ):
        raise ReleaseError("builder image must be a digest-pinned reference")
    if reproducibility["source_date_epoch"] is not None and (
        type(reproducibility["source_date_epoch"]) is not int
        or reproducibility["source_date_epoch"] <= 0
    ):
        raise ReleaseError("source date epoch is unsafe")
    if provenance["verifier"] is not None:
        verifier = require_keys(
            provenance["verifier"], {"argv", "id", "sha256"}, "provenance verifier"
        )
        if (
            not isinstance(verifier["id"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", verifier["id"])
            or not isinstance(verifier["argv"], list)
            or not verifier["argv"]
            or any(
                not isinstance(argument, str)
                or not argument
                or "\x00" in argument
                or argument.startswith("-")
                for argument in verifier["argv"]
            )
        ):
            raise ReleaseError("provenance verifier is unsafe")
        require_digest(verifier["sha256"], "provenance verifier digest")
    return lock, encoded


def tree_digest(path: Path, *, maximum: int = MAX_KEYRING_BYTES) -> str:
    """Hash a small public-key tree without following links or accepting devices."""
    try:
        root = path.lstat()
    except OSError as error:
        raise ReleaseError(f"cannot stat trusted keyring {path}") from error
    if not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode):
        raise ReleaseError("trusted keyring is not a real directory")
    records: list[tuple[str, bytes]] = []
    total = 0
    for current, directories, files in os.walk(path, followlinks=False):
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            candidate = Path(current) / name
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise ReleaseError("trusted keyring contains a link or special file")
        for name in files:
            candidate = Path(current) / name
            data = _stable_regular_bytes(candidate, maximum - total, "trusted keyring file")
            total += len(data)
            if total > maximum:
                raise ReleaseError("trusted keyring exceeds its size limit")
            relative = candidate.relative_to(path).as_posix()
            records.append((relative, data))
    digest = hashlib.sha256()
    for relative, data in records:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\\0")
        digest.update(data)
        digest.update(b"\\0")
    return digest.hexdigest()


def release_readiness(
    source_path: Path, build_path: Path, workspace: Path
) -> tuple[dict[str, Any], dict[str, Any], str]:
    workspace = workspace.resolve(strict=True)
    require_beneath(source_path, workspace, "source lock")
    require_beneath(build_path, workspace, "build lock")
    sources, _ = source_lock(source_path)
    build, _ = build_lock(build_path)
    fields = (
        build["builder_image"],
        build["provenance"],
        build["reproducibility"],
        build["trusted_keyring"],
    )
    if any(item["status"] != "CONFIGURED" for item in fields):
        raise ReleaseError(
            "guest release is intentionally unconfigured: reviewed trust roots are required"
        )
    if any(
        entry["tag_verification"]["status"] != "CONFIGURED"
        or entry["tag_verification"]["expected_signer_fingerprint"] is None
        for entry in sources["sources"]
    ):
        raise ReleaseError("upstream signed-tag identities are not pinned")
    if (
        build["builder_image"]["reference"] is None
        or build["provenance"]["verifier"] is None
        or build["reproducibility"]["source_date_epoch"] is None
    ):
        raise ReleaseError("builder image, verifier, and SOURCE_DATE_EPOCH are required")
    keyring = workspace / FIXED_KEYRING_PATH
    if tree_digest(keyring) != build["trusted_keyring"]["sha256"]:
        raise ReleaseError("trusted keyring digest does not match BUILD.lock.json")
    verifier = build["provenance"]["verifier"]
    assert isinstance(verifier, dict)
    registered = PROVENANCE_VERIFIER_REGISTRY.get(verifier["id"])
    if registered is None or registered != (verifier["sha256"], tuple(verifier["argv"])):
        raise ReleaseError("provenance verifier is not implemented in the fixed registry")
    return sources, build, keyring.as_posix()


def checked_git(
    source: Path,
    arguments: list[str],
    *,
    gnupg_home: Path | None = None,
    git_home: Path,
    include_stderr: bool = False,
) -> str:
    home = git_home
    try:
        home_info = home.lstat()
    except OSError as error:
        raise ReleaseError("isolated Git home is unavailable") from error
    if stat.S_ISLNK(home_info.st_mode) or not stat.S_ISDIR(home_info.st_mode):
        raise ReleaseError("isolated Git home is unsafe")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "HOME": os.fspath(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    if gnupg_home is not None:
        environment["GNUPGHOME"] = os.fspath(gnupg_home)
    completed = subprocess.run(
        [
            "git",
            *(item for config in SAFE_GIT_CONFIG for item in ("-c", config)),
            "-C",
            os.fspath(source),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )
    if completed.returncode != 0:
        raise ReleaseError(f"git verification failed for {source.name}: {completed.stderr.strip()}")
    return completed.stdout + completed.stderr if include_stderr else completed.stdout


def verify_clean_tag_checkout(source: Path, ref: str, git_home: Path) -> str:
    """Require HEAD, index, worktree, and untracked set to equal one tag commit."""
    tag_commit = checked_git(
        source, ["rev-parse", "--verify", f"{ref}^{{commit}}"], git_home=git_home
    ).strip()
    head = checked_git(source, ["rev-parse", "--verify", "HEAD"], git_home=git_home).strip()
    if tag_commit != head or HEX40.fullmatch(head) is None:
        raise ReleaseError(f"checkout HEAD does not equal signed tag commit: {source.name}")
    status = checked_git(
        source,
        ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"],
        git_home=git_home,
    )
    if status:
        raise ReleaseError(f"checkout is not clean: {source.name}")
    return head


def verify_remote_sources(args: argparse.Namespace) -> None:
    """Check only the two fixed official tag objects before any clone occurs."""
    sources, _, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
    for entry in sources["sources"]:
        completed = subprocess.run(
            ["git", "ls-remote", "--refs", entry["repository"], entry["ref"]],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
        if completed.returncode != 0:
            raise ReleaseError(f"remote source lookup failed: {entry['name']}")
        records = completed.stdout.strip().splitlines()
        if len(records) != 1:
            raise ReleaseError(f"remote tag lookup was ambiguous: {entry['name']}")
        fields = records[0].split()
        if len(fields) != 2 or fields[0] != entry["tag_object"] or fields[1] != entry["ref"]:
            raise ReleaseError(f"remote tag object substitution: {entry['name']}")


def print_source_field(args: argparse.Namespace) -> None:
    sources, _, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    fields = {"repository", "ref", "tag_object"}
    if args.field not in fields:
        raise ReleaseError("source field is not approved")
    for source in sources["sources"]:
        if source["name"] == args.name:
            print(source[args.field])
            return
    raise ReleaseError("source name is not approved")


def print_builder_image(args: argparse.Namespace) -> None:
    _, build, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    image = build["builder_image"]["reference"]
    assert isinstance(image, str)
    print(image)


def verify_checkouts(args: argparse.Namespace) -> None:
    sources, _, keyring = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    gnupg_home = args.gnupg_home or Path(keyring)
    if not gnupg_home.is_dir():
        raise ReleaseError("GnuPG home is unavailable")
    git_home = gnupg_home.parent / "leftovers-git-home"
    roots = {"buildroot": args.buildroot, "linux-stable": args.linux}
    evidence: list[dict[str, str]] = []
    for entry in sources["sources"]:
        root = roots[entry["name"]]
        object_id = checked_git(
            root, ["rev-parse", "--verify", entry["ref"]], git_home=git_home
        ).strip()
        if object_id != entry["tag_object"]:
            raise ReleaseError(f"tag object substitution: {entry['name']}")
        verification = checked_git(
            root,
            ["verify-tag", "--raw", entry["ref"]],
            gnupg_home=gnupg_home,
            git_home=git_home,
            include_stderr=True,
        )
        signer = entry["tag_verification"]["expected_signer_fingerprint"]
        if f"VALIDSIG {signer}" not in verification:
            raise ReleaseError(f"signed tag identity did not match: {entry['name']}")
        commit = verify_clean_tag_checkout(root, entry["ref"], git_home)
        evidence.append(
            {
                "name": entry["name"],
                "ref": entry["ref"],
                "tag_object": object_id,
                "tag_commit": commit,
                "verify_tag_output_sha256": sha256_bytes(verification.encode("utf-8")),
            }
        )
    output = {
        "schema_version": 1,
        "source_lock_sha256": sha256_bytes(source_lock(args.sources_lock)[1]),
        "sources": sorted(evidence, key=lambda item: item["name"]),
    }
    output_root = args.output_root or args.workspace
    write_new_canonical(args.output, output, root=output_root, mode=0o400)


def hash_artifact(path: Path, role: str, root: Path) -> dict[str, int | str]:
    path = require_beneath(path, root, f"{role} artifact")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise ReleaseError(f"missing {role} artifact") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_ARTIFACT_BYTES[role]
        ):
            raise ReleaseError(f"unsafe {role} artifact")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise ReleaseError(f"truncated {role} artifact")
            digest.update(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise ReleaseError(f"changed while hashing {role} artifact")
        return {"bytes": before.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(descriptor)


def metadata(value: Any, build: dict[str, Any], source_digest: str) -> None:
    item = require_keys(
        value,
        {
            "builder_image",
            "build_context_sha256",
            "schema_version",
            "source_date_epoch",
            "source_lock_sha256",
            "toolchain",
        },
        "build metadata",
    )
    toolchain = require_keys(item["toolchain"], {"compiler", "version_sha256"}, "toolchain")
    if (
        item["schema_version"] != 1
        or item["builder_image"] != build["builder_image"]["reference"]
        or item["source_lock_sha256"] != source_digest
        or item["source_date_epoch"] != build["reproducibility"]["source_date_epoch"]
        or not isinstance(toolchain["compiler"], str)
        or not toolchain["compiler"]
    ):
        raise ReleaseError("build metadata does not bind configured inputs")
    require_digest(item["build_context_sha256"], "build context digest")
    require_digest(toolchain["version_sha256"], "compiler version digest")


def sbom(value: Any, sources: dict[str, Any]) -> None:
    item = require_keys(value, {"components", "format", "schema_version"}, "SBOM")
    if (
        item["schema_version"] != 1
        or item["format"] != "leftovers-guest-sbom-v1"
        or not isinstance(item["components"], list)
    ):
        raise ReleaseError("unsupported SBOM")
    expected = {source["name"]: source for source in sources["sources"]}
    if len(item["components"]) != len(expected):
        raise ReleaseError("SBOM component count is unsafe")
    seen: set[str] = set()
    for component in item["components"]:
        entry = require_keys(
            component, {"name", "source_ref", "source_tag_object"}, "SBOM component"
        )
        name = entry["name"]
        if (
            name not in expected
            or name in seen
            or entry["source_ref"] != expected[name]["ref"]
            or entry["source_tag_object"] != expected[name]["tag_object"]
        ):
            raise ReleaseError("SBOM does not bind locked sources")
        seen.add(name)


def provenance(
    value: Any,
    *,
    artifacts: dict[str, dict[str, int | str]],
    metadata_digest: str,
    sbom_digest: str,
    source_digest: str,
) -> None:
    item = require_keys(
        value,
        {
            "artifacts",
            "build_metadata_sha256",
            "predicate_type",
            "sbom_sha256",
            "schema_version",
            "source_lock_sha256",
        },
        "provenance",
    )
    if (
        item["schema_version"] != 1
        or item["predicate_type"] != "https://slsa.dev/provenance/v1"
        or item["build_metadata_sha256"] != metadata_digest
        or item["sbom_sha256"] != sbom_digest
        or item["source_lock_sha256"] != source_digest
    ):
        raise ReleaseError("provenance does not bind candidate inputs")
    if item["artifacts"] != {name: details["sha256"] for name, details in artifacts.items()}:
        raise ReleaseError("provenance does not bind exact artifact digests")


def _direct_child(path: Path, root: Path, label: str) -> tuple[Path, Path]:
    root = root.resolve(strict=True)
    path = require_beneath(path, root, label)
    if path.parent != root:
        raise ReleaseError(f"{label} must be a direct child of its output root")
    return path, root


def create_output_directory(path: Path, root: Path) -> Path:
    path, root = _direct_child(path, root, "candidate output")
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        child = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent,
        )
        try:
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                raise ReleaseError("candidate output is not a directory")
        finally:
            os.close(child)
    except FileExistsError as error:
        raise ReleaseError(f"refusing to overwrite {path}") from error
    finally:
        os.close(parent)
    return path


def write_new_canonical(path: Path, value: Any, *, root: Path, mode: int) -> None:
    path, root = _direct_child(path, root, "output file")
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent,
        )
    except FileExistsError as error:
        raise ReleaseError(f"refusing to overwrite {path}") from error
    finally:
        os.close(parent)
    try:
        raw = canonical_json(value)
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            if count <= 0:
                raise ReleaseError(f"could not write {path}")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def generate_candidate(args: argparse.Namespace) -> None:
    sources, build, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    artifact_root = args.artifact_root or args.workspace
    artifact_root = artifact_root.resolve(strict=True)
    source_digest = sha256_bytes(source_lock(args.sources_lock)[1])
    artifacts = {
        "kernel": hash_artifact(args.kernel, "kernel", artifact_root),
        "initrd": hash_artifact(args.initrd, "initrd", artifact_root),
        "root_disk": hash_artifact(args.root_disk, "root_disk", artifact_root),
    }
    build_metadata, build_metadata_raw = read_json(
        require_beneath(args.build_metadata, artifact_root, "build metadata"), canonical=True
    )
    sbom_value, sbom_raw = read_json(
        require_beneath(args.sbom, artifact_root, "SBOM"), canonical=True
    )
    provenance_value, provenance_raw = read_json(
        require_beneath(args.provenance, artifact_root, "provenance"), canonical=True
    )
    metadata(build_metadata, build, source_digest)
    sbom(sbom_value, sources)
    metadata_digest, sbom_digest = sha256_bytes(build_metadata_raw), sha256_bytes(sbom_raw)
    provenance(
        provenance_value,
        artifacts=artifacts,
        metadata_digest=metadata_digest,
        sbom_digest=sbom_digest,
        source_digest=source_digest,
    )
    policy = {
        "boot_artifacts": {
            name + "_sha256": artifacts[name]["sha256"]
            for name in ("initrd", "kernel", "root_disk")
        },
        "execution_mode": "reject-all-actions",
        "profile": "leftovers-guest-rejection-only-v1",
        "schema_version": 1,
    }
    policy_raw = canonical_json(policy)
    manifest = {
        "boot_artifacts": artifacts,
        "build_metadata_sha256": metadata_digest,
        "guest_policy_sha256": sha256_bytes(policy_raw),
        "profile": "leftovers-guest-rejection-only-v1",
        "provenance_sha256": sha256_bytes(provenance_raw),
        "provenance_status": "UNVERIFIED-CANDIDATE",
        "sbom_sha256": sbom_digest,
        "schema_version": 1,
        "source_lock_sha256": source_digest,
    }
    output = create_output_directory(args.output, artifact_root)
    write_new_canonical(output / "guest-policy.json", policy, root=output, mode=0o400)
    try:
        write_new_canonical(
            output / "guest-artifact-manifest.json", manifest, root=output, mode=0o400
        )
    except Exception:
        # A lone policy is unsafe to mistake for a completed candidate.
        descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.unlink("guest-policy.json", dir_fd=descriptor)
        finally:
            os.close(descriptor)
        raise


def emit_build_metadata(args: argparse.Namespace) -> None:
    _, build, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    _, source_raw = source_lock(args.sources_lock)
    output_root = args.output_root or args.workspace
    version = _stable_regular_bytes(
        require_beneath(args.compiler_version, output_root, "compiler evidence"),
        64 * 1024,
        "compiler version evidence",
    )
    if not isinstance(args.compiler, str) or not args.compiler or "\x00" in args.compiler:
        raise ReleaseError("compiler identity is unsafe")
    value = {
        "builder_image": build["builder_image"]["reference"],
        "build_context_sha256": tree_digest(args.build_context),
        "schema_version": 1,
        "source_date_epoch": build["reproducibility"]["source_date_epoch"],
        "source_lock_sha256": sha256_bytes(source_raw),
        "toolchain": {
            "compiler": args.compiler,
            "version_sha256": sha256_bytes(version),
        },
    }
    write_new_canonical(args.output, value, root=output_root, mode=0o400)


def emit_sbom(args: argparse.Namespace) -> None:
    sources, _, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    components = [
        {
            "name": source["name"],
            "source_ref": source["ref"],
            "source_tag_object": source["tag_object"],
        }
        for source in sorted(sources["sources"], key=lambda item: item["name"])
    ]
    output_root = args.output_root or args.workspace
    write_new_canonical(
        args.output,
        {"components": components, "format": "leftovers-guest-sbom-v1", "schema_version": 1},
        root=output_root,
        mode=0o400,
    )


def emit_provenance(args: argparse.Namespace) -> None:
    _, build, _ = release_readiness(args.sources_lock, args.build_lock, args.workspace)
    _, source_raw = source_lock(args.sources_lock)
    artifact_root = (args.artifact_root or args.workspace).resolve(strict=True)
    artifacts = {
        "kernel": hash_artifact(args.kernel, "kernel", artifact_root),
        "initrd": hash_artifact(args.initrd, "initrd", artifact_root),
        "root_disk": hash_artifact(args.root_disk, "root_disk", artifact_root),
    }
    metadata_value, metadata_raw = read_json(
        require_beneath(args.build_metadata, artifact_root, "build metadata"), canonical=True
    )
    sbom_value, sbom_raw = read_json(
        require_beneath(args.sbom, artifact_root, "SBOM"), canonical=True
    )
    source_digest = sha256_bytes(source_raw)
    metadata(metadata_value, build, source_digest)
    sbom(sbom_value, source_lock(args.sources_lock)[0])
    write_new_canonical(
        args.output,
        {
            "artifacts": {name: item["sha256"] for name, item in artifacts.items()},
            "build_metadata_sha256": sha256_bytes(metadata_raw),
            "predicate_type": "https://slsa.dev/provenance/v1",
            "sbom_sha256": sha256_bytes(sbom_raw),
            "schema_version": 1,
            "source_lock_sha256": source_digest,
        },
        root=artifact_root,
        mode=0o400,
    )


def compare_candidates(left: Path, right: Path) -> None:
    names = ("guest-policy.json", "guest-artifact-manifest.json")
    for name in names:
        _, left_raw = read_json(left / name, canonical=True)
        _, right_raw = read_json(right / name, canonical=True)
        if left_raw != right_raw:
            raise ReleaseError(f"candidate artifacts differ: {name}")
    print("strict guest candidate reproducibility comparison passed")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--workspace", type=Path, default=HERE.parents[1])
    common.add_argument("--sources-lock", type=Path, default=HERE / "SOURCES.lock.json")
    common.add_argument("--build-lock", type=Path, default=HERE / "BUILD.lock.json")
    subparsers.add_parser("validate-locks", parents=[common])
    subparsers.add_parser("release-readiness", parents=[common])
    subparsers.add_parser("verify-remote", parents=[common])
    source_field = subparsers.add_parser("source-field", parents=[common])
    source_field.add_argument("--name", choices=("buildroot", "linux-stable"), required=True)
    source_field.add_argument("--field", choices=("repository", "ref", "tag_object"), required=True)
    subparsers.add_parser("builder-image", parents=[common])
    checkout = subparsers.add_parser("verify-checkouts", parents=[common])
    checkout.add_argument("--buildroot", type=Path, required=True)
    checkout.add_argument("--linux", type=Path, required=True)
    checkout.add_argument("--output", type=Path, required=True)
    checkout.add_argument("--output-root", type=Path)
    checkout.add_argument("--gnupg-home", type=Path)
    metadata_command = subparsers.add_parser("emit-build-metadata", parents=[common])
    metadata_command.add_argument("--build-context", type=Path, required=True)
    metadata_command.add_argument("--compiler", required=True)
    metadata_command.add_argument("--compiler-version", type=Path, required=True)
    metadata_command.add_argument("--output", type=Path, required=True)
    metadata_command.add_argument("--output-root", type=Path)
    sbom_command = subparsers.add_parser("emit-sbom", parents=[common])
    sbom_command.add_argument("--output", type=Path, required=True)
    sbom_command.add_argument("--output-root", type=Path)
    provenance_command = subparsers.add_parser("emit-provenance", parents=[common])
    provenance_command.add_argument("--kernel", type=Path, required=True)
    provenance_command.add_argument("--initrd", type=Path, required=True)
    provenance_command.add_argument("--root-disk", type=Path, required=True)
    provenance_command.add_argument("--build-metadata", type=Path, required=True)
    provenance_command.add_argument("--sbom", type=Path, required=True)
    provenance_command.add_argument("--output", type=Path, required=True)
    provenance_command.add_argument("--artifact-root", type=Path)
    candidate = subparsers.add_parser("generate-candidate", parents=[common])
    candidate.add_argument("--kernel", type=Path, required=True)
    candidate.add_argument("--initrd", type=Path, required=True)
    candidate.add_argument("--root-disk", type=Path, required=True)
    candidate.add_argument("--build-metadata", type=Path, required=True)
    candidate.add_argument("--sbom", type=Path, required=True)
    candidate.add_argument("--provenance", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--artifact-root", type=Path)
    comparison = subparsers.add_parser("compare-candidates")
    comparison.add_argument("--left", type=Path, required=True)
    comparison.add_argument("--right", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "validate-locks":
        source_lock(args.sources_lock)
        build_lock(args.build_lock)
        print("strict guest build locks are structurally valid")
    elif args.command == "release-readiness":
        release_readiness(args.sources_lock, args.build_lock, args.workspace)
        print("strict guest release trust roots are configured")
    elif args.command == "verify-remote":
        verify_remote_sources(args)
        print("strict guest remote source objects are exact")
    elif args.command == "source-field":
        print_source_field(args)
    elif args.command == "builder-image":
        print_builder_image(args)
    elif args.command == "verify-checkouts":
        verify_checkouts(args)
    elif args.command == "emit-build-metadata":
        emit_build_metadata(args)
        print("strict guest canonical build metadata generated")
    elif args.command == "emit-sbom":
        emit_sbom(args)
        print("strict guest canonical SBOM generated")
    elif args.command == "emit-provenance":
        emit_provenance(args)
        print("strict guest unverified provenance candidate generated")
    elif args.command == "generate-candidate":
        generate_candidate(args)
        print("strict guest unverified candidate manifest generated")
    elif args.command == "compare-candidates":
        compare_candidates(args.left, args.right)
    else:  # pragma: no cover - argparse makes this unreachable
        raise ReleaseError("unknown command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseError, subprocess.TimeoutExpired) as error:
        print(f"strict guest release pipeline failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
