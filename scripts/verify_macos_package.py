#!/usr/bin/env python3
"""Verify an extracted portable macOS package before invoking its installer.

Without ``--archive``, this checks internal consistency only: a manifest shipped
inside the package can be replaced together with its payload.  With both archive
arguments, it hashes the archive bytes, validates their bounded tar member set,
and requires the extracted tree to match that exact archive.  The supplied digest
must still come from an independently trusted release channel.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_NAME = "PACKAGE-MANIFEST.json"
MANAGED_STATE_NAME = ".leftovers"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MODE = re.compile(r"0[0-7]{3}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2_048
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


class PackageVerificationError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify an extracted Leftovers macOS package before installation"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-sha256")
    return parser


def _lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _require_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise PackageVerificationError(
                f"package path component is missing or unreadable: {current}"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise PackageVerificationError(f"package path contains a symlink: {current}")


def _safe_manifest_path(value: object) -> str:
    if not isinstance(value, str):
        raise PackageVerificationError("package manifest contains a non-string path")
    candidate = PurePosixPath(value)
    if (
        not value
        or candidate.is_absolute()
        or value != candidate.as_posix()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or value == MANIFEST_NAME
    ):
        raise PackageVerificationError(f"package manifest contains an unsafe path: {value!r}")
    return value


def _read_manifest(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest_path = root / MANIFEST_NAME
    try:
        info = manifest_path.lstat()
    except FileNotFoundError as exc:
        raise PackageVerificationError("package manifest is missing") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        raise PackageVerificationError("package manifest is not a single-link regular file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise PackageVerificationError("package manifest mode is not owner-only 0600")
    if info.st_size < 1 or info.st_size > MAX_MANIFEST_BYTES:
        raise PackageVerificationError("package manifest is outside its size bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(manifest_path, flags)
    except OSError as exc:
        raise PackageVerificationError("package manifest could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            raise PackageVerificationError("package manifest changed before reading")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise PackageVerificationError("package manifest could not be read safely") from exc
    finally:
        os.close(descriptor)
    if len(payload) > MAX_MANIFEST_BYTES or len(payload) != opened.st_size:
        raise PackageVerificationError("package manifest changed size while reading")
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ):
        raise PackageVerificationError("package manifest changed while reading")
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageVerificationError("package manifest is unreadable or invalid JSON") from exc
    if not isinstance(decoded, dict) or set(decoded) != {
        "format_version",
        "package",
        "version",
        "entrypoint",
        "publication_default",
        "files",
    }:
        raise PackageVerificationError("package manifest has an unexpected format")
    if (
        decoded["format_version"] != 1
        or decoded["package"] != "leftovers-macos-preview"
        or not isinstance(decoded["version"], str)
        or _VERSION.fullmatch(decoded["version"]) is None
        or decoded["entrypoint"] != "scripts/install-macos.sh"
        or decoded["publication_default"] != "disabled"
        or not isinstance(decoded["files"], list)
        or not decoded["files"]
        or len(decoded["files"]) > MAX_ARCHIVE_MEMBERS - 1
    ):
        raise PackageVerificationError("package manifest does not identify a safe preview package")

    entries: list[dict[str, Any]] = []
    paths: list[str] = []
    aggregate_bytes = 0
    for entry in decoded["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes", "mode"}:
            raise PackageVerificationError("package manifest contains an invalid file entry")
        path = _safe_manifest_path(entry["path"])
        digest = entry["sha256"]
        size = entry["bytes"]
        mode = entry["mode"]
        if (
            not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_ARCHIVE_MEMBER_BYTES
            or not isinstance(mode, str)
            or _MODE.fullmatch(mode) is None
        ):
            raise PackageVerificationError(f"package manifest has invalid metadata for {path}")
        aggregate_bytes += size
        if aggregate_bytes > MAX_ARCHIVE_PAYLOAD_BYTES:
            raise PackageVerificationError("package manifest payload exceeds its size bound")
        entries.append({"path": path, "sha256": digest, "bytes": size, "mode": mode})
        paths.append(path)
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise PackageVerificationError("package manifest paths are not unique and sorted")
    return entries, decoded


def _payload_paths(root: Path) -> tuple[set[str], set[str]]:
    """Collect every payload path without following directory entries."""

    files: set[str] = set()
    directories: set[str] = set()

    def scan(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise PackageVerificationError(
                f"could not scan package directory: {directory}"
            ) from exc
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise PackageVerificationError(
                    f"could not inspect package member: {relative}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                raise PackageVerificationError(f"package contains a symlink payload: {relative}")
            if relative == MANAGED_STATE_NAME:
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                ):
                    raise PackageVerificationError(
                        "package managed-state directory is not owner-private 0700"
                    )
                # The installer deliberately owns mutable state below this one exact,
                # root-level directory. Source payload verification must remain stable
                # across reinstall, relaunch, and later --verify-oci invocations.
                continue
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise PackageVerificationError(
                        f"package directory is not current-user-owned 0700: {relative}"
                    )
                directories.add(relative)
                scan(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_uid != os.getuid():
                    raise PackageVerificationError(
                        f"package member is not current-user-owned: {relative}"
                    )
                files.add(relative)
            else:
                raise PackageVerificationError(f"package contains an unsafe payload: {relative}")

    scan(root)
    return files, directories


def _hash_regular_file(path: Path, expected: dict[str, Any]) -> None:
    try:
        before = path.lstat()
    except OSError as exc:
        raise PackageVerificationError(f"package member is missing: {expected['path']}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid():
        raise PackageVerificationError(
            f"package member is not a current-user-owned single-link file: {expected['path']}"
        )
    if stat.S_IMODE(before.st_mode) != int(expected["mode"], 8):
        raise PackageVerificationError(f"package member mode mismatch: {expected['path']}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackageVerificationError(
            f"could not open package member: {expected['path']}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise PackageVerificationError(
                f"package member changed while reading: {expected['path']}"
            )
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (after.st_dev, after.st_ino, after.st_size) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
    ):
        raise PackageVerificationError(f"package member changed while reading: {expected['path']}")
    if size != expected["bytes"] or digest.hexdigest() != expected["sha256"]:
        raise PackageVerificationError(
            f"package member digest or size mismatch: {expected['path']}"
        )


def _read_verified_archive(path: Path, expected_digest: str) -> tuple[str, bytes]:
    if _SHA256.fullmatch(expected_digest) is None:
        raise PackageVerificationError(
            "external archive SHA-256 must be 64 lowercase hexadecimal characters"
        )
    path = _lexical(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise PackageVerificationError("external archive is missing") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PackageVerificationError("external archive is not a single-link regular file")
    if info.st_size < 1 or info.st_size > MAX_ARCHIVE_BYTES:
        raise PackageVerificationError("external archive is outside its compressed size bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackageVerificationError("could not open external archive") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            info.st_dev,
            info.st_ino,
        ):
            raise PackageVerificationError("external archive changed before reading")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_ARCHIVE_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_ARCHIVE_BYTES or len(payload) != opened.st_size:
        raise PackageVerificationError("external archive changed size while reading")
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ):
        raise PackageVerificationError("external archive changed while reading")
    observed = hashlib.sha256(payload).hexdigest()
    if observed != expected_digest:
        raise PackageVerificationError(
            "external archive SHA-256 does not match the supplied digest"
        )
    return observed, payload


def _verify_archive_tree_binding(
    payload: bytes,
    *,
    root: Path,
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
) -> None:
    expected_prefix = f"leftovers-macos-preview-v{manifest['version']}"
    expected_entries = {entry["path"]: entry for entry in entries}
    observed: dict[str, dict[str, Any]] = {}
    manifest_payload: bytes | None = None
    total_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for count, member in enumerate(archive, start=1):
                if count > MAX_ARCHIVE_MEMBERS:
                    raise PackageVerificationError("external archive has too many members")
                candidate = PurePosixPath(member.name)
                if (
                    candidate.is_absolute()
                    or candidate.as_posix() != member.name
                    or len(candidate.parts) < 2
                    or candidate.parts[0] != expected_prefix
                    or any(part in {"", ".", ".."} for part in candidate.parts)
                ):
                    raise PackageVerificationError(
                        f"external archive contains an unsafe path: {member.name!r}"
                    )
                if not member.isfile() or member.issym() or member.islnk():
                    raise PackageVerificationError(
                        f"external archive contains a non-regular member: {member.name}"
                    )
                relative = PurePosixPath(*candidate.parts[1:]).as_posix()
                if relative != MANIFEST_NAME:
                    _safe_manifest_path(relative)
                if relative in observed:
                    raise PackageVerificationError(
                        f"external archive contains a duplicate member: {relative}"
                    )
                if member.size < 0 or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise PackageVerificationError(
                        f"external archive member is outside its size bound: {relative}"
                    )
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_PAYLOAD_BYTES:
                    raise PackageVerificationError(
                        "external archive payload exceeds its size bound"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise PackageVerificationError(
                        f"external archive member is unreadable: {relative}"
                    )
                content = stream.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(content) != member.size:
                    raise PackageVerificationError(
                        f"external archive member changed size while reading: {relative}"
                    )
                observed[relative] = {
                    "path": relative,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "bytes": len(content),
                    "mode": f"{stat.S_IMODE(member.mode):04o}",
                }
                if relative == MANIFEST_NAME:
                    manifest_payload = content
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise PackageVerificationError("external archive is unreadable or malformed") from exc

    expected_paths = {MANIFEST_NAME, *expected_entries}
    if set(observed) != expected_paths:
        missing = expected_paths - set(observed)
        extra = set(observed) - expected_paths
        detail = sorted(missing or extra)[0]
        raise PackageVerificationError(f"external archive member set mismatch: {detail}")
    if manifest_payload is None or observed[MANIFEST_NAME]["mode"] != "0600":
        raise PackageVerificationError("external archive manifest is missing or has an unsafe mode")
    for path, expected in expected_entries.items():
        if observed[path] != expected:
            raise PackageVerificationError(f"external archive member mismatch: {path}")

    _hash_regular_file(
        root / MANIFEST_NAME,
        {
            "path": MANIFEST_NAME,
            "sha256": hashlib.sha256(manifest_payload).hexdigest(),
            "bytes": len(manifest_payload),
            "mode": "0600",
        },
    )


def verify(
    root: Path, *, archive: Path | None = None, archive_sha256: str | None = None
) -> dict[str, Any]:
    """Fail closed unless the extracted payload exactly matches its manifest."""

    if (archive is None) != (archive_sha256 is None):
        raise PackageVerificationError(
            "external archive verification requires both an archive path and SHA-256"
        )
    root = _lexical(root)
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise PackageVerificationError("package root is missing or cannot be resolved") from exc
    _require_no_symlink_components(root)
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise PackageVerificationError("package root is missing") from exc
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != os.getuid()
        or stat.S_IMODE(root_info.st_mode) != 0o700
    ):
        raise PackageVerificationError("package root is not a current-user-owned 0700 directory")
    entries, manifest = _read_manifest(root)
    if any(PurePosixPath(entry["path"]).parts[0] == MANAGED_STATE_NAME for entry in entries):
        raise PackageVerificationError("package manifest overlaps the managed-state directory")
    expected_paths = {MANIFEST_NAME, *(entry["path"] for entry in entries)}
    expected_directories = {
        parent.as_posix()
        for entry in entries
        for parent in PurePosixPath(entry["path"]).parents
        if parent != PurePosixPath(".")
    }
    observed_paths, observed_directories = _payload_paths(root)
    missing = expected_paths - observed_paths
    extra = observed_paths - expected_paths
    if missing:
        raise PackageVerificationError(f"package is missing manifest payload: {sorted(missing)[0]}")
    if extra:
        raise PackageVerificationError(f"package contains an extra payload: {sorted(extra)[0]}")
    extra_directories = observed_directories - expected_directories
    if extra_directories:
        raise PackageVerificationError(
            f"package contains an extra directory: {sorted(extra_directories)[0]}"
        )
    for entry in entries:
        _hash_regular_file(root / entry["path"], entry)
    result: dict[str, Any] = {
        "root": str(root),
        "files": len(entries),
        "internal_consistency": "verified",
        "authenticity": "not-established-by-package-manifest",
    }
    if archive is not None and archive_sha256 is not None:
        observed_digest, archive_payload = _read_verified_archive(archive, archive_sha256)
        _verify_archive_tree_binding(
            archive_payload,
            root=root,
            manifest=manifest,
            entries=entries,
        )
        result["external_archive_sha256"] = observed_digest
        result["external_digest"] = "matched-supplied-value"
        result["archive_tree_binding"] = "verified"
        result["authenticity"] = "bound-to-supplied-archive-digest"
    return result


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    print(
        json.dumps(
            verify(args.root, archive=args.archive, archive_sha256=args.archive_sha256),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PackageVerificationError as exc:
        print(json.dumps({"error": "PackageVerificationError", "message": str(exc)}))
        raise SystemExit(2) from None
