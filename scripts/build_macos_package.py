#!/usr/bin/env python3
"""Build a reproducible source bundle for the macOS preview installer."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
from contextlib import suppress
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
PACKAGE_NAME = f"leftovers-macos-preview-v{VERSION}"
DEFAULT_OUTPUT = ROOT / ".leftovers" / "dist" / f"{PACKAGE_NAME}.tar.gz"
# 1980-01-02 UTC remains at or after ZIP's 1980 minimum in every civil timezone.
REPRODUCIBLE_MTIME = 315_619_200
TOP_LEVEL_FILES = (
    "AGENTS.md",
    "ARCHITECTURE.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "Makefile",
    "PROTOCOL.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
)
TREE_ROOTS = ("config", "docs", "sandbox", "schemas", "src", "vm")
SCRIPT_FILES = (
    "build_macos_package.py",
    "codex_adapter.py",
    "install-macos.sh",
    "install_macos.py",
    "macos_job.py",
    "rehearsal_agent.py",
    "status-macos.sh",
    "status_macos.py",
    "uninstall-macos.sh",
    "uninstall_macos.py",
    "verify_macos_package.py",
)
EXECUTABLE_TREE_FILES = (
    "vm/check.sh",
    "vm/smoke_init.sh",
)


class PackageError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the portable Leftovers macOS bundle")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def _source_files() -> tuple[Path, ...]:
    paths = [ROOT / name for name in TOP_LEVEL_FILES]
    paths.extend(ROOT / "scripts" / name for name in SCRIPT_FILES)
    for tree_name in TREE_ROOTS:
        tree_root = ROOT / tree_name
        if tree_root.is_symlink() or not tree_root.is_dir():
            raise PackageError(f"required package tree is missing or unsafe: {tree_root}")
        paths.extend(
            path
            for path in tree_root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    unique = tuple(sorted(set(paths), key=lambda path: path.relative_to(ROOT).as_posix()))
    for path in unique:
        if path.is_symlink() or not path.is_file():
            raise PackageError(f"required package source is missing or unsafe: {path}")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PackageError(f"required package source is not a single-link file: {path}")
    return unique


def _mode(path: Path) -> int:
    if path.parent.name == "scripts" and path.name in SCRIPT_FILES:
        return 0o700
    if path.relative_to(ROOT).as_posix() in EXECUTABLE_TREE_FILES:
        return 0o700
    return 0o600


def _tar_info(name: str, payload: bytes, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = len(payload)
    info.mode = mode
    info.mtime = REPRODUCIBLE_MTIME
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    return info


def _manifest(files: tuple[Path, ...]) -> tuple[bytes, dict[str, Any]]:
    entries = []
    for path in files:
        payload = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "mode": f"{_mode(path):04o}",
            }
        )
    manifest = {
        "format_version": 1,
        "package": "leftovers-macos-preview",
        "version": VERSION,
        "entrypoint": "scripts/install-macos.sh",
        "publication_default": "disabled",
        "files": entries,
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), manifest


def _verify_archive(path: Path, expected: dict[str, Any]) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if any(
            member.issym()
            or member.islnk()
            or member.name.startswith("/")
            or ".." in Path(member.name).parts
            for member in members
        ):
            raise PackageError("package archive contains an unsafe member")
        manifest_name = f"{PACKAGE_NAME}/PACKAGE-MANIFEST.json"
        manifest_member = archive.getmember(manifest_name)
        stream = archive.extractfile(manifest_member)
        if stream is None:
            raise PackageError("package archive manifest is unreadable")
        try:
            observed = json.load(stream)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PackageError("package archive manifest is invalid") from exc
        if observed != expected:
            raise PackageError("package archive manifest does not match the build input")
        for entry in expected["files"]:
            member = archive.getmember(f"{PACKAGE_NAME}/{entry['path']}")
            payload_stream = archive.extractfile(member)
            if payload_stream is None:
                raise PackageError(f"package member is unreadable: {entry['path']}")
            payload = payload_stream.read()
            if (
                hashlib.sha256(payload).hexdigest() != entry["sha256"]
                or len(payload) != entry["bytes"]
                or f"{member.mode:04o}" != entry["mode"]
            ):
                raise PackageError(f"package member failed verification: {entry['path']}")


def _write_archive(raw: Any, files: tuple[Path, ...], manifest_bytes: bytes) -> None:
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        archive.addfile(
            _tar_info(
                f"{PACKAGE_NAME}/PACKAGE-MANIFEST.json",
                manifest_bytes,
                0o600,
            ),
            io.BytesIO(manifest_bytes),
        )
        for path in files:
            payload = path.read_bytes()
            name = f"{PACKAGE_NAME}/{path.relative_to(ROOT).as_posix()}"
            archive.addfile(_tar_info(name, payload, _mode(path)), io.BytesIO(payload))


def build(output: Path) -> dict[str, Any]:
    output = Path(os.path.abspath(os.fspath(output.expanduser())))
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.is_symlink():
        raise PackageError("package output may not be a symlink")
    files = _source_files()
    manifest_bytes, manifest = _manifest(files)
    temporary = output.parent / f".{output.name}.{os.getpid()}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise PackageError("temporary package output already exists")
    try:
        with temporary.open("xb") as raw:
            _write_archive(raw, files, manifest_bytes)
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
    except (OSError, tarfile.TarError) as exc:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise PackageError(f"could not build macOS package: {exc}") from exc
    _verify_archive(output, manifest)
    return {
        "package": manifest["package"],
        "version": VERSION,
        "archive": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "files": len(files),
        "verified": True,
    }


def main(argv: list[str] | None = None) -> int:
    result = build(_parser().parse_args(argv).output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PackageError as exc:
        print(json.dumps({"error": "PackageError", "message": str(exc)}))
        raise SystemExit(2) from None
