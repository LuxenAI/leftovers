from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from contextlib import AbstractContextManager
from datetime import timedelta
from pathlib import Path
from typing import Any

from .models import isoformat, utc_now
from .runner import execute


class WorkspaceError(RuntimeError):
    pass


def _is_descendant(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


class WorkspaceLease(AbstractContextManager["WorkspaceLease"]):
    def __init__(self, temp_root: Path, run_id: str, retain: bool = False):
        self.root = temp_root.expanduser().resolve()
        self.run_id = run_id
        self.retain = retain
        self.path: Path | None = None
        self.repo_path: Path | None = None

    def __enter__(self) -> WorkspaceLease:
        self.root.mkdir(parents=True, exist_ok=True)
        created = Path(tempfile.mkdtemp(prefix="leftovers-", dir=self.root))
        try:
            self.path = created.resolve()
            if not _is_descendant(self.path, self.root):
                raise WorkspaceError("temporary workspace escaped configured root")
            marker = {
                "managed_by": "leftovers",
                "run_id": self.run_id,
                "created_at": isoformat(utc_now()),
            }
            (self.path / ".leftovers-lease.json").write_text(json.dumps(marker, indent=2) + "\n")
            self.repo_path = self.path / "repo"
            return self
        except BaseException as setup_error:
            # The normal cleanup path intentionally requires a marker. If marker
            # creation itself fails, remove only the exact directory mkdtemp
            # returned while it is still a verified child of the configured root.
            cleanup_error: OSError | None = None
            if created.name.startswith("leftovers-") and created.parent.resolve() == self.root:
                try:
                    shutil.rmtree(created)
                except OSError as exc:
                    cleanup_error = exc
            if cleanup_error is None and not created.exists():
                self.path = None
            else:
                self.path = created.resolve()
            self.repo_path = None
            if self.path is not None:
                raise WorkspaceError(
                    "workspace lease initialization failed and unmarked workspace cleanup "
                    f"could not be proven: {self.path}"
                ) from (cleanup_error or setup_error)
            raise

    def clone(self, slug: str, branch: str) -> Path:
        if not self.path or not self.repo_path:
            raise WorkspaceError("workspace lease is not active")
        if slug.count("/") != 1 or any(part in slug for part in ("..", "@", ":")):
            raise WorkspaceError("invalid GitHub repository slug")
        isolated_home = self.path / "home"
        isolated_home.mkdir(mode=0o700)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(isolated_home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
        argv = [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "clone",
            "--depth=1",
            "--no-tags",
            "--single-branch",
            "--branch",
            branch,
            f"https://github.com/{slug}.git",
            str(self.repo_path),
        ]
        result = execute(
            argv,
            cwd=None,
            env=env,
            stdin=None,
            timeout=300,
            max_output_bytes=2_000,
        )
        if not result.passed:
            raise WorkspaceError(f"git clone failed: {result.stderr_tail[-2000:]}")
        return self.repo_path

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if self.path and not self.retain:
            self.cleanup()
        return False

    def cleanup(self) -> None:
        if not self.path:
            return
        if not _is_descendant(self.path, self.root) or not self.path.name.startswith("leftovers-"):
            raise WorkspaceError("refusing to remove a path outside the managed workspace root")
        marker = self.path / ".leftovers-lease.json"
        if not marker.is_file():
            raise WorkspaceError("refusing to remove a workspace without a Leftovers lease marker")

        def on_error(function: Any, path: str, exc: Any) -> None:
            os.chmod(path, stat.S_IRWXU)
            function(path)

        shutil.rmtree(self.path, onerror=on_error)


def reap_expired(
    temp_root: Path,
    older_than_hours: int,
    protected_run_ids: set[str] | None = None,
) -> list[Path]:
    root = temp_root.expanduser().resolve()
    if older_than_hours < 1:
        raise WorkspaceError("reaper age must be at least one hour")
    cutoff = utc_now() - timedelta(hours=older_than_hours)
    protected = protected_run_ids or set()
    removed: list[Path] = []
    if not root.exists():
        return removed
    for candidate in root.glob("leftovers-*"):
        marker = candidate / ".leftovers-lease.json"
        if not candidate.is_dir() or not marker.is_file() or not _is_descendant(candidate, root):
            continue
        try:
            data = json.loads(marker.read_text())
            created = data.get("created_at", "").replace("Z", "+00:00")
            from datetime import datetime

            created_at = datetime.fromisoformat(created)
            if created_at.tzinfo is None:
                continue
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if (
            data.get("managed_by") == "leftovers"
            and data.get("run_id") not in protected
            and created_at < cutoff
        ):
            lease = WorkspaceLease(root, data.get("run_id", "reaper"))
            lease.path = candidate
            lease.cleanup()
            removed.append(candidate)
    return removed
