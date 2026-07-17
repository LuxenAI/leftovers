from __future__ import annotations

import fnmatch
import re
import stat
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path, PurePosixPath

from .config import MANDATORY_FORBID_PATHS, PolicyConfig, RepositoryConfig
from .models import IssueCandidate, ScoreBreakdown

_DEPENDENCY_FILES = {
    "Package.resolved",
    "Package.swift",
    "Pipfile",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "poetry.lock",
    "pdm.lock",
    "pylock.toml",
    "uv.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements.in",
    "requirements-dev.in",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "Gemfile",
    "Gemfile.lock",
    "Podfile",
    "Podfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.lockfile",
    "gradle-wrapper.properties",
    "libs.versions.toml",
    "mix.exs",
    "mix.lock",
    "pubspec.yaml",
    "pubspec.lock",
    "packages.lock.json",
    "Directory.Packages.props",
    "Directory.Build.props",
    "Directory.Build.targets",
    "packages.config",
    "global.json",
    "nuget.config",
    "flake.nix",
    "flake.lock",
    "environment.yml",
    "environment.yaml",
    "conda-lock.yml",
    "conda-lock.yaml",
    "deps.edn",
    "bb.edn",
    "project.clj",
    "build.boot",
    "shadow-cljs.edn",
    "vcpkg.json",
    "vcpkg-configuration.json",
    "conanfile.txt",
    "conanfile.py",
    "conan.lock",
    "paket.dependencies",
    "paket.lock",
    "CPANfile",
    "CPANfile.snapshot",
    "cpanfile",
    "Cartfile",
    "Cartfile.resolved",
    "Mintfile",
    "MODULE.bazel",
    "MODULE.bazel.lock",
    "WORKSPACE",
    "WORKSPACE.bazel",
    "build.sbt",
    "renv.lock",
    "Project.toml",
    "Manifest.toml",
    "stack.yaml",
    "stack.yaml.lock",
    "cabal.project",
    "cabal.project.freeze",
    "package.yaml",
    "elm.json",
    "rebar.config",
    "rebar.lock",
    "erlang.mk",
    "bower.json",
    "Gopkg.toml",
    "Gopkg.lock",
    "glide.yaml",
    "glide.lock",
}
_DEPENDENCY_FILE_PATTERNS = (
    "*.csproj",
    "*.fsproj",
    "*.vbproj",
    "*.cabal",
    "*.gemspec",
    "*.nuspec",
    "*.podspec",
    "*.sbt",
    "Gemfile.*",
    "requirements*.txt",
    "requirements*.in",
    "constraints*.txt",
    "constraints*.in",
)
_DEPENDENCY_PATH_PATTERNS = (
    "requirements/*.txt",
    "requirements/*.in",
    "**/requirements/*.txt",
    "**/requirements/*.in",
    "constraints/*.txt",
    "constraints/*.in",
    "**/constraints/*.txt",
    "**/constraints/*.in",
    "project/build.properties",
    "project/plugins.sbt",
    "**/project/build.properties",
    "**/project/plugins.sbt",
    "vendor/modules.txt",
    "**/vendor/modules.txt",
    "vendor/vendor.json",
    "**/vendor/vendor.json",
)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
_SENSITIVE_SCOPE = re.compile(
    r"\b(?:security|vulnerabilit(?:y|ies)|credential(?:s)?|private[ -]key|"
    r"auth(?:entication|orization)|cryptograph(?:y|ic)|exploit(?:ation)?|"
    r"CVE-\d+|CWE-\d+|XSS|cross[ -]site scripting|SQLi|SQL injection|"
    r"remote code execution|RCE|command injection|path traversal|directory traversal|"
    r"buffer overflow|use[ -]after[ -]free|privilege escalation|sandbox escape|"
    r"access[ -]control bypass|permission bypass|CSRF|SSRF|XXE|memory corruption|"
    r"(?:secret|token|password|api[ -]key)s?[ -](?:leak(?:ed|age|ing)?|"
    r"expos(?:ed|ure)|disclos(?:ed|ure))|"
    r"infrastructure|production access|abuse report|release pipeline|supply[ -]chain|"
    r"github actions?|workflow permissions?|legal|licens(?:e|ing)|copyright|trademark)\b",
    re.IGNORECASE,
)
_SENSITIVE_LABEL = re.compile(
    r"(?:^|[^a-z0-9])(?:security|vulnerability|cve|cwe|legal|credentials?|auth|crypto|"
    r"infrastructure|abuse|release)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)

_DANGEROUS_GIT_KEY = re.compile(
    r"^(?:"
    r"alias\.|credential\.|difftool\.|filter\.|gpg\.|include\.|includeif\.|"
    r"merge\.|mergetool\.|pager\.|url\.|"
    r"core\.(?:attributesfile|editor|fsmonitor|gitproxy|hookspath|pager|sshcommand|worktree)|"
    r"diff\.external$|diff\..+\.(?:cachetextconv|command|textconv)$|"
    r"interactive\.difffilter$|remote\..+\.(?:proxy|receivepack|uploadpack)$|"
    r"sequence\.editor$"
    r")",
    re.IGNORECASE,
)
_MAX_INSPECTED_PATHS = 100
_MAX_PATH_OUTPUT_BYTES = 256_000


class _GitInspectionLimit(RuntimeError):
    pass


def controller_git_env(workspace: Path) -> dict[str, str]:
    """Return a minimal Git environment isolated from host/user configuration."""

    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(workspace.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def controller_git_prefix() -> list[str]:
    """Return command-scoped overrides for every trusted controller Git call."""

    return [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "credential.helper=",
    ]


def _bounded_git_output(workspace: Path, argv: list[str], maximum: int) -> bytes:
    """Run trusted Git with a hard stdout limit and timeout."""

    import subprocess

    output = bytearray()
    overflowed = threading.Event()
    with tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            argv,
            cwd=workspace,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            env=controller_git_env(workspace),
        )
        assert process.stdout is not None

        def drain() -> None:
            while chunk := process.stdout.read(65_536):
                remaining = maximum + 1 - len(output)
                if remaining > 0:
                    output.extend(chunk[:remaining])
                if len(output) > maximum or len(chunk) > remaining:
                    overflowed.set()
                    with suppress(ProcessLookupError):
                        process.kill()
                    break

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            with suppress(ProcessLookupError):
                process.kill()
            process.wait()
            reader.join(timeout=5)
            raise _GitInspectionLimit("Git path inspection exceeded 30 seconds") from exc
        reader.join(timeout=5)
        process.stdout.close()
        if reader.is_alive():
            raise _GitInspectionLimit("Git path inspection output could not be bounded")
        stderr_file.seek(0)
        stderr = stderr_file.read(4_096).decode("utf-8", errors="replace")
    if overflowed.is_set():
        raise _GitInspectionLimit("Git path inspection exceeded its output limit")
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, argv, stderr=stderr)
    return bytes(output)


def _refused_inspection(reason: str) -> DiffInspection:
    return DiffInspection(
        files=(),
        added_lines=0,
        deleted_lines=0,
        patch="",
        structural_failures=(reason,),
    )


def unsafe_git_configuration(workspace: Path) -> tuple[str, ...]:
    """Inspect only the repository-local config without honoring includes."""

    import subprocess

    git_dir = workspace / ".git"
    config_path = git_dir / "config"
    try:
        git_info = git_dir.lstat()
        config_info = config_path.lstat()
    except OSError:
        return ("repository Git metadata is missing or unreadable",)
    if not stat.S_ISDIR(git_info.st_mode) or stat.S_ISLNK(git_info.st_mode):
        return ("repository .git metadata is not a real directory",)
    if (
        not stat.S_ISREG(config_info.st_mode)
        or stat.S_ISLNK(config_info.st_mode)
        or config_info.st_nlink != 1
    ):
        return ("repository local Git config is not a single regular file",)
    result = subprocess.run(
        [
            *controller_git_prefix(),
            "config",
            "--file",
            str(config_path),
            "--no-includes",
            "--null",
            "--list",
        ],
        cwd=workspace,
        capture_output=True,
        timeout=30,
        env=controller_git_env(workspace),
    )
    if result.returncode != 0:
        return ("repository local Git config could not be parsed safely",)
    dangerous: list[str] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        raw_name, separator, _ = record.partition(b"\n")
        if not separator:
            return ("repository local Git config has an invalid record",)
        name = raw_name.decode("utf-8", errors="replace")
        if _DANGEROUS_GIT_KEY.match(name):
            dangerous.append(name)
    return tuple(sorted(set(dangerous)))


@dataclass(frozen=True)
class DiffInspection:
    files: tuple[str, ...]
    added_lines: int
    deleted_lines: int
    patch: str
    patch_truncated: bool = False
    invalid_utf8: bool = False
    structural_failures: tuple[str, ...] = ()

    @property
    def changed_lines(self) -> int:
        return self.added_lines + self.deleted_lines


def _tree_modes(workspace: Path, revision: str, files: tuple[str, ...]) -> dict[str, str]:
    import subprocess

    if not files:
        return {}
    result = subprocess.run(
        [
            *controller_git_prefix(),
            "ls-tree",
            "-r",
            "-z",
            revision,
            "--",
            *files,
        ],
        cwd=workspace,
        capture_output=True,
        check=True,
        env=controller_git_env(workspace),
    )
    modes: dict[str, str] = {}
    for record in result.stdout.split(b"\0"):
        if not record or b"\t" not in record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii", errors="replace")
        modes[raw_path.decode("utf-8", errors="surrogateescape")] = mode
    return modes


def _worktree_modes(workspace: Path, files: tuple[str, ...]) -> dict[str, str]:
    modes: dict[str, str] = {}
    root = workspace.resolve()
    for filename in files:
        candidate = workspace / filename
        try:
            candidate.parent.resolve().relative_to(root)
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            modes[filename] = "unsafe"
            continue
        if stat.S_ISLNK(info.st_mode):
            modes[filename] = "120000"
        elif stat.S_ISREG(info.st_mode):
            executable = bool(info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            modes[filename] = "100755" if executable else "100644"
        elif stat.S_ISDIR(info.st_mode):
            modes[filename] = "040000"
        else:
            modes[filename] = "unsafe"
    return modes


def _mode_failures(
    files: tuple[str, ...],
    old_modes: dict[str, str],
    new_modes: dict[str, str],
) -> tuple[str, ...]:
    failures: list[str] = []
    for filename in files:
        old = old_modes.get(filename)
        new = new_modes.get(filename)
        if old == "120000" or new == "120000":
            failures.append(f"symbolic-link path changed: {filename}")
        if old == "160000" or new == "160000":
            failures.append(f"Git submodule link changed: {filename}")
        if new is not None and new not in {"100644", "100755", "120000", "160000"}:
            failures.append(f"non-regular path changed: {filename}")
        if new == "100755" and old != "100755":
            failures.append(f"executable bit added: {filename}")
        elif old in {"100644", "100755"} and new in {"100644", "100755"} and old != new:
            failures.append(f"executable bit changed: {filename}")
    return tuple(dict.fromkeys(failures))


def candidate_gate(
    issue: IssueCandidate,
    score: ScoreBreakdown,
    repository: RepositoryConfig,
    policy: PolicyConfig,
    minimum_score: int,
) -> tuple[str, ...]:
    failures: list[str] = []
    labels = {label.casefold() for label in issue.labels}
    denied = {label.casefold() for label in (*policy.deny_labels, *repository.deny_labels)}
    if issue.state != "open":
        failures.append("issue is not confirmed open")
    if issue.repo.archived or issue.repo.disabled:
        failures.append("repository is archived or disabled")
    if issue.repo.forking_allowed is not True:
        failures.append("repository forking permission is disabled or unconfirmed")
    if issue.repo.pull_requests_enabled is not True:
        failures.append("repository pull-request access is disabled or unconfirmed")
    if issue.repo.pull_request_creation_policy != "ALL":
        failures.append("repository does not confirm that anyone may create pull requests")
    if policy.require_license and issue.repo.license_spdx in {None, "", "NOASSERTION", "OTHER"}:
        failures.append("repository has no recognized license")
    if repository.allowed_licenses and issue.repo.license_spdx not in repository.allowed_licenses:
        failures.append(f"license {issue.repo.license_spdx!r} is not allowlisted")
    if issue.locked:
        failures.append("issue is locked")
    if policy.require_unassigned and issue.assignees:
        failures.append("issue is assigned")
    if policy.require_no_open_linked_pr and issue.has_open_linked_pr:
        failures.append("issue has an open linked or cross-referenced PR")
    if issue.has_recent_claim:
        failures.append("a contributor recently claimed or started this issue")
    blocked_labels = sorted(labels.intersection(denied))
    if blocked_labels:
        failures.append("denied label(s): " + ", ".join(blocked_labels))
    sensitive_labels = sorted(label for label in issue.labels if _SENSITIVE_LABEL.search(label))
    if sensitive_labels:
        failures.append("sensitive label(s): " + ", ".join(sensitive_labels))
    if _SENSITIVE_SCOPE.search(f"{issue.title}\n{issue.body}"):
        failures.append("issue text indicates a sensitive unattended scope")
    allowed = {label.casefold() for label in repository.allow_labels}
    if allowed and not labels.intersection(allowed):
        failures.append("issue does not have an allowlisted maintainer label")
    if not repository.test_commands:
        failures.append("repository has no operator-curated verification command")
    if repository.ai_contributions_allowed is not True:
        failures.append("repository AI-contribution policy is not explicitly allowlisted")
    else:
        try:
            checked_at = date.fromisoformat(repository.ai_policy_checked_at or "")
        except ValueError:
            failures.append("repository AI-policy evidence date is invalid")
        else:
            today = datetime.now(UTC).date()
            oldest = today - timedelta(days=policy.ai_policy_max_age_days)
            if checked_at < oldest or checked_at > today + timedelta(days=1):
                failures.append("repository AI-policy evidence is stale or future-dated")
        if not repository.ai_policy_url or not repository.ai_policy_url.startswith("https://"):
            failures.append("repository AI-policy evidence URL is missing or invalid")
    if score.total < minimum_score:
        failures.append(f"score {score.total} is below minimum {minimum_score}")
    return tuple(failures)


def inspect_diff(workspace: Path, max_patch_bytes: int = 1_000_000) -> DiffInspection:
    import subprocess

    dangerous_config = unsafe_git_configuration(workspace)
    if dangerous_config:
        detail = ", ".join(dangerous_config)
        return _refused_inspection(f"unsafe repository Git configuration: {detail}")
    safe_env = controller_git_env(workspace)
    git_prefix = controller_git_prefix()
    try:
        untracked_output = _bounded_git_output(
            workspace,
            [
                *git_prefix,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            _MAX_PATH_OUTPUT_BYTES,
        )
    except _GitInspectionLimit as exc:
        return _refused_inspection(str(exc))
    untracked = [
        item.decode(errors="surrogateescape") for item in untracked_output.split(b"\0") if item
    ]
    if len(untracked) > _MAX_INSPECTED_PATHS:
        return _refused_inspection(f"untracked path count exceeds {_MAX_INSPECTED_PATHS}")
    if untracked:
        subprocess.run(
            [*git_prefix, "add", "-N", "--", *untracked],
            cwd=workspace,
            capture_output=True,
            check=True,
            env=safe_env,
            timeout=30,
        )

    try:
        name_output = _bounded_git_output(
            workspace,
            [
                *git_prefix,
                "diff",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "HEAD",
            ],
            _MAX_PATH_OUTPUT_BYTES,
        )
    except _GitInspectionLimit as exc:
        return _refused_inspection(str(exc))
    files = tuple(
        item.decode("utf-8", errors="surrogateescape") for item in name_output.split(b"\0") if item
    )
    if len(files) > _MAX_INSPECTED_PATHS:
        return _refused_inspection(f"changed path count exceeds {_MAX_INSPECTED_PATHS}")
    try:
        numstat_output = _bounded_git_output(
            workspace,
            [
                *git_prefix,
                "diff",
                "--numstat",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "HEAD",
            ],
            _MAX_PATH_OUTPUT_BYTES,
        )
    except _GitInspectionLimit as exc:
        return _refused_inspection(str(exc))
    added = deleted = 0
    for record in numstat_output.split(b"\0"):
        parts = record.split(b"\t", 2)
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            added += int(parts[0].decode())
            deleted += int(parts[1].decode())
        elif len(parts) >= 2:
            # Binary files are represented by '-'. Give them an effectively fatal size.
            added += 1_000_000
    with tempfile.TemporaryFile() as stderr_file:
        patch_process = subprocess.Popen(
            [
                *git_prefix,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--binary",
                "HEAD",
            ],
            cwd=workspace,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            env=safe_env,
        )
        assert patch_process.stdout is not None
        patch_bytes = patch_process.stdout.read(max_patch_bytes + 1)
        patch_process.stdout.close()
        truncated = len(patch_bytes) > max_patch_bytes
        if truncated:
            patch_process.kill()
        return_code = patch_process.wait()
        stderr_file.seek(0)
        stderr = stderr_file.read().decode("utf-8", errors="replace")
    if return_code != 0 and not truncated:
        raise subprocess.CalledProcessError(return_code, "git diff", stderr=stderr)
    raw_patch = patch_bytes[:max_patch_bytes]
    try:
        patch = raw_patch.decode("utf-8")
        invalid_utf8 = False
    except UnicodeDecodeError:
        patch = raw_patch.decode("utf-8", errors="replace")
        invalid_utf8 = True
    old_modes = _tree_modes(workspace, "HEAD", files)
    new_modes = _worktree_modes(workspace, files)
    return DiffInspection(
        files=files,
        added_lines=added,
        deleted_lines=deleted,
        patch=patch,
        patch_truncated=truncated,
        invalid_utf8=invalid_utf8,
        structural_failures=_mode_failures(files, old_modes, new_modes),
    )


def inspect_committed_diff(
    workspace: Path,
    base_sha: str,
    max_patch_bytes: int = 1_000_000,
) -> DiffInspection:
    """Inspect exactly the committed base..HEAD tree without consulting the worktree."""
    import subprocess

    if re.fullmatch(r"[0-9a-fA-F]{40,64}", base_sha) is None:
        raise ValueError("base SHA is not a full hexadecimal object identifier")
    dangerous_config = unsafe_git_configuration(workspace)
    if dangerous_config:
        raise ValueError("unsafe repository Git configuration: " + ", ".join(dangerous_config))
    safe_env = controller_git_env(workspace)
    prefix = [
        *controller_git_prefix(),
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
    ]
    try:
        name_output = _bounded_git_output(
            workspace,
            [*prefix, "--name-only", "-z", base_sha, "HEAD", "--"],
            _MAX_PATH_OUTPUT_BYTES,
        )
    except _GitInspectionLimit as exc:
        return _refused_inspection(str(exc))
    files = tuple(
        item.decode("utf-8", errors="surrogateescape") for item in name_output.split(b"\0") if item
    )
    if len(files) > _MAX_INSPECTED_PATHS:
        return _refused_inspection(f"changed path count exceeds {_MAX_INSPECTED_PATHS}")
    try:
        numstat_output = _bounded_git_output(
            workspace,
            [*prefix, "--numstat", "-z", base_sha, "HEAD", "--"],
            _MAX_PATH_OUTPUT_BYTES,
        )
    except _GitInspectionLimit as exc:
        return _refused_inspection(str(exc))
    added = deleted = 0
    for record in numstat_output.split(b"\0"):
        parts = record.split(b"\t", 2)
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            added += int(parts[0].decode())
            deleted += int(parts[1].decode())
        elif len(parts) >= 2:
            added += 1_000_000
    with tempfile.TemporaryFile() as stderr_file:
        patch_process = subprocess.Popen(
            [*prefix, "--binary", base_sha, "HEAD", "--"],
            cwd=workspace,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            env=safe_env,
        )
        assert patch_process.stdout is not None
        patch_bytes = patch_process.stdout.read(max_patch_bytes + 1)
        patch_process.stdout.close()
        truncated = len(patch_bytes) > max_patch_bytes
        if truncated:
            patch_process.kill()
        return_code = patch_process.wait()
        stderr_file.seek(0)
        stderr = stderr_file.read().decode("utf-8", errors="replace")
    if return_code != 0 and not truncated:
        raise subprocess.CalledProcessError(return_code, "git diff", stderr=stderr)
    raw_patch = patch_bytes[:max_patch_bytes]
    try:
        patch = raw_patch.decode("utf-8")
        invalid_utf8 = False
    except UnicodeDecodeError:
        patch = raw_patch.decode("utf-8", errors="replace")
        invalid_utf8 = True
    old_modes = _tree_modes(workspace, base_sha, files)
    new_modes = _tree_modes(workspace, "HEAD", files)
    return DiffInspection(
        files=files,
        added_lines=added,
        deleted_lines=deleted,
        patch=patch,
        patch_truncated=truncated,
        invalid_utf8=invalid_utf8,
        structural_failures=_mode_failures(files, old_modes, new_modes),
    )


def diff_gate(
    diff: DiffInspection, repository: RepositoryConfig, policy: PolicyConfig
) -> tuple[str, ...]:
    failures: list[str] = []
    failures.extend(diff.structural_failures)
    max_files = min(
        repository.max_changed_files or policy.max_changed_files,
        policy.max_changed_files,
    )
    max_lines = min(
        repository.max_changed_lines or policy.max_changed_lines,
        policy.max_changed_lines,
    )
    if not diff.files:
        failures.append("agent produced no tracked changes")
    if len(diff.files) > max_files:
        failures.append(f"changed {len(diff.files)} files; limit is {max_files}")
    if diff.changed_lines > max_lines:
        failures.append(f"changed {diff.changed_lines} lines; limit is {max_lines}")
    if diff.patch_truncated or len(diff.patch.encode()) > policy.max_patch_bytes:
        failures.append(f"patch exceeds {policy.max_patch_bytes} byte limit")
    if diff.invalid_utf8:
        failures.append("patch contains invalid UTF-8 text")
    patterns = (
        *MANDATORY_FORBID_PATHS,
        *policy.forbid_paths,
        *repository.forbid_paths,
    )
    for filename in diff.files:
        try:
            filename.encode("utf-8")
        except UnicodeEncodeError:
            failures.append(f"changed path is not valid UTF-8: {filename!r}")
        if any(ord(character) < 32 or ord(character) == 127 for character in filename):
            failures.append(f"control character in changed path: {filename!r}")
        if filename == ".git" or filename.startswith(".git/"):
            failures.append("changes to .git are forbidden")
        if any(
            fnmatch.fnmatch(filename, pattern) or PurePosixPath(filename).match(pattern)
            for pattern in patterns
        ):
            failures.append(f"forbidden path changed: {filename}")
        basename = Path(filename).name
        if policy.forbid_dependency_changes and (
            basename in _DEPENDENCY_FILES
            or any(fnmatch.fnmatch(basename, pattern) for pattern in _DEPENDENCY_FILE_PATTERNS)
            or any(
                fnmatch.fnmatch(filename, pattern) or PurePosixPath(filename).match(pattern)
                for pattern in _DEPENDENCY_PATH_PATTERNS
            )
        ):
            failures.append(f"dependency manifest or lockfile changed: {filename}")
    if "GIT binary patch" in diff.patch or "Binary files " in diff.patch:
        failures.append("binary changes are forbidden")
    if re.search(r"(?:new file mode|old mode|new mode) 120000", diff.patch):
        failures.append("symbolic-link changes are forbidden")
    if re.search(r"(?:new file mode|old mode|new mode) 160000", diff.patch):
        failures.append("Git submodule links are forbidden")
    if re.search(r"(?:new file mode|old mode|new mode) 100755", diff.patch):
        failures.append("executable-bit changes are forbidden")
    if any(pattern.search(diff.patch) for pattern in _SECRET_PATTERNS):
        failures.append("patch resembles a credential or private key")
    return tuple(dict.fromkeys(failures))
