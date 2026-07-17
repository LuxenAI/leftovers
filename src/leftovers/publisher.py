from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from .audit import redact
from .config import PublicationConfig
from .models import IssueCandidate, isoformat, utc_now
from .policy import (
    DiffInspection,
    controller_git_env,
    controller_git_prefix,
    inspect_committed_diff,
    inspect_diff,
    unsafe_git_configuration,
)


class PublicationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ApprovalBundle:
    run_id: str
    repository: str
    issue_number: int
    base_ref: str
    base_sha: str
    patch_sha256: str
    policy_hash: str
    approved_at: str
    expires_at: str
    bundle_hash: str


@dataclass(frozen=True)
class PublishResult:
    branch: str
    commit_sha: str
    pr_url: str


def create_approval_bundle(
    *,
    run_id: str,
    issue: IssueCandidate,
    base_sha: str,
    base_ref: str,
    diff: DiffInspection,
    policy_document: dict[str, object],
) -> ApprovalBundle:
    approved_at = utc_now()
    values = {
        "run_id": run_id,
        "repository": issue.repo.slug,
        "issue_number": issue.number,
        "base_ref": base_ref,
        "base_sha": base_sha,
        "patch_sha256": hashlib.sha256(diff.patch.encode()).hexdigest(),
        "policy_hash": hashlib.sha256(
            json.dumps(policy_document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "approved_at": isoformat(approved_at),
        "expires_at": isoformat(approved_at + timedelta(minutes=30)),
    }
    bundle_hash = hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ApprovalBundle(**values, bundle_hash=bundle_hash)


def validate_approval(
    bundle: ApprovalBundle,
    workspace: Path,
    *,
    issue: IssueCandidate | None = None,
    base_branch: str | None = None,
) -> None:
    _validate_approval_metadata(bundle, issue=issue, base_branch=base_branch)
    if unsafe_git_configuration(workspace):
        raise PublicationError("repository contains unsafe local Git configuration")
    head = _safe_head(workspace)
    if head != bundle.base_sha:
        raise PublicationError("local Git HEAD does not match the approved base SHA")
    current = inspect_diff(workspace)
    digest = hashlib.sha256(current.patch.encode()).hexdigest()
    if digest != bundle.patch_sha256:
        raise PublicationError("workspace patch no longer matches the approved patch")


def _validate_approval_metadata(
    bundle: ApprovalBundle,
    *,
    issue: IssueCandidate | None = None,
    base_branch: str | None = None,
) -> None:
    from datetime import datetime

    if datetime.fromisoformat(bundle.expires_at.replace("Z", "+00:00")) <= utc_now():
        raise PublicationError("approval bundle expired")
    if issue and (bundle.repository != issue.repo.slug or bundle.issue_number != issue.number):
        raise PublicationError("approval bundle target does not match the publication target")
    if base_branch is not None and bundle.base_ref != base_branch:
        raise PublicationError("approval bundle base branch does not match the publication target")
    values = {
        "run_id": bundle.run_id,
        "repository": bundle.repository,
        "issue_number": bundle.issue_number,
        "base_ref": bundle.base_ref,
        "base_sha": bundle.base_sha,
        "patch_sha256": bundle.patch_sha256,
        "policy_hash": bundle.policy_hash,
        "approved_at": bundle.approved_at,
        "expires_at": bundle.expires_at,
    }
    digest = hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if digest != bundle.bundle_hash:
        raise PublicationError("approval bundle integrity check failed")


def _safe_head(workspace: Path) -> str:
    head = subprocess.run(
        [*controller_git_prefix(), "rev-parse", "HEAD"],
        cwd=workspace,
        text=True,
        capture_output=True,
        timeout=30,
        env=controller_git_env(workspace),
    )
    if head.returncode != 0:
        raise PublicationError("could not resolve the local Git HEAD")
    return head.stdout.strip()


def validate_committed_approval(
    bundle: ApprovalBundle,
    workspace: Path,
    commit_sha: str,
    *,
    issue: IssueCandidate,
    base_branch: str,
    max_patch_bytes: int,
) -> None:
    """Revalidate a frozen approval after its exact patch has been committed."""

    _validate_approval_metadata(bundle, issue=issue, base_branch=base_branch)
    if unsafe_git_configuration(workspace):
        raise PublicationError("repository contains unsafe local Git configuration")
    if _safe_head(workspace) != commit_sha:
        raise PublicationError("local Git HEAD changed after publication commit")
    committed = inspect_committed_diff(
        workspace,
        bundle.base_sha,
        max_patch_bytes=max_patch_bytes,
    )
    if hashlib.sha256(committed.patch.encode()).hexdigest() != bundle.patch_sha256:
        raise PublicationError("committed tree no longer matches the approved patch")
    if inspect_diff(workspace).files:
        raise PublicationError("workspace changed after publication commit")


def _safe_title(value: str, maximum: int = 240) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", value).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = re.sub(r"@(?=[A-Za-z0-9])", "@\u200b", cleaned)
    if not cleaned:
        raise PublicationError("PR title is empty")
    return cleaned[:maximum]


class GhPublisher:
    """Deterministic publisher. This is the only component allowed GitHub write access."""

    def __init__(self, config: PublicationConfig):
        self.config = config

    def assert_authorized(self, publish_flag: bool) -> None:
        if self.config.mode != "draft-pr":
            raise PublicationError("publication.mode is not draft-pr")
        if not self.config.external_writes_acknowledged:
            raise PublicationError("publication.external_writes_acknowledged is false")
        if self.config.require_cli_flag and not publish_flag:
            raise PublicationError("the --publish authorization flag is required")
        if not self.config.draft:
            raise PublicationError("v1 refuses to publish a non-draft PR")
        if not self.config.fork:
            raise PublicationError("v1 publishes only through a contributor fork")

    def _run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if env is None:
            env = dict(os.environ)
            # gh gives these environment tokens precedence over its stored identity. The discovery
            # token must never silently become the publisher identity.
            for name in (
                "GITHUB_TOKEN",
                "GH_TOKEN",
                "GH_HOST",
                "GH_REPO",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            ):
                env.pop(name, None)
            env["GH_PROMPT_DISABLED"] = "1"
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                start_new_session=True,
            )
        except OSError as exc:
            raise PublicationError(f"command {argv[0]!r} could not start") from exc
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        overflowed: set[str] = set()
        output_limit = 2_000_000

        def drain(stream: Any, target: bytearray, name: str) -> None:
            while True:
                chunk = stream.read(8_192)
                if not chunk:
                    return
                target.extend(chunk)
                overflow = len(target) - output_limit
                if overflow > 0:
                    overflowed.add(name)
                    del target[:overflow]

        stdout_thread = threading.Thread(
            target=drain,
            args=(process.stdout, stdout_buffer, "stdout"),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=drain,
            args=(process.stderr, stderr_buffer, "stderr"),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            try:
                process.wait(timeout=180)
            except subprocess.TimeoutExpired as exc:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)
                raise PublicationError(f"command {argv[0]!r} timed out") from exc
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if stdout_thread.is_alive() or stderr_thread.is_alive() or overflowed:
            raise PublicationError(f"command {argv[0]!r} output could not be bounded")
        result = subprocess.CompletedProcess(
            argv,
            process.returncode,
            stdout_buffer.decode("utf-8", errors="replace"),
            stderr_buffer.decode("utf-8", errors="replace"),
        )
        if check and result.returncode != 0:
            detail = redact(result.stderr[-1500:], limit=1500)
            raise PublicationError(f"command {argv[0]!r} failed: {detail}")
        return result

    @staticmethod
    def _is_expected_fork(data: object, upstream: str) -> bool:
        if not isinstance(data, dict):
            return False
        if not data.get("fork"):
            return False
        parent = data.get("parent") or {}
        source = data.get("source") or {}
        return (
            isinstance(parent, dict)
            and parent.get("full_name") == upstream
            or isinstance(source, dict)
            and source.get("full_name") == upstream
        )

    def _ensure_fork(
        self,
        upstream: str,
        login: str,
        repo_name: str,
        *,
        approval_check: Callable[[], None],
    ) -> None:
        target = f"repos/{login}/{repo_name}"
        existing = self._run(["gh", "api", "--hostname", "github.com", target], check=False)
        if existing.returncode == 0:
            try:
                data = json.loads(existing.stdout)
            except json.JSONDecodeError as exc:
                raise PublicationError("could not parse existing fork metadata") from exc
            if not self._is_expected_fork(data, upstream):
                raise PublicationError(
                    f"{login}/{repo_name} exists but is not a fork of {upstream}"
                )
            return
        if "HTTP 404" not in existing.stderr and "Not Found" not in existing.stderr:
            raise PublicationError(
                "could not reconcile contributor fork: "
                + redact(existing.stderr[-1000:], limit=1000)
            )
        approval_check()
        self._run(["gh", "repo", "fork", f"https://github.com/{upstream}", "--clone=false"])
        for _ in range(15):
            ready = self._run(["gh", "api", "--hostname", "github.com", target], check=False)
            if ready.returncode == 0:
                try:
                    data = json.loads(ready.stdout)
                except json.JSONDecodeError:
                    data = {}
                if self._is_expected_fork(data, upstream):
                    return
            time.sleep(2)
        raise PublicationError("fork was not ready after 30 seconds")

    def _identity(self) -> tuple[str, int]:
        result = self._run(["gh", "api", "--hostname", "github.com", "user"])
        try:
            data = json.loads(result.stdout)
            return str(data["login"]), int(data["id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PublicationError("could not resolve authenticated GitHub identity") from exc

    @staticmethod
    def _is_expected_pr_url(value: object, repository: str) -> bool:
        return (
            isinstance(value, str)
            and re.fullmatch(
                rf"https://github\.com/{re.escape(repository)}/pull/[1-9][0-9]*",
                value,
            )
            is not None
        )

    @staticmethod
    def _validate_open_pr_preflight(value: object, repository: str) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            raise PublicationError("open-PR preflight response has an invalid shape")
        validated: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                raise PublicationError("open-PR preflight item has an invalid shape")
            owner = item.get("headRepositoryOwner")
            if (
                not isinstance(owner, dict)
                or not isinstance(owner.get("login"), str)
                or not all(
                    isinstance(item.get(field), str)
                    for field in (
                        "url",
                        "baseRefName",
                        "body",
                        "headRefName",
                        "headRefOid",
                        "title",
                    )
                )
                or type(item.get("isDraft")) is not bool
                or not GhPublisher._is_expected_pr_url(item.get("url"), repository)
            ):
                raise PublicationError("open-PR preflight item has an invalid shape")
            validated.append(item)
        return validated

    @staticmethod
    def _reconciled_pr_url(
        pull_requests: object,
        *,
        repository: str,
        expected_head_sha: str,
        expected_base_branch: str,
        expected_title: str | None = None,
        expected_body: str | None = None,
    ) -> str | None:
        if not isinstance(pull_requests, list) or any(
            not isinstance(item, dict) for item in pull_requests
        ):
            raise PublicationError("PR reconciliation response has an invalid shape")
        if not pull_requests:
            return None
        if len(pull_requests) != 1:
            raise PublicationError("PR reconciliation is ambiguous for the issue branch")
        item = pull_requests[0]
        url = item.get("url")
        if not GhPublisher._is_expected_pr_url(url, repository):
            raise PublicationError("PR reconciliation returned an unexpected URL")
        assert isinstance(url, str)
        if item.get("headRefOid") != expected_head_sha:
            raise PublicationError("existing issue PR has an unexpected head commit")
        if item.get("baseRefName") != expected_base_branch:
            raise PublicationError("existing issue PR targets an unexpected base branch")
        if item.get("isDraft") is not True:
            raise PublicationError("existing issue PR is not a draft")
        if expected_title is not None and item.get("title") != expected_title:
            raise PublicationError("existing issue PR has unexpected title text")
        if expected_body is not None and item.get("body") != expected_body:
            raise PublicationError("existing issue PR has unexpected body text")
        return url

    def _verify_created_pr(
        self,
        pr_url: str,
        *,
        repository: str,
        expected_head_sha: str,
        expected_base_branch: str,
        expected_title: str,
        expected_body: str,
    ) -> str:
        result = self._run(
            [
                "gh",
                "pr",
                "view",
                pr_url,
                "--repo",
                f"github.com/{repository}",
                "--json",
                "url,baseRefName,body,headRefOid,isDraft,title",
            ]
        )
        try:
            item = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise PublicationError("could not parse created PR verification") from exc
        verified = self._reconciled_pr_url(
            [item],
            repository=repository,
            expected_head_sha=expected_head_sha,
            expected_base_branch=expected_base_branch,
            expected_title=expected_title,
            expected_body=expected_body,
        )
        if verified != pr_url:
            raise PublicationError("created PR verification returned a different URL")
        return verified

    def _token(self) -> str:
        result = self._run(["gh", "auth", "token", "--hostname", "github.com"])
        token = result.stdout.strip()
        if not token:
            raise PublicationError("GitHub CLI returned no authentication token")
        return token

    def _base_git_env(self, workspace: Path) -> dict[str, str]:
        home = workspace.parent / "publisher-home"
        home.mkdir(mode=0o700, exist_ok=True)
        environment = controller_git_env(workspace)
        environment["HOME"] = str(home)
        return environment

    def _authenticated_git_env(self, workspace: Path, token: str) -> tuple[dict[str, str], Path]:
        helper = workspace.parent / "git-askpass.sh"
        helper.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
            "  *Password*) printf '%s\\n' \"$LEFTOVERS_PUBLISH_TOKEN\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n"
        )
        helper.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        env = {
            **self._base_git_env(workspace),
            "GIT_ASKPASS": str(helper),
            "LEFTOVERS_PUBLISH_TOKEN": token,
        }
        return env, helper

    def publish(
        self,
        *,
        publish_flag: bool,
        workspace: Path,
        issue: IssueCandidate,
        diff: DiffInspection,
        approval: ApprovalBundle,
        title: str,
        body: str,
        base_branch: str,
    ) -> PublishResult:
        self.assert_authorized(publish_flag)
        validate_approval(
            approval,
            workspace,
            issue=issue,
            base_branch=base_branch,
        )
        login, user_id = self._identity()
        if (
            login.casefold() != (self.config.expected_login or "").casefold()
            or user_id != self.config.expected_user_id
        ):
            raise PublicationError(
                "authenticated GitHub identity does not match the configured publisher identity"
            )
        token = ""
        helper: Path | None = None
        git_env = self._base_git_env(workspace)
        repo_name = issue.repo.slug.split("/", 1)[1]
        branch = f"{self.config.branch_prefix}/issue-{issue.number}"
        pr_title = _safe_title(title)
        body_file: Path | None = None
        try:
            git_base = controller_git_prefix()
            dangerous_config = unsafe_git_configuration(workspace)
            if dangerous_config:
                raise PublicationError("repository contains unsafe local Git configuration")
            self._run([*git_base, "add", "-A", "--", "."], cwd=workspace, env=git_env)
            commit_message = _safe_title(f"Fix #{issue.number}: {issue.title}", 200)
            email = f"{user_id}+{login}@users.noreply.github.com"
            self._run(
                [
                    *git_base,
                    "-c",
                    f"user.name={login}",
                    "-c",
                    f"user.email={email}",
                    "commit",
                    "-m",
                    commit_message,
                ],
                cwd=workspace,
                env=git_env,
            )
            commit_sha = self._run(
                [*git_base, "rev-parse", "HEAD"], cwd=workspace, env=git_env
            ).stdout.strip()
            committed_diff = inspect_committed_diff(
                workspace,
                approval.base_sha,
                max_patch_bytes=max(1, len(diff.patch.encode())),
            )
            if committed_diff != diff:
                raise PublicationError("committed tree does not match the approved patch")
            if inspect_diff(workspace).files:
                raise PublicationError("workspace has uncommitted changes after publication commit")

            def approval_check() -> None:
                validate_committed_approval(
                    approval,
                    workspace,
                    commit_sha,
                    issue=issue,
                    base_branch=base_branch,
                    max_patch_bytes=max(1, len(diff.patch.encode())),
                )

            open_prs_result = self._run(
                [
                    "gh",
                    "pr",
                    "list",
                    "--repo",
                    f"github.com/{issue.repo.slug}",
                    "--author",
                    login,
                    "--state",
                    "open",
                    "--limit",
                    "100",
                    "--json",
                    "url,baseRefName,body,headRefName,headRefOid,headRepositoryOwner,isDraft,title",
                ]
            )
            try:
                open_prs = json.loads(open_prs_result.stdout)
            except json.JSONDecodeError as exc:
                raise PublicationError("could not parse open-PR preflight response") from exc
            open_prs = self._validate_open_pr_preflight(open_prs, issue.repo.slug)
            matching_prs = [
                item
                for item in open_prs
                if item.get("headRefName") == branch
                and item["headRepositoryOwner"].get("login") == login
            ]
            if matching_prs:
                existing_url = self._reconciled_pr_url(
                    matching_prs,
                    repository=issue.repo.slug,
                    expected_head_sha=commit_sha,
                    expected_base_branch=base_branch,
                    expected_title=pr_title,
                    expected_body=body,
                )
                assert existing_url is not None
                return PublishResult(
                    branch=branch,
                    commit_sha=commit_sha,
                    pr_url=existing_url,
                )
            if len(open_prs) >= self.config.max_open_prs_per_repository:
                raise PublicationError("contributor account reached the per-repository open-PR cap")

            # Reconcile the fork only after the approved commit exists locally.
            self._ensure_fork(
                issue.repo.slug,
                login,
                repo_name,
                approval_check=approval_check,
            )
            encoded_branch = urllib.parse.quote(branch, safe="")
            remote_branch = self._run(
                [
                    "gh",
                    "api",
                    "--hostname",
                    "github.com",
                    f"repos/{login}/{repo_name}/branches/{encoded_branch}",
                ],
                check=False,
            )
            branch_ready = False
            if remote_branch.returncode == 0:
                try:
                    remote_data = json.loads(remote_branch.stdout)
                    remote_sha = remote_data["commit"]["sha"]
                except (json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise PublicationError("could not parse remote issue branch") from exc
                if remote_sha != commit_sha:
                    raise PublicationError(
                        "the deterministic issue branch exists with an unexpected commit"
                    )
                branch_ready = True
            elif "HTTP 404" not in remote_branch.stderr and "Not Found" not in remote_branch.stderr:
                raise PublicationError("could not reconcile the remote issue branch")

            if not branch_ready:
                token = self._token()
                authenticated_env, helper = self._authenticated_git_env(workspace, token)
                fork_url = f"https://github.com/{login}/{repo_name}.git"
                try:
                    approval_check()
                    self._run(
                        [*git_base, "push", fork_url, f"HEAD:refs/heads/{branch}"],
                        cwd=workspace,
                        env=authenticated_env,
                    )
                except PublicationError as push_error:
                    pushed = self._run(
                        [
                            "gh",
                            "api",
                            "--hostname",
                            "github.com",
                            f"repos/{login}/{repo_name}/branches/{encoded_branch}",
                        ],
                        check=False,
                    )
                    try:
                        pushed_data = json.loads(pushed.stdout) if pushed.returncode == 0 else {}
                        pushed_sha = pushed_data["commit"]["sha"]
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pushed_sha = None
                    if pushed_sha != commit_sha:
                        raise push_error

            existing = self._run(
                [
                    "gh",
                    "pr",
                    "list",
                    "--repo",
                    f"github.com/{issue.repo.slug}",
                    "--head",
                    f"{login}:{branch}",
                    "--state",
                    "open",
                    "--json",
                    "url,baseRefName,body,headRefOid,isDraft,title",
                ]
            )
            try:
                prs = json.loads(existing.stdout)
            except json.JSONDecodeError as exc:
                raise PublicationError("could not parse PR reconciliation response") from exc
            reconciled_url = self._reconciled_pr_url(
                prs,
                repository=issue.repo.slug,
                expected_head_sha=commit_sha,
                expected_base_branch=base_branch,
                expected_title=pr_title,
                expected_body=body,
            )
            if reconciled_url is not None:
                return PublishResult(
                    branch=branch,
                    commit_sha=commit_sha,
                    pr_url=reconciled_url,
                )

            descriptor, filename = tempfile.mkstemp(
                prefix="leftovers-pr-", suffix=".md", dir=workspace.parent
            )
            body_file = Path(filename)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(body)
            body_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
            try:
                approval_check()
                created = self._run(
                    [
                        "gh",
                        "pr",
                        "create",
                        "--repo",
                        f"github.com/{issue.repo.slug}",
                        "--base",
                        base_branch,
                        "--head",
                        f"{login}:{branch}",
                        "--title",
                        pr_title,
                        "--body-file",
                        str(body_file),
                        "--draft",
                    ]
                )
            except PublicationError as create_error:
                reconciliation = self._run(
                    [
                        "gh",
                        "pr",
                        "list",
                        "--repo",
                        f"github.com/{issue.repo.slug}",
                        "--head",
                        f"{login}:{branch}",
                        "--state",
                        "open",
                        "--json",
                        "url,baseRefName,body,headRefOid,isDraft,title",
                    ],
                    check=False,
                )
                try:
                    reconciled: object = (
                        json.loads(reconciliation.stdout) if reconciliation.returncode == 0 else []
                    )
                    reconciled_url = self._reconciled_pr_url(
                        reconciled,
                        repository=issue.repo.slug,
                        expected_head_sha=commit_sha,
                        expected_base_branch=base_branch,
                        expected_title=pr_title,
                        expected_body=body,
                    )
                except (json.JSONDecodeError, PublicationError):
                    raise create_error from None
                if reconciled_url is None:
                    raise create_error from None
                return PublishResult(
                    branch=branch,
                    commit_sha=commit_sha,
                    pr_url=reconciled_url,
                )
            pr_url = next(
                (
                    line.strip()
                    for line in created.stdout.splitlines()
                    if line.startswith("https://")
                ),
                "",
            )
            if not pr_url:
                raise PublicationError("gh did not return the new PR URL")
            if not self._is_expected_pr_url(pr_url, issue.repo.slug):
                raise PublicationError("gh returned a PR URL outside the approved repository")
            pr_url = self._verify_created_pr(
                pr_url,
                repository=issue.repo.slug,
                expected_head_sha=commit_sha,
                expected_base_branch=base_branch,
                expected_title=pr_title,
                expected_body=body,
            )
            return PublishResult(branch=branch, commit_sha=commit_sha, pr_url=pr_url)
        finally:
            token = ""
            if helper and helper.exists():
                helper.unlink()
            if body_file and body_file.exists():
                body_file.unlink()
