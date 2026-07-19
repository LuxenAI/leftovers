from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from .config import GitHubConfig, RepositoryConfig
from .models import IssueCandidate, RepositoryMetadata


class GitHubError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class IssueSource(Protocol):
    def discover(
        self, repositories: tuple[RepositoryConfig, ...], query: str, per_repo_limit: int
    ) -> list[IssueCandidate]: ...


@dataclass(frozen=True)
class SourceCapsule:
    """Opaque, immutable repository bytes acquired without host extraction."""

    repository: str
    base_sha: str
    path: Path
    sha256: str
    size_bytes: int


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Make every redirect visible so credentials can be stripped explicitly."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: BinaryIO,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class RepositorySupplyCriteria:
    """Read-only repository-supply screen; it never grants execution authority."""

    min_stars: int = 100
    max_stars: int = 3_000
    min_open_issues: int = 30
    max_open_issues: int = 200
    max_open_prs: int = 12
    min_issue_pr_ratio: float = 8.0
    pushed_within_days: int = 90
    fresh_issue_days: int = 180
    min_fresh_invited_issues: int = 3
    min_recent_human_activity: int = 2
    scan_limit: int = 25
    result_limit: int = 10


@dataclass(frozen=True)
class RepositorySupplyCandidate:
    slug: str
    url: str
    stars: int
    open_issues: int
    open_pull_requests: int
    issue_pr_ratio: float
    help_wanted_issues: int
    good_first_issues: int
    fresh_unassigned_invited_issues: int
    recent_human_merged_prs: int
    recent_human_closed_issues: int
    pushed_at: datetime
    license_spdx: str
    default_branch: str
    score: float
    forking_allowed: bool
    pull_requests_enabled: bool
    pull_request_creation_policy: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.slug,
            "url": self.url,
            "stars": self.stars,
            "open_issues": self.open_issues,
            "open_pull_requests": self.open_pull_requests,
            "issue_pr_ratio": self.issue_pr_ratio,
            "help_wanted_issues": self.help_wanted_issues,
            "good_first_issues": self.good_first_issues,
            "fresh_unassigned_invited_issues": self.fresh_unassigned_invited_issues,
            "recent_human_merged_prs": self.recent_human_merged_prs,
            "recent_human_closed_issues": self.recent_human_closed_issues,
            "pushed_at": self.pushed_at.isoformat(),
            "license_spdx": self.license_spdx,
            "default_branch": self.default_branch,
            "score": self.score,
            "forking_allowed": self.forking_allowed,
            "pull_requests_enabled": self.pull_requests_enabled,
            "pull_request_creation_policy": self.pull_request_creation_policy,
            "execution_authorized": False,
            "manual_review_required": [
                "confirm the repository's current AI-assisted contribution policy",
                "confirm contribution guide, CLA or DCO, and issue-claim etiquette",
                "curate an offline setup and exact verification argv",
                "add an explicit allowlist entry in reviewed configuration",
            ],
        }


def _parse_time(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise GitHubError("GitHub returned an invalid timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise GitHubError("GitHub returned an invalid timestamp") from exc


def _bot_login(login: str) -> bool:
    normalized = login.casefold()
    return normalized.endswith("[bot]") or normalized in {
        "dependabot",
        "github-actions",
        "renovate-bot",
    }


@dataclass
class GitHubClient:
    config: GitHubConfig

    def __post_init__(self) -> None:
        self._token = os.environ.get(self.config.token_env)
        self._requests = 0
        self._repos: dict[str, RepositoryMetadata] = {}

    def _reserve_read_request(self) -> None:
        if self._requests >= self.config.max_read_requests_per_run:
            raise GitHubError("configured GitHub read-request ceiling reached")
        self._requests += 1

    @staticmethod
    def _capsule_parent(destination: Path) -> int:
        if not destination.is_absolute() or destination.name in {"", ".", ".."}:
            raise GitHubError("source-capsule destination must be a direct absolute file path")
        try:
            parent = destination.parent.lstat()
        except OSError as exc:
            raise GitHubError("source-capsule parent is unavailable") from exc
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise GitHubError("source-capsule parent must be an owner-private directory")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            return os.open(destination.parent, flags)
        except OSError as exc:
            raise GitHubError("source-capsule parent cannot be opened safely") from exc

    @staticmethod
    def _validated_codeload_url(location: str, slug: str, base_sha: str) -> str:
        if not isinstance(location, str) or len(location) > 2_048:
            raise GitHubError("GitHub archive redirect is missing or oversized")
        try:
            parsed = urllib.parse.urlsplit(location)
            port = parsed.port
        except ValueError as exc:
            raise GitHubError("GitHub archive redirect URL is malformed") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname != "codeload.github.com"
            or port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise GitHubError("GitHub archive redirect target is not an approved codeload URL")
        decoded = urllib.parse.unquote(parsed.path)
        if urllib.parse.quote(decoded, safe="/-._~") != parsed.path:
            raise GitHubError("GitHub archive redirect path is not canonical")
        owner, repository = slug.split("/", 1)
        expected = {
            f"/{owner}/{repository}/legacy.tar.gz/{base_sha}".casefold(),
            f"/{owner}/{repository}/tar.gz/{base_sha}".casefold(),
        }
        if decoded.casefold() not in expected:
            raise GitHubError("GitHub archive redirect does not bind the requested repository SHA")
        return location

    def download_source_capsule(
        self,
        slug: str,
        base_sha: str,
        destination: Path,
        *,
        max_bytes: int = 128 * 1_024 * 1_024,
    ) -> SourceCapsule:
        """Stream a public repository archive as opaque, sealed bytes.

        The authenticated API request is never allowed to redirect implicitly.
        The second request is constructed from scratch without authorization and
        is restricted to the exact public codeload host/path for ``base_sha``.
        The host does not inspect or extract archive contents.
        """

        if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", slug) is None:
            raise GitHubError("source-capsule repository slug is invalid")
        if re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
            raise GitHubError("source-capsule base SHA must be exactly 40 lowercase hex characters")
        if type(max_bytes) is not int or not 1_024 <= max_bytes <= 256 * 1_024 * 1_024:
            raise GitHubError("source-capsule byte cap is outside conservative bounds")
        destination = Path(destination)
        parent_descriptor = self._capsule_parent(destination)
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _RejectRedirects(),
            )
            api_url = self.config.api_url.rstrip("/") + f"/repos/{slug}/tarball/{base_sha}"
            api_headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": self.config.api_version,
                "User-Agent": "leftovers-agent/0.2",
            }
            if self._token:
                api_headers["Authorization"] = f"Bearer {self._token}"
            self._reserve_read_request()
            redirect_error: urllib.error.HTTPError | None = None
            try:
                request = urllib.request.Request(api_url, method="GET", headers=api_headers)
                try:
                    response = opener.open(request, timeout=self.config.request_timeout_seconds)
                except urllib.error.HTTPError as exc:
                    if exc.code not in {301, 302, 303, 307, 308}:
                        try:
                            raise GitHubError(
                                f"GitHub archive request returned HTTP {exc.code}",
                                status=exc.code,
                                retryable=exc.code in {429, 500, 502, 503, 504},
                            ) from exc
                        finally:
                            exc.close()
                    redirect_error = exc
                    location = exc.headers.get("Location")
                except urllib.error.URLError as exc:
                    raise GitHubError("GitHub archive request failed", retryable=True) from exc
                else:
                    response.close()
                    raise GitHubError(
                        "GitHub archive request did not use the required explicit redirect"
                    )
                assert redirect_error is not None
                codeload_url = self._validated_codeload_url(location, slug, base_sha)
            finally:
                if redirect_error is not None:
                    redirect_error.close()
        except BaseException:
            os.close(parent_descriptor)
            raise

        try:
            self._reserve_read_request()
        except BaseException:
            os.close(parent_descriptor)
            raise
        public_request = urllib.request.Request(
            codeload_url,
            method="GET",
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "leftovers-agent/0.2",
            },
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        created = False
        try:
            try:
                response = opener.open(public_request, timeout=self.config.request_timeout_seconds)
            except urllib.error.HTTPError as exc:
                try:
                    raise GitHubError(
                        f"GitHub codeload request returned HTTP {exc.code}",
                        status=exc.code,
                        retryable=exc.code in {429, 500, 502, 503, 504},
                    ) from exc
                finally:
                    exc.close()
            except urllib.error.URLError as exc:
                raise GitHubError("GitHub codeload request failed", retryable=True) from exc
            with response:
                final_url = response.geturl()
                self._validated_codeload_url(final_url, slug, base_sha)
                status_code = response.getcode()
                if status_code != 200:
                    raise GitHubError(f"GitHub codeload returned unexpected HTTP {status_code}")
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError as exc:
                        raise GitHubError(
                            "GitHub codeload returned an invalid Content-Length"
                        ) from exc
                    if not 1 <= declared_length <= max_bytes:
                        raise GitHubError("GitHub source archive exceeds the configured byte cap")
                try:
                    descriptor = os.open(
                        destination.name,
                        flags,
                        0o600,
                        dir_fd=parent_descriptor,
                    )
                    created = True
                except OSError as exc:
                    raise GitHubError("source-capsule output cannot be created safely") from exc
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = response.read(min(1_048_576, max_bytes - total + 1))
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise GitHubError("GitHub codeload returned a non-byte response")
                    total += len(chunk)
                    if total > max_bytes:
                        raise GitHubError("GitHub source archive exceeded the configured byte cap")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise GitHubError("source-capsule write made no progress")
                        view = view[written:]
                if total == 0:
                    raise GitHubError("GitHub source archive was empty")
                if content_length is not None and total != declared_length:
                    raise GitHubError("GitHub source archive length did not match Content-Length")
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o400
                    or info.st_nlink != 1
                    or info.st_size != total
                ):
                    raise GitHubError("sealed source-capsule identity is unsafe")
                os.close(descriptor)
                descriptor = None
                os.fsync(parent_descriptor)
                return SourceCapsule(slug, base_sha, destination, digest.hexdigest(), total)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                try:
                    os.unlink(destination.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                except OSError as exc:
                    raise GitHubError("source-capsule cleanup could not be proven") from exc
                try:
                    os.stat(destination.name, dir_fd=parent_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise GitHubError("source-capsule cleanup could not prove path absence")
            raise
        finally:
            os.close(parent_descriptor)

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str | int] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if self._requests >= self.config.max_read_requests_per_run:
            raise GitHubError("configured GitHub read-request ceiling reached")
        url = path if path.startswith("https://") else self.config.api_url.rstrip("/") + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.config.api_version,
            "User-Agent": "leftovers-agent/0.1",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        self._requests += 1
        try:
            with urllib.request.urlopen(
                request, timeout=self.config.request_timeout_seconds
            ) as response:
                raw = response.read(10_000_001)
                if len(raw) > 10_000_000:
                    raise GitHubError("GitHub response exceeded the 10 MB safety limit")
                if not raw:
                    return None
                try:
                    return json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise GitHubError("GitHub returned malformed JSON") from exc
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After")
            remaining = exc.headers.get("X-RateLimit-Remaining")
            reset = exc.headers.get("X-RateLimit-Reset")
            retryable = exc.code in {429, 500, 502, 503, 504} or (
                exc.code == 403 and (retry_after is not None or remaining == "0")
            )
            detail = f"GitHub returned HTTP {exc.code}"
            if retry_after:
                detail += f"; retry after {retry_after}s"
            elif remaining == "0" and reset:
                detail += f"; rate limit resets at unix time {reset}"
            raise GitHubError(detail, status=exc.code, retryable=retryable) from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"GitHub request failed: {exc.reason}", retryable=True) from exc

    def repository(self, slug: str, *, refresh: bool = False) -> RepositoryMetadata:
        if slug in self._repos and not refresh:
            return self._repos[slug]
        data = self._request("GET", f"/repos/{slug}")
        if not isinstance(data, dict):
            raise GitHubError("GitHub repository response has an invalid shape")
        license_data = data.get("license") or {}
        if not isinstance(license_data, dict):
            raise GitHubError("GitHub repository license has an invalid shape")
        for field in ("stargazers_count", "open_issues_count"):
            if type(data.get(field, 0)) is not int or int(data.get(field, 0)) < 0:
                raise GitHubError(f"GitHub repository {field} has an invalid value")
        for field in ("archived", "disabled"):
            if type(data.get(field)) is not bool:
                raise GitHubError(f"GitHub repository {field} has an invalid value")
        default_branch = data.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise GitHubError("GitHub repository default_branch has an invalid value")
        spdx = license_data.get("spdx_id")
        if spdx is not None and not isinstance(spdx, str):
            raise GitHubError("GitHub repository license SPDX value is invalid")
        controls = self._repository_controls(slug)
        metadata = RepositoryMetadata(
            slug=slug,
            stars=data.get("stargazers_count", 0),
            archived=data["archived"],
            disabled=data["disabled"],
            license_spdx=spdx,
            default_branch=default_branch,
            pushed_at=_parse_time(data.get("pushed_at")),
            open_issues=data.get("open_issues_count", 0),
            forking_allowed=controls.get("forkingAllowed"),
            pull_requests_enabled=controls.get("hasPullRequestsEnabled"),
            pull_request_creation_policy=controls.get("pullRequestCreationPolicy"),
        )
        self._repos[slug] = metadata
        return metadata

    def _repository_controls(self, slug: str) -> dict[str, Any]:
        if not self._token:
            return {}
        owner, name = slug.split("/", 1)
        response = self._request(
            "POST",
            "https://api.github.com/graphql",
            body={
                "query": """
query LeftoversRepositoryControls($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    forkingAllowed
    hasPullRequestsEnabled
    pullRequestCreationPolicy
  }
}
""",
                "variables": {"owner": owner, "name": name},
            },
        )
        if not isinstance(response, dict):
            raise GitHubError("GitHub GraphQL response has an invalid shape")
        if response.get("errors"):
            raise GitHubError("GitHub GraphQL repository-policy check returned an error")
        response_data = response.get("data")
        if not isinstance(response_data, dict):
            raise GitHubError("GitHub GraphQL response data has an invalid shape")
        repository = response_data.get("repository")
        if not isinstance(repository, dict):
            raise GitHubError("GitHub did not return repository policy data")
        if (
            type(repository.get("forkingAllowed")) is not bool
            or type(repository.get("hasPullRequestsEnabled")) is not bool
        ):
            raise GitHubError("GitHub repository policy booleans have an invalid shape")
        if not isinstance(repository.get("pullRequestCreationPolicy"), str):
            raise GitHubError("GitHub repository PR policy has an invalid shape")
        return repository

    def discover_repository_supply(
        self,
        criteria: RepositorySupplyCriteria,
        *,
        observed_at: datetime | None = None,
    ) -> list[RepositorySupplyCandidate]:
        """Find review candidates with many issues and relatively few open PRs.

        GitHub's REST ``open_issues_count`` includes pull requests, so this screen uses
        independent GraphQL connections for the two exact counts. Results are deliberately
        non-authoritative: they are never added to ``repositories`` and always require manual
        policy and verification curation before an execution run.
        """

        if not self._token:
            raise GitHubError(
                "repository-supply scouting requires an authenticated GitHub read token"
            )
        if (
            criteria.min_stars < 1
            or criteria.max_stars < criteria.min_stars
            or criteria.min_open_issues < 1
            or criteria.max_open_issues < criteria.min_open_issues
            or criteria.max_open_prs < 0
            or criteria.min_issue_pr_ratio < 1
            or not 1 <= criteria.pushed_within_days <= 365
            or not 1 <= criteria.fresh_issue_days <= 365
            or not 1 <= criteria.min_fresh_invited_issues <= 100
            or not 0 <= criteria.min_recent_human_activity <= 100
            or not 1 <= criteria.scan_limit <= 50
            or not 1 <= criteria.result_limit <= criteria.scan_limit
        ):
            raise GitHubError("repository-supply criteria are outside conservative bounds")

        observed = (observed_at or datetime.now(UTC)).astimezone(UTC)
        cutoff = (observed - timedelta(days=criteria.pushed_within_days)).date().isoformat()
        query = " ".join(
            (
                f"stars:{criteria.min_stars}..{criteria.max_stars}",
                "size:<50000",
                "archived:false",
                "fork:false",
                f"pushed:>={cutoff}",
                "help-wanted-issues:5..100",
            )
        )
        response = self._request(
            "GET",
            "/search/repositories",
            query={
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": criteria.scan_limit,
            },
        )
        if not isinstance(response, dict) or not isinstance(response.get("items"), list):
            raise GitHubError("GitHub repository-search response has an invalid shape")

        candidates: list[RepositorySupplyCandidate] = []
        seen: set[str] = set()
        for item in response["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("full_name"), str):
                raise GitHubError("GitHub repository-search item has an invalid shape")
            slug = item["full_name"]
            if slug in seen or re.fullmatch(r"[^/\s]+/[^/\s]+", slug) is None:
                continue
            seen.add(slug)
            candidate = self._repository_supply_details(slug, observed, criteria)
            if candidate is None:
                continue
            if not (
                criteria.min_stars <= candidate.stars <= criteria.max_stars
                and criteria.min_open_issues <= candidate.open_issues <= criteria.max_open_issues
                and candidate.open_pull_requests <= criteria.max_open_prs
                and candidate.issue_pr_ratio >= criteria.min_issue_pr_ratio
                and candidate.pushed_at >= observed - timedelta(days=criteria.pushed_within_days)
                and candidate.fresh_unassigned_invited_issues >= criteria.min_fresh_invited_issues
                and (candidate.recent_human_merged_prs + candidate.recent_human_closed_issues)
                >= criteria.min_recent_human_activity
                and candidate.pull_request_creation_policy == "ALL"
            ):
                continue
            candidates.append(candidate)

        candidates.sort(
            key=lambda value: (
                value.score,
                value.issue_pr_ratio,
                value.open_issues,
                value.stars,
                value.slug.casefold(),
            ),
            reverse=True,
        )
        return candidates[: criteria.result_limit]

    def _repository_supply_details(
        self,
        slug: str,
        observed_at: datetime,
        criteria: RepositorySupplyCriteria,
    ) -> RepositorySupplyCandidate | None:
        owner, name = slug.split("/", 1)
        response = self._request(
            "POST",
            "https://api.github.com/graphql",
            body={
                "query": """
query LeftoversRepositorySupply($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    url
    description
    isArchived
    isDisabled
    isFork
    isLocked
    isMirror
    isTemplate
    stargazerCount
    pushedAt
    defaultBranchRef { name }
    licenseInfo { spdxId }
    issues(states: OPEN) { totalCount }
    pullRequests(states: OPEN) { totalCount }
    helpWanted: issues(
      states: OPEN
      labels: ["help wanted"]
      first: 20
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      totalCount
      nodes { id updatedAt assignees { totalCount } }
    }
    goodFirst: issues(
      states: OPEN
      labels: ["good first issue"]
      first: 20
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      totalCount
      nodes { id updatedAt assignees { totalCount } }
    }
    recentMerged: pullRequests(
      states: MERGED
      first: 20
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      nodes { mergedAt author { login } }
    }
    recentClosed: issues(
      states: CLOSED
      first: 20
      orderBy: {field: UPDATED_AT, direction: DESC}
    ) {
      nodes { closedAt author { login } }
    }
    forkingAllowed
    hasPullRequestsEnabled
    pullRequestCreationPolicy
  }
}
""",
                "variables": {"owner": owner, "name": name},
            },
        )
        if not isinstance(response, dict) or response.get("errors"):
            raise GitHubError("GitHub GraphQL repository-supply query returned an error")
        data = response.get("data")
        repository = data.get("repository") if isinstance(data, dict) else None
        if repository is None:
            return None
        if not isinstance(repository, dict):
            raise GitHubError("GitHub repository-supply data has an invalid shape")
        try:
            if any(
                type(repository.get(key)) is not bool
                for key in (
                    "isArchived",
                    "isDisabled",
                    "isFork",
                    "isLocked",
                    "isMirror",
                    "isTemplate",
                    "forkingAllowed",
                    "hasPullRequestsEnabled",
                )
            ):
                raise TypeError("repository controls")
            if (
                repository["isArchived"]
                or repository["isDisabled"]
                or repository["isFork"]
                or repository["isLocked"]
                or repository["isMirror"]
                or repository["isTemplate"]
                or not repository["forkingAllowed"]
                or not repository["hasPullRequestsEnabled"]
            ):
                return None
            name_with_owner = repository["nameWithOwner"]
            url = repository["url"]
            policy = repository["pullRequestCreationPolicy"]
            if not all(
                isinstance(value, str) and value for value in (name_with_owner, url, policy)
            ):
                raise TypeError("repository identity")
            if name_with_owner.casefold() != slug.casefold():
                raise TypeError("repository identity mismatch")
            description = repository.get("description")
            if description is not None and not isinstance(description, str):
                raise TypeError("repository description")
            tutorial_text = f"{name_with_owner} {description or ''}".casefold()
            if any(
                phrase in tutorial_text
                for phrase in (
                    "first contribution",
                    "first-contribution",
                    "fork-commit-merge",
                    "learn git",
                    "practice pull request",
                )
            ):
                return None
            stars = repository["stargazerCount"]
            connections = {
                key: repository[key]["totalCount"]
                for key in ("issues", "pullRequests", "helpWanted", "goodFirst")
            }
            if (
                type(stars) is not int
                or stars < 0
                or any(type(value) is not int or value < 0 for value in connections.values())
            ):
                raise TypeError("repository counters")
            default_branch = repository.get("defaultBranchRef") or {}
            license_info = repository.get("licenseInfo") or {}
            if not isinstance(default_branch, dict) or not isinstance(license_info, dict):
                raise TypeError("repository metadata")
            branch = default_branch.get("name")
            spdx = license_info.get("spdxId")
            if (
                not isinstance(branch, str)
                or not branch
                or not isinstance(spdx, str)
                or not spdx
                or spdx in {"NOASSERTION", "OTHER"}
            ):
                return None
            pushed_at = _parse_time(repository.get("pushedAt"))
            if pushed_at is None:
                return None

            fresh_cutoff = observed_at - timedelta(days=criteria.fresh_issue_days)
            fresh_issue_ids: set[str] = set()
            for connection_name in ("helpWanted", "goodFirst"):
                nodes = repository[connection_name].get("nodes")
                if not isinstance(nodes, list):
                    raise TypeError("invited issue nodes")
                for node in nodes:
                    if not isinstance(node, dict) or not isinstance(node.get("id"), str):
                        raise TypeError("invited issue node")
                    assignees = node.get("assignees")
                    if (
                        not isinstance(assignees, dict)
                        or type(assignees.get("totalCount")) is not int
                    ):
                        raise TypeError("invited issue assignees")
                    updated_at = _parse_time(node.get("updatedAt"))
                    if (
                        updated_at is not None
                        and updated_at >= fresh_cutoff
                        and assignees["totalCount"] == 0
                    ):
                        fresh_issue_ids.add(node["id"])

            activity_cutoff = observed_at - timedelta(days=90)

            def recent_human_count(connection_name: str, timestamp_name: str) -> int:
                connection = repository.get(connection_name)
                nodes = connection.get("nodes") if isinstance(connection, dict) else None
                if not isinstance(nodes, list):
                    raise TypeError("recent activity nodes")
                count = 0
                for node in nodes:
                    if not isinstance(node, dict):
                        raise TypeError("recent activity node")
                    author = node.get("author")
                    login = author.get("login") if isinstance(author, dict) else None
                    timestamp = _parse_time(node.get(timestamp_name))
                    if (
                        isinstance(login, str)
                        and timestamp is not None
                        and timestamp >= activity_cutoff
                        and not _bot_login(login)
                    ):
                        count += 1
                return count

            recent_merged = recent_human_count("recentMerged", "mergedAt")
            recent_closed = recent_human_count("recentClosed", "closedAt")
        except (KeyError, TypeError) as exc:
            raise GitHubError("GitHub repository-supply data has an invalid shape") from exc

        open_issues = connections["issues"]
        open_prs = connections["pullRequests"]
        ratio = open_issues / max(1, open_prs)
        invitation_count = len(fresh_issue_ids)
        human_activity = recent_merged + recent_closed
        recency = max(0.0, 1.0 - (observed_at - pushed_at).total_seconds() / (90 * 86_400))
        score = round(
            40 * min(ratio / 10, 1)
            + 20 * min(open_issues / 100, 1)
            + 15 * min(invitation_count / 10, 1)
            + 15 * min(human_activity / 10, 1)
            + 10 * recency,
            2,
        )
        return RepositorySupplyCandidate(
            slug=name_with_owner,
            url=url,
            stars=stars,
            open_issues=open_issues,
            open_pull_requests=open_prs,
            issue_pr_ratio=round(ratio, 2),
            help_wanted_issues=connections["helpWanted"],
            good_first_issues=connections["goodFirst"],
            fresh_unassigned_invited_issues=len(fresh_issue_ids),
            recent_human_merged_prs=recent_merged,
            recent_human_closed_issues=recent_closed,
            pushed_at=pushed_at,
            license_spdx=spdx,
            default_branch=branch,
            score=score,
            forking_allowed=repository["forkingAllowed"],
            pull_requests_enabled=repository["hasPullRequestsEnabled"],
            pull_request_creation_policy=policy,
        )

    def _linked_pr_graphql(self, slug: str, issue_number: int) -> bool:
        if not self._token:
            return self._linked_pr_rest(slug, issue_number)
        owner, name = slug.split("/", 1)
        graphql = """
query LeftoversLinkedPullRequests($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      closedByPullRequestsReferences(first: 20) {
        nodes { state }
        pageInfo { hasNextPage }
      }
      timelineItems(first: 100, itemTypes: [CROSS_REFERENCED_EVENT]) {
        nodes {
          ... on CrossReferencedEvent {
            source { ... on PullRequest { state } }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  }
}
"""
        response = self._request(
            "POST",
            "https://api.github.com/graphql",
            body={
                "query": graphql,
                "variables": {"owner": owner, "name": name, "number": issue_number},
            },
        )
        if not isinstance(response, dict):
            return True
        if response.get("errors"):
            raise GitHubError("GitHub GraphQL linked-PR check returned an error")
        response_data = response.get("data")
        if not isinstance(response_data, dict):
            return True
        repository = response_data.get("repository")
        if not isinstance(repository, dict):
            return True
        issue = repository.get("issue")
        if not isinstance(issue, dict):
            return True
        closing_connection = issue.get("closedByPullRequestsReferences") or {}
        timeline_connection = issue.get("timelineItems") or {}
        if not isinstance(closing_connection, dict) or not isinstance(timeline_connection, dict):
            return True
        closing = closing_connection.get("nodes") or []
        timeline = timeline_connection.get("nodes") or []
        if not isinstance(closing, list) or not isinstance(timeline, list):
            return True
        if (closing_connection.get("pageInfo") or {}).get("hasNextPage"):
            return True
        if (timeline_connection.get("pageInfo") or {}).get("hasNextPage"):
            return True
        for node in closing:
            if not isinstance(node, dict):
                return True
            if node.get("state") == "OPEN":
                return True
        for event in timeline:
            if not isinstance(event, dict):
                return True
            source = event.get("source") or {}
            if not isinstance(source, dict):
                return True
            if source.get("state") == "OPEN":
                return True
        return False

    def _has_recent_claim(self, slug: str, issue_number: int) -> bool:
        comments = self._request(
            "GET",
            f"/repos/{slug}/issues/{issue_number}/comments",
            query={"per_page": 100},
        )
        if not isinstance(comments, list) or len(comments) >= 100:
            return True
        claim = re.compile(
            r"\b(?:i(?:'m| am| will|'ll) (?:work|working|take|implement)|"
            r"working on (?:this|it)|started (?:working|a pr)|claim(?:ing)? this)\b",
            re.IGNORECASE,
        )
        cutoff = datetime.now(UTC).timestamp() - 30 * 86_400
        for comment in comments:
            if not isinstance(comment, dict):
                return True
            created_at = _parse_time(comment.get("created_at"))
            if (
                created_at
                and created_at.timestamp() >= cutoff
                and claim.search(comment.get("body") or "")
            ):
                return True
        return False

    def _candidate_from_api(
        self,
        item: dict[str, Any],
        metadata: RepositoryMetadata,
        *,
        check_linked: bool = True,
    ) -> IssueCandidate:
        try:
            reactions = item.get("reactions") or {}
            if not isinstance(reactions, dict):
                raise TypeError("reactions")
            labels = item.get("labels", [])
            assignees = item.get("assignees", [])
            if not isinstance(labels, list) or not isinstance(assignees, list):
                raise TypeError("labels or assignees")
            number = int(item["number"])
            title = item.get("title") or ""
            body = item.get("body") or ""
            url = item.get("html_url") or ""
            association = item.get("author_association") or "NONE"
            if not all(isinstance(value, str) for value in (title, body, url, association)):
                raise TypeError("issue text")
            label_names = tuple(label["name"] for label in labels)
            assignee_names = tuple(assignee["login"] for assignee in assignees)
            if not all(isinstance(value, str) for value in (*label_names, *assignee_names)):
                raise TypeError("label or assignee name")
            comments = item.get("comments", 0)
            reaction_count = reactions.get("total_count", 0)
            if (
                type(comments) is not int
                or comments < 0
                or type(reaction_count) is not int
                or reaction_count < 0
                or type(item.get("locked")) is not bool
            ):
                raise TypeError("issue counters or lock state")
            state = item.get("state")
            if not isinstance(state, str):
                raise TypeError("issue state")
            return IssueCandidate(
                repo=metadata,
                number=number,
                node_id=str(item.get("node_id") or f"{metadata.slug}#{number}"),
                title=title,
                body=body,
                url=url,
                labels=label_names,
                created_at=_parse_time(item.get("created_at")) or datetime.now(UTC),
                updated_at=_parse_time(item.get("updated_at")) or datetime.now(UTC),
                comments=comments,
                reactions=reaction_count,
                assignees=assignee_names,
                locked=item["locked"],
                author_association=association,
                has_open_linked_pr=(
                    self._linked_pr_graphql(metadata.slug, number) if check_linked else False
                ),
                has_recent_claim=self._has_recent_claim(metadata.slug, number),
                state=state.casefold(),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise GitHubError("GitHub issue response has an invalid shape") from exc

    def _linked_pr_rest(self, slug: str, issue_number: int) -> bool:
        events = self._request(
            "GET", f"/repos/{slug}/issues/{issue_number}/timeline", query={"per_page": 100}
        )
        if not isinstance(events, list):
            return True
        if len(events) >= 100:
            return True
        for event in events:
            if not isinstance(event, dict):
                return True
            if event.get("event") != "cross-referenced":
                continue
            source = event.get("source") or {}
            if not isinstance(source, dict):
                return True
            source_issue = source.get("issue") or {}
            if not isinstance(source_issue, dict):
                return True
            if source_issue.get("pull_request") and source_issue.get("state") == "open":
                return True
        return False

    def discover(
        self, repositories: tuple[RepositoryConfig, ...], query: str, per_repo_limit: int
    ) -> list[IssueCandidate]:
        issues: list[IssueCandidate] = []
        for repo_config in repositories:
            if not repo_config.enabled:
                continue
            metadata = self.repository(repo_config.slug)
            search = f"repo:{repo_config.slug} {query}"
            response = self._request(
                "GET",
                "/search/issues",
                query={"q": search, "sort": "updated", "order": "desc", "per_page": per_repo_limit},
            )
            if not isinstance(response, dict) or not isinstance(response.get("items"), list):
                raise GitHubError("GitHub issue-search response has an invalid shape")
            for item in response.get("items", []):
                if not isinstance(item, dict):
                    raise GitHubError("GitHub issue-search item has an invalid shape")
                if "pull_request" in item:
                    continue
                issues.append(self._candidate_from_api(item, metadata))
        return issues

    def refresh_issue(self, issue: IssueCandidate) -> IssueCandidate | None:
        data = self._request("GET", f"/repos/{issue.repo.slug}/issues/{issue.number}")
        if not isinstance(data, dict):
            raise GitHubError("GitHub issue response has an invalid shape")
        if data.get("state") != "open" or "pull_request" in data:
            return None
        metadata = self.repository(issue.repo.slug, refresh=True)
        return self._candidate_from_api(data, metadata)

    def branch_head(self, slug: str, branch: str) -> str:
        data = self._request("GET", f"/repos/{slug}/branches/{urllib.parse.quote(branch, safe='')}")
        if not isinstance(data, dict):
            raise GitHubError("GitHub branch response has an invalid shape")
        commit = data.get("commit")
        if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str):
            raise GitHubError("GitHub branch commit has an invalid shape")
        sha = commit["sha"]
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            raise GitHubError("GitHub branch commit SHA is not an exact lowercase object id")
        return sha


@dataclass
class FixtureIssueSource:
    path: Path

    def discover(
        self, repositories: tuple[RepositoryConfig, ...], query: str, per_repo_limit: int
    ) -> list[IssueCandidate]:
        del query
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise GitHubError(f"cannot read issue fixture: {exc}") from exc
        if not isinstance(data, dict):
            raise GitHubError("issue fixture root must be an object")
        allowed = {repo.slug for repo in repositories if repo.enabled}
        metadata: dict[str, RepositoryMetadata] = {}
        for repo in data.get("repositories", []):
            metadata[repo["slug"]] = RepositoryMetadata(
                slug=repo["slug"],
                stars=int(repo.get("stars", 0)),
                archived=bool(repo.get("archived", False)),
                disabled=bool(repo.get("disabled", False)),
                license_spdx=repo.get("license_spdx"),
                default_branch=repo.get("default_branch", "main"),
                pushed_at=_parse_time(repo.get("pushed_at")),
                open_issues=int(repo.get("open_issues", 0)),
                forking_allowed=repo.get("forking_allowed", True),
                pull_requests_enabled=repo.get("pull_requests_enabled", True),
                pull_request_creation_policy=repo.get("pull_request_creation_policy"),
            )
        issues: list[IssueCandidate] = []
        counts: dict[str, int] = {}
        for item in data.get("issues", []):
            slug = item["repo"]
            if slug not in allowed or slug not in metadata:
                continue
            if counts.get(slug, 0) >= per_repo_limit:
                continue
            counts[slug] = counts.get(slug, 0) + 1
            number = int(item["number"])
            issues.append(
                IssueCandidate(
                    repo=metadata[slug],
                    number=number,
                    node_id=item.get("node_id", f"fixture:{slug}#{number}"),
                    title=item.get("title", ""),
                    body=item.get("body", ""),
                    url=item.get("url", f"https://github.com/{slug}/issues/{number}"),
                    labels=tuple(item.get("labels", [])),
                    created_at=_parse_time(item.get("created_at")) or datetime.now(UTC),
                    updated_at=_parse_time(item.get("updated_at")) or datetime.now(UTC),
                    comments=int(item.get("comments", 0)),
                    reactions=int(item.get("reactions", 0)),
                    assignees=tuple(item.get("assignees", [])),
                    locked=bool(item.get("locked", False)),
                    author_association=item.get("author_association", "NONE"),
                    has_open_linked_pr=bool(item.get("has_open_linked_pr", False)),
                    has_recent_claim=bool(item.get("has_recent_claim", False)),
                    state=str(item.get("state") or "unknown").casefold(),
                )
            )
        return issues
