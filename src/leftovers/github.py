from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

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


def _parse_time(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise GitHubError("GitHub returned an invalid timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise GitHubError("GitHub returned an invalid timestamp") from exc


@dataclass
class GitHubClient:
    config: GitHubConfig

    def __post_init__(self) -> None:
        self._token = os.environ.get(self.config.token_env)
        self._requests = 0
        self._repos: dict[str, RepositoryMetadata] = {}

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
        return commit["sha"]


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
