import hashlib
import io
import os
import stat
import tempfile
import unittest
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from leftovers.config import GitHubConfig
from leftovers.github import (
    FixtureIssueSource,
    GitHubClient,
    GitHubError,
    RepositorySupplyCriteria,
)
from leftovers.models import RepositoryMetadata


class _Response:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload


class _ArchiveResponse:
    def __init__(self, url: str, payload: bytes, *, content_length: str | None = None):
        self.url = url
        self.payload = payload
        self.offset = 0
        self.headers = {} if content_length is None else {"Content-Length": content_length}
        self.closed = False

    def __enter__(self) -> "_ArchiveResponse":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self.closed = True

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return 200

    def read(self, limit: int) -> bytes:
        chunk = self.payload[self.offset : self.offset + limit]
        self.offset += len(chunk)
        return chunk


class _ArchiveOpener:
    def __init__(self, redirect_url: str, payload: bytes, *, content_length: str | None = None):
        self.redirect_url = redirect_url
        self.payload = payload
        self.content_length = content_length
        self.requests: list[object] = []

    def open(self, request: object, *, timeout: int):
        del timeout
        self.requests.append(request)
        if len(self.requests) == 1:
            raise urllib.error.HTTPError(
                request.full_url,  # type: ignore[attr-defined]
                302,
                "Found",
                {"Location": self.redirect_url},
                io.BytesIO(),
            )
        return _ArchiveResponse(
            self.redirect_url,
            self.payload,
            content_length=self.content_length,
        )


class GitHubClientTests(unittest.TestCase):
    def client_with_token(self) -> GitHubClient:
        with patch.dict("os.environ", {"LEFTOVERS_TEST_GH_TOKEN": "redacted"}):
            return GitHubClient(GitHubConfig(token_env="LEFTOVERS_TEST_GH_TOKEN"))

    def capsule_root(self) -> Path:
        root = Path(tempfile.mkdtemp()).resolve()
        os.chmod(root, 0o700)
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        return root

    def test_source_capsule_strips_auth_and_streams_opaque_sealed_bytes(self) -> None:
        client = self.client_with_token()
        root = self.capsule_root()
        destination = root / "source.tar.gz"
        base_sha = "a" * 40
        codeload = f"https://codeload.github.com/owner/repo/legacy.tar.gz/{base_sha}"
        payload = b"opaque archive bytes" * 100
        opener = _ArchiveOpener(codeload, payload, content_length=str(len(payload)))

        with patch("urllib.request.build_opener", return_value=opener):
            capsule = client.download_source_capsule(
                "owner/repo", base_sha, destination, max_bytes=4096
            )

        self.assertEqual(capsule.repository, "owner/repo")
        self.assertEqual(capsule.base_sha, base_sha)
        self.assertEqual(capsule.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(capsule.size_bytes, len(payload))
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)
        self.assertEqual(client._requests, 2)
        api_headers = dict(opener.requests[0].header_items())  # type: ignore[attr-defined]
        public_headers = dict(opener.requests[1].header_items())  # type: ignore[attr-defined]
        self.assertEqual(api_headers["Authorization"], "Bearer redacted")
        self.assertNotIn("Authorization", public_headers)
        self.assertEqual(opener.requests[1].full_url, codeload)  # type: ignore[attr-defined]

    def test_source_capsule_rejects_redirect_host_or_sha_before_public_request(self) -> None:
        client = self.client_with_token()
        root = self.capsule_root()
        base_sha = "a" * 40
        cases = (
            f"https://evil.example/owner/repo/legacy.tar.gz/{base_sha}",
            "https://codeload.github.com/owner/repo/legacy.tar.gz/" + "b" * 40,
            f"https://codeload.github.com/owner/repo/legacy.tar.gz/{base_sha}?token=bad",
        )
        for index, redirect in enumerate(cases):
            with self.subTest(redirect=redirect):
                opener = _ArchiveOpener(redirect, b"unused")
                destination = root / f"source-{index}.tar.gz"
                with (
                    patch("urllib.request.build_opener", return_value=opener),
                    self.assertRaisesRegex(GitHubError, "redirect"),
                ):
                    client.download_source_capsule("owner/repo", base_sha, destination)
                self.assertEqual(len(opener.requests), 1)
                self.assertFalse(destination.exists())

    def test_source_capsule_enforces_stream_cap_and_proves_partial_cleanup(self) -> None:
        client = self.client_with_token()
        root = self.capsule_root()
        base_sha = "a" * 40
        codeload = f"https://codeload.github.com/owner/repo/legacy.tar.gz/{base_sha}"
        opener = _ArchiveOpener(codeload, b"x" * 2049)
        destination = root / "too-large.tar.gz"
        with (
            patch("urllib.request.build_opener", return_value=opener),
            self.assertRaisesRegex(GitHubError, "exceeded"),
        ):
            client.download_source_capsule("owner/repo", base_sha, destination, max_bytes=2048)
        self.assertFalse(destination.exists())

    def test_source_capsule_rejects_unsafe_parent_existing_output_and_request_limit(self) -> None:
        client = self.client_with_token()
        root = self.capsule_root()
        base_sha = "a" * 40
        codeload = f"https://codeload.github.com/owner/repo/legacy.tar.gz/{base_sha}"

        os.chmod(root, 0o755)
        with self.assertRaisesRegex(GitHubError, "owner-private"):
            client.download_source_capsule("owner/repo", base_sha, root / "source.tar.gz")
        os.chmod(root, 0o700)

        destination = root / "source.tar.gz"
        destination.write_bytes(b"sentinel")
        opener = _ArchiveOpener(codeload, b"archive")
        with (
            patch("urllib.request.build_opener", return_value=opener),
            self.assertRaisesRegex(GitHubError, "cannot be created"),
        ):
            client.download_source_capsule("owner/repo", base_sha, destination)
        self.assertEqual(destination.read_bytes(), b"sentinel")

        limited = GitHubClient(
            GitHubConfig(
                token_env="LEFTOVERS_MISSING_TOKEN",
                max_read_requests_per_run=1,
            )
        )
        absent = root / "limited.tar.gz"
        opener = _ArchiveOpener(codeload, b"archive")
        with (
            patch("urllib.request.build_opener", return_value=opener),
            self.assertRaisesRegex(GitHubError, "ceiling"),
        ):
            limited.download_source_capsule("owner/repo", base_sha, absent)
        self.assertFalse(absent.exists())

    def test_malformed_rest_json_is_wrapped_as_github_error(self) -> None:
        client = GitHubClient(GitHubConfig(token_env="LEFTOVERS_MISSING_TOKEN"))
        with (
            patch("urllib.request.urlopen", return_value=_Response(b"{not-json")),
            self.assertRaisesRegex(GitHubError, "malformed JSON"),
        ):
            client._request("GET", "/rate_limit")

    def test_null_graphql_repository_controls_fail_closed(self) -> None:
        client = self.client_with_token()
        with (
            patch.object(
                client,
                "_request",
                return_value={"data": {"repository": None}},
            ),
            self.assertRaisesRegex(GitHubError, "repository policy data"),
        ):
            client._repository_controls("owner/repo")

    def test_null_graphql_issue_is_treated_as_linked(self) -> None:
        client = self.client_with_token()
        with patch.object(
            client,
            "_request",
            return_value={"data": {"repository": {"issue": None}}},
        ):
            self.assertTrue(client._linked_pr_graphql("owner/repo", 1))

    def test_malformed_rest_timeline_fails_closed(self) -> None:
        client = GitHubClient(GitHubConfig(token_env="LEFTOVERS_MISSING_TOKEN"))
        with patch.object(client, "_request", return_value={"unexpected": True}):
            self.assertTrue(client._linked_pr_rest("owner/repo", 1))

    def test_branch_head_requires_an_exact_lowercase_sha(self) -> None:
        client = GitHubClient(GitHubConfig(token_env="LEFTOVERS_MISSING_TOKEN"))
        for value in ("a" * 39, "A" * 40, "main", "a" * 41):
            with (
                self.subTest(value=value),
                patch.object(client, "_request", return_value={"commit": {"sha": value}}),
                self.assertRaisesRegex(GitHubError, "exact lowercase"),
            ):
                client.branch_head("owner/repo", "main")
        with patch.object(client, "_request", return_value={"commit": {"sha": "a" * 40}}):
            self.assertEqual(client.branch_head("owner/repo", "main"), "a" * 40)

    def test_malformed_issue_shape_is_wrapped(self) -> None:
        client = GitHubClient(GitHubConfig(token_env="LEFTOVERS_MISSING_TOKEN"))
        metadata = RepositoryMetadata("owner/repo", 1, False, False, "MIT", "main")
        item = {
            "number": 1,
            "title": "bug",
            "body": "body",
            "html_url": "https://github.com/owner/repo/issues/1",
            "labels": ["not-an-object"],
            "assignees": [],
            "comments": 0,
            "reactions": {"total_count": 0},
            "locked": False,
            "state": "open",
        }
        with (
            patch.object(client, "_has_recent_claim", return_value=False),
            self.assertRaisesRegex(GitHubError, "invalid shape"),
        ):
            client._candidate_from_api(item, metadata, check_linked=False)

    def test_malformed_fixture_json_is_wrapped_as_github_error(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        fixture = root / "issues.json"
        fixture.write_text("[not valid JSON")
        with self.assertRaisesRegex(GitHubError, "cannot read issue fixture"):
            FixtureIssueSource(fixture).discover((), "", 10)

    def test_repository_supply_uses_separate_issue_and_pr_counts(self) -> None:
        client = self.client_with_token()
        observed = datetime(2026, 7, 18, tzinfo=UTC)
        search = {"items": [{"full_name": "small/useful"}]}
        details = {
            "data": {
                "repository": {
                    "nameWithOwner": "small/useful",
                    "url": "https://github.com/small/useful",
                    "description": "A focused useful library",
                    "isArchived": False,
                    "isDisabled": False,
                    "isFork": False,
                    "isLocked": False,
                    "isMirror": False,
                    "isTemplate": False,
                    "stargazerCount": 450,
                    "pushedAt": "2026-07-17T00:00:00Z",
                    "defaultBranchRef": {"name": "main"},
                    "licenseInfo": {"spdxId": "MIT"},
                    "issues": {"totalCount": 80},
                    "pullRequests": {"totalCount": 5},
                    "helpWanted": {
                        "totalCount": 9,
                        "nodes": [
                            {
                                "id": f"issue-{index}",
                                "updatedAt": "2026-07-17T00:00:00Z",
                                "assignees": {"totalCount": 0},
                            }
                            for index in range(3)
                        ],
                    },
                    "goodFirst": {"totalCount": 3, "nodes": []},
                    "recentMerged": {
                        "nodes": [
                            {
                                "mergedAt": "2026-07-10T00:00:00Z",
                                "author": {"login": "maintainer"},
                            },
                            {
                                "mergedAt": "2026-07-11T00:00:00Z",
                                "author": {"login": "contributor"},
                            },
                        ]
                    },
                    "recentClosed": {"nodes": []},
                    "forkingAllowed": True,
                    "hasPullRequestsEnabled": True,
                    "pullRequestCreationPolicy": "ALL",
                }
            }
        }
        with patch.object(client, "_request", side_effect=(search, details)) as request:
            candidates = client.discover_repository_supply(
                RepositorySupplyCriteria(scan_limit=1, result_limit=1),
                observed_at=observed,
            )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].open_issues, 80)
        self.assertEqual(candidates[0].open_pull_requests, 5)
        self.assertEqual(candidates[0].issue_pr_ratio, 16.0)
        self.assertFalse(candidates[0].to_dict()["execution_authorized"])
        search_call = request.call_args_list[0]
        self.assertIn("help-wanted-issues:5..100", search_call.kwargs["query"]["q"])
        self.assertEqual(search_call.kwargs["query"]["sort"], "updated")
        graphql = request.call_args_list[1].kwargs["body"]["query"]
        self.assertIn("pullRequests(states: OPEN)", graphql)

    def test_repository_supply_filters_unknown_license_and_stale_projects(self) -> None:
        client = self.client_with_token()
        observed = datetime(2026, 7, 18, tzinfo=UTC)
        search = {
            "items": [
                {"full_name": "small/no-license"},
                {"full_name": "small/stale"},
            ]
        }

        def details(slug: str, *, spdx: str, pushed_at: str) -> dict[str, object]:
            return {
                "data": {
                    "repository": {
                        "nameWithOwner": slug,
                        "url": f"https://github.com/{slug}",
                        "description": "A focused library",
                        "isArchived": False,
                        "isDisabled": False,
                        "isFork": False,
                        "isLocked": False,
                        "isMirror": False,
                        "isTemplate": False,
                        "stargazerCount": 200,
                        "pushedAt": pushed_at,
                        "defaultBranchRef": {"name": "main"},
                        "licenseInfo": {"spdxId": spdx},
                        "issues": {"totalCount": 100},
                        "pullRequests": {"totalCount": 1},
                        "helpWanted": {"totalCount": 10, "nodes": []},
                        "goodFirst": {"totalCount": 0, "nodes": []},
                        "recentMerged": {"nodes": []},
                        "recentClosed": {"nodes": []},
                        "forkingAllowed": True,
                        "hasPullRequestsEnabled": True,
                        "pullRequestCreationPolicy": "ALL",
                    }
                }
            }

        responses = (
            search,
            details("small/no-license", spdx="NOASSERTION", pushed_at="2026-07-17T00:00:00Z"),
            details("small/stale", spdx="MIT", pushed_at="2025-01-01T00:00:00Z"),
        )
        with patch.object(client, "_request", side_effect=responses):
            candidates = client.discover_repository_supply(
                RepositorySupplyCriteria(
                    scan_limit=2,
                    result_limit=2,
                    min_fresh_invited_issues=1,
                    min_recent_human_activity=0,
                ),
                observed_at=observed,
            )
        self.assertEqual(candidates, [])

    def test_repository_supply_requires_authenticated_read_token(self) -> None:
        client = GitHubClient(GitHubConfig(token_env="LEFTOVERS_MISSING_TOKEN"))
        with self.assertRaisesRegex(GitHubError, "authenticated GitHub read token"):
            client.discover_repository_supply(RepositorySupplyCriteria())


if __name__ == "__main__":
    unittest.main()
