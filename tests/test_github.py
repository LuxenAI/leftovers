import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from leftovers.config import GitHubConfig
from leftovers.github import FixtureIssueSource, GitHubClient, GitHubError
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


class GitHubClientTests(unittest.TestCase):
    def client_with_token(self) -> GitHubClient:
        with patch.dict("os.environ", {"LEFTOVERS_TEST_GH_TOKEN": "redacted"}):
            return GitHubClient(GitHubConfig(token_env="LEFTOVERS_TEST_GH_TOKEN"))

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


if __name__ == "__main__":
    unittest.main()
