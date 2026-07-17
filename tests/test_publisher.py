import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from leftovers.config import PublicationConfig
from leftovers.models import IssueCandidate, RepositoryMetadata
from leftovers.policy import inspect_committed_diff, inspect_diff
from leftovers.publisher import (
    GhPublisher,
    PublicationError,
    create_approval_bundle,
    validate_approval,
)


class PublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root))
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.root, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"], cwd=self.root, check=True
        )
        (self.root / "file.txt").write_text("before\n")
        subprocess.run(["git", "add", "file.txt"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=self.root, check=True)
        self.base_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def issue(self) -> IssueCandidate:
        repo = RepositoryMetadata("owner/repo", 1, False, False, "MIT", "main")
        return IssueCandidate(
            repo,
            1,
            "I_1",
            "Fix bug",
            "body",
            "https://example.test",
            ("help wanted",),
            datetime.now(UTC),
            datetime.now(UTC),
            0,
            0,
            (),
            False,
            "MEMBER",
        )

    def test_publication_requires_all_explicit_gates(self) -> None:
        with self.assertRaises(PublicationError):
            GhPublisher(PublicationConfig()).assert_authorized(True)
        configured = PublicationConfig(mode="draft-pr", external_writes_acknowledged=True)
        with self.assertRaises(PublicationError):
            GhPublisher(configured).assert_authorized(False)
        GhPublisher(configured).assert_authorized(True)

    def test_publish_revalidates_committed_approval_through_all_write_boundaries(
        self,
    ) -> None:
        (self.root / "file.txt").write_text("after\n")
        diff = inspect_diff(self.root)
        issue = self.issue()
        approval = create_approval_bundle(
            run_id="publish-boundaries",
            issue=issue,
            base_sha=self.base_sha,
            base_ref="main",
            diff=diff,
            policy_document={"safe": True},
        )
        publisher = GhPublisher(
            PublicationConfig(
                mode="draft-pr",
                external_writes_acknowledged=True,
                expected_login="bot",
                expected_user_id=123,
            )
        )
        original_run = publisher._run
        calls: list[list[str]] = []
        fork_reads = 0

        def fake_run(
            argv: list[str],
            *,
            cwd: Path | None = None,
            env: dict[str, str] | None = None,
            check: bool = True,
        ) -> subprocess.CompletedProcess[str]:
            nonlocal fork_reads
            calls.append(argv)
            if argv[0] == "git" and "push" not in argv:
                return original_run(argv, cwd=cwd, env=env, check=check)
            if argv[0] == "git" and "push" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:4] == ["gh", "api", "--hostname", "github.com"]:
                endpoint = argv[4]
                if endpoint == "user":
                    return subprocess.CompletedProcess(argv, 0, '{"login":"bot","id":123}', "")
                if "/branches/" in endpoint:
                    return subprocess.CompletedProcess(argv, 1, "", "HTTP 404")
                fork_reads += 1
                if fork_reads == 1:
                    return subprocess.CompletedProcess(argv, 1, "", "HTTP 404")
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    '{"fork":true,"parent":{"full_name":"owner/repo"}}',
                    "",
                )
            if argv[:3] == ["gh", "repo", "fork"]:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[:3] == ["gh", "auth", "token"]:
                return subprocess.CompletedProcess(argv, 0, "fake-token", "")
            if argv[:3] == ["gh", "pr", "list"]:
                return subprocess.CompletedProcess(argv, 0, "[]", "")
            if argv[:3] == ["gh", "pr", "create"]:
                return subprocess.CompletedProcess(
                    argv, 0, "https://github.com/owner/repo/pull/7\n", ""
                )
            if argv[:3] == ["gh", "pr", "view"]:
                head = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=self.root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        {
                            "url": "https://github.com/owner/repo/pull/7",
                            "baseRefName": "main",
                            "body": "body",
                            "headRefOid": head,
                            "isDraft": True,
                            "title": "Fix bug",
                        }
                    ),
                    "",
                )
            raise AssertionError(argv)

        with mock.patch.object(publisher, "_run", side_effect=fake_run):
            result = publisher.publish(
                publish_flag=True,
                workspace=self.root,
                issue=issue,
                diff=diff,
                approval=approval,
                title="Fix bug",
                body="body",
                base_branch="main",
            )

        self.assertEqual(result.pr_url, "https://github.com/owner/repo/pull/7")
        self.assertTrue(any(call[:3] == ["gh", "repo", "fork"] for call in calls))
        self.assertTrue(any(call[0] == "git" and "push" in call for call in calls))
        self.assertTrue(any(call[:3] == ["gh", "pr", "create"] for call in calls))

    def test_fork_shape_validation_fails_closed(self) -> None:
        self.assertFalse(GhPublisher._is_expected_fork([], "owner/repo"))
        self.assertFalse(
            GhPublisher._is_expected_fork(
                {"fork": True, "parent": "not-an-object"},
                "owner/repo",
            )
        )

    def test_expired_approval_blocks_fork_creation_after_read_preflight(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        missing = subprocess.CompletedProcess(["gh", "api"], 1, "", "HTTP 404 Not Found")
        approval_check = mock.Mock(side_effect=PublicationError("approval bundle expired"))
        with (
            mock.patch.object(publisher, "_run", return_value=missing) as run,
            self.assertRaisesRegex(PublicationError, "expired"),
        ):
            publisher._ensure_fork(
                "owner/repo",
                "bot",
                "repo",
                approval_check=approval_check,
            )

        approval_check.assert_called_once_with()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][:2], ["gh", "api"])

    def test_open_pr_preflight_rejects_malformed_owner_shape(self) -> None:
        item = {
            "url": "https://github.com/owner/repo/pull/7",
            "baseRefName": "main",
            "body": "body",
            "headRefName": "leftovers/issue-1",
            "headRefOid": "abc",
            "headRepositoryOwner": "not-an-object",
            "isDraft": True,
            "title": "title",
        }
        with self.assertRaisesRegex(PublicationError, "invalid shape"):
            GhPublisher._validate_open_pr_preflight([item], "owner/repo")

    def test_approval_detects_patch_tampering(self) -> None:
        (self.root / "file.txt").write_text("after\n")
        diff = inspect_diff(self.root)
        bundle = create_approval_bundle(
            run_id="abc",
            issue=self.issue(),
            base_sha=self.base_sha,
            base_ref="main",
            diff=diff,
            policy_document={"safe": True},
        )
        validate_approval(bundle, self.root, issue=self.issue(), base_branch="main")
        (self.root / "file.txt").write_text("different\n")
        with self.assertRaisesRegex(PublicationError, "no longer matches"):
            validate_approval(bundle, self.root)

    def test_approval_binds_base_ref_and_local_head(self) -> None:
        (self.root / "file.txt").write_text("after\n")
        bundle = create_approval_bundle(
            run_id="abc",
            issue=self.issue(),
            base_sha=self.base_sha,
            base_ref="main",
            diff=inspect_diff(self.root),
            policy_document={"safe": True},
        )
        with self.assertRaisesRegex(PublicationError, "base branch"):
            validate_approval(bundle, self.root, issue=self.issue(), base_branch="develop")

        subprocess.run(["git", "add", "file.txt"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "unexpected"], cwd=self.root, check=True)
        with self.assertRaisesRegex(PublicationError, "HEAD"):
            validate_approval(bundle, self.root, issue=self.issue(), base_branch="main")

    def test_committed_tree_can_be_rebound_to_the_approved_diff(self) -> None:
        (self.root / "file.txt").write_text("after\n")
        approved = inspect_diff(self.root)
        subprocess.run(["git", "add", "-A", "--", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "candidate"], cwd=self.root, check=True)
        committed = inspect_committed_diff(
            self.root,
            self.base_sha,
            max_patch_bytes=len(approved.patch.encode()),
        )
        self.assertEqual(committed, approved)

    def test_pr_reconciliation_requires_the_approved_commit(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        expected_url = "https://github.com/owner/repo/pull/7"
        self.assertEqual(
            publisher._reconciled_pr_url(
                [
                    {
                        "url": expected_url,
                        "headRefOid": "approved",
                        "baseRefName": "main",
                        "isDraft": True,
                    }
                ],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
            ),
            expected_url,
        )
        with self.assertRaisesRegex(PublicationError, "head commit"):
            publisher._reconciled_pr_url(
                [
                    {
                        "url": expected_url,
                        "headRefOid": "different",
                        "baseRefName": "main",
                        "isDraft": True,
                    }
                ],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
            )

    def test_pr_reconciliation_requires_a_canonical_pr_url(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        with self.assertRaisesRegex(PublicationError, "unexpected URL"):
            publisher._reconciled_pr_url(
                [
                    {
                        "url": "https://github.com/owner/repo/pull/7/commits",
                        "headRefOid": "approved",
                        "baseRefName": "main",
                        "isDraft": True,
                    }
                ],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
            )

    def test_pr_reconciliation_requires_draft_and_expected_base(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        base = {
            "url": "https://github.com/owner/repo/pull/7",
            "headRefOid": "approved",
            "baseRefName": "main",
            "isDraft": True,
        }
        with self.assertRaisesRegex(PublicationError, "base branch"):
            publisher._reconciled_pr_url(
                [{**base, "baseRefName": "develop"}],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
            )
        with self.assertRaisesRegex(PublicationError, "not a draft"):
            publisher._reconciled_pr_url(
                [{**base, "isDraft": False}],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
            )

    def test_pr_reconciliation_rejects_multiple_open_prs_for_one_branch(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        item = {
            "url": "https://github.com/owner/repo/pull/7",
            "headRefOid": "approved",
            "baseRefName": "main",
            "isDraft": True,
        }
        with self.assertRaisesRegex(PublicationError, "ambiguous"):
            publisher._reconciled_pr_url(
                [item, {**item, "url": "https://github.com/owner/repo/pull/8"}],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
            )

    def test_pr_reconciliation_requires_controller_rendered_copy(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        item = {
            "url": "https://github.com/owner/repo/pull/7",
            "headRefOid": "approved",
            "baseRefName": "main",
            "isDraft": True,
            "title": "unexpected",
            "body": "expected body",
        }
        with self.assertRaisesRegex(PublicationError, "title text"):
            publisher._reconciled_pr_url(
                [item],
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
                expected_title="expected title",
                expected_body="expected body",
            )

    def test_created_pr_is_read_back_and_revalidated(self) -> None:
        publisher = GhPublisher(PublicationConfig())
        returned = subprocess.CompletedProcess(
            [],
            0,
            '{"url":"https://github.com/owner/repo/pull/7",'
            '"headRefOid":"approved","baseRefName":"main","isDraft":false}',
            "",
        )
        with (
            mock.patch.object(publisher, "_run", return_value=returned) as run,
            self.assertRaisesRegex(PublicationError, "not a draft"),
        ):
            publisher._verify_created_pr(
                "https://github.com/owner/repo/pull/7",
                repository="owner/repo",
                expected_head_sha="approved",
                expected_base_branch="main",
                expected_title="Expected title",
                expected_body="Expected body",
            )
        self.assertEqual(run.call_args.args[0][1:3], ["pr", "view"])


if __name__ == "__main__":
    unittest.main()
