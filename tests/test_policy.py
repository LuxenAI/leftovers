import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from leftovers.config import PolicyConfig, RepositoryConfig, ScoringConfig
from leftovers.models import IssueCandidate, RepositoryMetadata
from leftovers.policy import candidate_gate, diff_gate, inspect_diff
from leftovers.scoring import score_issue


class PolicyTests(unittest.TestCase):
    def issue(self, **changes: object) -> IssueCandidate:
        repo = RepositoryMetadata(
            "owner/repo",
            10000,
            False,
            False,
            "MIT",
            "main",
            forking_allowed=True,
            pull_requests_enabled=True,
            pull_request_creation_policy="ALL",
        )
        value = IssueCandidate(
            repo=repo,
            number=1,
            node_id="I_1",
            title="Bug with clear reproduction",
            body="Steps to reproduce. Expected result and actual error with test details.",
            url="https://github.com/owner/repo/issues/1",
            labels=("bug", "help wanted"),
            created_at=datetime(2025, 1, 1, tzinfo=UTC),
            updated_at=datetime(2026, 7, 1, tzinfo=UTC),
            comments=3,
            reactions=10,
            assignees=(),
            locked=False,
            author_association="MEMBER",
            state="open",
        )
        return replace(value, **changes)

    def test_security_and_assignment_are_hard_gates(self) -> None:
        issue = self.issue(labels=("security", "help wanted"), assignees=("someone",))
        repo = RepositoryConfig(slug="owner/repo", importance=1, ai_contributions_allowed=True)
        score = score_issue(issue, repo, ScoringConfig(minimum_score=0))
        failures = candidate_gate(issue, score, repo, PolicyConfig(), 0)
        self.assertTrue(any("security" in failure for failure in failures))
        self.assertIn("issue is assigned", failures)

    def test_security_synonyms_and_prefixed_labels_are_hard_gates(self) -> None:
        repo = RepositoryConfig(
            slug="owner/repo",
            importance=1,
            test_commands=(("test",),),
            ai_contributions_allowed=True,
        )
        for title, labels in (
            ("Stored XSS in HTML renderer", ("bug", "help wanted")),
            ("Parser bug", ("bug", "type: security", "help wanted")),
            ("Update trademark compliance", ("bug", "help wanted")),
            ("Password exposure in debug logs", ("bug", "help wanted")),
        ):
            with self.subTest(title=title, labels=labels):
                issue = self.issue(title=title, labels=labels)
                score = score_issue(issue, repo, ScoringConfig(minimum_score=0))
                failures = candidate_gate(issue, score, repo, PolicyConfig(), 0)
                self.assertTrue(
                    any(
                        "sensitive" in failure
                        or "denied label" in failure
                        or "sensitive unattended scope" in failure
                        for failure in failures
                    )
                )

    def test_closed_issue_and_restricted_pr_policy_are_hard_gates(self) -> None:
        restricted_repo = replace(
            self.issue().repo,
            pull_request_creation_policy="COLLABORATORS_ONLY",
        )
        issue = self.issue(repo=restricted_repo, state="closed")
        repo = RepositoryConfig(
            slug="owner/repo",
            importance=1,
            test_commands=(("test",),),
            ai_contributions_allowed=True,
        )
        score = score_issue(issue, repo, ScoringConfig(minimum_score=0))
        failures = candidate_gate(issue, score, repo, PolicyConfig(), 0)
        self.assertIn("issue is not confirmed open", failures)
        self.assertTrue(any("anyone may create" in failure for failure in failures))

    def test_unknown_ai_policy_fails_closed(self) -> None:
        issue = self.issue()
        repo = RepositoryConfig(slug="owner/repo", importance=1)
        score = score_issue(issue, repo, ScoringConfig(minimum_score=0))
        failures = candidate_gate(issue, score, repo, PolicyConfig(), 0)
        self.assertTrue(any("AI-contribution policy" in failure for failure in failures))

    def test_unrecognized_license_sentinels_fail_closed(self) -> None:
        repo = RepositoryConfig(
            slug="owner/repo",
            importance=1,
            test_commands=(("test",),),
            ai_contributions_allowed=True,
        )
        for spdx in ("NOASSERTION", "OTHER"):
            with self.subTest(spdx=spdx):
                issue = self.issue(repo=replace(self.issue().repo, license_spdx=spdx))
                score = score_issue(issue, repo, ScoringConfig(minimum_score=0))
                failures = candidate_gate(issue, score, repo, PolicyConfig(), 0)
                self.assertIn("repository has no recognized license", failures)

    def test_diff_inspection_includes_new_files_and_blocks_workflows(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "base.txt").write_text("base\n")
        subprocess.run(["git", "add", "base.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        (root / "new.py").write_text("print('safe')\n")
        (root / ".github/workflows").mkdir(parents=True)
        (root / ".github/workflows/pwn.yml").write_text("name: nope\n")
        diff = inspect_diff(root)
        self.assertIn("new.py", diff.files)
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", ai_contributions_allowed=True),
            PolicyConfig(),
        )
        self.assertTrue(any("forbidden path" in failure for failure in failures))

    def test_diff_gate_rejects_control_characters_and_root_secret_files(self) -> None:
        from leftovers.policy import DiffInspection

        diff = DiffInspection(
            files=("odd\nname.py", "private.pem"),
            added_lines=2,
            deleted_lines=0,
            patch="+safe text\n",
        )
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", ai_contributions_allowed=True),
            PolicyConfig(),
        )
        self.assertTrue(any("control character" in failure for failure in failures))
        self.assertIn("forbidden path changed: private.pem", failures)

    def test_invalid_utf8_patch_is_rejected(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "data.txt").write_bytes(b"before\n")
        subprocess.run(["git", "add", "data.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        (root / "data.txt").write_bytes(b"after-\xff\n")
        diff = inspect_diff(root)
        self.assertTrue(diff.invalid_utf8)
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        self.assertIn("patch contains invalid UTF-8 text", failures)

    def test_diff_gate_rejects_new_executables_and_gitlinks(self) -> None:
        from leftovers.policy import DiffInspection

        diff = DiffInspection(
            files=("run.sh", "nested"),
            added_lines=2,
            deleted_lines=0,
            patch=(
                "diff --git a/run.sh b/run.sh\n"
                "new file mode 100755\n"
                "diff --git a/nested b/nested\n"
                "new file mode 160000\n"
            ),
        )
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        self.assertIn("executable-bit changes are forbidden", failures)
        self.assertIn("Git submodule links are forbidden", failures)

    def test_common_dependency_manifests_are_blocked(self) -> None:
        from leftovers.policy import DiffInspection

        manifests = (
            "pom.xml",
            "build.gradle.kts",
            "composer.json",
            "Pipfile",
            "deno.lock",
            "bun.lockb",
            "mix.lock",
            "pubspec.lock",
            "app.csproj",
            "flake.nix",
            "flake.lock",
            "environment.yml",
            "environment.yaml",
            "conda-lock.yml",
            "conda-lock.yaml",
            "deps.edn",
            "project.clj",
            "vcpkg.json",
            "conanfile.txt",
            "conanfile.py",
            "packages.config",
            "requirements/base.txt",
            "services/api/requirements/dev.in",
            "constraints/runtime.txt",
        )
        diff = DiffInspection(
            files=manifests,
            added_lines=len(manifests),
            deleted_lines=0,
            patch="\n".join(f"+++ b/{name}" for name in manifests),
        )
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        for manifest in manifests:
            self.assertIn(f"dependency manifest or lockfile changed: {manifest}", failures)

    def test_git_textconv_and_filter_config_are_rejected_before_diff_execution(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        workspace.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=workspace, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=workspace,
            check=True,
        )
        (workspace / ".gitattributes").write_text("*.txt diff=evil filter=evil\n")
        (workspace / "value.txt").write_text("before\n")
        subprocess.run(["git", "add", "."], cwd=workspace, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=workspace, check=True)
        marker = root / "executed"
        command = f"sh -c 'touch {marker}; cat \"$1\"' sh"
        subprocess.run(
            ["git", "config", "diff.evil.textconv", command],
            cwd=workspace,
            check=True,
        )
        subprocess.run(
            ["git", "config", "filter.evil.clean", command],
            cwd=workspace,
            check=True,
        )
        (workspace / "value.txt").write_text("after\n")

        diff = inspect_diff(workspace)

        self.assertFalse(marker.exists())
        self.assertEqual(diff.files, ())
        self.assertTrue(
            any("unsafe repository Git configuration" in item for item in diff.structural_failures)
        )

    def test_global_git_config_is_ignored_by_controller_diff(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        workspace = root / "repo"
        workspace.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=workspace, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=workspace,
            check=True,
        )
        (workspace / ".gitattributes").write_text("*.txt diff=evil\n")
        (workspace / "value.txt").write_text("before\n")
        subprocess.run(["git", "add", "."], cwd=workspace, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=workspace, check=True)
        marker = root / "global-executed"
        (root / ".gitconfig").write_text(
            f'[diff "evil"]\n\ttextconv = sh -c \'touch {marker}; cat "$1"\' sh\n'
        )
        (workspace / "value.txt").write_text("after\n")

        diff = inspect_diff(workspace)

        self.assertFalse(marker.exists())
        self.assertEqual(diff.files, ("value.txt",))

    def test_many_untracked_paths_are_refused_before_index_or_mode_work(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "base.txt").write_text("base\n")
        subprocess.run(["git", "add", "base.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        for index in range(101):
            (root / f"untracked-{index:03d}.txt").write_text("x\n")

        diff = inspect_diff(root)

        self.assertEqual(diff.files, ())
        self.assertIn("untracked path count exceeds 100", diff.structural_failures)
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(staged.stdout, "")

    def test_workflow_and_infrastructure_baseline_cannot_be_overridden(self) -> None:
        from leftovers.policy import DiffInspection

        protected = (
            ".github/actions/bootstrap/action.yml",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            ".buildkite/pipeline.yml",
            "Jenkinsfile.release",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
            ".travis.yml",
            "infra/main.tf",
            "services/api/terraform/providers.tf",
            "k8s/deployment.yaml",
            "deploy/helm/values.yaml",
            "charts/service/Chart.yaml",
            "Dockerfile.release",
            "ops/docker-compose.prod.yml",
            "deploy/service.yaml",
            "services/api/deployment/service.yaml",
            "scripts/deploy-production.sh",
        )
        diff = DiffInspection(
            files=protected,
            added_lines=len(protected),
            deleted_lines=0,
            patch="\n".join(f"+++ b/{name}" for name in protected),
        )

        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(forbid_paths=()),
        )

        for filename in protected:
            with self.subTest(filename=filename):
                self.assertIn(f"forbidden path changed: {filename}", failures)

    def test_forbidden_source_path_cannot_be_hidden_by_rename(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        workflow = root / ".github/workflows/check.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: check\n")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        subprocess.run(
            ["git", "mv", ".github/workflows/check.yml", "safe.yml"],
            cwd=root,
            check=True,
        )
        diff = inspect_diff(root)
        self.assertIn(".github/workflows/check.yml", diff.files)
        self.assertIn("safe.yml", diff.files)
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        self.assertTrue(any("forbidden path" in failure for failure in failures))

    def test_existing_symlink_target_change_is_structurally_blocked(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "first").write_text("first\n")
        (root / "second").write_text("second\n")
        (root / "link").symlink_to("first")
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        (root / "link").unlink()
        (root / "link").symlink_to("second")
        diff = inspect_diff(root)
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        self.assertIn("symbolic-link path changed: link", failures)

    def test_license_files_are_always_forbidden(self) -> None:
        from leftovers.policy import DiffInspection

        diff = DiffInspection(
            files=("LICENSE", "docs/NOTICE-third-party"),
            added_lines=2,
            deleted_lines=0,
            patch="+legal text\n",
        )
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        self.assertIn("forbidden path changed: LICENSE", failures)
        self.assertIn("forbidden path changed: docs/NOTICE-third-party", failures)

    def test_non_utf8_changed_path_is_rejected(self) -> None:
        from leftovers.policy import DiffInspection

        diff = DiffInspection(
            files=("bad-\udcff.txt",),
            added_lines=1,
            deleted_lines=0,
            patch="+content\n",
        )
        failures = diff_gate(
            diff,
            RepositoryConfig(slug="owner/repo", test_commands=(("test",),)),
            PolicyConfig(),
        )
        self.assertTrue(any("not valid UTF-8" in failure for failure in failures))

    def test_git_pathspec_magic_in_filename_is_treated_literally(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        (root / "base.txt").write_text("base\n")
        subprocess.run(["git", "add", "base.txt"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
        (root / ":literal.txt").write_text("safe\n")
        diff = inspect_diff(root)
        self.assertIn(":literal.txt", diff.files)


if __name__ == "__main__":
    unittest.main()
