from __future__ import annotations

import unittest
from dataclasses import replace

from leftovers.sbx import controller_sandbox_name
from leftovers.sbx_staging import (
    GIT_BINARY,
    SBX_STAGING_ENABLED,
    STAGING_ROOT,
    CleanCloneEvidence,
    DescriptorIdentity,
    FixtureSbxStagingCapability,
    PrivateStagingRoot,
    RemoteEvidence,
    SbxStagingDisabled,
    SbxStagingError,
    StagingCleanupObservation,
    StagingState,
    build_fixture_staging_plan,
    fixture_sbx_staging_capability,
    fixture_staging_cleanup_receipt,
    prepare_live_sbx_staging_clone,
    staging_marker_sha256,
    validate_fixture_staging_plan,
)

RUN_ID = "a" * 32
BASE_SHA = "b" * 40
MANIFEST_SHA = "c" * 64
REPOSITORY = "openai/leftovers"
OWNER_UID = 501


class Explosive:
    def __getattribute__(self, _name: str) -> object:
        raise AssertionError("source-disabled entry inspected an argument")

    def __repr__(self) -> str:
        raise AssertionError("source-disabled entry rendered an argument")


class SbxDisposableStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.capability = fixture_sbx_staging_capability()
        self.root_identity = DescriptorIdentity(101, 201, OWNER_UID, 0o700)
        self.run_identity = DescriptorIdentity(101, 202, OWNER_UID, 0o700)
        self.clone_identity = DescriptorIdentity(101, 203, OWNER_UID, 0o700)
        self.marker_identity = DescriptorIdentity(101, 204, OWNER_UID, 0o600, kind="file")
        self.root = PrivateStagingRoot(STAGING_ROOT, OWNER_UID, self.root_identity)
        clone_path = f"{STAGING_ROOT}/run-{RUN_ID}/clone"
        marker_sha256 = staging_marker_sha256(
            run_id=RUN_ID,
            sandbox_name=controller_sandbox_name(RUN_ID),
            repository=REPOSITORY,
            base_sha=BASE_SHA,
            source_manifest_sha256=MANIFEST_SHA,
            clone_path=clone_path,
        )
        self.clone = CleanCloneEvidence(
            path=clone_path,
            identity=self.clone_identity,
            root_identity=self.root_identity,
            run_directory_path=f"{STAGING_ROOT}/run-{RUN_ID}",
            run_directory_identity=self.run_identity,
            marker_identity=self.marker_identity,
            marker_sha256=marker_sha256,
            base_sha_observed=BASE_SHA,
            source_manifest_sha256=MANIFEST_SHA,
            tracked_paths=("README.md", "src/main.py"),
            untracked_paths=(),
            ignored_paths=(),
            remotes=(),
            is_normal_clone=True,
            has_symlink=False,
            has_hardlink=False,
            has_alternates=False,
            has_shared_object_store=False,
        )
        self.plan = self.build()

    def build(self, **changes: object):
        values: dict[str, object] = {
            "run_id": RUN_ID,
            "repository": REPOSITORY,
            "base_sha": BASE_SHA,
            "source_manifest_sha256": MANIFEST_SHA,
            "root": self.root,
            "clone": self.clone,
        }
        values.update(changes)
        return build_fixture_staging_plan(self.capability, **values)  # type: ignore[arg-type]

    def observation(self, **changes: object) -> StagingCleanupObservation:
        values: dict[str, object] = {
            "run_id": RUN_ID,
            "sandbox_name": self.plan.sandbox_name,
            "sandbox_destruction_attestation_sha256": "d" * 64,
            "clone_identity_before": self.clone_identity,
            "run_directory_identity_before": self.run_identity,
            "root_identity_before": self.root_identity,
            "marker_identity_before": self.marker_identity,
            "marker_sha256_before": self.clone.marker_sha256,
            "root_identity_after": self.root_identity,
            "sandbox_destruction_proven": True,
            "sandbox_remote_absent": True,
            "no_labeled_containers": True,
            "clone_removed": True,
            "run_directory_removed": True,
            "removal_target_was_exact_run_directory": True,
            "marker_matched": True,
            "parent_chain_matched": True,
        }
        values.update(changes)
        return StagingCleanupObservation(**values)  # type: ignore[arg-type]

    def test_production_entry_is_false_and_rejects_before_poisoned_arguments(self) -> None:
        self.assertFalse(SBX_STAGING_ENABLED)
        with self.assertRaisesRegex(SbxStagingDisabled, "source-disabled"):
            prepare_live_sbx_staging_clone(Explosive(), plan=Explosive())

    def test_fixture_capability_is_singleton_and_cannot_enable_source(self) -> None:
        self.assertIs(self.capability, fixture_sbx_staging_capability())
        with self.assertRaisesRegex(SbxStagingError, "not constructible"):
            FixtureSbxStagingCapability(object())
        forged = object.__new__(FixtureSbxStagingCapability)
        forged._secret = object()
        with self.assertRaisesRegex(SbxStagingError, "capability is invalid"):
            validate_fixture_staging_plan(forged, self.plan)  # type: ignore[arg-type]
        self.assertFalse(SBX_STAGING_ENABLED)

    def test_exact_controller_plan_is_private_fetch_by_immutable_sha_and_binds_provision(
        self,
    ) -> None:
        binding = validate_fixture_staging_plan(self.capability, self.plan)
        self.assertEqual(binding.run_id, RUN_ID)
        self.assertEqual(binding.sandbox_name, self.plan.sandbox_name)
        self.assertEqual(binding.repository, REPOSITORY)
        self.assertEqual(binding.staged_clone_path, self.clone.path)
        self.assertEqual(binding.staging_plan_sha256, self.plan.sha256)
        self.assertEqual(binding.run_directory_identity, self.run_identity)
        self.assertEqual(
            self.plan.git_env[3:7],
            (
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_ATTR_NOSYSTEM", "1"),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("GIT_ASKPASS", "/bin/false"),
            ),
        )
        self.assertEqual(self.plan.fetch_argv[-3:], ("--depth=1", "origin", BASE_SHA))
        self.assertEqual(self.plan.checkout_argv[-2:], ("--force", BASE_SHA))
        self.assertEqual(self.plan.init_argv[0], GIT_BINARY)
        self.assertNotIn("--reference", self.plan.fetch_argv)
        self.assertNotIn("clone", self.plan.fetch_argv)
        self.assertEqual(self.plan.origin_remove_argv[-3:], ("remote", "remove", "origin"))
        self.assertEqual(self.plan.clone.remotes, ())
        self.assertEqual(self.plan.sandbox_remote_name, "sandbox-" + self.plan.sandbox_name)
        self.assertFalse(hasattr(self.plan, "sandbox_remote_add_argv"))
        self.assertFalse(hasattr(self.plan, "sandbox_remote_remove_argv"))

    def test_everyday_checkout_and_protected_or_user_roots_are_rejected(self) -> None:
        with self.assertRaisesRegex(SbxStagingError, "exact disposable"):
            self.build(clone=replace(self.clone, path="/Users/ganesh/Documents/Leftovers"))
        for path in ("/Users/ganesh", "/private/tmp", "/private/tmp/leftovers-sbx-staging/other"):
            with self.subTest(path=path), self.assertRaisesRegex(SbxStagingError, "fixed private"):
                PrivateStagingRoot(path, OWNER_UID, self.root_identity)

    def test_credential_ambient_or_git_helper_config_cannot_enter_exact_plan(self) -> None:
        with self.assertRaisesRegex(SbxStagingError, "fixed and isolated"):
            replace(self.plan, git_env=self.plan.git_env + (("GITHUB_TOKEN", "secret"),))
        unsafe = tuple(
            "credential.helper=store" if item == "credential.helper=" else item
            for item in self.plan.fetch_argv
        )
        with self.assertRaisesRegex(SbxStagingError, "fixed controller"):
            replace(self.plan, fetch_argv=unsafe)
        hooks = tuple(
            "core.hooksPath=/tmp/hooks" if item == "core.hooksPath=/dev/null" else item
            for item in self.plan.fetch_argv
        )
        with self.assertRaisesRegex(SbxStagingError, "fixed controller"):
            replace(self.plan, fetch_argv=hooks)

    def test_unsafe_url_ref_argv_and_nonexact_remote_allowlist_are_rejected(self) -> None:
        with self.assertRaisesRegex(SbxStagingError, "pre-sbx remotes"):
            self.build(
                clone=replace(
                    self.clone,
                    remotes=(
                        RemoteEvidence(
                            "origin",
                            "git@github.com:openai/leftovers.git",
                            "git@github.com:openai/leftovers.git",
                        ),
                    ),
                )
            )
        with self.assertRaisesRegex(SbxStagingError, "base SHA"):
            self.build(base_sha="main")
        with self.assertRaisesRegex(SbxStagingError, "repository"):
            self.build(repository="openai/..")
        with self.assertRaisesRegex(SbxStagingError, "fixed controller"):
            replace(self.plan, checkout_argv=self.plan.checkout_argv + (";rm",))

    def test_base_or_manifest_drift_is_rejected(self) -> None:
        with self.assertRaisesRegex(SbxStagingError, "base SHA drifted"):
            self.build(clone=replace(self.clone, base_sha_observed="d" * 40))
        with self.assertRaisesRegex(SbxStagingError, "manifest drifted"):
            self.build(clone=replace(self.clone, source_manifest_sha256="d" * 64))
        with self.assertRaisesRegex(SbxStagingError, "marker"):
            self.build(clone=replace(self.clone, marker_sha256="d" * 64))

    def test_untracked_ignored_linked_and_shared_clone_inputs_are_rejected(self) -> None:
        cases = (
            lambda: replace(self.clone, untracked_paths=(".env",)),
            lambda: replace(self.clone, ignored_paths=(".cache",)),
            lambda: replace(self.clone, has_symlink=True),
            lambda: replace(self.clone, has_hardlink=True),
            lambda: replace(self.clone, has_alternates=True),
            lambda: replace(self.clone, has_shared_object_store=True),
            lambda: replace(self.clone, is_normal_clone=False),
        )
        for make_clone in cases:
            with self.subTest(case=make_clone), self.assertRaises(SbxStagingError):
                self.build(clone=make_clone())

    def test_run_directory_parent_chain_and_tracked_paths_are_exact(self) -> None:
        replacement = DescriptorIdentity(101, 999, OWNER_UID, 0o700)
        for clone in (
            replace(self.clone, root_identity=replacement),
            replace(self.clone, run_directory_path=f"{STAGING_ROOT}/other"),
            replace(self.clone, run_directory_identity=self.clone_identity),
        ):
            with self.subTest(clone=clone), self.assertRaisesRegex(
                SbxStagingError, "parent chain"
            ):
                self.build(clone=clone)
        unsafe_paths = (
            ("src/control\n.py",),
            ("src/cafe\u0301.py",),
            (("a/" * 32) + "file.py",),
            ("a" * 241,),
        )
        for tracked_paths in unsafe_paths:
            with self.subTest(tracked_paths=tracked_paths), self.assertRaisesRegex(
                SbxStagingError, "tracked path"
            ):
                replace(self.clone, tracked_paths=tracked_paths)

    def test_clean_receipt_requires_exact_remote_container_marker_and_descriptor_proof(
        self,
    ) -> None:
        receipt = fixture_staging_cleanup_receipt(self.capability, self.plan, self.observation())
        self.assertEqual(receipt.state, StagingState.CLEANED)
        for change in (
            {"sandbox_remote_absent": False},
            {"sandbox_destruction_proven": False},
            {"no_labeled_containers": False},
            {"marker_matched": False},
            {"marker_sha256_before": "e" * 64},
            {"marker_identity_before": DescriptorIdentity(101, 205, OWNER_UID, 0o600, kind="file")},
            {"removal_target_was_exact_run_directory": False},
            {"parent_chain_matched": False},
            {"clone_removed": False},
            {"run_directory_removed": False},
        ):
            with self.subTest(change=change):
                pending = fixture_staging_cleanup_receipt(
                    self.capability, self.plan, self.observation(**change)
                )
                self.assertEqual(pending.state, StagingState.CLEANUP_PENDING)

    def test_root_or_parent_replacement_and_broad_delete_are_cleanup_pending(self) -> None:
        replacement = DescriptorIdentity(101, 999, OWNER_UID, 0o700)
        for change in (
            {"root_identity_after": replacement},
            {"root_identity_before": replacement},
            {"run_directory_identity_before": replacement},
            {"removal_target_was_exact_run_directory": False},
        ):
            with self.subTest(change=change):
                receipt = fixture_staging_cleanup_receipt(
                    self.capability, self.plan, self.observation(**change)
                )
                self.assertEqual(receipt.state, StagingState.CLEANUP_PENDING)
                self.assertIn("incomplete", receipt.reason or "")

    def test_public_origin_is_removed_and_controller_has_no_sandbox_remote_add_surface(self) -> None:
        self.assertEqual(self.plan.clone.remotes, ())
        self.assertEqual(self.plan.origin_remove_argv[-3:], ("remote", "remove", "origin"))
        self.assertFalse(hasattr(self.plan, "sandbox_remote_add_argv"))
        with self.assertRaisesRegex(SbxStagingError, "fixed controller"):
            replace(self.plan, origin_remove_argv=self.plan.origin_remove_argv[:-1] + ("upstream",))


if __name__ == "__main__":
    unittest.main()
