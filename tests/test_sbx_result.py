from __future__ import annotations

import dataclasses
import hashlib
import json
import unittest
from dataclasses import replace

from leftovers.sbx import controller_sandbox_name
from leftovers.sbx_execution import RUN_TOKEN_CAP, ExecutionStage
from leftovers.sbx_result import (
    CURRENT_SBX_ACTIVATION_BLOCKERS,
    DOCKER_SANDBOX_RESULT_ENABLED,
    FIXED_CAPTURE_DEADLINE_MS,
    HANDOFF_KIND,
    MAX_CAPTURE_BYTES,
    MAX_CHANGED_LINES,
    MAX_FRESH_BASE_AGE_NS,
    MAX_PATCH_BYTES,
    SBX_V035_DESTRUCTION_ATTESTATION_AVAILABLE,
    SBX_V035_POST_STOP_EXPORT_AVAILABLE,
    SBX_V035_UUID_GENERATION_ATTESTATION_AVAILABLE,
    CapabilityFreeSbxHandoff,
    ControllerResultEvidence,
    DescriptorIdentity,
    ExactCallUsage,
    ExactUsageReceipt,
    FixtureSbxResultCapability,
    FreshBaseRecheck,
    IndependentVerifierReceipt,
    RunningCaptureEvidence,
    SbxCleanupPending,
    SbxResultDisabled,
    SbxResultError,
    SbxResultPlan,
    SbxRunBinding,
    StopCleanupEvidence,
    VerifierCheckReceipt,
    encode_fixture_result,
    fixture_sbx_result_capability,
    inspect_canonical_patch,
    usage_event_stream_tree_sha256,
    verify_sbx_result,
    verify_sbx_result_fixture,
)

UUID = "123e4567-e89b-42d3-a456-426614174000"
RUN_ID = "a" * 32
BASE_SHA = "b" * 40
SOURCE_MANIFEST = "c" * 64
POLICY_SHA = "d" * 64
SECRET_SHA = "e" * 64
BOOT_SHA = "1" * 64
CHALLENGE_SHA = "2" * 64
VERIFIER_SHA = "3" * 64
PROFILE_SHA = "4" * 64
DAEMON_RECEIPT_SHA = "5" * 64
REMOTE_RECEIPT_SHA = "6" * 64
OUTPUT_SHA = "7" * 64
EVENT_SHA = "8" * 64
RESERVATION_SHA = "9" * 64
DIFF_SHA = "f" * 64

CAPTURE_START_NS = 100
CAPTURE_FINISH_NS = 200
STOP_NS = 300
CLEANUP_NS = 400
PARSE_NS = 500
VERIFY_NS = 600
RESULT_NS = 650
BASE_NS = 700
HANDOFF_NS = 701

PATCH = (
    b"diff --git a/src/example.py b/src/example.py\n"
    b"index 1111111..2222222 100644\n"
    b"--- a/src/example.py\n"
    b"+++ b/src/example.py\n"
    b"@@ -1 +1 @@\n"
    b"-before\n"
    b"+after\n"
)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        + b"\n"
    )


class SbxResultContractTests(unittest.TestCase):
    def binding(self, **changes: object) -> SbxRunBinding:
        values: dict[str, object] = {
            "daemon_sandbox_uuid": UUID,
            "daemon_sandbox_generation": 1,
            "controller_sandbox_name": controller_sandbox_name(RUN_ID),
            "controller_run_id": RUN_ID,
            "repository": "owner/repo",
            "issue_number": 17,
            "base_sha": BASE_SHA,
            "source_manifest_sha256": SOURCE_MANIFEST,
            "policy_epoch": 11,
            "policy_sha256": POLICY_SHA,
            "secret_epoch": 12,
            "secret_inventory_sha256": SECRET_SHA,
            "model": "gpt-5.6-terra",
            "reasoning_effort": "high",
            "total_token_cap": RUN_TOKEN_CAP,
        }
        values.update(changes)
        return SbxRunBinding(**values)  # type: ignore[arg-type]

    def plan(self, **changes: object) -> SbxResultPlan:
        values: dict[str, object] = {
            "binding": self.binding(),
            "controller_uid": 501,
            "controller_boot_sha256": BOOT_SHA,
            "freshness_challenge_sha256": CHALLENGE_SHA,
            "verifier_identity_sha256": VERIFIER_SHA,
            "verification_profile_sha256": PROFILE_SHA,
            "required_check_ids": ("lint", "unit"),
        }
        values.update(changes)
        return SbxResultPlan(**values)  # type: ignore[arg-type]

    def call_usage(
        self,
        stage: ExecutionStage,
        call_index: int,
        event_stream_sha256: str,
        **changes: object,
    ) -> ExactCallUsage:
        values: dict[str, object] = {
            "stage": stage,
            "call_index": call_index,
            "input_tokens": 100,
            "output_tokens": 40,
            "cached_input_tokens": 20,
            "cache_write_input_tokens": 10,
            "reasoning_tokens": 30,
            "total_tokens": 140,
            "source": "codex-cli-jsonl-v1",
            "exact": True,
            "event_stream_sha256": event_stream_sha256,
            "thread_id": f"thread-{call_index}",
            "reservation_sha256": RESERVATION_SHA,
        }
        values.update(changes)
        return ExactCallUsage(**values)  # type: ignore[arg-type]

    def usage(self, **changes: object) -> ExactUsageReceipt:
        calls = (
            self.call_usage(ExecutionStage.PLANNING, 0, EVENT_SHA),
            self.call_usage(ExecutionStage.IMPLEMENTATION, 1, "a" * 64),
            self.call_usage(ExecutionStage.VERIFICATION, 2, "b" * 64),
        )
        values: dict[str, object] = {
            "calls": calls,
            "input_tokens": 300,
            "output_tokens": 120,
            "cached_input_tokens": 60,
            "cache_write_input_tokens": 30,
            "reasoning_tokens": 90,
            "total_tokens": 420,
            "source": "codex-cli-jsonl-v1",
            "exact": True,
            "provider_call_count": 3,
            "aggregate_event_stream_sha256": usage_event_stream_tree_sha256(calls),
            "reservation_sha256": RESERVATION_SHA,
        }
        values.update(changes)
        return ExactUsageReceipt(**values)  # type: ignore[arg-type]

    def cleanup(self, plan: SbxResultPlan, **changes: object) -> StopCleanupEvidence:
        values: dict[str, object] = {
            "binding_sha256": plan.binding.sha256,
            "controller_boot_sha256": BOOT_SHA,
            "stop_observed_monotonic_ns": STOP_NS,
            "cleanup_observed_monotonic_ns": CLEANUP_NS,
            "identity_attestation_sha256": DAEMON_RECEIPT_SHA,
            "destruction_attestation_sha256": "a" * 64,
            "stop_command_sha256": "b" * 64,
            "remove_command_sha256": "c" * 64,
            "final_list_sha256": "d" * 64,
            "stop_returncode": 0,
            "remove_returncode": 0,
            "stop_acknowledged": True,
            "removal_acknowledged": True,
            "exact_name_absent": True,
            "sandbox_instance_absent": True,
            "identity_authority_independent": True,
            "destruction_authority_independent": True,
            "uncertainty_reason": None,
        }
        values.update(changes)
        return StopCleanupEvidence(**values)  # type: ignore[arg-type]

    def root(self, **changes: object) -> DescriptorIdentity:
        values: dict[str, object] = {
            "device": 1,
            "inode": 100,
            "owner_uid": 501,
            "owner_gid": 20,
            "permissions": 0o700,
            "link_count": 2,
            "kind": "directory",
        }
        values.update(changes)
        return DescriptorIdentity(**values)  # type: ignore[arg-type]

    def parent(self, **changes: object) -> DescriptorIdentity:
        values: dict[str, object] = {
            "device": 1,
            "inode": 99,
            "owner_uid": 0,
            "owner_gid": 0,
            "permissions": 0o755,
            "link_count": 2,
            "kind": "directory",
        }
        values.update(changes)
        return DescriptorIdentity(**values)  # type: ignore[arg-type]

    def capture(
        self,
        plan: SbxResultPlan,
        patch: bytes,
        **changes: object,
    ) -> RunningCaptureEvidence:
        root = self.root()
        parent = self.parent()
        values: dict[str, object] = {
            "binding_sha256": plan.binding.sha256,
            "controller_boot_sha256": BOOT_SHA,
            "capture_started_monotonic_ns": CAPTURE_START_NS,
            "capture_finished_monotonic_ns": CAPTURE_FINISH_NS,
            "capture_command_sha256": "e" * 64,
            "capture_output_sha256": "f" * 64,
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
            "patch_bytes": len(patch),
            "root_at_open": root,
            "root_descriptor_after": root,
            "root_entry_after": root,
            "parent_at_open": parent,
            "parent_after": parent,
            "transport": "sbx-cp-v0.35-fixed-files",
            "remote_relative_paths": (".leftovers-export/canonical.patch",),
            "artifact_names": ("canonical.patch",),
            "cp_options": (),
            "destination_quota_bytes": MAX_CAPTURE_BYTES,
            "capture_deadline_ms": FIXED_CAPTURE_DEADLINE_MS,
            "opened_nofollow": True,
            "descriptor_cloexec": True,
            "fixed_cp_used": True,
            "follow_links": False,
            "generic_cp_used": False,
            "issue_controlled_path_used": False,
            "sandbox_running_before": True,
            "sandbox_running_after": True,
            "destination_regular_files": True,
            "destination_unaliased_files": True,
            "destination_quota_enforced": True,
            "capture_deadline_enforced": True,
            "capture_process_reaped": True,
            "bytes_unparsed": True,
        }
        values.update(changes)
        return RunningCaptureEvidence(**values)  # type: ignore[arg-type]

    def checks(self, **changes: object) -> tuple[VerifierCheckReceipt, ...]:
        first: dict[str, object] = {
            "check_id": "lint",
            "exit_code": 0,
            "timed_out": False,
            "truncated": False,
            "output_sha256": OUTPUT_SHA,
        }
        first.update(changes)
        return (
            VerifierCheckReceipt(**first),  # type: ignore[arg-type]
            VerifierCheckReceipt("unit", 0, False, False, OUTPUT_SHA),
        )

    def verifier(
        self,
        plan: SbxResultPlan,
        cleanup: StopCleanupEvidence,
        capture: RunningCaptureEvidence,
        patch: bytes,
        **changes: object,
    ) -> IndependentVerifierReceipt:
        summary = inspect_canonical_patch(patch, forbidden_paths=plan.forbidden_paths)
        values: dict[str, object] = {
            "binding_sha256": plan.binding.sha256,
            "controller_boot_sha256": BOOT_SHA,
            "freshness_challenge_sha256": CHALLENGE_SHA,
            "verifier_identity_sha256": VERIFIER_SHA,
            "verification_profile_sha256": PROFILE_SHA,
            "parse_started_monotonic_ns": PARSE_NS,
            "verified_monotonic_ns": VERIFY_NS,
            "capture_sha256": capture.sha256,
            "cleanup_sha256": cleanup.sha256,
            "applied_patch_sha256": summary.sha256,
            "inspected_patch_sha256": summary.sha256,
            "inspected_diff_sha256": DIFF_SHA,
            "source_manifest_sha256": SOURCE_MANIFEST,
            "policy_sha256": POLICY_SHA,
            "base_sha": BASE_SHA,
            "changed_paths": summary.paths,
            "changed_lines": summary.changed_lines,
            "checks": self.checks(),
            "parse_root_descriptor": capture.root_at_open,
            "parse_root_entry": capture.root_at_open,
            "verifier_sandbox_uuid": "223e4567-e89b-42d3-a456-426614174000",
            "verifier_sandbox_generation": 1,
            "verifier_instance_attestation_sha256": "0" * 64,
            "verifier_cleanup_attestation_sha256": "1" * 64,
            "independent_domain": True,
            "fresh_verifier_sandbox": True,
            "worker_mount_absent": True,
            "network_denied": True,
            "credentials_absent": True,
            "reconstructed_source": True,
            "policy_allowed": True,
            "unresolved_review": False,
            "capture_root_removed": True,
            "verification_sandbox_removed": True,
        }
        values.update(changes)
        return IndependentVerifierReceipt(**values)  # type: ignore[arg-type]

    def controller_result(
        self,
        plan: SbxResultPlan,
        document: bytes,
        usage: ExactUsageReceipt,
        patch: bytes,
        **changes: object,
    ) -> ControllerResultEvidence:
        root = self.root(inode=200)
        parent = self.parent(inode=199)
        values: dict[str, object] = {
            "binding_sha256": plan.binding.sha256,
            "controller_boot_sha256": BOOT_SHA,
            "freshness_challenge_sha256": CHALLENGE_SHA,
            "constructed_monotonic_ns": RESULT_NS,
            "result_sha256": hashlib.sha256(document).hexdigest(),
            "result_bytes": len(document),
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
            "source_usage_sha256": usage.sha256,
            "source_event_stream_sha256": usage.aggregate_event_stream_sha256,
            "root_at_open": root,
            "root_descriptor_after": root,
            "root_entry_after": root,
            "parent_at_open": parent,
            "parent_after": parent,
            "artifact_name": "result.json",
            "opened_nofollow": True,
            "descriptor_cloexec": True,
            "controller_constructed": True,
            "constructed_from_exact_usage": True,
            "workspace_result_bytes_used": False,
            "result_regular_file": True,
            "result_unaliased_file": True,
            "result_root_removed": True,
        }
        values.update(changes)
        return ControllerResultEvidence(**values)  # type: ignore[arg-type]

    def base_recheck(
        self,
        plan: SbxResultPlan,
        verifier: IndependentVerifierReceipt,
        controller_result: ControllerResultEvidence,
        **changes: object,
    ) -> FreshBaseRecheck:
        values: dict[str, object] = {
            "binding_sha256": plan.binding.sha256,
            "controller_boot_sha256": BOOT_SHA,
            "freshness_challenge_sha256": CHALLENGE_SHA,
            "verifier_sha256": verifier.sha256,
            "controller_result_sha256": controller_result.sha256,
            "observed_monotonic_ns": BASE_NS,
            "repository": "owner/repo",
            "issue_number": 17,
            "observed_base_sha": BASE_SHA,
            "remote_read_receipt_sha256": REMOTE_RECEIPT_SHA,
            "issue_open": True,
            "assignment_clear": True,
            "linked_or_open_pr_absent": True,
        }
        values.update(changes)
        return FreshBaseRecheck(**values)  # type: ignore[arg-type]

    def evidence(self, *, patch: bytes = PATCH):
        plan = self.plan()
        usage = self.usage()
        cleanup = self.cleanup(plan)
        document = encode_fixture_result(
            plan,
            patch=patch,
            usage=usage,
            fixture_capability=fixture_sbx_result_capability(),
        )
        capture = self.capture(plan, patch)
        verifier = self.verifier(plan, cleanup, capture, patch)
        controller_result = self.controller_result(plan, document, usage, patch)
        base = self.base_recheck(plan, verifier, controller_result)
        return plan, usage, cleanup, document, capture, verifier, controller_result, base

    def verify(self, *, patch: bytes = PATCH, **changes: object) -> CapabilityFreeSbxHandoff:
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = self.evidence(
            patch=patch
        )
        values: dict[str, object] = {
            "plan": plan,
            "result_document": document,
            "patch": patch,
            "cleanup": cleanup,
            "capture": capture,
            "verifier": verifier,
            "controller_result": controller_result,
            "base_recheck": base,
            "handoff_observed_monotonic_ns": HANDOFF_NS,
            "fixture_capability": fixture_sbx_result_capability(),
        }
        values.update(changes)
        return verify_sbx_result_fixture(**values)  # type: ignore[arg-type]

    def test_production_gate_rejects_before_paths_or_executor(self) -> None:
        self.assertFalse(DOCKER_SANDBOX_RESULT_ENABLED)
        self.assertFalse(SBX_V035_UUID_GENERATION_ATTESTATION_AVAILABLE)
        self.assertFalse(SBX_V035_DESTRUCTION_ATTESTATION_AVAILABLE)
        self.assertFalse(SBX_V035_POST_STOP_EXPORT_AVAILABLE)
        self.assertEqual(len(CURRENT_SBX_ACTIVATION_BLOCKERS), 3)

        class Poison:
            def __getattribute__(self, _name: str):
                raise AssertionError("production gate inspected an argument")

            def __fspath__(self) -> str:
                raise AssertionError("production gate inspected a path")

            def __call__(self, *_args: object, **_kwargs: object) -> None:
                raise AssertionError("production gate called an executor")

        poison = Poison()
        with self.assertRaisesRegex(SbxResultDisabled, "before paths or executors"):
            verify_sbx_result(poison, artifact_root=poison, executor=poison)

    def test_fixture_capability_is_explicit_and_cannot_toggle_source_gate(self) -> None:
        with self.assertRaisesRegex(SbxResultError, "not constructible"):
            FixtureSbxResultCapability(object())
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        with self.assertRaisesRegex(SbxResultError, "explicit fixture"):
            verify_sbx_result_fixture(
                plan,
                result_document=document,
                patch=PATCH,
                cleanup=cleanup,
                capture=capture,
                verifier=verifier,
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=object(),  # type: ignore[arg-type]
            )
        self.assertFalse(DOCKER_SANDBOX_RESULT_ENABLED)

    def test_happy_chain_returns_only_bounded_capability_free_data(self) -> None:
        handoff = self.verify()
        self.assertEqual(handoff.kind, HANDOFF_KIND)
        self.assertEqual(handoff.canonical_patch, PATCH)
        self.assertEqual(handoff.patch_sha256, hashlib.sha256(PATCH).hexdigest())
        self.assertEqual(handoff.changed_paths, ("src/example.py",))
        self.assertEqual(handoff.changed_lines, 2)
        self.assertEqual(handoff.usage.total_tokens, 420)
        self.assertEqual(handoff.usage.provider_call_count, 3)
        self.assertFalse(hasattr(handoff, "path"))
        self.assertFalse(hasattr(handoff, "executor"))
        self.assertFalse(hasattr(handoff, "publisher"))
        self.assertFalse(
            any(
                isinstance(getattr(handoff, field.name), FixtureSbxResultCapability)
                for field in dataclasses.fields(handoff)
            )
        )
        with self.assertRaisesRegex(SbxResultError, "in-module construction"):
            CapabilityFreeSbxHandoff(
                kind=handoff.kind,
                binding=handoff.binding,
                canonical_patch=handoff.canonical_patch,
                patch_sha256=handoff.patch_sha256,
                result_sha256=handoff.result_sha256,
                usage=handoff.usage,
                cleanup_sha256=handoff.cleanup_sha256,
                capture_sha256=handoff.capture_sha256,
                verifier_sha256=handoff.verifier_sha256,
                controller_result_sha256=handoff.controller_result_sha256,
                base_recheck_sha256=handoff.base_recheck_sha256,
                changed_paths=handoff.changed_paths,
                changed_lines=handoff.changed_lines,
                seal=object(),
            )

    def test_result_is_exact_canonical_schema_and_digest_bound(self) -> None:
        plan, usage, cleanup, document, capture, verifier, controller_result, base = self.evidence()
        parsed = json.loads(document)
        self.assertEqual(canonical(parsed), document)
        self.assertEqual(controller_result.result_sha256, hashlib.sha256(document).hexdigest())
        self.assertNotIn("result.json", capture.artifact_names)
        self.assertEqual(len(parsed["usage"]["calls"]), 3)

        cases = {
            "unknown": canonical({**parsed, "extra": 1}),
            "duplicate": b'{"kind":"duplicate",' + document[1:],
            "whitespace": document.replace(b'"kind":', b'"kind": '),
            "float": document.replace(b'"total_token_cap":55000', b'"total_token_cap":55000.0'),
            "integer digit bomb": document.replace(
                b'"policy_epoch":11',
                b'"policy_epoch":' + b"9" * 5_000,
            ),
            "non_nfc": document.replace(
                b'"repository":"owner/repo"', '"repository":"ownér/repo"'.encode()
            ),
        }
        for label, malformed in cases.items():
            with self.subTest(label=label), self.assertRaises(SbxResultError):
                malformed_controller_result = self.controller_result(
                    plan,
                    malformed,
                    usage,
                    PATCH,
                )
                verify_sbx_result_fixture(
                    plan,
                    result_document=malformed,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=capture,
                    verifier=verifier,
                    controller_result=malformed_controller_result,
                    base_recheck=self.base_recheck(
                        plan,
                        verifier,
                        malformed_controller_result,
                    ),
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )
        self.assertEqual(usage.sha256, hashlib.sha256(canonical(usage.to_dict())).hexdigest())

    def test_workspace_capture_is_patch_only_and_cannot_supply_result_bytes(self) -> None:
        _plan, _usage, _cleanup, _document, capture, _verifier, controller_result, _base = (
            self.evidence()
        )
        self.assertEqual(capture.remote_relative_paths, (".leftovers-export/canonical.patch",))
        self.assertEqual(capture.artifact_names, ("canonical.patch",))
        self.assertFalse(hasattr(capture, "result_sha256"))
        self.assertFalse(controller_result.workspace_result_bytes_used)
        with self.assertRaisesRegex(SbxResultError, "source name"):
            replace(
                capture,
                remote_relative_paths=(
                    ".leftovers-export/result.json",
                    ".leftovers-export/canonical.patch",
                ),
            )
        with self.assertRaisesRegex(SbxResultError, "destination name"):
            replace(capture, artifact_names=("result.json", "canonical.patch"))

    def test_controller_result_is_jsonl_derived_and_post_verification_only(self) -> None:
        plan, usage, cleanup, document, capture, verifier, controller_result, base = self.evidence()
        self.assertGreater(
            controller_result.constructed_monotonic_ns,
            verifier.verified_monotonic_ns,
        )
        cases = (
            replace(controller_result, binding_sha256="0" * 64),
            replace(controller_result, result_sha256="0" * 64),
            replace(controller_result, result_bytes=len(document) + 1),
            replace(controller_result, patch_sha256="0" * 64),
            replace(controller_result, source_usage_sha256="0" * 64),
            replace(controller_result, source_event_stream_sha256="0" * 64),
            replace(controller_result, constructed_monotonic_ns=VERIFY_NS),
            replace(controller_result, root_at_open=self.root(inode=200, permissions=0o750)),
            replace(controller_result, root_descriptor_after=self.root(inode=201)),
            replace(controller_result, workspace_result_bytes_used=True),
            replace(controller_result, controller_constructed=False),
            replace(controller_result, constructed_from_exact_usage=False),
            replace(controller_result, result_regular_file=False),
            replace(controller_result, result_unaliased_file=False),
        )
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(SbxResultError):
                changed_base = self.base_recheck(plan, verifier, changed)
                verify_sbx_result_fixture(
                    plan,
                    result_document=document,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=capture,
                    verifier=verifier,
                    controller_result=changed,
                    base_recheck=changed_base,
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )
        self.assertEqual(controller_result.source_usage_sha256, usage.sha256)
        self.assertEqual(base.controller_result_sha256, controller_result.sha256)

    def test_result_binds_every_controller_and_daemon_identity(self) -> None:
        plan, usage, cleanup, document, capture, verifier, _controller_result, _base = (
            self.evidence()
        )
        original = json.loads(document)
        substitutions = {
            "daemon_sandbox_uuid": "123e4567-e89b-42d3-a456-426614174001",
            "daemon_sandbox_generation": 2,
            "controller_sandbox_name": "leftovers-ffffffffffffffffffffffff",
            "controller_run_id": "0" * 32,
            "repository": "other/repo",
            "issue_number": 18,
            "base_sha": "0" * 40,
            "source_manifest_sha256": "0" * 64,
            "policy_epoch": 13,
            "policy_sha256": "a" * 64,
            "secret_epoch": 14,
            "secret_inventory_sha256": "b" * 64,
            "model": "other-model",
            "reasoning_effort": "low",
            "total_token_cap": 9_999,
        }
        for field, replacement in substitutions.items():
            changed = json.loads(document)
            changed["binding"][field] = replacement
            changed_document = canonical(changed)
            changed_controller_result = self.controller_result(
                plan,
                changed_document,
                usage,
                PATCH,
            )
            with self.subTest(field=field), self.assertRaises(SbxResultError):
                verify_sbx_result_fixture(
                    plan,
                    result_document=changed_document,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=capture,
                    verifier=verifier,
                    controller_result=changed_controller_result,
                    base_recheck=self.base_recheck(
                        plan,
                        verifier,
                        changed_controller_result,
                    ),
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )
        self.assertEqual(original["binding"], plan.binding.to_dict())

    def test_result_binding_rejects_a_valid_but_underived_sandbox_name(self) -> None:
        with self.assertRaisesRegex(SbxResultError, "not derived"):
            self.binding(controller_sandbox_name="leftovers-ffffffffffffffffffffffff")

    def test_terra_high_and_exact_usage_cannot_be_weakened(self) -> None:
        for changes in ({"model": "gpt-5.6-sol"}, {"reasoning_effort": "medium"}):
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(SbxResultError, "Terra-high"),
            ):
                self.binding(**changes)
        invalid_usage = (
            {"exact": False},
            {"source": "model-output"},
            {"provider_call_count": 2},
            {"total_tokens": 419},
            {"cached_input_tokens": 101},
            {"cache_write_input_tokens": 101},
            {"reasoning_tokens": 41},
            {"input_tokens": True},
            {"aggregate_event_stream_sha256": "0" * 64},
        )
        for changes in invalid_usage:
            with self.subTest(changes=changes), self.assertRaises(SbxResultError):
                self.usage(**changes)

        with self.assertRaisesRegex(SbxResultError, "three-call run cap"):
            self.binding(total_token_cap=RUN_TOKEN_CAP - 1)

    def test_usage_binds_exact_three_stage_receipts_and_stage_caps(self) -> None:
        usage = self.usage()
        self.assertEqual(
            tuple(call.stage for call in usage.calls),
            (
                ExecutionStage.PLANNING,
                ExecutionStage.IMPLEMENTATION,
                ExecutionStage.VERIFICATION,
            ),
        )
        self.assertEqual(
            usage.aggregate_event_stream_sha256,
            usage_event_stream_tree_sha256(usage.calls),
        )
        for calls in (
            usage.calls[:1],
            tuple(reversed(usage.calls)),
            (usage.calls[0], usage.calls[0], usage.calls[2]),
        ):
            with self.subTest(calls=calls), self.assertRaises(SbxResultError):
                self.usage(calls=calls)
        with self.assertRaisesRegex(SbxResultError, "stage cap"):
            self.call_usage(
                ExecutionStage.PLANNING,
                0,
                EVENT_SHA,
                input_tokens=8_001,
                output_tokens=0,
                total_tokens=8_001,
            )
        with self.assertRaisesRegex(SbxResultError, "call index"):
            self.call_usage(ExecutionStage.PLANNING, 1, EVENT_SHA)

    def test_cleanup_uncertainty_always_wins_over_malformed_output(self) -> None:
        plan, _usage, cleanup, _document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        cases = (
            replace(cleanup, exact_name_absent=False),
            replace(cleanup, sandbox_instance_absent=False),
            replace(cleanup, identity_authority_independent=False),
            replace(cleanup, destruction_authority_independent=False),
            replace(cleanup, stop_returncode=1),
            replace(cleanup, uncertainty_reason="daemon response lost"),
            replace(cleanup, binding_sha256="0" * 64),
            replace(cleanup, cleanup_observed_monotonic_ns=STOP_NS),
        )
        for uncertain in cases:
            with (
                self.subTest(uncertain=uncertain),
                self.assertRaisesRegex(SbxCleanupPending, "cleanup|planned sandbox"),
            ):
                verify_sbx_result_fixture(
                    plan,
                    result_document=b"not-json",
                    patch=b"not-a-patch",
                    cleanup=uncertain,
                    capture=capture,
                    verifier=verifier,
                    controller_result=controller_result,
                    base_recheck=base,
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )

    def test_running_capture_requires_fixed_no_link_cp_and_private_stable_root(self) -> None:
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        unsafe = (
            replace(capture, root_at_open=self.root(permissions=0o750)),
            replace(capture, root_descriptor_after=self.root(inode=101)),
            replace(capture, root_entry_after=self.root(inode=101)),
            replace(capture, parent_after=self.parent(inode=98)),
            replace(capture, capture_finished_monotonic_ns=STOP_NS),
            replace(capture, fixed_cp_used=False),
            replace(capture, follow_links=True),
            replace(capture, generic_cp_used=True),
            replace(capture, issue_controlled_path_used=True),
            replace(capture, opened_nofollow=False),
            replace(capture, descriptor_cloexec=False),
            replace(capture, sandbox_running_before=False),
            replace(capture, sandbox_running_after=False),
            replace(capture, destination_regular_files=False),
            replace(capture, destination_unaliased_files=False),
            replace(capture, destination_quota_enforced=False),
            replace(capture, capture_deadline_enforced=False),
            replace(capture, bytes_unparsed=False),
            replace(capture, patch_sha256="0" * 64),
        )
        for changed in unsafe:
            with self.subTest(changed=changed), self.assertRaises(SbxResultError):
                verify_sbx_result_fixture(
                    plan,
                    result_document=document,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=changed,
                    verifier=verifier,
                    controller_result=controller_result,
                    base_recheck=base,
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )
        with self.assertRaisesRegex(SbxResultError, "fixed sbx cp"):
            replace(capture, transport="generic-cp")
        with self.assertRaisesRegex(SbxResultError, "source name"):
            replace(capture, remote_relative_paths=("issue-path",))
        with self.assertRaisesRegex(SbxResultError, "options"):
            replace(capture, cp_options=("-L",))
        with self.assertRaisesRegex(SbxResultError, "destination name"):
            replace(capture, artifact_names=("issue-path",))
        with self.assertRaisesRegex(SbxResultError, "destination quota"):
            replace(capture, destination_quota_bytes=MAX_CAPTURE_BYTES + 1)
        with self.assertRaisesRegex(SbxResultError, "deadline is not fixed"):
            replace(capture, capture_deadline_ms=FIXED_CAPTURE_DEADLINE_MS + 1)

    def test_capture_precedes_stop_and_parsing_cannot_precede_cleanup(self) -> None:
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        self.assertLess(capture.capture_finished_monotonic_ns, cleanup.stop_observed_monotonic_ns)
        self.assertGreater(
            verifier.parse_started_monotonic_ns, cleanup.cleanup_observed_monotonic_ns
        )

        with self.assertRaisesRegex(SbxResultError, "before sandbox stop"):
            verify_sbx_result_fixture(
                plan,
                result_document=document,
                patch=PATCH,
                cleanup=cleanup,
                capture=replace(capture, capture_finished_monotonic_ns=STOP_NS + 1),
                verifier=verifier,
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=fixture_sbx_result_capability(),
            )
        with self.assertRaisesRegex(SbxResultError, "before cleanup"):
            verify_sbx_result_fixture(
                plan,
                result_document=document,
                patch=PATCH,
                cleanup=cleanup,
                capture=capture,
                verifier=replace(verifier, parse_started_monotonic_ns=CLEANUP_NS),
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=fixture_sbx_result_capability(),
            )
        malformed_capture = self.capture(plan, b"not-a-patch")
        malformed_verifier = replace(
            verifier,
            capture_sha256=malformed_capture.sha256,
            parse_started_monotonic_ns=CLEANUP_NS,
        )
        with self.assertRaisesRegex(SbxResultError, "before cleanup"):
            verify_sbx_result_fixture(
                plan,
                result_document=document,
                patch=b"not-a-patch",
                cleanup=cleanup,
                capture=malformed_capture,
                verifier=malformed_verifier,
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=fixture_sbx_result_capability(),
            )

    def test_capture_and_verifier_cleanup_uncertainty_is_pending(self) -> None:
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        with self.assertRaises(SbxCleanupPending):
            verify_sbx_result_fixture(
                plan,
                result_document=document,
                patch=PATCH,
                cleanup=cleanup,
                capture=replace(capture, capture_process_reaped=False),
                verifier=verifier,
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=fixture_sbx_result_capability(),
            )
        for changed in (
            replace(verifier, capture_root_removed=False),
            replace(verifier, verification_sandbox_removed=False),
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaises(SbxCleanupPending),
            ):
                verify_sbx_result_fixture(
                    plan,
                    result_document=document,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=capture,
                    verifier=changed,
                    controller_result=controller_result,
                    base_recheck=base,
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )
        with self.assertRaises(SbxCleanupPending):
            verify_sbx_result_fixture(
                plan,
                result_document=b"not-json",
                patch=b"not-a-patch",
                cleanup=cleanup,
                capture=capture,
                verifier=verifier,
                controller_result=replace(controller_result, result_root_removed=False),
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=fixture_sbx_result_capability(),
            )

    def test_patch_rejects_binary_submodule_symlink_executable_and_mode_changes(self) -> None:
        variants = {
            "binary": PATCH.replace(b"@@ -1 +1 @@\n-before\n+after\n", b"GIT binary patch\n"),
            "executable": PATCH.replace(b"100644\n", b"100755\n", 1),
            "symlink": PATCH.replace(b"100644\n", b"120000\n", 1),
            "submodule": PATCH.replace(b"100644\n", b"160000\n", 1),
            "mode change": PATCH.replace(
                b"index 1111111..2222222 100644\n",
                b"old mode 100644\nnew mode 100755\nindex 1111111..2222222\n",
            ),
            "rename": PATCH.replace(
                b"diff --git a/src/example.py b/src/example.py\n",
                b"diff --git a/src/example.py b/src/renamed.py\n",
            ),
        }
        for label, patch in variants.items():
            with self.subTest(label=label), self.assertRaises(SbxResultError):
                inspect_canonical_patch(patch, forbidden_paths=self.plan().forbidden_paths)

    def test_patch_rejects_forbidden_and_dependency_paths(self) -> None:
        paths = (
            "SECURITY.md",
            ".github/workflows/ci.yml",
            "AGENTS.md",
            "nested/AGENTS.md",
            ".codex/rules.md",
            ".leftovers-export/canonical.patch",
            "nested/.leftovers-export/result.json",
            "CONTRIBUTING.md",
            "package.json",
            "nested/requirements-dev.txt",
            "src/project.csproj",
        )
        for path in paths:
            patch = PATCH.replace(b"src/example.py", path.encode())
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(SbxResultError, "forbidden or dependency"),
            ):
                inspect_canonical_patch(patch, forbidden_paths=self.plan().forbidden_paths)

    def test_patch_requires_canonical_text_hunks_paths_and_order(self) -> None:
        second = PATCH.replace(b"src/example.py", b"src/z.py")
        first = PATCH.replace(b"src/example.py", b"src/a.py")
        variants = {
            "missing newline": PATCH[:-1],
            "carriage return": PATCH.replace(b"\n", b"\r\n", 1),
            "invalid utf8": PATCH + b"\xff\n",
            "traversal": PATCH.replace(b"src/example.py", b"src/../escape.py"),
            "quoted path": PATCH.replace(b"src/example.py", b'"src/example.py"'),
            "bad hunk counts": PATCH.replace(b"@@ -1 +1 @@", b"@@ -2,2 +1 @@"),
            "explicit one": PATCH.replace(b"@@ -1 +1 @@", b"@@ -1,1 +1,1 @@"),
            "integer cap": PATCH.replace(b"@@ -1 +1 @@", b"@@ -2147483648 +1 @@"),
            "integer digit bomb": PATCH.replace(b"@@ -1 +1 @@", b"@@ -" + b"9" * 5_000 + b" +1 @@"),
            "duplicate": PATCH + PATCH,
            "unsorted": second + first,
            "unknown metadata": PATCH.replace(
                b"index 1111111..2222222 100644\n", b"similarity index 100%\n"
            ),
        }
        for label, patch in variants.items():
            with self.subTest(label=label), self.assertRaises(SbxResultError):
                inspect_canonical_patch(patch, forbidden_paths=self.plan().forbidden_paths)

    def test_patch_enforces_file_line_byte_and_line_length_caps(self) -> None:
        sections = []
        for number in range(33):
            path = f"src/file-{number:02d}.py".encode()
            sections.append(PATCH.replace(b"src/example.py", path))
        with self.assertRaisesRegex(SbxResultError, "file cap"):
            inspect_canonical_patch(b"".join(sections), forbidden_paths=self.plan().forbidden_paths)

        count = MAX_CHANGED_LINES // 2 + 1
        many_lines = (
            b"diff --git a/src/example.py b/src/example.py\n"
            b"index 1111111..2222222 100644\n"
            b"--- a/src/example.py\n"
            b"+++ b/src/example.py\n"
            + f"@@ -1,{count} +1,{count} @@\n".encode()
            + b"-old\n" * count
            + b"+new\n" * count
        )
        with self.assertRaisesRegex(SbxResultError, "changed-line cap"):
            inspect_canonical_patch(many_lines, forbidden_paths=self.plan().forbidden_paths)
        with self.assertRaisesRegex(SbxResultError, "byte cap"):
            inspect_canonical_patch(
                b"x" * (MAX_PATCH_BYTES + 1), forbidden_paths=self.plan().forbidden_paths
            )
        long_line = PATCH.replace(b"+after\n", b"+" + b"x" * (16 * 1024) + b"\n")
        with self.assertRaisesRegex(SbxResultError, "overlong"):
            inspect_canonical_patch(long_line, forbidden_paths=self.plan().forbidden_paths)

    def test_controller_per_run_caps_are_stricter_and_output_cannot_relax_them(self) -> None:
        self.assertEqual(self.plan().max_changed_files, 5)
        self.assertEqual(self.plan().max_changed_lines, 300)
        for changes in (
            {"max_changed_files": 0},
            {"max_changed_files": 33},
            {"max_changed_lines": 0},
            {"max_changed_lines": MAX_CHANGED_LINES + 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(SbxResultError):
                self.plan(**changes)

        with self.assertRaisesRegex(SbxResultError, "controller changed-line cap"):
            encode_fixture_result(
                self.plan(max_changed_lines=1),
                patch=PATCH,
                usage=self.usage(),
                fixture_capability=fixture_sbx_result_capability(),
            )
        two_files = PATCH.replace(b"src/example.py", b"src/a.py") + PATCH.replace(
            b"src/example.py", b"src/z.py"
        )
        with self.assertRaisesRegex(SbxResultError, "controller changed-file cap"):
            encode_fixture_result(
                self.plan(max_changed_files=1),
                patch=two_files,
                usage=self.usage(),
                fixture_capability=fixture_sbx_result_capability(),
            )

        plan, usage, cleanup, document, _capture, _verifier, _controller_result, _base = (
            self.evidence()
        )
        changed = json.loads(document)
        changed["limits"]["max_changed_files"] = 32
        changed_document = canonical(changed)
        capture = self.capture(plan, PATCH)
        verifier = self.verifier(plan, cleanup, capture, PATCH)
        controller_result = self.controller_result(plan, changed_document, usage, PATCH)
        base = self.base_recheck(plan, verifier, controller_result)
        with self.assertRaisesRegex(SbxResultError, "limits do not match"):
            verify_sbx_result_fixture(
                plan,
                result_document=changed_document,
                patch=PATCH,
                cleanup=cleanup,
                capture=capture,
                verifier=verifier,
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=HANDOFF_NS,
                fixture_capability=fixture_sbx_result_capability(),
            )

    def test_addition_and_deletion_use_only_regular_100644_mode(self) -> None:
        addition = (
            b"diff --git a/new.txt b/new.txt\n"
            b"new file mode 100644\n"
            b"index 0000000..2222222\n"
            b"--- /dev/null\n"
            b"+++ b/new.txt\n"
            b"@@ -0,0 +1 @@\n"
            b"+new\n"
        )
        deletion = (
            b"diff --git a/old.txt b/old.txt\n"
            b"deleted file mode 100644\n"
            b"index 1111111..0000000\n"
            b"--- a/old.txt\n"
            b"+++ /dev/null\n"
            b"@@ -1 +0,0 @@\n"
            b"-old\n"
        )
        self.assertEqual(
            inspect_canonical_patch(addition, forbidden_paths=self.plan().forbidden_paths).paths,
            ("new.txt",),
        )
        self.assertEqual(
            inspect_canonical_patch(deletion, forbidden_paths=self.plan().forbidden_paths).paths,
            ("old.txt",),
        )
        for patch in (
            addition.replace(b"100644", b"100755"),
            addition.replace(b"0000000..2222222", b"1111111..2222222"),
            addition.replace(b"@@ -0,0 +1 @@", b"@@ -7,0 +1 @@"),
            deletion.replace(b"1111111..0000000", b"1111111..2222222"),
            deletion.replace(b"@@ -1 +0,0 @@", b"@@ -1 +7,0 @@"),
        ):
            with self.assertRaises(SbxResultError):
                inspect_canonical_patch(patch, forbidden_paths=self.plan().forbidden_paths)

    def test_independent_verifier_receipt_rejects_substitution_and_failures(self) -> None:
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        failed_check = VerifierCheckReceipt("lint", 1, False, False, OUTPUT_SHA)
        cases = (
            replace(verifier, binding_sha256="0" * 64),
            replace(verifier, capture_sha256="0" * 64),
            replace(verifier, cleanup_sha256="0" * 64),
            replace(verifier, applied_patch_sha256="0" * 64),
            replace(verifier, source_manifest_sha256="0" * 64),
            replace(verifier, policy_sha256="0" * 64),
            replace(verifier, independent_domain=False),
            replace(verifier, fresh_verifier_sandbox=False),
            replace(verifier, worker_mount_absent=False),
            replace(verifier, network_denied=False),
            replace(verifier, credentials_absent=False),
            replace(verifier, reconstructed_source=False),
            replace(verifier, policy_allowed=False),
            replace(verifier, unresolved_review=True),
            replace(verifier, parse_started_monotonic_ns=CLEANUP_NS),
            replace(verifier, parse_root_entry=self.root(inode=101)),
            replace(verifier, verifier_sandbox_uuid=UUID),
            replace(verifier, checks=(failed_check, verifier.checks[1])),
            replace(verifier, checks=tuple(reversed(verifier.checks))),
        )
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(SbxResultError):
                verify_sbx_result_fixture(
                    plan,
                    result_document=document,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=capture,
                    verifier=changed,
                    controller_result=controller_result,
                    base_recheck=base,
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )

    def test_fresh_base_recheck_is_immediate_and_collision_free(self) -> None:
        plan, _usage, cleanup, document, capture, verifier, controller_result, base = (
            self.evidence()
        )
        cases = (
            replace(base, observed_base_sha="0" * 40),
            replace(base, issue_open=False),
            replace(base, assignment_clear=False),
            replace(base, linked_or_open_pr_absent=False),
            replace(base, freshness_challenge_sha256="0" * 64),
            replace(base, verifier_sha256="0" * 64),
            replace(base, controller_result_sha256="0" * 64),
            replace(base, observed_monotonic_ns=VERIFY_NS),
        )
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(SbxResultError):
                verify_sbx_result_fixture(
                    plan,
                    result_document=document,
                    patch=PATCH,
                    cleanup=cleanup,
                    capture=capture,
                    verifier=verifier,
                    controller_result=controller_result,
                    base_recheck=changed,
                    handoff_observed_monotonic_ns=HANDOFF_NS,
                    fixture_capability=fixture_sbx_result_capability(),
                )
        with self.assertRaisesRegex(SbxResultError, "stale"):
            verify_sbx_result_fixture(
                plan,
                result_document=document,
                patch=PATCH,
                cleanup=cleanup,
                capture=capture,
                verifier=verifier,
                controller_result=controller_result,
                base_recheck=base,
                handoff_observed_monotonic_ns=BASE_NS + MAX_FRESH_BASE_AGE_NS + 1,
                fixture_capability=fixture_sbx_result_capability(),
            )


if __name__ == "__main__":
    unittest.main()
