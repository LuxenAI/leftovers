from __future__ import annotations

import hashlib
import unittest
from datetime import UTC, datetime, timedelta

from leftovers.strict_vm_cycle import (
    STRICT_VM_WHOLE_CYCLE_CAPABILITY,
    CyclePhase,
    CyclePlan,
    CycleState,
    HostCheckEvidence,
    IndependentHostReceipt,
    MediatorReceipt,
    StoppedGuestReceipt,
    StrictVMCycleDisabled,
    StrictVMCycleError,
    accept_stopped_epoch,
    create_fixture_publisher_handoff,
    create_publisher_handoff,
    disabled_live_cycle,
    patch_sha256,
    start_offline_cycle,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
RUN_ID = "a" * 32
SHA = "b" * 64
BASE = "c" * 40
POLICY = "d" * 64
PATCH = (
    b"diff --git a/a.py b/a.py\nindex 0000000..1111111 100644\n--- a/a.py\n"
    b"+++ b/a.py\n@@ -0,0 +1 @@\n+safe\n"
)
PATCH_SHA = patch_sha256(PATCH)


def plan(**changes: object) -> CyclePlan:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "repository": "example/project",
        "issue_number": 7,
        "base_ref": "main",
        "base_sha": BASE,
        "policy_sha256": POLICY,
        "required_check_ids": ("lint", "test"),
        "max_rounds": 1,
        "token_cap": 100,
        "deadline_at": NOW + timedelta(minutes=10),
    }
    values.update(changes)
    return CyclePlan(**values)  # type: ignore[arg-type]


def mediator(**changes: object) -> MediatorReceipt:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "round": 0,
        "request_sha256": SHA,
        "action_batch_sha256": "e" * 64,
        "patch_sha256": PATCH_SHA,
        "charged_tokens": 50,
    }
    values.update(changes)
    return MediatorReceipt(**values)  # type: ignore[arg-type]


def guest(**changes: object) -> StoppedGuestReceipt:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "round": 0,
        "request_sha256": SHA,
        "action_batch_sha256": "e" * 64,
        "canonical_patch": PATCH,
        "canonical_patch_sha256": PATCH_SHA,
        "launcher_stop_proven": True,
        "result_extracted_after_stop": True,
        "cleanup_proven": True,
    }
    values.update(changes)
    return StoppedGuestReceipt(**values)  # type: ignore[arg-type]


def host(**changes: object) -> IndependentHostReceipt:
    values: dict[str, object] = {
        "run_id": RUN_ID,
        "base_sha_observed": BASE,
        "applied_patch_sha256": PATCH_SHA,
        "inspected_diff_sha256": PATCH_SHA,
        "policy_sha256": POLICY,
        "policy_allowed": True,
        "review_unresolved": False,
        "checks": (
            HostCheckEvidence("lint", 0, False, False),
            HostCheckEvidence("test", 0, False, False),
        ),
    }
    values.update(changes)
    return IndependentHostReceipt(**values)  # type: ignore[arg-type]


class StrictVMCycleTests(unittest.TestCase):
    def verified_state(self):
        return accept_stopped_epoch(
            start_offline_cycle(plan(), now=NOW), mediator(), guest(), now=NOW
        )

    def test_source_gate_is_false_and_live_entry_has_no_backend(self) -> None:
        self.assertFalse(STRICT_VM_WHOLE_CYCLE_CAPABILITY)
        with self.assertRaisesRegex(StrictVMCycleDisabled, "source-disabled"):
            disabled_live_cycle(object(), object())
        with self.assertRaisesRegex(StrictVMCycleDisabled, "broker attestation"):
            create_publisher_handoff(object(), object())

    def test_happy_path_creates_capability_free_handoff(self) -> None:
        state, handoff = create_fixture_publisher_handoff(
            self.verified_state(), host(), base_sha_rechecked=BASE, now=NOW
        )
        self.assertEqual(state.phase, CyclePhase.PUBLISH_READY)
        self.assertEqual(handoff.patch_sha256, PATCH_SHA)
        self.assertEqual(handoff.check_ids, ("lint", "test"))
        self.assertNotIn("guest", handoff.__dataclass_fields__)
        self.assertNotIn("mediator", handoff.__dataclass_fields__)
        self.assertNotIn("publisher", handoff.__dataclass_fields__)

    def test_receipt_mismatch_rejects_before_host_handoff(self) -> None:
        with self.assertRaisesRegex(StrictVMCycleError, "do not bind"):
            accept_stopped_epoch(
                start_offline_cycle(plan(), now=NOW),
                mediator(),
                guest(action_batch_sha256="f" * 64),
                now=NOW,
            )

    def test_post_stop_proof_is_mandatory(self) -> None:
        for field in ("launcher_stop_proven", "result_extracted_after_stop"):
            with self.subTest(field=field), self.assertRaisesRegex(StrictVMCycleError, "post-stop"):
                accept_stopped_epoch(
                    start_offline_cycle(plan(), now=NOW),
                    mediator(),
                    guest(**{field: False}),
                    now=NOW,
                )

    def test_cleanup_failure_is_pending_and_cannot_publish(self) -> None:
        pending = accept_stopped_epoch(
            start_offline_cycle(plan(), now=NOW), mediator(), guest(cleanup_proven=False), now=NOW
        )
        self.assertEqual(pending.phase, CyclePhase.CLEANUP_PENDING)
        with self.assertRaisesRegex(StrictVMCycleError, "cleanup_pending"):
            create_fixture_publisher_handoff(pending, host(), base_sha_rechecked=BASE, now=NOW)

    def test_patch_drift_is_rejected_after_independent_apply(self) -> None:
        with self.assertRaisesRegex(StrictVMCycleError, "drifted"):
            create_fixture_publisher_handoff(
                self.verified_state(),
                host(applied_patch_sha256="a" * 64),
                base_sha_rechecked=BASE,
                now=NOW,
            )

    def test_independent_diff_policy_and_check_failures_are_rejected(self) -> None:
        bad_cases = (
            (host(inspected_diff_sha256="a" * 64), "inspected diff"),
            (host(policy_allowed=False), "policy"),
            (host(review_unresolved=True), "unresolved"),
            (
                host(
                    checks=(
                        HostCheckEvidence("lint", 0, False, False),
                        HostCheckEvidence("test", 1, False, False),
                    )
                ),
                "checks",
            ),
            (host(checks=(HostCheckEvidence("lint", 0, False, False),)), "exactly match"),
        )
        for receipt, expected in bad_cases:
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(StrictVMCycleError, expected),
            ):
                create_fixture_publisher_handoff(
                    self.verified_state(), receipt, base_sha_rechecked=BASE, now=NOW
                )

    def test_base_movement_is_rechecked_twice(self) -> None:
        for receipt, rechecked in ((host(base_sha_observed="a" * 40), BASE), (host(), "a" * 40)):
            with (
                self.subTest(receipt=receipt.base_sha_observed, rechecked=rechecked),
                self.assertRaisesRegex(StrictVMCycleError, "base moved"),
            ):
                create_fixture_publisher_handoff(
                    self.verified_state(), receipt, base_sha_rechecked=rechecked, now=NOW
                )

    def test_budget_round_and_time_caps_fail_closed(self) -> None:
        with self.assertRaisesRegex(StrictVMCycleError, "token cap"):
            accept_stopped_epoch(
                start_offline_cycle(plan(token_cap=49), now=NOW), mediator(), guest(), now=NOW
            )
        with self.assertRaisesRegex(StrictVMCycleError, "deadline"):
            start_offline_cycle(plan(deadline_at=NOW), now=NOW)
        with self.assertRaisesRegex(StrictVMCycleError, "wall-time"):
            start_offline_cycle(plan(deadline_at=NOW + timedelta(hours=5)), now=NOW)
        state = self.verified_state()
        with self.assertRaisesRegex(StrictVMCycleError, "not accepting"):
            accept_stopped_epoch(state, mediator(), guest(), now=NOW)
        with self.assertRaisesRegex(StrictVMCycleError, "deadline"):
            create_fixture_publisher_handoff(
                state, host(), base_sha_rechecked=BASE, now=NOW + timedelta(minutes=10)
            )

    def test_fixture_state_is_bounded_and_cannot_be_production_authority(self) -> None:
        with self.assertRaisesRegex(StrictVMCycleError, "token accounting"):
            CycleState(plan(), CyclePhase.EPOCH_VERIFIED, spent_tokens=-1, patch_sha256=PATCH_SHA)
        with self.assertRaisesRegex(StrictVMCycleError, "forged progress"):
            CycleState(plan(), CyclePhase.READY, patch_sha256=PATCH_SHA)
        with self.assertRaisesRegex(StrictVMCycleError, "round cap"):
            plan(max_rounds=2)
        with self.assertRaisesRegex(StrictVMCycleError, "too long"):
            plan(repository=f"owner/{'r' * 140}")

    def test_patch_is_bounded_canonical_utf8(self) -> None:
        for patch in (b"", b"not-newline", b"bad\0\n", b"\xff\n"):
            with self.subTest(patch=patch), self.assertRaises(StrictVMCycleError):
                guest(
                    canonical_patch=patch,
                    canonical_patch_sha256=hashlib.sha256(patch).hexdigest(),
                )
