from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from leftovers.sbx_cycle import (
    DOCKER_SANDBOX_CYCLE_ENABLED,
    SBX_WHOLE_CYCLE_ENABLED,
    CyclePhase,
    SbxCycleDisabled,
    SbxCycleError,
    SbxStageCompletionReceipt,
    SbxStageLedgerReceipt,
    SbxWholeCyclePlan,
    SbxWholeRunReservationReceipt,
    complete_fixture_stage,
    execute_live_sbx_cycle,
    fixture_sbx_cycle_capability,
    new_fixture_sbx_cycle,
    reserve_fixture_sbx_cycle,
)
from leftovers.sbx_execution import (
    AUTH_MODE,
    ExecutionStage,
    InspectionExpectation,
    InVmRuntimeExpectation,
    build_fixture_execution_plan,
    canonical_fixture_inspection_document,
    derive_controller_sandbox_identity,
    fixture_sbx_execution_capability,
    parse_fixture_inspection_attestation,
)
from leftovers.sbx_result import ExactCallUsage, SbxResultPlan, SbxRunBinding

RUN_ID = "a" * 32
UUID = "123e4567-e89b-42d3-a456-426614174000"
POLICY = "d" * 64
SECRET = "e" * 64
BOOT = "1" * 64
START = 1_000_000_000
NOW = datetime(2026, 7, 19, 16, tzinfo=UTC)


class Explosive:
    def __getattribute__(self, _name: str) -> object:
        raise AssertionError("live cycle entry inspected an argument")


class SbxCycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cycle_cap = fixture_sbx_cycle_capability()
        self.execution_cap = fixture_sbx_execution_capability()
        controller = derive_controller_sandbox_identity(RUN_ID)
        runtime = InVmRuntimeExpectation(
            codex_executable_path="/opt/fixture/codex",
            codex_executable_sha256="c" * 64,
            codex_version="0.145.0-alpha.18",
            codex_executable_device=2,
            codex_executable_inode=3,
            codex_executable_owner_uid=0,
            codex_executable_owner_gid=0,
            codex_executable_mode=0o100755,
            codex_executable_link_count=1,
            codex_executable_size_bytes=10,
            codex_executable_mtime_ns=1,
            codex_executable_ctime_ns=2,
            user_name="agent",
            user_uid=1000,
            user_gid=1000,
            supplemental_gids=(),
            linux_capabilities=(),
            private_clone_workdir="/home/agent/workspace",
            codex_home="/home/agent/.codex",
            auth_mode=AUTH_MODE,
            user_config_loaded=False,
            repository_rules_loaded=False,
            hooks_loaded=False,
        )
        expectation = InspectionExpectation(controller, runtime, POLICY, SECRET)
        raw = canonical_fixture_inspection_document(
            self.execution_cap, expectation, daemon_uuid=UUID, generation=7
        )
        self.inspection = parse_fixture_inspection_attestation(self.execution_cap, raw, expectation)
        binding = SbxRunBinding(
            daemon_sandbox_uuid=UUID,
            daemon_sandbox_generation=7,
            controller_sandbox_name=controller.name,
            controller_run_id=RUN_ID,
            repository="owner/repo",
            issue_number=1,
            base_sha="b" * 40,
            source_manifest_sha256="f" * 64,
            policy_epoch=1,
            policy_sha256=POLICY,
            secret_epoch=2,
            secret_inventory_sha256=SECRET,
            model="gpt-5.6-terra",
            reasoning_effort="high",
            total_token_cap=55_000,
        )
        result = SbxResultPlan(
            binding=binding,
            controller_uid=501,
            controller_boot_sha256=BOOT,
            freshness_challenge_sha256="2" * 64,
            verifier_identity_sha256="3" * 64,
            verification_profile_sha256="4" * 64,
            required_check_ids=("lint",),
        )
        self.plan = SbxWholeCyclePlan(result, self.inspection, START)

    def reservation(self) -> SbxWholeRunReservationReceipt:
        return SbxWholeRunReservationReceipt(
            self.plan.binding_sha256,
            self.plan.inspection_sha256,
            BOOT,
            (10_000, 35_000, 10_000),
            55_000,
            "0" * 64,
            "1" * 64,
            True,
        )

    def stage(self, state, stage: ExecutionStage, index: int):
        run_reservation = state.reservation.reservation_head_sha256
        execution = build_fixture_execution_plan(
            self.execution_cap,
            self.inspection,
            stage=stage,
            stdin_bytes=b"bounded fixture prompt\n",
            run_started_at=NOW,
            call_started_at=NOW + timedelta(minutes=index + 1),
        )
        event = ("a" if index == 0 else "b" if index == 1 else "c") * 64
        usage = ExactCallUsage(
            stage=stage,
            call_index=index,
            input_tokens=10,
            output_tokens=5,
            cached_input_tokens=0,
            cache_write_input_tokens=0,
            reasoning_tokens=3,
            total_tokens=15,
            source="codex-cli-jsonl-v1",
            exact=True,
            event_stream_sha256=event,
            thread_id=f"thread-{index}",
            reservation_sha256=run_reservation,
        )
        previous = (
            run_reservation if index == 0 else state.completions[-1].settlement_ledger_head_sha256
        )
        reserve = ("4" if index == 0 else "5" if index == 1 else "6") * 64
        settle = ("7" if index == 0 else "8" if index == 1 else "9") * 64
        ledger = SbxStageLedgerReceipt(
            self.plan.binding_sha256,
            self.plan.inspection_sha256,
            BOOT,
            stage,
            index,
            execution.attestation_sha256,
            event,
            previous,
            reserve,
            settle,
            (10_000, 35_000, 10_000)[index],
            usage,
            True,
        )
        completion = SbxStageCompletionReceipt(
            self.plan.binding_sha256,
            self.plan.inspection_sha256,
            BOOT,
            execution.attestation_sha256,
            stage,
            index,
            START + (index + 1) * 10,
            START + (index + 1) * 10 + 1,
            1,
            1,
            "a" * 64,
            "b" * 64,
            0,
            False,
            False,
            True,
            usage,
            previous,
            reserve,
            settle,
        )
        return execution, ledger, completion

    def test_live_gate_rejects_before_poisoned_arguments(self) -> None:
        self.assertFalse(SBX_WHOLE_CYCLE_ENABLED)
        self.assertFalse(DOCKER_SANDBOX_CYCLE_ENABLED)
        with self.assertRaises(SbxCycleDisabled):
            execute_live_sbx_cycle(Explosive(), authority=Explosive())

    def test_fixture_capability_is_a_singleton(self) -> None:
        self.assertIs(self.cycle_cap, fixture_sbx_cycle_capability())
        with self.assertRaises(SbxCycleError):
            type(self.cycle_cap)(object())

    def test_plan_rejects_attestation_binding_drift(self) -> None:
        with self.assertRaises(SbxCycleError):
            SbxWholeCyclePlan(
                replace(
                    self.plan.result_plan,
                    binding=replace(self.plan.result_plan.binding, policy_sha256="0" * 64),
                ),
                self.inspection,
                START,
            )

    def test_stage_order_replay_and_fourth_call_are_rejected(self) -> None:
        state = reserve_fixture_sbx_cycle(
            new_fixture_sbx_cycle(self.plan, capability=self.cycle_cap),
            self.reservation(),
            capability=self.cycle_cap,
        )
        with self.assertRaises(SbxCycleError):
            replace(state, phase=CyclePhase.IMPLEMENTATION_DONE)
        for index, stage in enumerate(ExecutionStage):
            execution, ledger, completion = self.stage(state, stage, index)
            state = complete_fixture_stage(
                state, execution, ledger, completion, capability=self.cycle_cap
            )
        self.assertEqual(state.phase, CyclePhase.VERIFICATION_DONE)
        with self.assertRaises(SbxCycleError):
            execution, ledger, completion = self.stage(state, ExecutionStage.VERIFICATION, 2)
            complete_fixture_stage(state, execution, ledger, completion, capability=self.cycle_cap)

    def test_crashed_reservation_and_bad_output_force_non_retrying_failure(self) -> None:
        state = reserve_fixture_sbx_cycle(
            new_fixture_sbx_cycle(self.plan, capability=self.cycle_cap),
            self.reservation(),
            capability=self.cycle_cap,
        )
        execution, ledger, completion = self.stage(state, ExecutionStage.PLANNING, 0)
        with self.assertRaises(SbxCycleError):
            replace(completion, stdout_bytes=32 * 1024)
        crashed = complete_fixture_stage(
            state,
            execution,
            replace(ledger, pending_crash=True, settled_usage=None),
            replace(completion, pending_crash=True, usage=None),
            capability=self.cycle_cap,
        )
        self.assertEqual(crashed.phase, CyclePhase.CLEANUP_REQUIRED)
        self.assertIsNotNone(crashed.failed_ledger)
        with self.assertRaises(SbxCycleError):
            complete_fixture_stage(
                crashed, execution, ledger, completion, capability=self.cycle_cap
            )

    def test_ledger_rollback_is_rejected(self) -> None:
        state = reserve_fixture_sbx_cycle(
            new_fixture_sbx_cycle(self.plan, capability=self.cycle_cap),
            self.reservation(),
            capability=self.cycle_cap,
        )
        execution, ledger, completion = self.stage(state, ExecutionStage.PLANNING, 0)
        with self.assertRaises(SbxCycleError):
            complete_fixture_stage(
                state,
                execution,
                replace(ledger, previous_head_sha256="0" * 64),
                completion,
                capability=self.cycle_cap,
            )
