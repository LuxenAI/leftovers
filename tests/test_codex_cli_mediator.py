from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from leftovers.codex_cli_mediator import (
    DISABLED_MODEL_FEATURES,
    MODEL,
    PROVIDER,
    REASONING_EFFORT,
    ZERO_TOOL_CONFIGURATION_PROVEN,
    CodexCliIdentity,
    CodexCliMediator,
    CodexMediatorDisabled,
    CodexMediatorError,
    CodexTokenLedger,
    LedgerReservation,
    derive_mediation_result,
    fixed_codex_argv,
    parse_codex_event_evidence,
    parse_codex_event_usage,
    parse_provider_envelope,
)
from leftovers.model_mediator import (
    MediationLimits,
    MediationRequest,
    MediationStage,
    ReportedTokenCounts,
    canonical_json_bytes,
)

RUN_ID = "a" * 32
ROOT = Path(__file__).resolve().parents[1]


def request(
    stage: MediationStage = MediationStage.IMPLEMENTATION,
    *,
    call_index: int = 1,
    call_cap: int = 2,
    total_token_cap: int = 120,
    input_token_cap: int = 80,
    output_token_cap: int = 40,
) -> MediationRequest:
    return MediationRequest(
        run_id=RUN_ID,
        round=0,
        stage=stage,
        provider=PROVIDER,
        model=MODEL,
        reasoning_effort=REASONING_EFFORT,
        input_bytes=canonical_json_bytes({"untrusted": "repository instructions"}),
        allowed_check_ids=frozenset({"unit.tests"}),
        limits=MediationLimits(
            max_response_bytes=8_192,
            max_patch_bytes=2_048,
            max_actions=4,
            input_token_cap=input_token_cap,
            output_token_cap=output_token_cap,
            total_token_cap=total_token_cap,
            call_index=call_index,
            call_cap=call_cap,
        ),
        deadline_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def envelope(
    mediation_request: MediationRequest,
    *,
    actions: list[dict[str, object]] | None = None,
    patch: str | None = "diff --git a/a.py b/a.py\n",
) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": 1,
            "run_id": mediation_request.run_id,
            "round": mediation_request.round,
            "stage": mediation_request.stage.value,
            "provider": PROVIDER,
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "input_sha256": hashlib.sha256(mediation_request.input_bytes).hexdigest(),
            "actions": actions
            or [
                {"id": "patch", "type": "apply_patch"},
                {"id": "finish", "type": "finish", "status": "complete", "summary": "done"},
            ],
            "patch": patch,
        }
    )


def usage(*, total: int = 20) -> ReportedTokenCounts:
    return ReportedTokenCounts(
        input_tokens=12,
        output_tokens=total - 12,
        cached_input_tokens=0,
        reasoning_tokens=2,
        total_tokens=total,
        source="provider",
        exact=True,
    )


def event_stream(*, item_type: str = "agent_message", reasoning: bool = True) -> bytes:
    terminal_usage: dict[str, int] = {
        "input_tokens": 12,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 8,
    }
    if reasoning:
        terminal_usage["reasoning_output_tokens"] = 2
    events = (
        {"type": "thread.started", "thread_id": "thread-1"},
        {"type": "turn.started"},
        {
            "type": "item.started",
            "item": {"id": "item-1", "type": item_type, "text": ""},
        },
        {
            "type": "item.completed",
            "item": {"id": "item-1", "type": item_type, "text": "done"},
        },
        {"type": "turn.completed", "usage": terminal_usage},
    )
    return b"".join(json.dumps(event, separators=(",", ":")).encode() + b"\n" for event in events)


def evidence(mediation_request: MediationRequest):
    return parse_codex_event_evidence(event_stream(), mediation_request)


class CodexProviderEnvelopeTests(unittest.TestCase):
    def test_provider_cannot_supply_its_own_patch_digest_and_mediator_derives_it(self) -> None:
        mediation_request = request()
        raw = envelope(mediation_request)
        started = datetime.now(UTC)
        result = derive_mediation_result(
            raw,
            mediation_request,
            event_evidence=evidence(mediation_request),
            started_at=started,
            finished_at=started,
        )

        patch = b"diff --git a/a.py b/a.py\n"
        self.assertEqual(result.patch, patch)
        self.assertEqual(
            result.receipt.patch_sha256,
            hashlib.sha256(patch).hexdigest(),
        )
        self.assertEqual(result.batch.actions[0].patch_sha256, result.receipt.patch_sha256)
        self.assertEqual(result.receipt.usage_source, "provider")
        self.assertTrue(result.receipt.exact_usage)

    def test_envelope_requires_all_request_identity_bindings(self) -> None:
        mediation_request = request()
        data = json.loads(envelope(mediation_request))
        data["input_sha256"] = "b" * 64
        with self.assertRaisesRegex(CodexMediatorError, "input_sha256"):
            parse_provider_envelope(canonical_json_bytes(data), mediation_request)

    def test_apply_patch_digest_or_extra_authority_from_provider_is_rejected(self) -> None:
        mediation_request = request()
        raw = envelope(
            mediation_request,
            actions=[
                {"id": "patch", "type": "apply_patch", "patch_sha256": "a" * 64},
                {"id": "finish", "type": "finish", "status": "complete", "summary": "done"},
            ],
        )
        now = datetime.now(UTC)
        with self.assertRaisesRegex(CodexMediatorError, "unknown authority"):
            derive_mediation_result(
                raw,
                mediation_request,
                event_evidence=evidence(mediation_request),
                started_at=now,
                finished_at=now,
            )

    def test_stage_and_strict_action_grammar_remain_authoritative(self) -> None:
        mediation_request = request(MediationStage.PLANNING)
        raw = envelope(
            mediation_request,
            patch=None,
            actions=[
                {"id": "run", "type": "run_check", "check_id": "unit.tests"},
                {"id": "finish", "type": "finish", "status": "complete", "summary": "done"},
            ],
        )
        now = datetime.now(UTC)
        with self.assertRaisesRegex(CodexMediatorError, "strict action"):
            derive_mediation_result(
                raw,
                mediation_request,
                event_evidence=evidence(mediation_request),
                started_at=now,
                finished_at=now,
            )

    def test_model_envelope_cannot_claim_its_own_usage(self) -> None:
        mediation_request = request()
        data = json.loads(envelope(mediation_request))
        data["usage"] = {"total_tokens": 1}
        with self.assertRaisesRegex(CodexMediatorError, "unknown fields"):
            parse_provider_envelope(canonical_json_bytes(data), mediation_request)

    def test_usage_is_derived_from_separate_cli_event_stream(self) -> None:
        raw = event_stream()
        parsed = parse_codex_event_usage(raw, request())
        retained = parse_codex_event_evidence(raw, request())
        self.assertEqual(parsed, usage())
        self.assertEqual(retained.usage, parsed)
        self.assertEqual(retained.cache_write_input_tokens, 0)
        self.assertEqual(retained.stream_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(retained.thread_id, "thread-1")

    def test_event_stream_rejects_tool_items_and_missing_reasoning_usage(self) -> None:
        mediation_request = request()
        with self.assertRaisesRegex(CodexMediatorError, "forbidden or unknown tool"):
            parse_codex_event_usage(event_stream(item_type="command_execution"), mediation_request)
        with self.assertRaisesRegex(CodexMediatorError, "missing or unknown"):
            parse_codex_event_usage(event_stream(reasoning=False), mediation_request)

    def test_event_stream_requires_exact_fields_and_a_bound_item_lifecycle(self) -> None:
        mediation_request = request()
        events = [json.loads(line) for line in event_stream().splitlines()]
        events[0]["cwd"] = "/untrusted"
        raw = b"".join(
            json.dumps(event, separators=(",", ":")).encode() + b"\n" for event in events
        )
        with self.assertRaisesRegex(CodexMediatorError, "missing or unknown fields"):
            parse_codex_event_usage(raw, mediation_request)

        events = [json.loads(line) for line in event_stream().splitlines()]
        events[3]["item"]["type"] = "reasoning"
        raw = b"".join(
            json.dumps(event, separators=(",", ":")).encode() + b"\n" for event in events
        )
        with self.assertRaisesRegex(CodexMediatorError, "lifecycle"):
            parse_codex_event_usage(raw, mediation_request)

    def test_observed_cli_contract_allows_an_atomic_completed_agent_message(self) -> None:
        events = (
            {"type": "thread.started", "thread_id": "019f77f7-a2a0-7522-be34-74e241dd3917"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {"id": "item_0", "type": "agent_message", "text": "PROBE_OK"},
            },
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 11_787,
                    "cached_input_tokens": 0,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 7,
                    "reasoning_output_tokens": 0,
                },
            },
        )
        raw = b"".join(
            json.dumps(event, separators=(",", ":")).encode() + b"\n" for event in events
        )
        parsed = parse_codex_event_evidence(
            raw,
            request(
                total_token_cap=20_000,
                input_token_cap=12_000,
                output_token_cap=8_000,
            ),
        )
        self.assertEqual(parsed.usage.total_tokens, 11_794)
        self.assertEqual(parsed.usage.reasoning_tokens, 0)


class CodexLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_reservation_is_fsynced_conservative_and_settlement_releases_only_difference(
        self,
    ) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=150)
        first_request = request(total_token_cap=120)
        reservation = ledger.reserve(first_request)
        self.assertTrue(ledger.path.exists())
        self.assertEqual(ledger.path.stat().st_mode & 0o777, 0o600)

        with self.assertRaisesRegex(CodexMediatorError, "reservation exceeds"):
            ledger.reserve(request(call_index=2, total_token_cap=120))

        now = datetime.now(UTC)
        result = derive_mediation_result(
            envelope(first_request),
            first_request,
            event_evidence=evidence(first_request),
            started_at=now,
            finished_at=now,
        )
        ledger.settle(reservation, result)
        second = ledger.reserve(request(call_index=2, total_token_cap=120))
        self.assertEqual(second.call_index, 2)
        rows = ledger.path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(rows), 4)
        self.assertEqual(json.loads(rows[0])["event"], "genesis")
        self.assertEqual(json.loads(rows[1])["event_sha256"], reservation.reservation_id)
        self.assertNotIn("repository instructions", ledger.path.read_text(encoding="utf-8"))
        self.assertNotIn("diff --git", ledger.path.read_text(encoding="utf-8"))

    def test_crash_reservation_remains_charged_and_duplicate_settlement_is_rejected(self) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        first_request = request(total_token_cap=120)
        reservation = ledger.reserve(first_request)
        with self.assertRaisesRegex(CodexMediatorError, "reservation exceeds"):
            ledger.reserve(request(call_index=2, total_token_cap=80))
        now = datetime.now(UTC)
        result = derive_mediation_result(
            envelope(first_request),
            first_request,
            event_evidence=evidence(first_request),
            started_at=now,
            finished_at=now,
        )
        ledger.settle(reservation, result)
        with self.assertRaisesRegex(CodexMediatorError, "already recorded"):
            ledger.settle(reservation, result)

    def test_tampered_hash_chain_fails_closed(self) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        ledger.reserve(request(total_token_cap=120))
        text = ledger.path.read_text(encoding="utf-8")
        ledger.path.write_text(text.replace('"tokens":120', '"tokens":119'), encoding="utf-8")
        with self.assertRaisesRegex(CodexMediatorError, "hash chain"):
            ledger.reserve(request(call_index=2, total_token_cap=80))

    def test_group_readable_state_root_or_hardlinked_ledger_is_rejected(self) -> None:
        insecure_root = self.root / "insecure"
        insecure_root.mkdir(mode=0o755)
        insecure_root.chmod(0o755)
        with self.assertRaisesRegex(CodexMediatorError, "owner-private"):
            CodexTokenLedger(insecure_root, RUN_ID, run_token_cap=120).reserve(
                request(total_token_cap=120)
            )

        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        ledger.reserve(request(total_token_cap=120))
        link = self.root / "hardlink"
        link.hardlink_to(ledger.path)
        with self.assertRaisesRegex(CodexMediatorError, "non-hardlinked"):
            ledger.reserve(request(call_index=2, total_token_cap=80))

    def test_reservation_rejects_a_request_from_another_run(self) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        with self.assertRaisesRegex(CodexMediatorError, "not bound to this run"):
            ledger.reserve(replace(request(), run_id="b" * 32))

    def test_settlement_cannot_change_the_persisted_reservation_cap(self) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        first_request = request()
        reservation = ledger.reserve(first_request)
        forged = LedgerReservation(
            run_id=reservation.run_id,
            call_index=reservation.call_index,
            reserved_tokens=20,
            request_sha256=reservation.request_sha256,
            reservation_id=reservation.reservation_id,
        )
        now = datetime.now(UTC)
        result = derive_mediation_result(
            envelope(first_request),
            first_request,
            event_evidence=evidence(first_request),
            started_at=now,
            finished_at=now,
        )
        with self.assertRaisesRegex(CodexMediatorError, "persisted reservation cap"):
            ledger.settle(forged, result)

    def test_genesis_prevents_run_or_call_cap_expansion_on_reopen(self) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        ledger.reserve(request(total_token_cap=100, call_cap=2))
        with self.assertRaisesRegex(CodexMediatorError, "genesis policy"):
            CodexTokenLedger(self.root, RUN_ID, run_token_cap=200).reserve(
                request(call_index=2, total_token_cap=100, call_cap=2)
            )
        with self.assertRaisesRegex(CodexMediatorError, "call cap changed"):
            ledger.reserve(request(call_index=2, total_token_cap=100, call_cap=3))

    def test_settlement_cannot_change_the_persisted_reservation_identity(self) -> None:
        ledger = CodexTokenLedger(self.root, RUN_ID, run_token_cap=120)
        first_request = request()
        reservation = ledger.reserve(first_request)
        forged = replace(reservation, reservation_id="e" * 64)
        now = datetime.now(UTC)
        result = derive_mediation_result(
            envelope(first_request),
            first_request,
            event_evidence=evidence(first_request),
            started_at=now,
            finished_at=now,
        )
        with self.assertRaisesRegex(CodexMediatorError, "persisted reservation identity"):
            ledger.settle(forged, result)


class DisabledInvocationTests(unittest.TestCase):
    def test_live_zero_tool_probe_is_version_pinned_but_not_activation_proof(self) -> None:
        document = json.loads(
            (ROOT / "vm/evidence/2026-07-19-codex-zero-tool-probe.json").read_text(encoding="utf-8")
        )
        cli = document["cli_identity"]
        CodexCliIdentity(Path(cli["path"]), cli["sha256"], cli["version"]).validate()
        self.assertEqual(set(document["disabled_features"]), set(DISABLED_MODEL_FEATURES))
        raw = b"".join(
            json.dumps(event, separators=(",", ":")).encode() + b"\n"
            for event in document["events"]
        )
        parsed = parse_codex_event_evidence(
            raw,
            request(
                total_token_cap=20_000,
                input_token_cap=12_000,
                output_token_cap=8_000,
            ),
        )
        self.assertEqual(parsed.usage.total_tokens, 11_794)
        self.assertEqual(document["observations"]["model_tool_items_observed"], 0)
        self.assertFalse(ZERO_TOOL_CONFIGURATION_PROVEN)

    def test_fixed_identity_and_argv_have_no_caller_controlled_command(self) -> None:
        identity = CodexCliIdentity(Path("/opt/leftovers/codex"), "a" * 64, "0.145.0-alpha.18")
        argv = fixed_codex_argv(
            identity,
            private_cwd=Path("/private/leftovers/invocation"),
            output_schema=Path("/opt/leftovers/provider-envelope.schema.json"),
            output_last_message=Path("/private/leftovers/invocation/result.json"),
        )
        self.assertEqual(argv[0], "/opt/leftovers/codex")
        self.assertIn("gpt-5.6-terra", argv)
        self.assertIn('model_reasoning_effort="high"', argv)
        self.assertIn("--strict-config", argv)
        self.assertIn("--ephemeral", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertIn("shell_tool", argv)
        self.assertIn("unified_exec", argv)
        self.assertEqual(argv[-1], "-")
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", argv)

    def test_live_mediator_fails_before_creating_state_or_a_subprocess(self) -> None:
        identity = CodexCliIdentity(Path("/opt/leftovers/codex"), "a" * 64, "0.145.0-alpha.18")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "state"
            mediator = CodexCliMediator(identity, state_root=root, run_token_cap=120)
            with self.assertRaisesRegex(CodexMediatorDisabled, "hard-disabled"):
                mediator.mediate(request())
            self.assertFalse(root.exists())
        self.assertFalse(ZERO_TOOL_CONFIGURATION_PROVEN)
