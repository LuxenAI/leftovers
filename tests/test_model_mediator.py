from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from leftovers.model_mediator import (
    DEFAULT_MEDIATOR,
    PRODUCTION_MEDIATION_ENABLED,
    ActionKind,
    DisabledMediator,
    FixtureMediator,
    FixtureTurn,
    MediationDisabled,
    MediationLimits,
    MediationRequest,
    MediationStage,
    MediatorValidationError,
    ReportedTokenCounts,
    canonical_json_bytes,
    validate_action_batch,
    validate_mediation_request,
    validate_reported_token_counts,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "strict-vm-action-batch.schema.json"
JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None
RUN_ID = "a" * 32
PATCH_SHA = "a" * 64


def limits(
    *,
    max_response_bytes: int = 65_536,
    max_patch_bytes: int = 32_768,
    max_actions: int = 8,
    input_token_cap: int = 1_000,
    output_token_cap: int = 500,
    total_token_cap: int = 1_500,
    call_index: int = 1,
    call_cap: int = 1,
) -> MediationLimits:
    return MediationLimits(
        max_response_bytes=max_response_bytes,
        max_patch_bytes=max_patch_bytes,
        max_actions=max_actions,
        input_token_cap=input_token_cap,
        output_token_cap=output_token_cap,
        total_token_cap=total_token_cap,
        call_index=call_index,
        call_cap=call_cap,
    )


def request(
    stage: MediationStage = MediationStage.PLANNING,
    *,
    request_limits: MediationLimits | None = None,
    checks: frozenset[str] = frozenset(),
    deadline_at: datetime | None = None,
    input_bytes: bytes | None = None,
) -> MediationRequest:
    return MediationRequest(
        run_id=RUN_ID,
        round=0,
        stage=stage,
        provider="fixture",
        model="terra-fixture",
        reasoning_effort="high",
        input_bytes=input_bytes or canonical_json_bytes({"context": "offline fixture"}),
        allowed_check_ids=checks,
        limits=request_limits or limits(),
        deadline_at=deadline_at or datetime.now(UTC) + timedelta(minutes=5),
    )


def batch(stage: MediationStage, actions: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "round": 0,
        "stage": stage.value,
        "provider": "fixture",
        "model": "terra-fixture",
        "reasoning_effort": "high",
        "actions": actions,
    }


def finish(action_id: str = "finish") -> dict[str, object]:
    return {
        "id": action_id,
        "type": "finish",
        "status": "complete",
        "summary": "bounded fixture result",
    }


def usage(**changes: object) -> ReportedTokenCounts:
    values: dict[str, object] = {
        "input_tokens": 100,
        "output_tokens": 20,
        "cached_input_tokens": 10,
        "reasoning_tokens": 5,
        "total_tokens": 120,
        "source": "fixture",
        "exact": True,
    }
    values.update(changes)
    return ReportedTokenCounts(**values)  # type: ignore[arg-type]


class MediatorHappyPathTests(unittest.TestCase):
    def test_default_is_disabled_and_has_no_production_capability(self) -> None:
        self.assertFalse(PRODUCTION_MEDIATION_ENABLED)
        self.assertIsInstance(DEFAULT_MEDIATOR, DisabledMediator)
        self.assertFalse(DEFAULT_MEDIATOR.production_capable)
        with self.assertRaisesRegex(MediationDisabled, "disabled"):
            DEFAULT_MEDIATOR.mediate(request())

    def test_fixture_planning_batch_and_receipt_bind_every_identity(self) -> None:
        actions = [
            {
                "id": "read",
                "type": "read_file",
                "path": "src/main.py",
                "offset": 0,
                "max_bytes": 4096,
            },
            {"id": "list", "type": "list_dir", "path": "src", "max_entries": 20},
            {
                "id": "search",
                "type": "search_literal",
                "path": "src",
                "literal": "needle",
                "max_matches": 10,
            },
            finish(),
        ]
        raw = canonical_json_bytes(batch(MediationStage.PLANNING, actions), reject_controls=True)
        mediation_request = request()
        result = FixtureMediator((FixtureTurn(raw, usage()),)).mediate(mediation_request)

        self.assertEqual(
            tuple(action.kind for action in result.batch.actions),
            (
                ActionKind.READ_FILE,
                ActionKind.LIST_DIR,
                ActionKind.SEARCH_LITERAL,
                ActionKind.FINISH,
            ),
        )
        receipt = result.receipt
        self.assertEqual(receipt.run_id, mediation_request.run_id)
        self.assertEqual(receipt.round, mediation_request.round)
        self.assertEqual(receipt.stage, mediation_request.stage)
        self.assertEqual(receipt.provider, mediation_request.provider)
        self.assertEqual(receipt.model, mediation_request.model)
        self.assertEqual(receipt.reasoning_effort, mediation_request.reasoning_effort)
        self.assertEqual(
            receipt.input_sha256, hashlib.sha256(mediation_request.input_bytes).hexdigest()
        )
        self.assertEqual(receipt.action_batch_sha256, hashlib.sha256(raw).hexdigest())
        self.assertIsNone(result.patch)
        self.assertIsNone(receipt.patch_sha256)
        self.assertNotEqual(receipt.output_sha256, receipt.action_batch_sha256)
        self.assertEqual(receipt.total_tokens, 120)
        self.assertEqual(receipt.usage_source, "fixture")
        self.assertTrue(receipt.exact_usage)
        self.assertEqual(receipt.input_token_cap, mediation_request.limits.input_token_cap)
        self.assertEqual(receipt.output_token_cap, mediation_request.limits.output_token_cap)
        self.assertEqual(receipt.total_token_cap, mediation_request.limits.total_token_cap)
        self.assertEqual(receipt.deadline_at, mediation_request.deadline_at)
        self.assertLess(receipt.started_at, receipt.finished_at)
        self.assertEqual(
            receipt.to_dict()["deadline_at"],
            mediation_request.deadline_at.isoformat().replace("+00:00", "Z"),
        )

    def test_implementation_uses_only_a_separately_bound_patch_digest(self) -> None:
        proposed_patch = b"diff --git a/a.py b/a.py\n"
        proposed_digest = hashlib.sha256(proposed_patch).hexdigest()
        actions = [
            {"id": "patch", "type": "apply_patch", "patch_sha256": proposed_digest},
            finish(),
        ]
        raw = canonical_json_bytes(batch(MediationStage.IMPLEMENTATION, actions))
        result = FixtureMediator((FixtureTurn(raw, usage(), proposed_patch),)).mediate(
            request(MediationStage.IMPLEMENTATION)
        )
        self.assertEqual(result.batch.actions[0].kind, ActionKind.APPLY_PATCH)
        self.assertEqual(result.patch, proposed_patch)
        self.assertEqual(result.receipt.patch_sha256, proposed_digest)

    def test_patch_genesis_is_stage_bound_bounded_and_receipted(self) -> None:
        proposed_patch = b"diff --git a/a b/a\n"
        digest = hashlib.sha256(proposed_patch).hexdigest()
        patch_actions = [
            {"id": "patch", "type": "apply_patch", "patch_sha256": digest},
            finish(),
        ]
        raw = canonical_json_bytes(batch(MediationStage.IMPLEMENTATION, patch_actions))

        for turn, stage, message in (
            (FixtureTurn(raw, usage(), b""), MediationStage.IMPLEMENTATION, "empty"),
            (FixtureTurn(raw, usage(), b"x" * 33), MediationStage.IMPLEMENTATION, "oversized"),
            (FixtureTurn(raw, usage(), b"bad\0patch"), MediationStage.IMPLEMENTATION, "NUL"),
            (FixtureTurn(raw, usage(), b"\xff"), MediationStage.IMPLEMENTATION, "UTF-8"),
            (
                FixtureTurn(
                    canonical_json_bytes(batch(MediationStage.PLANNING, [finish()])),
                    usage(),
                    proposed_patch,
                ),
                MediationStage.PLANNING,
                "implementation",
            ),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(MediatorValidationError, message),
            ):
                FixtureMediator((turn,)).mediate(
                    request(
                        stage,
                        request_limits=limits(max_response_bytes=1_024, max_patch_bytes=32),
                    )
                )

        without_action = canonical_json_bytes(batch(MediationStage.IMPLEMENTATION, [finish()]))
        with self.assertRaisesRegex(MediatorValidationError, "present together"):
            FixtureMediator((FixtureTurn(without_action, usage(), proposed_patch),)).mediate(
                request(MediationStage.IMPLEMENTATION)
            )

        with self.assertRaisesRegex(MediatorValidationError, "present together"):
            validate_action_batch(raw, request(MediationStage.IMPLEMENTATION))

    def test_final_verify_runs_only_curated_check_ids_then_finishes(self) -> None:
        actions = [
            {"id": "check", "type": "run_check", "check_id": "unit-tests"},
            finish(),
        ]
        parsed = validate_action_batch(
            canonical_json_bytes(batch(MediationStage.FINAL_VERIFY, actions)),
            request(MediationStage.FINAL_VERIFY, checks=frozenset({"unit-tests"})),
        )
        self.assertEqual(
            tuple(action.kind for action in parsed.actions),
            (ActionKind.RUN_CHECK, ActionKind.FINISH),
        )


class CanonicalAndBindingTests(unittest.TestCase):
    def test_duplicate_keys_and_noncanonical_bytes_are_rejected(self) -> None:
        with self.assertRaisesRegex(MediatorValidationError, "duplicate"):
            validate_action_batch(b'{"run_id":"a","run_id":"b"}', request())

        value = batch(MediationStage.PLANNING, [finish()])
        noncanonical = json.dumps(value, sort_keys=False).encode()
        with self.assertRaisesRegex(MediatorValidationError, "not canonical"):
            validate_action_batch(noncanonical, request())

    def test_float_nan_boolean_round_and_control_characters_are_rejected(self) -> None:
        base = batch(MediationStage.PLANNING, [finish()])
        for bad_round in (0.5, float("nan"), True):
            hostile = copy.deepcopy(base)
            hostile["round"] = bad_round
            if isinstance(bad_round, float) and bad_round != bad_round:
                raw = json.dumps(
                    hostile, allow_nan=True, sort_keys=True, separators=(",", ":")
                ).encode()
            else:
                raw = json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode()
            with self.subTest(round=bad_round), self.assertRaises(MediatorValidationError):
                validate_action_batch(raw, request())

        hostile = copy.deepcopy(base)
        hostile["actions"][0]["summary"] = "line\nbreak"  # type: ignore[index]
        raw = json.dumps(hostile, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaisesRegex(MediatorValidationError, "control"):
            validate_action_batch(raw, request())

        hostile = copy.deepcopy(base)
        hostile["actions"][0]["status"] = []  # type: ignore[index]
        with self.assertRaisesRegex(MediatorValidationError, "status"):
            validate_action_batch(canonical_json_bytes(hostile), request())

    def test_every_response_identity_is_bound_exactly(self) -> None:
        original = batch(MediationStage.PLANNING, [finish()])
        changes = {
            "run_id": "b" * 32,
            "round": 1,
            "stage": "review",
            "provider": "other-provider",
            "model": "other-model",
            "reasoning_effort": "medium",
        }
        for key, value in changes.items():
            hostile = copy.deepcopy(original)
            hostile[key] = value
            with (
                self.subTest(field=key),
                self.assertRaisesRegex(MediatorValidationError, "does not match"),
            ):
                validate_action_batch(canonical_json_bytes(hostile), request())

    def test_unknown_authority_fields_are_rejected(self) -> None:
        forbidden = (
            "command",
            "url",
            "filesystem",
            "shell",
            "plugin",
            "tool",
            "credential",
            "argv",
            "endpoint",
            "environment",
        )
        for field in forbidden:
            hostile = batch(MediationStage.PLANNING, [finish()])
            hostile[field] = "forbidden"
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(MediatorValidationError, "unknown"),
            ):
                validate_action_batch(canonical_json_bytes(hostile), request())

    def test_response_and_action_count_limits_apply_before_acceptance(self) -> None:
        value = batch(
            MediationStage.PLANNING,
            [
                {
                    "id": "read",
                    "type": "read_file",
                    "path": "src/a.py",
                    "offset": 0,
                    "max_bytes": 1,
                },
                finish(),
            ],
        )
        raw = canonical_json_bytes(value)
        with self.assertRaisesRegex(MediatorValidationError, "action count"):
            validate_action_batch(raw, request(request_limits=limits(max_actions=1)))
        with self.assertRaisesRegex(MediatorValidationError, "oversized"):
            validate_action_batch(
                raw,
                request(
                    request_limits=limits(
                        max_response_bytes=len(raw) - 1,
                        max_patch_bytes=len(raw) - 1,
                    )
                ),
            )


class ActionAuthorityTests(unittest.TestCase):
    def test_hostile_paths_are_rejected_in_every_path_action(self) -> None:
        paths = (
            "/etc/passwd",
            "../secret",
            "src/../secret",
            ".git/config",
            "src/.Git/config",
            "src//main.py",
            "src\\main.py",
            "C:secret",
            "src/\x00name",
        )
        for path in paths:
            actions = [
                {"id": "read", "type": "read_file", "path": path, "offset": 0, "max_bytes": 32},
                finish(),
            ]
            raw = json.dumps(
                batch(MediationStage.PLANNING, actions),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            with self.subTest(path=path), self.assertRaises(MediatorValidationError):
                validate_action_batch(raw, request())

    def test_read_list_search_bounds_and_literal_only_contract(self) -> None:
        hostile_actions = [
            {"id": "read", "type": "read_file", "path": "src/a", "offset": -1, "max_bytes": 1},
            {"id": "read", "type": "read_file", "path": "src/a", "offset": 0, "max_bytes": 65_537},
            {"id": "list", "type": "list_dir", "path": "src", "max_entries": 1_025},
            {
                "id": "search",
                "type": "search_literal",
                "path": "src",
                "literal": "x",
                "max_matches": 1_001,
            },
            {
                "id": "search",
                "type": "search_literal",
                "path": "src",
                "literal": "x",
                "max_matches": 1,
                "regex": True,
            },
        ]
        for hostile in hostile_actions:
            raw = canonical_json_bytes(batch(MediationStage.PLANNING, [hostile, finish()]))
            with self.subTest(action=hostile), self.assertRaises(MediatorValidationError):
                validate_action_batch(raw, request())

    def test_patch_bytes_or_wrong_digest_cannot_enter_the_action_batch(self) -> None:
        mediation_request = request(MediationStage.IMPLEMENTATION)
        hostile_actions = [
            {"id": "patch", "type": "apply_patch", "patch_sha256": "b" * 64},
            {
                "id": "patch",
                "type": "apply_patch",
                "patch_sha256": PATCH_SHA,
                "patch": "diff --git a/a b/a",
            },
        ]
        for hostile in hostile_actions:
            with self.subTest(action=hostile), self.assertRaises(MediatorValidationError):
                validate_action_batch(
                    canonical_json_bytes(batch(MediationStage.IMPLEMENTATION, [hostile, finish()])),
                    mediation_request,
                    proposed_patch_sha256=PATCH_SHA,
                )

        repeated = [
            {"id": "patch-a", "type": "apply_patch", "patch_sha256": PATCH_SHA},
            {"id": "patch-b", "type": "apply_patch", "patch_sha256": PATCH_SHA},
            finish(),
        ]
        with self.assertRaisesRegex(MediatorValidationError, "at most one"):
            validate_action_batch(
                canonical_json_bytes(batch(MediationStage.IMPLEMENTATION, repeated)),
                mediation_request,
                proposed_patch_sha256=PATCH_SHA,
            )

    def test_check_id_membership_and_no_argv_are_enforced(self) -> None:
        mediation_request = request(
            MediationStage.FINAL_VERIFY,
            checks=frozenset({"unit-tests"}),
        )
        for hostile in (
            {"id": "check", "type": "run_check", "check_id": "unknown"},
            {
                "id": "check",
                "type": "run_check",
                "check_id": "unit-tests",
                "argv": ["sh", "-c", "escape"],
            },
        ):
            with self.subTest(action=hostile), self.assertRaises(MediatorValidationError):
                validate_action_batch(
                    canonical_json_bytes(batch(MediationStage.FINAL_VERIFY, [hostile, finish()])),
                    mediation_request,
                )

    def test_stage_permissions_are_fail_closed(self) -> None:
        run_check = {"id": "check", "type": "run_check", "check_id": "unit-tests"}
        for stage in (
            MediationStage.PLANNING,
            MediationStage.IMPLEMENTATION,
            MediationStage.REVIEW,
        ):
            with (
                self.subTest(stage=stage),
                self.assertRaisesRegex(MediatorValidationError, "forbidden"),
            ):
                validate_action_batch(
                    canonical_json_bytes(batch(stage, [run_check, finish()])),
                    request(stage, checks=frozenset({"unit-tests"})),
                )

        read = {"id": "read", "type": "read_file", "path": "src/a", "offset": 0, "max_bytes": 1}
        with self.assertRaisesRegex(MediatorValidationError, "forbidden"):
            validate_action_batch(
                canonical_json_bytes(batch(MediationStage.FINAL_VERIFY, [read, finish()])),
                request(
                    MediationStage.FINAL_VERIFY,
                    checks=frozenset({"unit-tests"}),
                ),
            )

    def test_finish_is_required_once_at_the_end_and_action_ids_are_unique(self) -> None:
        read = {"id": "same", "type": "read_file", "path": "src/a", "offset": 0, "max_bytes": 1}
        cases = (
            [read],
            [finish(), read],
            [read, finish("same")],
            [finish("a"), finish("b")],
        )
        for actions in cases:
            with self.subTest(actions=actions), self.assertRaises(MediatorValidationError):
                validate_action_batch(
                    canonical_json_bytes(batch(MediationStage.PLANNING, actions)),
                    request(),
                )


class QuotaReceiptAndDeadlineTests(unittest.TestCase):
    def test_token_caps_arithmetic_and_exact_source_are_enforced(self) -> None:
        good_limits = limits()
        validate_reported_token_counts(usage(source="provider"), good_limits, fixture=False)
        hostile = (
            usage(source="provider", exact=False),
            usage(source="wrong"),
            usage(input_tokens=None),
            usage(cached_input_tokens=101),
            usage(reasoning_tokens=21),
            usage(total_tokens=119),
            usage(output_tokens=501, total_tokens=601),
        )
        for reported in hostile:
            with self.subTest(usage=reported), self.assertRaises(MediatorValidationError):
                validate_reported_token_counts(reported, good_limits, fixture=False)

    def test_inconsistent_token_and_call_caps_are_rejected(self) -> None:
        bad_limits = (
            limits(total_token_cap=999),
            limits(total_token_cap=1_501),
            limits(call_index=2, call_cap=1),
            limits(call_index=1, call_cap=65),
            limits(max_actions=33),
            limits(max_response_bytes=262_145),
            limits(max_response_bytes=1_024, max_patch_bytes=1_025),
        )
        for request_limits in bad_limits:
            with self.subTest(limits=request_limits), self.assertRaises(MediatorValidationError):
                validate_mediation_request(request(request_limits=request_limits))

    def test_fixture_call_sequence_and_call_cap_cannot_be_bypassed(self) -> None:
        raw = canonical_json_bytes(batch(MediationStage.PLANNING, [finish()]))
        turns = (FixtureTurn(raw, usage()), FixtureTurn(raw, usage()))
        mediator = FixtureMediator(turns)
        with self.assertRaisesRegex(MediatorValidationError, "out of sequence"):
            mediator.mediate(request(request_limits=limits(call_index=2, call_cap=2)))
        with self.assertRaisesRegex(MediatorValidationError, "turn count"):
            mediator.mediate(request(request_limits=limits(call_index=1, call_cap=1)))

        mediator = FixtureMediator(turns)
        first = mediator.mediate(request(request_limits=limits(call_index=1, call_cap=2)))
        self.assertEqual(first.receipt.call_index, 1)
        second_request = request(request_limits=limits(call_index=2, call_cap=2))
        second = mediator.mediate(second_request)
        self.assertEqual(second.receipt.call_index, 2)

    def test_deadline_must_be_aware_live_and_bounded(self) -> None:
        now = datetime.now(UTC)
        hostile = (
            now.replace(tzinfo=None) + timedelta(minutes=1),
            now - timedelta(seconds=1),
            now + timedelta(hours=5),
        )
        for deadline in hostile:
            with self.subTest(deadline=deadline), self.assertRaises(MediatorValidationError):
                validate_mediation_request(request(deadline_at=deadline), now=now)

        malformed = request()
        object.__setattr__(malformed, "deadline_at", "later")
        with self.assertRaisesRegex(MediatorValidationError, "deadline"):
            validate_mediation_request(malformed)

        with self.assertRaisesRegex(MediatorValidationError, "validation time"):
            validate_mediation_request(request(), now=datetime.now())

    def test_request_identifier_types_fail_closed_without_runtime_type_errors(self) -> None:
        malformed = request()
        object.__setattr__(malformed, "reasoning_effort", ["high"])
        with self.assertRaisesRegex(MediatorValidationError, "reasoning_effort"):
            validate_mediation_request(malformed)

    def test_input_is_bounded_duplicate_free_canonical_json(self) -> None:
        for raw in (
            b'{"a":1,"a":2}',
            b'{ "a": 1 }',
            b'{"score":1.5}',
            b'{"text":"\\ud800"}',
            b"x" * 2_000_001,
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(MediatorValidationError):
                validate_mediation_request(request(input_bytes=raw))

        with self.assertRaisesRegex(MediatorValidationError, "validation time"):
            validate_mediation_request(request(), now="later")  # type: ignore[arg-type]


class ActionSchemaTests(unittest.TestCase):
    def test_schema_is_valid_json_and_defines_no_authority_escape_fields(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        property_names: set[str] = set()

        def walk(value: object) -> None:
            if isinstance(value, dict):
                properties = value.get("properties")
                if isinstance(properties, dict):
                    property_names.update(properties)
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(schema)
        self.assertTrue(
            {
                "schema_version",
                "run_id",
                "round",
                "stage",
                "provider",
                "model",
                "reasoning_effort",
                "actions",
            }.issubset(property_names)
        )
        for forbidden in (
            "command",
            "url",
            "filesystem",
            "shell",
            "plugin",
            "tool",
            "credential",
            "argv",
            "endpoint",
            "environment",
        ):
            self.assertNotIn(forbidden, property_names)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "optional jsonschema package is unavailable")
    def test_schema_accepts_valid_batch_and_rejects_stage_escalation(self) -> None:
        from jsonschema import Draft202012Validator

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        valid = batch(
            MediationStage.FINAL_VERIFY,
            [
                {"id": "check", "type": "run_check", "check_id": "unit-tests"},
                finish(),
            ],
        )
        self.assertEqual(list(validator.iter_errors(valid)), [])

        hostile = batch(
            MediationStage.REVIEW,
            [
                {"id": "check", "type": "run_check", "check_id": "unit-tests"},
                finish(),
            ],
        )
        self.assertTrue(list(validator.iter_errors(hostile)))


if __name__ == "__main__":
    unittest.main()
