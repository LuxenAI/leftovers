from __future__ import annotations

import copy
import hashlib
import os
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

import leftovers.vm_bundle as bundle
from leftovers.model_mediator import (
    FixtureMediator,
    FixtureTurn,
    MediationLimits,
    MediationRequest,
    MediationStage,
    ReportedTokenCounts,
    canonical_json_bytes,
)


class VMBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.request = self.root / "request.lfrq"
        self.scratch = self.root / "scratch.lfrs"
        self.binding = {"run_id": "a" * 32, "round": 7, "stage": "implementation"}
        self.source = self.root / "capsule.bin"
        self.source.write_bytes(b"capsule")
        os.chmod(self.source, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request_sections(self, **extra: object) -> dict[str, object]:
        sections: dict[str, object] = {
            "manifest": {"version": 1},
            "source_capsule": self.source,
            "task": {"issue": 42},
            "policy": {
                "schema_version": 1,
                "provider": "fixture",
                "model": "terra-fixture",
                "reasoning_effort": "high",
                "allowed_check_ids": [],
                "max_actions": 8,
            },
            "action_batch": self.action_batch("implementation", [self.finish_action()]),
        }
        sections.update(extra)
        policy = sections["policy"]
        action_batch = sections["action_batch"]
        assert isinstance(policy, dict)
        assert isinstance(action_batch, dict)
        allowed = policy.get("allowed_check_ids", [])
        if not isinstance(allowed, list):
            allowed = []
        registry = {
            "schema_version": 1,
            "checks": [
                {"check_id": check_id, "argv": ["python3", "-m", "unittest"]}
                for check_id in allowed
            ],
        }
        action_raw = bundle._canonical_json(action_batch, bundle.REQUEST_JSON_CAPS["action_batch"])
        policy_raw = bundle._canonical_json(policy, bundle.REQUEST_JSON_CAPS["policy"])
        registry_raw = bundle._canonical_json(registry, bundle.REQUEST_JSON_CAPS["check_registry"])
        proposed = sections.get("proposed_patch")
        if isinstance(proposed, str):
            proposed = proposed.encode("utf-8")
        patch_sha = None if proposed is None else hashlib.sha256(proposed).hexdigest()
        sections["check_registry"] = registry
        sections["mediation"] = {
            "schema_version": 1,
            "run_id": self.binding["run_id"],
            "round": self.binding["round"],
            "stage": action_batch["stage"],
            "provider": policy.get("provider", "fixture"),
            "model": policy.get("model", "terra-fixture"),
            "reasoning_effort": policy.get("reasoning_effort", "high"),
            "input_sha256": "c" * 64,
            "action_batch_sha256": hashlib.sha256(action_raw).hexdigest(),
            "patch_sha256": patch_sha,
            "output_sha256": "d" * 64,
            "input_tokens": 1,
            "output_tokens": 1,
            "cached_input_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 2,
            "usage_source": "fixture",
            "exact_usage": True,
            "max_response_bytes": 256 * 1024,
            "max_patch_bytes": 256 * 1024,
            "max_actions": policy.get("max_actions", 1),
            "input_token_cap": 1,
            "output_token_cap": 1,
            "total_token_cap": 2,
            "call_index": 1,
            "call_cap": 1,
            "deadline_at": "2030-01-01T00:00:00.000000Z",
            "started_at": "2029-01-01T00:00:00.000000Z",
            "finished_at": "2029-01-01T00:00:01.000000Z",
            "authority": "fixture",
            "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
            "check_registry_sha256": hashlib.sha256(registry_raw).hexdigest(),
            "token_ledger_reservation_id": "e" * 64,
            "provider_usage_evidence_sha256": bundle.FIXTURE_USAGE_EVIDENCE_SHA256,
        }
        return sections

    def action_batch(self, stage: str, actions: list[dict[str, object]]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "run_id": self.binding["run_id"],
            "round": self.binding["round"],
            "stage": stage,
            "provider": "fixture",
            "model": "terra-fixture",
            "reasoning_effort": "high",
            "actions": actions,
        }

    @staticmethod
    def finish_action() -> dict[str, object]:
        return {
            "id": "finish",
            "type": "finish",
            "status": "complete",
            "summary": "bounded fixture result",
        }

    @staticmethod
    def result_sections(patch: str = "diff --git a/a b/a\n") -> dict[str, object]:
        return {
            "guest_receipt": {"exit": 0},
            "observations": {"tests": "passed"},
            "canonical_patch": patch,
            "checks": {"curated": ["pytest"]},
            "stage_result": {"status": "complete"},
        }

    def build_request(self, **extra: object):
        return bundle.build_request_bundle(
            self.request,
            sections=self.request_sections(**extra),
            fixture_authorization=True,
            **self.binding,
        )

    def build_result(self, *, stage: str = "implementation", patch: str = "diff --git a/a b/a\n"):
        return bundle.build_tail_result(
            self.scratch,
            scratch_size=bundle.MIN_SCRATCH_BYTES,
            tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
            sections=self.result_sections(patch),
            **{**self.binding, "stage": stage},
        )

    def semantic_request(self, *, stage: str = "implementation", checks: list[str] | None = None):
        checks = [] if checks is None else checks
        patch = b"diff --git a/a b/a\n"
        policy = {
            "schema_version": 1,
            "provider": "fixture",
            "model": "terra-fixture",
            "reasoning_effort": "high",
            "allowed_check_ids": checks,
            "max_actions": 8,
        }
        if stage == "implementation":
            actions = [
                {
                    "id": "patch",
                    "type": "apply_patch",
                    "patch_sha256": hashlib.sha256(patch).hexdigest(),
                },
                self.finish_action(),
            ]
            extra: dict[str, object] = {"proposed_patch": patch}
        elif stage == "final_verify":
            actions = [
                {"id": "check", "type": "run_check", "check_id": checks[0]},
                self.finish_action(),
            ]
            extra = {"cumulative_patch": "frozen patch\n"}
        else:
            actions = [self.finish_action()]
            extra = {}
        return bundle.build_request_bundle(
            self.request,
            run_id=self.binding["run_id"],
            round=self.binding["round"],
            stage=stage,
            sections=self.request_sections(
                manifest={
                    "schema_version": 2,
                    "guest_policy_sha256": "b" * 64,
                },
                policy=policy,
                action_batch=self.action_batch(stage, actions),
                **extra,
            ),
            fixture_authorization=True,
        )

    @staticmethod
    def semantic_result_sections(
        request: bundle.ParsedBundle,
        *,
        stage: str = "implementation",
        status: str = "complete",
    ) -> dict[str, object]:
        patch = "diff --git a/a b/a\n" if stage == "implementation" and status == "complete" else ""
        patch_sha = hashlib.sha256(patch.encode("utf-8")).hexdigest() if patch else None
        action_ids = ["patch", "finish"] if stage == "implementation" else ["check", "finish"]
        observation_ids = action_ids
        checks: list[dict[str, object]] = []
        if stage == "final_verify":
            checks = [
                {
                    "check_id": "pytest_unit",
                    "exit": 0,
                    "timed_out": False,
                    "truncated": False,
                    "tail": "ok\n",
                }
            ]
        cumulative = patch_sha
        if stage != "implementation":
            reference = request.raw_sections.get("cumulative_patch")
            cumulative = None if reference is None else reference.sha256
        return {
            "guest_receipt": {
                "schema_version": 1,
                "run_id": request.binding.run_id,
                "round": request.binding.round,
                "stage": stage,
                "request_sha256": request.sha256,
                "guest_policy_sha256": "b" * 64,
                "isolation": {
                    "schema_version": 1,
                    "network": "absent",
                    "host_shares": 0,
                    "credential_files": 0,
                    "uid": 65534,
                    "no_new_privs": True,
                    "seccomp": True,
                    "landlock": True,
                    "cgroup_v2": True,
                    "pid1": True,
                    "root_read_only": True,
                },
            },
            "observations": [
                {"action_id": action_id, "status": "complete", "truncated": False, "tail": ""}
                for action_id in observation_ids
            ],
            "canonical_patch": patch,
            "checks": checks,
            "stage_result": {
                "status": status,
                "summary": "bounded fixture",
                "action_ids": action_ids,
                "cumulative_patch_sha256": cumulative,
            },
        }

    @staticmethod
    def _records(path: Path, header_offset: int = 0) -> list[tuple[str, int, int, bytes]]:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            header = os.pread(descriptor, bundle.HEADER_BYTES, header_offset)
        finally:
            os.close(descriptor)
        records = []
        for index in range(bundle.MAX_SECTIONS):
            location = bundle._PREFIX.size + index * bundle._SECTION.size
            type_raw, offset, length, digest = bundle._SECTION.unpack_from(header, location)
            if type_raw == b"\0" * 16:
                break
            records.append((bundle._decode_fixed(type_raw, "type"), offset, length, digest))
        return records

    @staticmethod
    def _write_at(path: Path, offset: int, raw: bytes, mode: int) -> None:
        os.chmod(path, 0o600)
        descriptor = os.open(path, os.O_WRONLY)
        try:
            os.pwrite(descriptor, raw, offset)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, mode)

    def test_request_is_variable_sealed_and_streams_opaque_source(self) -> None:
        # The source exceeds both the old 4KiB record size and the bounded copy chunk.
        self.source.write_bytes(b"x" * (bundle.COPY_CHUNK_BYTES * 2 + 4_097))
        original_fsync = os.fsync
        fsync_modes: list[int] = []

        def recording_fsync(descriptor: int) -> None:
            fsync_modes.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
            original_fsync(descriptor)

        with mock.patch.object(bundle.os, "fsync", side_effect=recording_fsync):
            parsed = self.build_request(cumulative_patch="already reviewed\n")
        self.assertGreater(self.request.stat().st_size, bundle.HEADER_BYTES)
        self.assertEqual(self.request.stat().st_size % bundle.ALIGNMENT, 0)
        self.assertEqual(self.request.stat().st_mode & 0o777, 0o400)
        self.assertEqual(fsync_modes, [0o400])
        self.assertEqual(parsed.raw_sections["source_capsule"].length, self.source.stat().st_size)
        self.assertIn("cumulative_patch", parsed.raw_sections)
        self.assertEqual(
            parsed.sha256,
            hashlib.sha256(self.request.read_bytes()).hexdigest(),
        )

    def test_request_rejects_invalid_raw_patch_and_caps(self) -> None:
        patch = self.root / "invalid.patch"
        patch.write_bytes(b"\xff")
        os.chmod(patch, 0o600)
        with self.assertRaisesRegex(bundle.BundleError, "UTF-8"):
            self.build_request(cumulative_patch=patch)
        os.truncate(self.source, bundle.REQUEST_RAW_CAPS["source_capsule"] + 1)
        with self.assertRaisesRegex(bundle.BundleError, "byte cap"):
            self.build_request()

    def test_proposed_patch_has_a_real_data_channel_bound_to_one_action(self) -> None:
        proposed = b"diff --git a/a.py b/a.py\n"
        digest = hashlib.sha256(proposed).hexdigest()
        parsed = self.build_request(
            proposed_patch=proposed,
            action_batch=self.action_batch(
                "implementation",
                [
                    {"id": "patch", "type": "apply_patch", "patch_sha256": digest},
                    self.finish_action(),
                ],
            ),
        )
        self.assertEqual(parsed.raw_sections["proposed_patch"].sha256, digest)
        with self.assertRaisesRegex(bundle.BundleError, "only cumulative_patch"):
            bundle.read_raw_section(self.request, parsed, "proposed_patch")

        for hostile in (
            self.action_batch(
                "implementation",
                [
                    {
                        "id": "patch",
                        "type": "apply_patch",
                        "patch_sha256": "b" * 64,
                    },
                    self.finish_action(),
                ],
            ),
            {
                **self.action_batch("implementation", [self.finish_action()]),
                "argv": ["sh", "-c", "escape"],
            },
        ):
            with (
                self.subTest(hostile=hostile),
                self.assertRaisesRegex(bundle.BundleError, "strict mediated action grammar"),
            ):
                self.build_request(proposed_patch=proposed, action_batch=hostile)

        with self.assertRaisesRegex(bundle.BundleError, "strict action-policy"):
            self.build_request(
                policy={"network": "none"},
                action_batch=self.action_batch("implementation", [self.finish_action()]),
            )

    def test_request_requires_a_private_streamed_source_capsule(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "streamed Path"):
            self.build_request(source_capsule=b"not a streamed file")
        os.chmod(self.source, 0o640)
        with self.assertRaisesRegex(bundle.BundleError, "unsafe"):
            self.build_request()

    def test_raw_action_data_without_explicit_fixture_authorization_is_rejected(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "fixture mediation authorization"):
            bundle.build_request_bundle(
                self.request,
                sections=self.request_sections(),
                **self.binding,
            )

    def test_receipt_and_check_registry_tampering_fail_closed(self) -> None:
        patch = b"diff --git a/a b/a\n"
        action = self.action_batch(
            "implementation",
            [
                {
                    "id": "patch",
                    "type": "apply_patch",
                    "patch_sha256": hashlib.sha256(patch).hexdigest(),
                },
                self.finish_action(),
            ],
        )
        sections = self.request_sections(proposed_patch=patch, action_batch=action)
        receipt = sections["mediation"]
        assert isinstance(receipt, dict)
        receipt["action_batch_sha256"] = "0" * 64
        with self.assertRaisesRegex(bundle.BundleError, "receipt digest"):
            bundle.build_request_bundle(
                self.request,
                sections=sections,
                fixture_authorization=True,
                **self.binding,
            )

        final_policy = {
            "schema_version": 1,
            "provider": "fixture",
            "model": "terra-fixture",
            "reasoning_effort": "high",
            "allowed_check_ids": ["pytest_unit"],
            "max_actions": 8,
        }
        final_actions = self.action_batch(
            "final_verify",
            [
                {"id": "check", "type": "run_check", "check_id": "pytest_unit"},
                self.finish_action(),
            ],
        )
        unknown = self.request_sections(
            policy=final_policy,
            action_batch=final_actions,
            cumulative_patch="frozen patch\n",
        )
        registry = unknown["check_registry"]
        assert isinstance(registry, dict)
        registry["checks"][0]["check_id"] = "unknown"  # type: ignore[index]
        with self.assertRaisesRegex(bundle.BundleError, "does not exactly match"):
            bundle.build_request_bundle(
                self.root / "unknown-check.lfrq",
                sections=unknown,
                fixture_authorization=True,
                **{**self.binding, "stage": "final_verify"},
            )

        altered = self.request_sections(
            policy=final_policy,
            action_batch=final_actions,
            cumulative_patch="frozen patch\n",
        )
        altered_registry = altered["check_registry"]
        assert isinstance(altered_registry, dict)
        altered_registry["checks"][0]["argv"] = ["python3", "-m", "unittest", "other"]  # type: ignore[index]
        with self.assertRaisesRegex(bundle.BundleError, "receipt digest"):
            bundle.build_request_bundle(
                self.root / "altered-argv.lfrq",
                sections=altered,
                fixture_authorization=True,
                **{**self.binding, "stage": "final_verify"},
            )

    def test_controller_authorization_rebuilds_and_binds_a_fixture_result(self) -> None:
        limits = MediationLimits(
            max_response_bytes=4096,
            max_patch_bytes=1024,
            max_actions=8,
            input_token_cap=100,
            output_token_cap=100,
            total_token_cap=200,
            call_index=1,
            call_cap=1,
        )
        request = MediationRequest(
            run_id=self.binding["run_id"],
            round=self.binding["round"],
            stage=MediationStage.PLANNING,
            provider="fixture",
            model="terra-fixture",
            reasoning_effort="high",
            input_bytes=canonical_json_bytes({"fixture": True}),
            allowed_check_ids=frozenset(),
            limits=limits,
            deadline_at=datetime.now(UTC) + timedelta(minutes=2),
        )
        raw = canonical_json_bytes(self.action_batch("planning", [self.finish_action()]))
        result = FixtureMediator(
            (
                FixtureTurn(
                    raw,
                    ReportedTokenCounts(10, 5, 0, 0, 15, "fixture", True),
                ),
            )
        ).mediate(request)
        authorization = bundle.authorize_mediation_result(
            request,
            result,
            policy={
                "schema_version": 1,
                "provider": "fixture",
                "model": "terra-fixture",
                "reasoning_effort": "high",
                "allowed_check_ids": [],
                "max_actions": 8,
            },
            curated_checks=(),
            token_ledger_reservation_id="f" * 64,
            provider_usage_evidence_sha256=bundle.FIXTURE_USAGE_EVIDENCE_SHA256,
            fixture=True,
        )
        parsed = bundle.build_authorized_request_bundle(
            self.request,
            run_id=request.run_id,
            round=request.round,
            stage=request.stage.value,
            manifest={"schema_version": 2, "guest_policy_sha256": "b" * 64},
            source_capsule=self.source,
            task={"issue": 42},
            authorization=authorization,
        )
        mediation = parsed.sections["mediation"]
        assert isinstance(mediation, dict)
        self.assertEqual(mediation["action_batch_sha256"], result.receipt.action_batch_sha256)
        with self.assertRaisesRegex(bundle.BundleError, "broker attestation"):
            bundle.authorize_mediation_result(
                request,
                result,
                policy={
                    "schema_version": 1,
                    "provider": "fixture",
                    "model": "terra-fixture",
                    "reasoning_effort": "high",
                    "allowed_check_ids": [],
                    "max_actions": 8,
                },
                curated_checks=(),
                token_ledger_reservation_id="f" * 64,
                provider_usage_evidence_sha256="a" * 64,
            )

    def test_request_rejects_size_hash_gaps_unknown_and_private_mode(self) -> None:
        self.build_request()
        os.chmod(self.request, 0o600)
        os.truncate(self.request, self.request.stat().st_size - bundle.ALIGNMENT)
        os.chmod(self.request, 0o400)
        with self.assertRaisesRegex(bundle.BundleError, "size|fields"):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)

        self.request.unlink()
        self.build_request()
        records = self._records(self.request)
        gaps = bundle._gaps(bundle.HEADER_BYTES, self.request.stat().st_size, records)
        self.assertTrue(gaps)
        self._write_at(self.request, gaps[0][0], b"x", 0o400)
        with self.assertRaisesRegex(bundle.BundleError, "nonzero"):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)

        self.request.unlink()
        self.build_request()
        location = bundle._PREFIX.size
        self._write_at(self.request, location, b"unknown" + b"\0" * 9, 0o400)
        with self.assertRaisesRegex(bundle.BundleError, "unknown"):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)

        os.chmod(self.request, 0o640)
        with self.assertRaisesRegex(bundle.BundleError, "mode"):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)

    def test_request_rejects_noncanonical_table_and_json(self) -> None:
        self.build_request()
        records = self._records(self.request)
        self.assertGreaterEqual(len(records), 2)
        first = bundle._PREFIX.size
        second = first + bundle._SECTION.size
        descriptor = os.open(self.request, os.O_RDONLY)
        try:
            header = os.pread(descriptor, bundle.HEADER_BYTES, 0)
        finally:
            os.close(descriptor)
        self._write_at(self.request, first, header[second : second + bundle._SECTION.size], 0o400)
        self._write_at(self.request, second, header[first : first + bundle._SECTION.size], 0o400)
        with self.assertRaisesRegex(bundle.BundleError, "canonical order"):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)
        with self.assertRaisesRegex(bundle.BundleError, "signed 64-bit"):
            bundle._canonical_json({"n": 2**63}, 64)
        with self.assertRaisesRegex(bundle.BundleError, "UTF-8 JSON"):
            bundle._parse_canonical_json(b'{"x":1,"x":2}', 64)

    def test_request_rejects_links_and_content_race(self) -> None:
        self.build_request()
        linked = self.root / "linked"
        os.link(self.request, linked)
        with self.assertRaisesRegex(bundle.BundleError, "links"):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)
        linked.unlink()

        original_identity = bundle._identity
        calls = 0

        def changing_identity(value: os.stat_result) -> bundle._Identity:
            nonlocal calls
            calls += 1
            current = original_identity(value)
            if calls >= 3:
                return bundle._Identity(
                    current.dev,
                    current.ino,
                    current.uid,
                    current.mode,
                    current.nlink,
                    current.size,
                    current.mtime_ns + 1,
                    current.ctime_ns,
                )
            return current

        with (
            mock.patch.object(bundle, "_identity", side_effect=changing_identity),
            self.assertRaisesRegex(bundle.BundleError, "identity changed"),
        ):
            bundle.parse_request_bundle(self.request, fixture_authorization=True, **self.binding)

    def test_tail_is_fixed_scratch_with_verified_footer_and_region_digest(self) -> None:
        parsed = self.build_result()
        self.assertEqual(self.scratch.stat().st_size, bundle.MIN_SCRATCH_BYTES)
        self.assertEqual(self.scratch.stat().st_mode & 0o777, 0o600)
        self.assertIn("canonical_patch", parsed.raw_sections)
        descriptor = os.open(self.scratch, os.O_RDONLY)
        try:
            expected = bundle._hash_plain_range(
                descriptor,
                bundle.MIN_SCRATCH_BYTES - bundle.MIN_RESULT_TAIL_BYTES,
                bundle.MIN_SCRATCH_BYTES,
            ).hex()
        finally:
            os.close(descriptor)
        self.assertEqual(parsed.sha256, expected)

    def test_bounded_raw_patch_reader_revalidates_the_record(self) -> None:
        request = self.build_request(cumulative_patch="frozen patch\n")
        self.assertEqual(
            bundle.read_raw_section(self.request, request, "cumulative_patch"), b"frozen patch\n"
        )
        with self.assertRaisesRegex(bundle.BundleError, "only cumulative_patch"):
            bundle.read_raw_section(self.request, request, "source_capsule")
        result = self.build_result()
        self.assertEqual(
            bundle.read_raw_section(
                self.scratch,
                result,
                "canonical_patch",
                scratch_size=bundle.MIN_SCRATCH_BYTES,
                tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
            ),
            b"diff --git a/a b/a\n",
        )
        record = self._records(self.request)[0]
        self._write_at(self.request, record[1], b"x", 0o400)
        with self.assertRaisesRegex(bundle.BundleError, "SHA-256"):
            bundle.read_raw_section(self.request, request, "cumulative_patch")

    def test_tail_rejects_nonzero_gap_bad_utf8_and_bad_footer(self) -> None:
        self.build_result()
        footer_offset = bundle.MIN_SCRATCH_BYTES - bundle.HEADER_BYTES
        region_start = bundle.MIN_SCRATCH_BYTES - bundle.MIN_RESULT_TAIL_BYTES
        records = self._records(self.scratch, footer_offset)
        gaps = bundle._gaps(region_start, footer_offset, records)
        self.assertTrue(gaps)
        self._write_at(self.scratch, gaps[-1][0], b"x", 0o600)
        with self.assertRaisesRegex(bundle.BundleError, "nonzero"):
            bundle.extract_tail_result(
                self.scratch,
                scratch_size=bundle.MIN_SCRATCH_BYTES,
                tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
                **self.binding,
            )

        self.scratch.unlink()
        with self.assertRaisesRegex(bundle.BundleError, "UTF-8"):
            self.build_result(patch="\udcff")
        self.assertFalse(self.scratch.exists())

        self.build_result()
        self._write_at(self.scratch, footer_offset + bundle._TABLE_END, b"x", 0o600)
        with self.assertRaisesRegex(bundle.BundleError, "reserved"):
            bundle.extract_tail_result(
                self.scratch,
                scratch_size=bundle.MIN_SCRATCH_BYTES,
                tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
                **self.binding,
            )

    def test_guest_result_binds_receipt_actions_patch_and_observation_cap(self) -> None:
        request = self.semantic_request()
        result = bundle.build_tail_result(
            self.scratch,
            scratch_size=bundle.MIN_SCRATCH_BYTES,
            tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
            run_id=request.binding.run_id,
            round=request.binding.round,
            stage="implementation",
            sections=self.semantic_result_sections(request),
        )
        verified = bundle.validate_guest_result(
            result,
            request,
            guest_policy_sha256="b" * 64,
            max_observation_bytes=1024,
        )
        self.assertEqual(verified.status, "complete")
        self.assertEqual(
            verified.canonical_patch_sha256, request.raw_sections["proposed_patch"].sha256
        )
        self.assertEqual(verified.action_ids, ("patch", "finish"))

        hostile = self.semantic_result_sections(request)
        hostile["guest_receipt"] = copy.deepcopy(hostile["guest_receipt"])
        hostile["guest_receipt"]["isolation"]["network"] = "loopback"  # type: ignore[index]
        hostile_result = bundle.build_tail_result(
            self.root / "hostile.raw",
            scratch_size=bundle.MIN_SCRATCH_BYTES,
            tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
            run_id=request.binding.run_id,
            round=request.binding.round,
            stage="implementation",
            sections=hostile,
        )
        with self.assertRaisesRegex(bundle.BundleError, "fixed strict profile"):
            bundle.validate_guest_result(
                hostile_result,
                request,
                guest_policy_sha256="b" * 64,
                max_observation_bytes=1024,
            )
        with self.assertRaisesRegex(bundle.BundleError, "observation byte cap"):
            bundle.validate_guest_result(
                result,
                request,
                guest_policy_sha256="b" * 64,
                max_observation_bytes=1,
            )

    def test_guest_result_rejects_patch_mismatch_duplicate_action_ids_and_failed_final_check(
        self,
    ) -> None:
        request = self.semantic_request()
        hostile = self.semantic_result_sections(request)
        hostile["stage_result"] = copy.deepcopy(hostile["stage_result"])
        hostile["stage_result"]["cumulative_patch_sha256"] = "0" * 64  # type: ignore[index]
        result = bundle.build_tail_result(
            self.scratch,
            scratch_size=bundle.MIN_SCRATCH_BYTES,
            tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
            run_id=request.binding.run_id,
            round=request.binding.round,
            stage="implementation",
            sections=hostile,
        )
        with self.assertRaisesRegex(bundle.BundleError, "cumulative patch digest"):
            bundle.validate_guest_result(
                result,
                request,
                guest_policy_sha256="b" * 64,
                max_observation_bytes=1024,
            )

        self.request.unlink()
        final_request = self.semantic_request(stage="final_verify", checks=["pytest_unit"])
        final_sections = self.semantic_result_sections(final_request, stage="final_verify")
        final_sections["checks"] = copy.deepcopy(final_sections["checks"])
        final_sections["checks"][0]["truncated"] = True  # type: ignore[index]
        final = bundle.build_tail_result(
            self.root / "final.raw",
            scratch_size=bundle.MIN_SCRATCH_BYTES,
            tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
            run_id=final_request.binding.run_id,
            round=final_request.binding.round,
            stage="final_verify",
            sections=final_sections,
        )
        with self.assertRaisesRegex(bundle.BundleError, "every curated check"):
            bundle.validate_guest_result(
                final,
                final_request,
                guest_policy_sha256="b" * 64,
                max_observation_bytes=1024,
            )

    def test_read_only_and_final_verify_stages_cannot_return_model_patches(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "read-only"):
            self.build_result(stage="planning")
        with self.assertRaisesRegex(bundle.BundleError, "read-only"):
            self.build_result(stage="review")
        final = self.build_result(stage="final_verify", patch="")
        self.assertEqual(final.raw_sections["canonical_patch"].length, 0)

        final_request = self.root / "final.lfrq"
        final_policy = {
            "schema_version": 1,
            "provider": "fixture",
            "model": "terra-fixture",
            "reasoning_effort": "high",
            "allowed_check_ids": ["pytest_unit"],
            "max_actions": 8,
        }
        final_actions = self.action_batch(
            "final_verify",
            [
                {"id": "check", "type": "run_check", "check_id": "pytest_unit"},
                self.finish_action(),
            ],
        )
        with self.assertRaisesRegex(bundle.BundleError, "frozen cumulative_patch"):
            bundle.build_request_bundle(
                final_request,
                sections=self.request_sections(
                    policy=final_policy,
                    action_batch=final_actions,
                ),
                fixture_authorization=True,
                **{**self.binding, "stage": "final_verify"},
            )
        with self.assertRaisesRegex(bundle.BundleError, "strict mediated action grammar"):
            bundle.build_request_bundle(
                final_request,
                sections=self.request_sections(
                    cumulative_patch="frozen patch\n",
                    policy=final_policy,
                    action_batch=self.action_batch(
                        "final_verify",
                        [
                            {"id": "check", "type": "run_check", "check_id": "pytest -q"},
                            self.finish_action(),
                        ],
                    ),
                ),
                fixture_authorization=True,
                **{**self.binding, "stage": "final_verify"},
            )
        bundle.build_request_bundle(
            final_request,
            sections=self.request_sections(
                cumulative_patch="frozen patch\n",
                policy=final_policy,
                action_batch=final_actions,
            ),
            fixture_authorization=True,
            **{**self.binding, "stage": "final_verify"},
        )

    def test_tail_validates_exact_sizes_and_links(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "bounds"):
            bundle.build_tail_result(
                self.scratch,
                scratch_size=bundle.MIN_SCRATCH_BYTES - bundle.ALIGNMENT,
                tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
                sections=self.result_sections(),
                **self.binding,
            )
        self.build_result()
        linked = self.root / "scratch-link"
        os.link(self.scratch, linked)
        with self.assertRaisesRegex(bundle.BundleError, "links"):
            bundle.extract_tail_result(
                self.scratch,
                scratch_size=bundle.MIN_SCRATCH_BYTES,
                tail_region_bytes=bundle.MIN_RESULT_TAIL_BYTES,
                **self.binding,
            )


if __name__ == "__main__":
    unittest.main()
