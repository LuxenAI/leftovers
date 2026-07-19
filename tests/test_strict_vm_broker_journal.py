from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import leftovers.vm_bundle as bundle
from leftovers.strict_vm_broker import (
    ALLOCATION_TTL_NS,
    BrokerAuthorizationError,
    BrokerInstallation,
    BrokerPeer,
    ImmutableBootIdentity,
)
from leftovers.strict_vm_broker_journal import (
    LFRQ_HEADER_BYTES,
    MAX_SLOT_RECORDS,
    BrokerBootSessionEvidence,
    BrokerJournalAnchor,
    BrokerJournalError,
    BrokerJournalRollbackError,
    BrokerJournalSlot,
    BrokerLFRQAdmissionBinding,
    BrokerPrivateRootContract,
    BrokerUnavailableError,
    DurableBrokerJournal,
    _slot_sha256,
    inspect_complete_lfrq_admission_contract,
    journal_genesis_sha256,
    observe_unverified_lfrq_header,
)


class _Sink:
    def __init__(self) -> None:
        self.slots: list[object | None] = [None, None]
        self.fail_before_write = False
        self.fail_after_write = False

    def read_slots(self) -> tuple[object | None, object | None]:
        return tuple(self.slots)  # type: ignore[return-value]

    def write_slot_fsynced(self, slot_index: int, slot: BrokerJournalSlot) -> None:
        if self.fail_before_write:
            raise OSError("simulated disk-full failure before slot durability")
        self.slots[slot_index] = slot
        if self.fail_after_write:
            raise OSError("simulated sync failure after slot durability")


class _Reader:
    def __init__(self, raw: bytes, *, safe: bool = True) -> None:
        self.raw = raw
        self.size = len(raw)
        self.opened_relative_to_private_root = safe
        self.opened_nofollow = safe
        self.identity_verified = safe

    def pread_exact(self, size: int, offset: int) -> bytes:
        return self.raw[offset : offset + size]


class _RetainedRequest:
    def __init__(self, descriptor: int, identity: bundle.DescriptorRequestIdentity) -> None:
        self.descriptor = descriptor
        self.identity = identity
        self.opened_relative_to_private_root = True
        self.opened_nofollow = True


class BrokerJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.controller_uid = os.getuid() + 1
        self.installation = BrokerInstallation(
            service_root=root / "broker",
            launcher_path=root / "launcher",
            controller_uid=self.controller_uid,
            broker_uid=os.getuid(),
            boot_identity=ImmutableBootIdentity(*(["a" * 64] * 5)),
        )
        self.sink = _Sink()
        self.peer = BrokerPeer(self.controller_uid, 20)
        self.boot_session = BrokerBootSessionEvidence("b" * 64)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _request_id(value: str = "1") -> str:
        return value * 32

    def _uploaded_journal(self) -> tuple[DurableBrokerJournal, str, str]:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        request = b"LFRQ staged bytes"
        journal.append_chunk(
            allocation.allocation_id,
            allocation.lease_token,
            self.peer,
            request,
            sequence=0,
            now_ns=101,
        )
        digest = hashlib.sha256(request).hexdigest()
        return journal, allocation.allocation_id, digest

    def _create(
        self,
        sink: _Sink | None = None,
        boot_session: BrokerBootSessionEvidence | None = None,
    ) -> DurableBrokerJournal:
        return DurableBrokerJournal.create(
            self.installation,
            self.sink if sink is None else sink,
            boot_session=self.boot_session if boot_session is None else boot_session,
        )

    def _recover(
        self,
        sink: _Sink | None = None,
        boot_session: BrokerBootSessionEvidence | None = None,
        now_ns: int = 102,
    ) -> DurableBrokerJournal:
        return DurableBrokerJournal.recover(
            self.installation,
            self.sink if sink is None else sink,
            boot_session=self.boot_session if boot_session is None else boot_session,
            now_ns=now_ns,
        )

    def test_genesis_binds_immutable_installation_and_boot_identity(self) -> None:
        journal = self._create()
        slot = journal.slot_snapshot
        genesis = json.loads(slot.records[0])
        self.assertEqual(genesis["kind"], "genesis")
        self.assertEqual(
            genesis["body"]["installation_sha256"], journal_genesis_sha256(self.installation)
        )
        self.assertEqual(slot.anchor.record_count, 1)
        self.assertEqual(slot.anchor.head_sha256, journal.head_sha256)
        self.assertEqual(self.sink.slots[0], slot)
        self.assertIsNone(self.sink.slots[1])
        self.assertFalse(hasattr(BrokerPrivateRootContract(502), "path"))

    def test_fsync_failure_never_updates_memory_authority(self) -> None:
        journal = self._create()
        before = journal.slot_snapshot
        self.sink.fail_before_write = True
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id(), 1)
        self.assertEqual(journal.allocations, {})
        self.assertEqual(len(journal.records), 1)
        self.assertEqual(journal.slot_snapshot, before)
        self.assertTrue(journal.recovery_required)
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id("2"), 2)

    def test_recovery_quarantines_upload_and_keeps_replay_guard(self) -> None:
        journal, allocation_id, _ = self._uploaded_journal()
        recovered = self._recover()
        self.assertEqual(recovered.allocations[allocation_id].state, "quarantined")
        self.assertEqual(recovered.reserved_tokens, 0)
        with self.assertRaises(BrokerJournalError):
            recovered.allocate(self.peer, self._request_id(), 102)
        self.assertGreater(recovered.anchor.record_count, journal.anchor.record_count)

    def test_restart_quarantines_incomplete_upload_and_preserves_replay_guard(self) -> None:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        journal.append_chunk(
            allocation.allocation_id,
            allocation.lease_token,
            self.peer,
            b"partial",
            sequence=0,
            now_ns=101,
        )
        recovered = self._recover()
        self.assertEqual(recovered.allocations[allocation.allocation_id].state, "quarantined")
        with self.assertRaises(BrokerJournalError):
            recovered.append_chunk(
                allocation.allocation_id,
                allocation.lease_token,
                self.peer,
                b"more",
                sequence=1,
                now_ns=102,
            )
        self.assertGreater(len(recovered.records), len(journal.records))

    def test_torn_record_rollback_and_installation_substitution_fail_closed(self) -> None:
        journal, _, _ = self._uploaded_journal()
        slot = journal.slot_snapshot
        # A malformed inactive peer does not wedge a valid active prefix.
        self.sink.slots[1] = object()
        recovered = self._recover()
        self.assertEqual(len(recovered.records), len(journal.records) + 1)
        self.assertTrue(all(item.state != "uploading" for item in recovered.allocations.values()))
        # If the only complete image is torn, recovery must fail closed.
        self.sink.slots = [replace(slot, records=slot.records[:-1]), None]
        with self.assertRaises(BrokerJournalError):
            self._recover()
        wrong_installation = BrokerInstallation(
            service_root=self.installation.service_root,
            launcher_path=self.installation.launcher_path,
            controller_uid=self.controller_uid,
            broker_uid=os.getuid() + 2,
            boot_identity=ImmutableBootIdentity(*(["b" * 64] * 5)),
        )
        with self.assertRaises(BrokerJournalRollbackError):
            DurableBrokerJournal.recover(
                wrong_installation, self.sink, boot_session=self.boot_session, now_ns=102
            )

    def test_recovery_persists_monotonic_floor_and_staging_authority_is_absent(self) -> None:
        journal, allocation_id, _ = self._uploaded_journal()
        with self.assertRaises(BrokerJournalRollbackError):
            journal.allocate(self.peer, self._request_id("2"), 1)
        recovered = self._recover()
        with self.assertRaises(BrokerJournalRollbackError):
            recovered.allocate(self.peer, self._request_id("2"), 1)
        self.assertFalse(hasattr(journal, "stage"))
        self.assertEqual(journal.allocations[allocation_id].state, "uploading")

    def test_invalid_semantic_requests_never_mutate_sink_or_anchor(self) -> None:
        journal = self._create()
        before = (tuple(self.sink.slots), journal.anchor, tuple(journal.snapshot()))
        with self.assertRaises(BrokerJournalError):
            journal.reserve_tokens("not-an-allocation", "0" * 64, "f" * 64, 1)
        with self.assertRaises(BrokerJournalError):
            journal.settle_tokens("f" * 64)
        with self.assertRaises(BrokerJournalError):
            journal.quarantine("f" * 32, reason="not-a-reason")
        self.assertEqual(
            before, (tuple(self.sink.slots), journal.anchor, tuple(journal.snapshot()))
        )

    def test_after_durability_sync_error_requires_recovery_and_allocation_replay_is_exact(
        self,
    ) -> None:
        journal = self._create()
        self.sink.fail_after_write = True
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id(), 100)
        self.assertTrue(journal.recovery_required)
        self.assertEqual(len(journal.records), 1)
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id(), 101)

        self.sink.fail_after_write = False
        recovered = self._recover()
        replay = recovered.allocate(self.peer, self._request_id(), 100)
        self.assertEqual(len(recovered.records), 2)
        self.assertEqual(replay, recovered.allocations[replay.allocation_id].allocation)
        with self.assertRaises(BrokerAuthorizationError):
            recovered.allocate(BrokerPeer(self.controller_uid, 21), self._request_id(), 102)

    def test_same_boot_only_replays_an_unuploaded_unexpired_allocation(self) -> None:
        journal = self._create()
        untouched = journal.allocate(self.peer, self._request_id(), 100)
        recovered = self._recover(now_ns=101)
        self.assertEqual(recovered.allocate(self.peer, self._request_id(), 101), untouched)

        with self.assertRaises(BrokerJournalError):
            recovered.allocate(self.peer, self._request_id(), untouched.expires_at_ns + 1)
        recovered.append_chunk(
            untouched.allocation_id,
            untouched.lease_token,
            self.peer,
            b"partial",
            sequence=0,
            now_ns=101,
        )
        recovered = self._recover(now_ns=102)
        with self.assertRaises(BrokerJournalError):
            recovered.allocate(self.peer, self._request_id(), 102)

    def test_boot_rollover_quarantines_pending_work_and_resets_monotonic_epoch(self) -> None:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        request = b"staged request"
        journal.append_chunk(
            allocation.allocation_id,
            allocation.lease_token,
            self.peer,
            request,
            sequence=0,
            now_ns=101,
        )
        request_sha256 = hashlib.sha256(request).hexdigest()
        journal._append(  # noqa: SLF001 - synthetic durable staged state
            "staged",
            {
                "allocation_id": allocation.allocation_id,
                "request_sha256": request_sha256,
                "total_bytes": len(request),
            },
        )
        reservation_id = "e" * 64
        journal.reserve_tokens(allocation.allocation_id, request_sha256, reservation_id, 2)

        next_boot = BrokerBootSessionEvidence("c" * 64)
        recovered = self._recover(boot_session=next_boot, now_ns=0)
        self.assertEqual(recovered.boot_session_sha256, next_boot.sha256)
        self.assertEqual(recovered.allocations[allocation.allocation_id].state, "quarantined")
        self.assertEqual(recovered.reservations[reservation_id].state, "reserved")
        with self.assertRaises(BrokerJournalError):
            recovered.allocate(self.peer, self._request_id(), 0)
        fresh = recovered.allocate(self.peer, self._request_id("2"), 0)
        self.assertEqual(fresh.expires_at_ns, ALLOCATION_TTL_NS)

    def test_slot_type_gaps_and_oversize_history_fail_without_attribute_errors(self) -> None:
        journal = self._create()
        slot = journal.slot_snapshot
        malformed = BrokerJournalSlot(0, slot.records, object(), "0" * 64)  # type: ignore[arg-type]
        self.sink.slots = [malformed, None]
        with self.assertRaises(BrokerJournalError):
            self._recover()

        skipped = replace(
            slot,
            generation=2,
            slot_sha256=_slot_sha256(2, slot.records, slot.anchor),
        )
        self.sink.slots = [slot, skipped]
        with self.assertRaises(BrokerJournalRollbackError):
            self._recover()

        with self.assertRaises(BrokerJournalError):
            _slot_sha256(
                0,
                (b"x",) * (MAX_SLOT_RECORDS + 1),
                BrokerJournalAnchor(1, "0" * 64, journal_genesis_sha256(self.installation)),
            )

    def test_two_slot_recovery_accepts_one_valid_prefix_for_torn_and_crossed_images(self) -> None:
        journal = self._create()
        genesis = journal.slot_snapshot
        journal.allocate(self.peer, self._request_id(), 100)
        newer = journal.slot_snapshot

        # A journal-ahead slot has newer records with an older embedded witness.
        journal_ahead = replace(
            newer,
            anchor=genesis.anchor,
            slot_sha256=_slot_sha256(newer.generation, newer.records, genesis.anchor),
        )
        self.sink.slots = [genesis, journal_ahead]
        recovered = self._recover()
        self.assertEqual(recovered.head_sha256, genesis.anchor.head_sha256)

        # A witness-ahead slot has an old journal with a newer embedded witness.
        witness_ahead = replace(
            genesis,
            anchor=newer.anchor,
            slot_sha256=_slot_sha256(genesis.generation, genesis.records, newer.anchor),
        )
        self.sink.slots = [witness_ahead, newer]
        recovered = self._recover()
        self.assertEqual(len(recovered.records), len(newer.records))
        self.assertTrue(any(item.state == "uploading" for item in recovered.allocations.values()))

        # Corruption in the inactive slot likewise leaves the valid prefix usable.
        self.sink.slots = [newer, replace(genesis, slot_sha256="0" * 64)]
        recovered = self._recover()
        self.assertEqual(len(recovered.records), len(newer.records))
        self.assertTrue(any(item.state == "uploading" for item in recovered.allocations.values()))

    def test_two_valid_slots_at_one_generation_with_different_contents_fail_closed(self) -> None:
        journal = self._create()
        journal.allocate(self.peer, self._request_id(), 100)
        slot = journal.slot_snapshot
        other_sink = _Sink()
        other = self._create(other_sink)
        other.allocate(self.peer, self._request_id("2"), 100)
        conflicting = other.slot_snapshot
        self.assertEqual(slot.generation, conflicting.generation)
        self.assertNotEqual(slot.slot_sha256, conflicting.slot_sha256)
        self.sink.slots = [slot, conflicting]
        with self.assertRaises(BrokerJournalRollbackError):
            self._recover()

    def test_no_complete_slot_fails_closed_without_erasing_torn_storage(self) -> None:
        torn = object()
        self.sink.slots = [torn, None]
        with self.assertRaises(BrokerJournalRollbackError):
            self._recover()
        with self.assertRaises(BrokerJournalError):
            self._create()
        self.assertIs(self.sink.slots[0], torn)

    def test_crash_before_atomic_commit_leaves_no_ambiguous_suffix(self) -> None:
        journal = self._create()
        before = (tuple(self.sink.slots), journal.slot_snapshot, tuple(journal.snapshot()))
        self.sink.fail_before_write = True
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id(), 100)
        self.assertEqual(
            before, (tuple(self.sink.slots), journal.slot_snapshot, tuple(journal.snapshot()))
        )

    def test_deep_journal_json_is_a_strict_error_not_recursion_crash(self) -> None:
        depth = 2_000
        raw = b'{"body":' + b"[" * depth + b"0" + b"]" * depth + b"}"
        with self.assertRaises(BrokerJournalError):
            self.sink.slots = [
                BrokerJournalSlot(
                    0,
                    (raw,),
                    BrokerJournalAnchor(1, "0" * 64, journal_genesis_sha256(self.installation)),
                    "0" * 64,
                ),
                None,
            ]
            self._recover()

    def test_staged_lfrq_requires_descriptor_proof_binds_run_and_rejects_broker_authority(
        self,
    ) -> None:
        journal, allocation_id, _ = self._uploaded_journal()
        allocation = journal.allocations[allocation_id]
        broker = self._lfrq(allocation.allocation.run_id, authority="broker")
        with self.assertRaises(BrokerUnavailableError):
            observe_unverified_lfrq_header(_Reader(broker), allocation)
        fixture = self._lfrq(allocation.allocation.run_id, authority="fixture")
        observation = observe_unverified_lfrq_header(_Reader(fixture), allocation)
        self.assertEqual(observation.run_id, allocation.allocation.run_id)
        self.assertEqual(observation.unverified_mediation_authority, "fixture")
        with self.assertRaises(BrokerUnavailableError):
            observe_unverified_lfrq_header(_Reader(fixture, safe=False), allocation)
        with self.assertRaises(BrokerAuthorizationError):
            observe_unverified_lfrq_header(
                _Reader(self._lfrq("f" * 32, authority="fixture")), allocation
            )

    def test_validate_and_stage_cannot_bypass_lfrq_attestation_gate(self) -> None:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        with self.assertRaises(BrokerUnavailableError):
            journal.validate_and_stage_lfrq(
                allocation.allocation_id,
                _Reader(self._lfrq(allocation.run_id, authority="fixture")),
            )
        self.assertEqual(journal.allocations[allocation.allocation_id].state, "uploading")

    def test_complete_descriptor_contract_binds_all_semantics_and_reservation(self) -> None:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        request_path, sections = self._broker_shaped_lfrq(allocation.run_id)
        raw = request_path.read_bytes()
        journal.append_chunk(
            allocation.allocation_id,
            allocation.lease_token,
            self.peer,
            raw,
            sequence=0,
            now_ns=101,
        )
        request_sha256 = hashlib.sha256(raw).hexdigest()
        # Only a future attested service may write this event after complete
        # parsing; the pure contract below verifies that its durable state is
        # already exact before any launcher plan could be considered.
        journal._append(  # noqa: SLF001 - explicit synthetic durable state
            "staged",
            {
                "allocation_id": allocation.allocation_id,
                "request_sha256": request_sha256,
                "total_bytes": len(raw),
            },
        )
        reservation_id = "e" * 64
        journal.reserve_tokens(allocation.allocation_id, request_sha256, reservation_id, 2)
        descriptor = os.open(request_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            identity = bundle.capture_request_descriptor_identity(
                descriptor, expected_uid=os.getuid()
            )
            retained = _RetainedRequest(descriptor, identity)
            binding = self._admission_binding(sections, reservation_id, allocation.run_id)
            parsed = inspect_complete_lfrq_admission_contract(
                journal,
                allocation.allocation_id,
                retained,
                binding=binding,
                **self._inspection_context(),
            )
            self.assertEqual(parsed.binding.run_id, allocation.run_id)

            with self.assertRaises(BrokerAuthorizationError):
                inspect_complete_lfrq_admission_contract(
                    journal,
                    allocation.allocation_id,
                    retained,
                    binding=replace(binding, reservation_tokens=1),
                    **self._inspection_context(),
                )
            reserved = journal.reservations[reservation_id]
            journal.reservations[reservation_id] = replace(reserved, tokens=1)
            try:
                with self.assertRaisesRegex(BrokerAuthorizationError, "usage or caps"):
                    inspect_complete_lfrq_admission_contract(
                        journal,
                        allocation.allocation_id,
                        retained,
                        binding=replace(binding, reservation_tokens=1),
                        **self._inspection_context(),
                    )
            finally:
                journal.reservations[reservation_id] = reserved
            with self.assertRaises(BrokerAuthorizationError):
                inspect_complete_lfrq_admission_contract(
                    journal,
                    allocation.allocation_id,
                    retained,
                    binding=binding,
                    **self._inspection_context(now_ns=allocation.expires_at_ns + 1),
                )
            with self.assertRaises(BrokerAuthorizationError):
                inspect_complete_lfrq_admission_contract(
                    journal,
                    allocation.allocation_id,
                    retained,
                    binding=binding,
                    observed_monotonic_ns=102,
                    boot_session=BrokerBootSessionEvidence("c" * 64),
                )

            wrong_base = BrokerLFRQAdmissionBinding(**{**binding.__dict__, "base_sha": "b" * 40})
            with self.assertRaises(BrokerAuthorizationError):
                inspect_complete_lfrq_admission_contract(
                    journal,
                    allocation.allocation_id,
                    retained,
                    binding=wrong_base,
                    **self._inspection_context(),
                )
            journal.settle_tokens(reservation_id)
            with self.assertRaises(BrokerAuthorizationError):
                inspect_complete_lfrq_admission_contract(
                    journal,
                    allocation.allocation_id,
                    retained,
                    binding=binding,
                    **self._inspection_context(),
                )
        finally:
            os.close(descriptor)

    def test_descriptor_parser_checks_original_fd_type_and_inheritability(self) -> None:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        request_path, _sections = self._broker_shaped_lfrq(allocation.run_id)
        descriptor = os.open(request_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            identity = bundle.capture_request_descriptor_identity(
                descriptor, expected_uid=os.getuid()
            )
            os.set_inheritable(descriptor, True)
            with self.assertRaisesRegex(bundle.BundleError, "original request descriptor"):
                bundle.parse_request_bundle_descriptor(
                    descriptor,
                    identity=identity,
                    expected_uid=os.getuid(),
                    run_id=allocation.run_id,
                    round=7,
                    stage="implementation",
                )
            os.set_inheritable(descriptor, False)
            forged = replace(identity, ino=identity.ino + 1)
            with self.assertRaisesRegex(bundle.BundleError, "identity changed"):
                bundle.parse_request_bundle_descriptor(
                    descriptor,
                    identity=forged,
                    expected_uid=os.getuid(),
                    run_id=allocation.run_id,
                    round=7,
                    stage="implementation",
                )
        finally:
            os.close(descriptor)
        fifo = Path(self.temporary.name) / "request.fifo"
        os.mkfifo(fifo, 0o600)
        descriptor = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(bundle.BundleError, "identity, mode, or size"):
                bundle.capture_request_descriptor_identity(descriptor, expected_uid=os.getuid())
        finally:
            os.close(descriptor)

    def test_descriptor_contract_rejects_fixture_tampering_and_replacement(self) -> None:
        journal = self._create()
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        request_path, sections = self._broker_shaped_lfrq(allocation.run_id)
        raw = request_path.read_bytes()
        journal.append_chunk(
            allocation.allocation_id,
            allocation.lease_token,
            self.peer,
            raw,
            sequence=0,
            now_ns=101,
        )
        request_sha256 = hashlib.sha256(raw).hexdigest()
        journal._append(  # noqa: SLF001 - explicit synthetic durable state
            "staged",
            {
                "allocation_id": allocation.allocation_id,
                "request_sha256": request_sha256,
                "total_bytes": len(raw),
            },
        )
        reservation_id = "e" * 64
        journal.reserve_tokens(allocation.allocation_id, request_sha256, reservation_id, 2)
        descriptor = os.open(request_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            identity = bundle.capture_request_descriptor_identity(
                descriptor, expected_uid=os.getuid()
            )
            retained = _RetainedRequest(descriptor, identity)
            binding = self._admission_binding(sections, reservation_id, allocation.run_id)
            os.chmod(request_path, 0o600)
            with request_path.open("r+b") as changed:
                changed.truncate(0)
            with self.assertRaises(BrokerJournalError):
                inspect_complete_lfrq_admission_contract(
                    journal,
                    allocation.allocation_id,
                    retained,
                    binding=binding,
                    **self._inspection_context(),
                )
        finally:
            os.close(descriptor)

        fixture_path = request_path.with_name("fixture.lfrq")
        fixture_journal = self._create(_Sink())
        fixture_allocation = fixture_journal.allocate(self.peer, self._request_id("2"), 200)
        fixture_sections = dict(sections)
        fixture_sections["action_batch"] = dict(sections["action_batch"])
        fixture_sections["action_batch"]["run_id"] = fixture_allocation.run_id
        fixture_sections["mediation"] = dict(sections["mediation"])
        fixture_sections["mediation"]["run_id"] = fixture_allocation.run_id
        fixture_sections["mediation"]["action_batch_sha256"] = self._sha(
            fixture_sections["action_batch"], bundle.REQUEST_JSON_CAPS["action_batch"]
        )
        fixture_sections["mediation"]["authority"] = "fixture"
        fixture_sections["mediation"]["usage_source"] = "fixture"
        fixture_sections["mediation"]["provider_usage_evidence_sha256"] = (
            bundle.FIXTURE_USAGE_EVIDENCE_SHA256
        )
        bundle.build_request_bundle(
            fixture_path,
            run_id=fixture_allocation.run_id,
            round=7,
            stage="implementation",
            sections=fixture_sections,
            fixture_capability=bundle.fixture_vm_bundle_capability(),
        )
        fixture_raw = fixture_path.read_bytes()
        fixture_journal.append_chunk(
            fixture_allocation.allocation_id,
            fixture_allocation.lease_token,
            self.peer,
            fixture_raw,
            sequence=0,
            now_ns=201,
        )
        fixture_sha256 = hashlib.sha256(fixture_raw).hexdigest()
        fixture_journal._append(  # noqa: SLF001 - explicit synthetic durable state
            "staged",
            {
                "allocation_id": fixture_allocation.allocation_id,
                "request_sha256": fixture_sha256,
                "total_bytes": len(fixture_raw),
            },
        )
        fixture_journal.reserve_tokens(
            fixture_allocation.allocation_id, fixture_sha256, reservation_id, 2
        )
        descriptor = os.open(fixture_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            retained = _RetainedRequest(
                descriptor,
                bundle.capture_request_descriptor_identity(descriptor, expected_uid=os.getuid()),
            )
            with self.assertRaises(BrokerJournalError):
                inspect_complete_lfrq_admission_contract(
                    fixture_journal,
                    fixture_allocation.allocation_id,
                    retained,
                    binding=self._admission_binding(
                        sections, reservation_id, fixture_allocation.run_id
                    ),
                    **self._inspection_context(now_ns=202),
                )
        finally:
            os.close(descriptor)

    def _broker_shaped_lfrq(self, run_id: str) -> tuple[Path, dict[str, object]]:
        source = Path(self.temporary.name) / "source.tar"
        source.write_bytes(b"sealed source")
        os.chmod(source, 0o600)
        policy = {
            "schema_version": 1,
            "provider": "openai-codex-cli",
            "model": "gpt-5.6-terra",
            "reasoning_effort": "high",
            "allowed_check_ids": [],
            "max_actions": 1,
        }
        action_batch = {
            "schema_version": 1,
            "run_id": run_id,
            "round": 7,
            "stage": "implementation",
            "provider": policy["provider"],
            "model": policy["model"],
            "reasoning_effort": policy["reasoning_effort"],
            "actions": [
                {
                    "id": "finish",
                    "type": "finish",
                    "status": "complete",
                    "summary": "bounded",
                }
            ],
        }
        registry = {"schema_version": 1, "checks": []}
        sections: dict[str, object] = {
            "manifest": {"schema_version": 1, "request": "strict"},
            "source_capsule": source,
            "task": {
                "trusted": {
                    "target": {
                        "repository": "owner/repository",
                        "issue_number": 42,
                        "base_sha": "a" * 40,
                    }
                },
                "untrusted": {},
            },
            "policy": policy,
            "check_registry": registry,
            "action_batch": action_batch,
        }
        mediation = {
            "schema_version": 1,
            "run_id": run_id,
            "round": 7,
            "stage": "implementation",
            "provider": policy["provider"],
            "model": policy["model"],
            "reasoning_effort": policy["reasoning_effort"],
            "input_sha256": "c" * 64,
            "action_batch_sha256": self._sha(
                action_batch, bundle.REQUEST_JSON_CAPS["action_batch"]
            ),
            "patch_sha256": None,
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
            "max_actions": 1,
            "input_token_cap": 1,
            "output_token_cap": 1,
            "total_token_cap": 2,
            "call_index": 1,
            "call_cap": 1,
            "deadline_at": "2030-01-01T00:00:00.000000Z",
            "started_at": "2029-01-01T00:00:00.000000Z",
            "finished_at": "2029-01-01T00:00:01.000000Z",
            "authority": "fixture",
            "policy_sha256": self._sha(policy, bundle.REQUEST_JSON_CAPS["policy"]),
            "check_registry_sha256": self._sha(
                registry, bundle.REQUEST_JSON_CAPS["check_registry"]
            ),
            "token_ledger_reservation_id": "e" * 64,
            "provider_usage_evidence_sha256": bundle.FIXTURE_USAGE_EVIDENCE_SHA256,
        }
        sections["mediation"] = mediation
        request = Path(self.temporary.name) / "request.lfrq"
        bundle.build_request_bundle(
            request,
            run_id=run_id,
            round=7,
            stage="implementation",
            sections=sections,
            fixture_capability=bundle.fixture_vm_bundle_capability(),
        )
        raw = bytearray(request.read_bytes())
        parsed = bundle.parse_request_bundle(
            request,
            run_id=run_id,
            round=7,
            stage="implementation",
            fixture_capability=bundle.fixture_vm_bundle_capability(),
        )
        records, _payload, _marker = bundle._parse_header(
            bytes(raw[: bundle.HEADER_BYTES]),
            magic=bundle.REQUEST_MAGIC,
            total_size=len(raw),
            expected=parsed.binding,
            allowed_types=bundle.REQUEST_SECTION_TYPES,
            required_types=bundle.REQUIRED_REQUEST_SECTION_TYPES,
            caps={**bundle.REQUEST_JSON_CAPS, **bundle.REQUEST_RAW_CAPS},
            payload_start=bundle.HEADER_BYTES,
            payload_end=len(raw),
            require_marker=False,
        )
        updated_records = []
        for name, offset, length, digest in records:
            if name == "mediation":
                broker_mediation = dict(mediation)
                broker_mediation["authority"] = "broker"
                broker_mediation["usage_source"] = "provider"
                encoded = bundle._canonical_json(
                    broker_mediation, bundle.REQUEST_JSON_CAPS["mediation"]
                )
                self.assertEqual(len(encoded), length)
                raw[offset : offset + length] = encoded
                digest = hashlib.sha256(encoded).digest()
                sections["mediation"] = broker_mediation
            updated_records.append((name, offset, length, digest))
        payload_digest = hashlib.sha256(raw[bundle.HEADER_BYTES :]).digest()
        raw[: bundle.HEADER_BYTES] = bundle._pack_header(
            bundle.REQUEST_MAGIC,
            parsed.binding,
            len(raw),
            payload_digest,
            updated_records,
            b"\0" * 32,
        )
        os.chmod(request, 0o600)
        request.write_bytes(raw)
        os.chmod(request, 0o400)
        return request, sections

    @staticmethod
    def _sha(value: object, maximum: int) -> str:
        return hashlib.sha256(bundle._canonical_json(value, maximum)).hexdigest()

    def _admission_binding(
        self, sections: dict[str, object], reservation_id: str, run_id: str
    ) -> BrokerLFRQAdmissionBinding:
        return BrokerLFRQAdmissionBinding(
            run_id=run_id,
            round=7,
            stage="implementation",
            repository="owner/repository",
            issue_number=42,
            base_sha="a" * 40,
            manifest_sha256=self._sha(sections["manifest"], bundle.REQUEST_JSON_CAPS["manifest"]),
            task_sha256=self._sha(sections["task"], bundle.REQUEST_JSON_CAPS["task"]),
            policy_sha256=self._sha(sections["policy"], bundle.REQUEST_JSON_CAPS["policy"]),
            check_registry_sha256=self._sha(
                sections["check_registry"], bundle.REQUEST_JSON_CAPS["check_registry"]
            ),
            action_batch_sha256=self._sha(
                sections["action_batch"], bundle.REQUEST_JSON_CAPS["action_batch"]
            ),
            mediation_receipt_sha256=self._sha(
                sections["mediation"], bundle.REQUEST_JSON_CAPS["mediation"]
            ),
            proposed_patch_sha256=None,
            reservation_id=reservation_id,
            reservation_tokens=2,
            boot_session_sha256=self.boot_session.sha256,
        )

    def _inspection_context(self, *, now_ns: int = 102) -> dict[str, object]:
        return {"observed_monotonic_ns": now_ns, "boot_session": self.boot_session}

    @staticmethod
    def _lfrq(run_id: str, *, authority: str) -> bytes:
        mediation = json.dumps(
            {"authority": authority, "token_ledger_reservation_id": "d" * 64},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        total = (LFRQ_HEADER_BYTES + len(mediation) + 511) & ~511
        raw = bytearray(total)
        prefix = struct.Struct("<4sHHHHQ32s64sI32s32s")
        section = struct.Struct("<16sQQ32s")

        def fixed(value: str, size: int) -> bytes:
            return value.encode() + b"\0" * (size - len(value))

        prefix.pack_into(
            raw,
            0,
            b"LFRQ",
            1,
            LFRQ_HEADER_BYTES,
            1,
            0,
            total,
            b"p" * 32,
            fixed(run_id, 64),
            0,
            fixed("implementation", 32),
            b"\0" * 32,
        )
        section.pack_into(
            raw,
            prefix.size,
            fixed("mediation", 16),
            LFRQ_HEADER_BYTES,
            len(mediation),
            hashlib.sha256(mediation).digest(),
        )
        raw[LFRQ_HEADER_BYTES : LFRQ_HEADER_BYTES + len(mediation)] = mediation
        return bytes(raw)


if __name__ == "__main__":
    unittest.main()
