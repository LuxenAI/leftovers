from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from leftovers.strict_vm_broker import (
    BrokerAuthorizationError,
    BrokerInstallation,
    BrokerPeer,
    ImmutableBootIdentity,
)
from leftovers.strict_vm_broker_journal import (
    LFRQ_HEADER_BYTES,
    BrokerJournalAnchor,
    BrokerJournalError,
    BrokerJournalRollbackError,
    BrokerPrivateRootContract,
    BrokerUnavailableError,
    DurableBrokerJournal,
    journal_genesis_sha256,
    observe_unverified_lfrq_header,
)


class _Sink:
    def __init__(self) -> None:
        self.records: list[bytes] = []
        self.fail = False
        self.anchor: BrokerJournalAnchor | None = None

    def commit_fsynced(self, record: bytes, anchor: BrokerJournalAnchor) -> None:
        if self.fail:
            raise OSError("simulated crash before atomic journal+witness commit")
        self.records.append(record)
        self.anchor = anchor


class _Reader:
    def __init__(self, raw: bytes, *, safe: bool = True) -> None:
        self.raw = raw
        self.size = len(raw)
        self.opened_relative_to_private_root = safe
        self.opened_nofollow = safe
        self.identity_verified = safe

    def pread_exact(self, size: int, offset: int) -> bytes:
        return self.raw[offset : offset + size]


class BrokerJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.installation = BrokerInstallation(
            service_root=root / "broker",
            launcher_path=root / "launcher",
            controller_uid=501,
            broker_uid=502,
            boot_identity=ImmutableBootIdentity(*(["a" * 64] * 5)),
        )
        self.sink = _Sink()
        self.peer = BrokerPeer(501, 20)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _request_id(value: str = "1") -> str:
        return value * 32

    def _uploaded_journal(self) -> tuple[DurableBrokerJournal, str, str]:
        journal = DurableBrokerJournal.create(self.installation, self.sink)
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

    def test_genesis_binds_immutable_installation_and_boot_identity(self) -> None:
        journal = DurableBrokerJournal.create(self.installation, self.sink)
        genesis = json.loads(self.sink.records[0])
        self.assertEqual(genesis["kind"], "genesis")
        self.assertEqual(
            genesis["body"]["installation_sha256"], journal_genesis_sha256(self.installation)
        )
        self.assertEqual(journal.anchor.record_count, 1)
        self.assertEqual(journal.anchor.head_sha256, journal.head_sha256)
        self.assertEqual(self.sink.anchor, journal.anchor)
        self.assertFalse(hasattr(BrokerPrivateRootContract(502), "path"))

    def test_fsync_failure_never_updates_memory_authority(self) -> None:
        journal = DurableBrokerJournal.create(self.installation, self.sink)
        self.sink.fail = True
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id(), 1)
        self.assertEqual(journal.allocations, {})
        self.assertEqual(len(journal.records), 1)

    def test_recovery_quarantines_upload_and_keeps_replay_guard(self) -> None:
        journal, allocation_id, _ = self._uploaded_journal()
        recovered = DurableBrokerJournal.recover(
            self.installation, self.sink, journal.snapshot(), journal.anchor
        )
        self.assertEqual(recovered.allocations[allocation_id].state, "quarantined")
        self.assertEqual(recovered.reserved_tokens, 0)
        with self.assertRaises(BrokerJournalError):
            recovered.allocate(self.peer, self._request_id(), 102)
        self.assertGreater(recovered.anchor.record_count, journal.anchor.record_count)

    def test_restart_quarantines_incomplete_upload_and_preserves_replay_guard(self) -> None:
        journal = DurableBrokerJournal.create(self.installation, self.sink)
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        journal.append_chunk(
            allocation.allocation_id,
            allocation.lease_token,
            self.peer,
            b"partial",
            sequence=0,
            now_ns=101,
        )
        recovered = DurableBrokerJournal.recover(
            self.installation, self.sink, journal.snapshot(), journal.anchor
        )
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
        records = journal.snapshot()
        with self.assertRaises(BrokerJournalError):
            DurableBrokerJournal.recover(
                self.installation, self.sink, records[:-1] + (records[-1][:-1],), journal.anchor
            )
        with self.assertRaises(BrokerJournalRollbackError):
            DurableBrokerJournal.recover(self.installation, self.sink, records[:-1], journal.anchor)
        wrong_installation = BrokerInstallation(
            service_root=self.installation.service_root,
            launcher_path=self.installation.launcher_path,
            controller_uid=501,
            broker_uid=502,
            boot_identity=ImmutableBootIdentity(*(["b" * 64] * 5)),
        )
        with self.assertRaises(BrokerJournalRollbackError):
            DurableBrokerJournal.recover(wrong_installation, self.sink, records, journal.anchor)

    def test_recovery_persists_monotonic_floor_and_staging_authority_is_absent(self) -> None:
        journal, allocation_id, _ = self._uploaded_journal()
        with self.assertRaises(BrokerJournalRollbackError):
            journal.allocate(self.peer, self._request_id("2"), 1)
        recovered = DurableBrokerJournal.recover(
            self.installation, self.sink, journal.snapshot(), journal.anchor
        )
        with self.assertRaises(BrokerJournalRollbackError):
            recovered.allocate(self.peer, self._request_id("2"), 1)
        self.assertFalse(hasattr(journal, "stage"))
        self.assertEqual(journal.allocations[allocation_id].state, "uploading")

    def test_invalid_semantic_requests_never_mutate_sink_or_anchor(self) -> None:
        journal = DurableBrokerJournal.create(self.installation, self.sink)
        before = (tuple(self.sink.records), journal.anchor, tuple(journal.snapshot()))
        with self.assertRaises(BrokerJournalError):
            journal.reserve_tokens("not-an-allocation", "0" * 64, "f" * 64, 1)
        with self.assertRaises(BrokerJournalError):
            journal.settle_tokens("f" * 64)
        with self.assertRaises(BrokerJournalError):
            journal.quarantine("f" * 32, reason="not-a-reason")
        self.assertEqual(
            before, (tuple(self.sink.records), journal.anchor, tuple(journal.snapshot()))
        )

    def test_crash_before_atomic_commit_leaves_no_ambiguous_suffix(self) -> None:
        journal = DurableBrokerJournal.create(self.installation, self.sink)
        before = (tuple(self.sink.records), journal.anchor, tuple(journal.snapshot()))
        self.sink.fail = True
        with self.assertRaises(BrokerJournalError):
            journal.allocate(self.peer, self._request_id(), 100)
        self.assertEqual(
            before, (tuple(self.sink.records), journal.anchor, tuple(journal.snapshot()))
        )

    def test_deep_journal_json_is_a_strict_error_not_recursion_crash(self) -> None:
        depth = 2_000
        raw = b'{"body":' + b"[" * depth + b"0" + b"]" * depth + b"}"
        with self.assertRaises(BrokerJournalError):
            DurableBrokerJournal.recover(
                self.installation,
                self.sink,
                (raw,),
                BrokerJournalAnchor(1, "0" * 64, journal_genesis_sha256(self.installation)),
            )

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
        journal = DurableBrokerJournal.create(self.installation, self.sink)
        allocation = journal.allocate(self.peer, self._request_id(), 100)
        with self.assertRaises(BrokerUnavailableError):
            journal.validate_and_stage_lfrq(
                allocation.allocation_id,
                _Reader(self._lfrq(allocation.run_id, authority="fixture")),
            )
        self.assertEqual(journal.allocations[allocation.allocation_id].state, "uploading")

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
