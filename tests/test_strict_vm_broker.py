from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from leftovers.strict_vm_broker import (
    ALLOCATION_TTL_NS,
    BROKER_FRAME_MAGIC,
    MAX_REQUEST_CHUNKS,
    STRICT_VM_BROKER_ENABLED,
    BrokerAuthorizationError,
    BrokerInstallation,
    BrokerPeer,
    BrokerProtocolError,
    BrokerUnavailableError,
    ImmutableBootIdentity,
    StrictVMBrokerAdmission,
    StrictVMBrokerError,
    StrictVMBrokerService,
    decode_frame,
    encode_frame,
    peer_from_socket,
)


class _Socket:
    def __init__(self, value: tuple[int, int] | OSError) -> None:
        self.value = value

    def getpeereid(self) -> tuple[int, int]:
        if isinstance(self.value, OSError):
            raise self.value
        return self.value


class StrictVMBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        identity = ImmutableBootIdentity(*(["a" * 64] * 5))
        self.installation = BrokerInstallation(
            service_root=root / "service",
            launcher_path=root / "launcher",
            controller_uid=501,
            broker_uid=502,
            boot_identity=identity,
        )
        self.admission = StrictVMBrokerAdmission(self.installation)
        self.peer = BrokerPeer(uid=501, gid=20)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def allocation_frame(request_id: str = "1" * 32) -> bytes:
        return encode_frame(
            {"schema_version": 1, "operation": "allocate", "request_id": request_id}
        )

    def allocate(self, now_ns: int = 1, request_id: str = "1" * 32):
        return self.admission.handle(self.allocation_frame(request_id), self.peer, now_ns=now_ns)

    @staticmethod
    def append_frame(
        allocation_id: str,
        lease_token: str,
        chunk: bytes,
        *,
        sequence: int = 0,
        final: bool = True,
        request_sha256: str | None = None,
        request_id: str = "1" * 32,
    ) -> bytes:
        if final and request_sha256 is None:
            request_sha256 = hashlib.sha256(chunk).hexdigest()
        return encode_frame(
            {
                "schema_version": 1,
                "operation": "append_request",
                "request_id": request_id,
                "allocation_id": allocation_id,
                "lease_token": lease_token,
                "sequence": sequence,
                "chunk_b64": base64.b64encode(chunk).decode("ascii"),
                "final": final,
                "request_sha256": request_sha256,
            }
        )

    def test_valid_bounded_upload_has_no_controller_selected_path_or_argv(self) -> None:
        allocation = self.allocate()
        staged = self.admission.handle(
            self.append_frame(allocation.allocation_id, allocation.lease_token, b"sealed request"),
            self.peer,
            now_ns=2,
        )
        self.assertEqual(staged.operation, "staged")
        self.assertEqual(staged.request_bytes, len(b"sealed request"))
        self.assertFalse(hasattr(staged, "path"))
        self.assertFalse(hasattr(staged, "argv"))
        self.assertNotIn("path", staged.payload())
        self.assertNotIn("argv", staged.payload())
        with self.assertRaises(BrokerUnavailableError):
            self.admission.fixed_launcher_argv(allocation.allocation_id)

    def test_rejects_invalid_framing_and_noncanonical_payload(self) -> None:
        frame = self.allocation_frame()
        with self.assertRaises(BrokerProtocolError):
            decode_frame(frame[:-1])
        altered = bytearray(frame)
        altered[0:4] = b"evil"
        with self.assertRaises(BrokerProtocolError):
            decode_frame(bytes(altered))
        payload = (
            b'{"schema_version":1, "operation":"allocate",'
            b'"request_id":"11111111111111111111111111111111"}'
        )
        header = frame[:8] + len(payload).to_bytes(4, "little") + hashlib.sha256(payload).digest()
        with self.assertRaises(BrokerProtocolError):
            decode_frame(header + payload)
        self.assertEqual(BROKER_FRAME_MAGIC, b"LVB1")

    def test_rejects_injected_path_argv_and_unknown_operation(self) -> None:
        injected = {
            "schema_version": 1,
            "operation": "allocate",
            "request_id": "1" * 32,
            "path": "/tmp/attacker",
            "argv": ["--run", "/tmp/attacker"],
            "run_id": "0" * 32,
        }
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(encode_frame(injected), self.peer, now_ns=1)
        unknown = {"schema_version": 1, "operation": "launch", "request_id": "1" * 32}
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(encode_frame(unknown), self.peer, now_ns=1)

    def test_broker_derives_run_location_from_its_own_identity_only(self) -> None:
        allocation = self.allocate()
        state = self.admission._pending[allocation.allocation_id]
        self.assertEqual(
            self.admission._broker_run_directory(state.allocation),
            self.installation.service_root / "runs" / allocation.run_id,
        )
        self.assertNotIn("run_directory", allocation.payload())

    def test_rejects_peer_mismatch_and_kernel_peer_failures(self) -> None:
        with self.assertRaises(BrokerAuthorizationError):
            self.admission.handle(self.allocation_frame(), BrokerPeer(uid=503, gid=20), now_ns=1)
        self.assertEqual(peer_from_socket(_Socket((501, 20))), self.peer)
        with self.assertRaises(BrokerAuthorizationError):
            peer_from_socket(_Socket(OSError("no peer")))

    def test_stale_replayed_and_foreign_allocations_fail_closed(self) -> None:
        allocation = self.allocate(now_ns=1)
        frame = self.append_frame(allocation.allocation_id, allocation.lease_token, b"x")
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(frame, self.peer, now_ns=1 + ALLOCATION_TTL_NS + 1)
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(frame, self.peer, now_ns=1 + ALLOCATION_TTL_NS + 2)
        allocation = self.allocate(now_ns=10)
        with self.assertRaises(BrokerAuthorizationError):
            self.admission.handle(
                self.append_frame(allocation.allocation_id, allocation.lease_token, b"x"),
                BrokerPeer(uid=501, gid=99),
                now_ns=11,
            )

    def test_allocation_request_id_cannot_be_replayed_during_its_ttl(self) -> None:
        self.allocate(now_ns=1)
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(self.allocation_frame(), self.peer, now_ns=2)

    def test_sequence_and_digest_replays_are_rejected(self) -> None:
        allocation = self.allocate()
        first = self.append_frame(
            allocation.allocation_id,
            allocation.lease_token,
            b"one",
            final=False,
            request_sha256=None,
        )
        self.admission.handle(first, self.peer, now_ns=2)
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(first, self.peer, now_ns=3)
        final = self.append_frame(
            allocation.allocation_id,
            allocation.lease_token,
            b"two",
            sequence=1,
            request_sha256="0" * 64,
        )
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(final, self.peer, now_ns=4)

    def test_append_binds_request_id_and_invalid_metadata_does_not_advance_state(self) -> None:
        allocation = self.allocate()
        state = self.admission._pending[allocation.allocation_id]
        foreign = self.append_frame(
            allocation.allocation_id,
            allocation.lease_token,
            b"x",
            request_id="2" * 32,
        )
        with self.assertRaises(BrokerAuthorizationError):
            self.admission.handle(foreign, self.peer, now_ns=2)
        invalid = self.append_frame(
            allocation.allocation_id,
            allocation.lease_token,
            b"x",
            final=False,
            request_sha256="0" * 64,
        )
        with self.assertRaises(BrokerProtocolError):
            self.admission.handle(invalid, self.peer, now_ns=3)
        self.assertEqual(state.next_sequence, 0)
        self.assertEqual(state.total_bytes, 0)
        self.assertEqual(state.digest.hexdigest(), hashlib.sha256().hexdigest())

    def test_empty_request_and_excessive_empty_chunk_sequence_are_bounded(self) -> None:
        allocation = self.allocate()
        with self.assertRaisesRegex(BrokerProtocolError, "may not be empty"):
            self.admission.handle(
                self.append_frame(allocation.allocation_id, allocation.lease_token, b""),
                self.peer,
                now_ns=2,
            )
        allocation = self.allocate(now_ns=3, request_id="2" * 32)
        state = self.admission._pending[allocation.allocation_id]
        state.next_sequence = MAX_REQUEST_CHUNKS
        with self.assertRaisesRegex(BrokerProtocolError, "chunk-count cap"):
            self.admission.handle(
                self.append_frame(
                    allocation.allocation_id,
                    allocation.lease_token,
                    b"",
                    sequence=MAX_REQUEST_CHUNKS,
                    final=False,
                    request_sha256=None,
                    request_id="2" * 32,
                ),
                self.peer,
                now_ns=4,
            )
        self.assertNotIn(allocation.allocation_id, self.admission._pending)

    def test_service_is_hard_disabled_before_any_host_mutation(self) -> None:
        self.assertFalse(STRICT_VM_BROKER_ENABLED)
        with self.assertRaises(BrokerUnavailableError):
            StrictVMBrokerService(self.installation).start()
        self.assertFalse(self.installation.service_root.exists())

    def test_installation_rejects_same_uid_and_non_absolute_paths(self) -> None:
        with self.assertRaises(StrictVMBrokerError):
            BrokerInstallation(
                service_root=Path("relative"),
                launcher_path=Path("/private/launcher"),
                controller_uid=501,
                broker_uid=501,
                boot_identity=self.installation.boot_identity,
            )
        with self.assertRaises(StrictVMBrokerError):
            BrokerInstallation(
                service_root=Path("/private/service/../operator"),
                launcher_path=Path("/private/launcher"),
                controller_uid=501,
                broker_uid=502,
                boot_identity=self.installation.boot_identity,
            )
