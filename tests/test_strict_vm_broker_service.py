from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

from leftovers.strict_vm_broker import (
    BrokerAuthorizationError,
    BrokerInstallation,
    BrokerProtocolError,
    BrokerUnavailableError,
    ImmutableBootIdentity,
    decode_frame,
    encode_frame,
)
from leftovers.strict_vm_broker_service import (
    STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED,
    STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED,
    STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED,
    STRICT_VM_BROKER_SERVICE_ENABLED,
    BrokerCancellationError,
    BrokerCleanupError,
    BrokerServiceError,
    BrokerStorageError,
    ControllerCodeSignatureBinding,
    FixedBrokerResourcePolicy,
    FixtureBrokerServiceCapability,
    FixturePrivateRunRoot,
    FixtureStrictVMBrokerServiceCore,
    StrictVMBrokerServiceCore,
    fixture_recv_bounded_frame,
    issue_fixture_broker_service_capability,
    verify_fixture_fixed_launcher_descriptor,
)


class _Connection:
    def __init__(self, chunks: list[bytes], *, uid: int, verified: bool = True) -> None:
        self.chunks = list(chunks)
        self.uid = uid
        self.verified = verified
        self.sent = bytearray()

    def getpeereid(self) -> tuple[int, int]:
        return self.uid, 20

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        current = self.chunks[0]
        result, self.chunks[0] = current[:size], current[size:]
        if not self.chunks[0]:
            self.chunks.pop(0)
        return result

    def send(self, data: bytes) -> int:
        self.sent.extend(data)
        return len(data)


class _Verifier:
    def verify(self, connection: _Connection, binding: ControllerCodeSignatureBinding) -> bool:
        del binding
        return connection.verified


class _DurableAck:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[bytes, str]] = []

    def commit_before_ack(self, request_frame: bytes, reply: object) -> None:
        if self.fail:
            raise OSError("simulated witness fsync failure")
        self.calls.append((request_frame, reply.operation))


class StrictVMBrokerServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.runs = root / "runs"
        self.runs.mkdir(mode=0o700)
        os.chmod(self.runs, 0o700)
        self.controller_uid = 501 if os.getuid() != 501 else 502
        self.installation = BrokerInstallation(
            service_root=root / "service",
            launcher_path=root / "launcher",
            controller_uid=self.controller_uid,
            broker_uid=os.getuid(),
            boot_identity=ImmutableBootIdentity(*(["a" * 64] * 5)),
        )
        self.binding = ControllerCodeSignatureBinding("TEAMID", "b" * 64)
        self.capability = issue_fixture_broker_service_capability()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _root(self) -> FixturePrivateRunRoot:
        fd = os.open(self.runs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            return FixturePrivateRunRoot(fd, broker_uid=os.getuid(), capability=self.capability)
        finally:
            os.close(fd)

    def test_private_storage_is_descriptor_relative_nofollow_and_exactly_cleaned(self) -> None:
        run_id = "1" * 32
        request = b"sealed LFRQ request"
        with self._root() as root:
            workspace = root.create_run(run_id)
            workspace.write_request(request, hashlib.sha256(request).hexdigest())
            request_path = self.runs / run_id / "request.lfrq"
            self.assertEqual(request_path.read_bytes(), request)
            self.assertEqual(stat.S_IMODE(request_path.stat().st_mode), 0o600)
            workspace.cleanup()
        self.assertFalse((self.runs / run_id).exists())

    def test_storage_rejects_symlink_collision_and_nonempty_cleanup_without_recursion(self) -> None:
        run_id = "2" * 32
        with self._root() as root:
            workspace = root.create_run(run_id)
            outside = self.runs.parent / "outside"
            outside.write_text("safe", encoding="utf-8")
            os.symlink(outside, self.runs / run_id / "request.lfrq")
            with self.assertRaises(BrokerStorageError):
                workspace.write_request(b"x", hashlib.sha256(b"x").hexdigest())
            with self.assertRaises(BrokerCleanupError):
                workspace.cleanup()
        self.assertEqual(outside.read_text(encoding="utf-8"), "safe")
        self.assertTrue((self.runs / run_id).exists())

    def test_storage_rejects_wrong_owner_mode_and_caller_run_id(self) -> None:
        os.chmod(self.runs, 0o755)
        fd = os.open(self.runs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerStorageError):
                FixturePrivateRunRoot(fd, broker_uid=os.getuid(), capability=self.capability)
        finally:
            os.close(fd)
        os.chmod(self.runs, 0o700)
        with self._root() as root, self.assertRaises(BrokerStorageError):
            root.create_run("../attacker")
        forged = object.__new__(FixtureBrokerServiceCapability)
        fd = os.open(self.runs, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerUnavailableError):
                FixturePrivateRunRoot(fd, broker_uid=os.getuid(), capability=forged)
        finally:
            os.close(fd)

    def test_fixed_launcher_identity_is_descriptor_rehashed_and_not_path_selected(self) -> None:
        launcher = self.runs.parent / "strict-vm-launcher"
        launcher.write_bytes(b"immutable launcher")
        os.chmod(launcher, 0o500)
        fd = os.open(launcher, os.O_RDONLY | os.O_CLOEXEC)
        try:
            verify_fixture_fixed_launcher_descriptor(
                fd,
                launcher_owner_uid=os.getuid(),
                expected_sha256=hashlib.sha256(b"immutable launcher").hexdigest(),
                capability=self.capability,
            )
            with self.assertRaises(BrokerStorageError):
                verify_fixture_fixed_launcher_descriptor(
                    fd,
                    launcher_owner_uid=os.getuid(),
                    expected_sha256="0" * 64,
                    capability=self.capability,
                )
        finally:
            os.close(fd)

        os.chmod(launcher, 0o500)
        linked = launcher.with_name("strict-vm-launcher-hardlink")
        os.link(launcher, linked)
        fd = os.open(launcher, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerStorageError):
                verify_fixture_fixed_launcher_descriptor(
                    fd,
                    launcher_owner_uid=os.getuid(),
                    expected_sha256=hashlib.sha256(b"immutable launcher").hexdigest(),
                    capability=self.capability,
                )
        finally:
            os.close(fd)
        linked.unlink()

        fd = os.open(launcher, os.O_RDONLY | os.O_CLOEXEC)
        os.set_inheritable(fd, True)
        try:
            with self.assertRaises(BrokerStorageError):
                verify_fixture_fixed_launcher_descriptor(
                    fd,
                    launcher_owner_uid=os.getuid(),
                    expected_sha256=hashlib.sha256(b"immutable launcher").hexdigest(),
                    capability=self.capability,
                )
        finally:
            os.close(fd)

        os.chmod(launcher, 0o700)
        fd = os.open(launcher, os.O_RDONLY | os.O_CLOEXEC)
        try:
            with self.assertRaises(BrokerStorageError):
                verify_fixture_fixed_launcher_descriptor(
                    fd,
                    launcher_owner_uid=os.getuid(),
                    expected_sha256=hashlib.sha256(b"immutable launcher").hexdigest(),
                    capability=self.capability,
                )
        finally:
            os.close(fd)

    def test_cleanup_rejects_renamed_and_recreated_run_identity(self) -> None:
        run_id = "8" * 32
        request = b"original request"
        with self._root() as root:
            workspace = root.create_run(run_id)
            workspace.write_request(request, hashlib.sha256(request).hexdigest())
            moved = self.runs / "moved-original"
            (self.runs / run_id).rename(moved)
            (self.runs / run_id).mkdir(mode=0o700)
            os.chmod(self.runs / run_id, 0o700)
            marker = self.runs / run_id / "replacement-marker"
            marker.write_text("replacement", encoding="utf-8")
            with self.assertRaisesRegex(BrokerCleanupError, "identity changed"):
                workspace.cleanup()
        self.assertEqual((moved / "request.lfrq").read_bytes(), request)
        self.assertEqual(marker.read_text(encoding="utf-8"), "replacement")

    def test_public_production_constructor_and_dispatch_reject_before_input_access(self) -> None:
        class _Exploding:
            def __getattribute__(self, name: str) -> object:
                raise AssertionError(f"production gate accessed {name}")

        exploding = _Exploding()
        with self.assertRaises(BrokerUnavailableError):
            StrictVMBrokerServiceCore(
                exploding,
                signature_binding=exploding,
                signature_verifier=exploding,
                durable_acknowledgement=exploding,
                resource_policy=exploding,
            )
        unconstructed = object.__new__(StrictVMBrokerServiceCore)
        with self.assertRaises(BrokerUnavailableError):
            unconstructed.dispatch_once(exploding, now_ns=1)
        with self.assertRaises(BrokerUnavailableError):
            unconstructed.fixed_launcher_plan("9" * 32)

    def test_bounded_protocol_requires_signature_before_parsing_controller_bytes(self) -> None:
        core = FixtureStrictVMBrokerServiceCore(
            self.installation,
            capability=self.capability,
            signature_binding=self.binding,
            signature_verifier=_Verifier(),
            durable_acknowledgement=_DurableAck(),
        )
        frame = encode_frame({"schema_version": 1, "operation": "allocate", "request_id": "1" * 32})
        connection = _Connection([frame], uid=self.controller_uid, verified=False)
        with self.assertRaises(BrokerAuthorizationError):
            core.dispatch_once(connection, now_ns=1)
        self.assertEqual(connection.chunks, [frame])
        denied = _Connection([frame], uid=self.controller_uid + 1)
        with self.assertRaises(BrokerAuthorizationError):
            core.dispatch_once(denied, now_ns=1)
        self.assertEqual(denied.chunks, [frame])

    def test_bounded_protocol_round_trip_and_cancelled_partial_frame_have_no_ack(self) -> None:
        durable_ack = _DurableAck()
        core = FixtureStrictVMBrokerServiceCore(
            self.installation,
            capability=self.capability,
            signature_binding=self.binding,
            signature_verifier=_Verifier(),
            durable_acknowledgement=durable_ack,
        )
        frame = encode_frame({"schema_version": 1, "operation": "allocate", "request_id": "1" * 32})
        connection = _Connection([frame[:8], frame[8:]], uid=self.controller_uid)
        reply = core.dispatch_once(connection, now_ns=1)
        self.assertEqual(reply.operation, "allocated")
        self.assertEqual(durable_ack.calls, [(frame, "allocated")])
        self.assertEqual(decode_frame(bytes(connection.sent))["operation"], "allocated")
        partial = _Connection([frame[:8]], uid=self.controller_uid)
        with self.assertRaises(BrokerCancellationError):
            fixture_recv_bounded_frame(partial, capability=self.capability, cancelled=lambda: True)
        self.assertEqual(partial.sent, b"")

    def test_failed_durable_acknowledgement_returns_no_protocol_reply(self) -> None:
        core = FixtureStrictVMBrokerServiceCore(
            self.installation,
            capability=self.capability,
            signature_binding=self.binding,
            signature_verifier=_Verifier(),
            durable_acknowledgement=_DurableAck(fail=True),
        )
        frame = encode_frame({"schema_version": 1, "operation": "allocate", "request_id": "7" * 32})
        connection = _Connection([frame], uid=self.controller_uid)
        with self.assertRaisesRegex(BrokerServiceError, "journal\\+witness"):
            core.dispatch_once(connection, now_ns=1)
        self.assertEqual(connection.sent, b"")
        retry = _Connection([frame], uid=self.controller_uid)
        with self.assertRaises(BrokerUnavailableError):
            core.dispatch_once(retry, now_ns=2)
        self.assertEqual(retry.sent, b"")

    def test_rejects_truncated_and_invalid_bounded_frame_header(self) -> None:
        with self.assertRaises(BrokerProtocolError):
            fixture_recv_bounded_frame(
                _Connection([b"short"], uid=self.controller_uid),
                capability=self.capability,
            )
        malformed = bytearray(
            encode_frame({"schema_version": 1, "operation": "allocate", "request_id": "1" * 32})
        )
        malformed[0:4] = b"NOPE"
        with self.assertRaises(BrokerProtocolError):
            fixture_recv_bounded_frame(
                _Connection([bytes(malformed)], uid=self.controller_uid),
                capability=self.capability,
            )

    def test_fixed_resources_empty_environment_and_every_activation_gate_remain_false(self) -> None:
        self.assertFalse(STRICT_VM_BROKER_SERVICE_ENABLED)
        self.assertFalse(STRICT_VM_BROKER_DEDICATED_UID_EVIDENCE_VERIFIED)
        self.assertFalse(STRICT_VM_BROKER_CODE_SIGNATURE_EVIDENCE_VERIFIED)
        self.assertFalse(STRICT_VM_BROKER_LIVE_CLEANUP_EVIDENCE_VERIFIED)
        policy = FixedBrokerResourcePolicy()
        self.assertEqual(policy.virtual_cpus, 2)
        self.assertEqual(policy.memory_bytes, 2 * 1_024 * 1_024 * 1_024)
        self.assertEqual(policy.scratch_bytes, 2 * 1_024 * 1_024 * 1_024)
        self.assertEqual(policy.wall_clock_seconds, 30 * 60)
        with self.assertRaises(BrokerServiceError):
            FixedBrokerResourcePolicy(memory_bytes=1)
        core = FixtureStrictVMBrokerServiceCore(
            self.installation,
            capability=self.capability,
            signature_binding=self.binding,
            signature_verifier=_Verifier(),
            durable_acknowledgement=_DurableAck(),
        )
        plan = core.fixed_launcher_plan("3" * 32)
        self.assertEqual(plan.environment, ())


if __name__ == "__main__":
    unittest.main()
