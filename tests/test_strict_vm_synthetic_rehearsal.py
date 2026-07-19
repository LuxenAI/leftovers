from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from leftovers import strict_vm_synthetic_rehearsal as synthetic
from leftovers.strict_vm_broker_service import BrokerUnavailableError, StrictVMBrokerServiceCore
from leftovers.strict_vm_cycle import CyclePhase
from leftovers.strict_vm_poststop import StrictVMPostStopDisabled, verify_post_stop
from leftovers.strict_vm_synthetic_rehearsal import (
    SYNTHETIC_REHEARSAL_ONLY,
    SyntheticRehearsalError,
    run_synthetic_rehearsal,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "codex-provider-envelope.schema.json"
GUEST_SOURCE = ROOT / "vm" / "guest" / "package" / "leftovers-guest-supervisor" / "src"
# The invocation-plan renderer independently refuses an expired request using
# the process clock.  The fixture bytes remain deterministic; this timestamp
# only gives that defensive admission check a current bounded deadline.
NOW = datetime.now(UTC)


class StrictVMSyntheticRehearsalTests(unittest.TestCase):
    def test_synthetic_chain_is_bounded_and_leaves_no_fixture_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            evidence = run_synthetic_rehearsal(
                root,
                provider_schema=SCHEMA,
                guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                now=NOW,
            )

            self.assertTrue(SYNTHETIC_REHEARSAL_ONLY)
            self.assertEqual(evidence.cycle_state.phase, CyclePhase.PUBLISH_READY)
            self.assertTrue(evidence.broker_workspace_removed)
            self.assertTrue(evidence.fixture_handoff_created)
            self.assertTrue(evidence.production_authorities_disabled)
            self.assertFalse(evidence.guest_interpreter_reachable)
            self.assertFalse(evidence.provider_called)
            self.assertFalse(evidence.vm_launched)
            self.assertFalse(evidence.git_or_check_executed)
            self.assertFalse(evidence.github_write_attempted)
            self.assertEqual(evidence.invocation_plan.environment, ())
            self.assertEqual(evidence.invocation_plan.private_cwd.name, "provider-cwd")
            self.assertEqual(
                {name for name, _digest in evidence.artifact_digests},
                {
                    "cleanup.json",
                    "result.json",
                    "canonical.patch",
                },
            )
            self.assertEqual(list(root.iterdir()), [])

    def test_rehearsal_rejects_a_nonprivate_or_nonempty_workspace_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            (root / "foreign").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(SyntheticRehearsalError, "empty"):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertEqual((root / "foreign").read_text(encoding="utf-8"), "keep")

    def test_no_subprocess_or_network_helper_is_invoked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            with (
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")),
                mock.patch("subprocess.run", side_effect=AssertionError("subprocess")),
                mock.patch("socket.socket", side_effect=AssertionError("network")),
            ):
                evidence = run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertFalse(evidence.provider_called)
            self.assertEqual(list(root.iterdir()), [])

    def test_public_broker_entry_rejects_before_any_dependency_is_inspected(self) -> None:
        with self.assertRaisesRegex(BrokerUnavailableError, "source-disabled"):
            StrictVMBrokerServiceCore(
                object(),
                signature_binding=object(),
                signature_verifier=object(),
                durable_acknowledgement=object(),
            )

    def test_operator_sources_are_bounded_regular_files_before_fixture_writes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            root = parent / "workspace"
            root.mkdir(mode=0o700)
            fifo = parent / "guest-source-fifo"
            os.mkfifo(fifo, mode=0o600)
            with self.assertRaisesRegex(SyntheticRehearsalError, "bounded trusted regular"):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=fifo,
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertEqual(list(root.iterdir()), [])

            oversized_schema = parent / "oversized-schema.json"
            oversized_schema.write_bytes(b"x" * 65_537)
            with self.assertRaisesRegex(SyntheticRehearsalError, "bounded trusted regular"):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=oversized_schema,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_identity_bound_cleanup_never_removes_a_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            original = parent / "owned"
            root_record = synthetic._open_private_empty_directory(parent, "test root")
            root_fd, root_identity = root_record.fd, root_record.identity
            directories: list[synthetic._DirectoryRecord] = []
            leaves: list[synthetic._LeafRecord] = []
            owned = synthetic._mkdir_private(root_fd, root_identity, original, directories)
            synthetic._write_private(
                owned,
                root_fd=root_fd,
                root_identity=root_identity,
                path=original / "result.json",
                raw=b"fixture",
                mode=0o600,
                records=leaves,
            )
            moved = parent / "moved-owned"
            original.rename(moved)
            original.mkdir(mode=0o700)
            replacement = original / "result.json"
            replacement.write_bytes(b"foreign")
            replacement.chmod(0o600)

            errors = synthetic._cleanup_fixture_tree(root_record, leaves, directories)
            self.assertTrue(any("identity changed" in str(error) for error in errors))
            self.assertEqual(replacement.read_bytes(), b"foreign")
            self.assertEqual(list(moved.iterdir()), [])

    def test_write_failure_rolls_back_every_registered_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            with (
                mock.patch.object(synthetic.os, "write", side_effect=OSError("injected write")),
                self.assertRaisesRegex(SyntheticRehearsalError, "write failed"),
            ):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_directory_open_failure_is_tracked_and_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            real_open = synthetic.os.open
            failed = False

            def fail_first_child_open(
                path: object, flags: int, *args: object, **kwargs: object
            ) -> int:
                nonlocal failed
                if path == "provider-cwd" and flags & os.O_DIRECTORY and not failed:
                    failed = True
                    raise OSError("injected directory open")
                return real_open(path, flags, *args, **kwargs)

            with (
                mock.patch.object(synthetic.os, "open", side_effect=fail_first_child_open),
                self.assertRaisesRegex(SyntheticRehearsalError, "directory creation failed"),
            ):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertTrue(failed)
            self.assertEqual(list(root.iterdir()), [])

    def test_cleanup_aggregates_failures_and_attempts_remaining_leaves(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            root_record = synthetic._open_private_empty_directory(root, "test root")
            root_fd, root_identity = root_record.fd, root_record.identity
            directories: list[synthetic._DirectoryRecord] = []
            leaves: list[synthetic._LeafRecord] = []
            owned = synthetic._mkdir_private(root_fd, root_identity, root / "owned", directories)
            for name in ("first", "second"):
                synthetic._write_private(
                    owned,
                    root_fd=root_fd,
                    root_identity=root_identity,
                    path=owned.path / name,
                    raw=name.encode(),
                    mode=0o600,
                    records=leaves,
                )
            real_unlink = synthetic._unlink_exact
            calls = 0

            def fail_once(record: synthetic._LeafRecord) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise SyntheticRehearsalError("injected cleanup failure")
                real_unlink(record)

            with mock.patch.object(synthetic, "_unlink_exact", side_effect=fail_once):
                errors = synthetic._cleanup_fixture_tree(root_record, leaves, directories)
            self.assertEqual(calls, 2)
            self.assertGreaterEqual(len(errors), 2)
            self.assertFalse((owned.path / "first").exists())
            self.assertTrue((owned.path / "second").exists())

    def test_root_replacement_is_preserved_and_prevents_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            root = parent / "workspace"
            root.mkdir(mode=0o700)
            moved = parent / "moved-original"
            original_gate = synthetic._require_all_production_authorities_disabled
            calls = 0

            def replace_at_final_gate() -> None:
                nonlocal calls
                original_gate()
                calls += 1
                if calls == 2:
                    root.rename(moved)
                    root.mkdir(mode=0o700)
                    (root / "replacement-marker").write_text("foreign", encoding="utf-8")

            with (
                mock.patch.object(
                    synthetic,
                    "_require_all_production_authorities_disabled",
                    side_effect=replace_at_final_gate,
                ),
                self.assertRaisesRegex(SyntheticRehearsalError, "root pathname identity changed"),
            ):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            self.assertEqual((root / "replacement-marker").read_text(encoding="utf-8"), "foreign")
            self.assertEqual(list(moved.iterdir()), [])

    def test_root_parent_replacement_is_detected_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            outer = Path(raw)
            parent = outer / "parent"
            parent.mkdir(mode=0o700)
            root = parent / "workspace"
            root.mkdir(mode=0o700)
            moved_parent = outer / "moved-parent"
            original_gate = synthetic._require_all_production_authorities_disabled
            calls = 0

            def replace_parent_at_final_gate() -> None:
                nonlocal calls
                original_gate()
                calls += 1
                if calls == 2:
                    parent.rename(moved_parent)
                    parent.mkdir(mode=0o700)
                    replacement = parent / "workspace"
                    replacement.mkdir(mode=0o700)
                    (replacement / "replacement-marker").write_text("foreign", encoding="utf-8")

            with (
                mock.patch.object(
                    synthetic,
                    "_require_all_production_authorities_disabled",
                    side_effect=replace_parent_at_final_gate,
                ),
                self.assertRaisesRegex(SyntheticRehearsalError, "root pathname identity changed"),
            ):
                run_synthetic_rehearsal(
                    root,
                    provider_schema=SCHEMA,
                    guest_interpreter_source=GUEST_SOURCE / "guest_interpreter.c",
                    guest_supervisor_source=GUEST_SOURCE / "guest_supervisor.c",
                    now=NOW,
                )
            marker = parent / "workspace" / "replacement-marker"
            self.assertEqual(marker.read_text(encoding="utf-8"), "foreign")
            self.assertEqual(list((moved_parent / "workspace").iterdir()), [])

    def test_public_poststop_entry_rejects_before_any_path_is_used(self) -> None:
        with self.assertRaisesRegex(StrictVMPostStopDisabled, "source-disabled"):
            verify_post_stop(
                object(),  # type: ignore[arg-type]
                artifact_root=object(),  # type: ignore[arg-type]
                verification_root=object(),  # type: ignore[arg-type]
            )
