from __future__ import annotations

import unittest

from leftovers.strict_vm_os_executor import (
    STRICT_VM_OS_EXECUTOR_ENABLED,
    CgroupV2DescendantProof,
    CgroupV2EmptySample,
    OSExecutorCaps,
    OSExecutorEvidenceError,
    PlatformEvidenceUnavailable,
    ProcessUnitIdentity,
    StrictVMOSExecutorDisabled,
    UnavailableLinuxCgroupV2EvidenceSource,
    collect_descendant_empty_receipt,
    validate_linux_cgroup_v2_descendant_proof,
)

RUN_ID = "a" * 32
BOOT_ID = "b" * 64
SERVICE_ID = "c" * 32


class FakeLinuxCgroupV2Source:
    """Deterministic adapter fake; the source gate must never call it."""

    def __init__(self) -> None:
        self.calls = 0

    def stop_and_collect(self, unit: ProcessUnitIdentity, caps: OSExecutorCaps):
        del unit, caps
        self.calls += 1
        raise AssertionError("source gate should reject before platform access")


class StrictVMOSExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = ProcessUnitIdentity(
            run_id=RUN_ID,
            platform="linux-cgroup-v2",
            boot_id_sha256=BOOT_ID,
            cgroup_mount_id=41,
            cgroup_inode=99,
            service_unit_id=SERVICE_ID,
        )
        self.caps = OSExecutorCaps(
            wall_seconds=60,
            cpu_quota_usec=50_000,
            cpu_period_usec=100_000,
            memory_max_bytes=64 * 1024 * 1024,
            pids_max=16,
            output_max_bytes=64 * 1024,
        )

    def empty_sample(self, *, monotonic_ns: int) -> CgroupV2EmptySample:
        return CgroupV2EmptySample(
            unit_sha256=self.unit.sha256,
            observed_monotonic_ns=monotonic_ns,
            cgroup_events_raw=b"populated 0\nfrozen 0\n",
            cgroup_procs_raw=b"",
        )

    def proof(self, **changes: object) -> CgroupV2DescendantProof:
        values: dict[str, object] = {
            "unit": self.unit,
            "caps_sha256": self.caps.sha256,
            "cgroup_type": "domain",
            "required_controllers": ("cpu", "memory", "pids"),
            "unit_not_delegated": True,
            "resource_limits_enforced": True,
            "network_denied": True,
            "filesystem_scope_enforced": True,
            "workload_cgroup_migration_blocked": True,
            "stop_requested": True,
            "cgroup_kill_completed": True,
            "leader_exited": True,
            "capture_pipes_closed": True,
            "first_empty": self.empty_sample(monotonic_ns=10_000_000),
            "second_empty": self.empty_sample(monotonic_ns=20_000_000),
            "unit_reaped_after_empty": True,
        }
        values.update(changes)
        return CgroupV2DescendantProof(**values)  # type: ignore[arg-type]

    def test_source_gate_stays_false_before_platform_evidence(self) -> None:
        self.assertFalse(STRICT_VM_OS_EXECUTOR_ENABLED)
        source = FakeLinuxCgroupV2Source()
        with self.assertRaisesRegex(StrictVMOSExecutorDisabled, "before platform or process"):
            collect_descendant_empty_receipt(self.unit, self.caps, source=source)
        self.assertEqual(source.calls, 0)

    def test_two_kernel_empty_observations_produce_a_bound_receipt(self) -> None:
        receipt = validate_linux_cgroup_v2_descendant_proof(self.unit, self.caps, self.proof())
        self.assertTrue(receipt.descendant_empty_proven)
        self.assertEqual(receipt.run_id, RUN_ID)
        self.assertEqual(receipt.unit_sha256, self.unit.sha256)
        self.assertEqual(receipt.caps_sha256, self.caps.sha256)

    def test_unavailable_platform_source_fails_closed(self) -> None:
        with self.assertRaisesRegex(PlatformEvidenceUnavailable, "no reviewed Linux"):
            UnavailableLinuxCgroupV2EvidenceSource().stop_and_collect(self.unit, self.caps)

    def test_daemonized_setsid_descendant_is_not_hidden_by_leader_or_pipes(self) -> None:
        # A daemon can call setsid() and close stdout/stderr.  It remains in a
        # non-delegated cgroup, so cgroup.events/procs still expose it.
        escaped_child = CgroupV2EmptySample(
            unit_sha256=self.unit.sha256,
            observed_monotonic_ns=1_000,
            cgroup_events_raw=b"populated 1\nfrozen 0\n",
            cgroup_procs_raw=b"4242\n",
        )
        with self.assertRaisesRegex(OSExecutorEvidenceError, "still contains a descendant"):
            validate_linux_cgroup_v2_descendant_proof(
                self.unit, self.caps, self.proof(first_empty=escaped_child)
            )

    def test_pipe_closure_is_not_a_descendant_empty_proof(self) -> None:
        # Closing capture descriptors makes the legacy helper return quickly;
        # it does not change the cgroup membership requirement.
        pipe_closing_child = CgroupV2EmptySample(
            unit_sha256=self.unit.sha256,
            observed_monotonic_ns=2_000,
            cgroup_events_raw=b"populated 1\nfrozen 0\n",
            cgroup_procs_raw=b"5151\n",
        )
        with self.assertRaisesRegex(OSExecutorEvidenceError, "still contains a descendant"):
            validate_linux_cgroup_v2_descendant_proof(
                self.unit, self.caps, self.proof(second_empty=pipe_closing_child)
            )

    def test_process_group_cleanup_or_unsealed_cgroup_cannot_substitute(self) -> None:
        with self.assertRaisesRegex(OSExecutorEvidenceError, "containment or stop evidence"):
            validate_linux_cgroup_v2_descendant_proof(
                self.unit, self.caps, self.proof(workload_cgroup_migration_blocked=False)
            )
        with self.assertRaisesRegex(OSExecutorEvidenceError, "containment or stop evidence"):
            validate_linux_cgroup_v2_descendant_proof(
                self.unit, self.caps, self.proof(unit_not_delegated=False)
            )

    def test_threaded_cgroup_and_incomplete_reap_cannot_claim_cleanup(self) -> None:
        with self.assertRaisesRegex(OSExecutorEvidenceError, "framing"):
            self.proof(cgroup_type="threaded")
        for field in ("leader_exited", "capture_pipes_closed"):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(OSExecutorEvidenceError, "containment or stop evidence"),
            ):
                validate_linux_cgroup_v2_descendant_proof(
                    self.unit, self.caps, self.proof(**{field: False})
                )

    def test_raw_kernel_observations_cannot_disagree_with_claimed_emptiness(self) -> None:
        for events, procs in (
            (b"populated 1\nfrozen 0\n", b""),
            (b"populated 0\nfrozen 0\n", b"6161\n"),
        ):
            sample = CgroupV2EmptySample(
                unit_sha256=self.unit.sha256,
                observed_monotonic_ns=10_000_000,
                cgroup_events_raw=events,
                cgroup_procs_raw=procs,
            )
            with (
                self.subTest(events=events, procs=procs),
                self.assertRaisesRegex(OSExecutorEvidenceError, "still contains a descendant"),
            ):
                validate_linux_cgroup_v2_descendant_proof(
                    self.unit, self.caps, self.proof(first_empty=sample)
                )

    def test_malformed_or_oversized_kernel_observations_are_rejected(self) -> None:
        for events, procs in (
            (b"populated 0", b""),
            (b"populated 0\npopulated 0\n", b""),
            (b"populated 2\n", b""),
            (b"populated 0\n", b"not-a-pid\n"),
            (b"populated 0\n", b"1" * 4_097),
        ):
            with (
                self.subTest(events=events[:20], procs=procs[:20]),
                self.assertRaises(OSExecutorEvidenceError),
            ):
                CgroupV2EmptySample(
                    unit_sha256=self.unit.sha256,
                    observed_monotonic_ns=10_000_000,
                    cgroup_events_raw=events,
                    cgroup_procs_raw=procs,
                )

    def test_identity_caps_and_second_observation_are_bound(self) -> None:
        wrong_unit = ProcessUnitIdentity(
            run_id=RUN_ID,
            platform="linux-cgroup-v2",
            boot_id_sha256=BOOT_ID,
            cgroup_mount_id=41,
            cgroup_inode=100,
            service_unit_id=SERVICE_ID,
        )
        with self.assertRaisesRegex(OSExecutorEvidenceError, "identity does not match"):
            validate_linux_cgroup_v2_descendant_proof(wrong_unit, self.caps, self.proof())
        with self.assertRaisesRegex(OSExecutorEvidenceError, "separated later observation"):
            validate_linux_cgroup_v2_descendant_proof(
                self.unit,
                self.caps,
                self.proof(second_empty=self.empty_sample(monotonic_ns=10_000_001)),
            )
