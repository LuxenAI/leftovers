from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from leftovers.sbx import controller_sandbox_name
from leftovers.sbx_execution import (
    AUTH_MODE,
    CLEANUP_TIMEOUT_SECONDS,
    CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE,
    CPU_CAP,
    CREATE_TIMEOUT_SECONDS,
    LIFECYCLE_TIMEOUT_SECONDS,
    MAX_INSPECTION_BYTES,
    MAX_MODEL_CALLS,
    MAX_STDIN_BYTES,
    MEMORY_CAP_BYTES,
    MODEL,
    PINNED_SBX_IDENTITY,
    REASONING_EFFORT,
    RUN_TOKEN_CAP,
    SBX_BINARY,
    SBX_EXEC_ID_TARGETING_DOCUMENTED,
    SBX_EXEC_NAME_BINDING_ATOMIC,
    SBX_EXECUTION_ENABLED,
    SBX_REVISION,
    SBX_SHA256,
    SBX_V035_IN_VM_RUNTIME_ATTESTATION_DOCUMENTED,
    SBX_VERSION,
    STAGE_LIMITS,
    TOKEN_CAPS_PROVIDER_ENFORCED,
    TOKEN_CAPS_REQUIRE_POST_CALL_RECEIPT,
    ControllerSandboxIdentity,
    DaemonSandboxIdentity,
    ExecutionStage,
    FixtureSbxExecutionCapability,
    InspectionExpectation,
    InVmRuntimeExpectation,
    SbxCliIdentity,
    SbxExecutionDisabled,
    SbxExecutionError,
    SbxExecutionPlan,
    build_fixture_execution_plan,
    canonical_fixture_inspection_document,
    derive_controller_sandbox_identity,
    execute_live_sbx_plan,
    fixed_sbx_codex_argv,
    fixture_sbx_execution_capability,
    parse_fixture_inspection_attestation,
    validate_fixture_execution_plan,
)

RUN_ID = "a" * 32
POLICY_EPOCH = "b" * 64
SECRET_EPOCH = "c" * 64
DAEMON_UUID = "123e4567-e89b-42d3-a456-426614174000"
CODEX_PATH = "/opt/leftovers-fixture/bin/codex"
CODEX_SHA256 = "d" * 64
CODEX_VERSION = "0.145.0-alpha.18"
CODEX_DEVICE = 2_049
CODEX_INODE = 47_112
CODEX_OWNER_UID = 0
CODEX_OWNER_GID = 0
CODEX_MODE = 0o100755
CODEX_LINK_COUNT = 1
CODEX_SIZE_BYTES = 94_208_000
CODEX_MTIME_NS = 1_752_940_800_000_000_000
CODEX_CTIME_NS = 1_752_940_801_000_000_000
USER_NAME = "agent"
USER_UID = 1000
USER_GID = 1000
SUPPLEMENTAL_GIDS: tuple[int, ...] = ()
LINUX_CAPABILITIES: tuple[str, ...] = ()
PRIVATE_CLONE_WORKDIR = "/home/agent/workspace"
CODEX_HOME = "/home/agent/.codex"
NOW = datetime(2026, 7, 19, 16, 0, tzinfo=UTC)


class Explosive:
    def __getattribute__(self, _name: str) -> object:
        raise AssertionError("source-disabled entry inspected an argument")

    def __repr__(self) -> str:
        raise AssertionError("source-disabled entry rendered an argument")


class SbxExecutionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.capability = fixture_sbx_execution_capability()
        self.controller = derive_controller_sandbox_identity(RUN_ID)
        self.runtime = InVmRuntimeExpectation(
            codex_executable_path=CODEX_PATH,
            codex_executable_sha256=CODEX_SHA256,
            codex_version=CODEX_VERSION,
            codex_executable_device=CODEX_DEVICE,
            codex_executable_inode=CODEX_INODE,
            codex_executable_owner_uid=CODEX_OWNER_UID,
            codex_executable_owner_gid=CODEX_OWNER_GID,
            codex_executable_mode=CODEX_MODE,
            codex_executable_link_count=CODEX_LINK_COUNT,
            codex_executable_size_bytes=CODEX_SIZE_BYTES,
            codex_executable_mtime_ns=CODEX_MTIME_NS,
            codex_executable_ctime_ns=CODEX_CTIME_NS,
            user_name=USER_NAME,
            user_uid=USER_UID,
            user_gid=USER_GID,
            supplemental_gids=SUPPLEMENTAL_GIDS,
            linux_capabilities=LINUX_CAPABILITIES,
            private_clone_workdir=PRIVATE_CLONE_WORKDIR,
            codex_home=CODEX_HOME,
            auth_mode=AUTH_MODE,
            user_config_loaded=False,
            repository_rules_loaded=False,
            hooks_loaded=False,
        )
        self.expectation = InspectionExpectation(
            self.controller,
            self.runtime,
            policy_epoch_sha256=POLICY_EPOCH,
            secret_epoch_sha256=SECRET_EPOCH,
        )
        self.raw = canonical_fixture_inspection_document(
            self.capability,
            self.expectation,
            daemon_uuid=DAEMON_UUID,
            generation=7,
        )
        self.inspection = parse_fixture_inspection_attestation(
            self.capability, self.raw, self.expectation
        )

    def document(self) -> dict[str, object]:
        return json.loads(self.raw)

    def render(self, value: object) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def parse(self, value: object):
        return parse_fixture_inspection_attestation(
            self.capability, self.render(value), self.expectation
        )

    def plan(
        self,
        *,
        stage: ExecutionStage = ExecutionStage.IMPLEMENTATION,
        stdin_bytes: bytes = b"ISSUE_MARKER_8f61: implement the bounded fix.\n",
        run_started_at: datetime = NOW,
        call_started_at: datetime = NOW + timedelta(minutes=7),
    ) -> SbxExecutionPlan:
        return build_fixture_execution_plan(
            self.capability,
            self.inspection,
            stage=stage,
            stdin_bytes=stdin_bytes,
            run_started_at=run_started_at,
            call_started_at=call_started_at,
        )

    def test_production_gate_rejects_before_argument_or_keyword_inspection(self) -> None:
        self.assertFalse(SBX_EXECUTION_ENABLED)
        with self.assertRaisesRegex(SbxExecutionDisabled, "source-disabled"):
            execute_live_sbx_plan(Explosive(), authority=Explosive())

    def test_fixture_capability_is_explicit_singleton_and_cannot_enable_source(self) -> None:
        self.assertIs(fixture_sbx_execution_capability(), self.capability)
        with self.assertRaisesRegex(SbxExecutionError, "not constructible"):
            FixtureSbxExecutionCapability(object())
        forged = object.__new__(FixtureSbxExecutionCapability)
        forged._secret = object()
        with self.assertRaisesRegex(SbxExecutionError, "capability is invalid"):
            parse_fixture_inspection_attestation(forged, Explosive(), self.expectation)  # type: ignore[arg-type]
        self.assertFalse(SBX_EXECUTION_ENABLED)

    def test_controller_name_is_derived_and_not_caller_selected(self) -> None:
        self.assertRegex(self.controller.name, r"^leftovers-[a-f0-9]{24}$")
        self.assertEqual(self.controller, derive_controller_sandbox_identity(RUN_ID))
        for run_id in ("0" * 32, "0123456789abcdef" * 2, "f" * 32):
            with self.subTest(shared_run_id=run_id):
                self.assertEqual(
                    derive_controller_sandbox_identity(run_id).name,
                    controller_sandbox_name(run_id),
                )
        with self.assertRaisesRegex(SbxExecutionError, "controller-derived"):
            ControllerSandboxIdentity(RUN_ID, "leftovers-" + "0" * 24)
        with patch("leftovers.sbx_execution.controller_sandbox_name") as shared_derivation:
            for run_id in ("A" * 32, "a" * 31, "a" * 33, "g" * 32, 7):
                with self.subTest(run_id=run_id), self.assertRaises(SbxExecutionError):
                    derive_controller_sandbox_identity(run_id)  # type: ignore[arg-type]
            shared_derivation.assert_not_called()

    def test_exact_sbx_identity_and_daemon_generation_are_bound(self) -> None:
        self.assertEqual(PINNED_SBX_IDENTITY.binary, SBX_BINARY)
        self.assertEqual(PINNED_SBX_IDENTITY.version, SBX_VERSION)
        self.assertEqual(PINNED_SBX_IDENTITY.revision, SBX_REVISION)
        self.assertEqual(PINNED_SBX_IDENTITY.sha256, SBX_SHA256)
        self.assertEqual(self.inspection.daemon.opaque_uuid, DAEMON_UUID)
        self.assertEqual(self.inspection.daemon.generation, 7)
        self.assertEqual(self.inspection.daemon.controller_name, self.controller.name)
        self.assertEqual(self.inspection.runtime.codex_executable_path, CODEX_PATH)
        self.assertEqual(self.inspection.runtime.codex_executable_sha256, CODEX_SHA256)
        self.assertEqual(self.inspection.runtime.codex_version, CODEX_VERSION)
        self.assertEqual(self.inspection.runtime.codex_executable_device, CODEX_DEVICE)
        self.assertEqual(self.inspection.runtime.codex_executable_inode, CODEX_INODE)
        self.assertEqual(self.inspection.runtime.codex_executable_owner_uid, CODEX_OWNER_UID)
        self.assertEqual(self.inspection.runtime.codex_executable_owner_gid, CODEX_OWNER_GID)
        self.assertEqual(self.inspection.runtime.codex_executable_mode, CODEX_MODE)
        self.assertEqual(self.inspection.runtime.codex_executable_link_count, CODEX_LINK_COUNT)
        self.assertEqual(self.inspection.runtime.codex_executable_size_bytes, CODEX_SIZE_BYTES)
        self.assertEqual(self.inspection.runtime.codex_executable_mtime_ns, CODEX_MTIME_NS)
        self.assertEqual(self.inspection.runtime.codex_executable_ctime_ns, CODEX_CTIME_NS)
        self.assertEqual(self.inspection.runtime.user_name, USER_NAME)
        self.assertEqual(self.inspection.runtime.user_uid, USER_UID)
        self.assertEqual(self.inspection.runtime.user_gid, USER_GID)
        self.assertEqual(self.inspection.runtime.supplemental_gids, ())
        self.assertEqual(self.inspection.runtime.linux_capabilities, ())
        self.assertEqual(self.inspection.runtime.private_clone_workdir, PRIVATE_CLONE_WORKDIR)
        self.assertEqual(self.inspection.runtime.codex_home, CODEX_HOME)
        self.assertEqual(self.inspection.runtime.auth_mode, AUTH_MODE)
        self.assertFalse(self.inspection.runtime.user_config_loaded)
        self.assertFalse(self.inspection.runtime.repository_rules_loaded)
        self.assertFalse(self.inspection.runtime.hooks_loaded)
        self.assertFalse(SBX_V035_IN_VM_RUNTIME_ATTESTATION_DOCUMENTED)
        self.assertEqual(self.inspection.canonical_sha256, hashlib.sha256(self.raw).hexdigest())
        with self.assertRaisesRegex(SbxExecutionError, "exact pinned release"):
            SbxCliIdentity(binary="/tmp/sbx")

    def test_daemon_identity_and_attestation_are_adapter_sealed(self) -> None:
        with self.assertRaisesRegex(SbxExecutionError, "adapter authority"):
            DaemonSandboxIdentity(DAEMON_UUID, 7, self.controller.name, object())
        forged = object.__new__(DaemonSandboxIdentity)
        object.__setattr__(forged, "opaque_uuid", DAEMON_UUID)
        object.__setattr__(forged, "generation", 7)
        object.__setattr__(forged, "controller_name", self.controller.name)
        object.__setattr__(forged, "_seal", object())
        object.__setattr__(self.inspection, "daemon", forged)
        with self.assertRaisesRegex(SbxExecutionError, "unsealed"):
            fixed_sbx_codex_argv(self.inspection)

    def test_inspection_is_canonical_exact_key_json(self) -> None:
        self.assertEqual(self.render(self.document()), self.raw)
        malformed = (
            b" " + self.raw,
            self.raw + b"\n",
            self.raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":NaN}',
            b"\xff",
            b"x" * (MAX_INSPECTION_BYTES + 1),
            bytearray(self.raw),
        )
        for raw in malformed:
            with self.subTest(raw=bytes(raw[:24])), self.assertRaises(SbxExecutionError):
                parse_fixture_inspection_attestation(  # type: ignore[arg-type]
                    self.capability, raw, self.expectation
                )

    def test_unknown_or_missing_keys_are_rejected_at_every_authority_object(self) -> None:
        paths = (
            (),
            ("sbx_identity",),
            ("sandbox",),
            ("runtime",),
            ("mounts",),
            ("network_policy",),
            ("credential_proxy",),
            ("credential_proxy", "service_capability"),
            ("resource_caps",),
        )
        for path in paths:
            with self.subTest(path=path):
                value = self.document()
                target = value
                for component in path:
                    target = target[component]  # type: ignore[index,assignment]
                target["unknown_authority"] = True  # type: ignore[index]
                with self.assertRaisesRegex(SbxExecutionError, "unknown fields"):
                    self.parse(value)

        for path, key in (
            ((), "ports"),
            (("runtime",), "model"),
            (("credential_proxy", "service_capability"), "name"),
        ):
            with self.subTest(path=path, missing=key):
                value = self.document()
                target = value
                for component in path:
                    target = target[component]  # type: ignore[index,assignment]
                del target[key]  # type: ignore[arg-type]
                with self.assertRaisesRegex(SbxExecutionError, "unknown fields"):
                    self.parse(value)

    def test_sbx_identity_substitution_is_rejected(self) -> None:
        cases = {
            "binary": "/tmp/sbx",
            "version": "v0.35.1",
            "revision": "0" * 40,
            "sha256": "0" * 64,
        }
        for key, replacement in cases.items():
            with self.subTest(key=key):
                value = self.document()
                value["sbx_identity"][key] = replacement  # type: ignore[index]
                with self.assertRaisesRegex(SbxExecutionError, "fixed value"):
                    self.parse(value)

    def test_runtime_and_mount_substitution_is_rejected(self) -> None:
        cases = (
            ("runtime", "agent", "shell"),
            ("runtime", "auth_mode", "host-token"),
            ("runtime", "codex_executable_ctime_ns", CODEX_CTIME_NS + 1),
            ("runtime", "codex_executable_device", CODEX_DEVICE + 1),
            ("runtime", "codex_executable_inode", CODEX_INODE + 1),
            ("runtime", "codex_executable_link_count", 2),
            ("runtime", "codex_executable_mode", 0o100555),
            ("runtime", "codex_executable_mtime_ns", CODEX_MTIME_NS + 1),
            ("runtime", "codex_executable_owner_gid", 1),
            ("runtime", "codex_executable_owner_uid", 1),
            ("runtime", "codex_executable_path", "/opt/other/codex"),
            ("runtime", "codex_executable_sha256", "e" * 64),
            ("runtime", "codex_executable_size_bytes", CODEX_SIZE_BYTES + 1),
            ("runtime", "codex_home", "/home/agent/.other-codex"),
            ("runtime", "codex_version", "0.146.0"),
            ("runtime", "hooks_loaded", True),
            ("runtime", "linux_capabilities", ["CAP_NET_RAW"]),
            ("runtime", "model", "gpt-5.6"),
            ("runtime", "private_clone_workdir", "/home/agent/other"),
            ("runtime", "reasoning_effort", "medium"),
            ("runtime", "repository_rules_loaded", True),
            ("runtime", "supplemental_gids", [1001]),
            ("runtime", "user_config_loaded", True),
            ("runtime", "user_gid", 1001),
            ("runtime", "user_name", "worker"),
            ("runtime", "user_uid", 1001),
            ("mounts", "clone_mode", "bind"),
            ("mounts", "source_mode", "read-write"),
            ("mounts", "workspace_mode", "host-bind-read-write"),
            ("mounts", "workspace_count", 2),
            ("mounts", "workspace_count", True),
        )
        for section, key, replacement in cases:
            with self.subTest(section=section, key=key):
                value = self.document()
                value[section][key] = replacement  # type: ignore[index]
                with self.assertRaisesRegex(SbxExecutionError, "fixed value"):
                    self.parse(value)

    def test_runtime_expectation_rejects_root_relative_and_unowned_values(self) -> None:
        base = {
            "codex_executable_path": CODEX_PATH,
            "codex_executable_sha256": CODEX_SHA256,
            "codex_version": CODEX_VERSION,
            "codex_executable_device": CODEX_DEVICE,
            "codex_executable_inode": CODEX_INODE,
            "codex_executable_owner_uid": CODEX_OWNER_UID,
            "codex_executable_owner_gid": CODEX_OWNER_GID,
            "codex_executable_mode": CODEX_MODE,
            "codex_executable_link_count": CODEX_LINK_COUNT,
            "codex_executable_size_bytes": CODEX_SIZE_BYTES,
            "codex_executable_mtime_ns": CODEX_MTIME_NS,
            "codex_executable_ctime_ns": CODEX_CTIME_NS,
            "user_name": USER_NAME,
            "user_uid": USER_UID,
            "user_gid": USER_GID,
            "supplemental_gids": SUPPLEMENTAL_GIDS,
            "linux_capabilities": LINUX_CAPABILITIES,
            "private_clone_workdir": PRIVATE_CLONE_WORKDIR,
            "codex_home": CODEX_HOME,
            "auth_mode": AUTH_MODE,
            "user_config_loaded": False,
            "repository_rules_loaded": False,
            "hooks_loaded": False,
        }
        cases = (
            ("codex_executable_path", "usr/bin/codex"),
            ("codex_executable_path", PRIVATE_CLONE_WORKDIR + "/codex"),
            ("codex_executable_sha256", "not-a-digest"),
            ("codex_version", "latest"),
            ("codex_executable_device", 0),
            ("codex_executable_device", True),
            ("codex_executable_inode", 0),
            ("codex_executable_owner_uid", USER_UID),
            ("codex_executable_owner_gid", USER_GID),
            ("codex_executable_mode", 0o120777),
            ("codex_executable_mode", 0o100775),
            ("codex_executable_mode", 0o104755),
            ("codex_executable_mode", 0o100644),
            ("codex_executable_link_count", 2),
            ("codex_executable_size_bytes", 0),
            ("codex_executable_size_bytes", 512 * 1024 * 1024 + 1),
            ("codex_executable_mtime_ns", -1),
            ("codex_executable_ctime_ns", True),
            ("user_name", "root"),
            ("user_uid", 0),
            ("user_uid", True),
            ("user_gid", 0),
            ("user_gid", True),
            ("supplemental_gids", (1001,)),
            ("supplemental_gids", []),
            ("linux_capabilities", ("CAP_NET_RAW",)),
            ("linux_capabilities", []),
            ("private_clone_workdir", "/home/other/workspace"),
            ("private_clone_workdir", "/home/agent/../other"),
            ("codex_home", PRIVATE_CLONE_WORKDIR + "/.codex"),
            ("codex_home", "/home/agent/.other-codex"),
            ("auth_mode", "host-token"),
            ("user_config_loaded", True),
            ("user_config_loaded", 0),
            ("repository_rules_loaded", True),
            ("hooks_loaded", True),
        )
        for field_name, replacement in cases:
            with self.subTest(field_name=field_name, replacement=replacement):
                values = dict(base)
                values[field_name] = replacement
                with self.assertRaises(SbxExecutionError):
                    InVmRuntimeExpectation(**values)  # type: ignore[arg-type]

    def test_daemon_identity_cannot_be_replaced_by_name_uuid_or_generation(self) -> None:
        cases = (
            ("controller_name", "leftovers-" + "0" * 24),
            ("daemon_uuid", "00000000-0000-0000-0000-000000000000"),
            ("daemon_uuid", DAEMON_UUID.upper()),
            ("daemon_uuid", "not-a-uuid"),
            ("generation", 0),
            ("generation", -1),
            ("generation", True),
            ("generation", 1 << 63),
        )
        for key, replacement in cases:
            with self.subTest(key=key, replacement=replacement):
                value = self.document()
                value["sandbox"][key] = replacement  # type: ignore[index]
                with self.assertRaises(SbxExecutionError):
                    self.parse(value)

    def test_policy_and_secret_epochs_bind_the_controller_expectation(self) -> None:
        for section in ("network_policy", "credential_proxy"):
            with self.subTest(section=section):
                value = self.document()
                value[section]["epoch_sha256"] = "d" * 64  # type: ignore[index]
                with self.assertRaisesRegex(SbxExecutionError, "epoch"):
                    self.parse(value)
        with self.assertRaisesRegex(SbxExecutionError, "domain-separated"):
            InspectionExpectation(self.controller, self.runtime, POLICY_EPOCH, POLICY_EPOCH)

    def test_credentials_are_exactly_openai_service_without_side_channels(self) -> None:
        cases = (
            (("service_capability", "name"), "github"),
            (("service_capability", "scope"), "sandbox"),
            (("service_capability", "type"), "environment"),
            (("environment_bytes_present",), True),
            (("github_capability_present",), True),
            (("ssh_agent_present",), True),
        )
        for path, replacement in cases:
            with self.subTest(path=path):
                value = self.document()
                target = value["credential_proxy"]  # type: ignore[assignment]
                for component in path[:-1]:
                    target = target[component]  # type: ignore[index,assignment]
                target[path[-1]] = replacement  # type: ignore[index]
                with self.assertRaisesRegex(SbxExecutionError, "fixed value"):
                    self.parse(value)

        value = self.document()
        value["credential_proxy"]["secret_bytes"] = "sk-not-allowed"  # type: ignore[index]
        with self.assertRaisesRegex(SbxExecutionError, "unknown fields"):
            self.parse(value)

    def test_ports_and_resource_substitution_are_rejected(self) -> None:
        values = (
            ("ports", [8080]),
            ("ports", {}),
            ("cpus", CPU_CAP + 1),
            ("cpus", True),
            ("memory_bytes", MEMORY_CAP_BYTES + 1),
        )
        for key, replacement in values:
            with self.subTest(key=key):
                value = self.document()
                if key == "ports":
                    value[key] = replacement
                else:
                    value["resource_caps"][key] = replacement  # type: ignore[index]
                with self.assertRaisesRegex(SbxExecutionError, "fixed value"):
                    self.parse(value)

    def test_stage_call_token_output_and_deadline_bounds_are_fixed(self) -> None:
        self.assertEqual(MAX_MODEL_CALLS, 3)
        self.assertEqual(RUN_TOKEN_CAP, 55_000)
        self.assertEqual(CREATE_TIMEOUT_SECONDS, 300)
        self.assertEqual(CLEANUP_TIMEOUT_SECONDS, 120)
        self.assertEqual(LIFECYCLE_TIMEOUT_SECONDS, 2_700)
        self.assertEqual(
            tuple(item.stage for item in STAGE_LIMITS),
            tuple(ExecutionStage),
        )
        expected = {
            ExecutionStage.PLANNING: (0, 360, 8_000, 2_000, 10_000, 32 * 1024),
            ExecutionStage.IMPLEMENTATION: (1, 1_200, 25_000, 10_000, 35_000, 64 * 1024),
            ExecutionStage.VERIFICATION: (2, 480, 8_000, 2_000, 10_000, 32 * 1024),
        }
        for stage, limits in expected.items():
            with self.subTest(stage=stage):
                plan = self.plan(stage=stage, call_started_at=NOW)
                self.assertEqual(
                    (
                        plan.call_index,
                        plan.limits.timeout_seconds,
                        plan.limits.input_token_cap,
                        plan.limits.output_token_cap,
                        plan.limits.total_token_cap,
                        plan.limits.combined_output_bytes,
                    ),
                    limits,
                )
                self.assertEqual(
                    plan.call_deadline_at,
                    NOW + timedelta(seconds=plan.limits.timeout_seconds),
                )
                self.assertEqual(
                    plan.cleanup_must_start_by,
                    NOW + timedelta(seconds=LIFECYCLE_TIMEOUT_SECONDS - CLEANUP_TIMEOUT_SECONDS),
                )

    def test_each_stage_enforces_its_conservative_stdin_boundary(self) -> None:
        largest = 0
        for stage in ExecutionStage:
            with self.subTest(stage=stage):
                limits = next(item for item in STAGE_LIMITS if item.stage is stage)
                byte_cap = limits.input_token_cap - CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE
                largest = max(largest, byte_cap)
                accepted = b"x" * (byte_cap - 1) + b"\n"
                plan = self.plan(stage=stage, stdin_bytes=accepted, call_started_at=NOW)
                self.assertEqual(plan.stdin_byte_cap, byte_cap)
                self.assertEqual(len(plan.stdin_bytes), byte_cap)
                self.assertEqual(
                    plan.conservative_input_token_admission,
                    limits.input_token_cap,
                )

                rejected = b"x" * byte_cap + b"\n"
                with self.assertRaisesRegex(SbxExecutionError, "input-token admission cap"):
                    self.plan(stage=stage, stdin_bytes=rejected, call_started_at=NOW)
        self.assertEqual(MAX_STDIN_BYTES, largest)

    def test_token_caps_are_local_admission_and_receipt_guards_only(self) -> None:
        self.assertEqual(CONSERVATIVE_CONTROLLER_CONTEXT_TOKEN_RESERVE, 4_096)
        self.assertFalse(TOKEN_CAPS_PROVIDER_ENFORCED)
        self.assertTrue(TOKEN_CAPS_REQUIRE_POST_CALL_RECEIPT)

    def test_late_call_is_clamped_to_cleanup_reserve_and_reserve_is_unavailable(self) -> None:
        cleanup_start = NOW + timedelta(seconds=LIFECYCLE_TIMEOUT_SECONDS - CLEANUP_TIMEOUT_SECONDS)
        call_start = cleanup_start - timedelta(seconds=1)
        plan = self.plan(call_started_at=call_start)
        self.assertEqual(plan.call_deadline_at, cleanup_start)
        with self.assertRaisesRegex(SbxExecutionError, "cleanup reserve"):
            self.plan(call_started_at=cleanup_start)

    def test_invocation_argv_is_computed_fixed_and_issue_text_is_stdin_only(self) -> None:
        marker = b"ISSUE_MARKER_8f61"
        plan = self.plan(stdin_bytes=marker + b": never place this in argv.\n")
        self.assertEqual(plan.model, MODEL)
        self.assertEqual(plan.reasoning_effort, REASONING_EFFORT)
        self.assertEqual(plan.argv, fixed_sbx_codex_argv(self.inspection))
        self.assertEqual(
            plan.argv,
            (
                SBX_BINARY,
                "exec",
                "-i",
                "--user",
                f"{USER_UID}:{USER_GID}",
                "--workdir",
                PRIVATE_CLONE_WORKDIR,
                self.controller.name,
                CODEX_PATH,
                "exec",
                "--strict-config",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--disable",
                "hooks",
                "--model",
                MODEL,
                "-c",
                'model_reasoning_effort="high"',
                "-c",
                'model_verbosity="low"',
                "-c",
                'approval_policy="never"',
                "-c",
                "allow_login_shell=false",
                "-c",
                'shell_environment_policy.inherit="none"',
                "--sandbox",
                "workspace-write",
                "--color",
                "never",
                "--json",
                "-",
            ),
        )
        self.assertNotIn(marker.decode(), "\0".join(plan.argv))
        self.assertEqual(hashlib.sha256(plan.stdin_bytes).hexdigest(), plan.stdin_sha256)
        self.assertRegex(plan.attestation_sha256, r"^[a-f0-9]{64}$")

    def test_exec_cannot_create_and_exposes_no_dangerous_sbx_exec_flags(self) -> None:
        argv = self.plan().argv
        self.assertEqual(argv[1], "exec")
        self.assertNotIn("run", argv)
        self.assertFalse(SBX_EXEC_ID_TARGETING_DOCUMENTED)
        self.assertFalse(SBX_EXEC_NAME_BINDING_ATOMIC)
        self.assertEqual(argv.count("-i"), 1)
        self.assertEqual(argv.count("--user"), 1)
        self.assertEqual(argv.count("--workdir"), 1)
        self.assertEqual(argv[argv.index("--user") + 1], f"{USER_UID}:{USER_GID}")
        self.assertEqual(argv[argv.index("--disable") + 1], "hooks")

        create_or_run_flags = {
            "--clone",
            "--cpus",
            "--kit",
            "--memory",
            "--name",
            "--profile",
            "--template",
        }
        dangerous_exec_flags = {
            "-d",
            "-e",
            "-t",
            "--detach",
            "--detach-keys",
            "--dangerously-bypass-approvals-and-sandbox",
            "--env",
            "--env-file",
            "--privileged",
            "--tty",
        }
        self.assertTrue(create_or_run_flags.isdisjoint(argv))
        self.assertTrue(dangerous_exec_flags.isdisjoint(argv))

    def test_plan_exposes_no_generic_authority_fields(self) -> None:
        names = {item.name for item in fields(SbxExecutionPlan)}
        forbidden = {
            "command",
            "environment",
            "env",
            "template",
            "kit",
            "profile",
            "port",
            "ports",
            "workspace",
            "workspaces",
            "extra_workspace",
            "extra_workspaces",
            "credential",
            "credentials",
            "github_token",
            "ssh_agent",
        }
        self.assertTrue(names.isdisjoint(forbidden))
        self.assertFalse(hasattr(self.plan(), "__dict__"))

    def test_stdin_is_bounded_utf8_immutable_and_framed(self) -> None:
        invalid = (
            b"",
            b"no final newline",
            b"nul\0byte\n",
            b"\xff\n",
            b"x" * MAX_STDIN_BYTES + b"\n",
            bytearray(b"mutable\n"),
        )
        for value in invalid:
            with self.subTest(value=bytes(value[:12])), self.assertRaises(SbxExecutionError):
                self.plan(stdin_bytes=value)  # type: ignore[arg-type]
        bounded = self.plan(stdin_bytes=b"x" * (MAX_STDIN_BYTES - 1) + b"\n")
        self.assertEqual(len(bounded.stdin_bytes), MAX_STDIN_BYTES)

    def test_time_and_stage_inputs_are_strict(self) -> None:
        with self.assertRaisesRegex(SbxExecutionError, "timezone-aware"):
            self.plan(run_started_at=NOW.replace(tzinfo=None))
        with self.assertRaisesRegex(SbxExecutionError, "before its run"):
            self.plan(call_started_at=NOW - timedelta(seconds=1))
        with self.assertRaisesRegex(SbxExecutionError, "stage"):
            build_fixture_execution_plan(
                self.capability,
                self.inspection,
                stage="implementation",  # type: ignore[arg-type]
                stdin_bytes=b"bounded\n",
                run_started_at=NOW,
                call_started_at=NOW,
            )

    def test_stored_plan_tampering_is_detected(self) -> None:
        mutations = (
            ("call_index", 0),
            ("stdin_bytes", b"replaced\n"),
            ("stdin_sha256", "0" * 64),
            ("call_deadline_at", NOW + timedelta(days=1)),
            ("cleanup_must_start_by", NOW + timedelta(days=1)),
            ("lifecycle_deadline_at", NOW + timedelta(days=1)),
            ("_seal", object()),
        )
        for field_name, replacement in mutations:
            with self.subTest(field_name=field_name):
                plan = self.plan()
                object.__setattr__(plan, field_name, replacement)
                with self.assertRaises(SbxExecutionError):
                    validate_fixture_execution_plan(plan)

        planning = self.plan(stage=ExecutionStage.PLANNING, call_started_at=NOW)
        oversized = b"x" * planning.stdin_byte_cap + b"\n"
        object.__setattr__(planning, "stdin_bytes", oversized)
        object.__setattr__(planning, "stdin_sha256", hashlib.sha256(oversized).hexdigest())
        with self.assertRaisesRegex(SbxExecutionError, "input-token admission cap"):
            validate_fixture_execution_plan(planning)

    def test_attested_fields_cannot_drift_from_canonical_daemon_document(self) -> None:
        mutations = (
            ("policy_epoch_sha256", "d" * 64),
            ("secret_epoch_sha256", "e" * 64),
            ("canonical_sha256", "f" * 64),
        )
        for field_name, replacement in mutations:
            with self.subTest(field_name=field_name):
                inspection = parse_fixture_inspection_attestation(
                    self.capability, self.raw, self.expectation
                )
                object.__setattr__(inspection, field_name, replacement)
                with self.assertRaises(SbxExecutionError):
                    fixed_sbx_codex_argv(inspection)

        inspection = parse_fixture_inspection_attestation(
            self.capability, self.raw, self.expectation
        )
        object.__setattr__(inspection.daemon, "generation", 8)
        with self.assertRaisesRegex(SbxExecutionError, "canonical daemon document"):
            fixed_sbx_codex_argv(inspection)

    def test_runtime_identity_mutation_invalidates_attestation_and_plan(self) -> None:
        mutations = (
            ("codex_executable_path", "/opt/alternate/bin/codex"),
            ("codex_executable_sha256", "e" * 64),
            ("codex_version", "0.145.0-alpha.19"),
            ("codex_executable_device", CODEX_DEVICE + 1),
            ("codex_executable_inode", CODEX_INODE + 1),
            ("codex_executable_owner_uid", 1),
            ("codex_executable_owner_gid", 1),
            ("codex_executable_mode", 0o100555),
            ("codex_executable_link_count", 2),
            ("codex_executable_size_bytes", CODEX_SIZE_BYTES + 1),
            ("codex_executable_mtime_ns", CODEX_MTIME_NS + 1),
            ("codex_executable_ctime_ns", CODEX_CTIME_NS + 1),
            ("user_name", "worker"),
            ("user_uid", 1001),
            ("user_gid", 1001),
            ("supplemental_gids", (1001,)),
            ("linux_capabilities", ("CAP_NET_RAW",)),
            ("private_clone_workdir", "/home/agent/alternate"),
            ("codex_home", "/home/agent/.other-codex"),
            ("auth_mode", "host-token"),
            ("user_config_loaded", True),
            ("repository_rules_loaded", True),
            ("hooks_loaded", True),
        )
        for field_name, replacement in mutations:
            with self.subTest(field_name=field_name):
                runtime = InVmRuntimeExpectation(
                    codex_executable_path=CODEX_PATH,
                    codex_executable_sha256=CODEX_SHA256,
                    codex_version=CODEX_VERSION,
                    codex_executable_device=CODEX_DEVICE,
                    codex_executable_inode=CODEX_INODE,
                    codex_executable_owner_uid=CODEX_OWNER_UID,
                    codex_executable_owner_gid=CODEX_OWNER_GID,
                    codex_executable_mode=CODEX_MODE,
                    codex_executable_link_count=CODEX_LINK_COUNT,
                    codex_executable_size_bytes=CODEX_SIZE_BYTES,
                    codex_executable_mtime_ns=CODEX_MTIME_NS,
                    codex_executable_ctime_ns=CODEX_CTIME_NS,
                    user_name=USER_NAME,
                    user_uid=USER_UID,
                    user_gid=USER_GID,
                    supplemental_gids=SUPPLEMENTAL_GIDS,
                    linux_capabilities=LINUX_CAPABILITIES,
                    private_clone_workdir=PRIVATE_CLONE_WORKDIR,
                    codex_home=CODEX_HOME,
                    auth_mode=AUTH_MODE,
                    user_config_loaded=False,
                    repository_rules_loaded=False,
                    hooks_loaded=False,
                )
                expectation = InspectionExpectation(
                    self.controller,
                    runtime,
                    POLICY_EPOCH,
                    SECRET_EPOCH,
                )
                raw = canonical_fixture_inspection_document(
                    self.capability,
                    expectation,
                    daemon_uuid=DAEMON_UUID,
                    generation=7,
                )
                inspection = parse_fixture_inspection_attestation(self.capability, raw, expectation)
                plan = build_fixture_execution_plan(
                    self.capability,
                    inspection,
                    stage=ExecutionStage.IMPLEMENTATION,
                    stdin_bytes=b"bounded\n",
                    run_started_at=NOW,
                    call_started_at=NOW,
                )
                object.__setattr__(inspection.runtime, field_name, replacement)
                with self.assertRaises(SbxExecutionError):
                    fixed_sbx_codex_argv(inspection)
                with self.assertRaises(SbxExecutionError):
                    validate_fixture_execution_plan(plan)


if __name__ == "__main__":
    unittest.main()
