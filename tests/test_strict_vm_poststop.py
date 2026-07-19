from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from leftovers.strict_vm_cycle import CyclePlan, patch_sha256
from leftovers.strict_vm_poststop import (
    STRICT_VM_POSTSTOP_ENABLED,
    BoundedCommandResult,
    FixturePostStopCapability,
    OfflineCheckSpec,
    PostStopPlan,
    PostStopVerificationError,
    StrictVMPostStopDisabled,
    _run_bounded,
    fixture_post_stop_capability,
    read_nofollow_artifact,
    verify_post_stop,
    verify_post_stop_fixture,
)

NOW = datetime(2026, 7, 19, tzinfo=UTC)
RUN_ID = "a" * 32
BASE_POLICY = "b" * 64
REQUEST = "c" * 64
MEDIATOR = "d" * 64
PATCH = (
    b"diff --git a/file.txt b/file.txt\n"
    b"index 7473def..a214ad8 100644\n"
    b"--- a/file.txt\n"
    b"+++ b/file.txt\n"
    b"@@ -1 +1 @@\n"
    b"-before\n"
    b"+after\n"
)


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        + b"\n"
    )


def git(*argv: str, cwd: Path) -> str:
    completed = subprocess.run(
        ("/usr/bin/git", *argv),
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


class RecordingOfflineExecutor:
    def __init__(self, callback=None) -> None:
        self.calls: list[OfflineCheckSpec] = []
        self.callback = callback

    def run(self, spec: OfflineCheckSpec, *, cwd: Path) -> BoundedCommandResult:
        self.calls.append(spec)
        if self.callback is not None:
            self.callback(cwd)
        return BoundedCommandResult(0, False, False, hashlib.sha256(b"ok").hexdigest())


class StrictVMPostStopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        git("init", "--initial-branch=main", cwd=self.source)
        git("config", "user.email", "test@example.invalid", cwd=self.source)
        git("config", "user.name", "Leftovers test", cwd=self.source)
        (self.source / "file.txt").write_text("before\n", encoding="utf-8")
        git("add", "file.txt", cwd=self.source)
        git("commit", "-m", "base", cwd=self.source)
        self.base = git("rev-parse", "HEAD", cwd=self.source)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.verification = self.root / "verify"
        self.verification.mkdir(mode=0o700)
        self.executor = RecordingOfflineExecutor()
        self.write_artifacts()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def cycle(self, **changes: object) -> CyclePlan:
        values: dict[str, object] = {
            "run_id": RUN_ID,
            "repository": "owner/repo",
            "issue_number": 1,
            "base_ref": "main",
            "base_sha": self.base,
            "policy_sha256": BASE_POLICY,
            "required_check_ids": ("lint",),
            "max_rounds": 1,
            "token_cap": 100,
            "deadline_at": NOW + timedelta(minutes=5),
        }
        values.update(changes)
        return CyclePlan(**values)  # type: ignore[arg-type]

    def plan(self, **changes: object) -> PostStopPlan:
        values: dict[str, object] = {
            "cycle": self.cycle(),
            "epoch": 0,
            "request_sha256": REQUEST,
            "mediator_receipt_sha256": MEDIATOR,
            "source_repository": self.source,
            "checks": (OfflineCheckSpec("lint", ("/usr/bin/true",), 10),),
            "forbidden_path_prefixes": (".github/workflows/", "secrets/"),
        }
        values.update(changes)
        return PostStopPlan(**values)  # type: ignore[arg-type]

    def write_artifacts(
        self, *, patch: bytes = PATCH, cleanup_changes: dict[str, object] | None = None
    ) -> None:
        cleanup: dict[str, object] = {
            "epoch": 0,
            "kind": "leftovers.strict-vm.cleanup.v1",
            "launcher_stop_proven": True,
            "resources_removed": True,
            "run_id": RUN_ID,
            "vm_stopped": True,
        }
        if cleanup_changes:
            cleanup.update(cleanup_changes)
        cleanup_raw = canonical(cleanup)
        result = {
            "cleanup_sha256": hashlib.sha256(cleanup_raw).hexdigest(),
            "epoch": 0,
            "kind": "leftovers.strict-vm.poststop-result.v1",
            "launcher_stop_proven": True,
            "mediator_receipt_sha256": MEDIATOR,
            "patch_sha256": patch_sha256(patch),
            "request_sha256": REQUEST,
            "result_extracted_after_stop": True,
            "run_id": RUN_ID,
        }
        (self.artifacts / "cleanup.json").write_bytes(cleanup_raw)
        (self.artifacts / "result.json").write_bytes(canonical(result))
        (self.artifacts / "canonical.patch").write_bytes(patch)

    def verify(self, *, plan: PostStopPlan | None = None, executor=None):
        return verify_post_stop_fixture(
            self.plan() if plan is None else plan,
            artifact_root=self.artifacts,
            verification_root=self.verification,
            executor=self.executor if executor is None else executor,
            fixture_capability=fixture_post_stop_capability(),
        )

    def test_source_gate_stays_false_and_happy_receipt_is_cleanup_bound(self) -> None:
        self.assertFalse(STRICT_VM_POSTSTOP_ENABLED)
        with self.assertRaisesRegex(StrictVMPostStopDisabled, "before filesystem or process"):
            verify_post_stop(
                self.plan(),
                artifact_root=Path("/definitely/missing/artifacts"),
                verification_root=Path("/definitely/missing/verification"),
            )
        receipt = self.verify()
        self.assertTrue(receipt.verification_clone_removed)
        self.assertEqual(receipt.patch_sha256, patch_sha256(PATCH))
        self.assertEqual(receipt.base_sha_before, self.base)
        self.assertEqual(receipt.base_sha_after, self.base)
        self.assertEqual(tuple(item.check_id for item in receipt.checks), ("lint",))
        self.assertEqual([item.argv for item in self.executor.calls], [("/usr/bin/true",)])
        self.assertEqual(list(self.verification.iterdir()), [])

    def test_default_executor_refuses_unattested_host_execution_and_cleans_clone(self) -> None:
        with self.assertRaisesRegex(
            PostStopVerificationError, "no-network post-stop check executor"
        ):
            verify_post_stop_fixture(
                self.plan(),
                artifact_root=self.artifacts,
                verification_root=self.verification,
                executor=None,
                fixture_capability=fixture_post_stop_capability(),
            )
        self.assertEqual(list(self.verification.iterdir()), [])

    def test_clone_open_failure_rolls_back_the_created_directory(self) -> None:
        real_open = os.open

        def fail_clone_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            if isinstance(path, str) and path.startswith("leftovers-poststop-"):
                raise OSError("injected clone open failure")
            return real_open(path, flags, *args, **kwargs)

        with (
            mock.patch("leftovers.strict_vm_poststop.os.open", side_effect=fail_clone_open),
            self.assertRaisesRegex(PostStopVerificationError, "clone cannot be opened"),
        ):
            self.verify()
        self.assertEqual(list(self.verification.iterdir()), [])

    def test_fixture_api_rejects_caller_constructed_capability(self) -> None:
        with self.assertRaisesRegex(PostStopVerificationError, "not constructible"):
            FixturePostStopCapability(object())

    def test_artifact_reader_rejects_symlink_and_hardlink_toctou_substitutions(self) -> None:
        target = self.artifacts / "target"
        target.write_bytes(b"safe")
        os.symlink(target.name, self.artifacts / "result-link")
        with self.assertRaisesRegex(PostStopVerificationError, "following links"):
            read_nofollow_artifact(self.artifacts, "result-link", maximum_bytes=64)
        os.link(target, self.artifacts / "result-hardlink")
        with self.assertRaisesRegex(PostStopVerificationError, "unaliased"):
            read_nofollow_artifact(self.artifacts, "result-hardlink", maximum_bytes=64)

    def test_trusted_root_rejects_untrusted_parent_permissions(self) -> None:
        os.chmod(self.root, 0o770)
        try:
            with self.assertRaisesRegex(PostStopVerificationError, "parent.*writable"):
                read_nofollow_artifact(self.artifacts, "result.json", maximum_bytes=16 * 1024)
        finally:
            os.chmod(self.root, 0o700)

    def test_malformed_and_deep_result_json_are_rejected(self) -> None:
        (self.artifacts / "result.json").write_bytes(b"not-json\n")
        with self.assertRaisesRegex(PostStopVerificationError, "valid JSON"):
            self.verify()
        nested = "[" * 18 + "0" + "]" * 18
        (self.artifacts / "result.json").write_text(nested, encoding="utf-8")
        with self.assertRaisesRegex(PostStopVerificationError, "depth cap"):
            self.verify()
        for invalid_number in ("0.0", "NaN", "Infinity"):
            with self.subTest(invalid_number=invalid_number):
                (self.artifacts / "result.json").write_text(
                    '{"epoch":' + invalid_number + "}\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(PostStopVerificationError, "finite integer"):
                    self.verify()

    def test_epoch_requires_exact_integer_not_boolean(self) -> None:
        result = json.loads((self.artifacts / "result.json").read_text(encoding="utf-8"))
        result["epoch"] = False
        (self.artifacts / "result.json").write_bytes(canonical(result))
        with self.assertRaisesRegex(PostStopVerificationError, "identity types"):
            self.verify()

    def test_result_exact_identity_and_cleanup_binding_are_mandatory(self) -> None:
        result = json.loads((self.artifacts / "result.json").read_text(encoding="utf-8"))
        result["mediator_receipt_sha256"] = "e" * 64
        (self.artifacts / "result.json").write_bytes(canonical(result))
        with self.assertRaisesRegex(PostStopVerificationError, "mediator identity"):
            self.verify()
        self.write_artifacts()
        result = json.loads((self.artifacts / "result.json").read_text(encoding="utf-8"))
        result["cleanup_sha256"] = "f" * 64
        (self.artifacts / "result.json").write_bytes(canonical(result))
        with self.assertRaisesRegex(PostStopVerificationError, "not bound"):
            self.verify()

    def test_patch_escape_mode_and_secret_policy_fail_before_checks(self) -> None:
        escape = PATCH.replace(b"a/file.txt b/file.txt", b"a/../escape b/../escape")
        self.write_artifacts(patch=escape)
        with self.assertRaisesRegex(PostStopVerificationError, "path escape"):
            self.verify()
        mode = PATCH.replace(
            b"index 7473def..a214ad8 100644\n",
            b"old mode 100644\nnew mode 100755\nindex 7473def..a214ad8\n",
        )
        self.write_artifacts(patch=mode)
        with self.assertRaisesRegex(PostStopVerificationError, "unsafe destination mode"):
            self.verify()
        secret = PATCH.replace(b"+after", b"+ghp_abcdefghijklmnopqrstuvwxyz1234567890")
        self.write_artifacts(patch=secret)
        with self.assertRaisesRegex(PostStopVerificationError, "secret-like"):
            self.verify()
        self.assertEqual(self.executor.calls, [])

    def test_check_registry_substitution_and_failures_are_rejected(self) -> None:
        with self.assertRaisesRegex(PostStopVerificationError, "exactly match"):
            self.plan(checks=(OfflineCheckSpec("other", ("/usr/bin/true",), 10),))

        class FailedExecutor:
            def run(self, spec: OfflineCheckSpec, *, cwd: Path) -> BoundedCommandResult:
                del spec, cwd
                return BoundedCommandResult(1, False, False, hashlib.sha256(b"failed").hexdigest())

        with self.assertRaisesRegex(PostStopVerificationError, "did not succeed"):
            self.verify(executor=FailedExecutor())

    def test_stale_base_is_rechecked_immediately_after_checks(self) -> None:
        def advance_base(_cwd: Path) -> None:
            (self.source / "file.txt").write_text("new base\n", encoding="utf-8")
            git("add", "file.txt", cwd=self.source)
            git("commit", "-m", "advance", cwd=self.source)

        with self.assertRaisesRegex(PostStopVerificationError, "immediately before handoff"):
            self.verify(executor=RecordingOfflineExecutor(advance_base))

    def test_cleanup_failure_has_no_receipt(self) -> None:
        self.write_artifacts(cleanup_changes={"resources_removed": False})
        with self.assertRaisesRegex(PostStopVerificationError, "cleanup proof"):
            self.verify()

    def test_source_artifact_and_verification_root_swaps_are_rejected(self) -> None:
        cases = ("source", "artifacts", "verification")
        for target_name in cases:
            with self.subTest(target_name=target_name):
                # Rebuild because each case deliberately replaces one live root.
                if target_name != cases[0]:
                    self.tearDown()
                    self.setUp()
                target = getattr(self, target_name)
                moved = target.with_name(f"{target.name}-moved")

                def swap(_cwd: Path, *, target=target, moved=moved) -> None:
                    target.rename(moved)
                    os.symlink(moved.name, target)

                with self.assertRaisesRegex(
                    PostStopVerificationError, f"{target_name.rstrip('s')}.*identity"
                ):
                    self.verify(executor=RecordingOfflineExecutor(swap))

    def test_escaped_setsid_pipe_holder_cannot_consume_declared_timeout(self) -> None:
        script = (
            "import os,time\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            " os.setsid()\n"
            " time.sleep(1.0)\n"
            " os._exit(0)\n"
            "os._exit(0)\n"
        )
        started = time.monotonic()
        result = _run_bounded((sys.executable, "-c", script), cwd=self.root, timeout_seconds=30)
        elapsed = time.monotonic() - started
        self.assertTrue(result.timed_out)
        self.assertLess(elapsed, 2.0)

    def test_escaped_setsid_output_flood_closes_capture_within_grace(self) -> None:
        script = (
            "import os\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            " os.setsid()\n"
            " while True: os.write(1,b'x'*4096)\n"
            "os._exit(0)\n"
        )
        started = time.monotonic()
        result = _run_bounded((sys.executable, "-c", script), cwd=self.root, timeout_seconds=30)
        elapsed = time.monotonic() - started
        self.assertTrue(result.truncated)
        self.assertLess(elapsed, 2.0)
