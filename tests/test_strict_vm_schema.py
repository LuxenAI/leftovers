from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA_PATH = ROOT / "schemas" / "strict-vm-manifest.schema.json"
RECEIPT_SCHEMA_PATH = ROOT / "schemas" / "strict-vm-receipt.schema.json"
EVIDENCE_PATH = ROOT / "vm" / "evidence" / "2026-07-18-live-smoke.json"
JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None


def valid_guest_stopped_receipt() -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema_version": 2,
        "launcher_version": "0.3.0-proof",
        "manifest_sha256": "b" * 64,
        "run_id": "b" * 32,
        "mode": "run",
        "status": "guest_stopped",
        "started_at": "2026-07-18T23:09:12.213Z",
        "finished_at": "2026-07-18T23:09:12.403Z",
        "config_validated": True,
        "stop_reason": "guest_shutdown",
        "limits": {
            "cpu_count": 1,
            "memory_bytes": 512 * 1024 * 1024,
            "wall_time_seconds": 60,
            "scratch_bytes": 64 * 1024 * 1024,
        },
        "artifacts": {
            "kernel_sha256": digest,
            "initrd_sha256": digest,
            "root_disk_sha256": digest,
            "request_disk_sha256": None,
        },
        "devices": {
            "platform": "generic",
            "boot_loader": "linux",
            "network_devices": 0,
            "socket_devices": 0,
            "directory_shares": 0,
            "serial_ports": 0,
            "console_devices": 0,
            "graphics_devices": 0,
            "audio_devices": 0,
            "usb_controllers": 0,
            "keyboards": 0,
            "pointing_devices": 0,
            "entropy_devices": 0,
            "memory_balloon_devices": 0,
            "storage_devices": [
                {
                    "role": "root",
                    "kind": "virtio-block",
                    "read_only": True,
                    "size_bytes": 1024 * 1024,
                },
                {
                    "role": "scratch",
                    "kind": "virtio-block",
                    "read_only": False,
                    "size_bytes": 64 * 1024 * 1024,
                },
            ],
        },
        "scratch_retained": True,
        "error_code": None,
    }


def valid_manifest() -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema_version": 2,
        "run_id": "b" * 32,
        "boot_artifact_directory": "/private/var/leftovers/boot",
        "run_directory": "/private/var/leftovers/runs/" + ("b" * 32),
        "kernel": {"path": "/private/var/leftovers/boot/kernel", "sha256": digest},
        "initrd": {"path": "/private/var/leftovers/boot/initrd", "sha256": digest},
        "root_disk": {"path": "/private/var/leftovers/boot/root.raw", "sha256": digest},
        "request_disk": {
            "path": "/private/var/leftovers/runs/" + ("b" * 32) + "/request.raw",
            "sha256": digest,
        },
        "scratch_disk": {
            "path": "/private/var/leftovers/runs/" + ("b" * 32) + "/scratch.raw",
            "size_bytes": 64 * 1024 * 1024,
        },
        "cpu_count": 1,
        "memory_bytes": 512 * 1024 * 1024,
        "wall_time_seconds": 60,
    }


class StrictVMReceiptSchemaSourceTests(unittest.TestCase):
    def test_manifest_schema_is_exact_v2(self) -> None:
        schema = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"], {"const": 2})
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("boot_artifact_directory", schema["required"])
        self.assertNotIn("artifact_directory", schema["properties"])

    def test_receipt_schema_is_valid_json_and_has_status_dependent_guards(self) -> None:
        schema = json.loads(RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        serialized = json.dumps(schema, sort_keys=True)
        for token in (
            '"schema_version": {"const": 2}',
            '"manifest_sha256"',
            '"guest_stopped"',
            '"config_validated": {"const": true}',
            '"scratch_retained": {"const": true}',
            '"rootStorage"',
            '"scratchStorage"',
            '"requestStorage"',
            '"multipleOf": 1048576',
        ):
            self.assertIn(token, serialized)

    def test_live_smoke_is_an_immutable_historical_v1_record(self) -> None:
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        identities = evidence["source_identity"]
        self.assertEqual(
            identities,
            {
                "entitlements_sha256": (
                    "5c1c6753b84cc1a1349de2a465074f166b5a47bade536b231683c22f53072259"
                ),
                "launcher_sha256": (
                    "1a4efbc68da0c7a8cbfb55b6e9f43cdf740ed3cc07a37baa3798f0ca54cfeabb"
                ),
                "smoke_init_sha256": (
                    "877b789f8eddafe393c6e24d73efcbe9349dc5ec6286cfa6aa3935511bdb18e5"
                ),
            },
        )
        receipt = evidence["launcher_receipt"]
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["launcher_version"], "0.2.0-proof")
        self.assertNotEqual(
            identities["launcher_sha256"],
            hashlib.sha256((ROOT / "vm" / "strict_vm_launcher.swift").read_bytes()).hexdigest(),
        )


@unittest.skipUnless(JSONSCHEMA_AVAILABLE, "optional jsonschema package is unavailable")
class StrictVMReceiptSchemaSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from jsonschema import Draft202012Validator

        cls.schema = json.loads(RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.manifest_schema = json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        Draft202012Validator.check_schema(cls.manifest_schema)
        cls.validator = Draft202012Validator(cls.schema)
        cls.manifest_validator = Draft202012Validator(cls.manifest_schema)

    def assert_valid(self, receipt: dict[str, object]) -> None:
        errors = sorted(self.validator.iter_errors(receipt), key=lambda item: list(item.path))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def assert_invalid(self, receipt: dict[str, object]) -> None:
        self.assertTrue(list(self.validator.iter_errors(receipt)))

    def test_valid_guest_stopped_without_request(self) -> None:
        self.assert_valid(valid_guest_stopped_receipt())

    def test_manifest_v2_accepts_exact_shape_and_rejects_v1_field(self) -> None:
        self.assertEqual(list(self.manifest_validator.iter_errors(valid_manifest())), [])
        old = valid_manifest()
        old["artifact_directory"] = old.pop("boot_artifact_directory")
        self.assertTrue(list(self.manifest_validator.iter_errors(old)))

    def test_current_v2_schema_rejects_recorded_v1_smoke_receipt(self) -> None:
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assert_invalid(evidence["launcher_receipt"])

    def test_valid_guest_stopped_with_read_only_request(self) -> None:
        receipt = valid_guest_stopped_receipt()
        artifacts = receipt["artifacts"]
        devices = receipt["devices"]
        assert isinstance(artifacts, dict)
        assert isinstance(devices, dict)
        storage = devices["storage_devices"]
        assert isinstance(storage, list)
        artifacts["request_disk_sha256"] = "b" * 64
        storage.append(
            {
                "role": "request",
                "kind": "virtio-block",
                "read_only": True,
                "size_bytes": 512,
            }
        )
        self.assert_valid(receipt)

    def test_guest_stopped_rejects_unsafe_semantic_combinations(self) -> None:
        mutations = []

        def mutate(path: tuple[object, ...], value: object) -> dict[str, object]:
            receipt = copy.deepcopy(valid_guest_stopped_receipt())
            target: object = receipt
            for key in path[:-1]:
                target = target[key]  # type: ignore[index]
            target[path[-1]] = value  # type: ignore[index]
            return receipt

        mutations.extend(
            [
                mutate(("config_validated",), False),
                mutate(("devices",), None),
                mutate(("limits",), None),
                mutate(("artifacts",), None),
                mutate(("scratch_retained",), False),
                mutate(("stop_reason",), "wall_timeout"),
                mutate(("devices", "storage_devices", 0, "read_only"), False),
                mutate(("devices", "storage_devices", 1, "read_only"), True),
                mutate(("devices", "storage_devices", 1, "role"), "root"),
                mutate(("devices", "storage_devices", 1, "size_bytes"), 67108865),
                mutate(("limits", "memory_bytes"), 536870913),
            ]
        )
        missing_scratch = valid_guest_stopped_receipt()
        devices = missing_scratch["devices"]
        assert isinstance(devices, dict)
        devices["storage_devices"] = [devices["storage_devices"][0]]  # type: ignore[index]
        mutations.append(missing_scratch)

        request_without_digest = valid_guest_stopped_receipt()
        devices = request_without_digest["devices"]
        assert isinstance(devices, dict)
        storage = devices["storage_devices"]
        assert isinstance(storage, list)
        storage.append(
            {
                "role": "request",
                "kind": "virtio-block",
                "read_only": True,
                "size_bytes": 512,
            }
        )
        mutations.append(request_without_digest)

        digest_without_request = valid_guest_stopped_receipt()
        artifacts = digest_without_request["artifacts"]
        assert isinstance(artifacts, dict)
        artifacts["request_disk_sha256"] = "b" * 64
        mutations.append(digest_without_request)

        for receipt in mutations:
            with self.subTest(receipt=receipt):
                self.assert_invalid(receipt)


if __name__ == "__main__":
    unittest.main()
