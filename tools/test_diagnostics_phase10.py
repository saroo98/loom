import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import loom_diagnostics


class DiagnosticsPhase10Tests(unittest.TestCase):
    @staticmethod
    def _write_runtime_pointer(home):
        runtime = home / "runtime"
        runtime.mkdir(parents=True)
        (runtime / "current.json").write_text(json.dumps({
            "version": "1.6.0",
            "path": "1.6.0",
            "payload_sha256": "a" * 64,
            "release_sequence": 16,
            "previous": None,
        }), encoding="utf-8")

    def test_doctor_reports_only_body_free_metadata(self):
        with tempfile.TemporaryDirectory(prefix="private-owner-name-") as temporary:
            home = Path(temporary) / ".loom"
            self._write_runtime_pointer(home)
            result = loom_diagnostics.doctor(home)
            rendered = json.dumps(result)
            self.assertEqual("healthy", result["status"])
            self.assertNotIn(str(home), rendered)
            self.assertNotIn("private-owner-name", rendered)
            self.assertFalse(result["privacy"]["telemetry"])

    def test_changed_owned_adapter_blocks_health(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / ".loom"
            self._write_runtime_pointer(home)
            target = Path(temporary) / "skill.md"
            target.write_text("changed", encoding="utf-8")
            receipts = home / "adapters" / "receipts"
            receipts.mkdir(parents=True)
            (receipts / "codex.json").write_text(json.dumps({
                "agent": "codex", "path": str(target), "sha256": "0" * 64}),
                encoding="utf-8")
            result = loom_diagnostics.doctor(home)
            self.assertEqual("blocked", result["status"])
            self.assertIn("ADAPTER_OWNERSHIP_CONFLICT", result["problems"])

    def test_support_export_contains_only_encrypted_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / ".loom"
            self._write_runtime_pointer(home)
            output = root / "support.loom-encrypted"
            wrapped = {"salt": "salt", "ciphertext": "cipher", "kdf": {"name": "argon2id"}}
            with mock.patch.object(
                    loom_diagnostics.loom_crypto, "passphrase_wrap", return_value=wrapped):
                result = loom_diagnostics.export_encrypted(
                    home, root / "helper", output, passphrase="a sufficiently long passphrase")
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("encrypted", result["status"])
            self.assertNotIn("runtime", payload)
            self.assertFalse(payload["upload"])
            self.assertRegex(payload["plaintext_sha256"], r"^[0-9a-f]{64}$")

    def test_invalid_owner_state_pointer_blocks_without_exposing_private_state(self):
        with tempfile.TemporaryDirectory(prefix="private-owner-name-") as temporary:
            home = Path(temporary) / ".loom"
            runtime = home / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "current.json").write_text(json.dumps({
                "version": "1.6.0", "release_sequence": 16, "previous": None}),
                encoding="utf-8")

            result = loom_diagnostics.doctor(home)
            rendered = json.dumps(result)

            self.assertEqual("blocked", result["status"])
            self.assertEqual("unverifiable", result["state"]["integrity"])
            self.assertIn("OWNER_STATE_POINTER_INVALID", result["problems"])
            self.assertNotIn(str(home), rendered)
            self.assertNotIn("private-owner-name", rendered)


if __name__ == "__main__":
    unittest.main()
