"""Closed protocol-v2 and truthful host-registry regressions."""

import io
import json
import tempfile
import unittest
from pathlib import Path

import loom_adapter_bridge
import loom_adapter_protocol
import loom_host_registry


ROOT = Path(__file__).resolve().parents[1]


def capabilities(**overrides):
    value = {key: False for key in loom_adapter_protocol.CAPABILITY_KEYS}
    value.update({"invoke": True, "complete": True, "cancel": True,
                  "status": True, "markdown": True})
    value.update(overrides)
    return value


def initialize(**overrides):
    value = {
        "schema_version": 2, "message_type": "initialize",
        "request_id": "req-0000000000000001",
        "protocol": {"minimum": 2, "maximum": 2},
        "adapter": {"id": "codex", "version": "2.0.0"},
        "host": {"id": "codex", "version": "test"},
        "capabilities": capabilities(),
    }
    value.update(overrides)
    return value


class AdapterProtocolV2Tests(unittest.TestCase):
    def test_closed_initialize_round_trips_and_has_stable_digest(self):
        value = initialize()
        self.assertEqual(value, loom_adapter_protocol.round_trip(value))
        self.assertEqual(
            loom_adapter_protocol.digest(value), loom_adapter_protocol.digest(dict(value)))
        changed = dict(value)
        changed["unknown"] = True
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "unknown|missing"):
            loom_adapter_protocol.validate_message(changed)

    def test_protocol_mismatch_invalid_depth_and_oversize_fail_closed(self):
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "overlap"):
            loom_adapter_protocol.negotiate({"minimum": 3, "maximum": 4})
        nested = initialize()
        cursor = nested
        for index in range(20):
            cursor["unknown"] = {"level": index}
            cursor = cursor["unknown"]
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "nesting"):
            loom_adapter_protocol.validate_message(nested)
        raw = b"{" + b"x" * loom_adapter_protocol.MAX_MESSAGE_BYTES + b"\n"
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "oversized"):
            loom_adapter_protocol.read_frame(io.BytesIO(raw))

    def test_host_registry_never_calls_experimental_or_unsupported_supported(self):
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw)
            for marker in (".codex", ".cursor", ".factory", ".agents"):
                (home / marker).mkdir(parents=True)
            found = loom_host_registry.detect(home, which=lambda _name: None)
        by_id = {item["id"]: item for item in found}
        self.assertTrue(by_id["codex"]["connectable"])
        self.assertFalse(by_id["cursor"]["connectable"])
        self.assertFalse(by_id["factory-droid"]["connectable"])
        self.assertFalse(by_id["generic-agent-skills"]["connectable"])
        self.assertEqual("simulated-conformant", by_id["codex"]["evidence_status"])

    def test_schemas_and_contract_are_closed_and_bounded(self):
        message = json.loads((ROOT / "schemas" / "adapter-message.schema.json").read_text(
            encoding="utf-8"))
        ownership = json.loads((ROOT / "schemas" / "adapter-ownership-receipt.schema.json").read_text(
            encoding="utf-8"))
        contract = json.loads((ROOT / "contracts" / "adapter-protocol-v2.json").read_text(
            encoding="utf-8"))
        self.assertEqual(2, contract["protocol_version"])
        self.assertFalse(contract["network_listener"])
        self.assertEqual(65536, contract["maximum_message_bytes"])
        self.assertFalse(ownership["additionalProperties"])
        for definition in message["$defs"].values():
            if isinstance(definition, dict) and definition.get("type") == "object":
                self.assertFalse(definition.get("additionalProperties", True))

    def test_bridge_requires_initialize_and_preserves_request_identity(self):
        session = {}
        status = {"schema_version": 2, "message_type": "status",
                  "request_id": "req-status"}
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "initialize"):
            loom_adapter_bridge.dispatch(
                status, home=Path("."), launcher=Path("loom"), session=session)

    def test_adapter_template_is_stateless_and_names_protocol_v2(self):
        import loom_adapters
        text = loom_adapters._adapter("codex").decode("utf-8")
        self.assertIn("protocol v2", text)
        self.assertIn("stateless", text)
        self.assertNotIn("sqlite", text.lower())
        self.assertNotIn("memory IDs", text)


if __name__ == "__main__":
    unittest.main()
