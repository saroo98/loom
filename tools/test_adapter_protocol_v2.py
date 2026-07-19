"""Closed protocol-v2 and truthful host-registry regressions."""

import io
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        "adapter": {"id": "codex", "version": loom_adapter_protocol.ADAPTER_VERSION},
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
        for malformed in (b"{not-json}\n", b'{"request":"\xff"}\n', b"{}"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(loom_adapter_protocol.ProtocolError):
                    loom_adapter_protocol.read_frame(io.BytesIO(malformed))

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
        self.assertEqual("bounded-utf8-json-stdio-end-to-end",
                         contract["request_transport"])
        self.assertIn("requestEnvelope", message["$defs"])
        self.assertFalse(ownership["additionalProperties"])
        for definition in message["$defs"].values():
            if isinstance(definition, dict) and definition.get("type") == "object":
                self.assertFalse(definition.get("additionalProperties", True))

    def test_host_contract_is_versioned_and_all_routes_share_one_authority(self):
        self.assertEqual("loom-host-contracts-v2", loom_host_registry.CONTRACT_ID)
        self.assertIn(".agents/skills/loom/SKILL.md",
                      loom_host_registry.HOSTS["codex"]["global_roots"])
        self.assertIn(".codex/skills/loom/SKILL.md",
                      loom_host_registry.project_skill_paths())
        self.assertEqual("stale", loom_host_registry.HOSTS["gemini-cli"]["contract_status"])
        self.assertFalse(loom_host_registry.detect(
            Path("."), which=lambda _name: None))

    def test_bridge_requires_initialize_before_any_request(self):
        session = {}
        status = {"schema_version": 2, "message_type": "status",
                  "request_id": "req-status"}
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "initialize"):
            loom_adapter_bridge.dispatch(
                status, home=Path("."), launcher=Path("loom"), session=session)

    def test_request_identity_uses_exact_decoded_utf8_bytes(self):
        request = "  line one\r\nline two % ! & | < > ^ ( ) \"'\nSorani: کوردی  "
        identity = loom_adapter_protocol.request_identity(request)
        raw = request.encode("utf-8")
        self.assertEqual(len(raw), identity["utf8_bytes"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), identity["sha256"])

    def test_request_envelope_is_closed_bounded_and_rejects_identity_changes(self):
        request = {
            "schema_version": 2, "message_type": "invoke",
            "request_id": "req-transport", "request": "\nPlan exactly.\n",
            "cwd": "C:/disposable/project",
        }
        envelope = loom_adapter_protocol.request_envelope(
            request, {"id": "codex", "version": "test"})
        self.assertEqual("request-envelope", envelope["message_type"])
        self.assertEqual(request["request"], envelope["request"])
        self.assertEqual(envelope, loom_adapter_protocol.round_trip(envelope))
        changed = json.loads(json.dumps(envelope))
        changed["request_identity"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "identity"):
            loom_adapter_protocol.validate_message(changed)

    def test_request_character_and_frame_byte_bounds_are_independent(self):
        host = {"id": "codex", "version": "test"}
        maximum = {
            "schema_version": 2, "message_type": "invoke",
            "request_id": "req-maximum", "request": "x" * 32768,
            "cwd": "C:/disposable/project",
        }
        self.assertEqual(32768, len(loom_adapter_protocol.request_envelope(
            maximum, host)["request"]))
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "request"):
            loom_adapter_protocol.request_envelope(
                dict(maximum, request="x" * 32769), host)
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "byte bound"):
            loom_adapter_protocol.request_envelope(
                dict(maximum, request="🧵" * 20000), host)
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "Unicode scalar"):
            loom_adapter_protocol.validate_message(
                dict(maximum, request="escaped surrogate: \ud800"))

    def test_internal_reader_rejects_missing_wrong_and_trailing_frames(self):
        message = {
            "schema_version": 2, "message_type": "invoke",
            "request_id": "req-single", "request": "exactly one",
            "cwd": "C:/disposable/project",
        }
        frame = loom_adapter_protocol.canonical_bytes(
            loom_adapter_protocol.request_envelope(
                message, {"id": "codex", "version": "test"})) + b"\n"
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "missing"):
            loom_adapter_protocol.read_single_frame(
                io.BytesIO(), message_type="request-envelope")
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "type"):
            loom_adapter_protocol.read_single_frame(
                io.BytesIO(loom_adapter_protocol.canonical_bytes(message) + b"\n"),
                message_type="request-envelope")
        with self.assertRaisesRegex(loom_adapter_protocol.ProtocolError, "trailing"):
            loom_adapter_protocol.read_single_frame(
                io.BytesIO(frame + frame), message_type="request-envelope")

    def test_bridge_preserves_request_identity_and_never_places_request_in_argv(self):
        session = {
            "host": {"id": "codex", "version": "test"},
            "adapter": {"id": "codex", "version": "2.1.0"},
            "capabilities": capabilities(), "protocol_version": 2,
        }
        request = "first line\nsecond line & % ! کوردی"
        message = {
            "schema_version": 2, "message_type": "invoke",
            "request_id": "req-exact", "request": request,
            "cwd": "C:/disposable/project",
        }
        with mock.patch.object(
                loom_adapter_bridge, "_run_request",
                return_value=(0, {"status": "action-required"})) as run_request:
            result = loom_adapter_bridge.dispatch(
                message, home=Path("C:/disposable/home/.loom"),
                launcher=Path("C:/disposable/home/.loom/bin/loom.py"),
                session=session)
        self.assertEqual(0, result["returncode"])
        envelope = run_request.call_args.args[2]
        self.assertEqual(request, envelope["request"])
        self.assertEqual(
            loom_adapter_protocol.request_identity(request),
            envelope["request_identity"])

    def test_adapter_template_is_stateless_and_names_protocol_v2(self):
        import loom_adapters
        text = loom_adapters._adapter("codex").decode("utf-8")
        self.assertIn("protocol v2", text)
        self.assertIn("stateless", text)
        self.assertIn("loom.py --home", text)
        self.assertIn("<absolute-user-home>/.loom bridge", text)
        self.assertNotIn("--request", text)
        self.assertIn("Never place request text", text)
        self.assertIn("never use `loom.cmd`", text)
        self.assertNotIn("sqlite", text.lower())
        self.assertNotIn("memory IDs", text)


if __name__ == "__main__":
    unittest.main()
