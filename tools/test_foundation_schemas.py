import tempfile
import unittest
import uuid
from pathlib import Path

import loom_lint
import loom_activation
import loom_execution_chain
import loom_operation_envelope
import loom_operation_supervisor
import loom_path_authority


class FoundationSchemaTests(unittest.TestCase):
    def assert_schema(self, value, schema):
        report = loom_lint.Report()
        loom_lint.validate_schema(report, schema, value, schema)
        self.assertEqual([], report.errors)

    def test_operation_envelope_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, envelope = loom_operation_envelope.begin(
                Path(temporary).resolve(), operation_class="fixture",
                subject_digest="1" * 64, sidecar_type="fixture-receipt",
                sidecar_id="fixture.json", sidecar_digest="2" * 64)
            self.assert_schema(envelope, "operation-envelope.schema.json")

    def test_supervisor_receipt_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            receipt = loom_operation_supervisor.run(
                operation_class="schema-fixture",
                command=["cmd", "/c", "exit", "0"] if __import__("os").name == "nt"
                else ["/bin/sh", "-c", "exit 0"],
                cwd=root, timeout=5, allowed_roots=[root])
            self.assert_schema(
                receipt, "operation-supervisor-receipt.schema.json")

    def test_authority_and_ownership_receipts_match_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            owned = root / "owned"
            owned.mkdir()
            ownership = loom_path_authority.create_ownership_receipt(
                path=owned, root=root, operation_id=str(uuid.uuid4()),
                expected_type="directory")
            authority = loom_path_authority.authorize(
                operation_class="staging", path=owned, root=root,
                expected_type="directory", replacement_policy="owned-exact",
                cleanup_disposition="remove-if-owned",
                ownership_receipt=ownership)
            self.assert_schema(
                ownership, "path-authority-receipt.schema.json")
            self.assert_schema(
                authority, "path-authority-receipt.schema.json")

    def test_execution_chain_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            launcher = root / "loom.py"
            launcher.write_text("print('fixture')\n", encoding="utf-8")
            chain = loom_execution_chain.create(
                root / ".loom", launcher_path=launcher)
            value = loom_execution_chain.read(
                root / ".loom", chain["chain_id"])
            self.assert_schema(value, "execution-chain.schema.json")

    def test_activation_set_matches_closed_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / ".loom"
            runtime = root / "runtime" / "versions" / "1.8.15"
            runtime.mkdir(parents=True)
            content = b"runtime"
            (runtime / "loom-runtime.txt").write_bytes(content)
            pointer = {
                "version": "1.8.15",
                "path": "1.8.15",
                "payload_sha256": __import__("hashlib").sha256(content).hexdigest(),
                "release_sequence": 15,
                "previous": None,
            }
            store = loom_activation.ActivationStore(root)
            activated = store.create(
                pointer, state_source=None,
                schema_range={"minimum": 0, "maximum": 0},
                previous_activation_set_id=None,
                purpose="baseline-adoption")
            receipt = store.read_receipt(activated["activation_set_id"])
            self.assert_schema(receipt, "activation-set.schema.json")


if __name__ == "__main__":
    unittest.main()
