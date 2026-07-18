import copy
import tempfile
import unittest
from pathlib import Path

import loom_capability_registry


ROOT = Path(__file__).resolve().parents[1]


class CapabilityRegistryPhase7Tests(unittest.TestCase):
    def declarations(self):
        return {"schema_version": 1, "version": "1.6.0", "capabilities": [
            {"id": "routing", "kind": "mechanical",
             "enforcement": ["tools/loom_runtime.py"],
             "tests": ["tools/test_loom_runtime.py"]},
            {"id": "human-review", "kind": "advisory",
             "enforcement": [], "tests": []},
        ]}

    def graph(self, *, active=True):
        evidence_id = "ev-cap-routing-current"
        return {"schema_version": 1, "policy_id": "loom-evidence-policy-v1",
                "subject_digest": "a" * 64, "evaluated_at": "2026-07-17T00:00:00Z",
                "active": [evidence_id] if active else [],
                "inactive": [] if active else [
                    {"evidence_id": evidence_id, "reason": "expired"}],
                "predicates": {"capability:routing": [evidence_id]} if active else {},
                "graph_sha256": "b" * 64}

    def test_missing_evidence_is_unverified_not_supported(self):
        result = loom_capability_registry.generate(self.declarations())
        statuses = {item["id"]: item["status"] for item in result["capabilities"]}
        self.assertEqual("unverified", statuses["routing"])
        self.assertEqual("unsupported", statuses["human-review"])

    def test_active_exact_evidence_supports_and_expiry_downgrades(self):
        supported = loom_capability_registry.generate(
            self.declarations(), self.graph(), root=ROOT)
        self.assertEqual("supported", supported["capabilities"][0]["status"])
        self.assertTrue(supported["capabilities"][0]["proof_binding"]["files"])
        self.assertEqual("a" * 64,
                         supported["capabilities"][0]["proof_binding"]["subject_digest"])
        stale = loom_capability_registry.generate(
            self.declarations(), self.graph(active=False))
        self.assertEqual("stale-proof", stale["capabilities"][0]["status"])

    def test_current_evidence_without_bound_code_bytes_is_not_supported(self):
        result = loom_capability_registry.generate(self.declarations(), self.graph())
        self.assertEqual("experimental", result["capabilities"][0]["status"])
        self.assertEqual([], result["capabilities"][0]["proof_binding"]["files"])

    def test_unknown_fields_and_duplicate_ids_fail_closed(self):
        invalid = self.declarations()
        invalid["capabilities"][0]["claimed"] = True
        with self.assertRaises(loom_capability_registry.CapabilityRegistryError):
            loom_capability_registry.generate(invalid)
        duplicated = self.declarations()
        duplicated["capabilities"].append(copy.deepcopy(duplicated["capabilities"][0]))
        with self.assertRaises(loom_capability_registry.CapabilityRegistryError):
            loom_capability_registry.generate(duplicated)

    def test_proof_binding_cannot_escape_the_declared_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            (base / "outside.py").write_text("private", encoding="utf-8")
            declarations = self.declarations()
            declarations["capabilities"][0]["enforcement"] = ["../outside.py"]
            declarations["capabilities"][0]["tests"] = []
            with self.assertRaisesRegex(
                    loom_capability_registry.CapabilityRegistryError, "unsafe"):
                loom_capability_registry.generate(
                    declarations, self.graph(), root=root)


if __name__ == "__main__":
    unittest.main()
