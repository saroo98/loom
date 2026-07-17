import copy
import unittest

import loom_capability_registry


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
        supported = loom_capability_registry.generate(self.declarations(), self.graph())
        self.assertEqual("supported", supported["capabilities"][0]["status"])
        stale = loom_capability_registry.generate(
            self.declarations(), self.graph(active=False))
        self.assertEqual("stale-proof", stale["capabilities"][0]["status"])

    def test_unknown_fields_and_duplicate_ids_fail_closed(self):
        invalid = self.declarations()
        invalid["capabilities"][0]["claimed"] = True
        with self.assertRaises(loom_capability_registry.CapabilityRegistryError):
            loom_capability_registry.generate(invalid)
        duplicated = self.declarations()
        duplicated["capabilities"].append(copy.deepcopy(duplicated["capabilities"][0]))
        with self.assertRaises(loom_capability_registry.CapabilityRegistryError):
            loom_capability_registry.generate(duplicated)


if __name__ == "__main__":
    unittest.main()
