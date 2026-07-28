import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import loom_capability_registry
import loom_subject_identity


ROOT = Path(__file__).resolve().parents[1]


class CapabilityRegistryPhase7Tests(unittest.TestCase):
    def seal_graph(self, value):
        value = dict(value)
        value["graph_sha256"] = hashlib.sha256(json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        return value

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
        return self.seal_graph({
                "schema_version": 1, "policy_id": "loom-evidence-policy-v1",
                "subject_digest": "a" * 64, "evaluated_at": "2026-07-17T00:00:00Z",
                "active": [evidence_id] if active else [],
                "inactive": [] if active else [
                    {"evidence_id": evidence_id, "reason": "expired"}],
                "predicates": {"capability:routing": [evidence_id]} if active else {},
        })

    def typed_graph(self):
        subject = loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "candidate-source",
            "subject_id": "candidate",
            "repository": loom_subject_identity.REPOSITORY,
            "base_commit": "1" * 40, "commit": "2" * 40,
            "tree_sha256": "3" * 64,
            "overlay_sha256": loom_subject_identity.EMPTY_OVERLAY_SHA256,
            "dirty": False,
        })
        binding = {key: subject[key] for key in
                   ("kind", "subject_id", "subject_digest")}
        return self.seal_graph({
            "schema_version": 2, "policy_id": "loom-evidence-policy-v1",
            "expected_subjects_sha256": "4" * 64,
            "subject_bindings": [binding],
            "active_bindings_by_evidence": {
                "ev-cap-routing-current": [binding]},
            "evaluated_at": "2026-07-17T00:00:00Z",
            "next_invalidation_at": "2026-08-17T00:00:00Z",
            "active": ["ev-cap-routing-current"], "inactive": [],
            "predicates": {
                "capability:routing": ["ev-cap-routing-current"]},
        })

    def authoritative_declarations(self):
        return {
            "schema_version": 1,
            "policy_id": "loom-capability-declarations-v1",
            "capabilities": [{
                "id": "routing", "kind": "mechanical",
                "enforcement": ["tools/loom_runtime.py"],
                "tests": ["tools/test_loom_runtime.py"],
                "required_predicates": ["capability:routing"],
                "required_subject_kinds": ["candidate-source"],
                "limitations": [],
            }],
        }

    def test_missing_evidence_is_unverified_not_supported(self):
        result = loom_capability_registry.generate(self.declarations())
        statuses = {item["id"]: item["status"] for item in result["capabilities"]}
        self.assertEqual("unverified", statuses["routing"])
        self.assertEqual("unsupported", statuses["human-review"])

    def test_active_exact_evidence_supports_and_expiry_downgrades(self):
        graph = self.typed_graph()
        untrusted = loom_capability_registry.generate(
            self.authoritative_declarations(), graph, root=ROOT)
        self.assertEqual("unverified",
                         untrusted["capabilities"][0]["status"])
        supported = loom_capability_registry.generate(
            self.authoritative_declarations(), graph, root=ROOT,
            trusted_expected_subjects_sha256="4" * 64)
        self.assertEqual("supported", supported["capabilities"][0]["status"])
        self.assertTrue(supported["capabilities"][0]["proof_binding"]["files"])
        self.assertEqual(
            "candidate-source",
            supported["capabilities"][0]["proof_binding"][
                "subject_bindings"][0]["kind"])
        stale = loom_capability_registry.generate(
            self.declarations(), self.graph(active=False))
        self.assertEqual("stale-proof", stale["capabilities"][0]["status"])
        tampered = self.typed_graph()
        tampered["active"].append("ev-forged")
        with self.assertRaisesRegex(
                loom_capability_registry.CapabilityRegistryError, "digest"):
            loom_capability_registry.generate(
                self.authoritative_declarations(), tampered, root=ROOT,
                trusted_expected_subjects_sha256="4" * 64)

    def test_current_evidence_without_bound_code_bytes_is_not_supported(self):
        result = loom_capability_registry.generate(self.declarations(), self.graph())
        self.assertEqual("unverified", result["capabilities"][0]["status"])
        self.assertEqual([], result["capabilities"][0]["proof_binding"]["files"])

    def test_inactive_subject_binding_cannot_complete_an_active_predicate(self):
        graph = self.typed_graph()
        inactive_helper = {
            "kind": "native-helper", "subject_id": "linux-x64",
            "subject_digest": "5" * 64,
        }
        graph["subject_bindings"].append(inactive_helper)
        graph["inactive"].append({
            "evidence_id": "ev-helper-expired", "reason": "expired",
            "predicate_type": "capability:routing",
            "subject_bindings": [inactive_helper],
        })
        graph = self.seal_graph({
            key: item for key, item in graph.items()
            if key != "graph_sha256"})
        declarations = self.authoritative_declarations()
        declarations["capabilities"][0]["required_subject_kinds"].append(
            "native-helper")
        result = loom_capability_registry.generate(
            declarations, graph, root=ROOT,
            trusted_expected_subjects_sha256="4" * 64)
        self.assertEqual("unverified", result["capabilities"][0]["status"])
        self.assertEqual(
            ["candidate-source"],
            [item["kind"] for item in
             result["capabilities"][0]["proof_binding"][
                 "subject_bindings"]])

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
            (root / "VERSION").write_text("1.6.0\n", encoding="utf-8")
            (base / "outside.py").write_text("private", encoding="utf-8")
            declarations = self.declarations()
            declarations["capabilities"][0]["enforcement"] = ["../outside.py"]
            declarations["capabilities"][0]["tests"] = []
            with self.assertRaisesRegex(
                    loom_capability_registry.CapabilityRegistryError, "unsafe"):
                loom_capability_registry.generate(
                    declarations, self.graph(), root=root)

    def test_cli_uses_fixed_declaration_and_root_version_authorities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "contracts").mkdir()
            output = root / "generated.json"
            (root / "VERSION").write_text("1.8.4\n", encoding="utf-8")
            declarations = self.authoritative_declarations()
            declarations["capabilities"] = []
            (root / "contracts" / "capability-declarations-v1.json").write_text(
                json.dumps(declarations), encoding="utf-8")

            self.assertEqual(0, loom_capability_registry.main([
                str(root), "--output", str(output)]))
            self.assertEqual("1.8.4", json.loads(
                output.read_text(encoding="utf-8"))["version"])

    def test_docs_projection_cannot_be_used_as_production_declarations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "VERSION").write_text("1.8.4\n", encoding="utf-8")
            (root / "docs" / "capabilities.json").write_text(
                json.dumps(self.declarations()), encoding="utf-8")
            self.assertEqual(
                2, loom_capability_registry.main([str(root)]))


if __name__ == "__main__":
    unittest.main()
