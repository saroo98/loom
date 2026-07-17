import copy
import datetime as dt
import unittest

import loom_evidence_graph


NOW = dt.datetime(2026, 7, 17, 12, tzinfo=dt.timezone.utc)
SUBJECT = "a" * 64


def envelope(identity, predicate, *, dependencies=(), expires="2026-08-17T00:00:00Z"):
    return loom_evidence_graph.seal_envelope({
        "schema_version": 1, "evidence_id": identity,
        "subject_digest": SUBJECT, "predicate_type": predicate,
        "producer": {"id": "loom-test", "version": "1", "digest": "b" * 64},
        "evidence_class": "mechanical-local", "environment": {"os": "test"},
        "issued_at": "2026-07-17T00:00:00Z", "expires_at": expires,
        "payload_sha256": "c" * 64, "limitations": ["fixture only"],
        "signer": {"authority": "local", "key_id": None,
                   "algorithm": "none", "signature": None},
        "verifier": {"id": "test", "verified_at": "2026-07-17T00:00:01Z",
                     "status": "passed"},
        "depends_on": list(dependencies), "revoked": False,
    })


class EvidenceGraphPhase7Tests(unittest.TestCase):
    def bundle(self, envelopes):
        return {"schema_version": 1, "policy_id": "loom-evidence-policy-v1",
                "subject_digest": SUBJECT, "envelopes": envelopes}

    def test_active_dependency_chain_exposes_predicates(self):
        root = envelope("ev-root", "suite:full")
        child = envelope("ev-child", "capability:routing", dependencies=["ev-root"])
        result = loom_evidence_graph.evaluate(self.bundle([child, root]), as_of=NOW)
        self.assertEqual(["ev-child", "ev-root"], result["active"])
        self.assertEqual(["ev-child"], result["predicates"]["capability:routing"])

    def test_expiry_propagates_to_dependent_claim(self):
        root = envelope("ev-root", "suite:full", expires="2026-07-17T00:00:02Z")
        child = envelope("ev-child", "capability:routing", dependencies=["ev-root"])
        result = loom_evidence_graph.evaluate(self.bundle([child, root]), as_of=NOW)
        reasons = {item["evidence_id"]: item["reason"] for item in result["inactive"]}
        self.assertEqual("expired", reasons["ev-root"])
        self.assertEqual("dependency-inactive", reasons["ev-child"])

    def test_revocation_propagates_to_dependent_claim(self):
        root = envelope("ev-root", "suite:full")
        root["revoked"] = True
        root = loom_evidence_graph.seal_envelope(root)
        child = envelope("ev-child", "capability:routing", dependencies=["ev-root"])
        result = loom_evidence_graph.evaluate(self.bundle([root, child]), as_of=NOW)
        self.assertEqual([], result["active"])

    def test_wrong_subject_tamper_and_cycles_fail_closed(self):
        wrong = envelope("ev-wrong", "suite:full")
        wrong["subject_digest"] = "d" * 64
        with self.assertRaises(loom_evidence_graph.EvidenceGraphError):
            loom_evidence_graph.evaluate(self.bundle([wrong]), as_of=NOW)
        tampered = envelope("ev-tampered", "suite:full")
        tampered["predicate_type"] = "suite:partial"
        with self.assertRaises(loom_evidence_graph.EvidenceGraphError):
            loom_evidence_graph.evaluate(self.bundle([tampered]), as_of=NOW)
        first = envelope("ev-first", "first", dependencies=["ev-second"])
        second = envelope("ev-second", "second", dependencies=["ev-first"])
        with self.assertRaises(loom_evidence_graph.EvidenceGraphError):
            loom_evidence_graph.evaluate(self.bundle([first, second]), as_of=NOW)

    def test_non_local_unsigned_evidence_is_rejected(self):
        value = envelope("ev-host", "host:codex")
        value["evidence_class"] = "real-host"
        value = loom_evidence_graph.seal_envelope(value)
        with self.assertRaises(loom_evidence_graph.EvidenceGraphError):
            loom_evidence_graph.evaluate(self.bundle([value]), as_of=NOW)


if __name__ == "__main__":
    unittest.main()
