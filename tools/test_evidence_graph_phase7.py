import copy
import datetime as dt
import unittest
import uuid

import loom_evidence_graph
import loom_subject_identity


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

    def typed_subject(self):
        return loom_subject_identity.seal_subject({
            "schema_version": 1, "kind": "plugin-zip",
            "subject_id": "loom.zip", "filename": "loom.zip",
            "bytes": 4,
            "sha256": "d" * 64,
        })

    def typed_envelope(self, subject, *, expires="2026-08-17T00:00:00Z",
                       revoked=False, stale=False):
        return loom_evidence_graph.seal_envelope({
            "schema_version": 2, "evidence_id": "ev-plugin",
            "subject_bindings": [{
                "kind": subject["kind"], "subject_id": subject["subject_id"],
                "subject_digest": subject["subject_digest"],
            }],
            "predicate_type": "release:plugin",
            "producer": {"id": "loom-test", "version": "2", "digest": "b" * 64},
            "evidence_class": "ci-reproduced",
            "environment": {"runner": "ubuntu-24.04", "workflow_digest": "e" * 64},
            "issued_at": "2026-07-17T00:00:00Z",
            "expires_at": expires, "payload_sha256": "c" * 64,
            "limitations": ["fixture only"],
            "signer": {"authority": "ci", "key_id": "ci-key",
                       "algorithm": "ed25519", "signature": "fixture"},
            "verifier": {"id": "external", "verified_at": "2026-07-17T00:00:01Z",
                         "status": "passed"},
            "depends_on": [], "revoked": revoked, "stale": stale,
        })

    def typed_bundle(self, subject, envelope):
        expected_digest = loom_subject_identity.digest({
            "schema_version": 1, "subjects": [subject]})
        return {
            "schema_version": 2, "policy_id": "loom-evidence-policy-v1",
            "expected_subjects_sha256": expected_digest,
            "evaluation_epoch": "2026-07-17T12:00:00Z",
            "envelopes": [envelope],
        }

    def expected_receipt(self, subject):
        value = {
            "schema_version": 1,
            "expectation_id": str(uuid.uuid4()),
            "issuer_kind": "ci",
            "issuer_id": "github-actions",
            "repository": loom_subject_identity.REPOSITORY,
            "run_id": "123",
            "job_id": "evidence-test",
            "workflow_digest": "1" * 64,
            "base_commit": "2" * 40,
            "candidate_commit": "3" * 40,
            "issued_at": "2026-07-17T00:00:00Z",
            "expires_at": "2026-08-16T00:00:00Z",
            "evaluation_epoch": "2026-07-17T12:00:00Z",
            "subjects": [subject],
            "authority": {
                "kind": "ci-attestation",
                "attestation_sha256": "4" * 64,
            },
        }
        value["expectation_sha256"] = loom_subject_identity.digest({
            key: item for key, item in value.items()
            if key not in {"authority", "expectation_sha256"}})
        return loom_subject_identity.validate_expected_subjects(
            value, ci_attestation_verifier=lambda _value: True)

    def test_typed_evidence_needs_expected_subject_and_exact_binding(self):
        subject = self.typed_subject()
        bundle = self.typed_bundle(subject, self.typed_envelope(subject))
        missing = loom_evidence_graph.evaluate(bundle)
        self.assertEqual(
            "expected-subject-unavailable", missing["inactive"][0]["reason"])
        active = loom_evidence_graph.evaluate(
            bundle, expected_receipt=self.expected_receipt(subject))
        self.assertEqual(["ev-plugin"], active["active"])
        with self.assertRaisesRegex(
                loom_evidence_graph.EvidenceGraphError,
                "stable controller or CI"):
            loom_evidence_graph.evaluate(
                bundle,
                expected_receipt=dict(self.expected_receipt(subject)))
        wrong = copy.deepcopy(subject)
        wrong["subject_digest"] = "f" * 64
        with self.assertRaises(loom_subject_identity.SubjectIdentityError):
            loom_subject_identity.validate_subject(wrong)
        other = loom_subject_identity.seal_subject({
            **{key: value for key, value in subject.items()
               if key != "subject_digest"},
            "sha256": "f" * 64,
        })
        wrong_bundle = self.typed_bundle(
            subject, self.typed_envelope(other))
        wrong_result = loom_evidence_graph.evaluate(
            wrong_bundle, expected_receipt=self.expected_receipt(subject))
        self.assertEqual("wrong-subject", wrong_result["inactive"][0]["reason"])

    def test_typed_expiry_boundary_is_deterministic(self):
        subject = self.typed_subject()
        envelope_value = self.typed_envelope(
            subject, expires="2026-07-17T12:00:00Z")
        bundle = self.typed_bundle(subject, envelope_value)
        first = loom_evidence_graph.evaluate(
            bundle, expected_receipt=self.expected_receipt(subject))
        second = loom_evidence_graph.evaluate(
            bundle, expected_receipt=self.expected_receipt(subject))
        self.assertEqual(first, second)
        self.assertEqual("expired", first["inactive"][0]["reason"])

    def test_typed_ci_evidence_requires_runner_and_workflow(self):
        subject = self.typed_subject()
        envelope_value = self.typed_envelope(subject)
        envelope_value["environment"] = {}
        envelope_value = loom_evidence_graph.seal_envelope(envelope_value)
        with self.assertRaisesRegex(
                loom_evidence_graph.EvidenceGraphError, "runner"):
            loom_evidence_graph.evaluate(
                self.typed_bundle(subject, envelope_value),
                expected_receipt=self.expected_receipt(subject))

    def test_typed_signature_bundle_is_bounded(self):
        subject = self.typed_subject()
        envelope_value = self.typed_envelope(subject)
        envelope_value["signer"]["signature"] = "x" * 262145
        envelope_value = loom_evidence_graph.seal_envelope(envelope_value)
        with self.assertRaisesRegex(
                loom_evidence_graph.EvidenceGraphError, "signer"):
            loom_evidence_graph.evaluate(
                self.typed_bundle(subject, envelope_value),
                expected_receipt=self.expected_receipt(subject))


if __name__ == "__main__":
    unittest.main()
