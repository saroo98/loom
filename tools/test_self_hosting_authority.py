import base64
import datetime as dt
import hashlib
import unittest

import loom_self_hosting


NOW = dt.datetime(2026, 7, 26, 12, 0, tzinfo=dt.timezone.utc)
DIGESTS = [f"{index:064x}" for index in range(1, 8)]
PUBLIC = base64.b64encode(b"c" * 32).decode("ascii")
TRUSTED = {"controller-key": PUBLIC}


def signer(message):
    return base64.b64encode(hashlib.sha512(b"controller-secret" + message).digest()).decode(
        "ascii")


def verifier(message, signature, public_key):
    return public_key == PUBLIC and signature == signer(message)


def authorize(value, **kwargs):
    return loom_self_hosting.authorize(
        value, trusted_controller_keys=TRUSTED,
        signature_verifier=verifier, **kwargs)


def receipt(**overrides):
    values = {
        "controller_subject": DIGESTS[0],
        "candidate_subject": DIGESTS[1],
        "candidate_source_digest": DIGESTS[2],
        "dirty_diff_digest": DIGESTS[3],
        "candidate_build_digest": DIGESTS[4],
        "roles": {
            "owner": "owner",
            "stable_controller": "controller-1.8.15",
            "candidate_runtime": "candidate-runtime",
            "candidate_self_test": "candidate-runtime",
            "external_verifier": "external-verifier",
            "release_authority": "release-authority",
        },
        "allowed_actions": [
            "plan", "authorize", "repair", "self-test", "verify", "certify", "sign"],
        "issued_at": "2026-07-26T11:00:00Z",
        "expires_at": "2026-07-27T11:00:00Z",
        "historical_work": False,
        "causal_scope": "implementation",
        "external_verification_digest": DIGESTS[5],
        "authority_key_id": "controller-key",
        "authority_public_key": PUBLIC,
        "signer": signer,
    }
    values.update(overrides)
    return loom_self_hosting.create(**values)


class SelfHostingAuthorityTests(unittest.TestCase):
    def test_each_role_can_perform_only_its_closed_action(self):
        value = receipt()
        for action, role in loom_self_hosting.ACTION_ROLE.items():
            result = authorize(
                value, action=action, actor=value["roles"][role],
                candidate_subject=DIGESTS[1], now=NOW)
            self.assertEqual(role, result["role"])
            self.assertEqual(
                action in {"verify", "certify"}, result["independent"])

    def test_candidate_cannot_substitute_for_controller_verifier_or_signer(self):
        value = receipt()
        for action in ("plan", "authorize", "repair", "verify", "certify", "sign"):
            with self.subTest(action=action), self.assertRaises(
                    loom_self_hosting.SelfHostingError):
                authorize(
                    value, action=action, actor="candidate-runtime",
                    candidate_subject=DIGESTS[1], now=NOW)

    def test_role_collapse_wrong_subject_stale_and_tampered_receipts_fail_closed(self):
        collapsed = dict(receipt())
        collapsed["roles"] = dict(collapsed["roles"])
        collapsed["roles"]["external_verifier"] = "candidate-runtime"
        collapsed["receipt_hash"] = loom_self_hosting._receipt_hash(collapsed)
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            loom_self_hosting.validate(collapsed)
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            authorize(
                receipt(), action="verify", actor="external-verifier",
                candidate_subject=DIGESTS[6], now=NOW)
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            authorize(
                receipt(), action="verify", actor="external-verifier",
                candidate_subject=DIGESTS[1],
                now=NOW + dt.timedelta(days=3))
        tampered = dict(receipt())
        tampered["candidate_build_digest"] = DIGESTS[6]
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            loom_self_hosting.validate(tampered)

    def test_verification_only_history_cannot_gain_implementation_credit(self):
        value = receipt(
            historical_work=True, causal_scope="verification-only",
            allowed_actions=["verify", "certify", "sign"])
        for action in ("verify", "certify"):
            authorize(
                value, action=action, actor="external-verifier",
                candidate_subject=DIGESTS[1], now=NOW)
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            authorize(
                value, action="repair", actor="controller-1.8.15",
                candidate_subject=DIGESTS[1], now=NOW)

    def test_signing_requires_external_verification_bound_to_same_subject(self):
        value = receipt(external_verification_digest=None)
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            authorize(
                value, action="sign", actor="release-authority",
                candidate_subject=DIGESTS[1], now=NOW)

    def test_forged_or_untrusted_controller_signature_fails_closed(self):
        value = receipt()
        forged = dict(value)
        forged["authority"] = dict(forged["authority"])
        forged["authority"]["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            authorize(
                forged, action="verify", actor="external-verifier",
                candidate_subject=DIGESTS[1], now=NOW)
        with self.assertRaises(loom_self_hosting.SelfHostingError):
            loom_self_hosting.authorize(
                value, action="verify", actor="external-verifier",
                candidate_subject=DIGESTS[1], now=NOW,
                trusted_controller_keys={"other": PUBLIC},
                signature_verifier=verifier)


if __name__ == "__main__":
    unittest.main()
