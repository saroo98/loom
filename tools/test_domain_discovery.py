import unittest

import loom_domain
import loom_domain_discovery


class DomainDiscoveryTests(unittest.TestCase):
    def test_questions_are_consequence_bounded(self):
        ordinary = loom_domain.select_domains("Plan a quantum optics write-up")["domain_contract"]
        receipt = loom_domain_discovery.create_receipt(ordinary, created_at="2030-01-01T00:00:00Z")
        self.assertLessEqual(len(receipt["questions"]), 4)
        self.assertEqual(8, receipt["budgets"]["questions"])

    def test_high_consequence_uses_at_most_eight_questions(self):
        route = loom_domain.select_domains(
            "Plan patient safety logic for a clinical system")["domain_contract"]
        receipt = loom_domain_discovery.create_receipt(route, created_at="2030-01-01T00:00:00Z")
        self.assertEqual(8, len(receipt["questions"]))

    def test_resume_rejects_changed_route(self):
        first_route = loom_domain.select_domains("Plan a quantum optics rig")["domain_contract"]
        receipt = loom_domain_discovery.create_receipt(
            first_route, created_at="2030-01-01T00:00:00Z")
        second_route = loom_domain.select_domains("Plan clinical software")["domain_contract"]
        with self.assertRaises(loom_domain_discovery.DomainDiscoveryError):
            loom_domain_discovery.resume(receipt, second_route)

    def test_retrieval_round_hard_bound(self):
        route = loom_domain.select_domains("Plan a quantum optics rig")["domain_contract"]
        with self.assertRaises(loom_domain_discovery.DomainDiscoveryError):
            loom_domain_discovery.create_receipt(route, retrieval_rounds=3)


if __name__ == "__main__":
    unittest.main()
