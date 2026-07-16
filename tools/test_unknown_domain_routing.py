import copy
import math
import unittest

import loom_domain
import loom_domain_contract


class UnknownDomainRoutingTests(unittest.TestCase):
    def test_recognized_unknown_keeps_identity_but_cannot_activate_memory(self):
        result = loom_domain.select_domains(
            "Plan collision-avoidance logic for a marine navigation system")
        self.assertEqual(["marine-navigation"], result["active_task_domains"])
        self.assertEqual([], result["memory_domains"])
        self.assertEqual("unknown", result["coverage_state"])
        self.assertEqual("blocked", result["g1_status"])
        loom_domain_contract.validate_route(result["domain_contract"])

    def test_known_and_unknown_route_is_partial_and_subsystem_blocked(self):
        result = loom_domain.select_domains(
            "Build a CLI that evaluates medical clinical scheduling rules")
        self.assertEqual("partial", result["coverage_state"])
        self.assertIn("cli", result["memory_domains"])
        self.assertIn("medical-clinical", result["active_task_domains"])
        blocked = {item["id"]: item["blocked"]
                   for item in result["composition_graph"]["nodes"]}
        self.assertFalse(blocked["domain-cli"])
        self.assertTrue(blocked["domain-medical-clinical"])

    def test_host_proposal_is_ranked_but_never_activates_memory(self):
        proposal = {"domains": ["legal-regulatory"], "subsystems": [],
                    "evidence": ["model hypothesis"], "provider": "host",
                    "model": "test", "confidence": 0.99}
        result = loom_domain.select_domains("Improve this", host_proposal=proposal)
        self.assertEqual([], result["active_task_domains"])
        self.assertEqual([], result["memory_domains"])
        candidate = result["domain_contract"]["candidates"][0]
        self.assertEqual("host-proposal", candidate["source"])

    def test_path_names_do_not_redefine_the_request(self):
        result = loom_domain.select_domains(
            "Read C:\\reports\\website.md and improve this planning agent runtime")
        self.assertIn("llm-agent", result["active_task_domains"])
        self.assertNotIn("website", result["active_task_domains"])

    def test_route_is_deterministic(self):
        request = "Build accounting desktop software with double-entry correctness"
        first = loom_domain.select_domains(request)
        second = loom_domain.select_domains(request)
        self.assertEqual(first["domain_contract"], second["domain_contract"])

    def test_canonical_json_rejects_negative_zero_and_non_finite(self):
        for value in (-0.0, math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaises(loom_domain_contract.DomainContractError):
                    loom_domain_contract.canonical_bytes({"value": value})

    def test_semantic_route_mutation_invalidates_digest(self):
        route = loom_domain.select_domains("Build a CLI tool")["domain_contract"]
        changed = copy.deepcopy(route)
        changed["coverage_state"] = "unknown"
        with self.assertRaises(loom_domain_contract.DomainContractError):
            loom_domain_contract.validate_route(changed)

    def test_explicit_unknown_domain_does_not_bypass_discovery(self):
        result = loom_domain.select_domains("Improve this", explicit=["fabricated-domain"])
        self.assertEqual(["fabricated-domain"], result["active_task_domains"])
        self.assertEqual([], result["memory_domains"])
        self.assertTrue(result["requires_domain_discovery"])


if __name__ == "__main__":
    unittest.main()
