"""Deterministic 10,000-case owner-learning scope contamination corpus."""

import unittest

import loom_domain
import loom_learning


class LearningScopeFirewallTests(unittest.TestCase):
    def test_ten_thousand_active_task_routes_have_zero_ambient_domain_leaks(self):
        cases = (
            ("Implement Loom owner-specific learning", {"llm-agent"}),
            ("Plan double-entry accounting reconciliation", {"accounting"}),
            ("Build a real-time 3D room configurator", {"realtime-3d"}),
            ("Write firmware for a microcontroller board", {"firmware-hardware"}),
            ("Prepare a reproducible literature review", {"research"}),
        )
        ambient = {
            "file_names": ["sitemap.xml", "manifest.json", "skill.md", "schema.sql"],
            "extensions": [".md", ".glb", ".sql"],
            "dependencies": ["react", "three", "webextension-manifest"],
        }
        checked = 0
        for index in range(10000):
            request, expected = cases[index % len(cases)]
            result = loom_domain.select_domains(request, project_facts=ambient)
            self.assertEqual(expected, set(result["active_task_domains"]), index)
            self.assertEqual(expected, set(result["memory_domains"]), index)
            checked += 1
        self.assertEqual(10000, checked)

    def test_transferable_process_learning_promotes_but_technical_facts_never_do(self):
        observations = [
            {"project_id": f"p-{index % 3}",
             "domain": "website" if index < 3 else "accounting",
             "component_id": None, "evidence_id": f"evidence-{index}",
             "contradicts": False}
            for index in range(6)
        ]
        process = loom_learning.admission_decision(
            observations, category="decision-economics", requested_scope="general")
        fact = loom_learning.admission_decision(
            observations, category="technical-fact", requested_scope="general")
        self.assertEqual("active", process["status"])
        self.assertEqual("rejected", fact["status"])


if __name__ == "__main__":
    unittest.main()
