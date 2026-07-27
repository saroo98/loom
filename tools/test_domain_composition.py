import unittest

import loom_domain_composition


class DomainCompositionTests(unittest.TestCase):
    def test_consequence_is_independent_from_domain(self):
        result = loom_domain_composition.classify_consequence(
            "A one-line change to a patient life-support shutdown interlock")
        self.assertEqual("critical", result["class"])
        self.assertIn("human-safety", result["categories"])

    def test_branch_propagation_preserves_unconnected_branch(self):
        nodes = [
            {"id": "control", "domains": ["firmware"], "coverage": "unknown",
             "consequence": "critical", "blocked": True},
            {"id": "display", "domains": ["website"], "coverage": "known",
             "consequence": "ordinary", "blocked": False},
            {"id": "release", "domains": ["firmware"], "coverage": "unknown",
             "consequence": "critical", "blocked": True},
        ]
        edges = [{"from": "control", "to": "release", "kind": "depends-on",
                  "consequence": "critical", "blocked": True}]
        graph = loom_domain_composition.build_graph(
            "safety control and isolated reporting display",
            ["firmware", "website"], {"firmware": "unknown", "website": "known"},
            subsystems=nodes, edges=edges)
        closure = loom_domain_composition.affected_branches(graph, ["control"])
        self.assertEqual(["control", "release"], closure["affected"])
        self.assertEqual(["display"], closure["isolated"])

    def test_graph_is_order_invariant_after_normalization(self):
        domains = ["accounting", "desktop"]
        coverage = {"accounting": "known", "desktop": "known"}
        first = loom_domain_composition.build_graph("desktop accounting", domains, coverage)
        second = loom_domain_composition.build_graph(
            "desktop accounting", list(reversed(domains)), coverage)
        self.assertEqual(first["nodes"], second["nodes"])
        self.assertEqual(first["graph_digest"], second["graph_digest"])

    def test_research_report_subject_does_not_inherit_database_consequence(self):
        result = loom_domain_composition.build_graph(
            "Plan a research comparison of embedded databases and produce a "
            "Markdown report; do not build software.",
            ["research"], {"research": "known"})
        self.assertEqual("ordinary", result["consequence"]["class"])
        self.assertNotIn(
            "durable-data-or-contract",
            result["consequence"]["categories"])

    def test_research_and_write_database_memo_is_not_a_database_operation(self):
        result = loom_domain_composition.build_graph(
            "Research and write a cited comparison of embedded databases. "
            "Deliver only a decision memo.",
            ["research"], {"research": "known"})
        self.assertEqual("ordinary", result["consequence"]["class"])

    def test_database_implementation_remains_material(self):
        result = loom_domain_composition.build_graph(
            "Build a database migration tool",
            ["cli"], {"cli": "known"})
        self.assertEqual("material", result["consequence"]["class"])
        self.assertIn(
            "durable-data-or-contract",
            result["consequence"]["categories"])

    def test_medication_reminder_is_high_consequence_without_claiming_certification(self):
        result = loom_domain_composition.build_graph(
            "Plan an offline-first mobile medication reminder.",
            ["mobile"], {"mobile": "known"})
        self.assertEqual("high", result["consequence"]["class"])
        self.assertIn("physical-safety", result["consequence"]["categories"])


if __name__ == "__main__":
    unittest.main()
