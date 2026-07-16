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


if __name__ == "__main__":
    unittest.main()
