import copy
import unittest

import loom_program


def milestone(identity):
    return {"id": identity, "outcome": identity + " complete", "effort": "m",
            "integration_points": [], "risks": ["failure"],
            "exit_evidence": ["real process pass"], "fact_ttls": {"api": 14}}


class PlanningProgramTests(unittest.TestCase):
    def test_selective_regating_keeps_isolated_work(self):
        graph = loom_program.build_milestone_graph(
            [milestone("core"), milestone("release"), milestone("docs")],
            [{"from": "core", "to": "release", "kind": "depends-on"}])
        result = loom_program.affected_milestones(graph, ["core"])
        self.assertEqual(["core", "release"], result["affected"])
        self.assertEqual(["docs"], result["isolated"])

    def test_multi_phase_program_is_content_bound_and_ordered(self):
        program = loom_program.build_program(
            "Plan Phase 8, Phase 9, and Phase 10, then implement them in order",
            tier="L", lifecycle_mode="project")
        loom_program.validate_program(program)
        graph = program["milestone_graph"]
        self.assertEqual(["phase-8", "phase-9", "phase-10"], [
            item["id"] for item in graph["milestones"]])
        self.assertTrue(all(item["impact_cone_hash"].startswith("sha256:")
                            for item in graph["milestones"]))
        self.assertTrue(all(item["effort_interval"]["unit"] == "relative-point"
                            for item in graph["milestones"]))

    def test_incident_and_maintenance_programs_use_distinct_initial_states(self):
        incident = loom_program.build_program(
            "Contain a production incident", tier="M", lifecycle_mode="incident")
        maintenance = loom_program.build_program(
            "Apply a dependency update", tier="M", lifecycle_mode="maintenance")
        self.assertIsNone(incident)
        self.assertIsNone(maintenance)

    def test_cycle_fails_closed(self):
        with self.assertRaisesRegex(loom_program.ProgramError, "cycle"):
            loom_program.build_milestone_graph(
                [milestone("a"), milestone("b")],
                [{"from": "a", "to": "b", "kind": "depends-on"},
                 {"from": "b", "to": "a", "kind": "depends-on"}])

    def test_graph_digest_detects_mutation(self):
        graph = loom_program.build_milestone_graph([milestone("one")], [])
        changed = copy.deepcopy(graph); changed["milestones"][0]["outcome"] = "changed"
        with self.assertRaisesRegex(loom_program.ProgramError, "digest mismatch"):
            loom_program.affected_milestones(changed, ["one"])

    def test_resume_capsule_is_bounded_and_content_bound(self):
        graph = loom_program.build_milestone_graph([milestone("one")], [])
        capsule = loom_program.resume_capsule(
            graph, current_milestone="one", frontier=["WO-1"],
            open_decisions=[], blockers=[], stale_facts=["api"],
            accepted_isolated_evidence=[])
        self.assertLessEqual(len(str(capsule)), loom_program.MAX_RESUME_CHARS)
        self.assertTrue(capsule["capsule_digest"].startswith("sha256:"))

    def test_incident_containment_must_be_reversible(self):
        with self.assertRaisesRegex(loom_program.ProgramError, "reversible"):
            loom_program.transition("incident", "triaged", "contained")
        result = loom_program.transition(
            "incident", "triaged", "contained", reversible=True)
        self.assertEqual("contained", result["to"])

    def test_incident_remediation_requires_evidence_and_authority(self):
        with self.assertRaises(loom_program.ProgramError):
            loom_program.transition(
                "incident", "remediation-planned", "fixed", authority=True)
        result = loom_program.transition(
            "incident", "remediation-planned", "fixed",
            authority=True, evidence_preserved=True)
        self.assertEqual("fixed", result["to"])

    def test_maintenance_authorization_is_explicit(self):
        with self.assertRaisesRegex(loom_program.ProgramError, "authorization"):
            loom_program.transition(
                "maintenance", "assessed", "authorized",
                maintenance_class="dependency-update")


if __name__ == "__main__":
    unittest.main()
