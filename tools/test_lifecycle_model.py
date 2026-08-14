import dataclasses
import itertools
import unittest

import loom_lifecycle_kernel as kernel
from test_lifecycle_kernel import HEX_A, HEX_B, _canonical_state_inputs


def _command(state, relation, **overrides):
    value = {
        "schema_version": 1,
        "command_id": "model-command",
        "relation": relation,
        "project_id": state.project_id or "project-1",
        "generation_id": state.generation_id,
        "plan_semantics_sha256": state.plan_semantics_sha256,
        "observed_world_sha256": state.reviewed_world_sha256,
        "action_id": "model-action",
        "work_order_id": state.in_progress_work_order_id,
        "evidence_sha256": HEX_A,
        "affected_scope_sha256": HEX_B,
        "successor_generation_id": "generation-2",
        "reason_code": "owner-requested",
    }
    value.update(overrides)
    return kernel.lifecycle_command(value)


class LifecycleBoundedModelTests(unittest.TestCase):
    def setUp(self):
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)
        self.reviewable = kernel.fold(index, semantics, ledger, witness)

    def test_rejected_decisions_never_carry_authoritative_events(self):
        """Break caught: one rejection path leaks a mutating event batch."""
        relations = sorted(kernel.COMMAND_RELATIONS)
        phases = [
            "reviewable", "active", "terminal-completed",
            "terminal-cancelled", "terminal-superseded",
        ]
        observations = ["stable", "prepared-not-committed", "ambiguous"]
        worlds = ["exact", "changed"]
        checked = 0
        for phase, observation, world, relation in itertools.product(
                phases, observations, worlds, relations):
            state = dataclasses.replace(
                self.reviewable,
                generation_phase=phase,
                transition_observation=observation,
                world_relation=world,
            )
            command = _command(
                state, relation,
                observed_world_sha256=(
                    state.reviewed_world_sha256 if world == "exact" else HEX_A),
            )
            decision = kernel.decide(state, command)
            checked += 1
            if not decision.accepted:
                self.assertEqual(
                    (), decision.event_batch.events,
                    (phase, observation, world, relation, decision.primary_code),
                )
        self.assertEqual(
            len(phases) * len(observations) * len(worlds) * len(relations),
            checked,
        )

    def test_terminal_history_never_accepts_continuation_or_repair(self):
        """Break caught: completed history is silently reused as active work."""
        for phase, relation in itertools.product(
                ["terminal-completed", "terminal-cancelled", "terminal-superseded"],
                ["start-exact", "continue-active", "repair-active", "revise-exact"]):
            state = dataclasses.replace(self.reviewable, generation_phase=phase)

            decision = kernel.decide(state, _command(state, relation))

            self.assertFalse(decision.accepted, (phase, relation))
            self.assertEqual("GENERATION_TERMINAL", decision.primary_code)

    def test_nonstable_observation_blocks_every_mutation_but_not_status(self):
        """Break caught: a new command races an unresolved transition."""
        for observation in (
                "prepared-not-committed", "committed-projection-pending", "ambiguous"):
            state = dataclasses.replace(
                self.reviewable, transition_observation=observation)
            for relation in kernel.COMMAND_RELATIONS - {"read-only"}:
                decision = kernel.decide(state, _command(state, relation))
                self.assertFalse(decision.accepted, (observation, relation))
                self.assertEqual(
                    "TRANSITION_RECONCILIATION_REQUIRED", decision.primary_code)
            self.assertTrue(
                kernel.decide(state, _command(state, "read-only")).accepted)

    def test_projection_is_exact_and_tampering_fails_closed(self):
        """Break caught: human-readable status diverges from reducer state."""
        projection = kernel.project(self.reviewable)
        self.assertIs(projection, kernel.verify_projection(self.reviewable, projection))
        projection["work_order_statuses"]["WO-002"] = "ready"

        with self.assertRaisesRegex(kernel.LifecycleKernelError, "does not match"):
            kernel.verify_projection(self.reviewable, projection)


if __name__ == "__main__":
    unittest.main()
