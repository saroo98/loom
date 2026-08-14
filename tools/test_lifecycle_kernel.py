import importlib
import json
import unittest
from pathlib import Path


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def _sealed(kernel, value, field):
    value = dict(value)
    value[field] = kernel.digest(value)
    return value


def _canonical_world_observation(kernel, *, generation_id="generation-1"):
    return _sealed(kernel, {
        "schema_version": 1,
        "project_id": "project-1",
        "generation_id": generation_id,
        "state_mode": "git",
        "state_sha256": HEX_B,
        "repo_head": "1" * 40,
        "files": {
            "README.md": HEX_A,
            "src/example.py": HEX_C,
        },
    }, "observation_sha256")


def _canonical_state_inputs(kernel, *, completed=(), authorized=False):
    reviewed_world = _canonical_world_observation(kernel)
    work_orders = [
        {
            "id": "WO-001", "title": "First", "outcome": "First complete",
            "tasks": ["Implement first"], "acceptance": ["First passes"],
            "negative_acceptance": ["First fails closed"],
            "out_of_scope": ["Other work"], "escalation": ["World changes"],
            "touches": ["src/first.py"], "depends_on": [],
        },
        {
            "id": "WO-002", "title": "Second", "outcome": "Second complete",
            "tasks": ["Implement second"], "acceptance": ["Second passes"],
            "negative_acceptance": ["Second fails closed"],
            "out_of_scope": ["Other work"], "escalation": ["World changes"],
            "touches": ["src/second.py"], "depends_on": ["WO-001"],
        },
    ]
    semantics = _sealed(kernel, {
        "schema_version": 1,
        "project_id": "project-1",
        "generation_id": "generation-1",
        "revision_number": 1,
        "title": "Reviewed plan",
        "summary": "Deliver two ordered outcomes.",
        "assumptions": [],
        "decisions": [],
        "execution_policy": "strict-serial-sequence-v1",
        "execution_sequence": ["WO-001", "WO-002"],
        "work_orders": work_orders,
        "plan_contract_sha256": HEX_A,
        "domain_bindings_sha256": None,
        "reviewed_world_sha256": HEX_B,
        "reviewed_world_observation_sha256": reviewed_world[
            "observation_sha256"],
    }, "plan_semantics_sha256")
    index = _sealed(kernel, {
        "schema_version": 1,
        "project_id": "project-1",
        "generation_id": "generation-1",
        "storage_kind": "generation-dir",
        "generation_path": "plans/generations/generation-1",
    }, "index_sha256")
    events = []

    def add(event_type, payload, command_id):
        event = {
            "sequence": len(events) + 1,
            "event_type": event_type,
            "command_id": command_id,
            "transition_id": HEX_C,
            "payload": payload,
            "previous_event_sha256": (
                events[-1]["event_sha256"] if events else None),
        }
        events.append(_sealed(kernel, event, "event_sha256"))

    add("generation-created", {
        "predecessor_generation_id": None,
        "relation": "new",
    }, "command-create")
    add("plan-reviewed", {
        "plan_semantics_sha256": semantics["plan_semantics_sha256"],
        "revision_number": 1,
        "reviewed_world_sha256": HEX_B,
    }, "command-review")
    if authorized:
        add("implementation-authorized", {"work_order_id": "WO-001"},
            "command-start")
        add("work-order-started", {
            "work_order_id": "WO-001", "action_id": "action-1",
        }, "command-start")
    for identifier in completed:
        if identifier == "WO-001" and not authorized:
            raise AssertionError("completion fixture requires authorization")
        add("work-order-completed", {
            "work_order_id": identifier,
            "completion_sha256": HEX_A,
            "completed_world_sha256": HEX_A,
        }, "command-complete")
    ledger = _sealed(kernel, {
        "schema_version": 3,
        "project_id": "project-1",
        "generation_id": "generation-1",
        "plan_semantics_sha256": semantics["plan_semantics_sha256"],
        "execution_policy": "strict-serial-sequence-v1",
        "execution_sequence_sha256": kernel.digest(
            semantics["execution_sequence"]),
        "events": events,
    }, "lifecycle_sha256")
    witness = _sealed(kernel, {
        "schema_version": 1,
        "project_id": "project-1",
        "generation_id": "generation-1",
        "transition_id": HEX_C,
        "authoritative_sha256": ledger["lifecycle_sha256"],
        "predecessor_witness_sha256": None,
    }, "witness_sha256")
    return index, semantics, ledger, witness


def _advance_state(kernel, index, semantics, ledger, witness, decision):
    target = {
        key: json.loads(json.dumps(value))
        for key, value in ledger.items() if key != "lifecycle_sha256"}
    target["events"] = [*target["events"], *({
        "sequence": event.sequence,
        "event_type": event.event_type,
        "command_id": event.command_id,
        "transition_id": event.transition_id,
        "payload": event.payload_dict,
        "previous_event_sha256": event.previous_event_sha256,
        "event_sha256": event.event_sha256,
    } for event in decision.event_batch.events)]
    target["lifecycle_sha256"] = kernel.digest(target)
    target_witness = _sealed(kernel, {
        "schema_version": 1,
        "project_id": target["project_id"],
        "generation_id": target["generation_id"],
        "transition_id": decision.transition_id,
        "authoritative_sha256": target["lifecycle_sha256"],
        "predecessor_witness_sha256": witness["witness_sha256"],
    }, "witness_sha256")
    return target, target_witness, kernel.fold(
        index, semantics, target, target_witness)


class LifecycleKernelSchedulingTests(unittest.TestCase):
    def kernel(self):
        try:
            return importlib.import_module("loom_lifecycle_kernel")
        except ModuleNotFoundError:
            self.fail("loom_lifecycle_kernel is required")

    def test_reviewed_world_observation_is_closed_bounded_and_self_bound(self):
        """Break caught: completion causality depends on an unbound file baseline."""
        kernel = self.kernel()
        observation = _canonical_world_observation(kernel)

        validated = kernel.validate_reviewed_world_observation(observation)

        self.assertEqual(HEX_B, validated["state_sha256"])
        self.assertEqual(2, len(validated["files"]))
        changed = json.loads(json.dumps(observation))
        changed["files"]["README.md"] = HEX_C
        with self.assertRaisesRegex(
                kernel.LifecycleKernelError, "digest"):
            kernel.validate_reviewed_world_observation(changed)

    def test_reviewed_sequence_not_identifier_spelling_controls_order(self):
        """Break caught: identifier spelling is accidentally used as scheduling authority."""
        kernel = self.kernel()
        graph = kernel.validate_work_order_graph(
            [
                {"id": "WO-900", "depends_on": []},
                {"id": "WO-100", "depends_on": []},
            ],
            ["WO-900", "WO-100"],
        )

        self.assertEqual("WO-900", kernel.select_work_order(graph).work_order_id)

    def test_sequence_must_place_every_dependency_before_its_dependent(self):
        """Break caught: a reviewed sequence contradicts its dependency graph."""
        kernel = self.kernel()

        with self.assertRaisesRegex(
                kernel.LifecycleKernelError, "topological linear extension"):
            kernel.validate_work_order_graph(
                [
                    {"id": "WO-001", "depends_on": []},
                    {"id": "WO-002", "depends_on": ["WO-001"]},
                ],
                ["WO-002", "WO-001"],
            )

    def test_blocked_first_entry_cannot_be_skipped_for_later_eligible_work(self):
        """Break caught: opportunistic selection bypasses the sealed serial order."""
        kernel = self.kernel()
        graph = kernel.validate_work_order_graph(
            [
                {"id": "WO-001", "depends_on": ["D-001"]},
                {"id": "WO-002", "depends_on": []},
            ],
            ["WO-001", "WO-002"],
        )

        selection = kernel.select_work_order(graph, resolved_decisions=())

        self.assertIsNone(selection.work_order_id)
        self.assertEqual("WO-001", selection.blocked_work_order_id)
        self.assertEqual(("D-001",), selection.blockers)

    def test_projection_has_one_ready_entry_and_blocks_later_sequence_entries(self):
        """Break caught: multiple valid-looking ready projections make execution ambiguous."""
        kernel = self.kernel()
        graph = kernel.validate_work_order_graph(
            [
                {"id": "WO-001", "depends_on": []},
                {"id": "WO-002", "depends_on": ["WO-001"]},
                {"id": "WO-003", "depends_on": ["WO-002"]},
            ],
            ["WO-001", "WO-002", "WO-003"],
        )

        projection = kernel.project_work_order_statuses(graph)

        self.assertEqual(
            {"WO-001": "ready", "WO-002": "blocked", "WO-003": "blocked"},
            projection,
        )

    def test_shared_execution_policy_is_closed_and_self_bound(self):
        """Break caught: author, linter, and writer silently consume different bounds."""
        kernel = self.kernel()
        path = Path(__file__).resolve().parents[1] / "contracts" / \
            "plan-execution-policy-v1.json"
        self.assertTrue(path.is_file(), "shared execution policy is required")
        value = json.loads(path.read_text(encoding="utf-8"))

        policy = kernel.validate_execution_policy(value)

        self.assertEqual("strict-serial-sequence-v1", policy.execution_policy)
        self.assertEqual(5, policy.max_touch_patterns_per_work_order)
        self.assertEqual(512, policy.max_ledger_events)

    def test_supported_graph_shapes_follow_only_the_reviewed_total_sequence(self):
        """Break caught: graph shape or dictionary order changes serial priority."""
        kernel = self.kernel()
        cases = (
            ([{"id": "WO-001", "depends_on": []}], ["WO-001"]),
            ([
                {"id": "WO-001", "depends_on": []},
                {"id": "WO-002", "depends_on": ["WO-001"]},
                {"id": "WO-003", "depends_on": ["WO-002"]},
            ], ["WO-001", "WO-002", "WO-003"]),
            ([
                {"id": "WO-700", "depends_on": []},
                {"id": "WO-200", "depends_on": []},
                {"id": "WO-900", "depends_on": ["WO-700", "WO-200"]},
            ], ["WO-700", "WO-200", "WO-900"]),
            ([
                {"id": "WO-800", "depends_on": []},
                {"id": "WO-300", "depends_on": ["WO-800"]},
                {"id": "WO-400", "depends_on": ["WO-800"]},
                {"id": "WO-100", "depends_on": ["WO-300", "WO-400"]},
            ], ["WO-800", "WO-300", "WO-400", "WO-100"]),
        )
        for records, sequence in cases:
            with self.subTest(sequence=sequence):
                graph = kernel.validate_work_order_graph(
                    list(reversed(records)), sequence)
                self.assertEqual(
                    sequence[0], kernel.select_work_order(graph).work_order_id)
                completed = []
                for expected in sequence:
                    self.assertEqual(
                        expected,
                        kernel.select_work_order(
                            graph, completed=completed).work_order_id,
                    )
                    completed.append(expected)
                self.assertTrue(
                    kernel.select_work_order(
                        graph, completed=completed).complete)

    def test_invalid_graph_and_sequence_classes_fail_closed(self):
        """Break caught: malformed order is normalized into executable authority."""
        kernel = self.kernel()
        invalid = (
            ([{"id": "WO-001", "depends_on": ["WO-999"]}], ["WO-001"]),
            ([
                {"id": "WO-001", "depends_on": ["WO-002"]},
                {"id": "WO-002", "depends_on": ["WO-001"]},
            ], ["WO-001", "WO-002"]),
            ([
                {"id": "WO-001", "depends_on": []},
                {"id": "WO-002", "depends_on": []},
            ], ["WO-001"]),
            ([
                {"id": "WO-001", "depends_on": []},
                {"id": "WO-002", "depends_on": []},
            ], ["WO-001", "WO-001"]),
        )
        for records, sequence in invalid:
            with self.subTest(records=records, sequence=sequence):
                with self.assertRaises(kernel.LifecycleKernelError):
                    kernel.validate_work_order_graph(records, sequence)

    def test_canonical_json_preserves_utf8_plan_meaning(self):
        """Break caught: lifecycle digests use a different JSON text convention."""
        kernel = self.kernel()

        encoded = kernel.canonical_bytes({"title": "café"})

        self.assertIn("café".encode("utf-8"), encoded)
        self.assertNotIn(b"\\u00e9", encoded)


class LifecycleKernelAuthorityTests(unittest.TestCase):
    def kernel(self):
        return importlib.import_module("loom_lifecycle_kernel")

    def test_fold_derives_reviewable_state_from_closed_canonical_inputs(self):
        """Break caught: projections become a competing lifecycle authority."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)

        state = kernel.fold(index, semantics, ledger, witness)

        self.assertEqual("reviewable", state.generation_phase)
        self.assertEqual("stable", state.transition_observation)
        self.assertEqual("owned-valid", state.authority_validity)
        self.assertEqual("WO-001", state.selected_work_order_id)
        self.assertEqual((), state.completed_work_orders)

    def test_start_decision_is_closed_and_changed_world_rejection_has_no_events(self):
        """Break caught: a rejected stale start appends authorization."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)
        state = kernel.fold(index, semantics, ledger, witness)
        command = kernel.lifecycle_command({
            "schema_version": 1,
            "command_id": "command-start-exact",
            "relation": "start-exact",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_A,
            "action_id": "action-1",
            "work_order_id": None,
            "evidence_sha256": None,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        })

        decision = kernel.decide(state, command)

        self.assertFalse(decision.accepted)
        self.assertEqual("PROJECT_WORLD_CHANGED", decision.primary_code)
        self.assertEqual((), decision.event_batch.events)

    def test_exact_start_accepts_authorization_and_selected_work_as_one_batch(self):
        """Break caught: authorization and executable-work selection can diverge."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)
        state = kernel.fold(index, semantics, ledger, witness)
        command = kernel.lifecycle_command({
            "schema_version": 1,
            "command_id": "command-start-exact",
            "relation": "start-exact",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_B,
            "action_id": "action-1",
            "work_order_id": None,
            "evidence_sha256": None,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        })

        decision = kernel.decide(state, command)

        self.assertTrue(decision.accepted)
        self.assertEqual("WO-001", decision.selected_work_order_id)
        self.assertEqual(
            ("implementation-authorized", "work-order-started"),
            tuple(event.event_type for event in decision.event_batch.events),
        )
        self.assertEqual(state.state_sha256, decision.source_state_sha256)

    def test_completion_binds_the_new_exact_world_for_the_next_frontier(self):
        """Break caught: accepted work cannot advance the exact-world baseline."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(
            kernel, authorized=True)
        state = kernel.fold(index, semantics, ledger, witness)
        command = kernel.lifecycle_command({
            "schema_version": 1,
            "command_id": "command-complete-exact",
            "relation": "complete-active",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_A,
            "action_id": "action-1",
            "work_order_id": "WO-001",
            "evidence_sha256": HEX_C,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        })

        decision = kernel.decide(state, command)

        self.assertTrue(decision.accepted)
        completion = decision.event_batch.events[0]
        self.assertEqual("work-order-completed", completion.event_type)
        self.assertEqual(
            HEX_A, completion.payload_dict["completed_world_sha256"])

    def test_resume_and_repair_attempts_are_explicitly_bound_and_recoverable(self):
        """Break caught: continuation and repair attempts exist only in owner pointers."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(
            kernel, authorized=True)
        active = kernel.fold(index, semantics, ledger, witness)
        resume = kernel.lifecycle_command({
            "schema_version": 1,
            "command_id": "command-resume-exact",
            "relation": "continue-active",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_B,
            "action_id": "action-2",
            "work_order_id": None,
            "evidence_sha256": None,
            "affected_scope_sha256": None,
            "successor_generation_id": None,
            "reason_code": None,
        })
        resumed = kernel.decide(active, resume)
        self.assertTrue(resumed.accepted)
        self.assertEqual(
            ("work-order-resumed",),
            tuple(item.event_type for item in resumed.event_batch.events))

        repair = kernel.lifecycle_command({
            "schema_version": 1,
            "command_id": "command-repair-exact",
            "relation": "repair-active",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_C,
            "action_id": "repair-action-1",
            "work_order_id": None,
            "evidence_sha256": None,
            "affected_scope_sha256": HEX_A,
            "successor_generation_id": None,
            "reason_code": None,
        })
        authorized = kernel.decide(active, repair)
        self.assertTrue(authorized.accepted)
        ledger2, witness2, repairing = _advance_state(
            kernel, index, semantics, ledger, witness, authorized)
        self.assertEqual("repairing", repairing.action_relation)
        self.assertEqual("repair-action-1", repairing.repair_action_id)

        complete = kernel.lifecycle_command({
            "schema_version": 1,
            "command_id": "command-repair-complete",
            "relation": "repair-complete",
            "project_id": "project-1",
            "generation_id": "generation-1",
            "plan_semantics_sha256": semantics["plan_semantics_sha256"],
            "observed_world_sha256": HEX_C,
            "action_id": "repair-action-1",
            "work_order_id": "WO-001",
            "evidence_sha256": HEX_B,
            "affected_scope_sha256": HEX_A,
            "successor_generation_id": None,
            "reason_code": None,
        })
        completed = kernel.decide(repairing, complete)
        self.assertTrue(completed.accepted)
        _ledger3, _witness3, repaired = _advance_state(
            kernel, index, semantics, ledger2, witness2, completed)
        self.assertEqual("pending", repaired.action_relation)
        self.assertIsNone(repaired.repair_action_id)
        self.assertEqual(HEX_C, repaired.expected_world_sha256)

    def test_fold_rejects_broken_event_predecessor_chain(self):
        """Break caught: a valid-looking ledger launders reordered lifecycle history."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)
        ledger["events"][1]["previous_event_sha256"] = HEX_A
        ledger["events"][1]["event_sha256"] = kernel.digest({
            key: value for key, value in ledger["events"][1].items()
            if key != "event_sha256"
        })
        ledger["lifecycle_sha256"] = kernel.digest({
            key: value for key, value in ledger.items()
            if key != "lifecycle_sha256"
        })

        with self.assertRaisesRegex(
                kernel.LifecycleKernelError, "predecessor"):
            kernel.fold(index, semantics, ledger, witness)

    def test_head_witness_cannot_authorize_a_different_project_ledger(self):
        """Break caught: private witness becomes authority for absent project state."""
        kernel = self.kernel()
        index, semantics, ledger, witness = _canonical_state_inputs(kernel)
        witness["authoritative_sha256"] = HEX_A
        witness["witness_sha256"] = kernel.digest({
            key: value for key, value in witness.items()
            if key != "witness_sha256"
        })

        with self.assertRaisesRegex(
                kernel.LifecycleKernelError, "witness"):
            kernel.fold(index, semantics, ledger, witness)

    def test_semantic_digest_covers_execution_relevant_work_order_content(self):
        """Break caught: mutable plan meaning retains an old reviewed identity."""
        kernel = self.kernel()
        _index, semantics, _ledger, _witness = _canonical_state_inputs(kernel)
        semantics["work_orders"][0]["outcome"] = "Different reviewed outcome"

        with self.assertRaisesRegex(
                kernel.LifecycleKernelError, "digest does not match"):
            kernel.validate_reviewed_plan_semantics(semantics)


if __name__ == "__main__":
    unittest.main()
