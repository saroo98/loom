"""Independent reference-model invariants for merge ordering and bounds."""

import unittest
from unittest import mock

import loom_modelcheck
import loom_vault


class MergeReferenceModelTests(unittest.TestCase):
    def test_all_bounded_two_device_orders_converge(self):
        self.assertEqual(24, loom_modelcheck.exhaustive_two_device())

    def test_seeded_three_device_duplicate_and_reorder_traces_converge(self):
        self.assertEqual(150, loom_modelcheck.seeded_three_device(12026, 50))

    def test_production_rank_matches_independent_model_total_order(self):
        events = [
            {"device_counter": 2,
             "device_id": "00000000-0000-4000-8000-000000000002",
             "event_id": "00000000-0000-4000-8000-000000000002"},
            {"device_counter": 2,
             "device_id": "00000000-0000-4000-8000-000000000001",
             "event_id": "00000000-0000-4000-8000-000000000009"},
            {"device_counter": 1,
             "device_id": "00000000-0000-4000-8000-000000000009",
             "event_id": "00000000-0000-4000-8000-000000000001"},
        ]
        model = sorted(events, key=loom_modelcheck.rank)
        production = sorted(events, key=lambda item: loom_vault._event_rank(
            item["device_counter"], item["device_id"], item["event_id"]))
        self.assertEqual(model, production)

    def test_production_rank_preserves_the_full_counter_word(self):
        device = "00000000-0000-4000-8000-000000000001"
        event = "00000000-0000-4000-8000-000000000002"
        first = loom_vault._event_rank(1, device, event)
        second = loom_vault._event_rank(2, device, event)
        self.assertEqual(1 << 32, second - first)
        self.assertEqual(2, second >> 32)

    def test_sqlite_rank_collision_fails_closed_instead_of_selecting_by_delivery_order(self):
        class Cursor:
            def fetchall(self):
                return [{"device_counter": 1,
                         "device_id": "00000000-0000-4000-8000-000000000001",
                         "event_id": "00000000-0000-4000-8000-000000000001"}]

        class Connection:
            def execute(self, _query, _parameters):
                return Cursor()

        with mock.patch("loom_vault._event_rank", return_value=7):
            with self.assertRaisesRegex(loom_vault.VaultError, "collision"):
                loom_vault._collision_checked_event_rank(
                    Connection(), 1,
                    "00000000-0000-4000-8000-000000000002",
                    "00000000-0000-4000-8000-000000000002")


if __name__ == "__main__":
    unittest.main()
