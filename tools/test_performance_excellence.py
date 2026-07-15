"""Behavioral tests for Loom's bounded context and honest usage accounting."""

import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

import loom_performance
import loom_memory
import loom_session


class PerformanceExcellenceTests(unittest.TestCase):
    def test_unchanged_context_is_read_once_then_served_from_hash_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "context.md"
            path.write_text("version one\n", encoding="utf-8")
            cache = loom_performance.ContextCache()

            first = cache.load_text(path)
            second = cache.load_text(path)
            self.assertEqual(first, second)
            self.assertEqual(cache.metrics()["disk_reads"], 1)
            self.assertEqual(cache.metrics()["cache_hits"], 1)

            path.write_bytes(b"version two is different\n")
            self.assertEqual(cache.load_text(path), "version two is different\n")
            self.assertEqual(cache.metrics()["disk_reads"], 2)

    def test_memory_budget_adapts_to_real_task_shape(self):
        small = loom_performance.adaptive_memory_budget(
            tier="S", intent="plan", domain_count=1)
        execute = loom_performance.adaptive_memory_budget(
            tier="M", intent="execute", domain_count=1)
        large = loom_performance.adaptive_memory_budget(
            tier="L", intent="plan", domain_count=3)
        portfolio = loom_performance.adaptive_memory_budget(
            tier="XL", intent="plan", domain_count=4)
        self.assertLessEqual(small["max_chars"], 512)
        self.assertFalse(execute["include_project_history"])
        self.assertLess(small["max_chars"], large["max_chars"])
        self.assertLessEqual(large["max_chars"], 4096)
        self.assertGreaterEqual(portfolio["max_chars"], large["max_chars"])
        self.assertLessEqual(portfolio["max_chars"], 4096)

    def test_usage_never_labels_a_partial_measurement_total(self):
        unreported = loom_performance.normalize_usage(None)
        self.assertEqual(unreported["measurement_status"], "unreported")
        self.assertIsNone(unreported["total_tokens"])
        with self.assertRaisesRegex(loom_performance.PerformanceError, "all five"):
            loom_performance.normalize_usage({"input_tokens": 10})
        measured = loom_performance.normalize_usage({
            "input_tokens": 100, "cache_read_tokens": 20,
            "output_tokens": 30, "tool_tokens": 40, "retry_tokens": 10,
        })
        self.assertEqual(measured["total_tokens"], 200)

    def test_performance_benchmarks_cover_all_lifecycle_shapes(self):
        report = loom_performance.evaluate_benchmarks()
        self.assertEqual(set(report["scenarios"]), {
            "cold-start", "warm-session", "project-switch", "resume",
            "year-long-memory"})
        self.assertTrue(report["passed"], report)
        self.assertTrue(report["scenarios"]["tiny-task"]["planning_le_implementation"]
                        if "tiny-task" in report["scenarios"] else
                         report["tiny_task"]["planning_le_implementation"])

    def test_observed_benchmark_distinguishes_disk_reads_cache_hits_and_fixture_cost(self):
        result = loom_performance.run_observed_benchmarks()
        self.assertEqual(set(result["scenarios"]), {
            "cold_start", "warm_session", "project_switch", "resume", "year_long"})
        self.assertEqual(result["scenarios"]["cold_start"]["disk_reads"], 2)
        self.assertEqual(result["scenarios"]["warm_session"]["disk_reads"], 0)
        self.assertEqual(result["scenarios"]["warm_session"]["cache_hits"], 2)
        self.assertEqual(result["scenarios"]["project_switch"]["disk_reads"], 1)
        self.assertEqual(result["scenarios"]["resume"]["disk_reads"], 1)
        self.assertLessEqual(result["scenarios"]["year_long"]["capsule_chars"], 512)
        self.assertEqual(result["tiny_task"]["measurement_kind"],
                         "synthetic-policy-fixture")
        self.assertTrue(all(type(item["elapsed_ns"]) is int and item["elapsed_ns"] >= 0
                            for item in result["scenarios"].values()))

    def test_execute_capsule_excludes_project_history_and_uses_adaptive_cap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home, install = root / "home", root / "install"
            install.mkdir()
            instance = loom_memory.initialize(home, install)
            project_id = loom_memory.project_identity(instance, root / "project")
            domain = loom_memory.admit_learning(
                home, instance, scope="domain", category="domain",
                signal="route-succeeded", future_decision="routing-strategy",
                evidence_count=3, confidence=1.0, domain="cli")
            project = loom_memory.admit_learning(
                home, instance, scope="project", category="process",
                signal="artifact-unused", future_decision="artifact-selection",
                evidence_count=2, confidence=1.0, domain="cli",
                project_id=project_id)
            adapter = loom_session.LocalMemoryAdapter(
                owner_home=home, instance_id=instance)
            context = SimpleNamespace(
                intent="execute", project_id=project_id,
                prepared=SimpleNamespace(
                    domains=("cli",), route_contract={"tier": "M"}))
            selected = adapter.select(context)
            identifiers = {item["id"] for item in selected}
            self.assertIn(domain["id"], identifiers)
            self.assertNotIn(project["id"], identifiers)
            self.assertLessEqual(
                len(__import__("json").dumps(selected, ensure_ascii=False)), 640)

    def test_session_receipt_reports_complete_usage_or_explicit_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / "README.md").write_text("fixture\n", encoding="utf-8")
            controller = loom_session.SessionController(
                owner_home=root / "home",
                instance_id="00000000-0000-4000-8000-000000001201",
                handlers={"plan": lambda _context: {
                    "status": "completed", "code": "plan-ready", "success": True,
                    "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
                    "usage": {
                        "input_tokens": 10, "cache_read_tokens": 5,
                        "output_tokens": 4, "tool_tokens": 3, "retry_tokens": 2,
                    },
                }}, memory=loom_session.NoopMemoryAdapter())
            receipt = controller.run(
                "Build a command-line tool", invocation_id=str(uuid.uuid4()),
                cwd=project, now="2026-07-14T12:00:00Z")
            self.assertEqual(receipt.usage["measurement_status"], "measured")
            self.assertEqual(receipt.usage["total_tokens"], 24)


if __name__ == "__main__":
    unittest.main()
