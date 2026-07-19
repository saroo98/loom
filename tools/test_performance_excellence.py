"""Behavioral tests for Loom's bounded context and honest usage accounting."""

import tempfile
import unittest
import uuid
import hashlib
from pathlib import Path
from types import SimpleNamespace

import loom_performance
import loom_memory
import loom_session
import loom_observe
import loom_orchestrator
import inspect


class PerformanceExcellenceTests(unittest.TestCase):
    def test_normal_completion_reuses_one_post_host_stable_preparation(self):
        source = inspect.getsource(loom_orchestrator._complete_under_lock)
        self.assertEqual(1, source.count("loom_runtime.prepare_invocation("))

    def test_static_prefix_and_dynamic_capsules_have_independent_authority_keys(self):
        manifest = {"context_hash": "a" * 64}
        first = loom_performance.static_prefix_key(
            runtime_version="1.6.0", context_manifest=manifest,
            policy_hashes=["b" * 64], host_adapter_version="1",
            provider="openai", model="gpt-test")
        second = loom_performance.static_prefix_key(
            runtime_version="1.6.0", context_manifest=manifest,
            policy_hashes=["b" * 64], host_adapter_version="1",
            provider="openai", model="gpt-test")
        self.assertEqual(first, second)
        capsule = loom_performance.dynamic_capsule(
            request_hash="c" * 64, route_digest="sha256:" + "d" * 64,
            survey_hash="e" * 64, vault_generation=2,
            domain_digest="sha256:" + "f" * 64, plan_digest="1" * 64,
            payload={"decision": "bounded"})
        self.assertLessEqual(capsule["capsule_bytes"], 4096)
        changed = loom_performance.dynamic_capsule(
            request_hash="c" * 64, route_digest="sha256:" + "d" * 64,
            survey_hash="e" * 64, vault_generation=3,
            domain_digest="sha256:" + "f" * 64, plan_digest="1" * 64,
            payload={"decision": "bounded"})
        self.assertNotEqual(capsule["capsule_hash"], changed["capsule_hash"])

    def test_local_spans_are_bounded_monotonic_and_content_free(self):
        recorder = loom_observe.SpanRecorder("a" * 64)
        self.assertEqual("ok", recorder.measure("survey-a", lambda: "ok",
                                                counters={"files": 2}))
        receipt = recorder.receipt()
        self.assertEqual(1, receipt["span_count"])
        span = receipt["spans"][0]
        self.assertGreaterEqual(span["duration_ns"], 0)
        self.assertEqual({"files": 2}, span["counters"])
        self.assertNotIn("prompt", __import__("json").dumps(receipt).casefold())

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
        self.assertEqual(unreported["measurement_status"], "unavailable")
        self.assertIsNone(unreported["processed_total_tokens"])
        with self.assertRaisesRegex(loom_performance.PerformanceError, "all five"):
            loom_performance.normalize_usage({"input_tokens": 10})
        measured = loom_performance.normalize_usage({
            "input_tokens": 100, "cache_read_tokens": 20,
            "output_tokens": 30, "tool_tokens": 40, "retry_tokens": 10,
        })
        self.assertEqual(measured["legacy_declared_total_tokens"], 200)
        self.assertIsNone(measured["processed_total_tokens"])
        self.assertEqual(measured["measurement_status"], "legacy-ambiguous")
        self.assertEqual(measured["measurement_source"], "caller-reported")
        with self.assertRaisesRegex(loom_performance.PerformanceError, "nonzero"):
            loom_performance.normalize_usage({
                "input_tokens": 0, "cache_read_tokens": 0,
                "output_tokens": 0, "tool_tokens": 0, "retry_tokens": 0,
            })

    def test_provider_receipt_identity_is_retained_without_false_attestation(self):
        receipt = {
            "source": "provider-response", "provider": "openai",
            "model": "gpt-test", "response_id": "resp-001",
            "captured_at": "2026-07-15T12:00:00Z",
            "raw_response_sha256": hashlib.sha256(b"raw-response").hexdigest(),
            "usage": {
                "input_tokens": 100, "cache_read_tokens": 20,
                "output_tokens": 30, "tool_tokens": 40, "retry_tokens": 10,
            },
        }
        measured = loom_performance.normalize_usage(receipt)
        self.assertEqual("provider-receipt", measured["measurement_source"])
        self.assertEqual("resp-001", measured["receipt"]["response_id"])
        self.assertEqual("requires-independent-attestation",
                         measured["receipt"]["attestation_status"])
        tampered = dict(receipt, response_id="unsafe response id")
        with self.assertRaises(loom_performance.PerformanceError):
            loom_performance.normalize_usage(tampered)

    def test_production_usage_ledger_is_bounded_and_reports_real_distribution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home, install = root / "home", root / "install"
            install.mkdir()
            instance = loom_memory.initialize(home, install)
            for index in range(300):
                loom_performance.record_usage(
                    home, instance,
                    session_id=str(uuid.uuid5(uuid.UUID(instance), f"session-{index}")),
                    project_id="p-00000000000000000000000000001201",
                    intent="plan", tier="S", domains=["cli"],
                    usage={
                        "input_tokens": 100 + index,
                        "cache_read_tokens": 10,
                        "output_tokens": 50,
                        "tool_tokens": 5,
                        "retry_tokens": 0,
                    },
                    recorded_at=f"2026-07-{1 + index % 28:02d}T12:00:00Z")
            report = loom_performance.usage_report(home, instance)

            self.assertEqual(300, report["total_count"])
            self.assertEqual(256, report["retained_sample_count"])
            self.assertEqual("caller-reported", report["measurement_source"])
            self.assertIn("descriptive", report["source_limitation"])
            self.assertLessEqual(
                report["p50_total_tokens"], report["p95_total_tokens"])
            self.assertLessEqual(
                report["p95_total_tokens"], report["worst_total_tokens"])
            self.assertEqual(0, report["budget_violation_count"])
            self.assertEqual("caller-reported-only", report["certification_status"])

    def test_provider_receipts_report_each_tier_but_do_not_self_certify(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home, install = root / "home", root / "install"
            install.mkdir()
            instance = loom_memory.initialize(home, install)
            for tier in ("S", "M", "L", "XL"):
                for index in range(20):
                    response_id = f"resp-{tier.lower()}-{index:02d}"
                    usage = {
                        "input_tokens": 100, "cache_read_tokens": 20,
                        "output_tokens": 30, "tool_tokens": 10, "retry_tokens": 0,
                    }
                    loom_performance.record_usage(
                        home, instance,
                        session_id=str(uuid.uuid5(
                            uuid.UUID(instance), f"provider-{tier}-{index}")),
                        project_id="p-00000000000000000000000000001201",
                        intent="plan", tier=tier, domains=["cli"],
                        usage={
                            "source": "provider-response", "provider": "openai",
                            "model": "gpt-test", "response_id": response_id,
                            "captured_at": "2026-07-15T12:00:00Z",
                            "raw_response_sha256": hashlib.sha256(
                                response_id.encode()).hexdigest(),
                            "usage": usage,
                        })
            report = loom_performance.usage_report(home, instance)
            self.assertEqual("provider-receipt", report["measurement_source"])
            self.assertEqual(80, report["provider_receipt_count"])
            self.assertTrue(all(
                report["tiers"][tier]["provider_receipt_count"] == 20
                for tier in ("S", "M", "L", "XL")))
            self.assertEqual(
                "requires-independent-attestation", report["certification_status"])

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
            self.assertEqual(receipt.usage["measurement_status"], "legacy-ambiguous")
            self.assertEqual(receipt.usage["legacy_declared_total_tokens"], 24)
            self.assertIsNone(receipt.usage["processed_total_tokens"])

    def test_session_receipt_preserves_provider_receipt_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / "README.md").write_text("fixture\n", encoding="utf-8")
            provider_usage = {
                "source": "provider-response", "provider": "openai",
                "model": "gpt-test", "response_id": "resp-session-001",
                "captured_at": "2026-07-14T12:00:00Z",
                "raw_response_sha256": hashlib.sha256(b"session-raw").hexdigest(),
                "usage": {
                    "input_tokens": 10, "cache_read_tokens": 5,
                    "output_tokens": 4, "tool_tokens": 3, "retry_tokens": 2,
                },
            }
            controller = loom_session.SessionController(
                owner_home=root / "home",
                instance_id="00000000-0000-4000-8000-000000001202",
                handlers={"plan": lambda _context: {
                    "status": "completed", "code": "plan-ready", "success": True,
                    "metrics": {}, "evidence_ids": [], "reversible_action_ids": [],
                    "usage": provider_usage,
                }}, memory=loom_session.NoopMemoryAdapter())
            receipt = controller.run(
                "Build a command-line tool", invocation_id=str(uuid.uuid4()),
                cwd=project, now="2026-07-14T12:00:00Z")
            self.assertEqual("provider-receipt", receipt.usage["measurement_source"])
            self.assertEqual("resp-session-001", receipt.usage["receipt"]["response_id"])


if __name__ == "__main__":
    unittest.main()
