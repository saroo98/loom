#!/usr/bin/env python3
"""Deterministic fast PR gate and complete release test runner."""

import argparse
import contextlib
import io
import json
import sys
import time
import unittest
from pathlib import Path


FAST_TESTS = (
    "test_privacy_excellence.PrivacyExcellenceTests."
    "test_firewall_rejects_common_provider_and_high_entropy_credentials",
    "test_privacy_excellence.PrivacyExcellenceTests."
    "test_firewall_scans_binary_content_and_every_filename",
    "test_automatic_lifecycle.AutomaticLifecycleTests."
    "test_detached_verifier_descendants_are_dead_before_evidence_is_sealed",
    "test_production_orchestrator.ProductionOrchestratorTests."
    "test_unknown_domain_is_promoted_out_of_the_small_lifecycle",
    "test_production_orchestrator.ProductionOrchestratorTests."
    "test_plan_completion_rejects_artifact_rows_outside_the_sealed_contract",
    "test_loom_learning.AutomaticLearningTests."
    "test_storage_boundary_rejects_domain_semantics_from_global_learning",
    "test_loom_learning.AutomaticLearningTests."
    "test_composite_project_attributes_learning_to_every_domain",
    "test_reliability_excellence.ReliabilityExcellenceTests."
    "test_uninstaller_fails_closed_when_owned_file_changed",
    "test_documentation_coherence.DocumentationCoherenceTests."
    "test_every_capability_is_mechanical_with_existing_proof_or_advisory",
    "test_loom_runtime.InvalidWorldStateTests."
    "test_invalid_lifecycle_preserves_only_valid_manifest_route_for_diagnosis",
    "test_owner_learning_phase2.OwnerLearningPhase2Tests."
    "test_active_task_language_never_inherits_ambient_web_domains",
    "test_owner_learning_phase2.OwnerLearningPhase2Tests."
    "test_per_memory_effects_prevent_session_wide_credit",
    "test_owner_learning_phase2.OwnerLearningPhase2Tests."
    "test_derived_forgetting_removes_children_and_checkpoints_floor",
    "test_unknown_domain_routing.UnknownDomainRoutingTests."
    "test_recognized_unknown_keeps_identity_but_cannot_activate_memory",
    "test_domain_evidence.DomainEvidenceTests.test_complete_bundle_is_gate_ready",
    "test_domain_evidence.DomainEvidenceTests.test_semantic_mutation_under_same_id_is_rejected",
    "test_domain_benchmark.DomainBenchmarkTests.test_locked_corpus_meets_release_thresholds",
    "test_unknown_domain_learning.UnknownDomainLearningTests."
    "test_gate_ready_invariant_reuses_only_in_exact_scope",
)


class TimingResult(unittest.TextTestResult):
    def startTest(self, test):
        self._started_at = time.perf_counter()
        self._statuses = getattr(self, "_statuses", {})
        self._statuses[test.id()] = "passed"
        super().startTest(test)

    def stopTest(self, test):
        elapsed = time.perf_counter() - self._started_at
        self.timings = getattr(self, "timings", [])
        self.timings.append({
            "test": test.id(), "seconds": round(elapsed, 6),
            "status": self._statuses[test.id()],
        })
        super().stopTest(test)

    def addFailure(self, test, err):
        self._statuses[test.id()] = "failed"
        super().addFailure(test, err)

    def addError(self, test, err):
        self._statuses[test.id()] = "error"
        super().addError(test, err)

    def addSkip(self, test, reason):
        self._statuses[test.id()] = "skipped"
        super().addSkip(test, reason)


def run(mode, *, max_seconds=None, verbosity=1):
    if mode == "fast":
        suite = unittest.defaultTestLoader.loadTestsFromNames(FAST_TESTS)
        budget = 30.0 if max_seconds is None else float(max_seconds)
    elif mode == "full":
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(Path(__file__).parent), pattern="test_*.py")
        budget = None if max_seconds is None else float(max_seconds)
    else:
        raise ValueError("mode must be fast or full")
    started = time.perf_counter()
    captured_stdout = io.StringIO()
    with contextlib.redirect_stdout(captured_stdout):
        result = unittest.TextTestRunner(
            stream=sys.stderr, verbosity=verbosity, resultclass=TimingResult).run(suite)
    elapsed = time.perf_counter() - started
    within_budget = budget is None or elapsed <= budget
    skip_receipts = sorted(
        ({"test": test.id(), "reason": str(reason)} for test, reason in result.skipped),
        key=lambda item: item["test"])
    capability_complete = not skip_receipts
    successful = result.wasSuccessful() and within_budget and capability_complete
    report = {
        "schema_version": 1, "mode": mode, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "elapsed_seconds": round(elapsed, 6),
        "suppressed_stdout_chars": len(captured_stdout.getvalue()),
        "max_seconds": budget, "within_budget": within_budget,
        "capability_complete": capability_complete,
        "status": ("passed" if successful else
                   "passed-with-capability-skips" if result.wasSuccessful()
                   and within_budget else "failed"),
        "successful": successful,
        "skip_receipts": skip_receipts,
        "timings": sorted(
            getattr(result, "timings", []),
            key=lambda item: (-item["seconds"], item["test"])),
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run Loom's bounded fast gate or complete release suite.")
    parser.add_argument("mode", choices=("fast", "full"))
    parser.add_argument("--max-seconds", type=float)
    parser.add_argument("--output")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    report = run(
        args.mode, max_seconds=args.max_seconds,
        verbosity=0 if args.quiet else 1)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
