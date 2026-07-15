#!/usr/bin/env python3
"""Deterministic fast PR gate and complete release test runner."""

import argparse
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
    result = unittest.TextTestRunner(
        stream=sys.stderr, verbosity=verbosity, resultclass=TimingResult).run(suite)
    elapsed = time.perf_counter() - started
    within_budget = budget is None or elapsed <= budget
    report = {
        "schema_version": 1, "mode": mode, "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "elapsed_seconds": round(elapsed, 6),
        "max_seconds": budget, "within_budget": within_budget,
        "successful": result.wasSuccessful() and within_budget,
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
