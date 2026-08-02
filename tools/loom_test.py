#!/usr/bin/env python3
"""Deterministic fast PR gate and complete release test runner."""

import argparse
import contextlib
import io
import json
import os
import re
import sys
import time
import unittest
from pathlib import Path

import loom_docs
import loom_reliability


CONTAINMENT_FAST_TEST = (
    "test_automatic_lifecycle.AutomaticLifecycleTests."
    + ("test_windows_detached_verifier_descendants_are_dead_before_evidence_is_sealed"
       if os.name == "nt" else
       "test_posix_verifier_descendants_are_dead_before_evidence_is_sealed")
)
FAST_GATE_MAX_SECONDS = 30.0
WINDOWS_FAST_GATE_MAX_SECONDS = 45.0
TEST_MODULE = re.compile(r"^test_[A-Za-z0-9_]+$")
AUTHORIZED_SKIP_REASON_CODES = {
    "platform-boundary", "host-capability-unavailable", "tool-unavailable",
}


def skip_reason_code(reason):
    """Map a private unittest reason onto one public, reviewable policy code."""
    value = str(reason).casefold()
    if re.search(
            r"windows|non-windows|posix|ntfs|fifo|platform|macos|linux|darwin|"
            r"chmod|alternate (?:data )?streams?|native", value):
        return "platform-boundary"
    if re.search(r"\b(?:git|cargo|rust|toolchain)\b.*unavailable", value):
        return "tool-unavailable"
    if re.search(
            r"unavailable|unsupported|symlinks?|hardlinks?|xattrs?|key store|"
            r"backend|privilege", value):
        return "host-capability-unavailable"
    return "unclassified"


def fast_gate_max_seconds(platform_name=None):
    """Return the bounded fast-gate ceiling for one host process model."""
    name = os.name if platform_name is None else platform_name
    return WINDOWS_FAST_GATE_MAX_SECONDS if name == "nt" else FAST_GATE_MAX_SECONDS


FAST_TESTS = (
    "test_scorecard_phase6.ScorecardPhase6Tests."
    "test_tamper_duplicate_wrong_subject_and_stale_evidence_fail_closed",
    "test_adapter_protocol_v2.AdapterProtocolV2Tests."
    "test_protocol_mismatch_invalid_depth_and_oversize_fail_closed",
    "test_adapter_conformance_v2.AdapterConformanceV2Tests."
    "test_disposable_profiles_share_one_runtime_and_touch_no_project",
    "test_token_accounting_v3.TokenAccountingV3Tests."
    "test_openai_cache_and_reasoning_are_subsets_not_additive",
    "test_token_accounting_v3.TokenAccountingV3Tests."
    "test_anthropic_cache_writes_are_disjoint_and_included",
    "test_token_accounting_v3.TokenAccountingV3Tests."
    "test_gemini_provider_total_governs_thought_and_tool_inclusion",
    "test_token_accounting_v3.TokenAccountingV3Tests."
    "test_unknown_provider_is_partial_and_never_guesses_total",
    "test_token_accounting_v3.TokenAccountingV3Tests."
    "test_missing_attempt_duplicate_identity_and_impossible_subset_fail",
    "test_tier_s_fast_path.TierSFastPathTests.test_deceptive_small_consequences_promote",
    "test_tier_s_fast_path.TierSFastPathTests.test_ordinary_small_work_stays_tier_s",
    "test_tier_s_fast_path.TierSFastPathTests.test_small_wording_never_overrides_observed_scope",
    "test_tier_s_fast_path.TierSFastPathTests."
    "test_every_small_promotion_trigger_prevents_tier_s",
    "test_owner_message.OwnerMessageTests."
    "test_every_state_is_closed_and_never_exceeds_two_lines",
    "test_continuation_authority.ContinuationAuthorityTests."
    "test_complete_boolean_truth_table_allows_only_the_safe_vector",
    "test_cache_policy.CachePolicyTests.test_exact_dependency_subtrees_invalidate",
    "test_privacy_excellence.PrivacyExcellenceTests."
    "test_firewall_rejects_common_provider_and_high_entropy_credentials",
    "test_privacy_excellence.PrivacyExcellenceTests."
    "test_firewall_scans_binary_content_and_every_filename",
    CONTAINMENT_FAST_TEST,
    "test_production_orchestrator.ProductionOrchestratorTests."
    "test_unknown_domain_is_promoted_out_of_the_small_lifecycle",
    "test_production_orchestrator.ProductionOrchestratorTests."
    "test_plan_completion_rejects_artifact_rows_outside_the_sealed_contract",
    "test_loom_learning.AutomaticLearningTests."
    "test_tampered_learning_event_fails_closed",
    "test_reliability_excellence.ReliabilityExcellenceTests."
    "test_uninstaller_fails_closed_when_owned_file_changed",
    "test_documentation_coherence.DocumentationCoherenceTests."
    "test_every_capability_is_mechanical_with_existing_proof_or_advisory",
    "test_loom_runtime.InvalidWorldStateTests."
    "test_invalid_lifecycle_preserves_only_valid_manifest_route_for_diagnosis",
    "test_owner_learning_phase2.OwnerLearningPhase2Tests."
    "test_missing_crypto_helper_never_falls_back_to_json_learning",
    "test_unknown_domain_routing.UnknownDomainRoutingTests."
    "test_recognized_unknown_keeps_identity_but_cannot_activate_memory",
    "test_domain_evidence.DomainEvidenceTests.test_complete_bundle_is_gate_ready",
    "test_domain_evidence.DomainEvidenceTests.test_semantic_mutation_under_same_id_is_rejected",
    "test_domain_benchmark.DomainBenchmarkTests.test_locked_corpus_meets_release_thresholds",
    "test_truth_shadow_corpus_phase4.TruthShadowCorpusPhase4Tests."
    "test_locked_corpus_meets_every_promotion_threshold",
    "test_workspace_boundaries.WorkspaceBoundaryTests."
    "test_registered_nested_worktree_is_independent_of_parent_world",
    "test_planning_evaluation.PlanningEvaluationTests."
    "test_release_corpus_has_zero_critical_failures",
    "test_unknown_domain_learning.UnknownDomainLearningTests."
    "test_gate_ready_invariant_reuses_only_in_exact_scope",
)


class TimingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._statuses = {}
        self.timings = []

    def startTest(self, test):
        self._started_at = time.perf_counter()
        self._statuses[test.id()] = "passed"
        super().startTest(test)

    def stopTest(self, test):
        elapsed = time.perf_counter() - self._started_at
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

    def addSubTest(self, test, subtest, err):
        if err is not None:
            status = ("failed" if issubclass(err[0], test.failureException)
                      else "error")
            if self._statuses.get(test.id()) != "error":
                self._statuses[test.id()] = status
        super().addSubTest(test, subtest, err)

    def addUnexpectedSuccess(self, test):
        self._statuses[test.id()] = "failed"
        super().addUnexpectedSuccess(test)

    def addSkip(self, test, reason):
        self._statuses[test.id()] = "skipped"
        super().addSkip(test, reason)


def _execute_suite(suite, *, mode, budget, verbosity, selected_modules=None):
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
    if selected_modules is not None:
        report["selected_modules"] = list(selected_modules)
    return report


def run(mode, *, max_seconds=None, verbosity=1):
    if mode == "fast":
        suite = unittest.defaultTestLoader.loadTestsFromNames(FAST_TESTS)
        budget = fast_gate_max_seconds() if max_seconds is None else float(max_seconds)
    elif mode == "full":
        suite = unittest.defaultTestLoader.discover(
            start_dir=str(Path(__file__).parent), pattern="test_*.py")
        budget = None if max_seconds is None else float(max_seconds)
    else:
        raise ValueError("mode must be fast or full")
    return _execute_suite(
        suite, mode=mode, budget=budget, verbosity=verbosity)


def run_modules(modules, *, start_dir=None, max_seconds=None, verbosity=1):
    """Run an exact closed module inventory without refreshing global evidence."""
    if not isinstance(modules, (list, tuple)) or not modules \
            or len(modules) != len(set(modules)) \
            or any(not isinstance(module, str) or TEST_MODULE.fullmatch(module) is None
                   for module in modules):
        raise ValueError("module inventory is invalid")
    root = Path(__file__).parent if start_dir is None else Path(start_dir).resolve()
    if not root.is_dir():
        raise ValueError("module inventory root is invalid")
    before_modules = set(sys.modules)
    sys.path.insert(0, str(root))
    try:
        suite = unittest.defaultTestLoader.loadTestsFromNames(list(modules))
        return _execute_suite(
            suite, mode="modules",
            budget=None if max_seconds is None else float(max_seconds),
            verbosity=verbosity, selected_modules=list(modules))
    finally:
        sys.path.remove(str(root))
        for name in set(sys.modules) - before_modules:
            module = sys.modules.get(name)
            filename = getattr(module, "__file__", None)
            if filename and Path(filename).resolve().is_relative_to(root):
                sys.modules.pop(name, None)


def refresh_final_evidence(root, report):
    """Refresh inventory after a complete correctness-clean suite, never a partial run."""
    correctness_clean = report.get("mode") == "full" \
        and report.get("successful") is True \
        and report.get("capability_complete") is True \
        and report.get("failures") == 0 and report.get("errors") == 0 \
        and report.get("skipped") == 0 \
        and report.get("within_budget") is True \
        and type(report.get("tests_run")) is int and report["tests_run"] > 0
    if not correctness_clean:
        raise loom_docs.DocsError(
            "generated evidence requires a correctness-clean complete test suite")
    evidence = loom_docs.refresh_evidence(
        root, expected_test_methods=report.get("tests_run"))
    return {
        "status": "refreshed",
        "discovered_test_methods": evidence["discovered_test_methods"],
    }


def _validated_output_path(value):
    """Reject an unusable report destination before the test suite starts."""
    path = Path(value)
    parent = path.parent
    if not parent.is_dir():
        raise ValueError("output parent directory does not exist")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("output must be a regular file path, not a redirected path")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run Loom's bounded fast gate or complete release suite.")
    parser.add_argument("mode", choices=("fast", "full"))
    parser.add_argument("--max-seconds", type=float)
    parser.add_argument("--output")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--refresh-generated-evidence", action="store_true")
    args = parser.parse_args(argv)
    evidence_root = Path(__file__).resolve().parents[1]
    if args.refresh_generated_evidence and args.mode != "full":
        parser.error("generated evidence refresh requires full mode")
    output_path = None
    if args.output:
        try:
            output_path = _validated_output_path(args.output)
        except ValueError as exc:
            parser.error(str(exc))
    evidence_path = evidence_root / "docs" / "generated-evidence.json"
    evidence_existed = evidence_path.is_file() and not evidence_path.is_symlink()
    evidence_before = evidence_path.read_bytes() if evidence_existed else None

    def restore_evidence():
        if evidence_existed:
            loom_reliability.atomic_write_bytes(evidence_path, evidence_before)
        elif evidence_path.exists() and evidence_path.is_file() \
                and not evidence_path.is_symlink():
            evidence_path.unlink()

    if args.refresh_generated_evidence:
        try:
            # Bind the checked-in inventory to the final source tree before that
            # same tree audits documentation coherence. A second refresh below
            # occurs only after the complete correctness suite passes.
            loom_docs.refresh_evidence(evidence_root)
        except loom_docs.DocsError as exc:
            parser.error(str(exc))
    try:
        report = run(
            args.mode, max_seconds=args.max_seconds,
            verbosity=0 if args.quiet else 1)
    except BaseException:
        if args.refresh_generated_evidence:
            restore_evidence()
        raise
    if args.refresh_generated_evidence:
        try:
            report["generated_evidence"] = refresh_final_evidence(
                evidence_root, report)
        except loom_docs.DocsError as exc:
            restore_evidence()
            report["generated_evidence"] = {
                "status": "failed", "detail": str(exc)}
            report["successful"] = False
            report["status"] = "failed"
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output_path is not None:
        output_path.write_text(text, encoding="utf-8")
    if output_path is not None and args.quiet:
        print(json.dumps({
            "capability_complete": report["capability_complete"],
            "errors": report["errors"],
            "failures": report["failures"],
            "status": report["status"],
            "successful": report["successful"],
            "tests_run": report["tests_run"],
        }, sort_keys=True))
    else:
        print(text, end="")
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
