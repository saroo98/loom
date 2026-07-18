#!/usr/bin/env python3
"""Run bounded, deterministic trust-critical mutation tests in disposable copies."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


MUTATIONS = (
    ("usage-openai-double-cache", "tools/loom_usage.py",
     "if cached > input_total or reasoning > output:\n        raise UsageError(\"OpenAI subset counter exceeds its containing total\")\n    processed = input_total + output",
     "if cached > input_total or reasoning > output:\n        raise UsageError(\"OpenAI subset counter exceeds its containing total\")\n    processed = input_total + cached + output",
     "test_token_accounting_v3.TokenAccountingV3Tests."
     "test_openai_cache_and_reasoning_are_subsets_not_additive"),
    ("usage-anthropic-omit-write", "tools/loom_usage.py",
     "input_total = fresh + read + write",
     "input_total = fresh + read",
     "test_token_accounting_v3.TokenAccountingV3Tests."
     "test_anthropic_cache_writes_are_disjoint_and_included"),
    ("usage-generic-false-complete", "tools/loom_usage.py",
     'state = "provider-partial" if profile == "generic-host-v1" else "provider-complete"',
     'state = "provider-complete"',
     "test_token_accounting_v3.TokenAccountingV3Tests."
     "test_unknown_provider_is_partial_and_never_guesses_total"),
    ("event-rank-order", "tools/loom_vault.py",
     "rank = (device_counter << 32) | tie_breaker",
     "rank = (device_counter << 31) | tie_breaker",
     "test_loom_merge_model.MergeReferenceModelTests."
     "test_production_rank_preserves_the_full_counter_word"),
    ("archive-collision", "tools/loom_plugin_package.py",
     "if canonical in seen:", "if False and canonical in seen:",
     "test_release_asset.ReleaseAssetTests.test_extra_member_and_case_alias_fail_closed"),
    ("runtime-hash", "tools/loom_update.py",
     "hashlib.sha256(path.read_bytes()).hexdigest() != item[\"sha256\"]",
     "hashlib.sha256(path.read_bytes()).hexdigest() == item[\"sha256\"]",
     "test_loom_update_v11.UpdateTests."
     "test_exact_existing_runtime_receipt_rejects_changed_owned_bytes"),
    ("pair-sender-pin", "tools/loom_transfer.py",
     "observed_sender != expected_sender_fingerprint",
     "observed_sender == expected_sender_fingerprint",
     "test_loom_transfer_v11.TransferTests."
     "test_pairing_requires_owner_authorized_sender_fingerprint"),
    ("cut-root-hash", "tools/loom_release.py",
     "manifest[\"root_sha256\"] != _canonical_hash(body)",
     "manifest[\"root_sha256\"] == _canonical_hash(body)",
     "test_release_standard.ReleaseStandardTests."
     "test_pristine_public_cut_is_independently_verifiable_without_git"),
    ("owner-learning-scope-firewall", "tools/loom_domain.py",
     "scored = [item for item in scored if item[3]]",
     "scored = list(scored)",
     "test_owner_learning_phase2.OwnerLearningPhase2Tests."
     "test_active_task_language_never_inherits_ambient_web_domains"),
    ("owner-learning-severe-harm", "tools/loom_vault.py",
     "if payload[\"serious_harm\"]:\n                record = self._decrypt_record(row)",
     "if False and payload[\"serious_harm\"]:\n                record = self._decrypt_record(row)",
     "test_owner_learning_phase2.OwnerLearningPhase2Tests."
     "test_serious_verified_harm_quarantines_immediately"),
    ("owner-learning-selection-is-not-use", "tools/loom_vault.py",
     'reference = row["last_applied"] or row["last_helped"] \\\n                    or row["last_hurt"] or record["created_at"]',
     'reference = row["last_selected"] or row["last_helped"] \\\n                    or row["last_hurt"] or record["created_at"]',
     "test_owner_learning_phase2.OwnerLearningPhase2Tests."
     "test_selection_is_not_application_and_does_not_prevent_dormancy"),
    ("owner-learning-derived-forgetting", "tools/loom_vault.py",
     "frontier = [record_id]", "frontier = []",
     "test_owner_learning_phase2.OwnerLearningPhase2Tests."
     "test_derived_forgetting_removes_children_and_checkpoints_floor"),
    ("domain-memory-scope", "tools/loom_domain_learning.py",
     'return (domain in invariant["domain_ids"]',
     'return (True',
     "test_unknown_domain_learning.UnknownDomainLearningTests."
     "test_gate_ready_invariant_reuses_only_in_exact_scope"),
    ("domain-route-digest", "tools/loom_domain_contract.py",
     'if claimed != digest("domain-route-v1", body):',
     'if False and claimed != digest("domain-route-v1", body):',
     "test_unknown_domain_routing.UnknownDomainRoutingTests."
     "test_semantic_route_mutation_invalidates_digest"),
    ("domain-bundle-target", "tools/loom_domain_bundle.py",
     'if receipt["target_fingerprint"] != target:',
     'if False and receipt["target_fingerprint"] != target:',
     "test_domain_evidence.DomainEvidenceTests.test_wrong_target_blocks_bundle"),
    ("domain-invariant-digest", "tools/loom_domain_contract.py",
     'if claimed != digest("domain-invariant-v1", body):',
     'if False and claimed != digest("domain-invariant-v1", body):',
     "test_domain_evidence.DomainEvidenceTests."
     "test_invariant_digest_rejects_semantic_mutation_directly"),
    ("adapter-protocol-overlap", "tools/loom_adapter_protocol.py",
     "or minimum > maximum or not minimum <= PROTOCOL_VERSION <= maximum:",
     "or minimum > maximum or False:",
     "test_adapter_protocol_v2.AdapterProtocolV2Tests."
     "test_protocol_mismatch_invalid_depth_and_oversize_fail_closed"),
    ("adapter-host-truth", "tools/loom_host_registry.py",
     '"connectable": value["evidence_status"] in CONNECTABLE,',
     '"connectable": True,',
     "test_adapter_protocol_v2.AdapterProtocolV2Tests."
     "test_host_registry_never_calls_experimental_or_unsupported_supported"),
    ("adapter-capability-binding", "tools/loom_adapters.py",
     'if version == 2 and (not capability_path.is_file()\n'
     '                         or receipt.get("capability_receipt_sha256") != _sha(\n'
     '                             capability_path.read_bytes())):',
     'if version == 2 and (not capability_path.is_file()\n'
     '                         or False):',
     "test_loom_plugin_adapters_v11.AdapterTests."
     "test_changed_capability_receipt_blocks_adapter_upgrade"),
    ("score-claimed-only", "tools/loom_scorecard.py",
     'and record["evidence_class"] != "claimed-only":',
     'and True:',
     "test_scorecard_phase6.ScorecardPhase6Tests."
     "test_claimed_only_never_earns_points"),
    ("score-stale-evidence", "tools/loom_scorecard.py",
     'and _time(record["expires_at"], "evidence expires_at") <= evaluated:',
     'and False:',
     "test_scorecard_phase6.ScorecardPhase6Tests."
     "test_tamper_duplicate_wrong_subject_and_stale_evidence_fail_closed"),
    ("score-duplicate-requirement", "tools/loom_scorecard.py",
     'if record["requirement_id"] in seen_requirements:',
     'if False and record["requirement_id"] in seen_requirements:',
     "test_scorecard_phase6.ScorecardPhase6Tests."
     "test_tamper_duplicate_wrong_subject_and_stale_evidence_fail_closed"),
    ("score-trust-regression", "tools/loom_scorecard.py",
     '"status": "blocked" if blocking else "passed",',
     '"status": "passed",',
     "test_scorecard_phase6.ScorecardPhase6Tests."
     "test_trust_regression_blocks_while_adoption_decrease_is_informational"),
    ("score-external-authority", "tools/loom_scorecard.py",
     'if trusted is None or not loom_release._signature_valid(record, trusted):',
     'if False:',
     "test_scorecard_phase6.ScorecardPhase6Tests."
     "test_self_asserted_external_evidence_cannot_inflate_a_score"),
)


class MutationError(RuntimeError):
    pass


def _ignore(_directory, names):
    blocked = {".git", "target", "__pycache__", ".pytest_cache"}
    return [name for name in names if name in blocked or name.endswith((".pyc", ".pyo"))]


def run(root, *, minimum_score=100, timeout=120):
    root = Path(root).resolve()
    if not (root / "tools").is_dir() or not 1 <= minimum_score <= 100:
        raise MutationError("mutation root or score is invalid")
    receipts = []
    for mutation_id, relative, original, replacement, test_name in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="loom-mutation-") as temporary:
            sandbox = Path(temporary) / "loom"
            shutil.copytree(root, sandbox, ignore=_ignore)
            target = sandbox / relative
            text = target.read_text(encoding="utf-8")
            if text.count(original) != 1:
                raise MutationError(f"{mutation_id} source anchor is not unique")
            target.write_text(text.replace(original, replacement), encoding="utf-8")
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                               HOME=str(sandbox / ".test-home"),
                               USERPROFILE=str(sandbox / ".test-home"),
                               PYTHONPATH=str(sandbox / "tools"))
            try:
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "unittest", test_name],
                    cwd=sandbox / "tools", env=environment,
                    capture_output=True, text=True, timeout=timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                raise MutationError(f"{mutation_id} exceeded its timeout") from exc
            receipts.append({"id": mutation_id, "test": test_name,
                             "killed": result.returncode != 0,
                             "returncode": result.returncode})
    killed = sum(item["killed"] for item in receipts)
    score = round(killed * 100 / len(receipts), 2)
    return {"schema_version": 1,
            "status": "passed" if score >= minimum_score else "failed",
            "mutants": len(receipts), "killed": killed, "score": score,
            "minimum_score": minimum_score, "receipts": receipts}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--minimum-score", type=int, default=100)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = run(args.root, minimum_score=args.minimum_score, timeout=args.timeout)
    except (MutationError, OSError, UnicodeError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).resolve().write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
