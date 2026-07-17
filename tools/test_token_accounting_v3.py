"""Trust-critical regression tests for non-overlapping usage accounting."""

import hashlib
import unittest
import uuid

import loom_performance
import loom_usage


OWNER = "00000000-0000-4000-8000-000000000401"
SESSION = "00000000-0000-4000-8000-000000000402"
PROJECT = "p-00000000000000000000000000000403"
OPERATION = "4" * 64


def event(profile, counters, *, response="resp-1", attempt=1):
    return {
        "schema_version": 3,
        "event_id": str(uuid.uuid5(uuid.UUID(SESSION), f"{response}:{attempt}")),
        "owner_vault_id": OWNER, "project_id": PROJECT, "session_id": SESSION,
        "operation_id": OPERATION, "stage": "delegated-host", "host": "codex",
        "provider": profile.split("-")[0], "api_surface": "responses",
        "model": "model-test", "response_id": response,
        "provider_schema_version": "2026-07", "captured_at": "2026-07-17T00:00:00Z",
        "raw_response_sha256": hashlib.sha256(response.encode()).hexdigest(),
        "semantics_profile": profile, "raw_counters": counters,
        "retry_group": "request-1", "attempt_number": attempt, "duration_ns": 10,
    }


def bundle(*events):
    return {"schema_version": 3, "measurement_source": "provider",
            "expected_event_count": len(events), "events": list(events),
            "capability_receipt_id": "capability-1"}


class TokenAccountingV3Tests(unittest.TestCase):
    def test_openai_cache_and_reasoning_are_subsets_not_additive(self):
        result = loom_performance.normalize_usage(bundle(event(
            "openai-responses-v1", {"input_tokens": 100,
                "input_cached_tokens": 80, "output_tokens": 40,
                "output_reasoning_tokens": 30, "total_tokens": 140})))
        self.assertEqual("provider-complete", result["measurement_status"])
        self.assertEqual(140, result["processed_total_tokens"])
        normalized = result["events"][0]["normalized"]
        self.assertEqual(20, normalized["input_fresh_tokens"])
        self.assertEqual("subset-of-input", result["events"][0]["relationships"]["cache_read"])

    def test_anthropic_cache_writes_are_disjoint_and_included(self):
        result = loom_performance.normalize_usage(bundle(event(
            "anthropic-messages-v1", {"input_tokens": 20,
                "cache_read_input_tokens": 50, "cache_creation_input_tokens": 30,
                "cache_creation_5m_input_tokens": 10,
                "cache_creation_1h_input_tokens": 20, "output_tokens": 40,
                "total_tokens": 140})))
        self.assertEqual(140, result["processed_total_tokens"])
        self.assertEqual(100, result["events"][0]["normalized"]["input_total_tokens"])

    def test_gemini_provider_total_governs_thought_and_tool_inclusion(self):
        result = loom_performance.normalize_usage(bundle(event(
            "gemini-generate-content-v1", {"prompt_token_count": 100,
                "cached_content_token_count": 80, "candidates_token_count": 20,
                "thoughts_token_count": 40, "tool_use_prompt_token_count": 10,
                "total_token_count": 160})))
        self.assertEqual(160, result["processed_total_tokens"])

    def test_unknown_provider_is_partial_and_never_guesses_total(self):
        result = loom_performance.normalize_usage(bundle(event(
            "generic-host-v1", {"tokens": 999})))
        self.assertEqual("provider-partial", result["measurement_status"])
        self.assertIsNone(result["processed_total_tokens"])

    def test_known_provider_with_genuine_but_incomplete_fields_is_partial(self):
        result = loom_performance.normalize_usage(bundle(event(
            "openai-responses-v1", {"input_tokens": 10})))
        self.assertEqual("provider-partial", result["measurement_status"])
        self.assertIsNone(result["processed_total_tokens"])

    def test_generic_host_total_requires_host_source_and_capability_receipt(self):
        value = bundle(event("generic-host-v1", {"processed_total_tokens": 77}))
        value["measurement_source"] = "host"
        result = loom_performance.normalize_usage(value)
        self.assertEqual("host-complete", result["measurement_status"])
        self.assertEqual(77, result["processed_total_tokens"])

    def test_legacy_five_counter_claim_is_ambiguous_and_not_a_total(self):
        result = loom_performance.normalize_usage({"input_tokens": 100,
            "cache_read_tokens": 80, "output_tokens": 40,
            "tool_tokens": 10, "retry_tokens": 0})
        self.assertEqual("legacy-ambiguous", result["measurement_status"])
        self.assertIsNone(result["processed_total_tokens"])
        self.assertEqual(230, result["legacy_declared_total_tokens"])

    def test_missing_attempt_duplicate_identity_and_impossible_subset_fail(self):
        first = event("openai-responses-v1", {"input_tokens": 10,
            "input_cached_tokens": 11, "output_tokens": 2, "total_tokens": 12})
        invalid = loom_performance.normalize_usage(bundle(first))
        self.assertEqual("invalid", invalid["measurement_status"])
        omitted = bundle(first)
        omitted["expected_event_count"] = 2
        with self.assertRaisesRegex(loom_performance.PerformanceError, "omits"):
            loom_performance.normalize_usage(omitted)
        duplicate = bundle(first, dict(first))
        with self.assertRaisesRegex(loom_performance.PerformanceError, "reused"):
            loom_performance.normalize_usage(duplicate)

    def test_unavailable_has_no_total_and_span_data_is_content_free(self):
        result = loom_performance.normalize_usage(None)
        self.assertEqual("unavailable", result["measurement_status"])
        self.assertIsNone(result["processed_total_tokens"])


if __name__ == "__main__":
    unittest.main()
