#!/usr/bin/env python3
"""Provider-aware, non-overlapping token accounting for Loom usage receipt v3."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid


SCHEMA_VERSION = 3
MAX_EVENTS = 128
MAX_RAW_COUNTERS = 32
MAX_COUNTER_NAME = 96
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROJECT = re.compile(r"^p-[0-9a-f]{32}$")
PROFILES = {
    "openai-responses-v1",
    "anthropic-messages-v1",
    "gemini-generate-content-v1",
    "gemini-interactions-v1",
    "generic-host-v1",
}
EVENT_FIELDS = {
    "schema_version", "event_id", "owner_vault_id", "project_id", "session_id",
    "operation_id", "stage", "host", "provider", "api_surface", "model",
    "response_id", "provider_schema_version", "captured_at", "raw_response_sha256",
    "semantics_profile", "raw_counters", "retry_group", "attempt_number",
    "duration_ns",
}
BUNDLE_FIELDS = {
    "schema_version", "measurement_source", "expected_event_count", "events",
    "capability_receipt_id",
}


class UsageError(RuntimeError):
    pass


class PartialUsage(UsageError):
    pass


def _integer(value, name, *, optional=False):
    if value is None and optional:
        return None
    if type(value) is not int or value < 0:
        raise UsageError(f"{name} must be a non-negative integer")
    return value


def _counter(raw, name, *, optional=False):
    if name not in raw or raw.get(name) is None:
        if optional:
            return None
        raise PartialUsage(f"provider did not expose required counter {name}")
    return _integer(raw.get(name), name, optional=optional)


def _timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise UsageError("captured_at must be a timezone-aware timestamp") from exc
    if parsed.tzinfo is None:
        raise UsageError("captured_at must be a timezone-aware timestamp")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _identity(event):
    for name in ("event_id", "owner_vault_id", "session_id"):
        try:
            canonical = str(uuid.UUID(str(event.get(name))))
        except (TypeError, ValueError, AttributeError) as exc:
            raise UsageError(f"{name} must be a canonical UUID") from exc
        if canonical != event.get(name):
            raise UsageError(f"{name} must be a canonical UUID")
    if not isinstance(event.get("project_id"), str) or not PROJECT.fullmatch(
            event["project_id"]):
        raise UsageError("project_id is invalid")
    if not isinstance(event.get("operation_id"), str) or not HEX64.fullmatch(
            event["operation_id"]):
        raise UsageError("operation_id is invalid")
    for name in ("stage", "host", "provider", "api_surface", "model",
                 "provider_schema_version", "retry_group"):
        if not isinstance(event.get(name), str) or not SAFE_TEXT.fullmatch(event[name]):
            raise UsageError(f"{name} is invalid")
    response = event.get("response_id")
    if response is not None and (not isinstance(response, str) or not SAFE_TEXT.fullmatch(response)):
        raise UsageError("response_id is invalid")
    digest = event.get("raw_response_sha256")
    if digest is not None and (not isinstance(digest, str) or not HEX64.fullmatch(digest)):
        raise UsageError("raw_response_sha256 is invalid")


def _raw_counters(value):
    if not isinstance(value, dict) or len(value) > MAX_RAW_COUNTERS:
        raise UsageError("raw_counters must be a bounded object")
    normalized = {}
    for name, count in value.items():
        if not isinstance(name, str) or not 1 <= len(name) <= MAX_COUNTER_NAME \
                or re.fullmatch(r"[a-z][a-z0-9_.-]*", name) is None:
            raise UsageError("raw counter name is invalid")
        normalized[name] = _integer(count, name, optional=True)
    return normalized


def _base_normalized():
    return {
        "input_total_tokens": None,
        "input_fresh_tokens": None,
        "input_cache_read_tokens": None,
        "input_cache_write_tokens": None,
        "output_total_tokens": None,
        "output_reasoning_tokens": None,
        "tool_input_tokens": None,
        "provider_total_tokens": None,
        "processed_total_tokens": None,
    }


def _openai(raw):
    allowed = {"input_tokens", "input_cached_tokens", "output_tokens",
               "output_reasoning_tokens", "total_tokens"}
    if set(raw) - allowed:
        raise UsageError("OpenAI receipt contains unknown counters")
    input_total = _counter(raw, "input_tokens")
    cached = _counter(raw, "input_cached_tokens", optional=True) or 0
    output = _counter(raw, "output_tokens")
    reasoning = _counter(raw, "output_reasoning_tokens", optional=True) or 0
    provider_total = _counter(raw, "total_tokens", optional=True)
    if cached > input_total or reasoning > output:
        raise UsageError("OpenAI subset counter exceeds its containing total")
    processed = input_total + output
    if provider_total is not None and provider_total != processed:
        raise UsageError("OpenAI provider total does not reconcile")
    return {
        **_base_normalized(), "input_total_tokens": input_total,
        "input_fresh_tokens": input_total - cached,
        "input_cache_read_tokens": cached, "output_total_tokens": output,
        "output_reasoning_tokens": reasoning, "provider_total_tokens": provider_total,
        "processed_total_tokens": processed,
    }, {"cache_read": "subset-of-input", "reasoning": "subset-of-output"}


def _anthropic(raw):
    allowed = {"input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
               "cache_creation_5m_input_tokens", "cache_creation_1h_input_tokens",
               "output_tokens", "total_tokens"}
    if set(raw) - allowed:
        raise UsageError("Anthropic receipt contains unknown counters")
    fresh = _counter(raw, "input_tokens")
    read = _counter(raw, "cache_read_input_tokens", optional=True) or 0
    write = _counter(raw, "cache_creation_input_tokens", optional=True) or 0
    write_5m = _counter(raw, "cache_creation_5m_input_tokens", optional=True)
    write_1h = _counter(raw, "cache_creation_1h_input_tokens", optional=True)
    if write_5m is not None or write_1h is not None:
        if (write_5m or 0) + (write_1h or 0) != write:
            raise UsageError("Anthropic cache-write TTL breakdown does not reconcile")
    output = _counter(raw, "output_tokens")
    provider_total = _counter(raw, "total_tokens", optional=True)
    input_total = fresh + read + write
    processed = input_total + output
    if provider_total is not None and provider_total != processed:
        raise UsageError("Anthropic provider total does not reconcile")
    return {
        **_base_normalized(), "input_total_tokens": input_total,
        "input_fresh_tokens": fresh, "input_cache_read_tokens": read,
        "input_cache_write_tokens": write, "output_total_tokens": output,
        "provider_total_tokens": provider_total, "processed_total_tokens": processed,
    }, {"cache_read": "disjoint-input", "cache_write": "disjoint-input"}


def _gemini(raw):
    allowed = {"prompt_token_count", "cached_content_token_count",
               "candidates_token_count", "thoughts_token_count",
               "tool_use_prompt_token_count", "total_token_count"}
    if set(raw) - allowed:
        raise UsageError("Gemini receipt contains unknown counters")
    input_total = _counter(raw, "prompt_token_count")
    cached = _counter(raw, "cached_content_token_count", optional=True) or 0
    output = _counter(raw, "candidates_token_count")
    reasoning = _counter(raw, "thoughts_token_count", optional=True) or 0
    tool = _counter(raw, "tool_use_prompt_token_count", optional=True) or 0
    provider_total = _counter(raw, "total_token_count")
    if cached > input_total:
        raise UsageError("Gemini cached content exceeds prompt total")
    if provider_total < input_total + output:
        raise UsageError("Gemini provider total is smaller than prompt plus candidates")
    return {
        **_base_normalized(), "input_total_tokens": input_total,
        "input_fresh_tokens": input_total - cached,
        "input_cache_read_tokens": cached, "output_total_tokens": output,
        "output_reasoning_tokens": reasoning, "tool_input_tokens": tool,
        "provider_total_tokens": provider_total, "processed_total_tokens": provider_total,
    }, {"cache_read": "subset-of-input", "reasoning": "provider-total-governed",
        "tool": "provider-total-governed"}


def normalize_event(value):
    if not isinstance(value, dict) or set(value) != EVENT_FIELDS \
            or value.get("schema_version") != SCHEMA_VERSION:
        raise UsageError("usage event v3 fields are invalid")
    _identity(value)
    profile = value.get("semantics_profile")
    if profile not in PROFILES:
        raise UsageError("semantics_profile is unsupported")
    raw = _raw_counters(value.get("raw_counters"))
    attempt = _integer(value.get("attempt_number"), "attempt_number")
    if attempt < 1:
        raise UsageError("attempt_number must be at least one")
    duration = _integer(value.get("duration_ns"), "duration_ns", optional=True)
    try:
        if profile == "openai-responses-v1":
            normalized, relationships = _openai(raw)
        elif profile == "anthropic-messages-v1":
            normalized, relationships = _anthropic(raw)
        elif profile.startswith("gemini-"):
            normalized, relationships = _gemini(raw)
        else:
            normalized, relationships = _base_normalized(), {"raw": "unknown-inclusion"}
            if set(raw) == {"processed_total_tokens"} \
                    and raw["processed_total_tokens"] is not None:
                normalized["processed_total_tokens"] = raw["processed_total_tokens"]
    except PartialUsage as exc:
        return {**value, "captured_at": _timestamp(value["captured_at"]),
                "raw_counters": raw, "duration_ns": duration,
                "measurement_state": "provider-partial", "normalization_reason": str(exc),
                "normalized": _base_normalized(), "relationships": {}}
    except UsageError as exc:
        return {**value, "captured_at": _timestamp(value["captured_at"]),
                "raw_counters": raw, "duration_ns": duration,
                "measurement_state": "invalid", "normalization_reason": str(exc),
                "normalized": _base_normalized(), "relationships": {}}
    state = "provider-partial" if profile == "generic-host-v1" else "provider-complete"
    return {**value, "captured_at": _timestamp(value["captured_at"]),
            "raw_counters": raw, "duration_ns": duration,
            "measurement_state": state,
            "normalization_reason": "formula-bound" if state.endswith("complete")
            else "unknown-provider-inclusion-semantics",
            "normalized": normalized, "relationships": relationships}


def normalize_bundle(value):
    if value is None:
        return unavailable()
    if not isinstance(value, dict) or set(value) != BUNDLE_FIELDS \
            or value.get("schema_version") != SCHEMA_VERSION \
            or value.get("measurement_source") not in {"provider", "host"}:
        raise UsageError("usage bundle v3 fields are invalid")
    expected = _integer(value.get("expected_event_count"), "expected_event_count")
    events = value.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise UsageError("usage events must be a bounded non-empty list")
    if expected != len(events):
        raise UsageError("usage bundle omits one or more response events")
    capability = value.get("capability_receipt_id")
    if capability is not None and (not isinstance(capability, str) or not SAFE_TEXT.fullmatch(capability)):
        raise UsageError("capability_receipt_id is invalid")
    normalized = [normalize_event(item) for item in events]
    event_ids = [item["event_id"] for item in normalized]
    response_ids = [item["response_id"] for item in normalized if item["response_id"]]
    if len(event_ids) != len(set(event_ids)) or len(response_ids) != len(set(response_ids)):
        raise UsageError("usage event or response identity is reused")
    identities = {(item["owner_vault_id"], item["project_id"], item["session_id"],
                   item["operation_id"]) for item in normalized}
    if len(identities) != 1:
        raise UsageError("usage events cross owner, project, session, or operation identity")
    states = {item["measurement_state"] for item in normalized}
    if "invalid" in states:
        state, total, reason = "invalid", None, "one or more response events are invalid"
    elif value["measurement_source"] == "host" and capability is not None \
            and all(item["semantics_profile"] == "generic-host-v1"
                    and item["normalized"]["processed_total_tokens"] is not None
                    for item in normalized):
        state = "host-complete"
        total = sum(item["normalized"]["processed_total_tokens"] for item in normalized)
        reason = "capability-bound host processed totals cover every response attempt"
    elif states == {"provider-complete"}:
        state = "provider-complete"
        total = sum(item["normalized"]["processed_total_tokens"] for item in normalized)
        reason = "all response attempts use known non-overlapping provider formulas"
    else:
        state, total, reason = "provider-partial", None, "one or more events lack complete semantics"
    return {
        "schema_version": SCHEMA_VERSION, "measurement_status": state,
        "measurement_source": value["measurement_source"],
        "capability_receipt_id": capability, "event_count": len(normalized),
        "events": normalized, "processed_total_tokens": total,
        "normalization_reason": reason,
    }


def unavailable(reason="host-exposes-no-trustworthy-usage"):
    return {"schema_version": SCHEMA_VERSION, "measurement_status": "unavailable",
            "measurement_source": None, "capability_receipt_id": None, "event_count": 0,
            "events": [], "processed_total_tokens": None,
            "normalization_reason": reason}


def semantic_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()
