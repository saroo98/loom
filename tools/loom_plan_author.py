#!/usr/bin/env python3
"""Bounded machine authoring for one sealed Loom planning contract."""

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path, PurePosixPath

import loom_domain_bundle
import loom_domain_contract
import loom_domain_discovery
import loom_domain_evidence
import loom_domain_invariants
import loom_gate
import loom_lifecycle
import loom_lint
import loom_plan_presentation
import loom_planning_intelligence
import loom_proofline
import loom_reliability
import loom_survey


SCHEMA_VERSION = 1
MAX_DRAFT_BYTES = 48 * 1024
MAX_TRANSACTION_BYTES = 1024 * 1024
TRANSACTION_PHASES = {
    "prepared", "source-moved", "candidate-active",
    "cleanup-backup", "cleanup-stage",
}
ROUTING = {
    "frontier-reasoning", "strong-coding", "fast-cheap", "specialist", "human"}
SIZE = {"S", "M"}
SOURCE_KEY_PATTERN = r"^[a-z][a-z0-9-]{0,31}$"
SOURCE_CLASSES = {"repository", "owner-attestation", "secondary-discovery"}
LOCATOR_VISIBILITY = {"public", "encrypted-private"}
CURRENTNESS = {"current", "stale", "superseded", "unknown"}
INVARIANT_TYPES = set(loom_domain_contract.INVARIANT_TYPES)
CONSEQUENCE_CLASSES = set(loom_domain_contract.CONSEQUENCE_CLASSES)
AUTHORITY_REQUIREMENTS = set(loom_domain_contract.AUTHORITY_CLASSES)
INVARIANT_TYPE_GUIDANCE = {
    "correctness": (
        "Owner- or repository-defined expected behavior, including bounded prohibitions on "
        "network access, file writes, output leakage, or other side effects when the claim does "
        "not assert physical, clinical, regulated, or similarly consequential safety."
    ),
    "safety": (
        "A claim whose failure can cause physical, clinical, regulated, or comparably "
        "consequential harm. It requires a pre-existing sealed governing-authority receipt; "
        "semantic repository or owner evidence alone cannot authorize it."
    ),
    "regulatory": (
        "A legal or regulatory obligation. It requires pre-existing official-law or regulator "
        "authority and must never be inferred from repository prose."
    ),
    "interface": "A required input, output, protocol, command, or compatibility boundary.",
    "release": "A deployment, migration, rollback, distribution, or release-channel invariant.",
    "verification": "A requirement governing how another invariant is proven in a real medium.",
}
TOP_FIELDS = {
    "schema_version", "title", "summary", "assumptions", "decisions",
    "current_facts", "release_exposure", "work_orders", "domain_evidence",
}
WORK_ORDER_FIELDS = {
    "title", "outcome", "tasks", "acceptance", "negative_acceptance",
    "out_of_scope", "escalation", "touches", "depends_on", "routing", "size",
}
FACT_FIELDS = {"domain", "fact", "source"}
EXPOSURE_FIELDS = {"external_users", "irreversible", "data_migration", "regulated"}
DOMAIN_EVIDENCE_FIELDS = {
    "retrieval_rounds", "answers", "sources", "invariants",
}
DOMAIN_SOURCE_FIELDS = {
    "key", "title", "locator", "locator_visibility", "publisher",
    "source_class", "content", "retrieval_method", "document_id", "version",
    "published_at", "effective_at", "revalidate_by", "jurisdiction",
    "product_class", "environment", "currentness", "ambiguity",
}
DOMAIN_INVARIANT_FIELDS = {
    "statement", "invariant_type", "domain_ids", "subsystem_ids", "scope",
    "consequence_class", "failure", "authority_requirements",
    "supporting_source_keys", "contradicting_source_keys",
    "applicability_evidence", "required_real_medium", "acceptance_target",
    "as_of", "revalidate_by", "revision_identity",
}
DOMAIN_SCOPE_FIELDS = {
    "component", "jurisdiction", "product_class", "environment",
    "version_range", "effective_period",
}
DOMAIN_DRAFT_LIMITS = {
    "retrieval_rounds": {"minimum": 0, "maximum": 2},
    "answers": {"required_items": 8, "maximum_item_characters": 1024},
    "sources": {
        "minimum_items": 1, "maximum_items": 20,
        "key_characters": 32, "title_characters": 256,
        "locator_characters": 512, "metadata_characters": 256,
        "content_bytes": 8192,
    },
    "invariants": {
        "minimum_items": 1, "maximum_items": 32,
        "statement_characters": 512, "failure_characters": 512,
        "domain_items": 16, "domain_characters": 64,
        "subsystem_items": 32, "subsystem_characters": 64,
        "scope_characters": 128, "authority_items": 8,
        "source_key_items": 20, "applicability_items": 16,
        "applicability_item_characters": 256,
        "real_medium_characters": 256, "acceptance_target_characters": 256,
        "revision_characters": 128,
    },
}


class PlanAuthorError(ValueError):
    def __init__(self, code, message, *, diagnostics=None):
        self.code = code
        self.message = message
        self.diagnostics = list(diagnostics or [])
        super().__init__(message)


def _canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def _bounded_text(value, label, maximum, *, minimum=1):
    if not isinstance(value, str) or not minimum <= len(value) <= maximum \
            or "\x00" in value:
        raise PlanAuthorError("PLAN_DRAFT_INVALID", f"{label} is invalid")
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def _bounded_list(value, label, *, maximum_items, maximum_characters, minimum_items=0):
    if not isinstance(value, list) \
            or not minimum_items <= len(value) <= maximum_items:
        raise PlanAuthorError("PLAN_DRAFT_INVALID", f"{label} is invalid")
    return [
        _bounded_text(item, f"{label} item", maximum_characters)
        for item in value
    ]


def _safe_touch(value):
    text = _bounded_text(value, "work-order touch", 300)
    normalized = text.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or not path.parts \
            or path.parts[0].casefold() == "plans" \
            or re.match(r"^[A-Za-z]:", normalized):
        raise PlanAuthorError(
            "PLAN_DRAFT_INVALID", f"unsafe work-order touch: {value}")
    return normalized


def _observable_criterion(value, *, negative=False):
    if loom_lint.CRITERION_OK_RE.search(value):
        return value
    prefix = "Observed rejection: " if negative else "Observed result: "
    return prefix + value


def _iso(value, label, *, default):
    if value is None:
        return default
    try:
        parsed = loom_domain_contract.parse_time(value, label)
    except loom_domain_contract.DomainContractError as exc:
        raise PlanAuthorError("DOMAIN_EVIDENCE_NOT_READY", str(exc)) from exc
    return parsed.isoformat().replace("+00:00", "Z")


def _nullable_text(value, label, maximum):
    if value is None:
        return None
    return _bounded_text(value, label, maximum)


def _repository_source(repo, locator):
    locator = _bounded_text(locator, "repository source locator", 512)
    if "\\" in locator or re.match(r"^[A-Za-z]:", locator):
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "repository source locator must be POSIX-relative")
    relative = PurePosixPath(locator)
    if relative.is_absolute() or not relative.parts \
            or any(part in {"", ".", ".."} for part in relative.parts) \
            or relative.parts[0].casefold() in {
                ".git", ".loom", ".loom-history", "plans"}:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "repository source locator is unsafe or circular")
    try:
        root = loom_reliability._absolute(
            repo, "repository evidence root", must_exist=True)
        target = loom_reliability._target(root, relative.as_posix())
        target.relative_to(root)
        initial = target.lstat()
        if loom_reliability._is_redirect(target) \
                or not stat.S_ISREG(initial.st_mode) \
                or int(initial.st_nlink) != 1 \
                or int(initial.st_size) > 8192:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "repository source must be one bounded, unlinked regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) \
            | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) \
                    or loom_reliability._stat_identity(opened) \
                    != loom_reliability._stat_identity(initial):
                raise PlanAuthorError(
                    "DOMAIN_EVIDENCE_NOT_READY",
                    "repository source changed before it could be read")
            content = os.read(descriptor, 8193)
            if len(content) > 8192:
                raise PlanAuthorError(
                    "DOMAIN_EVIDENCE_NOT_READY",
                    "repository source exceeds the 8192-byte evidence bound")
            after = os.fstat(descriptor)
            if loom_reliability._stat_identity(after) \
                    != loom_reliability._stat_identity(opened):
                raise PlanAuthorError(
                    "DOMAIN_EVIDENCE_NOT_READY",
                    "repository source changed while it was read")
        finally:
            os.close(descriptor)
        latest = target.lstat()
        if loom_reliability._is_redirect(target) \
                or loom_reliability._stat_identity(latest) \
                != loom_reliability._stat_identity(initial):
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "repository source changed after it was read")
        content.decode("utf-8")
        return relative.as_posix(), content
    except PlanAuthorError:
        raise
    except (OSError, UnicodeError, ValueError, loom_reliability.ReliabilityError) as exc:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            f"repository source could not be verified: {exc}") from exc


def _source_observation(raw, *, repo, request):
    source_class = raw["source_class"]
    if source_class == "repository":
        if raw["content"] is not None or raw["locator_visibility"] != "public":
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "repository source content is runtime-read; submit null content "
                "and a public repository-relative locator")
        locator, content_bytes = _repository_source(repo, raw["locator"])
        return {
            "locator": locator,
            "publisher": "Repository",
            "document_id": locator,
            "retrieval_method": "loom-runtime-repository-read",
            "content_bytes": content_bytes,
            "trust_state": "trusted-local",
        }
    if source_class == "owner-attestation":
        content = raw["content"]
        if not isinstance(content, str) or not content or len(content) > 8192 \
                or "\x00" in content or content not in request:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "owner attestation must be exact text from the sealed owner request")
        if raw["locator_visibility"] != "encrypted-private":
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "owner attestation locator must remain encrypted-private")
        digest = hashlib.sha256(request.encode("utf-8")).hexdigest()
        return {
            "locator": "receipt:sealed-request-" + digest[:24],
            "publisher": "Owner request",
            "document_id": "sealed-request-" + digest[:24],
            "retrieval_method": "loom-sealed-owner-request",
            "content_bytes": content.encode("utf-8"),
            "trust_state": "trusted-local",
        }
    if source_class == "secondary-discovery":
        content = raw["content"]
        if not isinstance(content, str) or not 1 <= len(content) <= 8192 \
                or "\x00" in content:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "secondary discovery content is invalid")
        return {
            "locator": _bounded_text(
                raw["locator"], "domain source locator", 512),
            "publisher": _bounded_text(
                raw["publisher"], "domain source publisher", 256),
            "document_id": _bounded_text(
                raw["document_id"], "domain source document ID", 256),
            "retrieval_method": _bounded_text(
                raw["retrieval_method"], "domain source retrieval method", 256),
            "content_bytes": content.encode("utf-8"),
            "trust_state": "untrusted-data",
        }
    raise PlanAuthorError(
        "DOMAIN_EVIDENCE_NOT_READY",
        "this source class requires a sealed retrieval, execution, or reviewer "
        "receipt that semantic plan authoring does not accept")


def _semantic_domain_bundle(value, contract, *, now, repo=None, request=None):
    """Compile inert semantic evidence into Loom-owned sealed domain records."""
    if repo is None or not isinstance(request, str):
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "sealed repository and request provenance are required")
    if not isinstance(value, dict) or set(value) != DOMAIN_EVIDENCE_FIELDS:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "domain evidence fields are unknown or missing")
    retrieval_rounds = value["retrieval_rounds"]
    if type(retrieval_rounds) is not int or not 0 <= retrieval_rounds <= 2:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "domain evidence retrieval rounds must be between 0 and 2")
    answers = value["answers"]
    answer_fields = {key for key, _question in loom_domain_discovery.QUESTIONS}
    if not isinstance(answers, dict) or set(answers) != answer_fields:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "all eight bounded domain discovery answers are required")
    normalized_answers = {
        key: _bounded_text(answers[key], f"domain answer {key}", 1024)
        for key in sorted(answer_fields)}
    stamp = now.astimezone(dt.timezone.utc).replace(microsecond=0) \
        .isoformat().replace("+00:00", "Z")
    default_revalidate = (
        now.astimezone(dt.timezone.utc) + dt.timedelta(days=14)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    source_values = value["sources"]
    if not isinstance(source_values, list) or not 1 <= len(source_values) <= 20:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "domain evidence requires between 1 and 20 sources")
    sources, source_by_key = [], {}
    for raw in source_values:
        if not isinstance(raw, dict) or set(raw) != DOMAIN_SOURCE_FIELDS:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain source fields are unknown or missing")
        key = _bounded_text(raw["key"], "domain source key", 32)
        if re.fullmatch(SOURCE_KEY_PATTERN, key) is None \
                or key in source_by_key:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain source keys must be unique safe identifiers")
        source_class = raw["source_class"]
        if source_class not in SOURCE_CLASSES:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY", "domain source class is unsupported")
        if raw["locator_visibility"] not in LOCATOR_VISIBILITY:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain source locator visibility is unsupported")
        if raw["currentness"] not in CURRENTNESS:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain source currentness is unsupported")
        observation = _source_observation(raw, repo=repo, request=request)
        content_bytes = observation["content_bytes"]
        receipt_id = "observed-" + hashlib.sha256(content_bytes).hexdigest()[:24]
        try:
            source = loom_domain_evidence.seal_source(
                title=_bounded_text(raw["title"], "domain source title", 256),
                locator=observation["locator"],
                locator_visibility=raw["locator_visibility"],
                publisher=observation["publisher"],
                source_class=source_class, authority_claims=[],
                trust_state=observation["trust_state"],
                document_id=observation["document_id"],
                version=_nullable_text(raw["version"], "domain source version", 256),
                published_at=_iso(
                    raw["published_at"], "domain source published_at", default=None),
                effective_at=_iso(
                    raw["effective_at"], "domain source effective_at", default=None),
                superseded_at=None, accessed_at=stamp,
                revalidate_by=_iso(
                    raw["revalidate_by"], "domain source revalidate_by",
                    default=default_revalidate),
                content=content_bytes,
                retrieval_method=observation["retrieval_method"],
                retrieval_receipt_id=receipt_id,
                jurisdiction=_nullable_text(
                    raw["jurisdiction"], "domain source jurisdiction", 256),
                product_class=_nullable_text(
                    raw["product_class"], "domain source product class", 256),
                environment=_nullable_text(
                    raw["environment"], "domain source environment", 256),
                currentness=raw["currentness"],
                ambiguity=_nullable_text(
                    raw["ambiguity"], "domain source ambiguity", 256),
                provenance_event_ids=[],
            )
            loom_domain_evidence.validate_host_source(
                source, raw_text=content_bytes.decode("utf-8"), now=now)
        except (loom_domain_evidence.DomainEvidenceError,
                loom_domain_contract.DomainContractError) as exc:
            raise PlanAuthorError("DOMAIN_EVIDENCE_NOT_READY", str(exc)) from exc
        sources.append(source)
        source_by_key[key] = source
    invariant_values = value["invariants"]
    if not isinstance(invariant_values, list) \
            or not 1 <= len(invariant_values) <= 32:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "domain evidence requires between 1 and 32 invariants")
    invariants, applicability = [], []
    covered_domains = set()
    for raw in invariant_values:
        if not isinstance(raw, dict) or set(raw) != DOMAIN_INVARIANT_FIELDS:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain invariant fields are unknown or missing")
        scope_value = raw["scope"]
        if not isinstance(scope_value, dict) or set(scope_value) != DOMAIN_SCOPE_FIELDS:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY", "domain invariant scope is invalid")
        scope = {
            "project_id": contract["project_id"],
            **{
                key: _nullable_text(
                    scope_value[key], f"domain invariant scope {key}", 128)
                for key in sorted(DOMAIN_SCOPE_FIELDS)
            },
        }
        supporting_keys = raw["supporting_source_keys"]
        contradicting_keys = raw["contradicting_source_keys"]
        if not isinstance(supporting_keys, list) or not supporting_keys \
                or len(supporting_keys) != len(set(supporting_keys)) \
                or not isinstance(contradicting_keys, list) \
                or len(contradicting_keys) != len(set(contradicting_keys)):
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain invariant source keys are invalid")
        unknown = sorted(
            (set(supporting_keys) | set(contradicting_keys)) - set(source_by_key))
        if unknown:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain invariant references unknown source keys: "
                + ", ".join(unknown))
        requirements = raw["authority_requirements"]
        if not isinstance(requirements, list) or not requirements \
                or len(requirements) != len(set(requirements)) \
                or not set(requirements).issubset(AUTHORITY_REQUIREMENTS):
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain invariant authority requirements are invalid")
        if raw["invariant_type"] not in INVARIANT_TYPES:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain invariant type is unsupported")
        if raw["consequence_class"] not in CONSEQUENCE_CLASSES:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "domain invariant consequence class is unsupported")
        authority_classes = set(requirements)
        governing = {
            "official-law", "regulator", "official-vendor",
            "governing-standard", "qualified-reviewer",
        }
        if raw["invariant_type"] == "regulatory" \
                and not authority_classes.intersection({"official-law", "regulator"}):
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "regulatory invariants require official-law or regulator authority")
        if raw["invariant_type"] == "safety" \
                and not authority_classes.intersection(governing):
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "safety invariants require a pre-existing sealed governing-authority receipt; "
                "owner or repository product constraints remain correctness invariants unless "
                "their failure asserts physical, clinical, regulated, or comparably "
                "consequential harm",
                diagnostics=[{
                    "code": "SAFETY_AUTHORITY_REQUIRED",
                    "path": "domain_evidence.invariants[].invariant_type",
                    "message": (
                        "observed safety without official-law, regulator, official-vendor, "
                        "governing-standard, or qualified-reviewer authority"),
                }])
        if raw["consequence_class"] in {"high", "critical"} \
                and ("real-medium-evidence" not in authority_classes
                     or not authority_classes.intersection(governing)):
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "high-consequence invariants require governing authority and "
                "real-medium evidence")
        domains = _bounded_list(
            raw["domain_ids"], "domain invariant domains",
            maximum_items=16, maximum_characters=64, minimum_items=1)
        covered_domains.update(domains)
        subsystems = _bounded_list(
            raw["subsystem_ids"], "domain invariant subsystems",
            maximum_items=32, maximum_characters=64)
        as_of = _iso(raw["as_of"], "domain invariant as_of", default=stamp)
        revalidate_by = _iso(
            raw["revalidate_by"], "domain invariant revalidate_by",
            default=default_revalidate)
        common = {
            "statement": _bounded_text(
                raw["statement"], "domain invariant statement", 512),
            "invariant_type": raw["invariant_type"], "domain_ids": domains,
            "subsystem_ids": subsystems, "scope": scope,
            "consequence_class": raw["consequence_class"],
            "failure": _bounded_text(
                raw["failure"], "domain invariant failure", 512),
            "authority_requirements": requirements,
            "supporting_source_ids": [
                source_by_key[key]["source_id"] for key in supporting_keys],
            "contradicting_source_ids": [
                source_by_key[key]["source_id"] for key in contradicting_keys],
            "required_real_medium": _bounded_text(
                raw["required_real_medium"], "domain invariant real medium", 256),
            "acceptance_target": _bounded_text(
                raw["acceptance_target"], "domain invariant acceptance target", 256),
            "freshness_policy": "target-and-source-v1",
            "as_of": as_of, "revalidate_by": revalidate_by,
            "revision_identity": _nullable_text(
                raw["revision_identity"], "domain invariant revision", 128),
            "provenance_event_ids": [],
        }
        try:
            candidate = loom_domain_invariants.seal_candidate(
                **common, applicability_receipt_ids=[])
            evidence = _bounded_list(
                raw["applicability_evidence"], "domain applicability evidence",
                maximum_items=16, maximum_characters=256, minimum_items=1)
            receipts = [
                loom_domain_evidence.seal_applicability(
                    source_id=source_by_key[key]["source_id"],
                    invariant_id=candidate["invariant_id"], scope=scope,
                    target_fingerprint=contract["target_fingerprint"],
                    decision="applicable", evidence=evidence,
                    checked_at=stamp,
                    revalidate_on=[
                        "source-revision", "target-change", "scope-change"],
                )
                for key in supporting_keys
            ]
            candidate = loom_domain_invariants.seal_candidate(
                **common,
                applicability_receipt_ids=[
                    item["applicability_id"] for item in receipts])
            promoted = loom_domain_invariants.promote_gate_ready(
                candidate, sources=sources, applicability=receipts,
                target_fingerprint=contract["target_fingerprint"], now=now)
        except (loom_domain_contract.DomainContractError,
                loom_domain_evidence.DomainEvidenceError,
                loom_domain_invariants.DomainInvariantError) as exc:
            raise PlanAuthorError("DOMAIN_EVIDENCE_NOT_READY", str(exc)) from exc
        if promoted["status"] != "gate-ready":
            missing = promoted["authority"]["missing"]
            reason = (
                "missing authority: " + ", ".join(missing)
                if missing else
                "applicability, freshness, or conflict checks did not pass")
            raise PlanAuthorError("DOMAIN_EVIDENCE_NOT_READY", reason)
        applicability.extend(receipts)
        invariants.append(promoted["invariant"])
    required_domains = set(contract["domain_route"]["active_task_domains"]) - set(
        contract["domain_route"]["memory_domains"])
    if not required_domains.issubset(covered_domains):
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "semantic evidence does not cover every active unknown domain")
    discovery = loom_domain_discovery.create_receipt(
        contract["domain_route"], answers=normalized_answers,
        sources=sources, invariants=invariants,
        retrieval_rounds=retrieval_rounds, status="gate-ready",
        created_at=stamp)
    if discovery["questions"]:
        raise PlanAuthorError(
            "DOMAIN_EVIDENCE_NOT_READY",
            "domain discovery still has unanswered questions")
    try:
        return loom_domain_bundle.seal(
            route=contract["domain_route"], discovery=discovery,
            target_fingerprint=contract["target_fingerprint"],
            sources=sources, applicability=applicability,
            invariants=invariants, created_at=stamp)
    except loom_domain_bundle.DomainBundleError as exc:
        raise PlanAuthorError("DOMAIN_EVIDENCE_NOT_READY", str(exc)) from exc


def validate_draft(value, contract, *, now=None, repo=None, request=None):
    """Return one canonical semantic draft or fail before any project write."""
    if not isinstance(value, dict) or set(value) != TOP_FIELDS \
            or value.get("schema_version") != SCHEMA_VERSION:
        raise PlanAuthorError(
            "PLAN_DRAFT_INVALID", "semantic plan fields are unknown or missing")
    if len(_canonical_bytes(value)) > MAX_DRAFT_BYTES:
        raise PlanAuthorError("PLAN_DRAFT_INVALID", "semantic plan exceeds 48 KiB")
    title = _bounded_text(value["title"], "plan title", 100)
    summary = _bounded_text(value["summary"], "plan summary", 1000)
    assumptions = _bounded_list(
        value["assumptions"], "assumptions", maximum_items=16,
        maximum_characters=500)
    decisions = _bounded_list(
        value["decisions"], "decisions", maximum_items=16,
        maximum_characters=500)
    exposure = value["release_exposure"]
    if not isinstance(exposure, dict) or set(exposure) != EXPOSURE_FIELDS \
            or type(exposure["external_users"]) is not int \
            or not 0 <= exposure["external_users"] <= 1_000_000_000 \
            or any(type(exposure[key]) is not bool
                   for key in ("irreversible", "data_migration", "regulated")):
        raise PlanAuthorError("PLAN_DRAFT_INVALID", "release exposure is invalid")
    required_facts = {
        (item["domain"], item["fact"])
        for item in contract["current_facts_to_verify"]}
    facts, observed_facts = [], set()
    if not isinstance(value["current_facts"], list) \
            or len(value["current_facts"]) > 48:
        raise PlanAuthorError("PLAN_DRAFT_INVALID", "current facts are invalid")
    for item in value["current_facts"]:
        if not isinstance(item, dict) or set(item) != FACT_FIELDS:
            raise PlanAuthorError("PLAN_DRAFT_INVALID", "current fact fields are invalid")
        record = {
            "domain": _bounded_text(item["domain"], "fact domain", 64),
            "fact": _bounded_text(item["fact"], "fact statement", 300),
            "source": _bounded_text(item["source"], "fact source", 500),
        }
        identity = (record["domain"], record["fact"])
        if identity in observed_facts:
            raise PlanAuthorError("PLAN_DRAFT_INVALID", "current fact is duplicated")
        observed_facts.add(identity)
        facts.append(record)
    if observed_facts != required_facts:
        missing = sorted(required_facts - observed_facts)
        extra = sorted(observed_facts - required_facts)
        raise PlanAuthorError(
            "PLAN_DRAFT_INVALID",
            f"current facts differ from the sealed contract; missing={missing}; extra={extra}")
    minimum = contract["work_order_topology"]["minimum"]
    maximum = contract["work_order_topology"]["maximum"]
    work_orders = value["work_orders"]
    if not isinstance(work_orders, list) or not minimum <= len(work_orders) <= maximum:
        raise PlanAuthorError(
            "PLAN_DRAFT_INVALID", "work-order count is outside the sealed topology")
    normalized_work_orders = []
    identities = [f"WO-{index:03d}" for index in range(1, len(work_orders) + 1)]
    for index, item in enumerate(work_orders):
        if not isinstance(item, dict) or set(item) != WORK_ORDER_FIELDS:
            raise PlanAuthorError(
                "PLAN_DRAFT_INVALID", f"work order {index + 1} fields are invalid")
        depends_on = _bounded_list(
            item["depends_on"], "work-order dependencies",
            maximum_items=16, maximum_characters=16)
        permitted = set(identities[:index])
        if len(depends_on) != len(set(depends_on)) \
                or any(dependency not in permitted for dependency in depends_on):
            raise PlanAuthorError(
                "PLAN_DRAFT_INVALID",
                f"{identities[index]} dependencies are not an earlier-work-order DAG")
        routing = item["routing"]
        size = item["size"]
        if routing not in ROUTING or size not in SIZE:
            raise PlanAuthorError(
                "PLAN_DRAFT_INVALID", f"{identities[index]} routing or size is invalid")
        touches = [_safe_touch(touch) for touch in _bounded_list(
            item["touches"], "work-order touches", maximum_items=32,
            maximum_characters=300, minimum_items=1)]
        if len(touches) != len(set(touches)):
            raise PlanAuthorError(
                "PLAN_DRAFT_INVALID", f"{identities[index]} touches are duplicated")
        normalized_work_orders.append({
            "id": identities[index],
            "title": _bounded_text(item["title"], "work-order title", 100),
            "outcome": _bounded_text(item["outcome"], "work-order outcome", 500),
            "tasks": _bounded_list(
                item["tasks"], "work-order tasks", maximum_items=16,
                maximum_characters=500, minimum_items=1),
            "acceptance": [
                _observable_criterion(value)
                for value in _bounded_list(
                    item["acceptance"], "acceptance criteria", maximum_items=16,
                    maximum_characters=500, minimum_items=1)],
            "negative_acceptance": [
                _observable_criterion(value, negative=True)
                for value in _bounded_list(
                    item["negative_acceptance"], "negative acceptance criteria",
                    maximum_items=8, maximum_characters=500, minimum_items=1)],
            "out_of_scope": _bounded_list(
                item["out_of_scope"], "out-of-scope items", maximum_items=16,
                maximum_characters=500, minimum_items=1),
            "escalation": _bounded_list(
                item["escalation"], "escalation triggers", maximum_items=16,
                maximum_characters=500, minimum_items=1),
            "touches": touches, "depends_on": depends_on,
            "routing": routing, "size": size,
        })
    limits = contract.get("semantic_draft_limits")
    if not isinstance(limits, dict):
        raise PlanAuthorError(
            "PLAN_DRAFT_INVALID", "sealed semantic draft limits are unavailable")
    for field, items in (("assumptions", assumptions), ("decisions", decisions)):
        bound = limits[field]
        if not bound["minimum_items"] <= len(items) <= bound["maximum_items"] \
                or any(len(item) > bound["maximum_item_characters"] for item in items):
            raise PlanAuthorError(
                "PLAN_DRAFT_INVALID",
                f"{contract['tier']} {field} exceed the sealed semantic limit")
    for work_order in normalized_work_orders:
        for field in (
                "tasks", "acceptance", "negative_acceptance",
                "out_of_scope", "escalation", "touches"):
            bound = limits[field]
            if not bound["minimum_items"] <= len(work_order[field]) <= \
                    bound["maximum_items"] \
                    or any(len(item) > bound["maximum_item_characters"]
                           for item in work_order[field]):
                raise PlanAuthorError(
                    "PLAN_DRAFT_INVALID",
                    f"{contract['tier']} {field.replace('_', ' ')} exceed "
                    "the sealed semantic limit")
    evidence = value["domain_evidence"]
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise PlanAuthorError("PLAN_DRAFT_INVALID", "authoring time must be timezone-aware")
    bundle = None
    if contract["domain_discovery"]["required"]:
        if evidence is None:
            raise PlanAuthorError(
                "DOMAIN_EVIDENCE_NOT_READY",
                "the sealed route requires bounded semantic domain evidence")
        bundle = _semantic_domain_bundle(
            evidence, contract, now=now, repo=repo, request=request)
    elif evidence is not None:
        raise PlanAuthorError(
            "PLAN_DRAFT_INVALID",
            "a shipped-domain plan must not add discovery evidence")
    return {
        "schema_version": SCHEMA_VERSION, "title": title, "summary": summary,
        "assumptions": assumptions, "decisions": decisions,
        "current_facts": facts, "release_exposure": dict(exposure),
        "work_orders": normalized_work_orders, "domain_bundle": bundle,
    }


def _yaml(value):
    return json.dumps(value, ensure_ascii=False)


def _frontmatter(artifact, status, today):
    return (
        "---\n"
        f"artifact: {artifact}\n"
        f"status: {status}\n"
        f"last_verified: {today}\n"
        "---\n")


def _bullet_lines(values, default):
    return "\n".join(f"- {item}" for item in values) if values else f"- {default}"


def _planning_assignments(contract, work_orders):
    atoms = [
        item for item in contract["planning_intelligence"]["atoms"]
        if item["gate_effect"] != "none"]
    by_wo = {item["id"]: [] for item in work_orders}
    stop_words = {
        "about", "after", "against", "before", "current", "declare", "each",
        "every", "from", "into", "keep", "must", "only", "requested", "that",
        "their", "them", "this", "through", "when", "where", "with",
    }

    def tokens(value):
        return {
            token for token in re.findall(r"[a-z0-9]+", value.casefold())
            if len(token) >= 4 and token not in stop_words
        }

    work_order_tokens = {}
    for item in work_orders:
        text = " ".join([
            item["title"], item["outcome"], *item["tasks"], *item["acceptance"],
            *item["negative_acceptance"], *item["escalation"], *item["touches"],
        ])
        work_order_tokens[item["id"]] = tokens(text)
    for atom in sorted(atoms, key=lambda item: item["atom_id"]):
        atom_tokens = tokens(
            atom["module_id"] + " " + atom["atom_id"] + " " + atom["statement"]
            + " " + atom["required_real_medium"])
        ranked = sorted(
            work_orders,
            key=lambda item: (
                -len(atom_tokens & work_order_tokens[item["id"]]),
                item["id"],
            ),
        )
        by_wo[ranked[0]["id"]].append(atom)
    program = contract["planning_intelligence"]["program"]
    milestone_ids = (
        ["delivery"] if program is None else
        [item["id"] for item in program["milestone_graph"]["milestones"]])
    assignments = []
    assignment_index = 0
    for work_order in work_orders:
        for atom in by_wo[work_order["id"]]:
            assignments.append({
                "atom_id": atom["atom_id"], "work_order": work_order["id"],
                "milestone": milestone_ids[assignment_index % len(milestone_ids)],
                "verification": loom_planning_intelligence.expanded_verification(
                    contract["planning_intelligence"], atom),
            })
            assignment_index += 1
    assignments.sort(key=lambda item: item["atom_id"])
    body = {
        "schema_version": 1, "plan_contract_hash": contract["contract_hash"],
        "planning_intelligence_digest": contract["planning_intelligence"][
            "intelligence_digest"],
        "program_digest": (contract["planning_intelligence"]["program"] or {}).get(
            "program_digest"),
        "assignments": assignments,
    }
    return {
        **body,
        "assignment_digest": loom_domain_contract.digest(
            "planning-obligation-assignments-v1", body),
    }, by_wo


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_json(path, value):
    _write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _write_work_orders(stage, contract, draft, today, atoms_by_wo):
    invariant_bindings = []
    if draft["domain_bundle"] is not None:
        invariant_bindings = [
            f"{item['invariant_id']}@{item['canonical_digest']}"
            for item in draft["domain_bundle"]["invariants"]]
    written = []
    assumption_refs = ", ".join(
        f"A-{index:03d}" for index, _item in enumerate(draft["assumptions"], 1))
    program = contract["planning_intelligence"]["program"]
    milestone_ids = (
        ["delivery"] if program is None else
        [item["id"] for item in program["milestone_graph"]["milestones"]])
    for work_order_index, work_order in enumerate(draft["work_orders"]):
        milestone = milestone_ids[work_order_index % len(milestone_ids)]
        required_atoms = sorted(
            item["atom_id"] for item in atoms_by_wo[work_order["id"]])
        blocks = [
            item["id"] for item in draft["work_orders"]
            if work_order["id"] in item["depends_on"]]
        tasks = "\n".join(f"{index}. {item}" for index, item in enumerate(
            work_order["tasks"], 1))
        acceptance = "\n".join(
            f"- [ ] {item}" for item in work_order["acceptance"])
        negative = "\n".join(
            f"- [ ] Negative: {item}" for item in work_order["negative_acceptance"])
        path = (
            stage / "WO-001.md" if contract["tier"] == "S" else
            stage / "work-orders" / f"{work_order['id']}-{_slug(work_order['title'])}.md")
        if contract["tier"] == "S":
            compact_tasks = "; ".join(work_order["tasks"])
            compact_acceptance = "\n".join(
                f"- [ ] {item}" for item in work_order["acceptance"])
            compact_negative = "\n".join(
                f"- [ ] Negative: {item}" for item in work_order["negative_acceptance"])
            _write(path, f"""---
id: {work_order['id']}
title: {_yaml(work_order['title'])}
status: ready
depends_on: {_yaml(work_order['depends_on'])}
blocks: {_yaml(blocks)}
routing: {work_order['routing']}
size: {work_order['size']}
touches: {_yaml(work_order['touches'])}
last_verified: {today}
milestone: {milestone}
planning_obligations: {_yaml(required_atoms)}
domain_invariants: {_yaml(invariant_bindings)}
---
## Intent
{work_order['outcome']}
## Context
[FACT — sealed plan] {draft['summary']}
## Preconditions
The sealed target, request, and plan contract remain current.
## Task
{compact_tasks}
## Acceptance criteria
{compact_acceptance}
{compact_negative}
## Out of scope
{"; ".join(work_order['out_of_scope'])}
## Escalation triggers
{"; ".join(work_order['escalation'])}
## Epistemic notes
[FACT — plan contract] Scope and obligations are machine-bound.
{"Assumptions: " + assumption_refs + "." if assumption_refs else ""}
## Close-out
Pending real implementation evidence.
""")
            written.append(path)
            continue
        _write(path, f"""---
id: {work_order['id']}
title: {_yaml(work_order['title'])}
status: ready
depends_on: {_yaml(work_order['depends_on'])}
blocks: {_yaml(blocks)}
routing: {work_order['routing']}
size: {work_order['size']}
touches: {_yaml(work_order['touches'])}
last_verified: {today}
milestone: {milestone}
planning_obligations: {_yaml(required_atoms)}
domain_invariants: {_yaml(invariant_bindings)}
---
## Intent
{work_order['outcome']}

## Context
[FACT — sealed plan] {draft['summary']}

## Preconditions
- The sealed project world and plan contract remain current.
- Every named touch remains within the authorized target.

## Task
{tasks}

## Acceptance criteria
{acceptance}
{negative}

## Out of scope
{_bullet_lines(work_order['out_of_scope'], "No additional scope.")}

## Escalation triggers
{_bullet_lines(work_order['escalation'], "Stop on any new consequential unknown.")}

## Epistemic notes
- [FACT — plan contract] Structure, scope, and planning obligations are machine-bound.
{"- [ASSUMPTION — ledger] " + assumption_refs + "." if assumption_refs else ""}

## Close-out
Pending real implementation evidence.
""")
        written.append(path)
    return written


def _artifact_text(name, draft, today):
    title = name[:-3].replace("-", " ").title()
    return (
        _frontmatter(name[:-3], "gated", today)
        + f"\n# {title}\n\n"
        + f"[FACT — sealed owner request] {draft['summary']}\n\n"
        + "## Decision contract\n\n"
        + _bullet_lines(
            draft["decisions"],
            "No additional decision beyond the sealed work-order outcomes.")
        + "\n\n## Verification effect\n\n"
        + "This artifact is consumed only through the acceptance and escalation "
          "conditions bound into the work orders.\n")


def _review_text(title, version, today, evidence_path):
    rows = "\n".join(
        f"| {index} {label} | 3 | {evidence_path} |"
        for index, label in enumerate((
            "Goal fidelity", "Epistemic hygiene", "Right-sizing", "Decision quality",
            "Boundary clarity", "WO executability", "Verifiability",
            "Failure preparedness", "Adaptation fit", "Clarity"), 1))
    return f"""---
artifact: gate-review
project: {_yaml(title)}
gate: G1
date: {today}
reviewer: "loom-deterministic-plan-validator-v2"
reviewer_independence: mechanical-independent
verdict: pass
open_high_findings: 0
rubric_average: 3.0
rubric_min: 3
loom_version: {_yaml(version)}
---
# G1 mechanical review

[FACT — validator execution] A deterministic validator separate from the host author checked the
sealed contract, artifact matrix, dependency graph, acceptance structure, and lint result. This
is mechanical independence, not a human or second-model review.

## Rubric scorecard (G1/G4)
| Dimension | Score | Evidence (pack location) |
|---|---|---|
{rows}
"""


def _render_known_or_bound_pack(stage, *, contract, draft, request, version, today):
    assignments, atoms_by_wo = _planning_assignments(
        contract, draft["work_orders"])
    material_ledger = loom_proofline.build_material_ledger(
        request=request, plan_contract=contract, semantic_draft=draft)
    proof_graph = loom_proofline.build_graph(
        ledger=material_ledger, plan_contract=contract,
        semantic_draft=draft, assignments=assignments)
    _write_json(
        stage / "proofline" / "material-intent-ledger.json",
        material_ledger)
    _write_json(stage / "proofline" / "proof-graph.json", proof_graph)
    if contract["tier"] == "S":
        _write_work_orders(stage, contract, draft, today, atoms_by_wo)
        return
    _write_json(stage / "plan-contract.json", contract)
    _write_json(stage / "planning-obligations.json", assignments)
    exposure = draft["release_exposure"]
    loom_lifecycle.seal_release_policy(stage, **exposure)
    produced = {
        item["artifact"] for item in contract["artifact_matrix"]
        if item["action"] == "produce"}
    coverage = "verified" if contract["domain_discovery"]["required"] else "adapter"
    rows = []
    for item in contract["artifact_matrix"]:
        status = today if item["action"] == "produce" else "—"
        artifact_status = "gated" if item["action"] == "produce" else "—"
        rows.append(
            f"| {item['artifact']} | {item['action']} | {item['consumer']} | "
            f"{item['decision']} | {item['reason']} | {artifact_status} | {status} |")
    frontier = "\n".join(
        f"| {item['id']} | ready | {item['routing']} | — | — | — |"
        for item in draft["work_orders"])
    routing_snapshot = ""
    if any(item["artifact"] == "routing" and item["action"] == "produce"
           for item in contract["artifact_matrix"]):
        routing_rows = "\n".join(
            f"| {item['id']} | {', '.join(item['depends_on']) or 'none'} | "
            f"{item['routing']} | {', '.join(item['touches'])} |"
            for item in draft["work_orders"])
        routing_snapshot = (
            "\n## Routing snapshot\n"
            "| Work order | Depends on | Routing | Future touches |\n"
            "|---|---|---|---|\n"
            f"{routing_rows}\n"
        )
    quoted = "\n".join(
        "> " + line for line in request.replace("\r", "").split("\n"))
    _write(stage / "MANIFEST.md", f"""---
artifact: manifest
project: {_yaml(draft['title'])}
tier: {contract['tier']}
status: draft
execution_mode: planned
last_verified: {today}
loom_version: {_yaml(version)}
plan_contract_version: {contract["schema_version"]}
domain_id: {contract['domains'][0]}
domain_ids: {_yaml(contract['domains'])}
domain_coverage: {coverage}
freshness_window_days: 14
---
# Planning pack

Original request (verbatim, do not paraphrase):
{quoted}

## Artifacts
| Artifact | Action | Consumer | Decision | Why (one line) | Status | last_verified |
|---|---|---|---|---|---|---|
{chr(10).join(rows)}
{routing_snapshot}

## Work order frontier
| WO | Status | Routing | Claimed by | Claimed at (UTC) | Heartbeat |
|---|---|---|---|---|---|
{frontier}
""")
    assumptions = "\n\n".join(
        f"## A-{index:03d}: {item}\n"
        "- status: open\n"
        "- basis: owner request or sealed project inspection\n"
        "- risk_if_wrong: HIGH — the affected work order must stop\n"
        "- verify_by: before implementation\n"
        "- used_in: intake.md"
        for index, item in enumerate(draft["assumptions"], 1))
    _write(stage / "assumptions.md", f"""---
artifact: assumption-ledger
status: draft
last_verified: {today}
---
# Assumptions

{assumptions or "No unstated planning assumptions were promoted into the plan."}
""")
    decisions = "\n\n".join(
        f"## D-{index:03d}: {item}\n- chosen: {item}"
        for index, item in enumerate(draft["decisions"], 1))
    _write(stage / "decisions.md", f"""---
artifact: decision-log
status: draft
last_verified: {today}
---
# Decisions

{decisions or "No separate owner decision was required beyond the sealed request."}
""")
    invariants = "\n".join(
        f"| {item['domain']} | {item['invariant']} | {item['evidence_target']} | "
        f"{item['required_real_medium']} | required |"
        for item in contract["required_domain_invariants"])
    facts = "\n".join(
        f"| {item['domain']} | {item['fact']} | {item['source']} | unverified |"
        for item in draft["current_facts"])
    atom_lines = "\n".join(
        f"- `{item['atom_id']}`"
        for item in contract["planning_intelligence"]["atoms"]
        if item["gate_effect"] != "none")
    if "intake.md" in produced:
        _write(stage / "intake.md", f"""---
artifact: intake
status: gated
last_verified: {today}
---
# Intake

[FACT — owner request] {draft['summary']}

## Domain adaptation

The sealed route is limited to {", ".join(contract['domains'])}. No unrelated domain memory or
template is active.

## Silence sweep

Swept the request, sealed project inspection, failure modes, reversibility, authority, and
verification media. Unresolved matters appear only as explicit escalation triggers.

## Domain invariant contract
| Domain | Invariant | Evidence target | Required real medium | Status |
|---|---|---|---|---|
{invariants or "| unclassified | no invariant promoted | work order | real acceptance medium | verified |"}

## Current facts to verify
| Domain | Fact | Source | Status |
|---|---|---|---|
{facts}

## Planning intelligence obligations
{atom_lines}
""")
    media = "\n".join(
        f"| {item['domain']} | {item['medium']} | {item['decision']} | planned |"
        for item in contract["verification_media"])
    if "testing.md" in produced:
        _write(stage / "testing.md", f"""---
artifact: testing-plan
status: gated
last_verified: {today}
---
# Testing

[FACT — sealed work orders] Acceptance must be observed through the exact criteria and negative
cases in each work order.

## Verification media contract
| Domain | Medium | Target | Status |
|---|---|---|---|
{media or "| unclassified | executable acceptance check | sealed outcome | planned |"}
""")
    for name in sorted(produced - {
            "intake.md", "testing.md", "work orders", "routing",
            "domain-discovery.md"}):
        _write(stage / name, _artifact_text(name, draft, today))
    if draft["domain_bundle"] is not None:
        bundle = draft["domain_bundle"]
        _write_json(stage / "domain-discovery.json", bundle)
        invariant_rows = "\n".join(
            f"| {item['invariant_id']} | {item['statement']} | "
            f"{', '.join(item['supporting_source_ids'])} | "
            f"{item['consequence']['failure']} | "
            f"{item['verification']['required_real_medium']} | verified | "
            f"{item['canonical_digest']} |"
            for item in bundle["invariants"])
        _write(stage / "domain-discovery.md", f"""---
artifact: domain-discovery
domain_id: {contract['domains'][0]}
status: verified
last_verified: {today}
---
# Domain discovery

## Coverage statement
[FACT — sealed domain bundle] The machine bundle covers only the sealed active route and target fingerprint.

## Authoritative sources and qualified reviewers
[FACT — sealed domain evidence] The exact source identities and mechanically accepted authority classes are sealed in `domain-discovery.json`.

## Invariant ledger
| Invariant ID | Invariant | Evidence | Failure if wrong | Required real medium | Status | Canonical digest |
|---|---|---|---|---|---|---|
{invariant_rows}

## Forbidden default transfers
[FACT — scope firewall] No unrelated framework, web, mobile, or prior-project rule transfers into this domain.

## Artifact and gate adaptation
[FACT — plan contract] Every work order binds the gate-ready invariant IDs and canonical digests below.
""")
    sections = []
    for work_order in draft["work_orders"]:
        sections.append({
            "id": work_order["id"].lower(),
            "target_patterns": work_order["touches"],
        })
    _write_json(stage / "plan-dependencies.json", {
        "schema_version": 1, "sections": sections})
    written_work_orders = _write_work_orders(
        stage, contract, draft, today, atoms_by_wo)
    evidence_path = (
        "WO-001.md" if contract["tier"] == "S" else
        "MANIFEST.md; planning-obligations.json; work-orders/")
    if contract["tier"] != "S":
        _write(
            stage / "reviews" / "G1-plan-review.md",
            _review_text(draft["title"], version, today, evidence_path))


def _slug(value):
    text = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return (text or "work")[:48]


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise PlanAuthorError(
                "PLAN_AUTHOR_RECOVERY_REQUIRED",
                f"plan transaction contains duplicate field {key}")
        value[key] = item
    return value


def _transaction_value(transaction_id, phase, before, after):
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "phase": phase,
        "before": before,
        "after": after,
    }


def _write_transaction(path, value):
    try:
        loom_reliability.atomic_write_json(path, value)
    except loom_reliability.ReliabilityError as exc:
        raise PlanAuthorError(
            "PLAN_AUTHOR_FAILED",
            f"plan transaction could not be recorded: {exc}") from exc


def _read_transaction(path):
    if not os.path.lexists(path):
        return None
    if not path.is_file() or path.is_symlink() \
            or path.stat().st_size > MAX_TRANSACTION_BYTES:
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "plan transaction is redirected, irregular, or oversized")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            f"plan transaction is unreadable: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "transaction_id", "phase", "before", "after"} \
            or value.get("schema_version") != 1 \
            or not isinstance(value.get("transaction_id"), str) \
            or not re.fullmatch(r"[0-9a-f]{32}", value["transaction_id"]) \
            or value.get("phase") not in TRANSACTION_PHASES:
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "plan transaction fields are unknown or invalid")
    try:
        loom_reliability.validate_exact_tree_manifest(value["before"])
        loom_reliability.validate_exact_tree_manifest(value["after"])
    except loom_reliability.ReliabilityError as exc:
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            f"plan transaction manifests are invalid: {exc}") from exc
    return value


def _tree_relation(path, expected):
    if not os.path.lexists(path):
        return "absent"
    try:
        actual = loom_reliability.exact_tree_manifest(path)
        if loom_reliability.exact_tree_manifests_equal(actual, expected):
            return "equal"
        if loom_reliability.exact_tree_manifest_is_subset(actual, expected):
            return "subset"
    except loom_reliability.ReliabilityError as exc:
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            f"plan transaction tree cannot be proven: {exc}") from exc
    return "changed"


def _remove_proven_tree(path, expected, *, allow_subset):
    relation = _tree_relation(path, expected)
    permitted = {"equal", "absent"} | ({"subset"} if allow_subset else set())
    if relation not in permitted:
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "plan transaction cleanup tree differs from its sealed manifest")
    if relation != "absent":
        shutil.rmtree(path)
    if os.path.lexists(path):
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "plan transaction cleanup did not remove its sealed tree")


def reconcile(pack, transaction_path):
    """Reconcile one interrupted pack activation from exact namespace evidence."""
    pack = Path(pack).resolve()
    transaction_path = Path(transaction_path).resolve()
    if transaction_path.parent != pack.parent \
            or not transaction_path.name.startswith(".loom-plan-transaction-") \
            or transaction_path.suffix != ".json":
        raise PlanAuthorError(
            "PLAN_AUTHOR_RECOVERY_REQUIRED",
            "plan transaction path is outside the sealed project namespace")
    value = _read_transaction(transaction_path)
    if value is None:
        return {"status": "clean"}
    transaction_id = value["transaction_id"]
    stage = pack.parent / f".loom-plan-stage-{transaction_id}"
    backup = pack.parent / f".loom-plan-backup-{transaction_id}"
    pack_state = _tree_relation(pack, value["before"])
    candidate_state = _tree_relation(pack, value["after"])
    stage_state = _tree_relation(stage, value["after"])
    backup_state = _tree_relation(backup, value["before"])

    if candidate_state == "equal" and stage_state == "absent" \
            and backup_state in {"equal", "subset", "absent"}:
        value["phase"] = "cleanup-backup"
        _write_transaction(transaction_path, value)
        _remove_proven_tree(
            backup, value["before"], allow_subset=True)
        transaction_path.unlink()
        return {"status": "activated", "recovered": True}

    if pack_state == "absent" and backup_state == "equal" \
            and stage_state in {"equal", "subset"}:
        try:
            os.replace(backup, pack)
        except OSError as exc:
            raise PlanAuthorError(
                "PLAN_AUTHOR_RECOVERY_REQUIRED",
                f"plan rollback namespace move failed: {exc}") from exc
        pack_state = _tree_relation(pack, value["before"])
        backup_state = _tree_relation(backup, value["before"])

    if pack_state == "equal" and backup_state == "absent" \
            and stage_state in {"equal", "subset", "absent"}:
        value["phase"] = "cleanup-stage"
        _write_transaction(transaction_path, value)
        _remove_proven_tree(
            stage, value["after"], allow_subset=True)
        transaction_path.unlink()
        return {"status": "rolled-back", "recovered": True}

    raise PlanAuthorError(
        "PLAN_AUTHOR_RECOVERY_REQUIRED",
        "plan activation namespace no longer matches a safe commit or rollback state")


def _safe_replace_pack(pack, stage, transaction_path, *, before, after,
                       transaction_id):
    pack = Path(pack).resolve()
    stage = Path(stage).resolve()
    transaction_path = Path(transaction_path).resolve()
    backup = pack.parent / f".loom-plan-backup-{transaction_id}"
    if os.path.lexists(backup) or stage == pack or stage.parent != pack.parent \
            or backup.parent != pack.parent or transaction_path.parent != pack.parent:
        raise PlanAuthorError("PLAN_AUTHOR_FAILED", "plan staging namespace is unsafe")
    value = _transaction_value(
        transaction_id, "prepared", before, after)
    _write_transaction(transaction_path, value)
    try:
        os.replace(pack, backup)
        value["phase"] = "source-moved"
        _write_transaction(transaction_path, value)
        try:
            os.replace(stage, pack)
        except BaseException as exc:
            try:
                os.replace(backup, pack)
                value["phase"] = "cleanup-stage"
                _write_transaction(transaction_path, value)
                _remove_proven_tree(stage, after, allow_subset=True)
                transaction_path.unlink()
            except (OSError, PlanAuthorError):
                raise PlanAuthorError(
                    "PLAN_AUTHOR_RECOVERY_REQUIRED",
                    "plan activation failed and exact rollback requires reconciliation") \
                    from exc
            raise
        value["phase"] = "candidate-active"
        _write_transaction(transaction_path, value)
        value["phase"] = "cleanup-backup"
        _write_transaction(transaction_path, value)
        _remove_proven_tree(backup, before, allow_subset=True)
        transaction_path.unlink()
    except PlanAuthorError:
        raise
    except OSError as exc:
        raise PlanAuthorError(
            "PLAN_AUTHOR_FAILED", f"atomic plan activation failed: {exc}") from exc


def author(
        pack, *, contract, draft, request, version, repo, transaction_path,
        validate_stage=None, now=None, fresh_lifecycle=False):
    """Render, validate, and atomically activate one machine-owned plan pack."""
    pack = Path(pack).resolve()
    repo = Path(repo).resolve()
    transaction_path = Path(transaction_path).resolve()
    reconcile(pack, transaction_path)
    now = now or dt.datetime.now(dt.timezone.utc)
    normalized = validate_draft(
        draft, contract, now=now, repo=repo, request=request)
    if not pack.is_dir() or pack.is_symlink():
        raise PlanAuthorError("PLAN_AUTHOR_FAILED", "sealed planning pack is unavailable")
    lifecycle_name = (
        ".loom-small-lifecycle.json"
        if contract["tier"] == "S" else loom_gate.LIFECYCLE_FILE)
    lifecycle = pack / lifecycle_name
    if not fresh_lifecycle and (
            not lifecycle.is_file() or lifecycle.is_symlink()):
        raise PlanAuthorError("PLAN_AUTHOR_FAILED", "planning lifecycle is unavailable")
    transaction_id = uuid.uuid4().hex
    stage = pack.parent / f".loom-plan-stage-{transaction_id}"
    if os.path.lexists(stage):
        raise PlanAuthorError("PLAN_AUTHOR_FAILED", "plan stage already exists")
    revision_baseline = None
    if fresh_lifecycle:
        try:
            revision_baseline = loom_gate._stable_snapshot(repo, pack)
        except loom_survey.SurveyError as exc:
            raise PlanAuthorError(
                "PLAN_AUTHOR_FAILED",
                f"revision lifecycle baseline could not be observed: {exc}") from exc
    try:
        stage.mkdir()
        if not fresh_lifecycle:
            shutil.copy2(lifecycle, stage / lifecycle_name)
        today = now.astimezone(dt.timezone.utc).date().isoformat()
        _render_known_or_bound_pack(
            stage, contract=contract, draft=normalized, request=request,
            version=version, today=today)
        if fresh_lifecycle:
            state, baseline_files = revision_baseline
            event_name = (
                "small-planning-started"
                if contract["tier"] == "S" else "planning-started")
            event = loom_gate.make_event(
                event_name, state, event_at=now,
                baseline_snapshot_sha256=loom_gate._mapping_hash(
                    baseline_files))
            if contract["tier"] == "S":
                loom_gate._atomic_write(stage / lifecycle_name, {
                    "schema_version": loom_gate.SCHEMA_VERSION,
                    "mode": "small",
                    "work_order_file": "WO-001.md",
                    "route_contract": {
                        "tier": "S",
                        "domain_ids": contract["domains"],
                        "last_verified": today,
                        "freshness_window_days": 14,
                    },
                    "baseline_files": baseline_files,
                    "events": [event],
                })
            else:
                manifest_path, manifest_text = loom_gate._render_manifest(
                    stage, state, "planned")
                loom_gate._write_lifecycle_and_manifest(
                    stage, {
                        "schema_version": loom_gate.SCHEMA_VERSION,
                        "mode": "planned",
                        "baseline_files": baseline_files,
                        "events": [event],
                        "work_order_completions": [],
                    },
                    manifest_path, manifest_text)
        if contract["tier"] == "S":
            _frontmatter_value, _body, standalone_errors = \
                loom_gate._standalone_wo_contract(stage / "WO-001.md", "ready")
            diagnostics = [{
                "level": "ERROR", "code": "E19", "path": "WO-001.md",
                "message": message,
            } for message in standalone_errors]
        else:
            report = loom_lint.lint(
                stage, repo_path=repo, enforce_lifecycle=False, check_repo_state=False)
            diagnostics = [
                {"level": item["sev"], "code": item["code"],
                 "path": str(Path(item["path"]).relative_to(stage))
                 if Path(item["path"]).is_relative_to(stage) else str(item["path"]),
                 "message": item["msg"]}
                for item in report.findings
            ]
        errors = [item for item in diagnostics if item["level"] == "ERROR"]
        warnings = [item for item in diagnostics if item["level"] == "WARN"]
        if errors or warnings:
            raise PlanAuthorError(
                "PLAN_AUTHOR_VALIDATION_FAILED",
                "machine-authored plan has "
                f"{len(errors)} validation error(s) and "
                f"{len(warnings)} warning(s)",
                diagnostics=diagnostics[:64])
        if validate_stage is not None:
            validate_stage(stage)
        try:
            before = loom_reliability.exact_tree_manifest(pack)
            after = loom_reliability.exact_tree_manifest(stage)
        except loom_reliability.ReliabilityError as exc:
            raise PlanAuthorError(
                "PLAN_AUTHOR_FAILED",
                f"plan activation manifest could not be sealed: {exc}") from exc
        _safe_replace_pack(
            pack, stage, transaction_path, before=before, after=after,
            transaction_id=transaction_id)
        files = sorted(
            path.relative_to(pack).as_posix()
            for path in pack.rglob("*") if path.is_file())
        return {
            "schema_version": 1, "status": "authored",
            "plan_contract_hash": contract["contract_hash"],
            "files": files, "diagnostics": diagnostics[:64],
            "presentation_semantics": (
                loom_plan_presentation.extract_semantics(normalized)),
            "pack_sha256": hashlib.sha256(
                "\n".join(
                    f"{name}:{hashlib.sha256((pack / name).read_bytes()).hexdigest()}"
                    for name in files).encode("utf-8")).hexdigest(),
        }
    finally:
        if stage.exists() and not transaction_path.exists():
            shutil.rmtree(stage, ignore_errors=True)
