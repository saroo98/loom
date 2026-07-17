#!/usr/bin/env python3
"""Conservative lower-tier-first classifier for Loom planning overhead."""

import argparse
import json
import re
import sys

RISK_RE = re.compile(
    r"(?i)\b(auth(?:entication|orization)?|payment|billing|tax|migration|delete|"
    r"production|credential|firmware|hardware|medical|safety|financial|trading|"
    r"dependency|lockfile|public api|cryptograph(?:y|ic)|encryption|destructive|"
    r"deploy(?:ment)?|database schema)\b")
PROGRAM_RE = re.compile(
    r"(?i)\b(platform|multi[- ]service|multiple apps|migration program|enterprise|"
    r"full product|multi[- ]subsystem|cross[- ]service|cross[- ]platform|"
    r"ios\s+(?:and|&)\s+android|android\s+(?:and|&)\s+ios|"
    r"etl\s+(?:and|&)\s+(?:machine[- ]learning|ml)|"
    r"(?:machine[- ]learning|ml)\s+(?:and|&)\s+etl)\b")
PORTFOLIO_RE = re.compile(
    r"(?i)\b(year[- ]long|portfolio|organization[- ]wide|many teams|"
    r"multi[- ]program|multi[- ]product)\b")
MULTI_PHASE_RE = re.compile(
    r"(?i)\b(?:phase|stage)\s+\d+"
    r"(?:\s*(?:,|and|&)\s*(?:(?:phase|stage)\s+)?\d+){1,}"
    r"|\ball\s+(?:three|four|five|six|seven|eight|nine|ten|\d+)\s+phases?\b")
PLAN_IMPLEMENT_RE = re.compile(
    r"(?is)\b(?:write|make|create|produce)\b[^.!?]{0,180}\bplans?\b"
    r"[^.!?]{0,180}\b(?:then|and)\b[^.!?]{0,100}\bimplement(?:ation)?\b"
    r"|\bplans?\b[^.!?]{0,180}\b(?:then|and)\b[^.!?]{0,100}\bimplement(?:ation)?\b")
DISCIPLINED_DELIVERABLE_RE = re.compile(
    r"(?i)\b(?:build|create|develop|produce|write)\s+"
    r"(?:(?:a|an|the|new|reproducible)\s+){0,4}"
    r"(?:command[- ]line (?:developer )?tool|cli tool|research write[- ]?up|"
    r"research paper|literature review)\b")
SMALL_RE = re.compile(
    r"(?i)\b(single[- ]file|one file|small script|bug fix|add a flag|landing page|"
    r"static page|command[- ]line flag|rename|copy change)\b")
GREENFIELD_RE = re.compile(
    r"(?i)\b(?:build|create|develop|design|implement)\s+"
    r"(?:(?:a|an|the|new|offline[- ]first)\s+){0,4}"
    r"(?:app|application|system|pipeline|service|platform|firmware)\b")
WHOLE_DELIVERABLE_RE = re.compile(
    r"(?i)\b(?:build|create|develop|design|implement|produce|write)\b")
DOMAIN_COMPLEXITY = {
    "accounting", "android", "cli", "data-etl", "desktop", "firmware-hardware",
    "ios-macos", "llm-agent", "ml", "mobile", "realtime-3d", "research", "web-app",
}


def classify(description, *, files=None, days=None, new_components=0,
             new_boundaries=0, implementers=1, irreversible=False, domains=None):
    text = str(description or "").strip()
    domain_ids = sorted(set(str(item).strip().casefold()
                            for item in (domains or []) if str(item).strip()))
    reasons = []
    tier = "S"
    risk_hits = sorted(set(match.group(0).lower() for match in RISK_RE.finditer(text)))
    program_hits = sorted(set(match.group(0).lower() for match in PROGRAM_RE.finditer(text)))
    portfolio_hits = sorted(set(
        match.group(0).lower() for match in PORTFOLIO_RE.finditer(text)))
    disciplined_hits = sorted(set(
        match.group(0).lower() for match in DISCIPLINED_DELIVERABLE_RE.finditer(text)))
    multi_phase = bool(MULTI_PHASE_RE.search(text))
    plan_and_implement = bool(PLAN_IMPLEMENT_RE.search(text))
    greenfield_unknown = bool(GREENFIELD_RE.search(text)) \
        and not disciplined_hits and not SMALL_RE.search(text)
    whole_deliverable = bool(WHOLE_DELIVERABLE_RE.search(text)) \
        and not SMALL_RE.search(text)
    subsystem_signals = len(re.findall(r",|\b(?:and|with)\b", text, re.IGNORECASE))
    cross_domain = whole_deliverable and len(domain_ids) > 1
    complex_single_domain = whole_deliverable and any(
        item in DOMAIN_COMPLEXITY for item in domain_ids)
    multi_subsystem_domain = complex_single_domain and subsystem_signals >= 3
    consequential_domain = bool(set(domain_ids) & {
        "accounting", "firmware-hardware", "high-risk", "medical-clinical",
        "legal-regulatory", "mechanical-industrial"}) and not SMALL_RE.search(text)
    if portfolio_hits or (days is not None and days > 60) \
            or new_components >= 8 or new_boundaries >= 8 or implementers >= 6:
        tier = "XL"
        reasons.append("portfolio-scale duration, scope, or coordination requires milestone slices")
    elif program_hits or cross_domain or multi_subsystem_domain \
            or (multi_phase and plan_and_implement) \
            or ("realtime-3d" in domain_ids and not SMALL_RE.search(text)) \
            or (days is not None and days > 10) \
            or new_components >= 3 or new_boundaries >= 3 or implementers >= 3:
        tier = "L"
        reasons.append(
            "product/subsystem, domain-boundary, or multi-implementer signals require a "
            "release pack")
    elif risk_hits or consequential_domain or irreversible or (days is not None and days > 1) \
            or new_components > 0 or new_boundaries > 0 \
            or (files is not None and files > 5) or implementers > 1 \
            or greenfield_unknown or complex_single_domain:
        tier = "M"
        reasons.append(
            "observed risk/scope or a whole domain deliverable exceeds proven small work")
    else:
        reasons.append("one implementer, one sitting, low blast radius; no architecture signal")
        if SMALL_RE.search(text):
            reasons.append("description contains an explicit small-work shape")
    promotion = []
    if tier == "S":
        promotion = [
            "promote to M if survey finds a new component/boundary, >5 touched files, "
            "irreversible state, or more than one sitting",
        ]
    elif tier == "M":
        promotion = [
            "promote to L if survey finds three or more subsystems/boundaries, "
            "multi-milestone release work, or three implementers",
        ]
    elif tier == "L":
        promotion = [
            "promote to XL if observed work spans more than 60 days, eight subsystems "
            "or boundaries, six implementers, or a portfolio-scale program",
        ]
    return {
        "schema_version": 1,
        "tier": tier,
        "reasons": reasons,
        "risk_terms": risk_hits,
        "program_terms": program_hits,
        "portfolio_terms": portfolio_hits,
        "disciplined_deliverable_terms": disciplined_hits,
        "multi_phase_program": multi_phase,
        "plan_and_implement": plan_and_implement,
        "promotion_triggers": promotion,
        "policy": (
            "labels never promote; ties choose the lower tier; risk, observed scope, or an "
            "unbounded whole-deliverable request may promote"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--description", required=True)
    parser.add_argument("--files", type=int)
    parser.add_argument("--days", type=float)
    parser.add_argument("--new-components", type=int, default=0)
    parser.add_argument("--new-boundaries", type=int, default=0)
    parser.add_argument("--implementers", type=int, default=1)
    parser.add_argument("--irreversible", action="store_true")
    parser.add_argument("--domain", action="append", default=[])
    args = parser.parse_args(argv)
    numeric = (args.files, args.days, args.new_components,
               args.new_boundaries, args.implementers)
    if any(value is not None and value < 0 for value in numeric) or args.implementers < 1:
        print(json.dumps({"status": "error", "error": "numeric inputs are out of range"}))
        return 1
    result = classify(
        args.description, files=args.files, days=args.days,
        new_components=args.new_components, new_boundaries=args.new_boundaries,
        implementers=args.implementers, irreversible=args.irreversible,
        domains=args.domain)
    print(json.dumps({"status": "ok", "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
