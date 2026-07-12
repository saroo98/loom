#!/usr/bin/env python3
"""Select Loom domain adapters without pretending generic coverage is expertise."""

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Stable invariants only. Concrete regulations, SDK behavior, limits, and policies must be
# verified from current authoritative sources during the planning run.
CATALOG = {
    "accounting": {
        "keywords": [r"\baccount(?:ing|ant)\b", r"\bbookkeep", r"\bdouble[- ]entry\b",
                     r"\bledger\b", r"\btax\b"],
        "invariants": ["balanced postings", "currency precision", "immutable audit trail",
                       "reconciliation", "period close", "jurisdiction/effective-date rules"],
    },
    "realtime-3d": {
        "keywords": [r"\breal[- ]time 3d\b", r"\broom configurator\b", r"\bwebgl\b",
                     r"\bthree\.js\b", r"\brender(?:er|ing)?\b", r"\bspatial ux\b"],
        "invariants": ["coordinate and unit convention", "asset pipeline", "frame budget",
                       "GPU/device budget", "spatial interaction", "real-device profiling"],
    },
    "firmware-hardware": {
        "keywords": [r"\bfirmware\b", r"\bmicrocontroller\b", r"\bembedded\b",
                     r"\bhardware\b", r"\bpcb\b", r"\bfpga\b"],
        "invariants": ["board/revision identity", "timing/power/memory budgets",
                       "fail-safe state", "hardware-in-loop evidence", "flash/recovery path",
                       "physical rollback and safety boundary"],
    },
    "research": {
        "keywords": [r"\bresearch\b", r"\bliterature review\b", r"\bwrite[- ]?up\b",
                     r"\bpaper\b", r"\bstudy\b", r"\bmethodology\b"],
        "invariants": ["research question", "source provenance", "claims/evidence matrix",
                       "method reproducibility", "limitations", "review and publication ethics"],
    },
    "data-etl": {
        "keywords": [r"\betl\b", r"\bdata pipeline\b", r"\bwarehouse\b",
                     r"\bbackfill\b", r"\bdata ingest"],
        "invariants": ["schema and lineage", "idempotency", "replay/backfill",
                       "late/duplicate data", "schema evolution", "retention and recovery"],
    },
    "ml": {
        "keywords": [r"\bmachine[- ]learning\b", r"\bml[- ]pipeline\b", r"\bmodel training\b",
                     r"\beval(?:uation)? set\b", r"\binference\b"],
        "invariants": ["data provenance", "leakage control", "predeclared evaluation",
                       "reproducibility", "model/artifact version", "drift thresholds"],
    },
    "android": {
        "keywords": [r"\bandroid\b", r"\bapk\b", r"\baab\b", r"\bplay store\b"],
        "invariants": ["device/OS floor", "lifecycle/process death", "permissions",
                       "offline/sync", "real-device evidence", "signed staged release"],
    },
    "ios-macos": {
        "keywords": [r"\bios\b", r"\biphone\b", r"\bipad\b", r"\bmacos\b",
                     r"\bapp store\b", r"\btestflight\b"],
        "invariants": ["device/OS floor", "lifecycle and entitlements", "permissions/privacy",
                       "real-device evidence", "signing/provisioning", "staged release"],
    },
    "mobile": {
        "keywords": [r"\bmobile app\b", r"\bcross[- ]platform mobile\b", r"\bflutter\b",
                     r"\breact native\b"],
        "invariants": ["target OS/device matrix", "native bridge/lifecycle", "offline/sync",
                       "permissions", "real-device evidence", "packaging/release channel"],
    },
    "cli": {
        "keywords": [r"\bcli\b", r"\bcommand[- ]line\b", r"\bterminal tool\b",
                     r"\bdeveloper tool\b"],
        "invariants": ["command/flag contract", "exit codes", "stdout/stderr separation",
                       "noninteractive mode", "path/encoding portability", "clean install"],
    },
    "website": {
        "keywords": [r"\bmarketing (?:site|website)\b", r"\bwebsite\b", r"\blanding page\b",
                     r"\bportfolio site\b"],
        "invariants": ["real content", "responsive/accessibility scope", "performance budget",
                       "SEO scope", "failure without script", "hosting/DNS rollback"],
    },
    "web-app": {
        "keywords": [r"\bweb app(?:lication)?\b", r"\bspa\b", r"\bssr\b",
                     r"\bweb dashboard\b"],
        "invariants": ["client/server contracts", "auth/session model", "state coverage",
                       "browser scope", "migration rollback", "end-to-end critical flows"],
    },
    "desktop": {
        "keywords": [r"\bdesktop app(?:lication)?\b", r"\bwindows app\b", r"\blinux desktop\b",
                     r"\bwinui\b", r"\bwpf\b", r"\btauri\b"],
        "invariants": ["OS/version matrix", "filesystem/config contract", "clean-machine test",
                       "DPI/input variance", "installer/signing", "update/rollback path"],
    },
    "library-sdk": {
        "keywords": [r"\blibrary\b", r"\bsdk\b", r"\bpackage\b", r"\bpublic api\b"],
        "invariants": ["public API contract", "compatibility/version policy", "examples in CI",
                       "deprecation path", "clean consumer install", "registry rollback"],
    },
    "automation": {
        "keywords": [r"\bautomation\b", r"\bscript\b", r"\bbot\b", r"\bscheduled job\b"],
        "invariants": ["blast radius", "dry run", "idempotency", "side-effect inventory",
                       "simulation evidence", "explicit live activation"],
    },
    "browser-extension": {
        "keywords": [r"\bbrowser extension\b", r"\bchrome extension\b", r"\bwebextension\b"],
        "invariants": ["permission budget", "browser/store scope", "hostile page boundary",
                       "state migration", "review lead time", "rollback through store"],
    },
    "llm-agent": {
        "keywords": [r"\bllm\b", r"\bai agent\b", r"\bchatbot\b", r"\bprompt pipeline\b"],
        "invariants": ["graded eval set", "prompt/model version", "tool blast radius",
                       "injection/exfiltration controls", "cost budget", "behavioral rollback"],
    },
}


class DomainError(RuntimeError):
    pass


def select_domains(description, explicit=None):
    description = str(description or "").strip()
    explicit = [str(item).strip().lower() for item in (explicit or []) if str(item).strip()]
    if any(not ID_RE.fullmatch(item) for item in explicit):
        raise DomainError("explicit domain IDs must be safe lower-case local identifiers")
    matches = []
    if explicit:
        for domain_id in dict.fromkeys(explicit):
            adapter = CATALOG.get(domain_id)
            matches.append({
                "id": domain_id,
                "coverage": "adapter" if adapter else "unknown",
                "keyword_hits": [],
                "required_invariants": list(adapter["invariants"]) if adapter else [],
            })
        source = "explicit"
    else:
        low = description.casefold()
        scored = []
        for order, (domain_id, adapter) in enumerate(CATALOG.items()):
            hits = [pattern for pattern in adapter["keywords"]
                    if re.search(pattern, low, flags=re.IGNORECASE)]
            if hits:
                scored.append((-len(hits), order, domain_id, hits, adapter))
        for _, _, domain_id, hits, adapter in sorted(scored):
            matches.append({
                "id": domain_id,
                "coverage": "adapter",
                "keyword_hits": hits,
                "required_invariants": list(adapter["invariants"]),
            })
        source = "keyword-evidence"

    unknown = not matches or any(item["coverage"] == "unknown" for item in matches)
    primary = matches[0]["id"] if matches else "unclassified"
    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "coverage": "unknown" if unknown else "adapter",
        "memory_domain": primary,
        "memory_domains": [item["id"] for item in matches],
        "adapters": matches,
        "requires_domain_discovery": unknown,
        "g1_status": "blocked" if unknown else "eligible-after-invariant-evidence",
        "required_artifact": "domain-discovery.md" if unknown else None,
        "note": ("No matching adapter supplies domain invariants. Discover and verify them "
                 "before G1; do not apply a web/software template by default."
                 if unknown else
                 "Adapters supply a checklist, not current domain truth. Verify concrete "
                 "rules, platforms, and release constraints before load-bearing use."),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--description")
    source.add_argument("--description-file")
    parser.add_argument("--domain", action="append", default=[],
                        help="explicit domain ID; repeat for a composite project")
    args = parser.parse_args(argv)
    try:
        if args.description_file:
            description = Path(args.description_file).read_text(encoding="utf-8")
        else:
            description = args.description
        result = select_domains(description, args.domain)
    except (OSError, UnicodeError, DomainError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "ok", "result": result},
                     sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
