#!/usr/bin/env python3
"""Select Loom domain adapters without pretending generic coverage is expertise."""

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

import loom_domain_composition
import loom_domain_contract

SCHEMA_VERSION = 2
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_PROJECT_FILES = 4096
MAX_MANIFEST_BYTES = 512 * 1024

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
        "keywords": [r"\bdesktop app(?:lication)?\b", r"\bdesktop\b", r"\bwindows app\b", r"\blinux desktop\b",
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
        "keywords": [r"\bllm\b", r"\bai agent\b", r"\bchatbot\b", r"\bprompt pipeline\b",
                     r"\bloom\b", r"\bowner[- ]specific learning\b",
                     r"\bplanning (?:os|system|intelligence)\b",
                     r"\bagent runtime\b"],
        "invariants": ["graded eval set", "prompt/model version", "tool blast radius",
                       "injection/exfiltration controls", "cost budget", "behavioral rollback"],
    },
    "high-risk": {
        "keywords": [r"\bsecurity[- ]critical\b", r"\bfinancial workflow\b",
                     r"\bcredential rotation\b", r"\bproduction access\b",
                     r"\bhigh[- ]risk\b", r"\bregulated workflow\b"],
        "invariants": ["explicit authority boundary", "least privilege",
                       "complete audit trail", "two-person irreversible control",
                       "fail-closed recovery", "independent real-medium verification"],
    },
}

STRUCTURAL_SIGNALS = {
    "cli": {"files": {"cli.py", "__main__.py"}, "dependencies": {
        "click", "typer", "argparse", "commander", "clap", "package-bin"},
        "extensions": set()},
    "mobile": {"files": {"pubspec.yaml", "app.json"}, "dependencies": {
        "react-native", "flutter"}, "extensions": set()},
    "android": {"files": {"androidmanifest.xml", "build.gradle", "build.gradle.kts"},
                "dependencies": {"com.android.application"}, "extensions": set()},
    "ios-macos": {"files": {"info.plist", "project.pbxproj"},
                  "dependencies": {"swiftui"}, "extensions": {".swift"}},
    "data-etl": {"files": {"dbt_project.yml", "airflow.cfg"}, "dependencies": {
        "apache-airflow", "dbt-core", "dagster", "pyspark"}, "extensions": set()},
    "ml": {"files": {"mlflow.yml", "model.onnx"}, "dependencies": {
        "torch", "tensorflow", "scikit-learn", "mlflow"},
        "extensions": {".onnx"}},
    "realtime-3d": {"files": {"project.godot", "defaultengine.ini"}, "dependencies": {
        "three", "@react-three/fiber", "babylonjs", "unity"},
        "extensions": {".glb", ".gltf", ".fbx"}},
    "firmware-hardware": {"files": {"platformio.ini", "west.yml"}, "dependencies": {
        "zephyr", "esp-idf"}, "extensions": {".ino", ".kicad_pcb"}},
    "research": {"files": {"references.bib", "citations.cff"}, "dependencies": set(),
                 "extensions": {".bib", ".tex"}},
    "desktop": {"files": {"tauri.conf.json", "electron-builder.yml"}, "dependencies": {
        "electron", "@tauri-apps/api"}, "extensions": {".csproj"}},
    "website": {"files": {"astro.config.mjs", "sitemap.xml"}, "dependencies": {
        "astro", "gatsby"}, "extensions": set()},
    "web-app": {"files": {"next.config.js", "vite.config.ts"}, "dependencies": {
        "next"}, "extensions": set()},
    "library-sdk": {"files": {"py.typed"}, "dependencies": set(),
                    "extensions": {".gemspec"}},
    "browser-extension": {"files": set(), "dependencies": {
        "webextension-polyfill", "webextension-manifest"}, "extensions": set()},
    "llm-agent": {"files": {"promptfoo.yaml"}, "dependencies": {
        "openai", "anthropic", "langchain"}, "extensions": set()},
}

# Recognized consequence-bearing families that intentionally do not pretend to ship a
# complete adapter. Matching one names the missing domain instead of collapsing to
# ``unclassified``; G1 remains blocked until a discovered invariant bundle is sealed.
DISCOVERY_CATALOG = {
    "medical-clinical": [
        r"\bmedical\b", r"\bclinical\b", r"\bpatient\b", r"\bdiagnos",
        r"\btherapy\b", r"\bhealthcare\b",
    ],
    "legal-regulatory": [
        r"\blegal\b", r"\bstatute\b", r"\bregulat(?:ion|ory)\b",
        r"\bjurisdiction\b", r"\blicen[cs]ing\b",
    ],
    "wet-lab": [
        r"\bwet[- ]lab\b", r"\bassay\b", r"\bcell culture\b",
        r"\breagent\b", r"\bbiosafety\b",
    ],
    "mechanical-industrial": [
        r"\bmechanical\b", r"\bindustrial\b", r"\bpressure vessel\b",
        r"\bmachine guarding\b", r"\bload[- ]bearing\b",
    ],
    "marine-navigation": [
        r"\bmarine navigation\b", r"\b(?:ship|boat|nautical) vessel\b",
        r"\bcollision avoidance\b",
        r"\bnautical\b",
    ],
    "quantum-optics": [
        r"\bquantum optics\b", r"\boptical rig\b", r"\bphotonics\b",
    ],
}

# A Codex plugin manifest plus an Agent Skill entry point is stronger evidence for an
# agent system than a documentation website nested in the same repository.
STRUCTURAL_SIGNALS["llm-agent"]["files"].update({"plugin.json", "skill.md"})

GUIDANCE = {
    "cli": (["ambiguous exit semantics", "shell and encoding variance"],
            ["clean install succeeds", "help and failure contracts are stable"],
            ["real process invocation", "stdout/stderr and exit-code assertions"]),
    "mobile": (["device and lifecycle fragmentation", "permission/offline failure"],
               ["signed staged build", "supported-device smoke pass"],
               ["real-device lifecycle test", "offline and permission transitions"]),
    "data-etl": (["duplicate or late data", "partial replay corruption"],
                 ["idempotent replay", "lineage and backfill evidence"],
                 ["production-shaped dataset", "duplicate/late/backfill probes"]),
    "ml": (["training-serving skew", "evaluation leakage and drift"],
           ["versioned model and dataset", "predeclared thresholds pass"],
           ["held-out evaluation", "reproducible train/inference run"]),
    "accounting": (["unbalanced postings", "rounding, period, or tax-rule error"],
                   ["balanced ledger and reconciliation", "immutable audit evidence"],
                   ["double-entry property tests", "dated jurisdiction edge cases"]),
    "realtime-3d": (["frame-budget regression", "unit/coordinate or asset mismatch"],
                    ["target-device frame budget", "asset pipeline reproducibility"],
                    ["real GPU/device profile", "spatial interaction and asset probes"]),
    "firmware-hardware": (["unsafe state", "brick, timing, power, or revision mismatch"],
                          ["recoverable flash", "hardware revision and safe-state proof"],
                          ["hardware-in-loop run", "power-cycle and recovery test"]),
    "research": (["unsupported claim", "source or method irreproducibility"],
                 ["claim/evidence review", "limitations and correction route"],
                 ["source audit", "independent method reproduction"]),
    "desktop": (["installer/update failure", "OS, DPI, input, or filesystem variance"],
                ["clean-machine install", "signed update and rollback proof"],
                ["real packaged application", "clean-machine upgrade/rollback"]),
    "high-risk": (["unauthorized irreversible effect", "audit or recovery failure"],
                  ["independent approval", "fail-closed rollback exercised"],
                  ["isolated real-medium rehearsal", "authority and audit verification"]),
    "android": (["process-death state loss", "permission or device fragmentation"],
                ["signed AAB/APK", "supported real-device matrix passes"],
                ["instrumented real-device run", "process-death and permission probes"]),
    "ios-macos": (["entitlement or lifecycle failure", "signing/device variance"],
                  ["signed archive", "supported-device and upgrade pass"],
                  ["real-device lifecycle run", "provisioning and privacy probes"]),
    "website": (["inaccessible or slow content", "SEO/hosting regression"],
                ["real-content acceptance", "hosting and DNS rollback documented"],
                ["browser accessibility audit", "real network performance measurement"]),
    "web-app": (["auth/session contract failure", "client/server state divergence"],
                ["critical flows pass end to end", "migration rollback exercised"],
                ["real browser/server run", "session, failure, and recovery probes"]),
    "library-sdk": (["consumer API break", "version or packaging incompatibility"],
                    ["clean consumer install", "compatibility and deprecation checks pass"],
                    ["external fixture project", "published-package-shaped API tests"]),
    "automation": (["unbounded side effect", "duplicate or partial execution"],
                   ["dry run reviewed", "bounded activation and recovery route"],
                   ["isolated simulation", "idempotency and partial-failure probes"]),
    "browser-extension": (["excess permission", "hostile page or store variance"],
                          ["least-permission package", "store rollback path recorded"],
                          ["real supported browsers", "hostile-page and migration probes"]),
    "llm-agent": (["prompt injection or exfiltration", "behavior/cost regression"],
                  ["graded eval threshold passes", "tool rollback is exercised"],
                  ["versioned adversarial eval", "real tool sandbox and cost measurement"]),
}

ADAPTER_FIXTURES = {
    "accounting": "double-entry accounting ledger",
    "realtime-3d": "real-time 3D room configurator",
    "firmware-hardware": "microcontroller firmware",
    "research": "research literature review",
    "data-etl": "ETL data pipeline backfill",
    "ml": "machine-learning model training",
    "android": "Android application",
    "ios-macos": "iOS application",
    "mobile": "cross-platform mobile app",
    "cli": "command-line developer tool",
    "website": "marketing website",
    "web-app": "web application dashboard",
    "desktop": "desktop application",
    "library-sdk": "public SDK library",
    "automation": "scheduled automation job",
    "browser-extension": "browser extension",
    "llm-agent": "LLM agent tool pipeline",
    "high-risk": "security-critical credential rotation",
}

BENCHMARKS = (
    ("cli-tool", "command-line developer tool", {"cli"}, "exit"),
    ("mobile-app", "cross-platform mobile app", {"mobile"}, "device"),
    ("etl-pipeline", "ETL data pipeline with backfills", {"data-etl"}, "duplicate"),
    ("ml-system", "machine-learning training and inference", {"ml"}, "leakage"),
    ("bookkeeping", "double-entry accounting ledger", {"accounting"}, "unbalanced"),
    ("realtime-3d", "real-time 3D room configurator", {"realtime-3d"}, "frame"),
    ("firmware", "microcontroller firmware", {"firmware-hardware"}, "unsafe"),
    ("research", "research literature review", {"research"}, "claim"),
    ("desktop", "desktop application installer", {"desktop"}, "installer"),
    ("high-risk", "security-critical credential rotation", {"high-risk"}, "unauthorized"),
)


class DomainError(RuntimeError):
    pass


def _guidance(domain_id):
    risks, release, verification = GUIDANCE.get(domain_id, (
        ["domain-specific contract failure", "unsupported environment variance"],
        ["supported-environment acceptance", "documented rollback route"],
        ["domain-real-medium execution", "negative and recovery probes"],
    ))
    return {
        "risks": list(risks),
        "release_criteria": list(release),
        "verification": list(verification),
        "current_facts_to_verify": [
            "current platform/tool versions and limits",
            "current governing policies, standards, or regulations",
            "current target environment and release channel",
        ],
    }


def inspect_project(root_path):
    """Return bounded structural evidence without treating project prose as domain truth."""
    root = Path(root_path)
    if not root.is_absolute():
        root = Path(os.path.abspath(root))
    if not root.is_dir() or root.is_symlink():
        raise DomainError("project root must be a real local directory")
    names, extensions, dependencies = set(), set(), set()
    stack, count = [root], 0
    manifests = {"package.json", "requirements.txt", "pyproject.toml", "cargo.toml",
                 "manifest.json", "build.gradle", "build.gradle.kts"}
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise DomainError(f"cannot inspect project structure: {exc}") from exc
        for path in entries:
            count += 1
            if count > MAX_PROJECT_FILES:
                raise DomainError("project structure exceeds its inspection bound")
            try:
                info = path.lstat()
            except OSError as exc:
                raise DomainError(f"cannot inspect project entry: {exc}") from exc
            if stat.S_ISLNK(info.st_mode):
                raise DomainError("project structure contains a symlink")
            if stat.S_ISDIR(info.st_mode):
                if path.name not in {".git", "node_modules", "vendor", ".venv", "dist"}:
                    stack.append(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise DomainError("project structure contains an unsupported special entry")
            low_name = path.name.casefold()
            names.add(low_name)
            if path.suffix:
                extensions.add(path.suffix.casefold())
            if low_name in manifests and info.st_size <= MAX_MANIFEST_BYTES:
                try:
                    text = path.read_text(encoding="utf-8").casefold()
                except (OSError, UnicodeError) as exc:
                    raise DomainError(f"cannot read dependency manifest: {exc}") from exc
                if low_name == "package.json":
                    try:
                        value = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(value, dict):
                        for field in ("dependencies", "devdependencies", "peerdependencies"):
                            if isinstance(value.get(field), dict):
                                dependencies.update(str(item).casefold()
                                                    for item in value[field])
                        if isinstance(value.get("bin"), (dict, str)):
                            dependencies.add("package-bin")
                elif low_name == "manifest.json":
                    try:
                        value = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(value, dict) and type(value.get("manifest_version")) is int:
                        dependencies.add("webextension-manifest")
                elif low_name in {"build.gradle", "build.gradle.kts"}:
                    if "com.android.application" in text:
                        dependencies.add("com.android.application")
                else:
                    for token in re.findall(r"(?m)^\s*([a-z0-9_.@/-]+)", text):
                        dependencies.add(re.split(r"[<>=!~\[]", token)[0])
    return {"file_names": sorted(names), "extensions": sorted(extensions),
            "dependencies": sorted(dependencies)}


def _validate_facts(project_facts):
    if project_facts is None:
        return {"file_names": [], "extensions": [], "dependencies": []}
    if not isinstance(project_facts, dict) or set(project_facts) != {
            "file_names", "extensions", "dependencies"}:
        raise DomainError("project facts fields are unknown or missing")
    normalized = {}
    for key in ("file_names", "extensions", "dependencies"):
        values = project_facts[key]
        if not isinstance(values, list) or len(values) > MAX_PROJECT_FILES \
                or not all(isinstance(item, str) and 0 < len(item) <= 200 for item in values):
            raise DomainError("project facts are invalid or exceed their bound")
        normalized[key] = sorted(set(item.casefold() for item in values))
    return normalized


def _adapter_result(domain_id, adapter, *, keyword_hits, structural_hits):
    guidance = _guidance(domain_id)
    return {
        "id": domain_id,
        "coverage": "adapter",
        "keyword_hits": keyword_hits,
        "structural_hits": structural_hits,
        "required_invariants": list(adapter["invariants"]),
        "durable_invariants": list(adapter["invariants"]),
        **guidance,
    }


def _unknown_result(domain_id, *, keyword_hits=None, source="request"):
    return {
        "id": domain_id, "coverage": "unknown",
        "keyword_hits": list(keyword_hits or []), "structural_hits": [],
        "required_invariants": [], "durable_invariants": [],
        "risks": [], "release_criteria": [], "verification": [],
        "current_facts_to_verify": [], "evidence_source": source,
    }


def _validate_host_proposal(value):
    if value is None:
        return None
    fields = {"domains", "subsystems", "evidence", "provider", "model", "confidence"}
    if not isinstance(value, dict) or set(value) != fields:
        raise DomainError("host domain proposal fields are unknown or missing")
    if not isinstance(value["domains"], list) or len(value["domains"]) > 16 \
            or len(value["domains"]) != len(set(value["domains"])) \
            or not all(isinstance(item, str) and ID_RE.fullmatch(item)
                       for item in value["domains"]):
        raise DomainError("host domain proposal domains are invalid")
    if not isinstance(value["subsystems"], list) or len(value["subsystems"]) > 32 \
            or not isinstance(value["evidence"], list) or len(value["evidence"]) > 16 \
            or not all(isinstance(item, str) and 0 < len(item) <= 256
                       for item in value["evidence"]):
        raise DomainError("host domain proposal evidence is invalid or oversized")
    if not all(isinstance(value[key], str) and 0 < len(value[key]) <= 128
               for key in ("provider", "model")):
        raise DomainError("host domain proposal identity is invalid")
    confidence = value["confidence"]
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise DomainError("host proposal confidence is descriptive and must be in [0,1]")
    return value


def select_domains(description, explicit=None, project_facts=None, host_proposal=None):
    description = str(description or "").strip()
    explicit = [str(item).strip().lower() for item in (explicit or []) if str(item).strip()]
    if any(not ID_RE.fullmatch(item) for item in explicit):
        raise DomainError("explicit domain IDs must be safe lower-case local identifiers")
    facts = _validate_facts(project_facts)
    host_proposal = _validate_host_proposal(host_proposal)
    matches = []
    ambient = []
    if explicit:
        for domain_id in dict.fromkeys(explicit):
            adapter = CATALOG.get(domain_id)
            if adapter:
                matches.append(_adapter_result(
                    domain_id, adapter, keyword_hits=[], structural_hits=[]))
            else:
                matches.append(_unknown_result(domain_id, source="owner"))
        source = "explicit"
    else:
        # Paths and report filenames identify evidence sources, not the requested target.
        # Remove them before keyword scoring so e.g. "Deep Research Reports" or a docs site
        # cannot silently redefine an agent-runtime engineering request.
        low = re.sub(r"\[[^\]]*\]\([^)]*\)", " ", description)
        low = re.sub(
            r"\b[a-z]:[\\/].*?\.(?:md|txt|json|yaml|yml|pdf)(?=\s|$)", " ", low,
                     flags=re.IGNORECASE).casefold()
        low = re.sub(r"(?:^|\s)/(?:[^\s]+/)+[^\s]+", " ", low)
        low = re.sub(r"\b[^\s]+\.(?:md|txt|json|yaml|yml|pdf)\b", " ", low)
        scored = []
        for order, (domain_id, adapter) in enumerate(CATALOG.items()):
            hits = [pattern for pattern in adapter["keywords"]
                    if re.search(pattern, low, flags=re.IGNORECASE)]
            structural = STRUCTURAL_SIGNALS.get(domain_id, {})
            structural_hits = []
            for key, signal_values in structural.items():
                fact_key = "file_names" if key == "files" else key
                for value in sorted(set(facts[fact_key]) & set(signal_values)):
                    structural_hits.append(f"{key}:{value}")
            score = len(hits) * 2 + len(structural_hits) * 3
            if score:
                scored.append((-score, order, domain_id, hits, structural_hits, adapter))
            if structural_hits:
                ambient.append(domain_id)
        # Repository structure describes the surrounding world, not the owner's active request.
        # It may support a domain already named by language, but can never introduce another
        # active domain by itself.
        scored = [item for item in scored if item[3]]
        ids = {item[2] for item in scored}
        if "android" in ids or "ios-macos" in ids:
            scored = [item for item in scored if item[2] != "mobile"
                      or not ("android" in ids or "ios-macos" in ids)]
        if "llm-agent" in ids:
            scored = [item for item in scored if item[2] != "website" or item[3]]
        for _, _, domain_id, hits, structural_hits, adapter in sorted(scored):
            matches.append(_adapter_result(
                domain_id, adapter, keyword_hits=hits,
                structural_hits=structural_hits))
        for domain_id, patterns in DISCOVERY_CATALOG.items():
            hits = [pattern for pattern in patterns if re.search(pattern, low, re.I)]
            if hits:
                matches.append(_unknown_result(domain_id, keyword_hits=hits))
        source = "language-evidence" if matches else "no-active-task-evidence"

    # Host/model judgment may rank alternatives, but it cannot activate a domain or memory
    # without independent request/owner evidence.
    host_candidates = []
    if host_proposal:
        active = {item["id"] for item in matches}
        host_candidates = [{
            "domain": domain_id,
            "coverage": next((item["coverage"] for item in matches
                              if item["id"] == domain_id), "unknown"),
            "evidence": list(host_proposal["evidence"]),
            "source": "host-proposal", "rank": index + 1,
        } for index, domain_id in enumerate(host_proposal["domains"])
         if domain_id not in active]

    active_domains = list(dict.fromkeys(item["id"] for item in matches))
    memory_domains = [item["id"] for item in matches if item["coverage"] == "adapter"]
    coverage_by_domain = {item["id"]: (
        "known" if item["coverage"] == "adapter" else "unknown") for item in matches}
    if not active_domains:
        coverage_state = "unknown"
    elif all(value == "known" for value in coverage_by_domain.values()):
        coverage_state = "known"
    elif any(value == "known" for value in coverage_by_domain.values()):
        coverage_state = "partial"
    else:
        coverage_state = "unknown"
    graph_domains = active_domains or ["unclassified"]
    graph_coverage = coverage_by_domain or {"unclassified": "unknown"}
    try:
        graph = loom_domain_composition.build_graph(
            description, graph_domains, graph_coverage,
            subsystems=(host_proposal["subsystems"] if host_proposal
                        and host_proposal["subsystems"] else None))
    except loom_domain_composition.DomainCompositionError as exc:
        raise DomainError(str(exc)) from exc
    candidates = []
    for rank, item in enumerate(matches, 1):
        evidence = [*item.get("keyword_hits", []), *item.get("structural_hits", [])]
        if explicit:
            evidence = [f"owner-explicit:{item['id']}"]
        candidates.append({
            "domain": item["id"],
            "coverage": "known" if item["coverage"] == "adapter" else "unknown",
            "evidence": evidence or [f"request-domain:{item['id']}"],
            "source": "owner" if explicit else "request", "rank": rank,
        })
    candidates.extend(host_candidates)
    missing = []
    if coverage_state in {"unknown", "partial"}:
        for domain_id, state in graph_coverage.items():
            if state != "known":
                missing.extend([
                    f"{domain_id}: governing authority and applicability",
                    f"{domain_id}: load-bearing invariants and failure modes",
                    f"{domain_id}: real verification medium",
                ])
    route_body = {
        "schema_version": loom_domain_contract.SCHEMA_VERSION,
        "policy_version": loom_domain_contract.POLICY_VERSION,
        "coverage_state": coverage_state,
        "composition": len(graph_domains) > 1,
        "active_task_domains": active_domains,
        "memory_domains": memory_domains,
        "ambient_domains": sorted(set(ambient if not explicit else [])),
        "candidates": candidates,
        "rejected_alternatives": [f"ambient-only:{item}"
                                  for item in sorted(set(ambient) - set(active_domains))],
        "missing_knowledge": missing[:32],
        "consequence": graph["consequence"],
        "subsystems": graph["nodes"],
        "graph_digest": graph["graph_digest"],
    }
    route_contract = {**route_body, "route_digest": loom_domain_contract.digest(
        "domain-route-v1", route_body)}
    try:
        loom_domain_contract.validate_route(route_contract)
    except loom_domain_contract.DomainContractError as exc:
        raise DomainError(str(exc)) from exc

    unknown = coverage_state != "known"
    primary = matches[0]["id"] if matches else "unclassified"
    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "coverage": "unknown" if unknown else "adapter",
        "coverage_state": coverage_state,
        "memory_domain": primary,
        "memory_domains": memory_domains,
        "active_task_domains": active_domains,
        "ambient_domains": sorted(set(ambient if not explicit else [])),
        "adapters": matches,
        "domain_contract": route_contract,
        "composition_graph": graph,
        "requires_domain_discovery": unknown,
        "g1_status": "blocked" if unknown else "eligible-after-invariant-evidence",
        "required_artifact": "domain-discovery.md" if unknown else None,
        "note": ("No matching adapter supplies domain invariants. Discover and verify them "
                 "before G1; do not apply a web/software template by default."
                 if unknown else
                 "Adapters supply a checklist, not current domain truth. Verify concrete "
                 "rules, platforms, and release constraints before load-bearing use."),
    }


def evaluate_benchmarks():
    results = []
    for benchmark_id, description, expected, risk_token in BENCHMARKS:
        selection = select_domains(description)
        actual = set(selection["memory_domains"])
        adapters = {item["id"]: item for item in selection["adapters"]}
        risks = " ".join(risk for domain_id in expected
                         for risk in adapters.get(domain_id, {}).get("risks", []))
        passed = expected.issubset(actual) and risk_token in risks \
            and all(adapters[item]["release_criteria"]
                    and adapters[item]["verification"]
                    and adapters[item]["durable_invariants"]
                    and adapters[item]["current_facts_to_verify"]
                    for item in expected if item in adapters)
        results.append({"id": benchmark_id, "expected": sorted(expected),
                        "actual": sorted(actual), "passed": passed})
    adapter_results = {}
    for domain_id, description in ADAPTER_FIXTURES.items():
        selection = select_domains(description)
        adapter = next((item for item in selection["adapters"]
                        if item["id"] == domain_id), None)
        adapter_results[domain_id] = bool(
            adapter and adapter["durable_invariants"]
            and adapter["current_facts_to_verify"] and adapter["risks"]
            and adapter["release_criteria"] and adapter["verification"])
    return {"schema_version": SCHEMA_VERSION, "benchmark_count": len(results),
            "passed": all(item["passed"] for item in results)
            and set(adapter_results) == set(CATALOG) and all(adapter_results.values()),
            "benchmarks": results, "adapter_fixtures": adapter_results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--description")
    source.add_argument("--description-file")
    parser.add_argument("--project-root")
    parser.add_argument("--evaluate-benchmarks", action="store_true")
    parser.add_argument("--domain", action="append", default=[],
                        help="explicit domain ID; repeat for a composite project")
    args = parser.parse_args(argv)
    try:
        if args.evaluate_benchmarks:
            result = evaluate_benchmarks()
            print(json.dumps({"status": "ok", "result": result}, sort_keys=True))
            return 0 if result["passed"] else 1
        if not args.description and not args.description_file:
            raise DomainError("description or --evaluate-benchmarks is required")
        if args.description_file:
            description = Path(args.description_file).read_text(encoding="utf-8")
        else:
            description = args.description
        facts = inspect_project(args.project_root) if args.project_root else None
        result = select_domains(description, args.domain, facts)
    except (OSError, UnicodeError, DomainError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "ok", "result": result},
                     sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
