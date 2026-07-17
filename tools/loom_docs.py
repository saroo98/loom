#!/usr/bin/env python3
"""Coherence and live-evidence checks for Loom's public documentation."""

import argparse
import ast
import json
import os
import re
import tempfile
from pathlib import Path


PUBLIC_SURFACE = ("README.md", "START-HERE.md", "skill/loom/SKILL.md", "docs/index.html")
VERSION_SURFACE = PUBLIC_SURFACE + (
    "docs/architecture.md", "docs/capabilities.json",
)
OPTIONAL_VERSION_SURFACE = ("docs/readme-hero.svg", "docs/social-card.svg")
VERSION_BADGE_SURFACE = ("docs/index.html",)
FORBIDDEN_PUBLIC_COMMANDS = (
    "/loom plan", "/loom resume", "/loom gate", "/loom wo", "/loom retro",
    "/loom profile", "/loom contribute", "subcommand",
)
LEGACY_PATTERNS = (
    ("LEGACY_MANUAL_LEARNING", re.compile(
        r"manually\s+(?:update|edit|append\s+to)\s+(?:feedback\.md|profile\.md|calibration\.md)",
        re.I)),
    ("IMPLICIT_CONTRIBUTION", re.compile(
        r"(?:automatically|implicitly)\s+(?:contribute|publish|upload)", re.I)),
    ("AUTOCLOSE_CONTRADICTION", re.compile(
        r"(?:run|invoke)\s+(?:an?\s+)?(?:auto[- ]?close|retro)\s+(?:command|step)", re.I)),
)
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
REPO_DOC_RE = re.compile(r"(?<![A-Za-z0-9_./-])(loom/[A-Za-z0-9_./-]+\.md)\b")
VERSION_BADGE_RE = re.compile(
    r"<[^>]+\bdata-loom-version=[\"']([^\"']+)[\"'][^>]*>([^<]+)</",
    re.I,
)


class DocsError(RuntimeError):
    pass


def _strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DocsError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _safe_relative(root, relative):
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise DocsError("documentation path is invalid")
    candidate = (Path(root) / relative).resolve()
    base = Path(root).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise DocsError("documentation path escapes repository") from exc
    return candidate


def scan_contradictions(root, relative_paths):
    findings = []
    for relative in relative_paths:
        path = _safe_relative(root, relative)
        if not path.is_file():
            findings.append({"code": "DOC_MISSING", "path": relative})
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        for code, pattern in LEGACY_PATTERNS:
            if pattern.search(text):
                findings.append({"code": code, "path": relative})
    return findings


def load_capabilities(root):
    path = _safe_relative(root, "docs/capabilities.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DocsError("capability registry is unreadable") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "version", "capabilities"} \
            or value["schema_version"] != 1 or not isinstance(value["capabilities"], list):
        raise DocsError("capability registry shape is invalid")
    seen = set()
    for item in value["capabilities"]:
        if not isinstance(item, dict) or set(item) != {"id", "kind", "enforcement", "tests"} \
                or item["kind"] not in {"mechanical", "advisory"} \
                or not isinstance(item["id"], str) or not item["id"] or item["id"] in seen \
                or not isinstance(item["enforcement"], list) or not isinstance(item["tests"], list) \
                or not all(isinstance(path, str) and path for path in item["enforcement"] + item["tests"]):
            raise DocsError("capability registry entry is invalid")
        seen.add(item["id"])
    return value


def check_version_coherence(root, version):
    findings = []
    marker = re.compile(rf"(?<![0-9.]){re.escape(version)}(?![0-9.])")
    for relative in VERSION_SURFACE:
        path = _safe_relative(root, relative)
        if not path.is_file() or not marker.search(path.read_text(encoding="utf-8")):
            findings.append({"code": "VERSION_DRIFT", "path": relative, "expected": version})
    for relative in OPTIONAL_VERSION_SURFACE:
        path = _safe_relative(root, relative)
        if path.is_file() and not marker.search(path.read_text(encoding="utf-8")):
            findings.append({"code": "VERSION_DRIFT", "path": relative, "expected": version})
    for relative in VERSION_BADGE_SURFACE:
        path = _safe_relative(root, relative)
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        badges = VERSION_BADGE_RE.findall(text)
        if "data-loom-version" in text and not badges:
            findings.append({
                "code": "VERSION_BADGE_MALFORMED", "path": relative, "expected": version})
            continue
        for attribute, label in badges:
            if attribute != version or label.strip() != version:
                findings.append({
                    "code": "VERSION_BADGE_DRIFT", "path": relative,
                    "expected": version, "attribute": attribute, "label": label.strip(),
                })
    return findings


def _link_findings(root, relative_paths):
    findings = []
    for relative in relative_paths:
        path = _safe_relative(root, relative)
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        for target in LINK_RE.findall(text):
            clean = target.split("#", 1)[0]
            if not clean or re.match(r"^[a-z]+://", clean, re.I):
                continue
            resolved = (path.parent / clean).resolve()
            try:
                resolved.relative_to(Path(root).resolve())
            except ValueError:
                findings.append({"code": "LINK_ESCAPE", "path": relative, "target": target})
                continue
            if not resolved.exists():
                findings.append({"code": "LINK_BROKEN", "path": relative, "target": target})
    return findings


def _repo_reference_findings(root):
    """Catch repository-document references that are prose/code literals, not links."""
    root = Path(root).resolve()
    findings = []
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts or not path.is_file() \
                or path.suffix.lower() not in {".md", ".py", ".json", ".html"}:
            continue
        relative = path.relative_to(root).as_posix()
        if relative == "tools/loom_docs.py" \
                or (relative.startswith("tools/test_") and relative.endswith(".py")):
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        for target in sorted(set(REPO_DOC_RE.findall(text))):
            if not _safe_relative(root, target).is_file():
                findings.append({
                    "code": "REPO_REFERENCE_MISSING",
                    "path": relative,
                    "target": target,
                })
    return findings


def audit_docs(root):
    root = Path(root).resolve()
    findings = []
    version_path = root / "VERSION"
    if not version_path.is_file():
        return {"status": "failed", "version": None,
                "findings": [{"code": "VERSION_MISSING", "path": "VERSION"}]}
    version = version_path.read_text(encoding="utf-8", errors="strict").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        findings.append({"code": "VERSION_INVALID", "path": "VERSION"})
    findings.extend(check_version_coherence(root, version))
    findings.extend(scan_contradictions(root, PUBLIC_SURFACE + ("docs/architecture.md",)))
    for relative in PUBLIC_SURFACE:
        path = _safe_relative(root, relative)
        if not path.is_file():
            continue
        lowered = path.read_text(encoding="utf-8", errors="strict").lower()
        if "/loom <request>" not in lowered and "/loom &lt;request&gt;" not in lowered:
            findings.append({"code": "ONE_COMMAND_MISSING", "path": relative})
        for command in FORBIDDEN_PUBLIC_COMMANDS:
            if command in lowered:
                findings.append({"code": "PUBLIC_COMMAND_SPRAWL", "path": relative,
                                 "value": command})
    findings.extend(_link_findings(root, PUBLIC_SURFACE + ("docs/architecture.md",)))
    findings.extend(_repo_reference_findings(root))
    try:
        registry = load_capabilities(root)
        for item in registry["capabilities"]:
            if item["kind"] == "mechanical" and (not item["enforcement"] or not item["tests"]):
                findings.append({"code": "CLAIM_WITHOUT_PROOF", "id": item["id"]})
            for relative in item["enforcement"] + item["tests"]:
                if not _safe_relative(root, relative).is_file():
                    findings.append({"code": "PROOF_PATH_MISSING", "id": item["id"],
                                     "path": relative})
    except DocsError as exc:
        findings.append({"code": "CAPABILITY_REGISTRY_INVALID", "detail": str(exc)})
    evidence_path = root / "docs" / "generated-evidence.json"
    try:
        observed_evidence = json.loads(
            evidence_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object)
        expected_evidence = generate_evidence(root)
        if observed_evidence != expected_evidence:
            findings.append({
                "code": "GENERATED_EVIDENCE_STALE",
                "path": "docs/generated-evidence.json",
            })
    except (OSError, UnicodeError, json.JSONDecodeError, DocsError, SyntaxError) as exc:
        findings.append({
            "code": "GENERATED_EVIDENCE_INVALID",
            "path": "docs/generated-evidence.json",
            "detail": str(exc),
        })
    return {"status": "passed" if not findings else "failed", "version": version,
            "findings": findings}


def generate_evidence(root):
    root = Path(root).resolve()
    test_modules = sorted((root / "tools").glob("test_*.py"))
    test_methods = 0
    for path in test_modules:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=str(path))
        test_methods += sum(
            1 for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_"))
    production_modules = [
        path for path in (root / "tools").glob("loom_*.py")
        if not path.name.startswith("test_")]
    return {
        "schema_version": 1,
        "loom_version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "measurement": "repository inventory; this does not claim tests passed",
        "discovered_test_modules": len(test_modules),
        "discovered_test_methods": test_methods,
        "production_tool_modules": len(production_modules),
        "schema_documents": len(list((root / "schemas").glob("*.schema.json"))),
        "capability_claims": len(load_capabilities(root)["capabilities"]),
    }


def _atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("audit", "generate"))
    parser.add_argument("--root", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.command == "audit":
        report = audit_docs(root)
    else:
        report = generate_evidence(root)
        output = Path(args.output).resolve() if args.output else root / "docs/generated-evidence.json"
        try:
            output.relative_to(root)
        except ValueError as exc:
            raise SystemExit("output must stay inside the repository") from exc
        _atomic_json(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if args.command == "generate" or report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
