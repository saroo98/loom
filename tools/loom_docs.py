#!/usr/bin/env python3
"""Coherence and live-evidence checks for Loom's public documentation."""

import argparse
import ast
import json
import os
import re
import tempfile
import subprocess
from pathlib import Path, PurePosixPath

import loom_capability_registry
import loom_reliability
import loom_subject_identity
import loom_truth
import loom_version


PUBLIC_SURFACE = ("README.md", "START-HERE.md", "skill/loom/SKILL.md", "docs/index.html")
VERSION_SURFACE = PUBLIC_SURFACE + (
    "docs/architecture.md", "docs/capabilities.json",
)
READINESS_VERSION_SURFACE = "docs/release-readiness.json"
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
    v1_fields = {"schema_version", "version", "capabilities"}
    v2_fields = v1_fields | {"generated_by", "evidence_policy", "subject_digest",
                             "evaluated_at"}
    v3_fields = v1_fields | {
        "generated_by", "evidence_policy", "declarations_policy",
        "subject_bindings", "expected_subjects_sha256",
        "evaluated_at", "next_invalidation_at",
    }
    expected_fields = (
        v1_fields if value.get("schema_version") == 1 else
        v2_fields if value.get("schema_version") == 2 else v3_fields)
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2, 3} \
            or set(value) != expected_fields \
            or not isinstance(value["capabilities"], list):
        raise DocsError("capability registry shape is invalid")
    if value["schema_version"] == 2 and (
            value.get("generated_by") != "tools/loom_capability_registry.py"
            or value.get("evidence_policy") != "loom-evidence-policy-v1"):
        raise DocsError("capability registry generator or policy is invalid")
    if value["schema_version"] == 3 and (
            value.get("generated_by") != "tools/loom_capability_registry.py"
            or value.get("evidence_policy") != "loom-evidence-policy-v1"
            or value.get("declarations_policy")
            not in {"loom-capability-declarations-v1", "legacy-read-only"}
            or not isinstance(value.get("subject_bindings"), list)
            or value.get("expected_subjects_sha256") is not None
            and not re.fullmatch(
                r"[0-9a-f]{64}", value["expected_subjects_sha256"])):
        raise DocsError("capability registry v3 authority metadata is invalid")
    seen = set()
    for item in value["capabilities"]:
        fields = {"id", "kind", "enforcement", "tests"}
        if value["schema_version"] == 2:
            fields |= {"status", "evidence_ids", "limitations", "proof_binding"}
        elif value["schema_version"] == 3:
            fields |= {
                "status", "evidence_ids", "limitations", "proof_binding",
                "required_predicates", "required_subject_kinds",
            }
        if not isinstance(item, dict) or set(item) != fields \
                or item["kind"] not in {"mechanical", "advisory"} \
                or not isinstance(item["id"], str) or not item["id"] or item["id"] in seen \
                or not isinstance(item["enforcement"], list) or not isinstance(item["tests"], list) \
                or not all(isinstance(path, str) and path for path in item["enforcement"] + item["tests"]) \
                or value["schema_version"] == 2 and (
                    item["status"] not in {"supported", "experimental", "stale-proof",
                                           "unsupported", "unverified"}
                    or not isinstance(item["evidence_ids"], list)
                    or not isinstance(item["limitations"], list)
                    or not isinstance(item["proof_binding"], dict)
                    or set(item["proof_binding"]) != {
                        "subject_digest", "evidence_graph_sha256", "files"}
                    or not isinstance(item["proof_binding"]["files"], list)):
            raise DocsError("capability registry entry is invalid")
        if value["schema_version"] == 3 and (
                item["status"] not in {"supported", "experimental", "stale-proof",
                                       "unsupported", "unverified"}
                or not isinstance(item["evidence_ids"], list)
                or not isinstance(item["limitations"], list)
                or not isinstance(item["required_predicates"], list)
                or not isinstance(item["required_subject_kinds"], list)
                or not isinstance(item["proof_binding"], dict)
                or set(item["proof_binding"]) != {
                    "subject_bindings", "evidence_graph_sha256", "files"}
                or not isinstance(item["proof_binding"]["subject_bindings"], list)
                or not isinstance(item["proof_binding"]["files"], list)):
            raise DocsError("capability registry v3 entry is invalid")
        seen.add(item["id"])
    return value


def load_capability_declarations(root):
    path = _safe_relative(root, "contracts/capability-declarations-v1.json")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
        _version, declarations, authoritative = \
            loom_capability_registry._declarations(value)
    except (
            OSError, UnicodeError, json.JSONDecodeError,
            loom_capability_registry.CapabilityRegistryError) as exc:
        raise DocsError("capability declarations are unreadable") from exc
    if not authoritative:
        raise DocsError("capability declarations are not authoritative")
    return value, declarations


def check_version_coherence(root, version):
    root = Path(root).resolve()
    if (root / "contracts" / "truth-authorities-v1.json").is_file():
        try:
            observed = loom_version.verify(root)
        except loom_version.VersionError as exc:
            return [{
                "code": "VERSION_DRIFT",
                "path": "registered-version-projections",
                "expected": version,
                "detail": str(exc),
            }]
        return [] if observed["version"] == version else [{
            "code": "VERSION_DRIFT",
            "path": "VERSION",
            "expected": version,
        }]
    findings = []
    marker = re.compile(rf"(?<![0-9.]){re.escape(version)}(?![0-9.])")
    try:
        require_readiness = tuple(int(item) for item in version.split(".")) >= (1, 7, 0)
    except (TypeError, ValueError):
        require_readiness = True
    surfaces = VERSION_SURFACE + ((READINESS_VERSION_SURFACE,)
                                  if require_readiness else ())
    for relative in surfaces:
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


def _bounded_repository_paths(root):
    """Return Git-tree paths plus exact declared generated outputs."""
    root = Path(root).resolve()
    paths = set(PUBLIC_SURFACE + ("docs/architecture.md", "tools/loom_docs.py"))
    has_git_metadata = (root / ".git").exists()
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=10, check=True).stdout.strip()
        inventory = loom_subject_identity.git_tree_inventory(root, commit)
        paths.update(item["path"] for item in inventory["entries"])
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"],
            cwd=root, capture_output=True, timeout=10, check=True).stdout
        overlay = [
            item.decode("utf-8", errors="strict")
            for item in untracked.split(b"\0") if item]
        if len(overlay) > 1024:
            raise DocsError(
                "bounded documentation overlay exceeds its path limit")
        paths.update(overlay)
    except (
            OSError, subprocess.SubprocessError,
            loom_subject_identity.SubjectIdentityError):
        if has_git_metadata:
            raise DocsError("bounded Git inventory is unavailable")
        # Unit fixtures and historical extracted cuts have no Git object store.
        # Keep their compatibility inspection explicitly shallow and bounded.
        for item in sorted(root.iterdir(), key=lambda path: path.name.encode("utf-8")):
            if item.is_file():
                paths.add(item.name)
        for directory in ("tools", "schemas", "docs", "contracts"):
            base = root / directory
            if not base.is_dir():
                continue
            for item in sorted(
                    base.iterdir(), key=lambda path: path.name.encode("utf-8")):
                if item.is_file():
                    paths.add(item.relative_to(root).as_posix())
    try:
        registry = loom_truth.validate_registry(json.loads(
            (root / "contracts" / "truth-authorities-v1.json").read_text(
                encoding="utf-8"), object_pairs_hook=_strict_object))
        paths.update(item["path"] for item in registry["generated_outputs"])
    except (OSError, UnicodeError, json.JSONDecodeError, loom_truth.TruthError):
        pass
    if len(paths) > 8192 + 256:
        raise DocsError("bounded documentation inventory exceeds its path limit")
    return tuple(sorted(paths, key=lambda item: item.encode("utf-8")))


def _repo_reference_findings(root):
    """Catch repository-document references that are prose/code literals, not links."""
    root = Path(root).resolve()
    findings = []
    for relative in _bounded_repository_paths(root):
        path = root.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file() \
                or path.suffix.lower() not in {".md", ".py", ".json", ".html"}:
            continue
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
        if registry["schema_version"] == 3:
            declarations_value, declarations = load_capability_declarations(root)
            expected_registry = loom_capability_registry.generate(
                declarations_value, root=root)
            expected_by_id = {
                item["id"]: item for item in expected_registry["capabilities"]}
            projection_static = {
                item["id"]: {
                    key: item[key] for key in (
                        "id", "kind", "enforcement", "tests",
                        "limitations", "required_predicates",
                        "required_subject_kinds")
                } | {"proof_files": item["proof_binding"]["files"]}
                for item in registry["capabilities"]
            }
            expected_static = {
                item_id: {
                    key: item[key] for key in (
                        "id", "kind", "enforcement", "tests",
                        "limitations", "required_predicates",
                        "required_subject_kinds")
                } | {"proof_files": item["proof_binding"]["files"]}
                for item_id, item in expected_by_id.items()
            }
            if registry["version"] != expected_registry["version"] \
                    or registry["declarations_policy"] \
                    != expected_registry["declarations_policy"] \
                    or projection_static != expected_static:
                findings.append({
                    "code": "CAPABILITY_PROJECTION_STALE",
                    "path": "docs/capabilities.json",
                })
            declared_ids = {item["id"] for item in declarations}
            projected_ids = {item["id"] for item in registry["capabilities"]}
            if declared_ids != projected_ids:
                findings.append({
                    "code": "CAPABILITY_DECLARATION_DRIFT",
                    "missing": sorted(declared_ids - projected_ids),
                    "extra": sorted(projected_ids - declared_ids),
                })
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
    inventory = _bounded_repository_paths(root)
    test_modules = [
        root.joinpath(*PurePosixPath(relative).parts)
        for relative in inventory
        if re.fullmatch(r"tools/test_[^/]+\.py", relative)]
    test_methods = 0
    for path in test_modules:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=str(path))
        test_methods += sum(
            1 for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_"))
    production_modules = [
        relative for relative in inventory
        if re.fullmatch(r"tools/loom_[^/]+\.py", relative)]
    schema_documents = [
        relative for relative in inventory
        if re.fullmatch(r"schemas/[^/]+\.schema\.json", relative)]
    try:
        _declarations_value, declarations = load_capability_declarations(root)
    except DocsError:
        registry = load_capabilities(root)
        if registry["schema_version"] == 3:
            raise
        declarations = registry["capabilities"]
    return {
        "schema_version": 1,
        "loom_version": (root / "VERSION").read_text(encoding="utf-8").strip(),
        "measurement": "repository inventory; this does not claim tests passed",
        "discovered_test_modules": len(test_modules),
        "discovered_test_methods": test_methods,
        "production_tool_modules": len(production_modules),
        "schema_documents": len(schema_documents),
        "capability_claims": len(declarations),
    }


def refresh_evidence(root, *, expected_test_methods=None):
    """Atomically refresh the inventory and prove it still matches the final tree."""
    root = Path(root).resolve()
    evidence = generate_evidence(root)
    if expected_test_methods is not None \
            and evidence["discovered_test_methods"] != expected_test_methods:
        raise DocsError(
            "final test execution count does not match the discovered test inventory")
    output = root / "docs" / "generated-evidence.json"
    loom_reliability.atomic_write_json(output, evidence)
    observed = json.loads(
        output.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    final = generate_evidence(root)
    if observed != evidence or final != evidence:
        raise DocsError("generated evidence changed during final inventory refresh")
    return evidence


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
        output = Path(args.output) if args.output else root / "docs/generated-evidence.json"
        try:
            safe_output = loom_reliability._absolute(output, "documentation evidence output")
            safe_output.relative_to(root)
        except (ValueError, loom_reliability.ReliabilityError) as exc:
            raise SystemExit("output must stay inside the repository") from exc
        if safe_output == root / "docs" / "generated-evidence.json":
            report = refresh_evidence(root)
        else:
            report = generate_evidence(root)
            loom_reliability.atomic_write_json(safe_output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if args.command == "generate" or report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
