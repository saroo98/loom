#!/usr/bin/env python3
"""loom_lint — mechanical validation of a Loom planning pack.

Checks the machine-checkable fraction of Loom's discipline so gates and humans
spend judgment only where judgment is needed. Stdlib only.

Usage:
    python loom_lint.py <pack_path> [--repo <target_repo_root>] [--json]

Exit codes: 0 = no errors (warnings allowed), 1 = errors found, 2 = usage/IO problem.

Checks (E = error, blocks gates; W = warning):
    E01 MANIFEST.md missing
    E02 frontmatter missing or unterminated
    E03 required frontmatter key missing
    E04 invalid enum value
    E05 invalid date (expects YYYY-MM-DD)
    E06 work-order id does not match its filename
    E07 duplicate id (WO or ledger A-id)
    E08 depends_on references an unknown work order
    E09 dependency cycle among work orders
    E10 ledger entry missing a required field
    E11 inline A-xxx reference with no ledger entry
    E12 secret-looking pattern (privacy rule 2)
    W01 ledger entry never referenced outside the ledger
    W02 hedge phrase stated as load-bearing prose
    W03 artifact older than the pack freshness window
    W04 a repo_head stamp (MANIFEST or any artifact, e.g. survey.md) is behind repo
        HEAD (staleness trigger 2); tolerated when only the pack itself moved since
        the stamp (restamp chicken-and-egg); message names the file and full hashes
    W05 broken assumption but a used_in artifact is not stale/blocked
    W06 inline D-xxx reference not found in decisions.md
    W07 touches overlap between concurrently-active work orders (parallel-work.md);
        prefix heuristic — non-prefix glob collisions (e.g. **/config.json) are NOT caught
    W08 plan artifact carries zero epistemic labels
    W09 MANIFEST glossary term never used outside the glossary
    W10 acceptance criterion with no checkable shape (no command/observable)
    W11 pack loom_version behind current Loom — run loom_migrate
    W12 tier M+ intake has no '## Silence sweep' section (loom/intake/intake.md §4)
    W13 heft: a WO's measured bulk disagrees with the size law (criteria > 8,
        touches > 5 globs, body > 150 lines, or ' and ' in the title — template law:
        S <1h · M one sitting · L → split). Lexical heuristic; the message asks,
        it doesn't accuse.
    W14 hedged criterion: an acceptance criterion shares a term with a hedge line in
        the same WO's epistemic notes ([SPECULATION]/[UNKNOWN]/"verify") — the fact the
        criterion rests on is not verified yet; verify before G1, not during execution.
        Lexical overlap heuristic (>=5-char tokens), conservative on purpose.
    --home mode (user home, loom/core/user-memory.md):
    W20 home/file missing or unshaped (informational)
    W21 outbox line looks un-anonymized (path/host-shaped token)
    W22 profile/calibration entry lacks date/provenance
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import loom_survey
import loom_gate
import loom_memory
import loom_domain
import loom_domain_bundle
import loom_domain_contract
import loom_lifecycle
import loom_planning_intelligence

ENUMS = {
    "manifest.status": {"draft", "gated", "active", "stale", "maintenance", "archived"},
    "manifest.tier": {"S", "M", "L", "XL"},
    "artifact.status": {"draft", "gated", "stale", "superseded", "frozen"},
    "domain-discovery.status": {"draft", "verified"},
    "wo.status": {"draft", "ready", "blocked", "in-progress", "done", "cancelled"},
    "wo.routing": {"frontier-reasoning", "strong-coding", "fast-cheap", "specialist", "human"},
    "wo.size": {"S", "M"},
    "assumption.status": {"open", "verified", "broken", "retired"},
}

REQUIRED_KEYS = {
    "manifest": ["artifact", "project", "tier", "status", "last_verified", "loom_version",
                 "domain_id", "domain_coverage"],
    "artifact": ["artifact", "status", "last_verified"],
    "wo": ["id", "title", "status", "depends_on", "blocks", "routing",
           "size", "touches", "last_verified"],
}

LEDGER_FIELDS = ["status", "basis", "risk_if_wrong", "verify_by", "used_in"]

HEDGES = ["should work", "probably fine", "should be fine", "probably works",
          "as everyone knows", "will obviously"]

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+.]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9_\-.=]{20,}"),
]
PLACEHOLDER_RE = re.compile(
    r"<[A-Z][A-Z0-9_ -]{0,63}>|\{\{[^{}\r\n]{1,80}\}\}|"
    r"\$\{[A-Z_][A-Z0-9_]*\}|\bxxx+\b", re.IGNORECASE)

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
A_REF_RE = re.compile(r"\bA-\d{3,}\b")
D_REF_RE = re.compile(r"\bD-\d{3,}\b")
WO_ID_RE = re.compile(r"^WO-\d{3,}$")
LABEL_RE = re.compile(r"\[(FACT|ASSUMPTION|SPECULATION|UNKNOWN|HUMAN-DECISION)\b")
CRITERION_OK_RE = re.compile(r"`|→|->|\d|(?i:\b(exit|green|pass|passes|output|diff|curl|http"
                             r"|screenshot|transcript|observ|returns|renders|matches)\b)")
FALLBACK_VERSION = "0.4.0"
SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

# W13 heft thresholds — generous on purpose: only real smells fire (plan-sharpening.md)
HEFT_MAX_CRITERIA = 8
HEFT_MAX_TOUCHES = 5
HEFT_MAX_BODY_LINES = 150

# W14 — hedge markers in epistemic notes that make a shared-term criterion suspect
HEDGE_MARK_RE = re.compile(r"\[(SPECULATION|UNKNOWN)\b|(?i:\bverify\b)|(?i:\bunverified\b)")
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z_-]{4,}")
W14_STOPWORDS = {"before", "after", "which", "there", "their", "these", "those",
                 "should", "would", "could", "against", "within", "while", "where",
                 "verify", "unverified", "check", "still", "holds", "notes", "under",
                 "relying", "because", "criteria", "criterion", "acceptance",
                 "speculation", "unknown", "assumption", "ledger", "expected"}

MATRIX_ARTIFACTS = {
    "intake.md", "survey.md", "product.md", "architecture.md", "uiux.md",
    "contracts.md", "testing.md", "release-rollback.md", "security.md",
    "maintenance.md", "scaffold.md", "domain-discovery.md", "work orders", "routing",
    "project instructions",
}


def artifact_matrix_key(value):
    low = re.sub(r"\s+", " ", str(value).strip().lower())
    file_match = re.search(r"[\w./-]+\.md", low)
    if file_match:
        return Path(file_match.group(0)).name
    if low.startswith("work order"):
        return "work orders"
    if low.startswith("routing"):
        return "routing"
    if low.startswith("project instruction"):
        return "project instructions"
    return low


def current_version():
    """Current Loom version comes from the single machine-readable VERSION file."""
    root = Path(__file__).resolve().parent.parent
    version_file = root / "VERSION"
    if version_file.is_file():
        value = version_file.read_text(encoding="utf-8", errors="strict").strip()
        if re.fullmatch(r"\d+\.\d+\.\d+", value):
            return value
    ch = root / "CHANGELOG.md"
    if ch.is_file():
        m = re.search(r"^##\s+(\d+\.\d+\.\d+)", ch.read_text(encoding="utf-8", errors="replace"), re.M)
        if m:
            return m.group(1)
    return FALLBACK_VERSION


def vtuple(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0, 0, 0)


def glob_root(g):
    """Literal path prefix of a glob (portion before the first wildcard)."""
    return str(g).replace("\\", "/").split("*")[0].split("?")[0].rstrip("/")


def touches_overlap(a, b):
    """Heuristic: two path globs collide if one's literal root prefixes the other's."""
    ra, rb = glob_root(a), glob_root(b)
    if ra == "" or rb == "":
        return True  # bare wildcard touches everything
    return ra == rb or ra.startswith(rb + "/") or rb.startswith(ra + "/")


class Report:
    def __init__(self):
        self.findings = []  # (sev, code, path, line, msg)

    def add(self, sev, code, path, line, msg):
        self.findings.append({"sev": sev, "code": code, "path": str(path),
                              "line": line, "msg": msg})

    @property
    def errors(self):
        return [f for f in self.findings if f["sev"] == "ERROR"]


def parse_frontmatter(text):
    """Parse flat 'key: value' YAML-subset frontmatter. Returns (dict|None, end_line)."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, 0
    fm = {}
    for i, raw in enumerate(lines[1:], start=2):
        s = raw.strip()
        if s == "---":
            return fm, i
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", s)
        if not m:
            continue  # tolerate nested/unknown lines
        key, val = m.group(1), m.group(2)
        val = re.split(r"\s+#", val, maxsplit=1)[0].strip()  # strip inline comment
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            fm[key] = [v.strip().strip("'\"") for v in inner.split(",") if v.strip()] if inner else []
        else:
            scalar = val.strip("'\"")
            if re.fullmatch(r"-?\d+", scalar):
                fm[key] = int(scalar)
            elif re.fullmatch(r"-?\d+\.\d+", scalar):
                fm[key] = float(scalar)
            elif scalar.lower() in {"true", "false"}:
                fm[key] = scalar.lower() == "true"
            else:
                fm[key] = scalar
    return None, 0  # unterminated


def validate_schema(rep, path, value, schema_name):
    """Validate the JSON-Schema subset Loom ships, without a dependency."""
    schema_path = SCHEMA_DIR / schema_name
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        rep.add("ERROR", "E18", path, 1,
                f"cannot load governing schema {schema_name}: {exc}")
        return

    documents = {schema_name: schema}

    def resolve_reference(reference, document):
        if not isinstance(reference, str) or not reference:
            raise ValueError("schema reference is invalid")
        filename, separator, fragment = reference.partition("#")
        target_document = document
        if filename:
            if Path(filename).name != filename or not filename.endswith(".json"):
                raise ValueError("schema reference escapes the schema directory")
            if filename not in documents:
                documents[filename] = json.loads(
                    (SCHEMA_DIR / filename).read_text(encoding="utf-8"))
            target_document = documents[filename]
        target = target_document
        if separator and fragment:
            if not fragment.startswith("/"):
                raise ValueError("schema reference fragment is invalid")
            for token in fragment[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or token not in target:
                    raise ValueError("schema reference fragment is unavailable")
                target = target[token]
        return target, target_document

    def collect(instance, rule, location, document=None, depth=0):
        errors = []
        document = schema if document is None else document
        if depth > 64:
            return [f"{location} schema reference depth exceeded"]
        if not isinstance(rule, dict):
            return errors if rule is not False else [f"{location} is not allowed"]
        if "$ref" in rule:
            try:
                target, target_document = resolve_reference(rule["$ref"], document)
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                return [f"{location} schema reference failed: {exc}"]
            errors.extend(collect(
                instance, target, location, target_document, depth + 1))
            rule = {key: item for key, item in rule.items() if key != "$ref"}

        for branch in rule.get("allOf", []):
            errors.extend(collect(instance, branch, location, document, depth + 1))
        if "oneOf" in rule:
            matches = sum(not collect(instance, branch, location, document, depth + 1)
                          for branch in rule["oneOf"])
            if matches != 1:
                errors.append(f"{location} must match exactly one oneOf branch")
        if "anyOf" in rule and not any(
                not collect(instance, branch, location, document, depth + 1)
                for branch in rule["anyOf"]):
            errors.append(f"{location} must match at least one anyOf branch")
        if "if" in rule:
            condition_matches = not collect(
                instance, rule["if"], location, document, depth + 1)
            selected = rule.get("then") if condition_matches else rule.get("else")
            if selected is not None:
                errors.extend(collect(
                    instance, selected, location, document, depth + 1))

        expected = rule.get("type")
        expected_types = expected if isinstance(expected, list) else [expected]
        type_checks = {
            "object": lambda item: isinstance(item, dict),
            "array": lambda item: isinstance(item, list),
            "string": lambda item: isinstance(item, str),
            "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
            "number": lambda item: isinstance(item, (int, float))
            and not isinstance(item, bool),
            "boolean": lambda item: isinstance(item, bool),
            "null": lambda item: item is None,
        }
        if expected and not any(
                type_checks.get(kind, lambda _item: False)(instance)
                for kind in expected_types):
            errors.append(f"{location} must be {expected}")
            return errors
        if "const" in rule and instance != rule["const"]:
            errors.append(f"{location} must equal {rule['const']!r}")
        if "enum" in rule and instance not in rule["enum"]:
            errors.append(f"{location} not in {rule['enum']}")

        if isinstance(instance, str):
            if rule.get("pattern") and not re.search(rule["pattern"], instance):
                errors.append(f"{location} does not match {rule['pattern']}")
            if "minLength" in rule and len(instance) < rule["minLength"]:
                errors.append(f"{location} is too short")
            if "maxLength" in rule and len(instance) > rule["maxLength"]:
                errors.append(
                    f"{location} exceeds {rule['maxLength']} characters")
            if rule.get("format") == "date":
                try:
                    dt.date.fromisoformat(instance)
                except ValueError:
                    errors.append(f"{location} is not an ISO date")
            elif rule.get("format") == "date-time":
                try:
                    instant = dt.datetime.fromisoformat(
                        instance.replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"{location} is not an ISO date-time")
                else:
                    if instant.tzinfo is None:
                        errors.append(f"{location} date-time lacks a timezone")
            elif rule.get("format") == "uuid" and not re.fullmatch(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", instance):
                errors.append(f"{location} is not a UUID")

        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in rule and instance < rule["minimum"]:
                errors.append(f"{location} is below {rule['minimum']}")
            if "maximum" in rule and instance > rule["maximum"]:
                errors.append(f"{location} exceeds {rule['maximum']}")

        if isinstance(instance, list):
            if "minItems" in rule and len(instance) < rule["minItems"]:
                errors.append(f"{location} has too few items")
            if "maxItems" in rule and len(instance) > rule["maxItems"]:
                errors.append(f"{location} has too many items")
            if rule.get("uniqueItems"):
                encoded = [json.dumps(item, sort_keys=True, ensure_ascii=False)
                           for item in instance]
                if len(encoded) != len(set(encoded)):
                    errors.append(f"{location} contains duplicate items")
            prefix = rule.get("prefixItems", [])
            for index, child in enumerate(prefix[:len(instance)]):
                errors.extend(collect(
                    instance[index], child, f"{location}[{index}]", document, depth + 1))
            remaining = instance[len(prefix):]
            item_rule = rule.get("items", {})
            if item_rule is False and remaining:
                errors.append(f"{location} has disallowed additional items")
            elif isinstance(item_rule, dict):
                for index, item in enumerate(remaining, start=len(prefix)):
                    errors.extend(collect(
                        item, item_rule, f"{location}[{index}]", document, depth + 1))

        if isinstance(instance, dict):
            if "minProperties" in rule and len(instance) < rule["minProperties"]:
                errors.append(f"{location} has too few properties")
            if "maxProperties" in rule and len(instance) > rule["maxProperties"]:
                errors.append(f"{location} has too many properties")
            for required in rule.get("required", []):
                if required not in instance:
                    errors.append(f"{location} missing '{required}'")
            properties = rule.get("properties", {})
            pattern_properties = rule.get("patternProperties", {})
            matched = set(properties) & set(instance)
            for key, child in properties.items():
                if key in instance:
                    errors.extend(collect(
                        instance[key], child, f"{location}.{key}", document, depth + 1))
            for pattern, child in pattern_properties.items():
                for key in instance:
                    if re.search(pattern, key):
                        matched.add(key)
                        errors.extend(collect(
                            instance[key], child, f"{location}.{key}", document, depth + 1))
            unknown = set(instance) - matched
            additional = rule.get("additionalProperties", {})
            if additional is False:
                for key in sorted(unknown):
                    errors.append(f"{location} has unknown key '{key}'")
            elif isinstance(additional, dict):
                for key in sorted(unknown):
                    errors.extend(collect(
                        instance[key], additional, f"{location}.{key}", document, depth + 1))
        return errors

    for message in collect(value, schema, "$"):
        rep.add("ERROR", "E18", path, 1, f"{schema_name} {message}")


def parse_markdown_table(text, heading):
    """Return normalized row dicts for the first table under a named heading."""
    section = re.search(
        rf"(?ms)^##\s+{re.escape(heading)}\s*$\n(.*?)(?=^##\s|\Z)", text)
    if not section:
        return []
    table_lines = [line.strip() for line in section.group(1).splitlines()
                   if line.strip().startswith("|")]
    if len(table_lines) < 2:
        return []

    def cells(line):
        return [cell.strip() for cell in line.strip().strip("|").split("|")]

    headers = [cell.lower() for cell in cells(table_lines[0])]
    rows = []
    for line in table_lines[1:]:
        values = cells(line)
        if values and all(re.fullmatch(r":?-{3,}:?", value) for value in values):
            continue
        if len(values) != len(headers):
            continue
        rows.append(dict(zip(headers, values)))
    return rows


def check_required(rep, path, fm, kind):
    for key in REQUIRED_KEYS[kind]:
        if key not in fm or fm[key] in ("", None):
            rep.add("ERROR", "E03", path, 1, f"missing required frontmatter key '{key}'")


def check_enum(rep, path, fm, key, enum_name):
    val = fm.get(key)
    if val is not None and val != "" and val not in ENUMS[enum_name]:
        rep.add("ERROR", "E04", path, 1,
                f"'{key}: {val}' not in {sorted(ENUMS[enum_name])}")


def check_date(rep, path, fm, key="last_verified"):
    val = fm.get(key)
    if val and not DATE_RE.match(str(val)):
        rep.add("ERROR", "E05", path, 1, f"'{key}: {val}' is not YYYY-MM-DD")
        return None
    if val:
        try:
            return dt.date.fromisoformat(val)
        except ValueError:
            rep.add("ERROR", "E05", path, 1, f"'{key}: {val}' is not a real date")
    return None


def scan_text(rep, path, text, skip_secret=False, skip_hedge=False):
    """Line scans that apply to every pack file: hedges, secrets."""
    for n, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        for h in ([] if skip_hedge else HEDGES):
            if h in low:
                rep.add("WARN", "W02", path, n, f"hedge phrase '{h}' — label it or evidence it")
        if not skip_secret:
            candidate = PLACEHOLDER_RE.sub("<SAFE_PLACEHOLDER>", line)
            for pat in SECRET_PATTERNS:
                if pat.search(candidate):
                    rep.add("ERROR", "E12", path, n,
                            "secret-looking content (privacy rule 2) — use <PLACEHOLDER>")


def parse_ledger(rep, path, text):
    """Return {A-id: {fields..., 'line': n}} from assumptions.md."""
    entries = {}
    current, cur_line = None, 0
    for n, line in enumerate(text.splitlines(), start=1):
        m = re.match(r"^##\s+(A-\d{3,})\s*:\s*(.+)$", line)
        if m:
            aid = m.group(1)
            if aid in entries:
                rep.add("ERROR", "E07", path, n, f"duplicate ledger id {aid}")
            current, cur_line = aid, n
            entries.setdefault(aid, {
                "line": n, "id": aid, "statement": m.group(2).strip()})
            continue
        if current:
            fm = re.match(r"^-\s*([a-z_]+)\s*:\s*(.*)$", line.strip())
            if fm:
                value = re.split(r"\s+#", fm.group(2), maxsplit=1)[0].strip()
                entries[current][fm.group(1)] = value
    for aid, e in entries.items():
        for field in LEDGER_FIELDS:
            if field not in e or not e[field]:
                rep.add("ERROR", "E10", path, e["line"], f"{aid} missing field '{field}'")
        st = e.get("status", "").split()[0] if e.get("status") else ""
        if st and st not in ENUMS["assumption.status"]:
            rep.add("ERROR", "E04", path, e["line"],
                    f"{aid} status '{st}' not in {sorted(ENUMS['assumption.status'])}")
        validate_schema(rep, path, {key: value for key, value in e.items()
                                    if key != "line"}, "assumption.schema.json")
    return entries


def check_wo_graph(rep, wos):
    """wos: {id: {'deps': [...], 'path': p}}. E08 unknown refs, E09 cycles."""
    for wid, w in wos.items():
        for dep in w["deps"]:
            if dep.startswith("WO-") and dep not in wos:
                rep.add("ERROR", "E08", w["path"], 1, f"{wid} depends_on unknown {dep}")
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {wid: WHITE for wid in wos}

    def dfs(u, stack):
        color[u] = GRAY
        for v in wos[u]["deps"]:
            if v not in wos or not v.startswith("WO-"):
                continue
            if color[v] == GRAY:
                cyc = " -> ".join(stack + [u, v])
                rep.add("ERROR", "E09", wos[u]["path"], 1, f"dependency cycle: {cyc}")
                return
            if color[v] == WHITE:
                dfs(v, stack + [u])
        color[u] = BLACK

    for wid in wos:
        if color[wid] == WHITE:
            dfs(wid, [])


def heads_match(a, b):
    """Commit-hash equality tolerant of short (>=7 char) forms on either side."""
    a, b = str(a).strip(), str(b).strip()
    if len(a) < 7 or len(b) < 7:
        return a == b
    return a.startswith(b) or b.startswith(a)


def git_head(repo):
    try:
        out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=15)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def pack_only_drift(repo, stamp, pack_rel):
    """True when everything committed since `stamp` lies inside the pack itself —
    the chicken-and-egg case: the commit that restamps repo_head always advances HEAD
    past its own stamp. Such drift is not staleness. False on any doubt."""
    if not pack_rel:
        return False
    try:
        out = subprocess.run(["git", "-C", str(repo), "diff", "--name-only",
                              f"{stamp}..HEAD"],
                             capture_output=True, text=True, timeout=15)
        if out.returncode != 0:
            return False  # unknown stamp etc. — keep the warning
        prefix = pack_rel.rstrip("/") + "/"
        paths = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        return bool(paths) and all(x.startswith(prefix) for x in paths)
    except (OSError, subprocess.TimeoutExpired):
        return False


HOME_FILES = ["profile.md", "calibration.md", "projects.md", "feedback-outbox.md"]
PATHY_RE = re.compile(
    "[A-Za-z]:" + chr(92) * 2
    + r"|/(home|Users)/|https?://|github\.com/|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
    re.IGNORECASE)
PROJECT_SHAPED_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9]+(?:-[A-Z][A-Za-z0-9]+)+\b|"
    r"\([^)]*\btier\s+[SMLX]+\b[^)]*\)")
PROFILE_LINE_RE = re.compile(r"^-\s*([a-z][\w-]*)\s*:\s*(.*?)\s*(?:#\s*(.*))?$")
PROFILE_PROVENANCE_RE = re.compile(
    r"^set\s+(\d{4}-\d{2}-\d{2})\s*,\s*source:\s*"
    r"(stated|inferred|observed(?:\s*\(\d+\s+projects?\))?)$")
MULTI_PROFILE_KEYS = {"hard_stop"}


def lint_home(home_path):
    """User-home checks (loom/core/user-memory.md): shape, provenance, secrets,
    outbox anonymization sniff. Warnings guide; only secrets are errors."""
    rep = Report()
    home = Path(home_path)
    if not home.is_dir():
        rep.add("WARN", "W20", home, 1,
                "user home does not exist yet — created on first retro or /loom profile set")
        return rep
    instances = home / "instances"
    quarantine_digests = {}
    if instances.is_dir():
        for directory in sorted(path for path in instances.iterdir() if path.is_dir()):
            try:
                findings = loom_memory.validate_instance(home, directory.name)
            except loom_memory.MemoryError as exc:
                rep.add("ERROR", "E21", directory, 1, str(exc))
                continue
            for message in findings:
                rep.add("ERROR", "E21", directory, 1, message)
        try:
            quarantine_digests = loom_memory.legacy_quarantine_digests(home)
        except loom_memory.MemoryError as exc:
            rep.add("ERROR", "E21", instances, 1, str(exc))
    for name in HOME_FILES:
        f = home / name
        if not f.is_file():
            if instances.is_dir():
                continue  # typed per-instance store supersedes legacy flat Markdown
            rep.add("WARN", "W20", f, 1, f"{name} missing — created on first use")
            continue
        raw = f.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        if instances.is_dir():
            digest = hashlib.sha256(raw).hexdigest()
            if digest not in quarantine_digests.get(name, set()):
                rep.add(
                    "WARN", "W20", f, 1,
                    "inactive legacy file is new or changed since quarantine; it remains "
                    "unloaded — run loom_memory migrate-legacy to preserve the new evidence")
            scan_text(rep, f, text, skip_hedge=True)
            continue
        fm, _ = parse_frontmatter(text)
        if fm is None:
            rep.add("WARN", "W20", f, 1, "frontmatter missing or unterminated")
        elif fm.get("loom_version") and vtuple(fm["loom_version"]) < vtuple(current_version()):
            rep.add("WARN", "W11", f, 1,
                    f"home file is Loom {fm['loom_version']}, current is {current_version()} "
                    "— migrate legacy memory before loading it")
        scan_text(rep, f, text, skip_hedge=True)  # secrets always; hedge scan is pack-prose only
        if name in ("profile.md", "calibration.md"):
            seen_keys = {}
            for n, line in enumerate(text.splitlines(), start=1):
                s = line.strip()
                if s.startswith("- ") and ":" in s and "<" not in s:
                    if name == "profile.md":
                        match = PROFILE_LINE_RE.match(s)
                        if not match:
                            rep.add("WARN", "W22", f, n,
                                    "profile entry is not a keyed preference")
                            continue
                        key, metadata = match.group(1), match.group(3) or ""
                        if key in seen_keys and key not in MULTI_PROFILE_KEYS:
                            rep.add("ERROR", "E21", f, n,
                                    f"duplicate active profile key '{key}' "
                                    f"(first at line {seen_keys[key]})")
                        seen_keys[key] = n
                        provenance = PROFILE_PROVENANCE_RE.match(metadata)
                        if not provenance:
                            code = "E21" if "source:" in metadata else "W22"
                            sev = "ERROR" if code == "E21" else "WARN"
                            rep.add(sev, code, f, n,
                                    "profile entry needs a valid set date and provenance "
                                    "(stated, observed (n projects), or inferred)")
                        else:
                            entry_date = dt.date.fromisoformat(provenance.group(1))
                            if (dt.date.today() - entry_date).days > 365:
                                rep.add("WARN", "W24", f, n,
                                        f"profile preference '{key}' is over 365 days old; "
                                        "reconfirm or forget it")
                    if name == "calibration.md" and not re.match(r"^- \d{4}-\d{2}-\d{2}", s):
                        rep.add("WARN", "W22", f, n, "calibration entry lacks a leading date")
        if name == "feedback-outbox.md":
            for n, line in enumerate(text.splitlines(), start=1):
                if (PATHY_RE.search(line) or PROJECT_SHAPED_RE.search(line)) \
                        and not line.strip().startswith("<!--"):
                    rep.add("WARN", "W21", f, n,
                            "legacy outbox line contains project/path/host-shaped data — quarantine "
                            "before /loom contribute (user-memory rules)")
    return rep


def lint(pack_path, repo_path=None, strict_staleness=False,
         enforce_lifecycle=True, check_repo_state=True,
         check_gate_requirements=True):
    rep = Report()
    pack = Path(pack_path)
    if not pack.is_dir():
        print(f"loom_lint: pack path not found: {pack}", file=sys.stderr)
        sys.exit(2)

    manifest = pack / "MANIFEST.md"
    window = 14
    today = dt.date.today()
    manifest_text = ""
    corpus_parts = []  # every pack text EXCEPT the manifest, for glossary usage check

    def add_staleness(warn_code, path, message):
        if strict_staleness:
            rep.add("ERROR", "E16", path, 1,
                    f"{warn_code}: {message} — strict staleness blocks execution")
        else:
            rep.add("WARN", warn_code, path, 1, message)

    if not manifest.is_file():
        rep.add("ERROR", "E01", manifest, 1, "MANIFEST.md missing from pack")
        mfm = {}
    else:
        text = manifest_text = manifest.read_text(encoding="utf-8", errors="replace")
        mfm, _ = parse_frontmatter(text)
        if mfm is None:
            rep.add("ERROR", "E02", manifest, 1, "frontmatter missing or unterminated")
            mfm = {}
        else:
            check_required(rep, manifest, mfm, "manifest")
            validate_schema(rep, manifest, mfm, "manifest.schema.json")
            check_enum(rep, manifest, mfm, "status", "manifest.status")
            check_enum(rep, manifest, mfm, "tier", "manifest.tier")
            manifest_date = check_date(rep, manifest, mfm)
            if str(mfm.get("freshness_window_days", "")).isdigit():
                window = int(mfm["freshness_window_days"])
            if manifest_date and (today - manifest_date).days > window:
                add_staleness(
                    "W03", manifest,
                    f"last_verified {manifest_date} exceeds freshness window "
                    f"({window}d) — recheck before use")
            if mfm.get("loom_version") and vtuple(mfm["loom_version"]) < vtuple(current_version()):
                rep.add("WARN", "W11", manifest, 1,
                        f"pack is Loom {mfm['loom_version']}, current is {current_version()} — "
                        f"run tools/loom_migrate.py")
        scan_text(rep, manifest, text)

    execution_mode = str(mfm.get("execution_mode", "planned") or "planned")
    historical = execution_mode == "historical"
    if execution_mode not in {"planned", "historical", "build-first"}:
        rep.add("ERROR", "E15", manifest, 1,
                "execution_mode must be planned, historical, or build-first")
    if historical and mfm.get("status") not in {"maintenance", "archived"}:
        rep.add("ERROR", "E15", manifest, 1,
                "historical packs must have status maintenance or archived")
    domain_id = str(mfm.get("domain_id", "") or "")
    domain_ids = mfm.get("domain_ids", [])
    domain_coverage = str(mfm.get("domain_coverage", "") or "")
    if domain_id and not loom_memory.ID_RE.fullmatch(domain_id):
        rep.add("ERROR", "E22", manifest, 1,
                "domain_id must be a safe lower-case local identifier")
    if domain_coverage and domain_coverage not in {"adapter", "unknown", "verified"}:
        rep.add("ERROR", "E22", manifest, 1,
                "domain_coverage must be adapter, unknown, or verified")
    if mfm and (not isinstance(domain_ids, list) or not domain_ids \
            or any(not isinstance(value, str)
                   or not loom_memory.ID_RE.fullmatch(value) for value in domain_ids) \
            or len(domain_ids) != len(set(domain_ids))):
        rep.add("ERROR", "E22", manifest, 1,
                "domain_ids must be a non-empty unique list of safe domain identifiers")
        domain_ids = [domain_id] if domain_id else []
    if mfm and domain_id and domain_id not in domain_ids:
        rep.add("ERROR", "E22", manifest, 1,
                "primary domain_id must be included in domain_ids")
    if domain_coverage == "adapter" \
            and any(value not in loom_domain.CATALOG for value in domain_ids):
        rep.add("ERROR", "E22", manifest, 1,
                "domain_ids contains a domain with no shipped adapter; "
                "coverage cannot be adapter")
    if not historical and domain_coverage == "unknown" \
            and mfm.get("status") in {"gated", "active", "maintenance"}:
        rep.add("ERROR", "E22", manifest, 1,
                "G1 is blocked while domain_coverage is unknown")
    if repo_path:
        config_path = Path(repo_path).resolve() / "loom.config.json"
        if config_path.is_file():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                rep.add("ERROR", "E18", config_path, 1,
                        f"loom.config.json is unreadable/invalid: {exc}")
            else:
                validate_schema(rep, config_path, config, "loom-config.schema.json")
                if domain_id and config.get("domain_id") != domain_id:
                    rep.add("ERROR", "E22", config_path, 1,
                            "config domain_id must match MANIFEST domain_id")
                if config.get("domain_ids") is not None \
                        and config.get("domain_ids") != domain_ids:
                    rep.add("ERROR", "E22", config_path, 1,
                            "config domain_ids must exactly match MANIFEST domain_ids")
    lifecycle_data = {}
    if mfm and execution_mode == "planned" and enforce_lifecycle:
        lifecycle_findings = loom_gate.verify(
            pack, repo_path,
            require_authorized=mfm.get("status") in {"active", "maintenance"})
        for finding in lifecycle_findings:
            rep.add("ERROR", "E17", pack / loom_gate.LIFECYCLE_FILE, 1, finding)
        lifecycle_path = pack / loom_gate.LIFECYCLE_FILE
        if lifecycle_path.is_file():
            try:
                lifecycle_data = json.loads(lifecycle_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
            else:
                validate_schema(
                    rep, lifecycle_path, lifecycle_data, "lifecycle.schema.json")
                if lifecycle_data.get("mode") != execution_mode:
                    rep.add("ERROR", "E17", lifecycle_path, 1,
                            "lifecycle mode does not match MANIFEST execution_mode")
    elif mfm and execution_mode == "build-first":
        rep.add("WARN", "W16", manifest, 1,
                "build-first pack is operational history only and is ineligible for "
                "plan-first causal credit")
    if mfm.get("tier") in {"M", "L", "XL"} and not historical:
        for required in ("intake.md", "assumptions.md", "decisions.md"):
            path = pack / required
            if not path.is_file():
                rep.add("ERROR", "E13", path, 1,
                        f"tier {mfm.get('tier')} planned pack requires {required}")

    artifact_rows = parse_markdown_table(manifest_text, "Artifacts")
    artifact_decisions = {
        artifact_matrix_key(row.get("artifact", "")):
        row.get("action", "").strip().lower()
        for row in artifact_rows
    }
    if mfm and not artifact_rows:
        rep.add("ERROR", "E15", manifest, 1,
                "MANIFEST must contain a parseable ## Artifacts decision table")
    for row in artifact_rows:
        artifact = row.get("artifact", "").strip()
        decision = row.get("action", "").strip().lower()
        consumer = row.get("consumer", "").strip()
        downstream_decision = row.get("decision", "").strip()
        reason = row.get("why (one line)", "").strip()
        if decision not in {"produce", "skip"}:
            rep.add("ERROR", "E15", manifest, 1,
                    f"artifact '{artifact}' has invalid decision '{decision}'")
            continue
        if not reason or reason.lower() in {"—", "-", "not needed", "n/a"}:
            rep.add("ERROR", "E15", manifest, 1,
                    f"artifact '{artifact}' needs a concrete one-line reason")
        if decision == "produce" and (
                not consumer or consumer.lower() in {"—", "-", "n/a", "none"}):
            rep.add("ERROR", "E15", manifest, 1,
                    f"produced artifact '{artifact}' must name its consumer")
        if decision == "produce" and (
                not downstream_decision
                or downstream_decision.lower() in {"—", "-", "n/a", "none"}):
            rep.add("ERROR", "E15", manifest, 1,
                    f"produced artifact '{artifact}' must name the decision it serves")
        if decision == "produce" \
                and artifact_matrix_key(artifact) not in {"work orders", "routing"}:
            match = re.search(r"[\w./-]+\.md", artifact)
            if not match:
                rep.add("ERROR", "E15", manifest, 1,
                        f"produced artifact '{artifact}' does not name a .md file")
            elif not (pack / match.group(0)).is_file():
                rep.add("ERROR", "E15", manifest, 1,
                        f"declared produced artifact '{match.group(0)}' is missing")
    if artifact_rows:
        accounted = {artifact_matrix_key(row.get("artifact", ""))
                     for row in artifact_rows}
        for missing in sorted(MATRIX_ARTIFACTS - accounted):
            rep.add("ERROR", "E15", manifest, 1,
                    f"artifact matrix row '{missing}' has no produce/skip decision")
    if artifact_decisions.get("routing") == "produce":
        routing_match = re.search(
            r"(?ms)^## Routing snapshot\s*\n(.*?)(?=^##\s|\Z)", manifest_text)
        routing_body = (routing_match.group(1).strip() if routing_match else "")
        routing_body = re.sub(r"<!--.*?-->", "", routing_body, flags=re.S).strip()
        has_route = re.search(
            r"\b(frontier-reasoning|strong-coding|fast-cheap|specialist|human)\b",
            routing_body)
        has_placeholder = re.search(r"<[^>]+>|\b(?:pending|tbd|todo)\b", routing_body, re.I)
        if not routing_body or not has_route or has_placeholder:
            rep.add("ERROR", "E15", manifest, 1,
                    "produced routing requires a substantive ## Routing snapshot")

    if mfm.get("tier") in {"M", "L", "XL"} and execution_mode == "planned" \
            and not historical:
        release_path = pack / loom_lifecycle.RELEASE_FILE
        try:
            release = loom_lifecycle.validate_release_policy(pack)
        except loom_lifecycle.LifecycleError as exc:
            rep.add("ERROR", "E24", release_path, 1, str(exc))
        else:
            validate_schema(
                rep, release_path, release, "release-exposure.schema.json")
            release_decision = artifact_decisions.get("release-rollback.md")
            if release["level"] in {"staged", "controlled"} \
                    and release_decision != "produce":
                rep.add("ERROR", "E24", manifest, 1,
                        f"{release['level']} exposure requires produced "
                        "release-rollback.md")

    discovery = pack / "domain-discovery.md"
    discovery_bundle = pack / "domain-discovery.json"
    discovery_decision = artifact_decisions.get("domain-discovery.md")
    if domain_coverage == "unknown" and discovery_decision != "produce":
        rep.add("ERROR", "E22", manifest, 1,
                "unknown domain coverage requires produced domain-discovery.md")
    if domain_coverage == "verified" and not historical \
            and discovery_decision != "produce":
        rep.add("ERROR", "E22", manifest, 1,
                "verified custom-domain coverage requires produced domain-discovery.md")
    validated_bundle = None
    if domain_coverage == "verified" and not historical:
        try:
            validated_bundle = json.loads(discovery_bundle.read_text(encoding="utf-8"))
            loom_domain_bundle.validate(validated_bundle)
        except (OSError, UnicodeError, json.JSONDecodeError,
                loom_domain_bundle.DomainBundleError) as exc:
            rep.add("ERROR", "E25", discovery_bundle, 1,
                    f"verified domain coverage requires a valid machine bundle: {exc}")
        else:
            if validated_bundle["route"]["active_task_domains"] != domain_ids:
                rep.add("ERROR", "E25", discovery_bundle, 1,
                        "machine bundle active domains must match MANIFEST domain_ids")
    if discovery_decision == "produce" and discovery.is_file():
        discovery_text = discovery.read_text(encoding="utf-8", errors="replace")
        dfm, _ = parse_frontmatter(discovery_text)
        if not dfm or dfm.get("artifact") != "domain-discovery" \
                or str(dfm.get("domain_id", "")) != domain_id:
            rep.add("ERROR", "E22", discovery, 1,
                    "domain discovery frontmatter must identify this manifest domain")
        required_sections = {
            "coverage statement", "authoritative sources and qualified reviewers",
            "invariant ledger", "forbidden default transfers",
            "artifact and gate adaptation",
        }
        headings = {match.group(1).strip().lower() for match in
                    re.finditer(r"(?m)^##\s+(.+?)\s*$", discovery_text)}
        for section in sorted(required_sections - headings):
            rep.add("ERROR", "E22", discovery, 1,
                    f"domain discovery missing section '## {section}'")
        invariant_rows = parse_markdown_table(discovery_text, "Invariant ledger")
        if not invariant_rows:
            rep.add("ERROR", "E22", discovery, 1,
                    "domain discovery requires a populated invariant ledger")
        for index, row in enumerate(invariant_rows, 1):
            for column in ("invariant", "evidence", "failure if wrong",
                           "required real medium", "status"):
                if not row.get(column, "").strip():
                    rep.add("ERROR", "E22", discovery, 1,
                            f"domain invariant row {index} lacks '{column}'")
            if domain_coverage == "verified" \
                    and row.get("status", "").lower() != "verified":
                rep.add("ERROR", "E22", discovery, 1,
                        f"verified domain coverage has non-verified invariant row {index}")
        if domain_coverage == "verified" and dfm \
                and dfm.get("status") != "verified":
                rep.add("ERROR", "E22", discovery, 1,
                    "verified domain coverage requires discovery status: verified")
        if validated_bundle is not None:
            projection = {(row.get("invariant id", "").strip(),
                           row.get("canonical digest", "").strip())
                          for row in invariant_rows}
            required_projection = {
                (item["invariant_id"], item["canonical_digest"])
                for item in validated_bundle["invariants"]}
            if not required_projection.issubset(projection):
                rep.add("ERROR", "E25", discovery, 1,
                        "Markdown projection omits a machine invariant ID or digest")

    frontier_rows = parse_markdown_table(manifest_text, "Work order frontier")

    repo_state = None
    head = None
    pack_rel = None
    if repo_path:
        try:
            pack_rel = pack.resolve().relative_to(Path(repo_path).resolve()).as_posix()
        except ValueError:
            pack_rel = None  # pack outside the repo — no tolerance possible
    if strict_staleness and not repo_path:
        add_staleness(
            "W15", manifest,
            "repository path was not supplied, so committed, staged, unstaged, "
            "untracked, or non-Git filesystem state cannot be established")
    if repo_path and check_repo_state:
        try:
            repo_state = loom_survey.repo_state(
                repo_path, exclude_prefixes=((pack_rel,) if pack_rel else ()))
            if repo_state.is_git:
                head = repo_state.head
        except loom_survey.SurveyError as exc:
            add_staleness("W15", manifest, f"repository state is indeterminate: {exc}")
    _drift_cache = {}

    def check_repo_state(path, fm_dict):
        if not repo_state:
            return
        stamped = str(fm_dict.get("repo_state_hash", "") or "")
        if not stamped:
            if strict_staleness or repo_state.dirty:
                add_staleness(
                    "W15", path,
                    f"{path.name}: no repo_state_hash; current state is "
                    f"{repo_state.state_hash} with staged={list(repo_state.staged)}, "
                    f"unstaged={list(repo_state.unstaged)}, "
                    f"untracked={list(repo_state.untracked)}")
            return
        if stamped != repo_state.state_hash:
            add_staleness(
                "W15", path,
                f"{path.name}: repo_state_hash {stamped} differs from current "
                f"{repo_state.state_hash}; staged={list(repo_state.staged)}, "
                f"unstaged={list(repo_state.unstaged)}, "
                f"untracked={list(repo_state.untracked)}")

    def check_repo_head(path, fm_dict):
        """W04 with source-file attribution, full values, and pack-only tolerance."""
        rh = str(fm_dict.get("repo_head", "") or "")
        if not (head and rh):
            return
        try:
            valid = loom_survey.run_git(
                repo_path, "rev-parse", "--verify", f"{rh}^{{commit}}",
                allowed=(0, 128))
        except loom_survey.SurveyError as exc:
            add_staleness("W04", path, f"cannot validate repo_head {rh}: {exc}")
            return
        if valid.returncode != 0:
            add_staleness("W04", path, f"invalid repo_head stamp: {rh}")
            return
        if heads_match(head, rh):
            return
        if rh not in _drift_cache:
            _drift_cache[rh] = pack_only_drift(repo_path, rh, pack_rel)
        if _drift_cache[rh]:
            return  # only the pack moved since the stamp — restamp noise, not staleness
        add_staleness(
            "W04", path,
            f"{path.name}: repo_head stamp {rh} is behind repo HEAD {head} — "
            f"staleness trigger 2 fired; run the recheck (fix the stamp in {path.name})")

    if manifest.is_file() and mfm:
        check_repo_head(manifest, mfm)
        check_repo_state(manifest, mfm)

    # W12 — silence sweep presence (intake §4; tier M and up)
    intake_file = pack / "intake.md"
    if mfm.get("tier") in ("M", "L", "XL") and intake_file.is_file():
        itext = intake_file.read_text(encoding="utf-8", errors="replace")
        if not historical and not re.search(
                r"(?mi)^##\s+Domain adaptation\s*$", itext):
            rep.add("ERROR", "E22", intake_file, 1,
                    "tier M+ intake requires a ## Domain adaptation section")
        if not re.search(r"(?mi)^##+\s*Silence sweep", itext):
            rep.add("WARN", "W12", intake_file, 1,
                    "no '## Silence sweep' section — tier M+ intake interrogates what the "
                    "description did NOT say (loom/intake/intake.md §4); record hits, or "
                    "'swept — no material silences'")

    # Ledger
    ledger_file = pack / "assumptions.md"
    ledger = {}
    if ledger_file.is_file():
        ltext = ledger_file.read_text(encoding="utf-8", errors="replace")
        lfm, _ = parse_frontmatter(ltext)
        if lfm is not None:
            ledger_date = check_date(rep, ledger_file, lfm)
            if ledger_date and (today - ledger_date).days > window:
                add_staleness(
                    "W03", ledger_file,
                    f"last_verified {ledger_date} exceeds freshness window "
                    f"({window}d) — recheck before use")
        ledger = parse_ledger(rep, ledger_file, ltext)
        scan_text(rep, ledger_file, ltext)
        corpus_parts.append(ltext)

    # Decisions
    decisions_file = pack / "decisions.md"
    d_ids = set()
    if decisions_file.is_file():
        dtext = decisions_file.read_text(encoding="utf-8", errors="replace")
        dfm, _ = parse_frontmatter(dtext)
        if dfm is not None:
            decision_date = check_date(rep, decisions_file, dfm)
            if decision_date and (today - decision_date).days > window:
                add_staleness(
                    "W03", decisions_file,
                    f"last_verified {decision_date} exceeds freshness window "
                    f"({window}d) — recheck before use")
        d_ids = set(re.findall(r"^##\s+(D-\d{3,})", dtext, flags=re.M))
        scan_text(rep, decisions_file, dtext)
        corpus_parts.append(dtext)

    # Root artifacts
    a_refs = {}   # A-id -> [(path,line)]
    d_refs = {}
    artifact_status = {}  # filename -> status
    skip_names = {"MANIFEST.md", "assumptions.md", "decisions.md"}
    for f in sorted(pack.glob("*.md")):
        if f.name in skip_names:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        corpus_parts.append(text)
        fm, _ = parse_frontmatter(text)
        if fm is None:
            rep.add("ERROR", "E02", f, 1, "frontmatter missing or unterminated")
        else:
            check_required(rep, f, fm, "artifact")
            status_enum = ("domain-discovery.status"
                           if f.name == "domain-discovery.md"
                           else "artifact.status")
            check_enum(rep, f, fm, "status", status_enum)
            d = check_date(rep, f, fm)
            artifact_status[f.name] = fm.get("status", "")
            st = fm.get("status", "")
            if d and st not in ("superseded",) and (today - d).days > window:
                add_staleness(
                    "W03", f,
                    f"last_verified {d} exceeds freshness window ({window}d) — recheck before use")
        scan_text(rep, f, text)
        if fm is not None:
            check_repo_head(f, fm)
            if f.name == "survey.md":
                check_repo_state(f, fm)
        if fm is not None and fm.get("status") not in ("superseded",) \
                and not LABEL_RE.search(text):
            rep.add("WARN", "W08", f, 1,
                    "no epistemic labels in this artifact — either nothing here is "
                    "load-bearing, or claims are unlabeled (loom/core/epistemics.md)")
        for n, line in enumerate(text.splitlines(), start=1):
            for aid in A_REF_RE.findall(line):
                a_refs.setdefault(aid, []).append((f, n))
            for did in D_REF_RE.findall(line):
                d_refs.setdefault(did, []).append((f, n))

    # Work orders
    wos = {}
    wo_dir = pack / "work-orders"
    if wo_dir.is_dir():
        for f in sorted(wo_dir.glob("*.md")):
            text = f.read_text(encoding="utf-8", errors="replace")
            corpus_parts.append(text)
            fm, _ = parse_frontmatter(text)
            if fm is None:
                rep.add("ERROR", "E02", f, 1, "frontmatter missing or unterminated")
                continue
            check_required(rep, f, fm, "wo")
            validate_schema(rep, f, fm, "work-order.schema.json")
            check_enum(rep, f, fm, "status", "wo.status")
            check_enum(rep, f, fm, "routing", "wo.routing")
            check_enum(rep, f, fm, "size", "wo.size")
            d = check_date(rep, f, fm)
            wid = fm.get("id", "")
            if wid:
                if not WO_ID_RE.match(wid):
                    rep.add("ERROR", "E04", f, 1, f"id '{wid}' does not match WO-nnn")
                if not f.name.startswith(wid):
                    rep.add("ERROR", "E06", f, 1, f"filename does not start with id '{wid}'")
                if wid in wos:
                    rep.add("ERROR", "E07", f, 1, f"duplicate work-order id {wid}")
                deps = fm.get("depends_on", [])
                if isinstance(deps, str):
                    deps = [deps] if deps else []
                for dependency in deps:
                    if str(dependency).startswith("D-") and dependency not in d_ids:
                        rep.add("ERROR", "E14", f, 1,
                                f"{wid} depends_on unknown decision {dependency}")
                touches = fm.get("touches", [])
                if isinstance(touches, str):
                    touches = [touches] if touches else []
                blocks = fm.get("blocks", [])
                if isinstance(blocks, str):
                    blocks = [blocks] if blocks else []
                wos[wid] = {"deps": deps, "path": f, "status": fm.get("status", ""),
                            "routing": fm.get("routing", ""),
                            "touches": touches, "blocks": blocks,
                            "domain_invariants": fm.get("domain_invariants", []),
                            "milestone": fm.get("milestone"),
                            "planning_obligations": fm.get("planning_obligations", []),
                            "stale_ok": fm.get("status") in ("blocked", "done", "cancelled")}
                if d and fm.get("status") in ("ready", "in-progress") and (today - d).days > window:
                    add_staleness(
                        "W03", f,
                        f"{wid} last_verified {d} exceeds freshness window "
                        f"({window}d) — pre-WO check required")
            scan_text(rep, f, text)
            active_status = fm.get("status") in {"ready", "in-progress", "done"}
            required_sections = {
                "intent", "context", "preconditions", "task", "acceptance criteria",
                "out of scope", "escalation triggers", "epistemic notes", "close-out",
            }
            if active_status:
                headings = {match.group(1).strip().lower()
                            for match in re.finditer(r"(?m)^##\s+(.+?)\s*$", text)}
                for missing in sorted(required_sections - headings):
                    rep.add("ERROR", "E19", f, 1,
                            f"{wid or f.name} missing required section '## {missing.title()}'")
                if not touches:
                    rep.add("ERROR", "E19", f, 1,
                            f"{wid or f.name} is active but touches is empty")
            if fm.get("status") == "blocked" and not deps:
                rep.add("ERROR", "E19", f, 1,
                        f"{wid or f.name} is blocked but names no dependency/blocker")
            in_criteria = False
            in_epi = False
            n_criteria = 0
            crit_lines = []      # (line_no, text) for W14
            hedge_tokens = set()  # hedged terms from epistemic notes, for W14
            for n, line in enumerate(text.splitlines(), start=1):
                for aid in A_REF_RE.findall(line):
                    a_refs.setdefault(aid, []).append((f, n))
                for did in D_REF_RE.findall(line):
                    d_refs.setdefault(did, []).append((f, n))
                if line.startswith("## "):
                    low_h = line.lower()
                    in_criteria = "acceptance criteria" in low_h
                    in_epi = "epistemic" in low_h
                elif in_criteria and re.match(r"^\s*-\s*\[[ x]\]", line):
                    n_criteria += 1
                    crit_lines.append((n, line))
                    if not CRITERION_OK_RE.search(re.sub(r"^\s*-\s*\[[ x]\]", "", line)):
                        rep.add("WARN", "W10", f, n,
                                "criterion has no checkable shape (no command, number, or "
                                "observable) — rewrite as something a reviewer can reproduce")
                elif in_epi and HEDGE_MARK_RE.search(line):
                    hedge_tokens |= {t.lower() for t in TOKEN_RE.findall(line)} \
                        - W14_STOPWORDS
            # W13 — heft: measured bulk vs the size law (S <1h · M one sitting · L → split).
            # Done/cancelled WOs are history, not warnings.
            if wid and wid in wos and wos[wid]["status"] not in ("done", "cancelled"):
                heft = []
                if n_criteria > HEFT_MAX_CRITERIA:
                    heft.append(f"{n_criteria} acceptance criteria (>{HEFT_MAX_CRITERIA})")
                if len(wos[wid]["touches"]) > HEFT_MAX_TOUCHES:
                    heft.append(f"{len(wos[wid]['touches'])} touches globs (>{HEFT_MAX_TOUCHES})")
                body_lines = len(text.splitlines())
                if body_lines > HEFT_MAX_BODY_LINES:
                    heft.append(f"{body_lines} body lines (>{HEFT_MAX_BODY_LINES})")
                if re.search(r"\s+and\s+", str(fm.get("title", "")), re.I):
                    heft.append("title joins outcomes with 'and'? (atomicity rule 4 — "
                                "lexical check, ignore if the 'and' is inside one outcome)")
                if heft:
                    rep.add("WARN", "W13", f, 1,
                            f"{wid} heft vs declared size '{fm.get('size', '?')}': "
                            + "; ".join(heft) + " — smells like two WOs (split by outcome)")
                # W14 — criterion resting on a fact this WO's own notes say is unverified
                if hedge_tokens:
                    for cn, cl in crit_lines:
                        hit = ({t.lower() for t in TOKEN_RE.findall(cl)}
                               - W14_STOPWORDS) & hedge_tokens
                        if hit:
                            rep.add("WARN", "W14", f, cn,
                                    f"criterion shares '{sorted(hit)[0]}' with a hedged "
                                    f"line in this WO's epistemic notes — the fact it "
                                    f"rests on is unverified; verify before G1, not "
                                    f"during execution")
            if active_status:
                if not crit_lines:
                    rep.add("ERROR", "E19", f, 1,
                            f"{wid} has no checkable acceptance criteria")
                if not any(re.search(r"(?i)negative:|must not|git diff", line)
                           for _, line in crit_lines):
                    rep.add("ERROR", "E19", f, 1,
                            f"{wid} lacks a negative blast-radius criterion")
            if fm.get("status") == "done":
                unchecked = [line for line in text.splitlines()
                             if re.match(r"^\s*-\s*\[ \]", line)]
                closeout = re.search(r"(?ms)^##\s+Close-out\s*$\n(.*?)(?=^##\s|\Z)", text)
                if unchecked:
                    rep.add("ERROR", "E19", f, 1,
                            f"{wid} is done with {len(unchecked)} unchecked criterion/criteria")
                if not closeout or not re.search(
                        r"(?i)\b(evidence|exit\s+0|observed|transcript|screenshot)\b",
                        closeout.group(1)):
                    rep.add("ERROR", "E19", f, 1,
                            f"{wid} is done without reproducible close-out evidence")
        check_wo_graph(rep, wos)

        if mfm.get("tier") in {"M", "L", "XL"} and execution_mode == "planned" \
                and not historical and mfm.get("plan_contract_version") == 3:
            contract_path = pack / "plan-contract.json"
            assignment_path = pack / "planning-obligations.json"
            contract = assignments = None
            try:
                contract = json.loads(
                    contract_path.read_text(encoding="utf-8"),
                    object_pairs_hook=loom_lifecycle._strict_object)
                validate_schema(rep, contract_path, contract, "plan-contract.schema.json")
                body = dict(contract); claimed = body.pop("contract_hash")
                expected = hashlib.sha256(json.dumps(
                    body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                    allow_nan=False).encode("utf-8")).hexdigest()
                if claimed != expected:
                    raise ValueError("plan contract digest mismatch")
                loom_planning_intelligence.validate(contract["planning_intelligence"])
                assignments = json.loads(
                    assignment_path.read_text(encoding="utf-8"),
                    object_pairs_hook=loom_lifecycle._strict_object)
                validate_schema(
                    rep, assignment_path, assignments,
                    "planning-obligations.schema.json")
            except (OSError, UnicodeError, json.JSONDecodeError, KeyError, ValueError,
                    loom_lifecycle.LifecycleError,
                    loom_planning_intelligence.PlanningIntelligenceError) as exc:
                rep.add("ERROR", "E26", contract_path, 1,
                        f"sealed planning intelligence is invalid: {exc}")
            if isinstance(contract, dict) and isinstance(assignments, dict):
                assignment_body = dict(assignments)
                assignment_digest = assignment_body.pop("assignment_digest", None)
                intelligence = contract["planning_intelligence"]
                program = intelligence["program"]
                expected_atoms = {item["atom_id"]: item for item in intelligence["atoms"]
                                  if item["gate_effect"] != "none"}
                expected_program = (program or {}).get("program_digest")
                rows = assignments.get("assignments", [])
                row_ids = [item.get("atom_id") for item in rows
                           if isinstance(item, dict)] if isinstance(rows, list) else []
                invalid = assignment_digest != loom_domain_contract.digest(
                    "planning-obligation-assignments-v1", assignment_body) \
                    or assignments.get("plan_contract_hash") != contract.get("contract_hash") \
                    or assignments.get("planning_intelligence_digest") != \
                    intelligence.get("intelligence_digest") \
                    or assignments.get("program_digest") != expected_program \
                    or row_ids != sorted(expected_atoms) \
                    or len(row_ids) != len(set(row_ids))
                milestones = ({"delivery"} if program is None else {
                    item["id"] for item in program["milestone_graph"]["milestones"]})
                used_milestones = set()
                assigned_by_wo = {identity: [] for identity in wos}
                if not invalid:
                    for row in rows:
                        atom = expected_atoms.get(row.get("atom_id"))
                        work_order = row.get("work_order")
                        milestone = row.get("milestone")
                        if set(row) != {"atom_id", "work_order", "milestone", "verification"} \
                                or atom is None or work_order not in wos \
                                or milestone not in milestones \
                                or row.get("verification") != \
                                loom_planning_intelligence.expanded_verification(
                                    intelligence, atom):
                            invalid = True
                            break
                        used_milestones.add(milestone)
                        assigned_by_wo[work_order].append(row["atom_id"])
                if program is not None and used_milestones != milestones:
                    invalid = True
                for identity, wo in wos.items():
                    declared = wo["planning_obligations"] \
                        if isinstance(wo["planning_obligations"], list) else []
                    if sorted(declared) != sorted(assigned_by_wo[identity]) \
                            or wo["milestone"] not in milestones:
                        invalid = True
                if invalid:
                    rep.add("ERROR", "E26", assignment_path, 1,
                            "planning assignments diverge from the sealed contract, work "
                            "orders, verification, or program milestones")

        if validated_bundle is not None:
            required_bindings = {
                (item["invariant_id"], item["canonical_digest"])
                for item in validated_bundle["invariants"]}
            observed_bindings = set()
            for wo in wos.values():
                for binding in wo.get("domain_invariants", []):
                    if isinstance(binding, str) and "@" in binding:
                        observed_bindings.add(tuple(binding.split("@", 1)))
            missing_bindings = sorted(required_bindings - observed_bindings)
            if missing_bindings:
                rep.add("ERROR", "E25", wo_dir, 1,
                        "work orders do not bind every gate-ready domain invariant: "
                        + ", ".join(item[0] for item in missing_bindings[:8]))

        if execution_mode == "build-first":
            executable_ids = sorted(
                wid for wid, wo in wos.items()
                if wo["status"] in {"ready", "in-progress"})
            if executable_ids:
                rep.add(
                    "ERROR", "E17", manifest, 1,
                    "build-first history cannot execute work orders or receive causal "
                    f"plan credit; start a fresh planned lifecycle (blocked: "
                    f"{', '.join(executable_ids)})")

        if execution_mode == "planned" and not historical and lifecycle_data:
            completions = lifecycle_data.get("work_order_completions", [])
            completed_ids = {str(item.get("work_order", ""))
                             for item in completions if isinstance(item, dict)}
            for wid, wo in wos.items():
                if wo["status"] == "done" and wid not in completed_ids:
                    rep.add("ERROR", "E17", wo["path"], 1,
                            f"{wid} is done without a sealed post-authorization "
                            "loom_gate close-wo record")
            for wid in completed_ids:
                if wid not in wos:
                    rep.add("ERROR", "E17", pack / loom_gate.LIFECYCLE_FILE, 1,
                            f"completion record references missing work order {wid}")
                elif wos[wid]["status"] != "done":
                    rep.add("ERROR", "E17", wos[wid]["path"], 1,
                            f"{wid} has a completion record but status is "
                            f"{wos[wid]['status']}")

        for wid, wo in wos.items():
            for blocked in wo["blocks"]:
                if blocked not in wos:
                    rep.add("ERROR", "E08", wo["path"], 1,
                            f"blocks references unknown work order {blocked}")
                elif wid not in wos[blocked]["deps"]:
                    rep.add("ERROR", "E15", wo["path"], 1,
                            f"{wid} blocks {blocked}, but {blocked} does not depend_on {wid}")
            for dep in (value for value in wo["deps"] if str(value).startswith("WO-")):
                if dep in wos and wid not in wos[dep]["blocks"]:
                    rep.add("ERROR", "E15", wo["path"], 1,
                            f"{wid} depends_on {dep}, but {dep} does not list {wid} in blocks")

        # W07 — touches overlap between concurrently-active WOs
        active = [(wid, w) for wid, w in sorted(wos.items())
                  if w["status"] in ("ready", "in-progress")]
        for i, (wa, a) in enumerate(active):
            for wb, b in active[i + 1:]:
                hits = [(ta, tb) for ta in a["touches"] for tb in b["touches"]
                        if touches_overlap(ta, tb)]
                if hits:
                    rep.add("WARN", "W07", a["path"], 1,
                            f"{wa} and {wb} are both active with overlapping touches "
                            f"({hits[0][0]} ~ {hits[0][1]}) — sequence them or re-slice "
                            f"(loom/execution/parallel-work.md)")

    if mfm.get("tier") in {"M", "L", "XL"} and not historical and not wos:
        rep.add("ERROR", "E13", wo_dir, 1,
                f"tier {mfm.get('tier')} planned pack requires at least one work order")

    if mfm.get("tier") in {"M", "L", "XL"} and execution_mode == "planned" \
            and not historical:
        dependency_path = pack / loom_lifecycle.DEPENDENCY_FILE
        dependency_map = None
        try:
            dependency_map = json.loads(
                dependency_path.read_text(encoding="utf-8"),
                object_pairs_hook=loom_lifecycle._strict_object)
            loom_lifecycle.plan_regate({}, {}, dependency_map)
        except (OSError, UnicodeError, json.JSONDecodeError,
                loom_lifecycle.LifecycleError) as exc:
            rep.add("ERROR", "E23", dependency_path, 1,
                    f"planned M+ pack requires a valid plan dependency map: {exc}")
        else:
            validate_schema(
                rep, dependency_path, dependency_map,
                "plan-dependencies.schema.json")
            section_ids = [item["id"] for item in dependency_map["sections"]]
            if len(section_ids) != len(set(section_ids)):
                rep.add("ERROR", "E23", dependency_path, 1,
                        "plan dependency section ids must be unique")
            mapped_patterns = {
                pattern for item in dependency_map["sections"]
                for pattern in item["target_patterns"]}
            uncovered = sorted({
                pattern for work_order in wos.values()
                for pattern in work_order["touches"]
                if pattern not in mapped_patterns})
            if uncovered:
                rep.add("ERROR", "E23", dependency_path, 1,
                        "work-order touches missing from plan dependency map: "
                        + ", ".join(uncovered[:20]))

    frontier = {}
    for row in frontier_rows:
        wid = row.get("wo", "").strip()
        status = row.get("status", "").strip()
        if wid:
            if wid in frontier:
                rep.add("ERROR", "E15", manifest, 1,
                        f"duplicate frontier row for {wid}")
            frontier[wid] = {
                "status": status,
                "routing": row.get("routing", "").strip(),
            }
    if mfm and not historical:
        for wid, wo in wos.items():
            frontier_row = frontier.get(wid)
            if not frontier_row or frontier_row["status"] != wo["status"]:
                rep.add("ERROR", "E15", manifest, 1,
                        f"frontier status for {wid} is "
                        f"'{frontier_row['status'] if frontier_row else 'missing'}', "
                        f"work order status is '{wo['status']}'")
            elif frontier_row["routing"] != str(wo["routing"]):
                rep.add("ERROR", "E15", manifest, 1,
                        f"frontier routing for {wid} differs from work order routing")
        for wid in set(frontier) - set(wos):
            rep.add("ERROR", "E15", manifest, 1,
                    f"frontier references missing work order {wid}")

    if (execution_mode == "planned"
            and mfm.get("status") in {"gated", "active", "maintenance"}):
        g1_records = []
        review_dir = pack / "reviews"
        for review in sorted(review_dir.glob("*.md")) if review_dir.is_dir() else []:
            review_text = review.read_text(encoding="utf-8", errors="replace")
            rfm, _ = parse_frontmatter(review_text)
            if rfm and rfm.get("gate") == "G1":
                g1_records.append((review, rfm, review_text))
        passing = [item for item in g1_records
                   if item[1].get("verdict") in {"pass", "pass-with-fixes"}]
        if not passing:
            rep.add("ERROR", "E15", review_dir, 1,
                    "gated/active planned pack requires a recorded passing G1 review")
        for review, rfm, review_text in g1_records:
            for key in ("artifact", "project", "gate", "date", "reviewer",
                        "reviewer_independence", "verdict", "open_high_findings",
                        "rubric_average", "rubric_min", "loom_version"):
                if key not in rfm or rfm[key] in ("", None):
                    rep.add("ERROR", "E15", review, 1,
                            f"G1 review missing required frontmatter key '{key}'")
            if rfm.get("reviewer_independence") != "independent":
                rep.add("ERROR", "E15", review, 1,
                        "passing G1 reviewer_independence must be independent")
            if str(rfm.get("open_high_findings", "")) != "0":
                rep.add("ERROR", "E15", review, 1,
                        "passing G1 review must declare open_high_findings: 0")
            rows = parse_markdown_table(review_text, "Rubric scorecard (G1/G4)")
            scores = {}
            for row in rows:
                match = re.match(r"(\d+)", row.get("dimension", ""))
                try:
                    score = float(row.get("score", ""))
                except ValueError:
                    continue
                if match:
                    scores[int(match.group(1))] = score
                evidence = row.get("evidence (pack location)", "").strip()
                if not evidence:
                    rep.add("ERROR", "E15", review, 1,
                            f"rubric dimension {match.group(1) if match else '?'} lacks evidence")
                else:
                    paths = re.findall(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.md", evidence)
                    if not paths:
                        rep.add("ERROR", "E15", review, 1,
                                f"rubric dimension {match.group(1) if match else '?'} "
                                "evidence does not name a pack Markdown file")
                    for rel in paths:
                        target = (pack / rel).resolve()
                        try:
                            target.relative_to(pack.resolve())
                        except ValueError:
                            rep.add("ERROR", "E15", review, 1,
                                    f"rubric evidence escapes the pack: {rel}")
                        else:
                            if not target.is_file():
                                rep.add("ERROR", "E15", review, 1,
                                        f"rubric evidence path does not exist: {rel}")
            if set(scores) != set(range(1, 11)):
                rep.add("ERROR", "E15", review, 1,
                        "G1 rubric must contain exactly dimensions 1 through 10")
            else:
                average, minimum = sum(scores.values()) / 10, min(scores.values())
                if average < 3.0 or minimum < 2.0:
                    rep.add("ERROR", "E15", review, 1,
                            f"G1 rubric fails threshold: average {average:.2f}, min {minimum:g}")
                try:
                    declared_average = float(rfm.get("rubric_average", ""))
                    declared_min = float(rfm.get("rubric_min", ""))
                except ValueError:
                    rep.add("ERROR", "E15", review, 1,
                            "rubric_average and rubric_min must be numeric")
                else:
                    if abs(declared_average - average) > 0.001 or declared_min != minimum:
                        rep.add("ERROR", "E15", review, 1,
                                "declared rubric summary does not match measured rows")

    review_records = {}
    review_dir = pack / "reviews"
    for review in sorted(review_dir.glob("*.md")) if review_dir.is_dir() else []:
        review_text = review.read_text(encoding="utf-8", errors="replace")
        rfm, _ = parse_frontmatter(review_text)
        if not rfm or not rfm.get("gate"):
            continue
        review_records.setdefault(str(rfm["gate"]), []).append((review, rfm))

    def require_passing_gate(gate, reason):
        records = review_records.get(gate, [])
        passing = [record for record in records
                   if record[1].get("verdict") in {"pass", "pass-with-fixes"}]
        if not passing:
            rep.add("ERROR", "E20", review_dir, 1,
                    f"{reason} requires a recorded passing {gate} review")
        for review, rfm in records:
            for key in ("artifact", "project", "gate", "date", "reviewer",
                        "verdict", "loom_version"):
                if key not in rfm or rfm[key] in ("", None):
                    rep.add("ERROR", "E20", review, 1,
                            f"{gate} review missing required key '{key}'")

    if execution_mode == "planned" and check_gate_requirements:
        executable = any(wo["status"] in {"ready", "in-progress", "done"}
                         for wo in wos.values())
        if artifact_decisions.get("scaffold.md") == "produce" and executable:
            require_passing_gate("G2", "executed scaffold")
        terminal = bool(wos) and all(
            wo["status"] in {"done", "cancelled"} for wo in wos.values())
        if terminal:
            require_passing_gate("G4", "terminal work-order frontier")
        if mfm.get("status") in {"maintenance", "archived"}:
            require_passing_gate("G4", f"pack status {mfm.get('status')}")
            require_passing_gate("G5", f"pack status {mfm.get('status')}")

    # Cross-reference integrity
    for aid, sites in a_refs.items():
        if aid not in ledger:
            p, n = sites[0]
            rep.add("ERROR", "E11", p, n, f"{aid} referenced but not in assumptions.md")
    for aid, entry in ledger.items():
        if aid not in a_refs:
            rep.add("WARN", "W01", ledger_file, entry["line"],
                    f"{aid} never referenced outside the ledger — used_in incomplete or entry dead")
        if entry.get("status", "").startswith("broken"):
            used = entry.get("used_in", "")
            for fname in re.findall(r"[\w./-]+\.md", used):
                base = Path(fname).name
                if base in artifact_status and artifact_status[base] != "stale":
                    rep.add("WARN", "W05", pack / base, 1,
                            f"{aid} is broken but {base} is '{artifact_status[base]}', not stale")
            for wid in re.findall(r"WO-\d{3,}", used):
                if wid in wos and not wos[wid]["stale_ok"]:
                    rep.add("WARN", "W05", wos[wid]["path"], 1,
                            f"{aid} is broken but {wid} is '{wos[wid]['status']}', not blocked")
    for did, sites in d_refs.items():
        if did not in d_ids:
            p, n = sites[0]
            rep.add("ERROR", "E14", p, n,
                    f"{did} referenced but not found in decisions.md")

    # W09 — glossary terms nobody uses
    if manifest_text:
        gloss = re.search(r"(?ms)^##\s+Glossary.*?(?=^##\s|\Z)", manifest_text)
        if gloss:
            corpus = "\n".join(corpus_parts)
            for n_off, row in enumerate(gloss.group(0).splitlines()):
                m = re.match(r"^\|\s*([^|<>—-][^|]*?)\s*\|", row)
                if not m or m.group(1).strip().lower() in ("term",):
                    continue
                term = m.group(1).strip()
                if term and not re.search(re.escape(term), corpus):
                    rep.add("WARN", "W09", manifest, 1,
                            f"glossary term '{term}' never used outside MANIFEST — dead "
                            f"entry, or the pack drifted to another name (rename sweep)")

    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mechanical validation of a Loom planning pack")
    ap.add_argument("pack", nargs="?", help="path to the plans/ directory")
    ap.add_argument("--repo", help="target repo root (enables repo_head drift check)")
    ap.add_argument("--home", nargs="?", const=str(Path.home() / ".loom"), default=None,
                    help="lint the Loom user home instead of (or before) a pack; "
                         "defaults to ~/.loom when given without a value")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict-staleness", action="store_true",
                    help="treat stale or indeterminate state as blocking errors")
    args = ap.parse_args(argv)
    if not args.pack and not args.home:
        ap.error("give a pack path, --home, or both")

    rep = Report()
    if args.home:
        rep.findings.extend(lint_home(args.home).findings)
    if args.pack:
        rep.findings.extend(lint(
            args.pack, args.repo, strict_staleness=args.strict_staleness).findings)
    errors = rep.errors
    warns = [f for f in rep.findings if f["sev"] == "WARN"]

    if args.json:
        print(json.dumps({"errors": len(errors), "warnings": len(warns),
                          "findings": rep.findings}, indent=2))
    else:
        for f in sorted(rep.findings, key=lambda x: (x["sev"] != "ERROR", x["path"], x["line"])):
            print(f'{f["sev"]:5} {f["code"]}  {f["path"]}:{f["line"]}  {f["msg"]}')
        if errors:
            status = "gates blocked"
        elif warns:
            status = f"no blocking errors; {len(warns)} warning(s) require review"
        else:
            status = "mechanically clean"
        print(f"\nloom_lint: {len(errors)} error(s), {len(warns)} warning(s)  — {status}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
