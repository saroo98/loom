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
import json
import re
import subprocess
import sys
from pathlib import Path

ENUMS = {
    "manifest.status": {"draft", "gated", "active", "stale", "maintenance", "archived"},
    "manifest.tier": {"S", "M", "L", "XL"},
    "artifact.status": {"draft", "gated", "stale", "superseded", "frozen"},
    "wo.status": {"draft", "ready", "blocked", "in-progress", "done", "cancelled"},
    "wo.routing": {"frontier-reasoning", "strong-coding", "fast-cheap", "specialist", "human"},
    "wo.size": {"S", "M"},
    "assumption.status": {"open", "verified", "broken", "retired"},
}

REQUIRED_KEYS = {
    "manifest": ["artifact", "project", "tier", "status", "last_verified", "loom_version"],
    "artifact": ["artifact", "status", "last_verified"],
    "wo": ["id", "title", "status", "routing", "size", "last_verified"],
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

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
A_REF_RE = re.compile(r"\bA-\d{3,}\b")
D_REF_RE = re.compile(r"\bD-\d{3,}\b")
WO_ID_RE = re.compile(r"^WO-\d{3,}$")
LABEL_RE = re.compile(r"\[(FACT|ASSUMPTION|SPECULATION|UNKNOWN|HUMAN-DECISION)\b")
CRITERION_OK_RE = re.compile(r"`|→|->|\d|(?i:\b(exit|green|pass|passes|output|diff|curl|http"
                             r"|screenshot|transcript|observ|returns|renders|matches)\b)")
FALLBACK_VERSION = "0.4.0"

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


def current_version():
    """Current Loom version = newest entry in this repo's CHANGELOG."""
    ch = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
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
        val = re.split(r"\s+#", val, 1)[0].strip()  # strip inline comment
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            fm[key] = [v.strip().strip("'\"") for v in inner.split(",") if v.strip()] if inner else []
        else:
            fm[key] = val.strip("'\"")
    return None, 0  # unterminated


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
            for pat in SECRET_PATTERNS:
                m = pat.search(line)
                if m and not re.search(r"<[A-Z_ ]+>|\{\{.*\}\}|\$\{.*\}|xxx+|str\b|<value>", line):
                    rep.add("ERROR", "E12", path, n,
                            "secret-looking content (privacy rule 2) — use <PLACEHOLDER>")


def parse_ledger(rep, path, text):
    """Return {A-id: {fields..., 'line': n}} from assumptions.md."""
    entries = {}
    current, cur_line = None, 0
    for n, line in enumerate(text.splitlines(), start=1):
        m = re.match(r"^##\s+(A-\d{3,})\s*:", line)
        if m:
            aid = m.group(1)
            if aid in entries:
                rep.add("ERROR", "E07", path, n, f"duplicate ledger id {aid}")
            current, cur_line = aid, n
            entries.setdefault(aid, {"line": n})
            continue
        if current:
            fm = re.match(r"^-\s*([a-z_]+)\s*:\s*(.*)$", line.strip())
            if fm:
                entries[current][fm.group(1)] = fm.group(2).strip()
    for aid, e in entries.items():
        for field in LEDGER_FIELDS:
            if field not in e or not e[field]:
                rep.add("ERROR", "E10", path, e["line"], f"{aid} missing field '{field}'")
        st = e.get("status", "").split()[0] if e.get("status") else ""
        if st and st not in ENUMS["assumption.status"]:
            rep.add("ERROR", "E04", path, e["line"],
                    f"{aid} status '{st}' not in {sorted(ENUMS['assumption.status'])}")
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
PATHY_RE = re.compile("[A-Za-z]:" + chr(92) * 2 + "|/(home|Users)/|github" + chr(92) + ".com/")


def lint_home(home_path):
    """User-home checks (loom/core/user-memory.md): shape, provenance, secrets,
    outbox anonymization sniff. Warnings guide; only secrets are errors."""
    rep = Report()
    home = Path(home_path)
    if not home.is_dir():
        rep.add("WARN", "W20", home, 1,
                "user home does not exist yet — created on first retro or /loom profile set")
        return rep
    for name in HOME_FILES:
        f = home / name
        if not f.is_file():
            rep.add("WARN", "W20", f, 1, f"{name} missing — created on first use")
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        fm, _ = parse_frontmatter(text)
        if fm is None:
            rep.add("WARN", "W20", f, 1, "frontmatter missing or unterminated")
        scan_text(rep, f, text, skip_hedge=True)  # secrets always; hedge scan is pack-prose only
        if name in ("profile.md", "calibration.md"):
            for n, line in enumerate(text.splitlines(), start=1):
                s = line.strip()
                if s.startswith("- ") and ":" in s and "<" not in s:
                    if name == "profile.md" and "# set" not in s:
                        rep.add("WARN", "W22", f, n,
                                "profile entry lacks '# set <date>, source: <provenance>'")
                    if name == "calibration.md" and not re.match(r"^- \d{4}-\d{2}-\d{2}", s):
                        rep.add("WARN", "W22", f, n, "calibration entry lacks a leading date")
        if name == "feedback-outbox.md":
            for n, line in enumerate(text.splitlines(), start=1):
                if PATHY_RE.search(line) and not line.strip().startswith("<!--"):
                    rep.add("WARN", "W21", f, n,
                            "outbox line contains a path/host-shaped token — anonymize "
                            "before /loom contribute (user-memory rules)")
    return rep


def lint(pack_path, repo_path=None):
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
            check_enum(rep, manifest, mfm, "status", "manifest.status")
            check_enum(rep, manifest, mfm, "tier", "manifest.tier")
            check_date(rep, manifest, mfm)
            if str(mfm.get("freshness_window_days", "")).isdigit():
                window = int(mfm["freshness_window_days"])
            if mfm.get("loom_version") and vtuple(mfm["loom_version"]) < vtuple(current_version()):
                rep.add("WARN", "W11", manifest, 1,
                        f"pack is Loom {mfm['loom_version']}, current is {current_version()} — "
                        f"run tools/loom_migrate.py")
        scan_text(rep, manifest, text)

    head = git_head(repo_path) if repo_path else None
    pack_rel = None
    if repo_path:
        try:
            pack_rel = pack.resolve().relative_to(Path(repo_path).resolve()).as_posix()
        except ValueError:
            pack_rel = None  # pack outside the repo — no tolerance possible
    _drift_cache = {}

    def check_repo_head(path, fm_dict):
        """W04 with source-file attribution, full values, and pack-only tolerance."""
        rh = str(fm_dict.get("repo_head", "") or "")
        if not (head and rh):
            return
        if heads_match(head, rh):
            return
        if rh not in _drift_cache:
            _drift_cache[rh] = pack_only_drift(repo_path, rh, pack_rel)
        if _drift_cache[rh]:
            return  # only the pack moved since the stamp — restamp noise, not staleness
        rep.add("WARN", "W04", path, 1,
                f"{path.name}: repo_head stamp {rh} is behind repo HEAD {head} — "
                f"staleness trigger 2 fired; run the recheck (fix the stamp in {path.name})")

    if manifest.is_file() and mfm:
        check_repo_head(manifest, mfm)

    # W12 — silence sweep presence (intake §4; tier M and up)
    intake_file = pack / "intake.md"
    if mfm.get("tier") in ("M", "L", "XL") and intake_file.is_file():
        itext = intake_file.read_text(encoding="utf-8", errors="replace")
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
        ledger = parse_ledger(rep, ledger_file, ltext)
        scan_text(rep, ledger_file, ltext)
        corpus_parts.append(ltext)

    # Decisions
    decisions_file = pack / "decisions.md"
    d_ids = set()
    if decisions_file.is_file():
        dtext = decisions_file.read_text(encoding="utf-8", errors="replace")
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
            check_enum(rep, f, fm, "status", "artifact.status")
            d = check_date(rep, f, fm)
            artifact_status[f.name] = fm.get("status", "")
            st = fm.get("status", "")
            if d and st not in ("superseded",) and (today - d).days > window:
                rep.add("WARN", "W03", f, 1,
                        f"last_verified {d} exceeds freshness window ({window}d) — recheck before use")
        scan_text(rep, f, text)
        if fm is not None:
            check_repo_head(f, fm)
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
                touches = fm.get("touches", [])
                if isinstance(touches, str):
                    touches = [touches] if touches else []
                wos[wid] = {"deps": deps, "path": f, "status": fm.get("status", ""),
                            "touches": touches,
                            "stale_ok": fm.get("status") in ("blocked", "done", "cancelled")}
                if d and fm.get("status") in ("ready", "in-progress") and (today - d).days > window:
                    rep.add("WARN", "W03", f, 1,
                            f"{wid} last_verified {d} exceeds freshness window ({window}d) — pre-WO check required")
            scan_text(rep, f, text)
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
        check_wo_graph(rep, wos)

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

    # Cross-reference integrity
    for aid, sites in a_refs.items():
        if ledger and aid not in ledger:
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
    if d_ids:
        for did, sites in d_refs.items():
            if did not in d_ids:
                p, n = sites[0]
                rep.add("WARN", "W06", p, n, f"{did} referenced but not found in decisions.md")

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
    args = ap.parse_args(argv)
    if not args.pack and not args.home:
        ap.error("give a pack path, --home, or both")

    rep = Report()
    if args.home:
        rep.findings.extend(lint_home(args.home).findings)
    if args.pack:
        rep.findings.extend(lint(args.pack, args.repo).findings)
    errors = rep.errors
    warns = [f for f in rep.findings if f["sev"] == "WARN"]

    if args.json:
        print(json.dumps({"errors": len(errors), "warnings": len(warns),
                          "findings": rep.findings}, indent=2))
    else:
        for f in sorted(rep.findings, key=lambda x: (x["sev"] != "ERROR", x["path"], x["line"])):
            print(f'{f["sev"]:5} {f["code"]}  {f["path"]}:{f["line"]}  {f["msg"]}')
        print(f"\nloom_lint: {len(errors)} error(s), {len(warns)} warning(s)"
              + ("  — gates blocked" if errors else "  — mechanically clean"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
