#!/usr/bin/env python3
"""loom_gate — record and verify causal lifecycle chronology.

The event chain binds planning start, G1, and implementation authorization to the
same repository state and to the exact G1 review bytes. It is tamper-evident, local,
and stdlib-only. A `build-first` chain is valid operational history but is never
eligible for plan-first causal credit.
"""

import argparse
import datetime as dt
import hashlib
import fnmatch
import functools
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).parent))
import loom_survey  # noqa: E402
import loom_lifecycle  # noqa: E402

SCHEMA_VERSION = 2
LIFECYCLE_FILE = "lifecycle.json"
EVENT_ORDER = ["planning-started", "g1-sealed", "implementation-authorized"]
LIFECYCLE_FIELDS = {
    "schema_version", "mode", "baseline_files", "events", "work_order_completions",
}
EVENT_BASE_FIELDS = {
    "event", "at", "repo_state_mode", "repo_state_hash", "repo_head",
    "previous_event_hash", "event_hash",
}
EVENT_FIELDS = {
    "planning-started": EVENT_BASE_FIELDS | {"baseline_snapshot_sha256"},
    "g1-sealed": EVENT_BASE_FIELDS | {
        "review", "review_sha256", "work_order_plans", "work_order_plans_sha256",
    },
    "implementation-authorized": EVENT_BASE_FIELDS | {"g1_event_hash"},
}
COMPLETION_FIELDS = {
    "work_order", "work_order_file", "work_order_sha256", "completed_at",
    "repo_state_mode", "repo_state_hash", "repo_head", "changed_paths",
    "after_hashes", "acceptance_evidence", "acceptance_evidence_sha256",
    "previous_completion_hash", "completion_hash",
}
SNAPSHOT_FILE_CAP = 100000
WORK_ORDER_PLAN_CAP = 10000
SMALL_WO_MAX_CHARS = 6000
SMALL_WO_MAX_LINES = 80
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
HEAD_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DOMAIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SMALL_FIELDS = {
    "schema_version", "mode", "work_order_file", "route_contract",
    "baseline_files", "events",
}
SMALL_ROUTE_FIELDS = {
    "tier", "domain_ids", "last_verified", "freshness_window_days",
}


class LifecycleBusy(RuntimeError):
    pass


class LifecycleLock:
    """Fail-closed cross-process lock; stale locks require explicit human review."""
    def __init__(self, path, timeout=5.0):
        self.path = Path(path)
        self.timeout = timeout
        self.fd = None
        self.token = f"{os.getpid()}:{os.urandom(16).hex()}\n"

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self.fd = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self.fd, self.token.encode("ascii"))
                return self
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise LifecycleBusy(
                        f"lifecycle is busy or a prior process left {self.path}; "
                        "verify no writer is active before removing that lock")
                time.sleep(0.05)
            except OSError as exc:
                raise LifecycleBusy(f"cannot acquire lifecycle lock {self.path}: {exc}") \
                    from exc

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            os.close(self.fd)
        try:
            if self.path.read_text(encoding="ascii") == self.token:
                self.path.unlink()
        except FileNotFoundError:
            pass


def _locked(small=False):
    def decorate(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            first = Path(args[0]).resolve()
            directory = first.parent if small else first
            try:
                with LifecycleLock(directory / ".loom-lifecycle.lock"):
                    return function(*args, **kwargs)
            except (LifecycleBusy, OSError, UnicodeError, ValueError,
                    loom_survey.SurveyError) as exc:
                print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
                return 2
        return wrapper
    return decorate


def _utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat() \
        .replace("+00:00", "Z")


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _mapping_hash(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()


def _file_hash(path):
    path = Path(path)
    digest = hashlib.sha256()
    try:
        if path.is_symlink():
            digest.update(b"symlink\0" + str(path.readlink()).encode("utf-8"))
        else:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    except OSError as exc:
        raise loom_survey.SurveyError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def _safe_relative_path(value, prefix=None):
    if not isinstance(value, str) or not value or "\\" in value \
            or "\x00" in value or re.match(r"^[A-Za-z]:", value):
        return False
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        return False
    return prefix is None or (len(pure.parts) > 1 and pure.parts[0] == prefix)


def _pack_file(pack, relative, prefix):
    if not _safe_relative_path(relative, prefix):
        return None
    candidate = Path(pack).joinpath(*PurePosixPath(relative).parts)
    try:
        candidate.resolve(strict=False).relative_to(Path(pack).resolve())
    except ValueError:
        return None
    if candidate.is_symlink():
        return None
    return candidate


def _touch_patterns(values):
    patterns = []
    for value in values:
        raw = str(value).replace("\\", "/")
        if not raw or raw.startswith("/") or "\x00" in raw \
                or re.match(r"^[A-Za-z]:", raw) \
                or ".." in PurePosixPath(raw).parts:
            raise ValueError(f"unsafe touches pattern: {value!r}")
        while raw.startswith("./"):
            raw = raw[2:]
        if not raw or raw == ".":
            raise ValueError(f"unsafe touches pattern: {value!r}")
        patterns.append(raw)
    return patterns


def _snapshot_files(repo, pack):
    """Hash every Git-visible file (or every non-Git file), excluding the private pack."""
    repo, pack = Path(repo).resolve(), Path(pack).resolve()
    excluded = None
    try:
        excluded = pack.relative_to(repo).as_posix()
    except ValueError:
        pass
    try:
        probe = loom_survey.run_git(
            repo, "rev-parse", "--is-inside-work-tree", allowed=(0, 128))
    except loom_survey.SurveyError:
        if (repo / ".git").exists():
            raise
        probe = None
    if probe is not None and probe.returncode == 0:
        listed = loom_survey.run_git(
            repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        paths = [item for item in listed.stdout.split("\0") if item]
    else:
        paths = []
        try:
            for path in repo.rglob("*"):
                if not (path.is_file() or path.is_symlink()):
                    continue
                rel = path.relative_to(repo)
                if ".git" in rel.parts:
                    continue
                paths.append(rel.as_posix())
                if len(paths) > SNAPSHOT_FILE_CAP:
                    raise loom_survey.SurveyError(
                        f"file snapshot exceeds hard cap {SNAPSHOT_FILE_CAP}")
        except OSError as exc:
            raise loom_survey.SurveyError(
                f"cannot enumerate lifecycle baseline: {exc}") from exc
    filtered = sorted(set(path.replace("\\", "/") for path in paths
                          if not excluded
                          or not (path == excluded or path.startswith(excluded + "/"))))
    if len(filtered) > SNAPSHOT_FILE_CAP:
        raise loom_survey.SurveyError(
            f"file snapshot exceeds hard cap {SNAPSHOT_FILE_CAP}")
    snapshot = {}
    for rel in filtered:
        if not _safe_relative_path(rel):
            raise loom_survey.SurveyError(
                f"unsafe path in lifecycle snapshot: {rel!r}")
        path = repo / Path(rel)
        if path.is_file() or path.is_symlink():
            snapshot[rel] = _file_hash(path)
    return snapshot


def _canonical_wo_hash(path):
    text = Path(path).read_text(encoding="utf-8")
    text = re.sub(
        r"(?m)^(?:last_verified|repo_head|repo_state_hash)\s*:.*(?:\n|$)", "", text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _wo_plan_hash(path):
    """Hash immutable WO plan content while allowing status/close-out evidence updates."""
    text = Path(path).read_text(encoding="utf-8")
    text = re.sub(r"(?m)^status\s*:.*$", "status: <mutable>", text, count=1)
    text = re.sub(r"(?m)^(\s*-\s*)\[[ xX]\]", r"\1[ ]", text)
    text = re.sub(
        r"(?ms)(^##\s+Close-out\s*$\n).*?(?=^##\s|\Z)",
        r"\1<mutable close-out>\n", text)
    text = re.sub(
        r"(?m)^(?:last_verified|repo_head|repo_state_hash)\s*:.*(?:\n|$)", "", text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _work_order_plan_snapshot(pack):
    """Return the exact safe work-order plan set that G1 is approving."""
    pack = Path(pack).resolve()
    root = pack / "work-orders"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("work-orders directory is missing or unsafe")
    try:
        if root.resolve().parent != pack:
            raise ValueError("work-orders directory escapes the pack")
    except OSError as exc:
        raise ValueError(f"cannot resolve work-orders directory: {exc}") from exc
    paths = sorted(root.glob("WO-*.md"), key=lambda item: item.name)
    if not paths:
        raise ValueError("G1 has no work orders to seal")
    if len(paths) > WORK_ORDER_PLAN_CAP:
        raise ValueError(
            f"work-order plan set exceeds hard cap {WORK_ORDER_PLAN_CAP}")
    snapshot = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"work order is missing or unsafe: {path.name}")
        rel = path.relative_to(pack).as_posix()
        if not _safe_relative_path(rel, "work-orders"):
            raise ValueError(f"unsafe work-order path: {rel!r}")
        try:
            snapshot[rel] = _wo_plan_hash(path)
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"cannot hash work order {rel}: {exc}") from exc
    return snapshot


def _stable_work_order_plan_snapshot(pack):
    first = _work_order_plan_snapshot(pack)
    second = _work_order_plan_snapshot(pack)
    if first != second:
        raise ValueError("work-order plans changed while G1 was being sealed")
    return second


def _completion_hash(event):
    payload = {key: value for key, value in event.items()
               if key != "completion_hash"}
    return _mapping_hash(payload)


def _work_order_contract(wo, required_status=None, *, compact=False):
    import loom_lint
    text = Path(wo).read_text(encoding="utf-8")
    fm, _ = loom_lint.parse_frontmatter(text)
    errors = []
    if compact and (len(text) > SMALL_WO_MAX_CHARS
                    or len(text.splitlines()) > SMALL_WO_MAX_LINES):
        errors.append(
            f"Tier-S work order exceeds compact budget ({SMALL_WO_MAX_CHARS} characters/"
            f"{SMALL_WO_MAX_LINES} lines); compress it or promote the task")
    if fm is None:
        return {}, text, ["work order frontmatter is missing"]
    for key in loom_lint.REQUIRED_KEYS["wo"]:
        if key not in fm or fm[key] in (None, ""):
            errors.append(f"work order missing required key {key}")
    status = fm.get("status")
    if required_status is not None and status != required_status:
        errors.append(f"work order status must be {required_status}")
    if status not in loom_lint.ENUMS["wo.status"]:
        errors.append("work order status is invalid")
    wid = str(fm.get("id", ""))
    filename = Path(wo).name
    if not loom_lint.WO_ID_RE.fullmatch(wid) or not (
            filename == f"{wid}.md" or filename.startswith(f"{wid}-")):
        errors.append("work order id/filename is invalid")
    required_sections = {
        "intent", "context", "preconditions", "task", "acceptance criteria",
        "out of scope", "escalation triggers", "epistemic notes", "close-out",
    }
    headings = {match.group(1).strip().lower() for match in
                re.finditer(r"(?m)^##\s+(.+?)\s*$", text)}
    active = status in {"ready", "in-progress", "done"}
    if active:
        for section in sorted(required_sections - headings):
            errors.append(f"work order missing section ## {section}")
    criteria = re.findall(r"(?m)^\s*-\s*\[([ xX])\]\s+(.+)$", text)
    if active and not criteria:
        errors.append("work order has no acceptance criteria")
    if status == "ready" and any(mark != " " for mark, _ in criteria):
        errors.append("ready work order contains pre-checked criteria")
    if status == "done" and any(mark == " " for mark, _ in criteria):
        errors.append("done work order has unchecked criteria")
    if active and not any(re.search(r"(?i)negative:|must not|git diff", body)
                          for _, body in criteria):
        errors.append("work order lacks a negative blast-radius criterion")
    touches = fm.get("touches", [])
    if isinstance(touches, str):
        touches = [touches] if touches else []
    if active and (not isinstance(touches, list) or not touches):
        errors.append("work order touches is empty")
    if status == "done":
        closeout = re.search(
            r"(?ms)^##\s+Close-out\s*$\n(.*?)(?=^##\s|\Z)", text)
        if not closeout or re.search(r"(?i)\bpending\b", closeout.group(1)) \
                or not re.search(
                    r"(?i)\b(evidence|exit\s+0|observed|transcript|screenshot)\b",
                    closeout.group(1)):
            errors.append("done work order lacks reproducible close-out evidence")
    return fm, text, errors


def _standalone_wo_contract(wo, required_status):
    return _work_order_contract(
        wo, required_status=required_status, compact=True)


def _pack_work_order_contracts(pack):
    """Read exact WO contracts and manifest frontier without trusting G1-normalized fields."""
    import loom_lint
    pack = Path(pack).resolve()
    root = pack / "work-orders"
    findings = []
    records = {}
    if root.is_symlink() or not root.is_dir():
        return {}, {}, ["work-orders directory is missing or unsafe"]
    try:
        paths = sorted(root.glob("*.md"), key=lambda item: item.name)
    except OSError as exc:
        return {}, {}, [f"work-orders directory is unreadable: {exc}"]
    for path in paths:
        rel = path.relative_to(pack).as_posix()
        if path.is_symlink() or not path.is_file() \
                or not _safe_relative_path(rel, "work-orders"):
            findings.append(f"work order is missing or unsafe: {path.name}")
            continue
        try:
            fm, _text, errors = _work_order_contract(path)
        except (OSError, UnicodeError, ValueError) as exc:
            findings.append(f"work order {rel} is unreadable: {exc}")
            continue
        findings.extend(f"work order {rel}: {error}" for error in errors)
        wid = str(fm.get("id", ""))
        if not loom_lint.WO_ID_RE.fullmatch(wid):
            continue
        if wid in records:
            findings.append(f"work order id {wid} is duplicated")
            continue
        records[wid] = {
            "path": path,
            "relative": rel,
            "status": fm.get("status"),
            "routing": str(fm.get("routing", "")),
        }

    frontier = {}
    manifest = pack / "MANIFEST.md"
    try:
        manifest_text = manifest.read_text(encoding="utf-8")
        rows = loom_lint.parse_markdown_table(manifest_text, "Work order frontier")
    except (OSError, UnicodeError, ValueError) as exc:
        findings.append(f"MANIFEST work-order frontier is unreadable: {exc}")
        rows = []
    for row in rows:
        wid = str(row.get("wo", "")).strip()
        if not wid:
            continue
        if wid in frontier:
            findings.append(f"MANIFEST frontier duplicates {wid}")
            continue
        frontier[wid] = {
            "status": str(row.get("status", "")).strip(),
            "routing": str(row.get("routing", "")).strip(),
        }
    return records, frontier, findings


def _event_hash(event):
    payload = {key: value for key, value in event.items() if key != "event_hash"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def make_event(name, state, previous_hash=None, **extra):
    event = {
        "event": name,
        "at": _utc_now(),
        "repo_state_mode": state.mode,
        "repo_state_hash": state.state_hash,
        "repo_head": state.head or None,
        "previous_event_hash": previous_hash,
        **extra,
    }
    event["event_hash"] = _event_hash(event)
    return event


def _state(repo, pack):
    repo, pack = Path(repo).resolve(), Path(pack).resolve()
    excluded = ()
    try:
        rel = pack.relative_to(repo).as_posix()
        excluded = (rel,)
    except ValueError:
        pass
    return loom_survey.repo_state(repo, exclude_prefixes=excluded)


def _stable_state(repo, pack):
    first = _state(repo, pack)
    second = _state(repo, pack)
    if first != second:
        raise loom_survey.SurveyError(
            "repository changed while lifecycle state was being measured")
    return second


def _stable_snapshot(repo, pack):
    before = _state(repo, pack)
    files = _snapshot_files(repo, pack)
    after = _state(repo, pack)
    if before != after:
        raise loom_survey.SurveyError(
            "repository changed while lifecycle files were being snapshotted")
    return after, files


def _atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _atomic_write_text(path, text):
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _render_manifest(pack, state, mode, *, completed_wo=None, restamp_date=False):
    path = Path(pack) / "MANIFEST.md"
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("MANIFEST.md has no parseable frontmatter")
    values = {
        "execution_mode": mode,
        "repo_state_hash": f'"{state.state_hash}"',
        "repo_state_mode": f'"{state.mode}"',
    }
    if restamp_date:
        values["last_verified"] = dt.date.today().isoformat()
    if state.head:
        values["repo_head"] = f'"{state.head}"'
    for key, value in values.items():
        replacement = f"{key}: {value}"
        pattern = rf"(?m)^{re.escape(key)}\s*:.*$"
        if re.search(pattern, text):
            text = re.sub(pattern, replacement, text, count=1)
        else:
            close = text.find("\n---", 4)
            if close < 0:
                raise ValueError("MANIFEST.md frontmatter is unterminated")
            text = text[:close] + "\n" + replacement + text[close:]
    if completed_wo:
        frontier = re.search(
            r"(?ms)^##\s+Work order frontier\s*$\n(.*?)(?=^##\s|\Z)", text)
        if not frontier:
            raise ValueError("MANIFEST has no Work order frontier section")
        row_pattern = re.compile(
            rf"(?m)^\|\s*{re.escape(completed_wo)}\s*\|[^\r\n]*$")
        rows = list(row_pattern.finditer(frontier.group(1)))
        if len(rows) != 1:
            raise ValueError(
                f"MANIFEST frontier must contain exactly one {completed_wo} row")
        row = rows[0]
        cells = row.group(0).split("|")
        if len(cells) < 4:
            raise ValueError(f"MANIFEST frontier row for {completed_wo} is malformed")
        cells[2] = " done "
        replacement = "|".join(cells)
        absolute_start = frontier.start(1) + row.start()
        absolute_end = frontier.start(1) + row.end()
        text = text[:absolute_start] + replacement + text[absolute_end:]
    return path, text


def _write_lifecycle_and_manifest(pack, lifecycle, manifest_path, manifest_text,
                                  previous_lifecycle=None):
    """Commit the two pack checkpoints or restore the exact previous lifecycle."""
    lifecycle_path = Path(pack) / LIFECYCLE_FILE
    _atomic_write(lifecycle_path, lifecycle)
    try:
        _atomic_write_text(manifest_path, manifest_text)
    except OSError as manifest_error:
        try:
            if _load(pack) != lifecycle:
                raise OSError("new lifecycle record changed before rollback")
            if previous_lifecycle is None:
                lifecycle_path.unlink()
            else:
                _atomic_write(lifecycle_path, previous_lifecycle)
        except (OSError, ValueError) as rollback_error:
            raise OSError(
                f"manifest update failed ({manifest_error}); lifecycle rollback "
                f"also failed ({rollback_error})") from rollback_error
        raise


def _load(pack):
    path = Path(pack) / LIFECYCLE_FILE
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"{LIFECYCLE_FILE} missing") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {LIFECYCLE_FILE}: {exc}") from exc


def _verify(pack, repo=None, require_authorized=False, *, pending_completion=None):
    pack = Path(pack).resolve()
    findings = []
    if pending_completion is not None \
            and not _safe_relative_path(pending_completion, "work-orders"):
        return ["pending work-order completion path is unsafe"]
    try:
        data = _load(pack)
    except ValueError as exc:
        return [str(exc)]
    if not isinstance(data, dict) or set(data) != LIFECYCLE_FIELDS:
        findings.append("lifecycle top-level fields are unknown or missing")
        if not isinstance(data, dict):
            return findings
    if data.get("schema_version") != SCHEMA_VERSION:
        findings.append(f"schema_version must be {SCHEMA_VERSION}")
    if data.get("mode") not in {"planned", "build-first"}:
        findings.append("mode must be planned or build-first")
    baseline_files = data.get("baseline_files")
    if not isinstance(baseline_files, dict) \
            or len(baseline_files) > SNAPSHOT_FILE_CAP \
            or not all(_safe_relative_path(path)
                       and isinstance(digest, str)
                       and DIGEST_RE.fullmatch(digest)
                       for path, digest in (baseline_files or {}).items()):
        findings.append("baseline_files is missing, invalid, or exceeds its hard cap")
    events = data.get("events")
    if not isinstance(events, list) or not events:
        return findings + ["events must be a non-empty list"]
    names = [event.get("event") if isinstance(event, dict) else None for event in events]
    if names != EVENT_ORDER[:len(names)] or len(names) > len(EVENT_ORDER):
        findings.append(f"event order must be a prefix of {EVENT_ORDER}")
    if data.get("mode") == "build-first" \
            and ("implementation-authorized" in names
                 or data.get("work_order_completions")):
        findings.append(
            "build-first history cannot authorize implementation or receive completion credit")
    previous = None
    last_time = None
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            findings.append(f"event {index} must be an object")
            continue
        expected_fields = EVENT_FIELDS.get(event.get("event"))
        if expected_fields is None or set(event) != expected_fields:
            findings.append(f"event {index} fields are unknown or missing")
        if event.get("previous_event_hash") != previous:
            findings.append(f"event {index} previous hash does not link")
        if event.get("event_hash") != _event_hash(event):
            findings.append(f"event {index} event hash is invalid")
        previous = event.get("event_hash")
        if event.get("repo_state_mode") not in {"git", "filesystem"}:
            findings.append(f"event {index} repo_state_mode is invalid")
        if not isinstance(event.get("repo_state_hash"), str) \
                or not DIGEST_RE.fullmatch(event["repo_state_hash"]):
            findings.append(f"event {index} repo_state_hash is invalid")
        head = event.get("repo_head")
        if head is not None and (not isinstance(head, str) or not HEAD_RE.fullmatch(head)):
            findings.append(f"event {index} repo_head is invalid")
        try:
            instant = dt.datetime.fromisoformat(str(event.get("at", "")).replace("Z", "+00:00"))
        except ValueError:
            findings.append(f"event {index} has invalid UTC timestamp")
        else:
            if instant.tzinfo is None or instant.utcoffset() != dt.timedelta(0):
                findings.append(f"event {index} timestamp is not UTC")
            else:
                if last_time and instant < last_time:
                    findings.append(f"event {index} timestamp precedes prior event")
                last_time = instant
        if event.get("event") == "g1-sealed":
            review = _pack_file(pack, event.get("review"), "reviews")
            if review is None or not review.is_file():
                findings.append("G1 review path is unsafe or missing")
            else:
                try:
                    actual_review_hash = _sha256(review)
                except OSError:
                    findings.append("G1 review is unreadable")
                else:
                    if not isinstance(event.get("review_sha256"), str) \
                            or not DIGEST_RE.fullmatch(event["review_sha256"]) \
                            or event.get("review_sha256") != actual_review_hash:
                        findings.append("G1 review hash does not match the sealed review")
            plans = event.get("work_order_plans")
            if not isinstance(plans, dict) or not plans \
                    or len(plans) > WORK_ORDER_PLAN_CAP \
                    or not all(_safe_relative_path(path, "work-orders")
                               and isinstance(digest, str)
                               and DIGEST_RE.fullmatch(digest)
                               for path, digest in (plans or {}).items()):
                findings.append("G1 work-order plan snapshot is missing or invalid")
            elif event.get("work_order_plans_sha256") != _mapping_hash(plans):
                findings.append("G1 work-order plan snapshot hash is invalid")
            else:
                try:
                    current_plans = _work_order_plan_snapshot(pack)
                except ValueError as exc:
                    findings.append(f"G1 work-order plans are unreadable: {exc}")
                else:
                    if current_plans != plans:
                        findings.append(
                            "work-order plan content/set changed after sealed G1")
    if events and isinstance(events[0], dict) and isinstance(baseline_files, dict) \
            and events[0].get("baseline_snapshot_sha256") \
            != _mapping_hash(baseline_files):
        findings.append("planning event does not bind the baseline file snapshot")
    work_orders, frontier, contract_findings = _pack_work_order_contracts(pack)
    findings.extend(contract_findings)
    for wid, work_order in work_orders.items():
        row = frontier.get(wid)
        if row is None:
            findings.append(f"MANIFEST frontier is missing work order {wid}")
            continue
        transition = (
            pending_completion == work_order["relative"]
            and work_order["status"] == "done"
            and row["status"] in {"ready", "in-progress"}
        )
        if row["status"] != work_order["status"] and not transition:
            findings.append(
                f"MANIFEST frontier status for {wid} is {row['status']!r}, "
                f"work-order status is {work_order['status']!r}")
        if row["routing"] != work_order["routing"]:
            findings.append(f"MANIFEST frontier routing for {wid} differs")
    for wid in sorted(set(frontier) - set(work_orders)):
        findings.append(f"MANIFEST frontier references missing work order {wid}")
    completions = data.get("work_order_completions")
    if not isinstance(completions, list):
        findings.append("work_order_completions must be a list")
        completions = []
    prior_completion = None
    completed_ids = set()
    completion_counts = {}
    authorization_time = None
    if len(events) == 3 and isinstance(events[2], dict):
        try:
            candidate_time = dt.datetime.fromisoformat(
                str(events[2].get("at", "")).replace("Z", "+00:00"))
        except ValueError:
            pass
        else:
            if candidate_time.tzinfo is not None \
                    and candidate_time.utcoffset() == dt.timedelta(0):
                authorization_time = candidate_time
    for index, completion in enumerate(completions):
        if not isinstance(completion, dict):
            findings.append(f"completion {index} must be an object")
            continue
        if set(completion) != COMPLETION_FIELDS:
            findings.append(f"completion {index} fields are unknown or missing")
        wid = str(completion.get("work_order", ""))
        if not re.fullmatch(r"WO-\d{3,}", wid):
            findings.append(f"completion {index} work-order id is invalid")
        if wid in completed_ids:
            findings.append(f"work order {wid} has duplicate completion records")
        completed_ids.add(wid)
        completion_counts[wid] = completion_counts.get(wid, 0) + 1
        if completion.get("previous_completion_hash") != prior_completion:
            findings.append(f"completion {index} previous hash does not link")
        if completion.get("completion_hash") != _completion_hash(completion):
            findings.append(f"completion {index} hash is invalid")
        prior_completion = completion.get("completion_hash")
        try:
            completed_at = dt.datetime.fromisoformat(
                str(completion.get("completed_at", "")).replace("Z", "+00:00"))
        except ValueError:
            findings.append(f"completion {index} has invalid UTC timestamp")
        else:
            if completed_at.tzinfo is None \
                    or completed_at.utcoffset() != dt.timedelta(0):
                findings.append(f"completion {index} timestamp is not UTC")
            elif authorization_time and completed_at < authorization_time:
                findings.append(f"completion {index} predates implementation authorization")
        if completion.get("repo_state_mode") not in {"git", "filesystem"}:
            findings.append(f"completion {index} repo_state_mode is invalid")
        if not isinstance(completion.get("repo_state_hash"), str) \
                or not DIGEST_RE.fullmatch(completion["repo_state_hash"]):
            findings.append(f"completion {index} repo_state_hash is invalid")
        head = completion.get("repo_head")
        if head is not None and (not isinstance(head, str) or not HEAD_RE.fullmatch(head)):
            findings.append(f"completion {index} repo_head is invalid")
        if not isinstance(completion.get("work_order_sha256"), str) \
                or not DIGEST_RE.fullmatch(completion["work_order_sha256"]):
            findings.append(f"completion {index} work-order hash is invalid")
        changed = completion.get("changed_paths")
        after_hashes = completion.get("after_hashes")
        if not isinstance(changed, list) or not changed \
                or not all(_safe_relative_path(path) for path in changed) \
                or len(changed) != len(set(changed)) \
                or not isinstance(after_hashes, dict) \
                or set(changed) != set(after_hashes) \
                or not all(value is None or (
                    isinstance(value, str) and DIGEST_RE.fullmatch(value))
                    for value in (after_hashes or {}).values()):
            findings.append(f"completion {index} changed-path evidence is invalid")
        wo_rel = str(completion.get("work_order_file", ""))
        wo_path = _pack_file(pack, wo_rel, "work-orders")
        if wo_path is None or not wo_path.is_file() \
                or not wo_path.name.startswith(wid):
            findings.append(f"completion {index} work-order file is unsafe or missing")
        else:
            try:
                current_wo_hash = _canonical_wo_hash(wo_path)
            except (OSError, UnicodeError):
                findings.append(f"completion {index} work-order file is unreadable")
            else:
                if completion.get("work_order_sha256") != current_wo_hash:
                    findings.append(
                        f"completion {index} work-order evidence hash does not match")
        record = work_orders.get(wid)
        if record is None:
            findings.append(f"completion {index} references missing work order {wid}")
        else:
            if wo_rel != record["relative"]:
                findings.append(
                    f"completion {index} work-order path does not match {wid}")
            if record["status"] != "done":
                findings.append(
                    f"completion {index} references {wid} with status "
                    f"{record['status']!r}, not 'done'")
        evidence_rel = str(completion.get("acceptance_evidence", ""))
        evidence_path = _pack_file(pack, evidence_rel, "evidence")
        if evidence_path is None or not evidence_path.is_file() \
                or completion.get("acceptance_evidence_sha256") != _file_hash(
                    evidence_path):
            findings.append(f"completion {index} acceptance evidence is missing or changed")
        else:
            try:
                loom_lifecycle.validate_acceptance_evidence(
                    pack, wid, expected_state_hash=completion.get("repo_state_hash"))
            except loom_lifecycle.LifecycleError as exc:
                findings.append(f"completion {index} acceptance evidence is invalid: {exc}")
    for wid, work_order in work_orders.items():
        count = completion_counts.get(wid, 0)
        transition = (
            pending_completion == work_order["relative"]
            and work_order["status"] == "done" and count == 0
        )
        if work_order["status"] == "done" and count == 0 and not transition:
            findings.append(f"work order {wid} is done without a sealed completion")
        if work_order["status"] != "done" and count:
            findings.append(
                f"work order {wid} has completion evidence but status is "
                f"{work_order['status']!r}")
    if require_authorized and names != EVENT_ORDER:
        findings.append("implementation is not authorized")
    if repo and names:
        try:
            current = _state(repo, pack)
        except loom_survey.SurveyError as exc:
            findings.append(f"repository state is indeterminate: {exc}")
        else:
            checkpoint = events[-1] if isinstance(events[-1], dict) else {}
            valid_completions = [item for item in completions if isinstance(item, dict)]
            if valid_completions:
                checkpoint = valid_completions[-1]
            if current.state_hash != checkpoint.get("repo_state_hash"):
                findings.append(
                    "repository has unrecorded changes since the last lifecycle checkpoint")
    return findings


def verify(pack, repo=None, require_authorized=False):
    """Verify only stable lifecycle states; transitional exceptions are never public."""
    findings = _verify(pack, repo, require_authorized)
    pack_path = Path(pack).resolve()
    if not pack_path.is_dir():
        return findings
    try:
        import loom_lint
        report = loom_lint.lint(
            pack_path, repo_path=None, enforce_lifecycle=False,
            check_repo_state=False, check_gate_requirements=False)
    except (OSError, UnicodeError, ValueError, SystemExit) as exc:
        findings.append(f"pack lint is indeterminate: {exc}")
    else:
        findings.extend(
            f"pack lint {item['code']}: {item['msg']}"
            for item in report.errors)
    return findings


@_locked()
def start(pack, repo, mode="planned"):
    pack = Path(pack).resolve()
    path = pack / LIFECYCLE_FILE
    if mode not in {"planned", "build-first"}:
        print("loom_gate: mode must be planned or build-first", file=sys.stderr)
        return 2
    if path.exists():
        print(f"loom_gate: REFUSED — {LIFECYCLE_FILE} already exists", file=sys.stderr)
        return 1
    try:
        state, baseline_files = _stable_snapshot(repo, pack)
        manifest_path, manifest_text = _render_manifest(pack, state, mode)
        event = make_event(
            "planning-started", state,
            baseline_snapshot_sha256=_mapping_hash(baseline_files))
        lifecycle = {
            "schema_version": SCHEMA_VERSION,
            "mode": mode,
            "baseline_files": baseline_files,
            "events": [event],
            "work_order_completions": [],
        }
        _write_lifecycle_and_manifest(
            pack, lifecycle, manifest_path, manifest_text)
    except (OSError, ValueError, loom_survey.SurveyError) as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    print(f"loom_gate: planning baseline recorded ({state.state_hash})")
    return 0


@_locked()
def seal_g1(pack, repo, review):
    pack, review = Path(pack).resolve(), Path(review).resolve()
    try:
        review_rel = review.relative_to(pack).as_posix()
    except ValueError:
        print("loom_gate: REFUSED — G1 review must live inside the pack", file=sys.stderr)
        return 1
    if not review_rel.startswith("reviews/") or not review.is_file():
        print("loom_gate: REFUSED — G1 review must exist under reviews/", file=sys.stderr)
        return 1
    findings = verify(pack)
    if findings:
        for finding in findings:
            print(f"loom_gate: BLOCKED — {finding}", file=sys.stderr)
        return 1
    data = _load(pack)
    if [event["event"] for event in data["events"]] != ["planning-started"]:
        print("loom_gate: REFUSED — G1 can only seal after planning-started",
              file=sys.stderr)
        return 1
    import loom_lint
    review_fm, _ = loom_lint.parse_frontmatter(review.read_text(encoding="utf-8"))
    if not review_fm or review_fm.get("gate") != "G1" \
            or review_fm.get("verdict") not in {"pass", "pass-with-fixes"}:
        print("loom_gate: REFUSED — review is not a passing G1 record", file=sys.stderr)
        return 1
    lint = loom_lint.lint(
        pack, repo_path=repo, enforce_lifecycle=False, check_repo_state=False)
    if lint.errors:
        for finding in lint.errors:
            print(f"loom_gate: LINT — {finding['code']} {finding['msg']}", file=sys.stderr)
        return 1
    try:
        state, current_files = _stable_snapshot(repo, pack)
        work_order_plans = _stable_work_order_plan_snapshot(pack)
    except loom_survey.SurveyError as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    previous = data["events"][-1]
    if state.state_hash != previous["repo_state_hash"]:
        print("loom_gate: BLOCKED — repository changed during planning; G1 cannot "
              "be credited", file=sys.stderr)
        return 1
    if current_files != data.get("baseline_files"):
        print("loom_gate: BLOCKED — repository files differ from the planning baseline; "
              "G1 cannot be credited", file=sys.stderr)
        return 1
    event = make_event(
        "g1-sealed", state, previous["event_hash"], review=review_rel,
        review_sha256=_sha256(review), work_order_plans=work_order_plans,
        work_order_plans_sha256=_mapping_hash(work_order_plans))
    data["events"].append(event)
    _atomic_write(pack / LIFECYCLE_FILE, data)
    print(f"loom_gate: G1 sealed to {review_rel} ({event['review_sha256']})")
    return 0


@_locked()
def authorize(pack, repo):
    pack = Path(pack).resolve()
    findings = verify(pack)
    if findings:
        for finding in findings:
            print(f"loom_gate: BLOCKED — {finding}", file=sys.stderr)
        return 1
    data = _load(pack)
    if data.get("mode") != "planned":
        print("loom_gate: REFUSED — build-first history cannot authorize implementation "
              "or receive plan-first causal credit; start a fresh planned lifecycle",
              file=sys.stderr)
        return 1
    if [event["event"] for event in data["events"]] != EVENT_ORDER[:2]:
        print("loom_gate: REFUSED — implementation requires a sealed G1",
              file=sys.stderr)
        return 1
    try:
        state, current_files = _stable_snapshot(repo, pack)
    except loom_survey.SurveyError as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    previous = data["events"][-1]
    if state.state_hash != previous.get("repo_state_hash") \
            or current_files != data.get("baseline_files"):
        print("loom_gate: BLOCKED — repository changed after G1; authorization refused",
              file=sys.stderr)
        return 1
    event = make_event(
        "implementation-authorized", state, previous["event_hash"],
        g1_event_hash=previous["event_hash"])
    data["events"].append(event)
    try:
        manifest_path, manifest_text = _render_manifest(
            pack, state, data["mode"], restamp_date=True)
        _write_lifecycle_and_manifest(
            pack, data, manifest_path, manifest_text,
            {**data, "events": data["events"][:-1]})
    except (OSError, ValueError) as exc:
        print(f"loom_gate: INDETERMINATE — cannot record authorization checkpoint: {exc}",
              file=sys.stderr)
        return 2
    print("loom_gate: implementation authorized; chronology chain is valid")
    return 0


@_locked()
def close_wo(pack, repo, wo):
    """Bind a done work order to target changes made after implementation authorization."""
    pack, wo = Path(pack).resolve(), Path(wo).resolve()
    try:
        wo_rel = wo.relative_to(pack).as_posix()
    except ValueError:
        print("loom_gate: REFUSED — work order must live inside the pack", file=sys.stderr)
        return 1
    if not wo_rel.startswith("work-orders/") or not wo.is_file():
        print("loom_gate: REFUSED — work order must exist under work-orders/",
              file=sys.stderr)
        return 1
    findings = _verify(pack, pending_completion=wo_rel)
    if findings:
        for finding in findings:
            print(f"loom_gate: BLOCKED — {finding}", file=sys.stderr)
        return 1
    data = _load(pack)
    if [event.get("event") for event in data["events"]] != EVENT_ORDER:
        print("loom_gate: REFUSED — implementation is not authorized", file=sys.stderr)
        return 1
    import loom_lint
    try:
        text = wo.read_text(encoding="utf-8")
        fm, _ = loom_lint.parse_frontmatter(text)
    except (OSError, UnicodeError) as exc:
        print(f"loom_gate: INDETERMINATE — cannot read work order: {exc}", file=sys.stderr)
        return 2
    wid = str((fm or {}).get("id", ""))
    if not fm or fm.get("status") != "done" or not loom_lint.WO_ID_RE.fullmatch(wid):
        print("loom_gate: REFUSED — work order must have valid id and status: done",
              file=sys.stderr)
        return 1
    if any(item.get("work_order") == wid
           for item in data.get("work_order_completions", [])):
        print(f"loom_gate: REFUSED — {wid} already has a completion record",
              file=sys.stderr)
        return 1
    criteria = re.findall(r"(?m)^\s*-\s*\[([ xX])\]\s+(.+)$", text)
    if not criteria or any(mark == " " for mark, _ in criteria):
        print("loom_gate: REFUSED — every acceptance criterion must be checked",
              file=sys.stderr)
        return 1
    closeout = re.search(
        r"(?ms)^##\s+Close-out\s*$\n(.*?)(?=^##\s|\Z)", text)
    if not closeout or re.search(r"(?i)\bpending\b", closeout.group(1)) \
            or not re.search(
                r"(?i)\b(evidence|exit\s+0|observed|transcript|screenshot)\b",
                closeout.group(1)):
        print("loom_gate: REFUSED — close-out lacks completed reproducible evidence",
              file=sys.stderr)
        return 1
    touches = fm.get("touches", [])
    if isinstance(touches, str):
        touches = [touches] if touches else []
    if not isinstance(touches, list) or not touches:
        print("loom_gate: REFUSED — work order touches is empty", file=sys.stderr)
        return 1
    try:
        patterns = _touch_patterns(touches)
    except ValueError:
        print("loom_gate: REFUSED — work order has unsafe touches", file=sys.stderr)
        return 1
    try:
        current_state, current_files = _stable_snapshot(repo, pack)
    except loom_survey.SurveyError as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    try:
        acceptance = loom_lifecycle.validate_acceptance_evidence(
            pack, wid, repo, require_current=True)
    except loom_lifecycle.LifecycleError as exc:
        print(f"loom_gate: REFUSED — {exc}", file=sys.stderr)
        return 1
    evidence_rel = f"evidence/{wid}.json"
    evidence_path = pack / evidence_rel
    reference = dict(data["baseline_files"])
    for completion in data.get("work_order_completions", []):
        reference.update(completion.get("after_hashes", {}))
    candidate_paths = sorted(set(reference) | set(current_files))
    all_changed = [path for path in candidate_paths
                   if reference.get(path) != current_files.get(path)]
    changed = [path for path in all_changed
               if any(fnmatch.fnmatchcase(path, pattern)
                      or (pattern.endswith("/**")
                          and path.startswith(pattern[:-3].rstrip("/") + "/"))
                      for pattern in patterns)]
    outside = sorted(set(all_changed) - set(changed))
    if outside:
        shown = ", ".join(outside[:20])
        suffix = f" (+{len(outside) - 20} more)" if len(outside) > 20 else ""
        print("loom_gate: REFUSED — repository changes fall outside this work "
              f"order's declared touches: {shown}{suffix}", file=sys.stderr)
        return 1
    if not changed:
        print(
            "loom_gate: REFUSED — no declared target changed after authorization; "
            "pre-existing deliverables cannot receive causal plan credit",
            file=sys.stderr)
        return 1
    previous = (data.get("work_order_completions") or [])[-1:]
    event = {
        "work_order": wid,
        "work_order_file": wo_rel,
        "work_order_sha256": _canonical_wo_hash(wo),
        "completed_at": _utc_now(),
        "repo_state_mode": current_state.mode,
        "repo_state_hash": current_state.state_hash,
        "repo_head": current_state.head or None,
        "changed_paths": changed,
        "after_hashes": {path: current_files.get(path) for path in changed},
        "acceptance_evidence": evidence_rel,
        "acceptance_evidence_sha256": _file_hash(evidence_path),
        "previous_completion_hash": (
            previous[0].get("completion_hash") if previous else None),
    }
    event["completion_hash"] = _completion_hash(event)
    previous_lifecycle = json.loads(json.dumps(data))
    data.setdefault("work_order_completions", []).append(event)
    try:
        manifest_path, manifest_text = _render_manifest(
            pack, current_state, data["mode"], completed_wo=wid,
            restamp_date=True)
        _write_lifecycle_and_manifest(
            pack, data, manifest_path, manifest_text, previous_lifecycle)
    except (OSError, ValueError) as exc:
        print(f"loom_gate: INDETERMINATE — cannot record completion checkpoint: {exc}",
              file=sys.stderr)
        return 2
    print(f"loom_gate: {wid} completion sealed ({len(changed)} changed path(s))")
    return 0


def _load_small(record):
    try:
        return json.loads(Path(record).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("small lifecycle record is missing") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read small lifecycle record: {exc}") from exc


def verify_small(record):
    record = Path(record).resolve()
    findings = []
    try:
        data = _load_small(record)
    except ValueError as exc:
        return [str(exc)]
    if set(data) != SMALL_FIELDS \
            or data.get("schema_version") != SCHEMA_VERSION \
            or data.get("mode") != "small":
        findings.append("small lifecycle header is invalid")
    route = data.get("route_contract")
    if not isinstance(route, dict) or set(route) != SMALL_ROUTE_FIELDS \
            or route.get("tier") != "S" \
            or not isinstance(route.get("domain_ids"), list) \
            or not route["domain_ids"] or len(route["domain_ids"]) > 16 \
            or len(route["domain_ids"]) != len(set(route["domain_ids"])) \
            or not all(isinstance(item, str) and DOMAIN_ID_RE.fullmatch(item)
                       for item in route["domain_ids"]) \
            or type(route.get("freshness_window_days")) is not int \
            or not 1 <= route["freshness_window_days"] <= 3650:
        findings.append("small lifecycle route contract is invalid")
    else:
        try:
            dt.date.fromisoformat(str(route.get("last_verified")))
        except ValueError:
            findings.append("small lifecycle last_verified is invalid")
    baseline = data.get("baseline_files")
    if not isinstance(baseline, dict) or len(baseline) > SNAPSHOT_FILE_CAP \
            or not all(_safe_relative_path(path)
                       and isinstance(digest, str) and DIGEST_RE.fullmatch(digest)
                       for path, digest in (baseline or {}).items()):
        findings.append("small lifecycle baseline is invalid or oversized")
        baseline = {}
    events = data.get("events")
    if not isinstance(events, list) or not events:
        return findings + ["small lifecycle events are missing"]
    names = [event.get("event") if isinstance(event, dict) else None for event in events]
    if names not in (["small-planning-started"],
                     ["small-planning-started", "small-authorized"],
                     ["small-planning-started", "small-authorized", "small-completed"]):
        findings.append("small lifecycle event order is invalid")
    previous = None
    last_time = None
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            findings.append(f"small event {index} must be an object")
            continue
        if event.get("previous_event_hash") != previous:
            findings.append(f"small event {index} previous hash does not link")
        if event.get("event_hash") != _event_hash(event):
            findings.append(f"small event {index} hash is invalid")
        previous = event.get("event_hash")
        if event.get("repo_state_mode") not in {"git", "filesystem"}:
            findings.append(f"small event {index} repo_state_mode is invalid")
        if not isinstance(event.get("repo_state_hash"), str) \
                or not DIGEST_RE.fullmatch(event["repo_state_hash"]):
            findings.append(f"small event {index} repo_state_hash is invalid")
        head = event.get("repo_head")
        if head is not None and (not isinstance(head, str) or not HEAD_RE.fullmatch(head)):
            findings.append(f"small event {index} repo_head is invalid")
        try:
            instant = dt.datetime.fromisoformat(
                str(event.get("at", "")).replace("Z", "+00:00"))
        except ValueError:
            findings.append(f"small event {index} has invalid UTC timestamp")
        else:
            if instant.tzinfo is None or instant.utcoffset() != dt.timedelta(0):
                findings.append(f"small event {index} timestamp is not UTC")
            else:
                if last_time and instant < last_time:
                    findings.append(f"small event {index} timestamp precedes prior event")
                last_time = instant
    if isinstance(events[0], dict) \
            and events[0].get("baseline_snapshot_sha256") != _mapping_hash(baseline):
        findings.append("small planning event does not bind its file baseline")
    wo_rel = data.get("work_order_file")
    wo = None
    if _safe_relative_path(wo_rel) \
            and len(PurePosixPath(wo_rel).parts) == 1:
        candidate = record.parent / wo_rel
        if not candidate.is_symlink():
            wo = candidate
    if len(events) >= 2:
        try:
            plan_hash = _wo_plan_hash(wo) if wo and wo.is_file() else None
        except (OSError, UnicodeError):
            plan_hash = None
        if not isinstance(events[1], dict) or plan_hash is None \
                or events[1].get("work_order_plan_sha256") != plan_hash:
            findings.append("authorized small work-order plan hash does not match")
    if len(events) == 3:
        final_event = events[2] if isinstance(events[2], dict) else {}
        changed = final_event.get("changed_paths")
        after = final_event.get("after_hashes")
        if not isinstance(changed, list) or not changed \
                or not all(_safe_relative_path(path) for path in changed) \
                or len(changed) != len(set(changed)) \
                or not isinstance(after, dict) or set(changed) != set(after) \
                or not all(value is None or (
                    isinstance(value, str) and DIGEST_RE.fullmatch(value))
                    for value in (after or {}).values()):
            findings.append("small completion changed-path evidence is invalid")
        try:
            wo_hash = _canonical_wo_hash(wo) if wo and wo.is_file() else None
        except (OSError, UnicodeError):
            wo_hash = None
        if wo_hash is None or final_event.get("work_order_sha256") != wo_hash:
            findings.append("completed small work-order evidence hash does not match")
        evidence_rel = final_event.get("acceptance_evidence")
        evidence_hash = final_event.get("acceptance_evidence_sha256")
        if not _safe_relative_path(evidence_rel) \
                or not str(evidence_rel).startswith("evidence/") \
                or not isinstance(evidence_hash, str) \
                or not DIGEST_RE.fullmatch(evidence_hash):
            findings.append("small completion acceptance evidence binding is invalid")
        else:
            evidence_path = record.parent / evidence_rel
            try:
                actual_hash = _file_hash(evidence_path)
                loom_lifecycle.validate_acceptance_evidence(
                    record.parent, final_event.get("work_order"),
                    expected_state_hash=final_event.get("repo_state_hash"))
                evidence_valid = True
            except (OSError, RuntimeError, ValueError):
                actual_hash, evidence_valid = None, False
            if actual_hash != evidence_hash or not evidence_valid:
                findings.append("small completion acceptance evidence does not validate")
    return findings


@_locked(small=True)
def small_start(record, repo, wo, domains=None):
    record, wo = Path(record).resolve(), Path(wo).resolve()
    if record.suffix.lower() != ".json" or wo.suffix.lower() != ".md" \
            or record.parent != wo.parent:
        print("loom_gate: REFUSED — Tier-S record and WO must be .json/.md siblings",
              file=sys.stderr)
        return 1
    if record.exists() or wo.exists():
        print("loom_gate: REFUSED — Tier-S record/WO already exists; baseline must come first",
              file=sys.stderr)
        return 1
    domains = ["unclassified"] if domains is None else list(domains)
    if not domains or len(domains) > 16 or len(domains) != len(set(domains)) \
            or not all(isinstance(item, str) and DOMAIN_ID_RE.fullmatch(item)
                       for item in domains):
        print("loom_gate: REFUSED — Tier-S domains are invalid", file=sys.stderr)
        return 1
    try:
        record.parent.mkdir(parents=True, exist_ok=True)
        state, baseline = _stable_snapshot(repo, record.parent)
        event = make_event(
            "small-planning-started", state,
            baseline_snapshot_sha256=_mapping_hash(baseline))
        _atomic_write(record, {
            "schema_version": SCHEMA_VERSION,
            "mode": "small",
            "work_order_file": wo.name,
            "route_contract": {
                "tier": "S", "domain_ids": domains,
                "last_verified": dt.datetime.now(dt.timezone.utc).date().isoformat(),
                "freshness_window_days": 14,
            },
            "baseline_files": baseline,
            "events": [event],
        })
    except (OSError, loom_survey.SurveyError) as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    print(f"loom_gate: Tier-S planning baseline recorded ({state.state_hash})")
    return 0


@_locked(small=True)
def small_authorize(record, repo, wo):
    record, wo = Path(record).resolve(), Path(wo).resolve()
    findings = verify_small(record)
    if findings:
        for finding in findings:
            print(f"loom_gate: BLOCKED — {finding}", file=sys.stderr)
        return 1
    data = _load_small(record)
    if [event["event"] for event in data["events"]] != ["small-planning-started"] \
            or wo.parent != record.parent or wo.name != data.get("work_order_file"):
        print("loom_gate: REFUSED — Tier-S authorization state/WO does not match",
              file=sys.stderr)
        return 1
    try:
        fm, _, errors = _standalone_wo_contract(wo, "ready")
    except (OSError, UnicodeError) as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"loom_gate: WO — {error}", file=sys.stderr)
        return 1
    try:
        state, current_files = _stable_snapshot(repo, record.parent)
    except loom_survey.SurveyError as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    first = data["events"][0]
    if state.state_hash != first.get("repo_state_hash") \
            or current_files != data["baseline_files"]:
        print("loom_gate: BLOCKED — target changed before Tier-S authorization",
              file=sys.stderr)
        return 1
    event = make_event(
        "small-authorized", state, first["event_hash"],
        work_order=str(fm["id"]), work_order_plan_sha256=_wo_plan_hash(wo))
    data["events"].append(event)
    _atomic_write(record, data)
    print(f"loom_gate: Tier-S work order {fm['id']} authorized")
    return 0


@_locked(small=True)
def small_close(record, repo, wo):
    record, wo = Path(record).resolve(), Path(wo).resolve()
    findings = verify_small(record)
    if findings:
        for finding in findings:
            print(f"loom_gate: BLOCKED — {finding}", file=sys.stderr)
        return 1
    data = _load_small(record)
    if [event["event"] for event in data["events"]] != [
            "small-planning-started", "small-authorized"]:
        print("loom_gate: REFUSED — Tier-S work is not in authorized state", file=sys.stderr)
        return 1
    try:
        fm, _, errors = _standalone_wo_contract(wo, "done")
    except (OSError, UnicodeError) as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"loom_gate: WO — {error}", file=sys.stderr)
        return 1
    try:
        state, current = _stable_snapshot(repo, record.parent)
    except loom_survey.SurveyError as exc:
        print(f"loom_gate: INDETERMINATE — {exc}", file=sys.stderr)
        return 2
    touches = fm["touches"] if isinstance(fm["touches"], list) else [fm["touches"]]
    try:
        patterns = _touch_patterns(touches)
    except ValueError:
        print("loom_gate: REFUSED — Tier-S work order has unsafe touches", file=sys.stderr)
        return 1
    all_changed = sorted(
        path for path in set(data["baseline_files"]) | set(current)
        if data["baseline_files"].get(path) != current.get(path))
    changed = [path for path in all_changed
               if any(fnmatch.fnmatchcase(path, pattern)
                      or (pattern.endswith("/**")
                          and path.startswith(pattern[:-3].rstrip("/") + "/"))
                      for pattern in patterns)]
    outside = sorted(set(all_changed) - set(changed))
    if outside:
        shown = ", ".join(outside[:20])
        suffix = f" (+{len(outside) - 20} more)" if len(outside) > 20 else ""
        print("loom_gate: REFUSED — Tier-S changes fall outside declared touches: "
              f"{shown}{suffix}", file=sys.stderr)
        return 1
    if not changed:
        print("loom_gate: REFUSED — no declared target changed after Tier-S authorization",
              file=sys.stderr)
        return 1
    try:
        evidence = loom_lifecycle.validate_acceptance_evidence(
            record.parent, str(fm["id"]), repo, require_current=True)
    except loom_lifecycle.LifecycleError as exc:
        print(f"loom_gate: REFUSED — {exc}", file=sys.stderr)
        return 1
    previous = data["events"][-1]
    event = make_event(
        "small-completed", state, previous["event_hash"],
        work_order=str(fm["id"]), work_order_sha256=_canonical_wo_hash(wo),
        acceptance_evidence=f"evidence/{fm['id']}.json",
        acceptance_evidence_sha256=_file_hash(
            record.parent / "evidence" / f"{fm['id']}.json"),
        changed_paths=changed,
        after_hashes={path: current.get(path) for path in changed})
    data["events"].append(event)
    _atomic_write(record, data)
    print(f"loom_gate: Tier-S completion sealed ({len(changed)} changed path(s))")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Record and verify Loom lifecycle chronology")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="record planning baseline before planning")
    init.add_argument("pack")
    init.add_argument("--repo", required=True)
    init.add_argument("--mode", choices=("planned", "build-first"), default="planned")
    seal = sub.add_parser("seal-g1", help="seal a passing G1 before implementation")
    seal.add_argument("pack")
    seal.add_argument("--repo", required=True)
    seal.add_argument("--review", required=True)
    auth = sub.add_parser("authorize", help="authorize implementation after sealed G1")
    auth.add_argument("pack")
    auth.add_argument("--repo", required=True)
    close = sub.add_parser(
        "close-wo", help="bind a done work order to post-authorization changes")
    close.add_argument("pack")
    close.add_argument("--repo", required=True)
    close.add_argument("--wo", required=True)
    small_init = sub.add_parser(
        "small-init", help="record a Tier-S baseline before its standalone WO exists")
    small_init.add_argument("record")
    small_init.add_argument("--repo", required=True)
    small_init.add_argument("--wo", required=True)
    small_auth = sub.add_parser(
        "small-authorize", help="authorize a complete standalone Tier-S WO")
    small_auth.add_argument("record")
    small_auth.add_argument("--repo", required=True)
    small_auth.add_argument("--wo", required=True)
    small_done = sub.add_parser(
        "small-close", help="seal Tier-S close-out and changed-path evidence")
    small_done.add_argument("record")
    small_done.add_argument("--repo", required=True)
    small_done.add_argument("--wo", required=True)
    small_check = sub.add_parser("small-verify", help="verify a Tier-S lifecycle record")
    small_check.add_argument("record")
    check = sub.add_parser("verify", help="verify the lifecycle hash chain")
    check.add_argument("pack")
    check.add_argument("--repo")
    check.add_argument("--require-authorized", action="store_true")
    args = parser.parse_args(argv)
    finish = lambda result, _signal: result
    mutating = {
        "init", "seal-g1", "authorize", "close-wo",
        "small-init", "small-authorize", "small-close",
    }
    if args.command in mutating:
        import loom_runtime
        import loom_session
        import loom_learning
        journal = os.environ.get("LOOM_SESSION_JOURNAL")
        session_id = os.environ.get("LOOM_SESSION_ID")
        operation_id = os.environ.get("LOOM_SESSION_OPERATION_ID")
        if not journal or not session_id or not operation_id:
            print("loom_gate: BLOCKED — active Loom session identity is required",
                  file=sys.stderr)
            return 2
        try:
            identity = loom_session.validate_active_session(
                journal, session_id, operation_id)
            resolved = loom_runtime.resolve_project(
                identity["instance_id"], explicit_target=args.repo, cwd=Path.cwd())
            if resolved.project_id != identity["project_id"]:
                raise loom_session.SessionBlocked(
                    "SESSION_IDENTITY_INVALID", "session belongs to another project")
        except (loom_session.SessionError, loom_runtime.RuntimeBlocked) as exc:
            print(f"loom_gate: BLOCKED — {exc}", file=sys.stderr)
            return 2
        domain = os.environ.get("LOOM_SESSION_DOMAIN")
        if not isinstance(domain, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9._-]{0,63}", domain):
            print("loom_gate: BLOCKED — active session domain is invalid", file=sys.stderr)
            return 2

        def finish(result, signal):
            if result == 0:
                owner_home = Path(journal).parents[5]
                active_memory = (owner_home / "instances" / identity["instance_id"] /
                                 "active.json")
                if not active_memory.is_file():
                    return result
                evidence = "lifecycle-" + hashlib.sha256(
                    f"{session_id}:{args.command}".encode("utf-8")).hexdigest()[:24]
                try:
                    loom_learning.LearningEngine(
                        owner_home, identity["instance_id"]).capture(
                            kind="lifecycle-outcome", scope="project", signal=signal,
                            decision_target="verification-strategy",
                            evidence_ids=[evidence], domain=domain,
                            project_id=identity["project_id"])
                except loom_learning.LearningError as exc:
                    print(f"loom_gate: INDETERMINATE — learning capture failed: {exc}",
                          file=sys.stderr)
                    return 2
            return result
    if args.command == "init":
        return finish(start(args.pack, args.repo, args.mode), "gate-passed")
    if args.command == "seal-g1":
        return finish(seal_g1(args.pack, args.repo, args.review), "gate-passed")
    if args.command == "authorize":
        return finish(authorize(args.pack, args.repo), "gate-passed")
    if args.command == "close-wo":
        return finish(close_wo(args.pack, args.repo, args.wo), "work-order-closed")
    if args.command == "small-init":
        return finish(small_start(args.record, args.repo, args.wo), "gate-passed")
    if args.command == "small-authorize":
        return finish(small_authorize(args.record, args.repo, args.wo), "gate-passed")
    if args.command == "small-close":
        return finish(small_close(args.record, args.repo, args.wo), "work-order-closed")
    if args.command == "small-verify":
        findings = verify_small(args.record)
        for finding in findings:
            print(f"loom_gate: FINDING — {finding}")
        print(f"loom_gate: {'PASS' if not findings else 'FAIL'} — "
              f"{len(findings)} finding(s)")
        return 1 if findings else 0
    findings = verify(args.pack, args.repo, args.require_authorized)
    for finding in findings:
        print(f"loom_gate: FINDING — {finding}")
    print(f"loom_gate: {'PASS' if not findings else 'FAIL'} — "
          f"{len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
