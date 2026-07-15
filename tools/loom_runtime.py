#!/usr/bin/env python3
"""Pure preparation for Loom's one natural-language invocation surface.

This module resolves a project, reads bounded state, and returns an immutable decision object.
It deliberately owns no session, capability, journal, learning, network, or target mutation.
"""

import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import loom_domain
import loom_gate
import loom_lifecycle
import loom_lint
import loom_survey
import loom_tier


SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_FRONTIER_FILES = 2048
MAX_FRONTIER_BYTES = 16 * 1024 * 1024
MAX_HARD_STOPS = 32
MAX_DOMAINS = 16
MAX_PROJECT_CANDIDATES = 16
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PROJECT_RE = re.compile(r"^p-[0-9a-f]{32}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TARGET_ID_RE = re.compile(r"^target-sha256:[0-9a-f]{64}$")
PRIVATE_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/]|\\\\|/(?:home|users|private|tmp|var/tmp)/)")
RUNTIME_SECRET_PATTERNS = (
    *loom_lint.SECRET_PATTERNS,
    re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)"
        r"\s+(?:is|was|equals?)\s+['\"]?[^\s'\"]{6,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\."
               r"[A-Za-z0-9_-]{6,}\b"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@]+:[^\s/@]{6,}@"),
)

INTENTS = {
    "plan", "resume", "execute", "review", "repair", "close", "status",
    "remember", "forget", "why", "undo",
}
CONFIG_SOURCES = {"explicit", "repository", "owner", "builtin-safe-default"}
EFFECT_COUNT_FIELDS = {
    "target_mutation_count", "journal_mutation_count", "network_call_count",
    "contribution_count", "real_home_call_count",
}
ROUTE_FIELDS = {
    "intent", "blocked", "code", "recommendation", "evidence", "confidence",
    "needs_owner", "routine_question_count", *EFFECT_COUNT_FIELDS,
    "tier", "autonomy", "use_profile", "requires_domain_discovery",
}
WORLD_COMPONENT_FIELDS = {
    "target_survey_hash", "pack_hash", "config_hash", "lifecycle_hash",
    "capsule_version", "profile_version", "prior_session_hash",
    "staleness_bucket",
}
PREPARED_FIELDS = {
    "schema_version", "instance_id", "project_id", "invocation_id",
    "request_hash", "canonical_target_identity", "survey_hash",
    "world_fingerprint", "intent", "domains", "route_contract", "hard_stops",
    "config_source", "retry_key", "prepared_at", "prepared_hash",
}
SESSION_FIELDS = {
    "schema_version", "session_id", "instance_id", "project_id", "request_hash",
    "invocation_id", "retry_key", "world_fingerprint", "intent", "domains",
    "started_at", "updated_at", "status", "commit_phase", "route_contract",
    "selected_memory_ids", "event_ids", "operation_ids", "reversible_action_ids",
    "receipt_id", "previous_session_id",
}

BASE_HARD_STOPS = (
    "safety.no-unapproved-external-effects",
    "safety.no-irreversible-action-under-uncertainty",
    "safety.no-owner-data-cross-scope",
)

DEFAULT_CONFIG = {
    "loom_version": "builtin",
    "domain_id": "unclassified",
    "domain_ids": ["unclassified"],
    "autonomy": "A1",
    "pack_path": "plans",
    "freshness_window_days": 14,
    "auto_decide": {"min_reversibility": "HIGH", "spend_limit": 0},
    "hard_stops_extra": [],
    "routing_map": {},
    "language": "en",
    "ask_me_first": [],
    "use_profile": True,
}
CONFIG_FIELDS = set(DEFAULT_CONFIG)


class RuntimeError(ValueError):
    pass


class RuntimeBlocked(RuntimeError):
    def __init__(self, code, message):
        self.code = str(code)
        self.message = str(message)
        super().__init__(f"{self.code}: {self.message}")


def _contains_sensitive_text(value):
    return bool(PRIVATE_PATH_RE.search(value) or any(
        pattern.search(value) for pattern in RUNTIME_SECRET_PATTERNS))


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha(value):
    if isinstance(value, bytes):
        content = value
    else:
        content = str(value).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, MappingProxyType):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _canonical_uuid(value, label):
    if not isinstance(value, str):
        raise RuntimeError(f"{label} must be a canonical UUID string")
    try:
        parsed = str(uuid.UUID(value))
    except ValueError as exc:
        raise RuntimeError(f"{label} must be a canonical UUID string") from exc
    if parsed != value:
        raise RuntimeError(f"{label} must be a canonical UUID string")
    return value


def _parse_time(value):
    if isinstance(value, dt.datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeError("prepared_at must be an ISO-8601 timestamp") from exc
    else:
        raise RuntimeError("prepared_at must be an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise RuntimeError("prepared_at must include a timezone")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0)


def _format_time(value):
    return _parse_time(value).isoformat().replace("+00:00", "Z")


def _path_has_link_or_junction(path):
    absolute = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    for component in [*reversed(absolute.parents), absolute]:
        try:
            if component.is_symlink():
                return True
            is_junction = getattr(component, "is_junction", None)
            if is_junction and is_junction():
                return True
            try:
                attributes = component.lstat().st_file_attributes
            except (FileNotFoundError, AttributeError):
                continue
            if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
        except OSError as exc:
            raise RuntimeBlocked(
                "PROJECT_INDETERMINATE", f"cannot inspect target path: {exc}") from exc
    return False


def _path_from_invocation(value, invocation_cwd, label):
    """Resolve a caller-supplied path without ever consulting process cwd."""
    if value is None:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", f"{label} was not supplied")
    try:
        raw = os.fspath(value)
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE",
            f"{label} is not a valid local path: {exc}") from exc
    if isinstance(raw, bytes):
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE",
            f"{label} must be a text path")
    try:
        path = Path(raw)
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE",
            f"{label} is not a valid local path: {exc}") from exc
    if not path.is_absolute():
        if invocation_cwd is None:
            raise RuntimeBlocked(
                "PROJECT_INDETERMINATE",
                "a relative path cannot be resolved without invocation cwd")
        path = Path(invocation_cwd) / path
    return path


def _validate_invocation_cwd(cwd):
    """Validate the supplied cwd; process cwd is never an implicit fallback."""
    if cwd is None:
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            "invocation cwd is required")
    try:
        raw = os.fspath(cwd)
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            f"invocation cwd is not a valid local path: {exc}") from exc
    if isinstance(raw, bytes):
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            "invocation cwd must be a text path")
    try:
        path = Path(raw)
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            f"invocation cwd is not a valid local path: {exc}") from exc
    if not path.is_absolute():
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            "invocation cwd must be absolute")
    if _path_has_link_or_junction(path):
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            "invocation cwd traverses a symlink or junction")
    try:
        before = path.stat()
    except OSError as exc:
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            f"cannot stat invocation cwd: {exc}") from exc
    if not path.is_dir():
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            "invocation cwd is not a directory")
    try:
        with os.scandir(path) as entries:
            next(entries, None)
        after = path.stat()
    except OSError as exc:
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            f"cannot read invocation cwd: {exc}") from exc
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeBlocked(
            "missing_or_invalid_invocation_cwd",
            "invocation cwd changed during resolution")
    return path


def _validate_target(path):
    if path is None:
        raise RuntimeBlocked("PROJECT_INDETERMINATE", "no project root was supplied")
    try:
        lexical = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", f"project root is not a valid local path: {exc}") \
            from exc
    if _path_has_link_or_junction(lexical):
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", "project path traverses a symlink or junction")
    try:
        before = lexical.stat()
    except OSError as exc:
        raise RuntimeBlocked("PROJECT_UNREADABLE", f"cannot stat project root: {exc}") from exc
    if not lexical.is_dir() or not os.access(lexical, os.R_OK | os.X_OK):
        raise RuntimeBlocked("PROJECT_UNREADABLE", "project root is not a readable directory")
    try:
        after = lexical.stat()
    except OSError as exc:
        raise RuntimeBlocked("PROJECT_UNREADABLE", f"cannot restat project root: {exc}") from exc
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeBlocked("PROJECT_INDETERMINATE", "project root changed during resolution")
    return lexical


@dataclass(frozen=True)
class ProjectResolution:
    root: Path
    project_id: str
    canonical_target_identity: str
    source: str
    state_mode: str


def resolve_project(instance_id, *, explicit_target=None, cwd=None,
                    candidate_roots=None):
    """Resolve exactly one project without searching any sibling directory."""
    _canonical_uuid(instance_id, "instance_id")
    invocation_cwd = _validate_invocation_cwd(cwd)
    if explicit_target is not None:
        root = _validate_target(
            _path_from_invocation(explicit_target, invocation_cwd, "project target"))
        source = "explicit"
    elif candidate_roots is not None:
        roots = []
        for index, candidate in enumerate(candidate_roots, 1):
            if index > MAX_PROJECT_CANDIDATES:
                raise RuntimeBlocked(
                    "PROJECT_INDETERMINATE",
                    f"project candidate count exceeds {MAX_PROJECT_CANDIDATES}")
            resolved = _validate_target(
                _path_from_invocation(candidate, invocation_cwd, "project candidate"))
            if resolved not in roots:
                roots.append(resolved)
                if len(roots) > 1:
                    raise RuntimeBlocked(
                        "PROJECT_AMBIGUOUS",
                        "multiple distinct project candidates were supplied")
        if not roots:
            raise RuntimeBlocked(
                "PROJECT_INDETERMINATE", "no project candidate was supplied")
        root, source = roots[0], "candidate"
    else:
        cwd_root = invocation_cwd
        try:
            probe = loom_survey.run_git(
                cwd_root, "rev-parse", "--show-toplevel", allowed=(0, 128))
        except loom_survey.SurveyError as exc:
            raise RuntimeBlocked(
                "PROJECT_INDETERMINATE", f"cannot establish Git containment: {exc}") from exc
        if probe.returncode == 0:
            root = _validate_target(probe.stdout.strip())
            try:
                cwd_root.relative_to(root)
            except ValueError as exc:
                raise RuntimeBlocked(
                    "PROJECT_INDETERMINATE", "Git root does not contain the working directory") \
                    from exc
            source = "git-cwd"
        else:
            root, source = cwd_root, "filesystem-cwd"
    # `root` is already absolute and link-free. Avoid the legacy helper's
    # implicit Path.resolve(), which can consult ambient process cwd on Windows.
    project_id = "p-" + uuid.uuid5(
        uuid.UUID(instance_id), os.path.normcase(str(root))).hex
    identity = "target-sha256:" + _sha(os.path.normcase(str(root)))
    try:
        git_probe = loom_survey.run_git(
            root, "rev-parse", "--is-inside-work-tree", allowed=(0, 128))
    except loom_survey.SurveyError as exc:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", f"cannot establish project state mode: {exc}") from exc
    state_mode = "git" if git_probe.returncode == 0 \
        and git_probe.stdout.strip() == "true" else "filesystem"
    return ProjectResolution(root, project_id, identity, source, state_mode)


def _decision(intent, *, blocked=False, code="ROUTED", recommendation="",
              evidence=(), confidence=1.0, needs_owner=False):
    if intent not in INTENTS:
        raise RuntimeError("unsupported internal intent")
    return {
        "intent": intent,
        "blocked": bool(blocked),
        "code": str(code),
        "recommendation": str(recommendation),
        "evidence": list(evidence),
        "confidence": float(confidence),
        "needs_owner": bool(needs_owner),
        "routine_question_count": 0,
        "target_mutation_count": 0,
        "journal_mutation_count": 0,
        "network_call_count": 0,
        "contribution_count": 0,
        "real_home_call_count": 0,
        "tier": "S",
        "autonomy": "A1",
        "use_profile": True,
        "requires_domain_discovery": False,
    }


def _request_span(text, match=None):
    """Return bounded request evidence without copying a path or secret."""
    if match is None:
        span = text[:200].strip()
    else:
        span = match.group(0).strip()[:200]
    if not span:
        return "request"
    return "request-sensitive" if _contains_sensitive_text(span) else span


def _route(text, intent, match=None, *, code=None, **kwargs):
    evidence = [_request_span(text, match)]
    if match is not None:
        evidence.append(f"signal:{intent}")
    return _decision(
        intent, evidence=tuple(evidence), code=code or f"ROUTE_{intent.upper()}",
        **kwargs)


_BUILD_REQUEST_RE = re.compile(
    r"^(?:please\s+)?(?:build|create|make|implement|develop|write|design|add|generate|plan)\b")
_BUILD_CONTROL_RE = re.compile(
    r"^(?:please\s+)?(?:build|implement)\s+(?:the\s+)?(?:next|remaining|rest)\b")
_QUESTION_BUILD_RE = re.compile(
    r"^(?:please\s+)?(?:can|could|would)\s+you\s+"
    r"(?:build|create|make|implement|develop|write|design|add)\b")
_ARTIFACT_NOUN_RE = re.compile(
    r"\b(?:dashboard|page|screen|tool|app|application|service|system|pipeline|"
    r"log|report|support|feature|workflow|integration|library|utility|module|"
    r"component|adapter|program|website)\b")
_SAFETY_PREFERENCE_RE = re.compile(
    r"\b(?:do not|don't|never)(?:\s+want(?:\s+you)?\s+to)?\s+"
    r"(?:deploy|publish|delete|drop|destroy|erase|overwrite|spend|pay|purchase|"
    r"transfer|refund|charge|send|email|message|notify|post|rotate|revoke|reset|"
    r"flash|wipe)\b|"
    r"\b(?:deploy|publish|delete|drop|destroy|erase|overwrite|spend|pay|purchase|"
    r"transfer|refund|charge|send|email|message|notify|post|rotate|revoke|reset|"
    r"flash|wipe)\s+nothing\b")
_HIGH_CONSEQUENCE_RE = re.compile(
    r"^(?:please\s+)?(?:deploy|publish|release|ship|delete|drop|destroy|erase|"
    r"overwrite|spend|pay|purchase|transfer|refund|charge|send|email|message|"
    r"notify|post|rotate|revoke|reset|flash|wipe)\b"
    r"|\b(?:and|then)\s+(?:deploy|publish|release|ship|delete|drop|destroy|"
    r"erase|overwrite|spend|pay|purchase|transfer|refund|charge|send|email|"
    r"message|notify|post|rotate|revoke|reset|flash|wipe)\b"
    r"|\b(?:force[- ]push|reset\s+--hard|clean\s+-fdx|rewrite\s+(?:the\s+)?"
    r"(?:git\s+)?history|wipe\s+(?:the\s+)?(?:disk|drive|database))\b")


def _is_build_request(text):
    if _BUILD_CONTROL_RE.search(text):
        return False
    if _BUILD_REQUEST_RE.search(text) or _QUESTION_BUILD_RE.search(text):
        return True
    return bool(
        re.search(r"^(?:please\s+)?(?:i|we)\s+(?:need|want)\b", text)
        and _ARTIFACT_NOUN_RE.search(text))


def _high_consequence_match(text):
    match = _HIGH_CONSEQUENCE_RE.search(text)
    if match is None:
        return None
    # A product noun such as "deploy tool" is a plan request, not an effect.
    if _is_build_request(text) and not re.search(
            r"\b(?:and|then)\s+(?:deploy|publish|release|ship|delete|drop|destroy|"
            r"erase|overwrite|spend|pay|purchase|transfer|refund|charge|send|email|"
            r"message|notify|post|rotate|revoke|reset|flash|wipe)\b", text):
        return None
    return match


def resolve_intent(request, state=None):
    """Resolve natural language plus lifecycle state; ambiguity returns one checkpoint."""
    if not isinstance(request, str) or not request.strip():
        raise RuntimeError("request must be non-empty natural language")
    state = dict(state or {})
    text = " ".join(request.casefold().split())
    safety_preference = _SAFETY_PREFERENCE_RE.search(text)
    remember_wrapper = bool(re.search(r"\bremember(?:\s+that|\s+this)?\b", text))
    negated_forget = re.search(
        r"\b(?:do not|don't|never)(?:\s+want(?:\s+you)?\s+to)?\s+forget\b|"
        r"\bforget\s+(?:nothing|none\b|anything)\b", text)
    if negated_forget:
        return _decision(
            "status", blocked=True, code="INTENT_NEGATED", needs_owner=True,
            confidence=0.0,
            evidence=("negated-forget", _request_span(text, negated_forget)),
            recommendation="Keep remembered state unchanged; state what should be retained.")
    negated_memory = bool(re.search(
        r"\b(?:do not|don't|never)\s+remember(?:\s+that)?\b", text))
    build_request = _is_build_request(text)
    profile_query = bool(re.search(
        r"\bshow (?:me )?what you remember about me\b|"
        r"\bwhat do you remember about me\b|\bshow my remembered preferences\b",
        text))
    explicit_forget = bool(re.search(r"\bforget\b|\bstop remembering\b", text)) \
        and not build_request
    explicit_remember = bool(re.search(
        r"\bremember(?: that| this)?\b|\bbe more careful\b|\bfrom now on\b|\bprefer\b|"
        r"\bbe less autonomous\b",
        text)) and not build_request and not profile_query
    memory_direct = None
    if profile_query:
        memory_direct = "status"
    elif negated_memory or explicit_forget:
        memory_direct = "forget"
    elif explicit_remember or (safety_preference and not build_request):
        memory_direct = "remember"
    secondary_action = re.search(
        r"(?:[,;]|\bthen\b|\band\b)\s*(?:please\s+)?(?:continue|keep going|"
        r"build|implement|review|inspect|audit|close|finish|repair|fix|undo)\b",
        text)
    if memory_direct is not None and secondary_action:
        return _decision(
            "status", blocked=True, code="INTENT_AMBIGUOUS", needs_owner=True,
            confidence=0.0, evidence=("multiple-requested-outcomes",),
            recommendation=(
                "Record or forget the preference first; pursue the separate action next."))
    lifecycle_negation = re.search(
        r"\b(?:do not|don't|never)\s+(?:close|continue|keep going|build|review|"
        r"inspect|forget|remember|undo)\b",
        text)
    if lifecycle_negation and memory_direct is None:
        return _decision(
            "status", blocked=True, code="INTENT_NEGATED", needs_owner=True,
            confidence=0.0, evidence=("negated-action",),
            recommendation=(
                "Keep state unchanged; state the positive outcome you want Loom to pursue."))
    if memory_direct is not None:
        signals = {name: name == memory_direct for name in (
            "remember", "forget", "why", "undo", "status", "review", "repair",
            "close", "continue")}
        memory_match = re.search(
            r"\b(?:remember|forget|stop remembering)\b|\bbe more careful\b|"
            r"\bfrom now on\b|\bprefer\b|\bshow (?:me )?what you remember\b", text)
        decision = _route(text, memory_direct, memory_match)
    else:
        signals = {
            "remember": False,
            "forget": False,
            "why": bool(re.search(r"\bwhy (?:did|do|was)\b|\bexplain why\b", text)),
            "undo": bool(re.search(r"\bundo\b|\btake back\b|\breverse (?:the )?last", text)),
            "status": bool(re.search(
                r"\bshow me where\b|\bwhere are we\b|\bwhat has happened\b|"
                r"\bshow (?:me )?the progress\b|\bwhat(?:'s| is) the status\b|"
                r"\bprogress\b|\bstatus\b", text)),
            "review": bool(re.search(r"\breview\b|\binspect\b|\baudit\b", text)),
            "repair": bool(re.search(
                r"\brepair\b|\bfix (?:the )?(?:stale |broken )?plan\b|"
                r"\bstale plan\b", text)),
            "close": bool(re.search(
                r"\bwe are done\b|\bclose this\b|\bproject is over\b|"
                r"\bfinish the project\b", text)),
            "continue": bool(re.search(
                r"\bcontinue\b|\bkeep going\b|\bresume\b|\bpick up\b|\bcarry on\b|"
                r"\bbuild the next\b|\bnext part\b", text)),
        }
    if build_request:
        # Product nouns such as review, status, audit, repair, undo, and forget
        # are not control commands when the sentence explicitly asks to build them.
        decision = _route(text, "plan", _BUILD_REQUEST_RE.search(text))
    else:
        direct = [name for name in (
            "remember", "forget", "why", "undo", "status", "review", "repair", "close")
                  if signals[name]]
        ambiguous = len(direct) > 1 \
            or (signals["close"] and signals["continue"])
        if ambiguous:
            return _decision(
                "status", blocked=True, code="INTENT_AMBIGUOUS", needs_owner=True,
                confidence=0.0,
                evidence=("conflicting-language", _request_span(text)),
                recommendation="Choose the recommended safe branch: inspect current state first.")
        if direct:
            intent = direct[0]
            match = re.search(
                r"\b(?:why|undo|take back|reverse|show me where|where are we|status|"
                r"review|inspect|audit|repair|fix|close|done|over)\b", text)
            decision = _route(text, intent, match)
        elif signals["continue"]:
            match = re.search(
                r"\b(?:continue|keep going|resume|pick up|carry on|build the next|"
                r"next part)\b", text)
            if state.get("drift") or state.get("failed"):
                intent = "repair"
            elif state.get("terminal"):
                intent = "close"
            elif state.get("pack_exists") and state.get("authorized") \
                    and state.get("active_frontier"):
                intent = "execute"
            elif state.get("pack_exists"):
                intent = "resume"
            else:
                intent = "plan"
            decision = _route(text, intent, match)
        elif (re.search(r"^(?:please\s+)?(?:i|we)\s+(?:need|want)\b", text)
              and _ARTIFACT_NOUN_RE.search(text)):
            decision = _route(text, "plan", _ARTIFACT_NOUN_RE.search(text))
        else:
            intent = "repair" if state.get("drift") or state.get("failed") else "plan"
            decision = _route(text, intent, None)
    high_consequence = _high_consequence_match(text)
    if high_consequence and memory_direct is None:
        decision.update({
            "blocked": True,
            "code": "HIGH_CONSEQUENCE_UNCERTAIN",
            "needs_owner": True,
            "confidence": 0.0,
            "recommendation": (
                "Keep the change staged only; confirm scope, verification, and rollback "
                "before any irreversible action."),
            "evidence": ["high-consequence", _request_span(text, high_consequence)],
        })
    return decision


def compose_world_fingerprint(components):
    if not isinstance(components, dict) \
            or set(components) != WORLD_COMPONENT_FIELDS:
        raise RuntimeError("world component fields are unknown or missing")
    bucket = components.get("staleness_bucket")
    if isinstance(bucket, bool) or not isinstance(bucket, int) or bucket < 0:
        raise RuntimeError("staleness_bucket must be a non-negative integer")
    if any(not isinstance(components[key], str) or not components[key]
           for key in WORLD_COMPONENT_FIELDS - {"staleness_bucket"}):
        raise RuntimeError("world components must be non-empty strings")
    return _sha(_canonical_json(components))


def _validate_route(route):
    if not isinstance(route, dict) or set(route) != ROUTE_FIELDS:
        raise RuntimeError("route contract fields are unknown or missing")
    if route.get("intent") not in INTENTS:
        raise RuntimeError("route intent is invalid")
    for field in ("blocked", "needs_owner", "use_profile",
                  "requires_domain_discovery"):
        if type(route.get(field)) is not bool:
            raise RuntimeError(f"route {field} must be boolean")
    if type(route.get("routine_question_count")) is not int \
            or route["routine_question_count"] != 0:
        raise RuntimeError("pure prepared route cannot ask a routine question")
    for field in EFFECT_COUNT_FIELDS:
        if type(route.get(field)) is not int or route[field] != 0:
            raise RuntimeError("pure prepared route cannot claim a side effect")
    if route.get("tier") not in {"S", "M", "L"} \
            or route.get("autonomy") not in {"A0", "A1", "A2", "A3"}:
        raise RuntimeError("route tier/autonomy is invalid")
    if not isinstance(route.get("recommendation"), str) \
            or len(route["recommendation"]) > 1000 \
            or not isinstance(route.get("code"), str) or not route["code"] \
            or not isinstance(route.get("evidence"), list) \
            or len(route["evidence"]) > 16 \
            or not all(isinstance(item, str) and len(item) <= 200
                       for item in route["evidence"]):
        raise RuntimeError("route text/evidence is invalid")
    if route["blocked"] and (not route["needs_owner"]
                              or not route["recommendation"].strip()):
        raise RuntimeError("blocked route requires one owner recommendation")
    confidence = route.get("confidence")
    if type(confidence) not in (int, float) or not math.isfinite(confidence) \
            or not 0 <= confidence <= 1:
        raise RuntimeError("route confidence must be in [0, 1]")


@dataclass(frozen=True)
class PreparedInvocation:
    schema_version: int
    instance_id: str
    project_id: str
    invocation_id: str
    request_hash: str
    canonical_target_identity: str
    survey_hash: str
    world_fingerprint: str
    intent: str
    domains: tuple
    route_contract: MappingProxyType
    hard_stops: tuple
    config_source: str
    retry_key: str
    prepared_at: str
    prepared_hash: str

    def to_dict(self):
        return {
            field: _thaw(getattr(self, field))
            for field in PREPARED_FIELDS
        }

    @classmethod
    def build(cls, **values):
        if "prepared_hash" in values:
            raise RuntimeError("prepared_hash is computed, not caller supplied")
        expected = PREPARED_FIELDS - {"prepared_hash"}
        if set(values) != expected:
            raise RuntimeError("prepared invocation fields are unknown or missing")
        data = dict(values)
        data["domains"] = list(data["domains"])
        data["route_contract"] = _thaw(data["route_contract"])
        data["hard_stops"] = list(data["hard_stops"])
        data["prepared_hash"] = _sha(_canonical_json(data))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != PREPARED_FIELDS:
            raise RuntimeError("prepared invocation fields are unknown or missing")
        try:
            data = json.loads(json.dumps(value, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"prepared invocation is not strict JSON: {exc}") from exc
        if type(data.get("schema_version")) is not int \
                or data["schema_version"] != SCHEMA_VERSION:
            raise RuntimeError("prepared schema_version is invalid")
        _canonical_uuid(data.get("instance_id"), "instance_id")
        _canonical_uuid(data.get("invocation_id"), "invocation_id")
        if not isinstance(data.get("project_id"), str) \
                or not PROJECT_RE.fullmatch(data["project_id"]):
            raise RuntimeError("project_id is invalid")
        for field in ("request_hash", "survey_hash", "world_fingerprint", "retry_key",
                      "prepared_hash"):
            if not isinstance(data.get(field), str) or not DIGEST_RE.fullmatch(data[field]):
                raise RuntimeError(f"{field} is invalid")
        if not isinstance(data.get("canonical_target_identity"), str) \
                or not TARGET_ID_RE.fullmatch(data["canonical_target_identity"]):
            raise RuntimeError("canonical_target_identity is invalid")
        if data.get("intent") not in INTENTS:
            raise RuntimeError("prepared intent is invalid")
        domains = data.get("domains")
        if not isinstance(domains, list) or not domains or len(domains) > MAX_DOMAINS \
                or not all(isinstance(item, str) and ID_RE.fullmatch(item)
                           for item in domains) \
                or len(set(domains)) != len(domains):
            raise RuntimeError("prepared domains are invalid")
        _validate_route(data.get("route_contract"))
        if data["route_contract"]["intent"] != data["intent"]:
            raise RuntimeError("prepared intent/route mismatch")
        stops = data.get("hard_stops")
        if not isinstance(stops, list) or len(stops) > MAX_HARD_STOPS or not all(
                isinstance(item, str) and item.strip() and len(item) <= 1000 for item in stops):
            raise RuntimeError("prepared hard stops are invalid")
        if stops != list(BASE_HARD_STOPS):
            raise RuntimeError(
                "prepared hard stops must contain the exact mandatory safety floor")
        if data.get("config_source") not in CONFIG_SOURCES:
            raise RuntimeError("prepared config_source is invalid")
        expected_retry = _sha(_canonical_json({
            "invocation_id": data["invocation_id"],
            "project_id": data["project_id"],
            "request_hash": data["request_hash"],
        }))
        if data["retry_key"] != expected_retry:
            raise RuntimeError("retry_key does not match invocation/project/request identity")
        data["prepared_at"] = _format_time(data.get("prepared_at"))
        claimed = data.pop("prepared_hash")
        expected = _sha(_canonical_json(data))
        if claimed != expected:
            raise RuntimeError("prepared_hash does not match the exact object")
        data["prepared_hash"] = claimed
        data["domains"] = tuple(data["domains"])
        data["route_contract"] = _freeze(data["route_contract"])
        data["hard_stops"] = tuple(data["hard_stops"])
        return cls(**data)


def _bounded_read(path, limit, label):
    path = Path(path)
    if _path_has_link_or_junction(path):
        raise RuntimeError(f"{label} must not traverse a symlink or junction")
    try:
        if not path.is_file():
            raise RuntimeError(f"{label} is not a regular file")
        size = path.stat().st_size
        if size > limit:
            raise RuntimeError(f"{label} exceeds its {limit}-byte bound")
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
    except OSError as exc:
        raise RuntimeError(f"cannot read {label}: {exc}") from exc
    if len(content) > limit:
        raise RuntimeError(f"{label} changed above its {limit}-byte bound")
    return content


def _digest_field(digest, label, value):
    label = bytes(label)
    value = bytes(value)
    digest.update(len(label).to_bytes(2, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _state_version(label, state, content=b""):
    digest = hashlib.sha256(b"loom-owner-state-version-v2\0")
    _digest_field(digest, b"label", str(label).encode("utf-8"))
    _digest_field(digest, b"state", str(state).encode("ascii"))
    if state == "present":
        _digest_field(digest, b"content", content)
    elif content:
        raise RuntimeError("non-present state version cannot carry content")
    return digest.hexdigest()


def _state_file_version(path, label, limit=MAX_FRONTIER_BYTES):
    path = Path(path)
    if _path_has_link_or_junction(path):
        raise RuntimeError(f"{label} must not traverse a symlink or junction")
    if not path.exists():
        return _state_version(label, "absent")
    return _state_version(
        label, "present", _bounded_read(path, limit, label))


def _validate_config(value):
    if not isinstance(value, dict) or set(value) != CONFIG_FIELDS:
        raise RuntimeError("config has unknown/missing fields")
    if not isinstance(value["loom_version"], str) or not value["loom_version"]:
        raise RuntimeError("config loom_version is invalid")
    domain_id, domain_ids = value["domain_id"], value["domain_ids"]
    if not isinstance(domain_id, str) or not ID_RE.fullmatch(domain_id) \
            or not isinstance(domain_ids, list) or not domain_ids \
            or not all(isinstance(item, str) and ID_RE.fullmatch(item)
                       for item in domain_ids) \
            or domain_ids[0] != domain_id or len(set(domain_ids)) != len(domain_ids):
        raise RuntimeError("config domain identifiers are invalid")
    if value["autonomy"] not in {"A0", "A1", "A2", "A3"} \
            or type(value["use_profile"]) is not bool:
        raise RuntimeError("config autonomy/profile setting is invalid")
    pack_path = value["pack_path"]
    if not isinstance(pack_path, str) or not pack_path.strip() \
            or Path(pack_path).is_absolute() or Path(pack_path).as_posix() in {"", "."} \
            or ".." in Path(pack_path).parts:
        raise RuntimeError("config pack_path must be a safe relative path")
    freshness = value["freshness_window_days"]
    if type(freshness) is not int or not 1 <= freshness <= 3650:
        raise RuntimeError("config freshness_window_days is invalid")
    auto = value["auto_decide"]
    if not isinstance(auto, dict) or set(auto) != {"min_reversibility", "spend_limit"} \
            or auto["min_reversibility"] not in {"MED", "HIGH"} \
            or type(auto["spend_limit"]) not in (int, float) \
            or not math.isfinite(auto["spend_limit"]) or auto["spend_limit"] < 0:
        raise RuntimeError("config auto_decide is invalid")
    for field in ("hard_stops_extra", "ask_me_first"):
        values = value[field]
        field_cap = (MAX_HARD_STOPS - len(BASE_HARD_STOPS)
                     if field == "hard_stops_extra" else MAX_HARD_STOPS)
        if not isinstance(values, list) or len(values) > field_cap or not all(
                isinstance(item, str) and item.strip() and len(item) <= 1000
                for item in values):
            raise RuntimeError(f"config {field} is invalid")
        if field == "hard_stops_extra" and any(
                _contains_sensitive_text(item) for item in values):
            raise RuntimeError("config hard stops contain a raw path or secret-shaped value")
    routing = value["routing_map"]
    allowed_routes = {"frontier-reasoning", "strong-coding", "fast-cheap",
                      "specialist", "human"}
    if not isinstance(routing, dict) or not set(routing) <= allowed_routes \
            or not all(isinstance(item, str) and item for item in routing.values()):
        raise RuntimeError("config routing_map is invalid")
    if not isinstance(value["language"], str) or not value["language"].strip():
        raise RuntimeError("config language is invalid")
    return json.loads(json.dumps(value))


def _load_config(root, explicit_config, owner_home):
    candidates = []
    if explicit_config is not None:
        try:
            raw = _canonical_json(explicit_config)
        except (TypeError, ValueError) as exc:
            raw = repr(explicit_config).encode("utf-8", errors="replace")
            error = f"config is not JSON-compatible: {exc}"
            return dict(DEFAULT_CONFIG), "explicit", _sha(raw), error
        if len(raw) > MAX_CONFIG_BYTES:
            return dict(DEFAULT_CONFIG), "explicit", _sha(raw), \
                f"explicit config exceeds its {MAX_CONFIG_BYTES}-byte bound"
        candidates.append(("explicit", raw))
    else:
        repo_config = root / "loom.config.json"
        if repo_config.exists() or repo_config.is_symlink():
            try:
                candidates.append((
                    "repository", _bounded_read(repo_config, MAX_CONFIG_BYTES, "repository config")))
            except RuntimeError as exc:
                return dict(DEFAULT_CONFIG), "repository", _sha(str(exc)), str(exc)
        elif owner_home is not None:
            owner_config = Path(owner_home) / "loom.config.json"
            if owner_config.exists() or owner_config.is_symlink():
                try:
                    candidates.append((
                        "owner", _bounded_read(owner_config, MAX_CONFIG_BYTES, "owner config")))
                except RuntimeError as exc:
                    return dict(DEFAULT_CONFIG), "owner", _sha(str(exc)), str(exc)
    if not candidates:
        value = json.loads(json.dumps(DEFAULT_CONFIG))
        return value, "builtin-safe-default", _sha(_canonical_json(value)), None
    source, raw = candidates[0]
    try:
        value = json.loads(raw.decode("utf-8"))
        value = _validate_config(value)
    except (UnicodeError, json.JSONDecodeError, RuntimeError) as exc:
        return json.loads(json.dumps(DEFAULT_CONFIG)), source, _sha(raw), str(exc)
    return value, source, _sha(raw), None


def _hash_frontier(path, *, lifecycle_only=False):
    path = Path(path)
    if _path_has_link_or_junction(path):
        raise RuntimeError("pack frontier must not traverse a symlink or junction")
    if not path.exists():
        return _sha(b"absent")
    if not path.is_dir():
        raise RuntimeError("pack frontier is not a directory")
    names = {"lifecycle.json", ".loom-lifecycle.json", "MANIFEST.md", "manifest.md"}
    candidates, stack, entries = [], [path], 0
    while stack:
        directory = stack.pop()
        try:
            children = sorted(directory.iterdir())
        except OSError as exc:
            raise RuntimeError(f"cannot enumerate pack frontier: {exc}") from exc
        for item in children:
            entries += 1
            if entries > MAX_FRONTIER_FILES:
                raise RuntimeError("pack frontier exceeds its entry bound")
            if _path_has_link_or_junction(item):
                raise RuntimeError("pack frontier contains a symlink or junction")
            if item.is_dir():
                stack.append(item)
            elif item.is_file() and (not lifecycle_only or item.name in names):
                candidates.append(item)
            elif not item.is_file():
                raise RuntimeError(
                    f"pack frontier contains unsupported special entry: {item.name}")
    candidates.sort(key=lambda item: os.fsencode(item.relative_to(path)))
    digest = hashlib.sha256(b"loom-pack-frontier-v2\0")
    digest.update(len(candidates).to_bytes(8, "big"))
    total = 0
    for item in candidates:
        relative = item.relative_to(path).as_posix()
        content = _bounded_read(item, MAX_FRONTIER_BYTES, "pack frontier file")
        total += len(content)
        if total > MAX_FRONTIER_BYTES:
            raise RuntimeError("pack frontier exceeds its byte bound")
        try:
            info = item.lstat()
        except OSError as exc:
            raise RuntimeError(f"cannot inspect pack frontier file: {exc}") from exc
        entry = hashlib.sha256(b"loom-pack-frontier-entry-v1\0")
        _digest_field(entry, b"path", os.fsencode(relative))
        _digest_field(entry, b"kind", b"file")
        _digest_field(
            entry, b"mode", f"{stat.S_IMODE(info.st_mode):o}".encode("ascii"))
        _digest_field(entry, b"content", content)
        digest.update(entry.digest())
    return digest.hexdigest()


def _inspect_small_lifecycle(pack, lifecycle_repo_hash, today):
    pack = Path(pack)
    record = pack / ".loom-small-lifecycle.json"
    work_order = pack / "WO-001.md"
    if not record.exists() and not work_order.exists():
        return None
    invalid = {
        "pack_exists": True, "authorized": False, "active_frontier": False,
        "terminal": False, "drift": False, "failed": True,
        "state_error": "INVALID_LIFECYCLE",
    }
    if not record.is_file() or record.is_symlink() \
            or not work_order.is_file() or work_order.is_symlink():
        return invalid
    findings = loom_gate.verify_small(record)
    if findings:
        return invalid
    try:
        data = json.loads(_bounded_read(
            record, MAX_CONFIG_BYTES, "Tier-S lifecycle").decode("utf-8"))
        frontmatter, _ = loom_lint.parse_frontmatter(
            _bounded_read(
                work_order, MAX_CONFIG_BYTES, "Tier-S work order").decode("utf-8"))
        names = [event["event"] for event in data["events"]]
        status = str((frontmatter or {}).get("status", ""))
        checkpoint = data["events"][-1]
        route = data["route_contract"]
        verified = dt.date.fromisoformat(route["last_verified"])
        current = today or dt.datetime.now(dt.timezone.utc).date()
    except (OSError, UnicodeError, KeyError, TypeError, ValueError,
            json.JSONDecodeError):
        return invalid
    authorized = names == ["small-planning-started", "small-authorized"]
    terminal = names == [
        "small-planning-started", "small-authorized", "small-completed"]
    if checkpoint.get("repo_state_hash") != lifecycle_repo_hash:
        return {
            "pack_exists": True, "authorized": False,
            "active_frontier": False, "terminal": False,
            "drift": True, "failed": False,
            "state_error": "STALE_LIFECYCLE",
        }
    result = {
        "pack_exists": True,
        "authorized": authorized,
        "active_frontier": authorized and status in {"ready", "in-progress"},
        "terminal": terminal and status == "done",
        "drift": False,
        "failed": False,
    }
    if verified > current:
        return invalid
    if authorized and (current - verified).days > route["freshness_window_days"]:
        result.update({
            "authorized": False, "active_frontier": False,
            "drift": True, "state_error": "STALE_TIME",
        })
    return result


def _inspect_lifecycle(pack, lifecycle_repo_hash, *, today=None):
    pack = Path(pack)
    if _path_has_link_or_junction(pack):
        raise RuntimeError("pack lifecycle must not traverse a symlink or junction")
    small = _inspect_small_lifecycle(pack, lifecycle_repo_hash, today)
    if small is not None:
        return small
    work_orders = pack / "work-orders"
    statuses = []
    work_order_ids = set()
    if _path_has_link_or_junction(work_orders):
        raise RuntimeError("work-order frontier must not traverse a symlink or junction")
    if work_orders.is_dir():
        try:
            candidates = []
            entry_count = 0
            for path in work_orders.iterdir():
                entry_count += 1
                if entry_count > MAX_FRONTIER_FILES:
                    raise RuntimeError("work-order frontier exceeds its entry bound")
                if _path_has_link_or_junction(path):
                    raise RuntimeError("work-order frontier contains a symlink or junction")
                if path.is_file() and re.fullmatch(r"WO-.*\.md", path.name):
                    candidates.append(path)
                elif not path.is_file() and not path.is_dir():
                    raise RuntimeError(
                        f"work-order frontier contains unsupported special entry: {path.name}")
        except OSError as exc:
            raise RuntimeError(f"cannot enumerate work-order frontier: {exc}") from exc
        for path in sorted(candidates):
            try:
                text = _bounded_read(path, 256 * 1024, "work order").decode("utf-8")
            except UnicodeError as exc:
                raise RuntimeError(f"work order is not UTF-8: {exc}") from exc
            frontmatter, _ = loom_lint.parse_frontmatter(text)
            report = loom_lint.Report()
            if frontmatter is not None:
                loom_lint.validate_schema(
                    report, path, frontmatter, "work-order.schema.json")
            work_order_id = str((frontmatter or {}).get("id", ""))
            valid = frontmatter is not None and not report.errors \
                and loom_lint.WO_ID_RE.fullmatch(work_order_id) \
                and path.name.startswith(work_order_id) \
                and work_order_id not in work_order_ids
            if valid:
                work_order_ids.add(work_order_id)
                statuses.append(str(frontmatter["status"]))
            else:
                statuses.append("invalid")
    authorized = False
    lifecycle = pack / loom_gate.LIFECYCLE_FILE
    if _path_has_link_or_junction(lifecycle):
        raise RuntimeError("lifecycle state must not traverse a symlink or junction")
    exists = pack.is_dir() and (bool(statuses)
                                or (pack / "MANIFEST.md").is_file()
                                or (pack / "manifest.md").is_file())
    if exists and not lifecycle.is_file():
        return {
            "pack_exists": True, "authorized": False,
            "active_frontier": False, "terminal": False,
            "drift": False, "failed": True,
            "state_error": "INVALID_LIFECYCLE",
        }
    if lifecycle.is_file():
        try:
            findings = loom_gate.verify(pack, repo=None)
            if findings:
                raise RuntimeError("; ".join(findings[:5]))
            value = json.loads(_bounded_read(
                lifecycle, MAX_CONFIG_BYTES, "lifecycle state").decode("utf-8"))
            events = value["events"]
            authorized = [item["event"] for item in events] == loom_gate.EVENT_ORDER
            completions = value["work_order_completions"]
            checkpoint = completions[-1] if completions else events[-1]
            if checkpoint.get("repo_state_hash") != lifecycle_repo_hash:
                receipt = loom_lifecycle.validate_regate_receipt(
                    pack, lifecycle_repo_hash, checkpoint.get("repo_state_hash"))
                if receipt is not None:
                    return {
                        "pack_exists": True, "authorized": authorized,
                        "active_frontier": any(
                            item in {"ready", "in-progress"} for item in statuses),
                        "terminal": bool(statuses) and all(
                            item == "done" for item in statuses),
                        "drift": False,
                        "failed": any(item == "invalid" for item in statuses),
                        "regated": True,
                        "regate_scope": receipt["regate_scope"],
                        "affected_plan_sections": receipt[
                            "affected_plan_sections"],
                    }
                return {
                    "pack_exists": True, "authorized": False,
                    "active_frontier": False, "terminal": False,
                    "drift": True, "failed": False,
                    "state_error": "STALE_LIFECYCLE",
                }
        except (UnicodeError, json.JSONDecodeError, RuntimeError):
            return {
                "pack_exists": True, "authorized": False,
                "active_frontier": False, "terminal": False,
                "drift": False, "failed": True,
                "state_error": "INVALID_LIFECYCLE",
            }
    result = {
        "pack_exists": exists,
        "authorized": authorized,
        "active_frontier": any(item in {"ready", "in-progress"} for item in statuses),
        "terminal": bool(statuses) and all(item == "done" for item in statuses),
        "drift": False,
        "failed": any(item == "invalid" for item in statuses),
    }
    if result["failed"]:
        result["state_error"] = "INVALID_LIFECYCLE"
    if authorized and not result["failed"]:
        manifest = pack / "MANIFEST.md"
        try:
            frontmatter, _ = loom_lint.parse_frontmatter(
                _bounded_read(
                    manifest, MAX_CONFIG_BYTES,
                    "planning-pack manifest").decode("utf-8"))
            verified = dt.date.fromisoformat(str((frontmatter or {})["last_verified"]))
            window = int((frontmatter or {})["freshness_window_days"])
            current = today or dt.datetime.now(dt.timezone.utc).date()
            if verified > current:
                raise ValueError("manifest last_verified is in the future")
            if (current - verified).days > window:
                result.update({
                    "authorized": False,
                    "active_frontier": False,
                    "terminal": False,
                    "drift": True,
                    "state_error": "STALE_TIME",
                })
        except (OSError, UnicodeError, KeyError, TypeError, ValueError):
            result.update({
                "authorized": False,
                "active_frontier": False,
                "terminal": False,
                "failed": True,
                "state_error": "INVALID_LIFECYCLE",
            })
    return result


def _pack_route_contract(pack, state):
    """Read the validated route identity owned by an existing planning pack."""
    if not state.get("pack_exists") or state.get("state_error") not in {
            None, "STALE_LIFECYCLE", "STALE_TIME"}:
        return None
    pack = Path(pack)
    manifest = pack / "MANIFEST.md"
    if not manifest.is_file():
        record = pack / ".loom-small-lifecycle.json"
        if not record.is_file() or _path_has_link_or_junction(record):
            return None
        try:
            data = json.loads(_bounded_read(
                record, MAX_CONFIG_BYTES, "Tier-S lifecycle").decode("utf-8"))
            route = data["route_contract"]
            domains = route["domain_ids"]
        except (OSError, UnicodeError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Tier-S route identity is unreadable: {exc}") from exc
        if route.get("tier") != "S" or not isinstance(domains, list) \
                or not domains or len(domains) > MAX_DOMAINS \
                or len(domains) != len(set(domains)) \
                or not all(isinstance(item, str) and ID_RE.fullmatch(item)
                           for item in domains):
            raise RuntimeError("Tier-S route identity is invalid")
        return {"tier": "S", "domains": domains}
    if _path_has_link_or_junction(manifest):
        return None
    try:
        text = _bounded_read(
            manifest, MAX_CONFIG_BYTES, "planning-pack manifest").decode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError(f"planning-pack manifest is not UTF-8: {exc}") from exc
    frontmatter, _ = loom_lint.parse_frontmatter(text)
    report = loom_lint.Report()
    if frontmatter is not None:
        loom_lint.validate_schema(
            report, manifest, frontmatter, "manifest.schema.json")
    tier = (frontmatter or {}).get("tier")
    domains = (frontmatter or {}).get("domain_ids")
    if frontmatter is None or report.errors or tier not in {"M", "L"} \
            or not isinstance(domains, list) or not domains \
            or len(domains) > MAX_DOMAINS \
            or len(domains) != len(set(domains)) \
            or not all(isinstance(item, str) and ID_RE.fullmatch(item)
                       for item in domains):
        raise RuntimeError(
            "authorized planning-pack route identity is missing or invalid")
    return {"tier": tier, "domains": domains}


def _canonical_owner_root(owner_home, invocation_cwd=None):
    if owner_home is None:
        return None
    try:
        root = _path_from_invocation(
            os.path.expanduser(os.fspath(owner_home)), invocation_cwd, "owner home")
    except (TypeError, ValueError, OSError) as exc:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", f"owner home is not a valid local path: {exc}") \
            from exc
    if _path_has_link_or_junction(root):
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", "owner home traverses a symlink or junction")
    return root


def _owner_state_versions(owner_root, instance_id, project_id, use_profile):
    """Hash only the bounded owner-local state relevant to this project."""
    if owner_root is None:
        return {
            "capsule_version": _state_version(
                "context capsule state", "home-not-supplied"),
            "profile_version": _state_version(
                "profile state", "home-not-supplied"),
            "prior_session_hash": _state_version(
                "prior session state", "home-not-supplied"),
        }
    instance_root = owner_root / "instances" / instance_id
    project_runtime = instance_root / "runtime" / "projects" / project_id
    return {
        "capsule_version": _state_file_version(
            project_runtime / "capsule.json", "context capsule state", MAX_CONFIG_BYTES),
        "profile_version": (
            _state_file_version(
                instance_root / "active.json", "profile state", MAX_CONFIG_BYTES)
            if use_profile else _state_version("profile state", "disabled")),
        "prior_session_hash": _state_file_version(
            project_runtime / "runtime.json", "prior session state", MAX_CONFIG_BYTES),
    }


def _observe_world(project, pack, config, config_hash, owner_root, instance_id,
                   prepared_time=None):
    """Read one complete preparation snapshot through owned bounded primitives."""
    pack_rel = pack.relative_to(project.root).as_posix()
    repo_state = loom_survey.repo_state(
        project.root, exclude_prefixes=(pack_rel,))
    state = _inspect_lifecycle(
        pack, repo_state.state_hash,
        today=(prepared_time.date() if prepared_time is not None else None))
    components = {
        "target_survey_hash": repo_state.state_hash,
        "pack_hash": _hash_frontier(pack),
        "config_hash": config_hash,
        "lifecycle_hash": _hash_frontier(pack, lifecycle_only=True),
        **_owner_state_versions(
            owner_root, instance_id, project.project_id, config["use_profile"]),
    }
    return repo_state, state, components


def prepare_invocation(request, *, instance_id, invocation_id, cwd=None,
                       explicit_target=None, candidate_roots=None,
                       explicit_config=None, owner_home=None, now=None):
    """Return one immutable, non-authorizing PreparedInvocation."""
    _canonical_uuid(instance_id, "instance_id")
    _canonical_uuid(invocation_id, "invocation_id")
    if not isinstance(request, str) or not request.strip() or len(request) > 20_000:
        raise RuntimeError("request must be 1..20000 characters of natural language")
    prepared_time = _parse_time(now or dt.datetime.now(dt.timezone.utc))
    invocation_cwd = _validate_invocation_cwd(cwd)
    project = resolve_project(
        instance_id, explicit_target=explicit_target, cwd=invocation_cwd,
        candidate_roots=candidate_roots)
    owner_root = _canonical_owner_root(owner_home, invocation_cwd)
    config, config_source, config_hash, config_error = _load_config(
        project.root, explicit_config, owner_root)
    pack = project.root / config["pack_path"]
    try:
        pack.relative_to(project.root)
    except ValueError as exc:
        raise RuntimeBlocked("PROJECT_INDETERMINATE", "pack path escapes the project") from exc
    try:
        first_repo, first_state, first_components = _observe_world(
            project, pack, config, config_hash, owner_root, instance_id,
            prepared_time)
        check_config = _load_config(project.root, explicit_config, owner_root)
        if check_config != (config, config_source, config_hash, config_error):
            raise RuntimeBlocked(
                "PROJECT_INDETERMINATE", "selected config changed during preparation")
        second_repo, second_state, second_components = _observe_world(
            project, pack, config, config_hash, owner_root, instance_id,
            prepared_time)
        if (first_repo, first_state, first_components) != \
                (second_repo, second_state, second_components):
            raise RuntimeBlocked(
                "PROJECT_INDETERMINATE", "project or owner state changed during preparation")
    except RuntimeBlocked:
        raise
    except (RuntimeError, loom_survey.SurveyError, OSError) as exc:
        raise RuntimeBlocked(
            "PROJECT_INDETERMINATE", f"cannot establish complete project state: {exc}") \
            from exc
    repo_state, state, components = first_repo, dict(first_state), dict(first_components)
    decision = resolve_intent(request, state)
    try:
        pack_route = (_pack_route_contract(pack, state)
                      if decision["intent"] != "plan" else None)
        explicit_domains = (
            pack_route["domains"] if pack_route is not None else
            (config["domain_ids"] if config_source != "builtin-safe-default"
             and config["domain_ids"] != ["unclassified"] else None))
        domains_result = loom_domain.select_domains(
            request, explicit_domains, loom_domain.inspect_project(project.root))
    except loom_domain.DomainError as exc:
        raise RuntimeBlocked(
            "DOMAIN_INDETERMINATE",
            f"cannot establish trustworthy domain evidence: {exc}") from exc
    domains = domains_result["memory_domains"] or ["unclassified"]
    tier = (pack_route["tier"] if pack_route is not None
            else loom_tier.classify(request)["tier"])
    decision.update({
        "tier": tier,
        "autonomy": config["autonomy"],
        "use_profile": config["use_profile"],
        "requires_domain_discovery": domains_result["requires_domain_discovery"],
    })
    if config_error:
        decision.update({
            "blocked": True,
            "code": "INVALID_CONFIG",
            "needs_owner": True,
            "confidence": 0.0,
            "recommendation": "Repair the invalid selected Loom config before continuing.",
            "evidence": ["invalid-config"],
        })
    elif state.get("state_error") in {"STALE_LIFECYCLE", "STALE_TIME"}:
        decision.update({
            "intent": "repair",
            "blocked": False,
            "code": "AUTO_REGATE_REQUIRED",
            "needs_owner": False,
            "confidence": 1.0,
            "recommendation": (
                "Regate the changed plan sections internally before execution."),
            "evidence": [
                "elapsed-time-drift" if state.get("state_error") == "STALE_TIME"
                else "target-drift"],
        })
    elif state.get("state_error"):
        decision.update({
            "blocked": True,
            "code": str(state["state_error"]),
            "needs_owner": True,
            "confidence": 0.0,
            "recommendation": "Repair or replace the invalid lifecycle state before continuing.",
            "evidence": ["invalid-lifecycle-state"],
        })
    _validate_route(decision)
    freshness_seconds = config["freshness_window_days"] * 86_400
    staleness_bucket = int(prepared_time.timestamp() // freshness_seconds)
    components["staleness_bucket"] = staleness_bucket
    world = compose_world_fingerprint(components)
    normalized = " ".join(request.split())
    request_hash = _sha(normalized)
    retry_key = _sha(_canonical_json({
        "invocation_id": invocation_id,
        "project_id": project.project_id,
        "request_hash": request_hash,
    }))
    # Custom owner rules remain only in the local, world-fingerprinted config.
    # PreparedInvocation carries no arbitrary owner text or attacker-substitutable digest.
    stops = list(BASE_HARD_STOPS)
    if len(stops) > MAX_HARD_STOPS:
        raise RuntimeError("combined hard-stop safety floor exceeds its bound")
    return PreparedInvocation.build(
        schema_version=SCHEMA_VERSION,
        instance_id=instance_id,
        project_id=project.project_id,
        invocation_id=invocation_id,
        request_hash=request_hash,
        canonical_target_identity=project.canonical_target_identity,
        survey_hash=repo_state.state_hash,
        world_fingerprint=world,
        intent=decision["intent"],
        domains=domains,
        route_contract=decision,
        hard_stops=stops,
        config_source=config_source,
        retry_key=retry_key,
        prepared_at=_format_time(prepared_time),
    )
