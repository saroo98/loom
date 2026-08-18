#!/usr/bin/env python3
"""Session-controller adapter backed only by the current Loom owner vault."""

import json
import re
import uuid
import datetime as dt
from pathlib import Path

import loom_performance
import loom_vault
import loom_memory
import loom_owner


class VaultAdapterError(RuntimeError):
    pass


_GENERAL_SCOPE_RE = re.compile(
    r"\b(?:in general|across (?:all|every) projects?|"
    r"for (?:all|every|future) projects?)\b", re.I)

_PLANNING_PREFERENCE_FIELDS = {
    "id", "key", "effective_value", "effective_source", "stated_confidence",
    "inferred_confidence", "domain", "task_class", "risk_class", "subject",
    "retired_values",
}
_PLANNING_PREFERENCE_KEYS = {
    "autonomy", "decision_batch_size", "report_detail", "stack",
}
_PLANNING_STORAGE_KEY_MAP = {
    "report_style": "report_detail",
    "decision_batching": "decision_batch_size",
    "autonomy_default": "autonomy",
    "stack_preference": "stack",
}
_PROJECT_ID = re.compile(r"p-[0-9a-f]{32}")


def _canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _planning_risk(tier):
    try:
        return {"S": "low", "M": "medium", "L": "high", "XL": "high"}[tier]
    except (KeyError, TypeError) as exc:
        raise VaultAdapterError("planning preference tier is invalid") from exc


def _validate_planning_scope(*, domains, project_id, tier, intent):
    if intent != "plan":
        raise VaultAdapterError("preference conflict projection is planning only")
    if not isinstance(domains, (list, tuple)) or not domains or len(domains) > 16 \
            or len(domains) != len(set(domains)) \
            or any(not isinstance(domain, str)
                   or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", domain) is None
                   for domain in domains) \
            or not isinstance(project_id, str) \
            or _PROJECT_ID.fullmatch(project_id) is None:
        raise VaultAdapterError("planning preference projection scope is invalid")
    return tuple(domains), _planning_risk(tier)


def _valid_planning_preference_value(key, value):
    return key in _PLANNING_PREFERENCE_KEYS \
        and isinstance(value, str) \
        and value == value.strip() \
        and 1 <= len(value) <= 200 \
        and "\n" not in value \
        and "\r" not in value \
        and all(character.isprintable() for character in value) \
        and (key == "stack" or loom_memory.RAW_PATH_RE.search(value) is None)


def _validate_planning_preference_record(record, *, domains, risk_class):
    if not isinstance(record, dict) or set(record) != _PLANNING_PREFERENCE_FIELDS \
            or not _canonical_uuid(record.get("id")) \
            or record.get("key") not in _PLANNING_PREFERENCE_KEYS \
            or not _valid_planning_preference_value(
                record.get("key"), record.get("effective_value")) \
            or record.get("effective_source") not in {
                "stated", "inferred", "inferred-confirmed"} \
            or record.get("subject") is not None:
        raise VaultAdapterError("planning preference record is invalid")
    stated = record.get("stated_confidence")
    inferred = record.get("inferred_confidence")
    if isinstance(stated, bool) or not isinstance(stated, (int, float)) \
            or isinstance(inferred, bool) or not isinstance(inferred, (int, float)) \
            or not 0 <= stated <= 1 or not 0 <= inferred <= 1 \
            or record["effective_source"] == "stated" and (
                stated != 1.0 or inferred != 0.0) \
            or record["effective_source"] != "stated" and (
                stated != 0.0 or inferred <= 0.0):
        raise VaultAdapterError("planning preference confidence is invalid")
    key = record["key"]
    domain = record.get("domain")
    task_class = record.get("task_class")
    record_risk = record.get("risk_class")
    if key == "stack":
        valid_scope = domain in domains and task_class is None and record_risk is None
    elif key == "autonomy":
        valid_scope = domain is None and task_class == "plan" \
            and record_risk == risk_class
    else:
        valid_scope = domain is None and task_class is None and record_risk is None
    retired = record.get("retired_values")
    if not valid_scope or not isinstance(retired, list) or len(retired) > 16 \
            or len(retired) != len(set(retired)) \
            or any(not _valid_planning_preference_value(key, item)
                   for item in retired):
        raise VaultAdapterError("planning preference scope or history is invalid")
    return (key, domain if key == "stack" else None)


def validate_planning_preference_projection(
        projection, *, domains, project_id, tier, intent, owner_vault_id=None):
    """Validate the closed public/private planning preference projection."""
    domains, risk_class = _validate_planning_scope(
        domains=domains, project_id=project_id, tier=tier, intent=intent)
    if owner_vault_id is not None and not _canonical_uuid(owner_vault_id):
        raise VaultAdapterError("planning preference owner identity is invalid")
    if not isinstance(projection, dict) or set(projection) != {
            "public_preferences", "conflict_keys", "private_conflict_evidence"}:
        raise VaultAdapterError("planning preference projection fields are invalid")
    public = projection["public_preferences"]
    keys = projection["conflict_keys"]
    private = projection["private_conflict_evidence"]
    if not isinstance(public, list) or len(public) > 32 \
            or not isinstance(keys, list) or keys != sorted(set(keys)) \
            or any(key not in _PLANNING_PREFERENCE_KEYS for key in keys) \
            or not isinstance(private, list) or len(private) > 128:
        raise VaultAdapterError("planning preference projection values are invalid")

    private_slots = set()
    private_identities = set()
    private_keys = set()
    for item in private:
        if not isinstance(item, dict) or set(item) != {
                "conflict_id", "preference_key", "owner_vault_id", "domain",
                "project_id", "task_class", "risk_class"} \
                or not _canonical_uuid(item.get("conflict_id")) \
                or not _canonical_uuid(item.get("owner_vault_id")) \
                or owner_vault_id is not None \
                and item.get("owner_vault_id") != owner_vault_id \
                or item.get("preference_key") not in _PLANNING_PREFERENCE_KEYS \
                or item.get("domain") not in domains \
                or item.get("project_id") != project_id \
                or item.get("task_class") != "plan" \
                or item.get("risk_class") != risk_class:
            raise VaultAdapterError("planning preference conflict evidence is invalid")
        identity = (
            item["conflict_id"], item["preference_key"], item["domain"])
        if identity in private_identities:
            raise VaultAdapterError("planning preference conflict evidence is duplicated")
        private_identities.add(identity)
        private_keys.add(item["preference_key"])
        private_slots.add((
            item["preference_key"],
            item["domain"] if item["preference_key"] == "stack" else None))
    if keys != sorted(private_keys):
        raise VaultAdapterError("planning preference conflict keys do not match evidence")

    public_slots = set()
    neutral_slots = set()
    preference_ids = set()
    for item in public:
        if isinstance(item, dict) and item.get("neutral_default") is True:
            expected_fields = {"key", "neutral_default"}
            if item.get("key") == "stack":
                expected_fields.add("domain")
            if set(item) != expected_fields \
                    or item.get("key") not in _PLANNING_PREFERENCE_KEYS \
                    or item.get("key") == "stack" and item.get("domain") not in domains:
                raise VaultAdapterError("neutral planning preference is invalid")
            slot = (item["key"], item.get("domain"))
            if slot in neutral_slots:
                raise VaultAdapterError("neutral planning preference is duplicated")
            neutral_slots.add(slot)
            continue
        slot = _validate_planning_preference_record(
            item, domains=domains, risk_class=risk_class)
        if item["id"] in preference_ids or slot in public_slots:
            raise VaultAdapterError("planning preference record is duplicated")
        preference_ids.add(item["id"])
        public_slots.add(slot)
    if neutral_slots != private_slots or public_slots & private_slots:
        raise VaultAdapterError("planning preference quarantine does not match evidence")
    return projection


def _domain_scope(statement, domains):
    matches = []
    for domain in domains:
        aliases = {
            domain.replace("-", " "),
            domain,
        }
        if domain == "data-etl":
            aliases.update({"data etl", "etl"})
        elif domain == "realtime-3d":
            aliases.update({"real time 3d", "real-time 3d", "3d"})
        for alias in aliases:
            words = [re.escape(item) for item in re.split(r"[-\s]+", alias) if item]
            if not words:
                continue
            phrase = r"[-\s]+".join(words)
            if re.search(
                    rf"\b(?:for|across)\s+(?:all\s+)?{phrase}\s+(?:projects?|work)\b"
                    rf"|\bin\s+{phrase}\s+(?:projects?|work)\b"
                    rf"|\bfor\s+(?:the\s+)?{phrase}\s+domain\b",
                    statement, re.I):
                matches.append(domain)
                break
    return sorted(set(matches))


class VaultMemoryAdapter:
    """Bounded runtime view over encrypted owner-vault records and events."""

    def __init__(self, *, owner_home, vault, project_root=None, max_chars=None):
        self.owner_home = Path(owner_home)
        self.vault = vault
        self.instance_id = vault.identity()["owner_vault_id"]
        self.project_root = Path(project_root).resolve() if project_root is not None else None
        self._rekeyed_project = None
        self._bound_project_id = None
        self._bound_state_mode = None
        if max_chars is not None and (
                type(max_chars) is not int or not 256 <= max_chars <= 4096):
            raise VaultAdapterError("memory max_chars ceiling must be between 256 and 4096")
        self.max_chars = max_chars

    def bind_project_state(self, project_id, state_mode):
        """Bind housekeeping to the runtime's already resolved project authority."""
        if not isinstance(project_id, str) \
                or re.fullmatch(r"p-[0-9a-f]{32}", project_id) is None \
                or state_mode not in {"git", "filesystem"}:
            raise VaultAdapterError("resolved project state binding is invalid")
        if self._bound_project_id is not None and (
                self._bound_project_id != project_id
                or self._bound_state_mode != state_mode):
            raise VaultAdapterError("resolved project state binding changed")
        self._bound_project_id = project_id
        self._bound_state_mode = state_mode

    def read_lifecycle_head_witness(self, project_id):
        """Return only the exact encrypted witness for one resolved project.

        The runtime kernel owns semantic validation of the closed witness.  This
        adapter is deliberately limited to exact, bounded vault selection and a
        strict JSON copy so private vault records cannot be confused across
        projects or exposed by reference.
        """
        if not isinstance(project_id, str) \
                or re.fullmatch(r"p-[0-9a-f]{32}", project_id) is None:
            raise VaultAdapterError("lifecycle witness project identity is invalid")
        try:
            matches = [
                item for item in self.vault.list_entities(
                    "lifecycle-head-witness-v1", limit=512)
                if item.get("id") == project_id
            ]
        except Exception as exc:
            raise VaultAdapterError(
                "lifecycle head witness could not be read") from exc
        if not matches:
            return None
        if len(matches) != 1 or not isinstance(matches[0].get("value"), dict):
            raise VaultAdapterError(
                "lifecycle head witness is missing or ambiguous")
        try:
            return json.loads(json.dumps(
                matches[0]["value"], ensure_ascii=False, allow_nan=False))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VaultAdapterError(
                "lifecycle head witness is not strict JSON") from exc

    def protect_session_payload(self, operation_id, payload):
        """Encrypt mutable session details while leaving the journal chain inspectable."""
        if not isinstance(operation_id, str) or not isinstance(payload, dict):
            raise VaultAdapterError("session payload protection inputs are invalid")
        aad = f"session-journal:{self.instance_id}:{operation_id}".encode("utf-8")
        try:
            ciphertext = self.vault.crypto.seal(
                json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8"), aad)
            if isinstance(ciphertext, bytes):
                ciphertext = ciphertext.decode("ascii")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise VaultAdapterError("session payload could not be encrypted") from exc
        return {
            "kind": "loom-encrypted-session-payload-v1",
            "owner_vault_id": self.instance_id,
            "ciphertext": ciphertext,
        }

    def open_session_payload(self, operation_id, payload):
        if not isinstance(payload, dict) or set(payload) != {
                "kind", "owner_vault_id", "ciphertext"} \
                or payload.get("kind") != "loom-encrypted-session-payload-v1" \
                or payload.get("owner_vault_id") != self.instance_id \
                or not isinstance(payload.get("ciphertext"), str):
            raise VaultAdapterError("encrypted session payload contract is invalid")
        aad = f"session-journal:{self.instance_id}:{operation_id}".encode("utf-8")
        try:
            value = json.loads(self.vault.crypto.open(
                payload["ciphertext"].encode("ascii"), aad).decode("utf-8"))
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise VaultAdapterError("encrypted session payload authentication failed") from exc
        if not isinstance(value, dict):
            raise VaultAdapterError("decrypted session payload is invalid")
        return value

    def housekeeping(self, context):
        rekeyed = 0
        if self.project_root is not None and self._rekeyed_project != context.project_id:
            if self._bound_project_id != context.project_id \
                    or self._bound_state_mode not in {"git", "filesystem"}:
                raise VaultAdapterError(
                    "memory housekeeping requires the resolved project state binding")
            for legacy_install_id in self.vault.legacy_alias_ids("legacy-install"):
                legacy_project = loom_memory.project_identity(
                    legacy_install_id, self.project_root,
                    state_mode=self._bound_state_mode)
                rekeyed += self.vault.rekey_project_memory(
                    legacy_project, context.project_id)["rekeyed"]
            self._rekeyed_project = context.project_id
        return {
            "memory": self.vault.maintain_memory_lifecycle(),
            "devices": self.vault.maintain_devices(),
            "project_memory_rekeyed": rekeyed,
        }

    def select(self, context):
        policy = loom_performance.adaptive_memory_budget(
            tier=context.prepared.route_contract["tier"], intent=context.intent,
            domain_count=len(context.prepared.domains))
        budget = min(policy["max_chars"], self.max_chars or policy["max_chars"])
        project_id = context.project_id if policy["include_project_history"] else None
        selected = []
        remaining = budget
        for domain in context.prepared.domains:
            records = self.vault.select_memory(
                domain=domain, project_id=project_id,
                max_records=min(4, max(1, policy["max_records"] - len(selected))),
                max_chars=max(256, remaining))
            for record in records:
                if record["id"] not in {item["id"] for item in selected}:
                    selected.append(record)
                    remaining -= loom_vault.memory_context_cost(record)
                if len(selected) >= policy["max_records"] or remaining < 256:
                    break
            if len(selected) >= policy["max_records"] or remaining < 256:
                break
        if project_id and len(selected) < policy["max_records"] and remaining >= 256:
            records = self.vault.select_project_preferences(
                project_id=project_id,
                max_records=min(4, policy["max_records"] - len(selected)),
                max_chars=max(256, remaining),
                exclude_ids={item["id"] for item in selected})
            for record in records:
                selected.append(record)
                remaining -= loom_vault.memory_context_cost(record)
        return selected

    def select_preferences(self, context):
        values = {}
        key_map = {
            "report_style": "report_detail",
            "decision_batching": "decision_batch_size",
            "autonomy_default": "autonomy",
            "stack_preference": "stack",
        }
        risk = {"S": "low", "M": "medium", "L": "high", "XL": "high"}[
            context.prepared.route_contract["tier"]]
        observations = self.vault.list_entities("preference-observation", limit=256)
        grouped = {}
        for item in observations:
            value = item["value"]
            if value.get("domain") not in {None, *context.prepared.domains}:
                continue
            if value.get("key") == "autonomy" and (
                    value.get("task_class") != context.intent
                    or value.get("risk_class") != risk):
                continue
            if value.get("key") == "autonomy":
                # Authority and safety posture are never inferred from behavior.
                continue
            slot = (value.get("key"), value.get("domain"), value.get("task_class"),
                    value.get("risk_class"), value.get("value"))
            grouped.setdefault(slot, []).append(item)
        by_preference = {}
        for slot, evidence in grouped.items():
            key, domain, task_class, risk_class, effective = slot
            projects = {item["value"].get("project_id") for item in evidence
                        if item["value"].get("project_id")}
            domains = {domain_id for item in evidence
                       for domain_id in item["value"].get("domains", [])}
            if domain is not None:
                if len(projects) < 2:
                    continue
            elif len(projects) < 3 or len(domains) < 2:
                continue
            identity = (key, domain, task_class, risk_class)
            candidate = (max(item["value"].get("observation_order", 0)
                             for item in evidence), len(evidence), effective)
            if identity not in by_preference or candidate > by_preference[identity][0]:
                by_preference[identity] = (candidate, evidence)
        for (key, domain, task_class, risk_class), ((_, count, effective), evidence) \
                in by_preference.items():
            slot = (key, domain if key == "stack" else None)
            values[slot] = {
                "id": str(uuid.uuid5(uuid.UUID(self.instance_id),
                    f"inferred-preference:{key}:{domain}:{task_class}:{risk_class}:{effective}")),
                "key": key, "effective_value": effective,
                "effective_source": "inferred", "stated_confidence": 0.0,
                "inferred_confidence": min(0.95, 0.5 + 0.1 * count),
                "domain": domain, "task_class": task_class,
                "risk_class": risk_class, "subject": None, "retired_values": [],
            }
        for record in context.selected_memory:
            if record.get("category") != "preference" or record.get("status") != "active":
                continue
            public_key = key_map.get(record.get("preference_key"))
            if public_key is None:
                continue
            slot = (public_key, record.get("domain") if public_key == "stack" else None)
            values[slot] = {
                "id": record["id"], "key": public_key,
                "effective_value": record["preference_value"],
                "effective_source": "stated", "stated_confidence": 1.0,
                "inferred_confidence": 0.0, "domain": record.get("domain"),
                "task_class": context.intent if public_key == "autonomy" else None,
                "risk_class": risk if public_key == "autonomy" else None,
                "subject": None, "retired_values": [],
            }
        return sorted(values.values(), key=lambda item: (
            item["key"], item.get("domain") or "", item["id"]))

    def project_planning_preferences(
            self, *, preferences, domains, project_id, tier, intent):
        """Separate usable planning preferences from private conflict evidence."""
        domains, risk_class = _validate_planning_scope(
            domains=domains, project_id=project_id, tier=tier, intent=intent)
        if not isinstance(preferences, list) or len(preferences) > 32:
            raise VaultAdapterError("planning preference records are invalid")
        seen_preferences = set()
        seen_slots = set()
        for preference in preferences:
            slot = _validate_planning_preference_record(
                preference, domains=domains, risk_class=risk_class)
            if preference["id"] in seen_preferences or slot in seen_slots:
                raise VaultAdapterError("planning preference record is duplicated")
            seen_preferences.add(preference["id"])
            seen_slots.add(slot)
        owner_vault_id = self.vault.identity()["owner_vault_id"]
        if not _canonical_uuid(owner_vault_id):
            raise VaultAdapterError("planning preference owner identity is invalid")
        conflict_keys = set()
        conflict_slots = set()
        private_evidence = []
        seen = set()
        for domain in domains:
            conflicts = self.vault.relevant_preference_conflicts(
                domain=domain, project_id=project_id)
            if not isinstance(conflicts, list) or len(conflicts) > 128:
                raise VaultAdapterError("preference conflict records are invalid")
            for conflict in conflicts:
                if not isinstance(conflict, dict) or set(conflict) != {
                        "conflict_id", "preference_key"} \
                        or not _canonical_uuid(conflict.get("conflict_id")):
                    raise VaultAdapterError("preference conflict record is invalid")
                public_key = _PLANNING_STORAGE_KEY_MAP.get(conflict["preference_key"])
                if public_key is None:
                    raise VaultAdapterError(
                        "preference conflict names an unsupported planning key")
                identity = (conflict["conflict_id"], public_key, domain)
                if identity in seen:
                    raise VaultAdapterError("preference conflict record is duplicated")
                seen.add(identity)
                conflict_keys.add(public_key)
                conflict_slots.add((
                    public_key, domain if public_key == "stack" else None))
                private_evidence.append({
                    "conflict_id": conflict["conflict_id"],
                    "preference_key": public_key,
                    "owner_vault_id": owner_vault_id,
                    "domain": domain,
                    "project_id": project_id,
                    "task_class": "plan",
                    "risk_class": risk_class,
                })
        usable = [
            item for item in preferences
            if isinstance(item, dict) and (
                item.get("key"),
                item.get("domain") if item.get("key") == "stack" else None,
            ) not in conflict_slots
        ]
        neutral_defaults = []
        for key, domain in sorted(conflict_slots):
            neutral = {"key": key, "neutral_default": True}
            if domain is not None:
                neutral["domain"] = domain
            neutral_defaults.append(neutral)
        public_preferences = [
            *usable,
            *neutral_defaults,
        ]
        projection = {
            "public_preferences": public_preferences,
            "conflict_keys": sorted(conflict_keys),
            "private_conflict_evidence": sorted(
                private_evidence,
                key=lambda item: (
                    item["preference_key"], item["domain"], item["conflict_id"])),
        }
        return validate_planning_preference_projection(
            projection, domains=domains, project_id=project_id, tier=tier,
            intent=intent, owner_vault_id=owner_vault_id)

    def relevant_preference_conflicts(self, *, domains, project_id):
        conflicts = {}
        for domain in domains:
            for item in self.vault.relevant_preference_conflicts(
                    domain=domain, project_id=project_id):
                conflicts[item["conflict_id"]] = item
        return [conflicts[key] for key in sorted(conflicts)]

    def archive_plan_revision(
            self, *, record_id, project_id, payload, created_at):
        """Retain superseded plan bytes inside the managed owner-vault lifecycle."""
        try:
            return self.vault.put_plan_revision_archive(
                record_id=record_id, project_id=project_id,
                payload=payload, created_at=created_at)
        except loom_vault.VaultError as exc:
            raise VaultAdapterError(
                f"private plan revision could not be retained safely: {exc}") from exc

    def archive_plan_generation(
            self, *, record_id, project_id, payload, created_at):
        """Retain one terminal generation inside the managed owner-vault lifecycle."""
        try:
            return self.vault.put_plan_generation_archive(
                record_id=record_id, project_id=project_id,
                payload=payload, created_at=created_at)
        except loom_vault.VaultError as exc:
            raise VaultAdapterError(
                f"private plan generation could not be retained safely: {exc}") from exc

    def record_outcome(self, context, result):
        if context.intent in {"why", "status", "undo", "forget", "remember"}:
            return {"outcome_ids": [], "adaptation_receipts": [],
                    "improvement_evidence_ids": [],
                    "reversible_action_ids": result.get("reversible_action_ids", [])}
        selected = [item["id"] for item in context.selected_memory
                    if isinstance(item, dict) and isinstance(item.get("id"), str)]
        applied = set(result.get("applied_memory_ids", []))
        rejected = set(result.get("rejected_memory_ids", []))
        if not applied <= set(selected) or not rejected <= set(selected):
            raise VaultAdapterError("outcome references memory outside the sealed context")
        provided_effects = result.get("memory_effects", [])
        if not isinstance(provided_effects, list):
            raise VaultAdapterError("memory effects must be a bounded list")
        by_id = {item.get("memory_id"): item for item in provided_effects
                 if isinstance(item, dict)}
        if len(by_id) != len(provided_effects) or not set(by_id) <= set(selected):
            raise VaultAdapterError("memory effects reference memory outside the sealed context")
        effects = []
        for memory_id in selected:
            if memory_id in by_id:
                effects.append(dict(by_id[memory_id]))
            elif memory_id in rejected:
                effects.append({
                    "memory_id": memory_id, "status": "rejected-before-use",
                    "decision_target": "host-outcome", "intended_effect": "not applied",
                    "evidence_id": None, "serious_harm": False,
                })
            elif memory_id in applied:
                effects.append({
                    "memory_id": memory_id, "status": "applied-unverified",
                    "decision_target": "host-outcome", "intended_effect": "host reported use",
                    "evidence_id": None, "serious_harm": False,
                })
            else:
                effects.append({
                    "memory_id": memory_id, "status": "selected-only",
                    "decision_target": "host-outcome", "intended_effect": "context candidate",
                    "evidence_id": None, "serious_harm": False,
                })
        outcome = self.vault.record_memory_effects(context.operation_id, effects)
        outcome_id = str(uuid.uuid5(
            uuid.UUID(self.instance_id), f"outcome:{context.operation_id}"))
        self.vault.put_entity("session-outcome", outcome_id, {
            "operation_id": context.operation_id,
            "project_id": context.project_id,
            "domains": list(context.prepared.domains),
            "intent": context.intent,
            "tier": context.prepared.route_contract["tier"],
            "success": bool(result.get("success")),
            "evidence_ids": list(result.get("evidence_ids", [])),
            "metrics": result.get("metrics", {}),
            "usage": result.get("usage", {}),
            "memory": outcome,
        })
        usage = result.get("usage", {})
        if isinstance(usage, dict) and usage.get("schema_version") == 3:
            performance_id = str(uuid.uuid5(
                uuid.UUID(self.instance_id), f"performance:{context.operation_id}"))
            self.vault.put_entity("performance-observation", performance_id, {
                "operation_id": context.operation_id,
                "project_id": context.project_id,
                "domains": list(context.prepared.domains),
                "intent": context.intent,
                "tier": context.prepared.route_contract["tier"],
                "measurement_status": usage.get("measurement_status"),
                "measurement_source": usage.get("measurement_source"),
                "processed_total_tokens": usage.get("processed_total_tokens"),
                "event_count": usage.get("event_count", 0),
                "usage": usage,
            })
        self._learn_from_outcome(context, result)
        return {"outcome_ids": [outcome_id], "adaptation_receipts": [],
                "improvement_evidence_ids": list(result.get("evidence_ids", [])),
                "reversible_action_ids": result.get("reversible_action_ids", [])}

    def _upsert_inferred_memory(self, *, key, scope, domain, project_id, statement,
                                evidence_count):
        record_id = str(uuid.uuid5(uuid.UUID(self.instance_id), "inferred:" + key))
        existing = self.vault.get_memory(record_id)
        created_at = existing["created_at"] if existing else dt.datetime.now(
            dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        record = {
            "id": record_id, "scope": scope, "domain": domain,
            "project_id": project_id, "category": "process", "statement": statement,
            "provenance": "inferred", "status": "active" if evidence_count >= 3 else "dormant",
            "confidence": min(0.95, 0.5 + 0.1 * evidence_count),
            "evidence_count": evidence_count, "created_at": created_at,
            "preference_key": None, "preference_value": None,
        }
        self.vault.put_memory(record, source_sequence=evidence_count)

    def _learn_from_outcome(self, context, result):
        evidence = list(result.get("evidence_ids", []))
        outcomes = self.vault.list_entities("session-outcome", limit=256)
        projects = {item["value"].get("project_id") for item in outcomes
                    if item["value"].get("project_id")}
        outcome_domains = {domain for item in outcomes
                           for domain in item["value"].get("domains", [])}
        if len(outcomes) >= 3 and len(projects) >= 3 and len(outcome_domains) >= 2:
            successes = sum(bool(item["value"].get("success")) for item in outcomes)
            rate = successes / len(outcomes)
            self._upsert_inferred_memory(
                key="general-confidence-calibration", scope="global", domain=None,
                project_id=None,
                statement=(f"Across {len(outcomes)} evidenced Loom outcomes, the observed success "
                           f"rate is {rate:.0%}; use this only as owner-specific calibration and "
                           "retain current-task evidence as authoritative."),
                evidence_count=len(outcomes))
        if not evidence:
            evidence = []
        risk = {"S": "low", "M": "medium", "L": "high", "XL": "high"}[
            context.prepared.route_contract["tier"]]
        if not evidence and result.get("preference_observations"):
            return
        for index, observation in enumerate(result.get("preference_observations", [])):
            key = observation.get("key")
            domain = observation.get("domain") if key == "stack" else None
            if key == "stack" and domain is None and len(context.prepared.domains) == 1:
                domain = context.prepared.domains[0]
            entity_id = str(uuid.uuid5(
                uuid.UUID(self.instance_id),
                f"preference:{context.operation_id}:{index}:{key}:{observation.get('value')}"))
            self.vault.put_entity("preference-observation", entity_id, {
                "key": key, "value": observation.get("value"), "domain": domain,
                "task_class": context.intent if key == "autonomy" else None,
                "risk_class": risk if key == "autonomy" else None,
                "project_id": context.project_id,
                "domains": list(context.prepared.domains),
                "evidence_ids": evidence,
                "observation_order": len(outcomes),
            })
            self.vault.record_observation({
                "observation_id": entity_id, "memory_id": None,
                "scope": "project", "domain": domain,
                "project_id": context.project_id, "component_id": None,
                "decision_target": f"preference-{key}", "evidence_id": evidence[0],
                "observed_at": context.prepared.prepared_at,
                "value": {"key": key, "value": observation.get("value"),
                          "domains": list(context.prepared.domains)},
            })
        if not evidence:
            return
        signal_map = {
            "verification-caught-defect": (
                "verification-strategy",
                "Include a real verification medium that has previously caught a defect, then "
                "revalidate it against the current project."),
            "rework-observed": (
                "effort-calibration",
                "Challenge effort, dependency, and reversibility assumptions before authorization."),
            "artifact-unused": (
                "artifact-selection",
                "Require a named downstream consumer before producing an optional artifact."),
            "guidance-wasted-work": (
                "guidance-selection",
                "Load only guidance tied to a current invariant, decision, or verification need."),
        }
        metrics = result.get("metrics", {})
        for metric, (target, guidance) in signal_map.items():
            if float(metrics.get(metric, 0)) <= 0:
                continue
            for domain in context.prepared.domains:
                key = f"domain:{domain}:{target}"
                observations = [item for item in self.vault.list_entities(
                    "learning-observation", limit=256)
                    if item["value"].get("key") == key]
                observation_id = str(uuid.uuid5(
                    uuid.UUID(self.instance_id),
                    f"learning:{context.operation_id}:{domain}:{metric}"))
                self.vault.put_entity("learning-observation", observation_id, {
                    "key": key, "domain": domain, "metric": metric,
                    "project_id": context.project_id, "evidence_ids": evidence})
                self.vault.record_observation({
                    "observation_id": observation_id, "memory_id": None,
                    "scope": "domain", "domain": domain,
                    "project_id": context.project_id, "component_id": None,
                    "decision_target": target, "evidence_id": evidence[0],
                    "observed_at": context.prepared.prepared_at,
                    "value": {"metric": metric, "guidance": guidance},
                })
                count = len(observations) + 1
                self._upsert_inferred_memory(
                    key=key, scope="domain", domain=domain, project_id=None,
                    statement=f"For {domain}: {guidance}", evidence_count=count)

    def compact(self, _context):
        checkpoint = self.vault.checkpoint_if_due()
        compaction = self.vault.compact_acknowledged()
        return {"checkpoint": checkpoint, "compaction": compaction}

    def record_replay(self, replay, project_id):
        if not isinstance(replay, dict) or not isinstance(project_id, str):
            raise VaultAdapterError("production replay contract is invalid")
        replay_id = replay.get("replay_id")
        if not isinstance(replay_id, str) or not replay_id:
            raise VaultAdapterError("production replay identity is invalid")
        record_ids = []
        for cohort in ("enabled", "disabled"):
            item = replay.get(cohort)
            if not isinstance(item, dict):
                raise VaultAdapterError("production replay cohort is invalid")
            entity_id = str(uuid.uuid5(
                uuid.UUID(self.instance_id), f"policy-evaluation:{replay_id}:{cohort}"))
            self.vault.record_policy_evaluation({
                "evaluation_id": entity_id,
                "partition": f"{replay.get('domain')}:{project_id}:{cohort}",
                "evidence_state": "structural-counterfactual-only",
                "policy_version": str(replay.get("policy_version", "shadow-v1")),
                "sample_count": 1,
                "effect_lower": None, "effect_upper": None, "harm_upper": None,
                "token_cost": int(item.get("token_cost", 0)),
                "elapsed_seconds": float(item.get("elapsed_seconds", 0.0)),
            })
            record_ids.append(entity_id)
        summary_id = str(uuid.uuid5(
            uuid.UUID(self.instance_id), f"policy-evaluation:{replay_id}:summary"))
        self.vault.record_policy_evaluation({
            "evaluation_id": summary_id,
            "partition": f"{replay.get('domain')}:{project_id}:summary",
            "evidence_state": "structural-counterfactual-only",
            "policy_version": str(replay.get("policy_version", "shadow-v1")),
            "sample_count": 1,
            "effect_lower": None, "effect_upper": None, "harm_upper": None,
            "token_cost": sum(int(replay.get(cohort, {}).get("token_cost", 0))
                              for cohort in ("enabled", "disabled")),
            "elapsed_seconds": sum(float(replay.get(cohort, {}).get("elapsed_seconds", 0.0))
                                   for cohort in ("enabled", "disabled")),
        })
        for parent_id in record_ids:
            self.vault.add_derivation(parent_id, summary_id, relation="evaluates")
        for memory_id in replay.get("enabled", {}).get("memory_ids", []):
            self.vault.add_derivation(memory_id, summary_id, relation="evaluates")
        return [*record_ids, summary_id]

    def remember(self, context, statement):
        if not isinstance(statement, str) or not statement.strip() or len(statement) > 1000:
            raise VaultAdapterError("Memory must be a bounded declarative statement.")
        executable = re.search(
            r"(?im)^\s*(?:sudo|curl|wget|powershell|pwsh|cmd(?:\.exe)?|bash|sh|python|node|"
            r"rm\s|del\s|remove-item|invoke-expression|start-process)\b|"
            r"(?:&&|\|\||`[^`]+`|\$\([^)]*\))", statement)
        secret = re.search(
            r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|private[_ -]?key|secret)\s*[:=]",
            statement)
        if executable or secret:
            raise VaultAdapterError(
                "Executable commands and secret-bearing text cannot become active memory; "
                "state the non-executable invariant instead.")
        domain = context.prepared.domains[0]
        lowered = statement.casefold()
        preference_key = preference_value = None
        if re.search(r"\b(?:less autonomous|careful review|ask me before|review first)\b", lowered):
            preference_key, preference_value = "autonomy_default", "careful-review"
        elif re.search(
                r"\b(?:prefer|use|favor|favour|want)\s+(?:a\s+)?concise\b|"
                r"\bplans?\s+should\s+(?:be|stay)\s+concise\b",
                lowered):
            preference_key, preference_value = "report_style", "concise"
        elif re.search(r"\b(?:prefer|use)\s+(?:a\s+)?detailed\b", lowered):
            preference_key, preference_value = "report_style", "detailed"
        general_scope = _GENERAL_SCOPE_RE.search(statement) is not None
        domain_scopes = _domain_scope(statement, context.prepared.domains)
        if general_scope and domain_scopes or len(domain_scopes) > 1:
            raise VaultAdapterError(
                "Memory scope is ambiguous; name exactly one of general, domain, or project.")
        if general_scope:
            scope, memory_domain, project_id = "general", None, None
        elif domain_scopes:
            scope, memory_domain, project_id = "domain", domain_scopes[0], None
        else:
            scope, memory_domain, project_id = "project", domain, context.project_id
        record = {
            "id": str(uuid.uuid4()), "scope": scope, "domain": memory_domain,
            "project_id": project_id,
            "category": "preference" if preference_key else "process",
            "statement": statement, "provenance": "stated", "status": "active",
            "confidence": 1.0, "evidence_count": 1,
            "created_at": context.prepared.prepared_at,
            "preference_key": preference_key, "preference_value": preference_value,
        }
        return self.vault.put_memory(record)

    def forget(self, text, selected):
        candidates = [item for item in selected if isinstance(item, dict)]
        identifiers = re.findall(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            text, re.I)
        if len(identifiers) == 1 \
                and identifiers[0] not in {item.get("id") for item in candidates}:
            record = self.vault.get_memory(identifiers[0])
            if record is not None and record.get("status") == "active":
                candidates.append(record)
        matching = [item for item in candidates if item.get("id") in identifiers]
        if not matching and len(candidates) == 1:
            matching = candidates
        if len(matching) != 1:
            raise VaultAdapterError("Name exactly one selected memory ID to forget permanently.")
        forgotten = self.vault.forget_memory(matching[0]["id"], reason="owner-request")
        if forgotten["status"] == "complete":
            message = (f"Forgotten from active Loom state: {forgotten['record_id']}. "
                       f"Deletion floor {forgotten['deletion_epoch']} is checkpointed.")
        else:
            message = (f"Forget is pending for {forgotten.get('record_id', forgotten['id'])}: "
                       f"{forgotten['status']}.")
        return {"message": message, "receipt": forgotten}

    def profile_summary(self, context):
        records = [
            item for item in context.selected_memory
            if isinstance(item, dict) or hasattr(item, "get")]
        visible = [{"id": item["id"], "scope": item["scope"],
                    "domain": item.get("domain"), "statement": item["statement"]}
                   for item in records
                   if item.get("provenance") == "stated"
                   and item.get("status") in {None, "active", "dormant"}]
        return json.dumps({"stated_memory": visible}, sort_keys=True, separators=(",", ":"))

    def special_status(self, context):
        text = context.request_text.casefold()
        if "loom health" in text:
            return {"user_message": json.dumps(
                loom_owner.health_summary(self.owner_home, self.vault),
                sort_keys=True, separators=(",", ":"))}
        if "show what you learned from this project" in text \
                or "show me what you learned from this project" in text:
            records = self.vault.select_memory(
                domain=context.prepared.domains[0], project_id=context.project_id)
            visible = [{"id": item["id"], "scope": item["scope"],
                        "statement": item["statement"],
                        "evidence_count": item["evidence_count"]} for item in records]
            return {"user_message": json.dumps(
                {"project_learning": visible}, sort_keys=True, separators=(",", ":"))}
        if "move my loom to this device" in text:
            return {"status": "blocked", "code": "pairing-authorization-required",
                    "success": False,
                    "user_message": ("Authorize this device from an existing Loom device using "
                                     "the displayed full pairing fingerprint. Loom will then "
                                     "verify and activate the encrypted vault automatically.")}
        if "restore my loom" in text:
            return {"status": "blocked", "code": "recovery-material-required",
                    "success": False,
                    "user_message": ("Select the encrypted Loom backup and provide its 24-word "
                                     "recovery phrase. The phrase alone cannot restore data.")}
        return None

    def performance_summary(self, _context=None):
        observations = self.vault.list_entities("performance-observation", limit=256)
        states = {}
        complete_totals = []
        for item in observations:
            value = item["value"]
            state = value.get("measurement_status", "unknown")
            states[state] = states.get(state, 0) + 1
            total = value.get("processed_total_tokens")
            if type(total) is int:
                complete_totals.append(total)
        return json.dumps({
            "schema_version": 1,
            "retained_observations": len(observations),
            "retained_bound": 256,
            "measurement_states": states,
            "complete_minimum": min(complete_totals) if complete_totals else None,
            "complete_maximum": max(complete_totals) if complete_totals else None,
            "improvement": self.vault.improvement_summary(),
        }, sort_keys=True, separators=(",", ":"))

    def undo_latest(self):
        raise VaultAdapterError("No reversible owner adaptation is available.")
