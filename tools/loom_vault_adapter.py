#!/usr/bin/env python3
"""Session-controller adapter backed only by the Loom 1.1 owner vault."""

import json
import re
import uuid
import datetime as dt
from pathlib import Path

import loom_performance
import loom_vault
import loom_memory
import loom_survey
import loom_owner


class VaultAdapterError(RuntimeError):
    pass


class VaultMemoryAdapter:
    """Bounded runtime view over encrypted owner-vault records and events."""

    def __init__(self, *, owner_home, vault, project_root=None, max_chars=None):
        self.owner_home = Path(owner_home)
        self.vault = vault
        self.instance_id = vault.identity()["owner_vault_id"]
        self.project_root = Path(project_root).resolve() if project_root is not None else None
        self._rekeyed_project = None
        if max_chars is not None and (
                type(max_chars) is not int or not 256 <= max_chars <= 4096):
            raise VaultAdapterError("memory max_chars ceiling must be between 256 and 4096")
        self.max_chars = max_chars

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
            probe = loom_survey.run_git(
                self.project_root, "rev-parse", "--is-inside-work-tree", allowed=(0, 128))
            state_mode = "git" if probe.returncode == 0 \
                and probe.stdout.strip() == "true" else "filesystem"
            for legacy_install_id in self.vault.legacy_alias_ids("legacy-install"):
                legacy_project = loom_memory.project_identity(
                    legacy_install_id, self.project_root, state_mode=state_mode)
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
                max_records=max(1, policy["max_records"] - len(selected)),
                max_chars=max(256, remaining))
            for record in records:
                if record["id"] not in {item["id"] for item in selected}:
                    selected.append(record)
                    remaining -= len(json.dumps(record, ensure_ascii=False)) + 1
                if len(selected) >= policy["max_records"] or remaining < 256:
                    break
            if len(selected) >= policy["max_records"] or remaining < 256:
                break
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
            slot = (value.get("key"), value.get("domain"), value.get("task_class"),
                    value.get("risk_class"), value.get("value"))
            grouped.setdefault(slot, []).append(item)
        by_preference = {}
        for slot, evidence in grouped.items():
            if len(evidence) < 3:
                continue
            key, domain, task_class, risk_class, effective = slot
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
        harmful = any(float(result.get("metrics", {}).get(key, 0)) > 0 for key in (
            "rework-observed", "verification-escape", "guidance-wasted-work"))
        helped = applied if result.get("success") and not harmful else set()
        hurt = applied if harmful else rejected
        outcome = self.vault.record_memory_outcome(
            selected, helped_ids=sorted(helped), hurt_ids=sorted(hurt))
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
        if len(outcomes) >= 3:
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
                "evidence_ids": evidence,
                "observation_order": len(outcomes),
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
                count = len(observations) + 1
                self._upsert_inferred_memory(
                    key=key, scope="domain", domain=domain, project_id=None,
                    statement=f"For {domain}: {guidance}", evidence_count=count)

    def compact(self, _context):
        checkpoint = self.vault.checkpoint_if_due()
        compaction = self.vault.compact_acknowledged()
        return {"checkpoint": checkpoint, "compaction": compaction}

    def remember(self, context, statement):
        domain = context.prepared.domains[0]
        record = {
            "id": str(uuid.uuid4()), "scope": "project", "domain": domain,
            "project_id": context.project_id, "category": "process",
            "statement": statement, "provenance": "stated", "status": "active",
            "confidence": 1.0, "evidence_count": 1,
            "created_at": context.prepared.prepared_at,
            "preference_key": None, "preference_value": None,
        }
        return self.vault.put_memory(record)

    def forget(self, text, selected):
        candidates = [item for item in selected if isinstance(item, dict)]
        identifiers = re.findall(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            text, re.I)
        matching = [item for item in candidates if item.get("id") in identifiers]
        if not matching and len(candidates) == 1:
            matching = candidates
        if len(matching) != 1:
            raise VaultAdapterError("Name exactly one selected memory ID to forget permanently.")
        forgotten = self.vault.forget_memory(matching[0]["id"], reason="owner-request")
        return {"message": f"Forgotten permanently: {forgotten['id']}."}

    def profile_summary(self):
        records = self.vault.list_memory(statuses={"active", "dormant"}, limit=32)
        visible = [{"id": item["id"], "scope": item["scope"],
                    "domain": item.get("domain"), "statement": item["statement"]}
                   for item in records if item.get("provenance") == "stated"]
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

    def performance_summary(self):
        return json.dumps(self.vault.improvement_summary(), sort_keys=True, separators=(",", ":"))

    def undo_latest(self):
        raise VaultAdapterError("No reversible owner adaptation is available.")

    def record_replay(self, replay, project_id):
        records = []
        for cohort in ("enabled", "disabled"):
            record_id = str(uuid.uuid5(
                uuid.UUID(self.instance_id),
                f"replay:{replay['replay_id']}:{cohort}"))
            self.vault.put_entity("production-replay", record_id, {
                "replay_id": replay["replay_id"], "cohort": cohort,
                "metric": replay["metric"], "domain": replay["domain"],
                "project_id": project_id, "value": replay[cohort]["value"],
                "evidence_id": replay[cohort]["evidence_id"],
                "provider_receipt": replay[cohort]["provider_receipt"],
            })
            records.append(record_id)
        return records
