#!/usr/bin/env python3
"""Consumer-driven artifact selection and proportional planning budgets."""

import json
import re
import uuid
from pathlib import Path

import loom_memory


SCHEMA_VERSION = 1
MAX_UTILITY_RECORDS = 256
MAX_PROJECTS = 16
SAFE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PROJECT = re.compile(r"^p-[0-9a-f]{32}$")


class PlanningError(RuntimeError):
    pass


class PlanningOptimizer:
    """Select only artifacts and checks that serve a named downstream decision."""

    def __init__(self, owner_home, instance_id):
        self.home = Path(owner_home)
        if not self.home.is_absolute():
            raise PlanningError("owner_home must be absolute")
        try:
            loom_memory.validate_instance(self.home, instance_id)
        except loom_memory.MemoryError as exc:
            raise PlanningError(str(exc)) from exc
        self.instance_id = instance_id
        self.directory = self.home / "instances" / instance_id
        self.path = self.directory / "artifact-utility.json"
        self.lock = self.directory / ".artifact-utility.lock"

    def _empty(self):
        return {"schema_version": SCHEMA_VERSION, "instance_id": self.instance_id,
                "total_observations": 0, "records": []}

    def _read(self):
        if not self.path.exists():
            return self._empty()
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PlanningError(f"artifact utility store is invalid: {exc}") from exc
        if not isinstance(value, dict) or set(value) != {
                "schema_version", "instance_id", "total_observations", "records"} \
                or value["schema_version"] != SCHEMA_VERSION \
                or value["instance_id"] != self.instance_id \
                or not isinstance(value["records"], list) \
                or len(value["records"]) > MAX_UTILITY_RECORDS:
            raise PlanningError("artifact utility store contract is invalid")
        fields = {"id", "domain", "artifact_id", "observation_count", "opened_count",
                  "cited_count", "work_order_used_count", "prevented_defect_count",
                  "unused_count", "projects"}
        for record in value["records"]:
            if not isinstance(record, dict) or set(record) != fields \
                    or not isinstance(record.get("domain"), str) \
                    or not SAFE.fullmatch(record["domain"]) \
                    or not isinstance(record.get("artifact_id"), str) \
                    or not SAFE.fullmatch(record["artifact_id"]) \
                    or not isinstance(record.get("projects"), list) \
                    or len(record["projects"]) > MAX_PROJECTS \
                    or len(record["projects"]) != len(set(record["projects"])) \
                    or not all(isinstance(item, str) and PROJECT.fullmatch(item)
                               for item in record["projects"]) \
                    or any(type(record[name]) is not int or record[name] < 0 for name in (
                        "observation_count", "opened_count", "cited_count",
                        "work_order_used_count", "prevented_defect_count", "unused_count")):
                raise PlanningError("artifact utility record contract is invalid")
            try:
                uuid.UUID(record["id"])
            except (ValueError, TypeError, AttributeError) as exc:
                raise PlanningError("artifact utility record contract is invalid") from exc
        return value

    def record_usage(self, *, domain, artifact_id, project_id, opened, cited,
                     work_order_used, prevented_defect):
        return self.record_usage_batch(
            domain=domain, project_id=project_id, usages=[{
                "artifact_id": artifact_id, "opened": opened, "cited": cited,
                "work_order_used": work_order_used,
                "prevented_defect": prevented_defect}])[0]

    def record_usage_batch(self, *, domain, project_id, usages):
        if not isinstance(domain, str) or not SAFE.fullmatch(domain) \
                or not isinstance(project_id, str) or not PROJECT.fullmatch(project_id) \
                or not isinstance(usages, list) or not 1 <= len(usages) <= 64:
            raise PlanningError("usage requires safe domain, artifact, project, and booleans")
        expected = {"artifact_id", "opened", "cited", "work_order_used", "prevented_defect"}
        for usage in usages:
            if not isinstance(usage, dict) or set(usage) != expected \
                    or not isinstance(usage["artifact_id"], str) \
                    or not SAFE.fullmatch(usage["artifact_id"]) \
                    or any(type(usage[name]) is not bool for name in expected - {"artifact_id"}):
                raise PlanningError("usage requires safe domain, artifact, project, and booleans")
        results = []
        with loom_memory.FileLock(self.lock):
            store = self._read()
            for usage in usages:
                artifact_id = usage["artifact_id"]
                record = next((item for item in store["records"]
                               if item["domain"] == domain
                               and item["artifact_id"] == artifact_id), None)
                if record is None:
                    record = {"id": str(uuid.uuid5(uuid.UUID(self.instance_id),
                        f"artifact:{domain}:{artifact_id}")), "domain": domain,
                        "artifact_id": artifact_id, "observation_count": 0,
                        "opened_count": 0, "cited_count": 0,
                        "work_order_used_count": 0, "prevented_defect_count": 0,
                        "unused_count": 0, "projects": []}
                    store["records"].append(record)
                consumed = usage["opened"] or usage["cited"] or usage["work_order_used"]
                record["observation_count"] += 1
                record["opened_count"] += int(usage["opened"])
                record["cited_count"] += int(usage["cited"])
                record["work_order_used_count"] += int(usage["work_order_used"])
                record["prevented_defect_count"] += int(usage["prevented_defect"])
                record["unused_count"] += int(not consumed)
                record["projects"] = sorted(set(
                    record["projects"] + [project_id]))[-MAX_PROJECTS:]
                store["total_observations"] += 1
                results.append(json.loads(json.dumps(record)))
            store["records"] = store["records"][-MAX_UTILITY_RECORDS:]
            loom_memory._atomic_json(self.path, store)
        return results

    def utility(self):
        return json.loads(json.dumps(self._read()["records"]))

    @staticmethod
    def _facts(facts):
        required = {"files", "days", "new_components", "new_boundaries",
                    "implementers", "irreversible"}
        if not isinstance(facts, dict) or set(facts) != required \
                or type(facts["irreversible"]) is not bool \
                or any(type(facts[name]) not in (int, float) or facts[name] < 0
                       for name in required - {"irreversible"}) \
                or facts["implementers"] < 1:
            raise PlanningError("facts must be complete observed scope and risk values")
        return facts

    @staticmethod
    def _tier(facts):
        portfolio = facts["new_components"] >= 8 or facts["new_boundaries"] >= 8 \
            or facts["days"] > 60 or facts["implementers"] >= 6
        if portfolio:
            return "XL", ["observed-portfolio-scope"]
        scope = facts["new_components"] >= 3 or facts["new_boundaries"] >= 3 \
            or facts["days"] > 10 or facts["implementers"] >= 3
        if scope:
            return "L", ["observed-scope"]
        medium = facts["irreversible"] or facts["new_components"] > 0 \
            or facts["new_boundaries"] > 0 or facts["days"] > 1 \
            or facts["files"] > 5 or facts["implementers"] > 1
        if medium:
            evidence = ["observed-risk" if facts["irreversible"] else "observed-scope"]
            return "M", evidence
        return "S", ["observed-small-scope"]

    def decide(self, *, description, domain, facts, implementation_chars,
               artifacts, sections, verification):
        if not isinstance(description, str) or not description.strip() \
                or not isinstance(domain, str) or not SAFE.fullmatch(domain):
            raise PlanningError("description and domain are required")
        facts = self._facts(facts)
        if type(implementation_chars) is not int or implementation_chars < 256:
            raise PlanningError("implementation_chars must be an integer of at least 256")
        if not isinstance(artifacts, list) or not isinstance(sections, dict) \
                or not isinstance(verification, list):
            raise PlanningError("artifacts, sections, and verification must be collections")
        tier, tier_evidence = self._tier(facts)
        mode = "compact-work-contract" if tier == "S" else "planning-pack"
        fraction = {"S": 0.8, "M": 0.9, "L": 1.0, "XL": 1.0}[tier]
        budget = min(implementation_chars, max(320, int(implementation_chars * fraction)))
        utility = {(item["domain"], item["artifact_id"]): item for item in self.utility()}
        selected, omitted, reasons = [], [], {}
        candidates = []
        for item in artifacts:
            if not isinstance(item, dict) or set(item) != {
                    "id", "consumer", "decision", "estimated_chars"} \
                    or not isinstance(item["id"], str) or not SAFE.fullmatch(item["id"]) \
                    or type(item["estimated_chars"]) is not int or item["estimated_chars"] < 1:
                raise PlanningError("artifact contract is invalid")
            if not isinstance(item["consumer"], str) or not item["consumer"].strip():
                omitted.append(item["id"]); reasons[item["id"]] = "no-consumer"; continue
            if not isinstance(item["decision"], str) or not item["decision"].strip():
                omitted.append(item["id"]); reasons[item["id"]] = "no-decision"; continue
            history = utility.get((domain, item["id"]))
            if history and history["unused_count"] >= 3 and len(history["projects"]) >= 2 \
                    and history["prevented_defect_count"] == 0:
                omitted.append(item["id"])
                reasons[item["id"]] = "demoted-repeatedly-unused"
                continue
            strength = history["prevented_defect_count"] if history else 0
            reason = "strengthened-prevented-defects" if strength >= 2 else "named-consumer-decision"
            candidates.append((-strength, item["estimated_chars"], item, reason))
        used = 0
        for _priority, estimated, item, reason in sorted(candidates,
                key=lambda row: (row[0], row[1], row[2]["id"])):
            if used + estimated <= budget:
                selected.append(dict(item)); used += estimated; reasons[item["id"]] = reason
            else:
                omitted.append(item["id"]); reasons[item["id"]] = "planning-budget"
        cleaned_sections = {str(key): value.strip() for key, value in sections.items()
                            if isinstance(key, str) and isinstance(value, str) and value.strip()}
        checks = []
        for item in verification:
            if not isinstance(item, dict) or set(item) != {"id", "target", "medium"}:
                raise PlanningError("verification contract is invalid")
            if all(isinstance(item[name], str) and item[name].strip()
                   for name in ("id", "target", "medium")) \
                    and SAFE.fullmatch(item["id"]):
                checks.append(dict(item))
        return {"schema_version": SCHEMA_VERSION, "tier": tier,
            "tier_evidence": tier_evidence, "mode": mode,
            "create_pack": tier != "S", "planning_char_budget": budget,
            "estimated_planning_chars": used, "artifacts": selected,
            "omitted_artifacts": sorted(set(omitted)), "artifact_reasons": reasons,
            "sections": cleaned_sections, "verification": checks}

    @staticmethod
    def verify_output(decision, *, actual_chars, artifact_ids, sections):
        """Fail closed when authored planning exceeds its decision contract."""
        if not isinstance(decision, dict) or type(actual_chars) is not int \
                or actual_chars < 0 or not isinstance(artifact_ids, list) \
                or len(artifact_ids) != len(set(artifact_ids)) \
                or not isinstance(sections, dict):
            raise PlanningError("planning output verification contract is invalid")
        budget = decision.get("planning_char_budget")
        if type(budget) is not int or actual_chars > budget:
            raise PlanningError("planning output exceeds its risk-proportional budget")
        declared = {item["id"] for item in decision.get("artifacts", [])}
        if not all(isinstance(item, str) and item in declared for item in artifact_ids):
            raise PlanningError("planning output contains an undeclared artifact")
        allowed_sections = decision.get("sections", {})
        if any(not isinstance(key, str) or key not in allowed_sections
               or not isinstance(value, str) or not value.strip()
               for key, value in sections.items()):
            raise PlanningError("planning output contains an empty or undeclared section")
        return {"status": "verified", "actual_chars": actual_chars,
                "budget_chars": budget, "artifact_count": len(artifact_ids),
                "section_count": len(sections)}
