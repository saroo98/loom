#!/usr/bin/env python3
"""Deterministic longitudinal evaluation of Loom's scoped adaptation behavior."""

import argparse
import concurrent.futures
import json
import shutil
import uuid
from pathlib import Path

import loom_domain
import loom_improvement
import loom_improvement_audit
import loom_memory
import loom_preferences
import loom_runtime
import loom_session


SCHEMA_VERSION = 1


class Scenario:
    def __init__(self, scenario_id, *, time_controlled=False):
        self.id = scenario_id
        self.time_controlled = time_controlled
        self.assertions = []
        self.measurements = {}

    def equal(self, name, expected, actual):
        def jsonable(value):
            if isinstance(value, set):
                return sorted(value)
            if isinstance(value, tuple):
                return [jsonable(item) for item in value]
            if isinstance(value, list):
                return [jsonable(item) for item in value]
            if isinstance(value, dict):
                return {key: jsonable(item) for key, item in value.items()}
            if isinstance(value, bytes):
                return {"bytes_hex": value.hex()}
            return value

        self.assertions.append({
            "name": name, "expected": jsonable(expected), "actual": jsonable(actual),
            "passed": actual == expected,
        })

    def true(self, name, actual):
        self.equal(name, True, bool(actual))

    def result(self):
        return {
            "id": self.id,
            "time_controlled": self.time_controlled,
            "passed": bool(self.assertions) and all(
                item["passed"] for item in self.assertions),
            "assertions": self.assertions,
            "measurements": self.measurements,
        }


class Fixture:
    def __init__(self, root, name):
        self.root = Path(root) / name
        self.home = self.root / "owner"
        self.install = self.root / "install"
        self.install.mkdir(parents=True)
        self.instance = loom_memory.initialize(self.home, self.install)

    def project(self, name):
        path = self.root / "projects" / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "README.md").write_text(f"{name} fixture\n", encoding="utf-8")
        return path, loom_memory.project_identity(self.instance, path)


def _domain_record(fixture, domain, *, signal="verification-caught-defect",
                   decision="verification-strategy", verify_by=None):
    return loom_memory.admit_learning(
        fixture.home, fixture.instance, scope="domain", category="domain",
        signal=signal, future_decision=decision, evidence_count=3,
        confidence=1.0, domain=domain, verify_by=verify_by)


def _project_record(fixture, domain, project_id):
    return loom_memory.admit_learning(
        fixture.home, fixture.instance, scope="project", category="process",
        signal="artifact-unused", future_decision="artifact-selection",
        evidence_count=2, confidence=1.0, domain=domain, project_id=project_id)


def _three_d_week_close(root):
    s = Scenario("three-d-week-close", time_controlled=True)
    f = Fixture(root, s.id)
    _path, project_id = f.project("room-configurator")
    domain = _domain_record(f, "three-d")
    project = _project_record(f, "three-d", project_id)
    selected = loom_memory.select(
        f.home, f.instance, domain="three-d", project_id=project_id,
        now="2026-07-21T12:00:00Z")
    s.equal("relevant week-one memory selected", {domain["id"], project["id"]},
            {item["id"] for item in selected})
    closed = loom_memory.close_project(
        f.home, f.instance, project_id, now="2026-07-21T12:05:00Z")
    s.equal("project-only memory archived on close", 1, closed["archived"])
    s.equal("project memory leaves active context", "archived",
            loom_memory.inspect_record(f.home, f.instance, project["id"])["status"])
    s.equal("domain invariant remains active after one project", "active",
            loom_memory.inspect_record(f.home, f.instance, domain["id"])["status"])
    return s.result()


def _accounting_after_three_d(root):
    s = Scenario("accounting-after-three-d")
    f = Fixture(root, s.id)
    three_d = _domain_record(f, "three-d")
    general = loom_memory.set_preference(
        f.home, f.instance, "report_style", "concise")
    selected = loom_memory.select(
        f.home, f.instance, domain="accounting", max_chars=1200,
        now="2026-07-22T12:00:00Z")
    ids = {item["id"] for item in selected}
    encoded = json.dumps(selected, sort_keys=True)
    s.equal("three-d memory is excluded from accounting", False, three_d["id"] in ids)
    s.equal("transferable preference crosses domain", True, general["id"] in ids)
    s.true("selected capsule respects byte budget", len(encoded) <= 1200)
    s.equal("domain token does not leak into accounting capsule", False,
            "three-d" in encoded)
    return s.result()


def _three_d_six_month_return(root):
    s = Scenario("three-d-six-month-return", time_controlled=True)
    f = Fixture(root, s.id)
    _path, project_id = f.project("first-three-d")
    useful = _domain_record(f, "three-d")
    loom_memory.select(
        f.home, f.instance, domain="three-d", project_id=project_id,
        now="2026-07-14T12:00:00Z")
    loom_memory.record_application(
        f.home, f.instance, useful["id"], outcome="helped", project_id=project_id,
        now="2026-07-14T12:05:00Z")
    loom_memory.maintain_lifecycle(
        f.home, f.instance, now="2027-01-15T12:00:00Z", inactive_days=90)
    s.equal("unused domain leaves active context", "dormant",
            loom_memory.inspect_record(f.home, f.instance, useful["id"])["status"])
    returned = loom_memory.rehydrate_domain(
        f.home, f.instance, domain="three-d", project_id=project_id,
        max_records=2, max_chars=1200, now="2027-01-16T12:00:00Z")
    s.equal("previously useful exact-domain rule returns", [useful["id"]],
            returned["reactivated_ids"])
    s.true("rehydration remains bounded", returned["character_count"] <= 1200)
    s.equal("rehydration never scans unbounded archive", 0,
            returned["archive_records_scanned"])
    return s.result()


def _alternating_projects(root):
    s = Scenario("alternating-projects")
    f = Fixture(root, s.id)
    three_d = _domain_record(f, "three-d")
    accounting = _domain_record(
        f, "accounting", signal="assumption-caught", decision="accounting-validation")
    observed = []
    for index in range(6):
        domain = "three-d" if index % 2 == 0 else "accounting"
        selected = loom_memory.select(
            f.home, f.instance, domain=domain, max_chars=1200,
            now=f"2026-07-{20 + index:02d}T12:00:00Z")
        observed.append({item["id"] for item in selected})
    s.true("three-d days exclude accounting", all(
        three_d["id"] in observed[index] and accounting["id"] not in observed[index]
        for index in (0, 2, 4)))
    s.true("accounting days exclude three-d", all(
        accounting["id"] in observed[index] and three_d["id"] not in observed[index]
        for index in (1, 3, 5)))
    return s.result()


def _two_month_pause(root):
    s = Scenario("two-month-pause", time_controlled=True)
    f = Fixture(root, s.id)
    stale = _domain_record(
        f, "mobile", verify_by="2026-08-01T00:00:00Z")
    changed = loom_memory.maintain_lifecycle(
        f.home, f.instance, now="2026-09-15T00:00:00Z", inactive_days=60)
    s.equal("expired current fact becomes stale", 1, changed["stale"])
    s.equal("stale rule cannot load as current", [], loom_memory.select(
        f.home, f.instance, domain="mobile", now="2026-09-15T00:05:00Z"))
    capsule = loom_memory.rehydrate_domain(
        f.home, f.instance, domain="mobile", max_chars=1200,
        now="2026-09-15T00:10:00Z")
    s.equal("resume explicitly requires reverification", [stale["id"]],
            capsule["verification_required_ids"])
    return s.result()


def _autonomy_change(root):
    s = Scenario("autonomy-change")
    f = Fixture(root, s.id)
    engine = loom_preferences.PreferenceEngine(f.home, f.instance)
    projects = [f"p-{value:032x}" for value in (1, 2, 1)]
    for index, project_id in enumerate(projects):
        engine.observe(
            key="autonomy", value="A1", source="observed", project_id=project_id,
            task_class="plan", risk_class="low", evidence_id=f"auto-{index}",
            observed_at=f"2026-07-{14 + index:02d}T12:00:00Z")
    selected = engine.select(task_class="plan", risk_class="low")
    s.equal("cross-project evidence admits inferred autonomy", "A1",
            selected[0]["effective_value"])
    engine.observe(
        key="autonomy", value="A0", source="stated", project_id=None,
        task_class="plan", risk_class="low", evidence_id="owner-careful",
        observed_at="2026-07-20T12:00:00Z")
    s.equal("new stated autonomy overrides old inference", "A0",
            engine.select(task_class="plan", risk_class="low")[0]["effective_value"])
    return s.result()


def _stack_change(root):
    s = Scenario("stack-change")
    f = Fixture(root, s.id)
    engine = loom_preferences.PreferenceEngine(f.home, f.instance)
    for index, project_id in enumerate((f"p-{1:032x}", f"p-{2:032x}", f"p-{1:032x}")):
        engine.observe(
            key="stack", value="react-three-fiber", source="observed",
            project_id=project_id, domain="three-d", evidence_id=f"stack-{index}",
            observed_at=f"2026-07-{14 + index:02d}T12:00:00Z")
    s.equal("domain stack does not transfer to accounting", [],
            engine.select(domain="accounting"))
    engine.observe(
        key="stack", value="babylon", source="stated", project_id=None,
        domain="three-d", evidence_id="owner-stack-change",
        observed_at="2026-07-20T12:00:00Z")
    s.equal("stated stack change applies only in its domain", "babylon",
            engine.select(domain="three-d")[0]["effective_value"])
    return s.result()


def _harmful_inference_correction(root):
    s = Scenario("harmful-inference-correction")
    f = Fixture(root, s.id)
    engine = loom_preferences.PreferenceEngine(f.home, f.instance)
    for index, project_id in enumerate((f"p-{1:032x}", f"p-{2:032x}", f"p-{1:032x}")):
        engine.observe(
            key="report_detail", value="detailed", source="observed",
            project_id=project_id, evidence_id=f"detail-{index}",
            observed_at=f"2026-07-{14 + index:02d}T12:00:00Z")
    before = engine.select()[0]
    engine.correct("prefer concise reports", observed_at="2026-07-20T12:00:00Z")
    after = engine.select()[0]
    s.equal("harmful inference existed before correction", "inferred",
            before["effective_source"])
    s.equal("explicit owner correction wins immediately", "concise",
            after["effective_value"])
    s.equal("correction is identified as stated evidence", "stated",
            after["effective_source"])
    return s.result()


def _useful_invariant_dormancy(root):
    s = Scenario("useful-invariant-dormancy", time_controlled=True)
    f = Fixture(root, s.id)
    _path, project_id = f.project("firmware-a")
    useful = _domain_record(f, "firmware")
    loom_memory.select(
        f.home, f.instance, domain="firmware", project_id=project_id,
        now="2026-07-14T12:00:00Z")
    loom_memory.record_application(
        f.home, f.instance, useful["id"], outcome="helped", project_id=project_id,
        now="2026-07-14T12:05:00Z")
    loom_memory.maintain_lifecycle(
        f.home, f.instance, now="2028-07-14T12:00:00Z", inactive_days=90)
    record = loom_memory.inspect_record(f.home, f.instance, useful["id"])
    s.equal("old useful invariant leaves active context", "dormant", record["status"])
    s.true("dormant evidence retains observed utility",
           record["helped_count"] > record["hurt_count"])
    returned = loom_memory.rehydrate_domain(
        f.home, f.instance, domain="firmware", project_id=project_id,
        max_records=2, max_chars=1200, now="2028-07-15T12:00:00Z")
    s.equal("useful invariant returns only for its domain", [useful["id"]],
            returned["reactivated_ids"])
    return s.result()


def _twenty_project_year(root):
    s = Scenario("twenty-project-year", time_controlled=True)
    f = Fixture(root, s.id)
    ids = []
    for index in range(20):
        project_id = f"p-{index + 100:032x}"
        record = _project_record(f, "cli", project_id)
        ids.append(record["id"])
        loom_memory.close_project(
            f.home, f.instance, project_id,
            now=f"2026-{index // 2 + 1:02d}-{(index % 2) * 14 + 1:02d}T12:00:00Z")
    active = loom_memory.read_store(f.home, f.instance)["records"]
    s.equal("closed-project memory has zero active tax", 0,
            len([item for item in active if item["scope"] == "project"]))
    s.equal("all project evidence remains inspectable", 20, sum(
        loom_memory.inspect_record(f.home, f.instance, record_id)["status"] == "archived"
        for record_id in ids))
    s.true("active store remains under hard bound", len(active) <= loom_memory.MAX_ACTIVE_RECORDS)
    s.measurements.update({"projects": 20, "active_records": len(active),
                           "active_record_bound": loom_memory.MAX_ACTIVE_RECORDS})
    return s.result()


def _hundreds_outcomes_feedback(root):
    s = Scenario("hundreds-outcomes-feedback")
    f = Fixture(root, s.id)
    total = loom_memory.MAX_OUTCOMES_ACTIVE + 8
    namespace = uuid.UUID(f.instance)
    for index in range(total):
        loom_memory.record_outcome(
            f.home, f.instance, metric="confidence", predicted=0.8,
            actual=(0.2 if index < total // 2 else 0.75), domain="general",
            outcome_id=str(uuid.uuid5(namespace, f"scale-outcome-{index}")))
    for index in range(loom_memory.MAX_OUTBOX_ENTRIES):
        loom_memory.queue_feedback(
            f.home, f.instance, pattern="stale-state", action="fail-closed",
            evidence_count=index + 1)
    refused = False
    try:
        loom_memory.queue_feedback(
            f.home, f.instance, pattern="stale-state", action="fail-closed",
            evidence_count=999)
    except loom_memory.MemoryError:
        refused = True
    directory = f.home / "instances" / f.instance
    outcomes = json.loads((directory / "outcomes.json").read_text(encoding="utf-8"))
    feedback = loom_memory._read_jsonl(directory / "outbox.jsonl")
    archive = loom_memory._read_jsonl(directory / "outcomes-archive.jsonl")
    s.equal("active outcomes stop at bound", loom_memory.MAX_OUTCOMES_ACTIVE,
            len(outcomes["records"]))
    s.equal("overflow outcomes move to archive", total - loom_memory.MAX_OUTCOMES_ACTIVE,
            len(archive))
    s.equal("feedback outbox refuses unbounded growth", True, refused)
    s.equal("feedback active count stops at bound", loom_memory.MAX_OUTBOX_ENTRIES,
            len(feedback))
    s.measurements.update({
        "outcomes_recorded": total, "active_outcomes": len(outcomes["records"]),
        "active_outcome_bound": loom_memory.MAX_OUTCOMES_ACTIVE,
        "feedback_active": len(feedback), "feedback_bound": loom_memory.MAX_OUTBOX_ENTRIES,
    })
    return s.result()


def _interrupted_session(root):
    s = Scenario("interrupted-session")
    f = Fixture(root, s.id)
    project, _project_id = f.project("cli")
    calls = []

    def handler(_context):
        calls.append("called")
        if len(calls) == 1:
            raise RuntimeError("deterministic interruption")
        return {"status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": []}

    controller = loom_session.SessionController(
        owner_home=f.home, instance_id=f.instance, handlers={"plan": handler},
        memory=loom_session.NoopMemoryAdapter())
    interrupted = False
    try:
        controller.run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000901",
            cwd=project, now="2026-07-14T12:00:00Z")
    except loom_session.SessionInterrupted:
        interrupted = True
    receipt = controller.run(
        "Build a command-line tool",
        invocation_id="00000000-0000-4000-8000-000000000902",
        cwd=project, now="2026-07-14T12:01:00Z")
    s.equal("first interrupted run fails closed", True, interrupted)
    s.equal("next run reconciles rather than duplicating history", receipt.session_id,
            receipt.reconciled_session_id)
    s.equal("handler completes once after one failure", ["called", "called"], calls)
    return s.result()


def _concurrent_memory_writers(root):
    s = Scenario("concurrent-memory-writers")
    f = Fixture(root, s.id)

    def add(index):
        return loom_memory.add_record(
            f.home, f.instance, scope="domain", category="process",
            statement=f"concurrent bounded rule {index}", provenance="observed",
            evidence_count=1, confidence=0.5, domain="cli")["id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(add, range(24)))
    stored = loom_memory.read_store(f.home, f.instance)["records"]
    s.equal("all concurrent writes have unique identities", 24, len(set(ids)))
    s.equal("all concurrent writes survive valid serialization", 24,
            len([item for item in stored if item["statement"].startswith("concurrent")]))
    s.equal("post-concurrency instance validation is clean", [],
            loom_memory.validate_instance(f.home, f.instance))
    return s.result()


def _corrupt_state(root):
    s = Scenario("corrupt-state")
    f = Fixture(root, s.id)
    active = f.home / "instances" / f.instance / "active.json"
    active.write_bytes(b"{not-json")
    blocked = False
    try:
        loom_memory.select(f.home, f.instance, domain="cli")
    except loom_memory.MemoryError:
        blocked = True
    s.equal("corrupt memory blocks selection", True, blocked)
    s.equal("corrupt source remains available for recovery", b"{not-json", active.read_bytes())
    return s.result()


def _wrong_instance_uuid(root):
    s = Scenario("wrong-instance-uuid")
    f = Fixture(root, s.id)
    blocked = False
    try:
        loom_memory.validate_instance(f.home, "not-a-canonical-uuid")
    except loom_memory.MemoryError:
        blocked = True
    s.equal("invalid installation identity fails closed", True, blocked)
    return s.result()


def _disabled_profile(root):
    s = Scenario("disabled-profile")
    f = Fixture(root, s.id)
    project, _project_id = f.project("profile-off")
    config = json.loads(json.dumps(loom_runtime.DEFAULT_CONFIG))
    config["loom_version"] = "1.0.0"
    config["use_profile"] = False
    observed = []

    def handler(context):
        observed.extend(context.selected_memory)
        return {"status": "completed", "code": "plan-ready", "success": True,
                "metrics": {}, "evidence_ids": [], "reversible_action_ids": []}

    receipt = loom_session.SessionController(
        owner_home=f.home, instance_id=f.instance, handlers={"plan": handler},
        memory=loom_session.NoopMemoryAdapter()).run(
            "Build a command-line tool",
            invocation_id="00000000-0000-4000-8000-000000000903", cwd=project,
            explicit_config=config, now="2026-07-14T12:00:00Z")
    s.equal("profile-disabled route is preserved", False,
            receipt.owner_input_required)
    s.equal("disabled profile selects no owner memory", [], observed)
    s.equal("disabled profile records no learning outcomes", (), receipt.outcome_ids)
    return s.result()


def _permanent_forget_and_migration(root):
    s = Scenario("permanent-forget-and-migration")
    f = Fixture(root, s.id)
    record = _domain_record(f, "three-d")
    loom_memory.forget(f.home, f.instance, record["id"])
    erased = loom_memory.inspect_record(f.home, f.instance, record["id"])
    readmitted = False
    try:
        _domain_record(f, "three-d")
        readmitted = True
    except loom_memory.MemoryError:
        pass
    (f.home / "profile.md").write_text(
        "- When deciding verification-strategy, account for the observed signal verification-caught-defect.\n",
        encoding="utf-8")
    migration = loom_memory.migrate_legacy(f.home, f.instance)
    selected = loom_memory.select(f.home, f.instance, domain="three-d")
    s.equal("forget receipt exposes content-erased tombstone", True,
            erased == {"id": record["id"], "status": "forgotten", "content_erased": True})
    s.equal("same semantic memory cannot be silently readmitted", False, readmitted)
    s.equal("legacy unscoped data is quarantined, not activated", 1, migration["quarantined"])
    s.equal("forgotten semantics remain absent after migration", [], selected)
    return s.result()


def _unknown_domain(_root):
    s = Scenario("unknown-domain")
    result = loom_domain.select_domains("Plan an experimental quantum optics rig")
    s.equal("unknown domain does not fake adapter coverage", "unknown", result["coverage"])
    s.equal("unknown domain blocks G1", "blocked", result["g1_status"])
    s.equal("unknown domain requires invariant discovery", "domain-discovery.md",
            result["required_artifact"])
    s.equal("web defaults are not injected", [], result["memory_domains"])
    return s.result()


def _composite_domain(_root):
    s = Scenario("composite-domain")
    result = loom_domain.select_domains(
        "Build desktop bookkeeping software with double-entry accounting")
    domains = set(result["memory_domains"])
    s.equal("every relevant adapter is retained", {"accounting", "desktop"}, domains)
    s.equal("unrelated web adapter is excluded", False,
            bool(domains & {"website", "web-app"}))
    s.true("every composite adapter carries verification",
           all(item["verification"] for item in result["adapters"]))
    return s.result()


def _second_relevant_project_improves(root):
    s = Scenario("second-relevant-project-improves")
    f = Fixture(root, s.id)
    first = f"p-{501:032x}"
    second = f"p-{502:032x}"
    tracker = loom_improvement.ImprovementTracker(f.home, f.instance)
    for index in range(16):
        tracker.record_observation(
            metric="prediction-calibration-error",
            value=0.8 if index < 8 else 0.2, domain="three-d",
            project_id=first if index < 8 else second,
            evidence_id=f"project-comparison-{index}",
            recorded_at=f"2026-0{7 + index // 8}-{index % 8 + 1:02d}T12:00:00Z")
    for index in range(8):
        tracker.record_replay_pair(
            metric="prediction-calibration-error", domain="three-d",
            replay_id=f"memory-replay-{index}", enabled_value=0.2,
            disabled_value=0.7, project_id=second,
            evidence_ids=[f"replay-enabled-{index}", f"replay-disabled-{index}"],
            recorded_at=f"2026-09-{index + 1:02d}T12:00:00Z")
    report = tracker.report(
        metric="prediction-calibration-error", domain="three-d")
    reproduced = loom_improvement_audit.audit_bundle(tracker.audit_bundle(
        metric="prediction-calibration-error", domain="three-d"))
    s.equal("second relevant project has comparative proof", True,
            report["improvement_claim_allowed"])
    s.true("recent error is below first-project error",
           report["longitudinal"]["recent_mean"]
           < report["longitudinal"]["early_mean"])
    s.equal("minimum longitudinal sample is met", 16,
            report["longitudinal"]["sample_count"])
    s.equal("memory replay minimum is met", 8, report["replay"]["pair_count"])
    s.equal("independent reproducer accepts claim", "passed", reproduced["status"])
    s.measurements.update({
        "early_mae": report["longitudinal"]["early_mean"],
        "recent_mae": report["longitudinal"]["recent_mean"],
        "sample_count": report["longitudinal"]["sample_count"],
        "replay_pair_count": report["replay"]["pair_count"],
        "claim_reproduced": reproduced["reproduced"],
    })
    return s.result()


SCENARIOS = (
    _three_d_week_close, _accounting_after_three_d, _three_d_six_month_return,
    _alternating_projects, _two_month_pause, _autonomy_change, _stack_change,
    _harmful_inference_correction, _useful_invariant_dormancy, _twenty_project_year,
    _hundreds_outcomes_feedback, _interrupted_session, _concurrent_memory_writers,
    _corrupt_state, _wrong_instance_uuid, _disabled_profile,
    _permanent_forget_and_migration, _unknown_domain, _composite_domain,
    _second_relevant_project_improves,
)


def run_suite(workspace):
    root = Path(workspace).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ValueError("evaluation workspace must be empty")
    results = []
    for function in SCENARIOS:
        try:
            results.append(function(root))
        except Exception as exc:  # Preserve the complete matrix after one scenario fails.
            scenario_id = function.__name__.lstrip("_").replace("_", "-")
            results.append({
                "id": scenario_id, "time_controlled": False, "passed": False,
                "assertions": [{"name": "scenario completed", "expected": "no exception",
                                "actual": f"{type(exc).__name__}: {exc}", "passed": False}],
                "measurements": {},
            })
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if all(item["passed"] for item in results) else "failed",
        "scenario_count": len(results),
        "scenarios": results,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True,
                        help="empty disposable directory; never use an owner home")
    parser.add_argument("--keep", action="store_true",
                        help="keep disposable evaluation state after the run")
    args = parser.parse_args(argv)
    workspace = Path(args.workspace).resolve()
    if workspace.exists():
        raise SystemExit("evaluation workspace must not already exist")
    if not workspace.parent.is_dir():
        raise SystemExit("evaluation workspace parent must already exist")
    workspace.mkdir()
    try:
        report = run_suite(workspace)
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        if not args.keep:
            shutil.rmtree(workspace)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
