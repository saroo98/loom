#!/usr/bin/env python3
"""Compile one exact release subject and verified observations into a public passport."""

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import loom_evidence_graph
import loom_readiness
import loom_release_subject_verify
import loom_reliability
import loom_subject_identity


SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+ -]{0,255}$")
ABSOLUTE_PATH = re.compile(
    r"(?:^|[\s\"'])(?:[A-Za-z]:[\\/]|/(?:home|Users|private|var/folders)/)", re.I)
RELEASE_PREDICATES = {
    "exact_cut": "release.exact-cut",
    "privacy": "release.privacy",
    "reproducibility": "release.reproducibility",
    "sbom": "release.sbom",
    "provenance": "release.provenance",
    "rollback": "release.rollback",
}


class ReleasePassportError(RuntimeError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _time(value, label):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ReleasePassportError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ReleasePassportError(f"{label} lacks a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _read_json(path, label):
    try:
        path = loom_reliability._absolute(path, label, must_exist=True)
        if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
            raise ReleasePassportError(f"{label} is missing, redirected, or oversized")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError,
            loom_reliability.ReliabilityError) as exc:
        raise ReleasePassportError(f"{label} is invalid: {exc}") from exc


def _artifact(path, label):
    try:
        path = loom_reliability._absolute(path, label, must_exist=True)
    except loom_reliability.ReliabilityError as exc:
        raise ReleasePassportError(str(exc)) from exc
    if not path.is_file() or path.stat().st_size < 1:
        raise ReleasePassportError(f"{label} is missing or unsafe")
    raw = path.read_bytes()
    if len(raw) != path.stat().st_size:
        raise ReleasePassportError(f"{label} changed while reading")
    return {"name": path.name, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}, raw


def _public_value(value, label):
    """Reject owner/project identity and raw diagnostic material from public output."""
    forbidden_keys = {
        "absolute_path", "cwd", "environment_values", "home", "owner",
        "owner_vault", "project_identity", "project_path", "prompt", "raw_log",
        "raw_logs", "request", "request_text", "user", "username", "vault",
    }

    def visit(item, path):
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str) or key.casefold() in forbidden_keys:
                    raise ReleasePassportError(
                        f"{label} contains a forbidden public field: {path + key}")
                visit(nested, path + key + ".")
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                visit(nested, f"{path}{index}.")
        elif isinstance(item, str) and ABSOLUTE_PATH.search(item):
            raise ReleasePassportError(f"{label} contains an absolute owner path")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise ReleasePassportError(f"{label} contains an unsupported public value")

    visit(value, "")
    return value


def _subject_bundle(value):
    if not isinstance(value, dict) or value.get("schema_version") != 3 \
            or value.get("repository") != loom_subject_identity.REPOSITORY \
            or not SHA.fullmatch(str(value.get("bundle_sha256", ""))) \
            or value["bundle_sha256"] != _digest({
                key: item for key, item in value.items() if key != "bundle_sha256"}):
        raise ReleasePassportError("release subject bundle is invalid")
    try:
        subjects = loom_subject_identity.subject_map(value.get("subjects"))
    except loom_subject_identity.SubjectIdentityError as exc:
        raise ReleasePassportError(str(exc)) from exc
    required = {"main-source", "candidate-source", "release-tag", "plugin-zip"}
    if not required <= {kind for kind, _subject_id in subjects} \
            or not any(kind == "native-helper" for kind, _subject_id in subjects):
        raise ReleasePassportError("release subject bundle is incomplete")
    return subjects


def _binding(subject):
    return {"kind": subject["kind"], "subject_id": subject["subject_id"],
            "subject_digest": subject["subject_digest"]}


def _ci_authority(value, *, evaluation_epoch, subjects):
    fields = {
        "run_id", "job_id", "runner", "workflow_digest", "attestation_sha256",
        "attestation_bundle", "issued_at", "verified_at", "expires_at",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or any(not isinstance(value.get(key), str) or not value[key]
                   for key in fields) \
            or not SHA.fullmatch(value["workflow_digest"]) \
            or not SHA.fullmatch(value["attestation_sha256"]) \
            or not SAFE_TEXT.fullmatch(value["run_id"]) \
            or not SAFE_TEXT.fullmatch(value["job_id"]) \
            or not SAFE_TEXT.fullmatch(value["runner"]):
        raise ReleasePassportError("CI release authority is invalid")
    try:
        bundle = base64.b64decode(value["attestation_bundle"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ReleasePassportError("CI attestation bundle encoding is invalid") from exc
    if not bundle or len(bundle) > 1024 * 1024 \
            or hashlib.sha256(bundle).hexdigest() != value["attestation_sha256"]:
        raise ReleasePassportError("CI attestation bundle digest is invalid")
    issued = _time(value["issued_at"], "CI issued_at")
    verified = _time(value["verified_at"], "CI verified_at")
    expires = _time(value["expires_at"], "CI expires_at")
    evaluated = _time(evaluation_epoch, "release evaluation epoch")
    if not issued <= verified <= evaluated < expires \
            or expires - issued > dt.timedelta(days=30):
        raise ReleasePassportError("CI release authority time bounds are invalid")
    main = next(item for (kind, _), item in subjects.items()
                if kind == "main-source")
    candidate = next(item for (kind, _), item in subjects.items()
                     if kind == "candidate-source")
    body = {
        "schema_version": 1,
        "expectation_id": "00000000-0000-5000-8000-" + value["attestation_sha256"][:12],
        "issuer_kind": "ci", "issuer_id": "github-actions-release",
        "repository": loom_subject_identity.REPOSITORY,
        "run_id": value["run_id"], "job_id": value["job_id"],
        "workflow_digest": value["workflow_digest"],
        "base_commit": main["commit"], "candidate_commit": candidate["commit"],
        "issued_at": value["issued_at"], "expires_at": value["expires_at"],
        "evaluation_epoch": evaluation_epoch,
        "subjects": sorted(subjects.values(), key=lambda item: (
            item["kind"], item["subject_id"])),
        "authority": {"kind": "ci-attestation",
                      "attestation_sha256": value["attestation_sha256"]},
    }
    receipt = {**body, "expectation_sha256": loom_subject_identity.digest({
        key: item for key, item in body.items() if key != "authority"})}
    try:
        verified_receipt = loom_subject_identity.validate_expected_subjects(
            receipt, now=evaluation_epoch,
            ci_attestation_verifier=lambda candidate: (
                candidate["authority"]["attestation_sha256"]
                == value["attestation_sha256"]))
    except loom_subject_identity.SubjectIdentityError as exc:
        raise ReleasePassportError(str(exc)) from exc
    return verified_receipt, bundle


def _passed_cut(value):
    if not isinstance(value, dict) or value.get("status") != "verified" \
            or not SHA.fullmatch(str(value.get("root_sha256", ""))) \
            or not isinstance(value.get("firewall"), dict) \
            or value["firewall"].get("clean") is not True \
            or not isinstance(value.get("offline"), dict) \
            or value["offline"].get("offline") is not True:
        raise ReleasePassportError("exact-cut verification is not a passing exact result")


def _passed_suite(value, *, commit, root_sha256):
    if not isinstance(value, dict) or value.get("schema_version") != 1 \
            or value.get("status") != "certified" \
            or value.get("subject") != {
                "source_commit": commit, "public_root_sha256": root_sha256}:
        raise ReleasePassportError("release suite is not certified for the exact subject")


def _passed_rollback(value, *, commit, root_sha256):
    fields = {"schema_version", "status", "commit", "public_root_sha256",
              "tests", "transcript_sha256", "result_sha256"}
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 or value.get("status") != "passed" \
            or value.get("commit") != commit \
            or value.get("public_root_sha256") != root_sha256 \
            or not isinstance(value.get("tests"), list) or not value["tests"] \
            or any(not isinstance(item, str) or not item for item in value["tests"]) \
            or not SHA.fullmatch(str(value.get("transcript_sha256", ""))) \
            or value.get("result_sha256") != _digest({
                key: item for key, item in value.items() if key != "result_sha256"}):
        raise ReleasePassportError("rollback evidence is invalid or wrong-subject")


def _native_evidence(values, subjects):
    helpers = {subject_id: item for (kind, subject_id), item in subjects.items()
               if kind == "native-helper"}
    if not isinstance(values, dict) or set(values) != set(helpers):
        raise ReleasePassportError("native evidence does not cover every release helper")
    payload = {}
    for platform, paths in sorted(values.items()):
        if not isinstance(paths, dict) or set(paths) != {"binary", "sbom", "provenance"}:
            raise ReleasePassportError("native evidence mapping is invalid")
        subject = helpers[platform]
        binary, _ = _artifact(paths["binary"], f"{platform} native helper")
        sbom, _ = _artifact(paths["sbom"], f"{platform} SBOM")
        provenance, _ = _artifact(paths["provenance"], f"{platform} provenance")
        if binary["bytes"] != subject["bytes"] or binary["sha256"] != subject["sha256"] \
                or sbom["sha256"] != subject["sbom_sha256"] \
                or provenance["sha256"] != subject["provenance_sha256"]:
            raise ReleasePassportError(
                f"native evidence does not match the {platform} release subject")
        payload[platform] = {
            "binary_sha256": binary["sha256"], "sbom_sha256": sbom["sha256"],
            "provenance_sha256": provenance["sha256"],
        }
    return payload


def _codex_observation(value, *, release_subject_sha256):
    fields = {
        "schema_version", "host", "surface", "status", "evidence_class",
        "release_subject_sha256", "installed_runtime_subject", "request_sha256",
        "response_sha256", "task_sha256", "observed_at", "route", "result",
        "fresh_task", "disposable_project", "privacy", "observation_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields \
            or value.get("schema_version") != 1 or value.get("host") != "codex-app" \
            or value.get("surface") != "app" or value.get("status") != "passed" \
            or value.get("evidence_class") != "host-observed" \
            or value.get("release_subject_sha256") != release_subject_sha256 \
            or value.get("fresh_task") is not True \
            or value.get("disposable_project") is not True \
            or value.get("observation_sha256") != _digest({
                key: item for key, item in value.items()
                if key != "observation_sha256"}):
        raise ReleasePassportError("Codex App observation is invalid or wrong-release")
    privacy = value.get("privacy")
    if not isinstance(privacy, dict) or any(privacy.values()):
        raise ReleasePassportError("Codex App observation contains public identity material")
    try:
        installed = loom_subject_identity.validate_subject(
            value["installed_runtime_subject"])
    except loom_subject_identity.SubjectIdentityError as exc:
        raise ReleasePassportError(str(exc)) from exc
    if installed["kind"] != "installed-runtime":
        raise ReleasePassportError("Codex App observation lacks an installed runtime subject")
    _public_value(value, "Codex App observation")
    return installed


def _envelope(*, evidence_id, predicate, bindings, payload, authority,
              producer_digest, dependencies=()):
    body = {
        "schema_version": 2, "evidence_id": evidence_id,
        "subject_bindings": bindings, "predicate_type": predicate,
        "producer": {"id": "loom-release-passport", "version": "1",
                     "digest": producer_digest},
        "evidence_class": "ci-reproduced",
        "environment": {
            "runner": authority["runner"], "workflow_digest": authority["workflow_digest"],
            "run_id": authority["run_id"], "job_id": authority["job_id"],
        },
        "issued_at": authority["issued_at"], "expires_at": authority["expires_at"],
        "payload_sha256": _digest(payload), "limitations": [],
        "signer": {
            "authority": "github-actions-artifact-attestation",
            "key_id": "sha256:" + authority["attestation_sha256"],
            "algorithm": "sigstore-bundle",
            "signature": authority["attestation_bundle"],
        },
        "verifier": {"id": "github-cli-attestation-verify",
                     "verified_at": authority["verified_at"], "status": "passed"},
        "depends_on": list(dependencies), "revoked": False, "stale": False,
    }
    return loom_evidence_graph.seal_envelope(body)


def compile_passport(*, subject, plugin, reproduced_plugin, cut_receipt,
                     suite_report, rollback_report, native_evidence,
                     ci_authority, evaluation_epoch, codex_observation=None):
    subjects = _subject_bundle(subject)
    try:
        verification = loom_release_subject_verify.verify(
            subject, plugin,
            commit=next(item["commit"] for (kind, _), item in subjects.items()
                        if kind == "candidate-source"),
            tag=next(item["tag"] for (kind, _), item in subjects.items()
                     if kind == "release-tag"))
    except loom_release_subject_verify.SubjectVerificationError as exc:
        raise ReleasePassportError(str(exc)) from exc
    plugin_artifact, _ = _artifact(plugin, "canonical plugin")
    reproduced_artifact, _ = _artifact(reproduced_plugin, "reproduced plugin")
    if (plugin_artifact["bytes"], plugin_artifact["sha256"]) != (
            reproduced_artifact["bytes"], reproduced_artifact["sha256"]):
        raise ReleasePassportError("independent plugin reproduction differs")
    main = next(item for (kind, _), item in subjects.items() if kind == "main-source")
    candidate = next(item for (kind, _), item in subjects.items()
                     if kind == "candidate-source")
    if main["commit"] != candidate["commit"] or candidate["dirty"]:
        raise ReleasePassportError("release source subjects do not name one clean commit")
    _passed_cut(cut_receipt)
    _passed_suite(suite_report, commit=candidate["commit"],
                  root_sha256=cut_receipt["root_sha256"])
    _passed_rollback(rollback_report, commit=candidate["commit"],
                     root_sha256=cut_receipt["root_sha256"])
    native_payload = _native_evidence(native_evidence, subjects)
    release_subjects = dict(subjects)
    installed = (_codex_observation(
        codex_observation, release_subject_sha256=verification["bundle_sha256"])
        if codex_observation is not None else None)
    expected_subjects = dict(subjects)
    if installed is not None:
        release_tag = next(item for (kind, _), item in subjects.items()
                           if kind == "release-tag")
        if installed["version"] != release_tag["tag"].removeprefix("v") \
                or installed["release_sequence"] != subject["release_sequence"]:
            raise ReleasePassportError(
                "Codex App observation names the wrong installed runtime version")
        expected_subjects[(installed["kind"], installed["subject_id"])] = installed
    expectation, _attestation_bundle = _ci_authority(
        ci_authority, evaluation_epoch=evaluation_epoch, subjects=expected_subjects)
    all_bindings = [_binding(item) for item in sorted(
        release_subjects.values(), key=lambda item: (item["kind"], item["subject_id"]))]
    producer_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    payloads = {
        "exact_cut": {"cut": cut_receipt, "suite": suite_report},
        "privacy": {"firewall": cut_receipt["firewall"],
                    "offline": cut_receipt["offline"]},
        "reproducibility": {"canonical": plugin_artifact,
                            "reproduced": reproduced_artifact},
        "sbom": {key: {"sbom_sha256": row["sbom_sha256"]}
                 for key, row in native_payload.items()},
        "provenance": {key: {"provenance_sha256": row["provenance_sha256"]}
                       for key, row in native_payload.items()},
        "rollback": rollback_report,
    }
    envelopes = []
    for name, predicate in RELEASE_PREDICATES.items():
        envelopes.append(_envelope(
            evidence_id="ev-release-" + name.replace("_", "-"), predicate=predicate,
            bindings=all_bindings, payload=payloads[name], authority=ci_authority,
            producer_digest=producer_digest))
    for platform, row in native_payload.items():
        helper = subjects[("native-helper", platform)]
        envelopes.append(_envelope(
            evidence_id=f"ev-platform-{platform}", predicate=f"platform.{platform}",
            bindings=[_binding(helper)], payload=row, authority=ci_authority,
            producer_digest=producer_digest))
    if installed is not None:
        candidate_binding = _binding(release_subjects[("candidate-source", "candidate")])
        plugin_subject = next(item for (kind, _), item in release_subjects.items()
                              if kind == "plugin-zip")
        envelopes.append(loom_evidence_graph.seal_envelope({
            "schema_version": 2, "evidence_id": "ev-host-codex-app-observed",
            "subject_bindings": [candidate_binding, _binding(plugin_subject),
                                 _binding(installed)],
            "predicate_type": "host.codex.app.observed",
            "producer": {"id": "loom-codex-release-evidence", "version": "1",
                         "digest": producer_digest},
            "evidence_class": "host-observed",
            "environment": {"host": "codex-app", "surface": "app"},
            "issued_at": codex_observation["observed_at"],
            "expires_at": ci_authority["expires_at"],
            "payload_sha256": codex_observation["observation_sha256"],
            "limitations": [
                "Host-observed evidence is not provider-native or independent certification."],
            "signer": {"authority": "local-observer", "key_id": None,
                       "algorithm": "none", "signature": None},
            "verifier": {"id": "codex-app-task-observer",
                         "verified_at": codex_observation["observed_at"],
                         "status": "passed"},
            "depends_on": [], "revoked": False, "stale": False,
        }))
    expected_digest = loom_subject_identity.digest({
        "schema_version": 1,
        "subjects": sorted(expectation["subjects"], key=lambda item: (
            item["kind"], item["subject_id"])),
    })
    bundle = {
        "schema_version": 2, "policy_id": "loom-evidence-policy-v1",
        "expected_subjects_sha256": expected_digest,
        "evaluation_epoch": evaluation_epoch, "envelopes": envelopes,
    }
    graph = loom_evidence_graph.evaluate(
        bundle, expected_receipt=expectation,
        as_of=_time(evaluation_epoch, "release evaluation epoch"))
    version = next(item["tag"][1:] for (kind, _), item in subjects.items()
                   if kind == "release-tag")
    readiness = loom_readiness.generate(
        version=version, evidence=graph, evaluation_epoch=evaluation_epoch,
        trusted_expected_subjects_sha256=expected_digest,
        report_kind="release", release_subject_sha256=verification["bundle_sha256"])
    outputs = {
        "evidence_bundle": _public_value(bundle, "release evidence bundle"),
        "evidence_graph": _public_value(graph, "release evidence graph"),
        "readiness": _public_value(readiness, "release readiness"),
    }
    return outputs


def write_outputs(output_directory, value):
    try:
        output = loom_reliability._absolute(
            output_directory, "release passport output")
    except loom_reliability.ReliabilityError as exc:
        raise ReleasePassportError(str(exc)) from exc
    if output.exists():
        raise ReleasePassportError("release passport output already exists")
    output.mkdir(parents=True)
    for name, key in (
            ("RELEASE-EVIDENCE.json", "evidence_bundle"),
            ("RELEASE-EVIDENCE-GRAPH.json", "evidence_graph"),
            ("RELEASE-READINESS.json", "readiness")):
        loom_reliability.atomic_write_json(output / name, value[key])
    checksums = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()} *{path.name}\n")
    loom_reliability.atomic_write_text(output / "SHA256SUMS", "".join(checksums))
    return {"status": "created", "release_subject_sha256":
            value["readiness"]["release_subject_sha256"], "files": 4}


def _mapping(values, label):
    result = {}
    for value in values:
        if "=" not in value:
            raise ReleasePassportError(f"{label} mapping is invalid")
        name, path = value.split("=", 1)
        if not name or name in result:
            raise ReleasePassportError(f"{label} mapping is duplicated")
        result[name] = path
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--reproduced-plugin", required=True)
    parser.add_argument("--cut-receipt", required=True)
    parser.add_argument("--suite-report", required=True)
    parser.add_argument("--rollback-report", required=True)
    parser.add_argument("--native-binary", action="append", default=[])
    parser.add_argument("--native-sbom", action="append", default=[])
    parser.add_argument("--native-provenance", action="append", default=[])
    parser.add_argument("--ci-authority", required=True)
    parser.add_argument("--codex-observation")
    parser.add_argument("--evaluation-epoch", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        binaries = _mapping(args.native_binary, "native binary")
        sboms = _mapping(args.native_sbom, "native SBOM")
        provenance = _mapping(args.native_provenance, "native provenance")
        if set(binaries) != set(sboms) or set(binaries) != set(provenance):
            raise ReleasePassportError("native evidence mappings disagree")
        native = {key: {"binary": binaries[key], "sbom": sboms[key],
                        "provenance": provenance[key]} for key in binaries}
        result = compile_passport(
            subject=_read_json(args.subject, "release subject"),
            plugin=args.plugin, reproduced_plugin=args.reproduced_plugin,
            cut_receipt=_read_json(args.cut_receipt, "cut receipt"),
            suite_report=_read_json(args.suite_report, "suite report"),
            rollback_report=_read_json(args.rollback_report, "rollback report"),
            native_evidence=native,
            ci_authority=_read_json(args.ci_authority, "CI authority"),
            evaluation_epoch=args.evaluation_epoch,
            codex_observation=(
                _read_json(args.codex_observation, "Codex App observation")
                if args.codex_observation else None))
        written = write_outputs(args.output, result)
    except (ReleasePassportError, loom_evidence_graph.EvidenceGraphError,
            loom_readiness.ReadinessError) as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(written, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
