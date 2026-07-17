#!/usr/bin/env python3
"""Generate a deterministic CycloneDX inventory for one exact native helper."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import loom_sbom


class CycloneDxError(RuntimeError):
    pass


def create(source, helper, output, *, platform_id, namespace_seed):
    source, helper, output = map(Path, (source, helper, output))
    if not source.is_dir() or not helper.is_file() or helper.is_symlink() \
            or output.exists() or not re.fullmatch(r"[a-z0-9-]{3,32}", platform_id) \
            or not re.fullmatch(r"[0-9a-f]{16,64}", namespace_seed):
        raise CycloneDxError("CycloneDX inputs are invalid")
    try:
        packages = loom_sbom._lock_packages(source)
    except (OSError, loom_sbom.SbomError) as exc:
        raise CycloneDxError(str(exc)) from exc
    helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
    components = [{
        "type": "application", "bom-ref": "loom-vault", "name": "loom-vault",
        "version": (source / "VERSION").read_text(encoding="utf-8").strip(),
        "hashes": [{"alg": "SHA-256", "content": helper_sha}],
        "properties": [{"name": "loom:platform", "value": platform_id}],
    }]
    components.extend({
        "type": "library", "bom-ref": f"cargo:{name}@{version}",
        "name": name, "version": version, "purl": f"pkg:cargo/{name}@{version}",
    } for name, version, _checksum in packages)
    body = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber":
            f"urn:uuid:{namespace_seed[:8]}-{namespace_seed[8:12]}-{namespace_seed[12:16]}-"
            f"8000-{namespace_seed[16:28].ljust(12, '0')}",
        "version": 1, "metadata": {"component": components[0]},
        "components": components,
    }
    output.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"status": "created", "components": len(components),
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("helper")
    parser.add_argument("output")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--namespace-seed", required=True)
    args = parser.parse_args(argv)
    try:
        result = create(args.source, args.helper, args.output,
                        platform_id=args.platform, namespace_seed=args.namespace_seed)
    except CycloneDxError as exc:
        print(json.dumps({"status": "refused", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
