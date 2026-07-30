# Start with Loom

Loom’s owner-facing request surface is:

```text
/loom <request>
```

The current source candidate is 1.8.20. Until its signed release is published, the latest immutable
artifact remains 1.8.19. Check [release readiness](./release-readiness.md) and
[current limitations](./limitations.md) before treating a host or platform as supported.

## Requirements

- Python 3.10 or newer
- A clean installation target
- A host integration whose current capability evidence is sufficient for your use

This repository does not claim that a public Codex marketplace listing has been approved.

## Use the published artifact

Download the immutable
[Loom 1.8.19 release](https://github.com/saroo98/loom/releases/tag/v1.8.19).

The expected SHA-256 for `loom-plugin-v1.8.19.zip` is:

```text
d14d7ab133ea3341a55af17bd53400528982470de36a6946fcbe977ac5b027b9
```

Verify the downloaded file:

```powershell
(Get-FileHash .\loom-plugin-v1.8.19.zip -Algorithm SHA256).Hash.ToLower()
```

The release also contains `SHA256SUMS` and `RELEASE-SUBJECT.json`. Treat a digest mismatch, missing
release subject, or changed archive as a hard stop.

## Evaluate from public source

For a direct-source evaluation:

```powershell
git clone https://github.com/saroo98/loom.git
cd loom
python -B tools/loom_release.py verify . --source-classification public-release
python tools/loom_install.py install . "$HOME/.codex/skills/loom"
python "$HOME/.codex/skills/loom/scripts/loom_bootstrap.py" --ensure --plugin-root "$HOME/.codex/skills/loom" --home "$HOME/.loom"
```

A direct-source install is labeled `direct-source-install-unattested`. Its ownership receipt proves
local byte consistency, not publisher identity. It does not become a signed-release install.

## Make the first request

Open a project and write:

```text
/loom Plan a safe health-check endpoint for this project.
```

Loom should return a reviewable plan or one bounded condition that must be resolved first. Review:

- the exact project and observed state;
- proposed steps and likely touch paths;
- facts, assumptions, and unresolved decisions;
- whether implementation authority exists; and
- the evidence required before completion.

A blocking result authorizes no fallback implementation. Resolve the condition and begin a fresh
request so the plan and authority describe the current world.

## What the plan can contain

Depending on consequence, uncertainty, domain coverage, and consumer need:

- a project-inspection receipt;
- plan contract and dependencies;
- bounded work orders;
- assumptions, decisions, and planning obligations;
- implementation-authority state;
- verification and recovery evidence; and
- an owner-facing result with consequence, freshness, reversibility, verification, and one next
  action.

Small work does not require every artifact. Produced artifacts have a consumer and decision;
skipped artifacts have a reason.

## Check the installation

Ask through the same request surface:

```text
/loom Check Loom's health.
```

Loom should report the runtime, integration, vault, and relevant blocking condition without
exposing owner-memory bodies.

## Local data and support

Loom sends no Loom telemetry. Owner learning and preferences remain in the local owner vault and
are excluded from the public package. Read the [privacy policy](../PRIVACY.md) for the exact
boundary.

If installation or invocation fails, open a
[GitHub issue](https://github.com/saroo98/loom/issues) with the Loom version, host version,
operating system, and exact bounded error message. Do not attach the private vault, credentials,
owner-memory bodies, or unrelated repository content.
