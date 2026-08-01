# Start with Loom

Loom gives AI coding agents one project-aware planning and verification surface:

```text
/loom <request>
```

The current signed release is **Loom 1.8.30**.

## Requirements

- Python 3.10 or newer
- A clean installation target
- A supported AI coding host or local development checkout

## Download and verify Loom 1.8.30

Open the immutable
[Loom 1.8.30 release](https://github.com/saroo98/loom/releases/tag/v1.8.30) and download
`loom-plugin-v1.8.30.zip`.

Verify the archive:

```powershell
(Get-FileHash .\loom-plugin-v1.8.30.zip -Algorithm SHA256).Hash.ToLower()
```

Compare the result with the plugin entry in the release's signed
[`SHA256SUMS`](https://github.com/saroo98/loom/releases/download/v1.8.30/SHA256SUMS).

The release also contains `SHA256SUMS`, `RELEASE-SUBJECT.json`, signature metadata, and the exact
installation instructions for the published artifact.

## Work from a source checkout

Developers can verify the public source before using the repository tools:

```powershell
git clone https://github.com/saroo98/loom.git
cd loom
python -B tools/loom_release.py verify . --source-classification public-release
```

For a local development installation:

```powershell
python tools/loom_install.py install . "$HOME/.codex/skills/loom"
python "$HOME/.codex/skills/loom/scripts/loom_bootstrap.py" --ensure --plugin-root "$HOME/.codex/skills/loom" --home "$HOME/.loom"
```

## Make the first request

Open a project and write:

```text
/loom Plan a health-check endpoint for this project.
```

Review:

- the exact project state Loom observed;
- the proposed steps and likely touch paths;
- known facts, assumptions, and owner decisions;
- the implementation-authority state; and
- the checks that define completion.

When the plan matches your intent, continue through the connected coding host.

## What Loom can return

Loom selects the smallest useful planning surface for the request. Depending on the work, that can
include:

- a bounded project snapshot;
- a plan contract and dependencies;
- work orders with expected touch paths;
- assumptions and decisions;
- explicit implementation authority;
- a proof graph that connects claims to evidence;
- verification and recovery records; and
- a plain-language completion report with one next action.

## Check the installation

Use the same request surface:

```text
/loom Check Loom's health.
```

Loom reports the active runtime, integration, local vault connection, and the next action when
attention is needed.

## Local data

Loom sends no Loom telemetry. Owner learning, preferences, outcomes, and device state remain in the
encrypted local owner vault and are excluded from the public package.

Read the [privacy policy](../PRIVACY.md) for the complete boundary.

## Get help

Open a [GitHub issue](https://github.com/saroo98/loom/issues) with:

- Loom version;
- host version;
- operating system; and
- the exact bounded error message.

Keep private vault data, credentials, owner-memory bodies, and unrelated repository content out of
public issues.
