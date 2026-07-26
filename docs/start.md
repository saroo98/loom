# Start with Loom

Loom runs inside Codex and keeps its evolving owner state on your device. You use one surface:

```text
/loom <request>
```

## Install from the Loom marketplace

Requirements:

- A current Codex installation with plugin support
- Python 3.10 or newer

Add the public Loom marketplace from a terminal:

```powershell
codex plugin marketplace add saroo98/loom
```

Then:

1. Open **Codex → Plugins**.
2. Find **Loom** and select **Install**.
3. Review and trust only the Loom integration shown by Codex.
4. Restart Codex once.
5. Open a project and write:

```text
/loom Plan a safe health-check endpoint for this project.
```

Loom should inspect the current project and return the plan or one concrete condition that must be
resolved first. It does not need repository-local Loom files.

## What the plan contains

A Loom plan identifies:

- the proposed implementation steps;
- files that may change;
- facts, assumptions, and unresolved decisions;
- how important assumptions will be checked; and
- the tests or runtime evidence required for completion.

Review and correct the plan before implementation starts.

## If marketplace installation is unavailable

Use the immutable
[Loom 1.8.15 release](https://github.com/saroo98/loom/releases/tag/v1.8.15) and follow its
signed-artifact instructions. Do not install an unverified archive over an active signed runtime.

## Check the installation

Ask through the same Loom surface:

```text
/loom Check Loom's health.
```

Loom reports its runtime, integration, vault, and relevant blocking condition without exposing
owner-memory bodies.

## Local data and support

Loom sends no telemetry. Owner learning and preferences remain in the local owner vault and are
excluded from the public package. Read the [privacy policy](../PRIVACY.md) for the exact boundary.

If installation or invocation fails, open a
[GitHub issue](https://github.com/saroo98/loom/issues) with the Loom version, Codex version,
operating system, and the exact bounded error message. Do not attach your private vault.
