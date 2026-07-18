# Start with Loom

Install the signed Loom plugin through a supported host, then use one surface:

```text
/loom <what you want to do>
```

Example:

```text
/loom Plan a safe health-check endpoint for this project.
```

Loom inspects the project, chooses planning depth from actual risk, asks only decisions it cannot
prove, and returns the next authorized action with a receipt. It does not require repository-local
installation files and does not upload owner learning.

To inspect local health, ask:

```text
/loom Check Loom's health.
```

If a host, platform, update, or project state cannot be verified, Loom blocks the affected action
and identifies the missing evidence. It does not convert missing evidence into a pass.
