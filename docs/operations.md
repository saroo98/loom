# Install, update, rollback, and uninstall

## Install

Install Loom through a supported host package. The installed adapter must route to the stable
user-scoped launcher at `~/.loom/bin/loom.py`. Request invocation uses its fixed-argument `bridge`
mode and bounded JSON stdin; `loom.cmd` is a refusal-only compatibility file, not an invocation
path. The owner vault stays under `~/.loom/vault` and is never
stored in a project or versioned plugin cache.

The public source tree can also be copied with `tools/loom_install.py`. On first `/loom`, bootstrap
verifies the complete install receipt before importing installed code, then uses an installer-owned
platform helper or builds one offline from the receipt-owned `Cargo.lock` and Rust source. This mode
is reported as `direct-source-install-unattested`. It is suitable for a reviewed local checkout but
is not a signed marketplace release. A source install therefore requires a compatible local Rust
toolchain and cached locked dependencies when no platform helper was supplied.

If exactly one of `release/metadata.json` and `release/trusted-root.json` exists, bootstrap blocks.
It never downgrades an incomplete signed delivery to direct-source authority. Changed, missing,
extra, redirected, or unowned install bytes also block before installed executable code is imported.

## Update

Updates are staged beside the active runtime. Loom verifies the exact payload, runs migration and
health checks, and waits for active sessions to finish. A session pins one runtime version and one
owner-state generation. Activation never changes a running session.

An unattested direct source cannot replace an active runtime. Install the next signed payload, or
use a separate fresh disposable home for source testing. A verified direct activation interrupted
after its runtime rename or pointer commit is completed idempotently from its receipts on retry.

## Rollback

Repeated trust-critical failures return the launcher to the last verified compatible runtime.
Owner events remain in the version-neutral encrypted vault. A rollback is refused while a session
is active or when no receipt-proven prior runtime exists.

## Uninstall

Loom removes only unchanged files named by its ownership receipts. Modified or unowned files block
removal. Runtime removal preserves the owner vault unless the owner separately and explicitly asks
to destroy it.

## Conflicts

Any competing global or project-local Loom route blocks execution. Loom reports the conflict but
does not edit the project or overwrite the unowned route.
