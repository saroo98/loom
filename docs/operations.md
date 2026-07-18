# Install, update, rollback, and uninstall

## Install

Install Loom through a supported host package. The installed adapter must route to the stable
user-scoped launcher at `~/.loom/bin/loom`. The owner vault stays under `~/.loom/vault` and is never
stored in a project or versioned plugin cache.

## Update

Updates are staged beside the active runtime. Loom verifies the exact payload, runs migration and
health checks, and waits for active sessions to finish. A session pins one runtime version and one
owner-state generation. Activation never changes a running session.

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
