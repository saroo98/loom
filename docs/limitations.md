# Loom 1.8.7 Limitations

Loom fails closed around evidence it does not possess.

- Actual improvement for a particular owner is **[UNVERIFIED]** until that owner's exact task,
  domain, tier, and risk partition accumulates valid evidence whose uncertainty clears the declared
  material threshold. Memory count, selection count, one outcome, and shadow-only comparison do not
  prove benefit.
- “Forget complete” means Loom removed active and reachable derived state, checkpointed the deletion
  floor, and obtained required active-device acknowledgements. It does not mean physical sanitization
  of unreachable external ciphertext, copied media, or plaintext already observed by a compromised
  device.

- Cross-platform behavior is **[UNVERIFIED]** until the current revision passes the native x64 and
  ARM64 Windows, macOS, and Linux helper matrix plus Python 3.10 through 3.14. A workflow
  definition or one-machine run cannot satisfy it. Capability skips are certified only when the
  same test passes in another bound matrix job.
- Fresh-install usability is **[UNVERIFIED]** until at least 1 person unfamiliar with Loom uses a
  clean environment, installs the exact public-build hash, and completes a real request without
  maintainer coaching. The certificate requires distinct study/install/request receipt bundles and
  complete participant counts.
- Independent hostile review is **[UNVERIFIED]** until a reviewer independent of the implementation
  reports 0 Critical and 0 High findings against the exact reproduced build. The certificate
  requires complete-scope and independence flags plus distinct report/review-bundle hashes.
- Production token and latency budgets are **[UNVERIFIED]** until current provider-native receipts
  cover a preregistered successful sample across S, M, L, and XL workloads,
  including p50, p95, worst case, and explicit token and wall-time budgets.
- Normal production sessions can retain the bounded provider/model/response/hash identity behind
  all five token categories, but that local receipt is still a host-supplied record. Even 20
  receipts in every tier remain host-observed, never a provider-native total.
- Cross-domain improvement is **[UNVERIFIED]** until an independent benchmark witnesses production
  sessions containing preregistered memory-enabled versus memory-disabled replay
  pairs: at least 8 for one exact domain and 8 for transferable general calibration. Simulations and
  deterministic adaptation fixtures do not satisfy this contract.
- The production orchestrator can ingest a controlled pair into the local improvement store, but
  its provider-response metadata and evidence hashes remain local host reports. The receipt is
  labeled `requires-independent-attestation` and cannot satisfy release certification by itself.
- Improvement claims remain unavailable for any metric/domain pair until it has at least 16 ordered
  observations and 8 controlled memory-enabled versus memory-disabled production replay pairs.
- Domain guidance is not current legal, tax, medical, safety, or regulatory advice. Loom must verify
  present rules and target-environment facts before those claims become load-bearing.
- The 240-case unknown-domain corpus is deterministic, templated regression evidence. Its observed
  zero unsafe authorizations and perfect routing metrics do not establish a population error rate,
  professional correctness, or universal domain coverage. Independent, naturally sampled holdout
  evaluation remains **[UNVERIFIED]**.
- Verification commands run in a disposable target snapshot, but the Python standard library does
  not provide a portable host-level filesystem/network sandbox. Loom protects the original target
  from relative-path mutation and detects target drift; command authority outside that snapshot is
  **[UNVERIFIED]** until an OS sandbox provider is configured and certified.
- The exact six-platform marketplace package is **[UNVERIFIED]** until independent x64 and ARM64
  builds, their second reproducible builds, SBOMs, provenance statements, and the final signed
  package all pass the package builder. The builder opens and hashes every claimed evidence
  artifact; local source tests do not substitute for those release inputs.
- The canonical deterministic ZIP builder, independent receipt verifier, semantic Cargo.lock SBOM
  reconciliation, and provenance schema are implemented and locally tested. GitHub attestations,
  native A/B helper rebuilds, a signed tag, and an immutable draft asset remain **[UNVERIFIED]**
  until the release workflow runs against the exact candidate bytes.
- Fresh marketplace installation trusts the Codex host as the initial delivery authority. Loom can
  detect internal corruption on first install, but cannot prove independence from a malicious host
  using a verifier delivered by that same host. Subsequent updates use the existing verified
  launcher before executing new payload code.
- A direct-source install is deliberately labeled `direct-source-install-unattested`. Its complete
  ownership receipt proves local byte consistency, not publisher identity. Without an included
  platform helper, first bootstrap also requires a local Rust toolchain with all locked dependencies
  available offline. Direct-source authority cannot replace an active runtime or satisfy a signed-
  release claim.
- Automatic host delivery is **[UNVERIFIED]** because Codex marketplace refresh behavior is owned
  by Codex. Once a newer plugin payload is present, Loom's verification, migration, activation,
  and rollback are automatic and offline.
- Device revocation rotates the data key locally and forces every other paired device to obtain a
  complete new checkpoint. Automatic re-wrapping and transport to every remaining device is not
  yet implemented; those devices remain dormant rather than receiving or contributing state.
- The natural-language move and restore intents currently stop at the unavoidable authorization
  or recovery-material checkpoint. A marketplace host UI for selecting the pairing payload or
  encrypted backup is not present in this source tree.
- The bootstrap migrates the exact verified active Loom 1.0 instance. Discovery and creation of
  separate inactive candidate vaults for additional independent legacy installations is not yet
  implemented; Loom leaves those installations untouched and does not merge them.
- Adapter installation verifies the receipt-owned shared launcher and every written adapter, but
  real disposable invocations through every named third-party host/version are **[UNVERIFIED]**
  until the clean-machine agent matrix runs. Unsupported hosts must not be described as connected.
- Codex App, CLI, and IDE are separate evidence surfaces even when they share an adapter location.
  None has a current exact-release real-host receipt. Cursor remains experimental, Gemini's current
  contract is stale during its host transition, and Factory Droid plus the generic Agent Skills
  format remain unsupported until their versioned contracts and disposable invocations pass.
- Adapter protocol v2 and the shared-runtime topology are mechanically exercised with disposable
  simulated host profiles. This proves protocol negotiation, one-runtime routing, receipt ownership,
  project non-mutation, and fail-closed conflicts. Codex's local MCP handshake and tool boundary are
  source-tested, but a fresh installed-host `/loom` completion remains **[UNVERIFIED]**. No MCP
  compatibility claim is made for the other named hosts, and no provider-usage claim follows from
  local MCP conformance.
- Codex lifecycle hooks are explicitly guardrails, not a sandbox. Structured write paths observed
  by `PreToolUse` can be checked against declared touches; shell semantics and specialized tool
  paths are not claimed to be completely confined. User-level `PostToolUse` execution remains a
  host-version evidence surface and is **[UNVERIFIED]** until a clean installed-host run records it.
- OpenAI, Anthropic, and Gemini profile arithmetic is locally tested against sanitized official-
  shape fixtures. Live provider-host runs with complete response inventories remain
  **[UNVERIFIED]** until content-bound usage receipt v3 bundles are captured from those hosts.
- Provider prompt-cache availability and delivery are host-controlled. A matching local prefix hash
  is not evidence of a provider cache hit; only the provider response receipt can establish one.
- Runtime-wide stage-span export and live host capability negotiation are **[UNVERIFIED]**. Loom
  provides bounded span and capability-receipt contracts, but the current agent adapters do not
  yet prove that every host emits either record during a real invocation.
- The generated release-readiness dashboard is expected to report `NOT-READY` until exact-cut,
  privacy, provenance, reproducibility, rollback, SBOM, threshold-authority, platform, real-host,
  and independent hostile-review evidence is supplied for one immutable release subject. Source
  tests and simulated profiles cannot discharge those claims.
- Independent two-builder reproducibility, distinct human signing authorities, native ARM64
  hardware runs, real virtual-machine power-loss tests, and an independent hostile review remain
  **[UNVERIFIED]**. Loom does not infer them from workflow definitions or local fault injection.
- The historical 0.9-1.7M-token single-file UI report is `reported-unbound` because its original
  provider receipts are unavailable. It is retained as an incident, not presented as a measured
  baseline or used for release certification.

`tools/loom_release.py certify` enforces the first 5 evidence contracts. Certification requires a
separate trust policy whose independently provisioned RSA public keys authorize each evidence type;
unsigned, self-asserted, duplicated, expired, irrelevant, tampered, or wrong-commit evidence fails.
Missing evidence blocks production certification and the 100 score; documentation cannot override
that result.

- The cross-cutting scorecard reports only evidence supplied for its exact subject tree. Local
  deterministic checks cannot award real-host, provider-native, public-adoption, cross-platform,
  independent usability, or hostile-review requirements. Those points stay withheld rather than
  being inferred from source quality or a test inventory.
- Competitive comparison snapshots expire. An unknown cell remains **[UNVERIFIED]** and widens the
  reported score interval; it is never filled from memory, project popularity, or author intent.
