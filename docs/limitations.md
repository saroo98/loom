# Loom 1.3.0 Limitations

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
- Production token and latency budgets are **[UNVERIFIED]** until an independent benchmark signs
  provider-attested receipts for at least 20 successful samples across S, M, L, and XL workloads,
  including p50, p95, worst case, and explicit token and wall-time budgets.
- Normal production sessions can retain the bounded provider/model/response/hash identity behind
  all five token categories, but that local receipt is still a host-supplied record. Even 20
  receipts in every tier report `requires-independent-attestation`, never a certified total.
- Cross-domain improvement is **[UNVERIFIED]** until an independent benchmark signs provider-
  attested production sessions containing at least 16 memory-enabled versus memory-disabled replay
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
  until the release workflow runs against the exact `v1.3.0` bytes.
- Fresh marketplace installation trusts the Codex host as the initial delivery authority. Loom can
  detect internal corruption on first install, but cannot prove independence from a malicious host
  using a verifier delivered by that same host. Subsequent updates use the existing verified
  launcher before executing new payload code.
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

`tools/loom_release.py certify` enforces the first 5 evidence contracts. Certification requires a
separate trust policy whose independently provisioned RSA public keys authorize each evidence type;
unsigned, self-asserted, duplicated, expired, irrelevant, tampered, or wrong-commit evidence fails.
Missing evidence blocks production certification and the 100 score; documentation cannot override
that result.
