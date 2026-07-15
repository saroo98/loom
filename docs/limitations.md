# Loom 1.0.0 Limitations

Loom fails closed around evidence it does not possess.

- Cross-platform behavior is **[UNVERIFIED]** until the current revision passes the exact 12-job
  matrix: Windows, macOS, and Linux on Python 3.10, 3.11, 3.12, and 3.13. The certificate requires
  unique bound job IDs/URLs and all 12 successful conclusions; a workflow definition or Linux-only
  run cannot satisfy it.
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
- Verification commands run in a disposable target snapshot, but the Python standard library does
  not provide a portable host-level filesystem/network sandbox. Loom protects the original target
  from relative-path mutation and detects target drift; command authority outside that snapshot is
  **[UNVERIFIED]** until an OS sandbox provider is configured and certified.

`tools/loom_release.py certify` enforces the first 5 evidence contracts. Certification requires a
separate trust policy whose independently provisioned RSA public keys authorize each evidence type;
unsigned, self-asserted, duplicated, expired, irrelevant, tampered, or wrong-commit evidence fails.
Missing evidence blocks production certification and the 100 score; documentation cannot override
that result.
