# Changelog

## 0.1.0 — initial reference implementation

* Python E1 engine (`python/pcb`): canonical JSON, pure-Python Ed25519, Merkle receipts, typed-null sidecar, mock
  attestation, negation-stratified Datalog, provenance rarity score, LTT calibration (score-ordered and
  learn-then-test), six-step gateway, hash-chained audit, gateway receipts, deny-by-default case endpoint,
  zk-attach/v0 composition (Sigma engine reused from 45h0kg/zk-proof-gateway).
* Rust E2 engine (`rust/pcbv`): the same chain with ed25519-dalek and cap-aware 2-aggregate Bulletproofs; `serve`,
  `verify`, `bench`, `vectors`, `zk-prove`.
* Go services (`go/`): gateway (MCP + A2A, audit, receipts, case store; verification delegated to `pcbv serve`) and
  sidecar (typed nulls, mock quotes). Standard library only.
* Seeded synthetic data generator and scripted agents; calibration, evaluation, adversarial suite T0–T11 (+ known-gap
  check T5b, zk-attach and Topology B checks), wire-level e2e on both stacks, cross-engine vectors, microbenchmarks.
* Dockerfiles, compose, Helm chart with deny-by-default NetworkPolicies and durable audit PVC; CI workflow including
  image builds, `helm lint` and a kind install.
* Not done in this release: real hardware attestation; the paper's public benchmarks; containers and the Helm chart
  were not built or installed in the authoring environment (no registry access) — CI covers them.
