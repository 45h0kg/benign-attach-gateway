# Changelog

## 0.3.0 — content gate across TLS runtimes; regenerated canonical run

* Content gate covers three runtime shapes with two kernel programs: shared OpenSSL (`SSL_write`/`SSL_write_ex` in
  `libssl.so`), statically linked OpenSSL/BoringSSL (same symbols inside the agent binary) and Go `crypto/tls`
  (`crypto/tls.(*Conn).Write`, Go register ABI). `escrow.tlsview` selects the program and symbol from the agent's ELF.
* `experiments/agents/`: Go and statically linked C agents; `experiments/tls_gate_demo.py [openssl|go|static|all]`.
* `results/` regenerated from one logged run of `experiments/run_all.sh` (36/36 eBPF, 34/34 iptables, 3/3 runtimes);
  `results/RESULTS.md` is generated from `bench_*.json` and `execution_log.txt`.
* Comprehensive README and `docs/` (architecture, threat model, reproduction).

## 0.2.0 — on-cluster enforcement

* Node agent mode for Kubernetes: pod registry from the API server, cgroup discovery under `kubepods`, per-pod attach,
  DNS pinning via `cgroup/sendmsg4`, `sockops` peer index for cross-namespace attribution; `deploy/k8s/` manifests.
* Cluster experiments on k3s: enforcement against real pods, sidecar-proxy bypass comparison, 6 pods x 100 connections.
* Content gate (first version): `SSL_write` uprobe, first-application-record hold, logistic-regression placeholder model.

## 0.1.0 — connection escrow

* `cgroup/connect4` hold point (socket cookie -> {dst, cgroup, pid}, destination rewrite), iptables `REDIRECT` fallback.
* Interceptor: attribution join (cookie, `/proc`, cgroup -> SPIFFE registry), parked first bytes, HMAC-authenticated
  records, single-use socket-bound release gate, deadline, hash-chained signed receipts.
* Verifier: rule engine (SNI/Host, service, address, port, method/path), per-workload budget, hold/release.
* Adversarial suite (`tests/test_escrow.py`), latency microbenchmark (`bench/bench.py`), CLI smoke test.
