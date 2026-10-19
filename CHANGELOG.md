# Changelog

## 0.4.0 — stream gate with socket-identity binding; every write on a content-gated connection is scored

* Each write is bound to its connection by resolving the TLS session handle to the writing socket's local port
  (`SSL_set_fd` probe for OpenSSL; the following `syscall.write`/libc `write` for Go and BIO-attached OpenSSL),
  so concurrent TLS sessions in one process are disambiguated by socket identity, not arrival order
  (`experiments/tls_gate_concurrent.py`: two interleaved sessions, the exfil confined to its own connection).
* Stream gate: every outgoing application-data record is held until the write that produced it is scored; records
  are matched to writes by handle and calibrated per-record overhead; deny resets with the record held; no plaintext
  for a held record denies (fail closed). The first-record gate is kept to demonstrate the keep-alive exploit it is
  blind to (benign GET, then exfil POST on the same connection), confirmed on all three runtimes and then closed.
* Capture raised to one full TLS record (16 KiB) per write; every write pushed to a kernel FIFO with the TLS handle.
* `experiments/tls_gate_multirecord.py`: accounting check, one 40 KiB write over three records then an exfil write.
* `experiments/gen_results_md.py`: `results/RESULTS.md` is generated from the log and benchmark JSON by `run_all.sh`.

## 0.3.0 — content gate across TLS runtimes

* Content gate covers three runtime shapes with two kernel programs: shared OpenSSL (`SSL_write`/`SSL_write_ex` in
  `libssl.so`), statically linked OpenSSL/BoringSSL (same symbols inside the agent binary) and Go `crypto/tls`
  (`crypto/tls.(*Conn).Write`, Go register ABI). `escrow.tlsview` selects the program and symbol from the agent's ELF.
* `experiments/agents/`: Go and statically linked C agents; `experiments/tls_gate_demo.py [openssl|go|static|all]`.
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
