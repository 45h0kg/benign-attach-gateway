# Connection Escrow

Reference implementation for the preprint *"Connection Escrow: Holding AI-Agent Pod Egress in the Kernel Until
an Isolated Verifier Rules"* (A. S. Gopalakrishna, 2026, arXiv: TBD).

Every outbound TCP connection from a supervised container is parked **inside the kernel's `connect()` path**,
attributed to its socket cookie, process, cgroup and pod, and released only when a verifier in a separate
container returns a signed verdict bound to that one socket. No verdict by the deadline: the connection is
reset and the destination never sees a packet. The agent is unmodified: no SDK, no proxy settings, no sidecar
library. `curl`, Python, a child shell: all held.

```
agent pod ──connect()──▶ eBPF cgroup/connect4 ──rewrite──▶ interceptor ──record──▶ verifier (own pod)
                        cookie→{dst,cgroup,pid}            park bytes  ◀─verdict──  policy / hold / release
                                                           release only the socket the verdict names, once
```

**Status.** Prototype in Python (stdlib + optional `cryptography` for native Ed25519) and 45 instructions of
eBPF. Both hold points (eBPF, iptables) pass the 33-check adversarial suite on Linux 6.18. Kubernetes manifests
are written but have not been applied to a cluster. See `docs/DESIGN.md` and `results/RESULTS.md`.

## Run it (root, Linux 6.x, cgroup v2, clang, iptables)
```bash
pip install pyelftools cryptography          # pyelftools for the loader; cryptography optional (faster Ed25519)
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/escrow_connect4.bpf.c -o bpf/escrow_connect4.bpf.o
python3 tests/test_escrow.py both             # 66/66 (33 checks x 2 hold points)
python3 bench/bench.py 200                    # results/bench_*.json
bash experiments/cli_smoke.sh                 # curl as the agent
bash experiments/run_all.sh                   # everything, logged to results/execution_log.txt
```

## Layout
```
bpf/escrow_connect4.bpf.c     kernel hold point (cgroup/connect4): record + rewrite
escrow/bpfload.py             raw bpf(2) loader (no libbpf), map access
escrow/attribution.py         socket cookie (inet_diag), /proc, pod registry
escrow/wire.py                HTTP / TLS ClientHello first-bytes parser
escrow/interceptor.py         hold, attribute, ask, release gate, receipts
escrow/verifier.py            policy, hold/release, signed verdicts
escrow/audit.py canon.py ed25519.py
escrow/cli.py                 keygen | verifier | interceptor (incl. Kubernetes node-agent mode)
tests/                        harness (real cgroups, real sockets, uid-separated agents), 33-check suite
bench/bench.py                latency breakdown, baseline, 16-way concurrency
deploy/k8s/                   verifier, node-agent DaemonSet, supervised pod, sidecar variant
docs/DESIGN.md  results/      design notes; canonical run
```

## Earlier work
Related earlier work: [zk-proof-gateway](https://github.com/45h0kg/zk-proof-gateway).

## License
MIT

## On a Kubernetes cluster
`deploy/k8s/` holds the DaemonSet (node agent: interceptor + eBPF) and the verifier Deployment.
`experiments/k8s/` reproduces the on-cluster results against real pods (see `results/RESULTS_K8S.md`):
```
experiments/k8s/build_image.py   build escrow/lab:dev from host files (no registry needed)
experiments/k8s/drive.py         per-connection enforcement on real pods, with attribution
experiments/k8s/bypass.py        sidecar-proxy vs escrow (raw socket bypasses the proxy, not escrow)
experiments/k8s/scale.py         K pods x N connections through one interceptor
```
Tested on single-node k3s v1.34.1 (upstream Kubernetes); the manifests are standard and run on
kind or any conformant cluster with cgroup v2 and BPF-LSM/`cgroup/connect4` support.
