# Reproducing the results

Every number in `results/` comes from a logged run of the commands below. Two environments: a single Linux host
(adversarial suite, microbenchmark, content gate) and a single-node Kubernetes cluster (on-cluster enforcement,
bypass comparison, scale).

## Prerequisites

- Linux ≥ 6.x with **cgroup v2** and `cgroup/connect4` support (most distros since ~5.15).
- `clang`/`llvm` with the bpf target, `iptables`, `openssl`, Python 3.10+.
- `pip install -r requirements.txt` (`pyelftools`, `cryptography` optional, `numpy` for the content model).
- **root** (loading eBPF and attaching to cgroups needs privilege).

Check quickly:

```bash
uname -r                                   # >= 5.15, ideally 6.x
ls /sys/fs/cgroup/cgroup.controllers       # cgroup v2 present
clang --version | head -1                  # bpf target
cat /sys/bus/event_source/devices/uprobe/type   # uprobe PMU (for the content gate)
```

## 1. Build the eBPF objects

```bash
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/escrow_connect4.bpf.c -o bpf/escrow_connect4.bpf.o
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/ssl_sniff.bpf.c       -o bpf/ssl_sniff.bpf.o
```

## 2. Adversarial suite (correctness)

```bash
sudo PYTHONPATH=. python3 tests/test_escrow.py both
# expect: 36/36 on the eBPF hold point, 34/34 on iptables (33 applicable + one not-applicable marker for UDP pinning)
```

The harness creates one cgroup per pod, runs each agent as a separate uid-separated process inside it, and uses
loopback echo servers that record every accepted connection. See `results/RESULTS.md` for the check list.

## 3. Latency microbenchmark

```bash
sudo PYTHONPATH=. python3 bench/bench.py 200          # -> results/bench_native.json / bench_purepy.json
```

Breaks a released connection into attribution, verifier round trip, gate, and upstream connect, with native and
pure-Python Ed25519, plus a 16-way concurrency figure.

## 4. End-to-end with an unmodified client

```bash
sudo bash experiments/cli_smoke.sh
# curl in a supervised cgroup reaches the allowed port; its attempt to reach the verifier is reset
```

## 5. Content gate (TLS plaintext, no termination)

```bash
bash experiments/agents/build.sh                           # builds go_agent (Go 1.21+) and static_agent (gcc + libssl-dev static archives)
sudo PYTHONPATH=. python3 experiments/tls_gate_demo.py all both # -> results/RESULTS_TLSGATE.md, results/tls_gate_runtimes.json
# for each of openssl / go / static, one keep-alive connection (benign GET then exfil POST on the same connection):
#   first  -> exploit confirmed: the POST reaches the server after the GET opened the connection
#   stream -> GET allowed, POST denied mid-stream on its plaintext, server receives only the GET
sudo PYTHONPATH=. python3 experiments/tls_gate_multirecord.py   # 40 KiB write over 3 records, then exfil: accounting
```

Requires the uprobe PMU. The OpenSSL runtime probes `libssl.so.3`; the Go and static runtimes probe the agent
binary itself (`crypto/tls.(*Conn).Write`, or `SSL_write` linked in), so those binaries must not be stripped. The demo uses TLS 1.2 so application-data
records are cleanly distinguishable from the handshake; see `docs/TLS_GATE.md` for TLS 1.3.

## 6. Everything, logged

```bash
sudo bash experiments/run_all.sh        # stages 0–6 -> results/execution_log.txt
```

## 7. On a Kubernetes cluster

Any single-node conformant cluster with cgroup v2 works. The reference run used **k3s v1.34.1**:

```bash
# (example) bring up a single-node k3s with a native snapshotter
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--snapshotter native" sh -

# build the lab image from host files (no registry needed) and import it
sudo PYTHONPATH=. python3 experiments/k8s/build_image.py /tmp/escrow-lab.tar
sudo k3s ctl images import /tmp/escrow-lab.tar        # or: ctr -n k8s.io images import

# deploy the lab namespace + services, then run the drivers (KUBECTL defaults to "k3s kubectl")
KUBECTL="k3s kubectl" sudo -E python3 experiments/k8s/drive.py     # -> results/k8s/experiment.json
KUBECTL="k3s kubectl" sudo -E python3 experiments/k8s/bypass.py    # -> results/k8s/bypass.json
KUBECTL="k3s kubectl" sudo -E python3 experiments/k8s/scale.py 6 100   # -> results/k8s/scale.json
```

`drive.py` runs the node agent (verifier + interceptor + eBPF) as a host process against real pods, exactly as
the DaemonSet in `deploy/k8s/` would; `bypass.py` compares a sidecar proxy with escrow (a raw socket bypasses
the proxy but is held by escrow); `scale.py` runs K pods × N connections through one interceptor. See
`results/RESULTS_K8S.md`.

### Managed clusters (GKE / AKS)

- **Standard node pools:** works. Recent kernels, cgroup v2. The node agent needs a privileged DaemonSet.
- **GKE Autopilot / AKS virtual nodes:** **not supported** — no privileged DaemonSet, no eBPF load. (A weaker,
  L7-only mesh variant is possible but loses the bypass-resistance; not in this repo.)
- **Cilium dataplanes** (GKE Dataplane V2, Cilium-AKS): the `connect4` program must coexist with Cilium’s own
  via `BPF_F_ALLOW_MULTI` — validate service-routing ordering before relying on it. Non-Cilium dataplanes are
  clean.

## Notes / gotchas

- Some sandboxes cap `RLIMIT_MEMLOCK`; the loaders here use raw `bpf(2)` with memcg accounting (kernel ≥ 5.11)
  and don’t need it.
- On a hybrid cgroup v1+v2 host the v2 hierarchy may be under `/sys/fs/cgroup/unified`; the CLI’s
  `--unified-root` sets the root used to compute cgroup paths.
- The content gate attaches the uprobe to a specific pid in the demo; a system-wide uprobe on `SSL_write` would
  instrument every TLS process on the node — prefer per-pid/per-cgroup attachment.
