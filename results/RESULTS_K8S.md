# On-cluster results (single-node Kubernetes, k3s v1.34.1)

One logged run on the same host, Linux 6.18, cgroup v2. The node agent (verifier + interceptor +
eBPF) runs as a host process against real pods, exactly as the DaemonSet in `deploy/k8s` would;
agent pods are unmodified and gate-released only after the eBPF programs are attached to their cgroup,
so the first connection is already held. `escrow/lab:dev` is built from host files (no registry).

## 1. Enforcement on real pods (`experiments/k8s/drive.py`)
Agent task: GET internal-api/data, POST internal-api/collect, POST external-sink/upload, GET external-sink/data, plus a child process POST to external-sink. Policy: this pod's SPIFFE id may reach `lab/internal-api` only.

| | unsupervised pod | supervised pod (escrow) |
|---|---|---|
| internal-api calls reached | 2 | 2 |
| external-sink calls reached | 2+child | 0 |
| posts external-sink received | 1 | 0 |
| posts internal-api received | 1 | 1 |

Supervised kernel counters: {'tcp_held': 5, 'udp_allowed': 20, 'udp_denied': 0, 'other_denied': 0} (every TCP connect held; DNS to the cluster resolver allowed, none leaked).
Receipts attribute each verdict to the pod's SPIFFE id, cgroup, pid and `comm`, with the resolved Host name:

- `RELEASED` rule[0] -> internal-api.lab.svc.cluster.local (10.43.226.60:80)  pod=`agent` comm=python3
- `RELEASED` rule[1] -> internal-api.lab.svc.cluster.local (10.43.226.60:80)  pod=`agent` comm=python3
- `DENIED` DENY: default -> external-sink.lab.svc.cluster.local (10.43.242.71:80)  pod=`agent` comm=python3
- `DENIED` DENY: default -> external-sink.lab.svc.cluster.local (10.43.242.71:80)  pod=`agent` comm=python3
- `DENIED` DENY: default -> external-sink.lab.svc.cluster.local (10.43.242.71:80)  pod=`agent` comm=python3

## 2. Bypass comparison (`experiments/k8s/bypass.py`)
Same goal (reach internal-api, not external-sink) under two controls. The agent makes one HTTP call (honours `HTTP_PROXY`) and one raw-socket call to external-sink's IP (ignores it).

| control | http-client call | raw-socket call | posts external-sink received |
|---|---|---|---|
| sidecar proxy (`HTTP_PROXY` -> deny-all) | blocked (403 at proxy) | **reached** | 1 |
| connection escrow (kernel hold) | blocked (reset) | blocked (reset) | 0 |

The proxy stops only traffic that consults it; the raw socket bypasses it and the data leaves the pod. Escrow holds both at `connect()`; escrow counters {'tcp_held': 2, 'udp_allowed': 4, 'udp_denied': 0, 'other_denied': 0}.

## 3. Scale (`experiments/k8s/scale.py`)
6 supervised pods x 100 connections to internal-api = 600, one interceptor, on 2 shared vCPUs.

- 600/600 connections released, 600 reached by the agents (100%).
- Throughput 58.6 conn/s over 10.25s wall.
- Hold latency (accept to release, real cluster routing + per-connection DNS): p50 18.34 ms, p95 37.57 ms, p99 57.19 ms.
- DNS: 2400 queries to the cluster resolver allowed, 0 denied/leaked.

Higher than the loopback microbenchmark because each connection is pod -> cni0 -> host interceptor -> ClusterIP (kube-proxy) -> backend pod, and the interceptor, verifier, six agent pods and k3s share two vCPUs. The kernel hook (one map update) is not the bottleneck; the single-process Python interceptor is.
