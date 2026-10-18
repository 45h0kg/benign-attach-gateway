# Connection Escrow

**Kernel-enforced, per-connection, identity-bound egress control for AI-agent workloads — with optional content inspection that never terminates TLS.**

Reference implementation for the preprint *“Connection Escrow: Holding AI-Agent Pod Egress in the Kernel Until an Isolated Verifier Rules”* (A. S. Gopalakrishna, 2026; arXiv: TBD).

---

## Table of contents
- [What this is](#what-this-is)
- [Why](#why-the-problem)
- [How it works](#how-it-works)
- [The content gate (see TLS plaintext without terminating)](#the-content-gate)
- [Quick start](#quick-start)
- [What the tests prove](#what-the-tests-prove)
- [Results](#results)
- [Repository layout](#repository-layout)
- [Deploying on Kubernetes](#deploying-on-kubernetes)
- [Security model](#security-model)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [Citing / related work](#citing--related-work)
- [License](#license)

---

## What this is

An autonomous agent running in a container decides what to do from text it is given — a web page, a tool’s
output, a ticket. When that text is hostile (prompt injection, a poisoned document, a compromised upstream
tool), the **connection the agent opens** is where the attack becomes a real action in the world. Connection
Escrow controls that connection at the one place the agent cannot route around it: **inside the operating-system
kernel, before any packet leaves.**

Two cooperating mechanisms:

1. **Connection escrow (the connection gate).** Every outbound TCP connection a supervised pod makes is *held*
   inside the kernel’s `connect()` path, attributed to the exact socket / process / pod, and released only when
   a verifier in a **separate container** returns a **signed verdict bound to that one socket**. No verdict by a
   deadline → the connection is reset and the destination never sees a packet. This decides **where** the agent
   may connect — which encryption cannot hide, because the kernel must know the destination to route.

2. **The content gate (optional).** For a connection the policy permits, an eBPF **uprobe** reads the plaintext
   the agent writes at its TLS-library boundary (`SSL_write`/`SSL_write_ex`), a model scores it, and the first
   application record is held until the verdict — **while the TLS session stays end-to-end to the real server
   with the real certificate and the enforcer holds no key.** This decides **what** the agent may send, without
   the man-in-the-middle a normal content inspector requires.

**The agent is unmodified** — no SDK, no proxy environment variable, no sidecar library, no changed image.
`curl`, Python, a Go binary, a child process, code the agent writes at runtime: all are held, because the hook
lives in the kernel, attached to the pod’s cgroup, not in the agent’s address space.

---

## Why (the problem)

Existing agent-egress controls sit at the application layer and share two weaknesses:

- **Bypassable.** A gateway, an SDK hook, or an `HTTP_PROXY` setting is defeated by a child process, a raw
  socket, a proxy-unaware client, or run-time-generated code. (This repo *demonstrates* the bypass: see
  `experiments/k8s/bypass.py`.)
- **Approval ≠ connection.** Even when not bypassed, the approval is not bound to the connection the kernel
  later opens — a time-of-check-to-time-of-use (TOCTOU) gap. A later or replayed connection to the same host
  reuses the approval.

Kernel-level allow-lists (ActPlane, mcpguard, Tetragon, ProcRoute) fix bypassability but apply **standing
policy**: once a destination is allowed, every matching connection is allowed, and the decision is local — it
cannot wait on an external, per-connection verdict. Connection escrow closes both gaps: a **held** connection,
decided by an **external** verifier, with the verdict **bound to one socket, used once, fail-closed.**

---

## How it works

```
 supervised pod (cgroup c_p)          kernel                      node agent                 separate pod
 ┌───────────────────────┐     ┌──────────────────────┐     ┌───────────────────────┐   ┌──────────────────┐
 │ agent (any language,  │     │ cgroup/connect4 (eBPF)│     │ interceptor           │   │ verifier         │
 │ any child, any tool)  │─connect()─▶ record cookie→  │     │  • accept redirected  │   │  • policy / ML    │
 │                       │     │   {dst, c_p, pid};    │─────▶  • attribute (cookie  │──▶│  • signs a verdict│
 │                       │     │   rewrite dst→icpt    │     │    →pod SPIFFE id)    │   │    bound to the  │
 └───────────────────────┘     │ sendmsg4: pin DNS     │     │  • park first bytes   │◀──│    one socket     │
                               │ sockops: cookie index │     │  • release gate       │   └──────────────────┘
                               └──────────────────────┘     │  • receipts (signed,  │
                                                            │    hash-chained)      │──▶ hash-chained audit log
 ALLOW: interceptor ──connect + forward parked bytes──▶ destination service        │
 DENY / no verdict by deadline D: RST — destination never receives a packet        │
```

Step by step, for one connection:

1. **Hold.** A `cgroup/connect4` eBPF program (attached to the pod’s cgroup) runs inside `connect(2)`, before a
   route is allocated. It records `socket cookie → {original destination, cgroup id, pid}` in a kernel map and
   rewrites the destination to the node-agent interceptor. The agent’s `connect()` simply succeeds.
2. **Attribute.** The interceptor accepts the redirected socket, recovers the **socket cookie** (via a `sockops`
   index that works across network namespaces, or `inet_diag`), reads back the original destination, and joins
   it to the process (pid, executable SHA-256, cgroup) and the **pod’s SPIFFE identity** (from a cgroup→identity
   registry). It parks the first bytes the agent writes (HTTP request line, or TLS ClientHello → SNI).
3. **Verify.** The interceptor sends a signed record to the verifier (a separate pod with its own key). The
   verifier evaluates a policy keyed on the SPIFFE identity and returns a verdict **bound to that socket cookie
   and destination**, `allow` / `deny` / `hold`.
4. **Release gate.** The interceptor releases the connection **only** if the verdict verifies under the
   verifier’s key, names this socket and destination, is unexpired, and has not been consumed — then it connects
   out and splices. Anything else (including no verdict by the deadline, or an unreachable verifier) resets the
   connection. A verdict arriving after the deadline is rejected as *stale*.
5. **Receipt.** Every decision becomes a signed, hash-chained receipt naming the agent identity, the connection,
   and the verdict.

Companion kernel programs: **`sendmsg4`** pins UDP (DNS) to the cluster resolver so resolution can’t be used as
an exfiltration channel; **`sockops`** indexes the socket cookie so the interceptor can attribute connections
from pods in other network namespaces.

Full detail: **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** and **[`docs/DESIGN.md`](docs/DESIGN.md)**.

---

## The content gate

The connection gate decides *where*; the content gate decides *what* — **without terminating TLS.**

The one thing encryption can never hide is the destination (the kernel needs it to route), and the connection
gate sits exactly there. What encryption hides is the request **content**. To see it without a man-in-the-middle
proxy (which holds a key and breaks end-to-end), we read the plaintext at the agent’s own endpoint:

- An eBPF **uprobe** on the agent’s TLS library (`SSL_write` / `SSL_write_ex` in OpenSSL 3) is invoked with the
  plaintext buffer *before* it is encrypted, and copies it into a kernel map. The TLS session is untouched — it
  completes end-to-end to the real server, which presents its real certificate, and the agent validates it. The
  enforcer never holds a key and never decrypts the wire.
- The interceptor forwards the handshake untouched, then **holds the first application-data record** until a
  verdict on the captured plaintext. A content model (`escrow/mlcheck.py`, a deterministic logistic-regression
  **placeholder**) scores the request; `allow` releases it end-to-end, `deny` resets before the server sees it.

```bash
bash experiments/agents/build.sh                            # Go + static-OpenSSL agents (needs go, gcc, libssl-dev)
sudo PYTHONPATH=. python3 experiments/tls_gate_demo.py all   # openssl | go | static | all
# benign  GET  /v1/items  -> cert OK, allowed end-to-end, server receives it
# exfil   POST /transfer  -> denied on its plaintext (p=0.999), connection reset, server receives nothing
```

Capturing TLS plaintext via uprobes is known from observability tools (e.g. AgentSight); they **observe**. The
contribution here is to **act** on it — to *gate* the connection on the plaintext with a single-use,
identity-bound verdict while keeping the connection end-to-end with no key at the enforcer. Full detail:
**[`docs/TLS_GATE.md`](docs/TLS_GATE.md)**.

---

## Quick start

Requirements: Linux ≥ 6.x with cgroup v2 and `cgroup/connect4` support, `clang` (bpf target), `iptables`,
Python 3.10+, root (to load eBPF / attach to cgroups). `pip install -r requirements.txt`.

```bash
# build the eBPF objects
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/escrow_connect4.bpf.c -o bpf/escrow_connect4.bpf.o
clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c bpf/ssl_sniff.bpf.c       -o bpf/ssl_sniff.bpf.o

# adversarial suite: 36 checks on the eBPF hold point, 33 on the iptables hold point
sudo PYTHONPATH=. python3 tests/test_escrow.py both

# latency microbenchmark (native + pure-Python Ed25519)
sudo PYTHONPATH=. python3 bench/bench.py 200

# end-to-end with an unmodified curl as the agent
sudo bash experiments/cli_smoke.sh

# content gate: TLS plaintext via uprobe + ML, no termination
bash experiments/agents/build.sh                            # Go + static-OpenSSL agents (needs go, gcc, libssl-dev)
sudo PYTHONPATH=. python3 experiments/tls_gate_demo.py all   # openssl | go | static | all

# everything, logged
sudo bash experiments/run_all.sh        # -> results/execution_log.txt
```

Reproduce the on-cluster results (needs a single-node Kubernetes host): see
**[`docs/REPRODUCE.md`](docs/REPRODUCE.md)**.

---

## What the tests prove

`tests/test_escrow.py` runs a 36-check adversarial suite (33 on the iptables path) against **real cgroups, real
sockets, and uid-separated agent processes**. Highlights:

| Check | What it demonstrates |
|---|---|
| T0 | Allowed connection released; destination receives exactly the parked bytes; receipt names the pid, pod cgroup, SPIFFE id, cookie, executable digest |
| T1 | Denied connection reset; **destination accepts nothing** |
| T3 / T4 | No verdict by the deadline → reset (fail-closed); a correctly-signed **late** ALLOW is refused as stale |
| T5 | Forged, re-bound (other socket / other destination), expired, and **replayed** verdicts all refused; a valid verdict is accepted exactly once |
| T6 | The agent’s own attempt to reach the verifier is itself escrowed and refused |
| T7 | TLS SNI allow/deny; the parked ClientHello is delivered byte-for-byte on release |
| T11 | A **child process** and a **renamed binary** are still attributed to the pod and gated |
| T12 | Verifier down → allowed destination still refused (fail closed) |
| T13 | Audit chains verify; a tampered receipt breaks the chain |
| T14 | UDP to a public resolver and UDP exfil denied in-kernel; the cluster resolver allowed (DNS pinning) |

---

## Results

All numbers come from logged runs (`results/`).

- **Correctness:** 36/36 (eBPF) adversarial checks pass on Linux 6.18; 33 of them apply on iptables and pass (the UDP-pinning checks need the kernel path).
- **Latency (loopback microbenchmark):** ~4.5 ms median hold per released connection (6.7 ms p95) on the eBPF
  path; **24 µs** of that is policy evaluation — the rest is attribution, one HTTP round trip and two signatures.
  See `results/RESULTS.md`.
- **Kubernetes (single-node k3s v1.34.1):** an unmodified agent pod is gated per connection and attributed to
  its SPIFFE identity; the exfil destination receives nothing while the allowed service is reached; a raw socket
  that **bypasses a comparison sidecar proxy** is **held by escrow**; 6 pods × 100 connections (600) are all
  gated at ~59 conn/s. See `results/RESULTS_K8S.md`.
- **Content gate (OpenSSL shared, Go `crypto/tls`, static OpenSSL — same gate, three probe placements):** an
  exfil POST is denied on its captured plaintext and never reaches the server, while a
  benign request completes on a certificate-verified end-to-end TLS connection; the enforcer holds no key. See
  `results/RESULTS_TLSGATE.md`.

---

## Repository layout

```
bpf/
  escrow_connect4.bpf.c    connection gate: connect4 (hold+rewrite), sendmsg4 (DNS pin), sockops (cookie index)
  ssl_sniff.bpf.c          content gate: uprobe reading SSL_write/SSL_write_ex plaintext
escrow/
  bpfload.py               raw bpf(2) loader for the connection-gate programs (no libbpf)
  tlsview.py               raw bpf(2) + perf_event_open loader for the TLS-plaintext uprobe
  attribution.py           socket cookie (sockops/inet_diag), /proc, cgroup→pod registry
  wire.py                  HTTP request / TLS ClientHello first-bytes parser
  interceptor.py           hold, attribute, ask the verifier, release gate, receipts
  verifier.py              policy engine, hold/release, signed verdicts, service map
  mlcheck.py               content-gate ML classifier (deterministic placeholder)
  audit.py canon.py ed25519.py   hash-chained log, canonical JSON, Ed25519 (pure-Python + native)
  cli.py                   keygen | verifier | interceptor (incl. Kubernetes node-agent mode)
tests/                     harness (real cgroups/sockets/uids) + 36-check adversarial suite
bench/bench.py             latency breakdown, baseline, concurrency
experiments/
  cli_smoke.sh             curl as the agent, end to end
  tls_gate_demo.py         content gate: plaintext via uprobe + ML, no TLS termination (3 runtimes)
  agents/                  Go and statically-linked OpenSSL agent clients for the content gate
  run_all.sh               one-command reproduction (stages 0–6) -> results/execution_log.txt
  k8s/                     on-cluster drivers: build_image, drive, bypass, scale + manifests
deploy/k8s/                verifier Deployment, node-agent DaemonSet, supervised pod, iptables sidecar variant
docs/                      ARCHITECTURE, THREAT_MODEL, DESIGN, TLS_GATE, REPRODUCE (+ this index)
results/                   logged runs: RESULTS, RESULTS_K8S, RESULTS_TLSGATE, benchmarks
```

---

## Deploying on Kubernetes

`deploy/k8s/` contains the verifier Deployment and the node-agent DaemonSet (host PID/network, host cgroup
mount, the capabilities needed to load/attach eBPF). A supervised pod needs only the label
`escrow.io/supervised=true` and its service account — no sidecar, no changed image. An `iptables` sidecar
variant is provided for clusters where eBPF cannot be loaded.

Validated on single-node **k3s v1.34.1** (upstream Kubernetes). Works on **standard GKE / AKS node pools**
(cgroup v2, recent kernels); **not** GKE Autopilot / AKS virtual nodes (no privileged DaemonSet / eBPF load).
On Cilium-based dataplanes (GKE Dataplane V2, Cilium-AKS) the `connect4` program must coexist with Cilium’s own
via `BPF_F_ALLOW_MULTI` — test ordering first. See **[`docs/REPRODUCE.md`](docs/REPRODUCE.md)**.

---

## Security model

- **Trusted:** the kernel, the node agent (interceptor + loader), the verifier, and the cluster control plane.
- **Untrusted:** everything in the supervised pod — the agent, its children, its libraries, its tool servers.
- **Adversary may:** connect anywhere, from any child/thread/renamed binary, craft any bytes, try to reach the
  verifier, replay verdicts, and race concurrently.
- **Adversary may not:** escape the pod cgroup (container escape, out of scope), get root on the node, read the
  verifier/record keys, or forge the kernel’s socket-cookie allocation.

How each goal is met is spelled out in **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)**.

---

## Limitations

- **Encrypted content vs. destination:** the connection gate decides on destination + identity (which encryption
  cannot hide) — it is **not** a content/DLP tool by itself. The content gate adds content inspection for
  TLS **without** terminating, for three runtime shapes: shared OpenSSL (`SSL_write`/`SSL_write_ex` in
  `libssl.so`), statically linked OpenSSL/BoringSSL (the same symbols inside the agent binary) and Go
  `crypto/tls` (`crypto/tls.(*Conn).Write`, Go register ABI). Rustls and stripped binaries are not yet covered.
- **IPv4 only** for now; IPv6 needs the `connect6`/`sendmsg6` hooks. UDP is *pinned* (DNS to the cluster
  resolver), not escrowed for a verdict.
- The prototype interceptor is a single Python process; the content model is a deterministic placeholder; both
  are replaceable and are not the contribution.
- The content gate correlates plaintext to a connection by writing task (`pid_tgid`) and decides on the first
  application record only; an agent multiplexing TLS sessions on one thread needs the `SSL*`/`*tls.Conn` handle
  as the key (readable by the uprobe, not wired).
- Fully-managed node tiers (GKE Autopilot, AKS virtual nodes) are unsupported by design (no node access).

---

## Roadmap

- Inline **proof-of-check**: the interceptor injects a verifier-signed token (e.g. an `X-Escrow-Verdict` header)
  on release so a cooperating destination can validate that a connection was checked, by which identity.
- **Attested receipts**: bind each receipt to a measurement of the loaded eBPF program set + a hardware
  attestation, so a relying party verifies both the decision and that the approved enforcement was in force.
- Compiled interceptor + persistent verifier connection (removes most per-connection latency); multi-worker
  `SO_REUSEPORT` scale-out; multi-node cluster run.
- Content gate: TLS 1.3 record handling via the uprobe-trigger path; Rustls probe target; handle-keyed
  correlation; a real content model keyed on identity.

---

## Documentation

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — components, data flow, kernel programs, attribution, gate.
- **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)** — assets, TCB, adversary, goals G1–G6, non-goals.
- **[docs/DESIGN.md](docs/DESIGN.md)** — the connection gate in depth, release-gate conditions, hold/deadline.
- **[docs/TLS_GATE.md](docs/TLS_GATE.md)** — content gate: uprobe capture, holding, TLS 1.3, scope.
- **[docs/REPRODUCE.md](docs/REPRODUCE.md)** — run everything (suite, bench, cluster, content gate).

---

## Citing / related work

```
A. S. Gopalakrishna, "Connection Escrow: Holding AI-Agent Pod Egress in the Kernel Until an
Isolated Verifier Rules," preprint, 2026.
```

Related earlier work: [zk-proof-gateway](https://github.com/45h0kg/zk-proof-gateway).

> **Note on disclosure/patent order.** If you intend to file a patent on the mechanisms here (kernel-held
> verifier-gated single-use release; content gating without TLS termination), file the provisional **before**
> making the repository or the paper public — most jurisdictions outside the US grace period treat your own
> publication as prior art against your filing.

## License

MIT (see `LICENSE`). Note: MIT grants no express patent licence; choose deliberately before relying on it for
patent strategy.
