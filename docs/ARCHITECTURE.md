# Architecture

This document describes the components of Connection Escrow, the data flow for one connection, the kernel
programs, the attribution join, the verifier and its policy, the release gate, receipts, and how the pieces are
deployed. For the threat model see [THREAT_MODEL.md](THREAT_MODEL.md); for the content gate see
[TLS_GATE.md](TLS_GATE.md); for the connection gate in depth see [DESIGN.md](DESIGN.md).

## Components

| Component | Where it runs | Responsibility |
|---|---|---|
| `cgroup/connect4` (eBPF) | kernel, attached to each supervised pod cgroup | hold the connection at `connect()`, record `cookie→{dst,cgroup,pid}`, rewrite the destination to the interceptor |
| `cgroup/sendmsg4` (eBPF) | same | pin UDP to the configured resolver (DNS), deny other datagram destinations |
| `sockops` (eBPF) | same | index `{local addr, local port}→cookie` so the interceptor can attribute across network namespaces |
| interceptor | node agent (DaemonSet), host network/PID | accept redirected sockets, attribute, park first bytes, ask the verifier, run the release gate, write receipts |
| verifier | its own pod, own signing key | evaluate policy on the pod identity, return a signed verdict bound to the socket; `allow`/`deny`/`hold` |
| registry | node agent | map cgroup path → pod identity (uid, namespace, service account, SPIFFE id) |
| audit log | both | hash-chained, signed receipts of every decision |
| TLS uprobe (`ssl_sniff`) + content model | node agent / verifier | optional: read plaintext at `SSL_write`, score it, gate content without terminating TLS |

Code map: `bpf/escrow_connect4.bpf.c`, `bpf/ssl_sniff.bpf.c`, `escrow/bpfload.py`, `escrow/tlsview.py`,
`escrow/attribution.py`, `escrow/wire.py`, `escrow/interceptor.py`, `escrow/verifier.py`, `escrow/mlcheck.py`,
`escrow/audit.py`, `escrow/canon.py`, `escrow/ed25519.py`, `escrow/cli.py`.

## Data flow for one connection

```
1. agent calls connect(dst)
2. cgroup/connect4 (in-kernel, inside the syscall, before any packet):
      escrow_map[cookie] = {dst, cgroup_id, pid}
      rewrite ctx->user_ip4/user_port  ->  interceptor
3. interceptor.accept():
      cookie   <- sockops peer_map[local addr,port]  (fallback: inet_diag)
      {dst, cgroup, pid} <- escrow_map[cookie]
      exe_sha256, comm   <- /proc/<pid>
      pod identity       <- registry[cgroup path]      (SPIFFE id)
      first bytes        <- read up to 4 KiB, <=150 ms (HTTP line / TLS ClientHello SNI)
4. interceptor -> verifier:  signed record {identity, dst, wire summary, cookie, escrow_id}
5. verifier: policy(identity, dst/service, L7) -> verdict
      Sign_k(escrow_id, cookie, H(dst, first bytes), ALLOW|DENY, t_issued, t_expires, nonce)
6. interceptor release gate (ALL must hold):
      escrow_id live (not decided, deadline not passed)
      signature verifies under verifier key
      names this escrow_id, this cookie, this H(dst, first bytes)
      not expired; not previously consumed; verdict == ALLOW
   pass -> consume atomically; connect() to dst; send parked bytes; splice
   fail / no verdict by deadline / verifier unreachable -> RST (SO_LINGER 0)
7. receipt -> hash-chained signed log (interceptor and verifier each keep one)
```

## The kernel programs (`bpf/escrow_connect4.bpf.c`)

All three attach to the supervised pod’s cgroup with `BPF_F_ALLOW_MULTI` (so several pods, and other cgroup
programs, coexist). Connections originating outside the supervised cgroups — including the interceptor’s and the
verifier’s own — are never rewritten, so there is no redirection loop.

- **`escrow_connect4`** (`cgroup/connect4`): runs inside `connect(2)`. For TCP it reads the socket cookie
  (`bpf_get_socket_cookie`), stores `{original dst, cgroup id, pid}` keyed by the cookie in `escrow_map`
  (LRU hash), and rewrites `user_ip4`/`user_port` to the interceptor. ~45 instructions, no loops.
- **`escrow_sendmsg4`** (`cgroup/sendmsg4`): applies the UDP rule to unconnected datagrams — allow the
  configured resolver, deny the rest (`EPERM`).
- **`escrow_sockops`** (`sockops`, on `ACTIVE_ESTABLISHED`): writes `{local addr, local port}→cookie` into
  `peer_map`. The interceptor accepts connections from pods that live in their own network namespace; a
  cross-namespace `inet_diag` query would not see the pod’s socket, so this index is how the interceptor finds
  the cookie. `inet_diag` remains a fallback (and the iptables path).

Maps: `escrow_map` (cookie→record), `peer_map` ({addr,port}→cookie), `cfg_map` (interceptor address, resolver),
`counter_map` (per-rule counters: tcp held, udp allowed, udp denied).

Loader: `escrow/bpfload.py` uses raw `bpf(2)` (no libbpf) — creates the maps, patches `ld_imm64` map
relocations, loads each program with its attach type, attaches to a cgroup directory. The iptables fallback
(`-t nat -A OUTPUT -p tcp -m owner --uid-owner $AGENT -j REDIRECT --to-ports $INT`) delivers the same socket and
the interceptor recovers the destination with `SO_ORIGINAL_DST`.

## Attribution (`escrow/attribution.py`)

The interceptor must identify, for a socket it did not create, three things joined through the socket cookie:

- **Kernel object:** the socket cookie (from `peer_map` or `inet_diag`), its inode and uid.
- **Process:** pid/tgid (from the eBPF map or `/proc/*/fd`→`socket:[inode]`), cgroup path, executable path and
  **SHA-256 read through `/proc/<pid>/exe`** (so a renamed/copied binary yields a new inode and the true digest
  of what ran), and `comm`.
- **Platform identity:** a registry maps the cgroup path (longest-prefix) to the pod’s uid, namespace, service
  account and **SPIFFE id** — the key the verifier’s policy is written against. On Kubernetes the node agent
  builds the registry from the API server for pods labelled supervised, refreshing on an interval.

The resulting record carries only fields supplied by the kernel or the node agent — none by the agent.

## Verifier and policy (`escrow/verifier.py`)

The verifier runs in its own pod with its own key. It accepts records authenticated by an HMAC key mounted only
in the interceptor (so a pod that reached the verifier’s port could not submit a record it would accept),
evaluates a policy keyed on the SPIFFE identity, and returns a signed verdict bound to the socket cookie and a
hash of the destination (and, for the content gate, the first bytes).

Policy rules match on: destination by name (SNI/Host glob), by Kubernetes **service** (a cluster-IP→`ns/name`
map the verifier keeps from the API server), or by address; destination port; HTTP method and path prefix. The
first matching rule decides `allow`/`deny`/`hold`. A per-workload **token-bucket budget** caps the rate of
allowed connections. A destination equal to the verifier’s own address is always denied. The policy function is
replaceable by any `decide(record) → verdict` — a rule engine, a calibrated-risk classifier, an operator queue,
or an ML model.

## The release gate (`escrow/interceptor.py`)

See the data-flow step 6. The gate is the security core: it binds a verdict to exactly one socket, consumed
once, atomically, fail-closed. A connection the gate refuses sends **no packet** to the destination, because the
interceptor only calls `connect()` toward the destination after the gate passes. The hold-and-release path adds
a kernel-independent **deadline** at the interceptor; a verdict for a connection whose deadline has passed is
rejected as stale, so a slow or replayed verdict cannot open a connection the agent attempted earlier.

## Receipts (`escrow/audit.py`)

Each decision is a receipt `{escrow_id, identity, cookie, pid, cgroup, exe digest, dst, wire summary, verdict,
reason, timings}` appended to a hash chain (each entry commits to its predecessor), signed by the node; the
verifier keeps its own chain. A tampered or removed receipt breaks the chain at that entry. In the hardened
roadmap the receipt is additionally bound to a measurement of the loaded eBPF program set plus a hardware
attestation, so a relying party verifies both the decision and that the approved enforcement was in force.

## Deployment (`deploy/k8s/`, `escrow/cli.py`)

- **Node agent** (`DaemonSet`, host PID/network, host cgroup mount, CAP_BPF/CAP_SYS_ADMIN): watches the API
  server for pods labelled `escrow.io/supervised=true`, resolves each pod cgroup under the node’s `kubepods`
  hierarchy, attaches the programs, builds the registry, and runs the interceptor on the node address reachable
  from pods (the CNI bridge).
- **Verifier** (`Deployment` + `Service` + `NetworkPolicy` admitting only node addresses), its own namespace and
  key.
- **Supervised pod:** only the label and a service account; no sidecar, no changed image.
- **iptables sidecar variant** (`deploy/k8s/40-sidecar-variant.yaml`): a per-pod init container installs the
  `REDIRECT` rule and a sidecar interceptor attributes via a shared process namespace, for clusters where eBPF
  cannot be loaded.

CLI (`escrow/cli.py`): `keygen` | `verifier` | `interceptor` (the interceptor has a Kubernetes node-agent mode:
`--kube-api` builds the registry, `--kubepods` discovers cgroups, `--dns` pins the resolver, `--workers`
`SO_REUSEPORT` scale-out, `--watch-s` picks up new pods).
