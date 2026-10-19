# Documentation index

Connection Escrow — kernel-enforced, per-connection, identity-bound egress control for AI-agent workloads, with
optional content inspection that never terminates TLS.

Start with the top-level [`../README.md`](../README.md), then:

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, data flow for one connection, the three kernel programs, the attribution join, the verifier and policy, the release gate, receipts, and deployment. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trusted computing base, adversary capabilities, the six goals (G1–G6) and how each is met, non-goals, residual risk. |
| [DESIGN.md](DESIGN.md) | The connection gate in depth: the hold point, release-gate conditions, hold-and-release with a deadline. |
| [TLS_GATE.md](TLS_GATE.md) | The content gate: reading every plaintext write via a TLS-write uprobe, holding each record until its write is scored (stream gate), what is and isn’t novel, TLS 1.3, scope and limitations. |
| [REPRODUCE.md](REPRODUCE.md) | Step-by-step reproduction of every result (adversarial suite, microbenchmark, content gate, Kubernetes). |

## Mental model in three sentences

1. The one thing encryption cannot hide is the destination, because the kernel must know it to route — and the
   connection gate sits exactly there, holding each `connect()` until an isolated verifier returns a verdict
   bound to that one socket, used once, fail-closed.
2. That decides *where* the agent may connect, which is the right control for the dominant agent-egress threats
   (exfiltration to an unauthorized destination, command-and-control, calling a forbidden service).
3. When you also need to decide *what* the agent sends, the content gate reads the plaintext at the agent’s own
   TLS-library boundary via an eBPF uprobe and gates on it — without terminating TLS, without a key at the
   enforcer, keeping the connection end-to-end to the real server.
