# Threat model

## Setting

A *supervised workload* is a Kubernetes pod (or any cgroup) running an agent and the tool processes it starts.
The pod has a service account and, through it, a platform identity (a SPIFFE verifiable identity document). The
operator wants to control every outbound connection the pod makes, one connection at a time, by a policy a
verifier evaluates. The verifier is trusted by the operator and outside the agent’s control.

The question is not *what the policy should say* — that is the operator’s, and the policy engine is replaceable
— but **where** the decision is enforced so the agent cannot route around it, and **how** the decision is tied
to the exact connection it is about.

## Assets

1. **Confidentiality** of data the pod holds — an unapproved outbound connection could exfiltrate it.
2. **Integrity** of external systems — an unapproved connection could write, delete, or transfer.

## Trust boundary

- **Trusted computing base (TCB):** the operating-system kernel; the node agent that loads the eBPF programs and
  runs the interceptor; the verifier; the cluster control plane (API server, kubelet, CNI).
- **Untrusted:** everything inside the supervised pod — the agent process, every process it spawns, every
  library/interpreter it loads, any tool server it starts.
- The boundary is the pod’s **cgroup**: the kernel is on one side, the untrusted workload on the other, and the
  eBPF hook sits exactly on that line — invoked by the untrusted code but not modifiable by it.

## Adversary capabilities

The adversary has full control of the code in the pod. It **may**:

- open a connection to any address, port and protocol;
- issue the connection from the agent process, a child process, a thread, or a freshly `exec`’d binary;
- rename, copy or rebuild its executables to defeat path-based rules;
- craft arbitrary application-layer bytes (any HTTP request, any TLS ClientHello, any opaque stream);
- attempt to contact the verifier directly to forge or solicit an approval;
- replay a verdict it has observed;
- open many connections concurrently to race the control;
- observe traffic on the node network between interceptor and verifier.

It **may not**:

- escape the pod’s cgroup (container escape — a separate problem, assumed solved by the sandbox);
- obtain root on the node;
- read the verifier’s signing key or the interceptor’s record-authentication key;
- forge the kernel’s socket-cookie allocation.

Escrow composes with the sandbox and namespace isolation; it does not replace them.

## Goals and how they are met

| Goal | Statement | How it is met | Evidence |
|---|---|---|---|
| **G1 Pre-packet hold** | A refused connection produces *no packet* to the destination | The interceptor calls `connect()` to the destination only after the gate passes; on the eBPF path the agent’s own `connect()` never carried the real destination past the hook | T1, T7 |
| **G2 Attribution** | Every held connection is attributed to the socket, process and pod identity, surviving renames and children | Join on the kernel-assigned socket cookie; executable digest via `/proc/<pid>/exe`; cgroup→SPIFFE registry | T0, T11 |
| **G3 Isolated verifier** | The verdict comes from a component the agent cannot reach or impersonate | The agent’s attempt to reach the verifier is itself escrowed and refused (`destination_is_verifier`); records are HMAC’d with an interceptor-only key | T6 |
| **G4 Single-use, socket-bound** | An approval releases exactly one socket, to one destination, once; replay/rebinding/forgery fail | The gate checks signature, escrow id, socket cookie, destination hash, expiry, and prior consumption; consumption is atomic | T5 |
| **G5 Fail closed** | No verdict by the deadline, or an unreachable verifier, resets; a late approval has no effect | Deadline enforced at the interceptor independently of the verifier; the escrow id is retired, so a late verdict is stale | T3, T4, T12 |
| **G6 No agent change** | No SDK, proxy setting, library or sidecar in the agent’s process | The hook is in the kernel, attached to the cgroup; it covers the agent, its children and tool servers in any language | bypass experiment (`experiments/k8s/bypass.py`) |

The adversarial suite (`tests/test_escrow.py`) exercises each goal; the check IDs above map to it.

## Non-goals

- Escrow does not decide *whether* a connection is acceptable — that is the policy’s job (replaceable).
- It does not defend against an adversary who has escaped the pod or holds root on the node.
- It does not inspect traffic on a released connection beyond the one-time first-byte / content check.
- It does not provide confidentiality for the traffic (that is TLS’s job) and, in pass-through mode, does not
  terminate TLS.
- It is not a replacement for NetworkPolicy or a service mesh; it composes with them, adding a per-connection,
  identity-bound, fail-closed decision those layers do not provide.

## Residual risk

- An attacker with **root on the node** can detach the programs or read keys; a production deployment pairs
  escrow with attestation of the loaded program set (roadmap).
- **Data-only reuse** of an already-released connection is out of scope: escrow controls the opening of a
  connection and (with the content gate) its first application record, not the full stream.
- **Encrypted content to an allowed destination:** the connection gate decides on destination + identity; the
  content gate adds content inspection without terminating for shared OpenSSL, static OpenSSL/BoringSSL and Go
  `crypto/tls`; Rustls and stripped binaries need their own probe targets, and a covert channel inside otherwise-allowed traffic is not addressed by the
  connection gate alone.
