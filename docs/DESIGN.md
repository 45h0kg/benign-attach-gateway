# Connection escrow: design

**Problem.** An AI agent running in a container decides, from text it was given, to open network
connections. The text can be hostile. A gateway or SDK hook between the agent and its tools can be bypassed by
a child process or a direct socket, and even where it is not bypassed, its approval is not tied to the
connection the kernel later opens.

**Idea.** Park every outbound connection of a supervised workload *in the kernel's connect() path*, before any
packet exists; attribute it to the exact socket, process, cgroup and pod; ask a verifier that lives in a
separate container; release only the one socket that a signed, single-use verdict names; fail closed at a
deadline. The agent needs no change, no library and no proxy setting: whatever it runs, in any language, in any
child process, is held.

## Components
| | where | does |
|---|---|---|
| `escrow_connect4` (eBPF, `cgroup/connect4`) | kernel, attached to each supervised pod's cgroup | records `cookie -> {orig dst, cgroup id, pid/tgid}` and rewrites the destination to the interceptor |
| interceptor (`escrow/interceptor.py`) | node agent (DaemonSet) or sidecar | accepts the held socket, attributes it, parks the first bytes, asks the verifier, releases or resets, signs a receipt |
| verifier (`escrow/verifier.py`) | its own pod, own key | policy per workload identity; `allow` / `deny` / `hold` (operator release); signed verdict bound to one socket |
| registry (`escrow/attribution.py`) | node agent | cgroup path -> pod uid / namespace / service account / SPIFFE id |
| audit (`escrow/audit.py`) | both | hash-chained receipts |

Without eBPF, an iptables `REDIRECT` keyed on the agent's uid gives the same hold point with conntrack NAT; the
interceptor recovers the destination with `SO_ORIGINAL_DST`. Both paths are tested.

## The attribution record
```
cookie       kernel socket cookie of the agent's socket (inet_diag; equals bpf_get_socket_cookie)
inode, uid   from inet_diag
pid, tgid    from the eBPF map (named by the kernel at connect()) or from /proc/*/fd -> socket:[inode]
cgroup       /proc/<pid>/cgroup (v2 path); cgroup_id from the eBPF map
exe, exe_sha256, comm
workload     {pod_uid, namespace, name, service_account, spiffe_id}  (registry, longest cgroup prefix)
dst          {ip, port, source: bpf_connect4 | so_original_dst | explicit_*}
wire         first bytes: HTTP method/host/path or TLS SNI, length, sha256
```

## The release gate (`Interceptor.accept_verdict`)
A held connection is released only if **all** hold:
1. the escrow id is live (not decided, not expired by the deadline);
2. the verdict's Ed25519 signature verifies under the verifier's key;
3. it names this escrow id, this socket cookie and `dst_hash = H(dst ip, dst port, sha256(first bytes))`;
4. it has not expired (`expires_ns`, default 2 s after issue);
5. it has not been consumed before;
6. its verdict is `ALLOW`.
Everything else, including no verdict by the deadline and the verifier being unreachable, resets the connection
(`SO_LINGER 0` -> RST). The destination never receives a SYN for a refused connection: the interceptor only
calls connect() after the gate passes.

## Why the agent cannot reach the verifier
The verifier is a destination like any other, so an agent's attempt to contact it is itself escrowed; the
verifier refuses its own address (`destination_is_verifier`). Records are HMAC'd with a key mounted only
into the interceptor container; the agent container has no key, so it cannot submit a record even if it
reached the port.

## Hold-and-release
`action: hold` makes the verifier park the decision until `POST /v1/release {hold_id, decision}` or its hold
timeout. The interceptor's deadline is independent and shorter; when it passes the connection is reset, the
escrow id is retired, and a verdict released later for it is refused (`stale`). A late approval therefore
cannot open a connection the agent attempted earlier.

## What is out of scope here
What decides the verdict. The verifier ships with a rule engine (host/SNI, port, HTTP method and path, budgets,
operator hold). Any `decide(record) -> (action, reason)` can replace it.

## Known limits
* Attribution by `/proc` needs `CAP_SYS_PTRACE` (or root) on the node; the eBPF path gives pid and cgroup id
  without it.
* Only IPv4 TCP is held. UDP (DNS) and IPv6 need the `sendmsg4` / `connect6` hooks (same design).
* A TLS ClientHello without SNI, or an opaque protocol, gives the verifier only the destination tuple.
* The agent's `getpeername()` shows the interceptor address after the eBPF rewrite; a `cgroup/getpeername4`
  program can hide that (not implemented).
* The hold point covers processes in the attached cgroups. On Kubernetes that is the pod; a process that
  escapes the pod's cgroup has already escaped the container.
