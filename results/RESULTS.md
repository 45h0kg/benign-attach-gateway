# Canonical run results

One logged run, all stages green: `bash experiments/run_all.sh` (`execution_log.txt`, 18 Oct 2026).
Environment: virtualised Intel Xeon 2.10 GHz, 2 vCPU, Linux 6.18, cgroup v2, Python 3.13, clang 18. Timings are host-dependent;
verdicts and counts are not. Agents are separate processes (uid 1001) in per-pod cgroups; everything is on loopback.

## Correctness (33 checks per hold point)
| Hold point | Suite | Released | Denied | Deadline | Verifier down |
|---|---|---|---|---|---|
| eBPF `cgroup/connect4` | 33/33 | 7 | 8 | 1 | 1 |
| iptables `REDIRECT` + `SO_ORIGINAL_DST` | 33/33 | 7 | 9 | 1 | 1 |

Checks: policy allow/deny with the destination accepting exactly the parked bytes or nothing at all; unknown workload;
deadline fail-closed (1000 ms) and a late correctly-signed ALLOW refused; forged, rebound (other cookie / other destination),
expired and replayed verdicts refused; the agent's own attempt to reach the verifier intercepted and refused; TLS SNI and HTTP
method/path rules; per-workload budget; operator hold then allow / deny; child-process and renamed-binary bypass attempts;
verifier unreachable; audit chains verify and a tampered receipt breaks the chain.

## Latency per released connection (sequential, N = 200, median / p95, ms)
| | eBPF, native Ed25519 | iptables, native Ed25519 | eBPF, pure-Python Ed25519 |
|---|---|---|---|
| attribution (inet_diag + /proc) | 0.99 / 1.30 | 1.81 / 2.58 | 0.91 / 1.19 |
| park first bytes | 0.10 / 0.16 | 0.09 / 0.15 | 0.09 / 0.14 |
| verifier round trip (HTTP, sign) | 2.41 / 3.52 | 2.33 / 3.18 | 3.70 / 5.48 |
| release gate (verify, bind, consume) | 0.33 / 0.58 | 0.33 / 0.53 | 3.13 / 4.95 |
| connect to destination | 0.42 / 0.68 | 0.43 / 0.65 | 0.57 / 0.89 |
| **total hold: accept to release** | 4.71 / 6.17 | 5.46 / 7.02 | 8.87 / 12.18 |
| agent wall: connect + send + echo | 6.05 / 7.95 | 6.72 / 8.76 | 10.07 / 13.59 |
| unsupervised baseline, agent wall | 0.89 / 1.16 | 0.86 / 1.20 | 0.83 / 1.27 |

Verifier policy decision alone: 23 µs median. The verifier round trip is dominated by one Ed25519
signature (native ~2 ms with `cryptography` key import, ~1.5 ms pure Python) plus a fresh HTTP/1.1 connection; the gate by one verification
(native 0.25 ms, pure Python 2.9 ms).

## 16 concurrent agents (16 long-lived agent processes, 12 connections each)
| | eBPF, native | iptables, native | eBPF, pure-Python |
|---|---|---|---|
| hold total, median / p95 (ms) | 43.1 / 65.4 | 71.0 / 126.2 | 104.9 / 125.8 |
| connections per second | 94.6 | 123.7 | 86.2 |

Single-process asyncio interceptor and a threaded Python verifier on 2 vCPUs shared with the 16 agents: the queueing is in the
prototype's user-space components, not in the kernel hook (45 instructions, one map update).

## CLI end to end
`experiments/cli_smoke.sh`: an unmodified `curl` in a supervised cgroup reaches the allowed port (RELEASED, `comm=curl`,
`source=bpf_connect4`); its attempt to reach the verifier, and the same attempt from a child shell, are reset (`destination_is_verifier`).
