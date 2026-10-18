# Canonical run results

One logged run, all stages green: `bash experiments/run_all.sh` (`execution_log.txt`, 2026-10-18 23:19:55 UTC).
Environment: virtualised Intel Xeon 2.80 GHz, 2 vCPU, Linux 6.18, cgroup v2, Python 3.13, clang 18. Timings are host-dependent;
verdicts and counts are not. Agents are separate processes (uid 1001) in per-pod cgroups; everything is on loopback.

## Correctness
| Hold point | Suite | Released | Denied | Deadline | Verifier down |
|---|---|---|---|---|---|
| eBPF `cgroup/connect4` | 36/36 | 7 | 9 | 1 | 1 |
| iptables `REDIRECT` + `SO_ORIGINAL_DST` | 34/34 | 7 | 9 | 1 | 1 |

36 checks on the eBPF path; 33 of them apply on iptables, where the three UDP-pinning checks (T14) need the kernel path and
are recorded as a single not-applicable marker (hence 34/34).

Checks: policy allow/deny with the destination accepting exactly the parked bytes or nothing at all; unknown workload;
deadline fail-closed (1000 ms) and a late correctly-signed ALLOW refused; forged, rebound (other cookie / other destination),
expired and replayed verdicts refused; the agent's own attempt to reach the verifier intercepted and refused; TLS SNI and HTTP
method/path rules; per-workload budget; operator hold then allow / deny; child-process and renamed-binary bypass attempts;
verifier unreachable; audit chains verify and a tampered receipt breaks the chain; UDP pinned to the cluster resolver (eBPF).

## Latency per released connection (sequential, N = 200, median / p95, ms)
| | eBPF, native Ed25519 | iptables, native Ed25519 | eBPF, pure-Python Ed25519 |
|---|---|---|---|
| attribution (inet_diag + /proc) | 0.90 / 1.36 | 1.85 / 2.63 | 0.85 / 1.17 |
| park first bytes | 0.09 / 0.13 | 0.09 / 0.15 | 0.09 / 0.15 |
| verifier round trip (HTTP, sign) | 2.38 / 3.66 | 2.30 / 4.05 | 3.76 / 5.44 |
| release gate (verify, bind, consume) | 0.33 / 0.50 | 0.34 / 0.47 | 3.15 / 5.03 |
| connect to destination | 0.41 / 0.65 | 0.42 / 0.61 | 0.58 / 0.86 |
| **total hold: accept to release** | 4.52 / 6.70 | 5.46 / 8.03 | 8.84 / 12.33 |
| agent wall: connect + send + echo | 5.81 / 8.59 | 6.70 / 9.63 | 10.13 / 13.96 |
| unsupervised baseline, agent wall | 0.82 / 1.17 | 0.88 / 1.54 | 0.83 / 1.26 |

Verifier policy decision alone: 24 µs median. The verifier round trip is dominated by one Ed25519
signature plus a fresh HTTP/1.1 connection; the gate by one verification (0.33 ms native, 3.15 ms pure Python).

## 16 concurrent agents (16 long-lived agent processes, 12 connections each)
| | eBPF, native | iptables, native | eBPF, pure-Python |
|---|---|---|---|
| hold total, median / p95 (ms) | 41.97 / 51.81 | 76.56 / 126.79 | 88.97 / 115.95 |
| connections per second | 175.5 | 72.7 | 93.3 |

The throughput figure varies noticeably between runs on a shared two-vCPU host; the queueing is in the single-process Python
interceptor and the threaded verifier, not in the kernel program.

## CLI end to end
`experiments/cli_smoke.sh`: an unmodified `curl` in a supervised cgroup reaches the allowed port (RELEASED, `comm=curl`,
`source=bpf_connect4`); its attempt to reach the verifier, and the same attempt from a child shell, are reset (`destination_is_verifier`).

## Content gate
See `RESULTS_TLSGATE.md` (three TLS runtimes through the same gate; `tls_gate_runtimes.json`).
