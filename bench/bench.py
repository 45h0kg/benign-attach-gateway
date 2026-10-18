"""Latency of the hold point. Run as root: python3 bench/bench.py [N]

Measures, per released connection, from the interceptor's receipts:
  attribution (inet_diag + /proc scan), parked-bytes peek, verifier round trip,
  upstream connect, and the total hold (accept -> release);
and from the agent: connect()+send+echo wall time, against an unsupervised
baseline (same echo server, no hold point). Sequential and 16-way concurrent.
"""
from __future__ import annotations
import json
import os
import statistics as st
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/../tests")
from harness import Harness  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 200


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summarize(xs):
    return {"n": len(xs), "median_us": int(st.median(xs)), "p95_us": int(pct(xs, 95)), "mean_us": int(st.mean(xs))}


def run(mode: str) -> dict:
    H = Harness(mode=mode, deadline_ms=2000)
    out = {"mode": mode}
    try:
        for _ in range(5):  # warm up
            H.agent("pod-a", H.U["allowed"], b"w")
        # baseline: unsupervised process, same server
        base = [H.agent(None, H.U["allowed"], b"b", raw=True)["t_total_us"] for _ in range(N)]
        out["baseline_agent_total"] = summarize(base)
        n0 = len(H.receipts())
        seq = [H.agent("pod-a", H.U["allowed"], b"s") for _ in range(N)]
        rcs = [r for r in H.receipts()[n0:] if r["outcome"] == "RELEASED"]
        assert len(rcs) == N, (len(rcs), N)
        out["sequential"] = {
            "agent_total": summarize([a["t_total_us"] for a in seq]),
            "agent_connect": summarize([a["t_connect_us"] for a in seq]),
            "attribution": summarize([r["timing"]["attribution_us"] for r in rcs]),
            "peek": summarize([r["timing"]["peek_us"] for r in rcs]),
            "verdict_rtt": summarize([r["timing"]["verdict_rtt_us"] for r in rcs]),
            "gate": summarize([r["timing"].get("gate_us", 0) for r in rcs]),
            "upstream_connect": summarize([r["timing"]["upstream_connect_us"] for r in rcs]),
            "hold_total": summarize([r["timing"]["total_us"] for r in rcs]),
            "verifier_decide": summarize([json.loads(l)["decide_us"] for l in open(H.verifier.audit.path) if l.strip()][-N:]),
        }
        # 16 long-lived agent processes, each making N/16 connections back to back
        n0 = len(H.receipts())
        k = max(1, N // 16)
        t0 = time.perf_counter()
        with ThreadPoolExecutor(16) as ex:
            procs = list(ex.map(lambda _: H.agent("pod-a", H.U["allowed"], b"c", timeout=60, repeat=k), range(16)))
        wall = time.perf_counter() - t0
        conc = [r for p in procs for r in p.get("runs", [])]
        rcs = [r for r in H.receipts()[n0:] if r["outcome"] == "RELEASED"]
        out["concurrent16"] = {"agent_total": summarize([a["t_total_us"] for a in conc]),
                               "gate": summarize([r["timing"].get("gate_us", 0) for r in rcs]),
                               "hold_total": summarize([r["timing"]["total_us"] for r in rcs]),
                               "released": len(rcs), "wall_s": round(wall, 2), "conn_per_s": round(len(conc) / wall, 1)}
        from escrow import ed25519
        out["ed25519_native"] = ed25519.NATIVE
        out["process_count"] = len([p for p in os.listdir("/proc") if p.isdigit()])
    finally:
        H.close()
    return out


def main():
    res = {m: run(m) for m in ("bpf", "iptables")}
    os.makedirs("results", exist_ok=True)
    tag = "native" if res["bpf"]["ed25519_native"] else "purepy"
    with open(f"results/bench_{tag}.json", "w") as f:
        json.dump(res, f, indent=1)
    for m, r in res.items():
        s = r["sequential"]
        print(f"[{m}] baseline agent total {r['baseline_agent_total']['median_us']} us | supervised {s['agent_total']['median_us']} us "
              f"(p95 {s['agent_total']['p95_us']}) | hold {s['hold_total']['median_us']} us = attribution {s['attribution']['median_us']} + "
              f"peek {s['peek']['median_us']} + verdict rtt {s['verdict_rtt']['median_us']} (verifier decide {s['verifier_decide']['median_us']}) + gate {s['gate']['median_us']} + "
              f"upstream {s['upstream_connect']['median_us']} | 16-way: hold {r['concurrent16']['hold_total']['median_us']} us, {r['concurrent16']['conn_per_s']} conn/s, procs {r['process_count']}")


if __name__ == "__main__":
    main()
