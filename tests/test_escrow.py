"""Adversarial suite for connection escrow. Run as root on Linux: python3 tests/test_escrow.py [bpf|iptables|both]

Each check states what the agent did, what the destination saw, and what the receipt says.
"""
from __future__ import annotations
import json
import sys
import time
import urllib.request

from harness import Harness, PODS
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))
from escrow import wire  # noqa: E402
from escrow.audit import AuditLog  # noqa: E402
from escrow.verifier import sign_verdict, dst_hash  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = ""):
    RESULTS.append((name, bool(cond), detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def http(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def run_suite(mode: str):
    print(f"\n=== hold point: {mode} ===")
    H = Harness(mode=mode, deadline_ms=1000)
    U, I, V = H.U, H.interceptor, H.verifier
    pa, pb = PODS["pod-a"], PODS["pod-b"]
    try:
        # T0 allowed connection is released; destination sees exactly the parked bytes
        r = H.agent("pod-a", U["allowed"], b"hello")
        rc = H.last_receipt()
        check("T0 allowed: agent connected and got the echo", r["connected"] and bytes.fromhex(r["recv"]) == b"echo:hello", r.get("error"))
        check("T0 allowed: destination accepted exactly one connection carrying the parked bytes",
              len(H.upstreams["allowed"].accepted) == 1 and H.upstreams["allowed"].accepted[0][1] == b"hello")
        check("T0 allowed: receipt RELEASED, attributed to the agent pid, pod-a cgroup and SPIFFE id",
              rc["outcome"] == "RELEASED" and rc["pid"] == r["pid"] and pa["pod_uid"] in rc["cgroup"]
              and rc["workload"] == pa["spiffe_id"] and rc["cookie"] > 0 and rc["dst"]["source"].startswith("bpf" if mode == "bpf" else "so_"),
              f"src={rc['dst']['source']} pid={rc['pid']} cookie={rc['cookie']}")
        check("T0 allowed: executable identified by digest", len(rc["exe_sha256"]) == 64 and rc["comm"].startswith("python"))

        # T1 policy deny: reset before any packet reaches the destination
        n0 = len(H.upstreams["denied"].accepted)
        r = H.agent("pod-a", U["denied"], b"exfil")
        rc = H.last_receipt()
        check("T1 denied: agent's connection was reset", "ConnectionReset" in r["error"] or "BrokenPipe" in r["error"] or r["recv"] == "", r["error"])
        check("T1 denied: destination never accepted a connection", len(H.upstreams["denied"].accepted) == n0)
        check("T1 denied: receipt DENIED by default rule", rc["outcome"] == "DENIED" and "default" in rc["reason"], rc["reason"])

        # T2 unknown workload: same uid, outside any pod cgroup
        if mode == "iptables":
            r = H.agent(None, U["allowed"], b"x")
            rc = H.last_receipt()
            check("T2 unknown workload: refused even for an allowed destination", not r["recv"] and rc["outcome"] == "DENIED" and "unknown_workload" in rc["reason"], rc["reason"])
        else:
            check("T2 unknown workload: (bpf) a process outside the attached cgroups is not supervised; covered under iptables", True)

        # T3 deadline: hold with no release -> fail closed at the interceptor deadline
        n0 = len(H.upstreams["hold"].accepted)
        t0 = time.perf_counter()
        r = H.agent("pod-a", U["hold"], b"wait", timeout=5)
        dt = time.perf_counter() - t0
        rc = H.last_receipt()
        check("T3 deadline: no verdict in 1000 ms -> reset, DENIED_DEADLINE", rc["outcome"] == "DENIED_DEADLINE" and not r["recv"], f"{rc['timing']['total_us']/1000:.0f} ms")
        check("T3 deadline: destination never accepted a connection", len(H.upstreams["hold"].accepted) == n0)
        check("T3 deadline: agent released within 1.0-1.6 s", 0.9 < dt < 1.6, f"{dt:.2f} s")
        late_id = rc["escrow_id"]
        # the verifier still has the hold; release it now, late
        pend = http(f"http://{H.vaddr[0]}:{H.vaddr[1]}/v1/pending")["pending"]
        late = [h for h in pend if h["escrow_id"] == late_id]
        if late:
            http(f"http://{H.vaddr[0]}:{H.vaddr[1]}/v1/release", {"hold_id": late[0]["id"], "decision": "allow"})
            time.sleep(0.2)
        rec, sig = I.records[late_id]
        body = {"schema": "escrow/verdict/v0", "verifier": "verifier", "escrow_id": late_id, "cookie": rec["attribution"]["cookie"],
                "dst_hash": dst_hash(rec), "verdict": "ALLOW", "reason": "late", "issued_ns": time.time_ns(),
                "expires_ns": time.time_ns() + 10**9, "nonce": "00"}
        ok, why = I.accept_verdict(late_id, sign_verdict(H.vsk, body))
        check("T4 late verdict: a correctly signed ALLOW arriving after the deadline is refused", not ok and "stale" in why, why)
        check("T4 late verdict: the verifier's late release did not open anything", len(H.upstreams["hold"].accepted) == n0 and I.stats["RELEASED"] == 1)

        # T5 replay / rebinding / forgery against a live escrow (synthetic live record)
        live_id = "ab" * 16
        rec2 = dict(rec, escrow_id=live_id)
        I.live[live_id] = rec2
        good = {"schema": "escrow/verdict/v0", "verifier": "verifier", "escrow_id": live_id, "cookie": rec2["attribution"]["cookie"],
                "dst_hash": dst_hash(rec2), "verdict": "ALLOW", "reason": "t5", "issued_ns": time.time_ns(),
                "expires_ns": time.time_ns() + 10**9, "nonce": "01"}
        ok, why = I.accept_verdict(live_id, sign_verdict(H.rogue_sk, good))
        check("T5 forged verdict (wrong key) refused", not ok and "signature" in why, why)
        ok, why = I.accept_verdict(live_id, sign_verdict(H.vsk, dict(good, cookie=good["cookie"] + 1)))
        check("T5 verdict for another socket cookie refused", not ok and "cookie" in why, why)
        ok, why = I.accept_verdict(live_id, sign_verdict(H.vsk, dict(good, dst_hash="00" * 32)))
        check("T5 verdict for another destination / first bytes refused", not ok and "destination" in why, why)
        ok, why = I.accept_verdict(live_id, sign_verdict(H.vsk, dict(good, expires_ns=time.time_ns() - 1)))
        check("T5 expired verdict refused", not ok and "expired" in why, why)
        v = sign_verdict(H.vsk, good)
        ok1, _ = I.accept_verdict(live_id, v)
        ok2, why2 = I.accept_verdict(live_id, v)
        check("T5 valid verdict accepted once, replay refused", ok1 and not ok2 and "stale" in why2, why2)

        # T6 agent cannot reach the verifier: the attempt is itself escrowed and refused
        n_rec = V.stats["records"]
        r = H.agent("pod-a", H.vaddr, b"POST /v1/release HTTP/1.1\r\nHost: v\r\nContent-Length: 2\r\n\r\n{}")
        rc = H.last_receipt()
        check("T6 agent -> verifier: intercepted and refused (destination_is_verifier)", not r["recv"] and rc["outcome"] == "DENIED" and "destination_is_verifier" in rc["reason"], rc["reason"])
        check("T6 agent -> verifier: only the interceptor's record reached the verifier", V.stats["records"] == n_rec + 1)

        # T7 TLS: SNI decides; parked ClientHello delivered byte-for-byte on release
        ch = wire.client_hello("api.allowed.test")
        r = H.agent("pod-a", U["tls"], ch)
        rc = H.last_receipt()
        check("T7 TLS allowed SNI: released; destination got the identical ClientHello",
              rc["outcome"] == "RELEASED" and rc["wire"]["sni"] == "api.allowed.test" and H.upstreams["tls"].accepted[-1][1] == ch)
        n0 = len(H.upstreams["tls"].accepted)
        r = H.agent("pod-a", U["tls"], wire.client_hello("evil.test"))
        rc = H.last_receipt()
        check("T7 TLS other SNI: reset, destination untouched", rc["outcome"] == "DENIED" and len(H.upstreams["tls"].accepted) == n0, rc["reason"])

        # T8 HTTP method/path rules
        r = H.agent("pod-a", U["http"], b"GET /v1/items HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        rc = H.last_receipt()
        check("T8 HTTP GET /v1/: released", rc["outcome"] == "RELEASED" and rc["wire"]["method"] == "GET", rc["reason"])
        r = H.agent("pod-a", U["http"], b"POST /v1/items HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
        rc = H.last_receipt()
        check("T8 HTTP POST /v1/: denied", rc["outcome"] == "DENIED", rc["reason"])
        r = H.agent("pod-a", U["http"], b"GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        rc = H.last_receipt()
        check("T8 HTTP GET /admin: denied", rc["outcome"] == "DENIED", rc["reason"])

        # T9 budget per workload
        outs = [H.last_receipt()["outcome"] if H.agent("pod-b", U["budget"], b"b") else None for _ in range(3)]
        check("T9 budget 2/min for pod-b: third connection denied", outs == ["RELEASED", "RELEASED", "DENIED"] and "budget" in H.last_receipt()["reason"], str(outs))

        # T10 hold then operator release (allow / deny)
        import threading
        res = {}
        def go(k, b):
            res[k] = H.agent("pod-a", U["hold"], b, timeout=8)
        th = threading.Thread(target=go, args=("allow", b"held-allow")); th.start()
        time.sleep(0.3)
        pend = http(f"http://{H.vaddr[0]}:{H.vaddr[1]}/v1/pending")["pending"]
        hid = pend[-1]["id"] if pend else None
        if hid:
            http(f"http://{H.vaddr[0]}:{H.vaddr[1]}/v1/release", {"hold_id": hid, "decision": "allow"})
        th.join()
        rc = H.last_receipt()
        check("T10 hold -> operator allow within deadline: released", hid is not None and rc["outcome"] == "RELEASED" and "released" in rc["reason"] and bytes.fromhex(res["allow"]["recv"]) == b"echo:held-allow", rc["reason"])
        th = threading.Thread(target=go, args=("deny", b"held-deny")); th.start()
        time.sleep(0.3)
        pend = http(f"http://{H.vaddr[0]}:{H.vaddr[1]}/v1/pending")["pending"]
        if pend:
            http(f"http://{H.vaddr[0]}:{H.vaddr[1]}/v1/release", {"hold_id": pend[-1]["id"], "decision": "deny"})
        th.join()
        rc = H.last_receipt()
        check("T10 hold -> operator deny: reset", rc["outcome"] == "DENIED" and "refused" in rc["reason"], rc["reason"])

        # T11 bypass attempts: child process, renamed interpreter
        n0 = len(H.upstreams["denied"].accepted)
        r = H.agent("pod-a", U["denied"], b"child", child=True)
        rc = H.last_receipt()
        check("T11 child process inherits the hold point: denied, destination untouched", rc["outcome"] == "DENIED" and len(H.upstreams["denied"].accepted) == n0 and rc["pid"] == r["pid"], rc["reason"])
        import shutil, os as _os
        alt = _os.path.join(H.tmp, "not-python")
        shutil.copy(sys.executable, alt); _os.chmod(alt, 0o755); _os.chmod(H.tmp, 0o755)
        r = H.agent("pod-a", U["allowed"], b"renamed", exe=alt)
        rc = H.last_receipt()
        check("T11 renamed binary: still attributed to pod-a by cgroup; digest equals the real interpreter",
              rc["outcome"] == "RELEASED" and rc["workload"] == pa["spiffe_id"] and rc["exe_sha256"] == [x for x in H.receipts() if x["outcome"] == "RELEASED"][0]["exe_sha256"], rc["comm"])

        # T14 UDP pinning (kernel path): only the configured resolver is reachable over UDP
        if mode == "bpf":
            r = H.agent("pod-a", ("0.0.0.0", 0), udp={"public_dns": ["8.8.8.8", 53], "resolver": ["127.0.0.53", 53], "udp_exfil": ["10.99.99.99", 4444]})
            res = r.get("results", {})
            check("T14 UDP: queries to a public resolver and UDP exfil refused in-kernel (EPERM); cluster resolver allowed",
                  res.get("resolver") == "sent" and "not permitted" in res.get("public_dns", "") and "not permitted" in res.get("udp_exfil", ""), str(res))
            n0 = len(H.upstreams["denied"].accepted)
            r = H.agent("pod-a", ("8.8.8.8", 53), b"\x00\x1c" + b"\x00" * 28)
            rc = H.last_receipt()
            check("T14 DNS over TCP to a public resolver: escrowed and refused", rc["outcome"] == "DENIED" and rc["dst"]["port"] == 53, rc["reason"])
            cnt = H.hook.counters()
            check("T14 kernel counters: udp_denied >= 2, udp_allowed >= 1", cnt["udp_denied"] >= 2 and cnt["udp_allowed"] >= 1, str(cnt))
        else:
            check("T14 UDP pinning needs the kernel path; not applicable to iptables", True)

        # T12 verifier down -> fail closed
        H.vsrv.shutdown(); H.vsrv.server_close()
        n0 = len(H.upstreams["allowed"].accepted)
        r = H.agent("pod-a", U["allowed"], b"nobody-home")
        rc = H.last_receipt()
        check("T12 verifier unreachable: allowed destination still refused (fail closed)", rc["outcome"] == "DENIED_VERIFIER_UNREACHABLE" and len(H.upstreams["allowed"].accepted) == n0, rc["reason"][:60])

        # T13 audit chains
        ok_i, n_i = AuditLog.verify_chain(I.audit.path)
        ok_v, n_v = AuditLog.verify_chain(V.audit.path)
        check("T13 interceptor and verifier audit chains verify", ok_i and ok_v and n_i == I.stats["accepted"], f"{n_i} / {n_v} entries")
        with open(I.audit.path) as f:
            lines = f.read().splitlines()
        rec0 = json.loads(lines[1]); rec0["outcome"] = "RELEASED"; lines[1] = json.dumps(rec0, sort_keys=True)
        tam = I.audit.path + ".tampered"
        with open(tam, "w") as f:
            f.write("\n".join(lines) + "\n")
        ok_t, n_t = AuditLog.verify_chain(tam)
        check("T13 tampered receipt breaks the chain at that entry", not ok_t and n_t == 1)
    finally:
        H.close()
    return I.stats


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    modes = ["bpf", "iptables"] if which == "both" else [which]
    stats = {}
    for m in modes:
        stats[m] = run_suite(m)
    n_ok = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\n{n_ok}/{len(RESULTS)} checks passed")
    print("interceptor stats:", json.dumps(stats))
    sys.exit(0 if n_ok == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
