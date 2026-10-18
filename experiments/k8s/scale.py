#!/usr/bin/env python3
"""Scale test on the cluster: K supervised agent pods, each opening N connections to the
allowed internal-api, all held by one interceptor. Reports aggregate throughput and the
interceptor's per-connection hold latency (p50/p95) from its receipts."""
import json, os, secrets, sys, time, asyncio, threading
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from escrow import ed25519
from escrow.attribution import PodRegistry
from escrow.bpfload import ConnectHook
from escrow.interceptor import Interceptor
from escrow.verifier import Policy, Verifier, serve
from experiments.k8s.drive import (CNI, OUT, jget, kc, pod_cgroup, svc_ip, crictl_logs, service_map)

K_PODS = int(sys.argv[1]) if len(sys.argv) > 1 else 6
N_CONN = int(sys.argv[2]) if len(sys.argv) > 2 else 100

def main():
    smap = service_map(); dns_ip = svc_ip("kube-system", "kube-dns")
    spiffe = "spiffe://cluster.local/ns/lab/sa/agent"
    ikey = secrets.token_bytes(32); vsk, vpk = ed25519.keypair_from_seed(secrets.token_bytes(32))
    policy = Policy({"workloads": {spiffe: {"rules": [{"svc": "lab/internal-api", "action": "allow"}], "budget_per_minute": 100000}}, "default": "deny"}, services=smap)
    vaddr = (CNI, 18445)
    verifier = Verifier(vsk, policy, [ikey], os.path.join(OUT, "scale_verifier.jsonl"), self_addrs=[vaddr], verdict_ttl_ms=5000)
    serve(verifier, *vaddr)
    loop = asyncio.new_event_loop(); threading.Thread(target=loop.run_forever, daemon=True).start()
    hook = ConnectHook(os.path.join(ROOT, "bpf", "escrow_connect4.bpf.o"))
    reg = PodRegistry(os.path.join(OUT, "scale_pods.json"))
    audit = os.path.join(OUT, "scale_interceptor.jsonl")
    open(audit, "w").close()
    it = Interceptor(ikey, vpk, vaddr, reg, audit, node="node", deadline_ms=4000,
                     bpf_map=hook.maps["escrow_map"], peer_map=hook.maps["peer_map"])
    iaddr = asyncio.run_coroutine_threadsafe(it.start("0.0.0.0", 15003), loop).result(10)
    hook.configure(CNI, iaddr[1], dns=(dns_ip, 53))
    print(f"interceptor {iaddr}, {K_PODS} pods x {N_CONN} connections each")

    task = {"load": {"url": "http://internal-api.lab.svc.cluster.local/data", "n": N_CONN}}
    names = [f"load-{i}" for i in range(K_PODS)]
    for name in names:
        kc("-n", "lab", "delete", "pod", name, "--ignore-not-found", "--now")
    for name in names:
        ov = {"metadata": {"labels": {"app": "agent", "escrow.io/supervised": "true"}},
              "spec": {"serviceAccountName": "agent", "containers": [{"name": name, "image": "escrow/lab:dev",
              "imagePullPolicy": "Never", "command": ["sh", "-c", "until [ -f /tmp/go ]; do sleep 0.2; done; exec python3 /opt/escrow/lab/agent.py"],
              "env": [{"name": "AGENT_NAME", "value": name}, {"name": "TASK", "value": json.dumps(task)}]}]}}
        kc("-n", "lab", "run", name, "--image=escrow/lab:dev", "--restart=Never", "--overrides=" + json.dumps(ov))
    # attach to each pod cgroup
    for name in names:
        cg_dir, cg_rel = pod_cgroup("lab", name)
        reg.entries[cg_rel] = {"pod_uid": cg_rel.split("pod")[-1].split("/")[0], "namespace": "lab", "name": name,
                               "service_account": "agent", "spiffe_id": spiffe}
        hook.attach(cg_dir)
    reg.save()
    # wait Running, release all at once
    for name in names:
        for _ in range(60):
            if jget("-n", "lab", "get", "pod", name, "-o", "json").get("status", {}).get("phase") == "Running":
                break
            time.sleep(0.3)
    t0 = time.perf_counter()
    for name in names:
        for _ in range(20):
            if kc("-n", "lab", "exec", name, "--", "sh", "-c", ": > /tmp/go").returncode == 0:
                break
            time.sleep(0.3)
    sums = []
    for name in names:
        for _ in range(120):
            if jget("-n", "lab", "get", "pod", name, "-o", "json").get("status", {}).get("phase") in ("Succeeded", "Failed"):
                break
            time.sleep(0.5)
        for l in crictl_logs(name).splitlines():
            if '"load_summary"' in l:
                sums.append(json.loads(l))
    wall = time.perf_counter() - t0
    # interceptor hold latency from receipts
    holds = [json.loads(l)["timing"]["total_us"] for l in open(audit) if l.strip() and '"RELEASED"' in l]
    holds.sort()
    pct = lambda p: holds[min(len(holds) - 1, int(p / 100 * (len(holds) - 1)))] / 1000 if holds else 0
    total = sum(s["reached"] for s in sums)
    res = {"pods": K_PODS, "per_pod": N_CONN, "released": len(holds), "agent_reached": total,
           "wall_s": round(wall, 2), "throughput_conn_per_s": round(len(holds) / wall, 1) if wall else 0,
           "hold_ms_p50": round(pct(50), 2), "hold_ms_p95": round(pct(95), 2), "hold_ms_p99": round(pct(99), 2),
           "counters": hook.counters()}
    json.dump({"summary": res, "per_pod": sums}, open(os.path.join(OUT, "scale.json"), "w"), indent=1)
    hook.close()
    print("\n=== SCALE ===")
    print(f"{K_PODS} pods x {N_CONN} = {K_PODS*N_CONN} connections; {len(holds)} released, {total} reached by agents")
    print(f"throughput {res['throughput_conn_per_s']} conn/s over {wall:.1f}s; hold latency p50 {res['hold_ms_p50']} ms  p95 {res['hold_ms_p95']} ms  p99 {res['hold_ms_p99']} ms")
    print(f"kernel counters {res['counters']}")
    for name in names:
        kc("-n", "lab", "delete", "pod", name, "--ignore-not-found", "--now")

if __name__ == "__main__":
    main()
