#!/usr/bin/env python3
"""Bypass comparison: a sidecar/proxy egress control vs connection escrow.

Both aim to stop an agent pod from reaching external-sink while letting it reach internal-api.

  proxy    the agent pod has HTTP_PROXY/HTTPS_PROXY pointing at a deny-all proxy, the strict
           form of a sidecar egress control. An HTTP client that honours the env is blocked;
           a direct socket to the destination IP is not.
  escrow   no proxy env; escrow_connect4 on the pod cgroup holds every connect() regardless of
           whether the process consults a proxy.

The agent runs the same task under each: one HTTP call to external-sink (honours proxy) and one
raw-socket call to external-sink's IP (ignores proxy). We report which of the two reached the
destination under each control.

Run: sudo PYTHONPATH=. python3 experiments/k8s/bypass.py
"""
import json
import os
import secrets
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
import asyncio
import threading

from escrow import ed25519
from escrow.attribution import PodRegistry
from escrow.bpfload import ConnectHook
from escrow.interceptor import Interceptor
from escrow.verifier import Policy, Verifier, serve
from experiments.k8s.drive import (CNI, OUT, UNIFIED, jget, kc, launch_agent, pod_cgroup,
                                   received, reset_sinks, svc_ip, crictl_logs, service_map)


def run_task(name, task, supervised=False, env=None):
    kc("-n", "lab", "delete", "pod", name, "--ignore-not-found", "--now")
    env = env or {}
    container = {"name": name, "image": "escrow/lab:dev", "imagePullPolicy": "Never",
                 "command": ["sh", "-c", "until [ -f /tmp/go ]; do sleep 0.2; done; exec python3 /opt/escrow/lab/agent.py"],
                 "env": [{"name": "AGENT_NAME", "value": name}, {"name": "TASK", "value": json.dumps(task)}]
                        + [{"name": k, "value": v} for k, v in env.items()]}
    overrides = {"metadata": {"labels": {"app": "agent", **({"escrow.io/supervised": "true"} if supervised else {})}},
                 "spec": {"serviceAccountName": "agent", "containers": [container]}}
    kc("-n", "lab", "run", name, "--image=escrow/lab:dev", "--restart=Never", "--overrides=" + json.dumps(overrides))
    cg = pod_cgroup("lab", name)
    return cg


def release_and_collect(name):
    for _ in range(60):
        if jget("-n", "lab", "get", "pod", name, "-o", "json").get("status", {}).get("phase") == "Running":
            break
        time.sleep(0.5)
    for _ in range(20):
        if kc("-n", "lab", "exec", name, "--", "sh", "-c", ": > /tmp/go").returncode == 0:
            break
        time.sleep(0.5)
    for _ in range(80):
        if jget("-n", "lab", "get", "pod", name, "-o", "json").get("status", {}).get("phase") in ("Succeeded", "Failed"):
            break
        time.sleep(0.5)
    return [json.loads(l) for l in crictl_logs(name).splitlines() if l.strip().startswith("{")]


def main():
    smap = service_map()
    external_ip = svc_ip("lab", "external-sink")
    dns_ip = svc_ip("kube-system", "kube-dns")

    # deny-all proxy on the host (stands in for a sidecar egress proxy), reachable from pods at CNI:3128
    proxy = subprocess.Popen([sys.executable, os.path.join(ROOT, "experiments/k8s/lab/denyproxy.py"), "3128"])
    time.sleep(1)

    # the task: one proxy-honouring HTTP POST to external-sink, one raw socket to external-sink's IP
    task = {"steps": [
        {"method": "POST", "url": "http://external-sink.lab.svc.cluster.local/upload", "body": "via-http-client"},
        {"raw": True, "host": external_ip, "port": 80, "send": b"POST /upload HTTP/1.0\r\nHost: x\r\nContent-Length: 11\r\n\r\nraw-socket!".decode()},
    ]}

    out = {}
    # --- proxy control ---
    reset_sinks()
    run_task("bypass-proxy", task, supervised=False,
             env={"HTTP_PROXY": f"http://{CNI}:3128", "HTTPS_PROXY": f"http://{CNI}:3128", "http_proxy": f"http://{CNI}:3128"})
    calls = release_and_collect("bypass-proxy")
    out["proxy"] = {"calls": calls, "external_received": received("lab", "external-sink")}

    # --- escrow control ---
    ikey = secrets.token_bytes(32)
    vsk, vpk = ed25519.keypair_from_seed(secrets.token_bytes(32))
    spiffe = "spiffe://cluster.local/ns/lab/sa/agent"
    policy = Policy({"workloads": {spiffe: {"rules": [{"svc": "lab/internal-api", "action": "allow"}]}}, "default": "deny"}, services=smap)
    vaddr = (CNI, 18444)
    verifier = Verifier(vsk, policy, [ikey], os.path.join(OUT, "bypass_verifier.jsonl"), self_addrs=[vaddr])
    serve(verifier, *vaddr)
    loop = asyncio.new_event_loop(); threading.Thread(target=loop.run_forever, daemon=True).start()
    hook = ConnectHook(os.path.join(ROOT, "bpf", "escrow_connect4.bpf.o"))
    reg = PodRegistry(os.path.join(OUT, "bypass_pods.json"))
    it = Interceptor(ikey, vpk, vaddr, reg, os.path.join(OUT, "bypass_interceptor.jsonl"), node="node",
                     deadline_ms=2000, bpf_map=hook.maps["escrow_map"], peer_map=hook.maps["peer_map"])
    iaddr = asyncio.run_coroutine_threadsafe(it.start("0.0.0.0", 15002), loop).result(10)
    hook.configure(CNI, iaddr[1], dns=(dns_ip, 53))

    reset_sinks()
    cg_dir, cg_rel = run_task("bypass-escrow", task, supervised=True)
    reg.entries[cg_rel] = {"pod_uid": cg_rel.split("pod")[-1].split("/")[0], "namespace": "lab",
                           "name": "bypass-escrow", "service_account": "agent", "spiffe_id": spiffe}
    reg.save()
    hook.attach(cg_dir)
    time.sleep(0.3)
    calls = release_and_collect("bypass-escrow")
    out["escrow"] = {"calls": calls, "external_received": received("lab", "external-sink"),
                     "counters": hook.counters()}
    hook.close(); proxy.terminate()

    json.dump(out, open(os.path.join(OUT, "bypass.json"), "w"), indent=1)

    def line(c):
        how = "raw socket" if c.get("raw") else "http client"
        return f"{how:12} -> external-sink  {'REACHED' if c.get('ok') and c.get('status', 200) < 500 else 'blocked'}  ({c.get('status', c.get('error',''))})"
    print("\n=== Bypass comparison (external-sink should be unreachable under each control) ===")
    print("\nSidecar/proxy control (HTTP_PROXY -> deny-all):")
    for c in out["proxy"]["calls"]:
        print("  " + line(c))
    print(f"  external-sink received {len(out['proxy']['external_received'])} posts  <-- the raw socket bypassed the proxy")
    print("\nConnection escrow (kernel hold on the pod cgroup):")
    for c in out["escrow"]["calls"]:
        print("  " + line(c))
    print(f"  external-sink received {len(out['escrow']['external_received'])} posts  <-- both held at connect(); kernel counters {out['escrow']['counters']}")


if __name__ == "__main__":
    main()
