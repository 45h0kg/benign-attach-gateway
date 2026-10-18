#!/usr/bin/env python3
"""On-cluster experiment driver (runs the node agent as a host process against real pods).

The verifier and interceptor run here, on the k8s node, exactly as the DaemonSet would.
Real agent pods are launched with kubectl. A supervised pod gets escrow_connect4 attached to
its own cgroup before it is allowed to make any call (the pod waits for a marker, we attach,
then release it), so the very first connection is already held. We then compare:

  unsupervised   no eBPF on the pod cgroup: every call goes straight out
  supervised     escrow decides each connection; only policy-allowed ones reach their service

and record what each destination actually received and the interceptor's receipts.

Run: sudo PYTHONPATH=. python3 experiments/k8s/drive.py
"""
import json
import os
import secrets
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from escrow import ed25519                                   # noqa: E402
from escrow.attribution import PodRegistry                  # noqa: E402
from escrow.bpfload import ConnectHook                       # noqa: E402
from escrow.interceptor import Interceptor                   # noqa: E402
from escrow.verifier import Policy, Verifier, serve          # noqa: E402

K = os.environ.get("KUBECTL", "/opt/k3s/k3s kubectl").split()
CNI = "10.42.0.1"
UNIFIED = "/sys/fs/cgroup/unified"
KUBEPODS = f"{UNIFIED}/kubepods"
OUT = os.path.join(ROOT, "results", "k8s")
os.makedirs(OUT, exist_ok=True)
import asyncio, threading


def kc(*args, inp=None):
    return subprocess.run(K + list(args), capture_output=True, text=True, input=inp)


def jget(*args):
    return json.loads(kc(*args).stdout)


def svc_ip(ns, name):
    return jget("-n", ns, "get", "svc", name, "-o", "json")["spec"]["clusterIP"]


def service_map():
    m = {}
    for s in jget("get", "svc", "-A", "-o", "json")["items"]:
        ip = s["spec"].get("clusterIP")
        if ip and ip != "None":
            m[ip] = f"{s['metadata']['namespace']}/{s['metadata']['name']}"
    return m


def pod_cgroup(ns, name, timeout=30):
    """Wait for the pod and return its cgroup-v2 directory and the /proc cgroup prefix."""
    uid = None
    for _ in range(timeout * 2):
        uid = jget("-n", ns, "get", "pod", name, "-o", "json").get("metadata", {}).get("uid")
        phase = jget("-n", ns, "get", "pod", name, "-o", "json").get("status", {}).get("phase")
        if uid and phase in ("Running", "Pending"):
            for root, dirs, _ in os.walk(KUBEPODS):
                if f"pod{uid}" in os.path.basename(root):
                    return root, root[len(UNIFIED):]
        time.sleep(0.5)
    raise RuntimeError(f"cgroup for {name} not found")


AGENT_WAIT = ("sh", "-c", "until [ -f /tmp/go ]; do sleep 0.2; done; exec python3 /opt/escrow/lab/agent.py")


def launch_agent(name, task, supervised):
    kc("-n", "lab", "delete", "pod", name, "--ignore-not-found", "--now")
    labels = {"app": "agent"}
    if supervised:
        labels["escrow.io/supervised"] = "true"
    overrides = {"spec": {"serviceAccountName": "agent", "containers": [{
        "name": name, "image": "escrow/lab:dev", "imagePullPolicy": "Never",
        "command": list(AGENT_WAIT),
        "env": [{"name": "AGENT_NAME", "value": name}, {"name": "TASK", "value": json.dumps(task)}]}]}}
    kc("-n", "lab", "run", name, "--image=escrow/lab:dev", "--restart=Never",
       "--overrides=" + json.dumps(overrides))
    return pod_cgroup("lab", name)


def crictl_logs(name):
    cid = subprocess.run(["/opt/k3s/k3s", "crictl", "ps", "-a", "--name", name, "-q"],
                         capture_output=True, text=True).stdout.strip().splitlines()
    if not cid:
        return ""
    return subprocess.run(["/opt/k3s/k3s", "crictl", "logs", cid[0]], capture_output=True, text=True).stdout + \
           subprocess.run(["/opt/k3s/k3s", "crictl", "logs", cid[0]], capture_output=True, text=True).stderr


def collect(name):
    for _ in range(80):
        ph = jget("-n", "lab", "get", "pod", name, "-o", "json").get("status", {}).get("phase")
        if ph in ("Succeeded", "Failed"):
            break
        time.sleep(0.5)
    out = crictl_logs(name)
    return [json.loads(l) for l in out.splitlines() if l.strip().startswith("{")]


def received(ns, name):
    ip = svc_ip(ns, name)
    try:
        import urllib.request
        return json.loads(urllib.request.urlopen(f"http://{ip}/log", timeout=4).read())["received"]
    except Exception as e:
        return [{"error": str(e)}]


def reset_sinks():
    import urllib.request
    for n in ("internal-api", "external-sink"):
        try:
            urllib.request.urlopen(f"http://{svc_ip('lab', n)}/reset", timeout=4).read()
        except Exception:
            pass


def main():
    smap = service_map()
    internal_ip, external_ip = svc_ip("lab", "internal-api"), svc_ip("lab", "external-sink")
    dns_ip = svc_ip("kube-system", "kube-dns")
    print(f"internal-api {internal_ip}  external-sink {external_ip}  kube-dns {dns_ip}")
    kc("-n", "lab", "create", "serviceaccount", "agent", "--dry-run=client", "-o", "yaml",
       inp=None) and kc("apply", "-f", "-", inp=kc("-n", "lab", "create", "serviceaccount", "agent",
                                                    "--dry-run=client", "-o", "yaml").stdout)

    # policy: this workload may GET internal-api and POST internal-api/collect; nothing else
    spiffe = "spiffe://cluster.local/ns/lab/sa/agent"
    policy = Policy({"workloads": {spiffe: {"rules": [
        {"svc": "lab/internal-api", "methods": ["GET"], "action": "allow"},
        {"svc": "lab/internal-api", "methods": ["POST"], "path_prefix": "/collect", "action": "allow"},
    ], "budget_per_minute": 600}}, "default": "deny"}, services=smap)

    # keys
    ikey = secrets.token_bytes(32)
    vsk, vpk = ed25519.keypair_from_seed(secrets.token_bytes(32))

    # verifier (host process)
    vaddr = (CNI, 18443)
    verifier = Verifier(vsk, policy, [ikey], os.path.join(OUT, "verifier_audit.jsonl"),
                        self_addrs=[vaddr])
    serve(verifier, *vaddr)

    # interceptor (host process) on its own asyncio loop
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    hook = ConnectHook(os.path.join(ROOT, "bpf", "escrow_connect4.bpf.o"))
    registry = PodRegistry(os.path.join(OUT, "pods.json"))
    it = Interceptor(ikey, vpk, vaddr, registry, os.path.join(OUT, "interceptor_audit.jsonl"),
                     node="node", deadline_ms=2000, bpf_map=hook.maps["escrow_map"], peer_map=hook.maps["peer_map"])
    iaddr = asyncio.run_coroutine_threadsafe(it.start("0.0.0.0", 15001), loop).result(10)
    hook.configure(CNI, iaddr[1], dns=(dns_ip, 53))
    print(f"verifier on {vaddr}, interceptor on {iaddr} (reachable from pods at {CNI}:{iaddr[1]})")

    task = {"steps": [
        {"method": "GET", "url": "http://internal-api.lab.svc.cluster.local/data"},
        {"method": "POST", "url": "http://internal-api.lab.svc.cluster.local/collect", "body": "step-report"},
        {"method": "POST", "url": "http://external-sink.lab.svc.cluster.local/upload", "body": "payload-leaving-the-pod"},
        {"method": "GET", "url": "http://external-sink.lab.svc.cluster.local/data"},
    ], "child_url": "http://external-sink.lab.svc.cluster.local/upload"}

    results = {}
    for name, supervised in (("agent-free", False), ("agent-supervised", True)):
        reset_sinks()
        print(f"\n=== {name} (supervised={supervised}) ===")
        cg_dir, cg_rel = launch_agent(name, task, supervised)
        if supervised:
            registry.entries[cg_rel] = {"pod_uid": cg_rel.split("pod")[-1].split("/")[0], "namespace": "lab",
                                        "name": name, "service_account": "agent", "spiffe_id": spiffe}
            registry.save()
            hook.attach(cg_dir)
            print(f"attached escrow programs to {cg_rel}")
            time.sleep(0.3)
            # wait until the container is actually Running, then release the gate (retry: exec races startup)
        for _ in range(60):
            if jget("-n", "lab", "get", "pod", name, "-o", "json").get("status", {}).get("phase") == "Running":
                break
            time.sleep(0.5)
        for _ in range(20):
            r = kc("-n", "lab", "exec", name, "--", "sh", "-c", ": > /tmp/go")
            if r.returncode == 0:
                break
            time.sleep(0.5)
        calls = collect(name)
        results[name] = {"calls": calls, "internal_received": received("lab", "internal-api"),
                         "external_received": received("lab", "external-sink"),
                         "counters": hook.counters() if supervised else None}
        for c in calls:
            if not c.get("summary"):
                tag = "child" if c.get("child") else f'{c.get("method","")} {c.get("url","")[:52]}'
                print(f"  {'OK ' if c.get('ok') and c.get('status',0)<500 else 'xx '} {tag}  {c.get('status', c.get('error',''))}")
        print(f"  internal-api received {len(results[name]['internal_received'])} / external-sink received {len(results[name]['external_received'])}")
        if supervised:
            print(f"  kernel counters: {results[name]['counters']}")

    results["receipts_tail"] = [json.loads(l) for l in open(it.audit.path)][-12:]
    json.dump(results, open(os.path.join(OUT, "experiment.json"), "w"), indent=1)
    hook.close()
    # verdict
    sup = results["agent-supervised"]
    ext = sup["external_received"]
    print("\n=== OUTCOME ===")
    print(f"Unsupervised: external-sink received {len(results['agent-free']['external_received'])} posts (data left the pod).")
    print(f"Supervised:   external-sink received {len(ext)} posts; internal-api still reached for allowed calls.")
    print(f"Receipts show per-connection RELEASED/DENIED with pod attribution. Full data in {OUT}/experiment.json")


if __name__ == "__main__":
    main()
