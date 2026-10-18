"""Command line: python3 -m escrow.cli {keygen|verifier|interceptor}

  keygen       --out PREFIX              Ed25519 verifier key (PREFIX.secret / PREFIX.public) and a record key
  verifier     --policy P --key SECRET --record-keys K1[,K2] --listen HOST:PORT --audit PATH
  interceptor  --listen HOST:PORT --verifier HOST:PORT --verifier-pk HEX --record-key HEX
               --registry pods.json --audit PATH [--deadline-ms N]
               [--bpf-obj bpf/escrow_connect4.bpf.o --attach-cgroup DIR ...]       (kernel hold point)
               [--kubepods /sys/fs/cgroup/kubepods.slice]   attach to every pod cgroup named in the registry
               [--kube-api]   build the registry from the API server for this node (needs a service account)
"""
from __future__ import annotations
import argparse
import asyncio
import json
import os
import secrets
import signal
import sys
import time

from . import ed25519
from .attribution import PodRegistry


def _hostport(s: str) -> tuple[str, int]:
    h, _, p = s.rpartition(":")
    return h or "0.0.0.0", int(p)


def cmd_keygen(a):
    seed = secrets.token_bytes(32)
    pk = ed25519.public_key(seed)
    with open(a.out + ".secret", "wb") as f:
        f.write(seed.hex().encode() + b"\n")
    os.chmod(a.out + ".secret", 0o600)
    with open(a.out + ".public", "w") as f:
        f.write(pk.hex() + "\n")
    with open(a.out + ".record-key", "w") as f:
        f.write(secrets.token_hex(32) + "\n")
    os.chmod(a.out + ".record-key", 0o600)
    print(f"wrote {a.out}.secret {a.out}.public {a.out}.record-key")


def kube_services() -> dict:
    """ClusterIP -> namespace/name for every Service (in-cluster service account)."""
    import ssl
    import urllib.request
    tok = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()
    ctx = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    req = urllib.request.Request("https://kubernetes.default.svc/api/v1/services", headers={"Authorization": f"Bearer {tok}"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        items = json.load(r)["items"]
    out = {}
    for sv in items:
        ip = sv["spec"].get("clusterIP")
        if ip and ip != "None":
            out[ip] = f"{sv['metadata']['namespace']}/{sv['metadata']['name']}"
    return out


def cmd_verifier(a):
    from .verifier import Policy, Verifier, serve
    import threading
    sk = bytes.fromhex(open(a.key).read().strip())
    src = a.record_keys or open(a.record_keys_file).read()
    keys = [bytes.fromhex(k.strip()) for k in src.replace("\n", ",").split(",") if k.strip()]
    host, port = _hostport(a.listen)
    pol = Policy.load(a.policy)
    if a.kube_services:
        pol.services = kube_services()
        print(f"service map: {len(pol.services)} services", flush=True)

        def refresh():
            while True:
                time.sleep(15)
                try:
                    pol.services = kube_services()
                except Exception as exc:
                    print(f"service map refresh: {exc}", flush=True)
        threading.Thread(target=refresh, daemon=True).start()
    self_addrs = [(host, port)] + [(ip, port) for ip, n in pol.services.items() if n == a.self_service]
    v = Verifier(sk, pol, keys, a.audit, name=a.name, verdict_ttl_ms=a.verdict_ttl_ms,
                 hold_timeout_ms=a.hold_timeout_ms, self_addrs=self_addrs)
    serve(v, host, port)
    print(f"verifier {a.name} pk={v.pk.hex()} listening on {host}:{port}", flush=True)
    signal.pause()


def kube_registry(node: str) -> dict:
    """Pod uid -> identity for this node, from the API server (in-cluster service account)."""
    import ssl
    import urllib.request
    tok = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()
    ctx = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    url = f"https://kubernetes.default.svc/api/v1/pods?fieldSelector=spec.nodeName={node}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        pods = json.load(r)["items"]
    out = {}
    for p in pods:
        md, sp = p["metadata"], p["spec"]
        if md.get("labels", {}).get("escrow.io/supervised") != "true":
            continue
        uid, ns, sa = md["uid"], md["namespace"], sp.get("serviceAccountName", "default")
        ident = {"pod_uid": uid, "namespace": ns, "name": md["name"], "service_account": sa,
                 "spiffe_id": f"spiffe://cluster.local/ns/{ns}/sa/{sa}"}
        out[uid] = ident
    return out


def find_pod_cgroups(kubepods: str, pod_uids: set[str]) -> dict[str, str]:
    """pod uid -> the pod-level cgroup directory (systemd or cgroupfs naming), covering all its containers."""
    found = {}
    for root, dirs, _ in os.walk(kubepods):
        base = os.path.basename(root)
        for uid in pod_uids:
            if (uid.replace("-", "_") in base or uid in base) and uid not in found:
                found[uid] = root
    return found


def cgroup_rel(path: str, unified_root: str) -> str:
    """Path as it appears in /proc/<pid>/cgroup (relative to the unified hierarchy root)."""
    rel = path[len(unified_root.rstrip("/")):] if path.startswith(unified_root.rstrip("/")) else path
    return rel or "/"


async def run_interceptor(a):
    from .interceptor import Interceptor
    reg = PodRegistry(a.registry)
    hook, bpf_map = None, None
    attach = list(a.attach_cgroup or [])
    node = os.environ.get("NODE_NAME", os.uname().nodename)
    if a.kube_api:
        ids = kube_registry(node)
        cgs = find_pod_cgroups(a.kubepods, set(ids))
        for uid, ident in ids.items():
            if uid in cgs:
                reg.entries[cgroup_rel(cgs[uid], a.unified_root)] = ident
                attach.append(cgs[uid])
        reg.save()
        print(f"registry: {len(reg.entries)} supervised pods on {node}; {len(attach)} cgroups", flush=True)
    peer_map = None
    if a.bpf_obj:
        from .bpfload import ConnectHook
        hook = ConnectHook(a.bpf_obj)
        bpf_map, peer_map = hook.maps["escrow_map"], hook.maps["peer_map"]
    host, port = _hostport(a.listen)
    rk = a.record_key or open(a.record_key_file).read().strip()
    vpk = a.verifier_pk or open(a.verifier_pk_file).read().strip()

    def make():
        return Interceptor(bytes.fromhex(rk), bytes.fromhex(vpk), _hostport(a.verifier), reg, a.audit,
                           node=node, deadline_ms=a.deadline_ms, bpf_map=bpf_map, peer_map=peer_map)
    it = make()
    addr = await it.start(host, port, reuse_port=a.workers > 1)
    if hook:
        redirect_ip = a.redirect_ip or (addr[0] if addr[0] != "0.0.0.0" else "127.0.0.1")
        dns = _hostport(a.dns) if a.dns else None
        hook.configure(redirect_ip, addr[1], dns)
        for cg in attach:
            hook.attach(cg)
            print(f"attached connect4/sendmsg4/sockops to {cg}", flush=True)
        print(f"kernel hold point -> {redirect_ip}:{addr[1]}; UDP pinned to {dns}", flush=True)
    # extra workers share the listening port (SO_REUSEPORT) and the maps (inherited fds)
    for w in range(1, a.workers):
        if os.fork() == 0:
            async def worker():
                i2 = make()
                i2.audit.path = a.audit + f".w{w}"
                i2.audit = type(i2.audit)(i2.audit.path)
                await i2.start(host, addr[1], reuse_port=True)
                await asyncio.Event().wait()
            asyncio.run(worker())
            os._exit(0)
    print(f"interceptor on {addr} x{a.workers} workers, verifier {a.verifier}, deadline {a.deadline_ms} ms", flush=True)
    if a.kube_api and a.watch_s:
        async def watch():
            while True:
                await asyncio.sleep(a.watch_s)
                try:
                    ids = kube_registry(node)
                    cgs = find_pod_cgroups(a.kubepods, set(ids))
                    for uid, ident in ids.items():
                        if uid in cgs and cgs[uid] not in attach:
                            reg.entries[cgroup_rel(cgs[uid], a.unified_root)] = ident
                            attach.append(cgs[uid])
                            if hook:
                                hook.attach(cgs[uid])
                            print(f"attached new pod {ident['namespace']}/{ident['name']}", flush=True)
                    reg.save()
                except Exception as exc:
                    print(f"watch: {exc}", flush=True)
        asyncio.create_task(watch())
    try:
        await asyncio.Event().wait()
    finally:
        if hook:
            hook.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="escrow")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out", required=True)
    v = sub.add_parser("verifier")
    v.add_argument("--policy", required=True); v.add_argument("--key", required=True)
    v.add_argument("--record-keys"); v.add_argument("--record-keys-file"); v.add_argument("--listen", default="0.0.0.0:8443")
    v.add_argument("--audit", default="verifier_audit.jsonl"); v.add_argument("--name", default="verifier")
    v.add_argument("--verdict-ttl-ms", type=int, default=2000); v.add_argument("--hold-timeout-ms", type=int, default=30000)
    v.add_argument("--kube-services", action="store_true"); v.add_argument("--self-service", default="escrow-system/escrow-verifier")
    i = sub.add_parser("interceptor")
    i.add_argument("--listen", default="127.0.0.1:15001"); i.add_argument("--verifier", required=True)
    i.add_argument("--verifier-pk"); i.add_argument("--verifier-pk-file")
    i.add_argument("--record-key"); i.add_argument("--record-key-file")
    i.add_argument("--registry", default="pods.json"); i.add_argument("--audit", default="interceptor_audit.jsonl")
    i.add_argument("--deadline-ms", type=int, default=2000)
    i.add_argument("--bpf-obj"); i.add_argument("--attach-cgroup", action="append")
    i.add_argument("--kubepods", default="/sys/fs/cgroup/kubepods.slice"); i.add_argument("--kube-api", action="store_true")
    i.add_argument("--unified-root", default="/sys/fs/cgroup", help="root of the cgroup v2 hierarchy as the kernel reports paths")
    i.add_argument("--redirect-ip", help="address pods use to reach this interceptor (node address on the pod network)")
    i.add_argument("--dns", help="HOST:PORT of the only resolver supervised pods may use over UDP")
    i.add_argument("--workers", type=int, default=1); i.add_argument("--watch-s", type=int, default=5)
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        cmd_keygen(a)
    elif a.cmd == "verifier":
        cmd_verifier(a)
    else:
        asyncio.run(run_interceptor(a))


if __name__ == "__main__":
    main()
