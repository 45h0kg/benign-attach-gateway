"""Test harness: real sockets, real cgroups, real kernel hold point.

Topology (all on this host, loopback):
  pod-a, pod-b   cgroups under /sys/fs/cgroup/unified/escrow-harness/<pod uid>;
                 agent processes run there as uid AGENT_UID
  interceptor    asyncio, own thread (root, outside the pod cgroups)
  verifier       ThreadingHTTPServer, own thread, isolated key
  upstreams      echo servers that record every accepted connection

Hold point, selectable:
  "bpf"       escrow_connect4 attached to each pod cgroup (in-kernel rewrite)
  "iptables"  nat OUTPUT -m owner --uid-owner AGENT_UID -j REDIRECT (conntrack NAT)
"""
from __future__ import annotations
import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from escrow import ed25519                       # noqa: E402
from escrow.attribution import PodRegistry       # noqa: E402
from escrow.interceptor import Interceptor       # noqa: E402
from escrow.verifier import Policy, Verifier, serve  # noqa: E402

AGENT_UID = 1001
CG_ROOT = "/sys/fs/cgroup/unified/escrow-harness"
AGENT_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")

PODS = {
    "pod-a": {"pod_uid": "0f1c6a1e-aaaa-4c1b-9e41-000000000001", "namespace": "agents", "name": "triage-agent-0",
              "service_account": "agent-a", "spiffe_id": "spiffe://cluster.local/ns/agents/sa/agent-a"},
    "pod-b": {"pod_uid": "0f1c6a1e-bbbb-4c1b-9e41-000000000002", "namespace": "agents", "name": "browse-agent-0",
              "service_account": "agent-b", "spiffe_id": "spiffe://cluster.local/ns/agents/sa/agent-b"},
}


class Upstream:
    """Echo server that records (peer, first bytes) for every accepted connection."""

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop, self.accepted, self.server, self.addr = loop, [], None, None

    async def _h(self, r, w):
        peer = w.get_extra_info("peername")
        try:
            data = await asyncio.wait_for(r.read(65536), 2)
        except asyncio.TimeoutError:
            data = b""
        self.accepted.append((peer, data))
        if data:
            w.write(b"echo:" + data)
            try:
                await w.drain()
            except ConnectionError:
                pass
        w.close()

    async def start(self):
        self.server = await asyncio.start_server(self._h, "127.0.0.1", 0)
        s = self.server.sockets[0].getsockname()
        self.addr = (s[0], s[1])
        return self.addr


class Harness:
    def __init__(self, mode: str = "bpf", deadline_ms: int = 1000, hold_timeout_ms: int = 10000,
                 verdict_ttl_ms: int = 2000, policy_extra: dict | None = None):
        self.mode = mode
        self.tmp = tempfile.mkdtemp(prefix="escrow-")
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.upstreams: dict[str, Upstream] = {}
        for name in ("allowed", "denied", "tls", "http", "hold", "budget"):
            u = Upstream(self.loop)
            self.run(u.start())
            self.upstreams[name] = u
        self.U = {k: v.addr for k, v in self.upstreams.items()}
        # cgroups + registry
        os.makedirs(CG_ROOT, exist_ok=True)
        entries = {}
        for pod, ident in PODS.items():
            path = f"{CG_ROOT}/{ident['pod_uid']}"
            os.makedirs(path, exist_ok=True)
            entries[f"/escrow-harness/{ident['pod_uid']}"] = ident
        self.registry = PodRegistry(os.path.join(self.tmp, "pods.json"), entries)
        self.registry.save()
        # keys
        self.ikey = secrets.token_bytes(32)   # interceptor<->verifier record key
        self.vsk, self.vpk = ed25519.keypair_from_seed(secrets.token_bytes(32))
        self.rogue_sk, self.rogue_pk = ed25519.keypair_from_seed(secrets.token_bytes(32))
        # verifier
        a, b = PODS["pod-a"]["spiffe_id"], PODS["pod-b"]["spiffe_id"]
        pol = {"workloads": {
            a: {"rules": [
                {"host": "127.0.0.1", "port": self.U["allowed"][1], "action": "allow"},
                {"host": "api.allowed.test", "port": self.U["tls"][1], "action": "allow"},
                {"host": "127.0.0.1", "port": self.U["http"][1], "methods": ["GET"], "path_prefix": "/v1/", "action": "allow"},
                {"port": self.U["hold"][1], "action": "hold"},
            ]},
            b: {"rules": [{"host": "127.0.0.1", "port": self.U["budget"][1], "action": "allow"}], "budget_per_minute": 2},
        }, "default": "deny"}
        if policy_extra:
            pol["workloads"].update(policy_extra)
        self.policy = Policy(pol)
        self.vaddr = ("127.0.0.1", self._free_port())
        self.verifier = Verifier(self.vsk, self.policy, [self.ikey], os.path.join(self.tmp, "verifier_audit.jsonl"),
                                 verdict_ttl_ms=verdict_ttl_ms, hold_timeout_ms=hold_timeout_ms, self_addrs=[self.vaddr])
        self.vsrv = serve(self.verifier, *self.vaddr)
        # interceptor
        self.hook = None
        bpf_map = peer_map = None
        if mode == "bpf":
            from escrow.bpfload import ConnectHook
            obj = os.path.join(ROOT, "bpf", "escrow_connect4.bpf.o")
            if not os.path.exists(obj):
                subprocess.check_call(["clang", "-O2", "-target", "bpf", "-I/usr/include/x86_64-linux-gnu", "-c",
                                       os.path.join(ROOT, "bpf", "escrow_connect4.bpf.c"), "-o", obj])
            self.hook = ConnectHook(obj)
            bpf_map = self.hook.maps["escrow_map"]
            peer_map = self.hook.maps["peer_map"]
        self.interceptor = Interceptor(self.ikey, self.vpk, self.vaddr, self.registry,
                                       os.path.join(self.tmp, "interceptor_audit.jsonl"), node="harness-node",
                                       deadline_ms=deadline_ms, bpf_map=bpf_map, peer_map=peer_map)
        self.iaddr = self.run(self.interceptor.start("127.0.0.1", 0))
        if mode == "bpf":
            self.hook.configure(*self.iaddr, dns=("127.0.0.53", 53))
            for ident in PODS.values():
                self.hook.attach(f"{CG_ROOT}/{ident['pod_uid']}")
        elif mode == "iptables":
            self.rule = ["-p", "tcp", "-m", "owner", "--uid-owner", str(AGENT_UID),
                         "-j", "REDIRECT", "--to-ports", str(self.iaddr[1])]
            subprocess.check_call(["iptables", "-t", "nat", "-A", "OUTPUT"] + self.rule)

    @staticmethod
    def _free_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    # ------------------------------------------------------------ agents
    def agent(self, pod: str | None, dst: tuple[str, int], send: bytes = b"hello", recv: int = 65536,
              timeout: float = 5.0, child: bool = False, exe: str | None = None, raw: bool = False, repeat: int = 0, udp: dict | None = None) -> dict:
        """Run tests/agent.py as uid AGENT_UID inside the pod's cgroup (or outside any pod if pod is None)."""
        job = {"dst": list(dst), "send": send.hex(), "recv": recv, "timeout": timeout, "child": child, "repeat": repeat, "udp": udp}
        cg = f"{CG_ROOT}/{PODS[pod]['pod_uid']}" if pod else None

        def pre():
            if raw:      # unsupervised baseline: root, outside every pod cgroup
                return
            if cg:
                with open(cg + "/cgroup.procs", "w") as f:
                    f.write(str(os.getpid()))
            os.setgid(AGENT_UID)
            os.setuid(AGENT_UID)
        p = subprocess.run([exe or sys.executable, AGENT_PY, json.dumps(job)], preexec_fn=pre,
                           capture_output=True, text=True, timeout=timeout + 10)
        try:
            out = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"error": f"agent crashed: {p.stderr[-400:]}"}
        out["pid_reported"] = out.get("pid")
        return out

    def last_receipt(self) -> dict:
        with open(self.interceptor.audit.path) as f:
            return json.loads(f.read().strip().splitlines()[-1])

    def receipts(self) -> list[dict]:
        with open(self.interceptor.audit.path) as f:
            return [json.loads(l) for l in f if l.strip()]

    def close(self):
        if self.mode == "iptables":
            subprocess.call(["iptables", "-t", "nat", "-D", "OUTPUT"] + self.rule)
        if self.hook:
            self.hook.close()
        self.vsrv.shutdown()
        self.run(self.interceptor.stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        time.sleep(0.1)
        for ident in PODS.values():
            try:
                os.rmdir(f"{CG_ROOT}/{ident['pod_uid']}")
            except OSError:
                pass
        try:
            os.rmdir(CG_ROOT)
        except OSError:
            pass
