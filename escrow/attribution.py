"""Attribution of a held connection to the kernel object and the workload that opened it.

Two views are joined into one record:

  kernel view   socket cookie (sock_gen_cookie, the same value eBPF's
                bpf_get_socket_cookie returns), socket inode, uid, pid/tgid,
                cgroup path, executable path + SHA-256, comm
  platform view pod uid, namespace, pod name, service account, SPIFFE id

The kernel view comes from the kernel itself:
  * the peer socket's cookie, inode and uid from NETLINK_SOCK_DIAG
    (inet_diag), looked up by exact 4-tuple;
  * the owning process from /proc/<pid>/fd (socket:[inode]), then
    /proc/<pid>/{cgroup,exe,comm,status}.
When the eBPF connect4 program is loaded, cgroup id, pid/tgid and the original
destination are also read from its map, keyed by the same cookie.

The platform view comes from a PodRegistry: on Kubernetes the kubelet names
each pod's cgroup after the pod uid, so a cgroup path prefix maps to a pod.
The registry is a JSON file {prefix -> identity}; the harness writes it, a
node agent would populate it from the kubelet.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
import socket
import struct

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
TCPF_ALL = 0xFFF
INET_DIAG_NOCOOKIE = 0xFFFFFFFF


def _nl_sockid(sport: int, dport: int, src: str, dst: str) -> bytes:
    # struct inet_diag_sockid { __be16 sport, dport; __be32 src[4], dst[4]; __u32 if; __u32 cookie[2]; }
    return (struct.pack("!HH", sport, dport) + socket.inet_aton(src) + b"\0" * 12
            + socket.inet_aton(dst) + b"\0" * 12 + struct.pack("=III", 0, INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE))


def peer_socket(peer: tuple[str, int], local: tuple[str, int]) -> dict:
    """Kernel-reported cookie, inode and uid of the *peer's* TCP socket
    (the agent's end of the accepted connection)."""
    req = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_TCP, 0, 0, TCPF_ALL)
    req += _nl_sockid(peer[1], local[1], peer[0], local[0])
    hdr = struct.pack("=IHHII", 16 + len(req), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST, 1, 0)
    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
    try:
        nl.send(hdr + req)
        data = nl.recv(65536)
    finally:
        nl.close()
    ln, typ, flags, seq, pid = struct.unpack("=IHHII", data[:16])
    if typ == NLMSG_ERROR:
        err = struct.unpack("=i", data[16:20])[0]
        raise OSError(-err, f"inet_diag: {os.strerror(-err)}")
    msg = data[16:ln]
    # struct inet_diag_msg { u8 family,state,timer,retrans; sockid(48); u32 expires,rqueue,wqueue,uid,inode; }
    family, state, timer, retrans = struct.unpack("=BBBB", msg[:4])
    sockid = msg[4:52]
    expires, rqueue, wqueue, uid, inode = struct.unpack("=IIIII", msg[52:72])
    c0, c1 = struct.unpack("=II", sockid[40:48])
    cookie = c0 | (c1 << 32)
    return {"cookie": cookie, "inode": inode, "uid": uid, "state": state}


def process_for_inode(inode: int) -> dict | None:
    """Find the process holding socket:[inode]; return its kernel attributes."""
    target = f"socket:[{inode}]"
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fddir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"{fddir}/{fd}") == target:
                    return process_attrs(int(pid))
            except OSError:
                continue
    return None


_DIGESTS: dict[tuple, str] = {}


def exe_digest(path: str) -> str:
    """SHA-256 of the executable, cached by (device, inode, size, mtime). The
    file is read through /proc/<pid>/exe, so a deleted-and-replaced binary gets
    a new inode and a fresh digest."""
    stt = os.stat(path)
    key = (stt.st_dev, stt.st_ino, stt.st_size, stt.st_mtime_ns)
    d = _DIGESTS.get(key)
    if d is None:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        d = _DIGESTS[key] = h.hexdigest()
    return d


def process_attrs(pid: int) -> dict:
    out = {"pid": pid}
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        v2 = [ln for ln in lines if ln.startswith("0::")]
        out["cgroup"] = v2[0][3:] if v2 else lines[0].split(":", 2)[2]
    except OSError:
        out["cgroup"] = ""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        out["exe"] = exe
        out["exe_sha256"] = exe_digest(f"/proc/{pid}/exe")
    except OSError:
        out["exe"], out["exe_sha256"] = "", ""
    try:
        with open(f"/proc/{pid}/comm") as f:
            out["comm"] = f.read().strip()
    except OSError:
        out["comm"] = ""
    try:
        with open(f"/proc/{pid}/status") as f:
            for ln in f:
                if ln.startswith("PPid:"):
                    out["ppid"] = int(ln.split()[1])
                elif ln.startswith("Uid:"):
                    out["uid"] = int(ln.split()[1])
    except OSError:
        pass
    return out


class PodRegistry:
    """cgroup-path prefix -> workload identity. Longest prefix wins."""

    def __init__(self, path: str | None = None, entries: dict | None = None):
        self.entries: dict[str, dict] = dict(entries or {})
        self.path = path
        if path and os.path.exists(path):
            with open(path) as f:
                self.entries.update(json.load(f))

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=1, sort_keys=True)

    def lookup(self, cgroup_path: str) -> dict | None:
        best = None
        for prefix, ident in self.entries.items():
            if cgroup_path == prefix or cgroup_path.startswith(prefix.rstrip("/") + "/"):
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, ident)
        return dict(best[1], cgroup_prefix=best[0]) if best else None


def attribute(peer: tuple[str, int], local: tuple[str, int], registry: PodRegistry,
              bpf_entry: dict | None = None, cookie: int | None = None) -> dict:
    """Full attribution record for the accepted connection from `peer`."""
    rec: dict = {"peer_ip": peer[0], "peer_port": peer[1]}
    try:
        ks = peer_socket(peer, local)
        rec.update(cookie=ks["cookie"], inode=ks["inode"], sock_uid=ks["uid"])
    except OSError as exc:
        rec.update(cookie=cookie or 0, inode=0, sock_uid=-1, diag_error=str(exc))
    if cookie and rec["cookie"] != cookie:
        rec["cookie"] = cookie            # the kernel's own index wins
    proc = None
    if bpf_entry and bpf_entry.get("tgid"):
        proc = process_attrs(bpf_entry["tgid"])          # the kernel named the task at connect()
        if not proc.get("cgroup") and not proc.get("exe"):
            proc = None                                   # gone already; fall back to the fd scan
    if proc is None and rec["inode"]:
        proc = process_for_inode(rec["inode"])
    if proc:
        rec.update(proc)
    else:
        rec.update(pid=0, cgroup="", exe="", exe_sha256="", comm="")
    if bpf_entry:
        rec["bpf"] = bpf_entry
        if not rec["cgroup"] and bpf_entry.get("cgroup_id"):
            rec["cgroup_id"] = bpf_entry["cgroup_id"]
    ident = registry.lookup(rec["cgroup"]) if rec["cgroup"] else None
    rec["workload"] = ident
    return rec
