"""Interceptor: the hold point for every outbound connection of a supervised workload.

Life of one connection
  1. The kernel delivers the agent's connect() here instead of to the
     destination (eBPF cgroup/connect4 rewrite, or iptables REDIRECT by
     owner uid). Nothing has left the node: no SYN was sent to the destination.
  2. accept(); attribute the peer socket (cookie, inode, pid, cgroup, exe,
     workload identity) and recover the original destination.
  3. Read the first bytes the agent writes (HTTP request line, TLS
     ClientHello) and park them with the connection.
  4. Send the signed escrow record to the verifier; wait at most
     `deadline_ms` for a verdict.
  5. Release only on an ALLOW that verifies, names this escrow_id, this
     socket cookie and this destination hash, is unexpired and unused.
     Anything else, including no verdict by the deadline, resets the
     connection (RST) and the destination never hears of it.
  6. Append a receipt to the hash-chained audit log.
"""
from __future__ import annotations
import asyncio
import json
import secrets
import socket
import struct
import time

from .attribution import PodRegistry, attribute
from .audit import AuditLog
from .verifier import dst_hash, sign_record, verify_verdict
from . import wire

SO_ORIGINAL_DST = 80
OUTCOMES = ("RELEASED", "DENIED", "DENIED_DEADLINE", "DENIED_BAD_VERDICT", "DENIED_VERIFIER_UNREACHABLE",
            "DENIED_UNKNOWN_DESTINATION", "UPSTREAM_FAILED")


class Interceptor:
    def __init__(self, record_key: bytes, verifier_pk: bytes, verifier_addr: tuple[str, int], registry: PodRegistry,
                 audit_path: str, node: str = "node", deadline_ms: int = 2000, peek_ms: int = 150,
                 bpf_map=None, peer_map=None, now_ns=time.time_ns):
        self.record_key = record_key
        self.vpk, self.vaddr = verifier_pk, verifier_addr
        self.registry, self.audit = registry, AuditLog(audit_path)
        self.node, self.deadline_ms, self.peek_ms = node, deadline_ms, peek_ms
        self.bpf_map, self.peer_map, self.now_ns = bpf_map, peer_map, now_ns
        self.live: dict[str, dict] = {}       # escrow_id -> record (awaiting verdict)
        self.consumed: set[str] = set()       # escrow ids released
        self.expired: set[str] = set()        # escrow ids denied before any verdict applied
        self.records: dict[str, tuple[dict, str]] = {}
        self.stats = {k: 0 for k in OUTCOMES}
        self.stats["accepted"] = 0
        self.server: asyncio.AbstractServer | None = None
        self.addr: tuple[str, int] | None = None

    # ---------------------------------------------------------------- server
    async def start(self, host: str = "127.0.0.1", port: int = 0, reuse_port: bool = False):
        self.server = await asyncio.start_server(self._handle, host, port, reuse_port=reuse_port)
        s = self.server.sockets[0].getsockname()
        self.addr = (s[0], s[1])
        return self.addr

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _original_dst(sock: socket.socket) -> tuple[str, int] | None:
        try:
            raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        except OSError:
            return None
        fam = struct.unpack("=H", raw[:2])[0]          # sockaddr_in: family (host order), port (network order), addr
        port = struct.unpack("!H", raw[2:4])[0]
        if fam != socket.AF_INET:
            return None
        return socket.inet_ntoa(raw[4:8]), port

    @staticmethod
    def _rst(writer: asyncio.StreamWriter):
        sock = writer.get_extra_info("socket")
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        writer.transport.abort()

    async def _ask_verifier(self, envelope: dict) -> dict:
        body = json.dumps(envelope).encode()
        r, w = await asyncio.open_connection(*self.vaddr)
        try:
            w.write(b"POST /v1/escrow HTTP/1.1\r\nHost: verifier\r\nContent-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await w.drain()
            head = await r.readuntil(b"\r\n\r\n")
            status = int(head.split(b" ", 2)[1])
            n = 0
            for ln in head.split(b"\r\n"):
                if ln.lower().startswith(b"content-length:"):
                    n = int(ln.split(b":")[1])
            data = await r.readexactly(n) if n else await r.read()
        finally:
            w.close()
        obj = json.loads(data or b"{}")
        if status != 200:
            raise RuntimeError(f"verifier returned {status}: {obj}")
        return obj

    def accept_verdict(self, escrow_id: str, verdict: dict) -> tuple[bool, str]:
        """The release gate. Every condition must hold; the verdict is consumed on success."""
        rec = self.live.get(escrow_id)
        if rec is None:
            return False, "stale: escrow id not live (expired or already decided)"
        if not isinstance(verdict, dict) or not verify_verdict(self.vpk, verdict):
            return False, "verdict signature invalid"
        b = verdict["body"]
        if b.get("schema") != "escrow/verdict/v0":
            return False, "bad schema"
        if b.get("escrow_id") != escrow_id:
            return False, "verdict names a different escrow id"
        if b.get("cookie") != rec["attribution"]["cookie"]:
            return False, "verdict bound to a different socket cookie"
        if b.get("dst_hash") != dst_hash(rec):
            return False, "verdict bound to a different destination or first bytes"
        if self.now_ns() > b.get("expires_ns", 0):
            return False, "verdict expired"
        if escrow_id in self.consumed:
            return False, "verdict already consumed"
        if b.get("verdict") != "ALLOW":
            return False, f"DENY: {b.get('reason')}"
        self.consumed.add(escrow_id)
        del self.live[escrow_id]
        return True, b.get("reason", "")

    # ---------------------------------------------------------------- per-connection
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        t_accept = self.now_ns()
        self.stats["accepted"] += 1
        sock = writer.get_extra_info("socket")
        peer, local = sock.getpeername()[:2], sock.getsockname()[:2]
        escrow_id = secrets.token_hex(16)
        timing = {}
        try:
            # 2. attribution + original destination -------------------------------
            # The peer socket's own 4-tuple names the destination as the agent sees it:
            # the interceptor address after an in-kernel connect() rewrite (eBPF), or the
            # original destination under conntrack NAT (iptables REDIRECT).
            od = self._original_dst(sock)
            nat = od is not None and od != tuple(local)
            peer_view = od if nat else local
            bpf_entry, cookie = None, None
            if self.peer_map is not None:
                # the sockops program indexed the agent's socket by its {local ip, local port};
                # this works from any network namespace (pods have their own)
                cookie = self.peer_map.cookie(*peer)
                if cookie and self.bpf_map is not None:
                    bpf_entry = self.bpf_map.lookup(cookie)
            if cookie is None:
                try:
                    from .attribution import peer_socket
                    cookie = peer_socket(peer, peer_view)["cookie"]
                    if self.bpf_map is not None:
                        bpf_entry = self.bpf_map.lookup(cookie)
                except OSError:
                    pass
            attrib = await asyncio.to_thread(attribute, peer, peer_view, self.registry, bpf_entry, cookie)
            timing["attribution_us"] = (self.now_ns() - t_accept) // 1000
            dst, src = None, "none"
            if bpf_entry:
                dst, src = (bpf_entry["orig_ip"], bpf_entry["orig_port"]), "bpf_connect4"
            elif nat:
                dst, src = od, "so_original_dst"
            # 3. park the first bytes -----------------------------------------------
            t0 = self.now_ns()
            try:
                held = await asyncio.wait_for(reader.read(wire.MAX_PEEK), self.peek_ms / 1000)
            except asyncio.TimeoutError:
                held = b""
            w = wire.parse(held)
            timing["peek_us"] = (self.now_ns() - t0) // 1000
            explicit = False
            if dst is None:  # explicit proxy mode: destination must be in the first bytes
                explicit = True
                if w["kind"] == "http" and w.get("host"):
                    h, _, p = w["host"].partition(":")
                    dst, src = (h, int(p) if p else (443 if w["method"] == "CONNECT" else 80)), "explicit_http"
                elif w["kind"] == "tls" and w.get("sni"):
                    dst, src = (w["sni"], 443), "explicit_sni"
            if dst is None:
                return await self._finish(writer, escrow_id, None, attrib, w, "DENIED_UNKNOWN_DESTINATION",
                                          "no original destination and none in first bytes", t_accept, timing)
            record = {"schema": "escrow/record/v0", "escrow_id": escrow_id, "node": self.node,
                      "t_hold_ns": t_accept, "attribution": attrib,
                      "dst": {"ip": dst[0], "port": dst[1], "source": src}, "wire": w,
                      "deadline_ms": self.deadline_ms}
            sig = sign_record(self.record_key, record)
            self.live[escrow_id] = record
            self.records[escrow_id] = (record, sig)
            if len(self.records) > 10000:
                self.records.pop(next(iter(self.records)))
            # 4. ask the verifier, bounded by the deadline ---------------------------
            remaining = self.deadline_ms / 1000 - (self.now_ns() - t_accept) / 1e9
            t0 = self.now_ns()
            try:
                verdict = await asyncio.wait_for(self._ask_verifier({"record": record, "sig": sig}), max(remaining, 0))
            except asyncio.TimeoutError:
                self.live.pop(escrow_id, None)
                self.expired.add(escrow_id)
                return await self._finish(writer, escrow_id, record, attrib, w, "DENIED_DEADLINE",
                                          f"no verdict within {self.deadline_ms} ms", t_accept, timing)
            except (OSError, RuntimeError, asyncio.IncompleteReadError, ValueError) as exc:
                self.live.pop(escrow_id, None)
                self.expired.add(escrow_id)
                return await self._finish(writer, escrow_id, record, attrib, w, "DENIED_VERIFIER_UNREACHABLE",
                                          str(exc), t_accept, timing)
            timing["verdict_rtt_us"] = (self.now_ns() - t0) // 1000
            # 5. the release gate ----------------------------------------------------
            t0 = self.now_ns()
            ok, why = self.accept_verdict(escrow_id, verdict)
            timing["gate_us"] = (self.now_ns() - t0) // 1000
            if not ok:
                self.live.pop(escrow_id, None)
                self.expired.add(escrow_id)
                outcome = "DENIED" if why.startswith("DENY:") else "DENIED_BAD_VERDICT"
                return await self._finish(writer, escrow_id, record, attrib, w, outcome, why, t_accept, timing)
            # 6. release: connect out and splice ------------------------------------
            t0 = self.now_ns()
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(dst[0], dst[1]), 5)
            except (OSError, asyncio.TimeoutError) as exc:
                return await self._finish(writer, escrow_id, record, attrib, w, "UPSTREAM_FAILED", str(exc), t_accept, timing)
            timing["upstream_connect_us"] = (self.now_ns() - t0) // 1000
            if explicit and w.get("method") == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            elif held:
                uw.write(held)
                await uw.drain()
            self._receipt(escrow_id, record, attrib, w, "RELEASED", why, t_accept, timing)
            await asyncio.gather(self._pipe(reader, uw), self._pipe(ur, writer))
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def _finish(self, writer, escrow_id, record, attrib, w, outcome, why, t_accept, timing):
        self._receipt(escrow_id, record, attrib, w, outcome, why, t_accept, timing)
        self._rst(writer)

    def _receipt(self, escrow_id, record, attrib, w, outcome, why, t_accept, timing):
        self.stats[outcome] += 1
        now = self.now_ns()
        timing["total_us"] = (now - t_accept) // 1000
        wl = attrib.get("workload") or {}
        self.audit.append({"escrow_id": escrow_id, "node": self.node, "t_hold_ns": t_accept, "t_decided_ns": now,
                           "cookie": attrib.get("cookie"), "inode": attrib.get("inode"), "pid": attrib.get("pid"),
                           "cgroup": attrib.get("cgroup"), "exe_sha256": attrib.get("exe_sha256"), "comm": attrib.get("comm"),
                           "workload": wl.get("spiffe_id"), "pod_uid": wl.get("pod_uid"),
                           "dst": record["dst"] if record else None, "wire": {k: w.get(k) for k in ("kind", "sni", "host", "method", "path", "bytes", "sha256")},
                           "outcome": outcome, "reason": why, "timing": timing})
