#!/usr/bin/env python3
"""Content-gated egress WITHOUT terminating TLS.

Proves the claim: an eBPF uprobe reads the plaintext the agent writes, a small ML model scores it,
and the connection is gated on that verdict -- while the TLS connection stays end-to-end to the
real server with the real certificate, and the enforcer never holds a TLS key.

Topology (loopback):
  agent (TLS client, verifies the real server cert)
      --> transparent relay (holds no key; parses only TLS record framing)
      --> real HTTPS server (real cert; records what it received)
  eBPF uprobe on the agent's TLS write function captures every plaintext write, in order.

Two gate modes, same relay, same model, same probe:

  first   the relay forwards the handshake, then holds the FIRST application-data record of the
          connection until the verdict on the plaintext that produced it; after that it splices.
          This is the gate described first in the paper. It is blind to anything written later on
          the same connection (HTTP keep-alive, a second request, the tail of a long body, HTTP/2).

  stream  the relay holds EVERY outgoing application-data record until the plaintext write that
          produced it has been scored. Writes are drained from a kernel FIFO; each is bound to the
          connection through the TLS handle (SSL* / *tls.Conn) so concurrent sessions in one
          process do not cross. A deny mid-stream resets the connection; the offending record
          never leaves. Keep-alive and multi-record bodies are covered.

The agents exercise exactly the keep-alive exploit: ONE TLS connection, a benign GET first,
then an exfiltration POST on the same connection. Under `first` the POST reaches the server
(the exploit works); under `stream` it is denied on its plaintext and the server never sees it.

Three TLS runtimes are gated identically, differing only in where the uprobe is placed:
  openssl : Python/ssl agent, SSL_write_ex in the shared libssl.so.3
  go      : Go agent, crypto/tls.(*Conn).Write inside the Go binary (build with experiments/agents/build.sh)
  static  : C agent statically linked against libssl (SSL_write inside the executable; the BoringSSL shape)

TLS 1.2 is used so application-data records (type 0x17) are cleanly distinguishable from the
handshake on the wire; under TLS 1.3 the stream gate works the same way, keyed on the uprobe
events rather than the record type (see docs/TLS_GATE.md). The relay decrypts nothing either way.

Run: sudo PYTHONPATH=. python3 experiments/tls_gate_demo.py [openssl|go|static|all] [first|stream|both]
"""
from __future__ import annotations
import collections
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from escrow.mlcheck import ContentCheck            # noqa: E402
from escrow.tlsview import TlsPlaintextProbe, RUNTIME_OPENSSL, RUNTIME_GO, RUNTIME_STATIC  # noqa: E402

TLS_HANDSHAKE, TLS_CCS, TLS_ALERT, TLS_APPDATA = 0x16, 0x14, 0x15, 0x17
TLS_MAX_PLAINTEXT = 16384
AGENTS_DIR = os.path.join(ROOT, "experiments", "agents")


def make_cert(d):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", f"{d}/key.pem",
                    "-out", f"{d}/cert.pem", "-days", "1", "-nodes", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)


SERVER_SRC = r'''
import ssl, sys, http.server, json
logfile = sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # keep-alive: several requests per connection
    def _h(self):
        n=int(self.headers.get("Content-Length","0")); body=self.rfile.read(n)
        with open(logfile, "a") as f:
            f.write(json.dumps({"path": self.path, "body": body.decode("latin-1","replace")}) + "\n")
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
    do_GET=do_POST=_h
    def log_message(self,*a): pass
srv=http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H)
srv.socket=ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
'''

# The exploit the agents run: one connection, benign request, then exfil on the SAME connection.
REQ_BENIGN = b"GET /v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
REQ_EXFIL = (b"POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\nConnection: keep-alive\r\n\r\n"
             b"SECRET_CARD=4111111111111111")

CLIENT_SRC = r'''
import ssl, socket, sys, time
relay_port = int(sys.argv[1]); cafile = sys.argv[2]; delay = float(sys.argv[3])
time.sleep(delay)
reqs = [%r, %r]
ctx = ssl.create_default_context(cafile=cafile)
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", relay_port)), server_hostname="localhost")
s.settimeout(3.0)
print("AGENT one TLS connection, cert OK")
for i, r in enumerate(reqs):
    path = r.split(b" ")[1].decode()
    try:
        s.sendall(r)
        resp = b""
        while b"\r\n\r\nok" not in resp:
            chunk = s.recv(200)
            if not chunk: raise ConnectionResetError("closed")
            resp += chunk
        print("AGENT request %%d %%-12s -> server replied %%r" %% (i + 1, path, resp[:15]))
    except Exception as e:
        print("AGENT request %%d %%-12s -> BLOCKED (%%s)" %% (i + 1, path, type(e).__name__)); break
s.close()
''' % (REQ_BENIGN, REQ_EXFIL)


def server_received(logfile):
    if not os.path.exists(logfile):
        return []
    return [json.loads(l) for l in open(logfile) if l.strip()]


def read_record(sock, buf):
    """Return (record_bytes, rest_buf) for one TLS record, or (None, buf) if incomplete+closed."""
    while len(buf) < 5:
        b = sock.recv(4096)
        if not b:
            return None, buf
        buf += b
    length = struct.unpack("!H", buf[3:5])[0]          # record header: type(1) version(2) length(2)
    while len(buf) < 5 + length:
        b = sock.recv(4096)
        if not b:
            return None, buf
        buf += b
    return buf[:5 + length], buf[5 + length:]


def splice(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _reset(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()
    except OSError:
        pass


class WritePool:
    """Captured plaintext writes, drained from the kernel FIFO, bucketed by pid and TLS handle."""

    def __init__(self, probe):
        self.probe = probe
        self.by_pid = collections.defaultdict(collections.deque)

    def _pull(self):
        for ev in self.probe.drain():
            self.by_pid[ev["pid"]].append(ev)

    def take(self, pid, handle=None, timeout=1.0):
        """Oldest unconsumed write of `pid`; if `handle` is given, oldest write on that TLS object.
        Waits up to `timeout` for the uprobe to deliver one. None = nothing captured (fail closed)."""
        t_end = time.monotonic() + timeout
        while True:
            self._pull()
            q = self.by_pid[pid]
            for i, ev in enumerate(q):
                if handle is None or ev["handle"] == handle:
                    del q[i]
                    return ev
            if time.monotonic() >= t_end:
                return None
            time.sleep(0.005)


def relay_first(client, server_addr, pid, pool, ml, log):
    """First-record gate: hold the first application-data record, then splice."""
    server = socket.create_connection(server_addr)
    threading.Thread(target=splice, args=(server, client), daemon=True).start()
    buf = b""
    while True:
        rec, buf = read_record(client, buf)
        if rec is None:
            return
        if rec[0] != TLS_APPDATA:
            server.sendall(rec)                    # handshake / CCS / alert: forward untouched
            continue
        ev = pool.take(pid)
        if ev is None:
            log.append({"record": 1, "verdict": "deny", "reason": "no_plaintext", "p": None, "request": ""})
            _reset(client); server.close(); return
        p, label, reasons = ml.score(ev["data"])
        log.append({"record": 1, "verdict": label, "p": round(p, 3), "reasons": reasons,
                    "request": ev["data"].split(b"\r\n", 1)[0].decode("latin-1", "replace")})
        if label != "allow":
            _reset(client); server.close(); return
        server.sendall(rec)
        if buf:
            server.sendall(buf)
        splice(client, server)                     # blind from here on
        return


def relay_stream(client, server_addr, pid, pool, ml, log):
    """Stream gate: hold EVERY application-data record until the write that produced it is scored."""
    server = socket.create_connection(server_addr)
    threading.Thread(target=splice, args=(server, client), daemon=True).start()
    buf = b""
    handle = None          # TLS object bound to this connection, learned from its first write
    remaining = 0          # plaintext bytes of the current write not yet seen on the wire
    overhead = None        # ciphertext bytes per record beyond the plaintext (nonce + tag), calibrated
    nrec = 0
    while True:
        rec, buf = read_record(client, buf)
        if rec is None:
            return
        if rec[0] != TLS_APPDATA:
            server.sendall(rec)
            continue
        nrec += 1
        reclen = len(rec) - 5
        if remaining <= 0:
            # a new write starts here: fetch its plaintext (bound to this connection's handle)
            ev = pool.take(pid, handle)
            if ev is None:
                log.append({"record": nrec, "verdict": "deny", "reason": "no_plaintext", "p": None, "request": ""})
                _reset(client); server.close(); return
            if handle is None:
                handle = ev["handle"]
            p, label, reasons = ml.score(ev["data"])
            log.append({"record": nrec, "verdict": label, "p": round(p, 3), "reasons": reasons,
                        "request": ev["data"].split(b"\r\n", 1)[0].decode("latin-1", "replace")})
            if label != "allow":
                _reset(client); server.close(); return     # this record never leaves
            remaining = ev["len"]
            if overhead is None:
                overhead = reclen - min(ev["len"], TLS_MAX_PLAINTEXT)
        server.sendall(rec)                                # scored: release this record
        remaining -= reclen - (overhead or 0)


def agent_command(runtime, relay_port, cafile):
    """Command line for the agent of a runtime, and the executable the uprobe is placed in."""
    if runtime == RUNTIME_OPENSSL:
        return [sys.executable, "-c", CLIENT_SRC, str(relay_port), cafile, "2.0"], None
    exe = os.path.join(AGENTS_DIR, "go_agent" if runtime == RUNTIME_GO else "static_agent")
    if not os.path.exists(exe):
        raise SystemExit(f"{exe} missing: run bash experiments/agents/build.sh")
    return [exe, str(relay_port), cafile, "2.0"], exe


def run(runtime, mode):
    d = tempfile.mkdtemp(prefix="tlsgate-")
    make_cert(d)
    _p = socket.socket(); _p.bind(("127.0.0.1", 0)); base = _p.getsockname()[1]; _p.close()
    logfile = f"{d}/received.jsonl"
    srv = subprocess.Popen([sys.executable, "-c", SERVER_SRC, str(base), f"{d}/cert.pem", f"{d}/key.pem", logfile],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    ml = ContentCheck(threshold=0.5)
    lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", 0)); lst.listen(8); relay_port = lst.getsockname()[1]

    cmd, exe = agent_command(runtime, relay_port, f"{d}/cert.pem")
    obj = os.path.join(ROOT, "bpf", "ssl_sniff.bpf.o")
    probe = TlsPlaintextProbe(obj, runtime=runtime) if exe is None else TlsPlaintextProbe(obj, lib=exe, runtime=runtime)
    probe.drain()                                          # start from an empty FIFO
    pool = WritePool(probe)
    client = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    nf = probe.attach(client.pid)
    where = "libssl.so.3" if exe is None else os.path.basename(exe)
    print(f"=== runtime {runtime}, gate {mode}: uprobe on {', '.join(probe.offsets)} in {where}, "
          f"agent pid={client.pid} ({nf} probe(s)); relay :{relay_port} -> server :{base}")
    print("    one keep-alive TLS connection: benign GET, then exfil POST on the same connection")

    log = []
    lst.settimeout(12)
    try:
        c, _ = lst.accept()
        (relay_stream if mode == "stream" else relay_first)(c, ("127.0.0.1", base), client.pid, pool, ml, log)
    except socket.timeout:
        pass
    agent_out = client.communicate()[0].strip()
    time.sleep(0.5)
    received = server_received(logfile)
    print("    agent saw:")
    for line in agent_out.splitlines():
        print("      " + line)
    print("    gate decisions (on plaintext captured from inside TLS):")
    for e in log:
        print(f"      record {e['record']}: {e['verdict'].upper():5} p={e['p']}  {e['request']}   reasons={e.get('reasons')}")
    print("    what the REAL server actually received:")
    if not received:
        print("      (nothing)")
    for r in received:
        print(f"      {r['path']}  body={r['body']!r}")
    paths = [r["path"] for r in received]
    if mode == "stream":
        ok = paths == ["/v1/items"] and len(log) == 2 and [e["verdict"] for e in log] == ["allow", "deny"]
        print(f"    RESULT {runtime}/{mode}: {'PASS' if ok else 'FAIL'} -- benign allowed, exfil on the same "
              f"connection denied mid-stream on its plaintext, server received only the benign request\n")
    else:
        exploit = paths == ["/v1/items", "/transfer"] and len(log) == 1
        print(f"    RESULT {runtime}/{mode}: {'EXPLOIT CONFIRMED' if exploit else 'unexpected'} -- first-record gate "
              f"saw only the GET; the exfil POST rode the released connection to the server\n")
        ok = exploit
    probe.close(); srv.terminate(); lst.close(); import shutil; shutil.rmtree(d, ignore_errors=True)
    return {"runtime": runtime, "mode": mode, "probe_in": where, "symbols": list(probe.offsets), "decisions": log,
            "server_received": received, "agent": agent_out.splitlines(), "pass": ok}


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    modes = sys.argv[2] if len(sys.argv) > 2 else "both"
    runtimes = [RUNTIME_OPENSSL, RUNTIME_GO, RUNTIME_STATIC] if which == "all" else [which]
    modes = ["first", "stream"] if modes == "both" else [modes]
    results = [run(rt, m) for rt in runtimes for m in modes]
    out = os.path.join(ROOT, "results", "tls_gate_runtimes.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=1)
    n_ok = sum(r["pass"] for r in results)
    print(f"{n_ok}/{len(results)} runs as expected; written {out}")
    sys.exit(0 if n_ok == len(results) else 1)


if __name__ == "__main__":
    main()
