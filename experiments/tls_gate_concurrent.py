#!/usr/bin/env python3
"""Two concurrent TLS sessions in ONE process, interleaved: the binding must not cross them.

This is the case the stream gate's handle binding exists for. One agent process (one thread per
connection, so one OS thread each but the same pid, and writes interleaved in time) opens two TLS
connections to the relay: connection A sends only benign requests, connection B sends an
exfiltration request. A gate that bound plaintext to a connection by arrival order could match B's
exfil plaintext to A's held record, or A's benign plaintext to B's -- allowing the exfil. The
stream gate binds each connection to the TLS handle whose socket is that connection (by port), so A
is allowed and B is denied regardless of interleaving.

Run: sudo PYTHONPATH=. python3 experiments/tls_gate_concurrent.py
"""
from __future__ import annotations
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls_gate_demo as D                                   # noqa: E402
from escrow.tlsview import TlsPlaintextProbe                # noqa: E402
from escrow.mlcheck import ContentCheck                     # noqa: E402

# One process, two connections, writes interleaved by a shared barrier so neither finishes first.
AGENT = r'''
import ssl, socket, sys, threading, time
port = int(sys.argv[1]); ca = sys.argv[2]
ctx = ssl.create_default_context(cafile=ca); ctx.maximum_version = ssl.TLSVersion.TLSv1_2
barrier = threading.Barrier(2)
def session(name, reqs):
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="localhost")
    s.settimeout(4)
    print("CONN %s localport %d" % (name, s.getsockname()[1]), flush=True)
    for r in reqs:
        barrier.wait()                       # step both connections together, interleaving writes
        try:
            s.sendall(r); resp = b""
            while b"ok" not in resp:
                c = s.recv(100)
                if not c: raise ConnectionResetError()
                resp += c
            print("CONN %s %s -> ok" % (name, r.split(b" ")[1].decode()), flush=True)
        except Exception as e:
            print("CONN %s %s -> BLOCKED (%s)" % (name, r.split(b" ")[1].decode(), type(e).__name__), flush=True)
            try: barrier.abort()
            except Exception: pass
            return
A = [b"GET /v1/items HTTP/1.1\r\nHost: localhost\r\n\r\n", b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n"]
B = [b"GET /v1/items HTTP/1.1\r\nHost: localhost\r\n\r\n",
     b"POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\n\r\nSECRET_CARD=4111111111111111"]
ta = threading.Thread(target=session, args=("A", A)); tb = threading.Thread(target=session, args=("B", B))
ta.start(); tb.start(); ta.join(); tb.join()
'''


def main():
    d = tempfile.mkdtemp(prefix="tlsconc-"); D.make_cert(d)
    _p = socket.socket(); _p.bind(("127.0.0.1", 0)); base = _p.getsockname()[1]; _p.close()
    logf = f"{d}/received.jsonl"
    srv = subprocess.Popen([sys.executable, "-c", D.SERVER_SRC, str(base), f"{d}/cert.pem", f"{d}/key.pem", logf],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    probe = TlsPlaintextProbe(os.path.join(ROOT, "bpf", "ssl_sniff.bpf.o")); probe.drain()
    pool = D.WritePool(probe); ml = ContentCheck(0.5)
    lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", 0)); lst.listen(8); relay_port = lst.getsockname()[1]
    cli = subprocess.Popen([sys.executable, "-c", AGENT, str(relay_port), f"{d}/cert.pem"],
                           stdout=subprocess.PIPE, text=True)
    probe.attach(cli.pid)
    print(f"=== two concurrent TLS sessions in one process (pid {cli.pid}), writes interleaved")

    logs = {}
    threads = []
    lst.settimeout(10)
    for _ in range(2):
        try:
            c, _ = lst.accept()
        except socket.timeout:
            break
        port = c.getpeername()[1]
        log = logs[port] = []
        t = threading.Thread(target=D.relay_stream, args=(c, ("127.0.0.1", base), cli.pid, pool, ml, log), daemon=True)
        t.start(); threads.append(t)
    out = cli.communicate()[0]
    for t in threads:
        t.join(timeout=5)
    time.sleep(0.3)
    received = D.server_received(logf)
    print("    agent saw:")
    for line in out.strip().splitlines():
        print("      " + line)
    print("    per-connection gate decisions (keyed by agent port):")
    for port, log in logs.items():
        for e in log:
            print(f"      port {port} record {e['record']}: {e['verdict'].upper():5} p={e['p']}  {e['request'][:34]}")
    paths = sorted(r["path"] for r in received)
    print("    server received:", paths or "(nothing)")
    # the exfil POST must never reach the server; both benign GETs on A should
    ok = "/transfer" not in paths and paths.count("/v1/items") >= 1 and "/v1/status" in paths
    print(f"    RESULT concurrent: {'PASS' if ok else 'FAIL'} -- the exfil on one session was denied without "
          f"crossing the benign session, which completed")
    probe.close(); srv.terminate(); lst.close()
    import shutil; shutil.rmtree(d, ignore_errors=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
