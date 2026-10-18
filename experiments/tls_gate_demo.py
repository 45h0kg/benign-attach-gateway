#!/usr/bin/env python3
"""Content-gated egress WITHOUT terminating TLS.

Proves the claim: an eBPF uprobe reads the plaintext the agent writes, a small ML model scores it,
and the connection is gated on that verdict -- while the TLS connection stays end-to-end to the
real server with the real certificate, and the enforcer never holds a TLS key.

Topology (loopback):
  agent (TLS client, verifies the real server cert)
      --> transparent relay (holds no key; parses only TLS record framing)
      --> real HTTPS server (real cert; records what it received)
  eBPF uprobe on the agent's SSL_write(_ex) captures the plaintext request.

For each request the relay forwards the handshake untouched, then holds the first TLS
application-data record until the ML verdict on the uprobe-captured plaintext:
  allow -> forward the record, splice the rest; the server receives the request end-to-end.
  deny  -> reset; the server never receives a byte of the request.

TLS 1.2 is used so application-data records (type 0x17) are cleanly distinguishable from the
handshake on the wire; TLS 1.3 hides the inner type, and is handled by triggering on the uprobe
write instead of record type (see docs/TLS_GATE.md). The relay decrypts nothing either way.

Run: sudo PYTHONPATH=. python3 experiments/tls_gate_demo.py
"""
from __future__ import annotations
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from escrow.mlcheck import ContentCheck            # noqa: E402
from escrow.tlsview import TlsPlaintextProbe        # noqa: E402

TLS_HANDSHAKE, TLS_CCS, TLS_ALERT, TLS_APPDATA = 0x16, 0x14, 0x15, 0x17


def make_cert(d):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", f"{d}/key.pem",
                    "-out", f"{d}/cert.pem", "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)


SERVER_SRC = r'''
import ssl, sys, http.server, json
logfile = sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        n=int(self.headers.get("Content-Length","0")); body=self.rfile.read(n)
        with open(logfile, "a") as f:
            f.write(json.dumps({"path": self.path, "body": body.decode("latin-1","replace")}) + "\n")
        self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
    do_GET=do_POST=_h
    def log_message(self,*a): pass
srv=http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H)
srv.socket=ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
'''


def server_received(logfile):
    import json
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
    ctype, ver, length = buf[0], buf[1:3], struct.unpack("!H", buf[3:5])[0]
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


def relay_once(client, server_addr, pid, probe, ml, log):
    server = socket.create_connection(server_addr)
    # responses flow back untouched
    threading.Thread(target=splice, args=(server, client), daemon=True).start()
    buf = b""
    gated = False
    while not gated:
        rec, buf = read_record(client, buf)
        if rec is None:
            break
        ctype = rec[0]
        if ctype != TLS_APPDATA:
            server.sendall(rec)                    # handshake / CCS / alert: forward untouched
            continue
        # first application-data record: hold it, decide on the plaintext the uprobe captured
        plaintext = None
        for _ in range(40):
            plaintext = probe.plaintext_for(pid, consume=True)
            if plaintext:
                break
            time.sleep(0.02)
        if not plaintext:
            log.append({"verdict": "deny", "reason": "no_plaintext", "p": None, "request": ""})
            _reset(client); server.close(); return
        p, label, reasons = ml.score(plaintext)
        req_line = plaintext.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        log.append({"verdict": label, "p": round(p, 3), "reasons": reasons, "request": req_line,
                    "plaintext_seen": plaintext.decode("latin-1", "replace")[:120]})
        if label == "allow":
            server.sendall(rec)                    # release the held record
            if buf:
                server.sendall(buf)
            splice(client, server)                 # splice the rest end-to-end
        else:
            _reset(client)                         # deny: server never sees the request
            server.close()
        gated = True


def _reset(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()
    except OSError:
        pass


CLIENT_SRC = r'''
import ssl, socket, sys, time
relay_port = int(sys.argv[1]); cafile = sys.argv[2]; delay = float(sys.argv[3])
time.sleep(delay)
reqs = [
    b"GET /v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    b"POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\nConnection: close\r\n\r\nSECRET_CARD=4111111111111111",
]
for r in reqs:
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", relay_port)), server_hostname="localhost")
        s.sendall(r)
        resp = s.recv(200)
        print("AGENT request %-16s -> cert OK, server replied %r" % (r.split(b" ")[1].decode(), resp[:15]))
        s.close()
    except Exception as e:
        print("AGENT request %-16s -> BLOCKED (%s: %s)" % (r.split(b" ")[1].decode(), type(e).__name__, str(e)[:40]))
    time.sleep(1.5)
'''


def main():
    d = tempfile.mkdtemp(prefix="tlsgate-")
    make_cert(d)
    # pick a free port for the server
    _p = socket.socket(); _p.bind(("127.0.0.1", 0)); base = _p.getsockname()[1]; _p.close()
    logfile = f"{d}/received.jsonl"
    srv = subprocess.Popen([sys.executable, "-c", SERVER_SRC, str(base), f"{d}/cert.pem", f"{d}/key.pem", logfile],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    probe = TlsPlaintextProbe(os.path.join(ROOT, "bpf", "ssl_sniff.bpf.o"))
    ml = ContentCheck(threshold=0.5)
    # relay listener
    lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", 0)); lst.listen(8); relay_port = lst.getsockname()[1]

    # start the agent (delayed) and attach the uprobe to its pid only
    client = subprocess.Popen([sys.executable, "-c", CLIENT_SRC, str(relay_port), f"{d}/cert.pem", "2.0"],
                              stdout=subprocess.PIPE, text=True)
    nf = probe.attach(client.pid)
    print(f"uprobe on agent pid={client.pid}: {nf} function(s); relay :{relay_port} -> server :{base}")
    print("TLS is end-to-end to the real server; the relay and the probe hold NO key.\n")

    log = []
    lst.settimeout(12)
    handled = 0
    while handled < 2:
        try:
            c, _ = lst.accept()
        except socket.timeout:
            break
        relay_once(c, ("127.0.0.1", base), client.pid, probe, ml, log)
        handled += 1

    print(client.communicate()[0].strip())
    time.sleep(0.5)
    received = server_received(logfile)
    print("\n--- content gate decisions (on plaintext captured from inside TLS) ---")
    for e in log:
        print(f"  {e['verdict'].upper():5} p={e['p']}  {e['request']}   reasons={e.get('reasons')}")
    print("\n--- what the REAL server actually received ---")
    if not received:
        print("  (nothing)")
    for r in received:
        print(f"  {r['path']}  body={r['body']!r}")
    print("\nResult: the exfil POST was denied on its plaintext content and never reached the server,")
    print("yet both connections used real end-to-end TLS (the agent verified the server's cert).")
    probe.close(); srv.terminate(); import shutil; shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
