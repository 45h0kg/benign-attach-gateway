#!/usr/bin/env python3
"""Stream-gate accounting check: one TLS write that spans several records, then an exfil write.

A 40 KiB benign GET (a long header) is one SSL_write but three TLS 1.2 records. The stream gate
must score it once, release all three records, and then recognise the next record as the start
of a new write and score that one on its own plaintext. If the record<->write accounting were
off by one, the exfil write would ride the tail of the allowed write.

Run: sudo PYTHONPATH=. python3 experiments/tls_gate_multirecord.py   (OpenSSL/Python agent)
"""
from __future__ import annotations
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls_gate_demo as D                                   # noqa: E402
from escrow.tlsview import TlsPlaintextProbe                # noqa: E402
from escrow.mlcheck import ContentCheck                     # noqa: E402

PAD = 40000
CLIENT = r'''
import ssl, socket, sys, time
port=int(sys.argv[1]); ca=sys.argv[2]; pad=int(sys.argv[3]); time.sleep(1.5)
ctx=ssl.create_default_context(cafile=ca); ctx.maximum_version=ssl.TLSVersion.TLSv1_2
s=ctx.wrap_socket(socket.create_connection(("127.0.0.1",port)),server_hostname="localhost"); s.settimeout(3)
big=b"GET /v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nX-Pad: " + b"A"*pad + b"\r\n\r\n"
ex=b"POST /transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 28\r\nConnection: keep-alive\r\n\r\nSECRET_CARD=4111111111111111"
for i,r in enumerate((big, ex)):
    try:
        s.sendall(r); resp=b""
        while b"\r\n\r\nok" not in resp:
            c=s.recv(200)
            if not c: raise ConnectionResetError()
            resp+=c
        print("AGENT request %d (%d bytes, one write) -> server replied %r" % (i+1, len(r), resp[:15]))
    except Exception as e:
        print("AGENT request %d -> BLOCKED (%s)" % (i+1, type(e).__name__)); break
'''


def main():
    d = tempfile.mkdtemp(prefix="tlsgate-mr-"); D.make_cert(d)
    _p = socket.socket(); _p.bind(("127.0.0.1", 0)); base = _p.getsockname()[1]; _p.close()
    logf = f"{d}/r.jsonl"
    srv = subprocess.Popen([sys.executable, "-c", D.SERVER_SRC, str(base), f"{d}/cert.pem", f"{d}/key.pem", logf],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    probe = TlsPlaintextProbe(os.path.join(ROOT, "bpf", "ssl_sniff.bpf.o")); probe.drain()
    pool = D.WritePool(probe); ml = ContentCheck(0.5)
    lst = socket.socket(); lst.bind(("127.0.0.1", 0)); lst.listen(2); rp = lst.getsockname()[1]
    cli = subprocess.Popen([sys.executable, "-c", CLIENT, str(rp), f"{d}/cert.pem", str(PAD)],
                           stdout=subprocess.PIPE, text=True)
    probe.attach(cli.pid); log = []
    lst.settimeout(10)
    c, _ = lst.accept()
    D.relay_stream(c, ("127.0.0.1", base), cli.pid, pool, ml, log)
    out = cli.communicate()[0].strip(); time.sleep(0.3)
    print("=== stream gate, one write spanning several records (OpenSSL/Python agent)")
    for line in out.splitlines():
        print("      " + line)
    for e in log:
        print(f"      record {e['record']}: {e['verdict'].upper():5} p={e['p']}  {e['request'][:40]}")
    rec = D.server_received(logf)
    print("      server received:", [(r["path"], len(r["body"])) for r in rec] or "(nothing)")
    ok = ([r["path"] for r in rec] == ["/v1/items"] and [e["verdict"] for e in log] == ["allow", "deny"]
          and log[1]["record"] > 2)
    print(f"    RESULT multirecord: {'PASS' if ok else 'FAIL'} -- {log[1]['record'] - 1 if len(log) > 1 else '?'} records "
          f"released as one scored write; the next record was recognised as a new write and denied")
    probe.close(); srv.terminate(); lst.close()
    import shutil; shutil.rmtree(d, ignore_errors=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
