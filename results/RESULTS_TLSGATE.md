# Content-gate result (TLS, no termination)

One logged run of `experiments/tls_gate_demo.py` (Linux 6.18, OpenSSL 3.0, TLS 1.2, eBPF uprobe on SSL_write/SSL_write_ex, logistic-regression content model).

```
uprobe on agent pid=699: 2 function(s); relay :43243 -> server :51095
TLS is end-to-end to the real server; the relay and the probe hold NO key.

AGENT request /v1/items        -> cert OK, server replied b'HTTP/1.0 200 OK'
AGENT request /transfer        -> BLOCKED (ConnectionResetError: [Errno 104] Connection reset by peer)

--- content gate decisions (on plaintext captured from inside TLS) ---
  ALLOW p=0.001  GET /v1/items HTTP/1.1   reasons=[]
  DENY  p=0.999  POST /transfer HTTP/1.1   reasons=['sensitive_kw', 'pan_like', 'sensitive_path', 'mutating']

--- what the REAL server actually received ---
  /v1/items  body=''

Result: the exfil POST was denied on its plaintext content and never reached the server,
yet both connections used real end-to-end TLS (the agent verified the server's cert).
```

The agent's TLS cert validation succeeded (`cert OK`), proving the real server's certificate reached it end-to-end through a relay that holds no key; the exfil request was denied on its captured plaintext and never reached the server.
