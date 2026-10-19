# Content-gate results (TLS, no termination)

One logged run of `experiments/tls_gate_demo.py all both` (`tls_gate_runtimes.json`): three TLS runtimes, two gates, one
keep-alive TLS connection per run carrying a benign `GET /v1/items` and then an exfiltration `POST /transfer` on the **same**
connection. The agent verified the real server certificate in every run; the relay and the probe held no key.

| Runtime | Probe placed in | Gate | GET (record 1) | POST (same connection) | Server received | Outcome |
|---|---|---|---|---|---|---|
| openssl | `libssl.so.3` | first | allow p=0.001 | **not inspected** (spliced) | `/v1/items, /transfer` | exfil reached the server -- **exploit confirmed** |
| openssl | `libssl.so.3` | stream | allow p=0.001 | deny p=0.999 (record 2) | `/v1/items` | exfil denied mid-stream, connection reset |
| go | `go_agent` | first | allow p=0.001 | **not inspected** (spliced) | `/v1/items, /transfer` | exfil reached the server -- **exploit confirmed** |
| go | `go_agent` | stream | allow p=0.001 | deny p=0.999 (record 2) | `/v1/items` | exfil denied mid-stream, connection reset |
| static | `static_agent` | first | allow p=0.001 | **not inspected** (spliced) | `/v1/items, /transfer` | exfil reached the server -- **exploit confirmed** |
| static | `static_agent` | stream | allow p=0.001 | deny p=0.999 (record 2) | `/v1/items` | exfil denied mid-stream, connection reset |

The first-record gate is the form first described; the stream gate holds every record until the write that produced it is
scored, so a second request on a kept-alive connection, or the tail of a long body, is gated like the first. Each write is
matched to its connection by resolving the TLS session handle to the writing socket's local port, so concurrent sessions in
one process are disambiguated (`experiments/tls_gate_concurrent.py`). `experiments/tls_gate_multirecord.py` checks the
record/write accounting: a 40 KiB write released as three records on one verdict, the fourth record a new write, denied.

```
=== openssl / first: probe in libssl.so.3 on SSL_write, SSL_write_ex
  AGENT one TLS connection, cert OK
  AGENT request 1 /v1/items    -> server replied b'HTTP/1.1 200 OK'
  AGENT request 2 /transfer    -> server replied b'HTTP/1.1 200 OK'
=== openssl / stream: probe in libssl.so.3 on SSL_write, SSL_write_ex
  AGENT one TLS connection, cert OK
  AGENT request 1 /v1/items    -> server replied b'HTTP/1.1 200 OK'
  AGENT request 2 /transfer    -> BLOCKED (ConnectionResetError)
=== go / first: probe in go_agent on crypto/tls.(*Conn).Write
  AGENT(go) one TLS connection, cert OK
  AGENT(go) request 1 /v1/items    -> server replied "HTTP/1.1 200 OK"
  AGENT(go) request 2 /transfer    -> server replied "HTTP/1.1 200 OK"
=== go / stream: probe in go_agent on crypto/tls.(*Conn).Write
  AGENT(go) one TLS connection, cert OK
  AGENT(go) request 1 /v1/items    -> server replied "HTTP/1.1 200 OK"
  AGENT(go) request 2 /transfer    -> BLOCKED (read tcp 127.0.0.1:41778->127.0.0.1:38319: read: connection reset by peer)
=== static / first: probe in static_agent on SSL_write, SSL_write_ex
  AGENT(static) one TLS connection, cert OK
  AGENT(static) request 1 /v1/items    -> server replied 'HTTP/1.1 200 OK'
  AGENT(static) request 2 /transfer    -> server replied 'HTTP/1.1 200 OK'
=== static / stream: probe in static_agent on SSL_write, SSL_write_ex
  AGENT(static) one TLS connection, cert OK
  AGENT(static) request 1 /v1/items    -> server replied 'HTTP/1.1 200 OK'
  AGENT(static) request 2 /transfer    -> BLOCKED (reset)
```
