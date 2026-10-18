# Content-gated egress without terminating TLS

Escrow's connect-time gate (DESIGN.md) decides *whether* an agent may open a connection, from
destination + SNI + identity. Encryption doesn't hide those. What it hides is the request
*content*. This module adds a content gate that sees the plaintext and decides on it, **without
terminating TLS** -- the connection stays end-to-end to the real server with the real certificate,
and the enforcer never holds a TLS key.

## How the plaintext is obtained
An eBPF uprobe on the agent's TLS library (`SSL_write` / `SSL_write_ex` in OpenSSL 3) reads the
plaintext buffer at the library boundary, *before* it is encrypted, into a kernel map keyed by
pid_tgid (`bpf/ssl_sniff.bpf.c`, `escrow/tlsview.py`). The wire is untouched; this is observation
inside the agent's own address space, via the kernel. It is the same technique observability tools
use -- the novelty here is not the capture but gating the connection on it.

## How the connection is gated
The interceptor already relays the agent's encrypted bytes (it never has a key). For a TLS
connection it forwards the handshake untouched, then **holds the first application-data record**
until a verdict on the plaintext the uprobe captured. A small ML model (`escrow/mlcheck.py`,
placeholder) scores the request; `allow` releases the held record and splices the rest end-to-end;
`deny` resets, and the server never receives the request. The agent's TLS cert validation is
unaffected because validation is on the hostname, and the real server's certificate flows through
the relay unbroken.

## What is and isn't novel
- Uprobe TLS-plaintext capture: **known** (AgentSight and others observe this way; they do not act).
- MITM proxies: **known**; they see content but terminate TLS, hold a key, and break end-to-end.
- The combination here -- see the plaintext via uprobe, **gate** the connection on it with a
  single-use, identity-bound verdict, keep the connection **end-to-end** with no key at the
  enforcer -- is the claimed contribution. It dissolves the usual "inspect or stay end-to-end,
  pick one" tradeoff.

## TLS version
The demo forces TLS 1.2 so application-data records (type 0x17) are distinguishable from the
handshake on the wire, which makes "hold the first application record" a clean record-boundary
operation. Under TLS 1.3 the outer record type is always 0x17 after ServerHello, so the gate
triggers on the uprobe write event (the application called `SSL_write`) rather than the record
type; the enforcer still decrypts nothing. Both are described; the prototype implements the 1.2
record-boundary path.

## Runtime coverage
The uprobe is placed at the write function of whichever TLS library the agent uses, in whichever
ELF holds that code. Two kernel programs cover three runtime shapes (`bpf/ssl_sniff.bpf.c`):

| Runtime | Symbol | Where the probe is placed | Registers read | Status |
|---|---|---|---|---|
| OpenSSL shared (Python, curl, Node, …) | `SSL_write`, `SSL_write_ex` | `libssl.so.3` | `rsi`=buf, `rdx`=len (SysV ABI) | demonstrated |
| OpenSSL/BoringSSL statically linked | `SSL_write`, `SSL_write_ex` | the agent's own executable | same | demonstrated (static libssl build) |
| Go `crypto/tls` | `crypto/tls.(*Conn).Write` | the Go binary (always static) | `rbx`=b.ptr, `rcx`=b.len (Go register ABI) | demonstrated |

`escrow.tlsview.detect_runtime(exe)` picks the runtime from the agent's executable: Go if it
carries the Go TLS symbol, static if it carries `SSL_write` itself, otherwise shared OpenSSL;
`TlsPlaintextProbe.for_executable(obj, exe)` loads the matching program and symbol. The relay, the
model and the gate are identical across runtimes -- only the probe placement differs.
`experiments/tls_gate_demo.py all` runs the three agents (`experiments/agents/`) through the same
gate; `results/tls_gate_runtimes.json` holds the logged run.

Not yet covered: Rustls (`rustls::conn::ConnectionCommon::writer` is a different shape and needs its
own probe), musl-linked OpenSSL variants with stripped symbols (no symbol → no offset; a stripped
binary needs an offset supplied out of band), and a BoringSSL build we have not tested directly --
the static-OpenSSL agent exercises the same mechanism (symbol inside the executable, SysV ABI) and
BoringSSL keeps the `SSL_write(ssl, buf, num)` signature.

## Limitations
- Correlation in the prototype is by writing task (`pid_tgid`); an agent that multiplexes several
  TLS sessions on one thread (asyncio-style) needs the `SSL*` / `*tls.Conn` handle (first argument of
  the write) as the key so concurrent sessions are disambiguated. The uprobe can read it; not wired.
- The gate decides on the first application-data record only; later writes on a released
  connection are not held, as with the connection gate.
- The ML model is a deterministic logistic-regression placeholder; it is not the contribution.
