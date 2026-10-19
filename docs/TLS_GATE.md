# Content-gated egress without terminating TLS

Escrow's connect-time gate (DESIGN.md) decides *whether* an agent may open a connection, from
destination + SNI + identity. Encryption doesn't hide those. What it hides is the request
*content*. This module adds a content gate that sees the plaintext and decides on it, **without
terminating TLS** -- the connection stays end-to-end to the real server with the real certificate,
and the enforcer never holds a TLS key.

## How the plaintext is obtained
An eBPF uprobe on the agent's TLS write function reads the plaintext buffer at the library boundary,
*before* it is encrypted (`bpf/ssl_sniff.bpf.c`, `escrow/tlsview.py`). Every write is captured, in
order, as an event `{pid, tid, handle, len, data[:16384]}` pushed to a kernel FIFO (`writes_q`), where
`handle` is the TLS object the write was made on (`SSL*` for OpenSSL, `*tls.Conn` for Go), `len`
is the full plaintext length of the write, and `data` is up to one full TLS record (16 KiB) of it.
A second pair of probes records which socket each handle writes to (`fd_by_handle`): exactly, via
`SSL_set_fd` for OpenSSL, or by the socket write (`syscall.write` for Go, libc `write` as a fallback)
that immediately follows a TLS write on the same task. Userspace resolves handle -> fd -> local port
via `/proc`, so each captured write is matched to the connection the relay accepted by that
connection's agent-side port, never by arrival order. The wire is untouched; this is observation inside the
agent's own address space, via the kernel. It is the same technique observability tools use -- the
novelty here is not the capture but gating the connection on it.

## How the connection is gated
The interceptor already relays the agent's encrypted bytes (it never has a key). For a TLS
connection it forwards the handshake untouched and then runs one of two gates on the
application-data records (`experiments/tls_gate_demo.py`):

**First-record gate** (`first`). Hold the first application-data record until the verdict on the
plaintext that produced it; on `allow` release it and splice the rest end-to-end; on `deny` reset.
This is the simplest form and the one the paper's first version described. It is **blind to
everything written after the first record**: a second request on an HTTP keep-alive connection, the
tail of a body longer than one record, every frame of an HTTP/2 session after the preface. The demo
runs this gate against a keep-alive agent to show the exploit is real: a benign `GET` opens the
connection and an exfiltration `POST` on the same connection reaches the server.

**Stream gate** (`stream`, the gate to use). Hold **every** outgoing application-data record until
the write that produced it has been scored. The relay drains the FIFO and binds the connection to
the TLS handle whose socket is that connection -- matching the handle's resolved local port to the
agent-side port the relay accepted -- then consumes only writes on that handle, so concurrent TLS
sessions in one process (asyncio-style, or threads) cannot cross, whatever the interleaving. A write of `len` plaintext bytes produces
one or more records; the relay calibrates the per-record ciphertext overhead (nonce + tag) from the
first record and releases records until `len` bytes are accounted for, then treats the next record
as the start of a new write and fetches its plaintext. A `deny` at any point resets the connection;
the offending record never leaves the node. If no plaintext arrives for a held record within the
timeout the gate denies (**fail closed**), so an agent whose TLS the probe cannot see loses egress
rather than gaining an unobserved channel. `experiments/tls_gate_multirecord.py` checks the
accounting with a 40 KiB write spanning three records followed by an exfil write.

The model is called once per write (microseconds for the placeholder); the relay stays in userspace
for the life of a content-gated connection, so content-gated connections cannot be handed to a kernel
splice. Connections gated only on destination still can.

The agent's TLS certificate validation is unaffected in both modes, because validation is on the
hostname and the real server's certificate flows through the relay unbroken.

## What is and isn't novel
- Uprobe TLS-plaintext capture: **known** (AgentSight and others observe this way; they do not act).
- MITM proxies: **known**; they see content but terminate TLS, hold a key, and break end-to-end.
- The combination here -- see the plaintext via uprobe, **gate** the connection on it with a
  single-use, identity-bound verdict, keep the connection **end-to-end** with no key at the
  enforcer -- is the claimed contribution. It dissolves the usual "inspect or stay end-to-end,
  pick one" tradeoff.

## TLS version
The demo forces TLS 1.2 so application-data records (type 0x17) are distinguishable from the
handshake on the wire, which makes record boundaries a clean place to hold. Under TLS 1.3 the outer record type is always
0x17 after ServerHello, so the stream gate cannot tell handshake tail from application data by type;
it holds every post-ServerHello record and uses the uprobe write events, which exist only for
application data, to decide what to score -- the enforcer still decrypts nothing. The prototype
implements the 1.2 path.

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
- Up to one full TLS record (16 KiB) of each write is captured (`MAXDATA`); a write longer than one
  record is seen up to its first record, so a model needing whole multi-record bodies needs the
  capture chunked across the write's records.
- Binding resolves handle -> fd -> port through `/proc`; if a connection's first write is captured
  before the kernel has recorded its socket fd (a race of a few microseconds), the relay falls back
  to the first write's handle until the fd is bound. `experiments/tls_gate_concurrent.py` exercises
  two interleaved sessions in one process and confirms the exfil stays on its own connection.
- HTTP/2: every frame is scored at the byte level, but HEADERS frames are HPACK-compressed, so a
  content model needs a per-connection HPACK decoder to read them; DATA frames are plain.
- Under a code-controlling adversary (one who ships its own TLS, strips symbols, or inlines
  encryption) the probe sees nothing and the gate fails closed; a decoy write through the probed
  function while the real payload goes another way, or a race on the buffer between the probe's copy
  and the library's encryption, is possible for such an adversary. The content gate's threat is
  hostile *input* to an honest agent; the connection gate's is hostile code.
- The ML model is a deterministic logistic-regression placeholder; it is not the contribution.
