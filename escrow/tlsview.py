"""TLS-plaintext view: read the plaintext an agent writes, without terminating TLS.

An eBPF uprobe on the agent's TLS library captures every plaintext write at the library
boundary -- before it is encrypted -- into a kernel FIFO, in order, each write tagged with the
writing task, the full write length and the TLS session object it was made on. Three runtime
shapes are covered by two capture programs:

  * OpenSSL shared library  -> `SSL_write` / `SSL_write_ex` in libssl.so       (RUNTIME_OPENSSL)
  * OpenSSL/BoringSSL static -> the same symbols inside the agent's own binary  (RUNTIME_STATIC)
  * Go crypto/tls            -> `crypto/tls.(*Conn).Write` in the Go binary    (RUNTIME_GO)

Binding a write to the connection that carries it: each TLS session object is mapped to its
socket fd -- exactly, by a probe on `SSL_set_fd` (OpenSSL), or by correlating a TLS write with
the socket write that follows it on the same task (`syscall.write` for Go; libc `write`/`send`
as a fallback for BIO-attached OpenSSL clients). Userspace resolves pid+fd to the socket's local
port, which is the peer port of the connection the relay accepted. So the stream gate matches
each captured write to the right connection even when one process multiplexes several TLS
sessions, and never by arrival order.

The TLS connection itself is untouched: it still completes end-to-end to the real destination
with the real certificate; the enforcer never holds a key and never decrypts the wire.

Loader uses raw bpf(2) + perf_event_open (no libbpf), consistent with escrow.bpfload.
"""
from __future__ import annotations
import ctypes
import os
import struct

from elftools.elf.elffile import ELFFile

from .bpfload import _bpf

_libc = ctypes.CDLL(None, use_errno=True)
SYS_PERF = 298
BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY = 0, 1, 3, 4
BPF_PROG_LOAD = 5
BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21
BPF_PROG_TYPE_KPROBE = 2
PERF_EVENT_IOC_ENABLE = 0x2400
PERF_EVENT_IOC_SET_BPF = 0x40042408
MAXDATA = 16384
HDR = struct.Struct("=IIQII")          # pid, tid, handle, len, cap
VSZ = HDR.size + MAXDATA

DEFAULT_LIB = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
DEFAULT_LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
WRITE_SYMS = ("SSL_write", "SSL_write_ex")
GO_WRITE_SYMS = ("crypto/tls.(*Conn).Write",)

RUNTIME_OPENSSL, RUNTIME_STATIC, RUNTIME_GO = "openssl", "static", "go"

# Per runtime: list of (program section, which ELF, symbols). "lib" = the TLS library path
# (libssl for OPENSSL; the agent executable for STATIC and GO), "libc" = the C library.
ATTACH_PLAN = {
    RUNTIME_OPENSSL: [("uprobe/SSL_write", "lib", WRITE_SYMS),
                      ("uprobe/SSL_set_fd", "lib", ("SSL_set_fd",)),
                      ("uprobe/fd_write_sysv", "libc", ("write", "send", "sendto"))],
    RUNTIME_STATIC:  [("uprobe/SSL_write", "lib", WRITE_SYMS),
                      ("uprobe/SSL_set_fd", "lib", ("SSL_set_fd",)),
                      ("uprobe/fd_write_sysv", "lib", ("write", "send", "sendto", "__libc_write", "__libc_send"))],
    RUNTIME_GO:      [("uprobe/go_tls_write", "lib", GO_WRITE_SYMS),
                      ("uprobe/fd_write_go", "lib", ("syscall.write",))],
}


def detect_runtime(exe: str) -> str:
    """Pick the runtime from the agent's executable: Go if it carries the Go TLS symbol,
    static if it carries SSL_write itself, otherwise assume shared OpenSSL."""
    offs = symbol_file_offsets(exe, GO_WRITE_SYMS + WRITE_SYMS)
    if GO_WRITE_SYMS[0] in offs:
        return RUNTIME_GO
    if "SSL_write" in offs:
        return RUNTIME_STATIC
    return RUNTIME_OPENSSL


def _uprobe_pmu_type() -> int:
    return int(open("/sys/bus/event_source/devices/uprobe/type").read())


def symbol_file_offsets(lib: str, names) -> dict:
    """File offset of each symbol (for perf uprobe config2)."""
    want = set(names)
    out = {}
    with open(lib, "rb") as f:
        elf = ELFFile(f)
        loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        for sec in elf.iter_sections():
            if sec.name not in (".dynsym", ".symtab"):
                continue
            for sym in sec.iter_symbols():
                if sym.name in want and sym["st_value"] and sym.name not in out:
                    v = sym["st_value"]
                    for seg in loads:
                        pv, po, msz = seg["p_vaddr"], seg["p_offset"], seg["p_memsz"]
                        if pv <= v < pv + msz:
                            out[sym.name] = v - pv + po
                            break
    return out


def local_port_of(pid: int, fd: int) -> int | None:
    """Local TCP port of socket `fd` in process `pid`, via /proc (inode -> /proc/<pid>/net/tcp)."""
    try:
        link = os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return None
    if not link.startswith("socket:["):
        return None
    inode = link[8:-1]
    for table in (f"/proc/{pid}/net/tcp", f"/proc/{pid}/net/tcp6"):
        try:
            with open(table) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if cols[9] == inode:
                        return int(cols[1].rsplit(":", 1)[1], 16)
        except OSError:
            continue
    return None


class TlsPlaintextProbe:
    """Loads the capture and binding uprobes for one TLS runtime and reads captured plaintext.

    `lib` is the ELF that holds the TLS write function: libssl.so for shared OpenSSL, or the
    agent's own executable for a static OpenSSL/BoringSSL build or a Go binary.
    """

    def __init__(self, obj_path: str, lib: str = DEFAULT_LIB, syms=None, runtime: str = RUNTIME_OPENSSL,
                 libc: str = DEFAULT_LIBC):
        self.runtime = runtime
        self.elfs = {"lib": lib, "libc": libc}
        self.plan = []                               # (section, elf path, {symbol: offset})
        for section, which, names in ATTACH_PLAN[runtime]:
            if syms and section.endswith(("SSL_write", "go_tls_write")):
                names = syms
            path = self.elfs[which]
            if not os.path.exists(path):
                continue
            offs = symbol_file_offsets(path, names)
            if offs:
                self.plan.append((section, path, offs))
        self.offsets = next((o for s, _, o in self.plan if s in ("uprobe/SSL_write", "uprobe/go_tls_write")), {})
        if not self.offsets:
            raise LookupError(f"no TLS write symbol for runtime {runtime!r} in {lib}")
        self.progs, self.maps = self._load(obj_path, [s for s, _, _ in self.plan])
        self.writes = self.maps["writes"]
        self.writes_q = self.maps["writes_q"]
        self.fd_by_handle = self.maps["fd_by_handle"]
        self.perf_fds: list[int] = []
        self._keep: list = []

    def _load(self, obj, sections):
        with open(obj, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            maps = elf.get_section_by_name("maps")
            data = maps.data()
            fds = {}
            for sym in symtab.iter_symbols():
                if sym["st_shndx"] == elf.get_section_index("maps"):
                    t, ks, vs, me, fl = struct.unpack("=IIIII", data[sym["st_value"]:sym["st_value"] + 20])
                    fds[sym.name] = (_bpf(BPF_MAP_CREATE, struct.pack("=IIIII", t, ks, vs, me, fl)), sym["st_value"])
            progs = {}
            for section in sections:
                sec = elf.get_section_by_name(section)
                insns = bytearray(sec.data())
                rel = elf.get_section_by_name(".rel" + section)
                if rel:
                    for r in rel.iter_relocations():
                        s = symtab.get_symbol(r["r_info_sym"])
                        fd = next(v[0] for v in fds.values() if v[1] == s["st_value"])
                        off = r["r_offset"]
                        insns[off + 1] = (insns[off + 1] & 0x0F) | (1 << 4)
                        struct.pack_into("=i", insns, off + 4, fd)
                lic = ctypes.create_string_buffer(b"GPL")
                ibuf = ctypes.create_string_buffer(bytes(insns))
                log = ctypes.create_string_buffer(1 << 16)
                attr = bytearray(struct.pack("=IIQQIIQII", BPF_PROG_TYPE_KPROBE, len(insns) // 8,
                                 ctypes.addressof(ibuf), ctypes.addressof(lic), 1, len(log), ctypes.addressof(log), 0, 0))
                attr += b"\0" * (16 * 8 - len(attr))
                try:
                    progs[section] = _bpf(BPF_PROG_LOAD, bytes(attr))
                except OSError as e:
                    raise OSError(e.errno, f"{section}: {e.strerror}; verifier log:\n{log.value.decode(errors='replace')}")
            return progs, {k: v[0] for k, v in fds.items()}

    @classmethod
    def for_executable(cls, obj_path: str, exe: str, libssl: str = DEFAULT_LIB):
        """Probe the right runtime for an agent executable (Go / static / shared OpenSSL)."""
        rt = detect_runtime(exe)
        return cls(obj_path, lib=exe if rt != RUNTIME_OPENSSL else libssl, runtime=rt)

    def _perf_attr(self, path: str, offset: int):
        a = bytearray(128)
        struct.pack_into("=II", a, 0, _uprobe_pmu_type(), 128)
        struct.pack_into("=Q", a, 8, 0)
        cpath = ctypes.create_string_buffer(path.encode() + b"\x00")
        struct.pack_into("=Q", a, 56, ctypes.addressof(cpath))
        struct.pack_into("=Q", a, 64, offset)
        return ctypes.create_string_buffer(bytes(a), 128), cpath

    def attach(self, pid: int = -1):
        """Attach every probe of the plan to one process (pid >= 0) or system-wide (pid=-1;
        aggressive, prefer a pid). Returns the number of probes placed."""
        for section, path, offs in self.plan:
            for name, off in offs.items():
                attr, cpath = self._perf_attr(path, off)
                self._keep += [attr, cpath]
                fd = _libc.syscall(SYS_PERF, attr, pid, -1 if pid >= 0 else 0, -1, 0)
                if fd < 0:
                    continue
                _libc.ioctl(fd, PERF_EVENT_IOC_SET_BPF, self.progs[section])
                _libc.ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)
                self.perf_fds.append(fd)
        return len(self.perf_fds)

    def _cmd(self, cmd, attr):
        buf = ctypes.create_string_buffer(attr, max(len(attr), 128))
        return _libc.syscall(321, cmd, buf, len(attr))

    def fd_for_handle(self, handle: int) -> int | None:
        """Socket fd the TLS session object `handle` writes to, if the kernel has bound it yet."""
        key = ctypes.create_string_buffer(struct.pack("=Q", handle), 8)
        val = ctypes.create_string_buffer(4)
        if self._cmd(BPF_MAP_LOOKUP_ELEM, struct.pack("=IIQQQ", self.fd_by_handle, 0,
                                                      ctypes.addressof(key), ctypes.addressof(val), 0)) == 0:
            return struct.unpack("=I", val.raw)[0]
        return None

    def local_port_for(self, pid: int, handle: int) -> int | None:
        """Local port of the socket behind TLS session `handle` in `pid`; None until bound."""
        fd = self.fd_for_handle(handle)
        return None if fd is None else local_port_of(pid, fd)

    def plaintext_for(self, pid: int, consume: bool = True) -> bytes | None:
        """Most recent plaintext written by any thread of `pid` (latest-write view)."""
        best = None
        key = ctypes.create_string_buffer(8)
        nxt = ctypes.create_string_buffer(8)
        have = False
        while True:
            kptr = ctypes.addressof(key) if have else 0
            if self._cmd(BPF_MAP_GET_NEXT_KEY, struct.pack("=IIQQQ", self.writes, 0, kptr, ctypes.addressof(nxt), 0)) != 0:
                break
            key = ctypes.create_string_buffer(nxt.raw, 8)
            have = True
            val = ctypes.create_string_buffer(VSZ)
            if self._cmd(BPF_MAP_LOOKUP_ELEM, struct.pack("=IIQQQ", self.writes, 0, ctypes.addressof(key), ctypes.addressof(val), 0)) == 0:
                epid, tid, handle, length, cap = HDR.unpack(val.raw[:HDR.size])
                if epid == pid:
                    best = val.raw[HDR.size:HDR.size + cap]
                    if consume:
                        self._cmd(BPF_MAP_DELETE_ELEM, struct.pack("=IIQQQ", self.writes, 0, ctypes.addressof(key), 0, 0))
        return best

    def drain(self) -> list[dict]:
        """Pop every captured write from the FIFO, oldest first. Each entry is
        {pid, tid, handle, len, cap, data}; `len` is the full plaintext length of the
        write, `data` its first `cap` bytes, `handle` the TLS session object."""
        out = []
        val = ctypes.create_string_buffer(VSZ)
        while self._cmd(BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                        struct.pack("=IIQQQ", self.writes_q, 0, 0, ctypes.addressof(val), 0)) == 0:
            pid, tid, handle, length, cap = HDR.unpack(val.raw[:HDR.size])
            out.append({"pid": pid, "tid": tid, "handle": handle, "len": length, "cap": cap,
                        "data": val.raw[HDR.size:HDR.size + cap]})
        return out

    def close(self):
        for fd in self.perf_fds:
            os.close(fd)
        for fd in self.maps.values():
            os.close(fd)
        for fd in self.progs.values():
            os.close(fd)
