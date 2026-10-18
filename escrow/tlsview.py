"""TLS-plaintext view: read the plaintext an agent writes, without terminating TLS.

An eBPF uprobe on the agent's TLS library captures the plaintext buffer at the library
boundary -- before it is encrypted -- into a kernel map keyed by pid_tgid. Three runtimes
are covered by two kernel programs:

  * OpenSSL shared library  -> `SSL_write` / `SSL_write_ex` in libssl.so       (RUNTIME_OPENSSL)
  * OpenSSL/BoringSSL static -> the same symbols inside the agent's own binary  (RUNTIME_STATIC)
  * Go crypto/tls            -> `crypto/tls.(*Conn).Write` in the Go binary    (RUNTIME_GO)

The TLS connection itself is untouched: it still completes end-to-end to the real destination
with the real certificate; the enforcer never holds a key and never decrypts the wire. The TLS connection itself is untouched: it still
completes end-to-end to the real destination with the real certificate; the enforcer
never holds a key and never decrypts the wire.

This is the capture half. Enforcement (holding the first application-data record of the
connection until a content verdict) is in the content gate; capture here only observes the
plaintext and makes it available, correlated to the writing process.

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
BPF_PROG_TYPE_KPROBE = 2
PERF_EVENT_IOC_ENABLE = 0x2400
PERF_EVENT_IOC_SET_BPF = 0x40042408
MAXDATA = 256
VSZ = 16 + MAXDATA

# OpenSSL 3 write functions; arg layout is (ssl, buf=rsi, num=rdx[, *written]) for both.
DEFAULT_LIB = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
WRITE_SYMS = ("SSL_write", "SSL_write_ex")
# Go crypto/tls: func (c *Conn) Write(b []byte); register ABI b.ptr=rbx, b.len=rcx.
GO_WRITE_SYMS = ("crypto/tls.(*Conn).Write",)

# runtime name -> (bpf program section, default symbols). The ELF that holds the symbol is
# libssl.so for OPENSSL and the agent's own executable for STATIC and GO.
RUNTIME_OPENSSL, RUNTIME_STATIC, RUNTIME_GO = "openssl", "static", "go"
RUNTIMES = {
    RUNTIME_OPENSSL: ("uprobe/SSL_write", WRITE_SYMS),
    RUNTIME_STATIC: ("uprobe/SSL_write", WRITE_SYMS),
    RUNTIME_GO: ("uprobe/go_tls_write", GO_WRITE_SYMS),
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
                if sym.name in want and sym["st_value"]:
                    v = sym["st_value"]
                    for seg in loads:
                        pv, po, msz = seg["p_vaddr"], seg["p_offset"], seg["p_memsz"]
                        if pv <= v < pv + msz:
                            out[sym.name] = v - pv + po
                            break
    return out


class TlsPlaintextProbe:
    """Loads the write-side uprobe for one TLS runtime and reads captured plaintext.

    `lib` is the ELF that holds the write function: libssl.so for shared OpenSSL, or the
    agent's own executable for a static OpenSSL/BoringSSL build or a Go binary.
    """

    def __init__(self, obj_path: str, lib: str = DEFAULT_LIB, syms=None, runtime: str = RUNTIME_OPENSSL):
        section, default_syms = RUNTIMES[runtime]
        self.runtime = runtime
        self.section = section
        self.lib = lib.encode() + b"\x00"
        self.offsets = symbol_file_offsets(lib, syms or default_syms)
        if not self.offsets:
            raise LookupError(f"no TLS write symbol for runtime {runtime!r} in {lib}")
        self.prog, self.maps = self._load(obj_path)
        self.writes = self.maps["writes"]
        self.perf_fds: list[int] = []
        self._keep: list = []

    def _load(self, obj):
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
            sec = elf.get_section_by_name(self.section)
            insns = bytearray(sec.data())
            rel = elf.get_section_by_name(".rel" + self.section)
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
                prog = _bpf(BPF_PROG_LOAD, bytes(attr))
            except OSError as e:
                raise OSError(e.errno, f"{e.strerror}; verifier log:\n{log.value.decode(errors='replace')}")
            return prog, {k: v[0] for k, v in fds.items()}

    @classmethod
    def for_executable(cls, obj_path: str, exe: str, libssl: str = DEFAULT_LIB):
        """Probe the right runtime for an agent executable (Go / static / shared OpenSSL)."""
        rt = detect_runtime(exe)
        return cls(obj_path, lib=exe if rt != RUNTIME_OPENSSL else libssl, runtime=rt)

    def _perf_attr(self, offset: int):
        a = bytearray(128)
        struct.pack_into("=II", a, 0, _uprobe_pmu_type(), 128)
        struct.pack_into("=Q", a, 8, 0)
        path = ctypes.create_string_buffer(self.lib)
        struct.pack_into("=Q", a, 56, ctypes.addressof(path))
        struct.pack_into("=Q", a, 64, offset)
        return ctypes.create_string_buffer(bytes(a), 128), path

    def attach(self, pid: int = -1):
        """Attach to one process (pid >= 0) or system-wide (pid=-1; aggressive, prefer a pid)."""
        for name, off in self.offsets.items():
            attr, path = self._perf_attr(off)
            self._keep += [attr, path]
            fd = _libc.syscall(SYS_PERF, attr, pid, -1 if pid >= 0 else 0, -1, 0)
            if fd < 0:
                continue
            _libc.ioctl(fd, PERF_EVENT_IOC_SET_BPF, self.prog)
            _libc.ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)
            self.perf_fds.append(fd)
        return len(self.perf_fds)

    def _cmd(self, cmd, attr):
        buf = ctypes.create_string_buffer(attr, max(len(attr), 128))
        return _libc.syscall(321, cmd, buf, len(attr))

    def plaintext_for(self, pid: int, consume: bool = True) -> bytes | None:
        """Most recent plaintext written by any thread of `pid` (demo correlation by pid).
        In production the correlation key also includes the socket/fd; see docs."""
        best = None
        key = ctypes.create_string_buffer(8)
        nxt = ctypes.create_string_buffer(8)
        have = False
        keys = []
        while True:
            kptr = ctypes.addressof(key) if have else 0
            if self._cmd(BPF_MAP_GET_NEXT_KEY, struct.pack("=IIQQQ", self.writes, 0, kptr, ctypes.addressof(nxt), 0)) != 0:
                break
            key = ctypes.create_string_buffer(nxt.raw, 8)
            have = True
            keys.append(nxt.raw)
            val = ctypes.create_string_buffer(VSZ)
            if self._cmd(BPF_MAP_LOOKUP_ELEM, struct.pack("=IIQQQ", self.writes, 0, ctypes.addressof(key), ctypes.addressof(val), 0)) == 0:
                epid, tid, length, cap = struct.unpack("=IIII", val.raw[:16])
                if epid == pid:
                    best = val.raw[16:16 + cap]
                    if consume:
                        self._cmd(BPF_MAP_DELETE_ELEM, struct.pack("=IIQQQ", self.writes, 0, ctypes.addressof(key), 0, 0))
        return best

    def close(self):
        for fd in self.perf_fds:
            os.close(fd)
        os.close(self.writes)
        os.close(self.maps.get("scratch", -1)) if self.maps.get("scratch", -1) >= 0 else None
        os.close(self.prog)
