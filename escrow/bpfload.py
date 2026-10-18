"""Minimal loader for bpf/escrow_connect4.bpf.o using raw bpf(2) (no libbpf).

Handles: ELF parse (pyelftools), legacy `maps` section, ld_imm64 map
relocations, BPF_PROG_LOAD for each program section with its attach type,
attach to a cgroup directory fd, and map access from user space.
"""
from __future__ import annotations
import ctypes
import os
import socket
import struct

BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_MAP_DELETE_ELEM = 0, 1, 2, 3
BPF_PROG_LOAD, BPF_PROG_ATTACH, BPF_PROG_DETACH = 5, 8, 9
BPF_PROG_TYPE_SOCK_OPS, BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 13, 18
BPF_CGROUP_SOCK_OPS, BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_UDP4_SENDMSG = 3, 10, 14
BPF_F_ALLOW_MULTI = 2
BPF_PSEUDO_MAP_FD = 1
SYS_BPF = 321
_libc = ctypes.CDLL(None, use_errno=True)

# section -> (prog type, attach type)
SECTIONS = {
    "cgroup/connect4": (BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT),
    "cgroup/sendmsg4": (BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG),
    "sockops": (BPF_PROG_TYPE_SOCK_OPS, BPF_CGROUP_SOCK_OPS),
}


def _bpf(cmd: int, attr: bytes) -> int:
    buf = ctypes.create_string_buffer(attr, max(len(attr), 128))
    r = _libc.syscall(SYS_BPF, cmd, buf, len(attr))
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


class Map:
    def __init__(self, fd: int, key_size: int, value_size: int):
        self.fd, self.key_size, self.value_size = fd, key_size, value_size

    def _attr(self, key: bytes, value: bytes | None, flags: int = 0):
        k = ctypes.create_string_buffer(key, self.key_size)
        v = ctypes.create_string_buffer(value or b"", self.value_size)
        return struct.pack("=IIQQQ", self.fd, 0, ctypes.addressof(k), ctypes.addressof(v), flags), k, v

    def lookup_raw(self, key: bytes) -> bytes | None:
        attr, k, v = self._attr(key, None)
        try:
            _bpf(BPF_MAP_LOOKUP_ELEM, attr)
        except OSError:
            return None
        return v.raw

    def update_raw(self, key: bytes, value: bytes, flags: int = 0):
        attr, k, v = self._attr(key, value, flags)
        _bpf(BPF_MAP_UPDATE_ELEM, attr)

    def delete_raw(self, key: bytes):
        attr, k, v = self._attr(key, None)
        try:
            _bpf(BPF_MAP_DELETE_ELEM, attr)
        except OSError:
            pass


class EscrowMap(Map):
    FMT = "=IHHQQQ"  # struct escrow_entry

    def lookup(self, cookie: int) -> dict | None:
        raw = self.lookup_raw(struct.pack("=Q", cookie))
        if raw is None:
            return None
        ip, port, _, cg, pt, kt = struct.unpack(self.FMT, raw[:32])
        if ip == 0 and port == 0:
            return None
        return {"orig_ip": socket.inet_ntoa(struct.pack("=I", ip)), "orig_port": port, "cgroup_id": cg,
                "tgid": pt >> 32, "pid": pt & 0xFFFFFFFF, "ktime_ns": kt}

    def delete(self, cookie: int):
        self.delete_raw(struct.pack("=Q", cookie))


class PeerMap(Map):
    """{local ip, local port} of the agent's socket -> cookie (filled by the sockops program)."""

    def cookie(self, ip: str, port: int) -> int | None:
        raw = self.lookup_raw(socket.inet_aton(ip) + struct.pack("=HH", port, 0))
        if raw is None:
            return None
        return struct.unpack("=Q", raw[:8])[0]


class CounterMap(Map):
    NAMES = ("tcp_held", "udp_allowed", "udp_denied", "other_denied")

    def read(self) -> dict:
        out = {}
        for i, n in enumerate(self.NAMES):
            raw = self.lookup_raw(struct.pack("=I", i))
            out[n] = struct.unpack("=Q", raw[:8])[0] if raw else 0
        return out


MAP_CLASSES = {"escrow_map": EscrowMap, "peer_map": PeerMap, "counter_map": CounterMap}


class ConnectHook:
    """Loads every program in the object and attaches them all to a cgroup."""

    def __init__(self, obj_path: str, sections: tuple[str, ...] = tuple(SECTIONS)):
        from elftools.elf.elffile import ELFFile
        self.maps: dict[str, Map] = {}
        self.progs: dict[str, int] = {}
        self.cgroup_fds: list[int] = []
        with open(obj_path, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            maps_sec = elf.get_section_by_name("maps")
            map_fd_by_off: dict[int, int] = {}
            if maps_sec:
                data = maps_sec.data()
                for sym in symtab.iter_symbols():
                    if sym["st_shndx"] == elf.get_section_index("maps"):
                        off = sym["st_value"]
                        typ, ks, vs, me, fl = struct.unpack("=IIIII", data[off:off + 20])
                        fd = _bpf(BPF_MAP_CREATE, struct.pack("=IIIII", typ, ks, vs, me, fl))
                        self.maps[sym.name] = MAP_CLASSES.get(sym.name, Map)(fd, ks, vs)
                        map_fd_by_off[off] = fd
            for sec in sections:
                prog_sec = elf.get_section_by_name(sec)
                if prog_sec is None:
                    continue
                ptype, atype = SECTIONS[sec]
                insns = bytearray(prog_sec.data())
                rel = elf.get_section_by_name(".rel" + sec)
                if rel:
                    for r in rel.iter_relocations():
                        sym = symtab.get_symbol(r["r_info_sym"])
                        fd = map_fd_by_off[sym["st_value"]]
                        off = r["r_offset"]
                        insns[off + 1] = (insns[off + 1] & 0x0F) | (BPF_PSEUDO_MAP_FD << 4)
                        struct.pack_into("=i", insns, off + 4, fd)
                self.progs[sec] = self._load(ptype, atype, bytes(insns))

    @staticmethod
    def _load(ptype: int, atype: int, insns: bytes) -> int:
        lic = ctypes.create_string_buffer(b"GPL")
        ibuf = ctypes.create_string_buffer(insns)
        log = ctypes.create_string_buffer(1 << 16)
        attr = bytearray(struct.pack("=IIQQIIQII", ptype, len(insns) // 8, ctypes.addressof(ibuf),
                                     ctypes.addressof(lic), 1, len(log), ctypes.addressof(log), 0, 0))
        attr += b"\0" * (16 * 8 - len(attr))
        struct.pack_into("=I", attr, 68, atype)          # expected_attach_type
        try:
            return _bpf(BPF_PROG_LOAD, bytes(attr))
        except OSError as exc:
            raise OSError(exc.errno, f"{exc.strerror}; verifier log:\n{log.value.decode(errors='replace')}")

    def configure(self, interceptor_ip: str, interceptor_port: int, dns: tuple[str, int] | None = None):
        dns_ip = socket.inet_aton(dns[0]) if dns else b"\0\0\0\0"
        dns_port = dns[1] if dns else 0
        self.maps["cfg_map"].update_raw(struct.pack("=I", 0),
                                        socket.inet_aton(interceptor_ip) + struct.pack("=HH", interceptor_port, dns_port) + dns_ip + b"\0\0\0\0")

    def attach(self, cgroup_path: str):
        fd = os.open(cgroup_path, os.O_RDONLY | os.O_DIRECTORY)
        self.cgroup_fds.append(fd)
        for sec, pfd in self.progs.items():
            _bpf(BPF_PROG_ATTACH, struct.pack("=IIII", fd, pfd, SECTIONS[sec][1], BPF_F_ALLOW_MULTI))

    def detach(self):
        for fd in self.cgroup_fds:
            for sec, pfd in self.progs.items():
                try:
                    _bpf(BPF_PROG_DETACH, struct.pack("=IIII", fd, pfd, SECTIONS[sec][1], 0))
                except OSError:
                    pass
            os.close(fd)
        self.cgroup_fds = []

    def counters(self) -> dict:
        return self.maps["counter_map"].read() if "counter_map" in self.maps else {}

    def close(self):
        self.detach()
        for m in self.maps.values():
            os.close(m.fd)
        for pfd in self.progs.values():
            os.close(pfd)
