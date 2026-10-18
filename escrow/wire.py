"""Parse the first bytes an agent writes on a held connection.

Nothing here is forwarded; the bytes are parked with the connection and only
released after an ALLOW verdict. The parser recognises:

  HTTP/1.x request line + headers  -> method, target, host, path
  TLS ClientHello                  -> SNI, offered version
  anything else                    -> opaque (length + hash only)
"""
from __future__ import annotations
import hashlib
import struct

MAX_PEEK = 4096


def parse(buf: bytes) -> dict:
    out = {"kind": "opaque", "bytes": len(buf), "sha256": hashlib.sha256(buf).hexdigest()}
    if not buf:
        out["kind"] = "empty"
        return out
    if buf[0] == 0x16 and len(buf) >= 5 and buf[1] == 3:
        tls = _client_hello(buf)
        if tls:
            out.update(tls)
            out["kind"] = "tls"
            return out
    http = _http(buf)
    if http:
        out.update(http)
        out["kind"] = "http"
    return out


def _http(buf: bytes) -> dict | None:
    head, sep, _ = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        method, target, version = lines[0].split(b" ", 2)
    except ValueError:
        return None
    if not version.startswith(b"HTTP/") or not method.isalpha():
        return None
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        if k:
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    host = headers.get("host", "")
    path = target.decode("latin-1")
    if method == b"CONNECT":
        host, path = path, ""
    elif path.startswith("http://") or path.startswith("https://"):
        rest = path.split("://", 1)[1]
        host, _, p = rest.partition("/")
        path = "/" + p
    return {"method": method.decode(), "host": host, "path": path,
            "headers_complete": bool(sep), "header_names": sorted(headers)}


def _client_hello(buf: bytes) -> dict | None:
    try:
        rec_len = struct.unpack("!H", buf[3:5])[0]
        body = buf[5:5 + rec_len]
        if not body or body[0] != 1:
            return None
        p = 4  # handshake header
        version = struct.unpack("!H", body[p:p + 2])[0]
        p += 2 + 32  # version + random
        sid_len = body[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", body[p:p + 2])[0]
        p += 2 + cs_len
        cm_len = body[p]
        p += 1 + cm_len
        if p + 2 > len(body):
            return {"sni": "", "tls_version": version, "complete": False}
        ext_len = struct.unpack("!H", body[p:p + 2])[0]
        p += 2
        end = min(p + ext_len, len(body))
        sni = ""
        while p + 4 <= end:
            et, el = struct.unpack("!HH", body[p:p + 4])
            p += 4
            if et == 0 and el >= 5:
                lst = body[p + 2:p + el]
                if lst and lst[0] == 0:
                    nl = struct.unpack("!H", lst[1:3])[0]
                    sni = lst[3:3 + nl].decode("ascii", "replace").lower()
            p += el
        return {"sni": sni, "tls_version": version, "complete": p >= end}
    except (struct.error, IndexError):
        return None


def client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 ClientHello carrying `sni` (for tests)."""
    name = sni.encode("idna")
    sni_ext = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack("!HH", 0, len(sni_ext)) + sni_ext
    body = struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
