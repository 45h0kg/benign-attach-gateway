"""Canonical JSON and domain-separated hashing (Spec.md section 2).

Every byte that is signed, hashed into a Merkle tree, or bound into a
transcript goes through `canon()`. The encoding is deliberately narrow so the
Python (E1), Rust (E2) and Go implementations produce identical bytes:

  * values: null, true/false, integers, strings, arrays, objects
  * NO floats -- scores are carried as integer parts-per-million (ppm)
  * strings: printable ASCII 0x20..0x7e plus newline; '"', '\\' and newline
    are escaped as \\", \\\\ and \\n; anything else is rejected, not escaped
  * objects: keys sorted by byte value, no whitespace anywhere

H(tag, data) = SHA-256(tag || 0x00 || data), so a leaf hash can never be
confused with a node hash, a transcript, or a quote digest.
"""
from __future__ import annotations
import hashlib


class CanonError(ValueError):
    pass


def _canon_str(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\n":
            out.append("\\n")
            continue
        if o < 0x20 or o > 0x7E:
            raise CanonError(f"non-printable or non-ASCII character U+{o:04X} in canonical string")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _canon(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise CanonError("floats are not allowed in canonical JSON; use integer ppm")
    if isinstance(v, str):
        return _canon_str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_canon(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonError("object keys must be strings")
        keys = sorted(v, key=lambda k: k.encode())
        return "{" + ",".join(_canon_str(k) + ":" + _canon(v[k]) for k in keys) + "}"
    raise CanonError(f"unsupported type {type(v).__name__}")


def canon(v) -> bytes:
    return _canon(v).encode("ascii")


def H(tag: str, data: bytes) -> bytes:
    return hashlib.sha256(tag.encode("ascii") + b"\x00" + data).digest()


def Hc(tag: str, obj) -> bytes:
    """Hash of the canonical encoding of obj under a domain tag."""
    return H(tag, canon(obj))


PPM = 1_000_000


def to_ppm(x: float) -> int:
    """Convert a probability-like float to integer ppm, clamped to [0, 1e6]."""
    return max(0, min(PPM, int(round(x * PPM))))
