"""Pure-Python Ed25519 (RFC 8032), standard library only.

Used by the E1 engine for governance signatures, mock attestation quotes,
gateway receipts and source-prover commitments. Interoperates with Go's
crypto/ed25519 and Rust's ed25519-dalek (checked against RFC 8032 test
vector 1 in tests_crypto.py).

Educational implementation: not constant-time, not hardened against side
channels. Fine for verification of public data in a research prototype; do
not use it to hold production secrets.
"""
from __future__ import annotations
import hashlib

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p
_SQRT_M1 = pow(2, (p - 1) // 4, p)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, Hh = B - A, D - C, D + C, B + A
    return (E * F % p, G * Hh % p, F * G % p, E * Hh % p)


_IDENT = (0, 1, 1, 0)


def _mul(s: int, P):
    Q = _IDENT
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * _inv(5) % p
_gx = _recover_x(_gy, 0)
_G = (_gx, _gy, 1, _gx * _gy % p)

# Fixed-base table: _GTAB[i] = 2^i * G, so s*G needs only additions.
_GTAB = []
_t = _G
for _i in range(256):
    _GTAB.append(_t)
    _t = _add(_t, _t)


def _mul_base(s: int):
    Q = _IDENT
    i = 0
    while s > 0:
        if s & 1:
            Q = _add(Q, _GTAB[i])
        s >>= 1
        i += 1
    return Q


def _compress(P) -> bytes:
    zinv = _inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _equal(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _h_modq(b: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % q


def _expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("Ed25519 secret key must be 32 bytes")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    a, _ = _expand(secret)
    return _compress(_mul_base(a))


def sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(secret)
    A = _compress(_mul_base(a))
    r = _h_modq(prefix + msg)
    Rs = _compress(_mul_base(r))
    h = _h_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    if A is None:
        return False
    Rs = sig[:32]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= q:
        return False
    h = _h_modq(Rs + public + msg)
    return _equal(_mul_base(s), _add(R, _mul(h, A)))


def keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """(secret, public) from a 32-byte seed."""
    return seed, public_key(seed)


# ---------------------------------------------------------------- optional native path
# If the `cryptography` package is present, use it; the wire format (32-byte seed,
# 32-byte public key, 64-byte signature) is identical, so the two interoperate.
try:  # pragma: no cover
    if __import__('os').environ.get('ESCROW_PUREPY'):
        raise ImportError
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ced
    from cryptography.exceptions import InvalidSignature as _IS

    _sign_py, _verify_py, _pk_py = sign, verify, public_key

    def sign(secret: bytes, msg: bytes) -> bytes:  # noqa: F811
        return _ced.Ed25519PrivateKey.from_private_bytes(secret).sign(msg)

    def verify(public: bytes, msg: bytes, sig: bytes) -> bool:  # noqa: F811
        try:
            _ced.Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except (_IS, ValueError):
            return False

    def public_key(secret: bytes) -> bytes:  # noqa: F811
        return _ced.Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()

    NATIVE = True
except ImportError:
    NATIVE = False
