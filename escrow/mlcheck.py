"""A small ML content check for a captured request.

This is a PLACEHOLDER model, deliberately simple and clearly labelled: a logistic-regression
classifier over hand-crafted features of an HTTP request (method, path, headers, body), trained
at import on a fixed synthetic, labelled dataset so the weights are deterministic and the whole
thing is dependency-light and reproducible. It stands in for the production model that would be
keyed on the agent's identity plus the request content; the point of the prototype is the
mechanism (capture plaintext without terminating TLS, score it, gate the connection), not the
model. Swap this module for a real classifier without touching the capture or the gate.

score(request, identity) -> (p_exfil in [0,1], label, reasons)
"""
from __future__ import annotations
import math
import re

import numpy as np

SENSITIVE = re.compile(r"(?i)(card|cvv|ssn|secret|password|passwd|api[_-]?key|token|BEGIN [A-Z ]*PRIVATE KEY|authorization:\s*bearer)")
PAN = re.compile(r"\b(?:\d[ -]?){13,19}\b")                 # card-like number
SENSITIVE_PATH = re.compile(r"(?i)(/transfer|/admin|/export|/dump|/secrets?|/credentials?)")
MUTATING = ("POST", "PUT", "PATCH", "DELETE")

FEATURES = ("sensitive_kw", "pan_like", "sensitive_path", "mutating", "body_len", "body_entropy")


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum() / 8.0)          # normalised to [0,1]


def featurize(request: bytes) -> np.ndarray:
    head, _, body = request.partition(b"\r\n\r\n")
    line = head.split(b"\r\n", 1)[0]
    method = line.split(b" ", 1)[0].decode("latin-1", "replace").upper()
    path = (line.split(b" ")[1].decode("latin-1", "replace") if b" " in line else "")
    text = request.decode("latin-1", "replace")
    return np.array([
        1.0 if SENSITIVE.search(text) else 0.0,
        1.0 if PAN.search(body.decode("latin-1", "replace")) else 0.0,
        1.0 if SENSITIVE_PATH.search(path) else 0.0,
        1.0 if method in MUTATING else 0.0,
        min(len(body) / 512.0, 1.0),
        _entropy(body),
    ], dtype=np.float64)


def _synthetic_dataset():
    """Small labelled set: 0 = benign, 1 = exfil/abuse. Hand-written, deterministic."""
    benign = [
        b"GET /v1/items HTTP/1.1\r\nHost: api\r\n\r\n",
        b"GET /health HTTP/1.1\r\nHost: api\r\n\r\n",
        b"GET /v1/orders/42 HTTP/1.1\r\nHost: api\r\n\r\n",
        b"POST /v1/collect HTTP/1.1\r\nHost: api\r\nContent-Length: 11\r\n\r\nstep-report",
        b"POST /v1/events HTTP/1.1\r\nHost: api\r\nContent-Length: 15\r\n\r\n{\"ok\":true,\"n\":1}",
        b"GET /v1/catalog?page=2 HTTP/1.1\r\nHost: api\r\n\r\n",
        b"PUT /v1/status HTTP/1.1\r\nHost: api\r\nContent-Length: 4\r\n\r\ndone",
        b"GET /metrics HTTP/1.1\r\nHost: api\r\n\r\n",
    ]
    exfil = [
        b"POST /transfer HTTP/1.1\r\nHost: x\r\nContent-Length: 28\r\n\r\nSECRET_CARD=4111111111111111",
        b"POST /export HTTP/1.1\r\nHost: x\r\nContent-Length: 40\r\n\r\nssn=123-45-6789&password=hunter2&dump=all",
        b"POST /v1/upload HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\napi_key=sk-live-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK",
        b"POST /dump HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg",
        b"POST /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer stolen\r\nContent-Length: 20\r\n\r\ncvv=321&card=400000",
        b"POST /v1/notes HTTP/1.1\r\nHost: x\r\nContent-Length: 88\r\n\r\n" + b"A" * 88,  # large opaque blob
    ]
    X = np.array([featurize(r) for r in benign + exfil])
    y = np.array([0] * len(benign) + [1] * len(exfil), dtype=np.float64)
    return X, y


def _train(X, y, epochs=4000, lr=0.3, l2=1e-3, seed=0):
    rng = np.random.default_rng(seed)
    mu, sd = X.mean(0), X.std(0) + 1e-9
    Xs = (X - mu) / sd
    w = rng.normal(0, 0.01, Xs.shape[1])
    b = 0.0
    for _ in range(epochs):
        z = Xs @ w + b
        p = 1.0 / (1.0 + np.exp(-z))
        g = p - y
        w -= lr * (Xs.T @ g / len(y) + l2 * w)
        b -= lr * g.mean()
    return w, b, mu, sd


_X, _y = _synthetic_dataset()
_W, _B, _MU, _SD = _train(_X, _y)


class ContentCheck:
    """Placeholder ML content classifier. threshold on p_exfil decides allow/deny."""

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def score(self, request: bytes, identity: str = "") -> tuple[float, str, list[str]]:
        f = featurize(request)
        z = float(((f - _MU) / _SD) @ _W + _B)
        p = 1.0 / (1.0 + math.exp(-z))
        reasons = [name for name, v in zip(FEATURES, f) if v > 0.5]
        label = "deny" if p >= self.threshold else "allow"
        return p, label, reasons


# module self-check: the synthetic set is separable
if __name__ == "__main__":
    c = ContentCheck()
    for r in [b"GET /v1/items HTTP/1.1\r\nHost: api\r\n\r\n",
              b"POST /transfer HTTP/1.1\r\nHost: x\r\nContent-Length: 28\r\n\r\nSECRET_CARD=4111111111111111"]:
        p, lab, why = c.score(r)
        print(f"{lab:5} p={p:.3f} {why}  <-  {r[:40]!r}")
