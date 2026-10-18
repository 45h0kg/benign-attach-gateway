"""Verifier: an isolated service that rules on each held connection.

It receives an escrow record authenticated by an interceptor (HMAC, shared key), evaluates a policy
keyed on the workload identity, and returns a verdict signed with its own
key and bound to exactly one socket:

    verdict = {escrow_id, cookie, dst_hash, verdict, reason, issued_ns, expires_ns}

The interceptor releases a held connection only for an ALLOW whose
escrow_id, cookie and dst_hash match the record it sent, whose signature
verifies, that has not expired and has not been consumed before.

Policy (JSON):
  {"workloads": {"<spiffe_id>": {"rules": [{"host": "api.example.com", "port": 443,
                                            "methods": ["GET"], "path_prefix": "/v1/",
                                            "action": "allow"|"deny"|"hold"}, ...],
                                 "budget_per_minute": 60}},
   "default": "deny"}

Rules are tried in order; the first match decides. `hold` parks the decision
until an operator posts to /v1/release or the verifier's hold timeout passes
(then DENY). The destination is matched on SNI, HTTP Host, or IP.

What judges a held call is deliberately not part of this module: the policy
engine is a plain function, `decide(record) -> (action, reason)`, and any
other engine with that signature can be plugged in.
"""
from __future__ import annotations
import fnmatch
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import ed25519
from .audit import AuditLog
from .canon import Hc, canon

RECORD_TAG = b"escrow/record/v0\x00"
VERDICT_TAG = b"escrow/verdict/v0\x00"
ALLOW, DENY = "ALLOW", "DENY"


def sign_record(key: bytes, record: dict) -> str:
    """Records travel interceptor -> verifier over a channel both ends share a
    key for (mounted secret); HMAC-SHA256 is enough and costs microseconds."""
    return hmac.new(key, RECORD_TAG + canon(record), hashlib.sha256).hexdigest()


def verify_record(key: bytes, record: dict, sig_hex: str) -> bool:
    try:
        return hmac.compare_digest(sign_record(key, record), sig_hex)
    except Exception:
        return False


def dst_hash(record: dict) -> str:
    """Binds the verdict to the destination and the parked first bytes."""
    w = record.get("wire", {})
    return Hc("escrow/dst/v0", {"ip": record["dst"]["ip"], "port": record["dst"]["port"],
                                "first_bytes_sha256": w.get("sha256", "")}).hex()


def sign_verdict(sk: bytes, body: dict) -> dict:
    return {"body": body, "sig": ed25519.sign(sk, VERDICT_TAG + canon(body)).hex()}


def verify_verdict(pk: bytes, v: dict) -> bool:
    try:
        return ed25519.verify(pk, VERDICT_TAG + canon(v["body"]), bytes.fromhex(v["sig"]))
    except Exception:
        return False


def _dst_name(record: dict, services: dict | None = None) -> str:
    w = record.get("wire", {})
    svc = (services or {}).get(record["dst"]["ip"])
    return w.get("sni") or w.get("host", "").split(":")[0] or (f"svc:{svc}" if svc else record["dst"]["ip"])


class Policy:
    def __init__(self, doc: dict, services: dict | None = None):
        self.doc = doc
        self.services = services or {}      # ClusterIP -> "namespace/name"

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path) as f:
            return cls(json.load(f))

    def decide(self, record: dict) -> tuple[str, str]:
        wl = record["attribution"].get("workload")
        if not wl:
            return "deny", "unknown_workload"
        spec = self.doc["workloads"].get(wl.get("spiffe_id", ""))
        if spec is None:
            return "deny", "workload_without_policy"
        name, port = _dst_name(record, self.services), record["dst"]["port"]
        svc = self.services.get(record["dst"]["ip"], "")
        w = record.get("wire", {})
        for i, r in enumerate(spec.get("rules", [])):
            if "port" in r and r["port"] != port:
                continue
            if "host" in r and not fnmatch.fnmatchcase(name, r["host"]):
                continue
            if "svc" in r and not fnmatch.fnmatchcase(svc, r["svc"]):
                continue
            if "methods" in r and (w.get("kind") != "http" or w.get("method") not in r["methods"]):
                continue
            if "path_prefix" in r and (w.get("kind") != "http" or not w.get("path", "").startswith(r["path_prefix"])):
                continue
            if r.get("require_l7") and w.get("kind") not in ("http", "tls"):
                continue
            return r["action"], f"rule[{i}]"
        return self.doc.get("default", "deny"), "default"


class Verifier:
    def __init__(self, sk: bytes, policy: Policy, interceptor_keys: list[bytes], audit_path: str,
                 name: str = "verifier", verdict_ttl_ms: int = 2000, hold_timeout_ms: int = 10000,
                 self_addrs: list[tuple[str, int]] | None = None, now_ns=time.time_ns):
        self.sk, self.pk = sk, ed25519.public_key(sk)
        self.policy, self.ikeys = policy, interceptor_keys
        self.audit = AuditLog(audit_path)
        self.name, self.ttl_ms, self.hold_timeout_ms = name, verdict_ttl_ms, hold_timeout_ms
        self.self_addrs = set(self_addrs or [])
        self.now_ns = now_ns
        self._budget: dict[str, deque] = {}
        self._holds: dict[str, dict] = {}
        self._lock = threading.Lock()
        self.stats = {"records": 0, "allow": 0, "deny": 0, "held": 0, "bad_sig": 0}

    # ---------------------------------------------------------------- budget
    def _budget_ok(self, spiffe: str) -> bool:
        spec = self.policy.doc["workloads"].get(spiffe, {})
        lim = spec.get("budget_per_minute")
        if not lim:
            return True
        now = self.now_ns()
        with self._lock:
            q = self._budget.setdefault(spiffe, deque())
            while q and now - q[0] > 60_000_000_000:
                q.popleft()
            if len(q) >= lim:
                return False
            q.append(now)
        return True

    # ---------------------------------------------------------------- core
    def handle(self, envelope: dict) -> tuple[int, dict]:
        rec, sig = envelope.get("record"), envelope.get("sig", "")
        if not isinstance(rec, dict) or not any(verify_record(k, rec, sig) for k in self.ikeys):
            self.stats["bad_sig"] += 1
            return 403, {"error": "record signature invalid"}
        self.stats["records"] += 1
        t0 = self.now_ns()
        if (rec["dst"]["ip"], rec["dst"]["port"]) in self.self_addrs:
            action, reason = "deny", "destination_is_verifier"
        else:
            action, reason = self.policy.decide(rec)
        wl = rec["attribution"].get("workload") or {}
        if action == "allow" and not self._budget_ok(wl.get("spiffe_id", "")):
            action, reason = "deny", "budget_exceeded"
        hold_id = None
        if action == "hold":
            self.stats["held"] += 1
            hold_id = secrets.token_hex(8)
            ev = threading.Event()
            h = {"id": hold_id, "escrow_id": rec["escrow_id"], "workload": wl.get("spiffe_id"),
                 "dst": rec["dst"], "name": _dst_name(rec, self.policy.services), "event": ev, "decision": None, "t": t0}
            with self._lock:
                self._holds[hold_id] = h
            ev.wait(self.hold_timeout_ms / 1000)
            with self._lock:
                self._holds.pop(hold_id, None)
            if h["decision"] == "allow":
                action, reason = "allow", f"released:{hold_id}"
            else:
                action, reason = "deny", "hold_timeout" if h["decision"] is None else f"refused:{hold_id}"
        verdict = ALLOW if action == "allow" else DENY
        self.stats["allow" if verdict == ALLOW else "deny"] += 1
        issued = self.now_ns()
        body = {"schema": "escrow/verdict/v0", "verifier": self.name, "escrow_id": rec["escrow_id"],
                "cookie": rec["attribution"]["cookie"], "dst_hash": dst_hash(rec), "verdict": verdict,
                "reason": reason, "issued_ns": issued, "expires_ns": issued + self.ttl_ms * 1_000_000,
                "nonce": secrets.token_hex(8)}
        self.audit.append({"escrow_id": rec["escrow_id"], "workload": wl.get("spiffe_id"),
                           "cookie": rec["attribution"]["cookie"], "pid": rec["attribution"].get("pid"),
                           "cgroup": rec["attribution"].get("cgroup"), "exe_sha256": rec["attribution"].get("exe_sha256"),
                           "dst": rec["dst"], "name": _dst_name(rec, self.policy.services), "verdict": verdict, "reason": reason,
                           "decide_us": (issued - t0) // 1000, "hold_id": hold_id})
        return 200, sign_verdict(self.sk, body)

    def release(self, hold_id: str, decision: str) -> tuple[int, dict]:
        with self._lock:
            h = self._holds.get(hold_id)
            if h is None:
                return 404, {"error": "no such hold (expired, already decided, or never existed)"}
            h["decision"] = decision
            h["event"].set()
        return 200, {"ok": True, "hold_id": hold_id, "decision": decision}

    def pending(self) -> list[dict]:
        with self._lock:
            return [{k: v for k, v in h.items() if k != "event"} for h in self._holds.values()]


def serve(verifier: Verifier, host: str, port: int) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _json(self, code: int, obj: dict):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/v1/pending":
                return self._json(200, {"pending": verifier.pending()})
            if self.path == "/v1/pubkey":
                return self._json(200, {"pk": verifier.pk.hex(), "name": verifier.name})
            if self.path == "/v1/stats":
                return self._json(200, verifier.stats)
            self._json(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json(400, {"error": "bad json"})
            if self.path == "/v1/escrow":
                code, obj = verifier.handle(body)
            elif self.path == "/v1/release":
                code, obj = verifier.release(body.get("hold_id", ""), body.get("decision", "deny"))
            else:
                code, obj = 404, {"error": "not found"}
            try:
                self._json(code, obj)
            except (BrokenPipeError, ConnectionResetError):
                pass  # interceptor gave up at its deadline; the verdict is dropped

    srv = ThreadingHTTPServer((host, port), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
