"""Append-only hash chain of receipts: entry_hash = H(tag, prev || canon(entry))."""
from __future__ import annotations
import json
import os

from .canon import Hc


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str, tag: str = "escrow/audit/v0"):
        self.path, self.tag = path, tag
        self._prev = self.GENESIS
        if os.path.exists(path) and os.path.getsize(path) > 0:
            last = None
            with open(path) as f:
                for line in f:
                    if line.strip():
                        last = line
            if last:
                self._prev = json.loads(last)["entry_hash"]
        else:
            open(path, "w").close()

    def _hash(self, prev: str, rec: dict) -> str:
        return Hc(self.tag, {"prev": prev, "entry": rec}).hex()

    def append(self, record: dict) -> str:
        rec = dict(record, prev_hash=self._prev)
        h = self._hash(self._prev, rec)
        with open(self.path, "a") as f:
            f.write(json.dumps(dict(rec, entry_hash=h), sort_keys=True) + "\n")
        self._prev = h
        return h

    @classmethod
    def verify_chain(cls, path: str, tag: str = "escrow/audit/v0") -> tuple[bool, int]:
        self = cls.__new__(cls)
        self.tag = tag
        prev, n = cls.GENESIS, 0
        with open(path) as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                claimed = rec.pop("entry_hash", None)
                if rec.get("prev_hash") != prev or self._hash(prev, rec) != claimed:
                    return False, n
                prev, n = claimed, n + 1
        return True, n
