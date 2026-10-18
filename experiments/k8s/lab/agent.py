"""A plain agent workload for the cluster experiment.

It does what an unsupervised tool-using agent does: a sequence of outbound HTTP
calls to whatever hosts its task names, using an ordinary HTTP client, with no
knowledge that anything mediates its egress. Some calls go to an internal API it
is meant to reach; others go to an external host it is not. The agent also spawns
a child process that makes its own call, to show that egress control must cover
children too.

It uses only the standard library and respects HTTP_PROXY if set (so the same
binary can be run behind a sidecar proxy for the comparison), but it does not
depend on it. One JSON line per call to stdout; a summary line at the end.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

AGENT = os.environ.get("AGENT_NAME", "agent")


def call(method: str, url: str, body: bytes | None = None, timeout: float = 4.0) -> dict:
    t0 = time.perf_counter_ns()
    rec = {"agent": AGENT, "method": method, "url": url}
    try:
        req = urllib.request.Request(url, data=body, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:   # honours HTTP_PROXY env if present
            data = r.read(4096)
        rec.update(ok=True, status=r.status, bytes=len(data))
    except urllib.error.HTTPError as e:
        rec.update(ok=True, status=e.code)
    except Exception as e:
        rec.update(ok=False, error=f"{type(e).__name__}: {e}")
    rec["ms"] = (time.perf_counter_ns() - t0) / 1e6
    print(json.dumps(rec), flush=True)
    return rec


def raw_connect(host: str, port: int, send: bytes, timeout: float = 4.0) -> dict:
    """A direct socket to host:port, ignoring HTTP_PROXY entirely. This is what a native
    tool, a statically linked client, or deliberate exfil does: no proxy env is consulted."""
    t0 = time.perf_counter_ns()
    rec = {"agent": AGENT, "raw": True, "host": host, "port": port}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if send:
            s.sendall(send)
        s.recv(256)
        s.close()
        rec["ok"] = True
    except Exception as e:
        rec.update(ok=False, error=f"{type(e).__name__}: {e}")
    rec["ms"] = (time.perf_counter_ns() - t0) / 1e6
    print(json.dumps(rec), flush=True)
    return rec


def main():
    task = json.loads(os.environ.get("TASK", "{}"))
    if task.get("load"):
        url, n = task["load"]["url"], task["load"]["n"]
        ms = []
        t0 = time.perf_counter()
        for _ in range(n):
            r = call("GET", url)
            if r.get("ok"):
                ms.append(r["ms"])
        wall = time.perf_counter() - t0
        ms.sort()
        pct = lambda p: ms[min(len(ms) - 1, int(p / 100 * (len(ms) - 1)))] if ms else 0
        print(json.dumps({"agent": AGENT, "load_summary": True, "n": n, "reached": len(ms), "wall_s": round(wall, 2),
                          "conn_per_s": round(len(ms) / wall, 1) if wall else 0,
                          "ms_p50": round(pct(50), 2), "ms_p95": round(pct(95), 2)}), flush=True)
        return
    results = []
    for step in task.get("steps", []):
        if step.get("raw"):
            results.append(raw_connect(step["host"], step["port"], step.get("send", "").encode()))
        else:
            results.append(call(step["method"], step["url"], step.get("body", "").encode() or None))
    # a child process that makes its own outbound call
    if task.get("child_url"):
        p = subprocess.run([sys.executable, "-c",
                            f"import urllib.request,json;\n"
                            f"try:\n r=urllib.request.urlopen({task['child_url']!r},timeout=4);print(json.dumps({{'child':True,'ok':True,'status':r.status}}))\n"
                            f"except Exception as e:print(json.dumps({{'child':True,'ok':False,'error':f'{{type(e).__name__}}: {{e}}'}}))"],
                           capture_output=True, text=True)
        line = p.stdout.strip() or json.dumps({"child": True, "ok": False, "error": p.stderr.strip()[-120:]})
        print(line, flush=True)
        results.append(json.loads(line))
    reached = sum(1 for r in results if r.get("ok") and r.get("status", 0) < 500)
    print(json.dumps({"agent": AGENT, "summary": True, "calls": len(results), "reached": reached}), flush=True)


if __name__ == "__main__":
    main()
