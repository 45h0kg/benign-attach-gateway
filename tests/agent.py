"""A stand-in for the agent's tool process: connect, send, receive, report.

It knows nothing about the hold point. Whatever intercepts it does so in the
kernel. Prints one JSON line.
Usage: agent.py '{"dst": [ip, port], "send": hex, "recv": n, "timeout": s, "child": bool}'
"""
import json
import os
import socket
import subprocess
import sys
import time


def main():
    job = json.loads(sys.argv[1])
    if job.get("child"):
        # bypass attempt: do the connect from a child process
        job2 = dict(job, child=False)
        p = subprocess.run([sys.executable, __file__, json.dumps(job2)], capture_output=True, text=True)
        sys.stdout.write(p.stdout)
        return
    if job.get("repeat"):
        outs = [one(dict(job, repeat=0)) for _ in range(job["repeat"])]
        print(json.dumps({"pid": os.getpid(), "runs": outs}))
        return
    print(json.dumps(one(job)))


def udp(job):
    out = {"pid": os.getpid(), "results": {}}
    for name, dst in job["udp"].items():
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01", tuple(dst))
            out["results"][name] = "sent"
        except OSError as exc:
            out["results"][name] = f"{type(exc).__name__}: {exc}"
        finally:
            u.close()
    return out


def one(job):
    if job.get("udp"):
        return udp(job)
    out = {"pid": os.getpid(), "uid": os.getuid(), "connected": False, "sent": 0, "recv": "", "error": "", "t_connect_us": 0}
    s = socket.socket()
    s.settimeout(job.get("timeout", 5))
    t0 = time.perf_counter_ns()
    try:
        s.connect(tuple(job["dst"]))
        out["connected"] = True
        out["t_connect_us"] = (time.perf_counter_ns() - t0) // 1000
        data = bytes.fromhex(job.get("send", ""))
        if data:
            out["sent"] = s.send(data)
        if job.get("recv"):
            buf = b""
            while len(buf) < job["recv"]:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if not job.get("recv_all"):
                    break
            out["recv"] = buf.hex()
        out["t_total_us"] = (time.perf_counter_ns() - t0) // 1000
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["t_total_us"] = (time.perf_counter_ns() - t0) // 1000
    finally:
        s.close()
    return out


if __name__ == "__main__":
    main()
