#!/usr/bin/env python3
"""Build the lab image `escrow/lab:dev` from the host's own Python, without a registry.

Where this is used no container registry is reachable, so the image is a rootfs assembled from
host files (python3, its stdlib, pyelftools + cryptography, curl, iptables, sh, coreutils) plus the
escrow package and the compiled eBPF object, written as a docker-format image tarball and imported
with `k3s ctr images import`. On a normal network use the Dockerfile instead.

Usage: python3 experiments/k8s/build_image.py out.tar   (then: k3s ctr images import out.tar)
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable
BINS = [PY, "/bin/sh", "/bin/dash", "/bin/bash", "/usr/bin/curl", "/usr/sbin/iptables", "/usr/sbin/xtables-nft-multi",
        "/usr/bin/env", "/bin/cat", "/bin/ls", "/bin/sleep", "/bin/echo", "/bin/mkdir", "/bin/chmod", "/usr/bin/id",
        "/usr/bin/nc", "/bin/grep", "/usr/bin/tee", "/usr/bin/head", "/usr/bin/tail", "/usr/bin/wc", "/usr/bin/getent",
        "/usr/bin/dig", "/usr/bin/nslookup"]
DIRS = ["/usr/lib/python3.13", "/usr/local/lib/python3.13/dist-packages/elftools",
        "/usr/local/lib/python3.13/dist-packages/cryptography", "/etc/ssl/certs", "/usr/lib/x86_64-linux-gnu/xtables"]
SKIP_PY = ("test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip", "__pycache__", "lib2to3")


def libs_of(path: str) -> set[str]:
    out = set()
    try:
        r = subprocess.run(["ldd", path], capture_output=True, text=True)
    except Exception:
        return out
    for ln in r.stdout.splitlines():
        for tok in ln.split():
            if tok.startswith("/") and os.path.exists(tok):
                out.add(os.path.realpath(tok))
                out.add(tok)
    return out


def main(out_path: str):
    files: set[str] = set()
    for b in BINS:
        if os.path.exists(b):
            files.add(b); files.add(os.path.realpath(b)); files |= libs_of(os.path.realpath(b))
    for d in DIRS:
        for dp, dn, fn in os.walk(d):
            dn[:] = [x for x in dn if x not in SKIP_PY]
            for f in fn:
                p = os.path.join(dp, f)
                files.add(p)
                if p.endswith(".so"):
                    files |= libs_of(p)
    # python's own .so modules and their libs
    for lib in ("libssl.so.3", "libcrypto.so.3", "libffi.so.8", "libbz2.so.1.0", "liblzma.so.5", "libsqlite3.so.0",
                "libreadline.so.8", "libnss_dns.so.2", "libnss_files.so.2", "libresolv.so.2", "libgcc_s.so.1",
                "libstdc++.so.6", "libmnl.so.0", "libnftnl.so.11", "libnfnetlink.so.0", "libnetfilter_conntrack.so.3"):
        for base in ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"):
            p = os.path.join(base, lib)
            if os.path.exists(p):
                files.add(p); files.add(os.path.realpath(p)); files |= libs_of(os.path.realpath(p))
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as tf:
        added = set()
        def add(path, arc):
            if arc in added:
                return
            added.add(arc)
            tf.add(path, arcname=arc, recursive=False)
        for p in sorted(files):
            if os.path.islink(p):
                tgt = os.path.realpath(p)          # flatten symlink chains: copy the target to the link's path
                if os.path.isfile(tgt):
                    add(tgt, p.lstrip("/"))
                    add(tgt, tgt.lstrip("/"))
            elif os.path.isfile(p):
                add(p, p.lstrip("/"))
        # escrow package + eBPF object + lab scripts
        for dp, dn, fn in os.walk(os.path.join(ROOT, "escrow")):
            dn[:] = [x for x in dn if x != "__pycache__"]
            for f in fn:
                add(os.path.join(dp, f), "opt/escrow/escrow/" + f)
        add(os.path.join(ROOT, "bpf", "escrow_connect4.bpf.o"), "opt/escrow/escrow_connect4.bpf.o")
        for f in os.listdir(os.path.join(ROOT, "experiments", "k8s", "lab")):
            add(os.path.join(ROOT, "experiments", "k8s", "lab", f), "opt/escrow/lab/" + f)
        for d in ("tmp", "var/lib/escrow", "etc", "root", "proc", "sys", "dev", "run"):
            ti = tarfile.TarInfo(d); ti.type = tarfile.DIRTYPE; ti.mode = 0o755; tf.addfile(ti)
        for name, content in (("etc/passwd", "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000::/tmp:/bin/sh\nescrow:x:1337:1337::/tmp:/bin/sh\n"),
                              ("etc/group", "root:x:0:\nagent:x:1000:\nescrow:x:1337:\n"),
                              ("etc/nsswitch.conf", "hosts: files dns\n")):
            b = content.encode(); ti = tarfile.TarInfo(name); ti.size = len(b); tf.addfile(ti, io.BytesIO(b))
    raw = layer.getvalue()
    diff_id = "sha256:" + hashlib.sha256(raw).hexdigest()
    config = {"architecture": "amd64", "os": "linux", "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PYTHONPATH=/opt/escrow",
                                 "PYTHONDONTWRITEBYTECODE=1"], "Cmd": ["/bin/sh"], "WorkingDir": "/opt/escrow"},
              "rootfs": {"type": "layers", "diff_ids": [diff_id]}}
    cfg = json.dumps(config).encode()
    cfg_name = hashlib.sha256(cfg).hexdigest() + ".json"
    manifest = [{"Config": cfg_name, "RepoTags": ["escrow/lab:dev"], "Layers": ["layer.tar"]}]
    with tarfile.open(out_path, "w") as tf:
        for name, data in ((cfg_name, cfg), ("layer.tar", raw), ("manifest.json", json.dumps(manifest).encode())):
            ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
    print(f"wrote {out_path}: {len(files)} host files, layer {len(raw)/1e6:.0f} MB")


if __name__ == "__main__":
    main(sys.argv[1])
