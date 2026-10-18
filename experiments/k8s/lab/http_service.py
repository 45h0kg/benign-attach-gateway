"""Lab destination service. GET /data returns a record; POST /collect and /upload store bodies;
GET /log lists what was received. `--name` tags the responses. Logs every connection."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = sys.argv[1] if len(sys.argv) > 1 else "service"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
RECEIVED = []


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"{NAME} {self.client_address[0]} {fmt % args}\n"); sys.stdout.flush()

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/data"):
            return self._send(200, {"service": NAME, "record": {"item": "A-1042", "value": 17}, "t": time.time()})
        if self.path == "/log":
            return self._send(200, {"service": NAME, "received": RECEIVED})
        if self.path == "/reset":
            RECEIVED.clear(); return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        RECEIVED.append({"path": self.path, "from": self.client_address[0], "bytes": len(body), "t": time.time(),
                         "body": body[:200].decode("utf-8", "replace")})
        self._send(200, {"service": NAME, "stored": len(body), "path": self.path})


srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
srv.daemon_threads = True
print(f"{NAME} listening on {PORT}", flush=True)
srv.serve_forever()
