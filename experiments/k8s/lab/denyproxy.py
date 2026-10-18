"""A stand-in egress proxy that denies everything (the strict case of an HTTP_PROXY/sidecar
egress control). An agent that honours HTTP_PROXY is blocked by it; a direct socket is not."""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3128
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): sys.stdout.write("denyproxy: refused %s %s\n" % (self.command, self.path)); sys.stdout.flush()
    def _deny(self):
        self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
    do_GET = do_POST = do_CONNECT = _deny
ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
