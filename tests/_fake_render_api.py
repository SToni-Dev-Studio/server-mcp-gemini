import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

received = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else None

    def do_GET(self):
        received.append(("GET", self.path, self.headers.get("Authorization"), None))
        if self.path.endswith("/env-vars"):
            body = json.dumps(
                [
                    {"envVar": {"key": "MCP_SERVER_PASSWORD", "value": "supersecret"}},
                    {"envVar": {"key": "PCS", "value": "{}"}},
                ]
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        body = self._read_body()
        received.append(("PUT", self.path, self.headers.get("Authorization"), body))
        resp = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_POST(self):
        body = self._read_body()
        received.append(("POST", self.path, self.headers.get("Authorization"), body))
        resp = json.dumps({"id": "dep-123"}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def start(port=18081):
    received.clear()
    server = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
