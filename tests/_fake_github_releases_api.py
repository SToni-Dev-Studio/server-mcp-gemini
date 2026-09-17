import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

requests_received = []


def make_handler(tag_name: str, deb_content: bytes, include_checksum: bool = True, include_deb_asset: bool = True):
    checksum = hashlib.sha256(deb_content).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            requests_received.append(self.path)
            if self.path.endswith("/releases/latest"):
                assets = []
                if include_deb_asset:
                    assets.append({
                        "name": "mcp-hub-tools_1.2.3_all.deb",
                        "browser_download_url": f"http://127.0.0.1:{self.server.server_address[1]}/download/deb",
                    })
                if include_checksum:
                    assets.append({
                        "name": "mcp-hub-tools_1.2.3_all.deb.sha256",
                        "browser_download_url": f"http://127.0.0.1:{self.server.server_address[1]}/download/checksum",
                    })
                body = json.dumps({"tag_name": tag_name, "assets": assets}).encode()
                self._send(200, body, "application/json")
            elif self.path == "/download/deb":
                self._send(200, deb_content, "application/octet-stream")
            elif self.path == "/download/checksum":
                self._send(200, f"{checksum}  mcp-hub-tools_1.2.3_all.deb\n".encode(), "text/plain")
            else:
                self._send(404, b"not found", "text/plain")

        def _send(self, code, body, content_type):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def start(tag_name="v1.2.3", deb_content=b"fake deb content", include_checksum=True, include_deb_asset=True, port=18092):
    requests_received.clear()
    handler = make_handler(tag_name, deb_content, include_checksum, include_deb_asset)
    server = HTTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
