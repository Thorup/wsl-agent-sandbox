import base64
import http.server
import importlib.util
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "linux" / "credential-proxy.py"
spec = importlib.util.spec_from_file_location("credential_proxy", MODULE_PATH)
credential_proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credential_proxy)


class CredentialProxyTests(unittest.TestCase):
    def test_corrupt_config_fails_closed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("{corrupt")
            cfg_path = f.name
        try:
            self.assertEqual(credential_proxy.load_routes(cfg_path), {})
        finally:
            os.unlink(cfg_path)

    def test_placeholder_validation_injection_redirect_block_streaming_head_options_and_chunked(self):
        received = {}
        stream_chunk1_seen = threading.Event()

        class UpstreamHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                if self.path.endswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "https://attacker.example/steal")
                    self.end_headers()
                    return
                if self.path.endswith("/stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"data: chunk1\n\n")
                    self.wfile.flush()
                    if stream_chunk1_seen.wait(timeout=3.0):
                        self.wfile.write(b"data: chunk2\n\n")
                        self.wfile.flush()
                    return
                received["headers"] = {k.lower(): v for k, v in self.headers.items()}
                received["path"] = self.path
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                received["post_body"] = self.rfile.read(length) if length else b""
                received["post_headers"] = {k.lower(): v for k, v in self.headers.items()}
                self.send_response(200)
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"POST")

            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Length", "123")
                self.end_headers()

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Allow", "GET, POST, OPTIONS")
                self.end_headers()

            def log_message(self, *args):
                pass

        up_srv = http.server.HTTPServer(("127.0.0.1", 0), UpstreamHandler)
        up_port = up_srv.server_address[1]
        up_thread = threading.Thread(target=up_srv.serve_forever, daemon=True)
        up_thread.start()

        cfg_data = {
            "routes": {
                "claude": {
                    "upstreamBaseUrl": f"http://127.0.0.1:{up_port}/api",
                    "expectedToken": "ph-claude-secret-123",
                    "injectHeaders": {"x-api-key": "real-anthropic-key"},
                },
                "jira": {
                    "upstreamBaseUrl": f"http://127.0.0.1:{up_port}/jira",
                    "expectedToken": "ph-jira-secret-456",
                    "injectHeaders": {"Authorization": "Basic " + base64.b64encode(b"user@example.com:real-jira-tok").decode()},
                },
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg_data, f)
            cfg_path = f.name

        orig_load = credential_proxy.load_routes
        orig_insecure = credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST
        credential_proxy.load_routes = lambda p=cfg_path: orig_load(p)
        credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = True

        proxy_srv = credential_proxy.ThreadingHTTPServer(("127.0.0.1", 0), credential_proxy.CredentialProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        proxy_thread = threading.Thread(target=proxy_srv.serve_forever, daemon=True)
        proxy_thread.start()

        try:
            def raw_req(payload):
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
                    s.sendall(payload)
                    chunks = []
                    while True:
                        d = s.recv(4096)
                        if not d:
                            break
                        chunks.append(d)
                    return b"".join(chunks).decode("utf-8", errors="replace")

            # 1. Missing/wrong placeholder token rejected 401
            r401 = raw_req(b"GET /claude/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            self.assertIn("401", r401.splitlines()[0])

            r401_bad = raw_req(b"GET /claude/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: wrong\r\n\r\n")
            self.assertIn("401", r401_bad.splitlines()[0])

            # 2. Valid placeholder token injects real upstream header and strips placeholder
            r200 = raw_req(b"GET /claude/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-claude-secret-123\r\n\r\n")
            self.assertIn("200", r200.splitlines()[0])
            self.assertEqual(received["path"], "/api/v1/models")
            self.assertEqual(received["headers"].get("x-api-key"), "real-anthropic-key")

            # 3. Jira Basic auth placeholder password passes and injects real Basic auth
            basic_ph = base64.b64encode(b"user@example.com:ph-jira-secret-456").decode()
            rj = raw_req(f"GET /jira/rest/api/3/myself HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {basic_ph}\r\n\r\n".encode())
            self.assertIn("200", rj.splitlines()[0])
            self.assertEqual(
                received["headers"].get("authorization"),
                "Basic " + base64.b64encode(b"user@example.com:real-jira-tok").decode(),
            )

            # 4. Upstream 3xx redirect is blocked with 403 without leaking Location
            r403 = raw_req(b"GET /claude/redirect HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-claude-secret-123\r\n\r\n")
            self.assertIn("403", r403.splitlines()[0])
            self.assertNotIn("attacker.example", r403)

            # 5. SSE streaming arrives incrementally before upstream closes
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
                s.sendall(b"GET /claude/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-claude-secret-123\r\n\r\n")
                buf = b""
                while b"data: chunk1" not in buf:
                    part = s.recv(4096)
                    if not part:
                        break
                    buf += part
                self.assertIn(b"200", buf.splitlines()[0])
                self.assertIn(b"data: chunk1", buf)
                stream_chunk1_seen.set()
                while b"data: chunk2" not in buf:
                    part = s.recv(4096)
                    if not part:
                        break
                    buf += part
                self.assertIn(b"data: chunk2", buf)

            # 6. HEAD & OPTIONS work
            rhead = raw_req(b"HEAD /claude/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-claude-secret-123\r\n\r\n")
            self.assertIn("200", rhead.splitlines()[0])
            ropt = raw_req(b"OPTIONS /claude/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-claude-secret-123\r\n\r\n")
            self.assertIn("204", ropt.splitlines()[0])

            # 7. Chunked POST body and malformed Content-Length 400
            chunked_req = (
                b"POST /claude/v1/messages HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"x-api-key: ph-claude-secret-123\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\n\r\n"
            )
            rchunk = raw_req(chunked_req)
            self.assertIn("200", rchunk.splitlines()[0])
            self.assertEqual(received["post_body"], b"hello")

            r400 = raw_req(b"POST /claude/v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-claude-secret-123\r\nContent-Length: nope\r\n\r\n")
            self.assertIn("400", r400.splitlines()[0])
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            up_srv.shutdown()
            up_srv.server_close()
            credential_proxy.load_routes = orig_load
            credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = orig_insecure
            os.unlink(cfg_path)


if __name__ == "__main__":
    unittest.main()
