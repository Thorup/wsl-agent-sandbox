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

    def test_egress_allowlist_and_ssrf_ip_enforcement(self):
        class OkHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *args):
                pass

        up_srv = http.server.HTTPServer(("127.0.0.1", 0), OkHandler)
        up_port = up_srv.server_address[1]
        threading.Thread(target=up_srv.serve_forever, daemon=True).start()

        cfg_data = {
            "routes": {
                "allowed_svc": {
                    "upstreamBaseUrl": f"http://localhost:{up_port}/api",
                    "expectedToken": "ph-allow-123",
                    "injectHeaders": {"x-api-key": "real-key"},
                },
                "blocked_domain_svc": {
                    "upstreamBaseUrl": f"http://127.0.0.1:{up_port}/api",
                    "expectedToken": "ph-block-456",
                    "injectHeaders": {"x-api-key": "real-key"},
                },
                "https_rebind_svc": {
                    "upstreamBaseUrl": "https://api.anthropic.com/v1",
                    "expectedToken": "ph-rebind-789",
                    "injectHeaders": {"x-api-key": "real-key"},
                },
            }
        }
        egress_data = {
            "egressMode": "allowlist",
            "allowedDomains": ["localhost", "llm-apis"],
            "blockHostAndLan": True,
            "hostIps": ["203.0.113.50"],
            "blockedCidrs": ["10.0.0.0/8", "192.168.0.0/16", "100.64.0.0/10"],
        }

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg_data, f)
            cfg_path = f.name
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(egress_data, f)
            egress_path = f.name

        orig_load = credential_proxy.load_routes
        orig_egress_file = credential_proxy.EGRESS_ALLOWLIST_FILE
        orig_insecure = credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST
        orig_resolver = credential_proxy.RESOLVER

        credential_proxy.load_routes = lambda p=cfg_path: orig_load(p)
        credential_proxy.EGRESS_ALLOWLIST_FILE = egress_path

        proxy_srv = credential_proxy.ThreadingHTTPServer(("127.0.0.1", 0), credential_proxy.CredentialProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()

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

        try:
            # 1. Domain allowlist check (with ALLOW_INSECURE_HTTP_FOR_TEST=True for local HTTP test server)
            credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = True
            r_ok = raw_req(b"GET /allowed_svc/ping HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-allow-123\r\n\r\n")
            self.assertIn("200", r_ok.splitlines()[0])

            r_denied_domain = raw_req(
                b"GET /blocked_domain_svc/ping HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-block-456\r\n\r\n"
            )
            self.assertIn("403", r_denied_domain.splitlines()[0])
            self.assertIn("not allowlisted", r_denied_domain)

            # 2. SSRF & DNS-rebinding IP check (with ALLOW_INSECURE_HTTP_FOR_TEST=False)
            credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = False
            for bad_ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "203.0.113.50"):
                credential_proxy.RESOLVER = lambda h, p, type=None, ip=bad_ip: [
                    (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p))
                ]
                r_ssrf = raw_req(
                    b"GET /https_rebind_svc/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-rebind-789\r\n\r\n"
                )
                self.assertIn("403", r_ssrf.splitlines()[0], f"Expected 403 for blocked IP {bad_ip}, got {r_ssrf}")

            # 3. Corrupt egress-allowlist.json fails closed (403)
            credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = True
            with open(egress_path, "w", encoding="utf-8") as f:
                f.write("{corrupt")
            r_corrupt = raw_req(b"GET /allowed_svc/ping HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-allow-123\r\n\r\n")
            self.assertIn("403", r_corrupt.splitlines()[0])
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            up_srv.shutdown()
            up_srv.server_close()
            credential_proxy.load_routes = orig_load
            credential_proxy.EGRESS_ALLOWLIST_FILE = orig_egress_file
            credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = orig_insecure
            credential_proxy.RESOLVER = orig_resolver
            os.unlink(cfg_path)
            os.unlink(egress_path)

    def test_oversized_content_length_and_chunked_body_return_413(self):
        cfg_data = {
            "routes": {
                "claude": {
                    "upstreamBaseUrl": "http://127.0.0.1:9/api",
                    "expectedToken": "ph-cap-123",
                    "injectHeaders": {"x-api-key": "real-key"},
                }
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cfg_data, f)
            cfg_path = f.name

        orig_load = credential_proxy.load_routes
        orig_insecure = credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST
        orig_max = credential_proxy.MAX_REQUEST_BODY_BYTES
        credential_proxy.load_routes = lambda p=cfg_path: orig_load(p)
        credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = True
        credential_proxy.MAX_REQUEST_BODY_BYTES = 16

        proxy_srv = credential_proxy.ThreadingHTTPServer(("127.0.0.1", 0), credential_proxy.CredentialProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()

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

        try:
            r413_cl = raw_req(
                b"POST /claude/v1/messages HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"x-api-key: ph-cap-123\r\n"
                b"Content-Length: 999999999\r\n\r\n"
            )
            self.assertIn("413", r413_cl.splitlines()[0])

            r413_chunked = raw_req(
                b"POST /claude/v1/messages HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"x-api-key: ph-cap-123\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"20\r\n" + (b"B" * 32) + b"\r\n0\r\n\r\n"
            )
            self.assertIn("413", r413_chunked.splitlines()[0])
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            credential_proxy.load_routes = orig_load
            credential_proxy.ALLOW_INSECURE_HTTP_FOR_TEST = orig_insecure
            credential_proxy.MAX_REQUEST_BODY_BYTES = orig_max
            os.unlink(cfg_path)

    def test_load_proxy_config_and_verify_caller_uid(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(
                {
                    "listenPort": 13101,
                    "allowedCallerUid": 26150,
                    "routes": {"claude": {"upstreamBaseUrl": "https://api.anthropic.com"}},
                },
                f,
            )
            cfg_path = f.name
        proc_tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:AFC8 0100007F:332D 01 00000000:00000000 00:00000000 00000000 26150        0 1001 1 00000000\n"
            "   1: 0100007F:AFC9 0100007F:332D 01 00000000:00000000 00:00000000 00000000  1000        0 1002 1 00000000\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".tcp", delete=False, encoding="utf-8") as tf:
            tf.write(proc_tcp_content)
            tcp_path = tf.name
        try:
            cfg = credential_proxy.load_proxy_config(cfg_path)
            self.assertEqual(cfg["listenPort"], 13101)
            self.assertEqual(cfg["allowedCallerUid"], 26150)
            self.assertIn("claude", cfg["routes"])
            self.assertTrue(credential_proxy.verify_caller_uid(("127.0.0.1", 0xAFC8), 0x332D, 26150, (tcp_path,)))
            self.assertFalse(credential_proxy.verify_caller_uid(("127.0.0.1", 0xAFC9), 0x332D, 26150, (tcp_path,)))
            self.assertTrue(credential_proxy.verify_caller_uid(("127.0.0.1", 0xAFC9), 0x332D, None, (tcp_path,)))
        finally:
            os.unlink(cfg_path)
            os.unlink(tcp_path)

    def test_live_handler_rejects_mismatched_caller_uid_with_403(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(
                {
                    "listenPort": 13101,
                    "allowedCallerUid": 26150,
                    "routes": {
                        "claude": {
                            "upstreamBaseUrl": "http://127.0.0.1:9/api",
                            "expectedToken": "ph-tok",
                            "injectHeaders": {"x-api-key": "real"},
                        }
                    },
                },
                f,
            )
            cfg_path = f.name

        orig_load_cfg = credential_proxy.load_proxy_config
        orig_verify = credential_proxy.verify_caller_uid
        credential_proxy.load_proxy_config = lambda p=cfg_path: orig_load_cfg(p)
        credential_proxy.verify_caller_uid = lambda *args, **kwargs: False

        proxy_srv = credential_proxy.ThreadingHTTPServer(("127.0.0.1", 0), credential_proxy.CredentialProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
                s.sendall(b"GET /claude/v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: ph-tok\r\n\r\n")
                resp = s.recv(4096).decode("utf-8", errors="replace")
            self.assertIn("403", resp.splitlines()[0])
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            credential_proxy.load_proxy_config = orig_load_cfg
            credential_proxy.verify_caller_uid = orig_verify
            os.unlink(cfg_path)


if __name__ == "__main__":
    unittest.main()
