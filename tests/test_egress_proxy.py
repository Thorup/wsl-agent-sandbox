import http.server
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "linux" / "egress-proxy.py"
spec = importlib.util.spec_from_file_location("egress_proxy", MODULE_PATH)
egress_proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress_proxy)


class EgressProxyTests(unittest.TestCase):
    def test_domain_and_preset_matching(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"egressMode": "allowlist", "allowedDomains": ["github", "api.example.com", "*.internal.test"]}, f)
            cfg_path = f.name
        try:
            cfg = egress_proxy.load_config(cfg_path)
            self.assertTrue(egress_proxy.is_domain_allowed("github.com", cfg["patterns"]))
            self.assertTrue(egress_proxy.is_domain_allowed("api.github.com", cfg["patterns"]))
            self.assertTrue(egress_proxy.is_domain_allowed("raw.githubusercontent.com", cfg["patterns"]))
            self.assertTrue(egress_proxy.is_domain_allowed("sub.internal.test", cfg["patterns"]))
            self.assertFalse(egress_proxy.is_domain_allowed("evil.com", cfg["patterns"]))
        finally:
            os.unlink(cfg_path)

    def test_corrupt_config_fails_closed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("{corrupt json")
            cfg_path = f.name
        try:
            cfg = egress_proxy.load_config(cfg_path)
            self.assertEqual(cfg["patterns"], [])
            self.assertTrue(cfg["blockHostAndLan"])
        finally:
            os.unlink(cfg_path)

    def test_parse_connect_target_ipv6_and_ports(self):
        self.assertEqual(egress_proxy.parse_connect_target("api.github.com:443"), ("api.github.com", 443))
        self.assertEqual(egress_proxy.parse_connect_target("api.github.com"), ("api.github.com", 443))
        self.assertEqual(egress_proxy.parse_connect_target("[::1]:443"), ("::1", 443))
        for bad in ["[::1]:notaport", "example.com:99999", "example.com:0", "[bad", ""]:
            with self.assertRaises(ValueError):
                egress_proxy.parse_connect_target(bad)

    def test_ssrf_ip_and_dns_rebinding_blocking(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(
                {
                    "egressMode": "allowlist",
                    "allowedDomains": ["*.example.com"],
                    "blockHostAndLan": True,
                    "hostIps": ["203.0.113.50"],
                    "blockedCidrs": ["10.0.0.0/8", "192.168.0.0/16", "100.64.0.0/10"],
                },
                f,
            )
            cfg_path = f.name
        try:
            cfg = egress_proxy.load_config(cfg_path)
            for private_ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "203.0.113.50"]:
                fake_resolver = lambda h, p, type=None, ip=private_ip: [
                    (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p))
                ]
                with self.assertRaises(PermissionError):
                    egress_proxy.resolve_and_validate_addresses("rebind.example.com", 443, cfg, resolver=fake_resolver)

            public_resolver = lambda h, p, type=None: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))
            ]
            addrs = egress_proxy.resolve_and_validate_addresses("ok.example.com", 443, cfg, resolver=public_resolver)
            self.assertEqual(addrs[0][4][0], "93.184.216.34")
        finally:
            os.unlink(cfg_path)

    def test_live_handler_blocks_bad_port_malformed_ipv6_and_forwards_http_without_redirect(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(
                {
                    "egressMode": "allowlist",
                    "allowedDomains": ["apt", "localhost"],
                    "blockHostAndLan": False,
                    "allowedPorts": [443],
                    "allowedHttpPorts": [],
                },
                f,
            )
            cfg_path = f.name

        class EchoRedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://evil.invalid/redirect")
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"REDR")

            def log_message(self, *args):
                pass

        up_srv = http.server.HTTPServer(("127.0.0.1", 0), EchoRedirectHandler)
        up_port = up_srv.server_address[1]
        up_thread = threading.Thread(target=up_srv.serve_forever, daemon=True)
        up_thread.start()

        # Re-write config allowing the test upstream port explicitly while keeping blockHostAndLan=False only for test socket
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "egressMode": "allowlist",
                    "allowedDomains": ["localhost"],
                    "blockHostAndLan": False,
                    "allowedPorts": [443],
                    "allowedHttpPorts": [up_port],
                },
                f,
            )

        orig_file = egress_proxy.ALLOWLIST_FILE
        orig_load = egress_proxy.load_config
        egress_proxy.ALLOWLIST_FILE = cfg_path
        egress_proxy.load_config = lambda p=cfg_path: orig_load(p)
        proxy_srv = egress_proxy.ThreadingHTTPServer(("127.0.0.1", 0), egress_proxy.EgressProxyHandler)
        proxy_port = proxy_srv.server_address[1]
        proxy_thread = threading.Thread(target=proxy_srv.serve_forever, daemon=True)
        proxy_thread.start()

        try:
            def raw_http(req_bytes):
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as s:
                    s.sendall(req_bytes)
                    chunks = []
                    while True:
                        d = s.recv(4096)
                        if not d:
                            break
                        chunks.append(d)
                    return b"".join(chunks).decode("utf-8", errors="replace")

            # Malformed IPv6 port returns 400 cleanly
            r400 = raw_http(b"CONNECT [::1]:notaport HTTP/1.1\r\nHost: [::1]:notaport\r\n\r\n")
            self.assertIn("400", r400.splitlines()[0])

            # Non-443 CONNECT returns 403
            r403_port = raw_http(b"CONNECT localhost:22 HTTP/1.1\r\nHost: localhost:22\r\n\r\n")
            self.assertIn("403", r403_port.splitlines()[0])

            # Non-allowlisted domain returns 403
            r403_dom = raw_http(b"GET http://evil.invalid/test HTTP/1.1\r\nHost: evil.invalid\r\n\r\n")
            self.assertIn("403", r403_dom.splitlines()[0])

            # Allowlisted plain HTTP forwards cleanly AND returns 302 without following redirect internally
            r302 = raw_http(f"GET http://localhost:{up_port}/pkg HTTP/1.1\r\nHost: localhost:{up_port}\r\n\r\n".encode())
            self.assertIn("302", r302.splitlines()[0])
            self.assertIn("REDR", r302)
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            up_srv.shutdown()
            up_srv.server_close()
            egress_proxy.ALLOWLIST_FILE = orig_file
            egress_proxy.load_config = orig_load
            os.unlink(cfg_path)

    def test_selector_tunnel_drains_and_closes(self):
        a_cli, a_srv = socket.socketpair()
        b_srv, b_rem = socket.socketpair()
        t = threading.Thread(target=egress_proxy.EgressProxyHandler._tunnel, args=(a_srv, b_srv, 5.0), daemon=True)
        t.start()
        try:
            a_cli.sendall(b"ping")
            self.assertEqual(b_rem.recv(16), b"ping")
            b_rem.sendall(b"pong")
            b_rem.shutdown(socket.SHUT_WR)
            self.assertEqual(a_cli.recv(16), b"pong")
            a_cli.close()
            b_rem.close()
            t.join(timeout=3)
            self.assertFalse(t.is_alive())
        finally:
            for s in (a_cli, b_rem):
                try:
                    s.close()
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
