#!/usr/bin/env python3
"""Root-owned L7 credential injection reverse proxy for wsl-agent-sandbox.

Listens on 127.0.0.1:3129 and injects real Authorization / API key headers ONLY
for strictly matching allowlisted upstream routes configured in root-only
/etc/wsl-agent-sandbox/credential-proxy.json after verifying the per-seed
placeholder token presented by the client.
"""

import base64
import hmac
import http.client
import http.server
import json
import os
import socketserver
import ssl
import sys
from urllib.parse import urlparse

CONFIG_FILE = sys.argv[1] if len(sys.argv) > 1 else "/etc/wsl-agent-sandbox/credential-proxy.json"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3129
UPSTREAM_TIMEOUT = 300.0
ALLOW_INSECURE_HTTP_FOR_TEST = False

HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
})


def load_routes(path=CONFIG_FILE):
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        routes = data.get("routes", {})
        return routes if isinstance(routes, dict) else {}
    except (OSError, ValueError):
        return {}


def extract_client_tokens(headers):
    """Extract candidate bearer/basic/api-key credentials supplied by the client."""
    tokens = []
    auth = headers.get("Authorization", "")
    if auth:
        parts = auth.strip().split(None, 1)
        if len(parts) == 2:
            scheme, val = parts[0].lower(), parts[1].strip()
            if scheme == "bearer" and val:
                tokens.append(val)
            elif scheme == "basic" and val:
                try:
                    decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                    if ":" in decoded:
                        _, pwd = decoded.split(":", 1)
                        if pwd:
                            tokens.append(pwd)
                    tokens.append(val)
                except Exception:
                    pass
    for hdr in ("x-api-key", "x-goog-api-key", "x-auth-token"):
        hv = headers.get(hdr, "")
        if hv and hv.strip():
            tokens.append(hv.strip())
    return tokens


def verify_placeholder_token(headers, route):
    """Verify the client presented a valid per-seed placeholder token configured on this route."""
    expected = []
    if route.get("expectedToken"):
        expected.append(str(route["expectedToken"]))
    for t in route.get("expectedTokens", []) or []:
        if t:
            expected.append(str(t))
    if not expected:
        # Fail closed if route lacks any expected placeholder token
        return False
    presented = extract_client_tokens(headers)
    for exp in expected:
        for got in presented:
            if hmac.compare_digest(got, exp):
                return True
    return False


def read_chunked_body(rfile):
    """Decode an HTTP/1.1 Transfer-Encoding: chunked request body."""
    chunks = []
    while True:
        size_line = rfile.readline(65536)
        if not size_line:
            raise ValueError("unexpected EOF reading chunk size")
        size_token = size_line.strip().split(b";", 1)[0]
        try:
            chunk_size = int(size_token, 16)
        except ValueError as exc:
            raise ValueError(f"invalid chunk size {size_token!r}") from exc
        if chunk_size < 0:
            raise ValueError("negative chunk size")
        if chunk_size == 0:
            while True:
                trailer = rfile.readline(65536)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break
        data = rfile.read(chunk_size)
        if len(data) != chunk_size:
            raise ValueError("unexpected EOF in chunk body")
        chunks.append(data)
        crlf = rfile.readline(65536)
        if crlf not in (b"\r\n", b"\n"):
            raise ValueError("missing chunk terminator")
    return b"".join(chunks)


class CredentialProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[credential-proxy] {fmt % args}\n")
        sys.stdout.flush()

    def _handle(self):
        routes = load_routes()
        parts = self.path.lstrip("/").split("/", 1)
        svc = parts[0] if parts else ""
        rest = "/" + parts[1] if len(parts) > 1 else "/"
        route = routes.get(svc)
        if not route:
            self.send_error(403, f"credential-proxy: unknown or unconfigured service route '{svc}'")
            return

        if not verify_placeholder_token(self.headers, route):
            self.send_error(401, f"credential-proxy: missing or invalid placeholder token for '{svc}'")
            return

        upstream = urlparse(route["upstreamBaseUrl"])
        allowed_schemes = ("https", "http") if ALLOW_INSECURE_HTTP_FOR_TEST else ("https",)
        if upstream.scheme not in allowed_schemes or not upstream.hostname:
            self.send_error(403, "credential-proxy: invalid upstreamBaseUrl")
            return

        te = (self.headers.get("Transfer-Encoding") or "").lower()
        cl_raw = self.headers.get("Content-Length")
        body = None
        if "chunked" in te:
            try:
                body = read_chunked_body(self.rfile)
            except ValueError as exc:
                self.send_error(400, f"credential-proxy: invalid chunked body: {exc}")
                return
        elif cl_raw is not None:
            try:
                length = int(cl_raw.strip())
                if length < 0:
                    raise ValueError("negative Content-Length")
            except ValueError:
                self.send_error(400, f"credential-proxy: invalid Content-Length {cl_raw!r}")
                return
            if length > 0:
                body = self.rfile.read(length)

        headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP_HEADERS or lk in ("host", "content-length", "authorization", "x-api-key", "x-goog-api-key", "x-auth-token"):
                continue
            headers[k] = v
        headers["Host"] = upstream.netloc
        headers["Connection"] = "close"
        for hk, hv in route.get("injectHeaders", {}).items():
            headers[hk] = hv

        if upstream.scheme == "http":
            conn = http.client.HTTPConnection(upstream.hostname, upstream.port or 80, timeout=UPSTREAM_TIMEOUT)
        else:
            conn = http.client.HTTPSConnection(
                upstream.hostname,
                upstream.port or 443,
                timeout=UPSTREAM_TIMEOUT,
                context=ssl.create_default_context(),
            )
        try:
            target_path = upstream.path.rstrip("/") + rest
            conn.request(self.command, target_path, body=body, headers=headers)
            resp = conn.getresponse()
            # Refuse redirects so credentials/tokens are never forwarded to another domain.
            if resp.status in (301, 302, 303, 307, 308):
                self.send_error(403, "credential-proxy: upstream redirect blocked")
                return

            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                lk = k.lower()
                if lk in HOP_BY_HOP_HEADERS or lk == "content-length":
                    continue
                self.send_header(k, v)
            content_len = resp.getheader("Content-Length")
            if content_len is not None and self.command != "HEAD":
                self.send_header("Content-Length", content_len)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

            if self.command != "HEAD" and resp.status not in (204, 304):
                while True:
                    chunk = resp.read1(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except Exception as exc:
            try:
                self.send_error(502, f"credential-proxy upstream error: {exc}")
            except OSError:
                pass
        finally:
            conn.close()

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), CredentialProxyHandler)
    print(f"[credential-proxy] listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    srv.serve_forever()
