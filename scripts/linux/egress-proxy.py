#!/usr/bin/env python3
"""Root-owned HTTP/HTTPS CONNECT domain allowlist proxy for wsl-agent-sandbox."""

import fnmatch
import http.client
import http.server
import ipaddress
import json
import os
import selectors
import socket
import socketserver
import sys
from urllib.parse import urlsplit

ALLOWLIST_FILE = sys.argv[1] if len(sys.argv) > 1 else "/etc/wsl-agent-sandbox/egress-allowlist.json"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3128
TUNNEL_IDLE_TIMEOUT = 600.0
UPSTREAM_CONNECT_TIMEOUT = 3.0
UPSTREAM_RESPONSE_TIMEOUT = 30.0
MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024


class PayloadTooLargeError(ValueError):
    """Raised when an HTTP request body exceeds MAX_REQUEST_BODY_BYTES."""


def read_chunked_body(rfile, max_bytes=None):
    """Decode an HTTP/1.1 Transfer-Encoding: chunked request body with a strict size cap."""
    limit = MAX_REQUEST_BODY_BYTES if max_bytes is None else max_bytes
    chunks = []
    total = 0
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
        if total + chunk_size > limit:
            raise PayloadTooLargeError(f"chunked request body exceeds {limit} bytes")
        data = rfile.read(chunk_size)
        if len(data) != chunk_size:
            raise ValueError("unexpected EOF in chunk body")
        chunks.append(data)
        total += chunk_size
        crlf = rfile.readline(65536)
        if crlf not in (b"\r\n", b"\n"):
            raise ValueError("missing chunk terminator")
    return b"".join(chunks)

PRESETS = {
    "llm-apis": ["generativelanguage.googleapis.com", "api.anthropic.com", "api.openai.com"],
    "github": ["github.com", "*.github.com", "*.githubusercontent.com"],
    "npm": ["registry.npmjs.org"],
    "pypi": ["pypi.org", "files.pythonhosted.org"],
    "apt": ["archive.ubuntu.com", "security.ubuntu.com", "*.archive.ubuntu.com"],
}

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


def load_config(path=ALLOWLIST_FILE):
    """Load egress allowlist config; fail closed on missing or corrupt JSON."""
    default_cfg = {
        "egressMode": "allowlist",
        "patterns": [],
        "blockHostAndLan": True,
        "hostIps": set(),
        "blockedNets": [],
        "allowedPorts": {443},
        "allowedHttpPorts": {80, 443},
    }
    if not os.path.isfile(path):
        return default_cfg
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return default_cfg
    except (OSError, ValueError):
        return default_cfg

    patterns = []
    for item in data.get("allowedDomains", []):
        if not isinstance(item, str):
            continue
        item = item.strip().lower()
        if item in PRESETS:
            patterns.extend(PRESETS[item])
        elif item:
            patterns.append(item)

    host_ips = set()
    for raw_ip in data.get("hostIps", []):
        if not isinstance(raw_ip, str):
            continue
        try:
            host_ips.add(ipaddress.ip_address(raw_ip.split("%")[0].strip()))
        except ValueError:
            pass

    blocked_nets = []
    for raw_cidr in data.get("blockedCidrs", []):
        if not isinstance(raw_cidr, str):
            continue
        try:
            blocked_nets.append(ipaddress.ip_network(raw_cidr.strip(), strict=False))
        except ValueError:
            pass

    def _port_set(key, fallback):
        vals = data.get(key)
        if not isinstance(vals, list) or not vals:
            return set(fallback)
        out = set()
        for v in vals:
            try:
                p = int(v)
                if 1 <= p <= 65535:
                    out.add(p)
            except (TypeError, ValueError):
                pass
        return out or set(fallback)

    return {
        "egressMode": data.get("egressMode", "open"),
        "patterns": patterns,
        "blockHostAndLan": bool(data.get("blockHostAndLan", True)),
        "hostIps": host_ips,
        "blockedNets": blocked_nets,
        "allowedPorts": _port_set("allowedPorts", (443,)),
        "allowedHttpPorts": _port_set("allowedHttpPorts", (80, 443)),
    }


def is_domain_allowed(host, patterns):
    host = (host or "").lower().strip().strip(".")
    if not host:
        return False
    for pat in patterns:
        if pat.startswith("*."):
            suffix = pat[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        elif fnmatch.fnmatch(host, pat):
            return True
    return False


def parse_connect_target(target):
    """Parse 'host:port', '[ipv6]:port', or 'host' for CONNECT; raise ValueError on invalid input."""
    raw = (target or "").strip()
    if not raw:
        raise ValueError("empty CONNECT target")
    if raw.startswith("["):
        end_bracket = raw.find("]")
        if end_bracket <= 1:
            raise ValueError("malformed IPv6 bracket target")
        host = raw[1:end_bracket]
        rest = raw[end_bracket + 1:]
        if not rest:
            port = 443
        elif rest.startswith(":"):
            port_str = rest[1:]
            if not port_str.isdigit():
                raise ValueError("invalid port")
            port = int(port_str)
        else:
            raise ValueError("unexpected trailing characters after IPv6 host")
    elif ":" in raw:
        host, port_str = raw.rsplit(":", 1)
        if not host or not port_str.isdigit():
            raise ValueError("invalid host:port")
        port = int(port_str)
    else:
        host = raw
        port = 443

    if not host or port < 1 or port > 65535:
        raise ValueError("invalid host or port out of range")
    return host, port


def is_ip_blocked(ip_str, cfg):
    """Return reason string if an IP is loopback, host, private/LAN, or blocked CIDR."""
    clean = ip_str.split("%")[0].strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return f"invalid resolved address {ip_str!r}"

    # Mapped IPv4 inside IPv6 (e.g. ::ffff:127.0.0.1) must be checked as IPv4 too.
    candidates = [ip_obj]
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        candidates.append(ip_obj.ipv4_mapped)

    if not cfg.get("blockHostAndLan", True):
        return None

    for cand in candidates:
        if (
            cand.is_loopback
            or cand.is_private
            or cand.is_link_local
            or cand.is_multicast
            or cand.is_reserved
            or cand.is_unspecified
        ):
            return f"non-global target IP {cand} forbidden"
        if cand in cfg.get("hostIps", ()):
            return f"Windows host IP {cand} forbidden"
        for net in cfg.get("blockedNets", ()):
            if cand.version == net.version and cand in net:
                return f"target IP {cand} matches blocked CIDR {net}"
    return None


def resolve_and_validate_addresses(host, port, cfg, resolver=socket.getaddrinfo):
    """Resolve host once, validate every returned IP, and return list of sockaddr info tuples."""
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PermissionError(f"DNS resolution failed for {host}: {exc}") from exc
    if not infos:
        raise PermissionError(f"no addresses resolved for {host}")

    validated = []
    for family, socktype, proto, canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        reason = is_ip_blocked(ip_str, cfg)
        if reason is not None:
            raise PermissionError(reason)
        validated.append((family, socktype, proto, canonname, sockaddr))
    return validated


def connect_validated_socket(host, port, cfg, resolver=socket.getaddrinfo, timeout=UPSTREAM_CONNECT_TIMEOUT):
    """Resolve and validate host, then dial a validated IP sockaddr directly (no DNS TOCTOU)."""
    addrs = resolve_and_validate_addresses(host, port, cfg, resolver=resolver)
    last_exc = None
    for family, socktype, proto, _, sockaddr in addrs:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            sock.settimeout(None)
            return sock
        except OSError as exc:
            last_exc = exc
            try:
                sock.close()
            except OSError:
                pass
    raise last_exc if last_exc is not None else OSError("failed to connect to validated address")


class EgressProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[egress-proxy] {self.address_string()} {fmt % args}\n")
        sys.stdout.flush()

    def do_CONNECT(self):
        try:
            host, port = parse_connect_target(self.path)
        except ValueError as exc:
            self.send_error(400, f"bad CONNECT target: {exc}")
            return

        cfg = load_config()
        if port not in cfg["allowedPorts"]:
            self.log_message("DENY CONNECT port %s:%d", host, port)
            self.send_error(403, f"egress-proxy blocked port: {port}")
            return
        if not is_domain_allowed(host, cfg["patterns"]):
            self.log_message("DENY CONNECT %s:%d", host, port)
            self.send_error(403, f"egress-proxy blocked domain: {host}")
            return

        try:
            upstream = connect_validated_socket(host, port, cfg)
        except PermissionError as exc:
            self.log_message("DENY SSRF CONNECT %s:%d (%s)", host, port, exc)
            self.send_error(403, f"egress-proxy blocked address: {exc}")
            return
        except OSError as exc:
            self.send_error(502, f"upstream connect failed: {exc}")
            return

        self.log_message("ALLOW CONNECT %s:%d", host, port)
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._tunnel(self.connection, upstream)

    def _handle_http(self):
        try:
            parsed = urlsplit(self.path)
        except ValueError as exc:
            self.send_error(400, f"malformed request URL: {exc}")
            return
        if parsed.scheme.lower() != "http":
            self.send_error(400, "absolute http:// URL required for non-CONNECT proxy requests")
            return
        host = parsed.hostname or ""
        try:
            port = parsed.port or 80
        except ValueError as exc:
            self.send_error(400, f"invalid target port: {exc}")
            return
        if not host or port < 1 or port > 65535:
            self.send_error(400, "invalid target host or port")
            return

        cfg = load_config()
        if port not in cfg["allowedHttpPorts"]:
            self.log_message("DENY HTTP port %s:%d", host, port)
            self.send_error(403, f"egress-proxy blocked HTTP port: {port}")
            return
        if not is_domain_allowed(host, cfg["patterns"]):
            self.log_message("DENY %s %s", self.command, host)
            self.send_error(403, f"egress-proxy blocked domain: {host}")
            return

        te_header = (self.headers.get("Transfer-Encoding") or "").lower()
        cl_header = self.headers.get("Content-Length")
        req_body = None
        if "chunked" in te_header:
            try:
                req_body = read_chunked_body(self.rfile, MAX_REQUEST_BODY_BYTES)
            except PayloadTooLargeError as exc:
                self.close_connection = True
                self.send_error(413, f"egress-proxy: {exc}")
                return
            except ValueError as exc:
                self.send_error(400, f"invalid chunked body: {exc}")
                return
        elif cl_header is not None:
            try:
                cl = int(cl_header.strip())
                if cl < 0:
                    raise ValueError("negative Content-Length")
            except ValueError:
                self.send_error(400, "invalid Content-Length header")
                return
            if cl > MAX_REQUEST_BODY_BYTES:
                self.close_connection = True
                self.send_error(413, f"egress-proxy: request body exceeds {MAX_REQUEST_BODY_BYTES} bytes")
                return
            if cl > 0:
                req_body = self.rfile.read(cl)

        try:
            addrs = resolve_and_validate_addresses(host, port, cfg)
        except PermissionError as exc:
            self.log_message("DENY SSRF %s %s:%d (%s)", self.command, host, port, exc)
            self.send_error(403, f"egress-proxy blocked address: {exc}")
            return

        req_target = parsed.path or "/"
        if parsed.query:
            req_target = f"{req_target}?{parsed.query}"

        fwd_headers = {}
        has_host = False
        for k, v in self.headers.items():
            if k.lower() in HOP_BY_HOP_HEADERS:
                continue
            if k.lower() == "host":
                has_host = True
            fwd_headers[k] = v
        if not has_host:
            fwd_headers["Host"] = parsed.netloc
        fwd_headers["Connection"] = "close"

        resp = None
        conn = None
        last_exc = None
        for _, _, _, _, sockaddr in addrs:
            resolved_ip = sockaddr[0].split("%")[0]
            try:
                conn = http.client.HTTPConnection(resolved_ip, port=port, timeout=UPSTREAM_CONNECT_TIMEOUT)
                conn.connect()
                if conn.sock is not None:
                    conn.sock.settimeout(UPSTREAM_RESPONSE_TIMEOUT)
                conn.request(self.command, req_target, body=req_body, headers=fwd_headers)
                resp = conn.getresponse()
                break
            except (OSError, http.client.HTTPException) as exc:
                last_exc = exc
                try:
                    if conn is not None:
                        conn.close()
                except OSError:
                    pass
                conn = None

        if resp is None:
            self.send_error(502, f"upstream HTTP request failed: {last_exc}")
            return

        try:
            self.log_message("ALLOW %s %s:%d -> %d", self.command, host, port, resp.status)
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                kl = k.lower()
                if kl in HOP_BY_HOP_HEADERS or kl == "content-length":
                    continue
                self.send_header(k, v)
            content_len = resp.getheader("Content-Length")
            if content_len is not None and self.command != "HEAD":
                self.send_header("Content-Length", content_len)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        finally:
            try:
                if conn is not None:
                    conn.close()
            except OSError:
                pass

    do_GET = _handle_http
    do_POST = _handle_http
    do_PUT = _handle_http
    do_DELETE = _handle_http
    do_HEAD = _handle_http

    @staticmethod
    def _tunnel(a, b, idle_timeout=TUNNEL_IDLE_TIMEOUT):
        sel = selectors.DefaultSelector()
        try:
            sel.register(a, selectors.EVENT_READ, data=b)
            sel.register(b, selectors.EVENT_READ, data=a)
            while sel.get_map():
                events = sel.select(timeout=idle_timeout)
                if not events:
                    break
                for key, _ in events:
                    src = key.fileobj
                    dst = key.data
                    data = src.recv(65536)
                    if not data:
                        sel.unregister(src)
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            sel.close()
            for sock in (a, b):
                try:
                    sock.close()
                except OSError:
                    pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), EgressProxyHandler)
    print(f"[egress-proxy] listening on {LISTEN_HOST}:{LISTEN_PORT} allowlist={ALLOWLIST_FILE}", flush=True)
    srv.serve_forever()
