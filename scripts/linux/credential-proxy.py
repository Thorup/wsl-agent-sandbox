#!/usr/bin/env python3
"""Root-owned L7 credential injection reverse proxy for wsl-agent-sandbox.

Listens on 127.0.0.1:3129 and injects real Authorization / API key headers ONLY
for strictly matching allowlisted upstream routes configured in root-only
/etc/wsl-agent-sandbox/credential-proxy.json after verifying the per-seed
placeholder token presented by the client.
"""

import base64
import fnmatch
import hmac
import http.client
import http.server
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import sys
from urllib.parse import parse_qsl, urlencode, urlparse

CONFIG_FILE = sys.argv[1] if len(sys.argv) > 1 else "/etc/wsl-agent-sandbox/credential-proxy.json"
EGRESS_ALLOWLIST_FILE = sys.argv[2] if len(sys.argv) > 2 else "/etc/wsl-agent-sandbox/egress-allowlist.json"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 3129
UPSTREAM_TIMEOUT = 300.0
MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024
ALLOW_INSECURE_HTTP_FOR_TEST = False


class PayloadTooLargeError(ValueError):
    """Raised when an HTTP request body exceeds MAX_REQUEST_BODY_BYTES."""
RESOLVER = socket.getaddrinfo

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


def load_proxy_config(path=CONFIG_FILE):
    """Load credential-proxy config including listenPort, allowedCallerUid, and routes."""
    default_cfg = {
        "listenPort": LISTEN_PORT,
        "allowedCallerUid": None,
        "routes": {},
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

    raw_port = data.get("listenPort")
    listen_port = LISTEN_PORT
    if isinstance(raw_port, int) and not isinstance(raw_port, bool) and 1 <= raw_port <= 65535:
        listen_port = raw_port

    raw_uid = data.get("allowedCallerUid")
    allowed_uid = None
    if isinstance(raw_uid, int) and not isinstance(raw_uid, bool) and raw_uid >= 0:
        allowed_uid = raw_uid

    routes = data.get("routes", {})
    return {
        "listenPort": listen_port,
        "allowedCallerUid": allowed_uid,
        "routes": routes if isinstance(routes, dict) else {},
    }


def load_routes(path=CONFIG_FILE):
    return load_proxy_config(path)["routes"]


def _format_proc_net_addr(ip_obj, port):
    """Format an IPv4 or IPv6 address + port as uppercase hex strings for /proc/net/tcp{,6}."""
    port_hex = f"{int(port):04X}"
    if isinstance(ip_obj, ipaddress.IPv4Address):
        ip_hex = f"{int.from_bytes(ip_obj.packed, sys.byteorder):08X}"
        mapped_hex = f"0000000000000000FFFF0000{ip_hex}"
        return [(f"{ip_hex}:{port_hex}", f"{mapped_hex}:{port_hex}")]
    packed = ip_obj.packed
    ip6_hex = "".join(f"{int.from_bytes(packed[i:i + 4], sys.byteorder):08X}" for i in range(0, 16, 4))
    return [(f"{ip6_hex}:{port_hex}",)]


def verify_caller_uid(client_address, server_port, allowed_uid, proc_net_paths=("/proc/net/tcp", "/proc/net/tcp6")):
    """Verify via /proc/net/tcp{,6} that the connecting loopback socket belongs to root (0) or allowed_uid."""
    if allowed_uid is None:
        return True
    try:
        allowed_uid_int = int(allowed_uid)
        client_ip_raw = str(client_address[0]).split("%")[0].strip()
        client_port = int(client_address[1])
        srv_port = int(server_port)
        client_ip = ipaddress.ip_address(client_ip_raw)
        if isinstance(client_ip, ipaddress.IPv6Address) and client_ip.ipv4_mapped is not None:
            client_ip = client_ip.ipv4_mapped
    except (IndexError, TypeError, ValueError):
        return False

    local_candidates = set()
    rem_candidates = set()
    for tup in _format_proc_net_addr(client_ip, client_port):
        local_candidates.update(tup)
    for tup in _format_proc_net_addr(client_ip, srv_port):
        rem_candidates.update(tup)

    for path in proc_net_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 8:
                continue
            local_col = parts[1].upper()
            rem_col = parts[2].upper()
            state_col = parts[3].upper()
            if state_col != "01":
                continue
            if local_col in local_candidates and rem_col in rem_candidates:
                try:
                    sock_uid = int(parts[7])
                except ValueError:
                    return False
                return sock_uid in (0, allowed_uid_int)
    return False


def load_egress_config(path=None):
    """Load egress allowlist config; fail closed if file exists but is corrupt."""
    target = EGRESS_ALLOWLIST_FILE if path is None else path
    if not os.path.isfile(target):
        return {
            "egressMode": "open",
            "patterns": [],
            "blockHostAndLan": True,
            "hostIps": set(),
            "blockedNets": [],
        }
    fail_closed = {
        "egressMode": "allowlist",
        "patterns": [],
        "blockHostAndLan": True,
        "hostIps": set(),
        "blockedNets": [],
    }
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return fail_closed
    except (OSError, ValueError):
        return fail_closed

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

    return {
        "egressMode": data.get("egressMode", "open"),
        "patterns": patterns,
        "blockHostAndLan": bool(data.get("blockHostAndLan", True)),
        "hostIps": host_ips,
        "blockedNets": blocked_nets,
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


def is_ip_blocked(ip_str, cfg):
    """Return reason string if an IP is loopback, host, private/LAN, or blocked CIDR."""
    clean = ip_str.split("%")[0].strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return f"invalid resolved address {ip_str!r}"

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


def resolve_and_validate_addresses(host, port, cfg, resolver=None):
    """Resolve host once, validate every returned IP, and return list of sockaddr info tuples."""
    res = RESOLVER if resolver is None else resolver
    try:
        infos = res(host, port, type=socket.SOCK_STREAM)
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


def _connect_validated_socket(addrs, timeout=UPSTREAM_TIMEOUT):
    last_exc = None
    for family, socktype, proto, _, sockaddr in addrs:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_exc = exc
            try:
                sock.close()
            except OSError:
                pass
    raise last_exc or OSError("failed to connect to any validated address")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, addrs, timeout=UPSTREAM_TIMEOUT):
        super().__init__(host, port, timeout=timeout)
        self._addrs = addrs

    def connect(self):
        self.sock = _connect_validated_socket(self._addrs, timeout=self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, addrs, timeout=UPSTREAM_TIMEOUT, context=None):
        super().__init__(host, port, timeout=timeout, context=context)
        self._addrs = addrs

    def connect(self):
        raw_sock = _connect_validated_socket(self._addrs, timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            try:
                raw_sock.close()
            except OSError:
                pass
            raise


def extract_client_tokens(headers, query_string=""):
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
    if query_string:
        for qk, qv in parse_qsl(query_string, keep_blank_values=True):
            if qk.lower() in ("key", "api_key") and qv and qv.strip():
                tokens.append(qv.strip())
    return tokens


def resolve_matched_token_profile(headers, route, query_string=""):
    """Verify the client presented a valid per-seed placeholder token and return any matched profile override."""
    presented = extract_client_tokens(headers, query_string=query_string)
    token_profiles = route.get("tokenProfiles")
    if isinstance(token_profiles, dict) and token_profiles:
        for exp_tok, prof_cfg in token_profiles.items():
            if not exp_tok or not isinstance(prof_cfg, dict):
                continue
            for got in presented:
                if hmac.compare_digest(got, str(exp_tok)):
                    return True, prof_cfg

    expected = []
    if route.get("expectedToken"):
        expected.append(str(route["expectedToken"]))
    for t in route.get("expectedTokens", []) or []:
        if t:
            expected.append(str(t))
    if not expected:
        # Fail closed if route lacks any expected placeholder token
        return False, None
    for exp in expected:
        for got in presented:
            if hmac.compare_digest(got, exp):
                return True, None
    return False, None


def verify_placeholder_token(headers, route):
    """Verify the client presented a valid per-seed placeholder token configured on this route."""
    ok, _ = resolve_matched_token_profile(headers, route)
    return ok


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


class CredentialProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[credential-proxy] {fmt % args}\n")
        sys.stdout.flush()

    def _handle(self):
        cfg = load_proxy_config()
        allowed_uid = cfg.get("allowedCallerUid")
        if allowed_uid is not None:
            server_port = self.server.server_address[1]
            if not verify_caller_uid(self.client_address, server_port, allowed_uid):
                self.log_message("DENY CALLER_UID client=%s allowed_uid=%s", self.client_address, allowed_uid)
                self.send_error(403, "credential-proxy: caller UID forbidden")
                return

        routes = load_routes()
        parts = self.path.lstrip("/").split("/", 1)
        svc = parts[0] if parts else ""
        rest = "/" + parts[1] if len(parts) > 1 else "/"
        route = routes.get(svc)
        if not route:
            self.send_error(403, f"credential-proxy: unknown or unconfigured service route '{svc}'")
            return

        rest_path, _, rest_query = rest.partition("?")
        ok, matched_profile = resolve_matched_token_profile(self.headers, route, query_string=rest_query)
        if not ok:
            self.send_error(401, f"credential-proxy: missing or invalid placeholder token for '{svc}'")
            return

        effective_upstream_url = (matched_profile or {}).get("upstreamBaseUrl") or route["upstreamBaseUrl"]
        effective_inject_headers = (matched_profile or {}).get("injectHeaders") or route.get("injectHeaders", {})
        upstream = urlparse(effective_upstream_url)
        allowed_schemes = ("https", "http") if ALLOW_INSECURE_HTTP_FOR_TEST else ("https",)
        if upstream.scheme not in allowed_schemes or not upstream.hostname:
            self.send_error(403, "credential-proxy: invalid upstreamBaseUrl")
            return

        egress_cfg = load_egress_config()
        if egress_cfg.get("egressMode") == "allowlist":
            if not is_domain_allowed(upstream.hostname, egress_cfg.get("patterns", [])):
                self.send_error(403, f"credential-proxy: upstream domain '{upstream.hostname}' is not allowlisted")
                return

        upstream_port = upstream.port or (80 if upstream.scheme == "http" else 443)
        validated_addrs = None
        if not ALLOW_INSECURE_HTTP_FOR_TEST:
            try:
                validated_addrs = resolve_and_validate_addresses(upstream.hostname, upstream_port, egress_cfg)
            except PermissionError as exc:
                self.send_error(403, f"credential-proxy: upstream address blocked: {exc}")
                return

        te = (self.headers.get("Transfer-Encoding") or "").lower()
        cl_raw = self.headers.get("Content-Length")
        body = None
        if "chunked" in te:
            try:
                body = read_chunked_body(self.rfile, MAX_REQUEST_BODY_BYTES)
            except PayloadTooLargeError as exc:
                self.close_connection = True
                self.send_error(413, f"credential-proxy: {exc}")
                return
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
            if length > MAX_REQUEST_BODY_BYTES:
                self.close_connection = True
                self.send_error(413, f"credential-proxy: request body exceeds {MAX_REQUEST_BODY_BYTES} bytes")
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
        for hk, hv in effective_inject_headers.items():
            headers[hk] = hv

        if upstream.scheme == "http":
            if validated_addrs is not None:
                conn = _PinnedHTTPConnection(upstream.hostname, upstream_port, validated_addrs, timeout=UPSTREAM_TIMEOUT)
            else:
                conn = http.client.HTTPConnection(upstream.hostname, upstream_port, timeout=UPSTREAM_TIMEOUT)
        else:
            ssl_ctx = ssl.create_default_context()
            if validated_addrs is not None:
                conn = _PinnedHTTPSConnection(
                    upstream.hostname,
                    upstream_port,
                    validated_addrs,
                    timeout=UPSTREAM_TIMEOUT,
                    context=ssl_ctx,
                )
            else:
                conn = http.client.HTTPSConnection(
                    upstream.hostname,
                    upstream_port,
                    timeout=UPSTREAM_TIMEOUT,
                    context=ssl_ctx,
                )
        try:
            clean_query = rest_query
            if rest_query:
                inject_header_keys = {hk.lower() for hk in effective_inject_headers}
                expected_tokens = []
                if isinstance(route.get("tokenProfiles"), dict):
                    expected_tokens.extend(str(t) for t in route["tokenProfiles"] if t)
                if route.get("expectedToken"):
                    expected_tokens.append(str(route["expectedToken"]))
                for t in route.get("expectedTokens", []) or []:
                    if t:
                        expected_tokens.append(str(t))
                kept_params = []
                for qk, qv in parse_qsl(rest_query, keep_blank_values=True):
                    qv_s = qv.strip()
                    if qk.lower() in ("key", "api_key") and (
                        ("x-goog-api-key" in inject_header_keys or "x-api-key" in inject_header_keys)
                        or any(hmac.compare_digest(qv_s, exp) for exp in expected_tokens)
                    ):
                        continue
                    kept_params.append((qk, qv))
                clean_query = urlencode(kept_params, doseq=True)
            clean_rest = f"{rest_path}?{clean_query}" if clean_query else rest_path
            target_path = upstream.path.rstrip("/") + clean_rest
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
    cfg = load_proxy_config()
    listen_port = cfg.get("listenPort") or LISTEN_PORT
    srv = ThreadingHTTPServer((LISTEN_HOST, listen_port), CredentialProxyHandler)
    print(f"[credential-proxy] listening on {LISTEN_HOST}:{listen_port}", flush=True)
    srv.serve_forever()
