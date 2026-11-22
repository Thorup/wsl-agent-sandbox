#!/usr/bin/env python3
"""Root-owned filtered SSH agent proxy for wsl-agent-sandbox.

Exposes a restricted SSH_AUTH_SOCK (/run/ssh-agent-proxy/agent.sock, 0660 root:<agent_gid>)
to the non-root agent user while keeping private keys and the upstream ssh-agent inside
root-only /run/box-root/. Fails closed when /etc/wsl-agent-sandbox/ssh-agent-allowlist.json
is missing, corrupt, or empty, filters SSH_AGENTC_REQUEST_IDENTITIES (11) responses to only
allowlisted key blobs, and bounds-checks + filters SSH_AGENTC_SIGN_REQUEST (13).
"""

import json
import os
import pwd
import socket
import struct
import threading

UPSTREAM_SOCK = "/run/box-root/ssh-agent/upstream.sock"
LISTEN_SOCK = "/run/ssh-agent-proxy/agent.sock"
ALLOWLIST_FILE = "/etc/wsl-agent-sandbox/ssh-agent-allowlist.json"
POLICY_FILE = "/etc/wsl-agent-sandbox/policy.json"

SSH_AGENT_FAILURE = 5
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13


def recv_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    (length,) = struct.unpack(">I", hdr)
    if length == 0 or length > 256 * 1024:
        return None
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk
    return payload


def send_msg(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def resolve_agent_gid(policy_path=POLICY_FILE):
    agent_name = "agent"
    if os.path.isfile(policy_path):
        try:
            with open(policy_path, "r", encoding="utf-8") as pf:
                pol = json.load(pf)
            au = pol.get("agentUser", {}) if isinstance(pol, dict) else {}
            if isinstance(au, dict):
                if au.get("gid") is not None:
                    return int(au["gid"])
                if au.get("name"):
                    agent_name = str(au["name"])
        except (OSError, ValueError, TypeError):
            pass
    try:
        return pwd.getpwnam(agent_name).pw_gid
    except KeyError:
        return os.getgid()


def load_allowed_blobs(path=ALLOWLIST_FILE):
    """Load allowlisted public key blobs (hex). Fails closed (empty set) on any error."""
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return set()
        blobs = data.get("allowedKeyBlobsHex")
        if not isinstance(blobs, list):
            return set()
        return {str(b).strip().lower() for b in blobs if isinstance(b, str) and b.strip()}
    except (OSError, ValueError, TypeError):
        return set()


def filter_identities_answer(resp_bytes, allowed_blobs):
    """Filter an SSH_AGENT_IDENTITIES_ANSWER (12) frame to only allowlisted public key blobs."""
    if not allowed_blobs:
        return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 0)
    if not resp_bytes or len(resp_bytes) < 5 or resp_bytes[0] != SSH_AGENT_IDENTITIES_ANSWER:
        return bytes([SSH_AGENT_FAILURE])
    (nkeys,) = struct.unpack(">I", resp_bytes[1:5])
    if nkeys > 1024:
        return bytes([SSH_AGENT_FAILURE])
    offset = 5
    kept = []
    total_len = len(resp_bytes)
    for _ in range(nkeys):
        if offset + 4 > total_len:
            return bytes([SSH_AGENT_FAILURE])
        (blob_len,) = struct.unpack(">I", resp_bytes[offset : offset + 4])
        offset += 4
        if offset + blob_len > total_len:
            return bytes([SSH_AGENT_FAILURE])
        blob = resp_bytes[offset : offset + blob_len]
        offset += blob_len

        if offset + 4 > total_len:
            return bytes([SSH_AGENT_FAILURE])
        (comment_len,) = struct.unpack(">I", resp_bytes[offset : offset + 4])
        offset += 4
        if offset + comment_len > total_len:
            return bytes([SSH_AGENT_FAILURE])
        comment = resp_bytes[offset : offset + comment_len]
        offset += comment_len

        if blob.hex().lower() in allowed_blobs:
            kept.append((blob, comment))

    if offset != total_len:
        return bytes([SSH_AGENT_FAILURE])

    out = [bytes([SSH_AGENT_IDENTITIES_ANSWER]), struct.pack(">I", len(kept))]
    for blob, comment in kept:
        out.append(struct.pack(">I", len(blob)))
        out.append(blob)
        out.append(struct.pack(">I", len(comment)))
        out.append(comment)
    return b"".join(out)


def is_allowed_sign_request(msg, allowed_blobs):
    """Validate frame bounds and allowlist membership for SSH_AGENTC_SIGN_REQUEST (13)."""
    if not allowed_blobs or not msg or len(msg) < 13 or msg[0] != SSH_AGENTC_SIGN_REQUEST:
        return False
    (blob_len,) = struct.unpack(">I", msg[1:5])
    if blob_len == 0 or 5 + blob_len + 4 > len(msg):
        return False
    blob = msg[5 : 5 + blob_len]
    (data_len,) = struct.unpack(">I", msg[5 + blob_len : 9 + blob_len])
    if 9 + blob_len + data_len + 4 != len(msg):
        return False
    return blob.hex().lower() in allowed_blobs


def handle_client(client, upstream_sock=UPSTREAM_SOCK, allowlist_file=ALLOWLIST_FILE):
    upstream = None
    try:
        while True:
            msg = recv_msg(client)
            if msg is None:
                break
            opcode = msg[0]
            if opcode == SSH_AGENTC_REQUEST_IDENTITIES:
                if len(msg) != 1:
                    send_msg(client, bytes([SSH_AGENT_FAILURE]))
                    continue
                allowed = load_allowed_blobs(allowlist_file)
                if not allowed:
                    send_msg(client, bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 0))
                    continue
                if upstream is None:
                    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    upstream.connect(upstream_sock)
                send_msg(upstream, msg)
                resp = recv_msg(upstream)
                if resp is None:
                    send_msg(client, bytes([SSH_AGENT_FAILURE]))
                    break
                send_msg(client, filter_identities_answer(resp, allowed))
            elif opcode == SSH_AGENTC_SIGN_REQUEST:
                allowed = load_allowed_blobs(allowlist_file)
                if not is_allowed_sign_request(msg, allowed):
                    send_msg(client, bytes([SSH_AGENT_FAILURE]))
                    continue
                if upstream is None:
                    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    upstream.connect(upstream_sock)
                send_msg(upstream, msg)
                resp = recv_msg(upstream)
                if resp is None:
                    send_msg(client, bytes([SSH_AGENT_FAILURE]))
                    break
                send_msg(client, resp)
            else:
                send_msg(client, bytes([SSH_AGENT_FAILURE]))
    except OSError:
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


def main():
    sock_dir = os.path.dirname(LISTEN_SOCK)
    os.makedirs(sock_dir, mode=0o755, exist_ok=True)
    if os.path.exists(LISTEN_SOCK):
        os.unlink(LISTEN_SOCK)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(LISTEN_SOCK)
    agent_gid = resolve_agent_gid()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(LISTEN_SOCK, 0, agent_gid)
    os.chmod(LISTEN_SOCK, 0o660)
    srv.listen(32)
    print(f"[ssh-agent-proxy] listening on {LISTEN_SOCK} (mode=0660, gid={agent_gid})", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
