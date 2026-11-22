import importlib.util
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "linux" / "ssh-agent-proxy.py"
spec = importlib.util.spec_from_file_location("ssh_agent_proxy", MODULE_PATH)
ssh_agent_proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh_agent_proxy)


def pack_str(b):
    return struct.pack(">I", len(b)) + b


class SshAgentProxyTests(unittest.TestCase):
    def test_missing_or_corrupt_allowlist_fails_closed(self):
        self.assertEqual(ssh_agent_proxy.load_allowed_blobs("/nonexistent/allowlist.json"), set())
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("{corrupt")
            p = f.name
        try:
            self.assertEqual(ssh_agent_proxy.load_allowed_blobs(p), set())
        finally:
            os.unlink(p)

    def test_identities_filtering_sign_allowlist_and_malformed_frames(self):
        blob_allowed = b"ssh-ed25519-allowed-key-blob"
        blob_forbidden = b"ssh-ed25519-forbidden-key-blob"
        signature_blob = b"valid-ssh-signature-bytes"

        tmpdir = tempfile.mkdtemp(prefix="ssh-proxy-test-")
        up_sock_path = os.path.join(tmpdir, "up.sock")
        proxy_sock_path = os.path.join(tmpdir, "proxy.sock")
        allowlist_path = os.path.join(tmpdir, "allowlist.json")

        up_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        up_srv.bind(up_sock_path)
        up_srv.listen(8)

        def upstream_loop():
            while True:
                try:
                    conn, _ = up_srv.accept()
                except OSError:
                    break
                try:
                    while True:
                        msg = ssh_agent_proxy.recv_msg(conn)
                        if msg is None:
                            break
                        if msg[0] == ssh_agent_proxy.SSH_AGENTC_REQUEST_IDENTITIES:
                            ans = (
                                bytes([ssh_agent_proxy.SSH_AGENT_IDENTITIES_ANSWER])
                                + struct.pack(">I", 2)
                                + pack_str(blob_allowed)
                                + pack_str(b"allowed@box")
                                + pack_str(blob_forbidden)
                                + pack_str(b"forbidden@box")
                            )
                            ssh_agent_proxy.send_msg(conn, ans)
                        elif msg[0] == ssh_agent_proxy.SSH_AGENTC_SIGN_REQUEST:
                            ssh_agent_proxy.send_msg(conn, bytes([14]) + pack_str(signature_blob))
                        else:
                            ssh_agent_proxy.send_msg(conn, bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]))
                finally:
                    conn.close()

        threading.Thread(target=upstream_loop, daemon=True).start()

        proxy_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        proxy_srv.bind(proxy_sock_path)
        proxy_srv.listen(8)

        def proxy_loop():
            while True:
                try:
                    conn, _ = proxy_srv.accept()
                except OSError:
                    break
                threading.Thread(
                    target=ssh_agent_proxy.handle_client,
                    args=(conn, up_sock_path, allowlist_path),
                    daemon=True,
                ).start()

        threading.Thread(target=proxy_loop, daemon=True).start()

        def rpc(payload):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                c.settimeout(3.0)
                c.connect(proxy_sock_path)
                ssh_agent_proxy.send_msg(c, payload)
                return ssh_agent_proxy.recv_msg(c)

        try:
            # 1. Fail-closed when allowlist file does not exist yet
            resp_no_al = rpc(bytes([ssh_agent_proxy.SSH_AGENTC_REQUEST_IDENTITIES]))
            self.assertEqual(resp_no_al, bytes([ssh_agent_proxy.SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]))

            sign_allowed_msg = (
                bytes([ssh_agent_proxy.SSH_AGENTC_SIGN_REQUEST])
                + pack_str(blob_allowed)
                + pack_str(b"commit-payload")
                + struct.pack(">I", 0)
            )
            self.assertEqual(rpc(sign_allowed_msg), bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]))

            # 2. Write allowlist authorizing only blob_allowed
            with open(allowlist_path, "w", encoding="utf-8") as f:
                json.dump({"allowedKeyBlobsHex": [blob_allowed.hex().upper()]}, f)

            # REQUEST_IDENTITIES must filter out blob_forbidden
            resp_ids = rpc(bytes([ssh_agent_proxy.SSH_AGENTC_REQUEST_IDENTITIES]))
            self.assertEqual(resp_ids[0], ssh_agent_proxy.SSH_AGENT_IDENTITIES_ANSWER)
            (count,) = struct.unpack(">I", resp_ids[1:5])
            self.assertEqual(count, 1)
            self.assertIn(blob_allowed, resp_ids)
            self.assertNotIn(blob_forbidden, resp_ids)

            # SIGN_REQUEST for allowlisted blob succeeds (opcode 14)
            resp_sign_ok = rpc(sign_allowed_msg)
            self.assertEqual(resp_sign_ok[0], 14)
            self.assertIn(signature_blob, resp_sign_ok)

            # SIGN_REQUEST for non-allowlisted blob is denied (SSH_AGENT_FAILURE = 5)
            sign_forbidden_msg = (
                bytes([ssh_agent_proxy.SSH_AGENTC_SIGN_REQUEST])
                + pack_str(blob_forbidden)
                + pack_str(b"commit-payload")
                + struct.pack(">I", 0)
            )
            self.assertEqual(rpc(sign_forbidden_msg), bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]))

            # 3. Malformed SIGN_REQUEST frames (< 5 bytes or truncated blob_len) are rejected (5)
            self.assertEqual(
                rpc(bytes([ssh_agent_proxy.SSH_AGENTC_SIGN_REQUEST, 0, 1])),
                bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]),
            )
            truncated_blob_msg = bytes([ssh_agent_proxy.SSH_AGENTC_SIGN_REQUEST]) + struct.pack(">I", 9999) + b"short"
            self.assertEqual(rpc(truncated_blob_msg), bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]))

            # 4. Mutating opcodes (SSH_AGENTC_ADD_IDENTITY=17, REMOVE_ALL=19) are rejected (5)
            self.assertEqual(rpc(bytes([17, 0, 0, 0, 0])), bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]))
            self.assertEqual(rpc(bytes([19])), bytes([ssh_agent_proxy.SSH_AGENT_FAILURE]))
        finally:
            proxy_srv.close()
            up_srv.close()
            for p in (up_sock_path, proxy_sock_path, allowlist_path):
                if os.path.exists(p):
                    os.unlink(p)
            os.rmdir(tmpdir)


if __name__ == "__main__":
    unittest.main()
