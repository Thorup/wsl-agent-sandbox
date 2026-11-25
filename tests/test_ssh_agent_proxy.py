import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "scripts" / "linux" / "ssh-agent-proxy.py"
CTL_SCRIPT_PATH = REPO_ROOT / "scripts" / "linux" / "box-ssh-agent-ctl.sh"
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

    def test_bind_succeeds_when_runtime_dir_already_exists_0755(self):
        tmpdir = tempfile.mkdtemp(prefix="ssh-proxy-rt-")
        sock_dir = os.path.join(tmpdir, "ssh-agent-proxy")
        os.makedirs(sock_dir, mode=0o755, exist_ok=True)
        os.chmod(sock_dir, 0o755)
        listen_sock = os.path.join(sock_dir, "agent.sock")
        orig_listen = ssh_agent_proxy.LISTEN_SOCK
        orig_accept = socket.socket.accept
        try:
            ssh_agent_proxy.LISTEN_SOCK = listen_sock

            class StopLoop(Exception):
                pass

            def stop_accept(self_sock):
                self_sock.close()
                raise StopLoop()

            socket.socket.accept = stop_accept
            with self.assertRaises(StopLoop):
                ssh_agent_proxy.main()
            self.assertTrue(os.path.exists(listen_sock))
            self.assertEqual(os.stat(listen_sock).st_mode & 0o777, 0o660)
        finally:
            socket.socket.accept = orig_accept
            ssh_agent_proxy.LISTEN_SOCK = orig_listen
            if os.path.exists(listen_sock):
                os.unlink(listen_sock)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ctl_script_syntax_and_idempotent_lifecycle(self):
        self.assertTrue(CTL_SCRIPT_PATH.is_file(), f"Missing {CTL_SCRIPT_PATH}")
        bash_check = subprocess.run(["bash", "-n", str(CTL_SCRIPT_PATH)], capture_output=True, text=True)
        self.assertEqual(bash_check.returncode, 0, f"bash -n failed: {bash_check.stderr}")

        if shutil.which("shellcheck"):
            sc = subprocess.run(["shellcheck", str(CTL_SCRIPT_PATH)], capture_output=True, text=True)
            self.assertEqual(sc.returncode, 0, f"shellcheck failed: {sc.stdout}\n{sc.stderr}")

        if not shutil.which("ssh-keygen") or not shutil.which("ssh-agent") or not shutil.which("ssh-add"):
            self.skipTest("OpenSSH tools (ssh-keygen/ssh-agent/ssh-add) not available")

        tmpdir = tempfile.mkdtemp(prefix="ssh-ctl-test-")
        try:
            key_path = os.path.join(tmpdir, "id_test")
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key_path, "-q"],
                check=True,
            )
            with open(key_path, "r", encoding="utf-8") as kf:
                priv_pem = kf.read()

            keys_file = os.path.join(tmpdir, "ssh-agent-keys.json")
            allowlist_file = os.path.join(tmpdir, "ssh-agent-allowlist.json")
            agent_dir = os.path.join(tmpdir, "box-root", "ssh-agent")
            upstream_sock = os.path.join(agent_dir, "upstream.sock")

            with open(keys_file, "w", encoding="utf-8") as f:
                json.dump({"services": {"git": [{"name": "id_test", "privateKey": priv_pem}]}}, f)
            with open(allowlist_file, "w", encoding="utf-8") as f:
                json.dump({"allowedKeyBlobsHex": []}, f)

            env = dict(
                os.environ,
                SSH_AGENT_KEYS_FILE=keys_file,
                SSH_AGENT_ALLOWLIST_FILE=allowlist_file,
                SSH_AGENT_DIR=agent_dir,
                SSH_AGENT_UPSTREAM_SOCK=upstream_sock,
            )

            # First ensure-upstream starts ssh-agent and loads key
            p1 = subprocess.run(["bash", str(CTL_SCRIPT_PATH), "ensure-upstream"], env=env, capture_output=True, text=True)
            self.assertEqual(p1.returncode, 0, f"ensure-upstream #1 failed: {p1.stderr}")
            self.assertTrue(os.path.exists(upstream_sock))

            # Second ensure-upstream is idempotent
            p2 = subprocess.run(["bash", str(CTL_SCRIPT_PATH), "ensure-upstream"], env=env, capture_output=True, text=True)
            self.assertEqual(p2.returncode, 0, f"ensure-upstream #2 failed: {p2.stderr}")

            # Verify exactly 1 key loaded
            ls_proc = subprocess.run(
                ["ssh-add", "-l"],
                env=dict(env, SSH_AUTH_SOCK=upstream_sock),
                capture_output=True,
                text=True,
            )
            self.assertEqual(ls_proc.returncode, 0, f"ssh-add -l failed: {ls_proc.stderr}")
            self.assertEqual(len([line for line in ls_proc.stdout.splitlines() if line.strip()]), 1)

            # stop-upstream cleans up socket, keys file, allowlist file, and agent
            p3 = subprocess.run(["bash", str(CTL_SCRIPT_PATH), "stop-upstream"], env=env, capture_output=True, text=True)
            self.assertEqual(p3.returncode, 0, f"stop-upstream failed: {p3.stderr}")
            self.assertFalse(os.path.exists(upstream_sock))
            self.assertFalse(os.path.exists(keys_file))
            self.assertFalse(os.path.exists(allowlist_file))
        finally:
            subprocess.run(["pkill", "-f", os.path.join(tmpdir, "box-root", "ssh-agent", "upstream.sock")], check=False)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ctl_ensure_upstream_fails_when_allowlist_has_blobs_but_keys_missing(self):
        tmpdir = tempfile.mkdtemp(prefix="ssh-proxy-ctl-missing-")
        try:
            keys_file = os.path.join(tmpdir, "ssh-agent-keys.json")
            allowlist_file = os.path.join(tmpdir, "ssh-agent-allowlist.json")
            agent_dir = os.path.join(tmpdir, "box-root", "ssh-agent")
            upstream_sock = os.path.join(agent_dir, "upstream.sock")

            with open(allowlist_file, "w", encoding="utf-8") as f:
                json.dump({"allowedKeyBlobsHex": ["deadbeef"]}, f)

            env = dict(
                os.environ,
                SSH_AGENT_KEYS_FILE=keys_file,
                SSH_AGENT_ALLOWLIST_FILE=allowlist_file,
                SSH_AGENT_DIR=agent_dir,
                SSH_AGENT_UPSTREAM_SOCK=upstream_sock,
            )

            proc = subprocess.run(["bash", str(CTL_SCRIPT_PATH), "ensure-upstream"], env=env, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("seed-secrets", proc.stderr)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
