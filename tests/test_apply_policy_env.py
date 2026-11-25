import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPLY_POLICY_SH = os.path.join(REPO_ROOT, "scripts", "linux", "apply-policy.sh")
BOX_HARDENING_SH = os.path.join(REPO_ROOT, "scripts", "linux", "box-hardening.sh")
INSTALL_TOOLS_SH = os.path.join(REPO_ROOT, "scripts", "linux", "install-tools.sh")
UPGRADE_TOOLS_SH = os.path.join(REPO_ROOT, "scripts", "linux", "upgrade-tools.sh")


@unittest.skipIf(shutil.which("bash") is None, "bash executable is required")
class TestApplyPolicyEnv(unittest.TestCase):
    def _run_render_env(self, policy: dict, host_ips_text: str, mock_gateway: str | None = None):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.json")
            host_ips_path = os.path.join(tmpdir, "host_ips.txt")
            profile_path = os.path.join(tmpdir, "99-agent-box.sh")
            env_path = os.path.join(tmpdir, "environment")
            mock_bin = os.path.join(tmpdir, "mock-bin")
            os.makedirs(mock_bin, exist_ok=True)

            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump(policy, f)
            with open(host_ips_path, "w", encoding="utf-8") as f:
                f.write(host_ips_text)

            mock_ip = os.path.join(mock_bin, "ip")
            with open(mock_ip, "w", encoding="utf-8") as f:
                if mock_gateway:
                    f.write(f"#!/usr/bin/env bash\necho 'default via {mock_gateway} dev eth0 proto kernel'\n")
                else:
                    f.write("#!/usr/bin/env bash\nexit 0\n")
            os.chmod(mock_ip, 0o755)

            env = os.environ.copy()
            env["PATH"] = f"{mock_bin}:{env.get('PATH', '')}"

            bash_cmd = (
                f'source "{APPLY_POLICY_SH}" && '
                f'render_agent_env "{policy_path}" "{host_ips_path}" "{profile_path}" "{env_path}"'
            )
            res = subprocess.run(["bash", "-c", bash_cmd], env=env, text=True, capture_output=True)
            self.assertEqual(res.returncode, 0, f"stderr: {res.stderr}")

            with open(profile_path, encoding="utf-8") as f:
                profile_content = f.read()
            with open(env_path, encoding="utf-8") as f:
                env_content = f.read()

            leftover_tmps = [name for name in os.listdir(tmpdir) if ".tmp." in name]
            self.assertEqual(leftover_tmps, [], f"Expected no leftover temp files, found: {leftover_tmps}")
            return profile_content, env_content

    def test_open_mode_omits_proxy_and_no_proxy(self):
        policy = {"network": {"egressMode": "open", "allowedHostPorts": [{"port": 11434, "protocol": "tcp"}]}}
        profile, env_file = self._run_render_env(policy, "172.24.160.1\n", mock_gateway="172.24.160.1")
        for content in (profile, env_file):
            self.assertNotIn("HTTP_PROXY=", content)
            self.assertNotIn("NO_PROXY=", content)
            self.assertNotIn("no_proxy=", content)

    def test_allowlist_without_allowed_host_ports_sets_both_no_proxy_cases(self):
        policy = {"network": {"egressMode": "allowlist", "allowedHostPorts": []}}
        profile, env_file = self._run_render_env(policy, "172.24.160.1\n", mock_gateway="172.24.160.1")
        expected = "localhost,127.0.0.1,::1"
        self.assertIn(f'export NO_PROXY="{expected}"', profile)
        self.assertIn(f'export no_proxy="{expected}"', profile)
        self.assertIn(f'NO_PROXY="{expected}"', env_file)
        self.assertIn(f'no_proxy="{expected}"', env_file)

    def test_allowlist_with_allowed_host_ports_appends_deduped_ipv4_hosts(self):
        policy = {
            "network": {
                "egressMode": "allowlist",
                "allowedHostPorts": [{"port": 11434, "protocol": "tcp"}],
            }
        }
        host_ips = "# comment\n127.0.0.1\n::1\nfe80::1%eth0\n192.168.1.50\n172.24.160.1\n192.168.1.50\n"
        profile, env_file = self._run_render_env(policy, host_ips, mock_gateway="172.24.160.1")
        expected = "localhost,127.0.0.1,::1,192.168.1.50,172.24.160.1"
        self.assertIn(f'export NO_PROXY="{expected}"', profile)
        self.assertIn(f'export no_proxy="{expected}"', profile)
        self.assertIn(f'NO_PROXY="{expected}"', env_file)
        self.assertIn(f'no_proxy="{expected}"', env_file)

    def test_allowlist_uses_deterministic_per_uid_egress_proxy_port(self):
        for uid, expected_port in ((26040, 3128), (26100, 30900), (27005, 29410)):
            policy = {
                "agentUser": {"name": "agent", "uid": uid, "gid": uid},
                "network": {"egressMode": "allowlist", "allowedHostPorts": []},
            }
            profile, env_file = self._run_render_env(policy, "")
            self.assertIn(f'export HTTP_PROXY="http://127.0.0.1:{expected_port}"', profile)
            self.assertIn(f'export https_proxy="http://127.0.0.1:{expected_port}"', profile)
            self.assertIn(f'HTTP_PROXY="http://127.0.0.1:{expected_port}"', env_file)
            self.assertIn(f'https_proxy="http://127.0.0.1:{expected_port}"', env_file)


@unittest.skipIf(shutil.which("bash") is None, "bash executable is required")
class TestBoxHardeningMaintenanceEgress(unittest.TestCase):
    def _render_nft(self, maintenance_open: bool) -> str:
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.json")
            host_ips_path = os.path.join(tmpdir, "host_ips.txt")
            resolv_path = os.path.join(tmpdir, "resolv.conf")
            nft_path = os.path.join(tmpdir, "nftables.conf")

            policy = {
                "distroName": "Ubuntu-Test",
                "agentUser": {"name": "agent", "uid": 26040, "gid": 26040},
                "network": {
                    "egressMode": "allowlist",
                    "blockHostAndLan": True,
                    "logDrops": False,
                    "blockedCidrs": ["10.0.0.0/8", "192.168.0.0/16"],
                    "allowedHostPorts": [],
                },
            }
            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump(policy, f)
            with open(host_ips_path, "w", encoding="utf-8") as f:
                f.write("172.24.160.1\n")
            with open(resolv_path, "w", encoding="utf-8") as f:
                f.write("nameserver 10.255.255.254\n")

            env = os.environ.copy()
            env["BOX_RESOLV_CONF"] = resolv_path
            if maintenance_open:
                env["BOX_MAINTENANCE_EGRESS_OPEN"] = "1"
            else:
                env.pop("BOX_MAINTENANCE_EGRESS_OPEN", None)

            res = subprocess.run(
                ["bash", BOX_HARDENING_SH, "--dry-run-nft", policy_path, host_ips_path, nft_path],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(res.returncode, 0, f"stderr: {res.stderr}")
            with open(nft_path, encoding="utf-8") as f:
                return f.read()

    def test_strict_allowlist_drops_dns_and_all_direct_egress(self):
        nft = self._render_nft(maintenance_open=False)
        self.assertNotIn("udp dport 53 accept", nft)
        self.assertNotIn("tcp dport 53 accept", nft)
        self.assertIn('oifname "loopback0" drop', nft)
        self.assertIn("172.24.160.1", nft)
        self.assertIn("\n        drop\n", nft)

    def test_maintenance_egress_open_keeps_block_host_and_lan_and_allows_dns(self):
        nft = self._render_nft(maintenance_open=True)
        self.assertIn("ip daddr { 10.255.255.254 } udp dport 53 accept", nft)
        self.assertIn("ip daddr { 10.255.255.254 } tcp dport 53 accept", nft)
        self.assertIn('oifname "loopback0" drop', nft)
        self.assertIn("172.24.160.1", nft)
        self.assertIn("10.0.0.0/8", nft)
        self.assertNotIn("\n        drop\n", nft)

    def test_scripts_ordering_and_proxy_unset_contracts(self):
        with open(APPLY_POLICY_SH, encoding="utf-8") as f:
            apply_sh = f.read()
        with open(INSTALL_TOOLS_SH, encoding="utf-8") as f:
            install_sh = f.read()
        with open(UPGRADE_TOOLS_SH, encoding="utf-8") as f:
            upgrade_sh = f.read()

        open_pos = apply_sh.find("BOX_MAINTENANCE_EGRESS_OPEN=1 /usr/local/sbin/box-hardening.sh")
        install_pos = apply_sh.find("/usr/local/sbin/box-install-tools.sh")
        restore_pos = apply_sh.rfind("/usr/local/sbin/box-hardening.sh")
        self.assertGreater(open_pos, -1)
        self.assertGreater(install_pos, open_pos)
        self.assertGreater(restore_pos, install_pos)

        self.assertIn("unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy", install_sh)
        self.assertIn("unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy", upgrade_sh)
        self.assertIn("BOX_MAINTENANCE_EGRESS_OPEN=1 /usr/local/sbin/box-hardening.sh", upgrade_sh)


if __name__ == "__main__":
    unittest.main()
