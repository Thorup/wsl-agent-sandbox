import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED_SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "linux", "box-seed-secrets.sh")
HARDENING_SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "linux", "box-hardening.sh")


def load_seed_secrets_namespace(policy_path, argv):
    """Extract and execute the embedded Python heredoc from box-seed-secrets.sh up to mode dispatch."""
    with open(SEED_SCRIPT_PATH, "r", encoding="utf-8") as f:
        sh_text = f.read()
    match = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF\b", sh_text, re.DOTALL)
    if not match:
        raise RuntimeError("Could not locate PYEOF heredoc in box-seed-secrets.sh")
    py_code = match.group(1)

    # Split right before `# Modes:` so we can configure temp paths before running modes,
    # or execute the whole script with mocked sys.argv / paths.
    marker = "# ------------------------------------------------------------------\n# Modes:"
    idx = py_code.index(marker)
    defs_code = py_code[:idx]

    ns = {"__name__": "__box_seed_secrets_test__"}
    with mock.patch("sys.argv", ["box-seed-secrets.sh", policy_path] + argv):
        exec(compile(defs_code, SEED_SCRIPT_PATH, "exec"), ns)
    return ns, py_code[idx:]


class TestTtlSweepAndPersistentTimers(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = self.tmp_dir.name
        self.agent_home = os.path.join(self.root, "home", "agent")
        self.state_dir = os.path.join(self.agent_home, ".config", "wsl-agent-sandbox")
        self.keys_dir = os.path.join(self.state_dir, "keys")
        self.env_d_dir = os.path.join(self.state_dir, "env.d")
        self.systemd_dir = os.path.join(self.root, "etc", "systemd", "system")
        self.wants_dir = os.path.join(self.systemd_dir, "timers.target.wants")
        self.etc_dir = os.path.join(self.root, "etc", "wsl-agent-sandbox")
        self.run_ssh_dir = os.path.join(self.root, "run", "box-root", "ssh-agent")

        for d in (self.agent_home, self.state_dir, self.keys_dir, self.env_d_dir, self.systemd_dir, self.wants_dir, self.etc_dir):
            os.makedirs(d, exist_ok=True)

        self.policy_path = os.path.join(self.etc_dir, "policy.json")
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000
        with open(self.policy_path, "w", encoding="utf-8") as f:
            json.dump({"agentUser": {"name": "agent", "uid": uid, "gid": gid}}, f)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _configure_ns(self, ns):
        ns["AGENT_HOME"] = self.agent_home
        ns["STATE_DIR"] = self.state_dir
        ns["KEYS_DIR"] = self.keys_dir
        ns["ENV_D_DIR"] = self.env_d_dir
        ns["SECRETS_ENV_FILE"] = os.path.join(self.state_dir, "secrets.env")
        ns["STATE_FILE"] = os.path.join(self.state_dir, "seeded-services.json")
        ns["PROXY_CFG_FILE"] = os.path.join(self.etc_dir, "credential-proxy.json")
        ns["SYSTEMD_UNIT_DIR"] = self.systemd_dir
        ns["SSH_AGENT_DIR"] = self.run_ssh_dir
        ns["SSH_AGENT_UPSTREAM_SOCK"] = os.path.join(self.run_ssh_dir, "upstream.sock")
        ns["SSH_AGENT_STATE_FILE"] = os.path.join(self.run_ssh_dir, "root-keys.json")
        ns["SSH_AGENT_ALLOWLIST_FILE"] = os.path.join(self.etc_dir, "ssh-agent-allowlist.json")
        ns["SSH_AGENT_ENV_FILE"] = os.path.join(self.env_d_dir, "90-ssh-agent-proxy.env")

    def test_sweep_expired_clears_only_expired_services(self):
        ns, _ = load_seed_secrets_namespace(self.policy_path, ["--sweep-expired"])
        self._configure_ns(ns)

        # Seed mock files for 'upcloud' (expired) and 'env' (active)
        with open(os.path.join(self.env_d_dir, "upcloud.env"), "w", encoding="utf-8") as f:
            f.write('export UPCLOUD_TOKEN="ucat_expired"\n')
        with open(os.path.join(self.env_d_dir, "env.env"), "w", encoding="utf-8") as f:
            f.write('export ACTIVE_VAR="still_valid"\n')
        ns["rebuild_secrets_env"]()

        # Add credential-proxy route for expired service and active service
        with open(ns["PROXY_CFG_FILE"], "w", encoding="utf-8") as f:
            json.dump({"routes": {"upcloud": {"upstream": "https://api.upcloud.com"}, "env": {"upstream": "https://example.com"}}}, f)

        # Create persistent timer/service files for expired service
        for suffix in (".timer", ".service"):
            with open(os.path.join(self.systemd_dir, f"wsl-box-ttl-upcloud{suffix}"), "w", encoding="utf-8") as f:
                f.write("[Unit]\nDescription=test\n")
        with open(os.path.join(self.wants_dir, "wsl-box-ttl-upcloud.timer"), "w", encoding="utf-8") as f:
            f.write("[Unit]\n")

        state = {
            "updatedAt": "2020-01-01T00:00:00Z",
            "services": {
                "upcloud": {
                    "envVars": ["UPCLOUD_TOKEN"],
                    "updatedAt": "2020-01-01T00:00:00Z",
                    "expiresAt": "2020-01-01T00:00:00Z",
                },
                "env": {
                    "envVars": ["ACTIVE_VAR"],
                    "updatedAt": "2026-01-01T00:00:00Z",
                    "expiresAt": "2099-01-01T00:00:00Z",
                },
            },
        }
        with open(ns["STATE_FILE"], "w", encoding="utf-8") as f:
            json.dump(state, f)

        orig_isdir = os.path.isdir
        orig_isfile = os.path.isfile
        stdout = io.StringIO()
        with mock.patch("os.path.isdir", side_effect=lambda p: False if p == "/run/systemd/system" else orig_isdir(p)), \
             mock.patch("os.path.isfile", side_effect=lambda p: False if p == "/usr/local/sbin/box-sync-context.py" else orig_isfile(p)), \
             mock.patch("os.chown", create=True), \
             mock.patch("os.fchown", create=True), \
             contextlib.redirect_stdout(stdout):
            expired = ns["sweep_expired_services"]()

        self.assertEqual(expired, ["upcloud"])
        self.assertIn("[EXPIRED] Auto-cleared expired credentials for upcloud", stdout.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self.env_d_dir, "upcloud.env")))
        self.assertTrue(os.path.exists(os.path.join(self.env_d_dir, "env.env")))

        # Persistent timer/service files for expired service must be removed
        self.assertFalse(os.path.exists(os.path.join(self.systemd_dir, "wsl-box-ttl-upcloud.timer")))
        self.assertFalse(os.path.exists(os.path.join(self.systemd_dir, "wsl-box-ttl-upcloud.service")))
        self.assertFalse(os.path.exists(os.path.join(self.wants_dir, "wsl-box-ttl-upcloud.timer")))

        # secrets.env must no longer contain UPCLOUD_TOKEN, but still contain ACTIVE_VAR
        with open(ns["SECRETS_ENV_FILE"], "r", encoding="utf-8") as f:
            secrets_env = f.read()
        self.assertNotIn("UPCLOUD_TOKEN", secrets_env)
        self.assertIn("ACTIVE_VAR", secrets_env)

        # credential-proxy.json must only have 'env' left
        with open(ns["PROXY_CFG_FILE"], "r", encoding="utf-8") as f:
            routes = json.load(f)["routes"]
        self.assertNotIn("upcloud", routes)
        self.assertIn("env", routes)

        # seeded-services.json must only have 'env' left
        with open(ns["STATE_FILE"], "r", encoding="utf-8") as f:
            new_state = json.load(f)
        self.assertNotIn("upcloud", new_state["services"])
        self.assertIn("env", new_state["services"])

    def test_status_proactively_sweeps_expired_services(self):
        ns, modes_code = load_seed_secrets_namespace(self.policy_path, ["--status"])
        self._configure_ns(ns)

        with open(os.path.join(self.env_d_dir, "upcloud.env"), "w", encoding="utf-8") as f:
            f.write('export UPCLOUD_TOKEN="ucat_expired"\n')
        with open(ns["STATE_FILE"], "w", encoding="utf-8") as f:
            json.dump({
                "updatedAt": "2020-01-01T00:00:00Z",
                "services": {
                    "upcloud": {
                        "envVars": ["UPCLOUD_TOKEN"],
                        "updatedAt": "2020-01-01T00:00:00Z",
                        "expiresAt": "2020-01-01T00:00:00Z",
                    }
                },
            }, f)

        orig_isdir = os.path.isdir
        orig_isfile = os.path.isfile
        stdout = io.StringIO()
        with mock.patch("os.path.isdir", side_effect=lambda p: False if p == "/run/systemd/system" else orig_isdir(p)), \
             mock.patch("os.path.isfile", side_effect=lambda p: False if p == "/usr/local/sbin/box-sync-context.py" else orig_isfile(p)), \
             mock.patch("os.chown", create=True), \
             mock.patch("os.fchown", create=True), \
             contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as cm:
                exec(compile(modes_code, SEED_SCRIPT_PATH, "exec"), ns)
        self.assertEqual(cm.exception.code, 0)
        out = stdout.getvalue()
        self.assertIn("[EXPIRED] Auto-cleared expired credentials for upcloud", out)
        self.assertIn("(none)", out)
        self.assertFalse(os.path.exists(ns["STATE_FILE"]))

    def test_persistent_ttl_units_rendered_and_cancelled(self):
        ns, _ = load_seed_secrets_namespace(self.policy_path, ["--status"])
        self._configure_ns(ns)

        with self.assertRaises(ValueError):
            ns["install_ttl_timer"]("../evil", 60)

        systemctl_calls = []

        def fake_run(cmd, **kwargs):
            systemctl_calls.append(cmd)
            res = mock.MagicMock()
            res.returncode = 0
            res.stdout = ""
            res.stderr = ""
            return res

        with mock.patch("os.path.isdir", side_effect=lambda p: True if p == "/run/systemd/system" else os.path.exists(p)), \
             mock.patch("subprocess.run", side_effect=fake_run):
            exp_dt = ns["install_ttl_timer"]("github", 3600)

        self.assertIsNotNone(exp_dt)
        svc_path = os.path.join(self.systemd_dir, "wsl-box-ttl-github.service")
        tmr_path = os.path.join(self.systemd_dir, "wsl-box-ttl-github.timer")
        self.assertTrue(os.path.isfile(svc_path))
        self.assertTrue(os.path.isfile(tmr_path))

        with open(svc_path, "r", encoding="utf-8") as f:
            svc_text = f.read()
        with open(tmr_path, "r", encoding="utf-8") as f:
            tmr_text = f.read()

        self.assertIn("Type=oneshot", svc_text)
        self.assertIn("Environment=WSL_BOX_TTL_ACTIVE_UNIT=wsl-box-ttl-github.service", svc_text)
        self.assertIn("ExecStart=/usr/local/sbin/box-seed-secrets.sh --clear --services github", svc_text)
        self.assertIn("Persistent=true", tmr_text)
        self.assertIn("AccuracySec=1s", tmr_text)
        self.assertRegex(tmr_text, r"OnCalendar=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")
        self.assertIn("WantedBy=timers.target", tmr_text)
        self.assertEqual(
            systemctl_calls,
            [
                ["systemctl", "daemon-reload"],
                ["systemctl", "enable", "--now", "wsl-box-ttl-github.timer"],
            ],
        )

        # Simulate self-invocation from wsl-box-ttl-github.service:
        # Must NOT stop wsl-box-ttl-github.service, MUST still remove both unit files.
        systemctl_calls.clear()
        with open(os.path.join(self.wants_dir, "wsl-box-ttl-github.timer"), "w", encoding="utf-8") as f:
            f.write("[Unit]\n")
        with mock.patch.dict(os.environ, {"WSL_BOX_TTL_ACTIVE_UNIT": "wsl-box-ttl-github.service"}), \
             mock.patch("os.path.isdir", side_effect=lambda p: True if p == "/run/systemd/system" else os.path.exists(p)), \
             mock.patch("subprocess.run", side_effect=fake_run):
            ns["cancel_ttl_timer"]("github")

        self.assertFalse(os.path.exists(svc_path))
        self.assertFalse(os.path.exists(tmr_path))
        self.assertFalse(os.path.exists(os.path.join(self.wants_dir, "wsl-box-ttl-github.timer")))
        self.assertNotIn(["systemctl", "stop", "wsl-box-ttl-github.service"], systemctl_calls)
        self.assertIn(["systemctl", "disable", "--now", "wsl-box-ttl-github.timer"], systemctl_calls)
        self.assertIn(["systemctl", "daemon-reload"], systemctl_calls)

    def test_box_hardening_runs_sweep_expired_on_boot(self):
        with open(HARDENING_SCRIPT_PATH, "r", encoding="utf-8") as f:
            hardening = f.read()
        self.assertIn("/usr/local/sbin/box-seed-secrets.sh --sweep-expired", hardening)


if __name__ == "__main__":
    unittest.main()
