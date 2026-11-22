import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT_PATH = os.path.join(REPO_ROOT, "scripts", "linux", "box-sync-context.py")

spec = importlib.util.spec_from_file_location("box_sync_context", SCRIPT_PATH)
box_sync_context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(box_sync_context)


class TestBoxSyncContext(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = self.tmp_dir.name
        self.agent_home = os.path.join(self.root, "home", "agent")
        self.bin_dir = os.path.join(self.root, "bin")
        os.makedirs(self.agent_home, exist_ok=True)
        os.makedirs(self.bin_dir, exist_ok=True)

        self.policy_path = os.path.join(self.root, "policy.json")
        self.policy = {
            "distroName": "wsl-agent-sandbox",
            "agentUser": {"name": "agent", "uid": 26040, "gid": 26040},
            "sharedFolders": [
                {"name": "docs", "windowsPath": "C:\\docs", "mode": "ro", "allowDockerBind": True}
            ],
            "network": {
                "blockHostAndLan": True,
                "egressMode": "open",
                "allowedHostPorts": [{"port": 11434, "protocol": "tcp", "comment": "Ollama"}],
            },
            "docker": {"enabled": True, "allowBindPrefixes": ["/home/agent"]},
        }
        with open(self.policy_path, "w", encoding="utf-8") as f:
            json.dump(self.policy, f)

        self.state_dir = os.path.join(self.agent_home, ".config", "wsl-agent-sandbox")
        self.keys_dir = os.path.join(self.state_dir, "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        self.key_a = os.path.join(self.keys_dir, "gcloud-project-a.json")
        self.key_b = os.path.join(self.keys_dir, "gcloud-project-b.json")
        with open(self.key_a, "w", encoding="utf-8") as f:
            f.write('{"type":"service_account"}')
        with open(self.key_b, "w", encoding="utf-8") as f:
            f.write('{"type":"service_account"}')

        self.seeded_state = {
            "updatedAt": "2026-11-22T22:00:00Z",
            "services": {
                "gcloud": {
                    "defaultProject": "project-a",
                    "profiles": ["project-a", "project-b"],
                    "projectDetails": [
                        {
                            "name": "project-a",
                            "project": "my-gcp-project-a",
                            "clientEmail": "sa-a@my-gcp-project-a.iam.gserviceaccount.com",
                            "region": "europe-north1",
                            "zone": "",
                            "keyPath": self.key_a,
                            "setAdc": True,
                        },
                        {
                            "name": "project-b",
                            "project": "my-gcp-project-b",
                            "clientEmail": "sa-b@my-gcp-project-b.iam.gserviceaccount.com",
                            "region": "europe-west1",
                            "zone": "",
                            "keyPath": self.key_b,
                            "setAdc": True,
                        },
                    ],
                    "updatedAt": "2026-11-22T22:00:00Z",
                },
                "aws": {
                    "profiles": ["default", "staging"],
                    "defaultProfile": "default",
                    "updatedAt": "2026-11-22T22:00:00Z",
                },
                "git": {
                    "mode": "agent-proxy",
                    "hosts": ["github.com"],
                    "keys": ["github-git"],
                    "updatedAt": "2026-11-22T22:00:00Z",
                },
            },
        }
        with open(os.path.join(self.state_dir, "seeded-services.json"), "w", encoding="utf-8") as f:
            json.dump(self.seeded_state, f)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_sync_generates_instructions_skills_and_preserves_custom_markdown(self):
        gemini_md = os.path.join(self.agent_home, ".gemini", "GEMINI.md")
        os.makedirs(os.path.dirname(gemini_md), exist_ok=True)
        with open(gemini_md, "w", encoding="utf-8") as f:
            f.write("# My Custom Agent Notes\nAlways prefer concise code.\n")

        box_sync_context.sync_all(self.policy_path, agent_home_override=self.agent_home, bin_dir=self.bin_dir)

        with open(gemini_md, "r", encoding="utf-8") as f:
            merged_gemini = f.read()
        self.assertIn("# My Custom Agent Notes", merged_gemini)
        self.assertIn(box_sync_context.MARKER_BEGIN, merged_gemini)
        self.assertIn("`project-a` (project=`my-gcp-project-a`", merged_gemini)
        self.assertIn("`project-b` (project=`my-gcp-project-b`", merged_gemini)
        self.assertIn("use-gcloud <name>", merged_gemini)

        for rel_skill in (
            os.path.join(".gemini", "skills", "wsl-agent-sandbox", "SKILL.md"),
            os.path.join(".claude", "skills", "wsl-agent-sandbox", "SKILL.md"),
            os.path.join(".codex", "skills", "wsl-agent-sandbox", "SKILL.md"),
        ):
            skill_path = os.path.join(self.agent_home, rel_skill)
            self.assertTrue(os.path.isfile(skill_path), f"Missing {skill_path}")
            with open(skill_path, "r", encoding="utf-8") as f:
                skill_text = f.read()
            self.assertTrue(skill_text.startswith("---\nname: wsl-agent-sandbox\n"))
            self.assertIn("use-gcloud <name-or-project-id>", skill_text)
            self.assertIn("use-aws <profile-name>", skill_text)

    def test_use_gcloud_and_use_aws_update_active_overrides(self):
        box_sync_context.sync_all(self.policy_path, agent_home_override=self.agent_home, bin_dir=self.bin_dir)
        env = os.environ.copy()
        env["HOME"] = self.agent_home
        env["USERPROFILE"] = self.agent_home

        use_gcloud_bin = os.path.join(self.bin_dir, "use-gcloud")
        res = subprocess.run(
            [sys.executable, use_gcloud_bin, "project-b"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Activated 'project-b'", res.stdout)

        active_cfg = os.path.join(self.agent_home, ".config", "gcloud", "active_config")
        with open(active_cfg, "r", encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "project-b")

        overrides_file = os.path.join(self.state_dir, "active-overrides.env")
        with open(overrides_file, "r", encoding="utf-8") as f:
            overrides_text = f.read()
        self.assertIn("CLOUDSDK_ACTIVE_CONFIG_NAME=", overrides_text)
        self.assertIn("project-b", overrides_text)
        self.assertIn("my-gcp-project-b", overrides_text)

        use_aws_bin = os.path.join(self.bin_dir, "use-aws")
        res_aws = subprocess.run(
            [sys.executable, use_aws_bin, "staging"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("Activated AWS profile 'staging'", res_aws.stdout)
        with open(overrides_file, "r", encoding="utf-8") as f:
            overrides_both = f.read()
        self.assertIn("# >>> gcloud >>>", overrides_both)
        self.assertIn("# >>> aws >>>", overrides_both)
        self.assertIn("AWS_PROFILE=", overrides_both)


if __name__ == "__main__":
    unittest.main()
