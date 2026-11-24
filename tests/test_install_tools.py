import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

try:
    import jsonschema
except ImportError:
    jsonschema = None

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_SCRIPT = os.path.join(REPO_ROOT, "scripts", "linux", "install-tools.sh")
SCHEMA_PATH = os.path.join(REPO_ROOT, "box.schema.json")


def _extract_bash_function(script_text: str, name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", re.MULTILINE | re.DOTALL)
    match = pattern.search(script_text)
    if not match:
        raise AssertionError(f"Could not find bash function {name}() in {INSTALL_SCRIPT}")
    return match.group(0)


class TestDotnetChannelsSchema(unittest.TestCase):
    @unittest.skipIf(jsonschema is None, "jsonschema package not installed")
    def test_schema_validates_dotnet_channels(self):
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            schema = json.load(f)
        with open(os.path.join(REPO_ROOT, "box.json"), encoding="utf-8") as f:
            base_cfg = json.load(f)

        valid_cfg = json.loads(json.dumps(base_cfg))
        valid_cfg["packages"]["dotnetChannels"] = ["8.0", "9.0"]
        jsonschema.validate(instance=valid_cfg, schema=schema)

        for bad in (["8"], ["8.0.1"], ["LTS"], ["8.0", "8.0"], "8.0"):
            bad_cfg = json.loads(json.dumps(base_cfg))
            bad_cfg["packages"]["dotnetChannels"] = bad
            with self.assertRaises(jsonschema.ValidationError, msg=f"Expected failure for {bad!r}"):
                jsonschema.validate(instance=bad_cfg, schema=schema)


@unittest.skipIf(shutil.which("bash") is None, "bash executable is required")
class TestInstallDotnetToolchains(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(INSTALL_SCRIPT, encoding="utf-8") as f:
            script_text = f.read()
        cls.fn_install = _extract_bash_function(script_text, "install_dotnet_toolchains")

    def _run_install(self, policy: dict, initial_sdks=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as f:
                json.dump(policy, f)

            install_dir = os.path.join(tmpdir, "dotnet")
            bin_link = os.path.join(tmpdir, "bin-dotnet")
            mock_bin_dir = os.path.join(tmpdir, "mock-bin")
            os.makedirs(mock_bin_dir, exist_ok=True)
            curl_log = os.path.join(tmpdir, "curl.log")
            installer_log = os.path.join(tmpdir, "installer.log")
            sdks_file = os.path.join(tmpdir, "sdks.txt")

            if initial_sdks:
                os.makedirs(install_dir, exist_ok=True)
                with open(sdks_file, "w", encoding="utf-8") as f:
                    for sdk in initial_sdks:
                        f.write(f"{sdk} [{install_dir}/sdk]\n")
                self._write_mock_dotnet(os.path.join(install_dir, "dotnet"), sdks_file)

            # Mock installer script downloaded by curl
            mock_installer_src = os.path.join(tmpdir, "mock-dotnet-install.sh")
            with open(mock_installer_src, "w", encoding="utf-8") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "set -euo pipefail\n"
                    f'echo "$*" >> "{self._posix_expr(installer_log)}"\n'
                    'channel=""\n'
                    'dest=""\n'
                    'while [[ $# -gt 0 ]]; do\n'
                    '  case "$1" in\n'
                    '    --channel) channel="$2"; shift 2 ;;\n'
                    '    --install-dir) dest="$2"; shift 2 ;;\n'
                    '    *) shift ;;\n'
                    '  esac\n'
                    'done\n'
                    'mkdir -p "${dest}"\n'
                    'if [[ "${channel}" == "LTS" ]]; then ver="10.0.404"; else ver="${channel}.100"; fi\n'
                    f'echo "${{ver}} [${{dest}}/sdk]" >> "{self._posix_expr(sdks_file)}"\n'
                    'cat > "${dest}/dotnet" <<\'DOTNETEOF\'\n'
                    '#!/usr/bin/env bash\n'
                    'if [[ "${1:-}" == "--version" ]]; then echo "10.0.404"; exit 0; fi\n'
                    f'if [[ "${{1:-}}" == "--list-sdks" ]]; then cat "{self._posix_expr(sdks_file)}" 2>/dev/null || true; exit 0; fi\n'
                    'DOTNETEOF\n'
                    'chmod +x "${dest}/dotnet"\n'
                )

            mock_curl = os.path.join(mock_bin_dir, "curl")
            with open(mock_curl, "w", encoding="utf-8") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "set -euo pipefail\n"
                    f'echo "$*" >> "{self._posix_expr(curl_log)}"\n'
                    'out=""\n'
                    'while [[ $# -gt 0 ]]; do\n'
                    '  case "$1" in\n'
                    '    -o) out="$2"; shift 2 ;;\n'
                    '    *) shift ;;\n'
                    '  esac\n'
                    'done\n'
                    f'cp "{self._posix_expr(mock_installer_src)}" "${{out}}"\n'
                )
            os.chmod(mock_curl, 0o755)

            bash_code = "\n".join([
                "set -euo pipefail",
                'log() { echo "[install-tools] $*"; }',
                self.fn_install,
                'p_policy="$1"; p_dir="$2"; p_link="$3"; p_mock="$4"',
                'if command -v wslpath >/dev/null 2>&1; then',
                '  for v in p_policy p_dir p_link p_mock; do',
                '    if [[ "${!v}" == [A-Za-z]:* || "${!v}" == *\\\\* ]]; then',
                '      printf -v "$v" "%s" "$(wslpath -u "${!v}")"',
                '    fi',
                '  done',
                'fi',
                'export PATH="${p_mock}:${PATH}"',
                'install_dotnet_toolchains "${p_policy}" "${p_dir}" "${p_link}" "https://example.invalid/dotnet-install.sh"',
            ])
            proc = subprocess.run(
                ["bash", "-c", bash_code, "_", policy_path, install_dir, bin_link, mock_bin_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            curl_calls = []
            if os.path.exists(curl_log):
                with open(curl_log, encoding="utf-8") as f:
                    curl_calls = f.read().splitlines()
            installer_calls = []
            if os.path.exists(installer_log):
                with open(installer_log, encoding="utf-8") as f:
                    installer_calls = f.read().splitlines()
            return proc.stdout + proc.stderr, curl_calls, installer_calls

    @staticmethod
    def _posix_expr(path: str) -> str:
        if re.match(r"^[A-Za-z]:", path) and shutil.which("wslpath"):
            return subprocess.check_output(["wslpath", "-u", path], text=True).strip()
        return path

    def _write_mock_dotnet(self, path: str, sdks_file: str):
        posix_sdks = self._posix_expr(sdks_file)
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/usr/bin/env bash\n"
                'if [[ "${1:-}" == "--version" ]]; then echo "10.0.404"; exit 0; fi\n'
                f'if [[ "${{1:-}}" == "--list-sdks" ]]; then cat "{posix_sdks}" 2>/dev/null || true; exit 0; fi\n'
            )
        os.chmod(path, 0o755)

    def test_fresh_install_lts_plus_channels_downloads_installer_once(self):
        out, curl_calls, installer_calls = self._run_install(
            {"packages": {"installDotnetSdk": True, "dotnetChannels": ["8.0", "9.0"]}}
        )
        self.assertEqual(len(curl_calls), 1, f"Expected single download, got {curl_calls}")
        self.assertEqual(len(installer_calls), 3, installer_calls)
        self.assertIn("--channel LTS ", installer_calls[0])
        self.assertIn("--channel 8.0 ", installer_calls[1])
        self.assertIn("--channel 9.0 ", installer_calls[2])
        self.assertIn("Installed .NET SDK channel 8.0.", out)

    def test_idempotent_when_channels_already_installed(self):
        out, curl_calls, installer_calls = self._run_install(
            {"packages": {"installDotnetSdk": True, "dotnetChannels": ["8.0"]}},
            initial_sdks=["8.0.428", "10.0.404"],
        )
        self.assertEqual(curl_calls, [])
        self.assertEqual(installer_calls, [])
        self.assertNotIn("Installing additional", out)

    def test_prefix_matching_does_not_collide_between_8_and_18_or_8_00(self):
        _, curl_calls, installer_calls = self._run_install(
            {"packages": {"installDotnetSdk": True, "dotnetChannels": ["8.0"]}},
            initial_sdks=["10.0.404", "18.0.100", "8.00.100"],
        )
        self.assertEqual(len(curl_calls), 1)
        self.assertEqual(len(installer_calls), 1)
        self.assertIn("--channel 8.0 ", installer_calls[0])

    def test_invalid_channels_warn_and_skip_without_blocking_valid_channels(self):
        out, curl_calls, installer_calls = self._run_install(
            {"packages": {"installDotnetSdk": True, "dotnetChannels": ["8", "8.0.1", "LTS", "", "8.0"]}},
            initial_sdks=["10.0.404"],
        )
        self.assertEqual(len(curl_calls), 1)
        self.assertEqual(len(installer_calls), 1)
        self.assertIn("--channel 8.0 ", installer_calls[0])
        self.assertEqual(out.count("WARN: skipping invalid packages.dotnetChannels entry"), 4, out)


if __name__ == "__main__":
    unittest.main()
