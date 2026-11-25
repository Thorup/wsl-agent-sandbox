import os
import re
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFY_SCRIPT = os.path.join(REPO_ROOT, "scripts", "linux", "verify-isolation.sh")


def _extract_bash_function(script_text: str, name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", re.MULTILINE | re.DOTALL)
    match = pattern.search(script_text)
    if not match:
        raise AssertionError(f"Could not find bash function {name}() in {VERIFY_SCRIPT}")
    return match.group(0)


@unittest.skipIf(shutil.which("bash") is None, "bash executable is required")
class TestVerifyIsolationWSLInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VERIFY_SCRIPT, encoding="utf-8") as f:
            script_text = f.read()
        cls.fn_interop = _extract_bash_function(script_text, "interop_disabled_in_wslconf")
        cls.fn_check = _extract_bash_function(script_text, "check_wslinterop_binfmt")

    def _run_check(self, binfmt_exists: bool, wslconf_content):
        with tempfile.TemporaryDirectory() as tmpdir:
            binfmt_path = os.path.join(tmpdir, "WSLInterop")
            if binfmt_exists:
                with open(binfmt_path, "w", encoding="utf-8") as f:
                    f.write("enabled\ninterpreter /init\n")

            conf_path = os.path.join(tmpdir, "wsl.conf")
            if wslconf_content is not None:
                with open(conf_path, "wb") as f:
                    f.write(wslconf_content.encode("utf-8"))

            # On Windows, convert paths for WSL bash if bash is WSL bash, or use POSIX paths directly on Linux.
            bash_code = "\n".join([
                "set -u",
                "PASS=0; FAIL=0; WARN=0",
                'pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }',
                'fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }',
                'warn() { echo "  [WARN] $*"; WARN=$((WARN + 1)); }',
                self.fn_interop,
                self.fn_check,
                'binfmt_path="$1"',
                'conf_path="$2"',
                'if command -v wslpath >/dev/null 2>&1; then',
                '  if [[ "${binfmt_path}" == [A-Za-z]:* || "${binfmt_path}" == *\\\\* ]]; then',
                '    binfmt_path="$(wslpath -u "${binfmt_path}")"',
                '  fi',
                '  if [[ "${conf_path}" == [A-Za-z]:* || "${conf_path}" == *\\\\* ]]; then',
                '    conf_path="$(wslpath -u "${conf_path}")"',
                '  fi',
                'fi',
                'check_wslinterop_binfmt "${binfmt_path}" "${conf_path}"',
                'echo "COUNTS:${PASS}:${FAIL}:${WARN}"',
            ])
            proc = subprocess.run(
                ["bash", "-c", bash_code, "_", binfmt_path, conf_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"bash failed: {proc.stderr}\n{proc.stdout}")
            lines = proc.stdout.strip().splitlines()
            counts_line = [l for l in lines if l.startswith("COUNTS:")][-1]
            _, p, f_cnt, w = counts_line.split(":")
            return proc.stdout, int(p), int(f_cnt), int(w)

    def test_handler_absent_passes(self):
        out, p, f_cnt, w = self._run_check(False, None)
        self.assertEqual((p, f_cnt, w), (1, 0, 0))
        self.assertIn("[PASS]", out)

    def test_handler_present_and_interop_disabled_warns_without_failing(self):
        wslconf = "[automount]\nenabled = false\n\n[interop]\nenabled = false\nappendWindowsPath = false\n\n[boot]\nsystemd = true\n"
        out, p, f_cnt, w = self._run_check(True, wslconf)
        self.assertEqual((p, f_cnt, w), (0, 0, 1))
        self.assertIn("[WARN]", out)
        self.assertIn("VM-wide", out)
        self.assertIn("another distro", out)

    def test_handler_present_and_interop_enabled_fails(self):
        wslconf = "[interop]\nenabled = true\n"
        out, p, f_cnt, w = self._run_check(True, wslconf)
        self.assertEqual((p, f_cnt, w), (0, 1, 0))
        self.assertIn("[FAIL]", out)

    def test_handler_present_and_wslconf_missing_fails(self):
        out, p, f_cnt, w = self._run_check(True, None)
        self.assertEqual((p, f_cnt, w), (0, 1, 0))
        self.assertIn("[FAIL]", out)

    def test_handler_present_and_other_section_disabled_fails(self):
        wslconf = "[automount]\nenabled = false\n\n[interop_other]\nenabled = false\n"
        out, p, f_cnt, w = self._run_check(True, wslconf)
        self.assertEqual((p, f_cnt, w), (0, 1, 0))
        self.assertIn("[FAIL]", out)

    def test_wslconf_variants_comments_case_and_last_value_wins(self):
        out, p, f_cnt, w = self._run_check(True, "[interop] # comment\r\nenabled=FALSE ; inline\r\n")
        self.assertEqual((p, f_cnt, w), (0, 0, 1))

        out, p, f_cnt, w = self._run_check(True, "[interop]\nenabled = false\nenabled = true\n")
        self.assertEqual((p, f_cnt, w), (0, 1, 0))

        out, p, f_cnt, w = self._run_check(True, "[interop]\nenabled = true\nenabled = false\n")
        self.assertEqual((p, f_cnt, w), (0, 0, 1))

    def _run_check_both(self, interop_exists: bool, interop_late_exists: bool, wslconf_content):
        with tempfile.TemporaryDirectory() as tmpdir:
            binfmt_path = os.path.join(tmpdir, "WSLInterop")
            binfmt_late_path = os.path.join(tmpdir, "WSLInterop-late")
            if interop_exists:
                with open(binfmt_path, "w", encoding="utf-8") as f:
                    f.write("enabled\ninterpreter /init\n")
            if interop_late_exists:
                with open(binfmt_late_path, "w", encoding="utf-8") as f:
                    f.write("enabled\ninterpreter /init\n")

            conf_path = os.path.join(tmpdir, "wsl.conf")
            if wslconf_content is not None:
                with open(conf_path, "wb") as f:
                    f.write(wslconf_content.encode("utf-8"))

            bash_code = "\n".join([
                "set -u",
                "PASS=0; FAIL=0; WARN=0",
                'pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }',
                'fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }',
                'warn() { echo "  [WARN] $*"; WARN=$((WARN + 1)); }',
                self.fn_interop,
                self.fn_check,
                'p1="$1"; p2="$2"; conf="$3"',
                'if command -v wslpath >/dev/null 2>&1; then',
                '  [[ "${p1}" == [A-Za-z]:* || "${p1}" == *\\\\* ]] && p1="$(wslpath -u "${p1}")"',
                '  [[ "${p2}" == [A-Za-z]:* || "${p2}" == *\\\\* ]] && p2="$(wslpath -u "${p2}")"',
                '  [[ "${conf}" == [A-Za-z]:* || "${conf}" == *\\\\* ]] && conf="$(wslpath -u "${conf}")"',
                'fi',
                'check_wslinterop_binfmt "${p1}" "${p2}" "${conf}"',
                'echo "COUNTS:${PASS}:${FAIL}:${WARN}"',
            ])
            proc = subprocess.run(
                ["bash", "-c", bash_code, "_", binfmt_path, binfmt_late_path, conf_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"bash failed: {proc.stderr}\n{proc.stdout}")
            lines = proc.stdout.strip().splitlines()
            counts_line = [l for l in lines if l.startswith("COUNTS:")][-1]
            _, p, f_cnt, w = counts_line.split(":")
            return proc.stdout, int(p), int(f_cnt), int(w)

    def test_wslinterop_late_only_warns_when_disabled_and_fails_when_enabled(self):
        out, p, f_cnt, w = self._run_check_both(False, True, "[interop]\nenabled = false\n")
        self.assertEqual((p, f_cnt, w), (0, 0, 1))
        self.assertIn("[WARN]", out)
        self.assertIn("WSLInterop-late", out)

        out, p, f_cnt, w = self._run_check_both(False, True, "[interop]\nenabled = true\n")
        self.assertEqual((p, f_cnt, w), (0, 1, 0))
        self.assertIn("[FAIL]", out)
        self.assertIn("WSLInterop-late", out)

    def test_both_handlers_absent_passes_and_both_present_reports_once(self):
        out, p, f_cnt, w = self._run_check_both(False, False, None)
        self.assertEqual((p, f_cnt, w), (1, 0, 0))
        self.assertIn("[PASS]", out)

        out, p, f_cnt, w = self._run_check_both(True, True, "[interop]\nenabled = false\n")
        self.assertEqual((p, f_cnt, w), (0, 0, 1))
        self.assertIn("WSLInterop WSLInterop-late", out)


@unittest.skipIf(shutil.which("bash") is None, "bash executable is required")
class TestVerifyIsolationPolicyHelpers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VERIFY_SCRIPT, encoding="utf-8") as f:
            script_text = f.read()
        cls.fn_block_host = _extract_bash_function(script_text, "is_block_host_and_lan_enabled")
        cls.fn_resolve_docker = _extract_bash_function(script_text, "resolve_docker_verify_image")

    def _run_helper(self, fn_def: str, fn_call: str, policy_content):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "verify-policy.json")
            if policy_content is not None:
                with open(policy_path, "w", encoding="utf-8") as f:
                    f.write(policy_content)

            bash_code = "\n".join([
                "set -u",
                fn_def,
                'p="$1"',
                'if command -v wslpath >/dev/null 2>&1; then',
                '  [[ "${p}" == [A-Za-z]:* || "${p}" == *\\\\* ]] && p="$(wslpath -u "${p}")"',
                'fi',
                fn_call,
            ])
            proc = subprocess.run(
                ["bash", "-c", bash_code, "_", policy_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"bash failed: {proc.stderr}\n{proc.stdout}")
            return proc.stdout.strip()

    def test_is_block_host_and_lan_enabled(self):
        self.assertEqual(self._run_helper(self.fn_block_host, 'is_block_host_and_lan_enabled "${p}"', None), "true")
        self.assertEqual(self._run_helper(self.fn_block_host, 'is_block_host_and_lan_enabled "${p}"', '{"blockHostAndLan": true}'), "true")
        self.assertEqual(self._run_helper(self.fn_block_host, 'is_block_host_and_lan_enabled "${p}"', '{"blockHostAndLan": false}'), "false")
        self.assertEqual(self._run_helper(self.fn_block_host, 'is_block_host_and_lan_enabled "${p}"', '{not-json'), "true")

    def test_resolve_docker_verify_image(self):
        self.assertEqual(self._run_helper(self.fn_resolve_docker, 'resolve_docker_verify_image "${p}"', None), "true|alpine:latest")
        self.assertEqual(self._run_helper(self.fn_resolve_docker, 'resolve_docker_verify_image "${p}"', '{"allowedRegistries": []}'), "true|alpine:latest")
        self.assertEqual(self._run_helper(self.fn_resolve_docker, 'resolve_docker_verify_image "${p}"', '{"allowedRegistries": ["ghcr.io", "docker.io"]}'), "true|alpine:latest")
        self.assertEqual(self._run_helper(self.fn_resolve_docker, 'resolve_docker_verify_image "${p}"', '{"allowedRegistries": ["INDEX.DOCKER.IO"]}'), "true|alpine:latest")
        self.assertEqual(
            self._run_helper(self.fn_resolve_docker, 'resolve_docker_verify_image "${p}"', '{"allowedRegistries": ["ghcr.io", "mcr.microsoft.com"]}'),
            "false|ghcr.io/wsl-sandbox-verify-dummy:latest",
        )


if __name__ == "__main__":
    unittest.main()
