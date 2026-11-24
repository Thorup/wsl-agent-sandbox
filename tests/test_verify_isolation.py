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


if __name__ == "__main__":
    unittest.main()
