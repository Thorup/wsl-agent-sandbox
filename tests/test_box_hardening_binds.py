import ast
import os
import re
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOX_HARDENING_SH = os.path.join(REPO_ROOT, "scripts", "linux", "box-hardening.sh")


def load_bind_helpers():
    """Extract and load bind-prefix helper functions directly from box-hardening.sh."""
    with open(BOX_HARDENING_SH, encoding="utf-8") as f:
        content = f.read()
    match = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF\b", content, re.DOTALL)
    if not match:
        raise RuntimeError("Could not locate embedded Python heredoc in box-hardening.sh")
    code = match.group(1)
    # Keep only imports and definitions up to '# --- A.'
    header_part = code.split("# --- A.", 1)[0]
    tree = ast.parse(header_part, filename=BOX_HARDENING_SH)
    # Filter out top-level file/policy loading statements; keep imports, constants, and defs
    kept_nodes = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))
        or (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id.isupper() for t in node.targets)
        )
    ]
    module_ast = ast.Module(body=kept_nodes, type_ignores=[])
    ast.fix_missing_locations(module_ast)
    ns = {}
    exec(compile(module_ast, BOX_HARDENING_SH, "exec"), ns)
    return ns


class TestBoxHardeningBinds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helpers = load_bind_helpers()

    def test_empty_allow_bind_prefixes_produces_no_mappings(self):
        policy = {"docker": {"allowBindPrefixes": []}}
        resolved = self.helpers["resolve_bind_prefixes"](policy, "/home/agent")
        self.assertEqual(resolved, [])

    def test_missing_allow_bind_prefixes_defaults_to_agent_home(self):
        policy = {"docker": {}}
        resolved = self.helpers["resolve_bind_prefixes"](policy, "/home/agent")
        self.assertEqual(resolved, [("/home/agent", "home-agent")])

    def test_subpath_of_home_emits_subpath_not_home(self):
        policy = {"docker": {"allowBindPrefixes": ["/home/agent/work"]}}
        resolved = self.helpers["resolve_bind_prefixes"](policy, "/home/agent")
        self.assertEqual(len(resolved), 1)
        guest_prefix, slug = resolved[0]
        self.assertEqual(guest_prefix, "/home/agent/work")
        self.assertNotEqual(guest_prefix, "/home/agent")
        self.assertTrue(slug.startswith("prefix-"))

    def test_multiple_prefixes_have_distinct_slugs_and_dedup(self):
        policy = {
            "docker": {
                "allowBindPrefixes": [
                    "/home/agent",
                    "/tmp/builds",
                    "/home/agent/",
                ]
            }
        }
        resolved = self.helpers["resolve_bind_prefixes"](policy, "/home/agent")
        self.assertEqual(len(resolved), 2)
        self.assertEqual(resolved[0], ("/home/agent", "home-agent"))
        self.assertEqual(resolved[1][0], "/tmp/builds")
        self.assertTrue(resolved[1][1].startswith("prefix-"))
        self.assertNotEqual(resolved[0][1], resolved[1][1])

    def test_rejects_unsafe_prefixes(self):
        unsafe = [
            "/",
            "/etc",
            "/etc/wsl-agent-sandbox",
            "/root",
            "/proc",
            "/sys",
            "/dev",
            "/boot",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/var/run",
            "/run",
            "/run/box-root",
            "/run/desktop",
            "/mnt",
            "/mnt/c",
            "/shared",
            "/shared/foo",
            "/home/agent/../etc",
            "relative/path",
            "",
        ]
        for bad in unsafe:
            with self.subTest(prefix=bad):
                with self.assertRaises(ValueError):
                    self.helpers["validate_bind_prefix"](bad)

    def test_ensure_bind_prefix_dir_creates_dirs_and_blocks_symlinks(self):
        ensure_dir = self.helpers["ensure_bind_prefix_dir"]
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "home", "agent"), exist_ok=True)
            os.makedirs(os.path.join(tmpdir, "tmp"), exist_ok=True)

            ensure_dir("/home/agent/work/app", "/home/agent", uid, gid, root_prefix=tmpdir)
            self.assertTrue(os.path.isdir(os.path.join(tmpdir, "home", "agent", "work", "app")))

            ensure_dir("/tmp/builds", "/home/agent", uid, gid, root_prefix=tmpdir)
            self.assertTrue(os.path.isdir(os.path.join(tmpdir, "tmp", "builds")))

            # Symlink component must be rejected
            os.symlink("/etc", os.path.join(tmpdir, "home", "agent", "evil"))
            with self.assertRaises(ValueError):
                ensure_dir("/home/agent/evil/sub", "/home/agent", uid, gid, root_prefix=tmpdir)


if __name__ == "__main__":
    unittest.main()
