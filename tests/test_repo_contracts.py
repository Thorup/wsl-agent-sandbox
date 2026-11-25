import ast
import configparser
import glob
import json
import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRepoContracts(unittest.TestCase):
    def test_tool_installer_parity(self):
        with open(os.path.join(REPO_ROOT, "box.schema.json"), encoding="utf-8") as f:
            schema = json.load(f)
        with open(os.path.join(REPO_ROOT, "box.json"), encoding="utf-8") as f:
            box_cfg = json.load(f)
        with open(os.path.join(REPO_ROOT, "scripts", "linux", "install-tools.sh"), encoding="utf-8") as f:
            install_sh = f.read()
        with open(os.path.join(REPO_ROOT, "scripts", "linux", "box-hardening.sh"), encoding="utf-8") as f:
            hardening_sh = f.read()

        schema_pkg_props = schema["properties"]["packages"]["properties"]
        schema_install_keys = {k for k in schema_pkg_props if k.startswith("install")}
        box_install_keys = {k for k in box_cfg["packages"] if k.startswith("install")}
        install_sh_keys = set(re.findall(r'\bflag\s+(install[A-Za-z0-9_]+)\b', install_sh))

        self.assertTrue(schema_install_keys, "Expected install* properties in box.schema.json")
        self.assertEqual(
            schema_install_keys,
            box_install_keys,
            "install* keys in box.schema.json and box.json must match",
        )
        self.assertEqual(
            schema_install_keys,
            install_sh_keys,
            "Every install* key in box.schema.json must be read via flag() in scripts/linux/install-tools.sh",
        )
        for key in sorted(schema_install_keys):
            self.assertIn(
                f'pkgs.get("{key}"',
                hardening_sh,
                f"Expected {key} to be checked in scripts/linux/box-hardening.sh expected_tools",
            )

    def test_embedded_python_heredocs_compile(self):
        heredoc_re = re.compile(r"<<'PYEOF'\n(.*?)\nPYEOF\b", re.DOTALL)
        checked = 0
        for sh_path in sorted(glob.glob(os.path.join(REPO_ROOT, "scripts", "linux", "*.sh"))):
            with open(sh_path, encoding="utf-8") as f:
                content = f.read()
            for idx, match in enumerate(heredoc_re.finditer(content), start=1):
                code = match.group(1)
                try:
                    ast.parse(code, filename=f"{os.path.basename(sh_path)}#PYEOF-{idx}")
                except SyntaxError as exc:
                    self.fail(f"SyntaxError in embedded Python heredoc #{idx} of {sh_path}: {exc}")
                checked += 1
        self.assertGreaterEqual(checked, 2, "Expected at least 2 embedded Python heredocs in scripts/linux/*.sh")

    def test_systemd_units_valid_and_paths_installed(self):
        with open(os.path.join(REPO_ROOT, "box.ps1"), encoding="utf-8") as f:
            box_ps1 = f.read()
        with open(os.path.join(REPO_ROOT, "scripts", "linux", "provision.sh"), encoding="utf-8") as f:
            provision_sh = f.read()
        installer_sources = box_ps1 + "\n" + provision_sh

        unit_files = sorted(glob.glob(os.path.join(REPO_ROOT, "systemd", "*.service")))
        self.assertTrue(unit_files, "Expected systemd/*.service files")

        for unit_path in unit_files:
            with open(unit_path, encoding="utf-8") as f:
                raw = f.read()
            # Collapse systemd line continuations before INI parsing
            collapsed = re.sub(r"\\\r?\n\s*", " ", raw)
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            parser.read_string(collapsed)
            for section in ("Unit", "Service", "Install"):
                self.assertTrue(
                    parser.has_section(section),
                    f"{os.path.basename(unit_path)} missing [{section}] section",
                )
            exec_start = parser.get("Service", "ExecStart", fallback="").strip()
            self.assertTrue(exec_start, f"{os.path.basename(unit_path)} missing ExecStart")
            exec_start_pre = parser.get("Service", "ExecStartPre", fallback="").strip()
            local_paths = re.findall(r"(/usr/local/[A-Za-z0-9._/-]+)", exec_start + "\n" + exec_start_pre)
            self.assertTrue(local_paths, f"{os.path.basename(unit_path)} ExecStart has no /usr/local/* target")
            for p in local_paths:
                self.assertIn(
                    p,
                    installer_sources,
                    f"Path {p} referenced in {os.path.basename(unit_path)} is not installed by box.ps1 or provision.sh",
                )
            protect_system = parser.get("Service", "ProtectSystem", fallback="").strip().lower()
            if protect_system == "strict":
                rw_paths = parser.get("Service", "ReadWritePaths", fallback="").split()
                runtime_dir = parser.get("Service", "RuntimeDirectory", fallback="").strip()
                for rw in rw_paths:
                    if rw.startswith("/run/") and not runtime_dir:
                        self.fail(
                            f"{os.path.basename(unit_path)} uses bare ReadWritePaths={rw} under ProtectSystem=strict without RuntimeDirectory= or '-' prefix"
                        )

    def test_docker_policy_compiler_matches_go_struct(self):
        with open(os.path.join(REPO_ROOT, "scripts", "linux", "box-hardening.sh"), encoding="utf-8") as f:
            hardening_sh = f.read()
        with open(os.path.join(REPO_ROOT, "docker-policy-proxy", "policy.go"), encoding="utf-8") as f:
            policy_go = f.read()

        # Extract Policy struct block in policy.go
        struct_match = re.search(r"type Policy struct \{(.*?)\n\}", policy_go, re.DOTALL)
        self.assertIsNotNone(struct_match, "Could not locate 'type Policy struct' in policy.go")
        go_json_tags = {
            tag.split(",")[0]
            for tag in re.findall(r'`json:"([^"]+)"`', struct_match.group(1))
            if tag != "-"
        }

        # Extract compiled_docker_policy dict keys + dynamic assignments in box-hardening.sh
        dict_match = re.search(r"compiled_docker_policy\s*=\s*\{(.*?)\n\}", hardening_sh, re.DOTALL)
        self.assertIsNotNone(dict_match, "Could not locate compiled_docker_policy in box-hardening.sh")
        py_keys = set(re.findall(r'"([A-Za-z0-9_]+)"\s*:', dict_match.group(1)))
        py_keys.update(re.findall(r'compiled_docker_policy\["([A-Za-z0-9_]+)"\]\s*=', hardening_sh))

        self.assertTrue(py_keys, "Expected keys in compiled_docker_policy")
        unknown_to_go = py_keys - go_json_tags
        self.assertEqual(
            unknown_to_go,
            set(),
            f"Keys emitted by box-hardening.sh not found in Go Policy struct: {sorted(unknown_to_go)}",
        )

    def test_cli_and_packaging_contracts(self):
        with open(os.path.join(REPO_ROOT, "box.ps1"), encoding="utf-8") as f:
            box_ps1 = f.read()

        # ValidateSet commands in box.ps1
        vs_match = re.search(r"\[ValidateSet\(([^)]+)\)\]\s*\[string\]\$Command", box_ps1)
        self.assertIsNotNone(vs_match, "Could not locate $Command ValidateSet in box.ps1")
        commands = re.findall(r"'([^']+)'", vs_match.group(1))
        self.assertTrue(commands, "Expected commands in box.ps1 ValidateSet")

        usage_match = re.search(r"function Show-Usage\s*\{(.*?)\n\}", box_ps1, re.DOTALL)
        self.assertIsNotNone(usage_match, "Could not locate Show-Usage in box.ps1")
        usage_text = usage_match.group(1)
        for cmd in commands:
            if cmd == "help":
                continue
            self.assertRegex(
                usage_text,
                rf"\b{re.escape(cmd)}\b",
                f"Command '{cmd}' in box.ps1 ValidateSet is missing from Show-Usage",
            )

        # Scoop manifest bin targets exist
        scoop_path = os.path.join(REPO_ROOT, "packaging", "scoop", "wsl-agent-sandbox.json")
        with open(scoop_path, encoding="utf-8") as f:
            scoop = json.load(f)
        for entry in scoop.get("bin", []):
            target = entry[0] if isinstance(entry, list) else entry
            self.assertTrue(
                os.path.isfile(os.path.join(REPO_ROOT, target)),
                f"Scoop manifest bin target does not exist: {target}",
            )

        # Release workflow includes assets, docs, and rendered Scoop manifest
        release_yml_path = os.path.join(REPO_ROOT, ".github", "workflows", "release.yml")
        with open(release_yml_path, encoding="utf-8") as f:
            release_yml = f.read()
        cp_match = re.search(r"cp -r\s+(.*?)\"dist/\$\{PKG_NAME\}/\"", release_yml, re.DOTALL)
        self.assertIsNotNone(cp_match, "Could not locate cp -r archive step in .github/workflows/release.yml")
        cp_items = set(re.findall(r"[A-Za-z0-9_.-]+", cp_match.group(1).replace("\\\n", " ")))
        for required_dir in ("assets", "docs", "scripts", "systemd", "packaging"):
            self.assertIn(
                required_dir,
                cp_items,
                f"Expected '{required_dir}' in release.yml cp -r archive list",
            )
        self.assertIn(
            "dist/wsl-agent-sandbox.json",
            release_yml,
            "Expected release.yml to render and upload dist/wsl-agent-sandbox.json",
        )

    def test_npm_and_pnpm_user_env_configured_for_non_root(self):
        with open(os.path.join(REPO_ROOT, "scripts/linux/apply-policy.sh"), encoding="utf-8") as f:
            apply_content = f.read()
        self.assertIn("$HOME/.local/share/pnpm", apply_content, "apply-policy.sh missing $HOME/.local/share/pnpm in PATH")
        self.assertIn('export NPM_CONFIG_PREFIX="$HOME/.npm-global"', apply_content, "apply-policy.sh missing NPM_CONFIG_PREFIX")
        self.assertIn('export PNPM_HOME="$HOME/.local/share/pnpm"', apply_content, "apply-policy.sh missing PNPM_HOME")
        self.assertIn('if [ "$(id -u)" -ne 0 ]; then', apply_content, "apply-policy.sh must scope NPM_CONFIG_PREFIX/PNPM_HOME to non-root")

        with open(os.path.join(REPO_ROOT, "scripts/linux/provision.sh"), encoding="utf-8") as f:
            provision_content = f.read()
        if "--render-env-only" not in provision_content:
            self.assertIn("$HOME/.local/share/pnpm", provision_content, "provision.sh missing $HOME/.local/share/pnpm in PATH")
            self.assertIn('export NPM_CONFIG_PREFIX="$HOME/.npm-global"', provision_content, "provision.sh missing NPM_CONFIG_PREFIX")
            self.assertIn('export PNPM_HOME="$HOME/.local/share/pnpm"', provision_content, "provision.sh missing PNPM_HOME")
            self.assertIn('if [ "$(id -u)" -ne 0 ]; then', provision_content, "provision.sh must scope NPM_CONFIG_PREFIX/PNPM_HOME to non-root")

    def test_hardening_and_audit_contracts(self):
        with open(os.path.join(REPO_ROOT, "scripts", "linux", "box-hardening.sh"), encoding="utf-8") as f:
            hardening_sh = f.read()
        with open(os.path.join(REPO_ROOT, "scripts", "linux", "provision.sh"), encoding="utf-8") as f:
            provision_sh = f.read()
        with open(os.path.join(REPO_ROOT, "box.ps1"), encoding="utf-8") as f:
            box_ps1 = f.read()

        # allowlist mode must use drop_action (so log_and_drop is used when logDrops=true)
        allowlist_match = re.search(
            r'if egress_mode == "allowlist"(?:\s+and\s+not\s+maintenance_egress_open)?:\s*\n(?:[^\n]*#[^\n]*\n)*\s*lines\.append\(([^)]+)\)',
            hardening_sh,
        )
        self.assertIsNotNone(allowlist_match, "Could not locate egress_mode == 'allowlist' drop rule in box-hardening.sh")
        self.assertIn("drop_action", allowlist_match.group(1))

        # Both box-hardening.sh and provision.sh must enforce dpkg-statoverride for sudo/sudo-rs
        for name, content in (("box-hardening.sh", hardening_sh), ("provision.sh", provision_sh)):
            self.assertIn("dpkg-statoverride", content, f"{name} missing dpkg-statoverride sudo hardening")
            self.assertIn("/usr/lib/cargo/bin/sudo", content, f"{name} missing sudo-rs path in sudo hardening")

        # Invoke-AuditLogs must cover all root security daemons and TTL units
        audit_match = re.search(r"function Invoke-AuditLogs\s*\{(.*?)\n\}", box_ps1, re.DOTALL)
        self.assertIsNotNone(audit_match, "Could not locate Invoke-AuditLogs in box.ps1")
        audit_body = audit_match.group(1)
        for unit in (
            "egress-proxy.service",
            "credential-proxy.service",
            "ssh-agent-proxy.service",
            "wsl-box-ttl-*.service",
        ):
            self.assertIn(unit, audit_body, f"Invoke-AuditLogs missing {unit}")


if __name__ == "__main__":
    unittest.main()
