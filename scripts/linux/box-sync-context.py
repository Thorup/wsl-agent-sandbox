#!/usr/bin/env python3
"""Synchronize dynamic agent instructions (.md), supplementary SKILL.md files,
and multi-cloud profile switchers (use-gcloud, use-aws, box-context) inside
wsl-agent-sandbox.

Never writes secret values (tokens, private keys, passwords) into any
instruction, skill, or summary file.
"""

import argparse
import datetime
import json
import os
import sys
import tempfile

MARKER_BEGIN = "# >>> wsl-agent-sandbox >>>"
MARKER_END = "# <<< wsl-agent-sandbox <<<"

USE_GCLOUD_SCRIPT = """#!/usr/bin/env python3
import configparser
import json
import os
import re
import shlex
import sys
import tempfile

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".config", "wsl-agent-sandbox")
STATE_FILE = os.path.join(STATE_DIR, "seeded-services.json")
OVERRIDES_FILE = os.path.join(STATE_DIR, "active-overrides.env")
GCLOUD_DIR = os.path.join(HOME, ".config", "gcloud")
CONFIGS_DIR = os.path.join(GCLOUD_DIR, "configurations")
ACTIVE_CFG_FILE = os.path.join(GCLOUD_DIR, "active_config")


def load_gcloud_projects():
    projects = []
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                st = json.load(f)
            gc = (st.get("services") or {}).get("gcloud") or {}
            details = gc.get("projectDetails")
            if isinstance(details, list) and details:
                projects.extend(details)
        except Exception:
            pass
    seen = {p.get("name") for p in projects if p.get("name")}
    if os.path.isdir(CONFIGS_DIR):
        for fname in sorted(os.listdir(CONFIGS_DIR)):
            if not fname.startswith("config_"):
                continue
            cname = fname[len("config_"):]
            if not cname or cname in seen:
                continue
            cfg_path = os.path.join(CONFIGS_DIR, fname)
            cp = configparser.RawConfigParser()
            try:
                cp.read(cfg_path, encoding="utf-8")
            except Exception:
                continue
            proj = cp.get("core", "project", fallback="")
            acct = cp.get("core", "account", fallback="")
            reg = cp.get("compute", "region", fallback="")
            zn = cp.get("compute", "zone", fallback="")
            kp = os.path.join(STATE_DIR, "keys", f"gcloud-{cname}.json")
            if not os.path.isfile(kp):
                alt = os.path.join(STATE_DIR, "keys", "gcloud-service-account.json")
                kp = alt if os.path.isfile(alt) else ""
            projects.append({
                "name": cname,
                "project": proj,
                "clientEmail": acct,
                "region": reg,
                "zone": zn,
                "keyPath": kp,
                "setAdc": bool(kp),
            })
    return projects


def get_active_config_name():
    if os.path.isfile(ACTIVE_CFG_FILE):
        try:
            with open(ACTIVE_CFG_FILE, "r", encoding="utf-8") as f:
                val = f.read().strip()
            if val:
                return val
        except Exception:
            pass
    return "default"


def update_overrides_section(section_name, lines):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    existing = ""
    if os.path.isfile(OVERRIDES_FILE):
        try:
            with open(OVERRIDES_FILE, "r", encoding="utf-8") as f:
                existing = f.read()
        except Exception:
            existing = ""
    begin_tag = f"# >>> {section_name} >>>"
    end_tag = f"# <<< {section_name} <<<"
    pattern = re.compile(
        r"^" + re.escape(begin_tag) + r"\\n.*?^" + re.escape(end_tag) + r"\\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", existing).strip()
    block = "\\n".join([begin_tag] + lines + [end_tag])
    new_text = (cleaned + "\\n\\n" + block + "\\n") if cleaned else (block + "\\n")
    fd, tmp_path = tempfile.mkstemp(prefix=".overrides-", dir=STATE_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
        os.replace(tmp_path, OVERRIDES_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main():
    args = sys.argv[1:]
    projects = load_gcloud_projects()
    active_name = get_active_config_name()

    if not args or args[0] in ("-l", "--list", "list"):
        if not projects:
            print("[use-gcloud] No seeded or configured gcloud projects found.")
            return 0
        print("Available gcloud configurations:")
        for p in projects:
            marker = "*" if p.get("name") == active_name else " "
            proj_id = p.get("project") or "(unset)"
            acct = p.get("clientEmail") or "(unset)"
            reg = f", region={p['region']}" if p.get("region") else ""
            print(f"  {marker} {p['name']} (project={proj_id}, account={acct}{reg})")
        return 0

    if args[0] in ("-h", "--help", "help"):
        print("Usage: use-gcloud [<configuration-name-or-project-id> | --list]")
        return 0

    target = args[0].strip()
    matched = None
    for p in projects:
        if p.get("name") == target or p.get("project") == target:
            matched = p
            break

    if not matched:
        avail = ", ".join(p.get("name", "") for p in projects if p.get("name")) or "(none)"
        print(
            f"[use-gcloud] ERROR: Unknown gcloud configuration or project '{target}'. Available: {avail}",
            file=sys.stderr,
        )
        return 1

    cfg_name = matched["name"]
    os.makedirs(GCLOUD_DIR, mode=0o700, exist_ok=True)
    with open(ACTIVE_CFG_FILE, "w", encoding="utf-8") as f:
        f.write(cfg_name + "\\n")
    os.chmod(ACTIVE_CFG_FILE, 0o600)

    lines = [f"export CLOUDSDK_ACTIVE_CONFIG_NAME={shlex.quote(cfg_name)}"]
    key_path = matched.get("keyPath") or ""
    if key_path and os.path.isfile(key_path):
        lines.append(f"export GOOGLE_APPLICATION_CREDENTIALS={shlex.quote(key_path)}")
    proj_id = matched.get("project") or ""
    if proj_id:
        lines.append(f"export GOOGLE_CLOUD_PROJECT={shlex.quote(proj_id)}")
        lines.append(f"export CLOUDSDK_CORE_PROJECT={shlex.quote(proj_id)}")
    else:
        lines.append("unset GOOGLE_CLOUD_PROJECT CLOUDSDK_CORE_PROJECT")
    region = matched.get("region") or ""
    if region:
        lines.append(f"export CLOUDSDK_COMPUTE_REGION={shlex.quote(region)}")
    else:
        lines.append("unset CLOUDSDK_COMPUTE_REGION")
    zone = matched.get("zone") or ""
    if zone:
        lines.append(f"export CLOUDSDK_COMPUTE_ZONE={shlex.quote(zone)}")
    else:
        lines.append("unset CLOUDSDK_COMPUTE_ZONE")

    update_overrides_section("gcloud", lines)
    print(
        f"[use-gcloud] Activated '{cfg_name}' (project={proj_id or 'unset'}, "
        f"account={matched.get('clientEmail') or 'unset'}, "
        f"GOOGLE_APPLICATION_CREDENTIALS={key_path or 'unchanged'})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
"""

USE_AWS_SCRIPT = """#!/usr/bin/env python3
import configparser
import json
import os
import re
import shlex
import sys
import tempfile

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".config", "wsl-agent-sandbox")
STATE_FILE = os.path.join(STATE_DIR, "seeded-services.json")
OVERRIDES_FILE = os.path.join(STATE_DIR, "active-overrides.env")
AWS_CRED_FILE = os.path.join(HOME, ".aws", "credentials")
AWS_CONF_FILE = os.path.join(HOME, ".aws", "config")


def load_aws_profiles():
    profiles = []
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                st = json.load(f)
            aws = (st.get("services") or {}).get("aws") or {}
            for p in aws.get("profiles") or []:
                if p and p not in profiles:
                    profiles.append(p)
        except Exception:
            pass
    for path, strip_prefix in ((AWS_CRED_FILE, False), (AWS_CONF_FILE, True)):
        if os.path.isfile(path):
            cp = configparser.RawConfigParser()
            try:
                cp.read(path, encoding="utf-8")
                for sec in cp.sections():
                    name = sec[len("profile "):].strip() if (strip_prefix and sec.startswith("profile ")) else sec.strip()
                    if name and name not in profiles:
                        profiles.append(name)
            except Exception:
                pass
    return profiles


def update_overrides_section(section_name, lines):
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    existing = ""
    if os.path.isfile(OVERRIDES_FILE):
        try:
            with open(OVERRIDES_FILE, "r", encoding="utf-8") as f:
                existing = f.read()
        except Exception:
            existing = ""
    begin_tag = f"# >>> {section_name} >>>"
    end_tag = f"# <<< {section_name} <<<"
    pattern = re.compile(
        r"^" + re.escape(begin_tag) + r"\\n.*?^" + re.escape(end_tag) + r"\\n?",
        re.MULTILINE | re.DOTALL,
    )
    cleaned = pattern.sub("", existing).strip()
    block = "\\n".join([begin_tag] + lines + [end_tag])
    new_text = (cleaned + "\\n\\n" + block + "\\n") if cleaned else (block + "\\n")
    fd, tmp_path = tempfile.mkstemp(prefix=".overrides-", dir=STATE_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
        os.replace(tmp_path, OVERRIDES_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main():
    args = sys.argv[1:]
    profiles = load_aws_profiles()
    active_prof = os.environ.get("AWS_PROFILE", "default")

    if not args or args[0] in ("-l", "--list", "list"):
        if not profiles:
            print("[use-aws] No seeded or configured AWS profiles found.")
            return 0
        print("Available AWS profiles:")
        for p in profiles:
            marker = "*" if p == active_prof else " "
            print(f"  {marker} {p}")
        return 0

    if args[0] in ("-h", "--help", "help"):
        print("Usage: use-aws [<profile-name> | --list]")
        return 0

    target = args[0].strip()
    if profiles and target not in profiles:
        avail = ", ".join(profiles)
        print(f"[use-aws] ERROR: Unknown AWS profile '{target}'. Available: {avail}", file=sys.stderr)
        return 1

    update_overrides_section("aws", [f"export AWS_PROFILE={shlex.quote(target)}"])
    print(f"[use-aws] Activated AWS profile '{target}' (AWS_PROFILE={target})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
"""

BOX_CONTEXT_SCRIPT = """#!/usr/bin/env python3
import json
import os
import sys

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".config", "wsl-agent-sandbox")
SUMMARY_JSON = os.path.join(STATE_DIR, "context-summary.json")
CONTEXT_MD = os.path.join(STATE_DIR, "SANDBOX_CONTEXT.md")


def main():
    if "--json" in sys.argv[1:]:
        if os.path.isfile(SUMMARY_JSON):
            with open(SUMMARY_JSON, "r", encoding="utf-8") as f:
                sys.stdout.write(f.read())
            return 0
        print("{}")
        return 0
    if os.path.isfile(CONTEXT_MD):
        with open(CONTEXT_MD, "r", encoding="utf-8") as f:
            sys.stdout.write(f.read())
        return 0
    print("wsl-agent-sandbox context not initialized yet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
"""


def build_context_summary(policy, seeded_state):
    agent_user = policy.get("agentUser") or {}
    agent_name = agent_user.get("name", "agent")
    agent_uid = int(agent_user.get("uid", 26040))
    distro_name = policy.get("distroName", "wsl-agent-sandbox")

    shared_folders = []
    for sf in policy.get("sharedFolders") or []:
        if not isinstance(sf, dict) or not sf.get("name"):
            continue
        shared_folders.append({
            "name": sf["name"],
            "mountPath": f"/shared/{sf['name']}",
            "mode": sf.get("mode", "ro"),
            "allowDockerBind": bool(sf.get("allowDockerBind", False)),
        })

    net = policy.get("network") or {}
    allowed_ports = []
    for p in net.get("allowedHostPorts") or []:
        if isinstance(p, dict) and p.get("port"):
            allowed_ports.append({
                "port": int(p["port"]),
                "protocol": p.get("protocol", "tcp"),
                "comment": p.get("comment", ""),
            })

    docker_cfg = policy.get("docker") or {}
    bind_prefixes = list(docker_cfg.get("allowBindPrefixes") or [f"/home/{agent_name}"])
    for sf in shared_folders:
        if sf["allowDockerBind"] and sf["mountPath"] not in bind_prefixes:
            bind_prefixes.append(sf["mountPath"])

    svcs = (seeded_state or {}).get("services") or {}
    seeded_summary = {}
    for svc_name in sorted(svcs.keys()):
        meta = svcs[svc_name] or {}
        entry = {"updatedAt": meta.get("updatedAt", "")}
        if meta.get("expiresAt"):
            entry["expiresAt"] = meta["expiresAt"]
        if svc_name == "gcloud":
            entry["defaultProject"] = meta.get("defaultProject", "default")
            entry["profiles"] = meta.get("profiles") or []
            entry["projects"] = [
                {
                    "name": p.get("name", "default"),
                    "project": p.get("project", ""),
                    "clientEmail": p.get("clientEmail", ""),
                    "region": p.get("region", ""),
                    "zone": p.get("zone", ""),
                    "keyPath": p.get("keyPath", ""),
                }
                for p in (meta.get("projectDetails") or [])
            ]
            if not entry["projects"] and (meta.get("project") or meta.get("clientEmail")):
                entry["projects"] = [{
                    "name": meta.get("defaultProject", "default"),
                    "project": meta.get("project", ""),
                    "clientEmail": meta.get("clientEmail", ""),
                    "region": "",
                    "zone": "",
                    "keyPath": meta.get("keyPath", ""),
                }]
        elif svc_name == "aws":
            entry["profiles"] = meta.get("profiles") or []
            entry["defaultProfile"] = meta.get("defaultProfile") or (entry["profiles"][0] if entry["profiles"] else "default")
        elif svc_name in ("git", "ssh"):
            entry["mode"] = meta.get("mode", "files")
            entry["hosts"] = meta.get("hosts") or []
            entry["keys"] = meta.get("keys") or []
            if meta.get("userEmail"):
                entry["userEmail"] = meta["userEmail"]
            if meta.get("signingKey"):
                entry["signingKey"] = meta["signingKey"]
        elif svc_name == "github":
            entry["hosts"] = meta.get("hosts") or ["github.com"]
        elif svc_name == "kubectl":
            entry["mode"] = meta.get("mode", "kubeconfig")
            if meta.get("context"):
                entry["context"] = meta["context"]
            if meta.get("namespace"):
                entry["namespace"] = meta["namespace"]
        elif svc_name == "jira":
            if meta.get("server"):
                entry["server"] = meta["server"]
            if meta.get("projectKey"):
                entry["projectKey"] = meta["projectKey"]
        elif svc_name == "azureDevops":
            if meta.get("organization"):
                entry["organization"] = meta["organization"]
            if meta.get("project"):
                entry["project"] = meta["project"]
        if meta.get("envVars"):
            entry["envVars"] = meta["envVars"]
        seeded_summary[svc_name] = entry

    return {
        "distroName": distro_name,
        "agentUser": {"name": agent_name, "uid": agent_uid, "home": f"/home/{agent_name}"},
        "network": {
            "blockHostAndLan": bool(net.get("blockHostAndLan", True)),
            "egressMode": net.get("egressMode", "open"),
            "allowedHostPorts": allowed_ports,
        },
        "docker": {
            "enabled": bool(docker_cfg.get("enabled", True)),
            "allowBindPrefixes": bind_prefixes,
            "forceLoopbackPortBindings": bool(docker_cfg.get("forceLoopbackPortBindings", True)),
            "forceInternalNetwork": bool(docker_cfg.get("forceInternalNetwork", False)),
        },
        "sharedFolders": shared_folders,
        "seededServices": seeded_summary,
    }


def render_context_markdown(summary):
    agent = summary["agentUser"]
    net = summary["network"]
    docker = summary["docker"]
    shares = summary["sharedFolders"]
    svcs = summary["seededServices"]

    lines = [
        "# wsl-agent-sandbox Environment Context",
        "",
        "You are running inside **`wsl-agent-sandbox`** (hardened Ubuntu 26.04 LTS WSL2 sandbox).",
        "Run `box-context` (or `box-context --json`) at any time to inspect the live environment.",
        "",
        "## 1. Sandbox Boundaries & Tooling Rules",
        f"- **User & Privilege**: Non-root `{agent['name']}` (UID `{agent['uid']}`), **no `sudo`** (`root` is locked). Install packages in user-space (`uv tool install`, `pip --user`, `npm install -g`, `pnpm`, `cargo install`, `dotnet tool install -g`).",
        "- **Filesystem**: Windows drives (`/mnt/c`) and Windows `.exe` interop are disabled.",
    ]
    if shares:
        share_items = ", ".join(
            f"`{s['mountPath']}` ({s['mode']}" + (", docker-bind allowed" if s["allowDockerBind"] else "") + ")"
            for s in shares
        )
        lines.append(f"- **Active `/shared` Mounts**: {share_items}")
    else:
        lines.append("- **Active `/shared` Mounts**: `(none — work inside /home/agent)`")

    if docker["enabled"]:
        prefixes = ", ".join(f"`{p}`" for p in docker["allowBindPrefixes"])
        lines.append(
            f"- **Docker (`docker-policy-proxy`)**: Enabled via `/var/run/docker.sock`. Bind mounts (`-v` / `--mount`) are **only allowed inside {prefixes}**. `--privileged`, `--network=host`, `--pid=host`, `--ipc=host`, `cap-add`, and non-loopback port bindings (`-p 0.0.0.0:...`) are blocked (use `-p 127.0.0.1:<host>:<container>` or `-p <host>:<container>`)."
        )
    else:
        lines.append("- **Docker**: Disabled by policy (`docker.enabled=false`).")

    if net["blockHostAndLan"]:
        if net["allowedHostPorts"]:
            port_items = ", ".join(
                f"`{p['port']}/{p['protocol']}`" + (f" ({p['comment']})" if p.get("comment") else "")
                for p in net["allowedHostPorts"]
            )
            lines.append(f"- **Network**: Direct traffic to Windows host & RFC1918 LAN is blocked except allowed host ports: {port_items}.")
        else:
            lines.append("- **Network**: Direct traffic to Windows host & RFC1918 LAN is blocked; outbound internet and local WSL `127.0.0.1` services work normally.")

    lines.append("")
    lines.append("## 2. Seeded Cloud, Git & CLI Credentials")
    if not svcs:
        lines.append("- No managed CLI secrets are currently seeded (run `.\\box.ps1 seed-secrets` from Windows to seed).")
    else:
        if "gcloud" in svcs:
            gc = svcs["gcloud"]
            projs = gc.get("projects") or []
            def_p = gc.get("defaultProject", "default")
            if projs:
                p_desc = ", ".join(
                    f"`{p['name']}` (project=`{p.get('project') or 'unset'}`, account=`{p.get('clientEmail') or 'unset'}`"
                    + (f", region=`{p['region']}`" if p.get("region") else "")
                    + (", **default**" if p["name"] == def_p else "")
                    + ")"
                    for p in projs
                )
                lines.append(f"- **GCP (`gcloud`)**: {p_desc}")
                lines.append(
                    "  - **Switching GCP Projects**: Always run **`use-gcloud <name>`** (or `use-gcloud --list`) instead of bare `gcloud config configurations activate`. `use-gcloud` switches both the `gcloud` active configuration **and** updates `GOOGLE_APPLICATION_CREDENTIALS` + `GOOGLE_CLOUD_PROJECT` persistently across subshells so Terraform/OpenTofu and GCP SDKs switch together."
                )
        if "aws" in svcs:
            aws = svcs["aws"]
            profs = ", ".join(f"`{p}`" + (" (**default**)" if p == aws.get("defaultProfile") else "") for p in (aws.get("profiles") or []))
            lines.append(f"- **AWS (`aws`)**: Profiles: {profs}")
            lines.append("  - **Switching AWS Profiles**: Run **`use-aws <profile>`** (or `use-aws --list`) to switch `AWS_PROFILE` in the current shell and persistently across subshells.")
        if "github" in svcs:
            gh = svcs["github"]
            hosts = ", ".join(f"`{h}`" for h in (gh.get("hosts") or ["github.com"]))
            lines.append(f"- **GitHub CLI (`gh`)**: Authenticated for {hosts}.")
        if "git" in svcs:
            gt = svcs["git"]
            hosts = ", ".join(f"`{h}`" for h in (gt.get("hosts") or ["github.com"]))
            mode_str = "filtered root `ssh-agent` proxy (`SSH_AUTH_SOCK`)" if gt.get("mode") == "agent-proxy" else "`~/.ssh/wsl-agent-sandbox-git/`"
            lines.append(f"- **Git SSH (`git`)**: Configured for {hosts} via {mode_str}.")
        if "ssh" in svcs:
            sh_meta = svcs["ssh"]
            hosts = ", ".join(f"`{h}`" for h in (sh_meta.get("hosts") or []))
            lines.append(f"- **Remote SSH (`ssh`)**: Configured host aliases: {hosts or '(default key)'}.")
        for other in ("azure", "azureDevops", "kubectl", "jira", "upcloud", "gemini", "claude", "env", "files"):
            if other in svcs:
                lines.append(f"- **`{other}`**: Seeded and active.")

    lines.append("")
    lines.append("> **Tip**: For detailed multi-cloud switching workflows and sandbox troubleshooting, load the **`wsl-agent-sandbox`** skill (`~/.gemini/skills/wsl-agent-sandbox/SKILL.md` / `~/.claude/skills/wsl-agent-sandbox/SKILL.md`).")
    return "\n".join(lines) + "\n"


def render_skill_markdown(summary):
    body = render_context_markdown(summary)
    frontmatter = """---
name: wsl-agent-sandbox
description: Hardened WSL2 sandbox environment guide, active cloud profiles (gcloud multi-project, AWS multi-profile, Git/SSH, Kubernetes), profile switchers (use-gcloud, use-aws, box-context), shared mounts, network rules, and Docker policy proxy constraints. Activate whenever switching GCP projects, AWS profiles, debugging permission/network/Docker errors, or checking available credentials in this sandbox.
---

"""
    workflows = """
## 3. Multi-Cloud & Multi-Project Switching Workflows

### Switching GCP Projects & Service Accounts (`use-gcloud`)
When multiple GCP projects with separate Service Accounts are seeded, each project has its own named `gcloud` configuration (`~/.config/gcloud/configurations/config_<name>`) and its own Service Account JSON key (`~/.config/wsl-agent-sandbox/keys/gcloud-<name>.json`).

- **Why `gcloud config configurations activate` alone is not enough**:
  Running `gcloud config configurations activate <name>` only changes the `gcloud` CLI's active config file; it leaves `GOOGLE_APPLICATION_CREDENTIALS` and `GOOGLE_CLOUD_PROJECT` pointing to the previous project's key file, causing OpenTofu/Terraform, Python/Node/Go GCP SDKs, and `google-auth` libraries to authenticate against the wrong GCP project.
- **Correct way to switch**:
  ```bash
  # List all available GCP configurations and see which one is active (*):
  use-gcloud --list

  # Switch active gcloud configuration AND update GOOGLE_APPLICATION_CREDENTIALS + GOOGLE_CLOUD_PROJECT persistently:
  use-gcloud <name-or-project-id>
  ```
- **One-off command against another GCP project without switching globally**:
  ```bash
  CLOUDSDK_ACTIVE_CONFIG_NAME=<name> \\
  GOOGLE_APPLICATION_CREDENTIALS="$HOME/.config/wsl-agent-sandbox/keys/gcloud-<name>.json" \\
  <command>
  ```

### Switching AWS Profiles (`use-aws`)
```bash
# List available AWS profiles:
use-aws --list

# Switch active AWS_PROFILE persistently across subshells:
use-aws <profile-name>
```

### Inspecting Live Sandbox State (`box-context`)
```bash
# Print human-readable markdown summary of mounts, ports, and seeded credentials:
box-context

# Print machine-readable JSON inventory (zero secrets):
box-context --json
```
"""
    return frontmatter + body + workflows


def merge_marker_block(existing_text, block_body):
    wrapped = f"{MARKER_BEGIN}\n{block_body.rstrip()}\n{MARKER_END}\n"
    if not existing_text or not existing_text.strip():
        return wrapped
    if MARKER_BEGIN in existing_text and MARKER_END in existing_text:
        start_idx = existing_text.index(MARKER_BEGIN)
        end_idx = existing_text.index(MARKER_END) + len(MARKER_END)
        if end_idx < len(existing_text) and existing_text[end_idx] == "\n":
            end_idx += 1
        return existing_text[:start_idx] + wrapped + existing_text[end_idx:]
    return existing_text.rstrip() + "\n\n" + wrapped


def write_owned_file(path, content, uid, gid, mode=0o644, dir_mode=0o755, root_Limit=None):
    parent = os.path.dirname(path)
    if root_Limit:
        real_root = os.path.realpath(root_Limit)
        # Ensure parent hierarchy exists with proper ownership
        rel = os.path.relpath(parent, root_Limit)
        if rel.startswith(".."):
            raise ValueError(f"Refusing to write outside {root_Limit}: {path}")
        cur = root_Limit
        if rel != ".":
            parts = rel.split(os.sep)
            for i, part in enumerate(parts):
                cur = os.path.join(cur, part)
                if not os.path.exists(cur):
                    d_mode = dir_mode if i == len(parts) - 1 else 0o755
                    os.mkdir(cur, d_mode)
                    if uid is not None and gid is not None:
                        os.chown(cur, uid, gid)
        real_parent = os.path.realpath(parent)
        if real_parent != real_root and not real_parent.startswith(real_root + os.sep):
            raise ValueError(f"Symlink escape detected outside {root_Limit}: {path}")
    else:
        os.makedirs(parent, mode=dir_mode, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".box-ctx-", dir=parent)
    try:
        os.fchmod(fd, mode)
        if uid is not None and gid is not None:
            os.fchown(fd, uid, gid)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        if uid is not None and gid is not None:
            os.chown(path, uid, gid)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def sync_all(policy_path, agent_home_override="", bin_dir="/usr/local/bin"):
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = json.load(f)

    agent_user = policy.get("agentUser") or {}
    agent_name = agent_user.get("name", "agent")
    agent_uid = int(agent_user.get("uid", 26040)) if hasattr(os, "chown") else None
    agent_gid = int(agent_user.get("gid", 26040)) if hasattr(os, "chown") else None
    agent_home = agent_home_override or f"/home/{agent_name}"

    if not os.path.isdir(agent_home):
        return

    state_dir = os.path.join(agent_home, ".config", "wsl-agent-sandbox")
    state_file = os.path.join(state_dir, "seeded-services.json")
    seeded_state = {"services": {}}
    if os.path.isfile(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                seeded_state = json.load(f)
        except Exception:
            seeded_state = {"services": {}}

    # 1. Install helper CLIs into bin_dir if writable/requested
    if bin_dir:
        root_uid = 0 if hasattr(os, "chown") and os.geteuid() == 0 else None
        root_gid = 0 if hasattr(os, "chown") and os.geteuid() == 0 else None
        for bname, bcontent in (
            ("use-gcloud", USE_GCLOUD_SCRIPT),
            ("use-aws", USE_AWS_SCRIPT),
            ("box-context", BOX_CONTEXT_SCRIPT),
        ):
            bpath = os.path.join(bin_dir, bname)
            write_owned_file(bpath, bcontent, root_uid, root_gid, mode=0o755, dir_mode=0o755)

    # 2. Build context summary & markdown
    summary = build_context_summary(policy, seeded_state)
    summary["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    context_md = render_context_markdown(summary)
    skill_md = render_skill_markdown(summary)

    write_owned_file(
        os.path.join(state_dir, "context-summary.json"),
        json.dumps(summary, indent=2) + "\n",
        agent_uid,
        agent_gid,
        mode=0o600,
        dir_mode=0o700,
        root_Limit=agent_home,
    )
    write_owned_file(
        os.path.join(state_dir, "SANDBOX_CONTEXT.md"),
        context_md,
        agent_uid,
        agent_gid,
        mode=0o644,
        dir_mode=0o700,
        root_Limit=agent_home,
    )

    # 3. Update marker-delimited blocks in global agent instruction files
    md_targets = [
        os.path.join(agent_home, ".gemini", "GEMINI.md"),
        os.path.join(agent_home, ".claude", "CLAUDE.md"),
        os.path.join(agent_home, ".codex", "AGENTS.md"),
        os.path.join(agent_home, ".config", "opencode", "AGENTS.md"),
    ]
    for target in md_targets:
        existing = ""
        if os.path.isfile(target) and not os.path.islink(target):
            try:
                with open(target, "r", encoding="utf-8") as f:
                    existing = f.read()
            except Exception:
                existing = ""
        merged = merge_marker_block(existing, context_md)
        write_owned_file(target, merged, agent_uid, agent_gid, mode=0o644, dir_mode=0o755, root_Limit=agent_home)

    # 4. Write supplementary SKILL.md files for Gemini/Antigravity, Claude Code, and Codex
    skill_targets = [
        os.path.join(agent_home, ".gemini", "skills", "wsl-agent-sandbox", "SKILL.md"),
        os.path.join(agent_home, ".claude", "skills", "wsl-agent-sandbox", "SKILL.md"),
        os.path.join(agent_home, ".codex", "skills", "wsl-agent-sandbox", "SKILL.md"),
    ]
    for starget in skill_targets:
        write_owned_file(starget, skill_md, agent_uid, agent_gid, mode=0o644, dir_mode=0o755, root_Limit=agent_home)


def main():
    parser = argparse.ArgumentParser(description="Sync wsl-agent-sandbox agent instructions, SKILL.md, and profile switchers")
    parser.add_argument("--policy", default="/etc/wsl-agent-sandbox/policy.json")
    parser.add_argument("--agent-home", default="")
    parser.add_argument("--bin-dir", default="/usr/local/bin")
    args = parser.parse_args()
    if not os.path.isfile(args.policy):
        print(f"[box-sync-context] ERROR: Policy file not found: {args.policy}", file=sys.stderr)
        return 1
    sync_all(args.policy, agent_home_override=args.agent_home, bin_dir=args.bin_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
