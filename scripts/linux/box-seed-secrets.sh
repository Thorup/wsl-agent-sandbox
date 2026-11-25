#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[seed-secrets] ERROR: must run as root" >&2
  exit 1
fi

if [[ ! -f "${POLICY_FILE}" ]]; then
  echo "[seed-secrets] ERROR: ${POLICY_FILE} missing" >&2
  exit 1
fi

python3 - "${POLICY_FILE}" "$@" 3<&0 <<'PYEOF'
import argparse
import base64
import configparser
import datetime
import io
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

policy_file = sys.argv[1]
argv = sys.argv[2:]

parser = argparse.ArgumentParser(prog="box-seed-secrets.sh")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--apply", action="store_true", help="Read resolved JSON payload from stdin and seed credentials")
group.add_argument("--clear", action="store_true", help="Clear managed seeded credentials")
group.add_argument("--status", action="store_true", help="Print non-sensitive summary of seeded credentials")
group.add_argument("--sweep-expired", action="store_true", help="Clear any seeded services whose TTL expiresAt timestamp has passed")
parser.add_argument("--services", default="", help="Comma-separated list of services (for --clear)")
args = parser.parse_args(argv)

with open(policy_file, "r", encoding="utf-8") as f:
    policy = json.load(f)

AGENT_NAME = policy["agentUser"]["name"]
AGENT_UID = int(policy["agentUser"]["uid"])
AGENT_GID = int(policy["agentUser"]["gid"])
AGENT_HOME = f"/home/{AGENT_NAME}"

def deterministic_proxy_ports(uid):
    uid = int(uid)
    if uid == 26040:
        return 3128, 3129
    if 26100 <= uid <= 26998:
        egress = 30900 + (uid - 26100) * 2
    else:
        egress = 29100 + ((uid * 31) % 450) * 2
    return egress, egress + 1

EGRESS_PROXY_PORT, CRED_PROXY_PORT = deterministic_proxy_ports(AGENT_UID)

STATE_DIR = os.path.join(AGENT_HOME, ".config", "wsl-agent-sandbox")
KEYS_DIR = os.path.join(STATE_DIR, "keys")
ENV_D_DIR = os.path.join(STATE_DIR, "env.d")
SECRETS_ENV_FILE = os.path.join(STATE_DIR, "secrets.env")
STATE_FILE = os.path.join(STATE_DIR, "seeded-services.json")
PROFILE_SNIPPET = "/etc/profile.d/99-agent-box.sh"

SECRET_STRINGS = set()

def register_secret(val):
    if isinstance(val, str) and len(val) >= 4:
        SECRET_STRINGS.add(val)

def redact(text):
    if not text:
        return ""
    out = text
    for s in sorted(SECRET_STRINGS, key=len, reverse=True):
        out = out.replace(s, "[REDACTED]")
    return out

def ensure_agent_dir(path, mode=0o700):
    rel = os.path.relpath(path, AGENT_HOME)
    if rel.startswith(".."):
        raise ValueError(f"Refusing to create directory outside {AGENT_HOME}: {path}")
    cur = AGENT_HOME
    if rel != ".":
        parts = rel.split(os.sep)
        for i, part in enumerate(parts):
            cur = os.path.join(cur, part)
            if not os.path.exists(cur):
                dir_mode = mode if i == len(parts) - 1 else 0o755
                os.mkdir(cur, dir_mode)
                os.chown(cur, AGENT_UID, AGENT_GID)
            elif i == len(parts) - 1:
                os.chown(cur, AGENT_UID, AGENT_GID)
                os.chmod(cur, mode)

def write_agent_file(path, data, mode=0o600, dir_mode=0o700):
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = data
    parent = os.path.dirname(path)
    ensure_agent_dir(parent, mode=dir_mode)
    # Verify realpath of parent stays inside AGENT_HOME (anti-symlink-escape)
    real_home = os.path.realpath(AGENT_HOME)
    real_parent = os.path.realpath(parent)
    if real_parent != real_home and not real_parent.startswith(real_home + os.sep):
        raise ValueError(f"Refusing to write outside {AGENT_HOME}: {path}")

    fd, tmp_path = tempfile.mkstemp(prefix=".box-secret-", dir=real_parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, AGENT_UID, AGENT_GID)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        os.chown(path, AGENT_UID, AGENT_GID)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

def remove_file_quiet(path):
    try:
        if os.path.lexists(path):
            os.unlink(path)
    except OSError:
        pass

def ensure_profile_hook():
    if not os.path.isfile(PROFILE_SNIPPET):
        return
    with open(PROFILE_SNIPPET, "r", encoding="utf-8") as f:
        content = f.read()
    marker = "wsl-agent-sandbox/secrets.env"
    if marker not in content:
        hook = (
            '\n# Load seeded CLI service credentials (managed by box.ps1 seed-secrets)\n'
            'if [ -r "$HOME/.config/wsl-agent-sandbox/secrets.env" ]; then\n'
            '  . "$HOME/.config/wsl-agent-sandbox/secrets.env"\n'
            'fi\n'
        )
        with open(PROFILE_SNIPPET, "a", encoding="utf-8") as f:
            f.write(hook)
        os.chmod(PROFILE_SNIPPET, 0o644)

def agent_env(extra=None):
    env = {
        "HOME": AGENT_HOME,
        "USER": AGENT_NAME,
        "LOGNAME": AGENT_NAME,
        "PATH": f"{AGENT_HOME}/.cargo/bin:{AGENT_HOME}/.dotnet/tools:{AGENT_HOME}/.local/bin:{AGENT_HOME}/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "DOCKER_HOST": "unix:///run/docker-policy/docker.sock",
        "DOTNET_ROOT": "/usr/local/share/dotnet",
        "LANG": "C.UTF-8",
    }
    if extra:
        env.update(extra)
    return env

def run_as_agent(cmd, input_text=None, extra_env=None, check=True):
    res = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        user=AGENT_UID,
        group=AGENT_GID,
        extra_groups=[],
        env=agent_env(extra_env),
        cwd=AGENT_HOME,
    )
    if check and res.returncode != 0:
        err = redact((res.stderr or res.stdout or "").strip())
        raise RuntimeError(f"Command '{cmd[0]}' failed (exit {res.returncode}): {err}")
    return res

def load_state():
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get("services"), dict):
                return data
        except Exception:
            pass
    return {"updatedAt": None, "services": {}}

def save_state(state):
    state["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_agent_file(STATE_FILE, json.dumps(state, indent=2) + "\n", mode=0o600, dir_mode=0o700)

def write_service_env(service_name, env_dict):
    ensure_agent_dir(ENV_D_DIR, mode=0o700)
    frag = os.path.join(ENV_D_DIR, f"{service_name}.env")
    if not env_dict:
        remove_file_quiet(frag)
        return []
    lines = [f"# Managed by box.ps1 seed-secrets ({service_name})"]
    keys = []
    for k, v in env_dict.items():
        if v is None or v == "":
            continue
        keys.append(k)
        lines.append(f"export {k}={shlex.quote(str(v))}")
    if not keys:
        remove_file_quiet(frag)
        return []
    write_agent_file(frag, "\n".join(lines) + "\n", mode=0o600, dir_mode=0o700)
    return keys

def rebuild_secrets_env():
    if not os.path.isdir(ENV_D_DIR):
        remove_file_quiet(SECRETS_ENV_FILE)
        return
    frags = sorted(f for f in os.listdir(ENV_D_DIR) if f.endswith(".env"))
    if not frags:
        remove_file_quiet(SECRETS_ENV_FILE)
        return
    parts = ["# Auto-generated by box.ps1 seed-secrets — DO NOT COMMIT"]
    for name in frags:
        path = os.path.join(ENV_D_DIR, name)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                parts.append(f.read().rstrip())
    parts.append(
        '# Load interactive/persistent profile overrides (use-gcloud / use-aws)\n'
        'if [ -r "$HOME/.config/wsl-agent-sandbox/active-overrides.env" ]; then\n'
        '  . "$HOME/.config/wsl-agent-sandbox/active-overrides.env"\n'
        'fi'
    )
    write_agent_file(SECRETS_ENV_FILE, "\n\n".join(parts) + "\n", mode=0o600, dir_mode=0o700)


def clear_overrides_section(section_name):
    overrides_file = os.path.join(STATE_DIR, "active-overrides.env")
    if not os.path.isfile(overrides_file):
        return
    try:
        with open(overrides_file, "r", encoding="utf-8") as f:
            existing = f.read()
        begin_tag = f"# >>> {section_name} >>>"
        end_tag = f"# <<< {section_name} <<<"
        pattern = re.compile(
            r"^" + re.escape(begin_tag) + r"\n.*?^" + re.escape(end_tag) + r"\n?",
            re.MULTILINE | re.DOTALL,
        )
        cleaned = pattern.sub("", existing).strip()
        if cleaned:
            write_agent_file(overrides_file, cleaned + "\n", mode=0o600, dir_mode=0o700)
        else:
            remove_file_quiet(overrides_file)
    except Exception:
        pass

def parse_gh_hosts_yml(text):
    """Minimal line-preserving parser for top-level host blocks in ~/.config/gh/hosts.yml."""
    blocks = {}
    order = []
    cur_host = None
    cur_lines = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t", "#")) and line.rstrip().endswith(":"):
            if cur_host is not None:
                blocks[cur_host] = cur_lines
            cur_host = line.rstrip()[:-1].strip().strip("'\"")
            if cur_host not in order:
                order.append(cur_host)
            cur_lines = []
        elif cur_host is not None:
            cur_lines.append(line)
    if cur_host is not None:
        blocks[cur_host] = cur_lines
    return order, blocks

def render_gh_hosts_yml(order, blocks):
    out = []
    for host in order:
        if host not in blocks:
            continue
        out.append(f"{host}:")
        out.extend(blocks[host])
    return ("\n".join(out) + "\n") if out else ""

def yaml_scalar(val):
    return json.dumps(str(val))

# ------------------------------------------------------------------
# Per-service seeders
# ------------------------------------------------------------------
def seed_github(cfg, prev_meta):
    raw_profiles = cfg.get("profiles")
    if isinstance(raw_profiles, list) and len(raw_profiles) > 0:
        profiles = raw_profiles
    else:
        profiles = [
            {
                "name": "default",
                "owner": cfg.get("owner") or cfg.get("user") or "default",
                "hostname": cfg["hostname"],
                "token": cfg["token"],
                "user": cfg.get("user", ""),
                "gitProtocol": cfg.get("gitProtocol", "https"),
                "setupGit": bool(cfg.get("setupGit", True)),
                "exportEnv": bool(cfg.get("exportEnv", True)),
                "loginOnline": bool(cfg.get("loginOnline", False)),
                "proxyInject": bool(cfg.get("proxyBaseUrl")),
                "proxyBaseUrl": cfg.get("proxyBaseUrl", ""),
            }
        ]

    default_prof_name = cfg.get("defaultProfile") or profiles[0].get("name") or "default"
    active_prof = profiles[0]
    new_hosts = set()
    new_prof_names = []
    profile_details = []
    profiles_store = []

    for p in profiles:
        p_name = (p.get("name") or "default").strip()
        p_token = p["token"]
        register_secret(p_token)
        p_host = p.get("hostname", "github.com")
        p_user = p.get("user", "")
        p_owner = p.get("owner") or p_user or p_name
        p_proto = p.get("gitProtocol", "https")
        p_setup_git = bool(p.get("setupGit", True))
        p_export_env = bool(p.get("exportEnv", True))
        p_login_online = bool(p.get("loginOnline", False))
        p_proxy_url = p.get("proxyBaseUrl", "")
        new_hosts.add(p_host)
        new_prof_names.append(p_name)
        profile_details.append({
            "name": p_name,
            "owner": p_owner,
            "hostname": p_host,
            "user": p_user,
            "gitProtocol": p_proto,
            "proxyInject": bool(p_proxy_url),
        })
        profiles_store.append({
            "name": p_name,
            "owner": p_owner,
            "hostname": p_host,
            "token": p_token,
            "user": p_user,
            "gitProtocol": p_proto,
            "exportEnv": p_export_env,
            "proxyBaseUrl": p_proxy_url,
        })
        if p_name == default_prof_name:
            active_prof = p

    gh_profiles_file = os.path.join(STATE_DIR, "github-profiles.json")
    write_agent_file(
        gh_profiles_file,
        json.dumps({"defaultProfile": active_prof.get("name", "default"), "profiles": profiles_store}, indent=2) + "\n",
        mode=0o600,
        dir_mode=0o700,
    )

    hostname = active_prof.get("hostname", "github.com")
    token = active_prof["token"]
    user = active_prof.get("user", "")
    git_protocol = active_prof.get("gitProtocol", "https")
    setup_git = bool(active_prof.get("setupGit", True))
    export_env = bool(active_prof.get("exportEnv", True))
    login_online = bool(active_prof.get("loginOnline", False))
    proxy_url = active_prof.get("proxyBaseUrl", "")

    hosts_file = os.path.join(AGENT_HOME, ".config", "gh", "hosts.yml")

    if login_online:
        if proxy_url:
            raise RuntimeError("github: loginOnline cannot be used when proxyInject is enabled.")
        if not shutil.which("gh"):
            raise RuntimeError("gh CLI is not installed inside WSL.")
        run_as_agent(
            ["gh", "auth", "login", "--hostname", hostname, "--git-protocol", git_protocol, "--with-token"],
            input_text=token + "\n",
        )
    else:
        existing = ""
        if os.path.isfile(hosts_file):
            with open(hosts_file, "r", encoding="utf-8") as f:
                existing = f.read()
        order, blocks = parse_gh_hosts_yml(existing)
        # Write each distinct hostname (with active_prof winning for its hostname)
        for p in profiles:
            h = p.get("hostname", "github.com")
            win_p = active_prof if h == hostname else p
            if win_p.get("proxyBaseUrl"):
                blocks.pop(h, None)
                continue
            if h not in order:
                order.append(h)
            h_lines = [
                f"    git_protocol: {win_p.get('gitProtocol', 'https')}",
                f"    oauth_token: {yaml_scalar(win_p['token'])}",
            ]
            if win_p.get("user"):
                h_lines.append(f"    user: {yaml_scalar(win_p['user'])}")
            blocks[h] = h_lines
        remaining_order = [h for h in order if h in blocks]
        rendered = render_gh_hosts_yml(remaining_order, blocks)
        if rendered.strip():
            write_agent_file(hosts_file, rendered, mode=0o600, dir_mode=0o700)
        elif os.path.isfile(hosts_file):
            remove_file_quiet(hosts_file)

    if setup_git and not proxy_url and shutil.which("gh"):
        run_as_agent(["gh", "auth", "setup-git", "--hostname", hostname])

    env_vars = {}
    if len(profiles) > 1 or active_prof.get("name", "default") != "default":
        env_vars["WSL_BOX_GITHUB_PROFILE"] = active_prof.get("name", "default")
    if proxy_url:
        env_vars["GITHUB_API_URL"] = proxy_url
        if export_env:
            env_vars["GITHUB_TOKEN"] = token
    elif export_env:
        env_key = "GH_TOKEN" if hostname == "github.com" else "GH_ENTERPRISE_TOKEN"
        env_vars[env_key] = token
    written_keys = write_service_env("github", env_vars)
    clear_overrides_section("github")

    managed_hosts = sorted(set((prev_meta or {}).get("hosts", [])).union(new_hosts))
    return {
        "hosts": managed_hosts,
        "profiles": new_prof_names,
        "defaultProfile": active_prof.get("name", "default"),
        "profileDetails": profile_details,
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_github(prev_meta):
    hosts_file = os.path.join(AGENT_HOME, ".config", "gh", "hosts.yml")
    hosts_to_remove = set((prev_meta or {}).get("hosts", ["github.com"]))
    if os.path.isfile(hosts_file):
        with open(hosts_file, "r", encoding="utf-8") as f:
            existing = f.read()
        order, blocks = parse_gh_hosts_yml(existing)
        for h in hosts_to_remove:
            blocks.pop(h, None)
        remaining_order = [h for h in order if h in blocks]
        rendered = render_gh_hosts_yml(remaining_order, blocks)
        if rendered.strip():
            write_agent_file(hosts_file, rendered, mode=0o600, dir_mode=0o700)
        else:
            remove_file_quiet(hosts_file)
    remove_file_quiet(os.path.join(STATE_DIR, "github-profiles.json"))
    write_service_env("github", {})
    clear_overrides_section("github")

def seed_aws(cfg, prev_meta):
    aws_dir = os.path.join(AGENT_HOME, ".aws")
    cred_file = os.path.join(aws_dir, "credentials")
    conf_file = os.path.join(aws_dir, "config")

    creds = configparser.RawConfigParser()
    if os.path.isfile(cred_file):
        creds.read(cred_file, encoding="utf-8")
    conf = configparser.RawConfigParser()
    if os.path.isfile(conf_file):
        conf.read(conf_file, encoding="utf-8")

    new_profiles = []
    profiles_raw = cfg.get("profiles", [])
    if isinstance(profiles_raw, dict):
        profiles_raw = [profiles_raw]
    for p in profiles_raw:
        name = p["name"]
        new_profiles.append(name)
        ak = p["accessKeyId"]
        sk = p["secretAccessKey"]
        st = p.get("sessionToken", "")
        register_secret(sk)
        if st:
            register_secret(st)

        if not creds.has_section(name):
            creds.add_section(name)
        creds.set(name, "aws_access_key_id", ak)
        creds.set(name, "aws_secret_access_key", sk)
        if st:
            creds.set(name, "aws_session_token", st)
        elif creds.has_option(name, "aws_session_token"):
            creds.remove_option(name, "aws_session_token")

        conf_sec = "default" if name == "default" else f"profile {name}"
        region = p.get("region", "")
        output = p.get("output", "")
        if region or output:
            if not conf.has_section(conf_sec):
                conf.add_section(conf_sec)
            if region:
                conf.set(conf_sec, "region", region)
            if output:
                conf.set(conf_sec, "output", output)

    # Prune stale previously managed profiles removed during rotation
    prev_profiles = (prev_meta or {}).get("profiles", [])
    for stale in prev_profiles:
        if stale not in new_profiles:
            creds.remove_section(stale)
            conf.remove_section("default" if stale == "default" else f"profile {stale}")

    buf = io.StringIO()
    creds.write(buf)
    write_agent_file(cred_file, buf.getvalue(), mode=0o600, dir_mode=0o700)

    if conf.sections():
        cbuf = io.StringIO()
        conf.write(cbuf)
        write_agent_file(conf_file, cbuf.getvalue(), mode=0o600, dir_mode=0o700)

    env_vars = {}
    default_profile = cfg.get("defaultProfile", "")
    if default_profile:
        env_vars["AWS_PROFILE"] = default_profile
    written_keys = write_service_env("aws", env_vars)
    clear_overrides_section("aws")

    return {
        "profiles": new_profiles,
        "defaultProfile": default_profile or (new_profiles[0] if new_profiles else "default"),
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_aws(prev_meta):
    aws_dir = os.path.join(AGENT_HOME, ".aws")
    cred_file = os.path.join(aws_dir, "credentials")
    conf_file = os.path.join(aws_dir, "config")
    managed_profiles = (prev_meta or {}).get("profiles", ["default"])

    if os.path.isfile(cred_file):
        creds = configparser.RawConfigParser()
        creds.read(cred_file, encoding="utf-8")
        for p in managed_profiles:
            creds.remove_section(p)
        if creds.sections():
            buf = io.StringIO()
            creds.write(buf)
            write_agent_file(cred_file, buf.getvalue(), mode=0o600, dir_mode=0o700)
        else:
            remove_file_quiet(cred_file)

    if os.path.isfile(conf_file):
        conf = configparser.RawConfigParser()
        conf.read(conf_file, encoding="utf-8")
        for p in managed_profiles:
            conf.remove_section("default" if p == "default" else f"profile {p}")
        if conf.sections():
            cbuf = io.StringIO()
            conf.write(cbuf)
            write_agent_file(conf_file, cbuf.getvalue(), mode=0o600, dir_mode=0o700)
        else:
            remove_file_quiet(conf_file)

    write_service_env("aws", {})
    clear_overrides_section("aws")

def seed_gcloud(cfg, prev_meta):
    raw_projects = cfg.get("projects")
    if isinstance(raw_projects, list) and len(raw_projects) > 0:
        projects = raw_projects
    else:
        projects = [
            {
                "name": "default",
                "serviceAccountKeyJson": cfg["serviceAccountKeyJson"],
                "clientEmail": cfg.get("clientEmail", ""),
                "project": cfg.get("project", ""),
                "region": cfg.get("region", ""),
                "zone": cfg.get("zone", ""),
            }
        ]

    set_adc = bool(cfg.get("setApplicationDefaultCredentials", True))
    skip_activate = bool(cfg.get("skipActivate", False))
    default_cfg_name = cfg.get("defaultProject") or projects[0].get("name") or "default"
    is_single_default = len(projects) == 1 and (projects[0].get("name") or "default") == "default"

    gcloud_dir = os.path.join(AGENT_HOME, ".config", "gcloud")
    configs_dir = os.path.join(gcloud_dir, "configurations")

    new_key_paths = []
    new_cfg_names = []
    new_emails = []
    project_details = []
    active_entry = projects[0]
    active_key_path = ""

    for item in projects:
        cfg_name = (item.get("name") or "default").strip()
        if not re.match(r"^[a-z0-9][-a-z0-9]{0,62}$", cfg_name):
            raise RuntimeError(f"Invalid gcloud configuration name: {cfg_name}")
        key_json = item["serviceAccountKeyJson"]
        register_secret(key_json)
        try:
            parsed = json.loads(key_json)
            register_secret(parsed.get("private_key", ""))
        except Exception:
            parsed = {}
        client_email = item.get("clientEmail") or parsed.get("client_email", "")
        project = item.get("project") or parsed.get("project_id", "")
        region = item.get("region", "")
        zone = item.get("zone", "")

        if is_single_default:
            key_path = os.path.join(KEYS_DIR, "gcloud-service-account.json")
        else:
            key_path = os.path.join(KEYS_DIR, f"gcloud-{cfg_name}.json")
        write_agent_file(key_path, key_json, mode=0o600, dir_mode=0o700)

        # Ensure the named configuration file exists with account/project/region/zone
        gcloud_cfg_path = os.path.join(configs_dir, f"config_{cfg_name}")
        gcfg = configparser.RawConfigParser()
        if os.path.isfile(gcloud_cfg_path):
            gcfg.read(gcloud_cfg_path, encoding="utf-8")
        if client_email or project:
            if not gcfg.has_section("core"):
                gcfg.add_section("core")
            if client_email:
                gcfg.set("core", "account", client_email)
            if project:
                gcfg.set("core", "project", project)
        if region or zone:
            if not gcfg.has_section("compute"):
                gcfg.add_section("compute")
            if region:
                gcfg.set("compute", "region", region)
            if zone:
                gcfg.set("compute", "zone", zone)
        gbuf = io.StringIO()
        gcfg.write(gbuf)
        write_agent_file(gcloud_cfg_path, gbuf.getvalue(), mode=0o600, dir_mode=0o700)

        if shutil.which("gcloud") and not skip_activate:
            cmd = [
                "gcloud",
                "auth",
                "activate-service-account",
                f"--key-file={key_path}",
                f"--configuration={cfg_name}",
                "--quiet",
            ]
            if project:
                cmd.append(f"--project={project}")
            run_as_agent(cmd)
            if region:
                run_as_agent(["gcloud", "config", "set", "compute/region", region, f"--configuration={cfg_name}", "--quiet"])
            if zone:
                run_as_agent(["gcloud", "config", "set", "compute/zone", zone, f"--configuration={cfg_name}", "--quiet"])

        new_key_paths.append(key_path)
        new_cfg_names.append(cfg_name)
        if client_email and client_email not in new_emails:
            new_emails.append(client_email)
        project_details.append({
            "name": cfg_name,
            "project": project,
            "clientEmail": client_email,
            "region": region,
            "zone": zone,
            "keyPath": key_path,
            "setAdc": set_adc,
        })
        if cfg_name == default_cfg_name or not active_key_path:
            active_entry = {
                "name": cfg_name,
                "clientEmail": client_email,
                "project": project,
                "region": region,
                "zone": zone,
            }
            active_key_path = key_path

    # Set active_config to default_cfg_name
    write_agent_file(os.path.join(gcloud_dir, "active_config"), default_cfg_name + "\n", mode=0o600, dir_mode=0o700)

    # Prune any stale managed key files, configurations, and accounts from previous seed
    old_key_paths = (prev_meta or {}).get("keyPaths", [])
    if not old_key_paths and (prev_meta or {}).get("keyPath"):
        old_key_paths = [prev_meta["keyPath"]]
    for old_kp in old_key_paths:
        if old_kp not in new_key_paths:
            remove_file_quiet(old_kp)

    old_cfg_names = (prev_meta or {}).get("profiles", [])
    for old_cfg in old_cfg_names:
        if old_cfg not in new_cfg_names and old_cfg != "default":
            remove_file_quiet(os.path.join(configs_dir, f"config_{old_cfg}"))

    old_emails = (prev_meta or {}).get("clientEmails", [])
    if not old_emails and (prev_meta or {}).get("clientEmail"):
        old_emails = [prev_meta["clientEmail"]]
    if shutil.which("gcloud"):
        for old_em in old_emails:
            if old_em and old_em not in new_emails:
                run_as_agent(["gcloud", "auth", "revoke", old_em, "--quiet"], check=False)

    env_vars = {}
    if set_adc and active_key_path:
        env_vars["GOOGLE_APPLICATION_CREDENTIALS"] = active_key_path
    if active_entry.get("project"):
        env_vars["GOOGLE_CLOUD_PROJECT"] = active_entry["project"]
        if len(projects) == 1:
            env_vars["CLOUDSDK_CORE_PROJECT"] = active_entry["project"]
    if len(projects) == 1:
        if active_entry.get("region"):
            env_vars["CLOUDSDK_COMPUTE_REGION"] = active_entry["region"]
        if active_entry.get("zone"):
            env_vars["CLOUDSDK_COMPUTE_ZONE"] = active_entry["zone"]
    written_keys = write_service_env("gcloud", env_vars)
    clear_overrides_section("gcloud")

    return {
        "clientEmail": active_entry.get("clientEmail", ""),
        "clientEmails": new_emails,
        "project": active_entry.get("project", ""),
        "profiles": new_cfg_names,
        "defaultProject": active_entry.get("name", "default"),
        "projectDetails": project_details,
        "keyPath": active_key_path,
        "keyPaths": new_key_paths,
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_gcloud(prev_meta):
    gcloud_dir = os.path.join(AGENT_HOME, ".config", "gcloud")
    configs_dir = os.path.join(gcloud_dir, "configurations")

    key_paths = (prev_meta or {}).get("keyPaths", [])
    if not key_paths:
        key_paths = [(prev_meta or {}).get("keyPath", os.path.join(KEYS_DIR, "gcloud-service-account.json"))]
    client_emails = (prev_meta or {}).get("clientEmails", [])
    if not client_emails and (prev_meta or {}).get("clientEmail"):
        client_emails = [prev_meta["clientEmail"]]
    if shutil.which("gcloud"):
        for em in client_emails:
            if em:
                run_as_agent(["gcloud", "auth", "revoke", em, "--quiet"], check=False)
    for kp in key_paths:
        remove_file_quiet(kp)
    for cfg_name in (prev_meta or {}).get("profiles", []):
        if cfg_name != "default":
            remove_file_quiet(os.path.join(configs_dir, f"config_{cfg_name}"))
    if os.path.isfile(os.path.join(gcloud_dir, "active_config")):
        write_agent_file(os.path.join(gcloud_dir, "active_config"), "default\n", mode=0o600, dir_mode=0o700)
    write_service_env("gcloud", {})
    clear_overrides_section("gcloud")

def seed_azure(cfg, prev_meta):
    client_id = cfg["clientId"]
    tenant_id = cfg["tenantId"]
    client_secret = cfg.get("clientSecret", "")
    cert_pem = cfg.get("certificatePem", "")
    subscription = cfg.get("subscription", "")
    allow_no_subs = bool(cfg.get("allowNoSubscriptions", False))
    export_env = bool(cfg.get("exportEnv", True))
    skip_login = bool(cfg.get("skipLogin", False))

    if client_secret:
        register_secret(client_secret)
    if cert_pem:
        register_secret(cert_pem)

    cert_path = os.path.join(KEYS_DIR, "azure-sp.pem")
    if cert_pem:
        write_agent_file(cert_path, cert_pem, mode=0o600, dir_mode=0o700)
        cred_arg = cert_path
    else:
        remove_file_quiet(cert_path)
        cred_arg = client_secret

    if not skip_login:
        if not shutil.which("az"):
            raise RuntimeError("Azure CLI (az) is not installed inside WSL.")
        cmd = [
            "az", "login", "--service-principal",
            "--username", client_id,
            "--password", cred_arg,
            "--tenant", tenant_id,
            "--output", "none",
        ]
        if allow_no_subs:
            cmd.append("--allow-no-subscriptions")
        run_as_agent(cmd)
        if subscription:
            run_as_agent(["az", "account", "set", "--subscription", subscription])

    env_vars = {}
    if export_env:
        env_vars["AZURE_CLIENT_ID"] = client_id
        env_vars["AZURE_TENANT_ID"] = tenant_id
        if cert_pem:
            env_vars["AZURE_CLIENT_CERTIFICATE_PATH"] = cert_path
        else:
            env_vars["AZURE_CLIENT_SECRET"] = client_secret
        if subscription:
            env_vars["AZURE_SUBSCRIPTION_ID"] = subscription
    written_keys = write_service_env("azure", env_vars)

    return {
        "clientId": client_id,
        "tenantId": tenant_id,
        "certPath": cert_path if cert_pem else "",
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_azure(prev_meta):
    if shutil.which("az"):
        run_as_agent(["az", "logout"], check=False)
    remove_file_quiet(os.path.join(KEYS_DIR, "azure-sp.pem"))
    write_service_env("azure", {})

def seed_azure_devops(cfg, prev_meta):
    org = cfg["organization"]
    project = cfg.get("project", "")
    pat = cfg["pat"]
    register_secret(pat)

    written_keys = write_service_env("azureDevops", {"AZURE_DEVOPS_EXT_PAT": pat})

    if shutil.which("az"):
        defaults = [f"organization={org}"]
        if project:
            defaults.append(f"project={project}")
        run_as_agent(["az", "devops", "configure", "--defaults"] + defaults)

    return {
        "organization": org,
        "project": project,
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_azure_devops(prev_meta):
    if shutil.which("az"):
        run_as_agent(["az", "devops", "configure", "--defaults", "organization=", "project="], check=False)
    write_service_env("azureDevops", {})

def seed_jira(cfg, prev_meta):
    server = cfg["server"]
    login = cfg["login"]
    api_token = cfg["apiToken"]
    register_secret(api_token)
    installation = cfg.get("installation", "cloud")
    auth_type = cfg.get("authType", "basic")
    project_key = cfg.get("projectKey", "")
    project_type = cfg.get("projectType", "")
    board_id = cfg.get("boardId", None)
    board_name = cfg.get("boardName", "")
    board_type = cfg.get("boardType", "")

    lines = [
        f"installation: {yaml_scalar(installation)}",
        f"server: {yaml_scalar(server)}",
        f"login: {yaml_scalar(login)}",
        f"auth_type: {yaml_scalar(auth_type)}",
    ]
    if project_key or project_type:
        lines.append("project:")
        if project_key:
            lines.append(f"  key: {yaml_scalar(project_key)}")
        if project_type:
            lines.append(f"  type: {yaml_scalar(project_type)}")
    if board_id is not None or board_name or board_type:
        lines.append("board:")
        if board_id is not None:
            lines.append(f"  id: {int(board_id)}")
        if board_name:
            lines.append(f"  name: {yaml_scalar(board_name)}")
        if board_type:
            lines.append(f"  type: {yaml_scalar(board_type)}")

    jira_cfg = os.path.join(AGENT_HOME, ".config", ".jira", ".config.yml")
    write_agent_file(jira_cfg, "\n".join(lines) + "\n", mode=0o600, dir_mode=0o700)
    written_keys = write_service_env("jira", {"JIRA_API_TOKEN": api_token})

    return {
        "server": server,
        "login": login,
        "configPath": jira_cfg,
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_jira(prev_meta):
    remove_file_quiet(os.path.join(AGENT_HOME, ".config", ".jira", ".config.yml"))
    write_service_env("jira", {})

def seed_upcloud(cfg, prev_meta):
    token = cfg.get("token", "")
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    export_env = bool(cfg.get("exportEnv", True))

    if token:
        register_secret(token)
    if password:
        register_secret(password)

    upctl_cfg = os.path.join(AGENT_HOME, ".config", "upctl.yaml")
    env_vars = {}
    if token:
        content = f"token: {yaml_scalar(token)}\n"
        if export_env:
            env_vars["UPCLOUD_TOKEN"] = token
    else:
        content = f"username: {yaml_scalar(username)}\npassword: {yaml_scalar(password)}\n"
        if export_env:
            env_vars["UPCLOUD_USERNAME"] = username
            env_vars["UPCLOUD_PASSWORD"] = password

    write_agent_file(upctl_cfg, content, mode=0o600, dir_mode=0o700)
    written_keys = write_service_env("upcloud", env_vars)

    return {
        "authMode": "token" if token else "username",
        "configPath": upctl_cfg,
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_upcloud(prev_meta):
    remove_file_quiet(os.path.join(AGENT_HOME, ".config", "upctl.yaml"))
    write_service_env("upcloud", {})

def seed_kubectl(cfg, prev_meta):
    kube_cfg = os.path.join(AGENT_HOME, ".kube", "config")
    mode = cfg.get("mode", "file")
    context = cfg.get("context", "")

    if mode == "file":
        content = cfg["kubeconfigContent"]
        write_agent_file(kube_cfg, content, mode=0o600, dir_mode=0o700)
    else:
        server = cfg["server"]
        token = cfg["token"]
        register_secret(token)
        ca_data = cfg.get("caCertData", "")
        insecure = bool(cfg.get("insecureSkipTlsVerify", False))
        ns = cfg.get("namespace", "default")
        cluster_name = cfg.get("clusterName", "sandbox")
        user_name = cfg.get("userName", "sandbox-sa")
        ctx_name = cfg.get("contextName", "sandbox")

        lines = [
            "apiVersion: v1",
            "kind: Config",
            "clusters:",
            f"- name: {yaml_scalar(cluster_name)}",
            "  cluster:",
            f"    server: {yaml_scalar(server)}",
        ]
        if ca_data:
            lines.append(f"    certificate-authority-data: {yaml_scalar(ca_data)}")
        elif insecure:
            lines.append("    insecure-skip-tls-verify: true")
        lines.extend([
            "users:",
            f"- name: {yaml_scalar(user_name)}",
            "  user:",
            f"    token: {yaml_scalar(token)}",
            "contexts:",
            f"- name: {yaml_scalar(ctx_name)}",
            "  context:",
            f"    cluster: {yaml_scalar(cluster_name)}",
            f"    user: {yaml_scalar(user_name)}",
            f"    namespace: {yaml_scalar(ns)}",
            f"current-context: {yaml_scalar(ctx_name)}",
        ])
        write_agent_file(kube_cfg, "\n".join(lines) + "\n", mode=0o600, dir_mode=0o700)

    if context and shutil.which("kubectl"):
        run_as_agent(["kubectl", "config", "use-context", context])

    return {
        "mode": mode,
        "configPath": kube_cfg,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_kubectl(prev_meta):
    remove_file_quiet(os.path.join(AGENT_HOME, ".kube", "config"))

def seed_gemini(cfg, prev_meta):
    api_key = cfg.get("apiKey", "")
    if api_key:
        register_secret(api_key)
    env_vars = {}
    if api_key:
        env_vars["GEMINI_API_KEY"] = api_key
    if cfg.get("googleCloudProject"):
        env_vars["GOOGLE_CLOUD_PROJECT"] = cfg["googleCloudProject"]
    if cfg.get("googleCloudLocation"):
        env_vars["GOOGLE_CLOUD_LOCATION"] = cfg["googleCloudLocation"]
    if cfg.get("useVertexAi"):
        env_vars["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
    if cfg.get("proxyBaseUrl"):
        env_vars["GOOGLE_GEMINI_BASE_URL"] = cfg["proxyBaseUrl"]
    written_keys = write_service_env("gemini", env_vars)
    return {
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_gemini(prev_meta):
    write_service_env("gemini", {})

def seed_claude(cfg, prev_meta):
    api_key = cfg.get("apiKey", "")
    oauth = cfg.get("oauthToken", "")
    if api_key:
        register_secret(api_key)
    if oauth:
        register_secret(oauth)
    env_vars = {}
    if api_key:
        env_vars["ANTHROPIC_API_KEY"] = api_key
    if oauth:
        env_vars["CLAUDE_CODE_OAUTH_TOKEN"] = oauth
    if cfg.get("proxyBaseUrl"):
        env_vars["ANTHROPIC_BASE_URL"] = cfg["proxyBaseUrl"]
    written_keys = write_service_env("claude", env_vars)
    return {
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_claude(prev_meta):
    write_service_env("claude", {})

SSH_DIR = os.path.join(AGENT_HOME, ".ssh")
SSH_MANAGED_DIR = os.path.join(SSH_DIR, "wsl-agent-sandbox")
SSH_CONFIG_FILE = os.path.join(SSH_DIR, "config")
SSH_KNOWN_HOSTS_FILE = os.path.join(SSH_MANAGED_DIR, "known_hosts")

GIT_SSH_MANAGED_DIR = os.path.join(SSH_DIR, "wsl-agent-sandbox-git")
GIT_KNOWN_HOSTS_FILE = os.path.join(GIT_SSH_MANAGED_DIR, "known_hosts")
GIT_ALLOWED_SIGNERS_FILE = os.path.join(GIT_SSH_MANAGED_DIR, "allowed_signers")
GIT_MANAGED_CONFIG_FILE = os.path.join(STATE_DIR, "gitconfig")
GIT_USER_CONFIG_FILE = os.path.join(AGENT_HOME, ".gitconfig")

GIT_SSH_HOSTS_START = "# >>> wsl-agent-sandbox managed git ssh hosts (DO NOT EDIT) >>>"
GIT_SSH_HOSTS_END = "# <<< wsl-agent-sandbox managed git ssh hosts <<<"
SSH_HOSTS_START = "# >>> wsl-agent-sandbox managed ssh hosts (DO NOT EDIT) >>>"
SSH_HOSTS_END = "# <<< wsl-agent-sandbox managed ssh hosts <<<"
SSH_DEFAULTS_START = "# >>> wsl-agent-sandbox managed ssh defaults (DO NOT EDIT) >>>"
SSH_DEFAULTS_END = "# <<< wsl-agent-sandbox managed ssh defaults <<<"

GIT_CONFIG_INCLUDE_START = "# >>> wsl-agent-sandbox managed git config (DO NOT EDIT) >>>"
GIT_CONFIG_INCLUDE_END = "# <<< wsl-agent-sandbox managed git config <<<"

def register_ssh_private_key(pem_text):
    if not pem_text:
        return
    register_secret(pem_text)
    for line in pem_text.splitlines():
        s = line.strip()
        if s and not s.startswith("-----"):
            register_secret(s)

def strip_managed_block(text, start_marker, end_marker):
    out = []
    skipping = False
    for line in text.splitlines():
        s = line.strip()
        if s == start_marker:
            skipping = True
            continue
        if skipping:
            if s == end_marker:
                skipping = False
            continue
        out.append(line)
    return "\n".join(out)

def extract_managed_block(text, start_marker, end_marker):
    out = []
    capturing = False
    for line in text.splitlines():
        s = line.strip()
        if s == start_marker:
            capturing = True
            out.append(line)
            continue
        if capturing:
            out.append(line)
            if s == end_marker:
                capturing = False
    return "\n".join(out).strip("\n")

def update_ssh_config(git_hosts_block=None, ssh_hosts_block=None, ssh_defaults_block=None):
    existing = ""
    if os.path.isfile(SSH_CONFIG_FILE):
        with open(SSH_CONFIG_FILE, "r", encoding="utf-8") as f:
            existing = f.read()

    eff_git_hosts = (
        extract_managed_block(existing, GIT_SSH_HOSTS_START, GIT_SSH_HOSTS_END)
        if git_hosts_block is None
        else git_hosts_block.strip("\n")
    )
    eff_ssh_hosts = (
        extract_managed_block(existing, SSH_HOSTS_START, SSH_HOSTS_END)
        if ssh_hosts_block is None
        else ssh_hosts_block.strip("\n")
    )
    eff_ssh_defaults = (
        extract_managed_block(existing, SSH_DEFAULTS_START, SSH_DEFAULTS_END)
        if ssh_defaults_block is None
        else ssh_defaults_block.strip("\n")
    )

    user_body = strip_managed_block(existing, GIT_SSH_HOSTS_START, GIT_SSH_HOSTS_END)
    user_body = strip_managed_block(user_body, SSH_HOSTS_START, SSH_HOSTS_END)
    user_body = strip_managed_block(user_body, SSH_DEFAULTS_START, SSH_DEFAULTS_END)
    user_body = user_body.strip("\n")

    sections = []
    if eff_git_hosts:
        sections.append(eff_git_hosts)
    if eff_ssh_hosts:
        sections.append(eff_ssh_hosts)
    if user_body.strip():
        sections.append(user_body)
    if eff_ssh_defaults:
        sections.append(eff_ssh_defaults)

    if sections:
        ensure_agent_dir(SSH_DIR, mode=0o700)
        write_agent_file(SSH_CONFIG_FILE, "\n\n".join(sections) + "\n", mode=0o600, dir_mode=0o700)
    else:
        remove_file_quiet(SSH_CONFIG_FILE)

def merge_ssh_config(hosts_block, defaults_block):
    update_ssh_config(ssh_hosts_block=hosts_block, ssh_defaults_block=defaults_block)

def gitconfig_quote(val):
    s = str(val).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'

def known_hosts_covers_host(known_hosts_lines, hostname, port=None):
    targets = {hostname.lower()}
    if port is not None and int(port) != 22:
        targets.add(f"[{hostname.lower()}]:{int(port)}")
    for line in known_hosts_lines:
        parts = line.split()
        if not parts:
            continue
        host_field = parts[0]
        if host_field.startswith("@"):
            if len(parts) < 2:
                continue
            host_field = parts[1]
        for token in host_field.split(","):
            if token.strip().lower() in targets:
                return True
    return False

def update_gitconfig_include(enable_include):
    existing = ""
    if os.path.isfile(GIT_USER_CONFIG_FILE):
        with open(GIT_USER_CONFIG_FILE, "r", encoding="utf-8") as f:
            existing = f.read()
    user_body = strip_managed_block(existing, GIT_CONFIG_INCLUDE_START, GIT_CONFIG_INCLUDE_END).strip("\n")

    sections = []
    if user_body.strip():
        sections.append(user_body)
    if enable_include:
        include_block = "\n".join([
            GIT_CONFIG_INCLUDE_START,
            "[include]",
            f"\tpath = {GIT_MANAGED_CONFIG_FILE}",
            GIT_CONFIG_INCLUDE_END,
        ])
        sections.append(include_block)

    if sections:
        write_agent_file(GIT_USER_CONFIG_FILE, "\n\n".join(sections) + "\n", mode=0o644, dir_mode=0o755)
    else:
        remove_file_quiet(GIT_USER_CONFIG_FILE)

def derive_public_key_line(priv_path):
    if not shutil.which("ssh-keygen"):
        return ""
    res = run_as_agent(["ssh-keygen", "-y", "-f", priv_path], check=False)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip().splitlines()[0].strip()
    return ""

def derive_public_key_from_private_text(priv_raw):
    if not shutil.which("ssh-keygen"):
        return ""
    import tempfile
    os.makedirs("/run/box-root", mode=0o700, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="pubderive-", dir="/run/box-root")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            tf.write(priv_raw)
        os.chmod(tmp_path, 0o600)
        res = subprocess.run(["ssh-keygen", "-y", "-f", tmp_path], check=False, text=True, capture_output=True)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().splitlines()[0].strip()
        return ""
    finally:
        remove_file_quiet(tmp_path)

def extract_pubkey_blob_hex(pub_line):
    parts = (pub_line or "").strip().split()
    if len(parts) < 2:
        return ""
    try:
        return base64.b64decode(parts[1]).hex().lower()
    except Exception:
        return ""

def seed_git(cfg, prev_meta):
    ensure_agent_dir(SSH_DIR, mode=0o700)
    ensure_agent_dir(GIT_SSH_MANAGED_DIR, mode=0o700)

    is_agent_proxy = (cfg.get("mode") == "agent-proxy")
    agent_proxy_keys = []

    keys_raw = cfg.get("keys") or []
    if isinstance(keys_raw, dict):
        keys_raw = [keys_raw]
    hosts_raw = cfg.get("hosts") or []
    if isinstance(hosts_raw, dict):
        hosts_raw = [hosts_raw]
    known_hosts_raw = cfg.get("knownHosts") or []
    if isinstance(known_hosts_raw, str):
        known_hosts_raw = [known_hosts_raw]

    expected_basenames = set()
    key_paths = {}
    pub_keys = {}
    cert_paths = {}
    key_names = []

    for k in keys_raw:
        k_name = k["name"]
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", k_name) or k_name in ("known_hosts", "config", "allowed_signers"):
            raise ValueError(f"Invalid Git SSH key name: {k_name}")
        priv_raw = k["privateKey"].replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
        register_ssh_private_key(priv_raw)

        pub_raw = (k.get("publicKey") or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        pub_norm = pub_raw or derive_public_key_from_private_text(priv_raw)

        if is_agent_proxy:
            if not pub_norm:
                raise ValueError(f"Failed to derive public key for Git SSH key '{k_name}' in agent-proxy mode.")
            blob_hex = extract_pubkey_blob_hex(pub_norm)
            if not blob_hex:
                raise ValueError(f"Invalid public key material for Git SSH key '{k_name}'.")
            pub_basename = f"{k_name}.pub"
            pub_path = os.path.join(GIT_SSH_MANAGED_DIR, pub_basename)
            write_agent_file(pub_path, pub_norm + "\n", mode=0o644, dir_mode=0o700)
            expected_basenames.add(pub_basename)
            key_paths[k_name] = pub_path
            pub_keys[k_name] = pub_norm
            key_names.append(k_name)
            agent_proxy_keys.append({"name": k_name, "privateKey": priv_raw, "blobHex": blob_hex})
        else:
            priv_path = os.path.join(GIT_SSH_MANAGED_DIR, k_name)
            write_agent_file(priv_path, priv_raw, mode=0o600, dir_mode=0o700)
            expected_basenames.add(k_name)
            key_paths[k_name] = priv_path
            key_names.append(k_name)
            if pub_raw:
                pub_basename = f"{k_name}.pub"
                write_agent_file(
                    os.path.join(GIT_SSH_MANAGED_DIR, pub_basename),
                    pub_norm + "\n",
                    mode=0o644,
                    dir_mode=0o700,
                )
                expected_basenames.add(pub_basename)
                pub_keys[k_name] = pub_norm

        cert_raw = k.get("certificate") or ""
        if cert_raw.strip():
            cert_basename = f"{k_name}-cert.pub"
            cert_path = os.path.join(GIT_SSH_MANAGED_DIR, cert_basename)
            write_agent_file(
                cert_path,
                cert_raw.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n",
                mode=0o644,
                dir_mode=0o700,
            )
            expected_basenames.add(cert_basename)
            cert_paths[k_name] = cert_path
            if is_agent_proxy:
                cert_blob_hex = extract_pubkey_blob_hex(cert_raw)
                if not cert_blob_hex:
                    raise ValueError(f"Invalid certificate material for Git SSH key '{k_name}'.")
                agent_proxy_keys[-1]["certBlobHex"] = cert_blob_hex

    has_known_hosts = False
    cleaned_kh = [line.strip() for line in known_hosts_raw if isinstance(line, str) and line.strip()]
    if cleaned_kh:
        write_agent_file(GIT_KNOWN_HOSTS_FILE, "\n".join(cleaned_kh) + "\n", mode=0o600, dir_mode=0o700)
        expected_basenames.add("known_hosts")
        has_known_hosts = True

    user_name = (cfg.get("userName") or "").strip()
    user_email = (cfg.get("userEmail") or "").strip()

    signing_cfg = cfg.get("signing")
    signing_key_name = ""
    allowed_signers_lines = []
    if isinstance(signing_cfg, dict) and signing_cfg.get("key"):
        s_key = signing_cfg["key"]
        if s_key not in key_paths:
            raise ValueError(f"git.signing key '{s_key}' was not materialized.")
        signing_key_name = s_key
        raw_as = signing_cfg.get("allowedSigners") or []
        if isinstance(raw_as, str):
            raw_as = [raw_as]
        for line in raw_as:
            if isinstance(line, str) and line.strip():
                allowed_signers_lines.append(line.strip())
        if user_email:
            pub_line = pub_keys.get(s_key) or derive_public_key_line(key_paths[s_key])
            if pub_line:
                pub_parts = pub_line.split()
                if len(pub_parts) >= 2:
                    auto_signer = f'{user_email} namespaces="git" {pub_parts[0]} {pub_parts[1]}'
                    if auto_signer not in allowed_signers_lines:
                        allowed_signers_lines.append(auto_signer)
        if allowed_signers_lines:
            write_agent_file(
                GIT_ALLOWED_SIGNERS_FILE,
                "\n".join(allowed_signers_lines) + "\n",
                mode=0o644,
                dir_mode=0o700,
            )
            expected_basenames.add("allowed_signers")

    # Prune any stale managed files inside GIT_SSH_MANAGED_DIR
    real_home = os.path.realpath(AGENT_HOME)
    real_managed = os.path.realpath(GIT_SSH_MANAGED_DIR)
    if real_managed.startswith(real_home + os.sep) and os.path.isdir(real_managed):
        for entry in os.listdir(real_managed):
            if entry not in expected_basenames:
                remove_file_quiet(os.path.join(real_managed, entry))

    global_shkc = cfg.get("strictHostKeyChecking") or ""
    global_identities_only = bool(cfg.get("identitiesOnly", True))
    global_forward_agent = bool(cfg.get("forwardAgent", False))
    global_alive = cfg.get("serverAliveInterval", None)
    global_timeout = cfg.get("connectTimeout", None)
    global_batch = cfg.get("batchMode", True)

    user_known_hosts_value = f"{os.path.join(SSH_DIR, 'known_hosts')} {GIT_KNOWN_HOSTS_FILE}"

    host_names = []
    hosts_lines = []
    url_rewrites = []
    for h in hosts_raw:
        h_name = h["name"]
        h_hostname = h["hostName"]
        h_user = h.get("user") or "git"
        host_names.append(h_name)
        hosts_lines.append(f"Host {h_name}")
        hosts_lines.append(f"  HostName {h_hostname}")
        hosts_lines.append(f"  User {h_user}")
        if h.get("port") is not None:
            hosts_lines.append(f"  Port {int(h['port'])}")
        h_key = h.get("key") or ""
        if h_key and h_key in key_paths:
            hosts_lines.append(f"  IdentityFile {key_paths[h_key]}")
            if h_key in cert_paths:
                hosts_lines.append(f"  CertificateFile {cert_paths[h_key]}")
        if h.get("proxyJump"):
            hosts_lines.append(f"  ProxyJump {h['proxyJump']}")

        h_io = h.get("identitiesOnly")
        eff_io = global_identities_only if h_io is None else bool(h_io)
        hosts_lines.append(f"  IdentitiesOnly {'yes' if eff_io else 'no'}")

        h_fa = h.get("forwardAgent")
        eff_fa = global_forward_agent if h_fa is None else bool(h_fa)
        hosts_lines.append(f"  ForwardAgent {'yes' if eff_fa else 'no'}")

        host_pinned = bool(h.get("hasPinnedKnownHost")) or known_hosts_covers_host(cleaned_kh, h_hostname, h.get("port"))
        eff_shkc = h.get("strictHostKeyChecking") or global_shkc or ("yes" if host_pinned else "accept-new")
        hosts_lines.append(f"  StrictHostKeyChecking {eff_shkc}")

        if has_known_hosts:
            hosts_lines.append(f"  UserKnownHostsFile {user_known_hosts_value}")

        eff_alive = h.get("serverAliveInterval") if h.get("serverAliveInterval") is not None else global_alive
        if eff_alive is not None:
            hosts_lines.append(f"  ServerAliveInterval {int(eff_alive)}")

        eff_timeout = h.get("connectTimeout") if h.get("connectTimeout") is not None else global_timeout
        if eff_timeout is not None:
            hosts_lines.append(f"  ConnectTimeout {int(eff_timeout)}")

        eff_batch = h.get("batchMode") if h.get("batchMode") is not None else global_batch
        if eff_batch is not None:
            hosts_lines.append(f"  BatchMode {'yes' if eff_batch else 'no'}")
        hosts_lines.append("")

        if h.get("rewriteHttpsToSsh"):
            url_rewrites.append((h_user, h_name, h_hostname))

    git_hosts_block = ""
    if hosts_lines:
        git_hosts_block = "\n".join([GIT_SSH_HOSTS_START] + hosts_lines[:-1] + [GIT_SSH_HOSTS_END])

    update_ssh_config(git_hosts_block=git_hosts_block)

    # Render managed gitconfig if any identity, signing, or URL rewrites are configured
    gc_lines = []
    if user_name or user_email or signing_key_name:
        gc_lines.append("[user]")
        if user_name:
            gc_lines.append(f"\tname = {gitconfig_quote(user_name)}")
        if user_email:
            gc_lines.append(f"\temail = {gitconfig_quote(user_email)}")
        if signing_key_name:
            gc_lines.append(f"\tsigningkey = {gitconfig_quote(key_paths[signing_key_name])}")

    if signing_key_name:
        gc_lines.append("[gpg]")
        gc_lines.append("\tformat = ssh")
        if allowed_signers_lines:
            gc_lines.append('[gpg "ssh"]')
            gc_lines.append(f"\tallowedSignersFile = {gitconfig_quote(GIT_ALLOWED_SIGNERS_FILE)}")
        if bool(signing_cfg.get("signCommits", True)):
            gc_lines.append("[commit]")
            gc_lines.append("\tgpgsign = true")
        if bool(signing_cfg.get("signTags", False)):
            gc_lines.append("[tag]")
            gc_lines.append("\tgpgsign = true")

    for r_user, r_alias, r_hostname in url_rewrites:
        gc_lines.append(f'[url "ssh://{r_user}@{r_alias}/"]')
        gc_lines.append(f"\tinsteadOf = https://{r_hostname}/")

    if gc_lines:
        gc_content = "# Auto-generated by box.ps1 seed-secrets (git) — DO NOT EDIT\n" + "\n".join(gc_lines) + "\n"
        write_agent_file(GIT_MANAGED_CONFIG_FILE, gc_content, mode=0o600, dir_mode=0o700)
        update_gitconfig_include(True)
    else:
        remove_file_quiet(GIT_MANAGED_CONFIG_FILE)
        update_gitconfig_include(False)

    return {
        "mode": "agent-proxy" if is_agent_proxy else "files",
        "keys": key_names,
        "hosts": host_names,
        "knownHostsCount": len(cleaned_kh),
        "signingKey": signing_key_name,
        "userEmail": user_email,
        "managedDir": GIT_SSH_MANAGED_DIR,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_agentProxyKeys": agent_proxy_keys,
    }

def clear_git(prev_meta):
    update_ssh_config(git_hosts_block="")
    remove_file_quiet(GIT_MANAGED_CONFIG_FILE)
    update_gitconfig_include(False)
    real_home = os.path.realpath(AGENT_HOME)
    if os.path.isdir(GIT_SSH_MANAGED_DIR):
        real_managed = os.path.realpath(GIT_SSH_MANAGED_DIR)
        if real_managed.startswith(real_home + os.sep):
            for entry in os.listdir(real_managed):
                remove_file_quiet(os.path.join(real_managed, entry))
            try:
                os.rmdir(real_managed)
            except OSError:
                pass

def seed_ssh(cfg, prev_meta):
    ensure_agent_dir(SSH_DIR, mode=0o700)
    ensure_agent_dir(SSH_MANAGED_DIR, mode=0o700)

    is_agent_proxy = (cfg.get("mode") == "agent-proxy")
    agent_proxy_keys = []

    keys_raw = cfg.get("keys") or []
    if isinstance(keys_raw, dict):
        keys_raw = [keys_raw]
    hosts_raw = cfg.get("hosts") or []
    if isinstance(hosts_raw, dict):
        hosts_raw = [hosts_raw]
    known_hosts_raw = cfg.get("knownHosts") or []
    if isinstance(known_hosts_raw, str):
        known_hosts_raw = [known_hosts_raw]

    expected_basenames = set()
    key_paths = {}
    cert_paths = {}
    key_names = []

    for k in keys_raw:
        k_name = k["name"]
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", k_name) or k_name in ("known_hosts", "config"):
            raise ValueError(f"Invalid SSH key name: {k_name}")
        priv_raw = k["privateKey"].replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
        register_ssh_private_key(priv_raw)

        pub_raw = (k.get("publicKey") or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        pub_norm = pub_raw or derive_public_key_from_private_text(priv_raw)

        if is_agent_proxy:
            if not pub_norm:
                raise ValueError(f"Failed to derive public key for SSH key '{k_name}' in agent-proxy mode.")
            blob_hex = extract_pubkey_blob_hex(pub_norm)
            if not blob_hex:
                raise ValueError(f"Invalid public key material for SSH key '{k_name}'.")
            pub_basename = f"{k_name}.pub"
            pub_path = os.path.join(SSH_MANAGED_DIR, pub_basename)
            write_agent_file(pub_path, pub_norm + "\n", mode=0o644, dir_mode=0o700)
            expected_basenames.add(pub_basename)
            key_paths[k_name] = pub_path
            key_names.append(k_name)
            agent_proxy_keys.append({"name": k_name, "privateKey": priv_raw, "blobHex": blob_hex})
        else:
            priv_path = os.path.join(SSH_MANAGED_DIR, k_name)
            write_agent_file(priv_path, priv_raw, mode=0o600, dir_mode=0o700)
            expected_basenames.add(k_name)
            key_paths[k_name] = priv_path
            key_names.append(k_name)
            if pub_raw:
                pub_basename = f"{k_name}.pub"
                write_agent_file(
                    os.path.join(SSH_MANAGED_DIR, pub_basename),
                    pub_norm + "\n",
                    mode=0o644,
                    dir_mode=0o700,
                )
                expected_basenames.add(pub_basename)

        cert_raw = k.get("certificate") or ""
        if cert_raw.strip():
            cert_basename = f"{k_name}-cert.pub"
            cert_path = os.path.join(SSH_MANAGED_DIR, cert_basename)
            write_agent_file(
                cert_path,
                cert_raw.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n",
                mode=0o644,
                dir_mode=0o700,
            )
            expected_basenames.add(cert_basename)
            cert_paths[k_name] = cert_path
            if is_agent_proxy:
                cert_blob_hex = extract_pubkey_blob_hex(cert_raw)
                if not cert_blob_hex:
                    raise ValueError(f"Invalid certificate material for SSH key '{k_name}'.")
                agent_proxy_keys[-1]["certBlobHex"] = cert_blob_hex

    has_known_hosts = False
    cleaned_kh = [line.strip() for line in known_hosts_raw if isinstance(line, str) and line.strip()]
    if cleaned_kh:
        write_agent_file(SSH_KNOWN_HOSTS_FILE, "\n".join(cleaned_kh) + "\n", mode=0o600, dir_mode=0o700)
        expected_basenames.add("known_hosts")
        has_known_hosts = True

    # Prune any stale managed key/cert/known_hosts files inside SSH_MANAGED_DIR
    real_home = os.path.realpath(AGENT_HOME)
    real_managed = os.path.realpath(SSH_MANAGED_DIR)
    if real_managed.startswith(real_home + os.sep) and os.path.isdir(real_managed):
        for entry in os.listdir(real_managed):
            if entry not in expected_basenames:
                remove_file_quiet(os.path.join(real_managed, entry))

    default_key = cfg.get("defaultKey") or ""
    global_shkc = cfg.get("strictHostKeyChecking") or ""
    global_identities_only = bool(cfg.get("identitiesOnly", True))
    global_forward_agent = bool(cfg.get("forwardAgent", False))
    global_alive = cfg.get("serverAliveInterval", None)
    global_timeout = cfg.get("connectTimeout", None)
    global_batch = cfg.get("batchMode", None)

    user_known_hosts_value = f"{os.path.join(SSH_DIR, 'known_hosts')} {SSH_KNOWN_HOSTS_FILE}"

    host_names = []
    hosts_lines = []
    for h in hosts_raw:
        h_name = h["name"]
        host_names.append(h_name)
        hosts_lines.append(f"Host {h_name}")
        hosts_lines.append(f"  HostName {h['hostName']}")
        if h.get("user"):
            hosts_lines.append(f"  User {h['user']}")
        if h.get("port") is not None:
            hosts_lines.append(f"  Port {int(h['port'])}")
        h_key = h.get("key") or ""
        if h_key and h_key in key_paths:
            hosts_lines.append(f"  IdentityFile {key_paths[h_key]}")
            if h_key in cert_paths:
                hosts_lines.append(f"  CertificateFile {cert_paths[h_key]}")
        if h.get("proxyJump"):
            hosts_lines.append(f"  ProxyJump {h['proxyJump']}")

        h_io = h.get("identitiesOnly")
        eff_io = global_identities_only if h_io is None else bool(h_io)
        hosts_lines.append(f"  IdentitiesOnly {'yes' if eff_io else 'no'}")

        h_fa = h.get("forwardAgent")
        eff_fa = global_forward_agent if h_fa is None else bool(h_fa)
        hosts_lines.append(f"  ForwardAgent {'yes' if eff_fa else 'no'}")

        eff_shkc = h.get("strictHostKeyChecking") or global_shkc or ("yes" if has_known_hosts else "accept-new")
        hosts_lines.append(f"  StrictHostKeyChecking {eff_shkc}")

        if has_known_hosts:
            hosts_lines.append(f"  UserKnownHostsFile {user_known_hosts_value}")

        eff_alive = h.get("serverAliveInterval") if h.get("serverAliveInterval") is not None else global_alive
        if eff_alive is not None:
            hosts_lines.append(f"  ServerAliveInterval {int(eff_alive)}")

        eff_timeout = h.get("connectTimeout") if h.get("connectTimeout") is not None else global_timeout
        if eff_timeout is not None:
            hosts_lines.append(f"  ConnectTimeout {int(eff_timeout)}")

        eff_batch = h.get("batchMode") if h.get("batchMode") is not None else global_batch
        if eff_batch is not None:
            hosts_lines.append(f"  BatchMode {'yes' if eff_batch else 'no'}")
        hosts_lines.append("")

    hosts_block = ""
    if hosts_lines:
        hosts_block = "\n".join([SSH_HOSTS_START] + hosts_lines[:-1] + [SSH_HOSTS_END])

    defaults_body = []
    if default_key and default_key in key_paths:
        defaults_body.append(f"  IdentityFile {key_paths[default_key]}")
        if default_key in cert_paths:
            defaults_body.append(f"  CertificateFile {cert_paths[default_key]}")
        defaults_body.append(f"  IdentitiesOnly {'yes' if global_identities_only else 'no'}")
        defaults_body.append(f"  ForwardAgent {'yes' if global_forward_agent else 'no'}")
    if has_known_hosts:
        defaults_body.append(f"  UserKnownHostsFile {user_known_hosts_value}")
    if global_shkc:
        defaults_body.append(f"  StrictHostKeyChecking {global_shkc}")
    elif default_key or has_known_hosts:
        defaults_body.append(f"  StrictHostKeyChecking {'yes' if has_known_hosts else 'accept-new'}")
    if global_alive is not None:
        defaults_body.append(f"  ServerAliveInterval {int(global_alive)}")
    if global_timeout is not None:
        defaults_body.append(f"  ConnectTimeout {int(global_timeout)}")
    if global_batch is not None:
        defaults_body.append(f"  BatchMode {'yes' if global_batch else 'no'}")

    defaults_block = ""
    if defaults_body:
        defaults_block = "\n".join([SSH_DEFAULTS_START, "Host *"] + defaults_body + [SSH_DEFAULTS_END])

    merge_ssh_config(hosts_block, defaults_block)

    return {
        "mode": "agent-proxy" if is_agent_proxy else "files",
        "keys": key_names,
        "hosts": host_names,
        "knownHostsCount": len(cleaned_kh),
        "managedDir": SSH_MANAGED_DIR,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_agentProxyKeys": agent_proxy_keys,
    }

def clear_ssh(prev_meta):
    merge_ssh_config("", "")
    real_home = os.path.realpath(AGENT_HOME)
    if os.path.isdir(SSH_MANAGED_DIR):
        real_managed = os.path.realpath(SSH_MANAGED_DIR)
        if real_managed.startswith(real_home + os.sep):
            for entry in os.listdir(real_managed):
                remove_file_quiet(os.path.join(real_managed, entry))
            try:
                os.rmdir(real_managed)
            except OSError:
                pass

def seed_env(cfg, prev_meta):
    env_vars = {}
    for k, v in cfg.items():
        register_secret(v)
        env_vars[k] = v
    written_keys = write_service_env("env", env_vars)
    return {
        "envVars": written_keys,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_env(prev_meta):
    write_service_env("env", {})

def seed_files(cfg, prev_meta):
    managed_paths = []
    items = [cfg] if isinstance(cfg, dict) else (cfg or [])
    for item in items:
        target = item["targetPath"]
        if not target.startswith(AGENT_HOME + "/"):
            raise ValueError(f"Refusing to write file outside {AGENT_HOME}: {target}")
        mode = int(str(item.get("mode", "0600")), 8)
        raw = base64.b64decode(item["contentBase64"])
        write_agent_file(target, raw, mode=mode, dir_mode=0o700)
        managed_paths.append(target)

    # Remove stale previously managed files no longer listed
    prev_paths = (prev_meta or {}).get("paths", [])
    for stale in prev_paths:
        if stale not in managed_paths and stale.startswith(AGENT_HOME + "/"):
            remove_file_quiet(stale)

    return {
        "paths": managed_paths,
        "updatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

def clear_files(prev_meta):
    for p in (prev_meta or {}).get("paths", []):
        if p.startswith(AGENT_HOME + "/"):
            remove_file_quiet(p)

SEEDERS = {
    "github": seed_github,
    "git": seed_git,
    "aws": seed_aws,
    "gcloud": seed_gcloud,
    "azure": seed_azure,
    "azureDevops": seed_azure_devops,
    "jira": seed_jira,
    "upcloud": seed_upcloud,
    "kubectl": seed_kubectl,
    "gemini": seed_gemini,
    "claude": seed_claude,
    "ssh": seed_ssh,
    "env": seed_env,
    "files": seed_files,
}

CLEARERS = {
    "github": clear_github,
    "git": clear_git,
    "aws": clear_aws,
    "gcloud": clear_gcloud,
    "azure": clear_azure,
    "azureDevops": clear_azure_devops,
    "jira": clear_jira,
    "upcloud": clear_upcloud,
    "kubectl": clear_kubectl,
    "gemini": clear_gemini,
    "claude": clear_claude,
    "ssh": clear_ssh,
    "env": clear_env,
    "files": clear_files,
}

PROXY_CFG_FILE = "/etc/wsl-agent-sandbox/credential-proxy.json"

def load_credential_proxy_routes():
    if not os.path.isfile(PROXY_CFG_FILE):
        return {}
    try:
        with open(PROXY_CFG_FILE, "r", encoding="utf-8") as pf:
            data = json.load(pf)
        routes = data.get("routes", {}) if isinstance(data, dict) else {}
        return routes if isinstance(routes, dict) else {}
    except (OSError, ValueError):
        return {}

def _find_listening_sockets(port):
    hex_port = f"{int(port):04X}"
    found = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            local_addr = parts[1].upper()
            state = parts[3].upper()
            if state == "0A" and local_addr.endswith(":" + hex_port):
                try:
                    found.append((local_addr, int(parts[7]), parts[9]))
                except ValueError:
                    pass
    return found

def _kill_socket_inodes(inodes):
    if not inodes:
        return
    targets = {f"socket:[{ino}]" for ino in inodes}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = f"/proc/{entry}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"{fd_dir}/{fd}") in targets:
                    os.kill(int(entry), signal.SIGKILL)
                    break
            except OSError:
                pass

def sync_credential_proxy(routes):
    has_systemd = os.path.isdir("/run/systemd/system")
    if routes:
        tmp_path = f"{PROXY_CFG_FILE}.tmp.{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as pf:
            json.dump({
                "listenPort": CRED_PROXY_PORT,
                "allowedCallerUid": AGENT_UID,
                "routes": routes,
            }, pf, indent=2)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, PROXY_CFG_FILE)
        if has_systemd:
            squatters = [x for x in _find_listening_sockets(CRED_PROXY_PORT) if x[1] != 0]
            if squatters:
                _kill_socket_inodes([x[2] for x in squatters])
                time.sleep(0.3)
                remaining = [x for x in _find_listening_sockets(CRED_PROXY_PORT) if x[1] != 0]
                if remaining:
                    raise RuntimeError(
                        f"SECURITY ERROR: non-root process (uid={remaining[0][1]}) is squatting on 127.0.0.1:{CRED_PROXY_PORT}"
                    )
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "credential-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "restart", "credential-proxy.service"], check=True)
            hex_port = f"{CRED_PROXY_PORT:04X}"
            loopback_hex = f"{int.from_bytes(b'\x7f\x00\x00\x01', sys.byteorder):08X}"
            deadline = time.monotonic() + 3.0
            verified = False
            while time.monotonic() < deadline:
                active = subprocess.run(["systemctl", "is-active", "--quiet", "credential-proxy.service"], check=False).returncode == 0
                root_listen = any(addr == f"{loopback_hex}:{hex_port}" and uid == 0 for addr, uid, _ in _find_listening_sockets(CRED_PROXY_PORT))
                if active and root_listen:
                    verified = True
                    break
                time.sleep(0.1)
            if not verified:
                raise RuntimeError(
                    f"credential-proxy.service failed to bind 127.0.0.1:{CRED_PROXY_PORT} as root within 3s"
                )
    else:
        remove_file_quiet(PROXY_CFG_FILE)
        if has_systemd:
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "stop", "credential-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "disable", "credential-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

SYSTEMD_UNIT_DIR = os.environ.get("WSL_BOX_SYSTEMD_UNIT_DIR", "/etc/systemd/system")
TTL_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def validate_ttl_service_name(svc_name):
    if not isinstance(svc_name, str) or not TTL_SERVICE_NAME_RE.match(svc_name):
        raise ValueError(f"Invalid service name for TTL timer: {svc_name!r}")


def install_ttl_timer(svc_name, svc_ttl):
    """Write persistent systemd timer/service units for TTL expiration and enable the timer."""
    validate_ttl_service_name(svc_name)
    exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=svc_ttl)
    on_calendar_utc = exp_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    unit = f"wsl-box-ttl-{svc_name}"

    service_content = (
        "[Unit]\n"
        f"Description=wsl-agent-sandbox TTL Credential Expiration ({svc_name})\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"Environment=WSL_BOX_TTL_ACTIVE_UNIT={unit}.service\n"
        f"ExecStart=/usr/local/sbin/box-seed-secrets.sh --clear --services {svc_name}\n"
    )
    timer_content = (
        "[Unit]\n"
        f"Description=wsl-agent-sandbox TTL Timer ({svc_name})\n\n"
        "[Timer]\n"
        f"OnCalendar={on_calendar_utc}\n"
        "Persistent=true\n"
        "AccuracySec=1s\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )

    os.makedirs(SYSTEMD_UNIT_DIR, mode=0o755, exist_ok=True)
    service_path = os.path.join(SYSTEMD_UNIT_DIR, f"{unit}.service")
    timer_path = os.path.join(SYSTEMD_UNIT_DIR, f"{unit}.timer")
    for unit_path, content in ((service_path, service_content), (timer_path, timer_content)):
        with open(unit_path, "w", encoding="utf-8", newline="\n") as uf:
            uf.write(content)
        os.chmod(unit_path, 0o644)

    if os.path.isdir("/run/systemd/system"):
        reload_proc = subprocess.run(
            ["systemctl", "daemon-reload"],
            check=False,
            text=True,
            capture_output=True,
        )
        if reload_proc.returncode != 0:
            raise RuntimeError(
                f"systemctl daemon-reload failed for {svc_name}: {(reload_proc.stderr or reload_proc.stdout).strip()}"
            )
        enable_proc = subprocess.run(
            ["systemctl", "enable", "--now", f"{unit}.timer"],
            check=False,
            text=True,
            capture_output=True,
        )
        if enable_proc.returncode != 0:
            raise RuntimeError(
                f"systemctl enable --now {unit}.timer failed: {(enable_proc.stderr or enable_proc.stdout).strip()}"
            )
    return exp_dt


def cancel_ttl_timer(svc_name):
    """Stop, disable, and remove persistent TTL systemd units for a service."""
    validate_ttl_service_name(svc_name)
    unit = f"wsl-box-ttl-{svc_name}"
    active_unit = os.environ.get("WSL_BOX_TTL_ACTIVE_UNIT", "")
    is_self_service = active_unit == f"{unit}.service"
    has_systemd = os.path.isdir("/run/systemd/system")

    if has_systemd:
        subprocess.run(["systemctl", "disable", "--now", f"{unit}.timer"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "reset-failed", f"{unit}.timer"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not is_self_service:
            subprocess.run(["systemctl", "stop", f"{unit}.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "reset-failed", f"{unit}.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    remove_file_quiet(os.path.join(SYSTEMD_UNIT_DIR, f"{unit}.timer"))
    remove_file_quiet(os.path.join(SYSTEMD_UNIT_DIR, f"{unit}.service"))
    remove_file_quiet(os.path.join(SYSTEMD_UNIT_DIR, "timers.target.wants", f"{unit}.timer"))

    if has_systemd:
        subprocess.run(["systemctl", "daemon-reload"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

SSH_AGENT_DIR = "/run/box-root/ssh-agent"
SSH_AGENT_UPSTREAM_SOCK = os.path.join(SSH_AGENT_DIR, "upstream.sock")
SSH_AGENT_STATE_FILE = "/etc/wsl-agent-sandbox/ssh-agent-keys.json"
SSH_AGENT_LEGACY_STATE_FILE = os.path.join(SSH_AGENT_DIR, "root-keys.json")
SSH_AGENT_ALLOWLIST_FILE = "/etc/wsl-agent-sandbox/ssh-agent-allowlist.json"
SSH_AGENT_ENV_FILE = os.path.join(ENV_D_DIR, "90-ssh-agent-proxy.env")
SSH_AGENT_CTL = "/usr/local/sbin/box-ssh-agent-ctl.sh"

def load_root_ssh_agent_services():
    if not os.path.isfile(SSH_AGENT_STATE_FILE):
        return {}
    try:
        with open(SSH_AGENT_STATE_FILE, "r", encoding="utf-8") as sf:
            data = json.load(sf)
        svcs = data.get("services", {}) if isinstance(data, dict) else {}
        return svcs if isinstance(svcs, dict) else {}
    except (OSError, ValueError):
        return {}

def sync_root_ssh_agent_state(agent_services_map):
    has_systemd = os.path.isdir("/run/systemd/system")
    if os.path.isdir(SSH_AGENT_DIR):
        for entry in os.listdir(SSH_AGENT_DIR):
            if entry.startswith("keys-"):
                shutil.rmtree(os.path.join(SSH_AGENT_DIR, entry), ignore_errors=True)
    remove_file_quiet(SSH_AGENT_LEGACY_STATE_FILE)

    all_keys = []
    all_blobs = set()
    cleaned_map = {}
    for s_name, k_list in (agent_services_map or {}).items():
        if not isinstance(k_list, list) or not k_list:
            continue
        valid_items = []
        for item in k_list:
            if isinstance(item, dict) and item.get("privateKey") and item.get("blobHex"):
                register_ssh_private_key(item["privateKey"])
                entry = {"name": item.get("name", ""), "privateKey": item["privateKey"], "blobHex": item["blobHex"].lower()}
                all_keys.append(item["privateKey"])
                all_blobs.add(item["blobHex"].lower())
                if item.get("certBlobHex"):
                    cert_blob = str(item["certBlobHex"]).lower()
                    entry["certBlobHex"] = cert_blob
                    all_blobs.add(cert_blob)
                valid_items.append(entry)
        if valid_items:
            cleaned_map[s_name] = valid_items

    env = dict(os.environ, SSH_AUTH_SOCK=SSH_AGENT_UPSTREAM_SOCK)
    if all_keys:
        os.makedirs(os.path.dirname(SSH_AGENT_STATE_FILE), mode=0o755, exist_ok=True)
        tmp_state = f"{SSH_AGENT_STATE_FILE}.tmp.{os.getpid()}"
        with open(tmp_state, "w", encoding="utf-8") as sf:
            json.dump({"services": cleaned_map}, sf, indent=2)
        os.chmod(tmp_state, 0o600)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp_state, 0, 0)
        os.replace(tmp_state, SSH_AGENT_STATE_FILE)

        os.makedirs(os.path.dirname(SSH_AGENT_ALLOWLIST_FILE), mode=0o755, exist_ok=True)
        tmp_al = f"{SSH_AGENT_ALLOWLIST_FILE}.tmp.{os.getpid()}"
        with open(tmp_al, "w", encoding="utf-8") as af:
            json.dump({"allowedKeyBlobsHex": sorted(all_blobs)}, af, indent=2)
        os.chmod(tmp_al, 0o600)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp_al, 0, 0)
        os.replace(tmp_al, SSH_AGENT_ALLOWLIST_FILE)

        if os.path.isfile(SSH_AGENT_CTL):
            subprocess.run([SSH_AGENT_CTL, "ensure-upstream"], check=True)
        else:
            os.makedirs("/run/box-root", mode=0o700, exist_ok=True)
            os.makedirs(SSH_AGENT_DIR, mode=0o700, exist_ok=True)
            os.chmod(SSH_AGENT_DIR, 0o700)
            probe = subprocess.run(["ssh-add", "-l"], env=env, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode not in (0, 1):
                remove_file_quiet(SSH_AGENT_UPSTREAM_SOCK)
                subprocess.run(["ssh-agent", "-a", SSH_AGENT_UPSTREAM_SOCK], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.chmod(SSH_AGENT_UPSTREAM_SOCK, 0o600)
            subprocess.run(["ssh-add", "-D"], env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for priv_key in all_keys:
                add_proc = subprocess.run(["ssh-add", "-"], input=priv_key, text=True, env=env, check=False, capture_output=True)
                if add_proc.returncode != 0:
                    raise RuntimeError(f"ssh-add failed loading key into root ssh-agent: {(add_proc.stderr or add_proc.stdout).strip()}")

        write_agent_file(SSH_AGENT_ENV_FILE, 'export SSH_AUTH_SOCK="/run/ssh-agent-proxy/agent.sock"\n', mode=0o600)
        if has_systemd:
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "enable", "ssh-agent-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "restart", "ssh-agent-proxy.service"], check=True)
    else:
        if os.path.isfile(SSH_AGENT_CTL):
            subprocess.run([SSH_AGENT_CTL, "stop-upstream"], check=False)
        if os.path.exists(SSH_AGENT_UPSTREAM_SOCK):
            subprocess.run(["ssh-add", "-D"], env=env, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", SSH_AGENT_UPSTREAM_SOCK], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            remove_file_quiet(SSH_AGENT_UPSTREAM_SOCK)
        remove_file_quiet(SSH_AGENT_STATE_FILE)
        remove_file_quiet(SSH_AGENT_ALLOWLIST_FILE)
        remove_file_quiet(SSH_AGENT_ENV_FILE)
        if has_systemd:
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            subprocess.run(["systemctl", "stop", "ssh-agent-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "disable", "ssh-agent-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ------------------------------------------------------------------
# Shared revocation & TTL sweep helpers
# ------------------------------------------------------------------
def revoke_services(targets, explicit_targets=False, clear_all=False, expired_mode=False):
    """Clear the given services from disk, credential-proxy, ssh-agent, secrets.env, and state."""
    state = load_state()
    svcs = state.get("services", {})
    cleared_any = False
    proxy_routes_state = load_credential_proxy_routes()
    proxy_changed = False
    ssh_agent_state = load_root_ssh_agent_services()
    ssh_agent_changed = False

    for name in targets:
        if name not in CLEARERS:
            print(f"[seed-secrets] [FAIL] Unknown service: {name}", file=sys.stderr)
            sys.exit(1)
        prev_meta = svcs.get(name)
        cancel_ttl_timer(name)
        CLEARERS[name](prev_meta)
        if name in proxy_routes_state:
            proxy_routes_state.pop(name, None)
            proxy_changed = True
        if name in ("git", "ssh"):
            if name in ssh_agent_state:
                ssh_agent_state.pop(name, None)
            ssh_agent_changed = True
        if name in svcs:
            svcs.pop(name, None)
            if expired_mode:
                print(f"[seed-secrets] [EXPIRED] Auto-cleared expired credentials for {name}")
            else:
                print(f"[seed-secrets] [CLEARED] {name}")
            cleared_any = True
        elif explicit_targets:
            print(f"[seed-secrets] [CLEARED] {name} (was not recorded in state)")
            cleared_any = True

    if proxy_changed or (clear_all and os.path.isfile(PROXY_CFG_FILE)):
        if clear_all:
            proxy_routes_state = {}
        sync_credential_proxy(proxy_routes_state)

    if ssh_agent_changed or (clear_all and (os.path.isfile(SSH_AGENT_ALLOWLIST_FILE) or os.path.exists(SSH_AGENT_UPSTREAM_SOCK))):
        if clear_all:
            ssh_agent_state = {}
        sync_root_ssh_agent_state(ssh_agent_state)

    rebuild_secrets_env()
    if svcs:
        save_state(state)
    else:
        remove_file_quiet(STATE_FILE)

    if os.path.isfile("/usr/local/sbin/box-sync-context.py"):
        subprocess.run(["python3", "/usr/local/sbin/box-sync-context.py"], check=False)

    return cleared_any


def sweep_expired_services():
    """Clear any seeded services whose TTL expiresAt timestamp has passed."""
    state = load_state()
    svcs = state.get("services", {})
    if not svcs:
        return []
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    expired = []
    for name, meta in list(svcs.items()):
        if name not in CLEARERS:
            continue
        exp_raw = (meta or {}).get("expiresAt")
        if not exp_raw:
            continue
        try:
            exp_dt = datetime.datetime.strptime(exp_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        if exp_dt <= now_utc:
            expired.append(name)
    if not expired:
        return []
    revoke_services(expired, explicit_targets=False, clear_all=False, expired_mode=True)
    return expired


# ------------------------------------------------------------------
# Modes: --status, --sweep-expired, --clear, --apply
# ------------------------------------------------------------------
if args.sweep_expired:
    sweep_expired_services()
    sys.exit(0)

if args.status:
    sweep_expired_services()
    state = load_state()
    svcs = state.get("services", {})
    if not svcs:
        print("  (none)")
    else:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        for name in sorted(svcs.keys()):
            meta = svcs[name] or {}
            ts = meta.get("updatedAt", "unknown")
            extras = []
            if meta.get("envVars"):
                extras.append("env=" + ",".join(meta["envVars"]))
            if meta.get("profiles"):
                extras.append("profiles=" + ",".join(meta["profiles"]))
            if meta.get("keys"):
                extras.append("keys=" + ",".join(meta["keys"]))
            if meta.get("hosts"):
                extras.append("hosts=" + ",".join(meta["hosts"]))
            if meta.get("knownHostsCount"):
                extras.append("knownHosts=" + str(meta["knownHostsCount"]))
            if meta.get("signingKey"):
                extras.append("signing=" + meta["signingKey"])
            if meta.get("userEmail"):
                extras.append("email=" + meta["userEmail"])
            if meta.get("clientEmail"):
                extras.append("account=" + meta["clientEmail"])
            if meta.get("server"):
                extras.append("server=" + meta["server"])
            if meta.get("organization"):
                extras.append("org=" + meta["organization"])
            if meta.get("paths"):
                extras.append("files=" + str(len(meta["paths"])))
            exp_info = ""
            exp_raw = meta.get("expiresAt")
            if exp_raw:
                try:
                    exp_dt = datetime.datetime.strptime(exp_raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
                    rem_sec = int((exp_dt - now_utc).total_seconds())
                    if rem_sec <= 0:
                        exp_info = f", expires {exp_raw} (expired)"
                    else:
                        hrs, rem = divmod(rem_sec, 3600)
                        mins, secs = divmod(rem, 60)
                        if hrs > 0:
                            rem_fmt = f"{hrs}h{mins}m{secs}s"
                        elif mins > 0:
                            rem_fmt = f"{mins}m{secs}s"
                        else:
                            rem_fmt = f"{secs}s"
                        exp_info = f", expires {exp_raw} ({rem_fmt} remaining)"
                except ValueError:
                    exp_info = f", expires {exp_raw}"
            detail = f" ({'; '.join(extras)})" if extras else ""
            print(f"  - {name}{detail} [updated {ts}{exp_info}]")
    sys.exit(0)

if args.clear:
    state = load_state()
    svcs = state.get("services", {})
    explicit_targets = bool(args.services.strip())
    if explicit_targets:
        targets = [s.strip() for s in args.services.split(",") if s.strip()]
    else:
        targets = list(svcs.keys())
        # Also sweep any known service fragments if state file was missing
        if not targets:
            targets = list(CLEARERS.keys())

    cleared_any = revoke_services(targets, explicit_targets=explicit_targets, clear_all=not explicit_targets)
    if not cleared_any:
        print("[seed-secrets] No managed seeded credentials were present.")
    sys.exit(0)

# --apply mode
with os.fdopen(3, "r", encoding="utf-8") as payload_stream:
    raw_stdin = payload_stream.read()
if not raw_stdin.strip():
    print("[seed-secrets] ERROR: empty payload on stdin", file=sys.stderr)
    sys.exit(1)

payload = json.loads(raw_stdin)
services_payload = payload.get("services", {})
new_proxy_routes = payload.get("proxyRoutes", {}) or {}
filter_services = payload.get("filterServices", [])
if isinstance(filter_services, str):
    filter_services = [filter_services]
prune = bool(payload.get("prune", False))
ttl_seconds = int(payload.get("ttlSeconds", 0) or 0)
service_ttls = payload.get("serviceTtls", {}) or {}

ensure_profile_hook()
ensure_agent_dir(STATE_DIR, mode=0o700)
state = load_state()
state_services = state.get("services", {})
merged_proxy_routes = load_credential_proxy_routes()
merged_ssh_agent_services = load_root_ssh_agent_services()

failures = 0
seeded_count = 0

for svc_name, svc_cfg in services_payload.items():
    if svc_name not in SEEDERS:
        print(f"[seed-secrets] [FAIL] Unsupported service: {svc_name}", file=sys.stderr)
        failures += 1
        continue
    try:
        meta = SEEDERS[svc_name](svc_cfg, state_services.get(svc_name))
        agent_proxy_keys = meta.pop("_agentProxyKeys", None)
        if svc_name in ("ssh", "git"):
            if isinstance(svc_cfg, dict) and svc_cfg.get("mode") == "agent-proxy" and agent_proxy_keys:
                merged_ssh_agent_services[svc_name] = agent_proxy_keys
            else:
                merged_ssh_agent_services.pop(svc_name, None)
        svc_ttl = int(service_ttls.get(svc_name, ttl_seconds) or 0)
        cancel_ttl_timer(svc_name)
        if svc_ttl > 0:
            exp_dt = install_ttl_timer(svc_name, svc_ttl)
            meta["expiresAt"] = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            meta.pop("expiresAt", None)
        state_services[svc_name] = meta
        if svc_name in new_proxy_routes:
            merged_proxy_routes[svc_name] = new_proxy_routes[svc_name]
        else:
            merged_proxy_routes.pop(svc_name, None)
        seeded_count += 1
        print(f"[seed-secrets] [OK] Seeded {svc_name}")
    except Exception as exc:
        failures += 1
        print(f"[seed-secrets] [FAIL] {svc_name}: {redact(str(exc))}", file=sys.stderr)

if prune:
    candidates = filter_services if filter_services else list(state_services.keys())
    for svc_name in list(candidates):
        if svc_name not in services_payload and svc_name in state_services:
            cancel_ttl_timer(svc_name)
            if svc_name in CLEARERS:
                CLEARERS[svc_name](state_services.get(svc_name))
            state_services.pop(svc_name, None)
            merged_proxy_routes.pop(svc_name, None)
            merged_ssh_agent_services.pop(svc_name, None)
            print(f"[seed-secrets] [PRUNED] Removed previously seeded {svc_name}")

sync_credential_proxy(merged_proxy_routes)
sync_root_ssh_agent_state(merged_ssh_agent_services)

rebuild_secrets_env()
state["services"] = state_services
if state_services:
    save_state(state)
else:
    remove_file_quiet(STATE_FILE)

if os.path.isfile("/usr/local/sbin/box-sync-context.py"):
    subprocess.run(["python3", "/usr/local/sbin/box-sync-context.py"], check=False)

print(f"[seed-secrets] Complete: seeded={seeded_count}, failed={failures}, active_services={len(state_services)}")
if failures > 0:
    sys.exit(1)
PYEOF
