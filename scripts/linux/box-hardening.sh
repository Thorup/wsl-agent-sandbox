#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"
HOST_IPS_FILE="/etc/wsl-agent-sandbox/host_ips.txt"
DOCKER_POLICY_FILE="/etc/wsl-agent-sandbox/docker-policy.json"
VERIFY_POLICY_FILE="/etc/wsl-agent-sandbox/verify-policy.json"
NFT_CONF_FILE="/etc/wsl-agent-sandbox/nftables.conf"
BOX_ROOT="/run/box-root"
PRIVATE_WSL_MNT="${BOX_ROOT}/mnt-wsl"

log() {
  echo "[box-hardening] $*"
}

if [[ ! -f "${POLICY_FILE}" ]]; then
  log "ERROR: ${POLICY_FILE} not found; skipping hardening."
  exit 1
fi

# 1. Isolate /mnt/wsl and /mnt/wslg per-distro without propagating unmounts to other distros.
mkdir -p "${BOX_ROOT}"
chmod 0700 "${BOX_ROOT}"
chown root:root "${BOX_ROOT}"

if ! mountpoint -q "${PRIVATE_WSL_MNT}"; then
  if mountpoint -q /mnt/wsl; then
    mkdir -p "${PRIVATE_WSL_MNT}"
    # Use --rbind so ALL pre-existing submounts under /mnt/wsl (e.g. Docker Desktop sockets)
    # are preserved inside /run/box-root/mnt-wsl!
    mount --rbind /mnt/wsl "${PRIVATE_WSL_MNT}"
    # Detach /mnt/wsl from shared peer group BEFORE unmounting so we NEVER
    # propagate the unmount to docker-desktop or other WSL distros!
    mount --make-rprivate /mnt/wsl
    umount -l /mnt/wsl || true
    chmod 000 /mnt/wsl || true
    log "Moved /mnt/wsl to root-only ${PRIVATE_WSL_MNT} (--rbind) and hid /mnt/wsl."
  else
    log "Note: /mnt/wsl is not mounted (already isolated or unavailable)."
  fi
fi

# Keep /etc/resolv.conf working and live-synced after hiding /mnt/wsl.
# WSL defaults /etc/resolv.conf to a symlink -> /mnt/wsl/resolv.conf which breaks
# once /mnt/wsl is unmounted; bind-mounting the single file read-only exposes ONLY DNS.
if [[ -f "${PRIVATE_WSL_MNT}/resolv.conf" ]]; then
  if [[ -L /etc/resolv.conf ]] || [[ ! -e /etc/resolv.conf ]]; then
    rm -f /etc/resolv.conf
    touch /etc/resolv.conf
    chmod 0644 /etc/resolv.conf
  fi
  if ! mountpoint -q /etc/resolv.conf; then
    mount --bind "${PRIVATE_WSL_MNT}/resolv.conf" /etc/resolv.conf
    mount -o remount,ro,bind /etc/resolv.conf 2>/dev/null || true
    log "Bind-mounted live resolv.conf (ro) onto /etc/resolv.conf."
  fi
fi

# Unmount WSLg (GUI / shared clipboard / PulseAudio) strictly inside this distro's mount namespace.
if mountpoint -q /mnt/wslg/distro 2>/dev/null; then
  mount --make-rprivate /mnt/wslg/distro || true
  umount -l /mnt/wslg/distro || true
fi
if mountpoint -q /mnt/wslg 2>/dev/null; then
  mount --make-rprivate /mnt/wslg || true
  umount -l /mnt/wslg || true
fi
if [[ -d /mnt/wslg ]]; then
  chmod 000 /mnt/wslg || true
fi
if mountpoint -q /tmp/.X11-unix 2>/dev/null; then
  mount --make-rprivate /tmp/.X11-unix || true
  umount -l /tmp/.X11-unix || true
fi
rm -rf /tmp/.X11-unix 2>/dev/null || true

# Safety sweep: ensure no Windows drive letters remain mounted under /mnt/[a-z].
for d in /mnt/[a-z]; do
  if [[ -d "$d" ]] && mountpoint -q "$d"; then
    log "Unmounting unexpected drive mount $d"
    mount --make-rprivate "$d" || true
    umount -l "$d" || true
  fi
done

# 2. Parse policy.json with Python 3 to apply shared folders, Docker bind mirrors,
#    docker-policy.json, and per-UID nftables rules atomically.
python3 - "${POLICY_FILE}" "${HOST_IPS_FILE}" "${DOCKER_POLICY_FILE}" "${NFT_CONF_FILE}" "${PRIVATE_WSL_MNT}" "${VERIFY_POLICY_FILE}" <<'PYEOF'
import ipaddress
import json
import os
import re
import subprocess
import sys

policy_file, host_ips_file, docker_policy_file, nft_conf_file, private_wsl_mnt, verify_policy_file = sys.argv[1:7]

with open(policy_file, "r", encoding="utf-8") as f:
    policy = json.load(f)

def deterministic_proxy_ports(uid):
    uid = int(uid)
    if uid == 26040:
        return 3128, 3129
    if 26100 <= uid <= 26998:
        egress = 30900 + (uid - 26100) * 2
    else:
        egress = 29100 + ((uid * 31) % 450) * 2
    return egress, egress + 1

distro = policy["distroName"]
agent_name = policy["agentUser"]["name"]
agent_uid = int(policy["agentUser"]["uid"])
agent_gid = int(policy["agentUser"]["gid"])
agent_home = f"/home/{agent_name}"

def run(cmd, check=True):
    return subprocess.run(cmd, check=check, text=True, capture_output=True)

def is_mountpoint(path):
    return subprocess.run(["mountpoint", "-q", path]).returncode == 0

# --- A. Allowlisted Windows shared folders under /shared/<name> ---
shared_root = "/shared"
os.makedirs(shared_root, mode=0o755, exist_ok=True)
os.chown(shared_root, 0, 0)

desired_shares = {}
for sf in policy.get("sharedFolders", []):
    name = sf["name"]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$", name):
        raise ValueError(f"Invalid shared folder name: {name}")
    desired_shares[name] = sf

# Unmount any stale /shared/* mounts not in desired_shares
if os.path.isdir(shared_root):
    for entry in os.listdir(shared_root):
        mp = os.path.join(shared_root, entry)
        if entry not in desired_shares and is_mountpoint(mp):
            run(["mount", "--make-rprivate", mp], check=False)
            run(["umount", "-l", mp], check=False)
            try:
                os.rmdir(mp)
            except OSError:
                pass

for name, sf in desired_shares.items():
    mp = os.path.join(shared_root, name)
    os.makedirs(mp, mode=0o755, exist_ok=True)
    win_path = sf["windowsPath"]
    mode = sf.get("mode", "ro")
    if mode not in ("ro", "rw"):
        raise ValueError(f"Invalid mode {mode} for share {name}")
    # Re-mount cleanly to ensure mode/source always matches policy
    if is_mountpoint(mp):
        run(["mount", "--make-rprivate", mp], check=False)
        run(["umount", "-l", mp], check=False)
    opts = f"{mode},uid={agent_uid},gid={agent_gid},umask=022,metadata"
    if mode == "ro":
        opts += ",noexec"
    res = run(["mount", "-t", "drvfs", win_path, mp, "-o", opts], check=False)
    if res.returncode != 0:
        print(f"[box-hardening] WARNING: failed mounting {win_path} -> {mp}: {res.stderr.strip()}", file=sys.stderr)
    else:
        print(f"[box-hardening] Mounted {win_path} -> {mp} ({mode})")

# --- B. Root-only Docker Desktop bind-mount mirrors under /run/box-root/mnt-wsl/box-binds/<distro> ---
bind_mappings = []
if is_mountpoint(private_wsl_mnt):
    binds_base = os.path.join(private_wsl_mnt, "box-binds")
    distro_binds = os.path.join(binds_base, distro)
    os.makedirs(distro_binds, mode=0o700, exist_ok=True)
    os.chmod(binds_base, 0o700)
    os.chmod(distro_binds, 0o700)

    # Mirror /home/<agent>
    home_mirror_local = os.path.join(distro_binds, "home-agent")
    home_mirror_daemon = f"/run/desktop/mnt/host/wsl/box-binds/{distro}/home-agent"
    os.makedirs(home_mirror_local, mode=0o700, exist_ok=True)
    if not is_mountpoint(home_mirror_local) and os.path.isdir(agent_home):
        run(["mount", "--bind", agent_home, home_mirror_local])

    for prefix in policy.get("docker", {}).get("allowBindPrefixes", [agent_home]):
        p_clean = os.path.normpath(prefix)
        if p_clean == agent_home:
            bind_mappings.append({
                "guestPrefix": agent_home,
                "daemonPrefix": home_mirror_daemon,
                "readOnly": False,
            })

    # Mirror any sharedFolders with allowDockerBind == true
    shared_mirror_dir = os.path.join(distro_binds, "shared")
    os.makedirs(shared_mirror_dir, mode=0o700, exist_ok=True)
    active_docker_shares = set()
    for name, sf in desired_shares.items():
        if not sf.get("allowDockerBind", False):
            continue
        active_docker_shares.add(name)
        guest_dir = os.path.join(shared_root, name)
        mirror_local = os.path.join(shared_mirror_dir, name)
        mirror_daemon = f"/run/desktop/mnt/host/wsl/box-binds/{distro}/shared/{name}"
        os.makedirs(mirror_local, mode=0o700, exist_ok=True)
        if is_mountpoint(mirror_local):
            run(["mount", "--make-rprivate", mirror_local], check=False)
            run(["umount", "-l", mirror_local], check=False)
        if is_mountpoint(guest_dir):
            run(["mount", "--bind", guest_dir, mirror_local])
            if sf.get("mode", "ro") == "ro":
                run(["mount", "-o", "remount,ro,bind", mirror_local], check=False)
            bind_mappings.append({
                "guestPrefix": guest_dir,
                "daemonPrefix": mirror_daemon,
                "readOnly": sf.get("mode", "ro") == "ro",
            })

    # Clean stale shared mirrors
    for entry in os.listdir(shared_mirror_dir):
        if entry not in active_docker_shares:
            stale = os.path.join(shared_mirror_dir, entry)
            if is_mountpoint(stale):
                run(["mount", "--make-rprivate", stale], check=False)
                run(["umount", "-l", stale], check=False)
            try:
                os.rmdir(stale)
            except OSError:
                pass
else:
    # Still generate bind_mappings even if /mnt/wsl wasn't available yet
    bind_mappings.append({
        "guestPrefix": agent_home,
        "daemonPrefix": f"/run/desktop/mnt/host/wsl/box-binds/{distro}/home-agent",
        "readOnly": False,
    })

docker_cfg = policy.get("docker", {})
force_internal = bool(docker_cfg.get("forceInternalNetwork", False))
allowed_registries = docker_cfg.get("allowedRegistries", [])
effective_buildkit = bool(docker_cfg.get("allowBuildKit", True)) and not force_internal and not allowed_registries
compiled_docker_policy = {
    "enabled": bool(docker_cfg.get("enabled", True)),
    "allowBuildKit": effective_buildkit,
    "allowCapAdd": docker_cfg.get("allowCapAdd", []),
    "denyEndpoints": docker_cfg.get("denyEndpoints", [
        "/plugins", "/swarm", "/services", "/nodes", "/secrets", "/configs", "/tasks"
    ]),
    "allowPortBindings": bool(docker_cfg.get("allowPortBindings", True)),
    "forceLoopbackPortBindings": bool(docker_cfg.get("forceLoopbackPortBindings", True)),
    "allowedPublishedPorts": [int(p) for p in docker_cfg.get("allowedPublishedPorts", [])],
    "forceInternalNetwork": bool(docker_cfg.get("forceInternalNetwork", False)),
    "defaultLimits": docker_cfg.get("defaultLimits", {}),
    "maxLimits": docker_cfg.get("maxLimits", {}),
    "allowedRegistries": docker_cfg.get("allowedRegistries", []),
    "bindMappings": bind_mappings,
}
if is_mountpoint(private_wsl_mnt):
    eph_local = os.path.join(private_wsl_mnt, "box-binds", distro, "ephemeral")
    os.makedirs(eph_local, mode=0o700, exist_ok=True)
    compiled_docker_policy["ephemeralBindRoot"] = eph_local
    compiled_docker_policy["ephemeralDaemonRoot"] = f"/run/desktop/mnt/host/wsl/box-binds/{distro}/ephemeral"
with open(docker_policy_file, "w", encoding="utf-8") as f:
    json.dump(compiled_docker_policy, f, indent=2)
os.chmod(docker_policy_file, 0o600)

# --- B2. World-readable non-secret verify-policy.json for policy-aware verification ---
pkgs = policy.get("packages", {})
apt_pkgs = set(pkgs.get("apt", []) or [])
expected_tools = ["python3"]
if "git" in apt_pkgs:
    expected_tools.insert(0, "git")
if pkgs.get("installDockerCli", True):
    expected_tools.append("docker")
if pkgs.get("installUv", True):
    expected_tools.append("uv")
    if pkgs.get("installAider", False):
        expected_tools.append("aider")
if pkgs.get("installNodeLts", True):
    expected_tools.append("node")
    if pkgs.get("installPnpm", True):
        expected_tools.append("pnpm")
    if pkgs.get("installGeminiCli", True):
        expected_tools.append("gemini")
    if pkgs.get("installClaudeCode", True):
        expected_tools.append("claude")
    if pkgs.get("installCodexCli", False):
        expected_tools.append("codex")
    if pkgs.get("installOpenCode", False):
        expected_tools.append("opencode")
    if pkgs.get("installPlaywrightChromium", False) or pkgs.get("installPlaywrightFirefox", False):
        expected_tools.append("playwright")
if pkgs.get("installKubectl", False):
    expected_tools.append("kubectl")
if pkgs.get("installHelm", False):
    expected_tools.append("helm")
if pkgs.get("installOpenTofu", False):
    expected_tools.append("tofu")
if pkgs.get("installTerraform", False):
    expected_tools.append("terraform")
if pkgs.get("installAwsCli", False):
    expected_tools.append("aws")
if pkgs.get("installGcloudCli", False):
    expected_tools.append("gcloud")
if pkgs.get("installAzureCli", False) or pkgs.get("installAzureDevopsCli", False):
    expected_tools.append("az")
if pkgs.get("installGithubCli", False):
    expected_tools.append("gh")
if pkgs.get("installJiraCli", False):
    expected_tools.append("jira")
if pkgs.get("installUpctl", False):
    expected_tools.append("upctl")
if pkgs.get("installDotnetSdk", False):
    expected_tools.append("dotnet")
if pkgs.get("installRust", False):
    expected_tools.extend(["rustc", "cargo", "rustup"])

verify_policy = {
    "dockerEnabled": bool(docker_cfg.get("enabled", True)),
    "allowPortBindings": bool(docker_cfg.get("allowPortBindings", True)),
    "forceLoopbackPortBindings": bool(docker_cfg.get("forceLoopbackPortBindings", True)),
    "forceInternalNetwork": bool(docker_cfg.get("forceInternalNetwork", False)),
    "allowedRegistries": docker_cfg.get("allowedRegistries", []),
    "blockHostAndLan": bool(policy.get("network", {}).get("blockHostAndLan", True)),
    "egressMode": policy.get("network", {}).get("egressMode", "open"),
    "allowedDomains": policy.get("network", {}).get("allowedDomains", []),
    "expectedTools": expected_tools,
    "checkDockerCompose": bool(pkgs.get("installDockerCli", True)),
    "checkAzureDevopsExt": bool(pkgs.get("installAzureDevopsCli", False)),
    "egressProxyPort": deterministic_proxy_ports(agent_uid)[0],
    "credentialProxyPort": deterministic_proxy_ports(agent_uid)[1],
}
verify_tmp = f"{verify_policy_file}.tmp.{os.getpid()}"
with open(verify_tmp, "w", encoding="utf-8") as f:
    json.dump(verify_policy, f, indent=2)
os.chmod(verify_tmp, 0o644)
os.replace(verify_tmp, verify_policy_file)

# --- C. Per-UID nftables firewall (table inet wsl_agent_sandbox) ---
dns_v4, dns_v6 = set(), set()
if os.path.isfile("/etc/resolv.conf"):
    with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("nameserver "):
                addr = line.split()[1].split("%")[0]
                try:
                    ip = ipaddress.ip_address(addr)
                    (dns_v4 if ip.version == 4 else dns_v6).add(str(ip))
                except ValueError:
                    pass

host_v4, host_v6 = set(), set()
# Default gateway IP (Windows Hyper-V vSwitch IP in NAT mode)
for fam, dest in [("-4", host_v4), ("-6", host_v6)]:
    r = run(["ip", fam, "route", "show", "default"], check=False)
    for line in r.stdout.splitlines():
        parts = line.split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts):
                addr = parts[idx + 1].split("%")[0]
                try:
                    ip = ipaddress.ip_address(addr)
                    dest.add(str(ip))
                except ValueError:
                    pass

# Additional Windows host IPs provided by box.ps1
if os.path.isfile(host_ips_file):
    with open(host_ips_file, "r", encoding="utf-8") as f:
        for line in f:
            addr = line.strip().split("%")[0]
            if not addr or addr.startswith("#"):
                continue
            try:
                ip = ipaddress.ip_address(addr)
                if not ip.is_loopback:
                    (host_v4 if ip.version == 4 else host_v6).add(str(ip))
            except ValueError:
                pass

net_cfg = policy.get("network", {})
block_host_and_lan = bool(net_cfg.get("blockHostAndLan", True))
egress_mode = net_cfg.get("egressMode", "open")
allowed_domains = net_cfg.get("allowedDomains", [])
blocked_v4 = []
blocked_v6 = ["fc00::/7", "fe80::/10"]
for cidr in net_cfg.get("blockedCidrs", []):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version == 4:
        blocked_v4.append(str(net))
    else:
        blocked_v6.append(str(net))

egress_port, cred_port = deterministic_proxy_ports(agent_uid)
egress_cfg_file = "/etc/wsl-agent-sandbox/egress-allowlist.json"
egress_cfg_tmp = f"{egress_cfg_file}.tmp.{os.getpid()}"
with open(egress_cfg_tmp, "w", encoding="utf-8") as f:
    json.dump({
        "egressMode": egress_mode,
        "allowedDomains": allowed_domains,
        "blockHostAndLan": block_host_and_lan,
        "hostIps": sorted(host_v4 | host_v6),
        "blockedCidrs": sorted(set(blocked_v4 + blocked_v6)),
        "allowedPorts": [443],
        "allowedHttpPorts": [80, 443],
        "listenPort": egress_port,
        "allowedCallerUid": agent_uid,
    }, f, indent=2)
os.chmod(egress_cfg_tmp, 0o600)
os.replace(egress_cfg_tmp, egress_cfg_file)

allowed_tcp = sorted({int(p["port"]) for p in net_cfg.get("allowedHostPorts", []) if p.get("protocol") == "tcp"})
allowed_udp = sorted({int(p["port"]) for p in net_cfg.get("allowedHostPorts", []) if p.get("protocol") == "udp"})

# Detect WSL2 mirrored networking (presence of 'loopback0' interface)
has_loopback0 = run(["ip", "link", "show", "loopback0"], check=False).returncode == 0
SHARED_MARK_HEX = "0x00002604"
LEGACY_MARK_HEX = f"0x{agent_uid:08x}"
NFT_TABLE = f"wsl_agent_sandbox_{agent_uid}"
SHARED_NFT_TABLE = "wsl_agent_sandbox_shared"

def sync_shared_nft_prerouting(enable_shared):
    if enable_shared:
        shared_script = (
            f"table inet {SHARED_NFT_TABLE} {{\n"
            "    chain prerouting {\n"
            "        type filter hook prerouting priority mangle; policy accept;\n"
            "    }\n"
            "}\n"
            f"flush chain inet {SHARED_NFT_TABLE} prerouting\n"
            f'add rule inet {SHARED_NFT_TABLE} prerouting iifname "loopback0" ct mark set {SHARED_MARK_HEX}\n'
        )
        r = subprocess.run(["nft", "-f", "-"], input=shared_script, text=True, capture_output=True)
        if r.returncode != 0:
            print(f"[box-hardening] ERROR loading {SHARED_NFT_TABLE}: {r.stderr}", file=sys.stderr)
            sys.exit(1)
    else:
        run(["nft", "delete", "table", "inet", SHARED_NFT_TABLE], check=False)

def any_sandbox_mangle_tables_active():
    res = run(["nft", "list", "tables", "inet"], check=False)
    if res.returncode != 0:
        return False
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "table" and parts[1] == "inet" and parts[2].startswith("wsl_agent_sandbox_"):
            suffix = parts[2][len("wsl_agent_sandbox_"):]
            if suffix.isdigit():
                tbl = run(["nft", "list", "table", "inet", parts[2]], check=False)
                if tbl.returncode == 0 and "chain mangle_output" in tbl.stdout:
                    return True
    return False

# Manage per-UID mirrored-loopback policy routing rules cleanly (only affects agent_uid!),
# while keeping one shared fwmark 0x00002604 rule across concurrent profiles.
def sync_mirrored_ip_rules(enable_uid, enable_shared):
    for fam, target, wsl_table in [("-4", "127.0.0.0/8", "127"), ("-6", "::1/128", "127")]:
        # Remove legacy per-UID fwmark rules and this UID's uidrange rule
        legacy_and_uid_specs = [
            ["pref", "0", "to", target, "fwmark", LEGACY_MARK_HEX, "lookup", wsl_table],
            ["pref", "0", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "lookup", "local"],
            ["pref", "0", "not", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "fwmark", LEGACY_MARK_HEX, "lookup", "local"],
            ["pref", "0", "not", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "fwmark", SHARED_MARK_HEX, "lookup", "local"],
        ]
        for spec in legacy_and_uid_specs:
            for _ in range(4):
                r = run(["ip", fam, "rule", "del"] + spec, check=False)
                if r.returncode != 0:
                    break
        if enable_uid:
            # Shared rule (checked first): marked Windows->WSL replies & allowlisted host ports -> WSL loopback0 table
            existing = run(["ip", fam, "rule", "show"], check=False).stdout
            target_prefix = target.split("/")[0]
            has_shared = any(
                ("0x2604" in ln or SHARED_MARK_HEX in ln)
                and target_prefix in ln
                and f"lookup {wsl_table}" in ln
                for ln in existing.splitlines()
            )
            if not has_shared:
                run(["ip", fam, "rule", "add", "pref", "0", "to", target, "fwmark", SHARED_MARK_HEX, "lookup", wsl_table], check=False)
            # Per-UID rule (checked second): all other agent UID loopback traffic -> Linux local lo only
            run(["ip", fam, "rule", "add", "pref", "0", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "lookup", "local"], check=False)
        elif not enable_shared:
            for _ in range(4):
                r = run(["ip", fam, "rule", "del", "pref", "0", "to", target, "fwmark", SHARED_MARK_HEX, "lookup", wsl_table], check=False)
                if r.returncode != 0:
                    break

lines = [
    f"table inet {NFT_TABLE} {{",
]

log_drops = bool(net_cfg.get("logDrops", True))
if block_host_and_lan and log_drops:
    probe_rule = (
        "table inet __box_log_probe {\n"
        "    chain c {\n"
        '        limit rate 5/minute burst 10 packets log prefix "[wsl-agent-sandbox-drop] "\n'
        "        drop\n"
        "    }\n"
        "}\n"
    )
    probe = subprocess.run(["nft", "-c", "-f", "-"], input=probe_rule, text=True, capture_output=True)
    if probe.returncode != 0:
        print(
            f"[box-hardening] WARNING: kernel/nftables log target unavailable ({probe.stderr.strip()}); falling back to unconditional drop without log.",
            file=sys.stderr,
        )
        log_drops = False

if block_host_and_lan and log_drops:
    lines.extend([
        "    chain log_and_drop {",
        '        limit rate 5/minute burst 10 packets log prefix "[wsl-agent-sandbox-drop] "',
        "        drop",
        "    }",
    ])

if has_loopback0 and block_host_and_lan:
    # Per-UID mangle_output uses the shared 0x00002604 reply mark from wsl_agent_sandbox_shared,
    # while scoping allowedHostPorts strictly to this UID so concurrent profiles never interfere.
    lines.extend([
        "    chain mangle_output {",
        "        type route hook output priority mangle; policy accept;",
        f"        ct mark {SHARED_MARK_HEX} meta mark set {SHARED_MARK_HEX} accept",
        f"        meta skuid != {agent_uid} accept",
    ])
    if allowed_tcp:
        ports = ", ".join(str(p) for p in allowed_tcp)
        lines.append(f"        ip daddr 127.0.0.0/8 tcp dport {{ {ports} }} meta mark set {SHARED_MARK_HEX} accept")
        lines.append(f"        ip6 daddr ::1 tcp dport {{ {ports} }} meta mark set {SHARED_MARK_HEX} accept")
    if allowed_udp:
        ports = ", ".join(str(p) for p in allowed_udp)
        lines.append(f"        ip daddr 127.0.0.0/8 udp dport {{ {ports} }} meta mark set {SHARED_MARK_HEX} accept")
        lines.append(f"        ip6 daddr ::1 udp dport {{ {ports} }} meta mark set {SHARED_MARK_HEX} accept")
    lines.append("    }")

lines.extend([
    "    chain output {",
    "        type filter hook output priority 0; policy accept;",
    f"        meta skuid != {agent_uid} accept",
    "        ct state established,related accept",
    f'        oifname "lo" tcp dport {{ {egress_port}, {cred_port} }} accept',
    '        oifname "lo" tcp dport { 3128, 3129, 29100-29999, 30900-32697 } drop',
    '        oifname "lo" accept',
])

# Only permit direct agent UDP/TCP DNS queries in 'open' egress mode; in 'allowlist' mode
# egress-proxy.py performs root-side DNS resolution, preventing direct DNS tunneling exfiltration.
if egress_mode != "allowlist":
    if dns_v4:
        elems = ", ".join(sorted(dns_v4))
        lines.append(f"        ip daddr {{ {elems} }} udp dport 53 accept")
        lines.append(f"        ip daddr {{ {elems} }} tcp dport 53 accept")
    if dns_v6:
        elems = ", ".join(sorted(dns_v6))
        lines.append(f"        ip6 daddr {{ {elems} }} udp dport 53 accept")
        lines.append(f"        ip6 daddr {{ {elems} }} tcp dport 53 accept")

if allowed_tcp:
    ports = ", ".join(str(p) for p in allowed_tcp)
    lines.append(f'        oifname "loopback0" tcp dport {{ {ports} }} accept')
    if host_v4:
        hosts = ", ".join(sorted(host_v4))
        lines.append(f"        ip daddr {{ {hosts} }} tcp dport {{ {ports} }} accept")
if allowed_udp:
    ports = ", ".join(str(p) for p in allowed_udp)
    lines.append(f'        oifname "loopback0" udp dport {{ {ports} }} accept')
    if host_v4:
        hosts = ", ".join(sorted(host_v4))
        lines.append(f"        ip daddr {{ {hosts} }} udp dport {{ {ports} }} accept")

if block_host_and_lan:
    # Block WSL2 mirrored-mode outbound connections to Windows 127.0.0.1/::1 ports
    # (Windows -> WSL localhost replies still pass via 'ct state established,related accept',
    # and WSL-internal localhost still passes via 'oifname "lo" accept').
    drop_action = "jump log_and_drop" if log_drops else "drop"
    lines.append(f'        oifname "loopback0" {drop_action}')
    if host_v4:
        hosts = ", ".join(sorted(host_v4))
        lines.append(f"        ip daddr {{ {hosts} }} {drop_action}")
    if host_v6:
        hosts = ", ".join(sorted(host_v6))
        lines.append(f"        ip6 daddr {{ {hosts} }} {drop_action}")
    if blocked_v4:
        cidrs = ", ".join(sorted(set(blocked_v4)))
        lines.append(f"        ip daddr {{ {cidrs} }} {drop_action}")
    if blocked_v6:
        cidrs = ", ".join(sorted(set(blocked_v6)))
        lines.append(f"        ip6 daddr {{ {cidrs} }} {drop_action}")

if egress_mode == "allowlist":
    # Loopback (127.0.0.1:3128 egress-proxy) is already permitted above via 'oifname "lo" accept'.
    lines.append("        drop")

lines.extend([
    "    }",
    "}",
])

nft_text = "\n".join(lines) + "\n"
with open(nft_conf_file, "w", encoding="utf-8") as f:
    f.write(nft_text)
os.chmod(nft_conf_file, 0o600)

# Replace ONLY our table so Docker / other distros / other profiles are never disrupted.
run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
run(["nft", "delete", "table", "inet", "wsl_agent_sandbox"], check=False)
run(["nft", "delete", "table", "inet", "ubuntu_agent_box"], check=False)
res = run(["nft", "-f", nft_conf_file], check=False)
if res.returncode != 0:
    print(f"[box-hardening] ERROR loading nftables: {res.stderr}", file=sys.stderr)
    sys.exit(1)

enable_uid_mirrored = bool(has_loopback0 and block_host_and_lan)
enable_shared_mirrored = bool(has_loopback0 and (enable_uid_mirrored or any_sandbox_mangle_tables_active()))
sync_shared_nft_prerouting(enable_shared_mirrored)
sync_mirrored_ip_rules(enable_uid_mirrored, enable_shared_mirrored)

print(f"[box-hardening] Loaded nftables table inet {NFT_TABLE} for UID {agent_uid} (blockHostAndLan={block_host_and_lan}).")

# --- D. Optional per-UID systemd resource quotas (user-<uid>.slice) ---
slice_dir = f"/etc/systemd/system/user-{agent_uid}.slice.d"
dropin_path = os.path.join(slice_dir, "50-wsl-agent-sandbox.conf")
res_cfg = policy.get("resources") or {}
slice_lines = []
if res_cfg.get("memoryMax"):
    slice_lines.append(f"MemoryMax={res_cfg['memoryMax']}")
if res_cfg.get("cpuQuota"):
    slice_lines.append(f"CPUQuota={res_cfg['cpuQuota']}")
if res_cfg.get("tasksMax") is not None:
    slice_lines.append(f"TasksMax={int(res_cfg['tasksMax'])}")

if slice_lines:
    os.makedirs(slice_dir, mode=0o755, exist_ok=True)
    with open(dropin_path, "w", encoding="utf-8") as f:
        f.write("[Slice]\n" + "\n".join(slice_lines) + "\n")
    os.chmod(dropin_path, 0o644)
    if os.path.isdir("/run/systemd/system"):
        r = run(["systemctl", "daemon-reload"], check=False)
        if r.returncode != 0:
            print(f"[box-hardening] WARNING: systemctl daemon-reload failed: {r.stderr.strip()}", file=sys.stderr)
    print(f"[box-hardening] Configured {dropin_path}: {', '.join(slice_lines)}")
elif os.path.exists(dropin_path):
    os.remove(dropin_path)
    if os.path.isdir("/run/systemd/system"):
        r = run(["systemctl", "daemon-reload"], check=False)
        if r.returncode != 0:
            print(f"[box-hardening] WARNING: systemctl daemon-reload failed: {r.stderr.strip()}", file=sys.stderr)
    print(f"[box-hardening] Removed {dropin_path} (no resources quota configured).")
PYEOF

if [[ -x /usr/local/sbin/box-seed-secrets.sh ]]; then
  /usr/local/sbin/box-seed-secrets.sh --sweep-expired || log "WARNING: box-seed-secrets.sh --sweep-expired failed (continuing)."
fi
