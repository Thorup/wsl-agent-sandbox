#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/ubuntu-agent-box/policy.json"
HOST_IPS_FILE="/etc/ubuntu-agent-box/host_ips.txt"
DOCKER_POLICY_FILE="/etc/ubuntu-agent-box/docker-policy.json"
NFT_CONF_FILE="/etc/ubuntu-agent-box/nftables.conf"
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
python3 - "${POLICY_FILE}" "${HOST_IPS_FILE}" "${DOCKER_POLICY_FILE}" "${NFT_CONF_FILE}" "${PRIVATE_WSL_MNT}" <<'PYEOF'
import ipaddress
import json
import os
import re
import subprocess
import sys

policy_file, host_ips_file, docker_policy_file, nft_conf_file, private_wsl_mnt = sys.argv[1:6]

with open(policy_file, "r", encoding="utf-8") as f:
    policy = json.load(f)

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
compiled_docker_policy = {
    "enabled": bool(docker_cfg.get("enabled", True)),
    "allowBuildKit": bool(docker_cfg.get("allowBuildKit", True)),
    "allowCapAdd": docker_cfg.get("allowCapAdd", []),
    "denyEndpoints": docker_cfg.get("denyEndpoints", [
        "/plugins", "/swarm", "/services", "/nodes", "/secrets", "/configs", "/tasks"
    ]),
    "bindMappings": bind_mappings,
}
with open(docker_policy_file, "w", encoding="utf-8") as f:
    json.dump(compiled_docker_policy, f, indent=2)
os.chmod(docker_policy_file, 0o600)

# --- C. Per-UID nftables firewall (table inet ubuntu_agent_box) ---
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
blocked_v4 = []
blocked_v6 = ["fc00::/7", "fe80::/10"]
for cidr in net_cfg.get("blockedCidrs", []):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version == 4:
        blocked_v4.append(str(net))
    else:
        blocked_v6.append(str(net))

allowed_tcp = sorted({int(p["port"]) for p in net_cfg.get("allowedHostPorts", []) if p.get("protocol") == "tcp"})
allowed_udp = sorted({int(p["port"]) for p in net_cfg.get("allowedHostPorts", []) if p.get("protocol") == "udp"})

# Detect WSL2 mirrored networking (presence of 'loopback0' interface)
has_loopback0 = run(["ip", "link", "show", "loopback0"], check=False).returncode == 0
MARK_HEX = "0x00002604"

# Manage per-UID mirrored-loopback policy routing rules cleanly (only affects agent_uid!)
def sync_mirrored_ip_rules(enable):
    for fam, target, wsl_table in [("-4", "127.0.0.0/8", "127"), ("-6", "::1/128", "127")]:
        # Clean up any prior rules we installed (including legacy 'not' rule if present)
        cleanup_specs = [
            ["pref", "0", "to", target, "fwmark", MARK_HEX, "lookup", wsl_table],
            ["pref", "0", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "lookup", "local"],
            ["pref", "0", "not", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "fwmark", MARK_HEX, "lookup", "local"],
        ]
        for spec in cleanup_specs:
            for _ in range(4):
                r = run(["ip", fam, "rule", "del"] + spec, check=False)
                if r.returncode != 0:
                    break
        if enable:
            # Rule 1 (checked first): marked Windows->WSL replies & allowlisted host ports -> WSL loopback0 table
            run(["ip", fam, "rule", "add", "pref", "0", "to", target, "fwmark", MARK_HEX, "lookup", wsl_table], check=False)
            # Rule 2 (checked second): all other agent UID loopback traffic -> Linux local lo only
            run(["ip", fam, "rule", "add", "pref", "0", "to", target, "uidrange", f"{agent_uid}-{agent_uid}", "lookup", "local"], check=False)

sync_mirrored_ip_rules(has_loopback0 and block_host_and_lan)

lines = [
    "table inet ubuntu_agent_box {",
]

if has_loopback0 and block_host_and_lan:
    # Tag inbound connections from Windows -> WSL arriving on loopback0 so replies route back via loopback0
    lines.extend([
        "    chain prerouting {",
        "        type filter hook prerouting priority mangle; policy accept;",
        f'        iifname "loopback0" ct mark set {MARK_HEX}',
        "    }",
        "    chain mangle_output {",
        "        type route hook output priority mangle; policy accept;",
        f"        ct mark {MARK_HEX} meta mark set {MARK_HEX} accept",
        f"        meta skuid != {agent_uid} accept",
    ])
    if allowed_tcp:
        ports = ", ".join(str(p) for p in allowed_tcp)
        lines.append(f"        ip daddr 127.0.0.0/8 tcp dport {{ {ports} }} meta mark set {MARK_HEX} accept")
        lines.append(f"        ip6 daddr ::1 tcp dport {{ {ports} }} meta mark set {MARK_HEX} accept")
    if allowed_udp:
        ports = ", ".join(str(p) for p in allowed_udp)
        lines.append(f"        ip daddr 127.0.0.0/8 udp dport {{ {ports} }} meta mark set {MARK_HEX} accept")
        lines.append(f"        ip6 daddr ::1 udp dport {{ {ports} }} meta mark set {MARK_HEX} accept")
    lines.append("    }")

lines.extend([
    "    chain output {",
    "        type filter hook output priority 0; policy accept;",
    f"        meta skuid != {agent_uid} accept",
    "        ct state established,related accept",
    '        oifname "lo" accept',
])

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
    lines.append('        oifname "loopback0" drop')
    if host_v4:
        hosts = ", ".join(sorted(host_v4))
        lines.append(f"        ip daddr {{ {hosts} }} drop")
    if host_v6:
        hosts = ", ".join(sorted(host_v6))
        lines.append(f"        ip6 daddr {{ {hosts} }} drop")
    if blocked_v4:
        cidrs = ", ".join(sorted(set(blocked_v4)))
        lines.append(f"        ip daddr {{ {cidrs} }} drop")
    if blocked_v6:
        cidrs = ", ".join(sorted(set(blocked_v6)))
        lines.append(f"        ip6 daddr {{ {cidrs} }} drop")

lines.extend([
    "    }",
    "}",
])

nft_text = "\n".join(lines) + "\n"
with open(nft_conf_file, "w", encoding="utf-8") as f:
    f.write(nft_text)
os.chmod(nft_conf_file, 0o600)

# Replace ONLY our table so Docker / other distros are never disrupted.
run(["nft", "delete", "table", "inet", "ubuntu_agent_box"], check=False)
res = run(["nft", "-f", nft_conf_file], check=False)
if res.returncode != 0:
    print(f"[box-hardening] ERROR loading nftables: {res.stderr}", file=sys.stderr)
    sys.exit(1)

print(f"[box-hardening] Loaded nftables table inet ubuntu_agent_box for UID {agent_uid} (blockHostAndLan={block_host_and_lan}).")
PYEOF
