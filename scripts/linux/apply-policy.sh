#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"

log() {
  echo "[apply-policy] $*"
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[apply-policy] ERROR: must run as root" >&2
  exit 1
fi

log "Re-applying mounts, Docker bind mirrors, docker-policy.json, and nftables..."
/usr/local/sbin/box-hardening.sh

# Install any newly added apt packages from policy.json
mapfile -t APT_PKGS < <(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print("\n".join(d["packages"].get("apt", [])))' "${POLICY_FILE}")
MISSING=()
for pkg in "${APT_PKGS[@]}"; do
  if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
    MISSING+=("${pkg}")
  fi
done
if [[ "${#MISSING[@]}" -gt 0 ]]; then
  log "Installing newly configured apt packages: ${MISSING[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "${MISSING[@]}"
fi

# Install any newly enabled CLI tools (kubectl, aws, gcloud, claude, dotnet, rust, etc.)
if [[ -x /usr/local/sbin/box-install-tools.sh ]]; then
  /usr/local/sbin/box-install-tools.sh
fi

# Keep shell profile and /etc/environment in sync
cat >/etc/profile.d/99-agent-box.sh <<'EOF'
# wsl-agent-sandbox environment
unset DISPLAY WAYLAND_DISPLAY PULSE_SERVER WSL_INTEROP
export DOCKER_HOST="unix:///run/docker-policy/docker.sock"
export DOTNET_ROOT="/usr/local/share/dotnet"
export PATH="$HOME/.cargo/bin:$HOME/.dotnet/tools:$HOME/.local/bin:$HOME/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export BASH_ENV="/etc/profile.d/99-agent-box.sh"
# Load seeded CLI service credentials (managed by box.ps1 seed-secrets)
if [ -r "$HOME/.config/wsl-agent-sandbox/secrets.env" ]; then
  . "$HOME/.config/wsl-agent-sandbox/secrets.env"
fi
# Load active profile overrides (managed by use-gcloud / use-aws)
if [ -r "$HOME/.config/wsl-agent-sandbox/active-overrides.env" ]; then
  . "$HOME/.config/wsl-agent-sandbox/active-overrides.env"
fi
use-gcloud() {
  /usr/local/bin/use-gcloud "$@" || return $?
  if [ -r "$HOME/.config/wsl-agent-sandbox/active-overrides.env" ]; then
    . "$HOME/.config/wsl-agent-sandbox/active-overrides.env"
  fi
}
use-aws() {
  /usr/local/bin/use-aws "$@" || return $?
  if [ -r "$HOME/.config/wsl-agent-sandbox/active-overrides.env" ]; then
    . "$HOME/.config/wsl-agent-sandbox/active-overrides.env"
  fi
}
use-github() {
  /usr/local/bin/use-github "$@" || return $?
  if [ -r "$HOME/.config/wsl-agent-sandbox/active-overrides.env" ]; then
    . "$HOME/.config/wsl-agent-sandbox/active-overrides.env"
  fi
}
EOF
chmod 0644 /etc/profile.d/99-agent-box.sh

cat >/etc/environment <<'EOF'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DOCKER_HOST="unix:///run/docker-policy/docker.sock"
DOTNET_ROOT="/usr/local/share/dotnet"
BASH_ENV="/etc/profile.d/99-agent-box.sh"
EOF

if [[ -x /usr/local/sbin/box-sync-context.py ]]; then
  /usr/local/sbin/box-sync-context.py
fi

DOCKER_ENABLED="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print("1" if d["docker"].get("enabled", True) else "0")' "${POLICY_FILE}")"
EGRESS_MODE="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("network", {}).get("egressMode", "open"))' "${POLICY_FILE}")"
EGRESS_PROXY_PORT="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print(int(d.get("listenPort", 3128)))' /etc/wsl-agent-sandbox/egress-allowlist.json 2>/dev/null || echo 3128)"

if [[ "${EGRESS_MODE}" == "allowlist" ]]; then
  cat >>/etc/profile.d/99-agent-box.sh <<EOF
export HTTP_PROXY="http://127.0.0.1:${EGRESS_PROXY_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${EGRESS_PROXY_PORT}"
export http_proxy="http://127.0.0.1:${EGRESS_PROXY_PORT}"
export https_proxy="http://127.0.0.1:${EGRESS_PROXY_PORT}"
export NO_PROXY="localhost,127.0.0.1,::1"
EOF
  cat >>/etc/environment <<EOF
HTTP_PROXY="http://127.0.0.1:${EGRESS_PROXY_PORT}"
HTTPS_PROXY="http://127.0.0.1:${EGRESS_PROXY_PORT}"
http_proxy="http://127.0.0.1:${EGRESS_PROXY_PORT}"
https_proxy="http://127.0.0.1:${EGRESS_PROXY_PORT}"
NO_PROXY="localhost,127.0.0.1,::1"
EOF
fi

if pidof systemd >/dev/null 2>&1; then
  systemctl daemon-reload
  if [[ "${EGRESS_MODE}" == "allowlist" ]] && [[ -f /etc/systemd/system/egress-proxy.service ]]; then
    python3 - "${EGRESS_PROXY_PORT}" <<'PYEOF'
import os, signal, subprocess, sys, time

port = int(sys.argv[1])
hex_port = f"{port:04X}"

def find_listeners(target_hex_port):
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
            if state == "0A" and local_addr.endswith(":" + target_hex_port):
                try:
                    found.append((local_addr, int(parts[7]), parts[9]))
                except ValueError:
                    pass
    return found

def kill_inodes(inodes):
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

squatters = [x for x in find_listeners(hex_port) if x[1] != 0]
if squatters:
    kill_inodes([x[2] for x in squatters])
    time.sleep(0.3)
    remaining = [x for x in find_listeners(hex_port) if x[1] != 0]
    if remaining:
        print(f"[apply-policy] SECURITY ERROR: non-root process (uid={remaining[0][1]}) squatting on port {port}", file=sys.stderr)
        sys.exit(1)

subprocess.run(["systemctl", "enable", "egress-proxy.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["systemctl", "restart", "egress-proxy.service"], check=True)

deadline = time.monotonic() + 3.0
while time.monotonic() < deadline:
    active = subprocess.run(["systemctl", "is-active", "--quiet", "egress-proxy.service"], check=False).returncode == 0
    root_listen = any(addr == f"0100007F:{hex_port}" and uid == 0 for addr, uid, _ in find_listeners(hex_port))
    if active and root_listen:
        sys.exit(0)
    time.sleep(0.1)

print(f"[apply-policy] ERROR: egress-proxy.service failed to bind 127.0.0.1:{port} as root within 3s", file=sys.stderr)
sys.exit(1)
PYEOF
    log "egress-proxy.service active on 127.0.0.1:${EGRESS_PROXY_PORT} (allowlist mode)."
  else
    systemctl stop egress-proxy.service 2>/dev/null || true
    systemctl disable egress-proxy.service >/dev/null 2>&1 || true
  fi
  if [[ "${DOCKER_ENABLED}" == "1" ]]; then
    systemctl enable docker-policy-proxy.service >/dev/null 2>&1 || true
    systemctl restart docker-policy-proxy.service
    log "docker-policy-proxy.service active."
  else
    systemctl stop docker-policy-proxy.service || true
    systemctl disable docker-policy-proxy.service >/dev/null 2>&1 || true
    rm -f /var/run/docker.sock /run/docker-policy/docker.sock
    log "Docker proxy disabled per policy."
  fi
else
  log "WARNING: systemd is not PID 1 yet; restart distro ('wsl --terminate <distro>') to start services."
fi

log "Policy applied successfully."
