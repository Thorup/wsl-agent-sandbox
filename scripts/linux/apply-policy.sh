#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/ubuntu-agent-box/policy.json"

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
mapfile -t APT_PKGS < <(python3 -c 'import json; d=json.load(open("/etc/ubuntu-agent-box/policy.json")); print("\n".join(d["packages"].get("apt", [])))')
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
# Hardened Ubuntu WSL Agent Box environment
unset DISPLAY WAYLAND_DISPLAY PULSE_SERVER WSL_INTEROP
export DOCKER_HOST="unix:///run/docker-policy/docker.sock"
export DOTNET_ROOT="/usr/local/share/dotnet"
export PATH="$HOME/.cargo/bin:$HOME/.dotnet/tools:$HOME/.local/bin:$HOME/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 0644 /etc/profile.d/99-agent-box.sh

cat >/etc/environment <<'EOF'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DOCKER_HOST="unix:///run/docker-policy/docker.sock"
DOTNET_ROOT="/usr/local/share/dotnet"
EOF

DOCKER_ENABLED="$(python3 -c 'import json; d=json.load(open("/etc/ubuntu-agent-box/policy.json")); print("1" if d["docker"].get("enabled", True) else "0")')"

if pidof systemd >/dev/null 2>&1; then
  systemctl daemon-reload
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
  log "WARNING: systemd is not PID 1 yet; restart distro (`wsl --terminate <distro>`) to start services."
fi

log "Policy applied successfully."
