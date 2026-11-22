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

if [[ "${EGRESS_MODE}" == "allowlist" ]]; then
  cat >>/etc/profile.d/99-agent-box.sh <<'EOF'
export HTTP_PROXY="http://127.0.0.1:3128"
export HTTPS_PROXY="http://127.0.0.1:3128"
export http_proxy="http://127.0.0.1:3128"
export https_proxy="http://127.0.0.1:3128"
export NO_PROXY="localhost,127.0.0.1,::1"
EOF
  cat >>/etc/environment <<'EOF'
HTTP_PROXY="http://127.0.0.1:3128"
HTTPS_PROXY="http://127.0.0.1:3128"
http_proxy="http://127.0.0.1:3128"
https_proxy="http://127.0.0.1:3128"
NO_PROXY="localhost,127.0.0.1,::1"
EOF
fi

if pidof systemd >/dev/null 2>&1; then
  systemctl daemon-reload
  if [[ "${EGRESS_MODE}" == "allowlist" ]] && [[ -f /etc/systemd/system/egress-proxy.service ]]; then
    systemctl enable egress-proxy.service >/dev/null 2>&1 || true
    systemctl restart egress-proxy.service
    log "egress-proxy.service active (allowlist mode)."
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
