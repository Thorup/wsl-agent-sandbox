#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"
HOST_IPS_FILE="/etc/wsl-agent-sandbox/host_ips.txt"

log() {
  echo "[apply-policy] $*"
}

render_agent_env() {
  local policy_file="${1:-${POLICY_FILE}}"
  local host_ips_file="${2:-${HOST_IPS_FILE}}"
  local profile_file="${3:-/etc/profile.d/99-agent-box.sh}"
  local env_file="${4:-/etc/environment}"

  local egress_mode=""
  local no_proxy_val=""
  local egress_port="3128"
  local env_meta=""
  env_meta="$(python3 - "${policy_file}" "${host_ips_file}" <<'PYEOF'
import ipaddress
import json
import os
import subprocess
import sys

policy_file, host_ips_file = sys.argv[1:3]
with open(policy_file, "r", encoding="utf-8") as f:
    policy = json.load(f)

uid = int((policy.get("agentUser") or {}).get("uid", 26040))
if uid == 26040:
    egress_port = 3128
elif 26100 <= uid <= 26998:
    egress_port = 30900 + ((uid - 26100) * 2)
else:
    egress_port = 29100 + (((uid * 31) % 450) * 2)

net_cfg = policy.get("network", {}) or {}
egress_mode = net_cfg.get("egressMode", "open")
no_proxy_entries = ["localhost", "127.0.0.1", "::1"]

if egress_mode == "allowlist" and net_cfg.get("allowedHostPorts"):
    seen = set(no_proxy_entries)
    candidates = []

    if os.path.isfile(host_ips_file):
        with open(host_ips_file, "r", encoding="utf-8") as hf:
            for line in hf:
                addr = line.strip().split("%")[0]
                if addr and not addr.startswith("#"):
                    candidates.append(addr)

    try:
        r = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True, check=False)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    candidates.append(parts[idx + 1].split("%")[0])
    except OSError:
        pass

    for addr in candidates:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback:
            ip_str = str(ip)
            if ip_str not in seen:
                seen.add(ip_str)
                no_proxy_entries.append(ip_str)

print(egress_mode)
print(",".join(no_proxy_entries))
print(egress_port)
PYEOF
)"
  egress_mode="$(printf '%s\n' "${env_meta}" | sed -n '1p')"
  no_proxy_val="$(printf '%s\n' "${env_meta}" | sed -n '2p')"
  egress_port="$(printf '%s\n' "${env_meta}" | sed -n '3p')"

  local profile_tmp="${profile_file}.tmp.$$"
  local env_tmp="${env_file}.tmp.$$"

  cat >"${profile_tmp}" <<'EOF'
# wsl-agent-sandbox environment
unset DISPLAY WAYLAND_DISPLAY PULSE_SERVER WSL_INTEROP
export DOCKER_HOST="unix:///run/docker-policy/docker.sock"
export DOTNET_ROOT="/usr/local/share/dotnet"
export PATH="$HOME/.cargo/bin:$HOME/.dotnet/tools:$HOME/.local/bin:$HOME/.local/share/pnpm:$HOME/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
if [ "$(id -u)" -ne 0 ]; then
  export NPM_CONFIG_PREFIX="$HOME/.npm-global"
  export PNPM_HOME="$HOME/.local/share/pnpm"
fi
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

  cat >"${env_tmp}" <<'EOF'
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DOCKER_HOST="unix:///run/docker-policy/docker.sock"
DOTNET_ROOT="/usr/local/share/dotnet"
BASH_ENV="/etc/profile.d/99-agent-box.sh"
EOF

  if [[ "${egress_mode}" == "allowlist" ]]; then
    cat >>"${profile_tmp}" <<EOF
export HTTP_PROXY="http://127.0.0.1:${egress_port}"
export HTTPS_PROXY="http://127.0.0.1:${egress_port}"
export http_proxy="http://127.0.0.1:${egress_port}"
export https_proxy="http://127.0.0.1:${egress_port}"
export NO_PROXY="${no_proxy_val}"
export no_proxy="${no_proxy_val}"
EOF
    cat >>"${env_tmp}" <<EOF
HTTP_PROXY="http://127.0.0.1:${egress_port}"
HTTPS_PROXY="http://127.0.0.1:${egress_port}"
http_proxy="http://127.0.0.1:${egress_port}"
https_proxy="http://127.0.0.1:${egress_port}"
NO_PROXY="${no_proxy_val}"
no_proxy="${no_proxy_val}"
EOF
  fi

  chmod 0644 "${profile_tmp}" "${env_tmp}"
  mv -f "${profile_tmp}" "${profile_file}"
  mv -f "${env_tmp}" "${env_file}"
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "[apply-policy] ERROR: must run as root" >&2
    exit 1
  fi

  if [[ "${1:-}" == "--render-env-only" ]]; then
    render_agent_env "${POLICY_FILE}" "${HOST_IPS_FILE}" "/etc/profile.d/99-agent-box.sh" "/etc/environment"
    exit 0
  fi

  # Global (not `local`): the EXIT trap fires after main() returns, when locals are gone and
  # `set -u` would abort with "unbound variable" (turning a successful apply into exit 1).
  maintenance_egress_active=0
  restore_maintenance_egress() {
    if [[ "${maintenance_egress_active:-0}" -eq 1 ]] && [[ -x /usr/local/sbin/box-hardening.sh ]]; then
      /usr/local/sbin/box-hardening.sh >/dev/null 2>&1 || true
    fi
  }
  trap restore_maintenance_egress EXIT

  log "Applying mounts, Docker bind mirrors, docker-policy.json, and host/LAN nftables (maintenance egress open)..."
  maintenance_egress_active=1
  BOX_MAINTENANCE_EGRESS_OPEN=1 /usr/local/sbin/box-hardening.sh

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

  # Atomically keep shell profile and /etc/environment in sync
  render_agent_env "${POLICY_FILE}" "${HOST_IPS_FILE}" "/etc/profile.d/99-agent-box.sh" "/etc/environment"

  if [[ -x /usr/local/sbin/box-sync-context.py ]]; then
    /usr/local/sbin/box-sync-context.py
  fi

  log "Restoring strict nftables egress rules..."
  maintenance_egress_active=0
  /usr/local/sbin/box-hardening.sh

  DOCKER_ENABLED="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print("1" if d["docker"].get("enabled", True) else "0")' "${POLICY_FILE}")"
  EGRESS_MODE="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("network", {}).get("egressMode", "open"))' "${POLICY_FILE}")"

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
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
