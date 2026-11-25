#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"
PROXY_SRC_DIR="/usr/local/src/docker-policy-proxy"
PROXY_BIN="/usr/local/libexec/docker-policy-proxy"
PROXY_HASH_FILE="/usr/local/libexec/docker-policy-proxy.sha256"

log() {
  echo "[provision] $*"
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[provision] ERROR: must run as root" >&2
  exit 1
fi

if [[ ! -f "${POLICY_FILE}" ]]; then
  echo "[provision] ERROR: ${POLICY_FILE} missing" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Wait for apt/dpkg locks if any
apt-get update -y
apt-get install -y --no-install-recommends python3 jq ca-certificates curl gnupg

# Read config values via python3
AGENT_NAME="$(python3 -c 'import json; d=json.load(open("/etc/wsl-agent-sandbox/policy.json")); print(d["agentUser"]["name"])')"
AGENT_UID="$(python3 -c 'import json; d=json.load(open("/etc/wsl-agent-sandbox/policy.json")); print(d["agentUser"]["uid"])')"
AGENT_GID="$(python3 -c 'import json; d=json.load(open("/etc/wsl-agent-sandbox/policy.json")); print(d["agentUser"]["gid"])')"

log "Configuring /etc/wsl.conf (automount=false, interop=false, systemd=true, default=${AGENT_NAME})..."
cat >/etc/wsl.conf <<EOF
[automount]
enabled = false
mountFsTab = false

[interop]
enabled = false
appendWindowsPath = false

[boot]
systemd = true

[user]
default = ${AGENT_NAME}
EOF
chmod 0644 /etc/wsl.conf

log "Creating dedicated non-root user ${AGENT_NAME} (UID=${AGENT_UID}, GID=${AGENT_GID}) with NO sudo..."
if ! getent group agent-docker >/dev/null; then
  groupadd --system agent-docker
fi
if ! getent group "${AGENT_GID}" >/dev/null && ! getent group "${AGENT_NAME}" >/dev/null; then
  groupadd --gid "${AGENT_GID}" "${AGENT_NAME}"
fi
if ! id -u "${AGENT_NAME}" >/dev/null 2>&1; then
  useradd --uid "${AGENT_UID}" --gid "${AGENT_GID}" --create-home --shell /bin/bash "${AGENT_NAME}"
fi
usermod -aG agent-docker "${AGENT_NAME}"

# Ensure agent is NEVER in privileged groups
for priv_grp in sudo adm wheel docker root shadow staff; do
  if getent group "${priv_grp}" >/dev/null && id -nG "${AGENT_NAME}" | grep -qw "${priv_grp}"; then
    gpasswd -d "${AGENT_NAME}" "${priv_grp}" || true
  fi
done

# Lock root and agent passwords (root is accessible ONLY via Windows `wsl -u root`)
passwd -l root >/dev/null 2>&1 || true
passwd -l "${AGENT_NAME}" >/dev/null 2>&1 || true

# Remove any default cloud/ubuntu passwordless sudoers and restrict sudo binary to root:sudo
rm -f /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/ubuntu 2>/dev/null || true
if [[ -f /usr/bin/sudo ]]; then
  chown root:sudo /usr/bin/sudo 2>/dev/null || true
  chmod 0750 /usr/bin/sudo 2>/dev/null || true
fi

log "Installing configured apt packages..."
mapfile -t APT_PKGS < <(python3 -c 'import json; d=json.load(open("/etc/wsl-agent-sandbox/policy.json")); print("\n".join(d["packages"].get("apt", [])))')
if [[ "${#APT_PKGS[@]}" -gt 0 ]]; then
  apt-get install -y --no-install-recommends "${APT_PKGS[@]}"
fi

# Symlink fd -> fdfind for convenience
if command -v fdfind >/dev/null 2>&1 && [[ ! -e /usr/local/bin/fd ]]; then
  ln -s "$(command -v fdfind)" /usr/local/bin/fd
fi

# Install configured developer, cloud, and agent CLI tools
/usr/local/sbin/box-install-tools.sh

# Build & test Go Docker API Policy Proxy
if [[ -d "${PROXY_SRC_DIR}" ]]; then
  log "Installing Go toolchain to build and test docker-policy-proxy..."
  apt-get install -y --no-install-recommends golang-go
  log "Running Go unit & integration tests (go test -v -race ./...)..."
  (cd "${PROXY_SRC_DIR}" && go test -v -race ./...)
  log "Building ${PROXY_BIN}..."
  mkdir -p "$(dirname "${PROXY_BIN}")"
  (cd "${PROXY_SRC_DIR}" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${PROXY_BIN}" .)
  chown root:root "${PROXY_BIN}"
  chmod 0755 "${PROXY_BIN}"
  python3 -c '
import hashlib, pathlib, sys
src = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
for p in sorted((f for f in src.iterdir() if f.is_file() and (f.name in ("go.mod", "go.sum") or f.suffix == ".go")), key=lambda x: x.name):
    data = p.read_text(encoding="utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    h.update(f"FILE:{p.name}\n".encode("utf-8"))
    h.update(data.encode("utf-8"))
    h.update(b"\n")
pathlib.Path(sys.argv[2]).write_text(h.hexdigest() + "\n", encoding="utf-8")
' "${PROXY_SRC_DIR}" "${PROXY_HASH_FILE}"
  chown root:root "${PROXY_HASH_FILE}"
  chmod 0644 "${PROXY_HASH_FILE}"
fi

# Pre-create user-space npm/pnpm directories so non-root global installs work without prompts
for dir in \
  "/home/${AGENT_NAME}/.npm-global" \
  "/home/${AGENT_NAME}/.npm-global/bin" \
  "/home/${AGENT_NAME}/.local" \
  "/home/${AGENT_NAME}/.local/share" \
  "/home/${AGENT_NAME}/.local/share/pnpm"
do
  install -d -o "${AGENT_UID}" -g "${AGENT_GID}" -m 0755 "${dir}"
done

# Configure agent shell environment & /etc/environment atomically (including allowlist proxy/no_proxy if enabled)
if [[ -x /usr/local/sbin/box-apply-policy.sh ]]; then
  /usr/local/sbin/box-apply-policy.sh --render-env-only
fi

# Ensure non-login bash shells (e.g. VS Code / Antigravity / scripts) also get DOCKER_HOST and clean env
AGENT_BASHRC="/home/${AGENT_NAME}/.bashrc"
if ! grep -q "99-agent-box.sh" "${AGENT_BASHRC}" 2>/dev/null; then
  cat >>"${AGENT_BASHRC}" <<'EOF'

# Source wsl-agent-sandbox environment
if [ -f /etc/profile.d/99-agent-box.sh ]; then
  . /etc/profile.d/99-agent-box.sh
fi
EOF
  chown "${AGENT_UID}:${AGENT_GID}" "${AGENT_BASHRC}"
fi

if [[ -x /usr/local/sbin/box-sync-context.py ]]; then
  /usr/local/sbin/box-sync-context.py
fi

enforce_sudo_hardening() {
  local -A seen=()
  local -a targets=()
  local candidate resolved

  if [[ -L /usr/bin/sudo ]]; then
    dpkg-statoverride --remove /usr/bin/sudo >/dev/null 2>&1 || true
  fi

  for candidate in \
    "$(readlink -f /usr/bin/sudo 2>/dev/null || true)" \
    /usr/bin/sudo \
    /usr/bin/sudo.ws \
    /usr/lib/cargo/bin/sudo \
    $(update-alternatives --list sudo 2>/dev/null || true)
  do
    [[ -n "${candidate}" && -e "${candidate}" ]] || continue
    resolved="$(readlink -f "${candidate}" 2>/dev/null || printf '%s' "${candidate}")"
    if [[ -f "${resolved}" && ! -L "${resolved}" && -z "${seen[${resolved}]:-}" ]]; then
      seen["${resolved}"]=1
      targets+=("${resolved}")
    fi
  done

  local desired current target
  for target in "${targets[@]}"; do
    desired="root sudo 750 ${target}"
    current="$(dpkg-statoverride --list "${target}" 2>/dev/null || true)"
    if [[ "${current}" != "${desired}" ]]; then
      if [[ -n "${current}" ]]; then
        dpkg-statoverride --remove "${target}" >/dev/null 2>&1 || true
      fi
      dpkg-statoverride --update --add root sudo 0750 "${target}" >/dev/null 2>&1 || true
    fi
    chown root:sudo "${target}" 2>/dev/null || true
    chmod 0750 "${target}" 2>/dev/null || true
  done
}

# Re-enforce sudo/sudo-rs hardening after all apt-get and tool installations
enforce_sudo_hardening

# Enable systemd services (active after WSL restart with systemd=true)
chmod 0755 /usr/local/sbin/box-hardening.sh
chmod 0644 /etc/systemd/system/box-hardening.service /etc/systemd/system/docker-policy-proxy.service
systemctl enable box-hardening.service docker-policy-proxy.service >/dev/null 2>&1 || true

log "Provisioning complete! Restart the WSL distro so /etc/wsl.conf and systemd take effect."
