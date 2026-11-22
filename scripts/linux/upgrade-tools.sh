#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"
SCOPE="${1:-all}"

log() {
  echo "[upgrade] $*"
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[upgrade] ERROR: must run as root" >&2
  exit 1
fi

if [[ ! -f "${POLICY_FILE}" ]]; then
  echo "[upgrade] ERROR: ${POLICY_FILE} missing" >&2
  exit 1
fi

has_scope() {
  local target="$1"
  [[ "${SCOPE}" == "all" ]] || [[ ",${SCOPE}," == *",${target},"* ]]
}

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

AGENT_NAME="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d["agentUser"]["name"])' "${POLICY_FILE}")"
ARCH="$(dpkg --print-architecture)"
export DEBIAN_FRONTEND=noninteractive

declare -A BEFORE_VERSIONS=()
declare -A AFTER_VERSIONS=()

record_ver() {
  local name="$1"
  local cmd="$2"
  local phase="$3"
  local ver
  ver="$(bash -c "${cmd}" 2>/dev/null | head -n 1 || true)"
  if [[ -z "${ver}" ]]; then
    ver="(unavailable)"
  fi
  if [[ "${phase}" == "before" ]]; then
    BEFORE_VERSIONS["${name}"]="${ver}"
  else
    AFTER_VERSIONS["${name}"]="${ver}"
  fi
}

if has_scope "apt"; then
  record_ver "apt-upgradable" "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l" "before"
  log "Updating apt package index and upgrading installed packages..."
  apt-get update -y
  apt-get upgrade -y --no-install-recommends \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold"
  enforce_sudo_hardening
  if [[ -x /usr/local/sbin/box-hardening.sh ]]; then
    log "Re-applying sandbox hardening after apt upgrade..."
    /usr/local/sbin/box-hardening.sh
  fi
  record_ver "apt-upgradable" "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l" "after"
fi

if has_scope "agents"; then
  if command -v npm >/dev/null 2>&1; then
    for pkg in pnpm @google/gemini-cli @anthropic-ai/claude-code; do
      if npm list -g --depth=0 "${pkg}" >/dev/null 2>&1; then
        record_ver "npm:${pkg}" "npm list -g --depth=0 '${pkg}' --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('dependencies',{}).get('${pkg}',{}).get('version','unknown'))\"" "before"
        log "Updating global npm package ${pkg}..."
        npm install -g "${pkg}@latest"
        record_ver "npm:${pkg}" "npm list -g --depth=0 '${pkg}' --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('dependencies',{}).get('${pkg}',{}).get('version','unknown'))\"" "after"
      fi
    done
  fi
fi

if has_scope "toolchains"; then
  if command -v uv >/dev/null 2>&1; then
    record_ver "uv" "uv --version" "before"
    log "Updating uv..."
    uv self update 2>/dev/null || log "Note: uv self update skipped/unavailable."
    record_ver "uv" "uv --version" "after"
  fi
  if [[ -x "/home/${AGENT_NAME}/.cargo/bin/rustup" ]]; then
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    record_ver "rust" "su -s /bin/bash - '${AGENT_NAME}' -c '\"\$HOME/.cargo/bin/rustc\" --version'" "before"
    log "Updating Rust toolchain for '${AGENT_NAME}'..."
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    su -s /bin/bash - "${AGENT_NAME}" -c '"$HOME/.cargo/bin/rustup" update'
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    record_ver "rust" "su -s /bin/bash - '${AGENT_NAME}' -c '\"\$HOME/.cargo/bin/rustc\" --version'" "after"
  fi
  if command -v az >/dev/null 2>&1; then
    if su -s /bin/bash - "${AGENT_NAME}" -c 'az extension show --name azure-devops >/dev/null 2>&1'; then
      record_ver "azure-devops" "su -s /bin/bash - '${AGENT_NAME}' -c 'az extension show --name azure-devops --query version -o tsv'" "before"
      log "Updating azure-devops extension for '${AGENT_NAME}'..."
      su -s /bin/bash - "${AGENT_NAME}" -c 'az extension update --name azure-devops' || true
      record_ver "azure-devops" "su -s /bin/bash - '${AGENT_NAME}' -c 'az extension show --name azure-devops --query version -o tsv'" "after"
    fi
  fi
  if command -v kubectl >/dev/null 2>&1; then
    record_ver "kubectl" "kubectl version --client --output=yaml 2>/dev/null | grep -m1 gitVersion | awk '{print \$2}'" "before"
    K8S_VER="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
    TMP_DIR="$(mktemp -d)"
    curl -fsSL "https://dl.k8s.io/release/${K8S_VER}/bin/linux/${ARCH}/kubectl" -o "${TMP_DIR}/kubectl"
    curl -fsSL "https://dl.k8s.io/release/${K8S_VER}/bin/linux/${ARCH}/kubectl.sha256" -o "${TMP_DIR}/kubectl.sha256"
    (cd "${TMP_DIR}" && echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check -)
    install -o root -g root -m 0755 "${TMP_DIR}/kubectl" /usr/local/bin/kubectl
    rm -rf "${TMP_DIR}"
    record_ver "kubectl" "kubectl version --client --output=yaml 2>/dev/null | grep -m1 gitVersion | awk '{print \$2}'" "after"
  fi
  if command -v upctl >/dev/null 2>&1; then
    # shellcheck disable=SC2016 # $2 expands inside inner subshell awk
    record_ver "upctl" "upctl version 2>/dev/null | grep -m1 'Version:' | awk '{print \$2}'" "before"
    UPCTL_ARCH="x86_64"
    [[ "${ARCH}" == "arm64" ]] && UPCTL_ARCH="arm64"
    TMP_DIR="$(mktemp -d)"
    RELEASE_JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' https://api.github.com/repos/UpCloudLtd/upcloud-cli/releases/latest)"
    ASSET_URL="$(printf '%s' "${RELEASE_JSON}" | python3 -c "import json,sys; r=json.load(sys.stdin); print(next(a['browser_download_url'] for a in r['assets'] if a['name'].endswith('_linux_${UPCTL_ARCH}.tar.gz')))")"
    CHECKSUMS_URL="$(printf '%s' "${RELEASE_JSON}" | python3 -c "import json,sys; r=json.load(sys.stdin); print(next(a['browser_download_url'] for a in r['assets'] if a['name'].endswith('checksums.txt')))")"
    ASSET_NAME="$(basename "${ASSET_URL}")"
    curl -fsSL "${ASSET_URL}" -o "${TMP_DIR}/${ASSET_NAME}"
    curl -fsSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/checksums.txt"
    (cd "${TMP_DIR}" && sha256sum -c --ignore-missing checksums.txt)
    tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "${TMP_DIR}"
    UPCTL_BIN="$(find "${TMP_DIR}" -maxdepth 3 -type f -name upctl | head -n 1)"
    install -o root -g root -m 0755 "${UPCTL_BIN}" /usr/local/bin/upctl
    rm -rf "${TMP_DIR}"
    # shellcheck disable=SC2016 # $2 expands inside inner subshell awk
    record_ver "upctl" "upctl version 2>/dev/null | grep -m1 'Version:' | awk '{print \$2}'" "after"
  fi
  if command -v jira >/dev/null 2>&1; then
    record_ver "jira" "jira version" "before"
    JIRA_ARCH="x86_64"
    [[ "${ARCH}" == "arm64" ]] && JIRA_ARCH="arm64"
    TMP_DIR="$(mktemp -d)"
    RELEASE_JSON="$(curl -fsSL -H 'Accept: application/vnd.github+json' https://api.github.com/repos/ankitpokhrel/jira-cli/releases/latest)"
    ASSET_URL="$(printf '%s' "${RELEASE_JSON}" | python3 -c "import json,sys; r=json.load(sys.stdin); print(next(a['browser_download_url'] for a in r['assets'] if a['name'].endswith('_linux_${JIRA_ARCH}.tar.gz')))")"
    CHECKSUMS_URL="$(printf '%s' "${RELEASE_JSON}" | python3 -c "import json,sys; r=json.load(sys.stdin); print(next(a['browser_download_url'] for a in r['assets'] if a['name'].endswith('checksums.txt')))")"
    ASSET_NAME="$(basename "${ASSET_URL}")"
    curl -fsSL "${ASSET_URL}" -o "${TMP_DIR}/${ASSET_NAME}"
    curl -fsSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/checksums.txt"
    (cd "${TMP_DIR}" && sha256sum -c --ignore-missing checksums.txt)
    tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "${TMP_DIR}"
    JIRA_BIN="$(find "${TMP_DIR}" -maxdepth 3 -type f -name jira | head -n 1)"
    install -o root -g root -m 0755 "${JIRA_BIN}" /usr/local/bin/jira
    rm -rf "${TMP_DIR}"
    record_ver "jira" "jira version" "after"
  fi
fi

if [[ "${#BEFORE_VERSIONS[@]}" -gt 0 ]]; then
  log "Version deltas:"
  for key in "${!BEFORE_VERSIONS[@]}"; do
    b="${BEFORE_VERSIONS[${key}]}"
    a="${AFTER_VERSIONS[${key}]:-${b}}"
    log "  ${key}: ${b} -> ${a}"
  done
fi

log "In-place upgrade complete (scope=${SCOPE})."
