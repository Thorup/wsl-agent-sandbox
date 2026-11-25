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

fetch_github_latest_json() {
  local repo="$1"
  local api_url="https://api.github.com/repos/${repo}/releases/latest"
  local -a auth_args=()
  if [[ -n "${GITHUB_TOKEN:-}" && "${GITHUB_TOKEN}" != sandbox-proxy-* ]]; then
    auth_args=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi

  local api_json=""
  if api_json="$(curl -fsSL --retry 3 --retry-delay 2 -H 'Accept: application/vnd.github+json' "${auth_args[@]}" "${api_url}" 2>/dev/null)"; then
    printf '%s' "${api_json}"
    return 0
  fi

  # Fallback: resolve latest tag via github.com HTML redirect + expanded_assets (avoids 60/hr API rate limit)
  local effective_url tag expanded_html
  effective_url="$(curl -fsSL --retry 3 --retry-delay 2 -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")"
  tag="${effective_url##*/}"
  tag="${tag%%\?*}"
  if [[ -z "${tag}" || "${tag}" == "latest" ]]; then
    echo "[upgrade] ERROR: failed to resolve latest release tag for ${repo}" >&2
    return 1
  fi
  expanded_html="$(curl -fsSL --retry 3 --retry-delay 2 "https://github.com/${repo}/releases/expanded_assets/${tag}")"
  python3 -c '
import json, re, sys
repo, tag = sys.argv[1], sys.argv[2]
html = sys.stdin.read()
prefix = f"/{repo}/releases/download/{tag}/"
assets = []
seen = set()
for match in re.finditer(r"href=[\"\x27](" + re.escape(prefix) + r"[^\"\x27?#]+)", html):
    rel = match.group(1)
    if rel in seen:
        continue
    seen.add(rel)
    assets.append({
        "name": rel.rsplit("/", 1)[-1],
        "browser_download_url": "https://github.com" + rel,
    })
if not assets:
    sys.exit(1)
print(json.dumps({"tag_name": tag, "assets": assets}))
' "${repo}" "${tag}" <<< "${expanded_html}"
}

resolve_helm_latest_version() {
  local ver=""
  if ver="$(curl -fsSL --retry 3 --retry-delay 2 https://get.helm.sh/helm-latest-version 2>/dev/null | tr -d '[:space:]')" && [[ "${ver}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    printf '%s' "${ver}"
    return 0
  fi
  fetch_github_latest_json "helm/helm" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])"
}

upgrade_aws_cli() {
  local install_dir="${1:-/usr/local/aws-cli}"
  local bin_dir="${2:-/usr/local/bin}"
  local arch="${3:-${ARCH:-$(dpkg --print-architecture)}}"
  if ! command -v aws >/dev/null 2>&1 || [[ ! -d "${install_dir}" ]]; then
    return 0
  fi

  record_ver "aws" "aws --version" "before"
  local aws_arch="x86_64"
  if [[ "${arch}" == "arm64" ]]; then
    aws_arch="aarch64"
  fi
  log "Updating AWS CLI v2 (${aws_arch})..."
  (
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${aws_arch}.zip" -o "${tmp_dir}/awscliv2.zip"
    unzip -q "${tmp_dir}/awscliv2.zip" -d "${tmp_dir}"
    "${tmp_dir}/aws/install" --bin-dir "${bin_dir}" --install-dir "${install_dir}" --update
  )
  record_ver "aws" "aws --version" "after"
}

upgrade_dotnet_toolchains() {
  local policy_file="${1:-${POLICY_FILE}}"
  local install_dir="${2:-/usr/local/share/dotnet}"
  local installer_url="${3:-https://dot.net/v1/dotnet-install.sh}"
  local dotnet_bin="${install_dir}/dotnet"
  if [[ ! -x "${dotnet_bin}" ]]; then
    return 0
  fi

  record_ver "dotnet" "'${dotnet_bin}' --list-sdks | tr '\n' ';'" "before"
  log "Updating .NET SDK (LTS) in ${install_dir}..."
  (
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "${tmp_dir}"' EXIT
    installer_bin="${tmp_dir}/dotnet-install.sh"
    curl -fsSL "${installer_url}" -o "${installer_bin}"
    chmod +x "${installer_bin}"
    "${installer_bin}" --channel LTS --install-dir "${install_dir}" --no-path

    mapfile -t dotnet_channels < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
channels = d.get("packages", {}).get("dotnetChannels")
if channels is None:
    sys.exit(0)
if not isinstance(channels, list):
    print(f"[upgrade] WARN: packages.dotnetChannels must be an array; ignoring {type(channels).__name__}.", file=sys.stderr)
    sys.exit(0)
for ch in channels:
    if ch is not None:
        print(str(ch))
' "${policy_file}")

    for ch in "${dotnet_channels[@]}"; do
      if [[ ! "${ch}" =~ ^[0-9]+\.[0-9]+$ ]]; then
        log "WARN: skipping invalid packages.dotnetChannels entry '${ch}' (expected '<major>.<minor>', e.g. '8.0')."
        continue
      fi
      log "Updating .NET SDK channel ${ch} in ${install_dir}..."
      "${installer_bin}" --channel "${ch}" --install-dir "${install_dir}" --no-path
    done
  )
  record_ver "dotnet" "'${dotnet_bin}' --list-sdks | tr '\n' ';'" "after"
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
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy

run_as_agent_no_proxy() {
  local cmd="$1"
  su -s /bin/bash - "${AGENT_NAME}" -c "unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; ${cmd}"
}

MAINTENANCE_EGRESS_ACTIVE=0
restore_maintenance_egress() {
  if [[ "${MAINTENANCE_EGRESS_ACTIVE}" -eq 1 ]] && [[ -x /usr/local/sbin/box-hardening.sh ]]; then
    /usr/local/sbin/box-hardening.sh >/dev/null 2>&1 || true
  fi
}
trap restore_maintenance_egress EXIT

if [[ -x /usr/local/sbin/box-hardening.sh ]]; then
  log "Opening maintenance egress for upgrade while keeping host/LAN blocked..."
  MAINTENANCE_EGRESS_ACTIVE=1
  BOX_MAINTENANCE_EGRESS_OPEN=1 /usr/local/sbin/box-hardening.sh
fi

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
    log "Re-applying sandbox hardening after apt upgrade (maintenance egress open)..."
    BOX_MAINTENANCE_EGRESS_OPEN=1 /usr/local/sbin/box-hardening.sh
  fi
  record_ver "apt-upgradable" "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l" "after"
fi

if has_scope "agents"; then
  if command -v npm >/dev/null 2>&1; then
    for pkg in @google/gemini-cli @anthropic-ai/claude-code @openai/codex opencode-ai; do
      if npm list -g --depth=0 "${pkg}" >/dev/null 2>&1; then
        record_ver "npm:${pkg}" "npm list -g --depth=0 '${pkg}' --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('dependencies',{}).get('${pkg}',{}).get('version','unknown'))\"" "before"
        log "Updating global npm package ${pkg}..."
        npm install -g "${pkg}@latest"
        record_ver "npm:${pkg}" "npm list -g --depth=0 '${pkg}' --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('dependencies',{}).get('${pkg}',{}).get('version','unknown'))\"" "after"
      fi
    done
  fi
  if command -v uv >/dev/null 2>&1 && [[ -x "/home/${AGENT_NAME}/.local/bin/aider" ]]; then
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    record_ver "uv:aider-chat" "su -s /bin/bash - '${AGENT_NAME}' -c '\"\$HOME/.local/bin/aider\" --version'" "before"
    log "Updating aider-chat via uv for '${AGENT_NAME}'..."
    run_as_agent_no_proxy 'uv tool upgrade aider-chat'
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    record_ver "uv:aider-chat" "su -s /bin/bash - '${AGENT_NAME}' -c '\"\$HOME/.local/bin/aider\" --version'" "after"
  fi
fi

if has_scope "toolchains"; then
  if command -v npm >/dev/null 2>&1 && npm list -g --depth=0 pnpm >/dev/null 2>&1; then
    record_ver "npm:pnpm" "npm list -g --depth=0 'pnpm' --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('dependencies',{}).get('pnpm',{}).get('version','unknown'))\"" "before"
    log "Updating global npm package pnpm..."
    npm install -g pnpm@latest
    record_ver "npm:pnpm" "npm list -g --depth=0 'pnpm' --json 2>/dev/null | python3 -c \"import json,sys; d=json.load(sys.stdin); print(d.get('dependencies',{}).get('pnpm',{}).get('version','unknown'))\"" "after"
  fi
  upgrade_aws_cli "/usr/local/aws-cli" "/usr/local/bin" "${ARCH}"
  upgrade_dotnet_toolchains "${POLICY_FILE}"
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
    run_as_agent_no_proxy '"$HOME/.cargo/bin/rustup" update'
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    record_ver "rust" "su -s /bin/bash - '${AGENT_NAME}' -c '\"\$HOME/.cargo/bin/rustc\" --version'" "after"
  fi
  if command -v az >/dev/null 2>&1; then
    if su -s /bin/bash - "${AGENT_NAME}" -c 'az extension show --name azure-devops >/dev/null 2>&1'; then
      record_ver "azure-devops" "su -s /bin/bash - '${AGENT_NAME}' -c 'az extension show --name azure-devops --query version -o tsv'" "before"
      log "Updating azure-devops extension for '${AGENT_NAME}'..."
      run_as_agent_no_proxy 'az extension update --name azure-devops' || true
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
    RELEASE_JSON="$(fetch_github_latest_json "UpCloudLtd/upcloud-cli")"
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
    RELEASE_JSON="$(fetch_github_latest_json "ankitpokhrel/jira-cli")"
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
  if command -v helm >/dev/null 2>&1; then
    record_ver "helm" "helm version --short" "before"
    log "Updating Helm (${ARCH}) with SHA256 verification..."
    TMP_DIR="$(mktemp -d)"
    HELM_VER="$(resolve_helm_latest_version)"
    HELM_TAR="helm-${HELM_VER}-linux-${ARCH}.tar.gz"
    curl -fsSL "https://get.helm.sh/${HELM_TAR}" -o "${TMP_DIR}/${HELM_TAR}"
    curl -fsSL "https://get.helm.sh/${HELM_TAR}.sha256sum" -o "${TMP_DIR}/${HELM_TAR}.sha256sum"
    (cd "${TMP_DIR}" && sha256sum --check "${HELM_TAR}.sha256sum")
    tar -xzf "${TMP_DIR}/${HELM_TAR}" -C "${TMP_DIR}"
    install -o root -g root -m 0755 "${TMP_DIR}/linux-${ARCH}/helm" /usr/local/bin/helm
    rm -rf "${TMP_DIR}"
    record_ver "helm" "helm version --short" "after"
  fi
  if command -v npm >/dev/null 2>&1 && npm list -g --depth=0 playwright >/dev/null 2>&1; then
    record_ver "npm:playwright" "playwright --version" "before"
    log "Updating global playwright CLI..."
    npm install -g playwright@latest
    PW_CACHE="/home/${AGENT_NAME}/.cache/ms-playwright"
    if compgen -G "${PW_CACHE}/chromium-*" >/dev/null; then
      log "Updating Playwright Chromium + system dependencies..."
      playwright install-deps chromium
      run_as_agent_no_proxy 'playwright install chromium'
    fi
    if compgen -G "${PW_CACHE}/firefox-*" >/dev/null; then
      log "Updating Playwright Firefox + system dependencies..."
      playwright install-deps firefox
      run_as_agent_no_proxy 'playwright install firefox'
    fi
    record_ver "npm:playwright" "playwright --version" "after"
  fi
fi

if [[ "${MAINTENANCE_EGRESS_ACTIVE}" -eq 1 ]] && [[ -x /usr/local/sbin/box-hardening.sh ]]; then
  log "Restoring strict nftables egress rules..."
  MAINTENANCE_EGRESS_ACTIVE=0
  /usr/local/sbin/box-hardening.sh
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
