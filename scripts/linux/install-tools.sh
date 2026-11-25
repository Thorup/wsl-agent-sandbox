#!/usr/bin/env bash
set -euo pipefail

POLICY_FILE="/etc/wsl-agent-sandbox/policy.json"

log() {
  echo "[install-tools] $*"
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[install-tools] ERROR: must run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy

run_as_agent_no_proxy() {
  local cmd="$1"
  su -s /bin/bash - "${AGENT_NAME}" -c "unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; ${cmd}"
}

flag() {
  local key="$1"
  local def="${2:-false}"
  python3 -c "import json; d=json.load(open('${POLICY_FILE}')); print('1' if d.get('packages', {}).get('${key}', ${def}) else '0')"
}

fetch_github_latest_json() {
  local repo="$1"
  local api_url="https://api.github.com/repos/${repo}/releases/latest"
  local -a auth_args=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
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
    echo "[install-tools] ERROR: failed to resolve latest release tag for ${repo}" >&2
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

INSTALL_DOCKER_CLI="$(flag installDockerCli True)"
INSTALL_UV="$(flag installUv True)"
INSTALL_NODE="$(flag installNodeLts True)"
INSTALL_PNPM="$(flag installPnpm True)"
INSTALL_GEMINI="$(flag installGeminiCli True)"
INSTALL_CLAUDE="$(flag installClaudeCode True)"
INSTALL_KUBECTL="$(flag installKubectl False)"
INSTALL_AWS="$(flag installAwsCli False)"
INSTALL_GCLOUD="$(flag installGcloudCli False)"
INSTALL_AZURE="$(flag installAzureCli False)"
INSTALL_AZURE_DEVOPS="$(flag installAzureDevopsCli False)"
INSTALL_GH="$(flag installGithubCli False)"
INSTALL_JIRA="$(flag installJiraCli False)"
INSTALL_UPCTL="$(flag installUpctl False)"
INSTALL_DOTNET="$(flag installDotnetSdk False)"
INSTALL_RUST="$(flag installRust False)"
INSTALL_CODEX="$(flag installCodexCli False)"
INSTALL_OPENCODE="$(flag installOpenCode False)"
INSTALL_AIDER="$(flag installAider False)"
INSTALL_HELM="$(flag installHelm False)"
INSTALL_OPENTOFU="$(flag installOpenTofu False)"
INSTALL_TERRAFORM="$(flag installTerraform False)"
INSTALL_PLAYWRIGHT_CHROMIUM="$(flag installPlaywrightChromium False)"
INSTALL_PLAYWRIGHT_FIREFOX="$(flag installPlaywrightFirefox False)"
AGENT_NAME="$(python3 -c "import json; d=json.load(open('${POLICY_FILE}')); print(d['agentUser']['name'])")"

ARCH="$(dpkg --print-architecture)" # amd64 or arm64

# 1. Docker CLI + Compose + Buildx plugins (client-only, NO dockerd)
if [[ "${INSTALL_DOCKER_CLI}" == "1" ]] && ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker CLI + Compose + Buildx plugins (client-only)..."
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
  fi
  # shellcheck source=/dev/null
  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-resolute}")"
  DOCKER_SUITE="${CODENAME}"
  if ! curl -fsI "https://download.docker.com/linux/ubuntu/dists/${DOCKER_SUITE}/Release" >/dev/null 2>&1; then
    log "Docker apt suite '${DOCKER_SUITE}' not published yet; falling back to 'noble' for static Docker CLI packages."
    DOCKER_SUITE="noble"
  fi
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${DOCKER_SUITE} stable
EOF
  apt-get update -y
  apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin docker-buildx-plugin
fi

# 2. uv
if [[ "${INSTALL_UV}" == "1" ]] && ! command -v uv >/dev/null 2>&1; then
  log "Installing uv into /usr/local/bin..."
  UV_INSTALL_DIR="/usr/local/bin" curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
  chmod 0755 /usr/local/bin/uv /usr/local/bin/uvx 2>/dev/null || true
fi

# 3. Node.js LTS (22.x) + pnpm + Gemini CLI + optional Claude Code
if [[ "${INSTALL_NODE}" == "1" ]]; then
  if id -u "${AGENT_NAME}" >/dev/null 2>&1; then
    AGENT_GID_VAL="$(id -g "${AGENT_NAME}")"
    for dir in \
      "/home/${AGENT_NAME}/.npm-global" \
      "/home/${AGENT_NAME}/.npm-global/bin" \
      "/home/${AGENT_NAME}/.local" \
      "/home/${AGENT_NAME}/.local/share" \
      "/home/${AGENT_NAME}/.local/share/pnpm"
    do
      install -d -o "${AGENT_NAME}" -g "${AGENT_GID_VAL}" -m 0755 "${dir}"
    done
  fi
  if ! command -v node >/dev/null 2>&1; then
    log "Installing Node.js LTS..."
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y --no-install-recommends nodejs
  fi
  if [[ "${INSTALL_PNPM}" == "1" ]] && ! command -v pnpm >/dev/null 2>&1; then
    log "Installing pnpm..."
    npm install -g pnpm
  fi
  if [[ "${INSTALL_GEMINI}" == "1" ]] && ! command -v gemini >/dev/null 2>&1; then
    log "Installing @google/gemini-cli..."
    npm install -g @google/gemini-cli
  fi
  if [[ "${INSTALL_CLAUDE}" == "1" ]] && ! command -v claude >/dev/null 2>&1; then
    log "Installing @anthropic-ai/claude-code..."
    npm install -g @anthropic-ai/claude-code
  fi
fi

# 4. Kubernetes CLI (kubectl) with SHA256 verification
if [[ "${INSTALL_KUBECTL}" == "1" ]] && ! command -v kubectl >/dev/null 2>&1; then
  log "Installing kubectl (${ARCH}) with SHA256 verification..."
  K8S_VER="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
  curl -fsSL "https://dl.k8s.io/release/${K8S_VER}/bin/linux/${ARCH}/kubectl" -o "${TMP_DIR}/kubectl"
  curl -fsSL "https://dl.k8s.io/release/${K8S_VER}/bin/linux/${ARCH}/kubectl.sha256" -o "${TMP_DIR}/kubectl.sha256"
  (cd "${TMP_DIR}" && echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check -)
  install -o root -g root -m 0755 "${TMP_DIR}/kubectl" /usr/local/bin/kubectl
  rm -rf "${TMP_DIR}"
  trap - EXIT
  log "Installed kubectl ${K8S_VER}."
fi

# 5. AWS CLI v2 (aws)
if [[ "${INSTALL_AWS}" == "1" ]] && ! command -v aws >/dev/null 2>&1; then
  AWS_ARCH="x86_64"
  if [[ "${ARCH}" == "arm64" ]]; then
    AWS_ARCH="aarch64"
  fi
  log "Installing AWS CLI v2 (${AWS_ARCH})..."
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}.zip" -o "${TMP_DIR}/awscliv2.zip"
  unzip -q "${TMP_DIR}/awscliv2.zip" -d "${TMP_DIR}"
  "${TMP_DIR}/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
  rm -rf "${TMP_DIR}"
  trap - EXIT
  log "Installed $(aws --version 2>&1)."
fi

# 6. Google Cloud CLI (gcloud + gke-gcloud-auth-plugin)
if [[ "${INSTALL_GCLOUD}" == "1" ]] && ! command -v gcloud >/dev/null 2>&1; then
  log "Installing Google Cloud CLI (google-cloud-cli + gke-gcloud-auth-plugin)..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor --yes -o /etc/apt/keyrings/cloud.google.gpg
  chmod a+r /etc/apt/keyrings/cloud.google.gpg
  cat >/etc/apt/sources.list.d/google-cloud-sdk.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main
EOF
  apt-get update -y
  apt-get install -y --no-install-recommends google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin
  log "Installed $(gcloud version --format='value(Google Cloud SDK)' 2>/dev/null || echo 'google-cloud-cli')."
fi

# 7. .NET SDK (LTS) + optional side-by-side channels installed globally to /usr/local/share/dotnet (+ user-space ~/.dotnet/tools on PATH)
install_dotnet_toolchains() {
  local policy_file="$1"
  local install_dir="${2:-/usr/local/share/dotnet}"
  local bin_link="${3:-/usr/local/bin/dotnet}"
  local installer_url="${4:-https://dot.net/v1/dotnet-install.sh}"
  local dotnet_bin="${install_dir}/dotnet"
  local installer_bin=""
  DOTNET_TMP_DIR=""
  trap 'rm -rf "${DOTNET_TMP_DIR:-}"' EXIT

  if [[ ! -x "${dotnet_bin}" ]]; then
    log "Installing .NET SDK (LTS) to ${install_dir}..."
    DOTNET_TMP_DIR="$(mktemp -d)"
    installer_bin="${DOTNET_TMP_DIR}/dotnet-install.sh"
    curl -fsSL "${installer_url}" -o "${installer_bin}"
    chmod +x "${installer_bin}"
    mkdir -p "${install_dir}"
    "${installer_bin}" --channel LTS --install-dir "${install_dir}" --no-path
    ln -sf "${dotnet_bin}" "${bin_link}"
    log "Installed .NET SDK $("${bin_link}" --version 2>&1)."
  fi

  # 7b. Optional side-by-side .NET SDK channels (e.g., ["8.0"])
  local -a dotnet_channels=()
  mapfile -t dotnet_channels < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
channels = d.get("packages", {}).get("dotnetChannels")
if channels is None:
    sys.exit(0)
if not isinstance(channels, list):
    print(f"[install-tools] WARN: packages.dotnetChannels must be an array; ignoring {type(channels).__name__}.", file=sys.stderr)
    sys.exit(0)
for ch in channels:
    if ch is not None:
        print(str(ch))
' "${policy_file}")

  if [[ "${#dotnet_channels[@]}" -gt 0 ]]; then
    local installed_sdks=""
    if [[ -x "${dotnet_bin}" ]]; then
      installed_sdks="$("${dotnet_bin}" --list-sdks 2>/dev/null || true)"
    fi

    local ch escaped_ch
    for ch in "${dotnet_channels[@]}"; do
      if [[ ! "${ch}" =~ ^[0-9]+\.[0-9]+$ ]]; then
        log "WARN: skipping invalid packages.dotnetChannels entry '${ch}' (expected '<major>.<minor>', e.g. '8.0')."
        continue
      fi
      escaped_ch="${ch//./\\.}"
      if printf '%s\n' "${installed_sdks}" | grep -qE "^${escaped_ch}\."; then
        continue
      fi
      log "Installing additional .NET SDK channel ${ch} to ${install_dir}..."
      if [[ -z "${installer_bin}" ]]; then
        DOTNET_TMP_DIR="$(mktemp -d)"
        installer_bin="${DOTNET_TMP_DIR}/dotnet-install.sh"
        curl -fsSL "${installer_url}" -o "${installer_bin}"
        chmod +x "${installer_bin}"
      fi
      mkdir -p "${install_dir}"
      "${installer_bin}" --channel "${ch}" --install-dir "${install_dir}" --no-path
      ln -sf "${dotnet_bin}" "${bin_link}"
      installed_sdks="$("${dotnet_bin}" --list-sdks 2>/dev/null || true)"
      log "Installed .NET SDK channel ${ch}."
    done
  fi

  rm -rf "${DOTNET_TMP_DIR:-}"
  trap - EXIT
}

if [[ "${INSTALL_DOTNET}" == "1" ]]; then
  install_dotnet_toolchains "${POLICY_FILE}"
fi

# 8. Rust toolchain (rustup, rustc, cargo, clippy, rustfmt) owned by agent user in $HOME
if [[ "${INSTALL_RUST}" == "1" ]] && [[ ! -x "/home/${AGENT_NAME}/.cargo/bin/rustc" ]]; then
  log "Installing Rust (rustup + stable + clippy + rustfmt) for user '${AGENT_NAME}'..."
  run_as_agent_no_proxy 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile default -c clippy -c rustfmt'
  # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
  log "Installed $(su -s /bin/bash - "${AGENT_NAME}" -c '"$HOME/.cargo/bin/rustc" --version && "$HOME/.cargo/bin/cargo" --version' | tr '\n' ' ')."
fi

# 9. UpCloud CLI (upctl) from official GitHub releases with SHA256 verification
if [[ "${INSTALL_UPCTL}" == "1" ]] && ! command -v upctl >/dev/null 2>&1; then
  UPCTL_ARCH="x86_64"
  if [[ "${ARCH}" == "arm64" ]]; then
    UPCTL_ARCH="arm64"
  fi
  log "Installing UpCloud CLI (upctl, ${UPCTL_ARCH}) with SHA256 verification..."
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
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
  trap - EXIT
  log "Installed $(/usr/local/bin/upctl version 2>&1 | head -n 1)."
fi

# 10. GitHub CLI (gh) from official GitHub APT repository
if [[ "${INSTALL_GH}" == "1" ]] && ! command -v gh >/dev/null 2>&1; then
  log "Installing GitHub CLI (gh)..."
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/githubcli-archive-keyring.gpg ]]; then
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
  fi
  cat >/etc/apt/sources.list.d/github-cli.list <<EOF
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main
EOF
  apt-get update -y
  apt-get install -y --no-install-recommends gh
  log "Installed $(gh --version 2>&1 | head -n 1)."
fi

# 11. Microsoft Azure CLI (az) from official Microsoft APT repository
if [[ "${INSTALL_AZURE}" == "1" || "${INSTALL_AZURE_DEVOPS}" == "1" ]] && ! command -v az >/dev/null 2>&1; then
  log "Installing Microsoft Azure CLI (az)..."
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/microsoft.gpg ]]; then
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor --yes -o /etc/apt/keyrings/microsoft.gpg
    chmod a+r /etc/apt/keyrings/microsoft.gpg
  fi
  # shellcheck source=/dev/null
  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-resolute}")"
  AZ_SUITE="${CODENAME}"
  if ! curl -fsI "https://packages.microsoft.com/repos/azure-cli/dists/${AZ_SUITE}/Release" >/dev/null 2>&1; then
    log "Azure CLI apt suite '${AZ_SUITE}' not published yet; falling back to 'noble'."
    AZ_SUITE="noble"
  fi
  cat >/etc/apt/sources.list.d/azure-cli.list <<EOF
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ ${AZ_SUITE} main
EOF
  apt-get update -y
  apt-get install -y --no-install-recommends azure-cli
  log "Installed $(az version --output json 2>/dev/null | jq -r '"azure-cli " + (."azure-cli" // "")' || echo 'azure-cli')."
fi

# 12. Azure DevOps CLI (azure-devops extension for az) installed for agent user
if [[ "${INSTALL_AZURE_DEVOPS}" == "1" ]] && command -v az >/dev/null 2>&1; then
  if ! su -s /bin/bash - "${AGENT_NAME}" -c 'az extension show --name azure-devops >/dev/null 2>&1'; then
    log "Installing Azure DevOps CLI extension (azure-devops) for user '${AGENT_NAME}'..."
    run_as_agent_no_proxy 'az extension add --name azure-devops --yes'
    log "Installed Azure DevOps CLI extension ($(su -s /bin/bash - "${AGENT_NAME}" -c 'az extension show --name azure-devops --query version -o tsv' 2>/dev/null || echo 'azure-devops'))."
  fi
fi

# 13. Jira CLI (jira, ankitpokhrel/jira-cli) from official GitHub releases with SHA256 verification
if [[ "${INSTALL_JIRA}" == "1" ]] && ! command -v jira >/dev/null 2>&1; then
  JIRA_ARCH="x86_64"
  if [[ "${ARCH}" == "arm64" ]]; then
    JIRA_ARCH="arm64"
  fi
  log "Installing Jira CLI (jira, ${JIRA_ARCH}) with SHA256 verification..."
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
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
  trap - EXIT
  log "Installed $(/usr/local/bin/jira version 2>&1 | head -n 1)."
fi

# 14. Additional AI Coding Agents (Codex CLI, OpenCode, Aider)
if [[ "${INSTALL_CODEX}" == "1" ]]; then
  if [[ "${INSTALL_NODE}" != "1" ]] || ! command -v npm >/dev/null 2>&1; then
    log "WARNING: installCodexCli is enabled but Node.js/npm is unavailable (installNodeLts=${INSTALL_NODE}); skipping Codex CLI install."
  elif ! command -v codex >/dev/null 2>&1; then
    log "Installing @openai/codex..."
    npm install -g @openai/codex
  fi
fi

if [[ "${INSTALL_OPENCODE}" == "1" ]]; then
  if [[ "${INSTALL_NODE}" != "1" ]] || ! command -v npm >/dev/null 2>&1; then
    log "WARNING: installOpenCode is enabled but Node.js/npm is unavailable (installNodeLts=${INSTALL_NODE}); skipping OpenCode install."
  elif ! command -v opencode >/dev/null 2>&1; then
    log "Installing opencode-ai..."
    npm install -g opencode-ai
  fi
fi

if [[ "${INSTALL_AIDER}" == "1" ]]; then
  if [[ "${INSTALL_UV}" != "1" ]] || ! command -v uv >/dev/null 2>&1; then
    log "WARNING: installAider is enabled but uv is unavailable (installUv=${INSTALL_UV}); skipping Aider install."
  elif [[ ! -x "/home/${AGENT_NAME}/.local/bin/aider" ]]; then
    log "Installing aider-chat via uv (Python 3.12) for '${AGENT_NAME}'..."
    # aider-chat requires Python <3.13; use uv-managed Python 3.12 on Ubuntu 26.04.
    run_as_agent_no_proxy 'uv tool install --python 3.12 aider-chat'
  fi
fi

# 15. Helm (official release tarball with SHA256 verification)
if [[ "${INSTALL_HELM}" == "1" ]] && ! command -v helm >/dev/null 2>&1; then
  log "Installing Helm (${ARCH}) with SHA256 verification..."
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
  HELM_VER="$(resolve_helm_latest_version)"
  HELM_TAR="helm-${HELM_VER}-linux-${ARCH}.tar.gz"
  curl -fsSL "https://get.helm.sh/${HELM_TAR}" -o "${TMP_DIR}/${HELM_TAR}"
  curl -fsSL "https://get.helm.sh/${HELM_TAR}.sha256sum" -o "${TMP_DIR}/${HELM_TAR}.sha256sum"
  (cd "${TMP_DIR}" && sha256sum --check "${HELM_TAR}.sha256sum")
  tar -xzf "${TMP_DIR}/${HELM_TAR}" -C "${TMP_DIR}"
  install -o root -g root -m 0755 "${TMP_DIR}/linux-${ARCH}/helm" /usr/local/bin/helm
  rm -rf "${TMP_DIR}"
  trap - EXIT
  log "Installed $(/usr/local/bin/helm version --short 2>&1)."
fi

# 16. OpenTofu (official signed APT repository)
if [[ "${INSTALL_OPENTOFU}" == "1" ]] && ! command -v tofu >/dev/null 2>&1; then
  log "Installing OpenTofu via official signed APT repository..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://get.opentofu.org/opentofu.gpg -o /etc/apt/keyrings/opentofu.gpg
  curl -fsSL https://packages.opentofu.org/opentofu/tofu/gpgkey | gpg --dearmor --yes -o /etc/apt/keyrings/opentofu-repo.gpg
  chmod a+r /etc/apt/keyrings/opentofu.gpg /etc/apt/keyrings/opentofu-repo.gpg
  cat >/etc/apt/sources.list.d/opentofu.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/opentofu.gpg,/etc/apt/keyrings/opentofu-repo.gpg] https://packages.opentofu.org/opentofu/tofu/any/ any main
EOF
  apt-get update -y
  apt-get install -y --no-install-recommends tofu
  log "Installed $(tofu version 2>&1 | head -n 1)."
fi

resolve_terraform_suite() {
  local codename="${1:-}"
  if [[ -z "${codename}" ]]; then
    # shellcheck source=/dev/null
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-resolute}")"
  fi
  local suite="${codename}"
  if ! curl -fsI "https://apt.releases.hashicorp.com/dists/${suite}/Release" >/dev/null 2>&1; then
    log "HashiCorp apt suite '${suite}' not published yet; falling back to 'noble'."
    suite="noble"
  fi
  printf '%s' "${suite}"
}

# 16b. Terraform (official HashiCorp signed APT repository)
if [[ "${INSTALL_TERRAFORM}" == "1" ]] && ! command -v terraform >/dev/null 2>&1; then
  log "Installing Terraform via official HashiCorp signed APT repository..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/hashicorp-archive-keyring.gpg
  chmod a+r /etc/apt/keyrings/hashicorp-archive-keyring.gpg
  # shellcheck source=/dev/null
  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-resolute}")"
  TF_SUITE="$(resolve_terraform_suite "${CODENAME}")"
  cat >/etc/apt/sources.list.d/hashicorp.list <<EOF
deb [arch=${ARCH} signed-by=/etc/apt/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com ${TF_SUITE} main
EOF
  apt-get update -y
  apt-get install -y --no-install-recommends terraform
  log "Installed $(terraform version 2>&1 | head -n 1)."
fi

# 17. Headless Playwright browsers (Chromium / Firefox) + system dependencies
if [[ "${INSTALL_PLAYWRIGHT_CHROMIUM}" == "1" || "${INSTALL_PLAYWRIGHT_FIREFOX}" == "1" ]]; then
  if [[ "${INSTALL_NODE}" != "1" ]] || ! command -v npm >/dev/null 2>&1; then
    log "WARNING: Playwright browser installation is enabled but Node.js/npm is unavailable (installNodeLts=${INSTALL_NODE}); skipping Playwright install."
  else
    if ! command -v playwright >/dev/null 2>&1; then
      log "Installing global playwright CLI..."
      npm install -g playwright
    fi
    PW_CACHE="/home/${AGENT_NAME}/.cache/ms-playwright"
    if [[ "${INSTALL_PLAYWRIGHT_CHROMIUM}" == "1" ]] && ! compgen -G "${PW_CACHE}/chromium-*" >/dev/null; then
      log "Installing Playwright Chromium + system dependencies..."
      playwright install-deps chromium
      run_as_agent_no_proxy 'playwright install chromium'
    fi
    if [[ "${INSTALL_PLAYWRIGHT_FIREFOX}" == "1" ]] && ! compgen -G "${PW_CACHE}/firefox-*" >/dev/null; then
      log "Installing Playwright Firefox + system dependencies..."
      playwright install-deps firefox
      run_as_agent_no_proxy 'playwright install firefox'
    fi
  fi
fi
