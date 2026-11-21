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

flag() {
  local key="$1"
  local def="${2:-false}"
  python3 -c "import json; d=json.load(open('${POLICY_FILE}')); print('1' if d.get('packages', {}).get('${key}', ${def}) else '0')"
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

# 7. .NET SDK (LTS) installed globally to /usr/local/share/dotnet (+ user-space ~/.dotnet/tools on PATH)
if [[ "${INSTALL_DOTNET}" == "1" ]] && ! command -v dotnet >/dev/null 2>&1; then
  log "Installing .NET SDK (LTS) to /usr/local/share/dotnet..."
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "${TMP_DIR}"' EXIT
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o "${TMP_DIR}/dotnet-install.sh"
  chmod +x "${TMP_DIR}/dotnet-install.sh"
  mkdir -p /usr/local/share/dotnet
  "${TMP_DIR}/dotnet-install.sh" --channel LTS --install-dir /usr/local/share/dotnet --no-path
  ln -sf /usr/local/share/dotnet/dotnet /usr/local/bin/dotnet
  rm -rf "${TMP_DIR}"
  trap - EXIT
  log "Installed .NET SDK $(/usr/local/bin/dotnet --version 2>&1)."
fi

# 8. Rust toolchain (rustup, rustc, cargo, clippy, rustfmt) owned by agent user in $HOME
if [[ "${INSTALL_RUST}" == "1" ]] && [[ ! -x "/home/${AGENT_NAME}/.cargo/bin/rustc" ]]; then
  log "Installing Rust (rustup + stable + clippy + rustfmt) for user '${AGENT_NAME}'..."
  su -s /bin/bash - "${AGENT_NAME}" -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile default -c clippy -c rustfmt'
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
    su -s /bin/bash - "${AGENT_NAME}" -c 'az extension add --name azure-devops --yes'
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
  trap - EXIT
  log "Installed $(/usr/local/bin/jira version 2>&1 | head -n 1)."
fi
