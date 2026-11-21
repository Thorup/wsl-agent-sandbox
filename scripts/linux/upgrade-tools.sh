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

AGENT_NAME="$(python3 -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d["agentUser"]["name"])' "${POLICY_FILE}")"
export DEBIAN_FRONTEND=noninteractive

if has_scope "apt"; then
  log "Updating apt package index and upgrading installed packages..."
  apt-get update -y
  apt-get upgrade -y --no-install-recommends
fi

if has_scope "agents"; then
  if command -v npm >/dev/null 2>&1; then
    for pkg in pnpm @google/gemini-cli @anthropic-ai/claude-code; do
      if npm list -g --depth=0 "${pkg}" >/dev/null 2>&1; then
        log "Updating global npm package ${pkg}..."
        npm install -g "${pkg}@latest"
      fi
    done
  fi
fi

if has_scope "toolchains"; then
  if command -v uv >/dev/null 2>&1; then
    log "Updating uv..."
    uv self update 2>/dev/null || log "Note: uv self update skipped/unavailable."
  fi
  if [[ -x "/home/${AGENT_NAME}/.cargo/bin/rustup" ]]; then
    log "Updating Rust toolchain for '${AGENT_NAME}'..."
    # shellcheck disable=SC2016 # $HOME expands inside the target user's shell
    su -s /bin/bash - "${AGENT_NAME}" -c '"$HOME/.cargo/bin/rustup" update'
  fi
  if command -v az >/dev/null 2>&1; then
    if su -s /bin/bash - "${AGENT_NAME}" -c 'az extension show --name azure-devops >/dev/null 2>&1'; then
      log "Updating azure-devops extension for '${AGENT_NAME}'..."
      su -s /bin/bash - "${AGENT_NAME}" -c 'az extension update --name azure-devops' || true
    fi
  fi
fi

log "In-place upgrade complete (scope=${SCOPE})."
