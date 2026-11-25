#!/usr/bin/env bash
set -u

PASS=0
FAIL=0
WARN=0

HOST_TEST_PORT="${1:-}"
HOST_TEST_IP="${2:-}"

pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $*"; WARN=$((WARN + 1)); }

echo "=== wsl-agent-sandbox Security & Capability Audit ==="
echo "Running as: $(id)"
echo ""

# ------------------------------------------------------------------
# 1. Privilege & Identity Containment
# ------------------------------------------------------------------
echo "[1/6] Privilege & Identity Containment"

if [[ "$(id -u)" -ne 0 ]]; then
  pass "Running as non-root user (UID=$(id -u))"
else
  fail "Running as root! Audit must run as non-root agent user."
fi

if sudo -n true >/dev/null 2>&1; then
  fail "Passwordless sudo succeeded!"
else
  pass "sudo is unavailable/denied for agent user"
fi

if [[ -r /etc/wsl-agent-sandbox/policy.json ]] || [[ -r /etc/wsl-agent-sandbox/docker-policy.json ]] || [[ -r /etc/wsl-agent-sandbox/credential-proxy.json ]] || [[ -r /etc/wsl-agent-sandbox/ssh-agent-keys.json ]] || [[ -w /etc/wsl.conf ]]; then
  fail "Agent can read root-only config/credential-proxy/ssh-agent state or write /etc/wsl.conf!"
else
  pass "Root-owned config files (/etc/wsl.conf, policy.json, docker-policy.json, credential-proxy.json, ssh-agent-keys.json) protected"
fi

if command -v curl >/dev/null 2>&1 && nc -z -w 1 127.0.0.1 3129 >/dev/null 2>&1; then
  UNAUTH_PROXY_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:3129/claude/v1/messages || echo "000")"
  if [[ "${UNAUTH_PROXY_CODE}" == "401" ]] || [[ "${UNAUTH_PROXY_CODE}" == "403" ]]; then
    pass "L7 credential-proxy rejects unauthenticated caller (HTTP ${UNAUTH_PROXY_CODE})"
  else
    fail "L7 credential-proxy accepted or mis-handled unauthenticated caller (HTTP ${UNAUTH_PROXY_CODE})"
  fi
fi

if ls /run/box-root >/dev/null 2>&1; then
  fail "Agent can access /run/box-root!"
else
  pass "/run/box-root is inaccessible (permission denied)"
fi

# ------------------------------------------------------------------
# 2. Windows Filesystem & Mount Containment
# ------------------------------------------------------------------
echo ""
echo "[2/6] Windows Filesystem & Mount Containment"

if [[ -d /mnt/c ]] && ls /mnt/c/Windows >/dev/null 2>&1; then
  fail "/mnt/c/Windows is accessible!"
else
  pass "/mnt/c is not mounted / inaccessible"
fi

TMP_MNT="$(mktemp -d)"
if mount -t drvfs C: "${TMP_MNT}" >/dev/null 2>&1; then
  fail "Manual mount -t drvfs C: succeeded!"
  umount -l "${TMP_MNT}" 2>/dev/null || true
else
  pass "Manual 'mount -t drvfs C:' blocked"
fi

if unshare -Urm mount -t drvfs C: "${TMP_MNT}" >/dev/null 2>&1; then
  fail "User-namespace 'unshare -Urm mount -t drvfs C:' succeeded!"
else
  pass "User-namespace 'unshare -Urm mount -t drvfs C:' blocked"
fi
rmdir "${TMP_MNT}" 2>/dev/null || true

# ------------------------------------------------------------------
# 3. Windows Interop & WSLg / Shared Namespace Containment
# ------------------------------------------------------------------
echo ""
echo "[3/6] Windows Interop, WSLg & /mnt/wsl Containment"

if command -v powershell.exe >/dev/null 2>&1 || command -v cmd.exe >/dev/null 2>&1; then
  fail "Windows .exe binaries found in PATH!"
else
  pass "No Windows .exe binaries in PATH"
fi

interop_disabled_in_wslconf() {
  local conf_file="${1:-/etc/wsl.conf}"
  [[ -r "${conf_file}" ]] || return 1
  # True when wsl.conf has 'enabled = false' inside the [interop] section.
  awk '
    /^[[:space:]]*\[/ {
      in_sec = ($0 ~ /^[[:space:]]*\[interop\][[:space:]]*([#;].*)?$/)
      next
    }
    in_sec && /^[[:space:]]*enabled[[:space:]]*=/ {
      v = $0
      sub(/^[^=]*=[[:space:]]*/, "", v)
      sub(/[[:space:]#;].*$/, "", v)
      found = (tolower(v) == "false") ? 1 : 0
    }
    END { exit(found ? 0 : 1) }
  ' "${conf_file}" 2>/dev/null
}

check_wslinterop_binfmt() {
  local binfmt_path="$1"
  local wsl_conf="$2"
  if [[ -f "${binfmt_path}" ]]; then
    if interop_disabled_in_wslconf "${wsl_conf}"; then
      # binfmt_misc is shared across all distros in the WSL2 utility VM, so another distro with
      # interop enabled registers this handler VM-wide. With [interop] enabled=false, this distro's
      # /init refuses to launch Windows processes (the vsock handshake never completes).
      warn "WSLInterop binfmt_misc handler is registered VM-wide by another distro; interop is disabled for this distro in /etc/wsl.conf"
    else
      fail "WSLInterop binfmt_misc handler is registered and [interop] is not disabled in /etc/wsl.conf!"
    fi
  else
    pass "WSLInterop binfmt_misc handler is absent (interop disabled)"
  fi
}

check_wslinterop_binfmt /proc/sys/fs/binfmt_misc/WSLInterop /etc/wsl.conf

if [[ -n "${WSL_INTEROP:-}" ]]; then
  fail "WSL_INTEROP environment variable is set!"
else
  pass "WSL_INTEROP is unset"
fi

if ls /mnt/wsl/docker-desktop >/dev/null 2>&1; then
  fail "/mnt/wsl/docker-desktop is visible to agent!"
else
  pass "/mnt/wsl is hidden / inaccessible to agent"
fi

if ls /mnt/wslg/.X11-unix >/dev/null 2>&1 || [[ -S /tmp/.X11-unix/X0 ]] || [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
  fail "WSLg sockets or DISPLAY/WAYLAND_DISPLAY still exposed!"
else
  pass "WSLg / clipboard / X11 / Wayland completely disabled in this distro"
fi

# ------------------------------------------------------------------
# 4. Network Containment (WSL -> Windows Host & LAN Blocked, Internet OK)
# ------------------------------------------------------------------
echo ""
echo "[4/6] Network Isolation & Internet Access"

GW_IP="$(ip -4 route show default | awk '/via/ {print $3; exit}')"
TARGET_IP="${HOST_TEST_IP:-${GW_IP}}"

if [[ -n "${TARGET_IP}" ]]; then
  TEST_PORT="${HOST_TEST_PORT:-445}"
  if nc -z -w 2 "${TARGET_IP}" "${TEST_PORT}" >/dev/null 2>&1; then
    fail "Agent was able to connect to Windows host ${TARGET_IP}:${TEST_PORT}!"
  else
    pass "Outbound connection from agent to Windows host ${TARGET_IP}:${TEST_PORT} blocked"
  fi
else
  warn "Could not determine default gateway IP to probe Windows host"
fi

VERIFY_POLICY_FILE="/etc/wsl-agent-sandbox/verify-policy.json"
EGRESS_MODE="open"
ALLOWED_DOMAIN_COUNT=0
ALLOWLIST_PROBE_URL=""
if [[ -r "${VERIFY_POLICY_FILE}" ]]; then
  EGRESS_MODE="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("egressMode", "open"))' "${VERIFY_POLICY_FILE}" 2>/dev/null || echo "open")"
  ALLOWED_DOMAIN_COUNT="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("allowedDomains", [])))' "${VERIFY_POLICY_FILE}" 2>/dev/null || echo "0")"
  ALLOWLIST_PROBE_URL="$(python3 -c 'import json,sys
PRESETS = {"llm-apis": "https://api.openai.com", "github": "https://github.com", "npm": "https://registry.npmjs.org", "pypi": "https://pypi.org", "apt": "http://archive.ubuntu.com/ubuntu/dists/resolute/Release"}
d = json.load(open(sys.argv[1]))
for item in d.get("allowedDomains", []):
    s = str(item).strip().lower()
    if s in PRESETS:
        print(PRESETS[s]); sys.exit(0)
    if s and not s.startswith("*"):
        print(f"https://{s}"); sys.exit(0)
' "${VERIFY_POLICY_FILE}" 2>/dev/null || true)"
fi

if [[ "${EGRESS_MODE}" == "allowlist" ]]; then
  if curl --noproxy '*' -fsS --max-time 4 https://example.com >/dev/null 2>&1; then
    fail "Direct non-proxy internet access bypassed egress allowlist firewall!"
  else
    pass "Direct internet egress blocked in allowlist mode"
  fi

  if nc -z -u -w 2 1.1.1.1 53 >/dev/null 2>&1 && dig +short +time=2 +tries=1 @1.1.1.1 example.com >/dev/null 2>&1; then
    fail "Direct external DNS query bypassed allowlist firewall!"
  else
    pass "Direct external DNS blocked in allowlist mode"
  fi

  BLOCK_CODE="$(curl --proxy http://127.0.0.1:3128 -s -o /dev/null -w '%{http_connect}' --max-time 6 https://blocked-verify.example.invalid 2>/dev/null || true)"
  if [[ "${BLOCK_CODE}" == "403" ]]; then
    pass "Egress allowlist proxy blocked non-allowlisted domain (HTTP 403)"
  else
    fail "Expected egress proxy HTTP 403 for blocked domain, got status ${BLOCK_CODE}"
  fi

  if [[ "${ALLOWED_DOMAIN_COUNT}" -gt 0 ]] && [[ -n "${ALLOWLIST_PROBE_URL}" ]]; then
    if curl --proxy http://127.0.0.1:3128 -fsSI --max-time 8 "${ALLOWLIST_PROBE_URL}" >/dev/null 2>&1 || curl --proxy http://127.0.0.1:3128 -sS -o /dev/null -w '%{http_code}' --max-time 8 "${ALLOWLIST_PROBE_URL}" | grep -qE '^[234][0-9]{2}$'; then
      pass "Allowlisted egress works via proxy (${ALLOWLIST_PROBE_URL})"
    else
      fail "Allowlisted egress failed via proxy (${ALLOWLIST_PROBE_URL})"
    fi
  else
    pass "Strict allowlist active (0 allowedDomains configured)"
  fi
else
  if curl -fsS --max-time 8 https://example.com >/dev/null 2>&1; then
    pass "Outbound HTTPS internet access works"
  else
    fail "Outbound HTTPS internet access failed"
  fi
fi

# ------------------------------------------------------------------
# 5. Docker Desktop Policy Proxy Containment & Positive Tests
# ------------------------------------------------------------------
echo ""
echo "[5/6] Docker Desktop Policy Proxy (Escapes Blocked + Normal Use Allowed)"

VERIFY_POLICY_FILE="/etc/wsl-agent-sandbox/verify-policy.json"
DOCKER_ENABLED="true"
if [[ -r "${VERIFY_POLICY_FILE}" ]]; then
  DOCKER_ENABLED="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("true" if d.get("dockerEnabled", True) else "false")' "${VERIFY_POLICY_FILE}" 2>/dev/null || echo "true")"
fi

export DOCKER_HOST="unix:///run/docker-policy/docker.sock"

if [[ "${DOCKER_ENABLED}" == "false" ]]; then
  if [[ -S /run/docker-policy/docker.sock ]] || [[ -S /var/run/docker.sock ]]; then
    fail "Docker socket exists even though docker.enabled is false!"
  else
    pass "Docker proxy socket is absent/disabled per policy (docker.enabled=false)"
  fi
  if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
      fail "Docker daemon is reachable even though docker.enabled is false!"
    else
      pass "Docker CLI cannot reach daemon when docker.enabled=false"
    fi
  fi
elif ! command -v docker >/dev/null 2>&1; then
  warn "Docker CLI is not installed (packages.installDockerCli=false); skipping Docker proxy tests"
elif docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  SRV_VER="$(docker version --format '{{.Server.Version}}')"
  pass "Docker Desktop reachable through policy proxy (Engine ${SRV_VER})"

  # Ensure alpine:latest is cached before testing so pull progress doesn't pollute stdout
  docker pull -q alpine:latest >/dev/null 2>&1 || true

  # Test allowed container execution + bind mount inside $HOME
  WORK_DIR="$(mktemp -d "${HOME}/.box-verify-XXXXXX")"
  echo "hello-from-wsl-agent" > "${WORK_DIR}/input.txt"

  OUT="$(docker run --rm -v "${WORK_DIR}:/data" alpine:latest sh -c 'cat /data/input.txt && echo ok-from-docker > /data/output.txt' 2>&1)"
  if echo "${OUT}" | grep -q "hello-from-wsl-agent" && [[ "$(cat "${WORK_DIR}/output.txt" 2>/dev/null)" == "ok-from-docker" ]]; then
    pass "Allowed bind mount inside /home/agent works seamlessly through proxy rewrite"
  else
    fail "Allowed bind mount inside /home/agent failed: ${OUT}"
  fi

  # Helper: assert docker command is blocked by policy proxy (HTTP 403 / docker-policy-proxy)
  expect_docker_blocked() {
    local desc="$1"
    shift
    local err
    if err="$("$@" 2>&1)"; then
      fail "Docker escape NOT blocked: ${desc}"
    elif echo "${err}" | grep -qi "docker-policy-proxy blocked"; then
      pass "Docker escape blocked: ${desc}"
    else
      fail "Docker command failed for unexpected reason (${desc}): ${err}"
    fi
  }

  expect_docker_blocked "Windows host mount (/run/desktop/mnt/host/c)" \
    docker run --rm -v /run/desktop/mnt/host/c:/host alpine:latest ls /host

  expect_docker_blocked "/mnt/c bind mount" \
    docker run --rm -v /mnt/c:/host alpine:latest ls /host

  expect_docker_blocked "/etc bind mount" \
    docker run --rm -v /etc:/host alpine:latest ls /host

  expect_docker_blocked "/var/run/docker.sock bind mount" \
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:latest ls

  expect_docker_blocked "--privileged container" \
    docker run --rm --privileged alpine:latest id

  expect_docker_blocked "--cap-add=SYS_ADMIN" \
    docker run --rm --cap-add=SYS_ADMIN alpine:latest id

  expect_docker_blocked "--pid=host" \
    docker run --rm --pid=host alpine:latest ps

  expect_docker_blocked "--network=host" \
    docker run --rm --network=host alpine:latest ip a

  expect_docker_blocked "--security-opt seccomp=unconfined" \
    docker run --rm --security-opt seccomp=unconfined alpine:latest id

  expect_docker_blocked "host-gateway ExtraHosts" \
    docker run --rm --add-host=win:host-gateway alpine:latest cat /etc/hosts

  ln -s /etc "${WORK_DIR}/sym_etc"
  expect_docker_blocked "local symlink escape (/home/agent/... -> /etc)" \
    docker run --rm -v "${WORK_DIR}/sym_etc:/host" alpine:latest ls /host

  ln -s /run/desktop/mnt/host/c "${WORK_DIR}/sym_win"
  expect_docker_blocked "cross-VM dangling symlink escape (-> /run/desktop/mnt/host/c)" \
    docker run --rm -v "${WORK_DIR}/sym_win:/host" alpine:latest ls /host

  expect_docker_blocked "malicious volume create (type=none,o=bind,device=/run/desktop/mnt/host/c)" \
    docker volume create --driver local --opt type=none --opt o=bind --opt device=/run/desktop/mnt/host/c evil_box_vol

  VERIFY_POLICY_FILE="/etc/wsl-agent-sandbox/verify-policy.json"
  ENFORCE_LOOPBACK_PB="true"
  FORCE_INTERNAL_NET="false"
  if [[ -r "${VERIFY_POLICY_FILE}" ]]; then
    ENFORCE_LOOPBACK_PB="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("true" if (not d.get("allowPortBindings", True) or d.get("forceLoopbackPortBindings", True)) else "false")' "${VERIFY_POLICY_FILE}" 2>/dev/null || echo "true")"
    FORCE_INTERNAL_NET="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("true" if d.get("forceInternalNetwork", False) else "false")' "${VERIFY_POLICY_FILE}" 2>/dev/null || echo "false")"
  fi

  if [[ "${ENFORCE_LOOPBACK_PB}" == "true" ]]; then
    expect_docker_blocked "non-loopback PortBindings (0.0.0.0:18999:80)" \
      docker run --rm -p 0.0.0.0:18999:80 alpine:latest true
  else
    pass "Non-loopback PortBindings allowed by policy (allowPortBindings=true, forceLoopbackPortBindings=false)"
  fi

  if [[ "${FORCE_INTERNAL_NET}" == "true" ]]; then
    expect_docker_blocked "--network=bridge when forceInternalNetwork=true" \
      docker run --rm --network=bridge alpine:latest true

    NET_AUDIT_OUT="$(docker run --rm alpine:latest sh -c '
      if nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1; then
        echo "LEAK_INTERNET"
        exit 0
      fi
      if nc -z -w 2 host.docker.internal 80 >/dev/null 2>&1; then
        echo "LEAK_HOST"
        exit 0
      fi
      echo "ISOLATED_OK"
    ' 2>/dev/null || true)"
    if [[ "${NET_AUDIT_OUT}" == "ISOLATED_OK" ]]; then
      pass "Default container isolated from host.docker.internal and external internet (forceInternalNetwork=true)"
    elif [[ "${NET_AUDIT_OUT}" == "LEAK_"* ]]; then
      fail "Default container leaked outbound connectivity (${NET_AUDIT_OUT}) despite forceInternalNetwork=true"
    else
      warn "Could not execute active container network audit (alpine:latest unavailable or container failed to start)"
    fi
  fi

  rm -rf "${WORK_DIR}"
else
  warn "Docker Desktop not reachable via proxy (is Docker Desktop running on Windows?)"
fi

# ------------------------------------------------------------------
# 6. Pre-installed Developer, Cloud & AI Agent Toolchain
# ------------------------------------------------------------------
echo ""
echo "[6/6] Pre-installed Developer, Cloud & AI Agent Toolchain"

if [[ -r "${VERIFY_POLICY_FILE}" ]] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${VERIFY_POLICY_FILE}" >/dev/null 2>&1; then
  mapfile -t EXPECTED_TOOLS < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("\n".join(d.get("expectedTools", [])))' "${VERIFY_POLICY_FILE}")
  CHECK_DOCKER_COMPOSE="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("true" if d.get("checkDockerCompose", False) else "false")' "${VERIFY_POLICY_FILE}")"
  CHECK_AZ_DEVOPS="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("true" if d.get("checkAzureDevopsExt", False) else "false")' "${VERIFY_POLICY_FILE}")"
else
  if [[ -r "${VERIFY_POLICY_FILE}" ]]; then
    warn "Could not parse ${VERIFY_POLICY_FILE}; falling back to default toolchain checks"
  fi
  EXPECTED_TOOLS=(git python3 uv node pnpm gemini claude docker)
  CHECK_DOCKER_COMPOSE="true"
  CHECK_AZ_DEVOPS="false"
fi

for tool in "${EXPECTED_TOOLS[@]}"; do
  if [[ -z "${tool}" ]]; then
    continue
  fi
  if command -v "${tool}" >/dev/null 2>&1; then
    pass "Tool available: ${tool} ($(command -v "${tool}"))"
  else
    fail "Expected tool missing: ${tool}"
  fi
done

if [[ "${CHECK_AZ_DEVOPS}" == "true" ]]; then
  if az extension show --name azure-devops >/dev/null 2>&1; then
    AZ_DEVOPS_VER="$(az extension show --name azure-devops --query version -o tsv 2>/dev/null || echo ok)"
    pass "Azure DevOps CLI extension available (azure-devops ${AZ_DEVOPS_VER})"
  else
    fail "Azure DevOps CLI extension missing (azure-devops)"
  fi
fi

if [[ "${CHECK_DOCKER_COMPOSE}" == "true" ]]; then
  if docker compose version >/dev/null 2>&1; then
    pass "Docker Compose plugin available ($(docker compose version --short 2>/dev/null || echo ok))"
  else
    fail "Docker Compose plugin missing"
  fi
fi

echo ""
echo "=== Summary: PASS=${PASS} FAIL=${FAIL} WARN=${WARN} ==="
if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
exit 0
