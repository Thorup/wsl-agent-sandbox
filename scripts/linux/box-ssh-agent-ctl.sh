#!/usr/bin/env bash
set -euo pipefail

# Root-only helper to manage the upstream ssh-agent lifecycle for mode: "agent-proxy".
# Supports ensure-upstream (used by box-seed-secrets.sh and systemd ExecStartPre)
# and stop-upstream (used when clearing secrets or disabling agent-proxy).

SSH_AGENT_KEYS_FILE="${SSH_AGENT_KEYS_FILE:-/etc/wsl-agent-sandbox/ssh-agent-keys.json}"
SSH_AGENT_ALLOWLIST_FILE="${SSH_AGENT_ALLOWLIST_FILE:-/etc/wsl-agent-sandbox/ssh-agent-allowlist.json}"
SSH_AGENT_DIR="${SSH_AGENT_DIR:-/run/box-root/ssh-agent}"
SSH_AGENT_UPSTREAM_SOCK="${SSH_AGENT_UPSTREAM_SOCK:-${SSH_AGENT_DIR}/upstream.sock}"

ensure_upstream() {
  if [[ ! -f "${SSH_AGENT_KEYS_FILE}" ]]; then
    return 0
  fi

  local key_count
  key_count="$(python3 - "${SSH_AGENT_KEYS_FILE}" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    svcs = data.get("services", {}) if isinstance(data, dict) else {}
    count = 0
    if isinstance(svcs, dict):
        for items in svcs.values():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get("privateKey"):
                        count += 1
    print(count)
except Exception:
    print(0)
PYEOF
)"
  if [[ "${key_count}" -eq 0 ]]; then
    return 0
  fi

  local parent_dir
  parent_dir="$(dirname "${SSH_AGENT_DIR}")"
  mkdir -p "${parent_dir}" "${SSH_AGENT_DIR}"
  chmod 0700 "${parent_dir}" "${SSH_AGENT_DIR}"
  if [[ "$(id -u)" -eq 0 ]]; then
    chown 0:0 "${parent_dir}" "${SSH_AGENT_DIR}"
  fi

  local probe_rc=0
  SSH_AUTH_SOCK="${SSH_AGENT_UPSTREAM_SOCK}" ssh-add -l >/dev/null 2>&1 || probe_rc=$?
  if [[ "${probe_rc}" -ne 0 ]] && [[ "${probe_rc}" -ne 1 ]]; then
    rm -f "${SSH_AGENT_UPSTREAM_SOCK}"
    (umask 0077 && ssh-agent -a "${SSH_AGENT_UPSTREAM_SOCK}" >/dev/null)
    chmod 0600 "${SSH_AGENT_UPSTREAM_SOCK}"
  fi

  python3 - "${SSH_AGENT_KEYS_FILE}" "${SSH_AGENT_UPSTREAM_SOCK}" <<'PYEOF'
import json
import os
import subprocess
import sys

keys_file, sock_path = sys.argv[1], sys.argv[2]
with open(keys_file, "r", encoding="utf-8") as f:
    data = json.load(f)

svcs = data.get("services", {}) if isinstance(data, dict) else {}
keys = []
if isinstance(svcs, dict):
    for items in svcs.values():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("privateKey"):
                    keys.append(item["privateKey"])

env = dict(os.environ, SSH_AUTH_SOCK=sock_path)
subprocess.run(["ssh-add", "-D"], env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for priv_key in keys:
    proc = subprocess.run(["ssh-add", "-"], input=priv_key, text=True, env=env, check=False, capture_output=True)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        raise SystemExit(f"ssh-add failed loading key into upstream ssh-agent: {msg}")
PYEOF
}

stop_upstream() {
  if [[ -S "${SSH_AGENT_UPSTREAM_SOCK}" ]] || [[ -e "${SSH_AGENT_UPSTREAM_SOCK}" ]]; then
    SSH_AUTH_SOCK="${SSH_AGENT_UPSTREAM_SOCK}" ssh-add -D >/dev/null 2>&1 || true
    pkill -f "${SSH_AGENT_UPSTREAM_SOCK}" >/dev/null 2>&1 || true
    rm -f "${SSH_AGENT_UPSTREAM_SOCK}"
  fi
  rm -f "${SSH_AGENT_KEYS_FILE}" "${SSH_AGENT_ALLOWLIST_FILE}"
}

case "${1:-}" in
  ensure-upstream)
    ensure_upstream
    ;;
  stop-upstream)
    stop_upstream
    ;;
  *)
    echo "Usage: $0 {ensure-upstream|stop-upstream}" >&2
    exit 1
    ;;
esac
