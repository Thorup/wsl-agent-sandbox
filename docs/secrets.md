# Seeding & Rotating CLI Service Secrets

[← Back to README](../README.md)

Seed and rotate machine account tokens and service account credentials directly from a **central Windows location**—completely outside `init` / `apply`, without mounting your secrets folder into WSL or storing any secrets in `box.json` / git.

> **Least-Privilege Note:** Credentials seeded as files inside `/home/agent` (`~/.aws`, `~/.azure`, `~/.config/gcloud`, etc.) are accessible to autonomous agents running in the sandbox. Use dedicated, least-privilege sandbox accounts, short-lived TTLs (`-Ttl`), L7 `"proxyInject": true` (where supported), or `"mode": "agent-proxy"` for SSH keys.

---

## 1. Create Your Central Windows Secrets Manifest

Copy [`examples/secrets.example.json`](../examples/secrets.example.json) into `%USERPROFILE%\.wsl-agent-sandbox\secrets.json`:

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\.wsl-agent-sandbox" -Force | Out-Null
Copy-Item .\examples\secrets.example.json "$env:USERPROFILE\.wsl-agent-sandbox\secrets.json"
```

Every secret field supports **four mutually exclusive sources**:
- **Inline value** (e.g., `"token": "..."`)
- **Windows file** (e.g., `"tokenFile": "tokens/github.txt"`, `"serviceAccountKeyFile": "keys/gcp-sa.json"` — relative paths resolve against the manifest directory; `%ENVVAR%` expansion supported)
- **Windows environment variable** (e.g., `"tokenEnv": "SANDBOX_GH_TOKEN"`)
- **Password manager or cloud vault URI** (e.g., `"tokenVault": "op://Sandbox/GitHub/pat"` — supports `op://` 1Password CLI, `bw://` Bitwarden CLI, `dpapi://` Windows CurrentUser DPAPI file, `azkv://` Azure Key Vault, `awssm://` AWS Secrets Manager, and `gcpsm://` GCP Secret Manager, resolved on Windows at seed time)

### Manifest Path Resolution Priority
1. CLI argument: `.\box.ps1 seed-secrets "D:\vault\secrets.json"` or `-SecretsPath "D:\vault\secrets.json"`
2. Windows environment variable: `$env:WSL_AGENT_SANDBOX_SECRETS_PATH`
3. Optional non-secret pointer in `box.json`: `"secrets": { "manifestPath": "%USERPROFILE%\\.wsl-agent-sandbox\\secrets.json" }`
4. Default: `%USERPROFILE%\.wsl-agent-sandbox\secrets.json`

---

## 2. Seed, Rotate, Expire, or Revoke Secrets

```powershell
# Preview and validate without pushing any secrets:
.\box.ps1 seed-secrets -DryRun

# Seed all enabled services:
.\box.ps1 seed-secrets

# Rotate only specific service(s):
.\box.ps1 seed-secrets -Service github,jira

# Seed with ephemeral auto-expiration (enforced by root systemd timers):
.\box.ps1 seed-secrets -Service aws,github -Ttl 2h

# Seed and prune credentials for disabled/removed services:
.\box.ps1 seed-secrets -Prune

# Revoke managed credentials inside WSL (all, or specific service(s)):
.\box.ps1 clear-secrets
.\box.ps1 clear-secrets -Service aws,gcloud
```

---

## 3. Supported CLI Services ([`secrets.schema.json`](../secrets.schema.json))

| Service Key | CLI / Tool | Auth Mechanism & Linux Target |
| :--- | :--- | :--- |
| `github` | `gh` + `git` (HTTPS) | Machine account / fine-grained PAT (single or multi-profile `profiles[]` across personal and org Resource Owners, switchable via `use-github <profile>`) → `~/.config/gh/hosts.yml`, `gh auth setup-git`, optional `GH_TOKEN` / `GH_ENTERPRISE_TOKEN`; supports `"proxyInject": true` (`GITHUB_API_URL=http://127.0.0.1:3129/github`). |
| `git` | `git` (SSH + signing) | Dedicated Git SSH keys (plus optional `.pub` & OpenSSH `-cert.pub` certs) → `~/.ssh/wsl-agent-sandbox-git/` (`0600`) or root-owned `ssh-agent` (`"mode": "agent-proxy"` via filtered `SSH_AUTH_SOCK=/run/ssh-agent-proxy/agent.sock`), independent Git `Host` stanzas in `~/.ssh/config`, pinned `known_hosts`, optional Git identity (`user.name`/`user.email`), SSH commit/tag signing (`gpg.format = ssh`, `allowed_signers`), and `rewriteHttpsToSsh`. |
| `aws` | `aws` | IAM access keys / STS tokens (single or multi-profile, switchable via `use-aws <profile>`) → `~/.aws/credentials`, `~/.aws/config`, optional `AWS_PROFILE`. |
| `gcloud` | `gcloud` + GCP SDKs | Service Account JSON key(s) (single-project or multi-project `projects[]` / `profiles[]`, switchable via `use-gcloud <name>`) → `~/.config/wsl-agent-sandbox/keys/gcloud-*.json`, named `gcloud` configurations, `GOOGLE_APPLICATION_CREDENTIALS`. |
| `azure` | `az` + Azure SDKs | Entra ID Service Principal (client secret or PEM cert) → `az login --service-principal`, optional subscription, `AZURE_CLIENT_ID`/`AZURE_TENANT_ID`/`AZURE_CLIENT_SECRET` (or `AZURE_CLIENT_CERTIFICATE_PATH`). |
| `azureDevops` | `az devops` | Personal Access Token → `AZURE_DEVOPS_EXT_PAT` + `az devops configure --defaults organization=... project=...`. |
| `jira` | `jira` (`jira-cli`) | API token → `~/.config/.jira/.config.yml` + `JIRA_API_TOKEN`; supports `"proxyInject": true` (`http://127.0.0.1:3129/jira`). |
| `upcloud` | `upctl` | API token (or subaccount username/password) → `~/.config/upctl.yaml` + optional `UPCLOUD_TOKEN`. |
| `kubectl` | `kubectl` | Dedicated kubeconfig file or Service Account bearer token → `~/.kube/config` + optional context switch. |
| `gemini` | `gemini` | `GEMINI_API_KEY` and/or Vertex AI; supports `"proxyInject": true` (`GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:3129/gemini` + placeholder token). |
| `claude` | `claude` | `ANTHROPIC_API_KEY` and/or `CLAUDE_CODE_OAUTH_TOKEN`; supports `"proxyInject": true` (`ANTHROPIC_BASE_URL=http://127.0.0.1:3129/claude` + placeholder token). |
| `ssh` | `ssh` / `scp` / `sftp` | Named SSH private keys for remote servers/bastions (plus optional `.pub` & `-cert.pub` certs) → `~/.ssh/wsl-agent-sandbox/` (`0600`) or root-owned `ssh-agent` (`"mode": "agent-proxy"`), marker-delimited `Host` stanzas in `~/.ssh/config`, and pinned `known_hosts`. |
| `env` | Any CLI | Additional custom token environment variables exported into `~/.config/wsl-agent-sandbox/secrets.env` (protected system vars like `PATH`/`DOCKER_HOST`/`LD_PRELOAD` are rejected). |
| `files` | Any CLI | Additional secret files (e.g., `~/.npmrc`, `~/.netrc`) copied atomically with `0600` strictly inside `/home/<agent>/`. |

---

## 4. Persistent Multi-Cloud Profile Switchers (Inside WSL)

When multiple profiles are seeded, switch cleanly across both interactive shells and non-interactive agent subshells (`~/.config/wsl-agent-sandbox/active-overrides.env`):

- `use-gcloud <name>` (or `use-gcloud --list`) — Switches active `gcloud` configuration **and** updates `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT`, `CLOUDSDK_CORE_PROJECT`, and compute region/zone together.
- `use-aws <profile>` (or `use-aws --list`) — Switches `AWS_PROFILE` persistently.
- `use-github <profile>` (or `use-github --list`) — Switches active GitHub fine-grained PAT profile (`GH_TOKEN` / `GH_ENTERPRISE_TOKEN` and `~/.config/gh/hosts.yml`), including `"proxyInject": true` profiles.

---

## 5. Git SSH, Remote SSH & Security Guarantees

- **Zero Windows Mounts:** Your Windows secrets folder is never mounted into WSL (`/shared` or `/mnt/c`) and never written to `box.json` or `/etc/wsl-agent-sandbox/policy.json`. Payloads are piped strictly over `stdin` to `wsl -u root`, written atomically with `0600` ownership, and redacted from error output.
- **L7 Credential Injection (`proxyInject: true`):** Real tokens stay in root-only `/etc/wsl-agent-sandbox/credential-proxy.json`. The agent only receives placeholder tokens pointing at `127.0.0.1:3129`, which enforces `egressMode: "allowlist"`, SSRF/DNS-rebinding protection, redirect blocking, and request size caps.
- **Filtered SSH Agent Proxy (`"mode": "agent-proxy"`):** Private keys stay in a root-owned `ssh-agent` behind `/run/ssh-agent-proxy/agent.sock` (`ssh-agent-proxy.service`), which filters `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST` against an allowlist of public key blobs and blocks add/remove/lock operations.
- **Independent `git` & `ssh` Blocks:** `git` and `ssh` maintain separate key directories and marker-delimited blocks in `~/.ssh/config`, so rotating or clearing one never clobbers the other or custom user entries. `StrictHostKeyChecking` defaults to `yes` when pinned `knownHosts` cover a host (`accept-new` otherwise), and `git` sets `BatchMode yes` by default so agents fail fast instead of hanging on prompts.
- **Network Isolation Preserved:** `seed-secrets` never weakens `box.json` network rules—public remote SSH servers work out of the box while RFC1918/LAN/Tailscale targets remain governed by `network.blockHostAndLan` and `network.blockedCidrs`.
