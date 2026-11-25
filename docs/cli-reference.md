# CLI Command Reference (`box.ps1`)

[← Back to README](../README.md)

All commands accept:
- `-Profile <name>` (alias `-ProfileName`) — target a named sandbox profile (`box.<profile>.json` or `profiles/<profile>.json`).
- `-ConfigPath <path>` — use a custom config JSON file instead of `box.json`.

*(If installed globally via Scoop, replace `.\box.ps1` with `wsl-sandbox`.)*

---

## Provisioning & Daily Lifecycle

| Command | Description |
| :--- | :--- |
| `.\box.ps1 init [-SaveGolden]` | Full Ubuntu 26.04 LTS download (with SHA256 verification), WSL import, toolchain provisioning, `docker-policy-proxy` build & test, hardening, and `verify`. Pass `-SaveGolden` to save a fast-reset golden snapshot immediately. |
| `.\box.ps1 up` | Ensure the distro is running and systemd hardening services are active (runs `init` if not installed). |
| `.\box.ps1 apply [-RebuildProxy]` | Hot-reload `box.json` / `box.local.json` changes (shared folders, host ports, egress allowlist, Docker policy, `apt` packages, toolchains, IDE settings) without rebuilding. Pass `-RebuildProxy` to recompile `docker-policy-proxy`. |
| `.\box.ps1 shell` | Open an interactive bash shell as the sandboxed non-root `agent` user. |
| `.\box.ps1 root-shell` | Open an administrative `root` shell from Windows (not reachable from inside the sandbox). |
| `.\box.ps1 list` | List all configured sandbox profiles (`default` + `box.<profile>.json` / `profiles/<profile>.json`), their distro names, UIDs, and WSL installation states. |

---

## Code Bridge Commands

| Command | Description |
| :--- | :--- |
| `.\box.ps1 push-repo <path> [-Dest <relpath>] [-Branch <ref>] [-Force]` | Bundle a Windows git repository and import it onto native Linux `ext4` (`~/work/<name>`) without mounting `/mnt/c` or `rw` `/shared`. |
| `.\box.ps1 pull-diff <name>` | Display a clean diff summary of agent commits made inside `~/work/<name>`. |
| `.\box.ps1 pull-branch <name> [-RepoPath <winPath>] [-Branch <ref>]` | Pull agent commits back into a reviewable local `sandbox/<name>` branch on Windows without touching your active working tree or `.git/hooks`. |

---

## Secrets Management

| Command | Description |
| :--- | :--- |
| `.\box.ps1 seed-secrets [path]` | Seed or rotate CLI tokens and cloud credentials from a central Windows manifest (independently of `init`/`apply`). Supports `-SecretsPath <path>`, `-Service <names>`, `-Ttl <dur>`, `-Prune`, and `-DryRun`. |
| `.\box.ps1 clear-secrets [-Service <names>]` | Revoke managed seeded CLI credentials inside WSL (all, or scoped to specific service(s)). |

---

## Verification, Diagnostics & Maintenance

| Command | Description |
| :--- | :--- |
| `.\box.ps1 verify` | Run the full red-team isolation audit + Windows ↔ WSL `localhost` web check. |
| `.\box.ps1 status` | Inspect systemd services, active `/shared` mounts, seeded CLI secrets, VHDX disk footprint, resource quotas, `nftables` rules, and security advisories. |
| `.\box.ps1 doctor` | Run Windows + WSL preflight diagnostics (WSL2, `.wslconfig`, Docker Desktop, systemd, VHDX size, image cache, Docker security advisories). |
| `.\box.ps1 logs` / `.\box.ps1 audit` | View root-owned security events (`nftables` drops, `docker-policy-proxy` denials, `egress-proxy`, `credential-proxy`, `ssh-agent-proxy`, `wsl-box-ttl-*` expirations, and `box-hardening` reloads). Supports `-Source <all\|docker\|network\|egress\|credentials\|ssh-agent\|hardening>`, `-Since <time>`, and `-Lines <1..100000>`. |
| `.\box.ps1 upgrade [-Scope all\|apt,agents,toolchains]` | Update installed `apt` packages, AI agents, and language/cloud toolchains in place. |
| `.\box.ps1 compact` | Run `fstrim` inside WSL and compact `ext4.vhdx` to reclaim disk space (requires elevated Administrator PowerShell). |
| `.\box.ps1 register-terminal [-Unregister]` | Add or update a dedicated Windows Terminal profile for this sandbox (pass `-Unregister` to remove it). |

---

## Snapshots, Rollbacks & Teardown

| Command | Description |
| :--- | :--- |
| `.\box.ps1 snapshot [path] [-Golden]` | Export a `.tar` backup of the distro (pass `-Golden` to save `.cache\<distro>-golden.tar`). |
| `.\box.ps1 restore <path> [-Force]` | Import a `.tar` backup, re-apply `box.json` policy, and run `verify`. |
| `.\box.ps1 reset [-Full] [-SaveGolden] [-Force]` | Fast-restore from golden snapshot (or pass `-Full` for a clean Ubuntu rebuild). |
| `.\box.ps1 destroy [-Force]` | Unregister and remove the WSL distribution completely. |
