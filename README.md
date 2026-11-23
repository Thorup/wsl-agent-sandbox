<p align="center">
  <img src="assets/banner.jpg" alt="wsl-agent-sandbox — Hardened Ubuntu 26.04 LTS WSL2 Sandbox for Autonomous AI Agents" width="760">
</p>

# `wsl-agent-sandbox`

**Run autonomous AI coding agents at full Linux speed on Windows—without risking your host machine.**

`wsl-agent-sandbox` creates a dedicated, hardened **Ubuntu 26.04 LTS** WSL2 environment for **Claude Code**, **Gemini CLI**, **Codex**, **VS Code / Antigravity Remote-WSL**, or any custom agent. It works out of the box with zero configuration, keeps your Windows files and local network off-limits by default, and lets you open explicit bridges only when you need them.

---

## Why Use It?

- **Safe by default, zero config required:** No `/mnt/c`, no `sudo`, no Windows `.exe` interop, no clipboard/X11 sharing, and no access to your Windows host or local LAN.
- **Real Docker, safely mediated:** Containers work normally inside the sandbox while host drive mounts, `--privileged`, and container escapes are blocked automatically.
- **Controlled bridges on your terms:** Share a specific folder (`ro`/`rw`), open a single local port (like Ollama or `kubectl port-forward`), or push a git repo safely—and reload live with `.\box.ps1 apply`.
- **Pre-loaded developer environment:** Ubuntu 26.04 LTS with Node, Python (`uv`), Rust, .NET, Docker CLI, cloud CLIs, and AI coding agents ready out of the box.
- **Instant clean-room resets:** Take a golden snapshot once and roll back to a fresh sandbox in seconds.
- **Zero impact on your other WSL distros:** Never modifies `%USERPROFILE%\.wslconfig` or collides with existing distros.

---

## Quick Start (Zero Configuration Needed)

```powershell
# 1. Clone the repository
git clone https://github.com/Thorup/wsl-agent-sandbox.git
cd wsl-agent-sandbox

# 2. Provision Ubuntu 26.04 LTS, harden the sandbox, and run the isolation audit
.\box.ps1 init

# 3. Drop into the sandboxed Linux agent shell
.\box.ps1 shell
```

> **Tip:** Prefer a global command (`wsl-sandbox`) without keeping a git clone around? See [Scoop / global installation](docs/getting-started.md#global-installation-scoop).
> **Docker Desktop users:** Leave **WSL Integration OFF** for `wsl-agent-sandbox` in Docker Desktop—our built-in policy proxy connects automatically without exposing the raw Docker socket.

---

## Common Next Steps

### 1. Bring a Repository In Safely (Recommended over `rw` mounts)
Transfer any Windows git repo onto fast Linux `ext4` without exposing your Windows directory or `.git/hooks`:
```powershell
.\box.ps1 push-repo C:\Users\you\projects\my-app
# ...let your agent work inside WSL...
.\box.ps1 pull-diff my-app       # Review changes from Windows
.\box.ps1 pull-branch my-app     # Pull commits into a reviewable local branch
```

### 2. Connect VS Code or Antigravity
Create a gitignored `box.local.json` next to `box.json`:
```json
{
  "ide": { "configureRemoteWsl": true }
}
```
Run `.\box.ps1 apply`, then connect via **Remote-WSL → `wsl-agent-sandbox`**. See [Getting Started & IDE Setup](docs/getting-started.md#connecting-vs-code--antigravity-remote-wsl).

### 3. Pass API Keys & Cloud Credentials Safely
Keep all secrets in a central Windows folder (`%USERPROFILE%\.wsl-agent-sandbox\secrets.json`) or password manager/cloud vault—never in git or `box.json`—and push them over `stdin`:
```powershell
.\box.ps1 seed-secrets -DryRun   # Validate first
.\box.ps1 seed-secrets           # Seed or rotate credentials
```
Supports L7 token injection (`proxyInject`), filtered SSH agent forwarding (`agent-proxy`), ephemeral TTL expiry, and multi-cloud switchers (`use-gcloud`, `use-aws`, `use-github`). See [Secrets & Cloud Auth](docs/secrets.md).

### 4. Customize Without Touching Git (`box.local.json` & Starter Presets)
Put any local overrides in a gitignored `box.local.json` and run `.\box.ps1 apply` to live-reload. Start from a ready-made preset in [`examples/presets/`](examples/presets/):
- [`ide-dev.local.json`](examples/presets/ide-dev.local.json) — Remote-WSL IDE integration + optional IaC/K8s tools (`installTerraform`, `installHelm`).
- [`strict-lockdown.local.json`](examples/presets/strict-lockdown.local.json) — Domain egress allowlist (`llm-apis`, `github`, `npm`, `pypi`), isolated Docker internal network, registry allowlist, and CPU/RAM quotas.
- [`no-docker-minimal.local.json`](examples/presets/no-docker-minimal.local.json) — Disables Docker completely for maximum host isolation alongside sensitive Windows port-forwards.

---

## Explore All Features

Everything in `wsl-agent-sandbox` is documented in focused guides so you only read what you need:

| Guide | What You'll Find |
| :--- | :--- |
| **[Getting Started & IDE Setup](docs/getting-started.md)** | Prerequisites, Scoop global install, VS Code / Antigravity Remote-WSL, Windows Terminal profile, supported AI agents, and automatic agent context (`SKILL.md` & `box-context`). |
| **[Configuration & Networking](docs/configuration.md)** | `box.json` & `box.local.json` deep-merge, shared folders (`ro`/`rw`), Windows port-forwards (NAT vs. Mirrored matrix), domain egress allowlists, 23 built-in tool toggles, and multi-box `-Profile` isolation. |
| **[Secrets & Cloud Auth](docs/secrets.md)** | Central Windows `secrets.json`, 14 supported CLI services, password manager & cloud vault URIs (`op://`, `bw://`, `dpapi://`, `azkv://`, `awssm://`, `gcpsm://`), L7 `proxyInject`, SSH `agent-proxy`, TTLs, and `use-gcloud` / `use-aws` / `use-github`. |
| **[Security Architecture](docs/security-architecture.md)** | Full containment boundary matrix, `nftables` & mirrored `loopback0` rules, `docker-policy-proxy` protections, BuildKit & `host.docker.internal` advisories, systemd resource quotas, `verify`, and `audit` logs. |
| **[CLI Command Reference](docs/cli-reference.md)** | Complete reference for all `box.ps1` commands, flags, snapshots/resets, `doctor`, `upgrade`, `compact`, and multi-profile workflows. |

---

## Everyday Commands

| Command | What It Does |
| :--- | :--- |
| `.\box.ps1 init [-SaveGolden]` | Provision, harden, and verify the sandbox from scratch. |
| `.\box.ps1 shell` | Open an interactive shell as the sandboxed `agent` user. |
| `.\box.ps1 apply` | Live-reload `box.json` / `box.local.json` changes without rebuilding. |
| `.\box.ps1 push-repo <path>` / `pull-diff <name>` | Safely move a Windows git repo into WSL and review agent diffs. |
| `.\box.ps1 seed-secrets` / `clear-secrets` | Push, rotate, or revoke CLI tokens and cloud credentials from Windows. |
| `.\box.ps1 verify` / `doctor` | Run the red-team isolation audit or Windows + WSL preflight checks. |
| `.\box.ps1 reset` | Roll back to a clean golden snapshot in seconds. |

See the full 18-command reference in [docs/cli-reference.md](docs/cli-reference.md).

---

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
