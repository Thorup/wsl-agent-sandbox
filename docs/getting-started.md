# Getting Started, IDEs & AI Agents

[← Back to README](../README.md)

## Prerequisites

- **Windows 10/11** with **WSL2** enabled (`wsl --status`).
- **PowerShell 5.1** (built-in) or **PowerShell 7+**.
- *(Optional)* **Docker Desktop** if you want mediated Docker access inside the sandbox. Leave **WSL Integration OFF** for `wsl-agent-sandbox` in Docker Desktop settings.

---

## Installation

### From a Git Clone (Recommended for Local Customization)
```powershell
git clone https://github.com/Thorup/wsl-agent-sandbox.git
cd wsl-agent-sandbox
.\box.ps1 init
.\box.ps1 shell
```

### Global Installation (Scoop)
Install directly from the latest GitHub Release Scoop manifest (or use [`packaging/scoop/wsl-agent-sandbox.json`](../packaging/scoop/wsl-agent-sandbox.json) as a template):
```powershell
scoop install https://github.com/Thorup/wsl-agent-sandbox/releases/latest/download/wsl-agent-sandbox.json
```
Once installed, invoke `wsl-sandbox` from any directory:
```powershell
wsl-sandbox init
wsl-sandbox shell
```
When invoked globally without a `box.json` in the current directory, `wsl-sandbox` automatically looks for `%USERPROFILE%\.wsl-agent-sandbox\box.json` (and merges `%USERPROFILE%\.wsl-agent-sandbox\box.local.json` over the bundled `box.json`).

---

## Connecting VS Code / Antigravity Remote-WSL

Because `/mnt/c` and Windows `.exe` interop are disabled inside the sandbox, Remote-WSL uses modern script-less startup (`"remote.WSL.experimental.scriptLessStartup": true`) to stream the server tarball over `stdin`.

1. Opt in via `box.local.json` (or `box.json`) so `init` and `apply` configure VS Code (`%APPDATA%\Code\User\settings.json`) and Antigravity (`%APPDATA%\Antigravity\User\settings.json`) automatically:
   ```json
   {
     "ide": {
       "configureRemoteWsl": true
     }
   }
   ```
   *(Defaults to `false` so global IDE settings are left untouched unless you opt in.)*
2. Run `.\box.ps1 apply`.
3. Launch from Windows:
   ```powershell
   code --remote wsl+wsl-agent-sandbox /home/agent
   # or:
   antigravity --remote wsl+wsl-agent-sandbox /home/agent
   ```
   Or use the bottom-left **`><`** Remote window menu → **Connect to WSL using Distro...** → **`wsl-agent-sandbox`**.

---

## Windows Terminal Profile

Register a visually distinct Windows Terminal profile (with automatic timestamped backup of `settings.json`):
```powershell
.\box.ps1 register-terminal
# Remove later if desired:
.\box.ps1 register-terminal -Unregister
```

---

## Using AI Coding Agents Inside the Sandbox

Every containment boundary (non-root UID `26040`, no `sudo`, no `/mnt/c`, no Windows interop, no WSLg/clipboard, per-UID `nftables`, and `docker-policy-proxy`) is enforced at the **Linux OS / kernel / systemd level**, so the sandbox works identically for any CLI or IDE agent:

- **Gemini CLI** (`gemini` — pre-installed by default; `installGeminiCli`)
- **Claude Code** (`claude` — pre-installed by default; `installClaudeCode`)
- **OpenAI Codex CLI** (`codex` — toggle `installCodexCli: true`)
- **OpenCode** (`opencode` — toggle `installOpenCode: true`)
- **Aider** (`aider` — toggle `installAider: true`)
- **Custom agents** — install freely in user-space inside `/home/agent` via `uv`, `pip`, `npm`, `pnpm`, `cargo`, or `dotnet tool install -g` without `sudo`.

### Dynamic Agent Context (`SKILL.md` & `box-context`)

Whenever you run `.\box.ps1 apply`, `.\box.ps1 seed-secrets`, or `.\box.ps1 clear-secrets`, `/usr/local/sbin/box-sync-context.py` automatically keeps agents aware of active sandbox boundaries, mounts, allowed host ports, and seeded cloud profiles (**with zero secret values written to disk**):

- **Global Agent Instruction Files (non-destructive marker blocks):** Updates `# >>> wsl-agent-sandbox >>>` blocks in `~/.gemini/GEMINI.md`, `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.config/opencode/AGENTS.md`, and `~/.config/wsl-agent-sandbox/SANDBOX_CONTEXT.md`.
- **Supplementary Global Agent Skill (`SKILL.md`):** Generates `~/.gemini/skills/wsl-agent-sandbox/SKILL.md`, `~/.claude/skills/wsl-agent-sandbox/SKILL.md`, and `~/.codex/skills/wsl-agent-sandbox/SKILL.md` so agents discover sandbox rules even when a repository has its own `GEMINI.md` / `CLAUDE.md` / `AGENTS.md`.
- **Live Context CLI:** Run `box-context` (or `box-context --json`) inside WSL to inspect the live non-secret sandbox inventory.
