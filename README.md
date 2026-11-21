# `wsl-agent-sandbox` — Hardened Ubuntu 26.04 LTS WSL2 Sandbox for Autonomous AI Agents

A declaratively configured, isolated **Ubuntu 26.04 LTS (Resolute Raccoon)** WSL2 distribution (`ubuntu-2604-agent`) where autonomous AI coding agents (**Gemini CLI**, **Claude Code**, **Codex**, **Antigravity / VS Code Remote-WSL**, or custom agents) can run freely inside Linux while being **strictly contained from accessing your underlying Windows host**, with explicit Windows-side control over every bridge.

---

## Security & Isolation Guarantees

| Boundary | Default Policy | Controlled Bridge |
| :--- | :--- | :--- |
| **Privilege Escalation** | Agent runs as non-root `agent` (UID `26040`), zero `sudo`, locked `root` password. | Admin access only from Windows via `.\box.ps1 root-shell`. |
| **Windows Filesystem** | `/mnt/c` automount disabled (`[automount] enabled=false`), manual `mount -t drvfs` blocked. | Declarative `sharedFolders` allowlist in `box.json` mounted at `/shared/<name>` (`ro` or `rw`). |
| **Windows `.exe` Interop** | Disabled (`[interop] enabled=false`, `appendWindowsPath=false`). | None (Antigravity / VS Code Remote-WSL uses modern script-less startup). |
| **WSLg / Clipboard / `/mnt/wsl`** | Unmounted per-distro (`rprivate` + `umount -l` + `chmod 000`); no X11/Wayland/clipboard/raw sockets. | Root-only `/run/box-root/mnt-wsl` (`0700 root:root`) used exclusively by `docker-policy-proxy`. |
| **Network (WSL → Windows & LAN)** | Per-UID `nftables` (`meta skuid 26040`) drops all new outbound traffic to Windows host & RFC1918 LAN. | Optional `network.allowedHostPorts` in `box.json`; outbound internet remains open. |
| **Network (Windows → WSL)** | `ct state established,related accept` + WSL `localhostForwarding`. | Browse any web app hosted in WSL at `http://localhost:<port>` from Windows! |
| **Docker Desktop** | Docker Desktop WSL Integration stays **OFF** for this distro; root-owned Go `docker-policy-proxy` mediates `/var/run/docker.sock`. | Blocks host drive bind mounts (`/run/desktop/mnt/host/c`, `/mnt/c`, `C:\`), symlink escapes, `--privileged`, dangerous `CapAdd`, `host` namespaces, devices, malicious volume options, Swarm/plugins. Automatically rewrites allowed `/home/agent` (and opted-in `/shared/*`) bind mounts! |
| **Other WSL Distros** | Zero changes to `%USERPROFILE%\.wslconfig` or other distros; `nftables` scoped strictly to UID `26040`. | Optional reference in `examples/wslconfig.optional.ini`. |

---

## Quick Start

```powershell
# 1. Clone the repository:
git clone https://github.com/Thorup/wsl-agent-sandbox.git
cd wsl-agent-sandbox

# 2. Provision Ubuntu 26.04 LTS, build & test the Docker policy proxy, harden, and verify:
.\box.ps1 init

# 3. Open an interactive shell as the sandboxed agent user:
.\box.ps1 shell

# 4. Check status (systemd health, active /shared mounts, nftables):
.\box.ps1 status

# 5. Run the full red-team isolation & capability audit at any time:
.\box.ps1 verify
```

---

## Controlling What WSL Can Access on Windows (`box.json`)

Edit `box.json` on Windows (invisible to the agent inside WSL), then run `.\box.ps1 apply` to live-reload without rebuilding.

### Share a Specific Windows Folder (Read-Only or Read-Write)
```json
"sharedFolders": [
  {
    "name": "reference-docs",
    "windowsPath": "C:\\Users\\you\\Documents\\reference",
    "mode": "ro",
    "allowDockerBind": true
  }
]
```
After `.\box.ps1 apply`, the folder appears at `/shared/reference-docs` (mounted read-only, and if `allowDockerBind` is `true`, the Docker proxy forces `:ro` even if a container requests `:rw`).

### Allow a Specific Windows Host Port or Port-Forward (e.g., `kubectl port-forward`, SSH Tunnels, Local Ollama)

By default (`network.blockHostAndLan: true`, `allowedHostPorts: []`), direct processes running as `agent` inside WSL **cannot** reach ports bound on your Windows host (including `kubectl port-forward` or SSH tunnels on Windows `127.0.0.1` or LAN IPs) in either `networkingMode=nat` or `networkingMode=mirrored`.

#### Port-Forward Hardening Matrix

Use this table to determine what can reach a port forwarded to your Windows client:

| Configuration in `box.json` | Direct WSL Processes (`agent`) | Containers via Docker Desktop (`host.docker.internal`) | Effective Hardening Level |
| :--- | :--- | :--- | :--- |
| `blockHostAndLan: true`, `allowedHostPorts: []`, `docker.enabled: false` | **Blocked** (NAT & Mirrored) | **Disabled** (no Docker access) | **Strictest** — WSL box cannot reach any Windows host or port-forwarded service. |
| `blockHostAndLan: true`, `allowedHostPorts: []`, `docker.enabled: true` *(default)* | **Blocked** (NAT & Mirrored) | **Reachable via `host.docker.internal:<port>`** (unless blocked by Windows Firewall) | **Standard** — Direct WSL egress is blocked, but Docker Desktop bridge containers can still reach Windows host ports. |
| `blockHostAndLan: true`, `allowedHostPorts: [<port>]` | **Allowed on `<port>` only** | **Reachable** (if `docker.enabled: true`) | **Targeted Bridge** — Explicitly shares only the listed port(s) with WSL. |
| `blockHostAndLan: false` | **Allowed** (all host & LAN ports) | **Reachable** (if `docker.enabled: true`) | **Open Host/LAN** — No host/LAN network isolation. |

> **Security Tip:** If you run sensitive port-forwards on Windows (e.g., `kubectl port-forward` to a production cluster) while an untrusted agent runs in this box, set `"docker": { "enabled": false }` in `box.json` and run `.\box.ps1 apply` (or block Docker Desktop bridge traffic via Windows Firewall).

#### How to Share a Windows Port-Forward with the WSL Box

1. Add the port to `network.allowedHostPorts` in `box.json`:
```json
"network": {
  "blockHostAndLan": true,
  "allowedHostPorts": [
    { "port": 8080, "protocol": "tcp", "comment": "k8s port-forward on Windows" },
    { "port": 11434, "protocol": "tcp", "comment": "Local Ollama on Windows" }
  ]
}
```
2. Run `.\box.ps1 apply` to live-reload `nftables` (and mirrored loopback policy routing) immediately.
3. Connect based on your WSL2 `networkingMode` (in `%USERPROFILE%\.wslconfig`):
   - **Mirrored mode (`networkingMode=mirrored`):** Standard `kubectl port-forward ... 8080:<target>` (bound to `127.0.0.1` on Windows) is reachable directly at `localhost:8080` from inside WSL.
   - **NAT mode (default WSL2):** Windows `127.0.0.1` is not routed into WSL NAT, so bind the forward to your Windows host/WSL interface (e.g., `kubectl port-forward --address 0.0.0.0 ... 8080:<target>` or the `vEthernet (WSL)` IP), allow the port through Windows Firewall if prompted, and connect from WSL to the Windows host gateway IP (`ip route show default | awk '{print $3}'`).

### Add System `apt` Packages & Cloud/Agent/Language Toolchains
Add package names to `packages.apt` or toggle built-in installers (`installKubectl`, `installAwsCli`, `installGcloudCli`, `installUpctl`, `installDotnetSdk`, `installRust`, `installGeminiCli`, `installClaudeCode`) in `box.json` and run `.\box.ps1 apply`. (User-space tools via `uv`, `pip`, `npm`, `pnpm`, `cargo`, `rustup`, and `dotnet tool install -g` can be installed freely by the agent inside `/home/agent` without `sudo`.)

---

## Using Other AI Agents (Claude Code, Codex, etc.)

Because every containment boundary (non-root UID `26040`, no `sudo`, no `/mnt/c`, no Windows interop, no WSLg/clipboard, per-UID `nftables` + `loopback0` blocking, and `docker-policy-proxy`) is enforced at the **Linux OS / kernel / systemd level**, this box works identically for **any** CLI or IDE agent:
- **Gemini CLI** (`gemini` — pre-installed)
- **Claude Code** (`claude` — pre-installed by default; toggle `installClaudeCode` in `box.json`)
- **OpenAI Codex CLI**, **Aider**, **OpenCode**, or custom agents (installable via `npm`/`uv` in user-space or via `box.json`)

> **Cloud Credentials Note**: Any credentials you configure inside `/home/agent` (`~/.aws`, `~/.config/gcloud`, `~/.kube/config`) are accessible to autonomous agents running in this box. Use dedicated, least-privilege sandbox accounts/clusters or short-lived tokens rather than production admin credentials.

---

## Connecting Antigravity / VS Code Remote-WSL

1. Launch Antigravity / VS Code **from Windows**.
2. Connect via **Remote - WSL** to distro `ubuntu-2604-agent`.
3. Modern Remote-WSL uses script-less startup and works cleanly with `[interop] enabled=false` and `[automount] enabled=false`.

---

## Important Security Notes

1. **Keep Docker Desktop "WSL Integration" OFF for `ubuntu-2604-agent`**: Do not toggle `ubuntu-2604-agent` on in Docker Desktop's WSL Integration settings. Our root-owned `docker-policy-proxy` already connects to Docker Desktop cleanly while preventing raw socket exposure.
2. **Docker Desktop Container Bridge Egress**: While direct WSL processes (`agent` UID `26040`) are blocked from reaching Windows host ports by `nftables`, and containers cannot use `--network=host` or `--add-host=...:host-gateway`, containers running inside Docker Desktop's own bridge network can still resolve `host.docker.internal` unless restricted via Windows Firewall. Filesystem and privilege escapes via Docker are fully blocked by `docker-policy-proxy`.
3. **Global `.wslconfig` (`networkingMode`)**: `wsl-agent-sandbox` works cleanly in **both** `networkingMode=nat` and `networkingMode=mirrored` without modifying your global `%USERPROFILE%\.wslconfig`. In `networkingMode=mirrored`, `box-hardening.sh` installs per-UID (`uidrange 26040-26040`) policy routing + `nftables` `ct mark 0x2604` rules on `loopback0` so `agent` is blocked from reaching Windows `127.0.0.1` ports while Windows → WSL `localhost` web browsing and WSL-internal `127.0.0.1` services continue working seamlessly.

---

## Lifecycle Commands

- `.\box.ps1 init` — Full download (with SHA256 verification), import, provision, harden, verify.
- `.\box.ps1 apply` — Hot-reload `box.json` changes (mounts, ports, Docker policy, `apt` packages).
- `.\box.ps1 verify` — Run full red-team isolation audit + Windows ↔ WSL `localhost` web test.
- `.\box.ps1 status` — Inspect systemd services, active `/shared` mounts, and `nftables` rules.
- `.\box.ps1 shell` / `.\box.ps1 root-shell` — Open agent shell or Windows-side admin root shell.
- `.\box.ps1 snapshot [path]` — Export a `.tar` backup of the distro.
- `.\box.ps1 reset` / `.\box.ps1 destroy` — Rebuild cleanly or remove the distro completely.

---

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
