# Security & Isolation Architecture

[← Back to README](../README.md)

## Containment Boundary Matrix

| Boundary | Default Policy | Controlled Bridge |
| :--- | :--- | :--- |
| **Privilege Escalation** | Agent runs as non-root `agent` (UID `26040`), zero `sudo`, locked `root` password. | Admin access only from Windows via `.\box.ps1 root-shell`. |
| **Windows Filesystem** | `/mnt/c` automount disabled (`[automount] enabled=false`), manual `mount -t drvfs` blocked. | Declarative `sharedFolders` allowlist in `box.json` mounted at `/shared/<name>` (`ro` or `rw`), or safe git bundles via `push-repo` / `pull-diff`. |
| **Windows `.exe` Interop** | Disabled (`[interop] enabled=false`, `appendWindowsPath=false`). | None (VS Code / Antigravity Remote-WSL uses modern script-less startup). |
| **WSLg / Clipboard / `/mnt/wsl`** | Unmounted per-distro (`rprivate` + `umount -l` + `chmod 000`); no X11/Wayland/clipboard/raw sockets. | Root-only `/run/box-root/mnt-wsl` (`0700 root:root`) used exclusively by `docker-policy-proxy`. |
| **Network (WSL → Windows & LAN)** | Per-UID `nftables` (`meta skuid 26040`) drops all new outbound traffic to Windows host & RFC1918 LAN (`network.logDrops: true` rate-limit logs blocked connections). | Optional `network.allowedHostPorts` in `box.json`; outbound internet is `"open"` by default or restricted via `network.egressMode: "allowlist"` (`network.allowedDomains` enforced by root `egress-proxy.service` on `127.0.0.1:3128`). |
| **Network (Windows → WSL)** | `ct state established,related accept` + WSL `localhostForwarding`. | Browse any web app hosted in WSL at `http://localhost:<port>` from Windows. |
| **Docker Desktop** | Docker Desktop WSL Integration stays **OFF** for this distro; root-owned Go `docker-policy-proxy` mediates `/var/run/docker.sock`. | Blocks host drive bind mounts (`/run/desktop/mnt/host/c`, `/mnt/c`, `C:\`), symlink & TOCTOU escapes (`O_NOFOLLOW` ephemeral bind pinning), `--privileged`, dangerous `CapAdd`, `host` namespaces, devices, malicious volume options, Swarm/plugins. Enforces loopback `PortBindings`, optional `forceInternalNetwork`, container `defaultLimits`/`maxLimits`, `allowedRegistries`, and automatic BuildKit disabling when strict network/registry rules are active. Automatically rewrites allowed `/home/agent` (and opted-in `/shared/*`) bind mounts. |
| **Root Python Proxies** | `egress-proxy.service`, `credential-proxy.service`, and `ssh-agent-proxy.service` run under systemd sandboxing (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome`, `MemoryMax`) with 32 MiB HTTP body caps (`413`). | Explicit allowlisted L7 routes (`127.0.0.1:3129`), domain allowlist (`127.0.0.1:3128`), and key-blob filtered SSH agent (`/run/ssh-agent-proxy/agent.sock`). |
| **Resource Quotas** | Optional per-UID `systemd` slice limits on `user-<uid>.slice` (never restricts root control plane). | Declarative `resources` (`memoryMax`, `cpuQuota`, `tasksMax`) in `box.json`. |
| **Other WSL Distros** | Zero changes to `%USERPROFILE%\.wslconfig` or other distros; `nftables` scoped strictly to UID `26040` (or profile UID `26100..26998`). | Optional reference in [`examples/wslconfig.optional.ini`](../examples/wslconfig.optional.ini). |

---

## Important Security Notes

1. **Keep Docker Desktop "WSL Integration" OFF for `wsl-agent-sandbox`:** Do not toggle `wsl-agent-sandbox` on in Docker Desktop's WSL Integration settings. Our root-owned `docker-policy-proxy` already connects to Docker Desktop cleanly while preventing raw socket exposure.
2. **Docker Desktop Container Bridge Egress (`host.docker.internal`) & BuildKit:** While direct WSL processes (`agent`) are blocked from reaching Windows host ports by `nftables`, containers running inside Docker Desktop's default bridge network can still resolve `host.docker.internal` unless you set `"docker": { "forceInternalNetwork": true }` (or `"enabled": false`) in `box.local.json`, or restrict Docker Desktop bridge traffic via Windows Firewall. Both `.\box.ps1 doctor` and `.\box.ps1 status` emit advisories when `docker.enabled: true` is combined with `forceInternalNetwork: false` alongside strict network policies.
3. **Global `.wslconfig` (`networkingMode`):** `wsl-agent-sandbox` works cleanly in **both** `networkingMode=nat` and `networkingMode=mirrored` without modifying `%USERPROFILE%\.wslconfig`. In `networkingMode=mirrored`, `box-hardening.sh` installs per-UID policy routing + `nftables` `ct mark` rules on `loopback0` so `agent` is blocked from reaching Windows `127.0.0.1` ports while Windows → WSL `localhost` web browsing and WSL-internal `127.0.0.1` services continue working seamlessly.

---

## Verification & Audit Logging

- **Red-Team Isolation Audit:** Run `.\box.ps1 verify` at any time to test privilege isolation, `/mnt/c` & `drvfs` denial, WSLg unmount, Windows host/LAN blocking, Docker escape blocking (including active container egress isolation when `forceInternalNetwork: true`), and pre-installed tools.
- **Preflight Diagnostics:** Run `.\box.ps1 doctor` to check WSL2, `.wslconfig`, Docker Desktop, systemd health, VHDX size, image cache, and Docker security advisories.
- **Security Event Logs:** Run `.\box.ps1 audit` (or `.\box.ps1 logs -Source docker|network|hardening -Since "1 hour ago"`) to inspect root-owned `nftables` drops, `docker-policy-proxy` denials, and `box-hardening` reloads.
