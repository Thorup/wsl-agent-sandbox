# Configuration, Networking & Multi-Box Profiles

[← Back to README](../README.md)

## How `box.json` & `box.local.json` Work

All sandbox settings are declared in [`box.json`](../box.json) (validated by [`box.schema.json`](../box.schema.json)).

> **Recommended:** Put your personal overrides in a gitignored **`box.local.json`** next to `box.json`. `box.ps1` automatically deep-merges `box.local.json` over `box.json` (objects merge recursively; arrays replace cleanly) without leaving a dirty git working tree.

After editing `box.local.json`, apply changes live without rebuilding:
```powershell
.\box.ps1 apply
```

You can also start from a ready-made preset in [`examples/presets/`](../examples/presets/).

---

## Sharing Specific Windows Folders (`sharedFolders`)

By default, `/mnt/c` is disabled and `sharedFolders` is empty (deny-all). To expose a specific directory at `/shared/<name>`:

```json
{
  "sharedFolders": [
    {
      "name": "reference-docs",
      "windowsPath": "C:\\Users\\you\\Documents\\reference",
      "mode": "ro",
      "allowDockerBind": true
    }
  ]
}
```
- `mode`: `"ro"` (read-only) or `"rw"` (read-write). For active code editing, prefer [`push-repo` / `pull-diff`](cli-reference.md#code-bridge-commands) over `rw` mounts for faster Linux `ext4` I/O and host `.git/hooks` safety.
- `allowDockerBind`: When `true` on a `"ro"` mount, `docker-policy-proxy` enforces `:ro` even if a container requests `:rw`.

---

## Allowing Specific Windows Host Ports (`network.allowedHostPorts`)

By default (`network.blockHostAndLan: true`, `allowedHostPorts: []`), processes running as `agent` inside WSL **cannot** reach ports bound on your Windows host (including `kubectl port-forward`, SSH tunnels, or local Ollama) in either `networkingMode=nat` or `networkingMode=mirrored`.

### Port-Forward Hardening Matrix

| Configuration in `box.json` | Direct WSL Processes (`agent`) | Containers via Docker Desktop (`host.docker.internal`) | Effective Hardening Level |
| :--- | :--- | :--- | :--- |
| `blockHostAndLan: true`, `allowedHostPorts: []`, `docker.enabled: false` | **Blocked** (NAT & Mirrored) | **Disabled** (no Docker access) | **Strictest** — WSL box cannot reach any Windows host or port-forwarded service. |
| `blockHostAndLan: true`, `allowedHostPorts: []`, `docker.enabled: true` *(default)* | **Blocked** (NAT & Mirrored) | **Reachable via `host.docker.internal:<port>`** (unless `docker.forceInternalNetwork: true` or blocked by Windows Firewall) | **Standard** — Direct WSL egress is blocked, `PortBindings` forced to `127.0.0.1` by default. |
| `blockHostAndLan: true`, `allowedHostPorts: [<port>]` | **Allowed on `<port>` only** | **Reachable** (if `docker.enabled: true`) | **Targeted Bridge** — Explicitly shares only the listed port(s) with WSL. |
| `blockHostAndLan: false` | **Allowed** (all host & LAN ports) | **Reachable** (if `docker.enabled: true`) | **Open Host/LAN** — No host/LAN network isolation. |

### Sharing a Port-Forward

1. Add the port to `box.local.json`:
   ```json
   {
     "network": {
       "blockHostAndLan": true,
       "allowedHostPorts": [
         { "port": 8080, "protocol": "tcp", "comment": "k8s port-forward on Windows" },
         { "port": 11434, "protocol": "tcp", "comment": "Local Ollama on Windows" }
       ]
     }
   }
   ```
2. Run `.\box.ps1 apply` to live-reload `nftables` (and mirrored loopback policy routing).
3. Connect based on your WSL2 `networkingMode` (in `%USERPROFILE%\.wslconfig`):
   - **Mirrored mode (`networkingMode=mirrored`):** Standard `kubectl port-forward ... 8080:<target>` on Windows `127.0.0.1` is reachable directly at `localhost:8080` inside WSL.
   - **NAT mode (default WSL2):** Bind the forward to `0.0.0.0` (e.g., `kubectl port-forward --address 0.0.0.0 ... 8080:<target>`) or the `vEthernet (WSL)` IP, allow it through Windows Firewall if prompted, and connect from WSL to the Windows gateway IP (`ip route show default | awk '{print $3}'`).

---

## Restricting Public Internet Egress (`network.egressMode`)

By default (`"egressMode": "open"`), the agent has open outbound internet access while Windows host and RFC1918 LAN IPs are blocked. To restrict outbound HTTP/HTTPS traffic strictly to allowlisted domains (and block direct non-proxy egress and UDP/TCP port 53 DNS exfiltration in `nftables`), set `"egressMode": "allowlist"`:

```json
{
  "network": {
    "blockHostAndLan": true,
    "logDrops": true,
    "egressMode": "allowlist",
    "allowedDomains": [
      "llm-apis",
      "github",
      "npm",
      "pypi",
      "*.example.com"
    ]
  }
}
```
- **Built-in presets:** `llm-apis`, `github`, `npm`, `pypi`, and `apt`.
- `.\box.ps1 apply` automatically starts the root-owned `egress-proxy.service` on `127.0.0.1:3128` (with SSRF and DNS-rebinding protection) and exports `HTTP_PROXY` / `HTTPS_PROXY` into the agent environment.

---

## Hardening Docker Containers & Systemd Resource Quotas

Fine-tune `docker-policy-proxy` and per-UID `systemd` slice quotas (`user-<uid>.slice`) in `box.local.json`:

```json
{
  "docker": {
    "enabled": true,
    "allowBindPrefixes": ["/home/agent"],
    "allowBuildKit": true,
    "allowPortBindings": true,
    "forceLoopbackPortBindings": true,
    "allowedPublishedPorts": [3000, 8080],
    "forceInternalNetwork": false,
    "defaultLimits": { "memoryBytes": 2147483648, "nanoCpus": 2000000000, "pidsLimit": 256 },
    "maxLimits": { "memoryBytes": 4294967296, "nanoCpus": 4000000000, "pidsLimit": 512 },
    "allowedRegistries": ["docker.io", "ghcr.io", "mcr.microsoft.com"]
  },
  "resources": {
    "memoryMax": "8G",
    "cpuQuota": "400%",
    "tasksMax": 512
  }
}
```
> **Note:** BuildKit (`/grpc`, `/session`) is automatically disabled whenever `forceInternalNetwork: true` or `allowedRegistries` is non-empty, preventing `docker buildx` from bypassing network or registry policies.

---

## System `apt` Packages & Built-in Toolchains

Add package names to `packages.apt` or toggle any of the **23 built-in installers** in `box.local.json` and run `.\box.ps1 apply`:

- **Core Runtimes & Package Managers:** `installDockerCli`, `installUv`, `installNodeLts`, `installPnpm`, `installDotnetSdk`, `installRust`
- **AI Coding Agents:** `installGeminiCli`, `installClaudeCode`, `installCodexCli`, `installOpenCode`, `installAider`
- **Cloud, Kubernetes, IaC & DevOps CLIs:** `installKubectl`, `installHelm`, `installOpenTofu`, `installTerraform`, `installAwsCli`, `installGcloudCli`, `installAzureCli`, `installAzureDevopsCli`, `installGithubCli`, `installJiraCli`, `installUpctl`, `installPlaywrightChromium`

---

## Named Multi-Box Profiles (`-Profile <name>`)

Run multiple independent, isolated sandboxes side-by-side—each with its own WSL distribution, VHDX directory, and deterministic high UID in `26100..26998` so per-UID `nftables` rules never collide:

- Create an optional `box.<profile>.json` (or `profiles/<profile>.json`) override file, or pass `-Profile <name>` directly to any command:
  ```powershell
  .\box.ps1 init -Profile untrusted
  .\box.ps1 shell -Profile untrusted
  .\box.ps1 apply -Profile untrusted
  ```
- Run `.\box.ps1 list` to inspect all configured sandbox profiles, resolved distro names, UIDs, and WSL states.
