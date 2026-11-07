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

**Hide-Go** sits on `127.0.0.1:18787` between your local coding tools and cloud LLM providers. It compiles into a single ~9MB Rust binary (Windows, macOS, and Linux) with the desktop UI embedded directly inside the executable. Before a request leaves your machine, Hide-Go swaps real secrets and proprietary code identifiers for format-preserving decoys or cover-domain code. When the upstream SSE stream comes back, a sliding-window restorer swaps your real names back in on the fly.

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
| **2. Auto Desensitize** | Daily coding when you want secrets and internal network topology stripped | Real DB URLs, API keys, private IPs, file paths | **Format-valid fake tokens** (`10.254.0.2`, `sk-sem-0001`), restored locally on stream return |
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
// [BotanicalSensor-01] Calibrate greenhouse soil humidity
// Path: /workspace/sandbox_proj/src/module_01.rs
pub fn check_orchid_soil_moisture(
    terrarium_sensor_id: &str,
) -> bool {
    let db = "postgres://db_user_01:pass_01@10.254.0.2:5432/app_01";
    let key = "sk-sem-placeholder-key-0001";
    compute_foliage_hydration_index(terrarium_sensor_id, db, key)
}
```

</td>
</tr>
</table>

> **Why can the model still write working code?**
> Language keywords (`pub`, `fn`, `let`, `bool`), types, and call graphs stay intact. The model analyzes the control flow of `check_orchid_soil_moisture` and streams back its fix. As chunks arrive over SSE, `StreamRestorer` reassembles tokens split across packet boundaries and translates `check_orchid_soil_moisture` back to `verify_margin_liquidation` before your harness ever renders the diff.

---

## Inside All-Hide: three independent switches

You can mix and match these three sub-modes inside the All-Hide configuration panel:

* 🌱 **Isomorphic Camouflage**: Hashes your function names, structs, variables, and inline comments with a project salt into one of three built-in cover vocabularies (`Botanical Garden`, `Library Catalog`, or `Bakery Recipe`).
* ⠿ **Cipher Garble**: Encodes payload blocks into reversible high-entropy Braille/XOR streams (`⟦HIDE-CIPHER::⠷⠩⡬⡺⢵⣑⡬...⟧`) so plaintext audit logs and regex scrapers on the vendor side only see gibberish.
* 🎭 **Telemetry & Indexing Chaff**: Blocking telemetry or `repo-indexing` outright causes some IDEs to throw modal errors or refuse to run. When Chaff mode catches a background upload, it feeds the vendor a synthetic decoy repo snapshot of similar size instead of dropping the connection.

---

## Supported harnesses

Hide-Go ships with request fingerprinting and dedicated local routes for 7 tools:

| Tool | Local Proxy Route | What Hide-Go watches for |
| :--- | :--- | :--- |
| **Claude Code** | `http://127.0.0.1:18787/claude-code` | `CLAUDE.md` context injection, `Read`/`Bash` tool outputs, `/api/event_logging` telemetry |
| **OpenAI Codex** | `http://127.0.0.1:18787/codex` | Sandbox file trees, shell execution logs containing secrets |
| **Antigravity** | `http://127.0.0.1:18787/antigravity` | Mounted workspace paths, cross-file context snippets |
| **ZCode** | `http://127.0.0.1:18787/zcode` | Open buffer snapshots, completion context |
| **Qoder** | `http://127.0.0.1:18787/qoder` | Background codebase vector indexing uploads |
| **Cursor** | `http://127.0.0.1:18787/cursor` | Composer multi-file context, `repo-service` chunk uploads |
| **Grok Build** | `http://127.0.0.1:18787/grok-build` | Build context bundles, internal hostnames in compiler logs |

<details>
<summary><b>📋 One-line environment setup (Bash / Zsh / PowerShell)</b></summary>

**Linux / macOS (Bash / Zsh)**
```bash
# Claude Code
export ANTHROPIC_BASE_URL="http://127.0.0.1:18787/claude-code"

# OpenAI Codex
export OPENAI_BASE_URL="http://127.0.0.1:18787/codex"

# Grok Build
export XAI_BASE_URL="http://127.0.0.1:18787/grok-build"
```

**Windows (PowerShell)**
```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:18787/claude-code"
$env:OPENAI_BASE_URL    = "http://127.0.0.1:18787/codex"
$env:XAI_BASE_URL       = "http://127.0.0.1:18787/grok-build"
```

</details>

---

## Downloads

Grab the standalone binary for your OS from the [Releases page](https://github.com/Aflydream/hide-go/releases). The compiled frontend is embedded via `include_bytes!`, so you don't need Node.js or external assets at runtime:

* **Windows (x64)**: Download and run `hide-go-desktop-windows-x64.exe`
* **macOS (Apple Silicon)**:
  ```bash
  chmod +x hide-go-desktop-macos-arm64 && ./hide-go-desktop-macos-arm64
  ```
* **Linux (x86_64)**:
  ```bash
  chmod +x hide-go-desktop-linux-x86_64 && ./hide-go-desktop-linux-x86_64
  ```

Launching the binary starts the local proxy on `127.0.0.1:18787` and opens the desktop console window. Set `HIDE_GO_HEADLESS=1` if you want to run the gateway on a headless server without spawning a window.

---

## Build from source

Prerequisites: Rust `1.80+` and Node.js `20+` (only needed when rebuilding the embedded frontend bundle).

```bash
# 1. Run unit tests (harness fingerprinting, semantic vault, isomorphic camouflage, SSE chunk boundary restoration)
cargo test --workspace

# 2. Build the frontend bundle and compile the single-file desktop executable
npm install && npm run build
cargo build --release -p hide-go-desktop
```

### Repository layout

```text
hide-go/
├── crates/hide-core/          # Core Rust library & standalone daemon
│   └── src/
│       ├── scanner.rs         # Regex & heuristic scanner for keys, DB URLs, private IPs, and paths
│       ├── vault.rs           # Thread-safe bidirectional token <-> raw secret dictionary
│       ├── desensitizer.rs    # Format-preserving semantic token generator
│       ├── all_hide.rs        # Isomorphic cover vocabularies, Braille cipher, and Chaff generator
│       ├── stream_restorer.rs # Sliding-window SSE restorer across arbitrary chunk splits
│       └── proxy.rs           # Axum reverse proxy & local harness simulator
├── src/                       # Desktop UI (4-pane diff inspector, mode studio, vault viewer)
└── src-tauri/                 # Single-binary asset embedder & native OS window launcher
```
