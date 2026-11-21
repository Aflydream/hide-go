# Changelog

All notable changes to Hide-Go are documented in this file.

## [0.2.2] - 2026-11-21

### Changed
- Split `Hide-Go-Setup` into compressed platform archives (`.zip` on Windows, `.tar.gz` on macOS and Linux) with separate `payload/` binaries verified via `payload-manifest.json` SHA-256 digests instead of embedding `hide-go-desktop` and `hide-go-daemon` inside a single executable
- Publish Setup archives only on GitHub Releases rather than attaching separate standalone desktop binaries
- Strip symbols and enable thin LTO in release builds (`[profile.release]`), and drop unused `cdylib`/`staticlib` outputs from `hide-go-desktop`

## [0.2.1] - 2026-11-21

### Added
- Bilingual interface support (`zh-CN` and `en`) backed by externalized locale files (`src/locales/*.json`) across the desktop console and `hide-go-setup` installer/uninstaller
- Automatic OS system language detection on Windows, macOS, and Linux, defaulting to English for non-Chinese locales
- Console **Settings** view for switching language (`system`, `zh-CN`, `en`), choosing light/dark appearance, and viewing gateway version, listen address, and config path
- Installer language selector and localized native window/folder-picker titles, persisting the chosen `language` to `config.json` for the desktop app

### Changed
- Memoized frontend log/harness aggregations and added timer and unmount cleanup across polling hooks, toasts, and copy buttons
- Deduplicated canonical path comparisons in `hide-setup` into a shared `same_path` helper

## [0.2.0] - 2026-11-20

### Added
- Self-contained `hide-go-setup` installer and uninstaller wizard with directory selection, shortcuts, `PATH` setup, autostart, harness auto-connect, and `--silent` CLI mode
- Frameless native WebView window shell (`hide-chrome`) for the desktop console and installer, with browser fallback when WebView is unavailable
- Selective `HTTPS CONNECT` TLS inspection and local Root CA management (`/api/ca/*`) for AI API hosts, with raw TCP passthrough for OAuth and non-AI origins
- Automatic local detection, one-click configuration, and reversible backups (`/api/harnesses/*`) for Claude Code, Codex, Antigravity, ZCode, Qoder, Cursor, and Grok Build
- HTTP/2 (`h2` ALPN), WebSocket (`wss://`) passthrough, `multipart/form-data` binary RPC passthrough, and bounded `gzip`/`deflate` payload decompression
- Light and dark theme toggle (`color-scheme`) and native `<dialog>` modals in the desktop console

### Changed
- Scope `PrivacyVault` placeholder mappings per vendor domain with cached Aho-Corasick matchers so cross-vendor traffic cannot probe another vendor's tokens
- Replace `'unsafe-inline'` in `script-src` with per-request CSP nonces across desktop and installer HTML responses
- Allow operator-configured upstreams (`HIDE_GO_UPSTREAM_URL` and `harness_upstreams`) on private RFC1918 LAN addresses while blocking cloud metadata endpoints and proxy self-loops
- Write `config.json`, CA keys, and harness backups atomically with restricted user-only file permissions
- Guard managed shell and PowerShell proxy scripts with a local TCP port check so closing Hide-Go does not break terminal networking

### Fixed
- Preserve Gemini `thoughtSignature` / `thought_signature` fields and stop coercing JSON booleans or short strings (`< 6` chars) under `token` keys into secret placeholders
- Handle single-newline `data: [DONE]` at SSE EOF and fall back to text restoration when `max_tokens` truncates a tool-call JSON fragment mid-stream
- Restore OpenAI Responses `response.reasoning_summary_text.delta` and `response.refusal.delta` SSE events, and enforce `ToolCallSecretPolicy` on custom tool, MCP, and nested JSON arguments
- Skip English contractions in quoted-literal scanning and narrow internal placeholder prefix checks (`svc-node-`) to avoid false-positive literal masking
- Preserve upstream `Access-Control-*` and non-session `Set-Cookie` headers across proxy responses

## [0.1.1] - 2026-11-13

### Added
- Standalone `hide-go-desktop` binary serving compile-time embedded UI assets on `127.0.0.1` without Tauri
- `ToolCallSecretPolicy` to keep credential placeholders masked inside tool-call commands
- Protocol-aware SSE stream restorer for OpenAI Chat/Responses, Anthropic Messages, and Gemini candidates
- Console views for policy configuration, custom rules, traffic diffs, vault inspection, and harness setup
- `.sha256` checksum files for all Windows, macOS, and Linux release binaries

### Changed
- Default `project_salt` is now randomly generated per install instead of using a static string
- Management endpoints (`/api/*`) require loopback origin checks and `X-Hide-Go-Token` or Bearer auth rather than cookies
- Proxy fails closed on compressed or non-UTF-8 request bodies and malformed SSE streams
- Harness setup snippets configure reverse-proxy routes without `HTTP_PROXY` or `HTTPS_PROXY` flags

### Fixed
- Ignore type annotations (such as `String` or `Option<String>`) in unquoted env-secret scans while still matching quoted secrets with spaces
- Preserve API tool schemas, tool names, and signed `thinking` blocks during desensitization and token resealing
- Prevent double-masking `C:\workspace\user_*` placeholder paths
- Route Gemini SSE text chunks per part index so multiple text parts in one candidate restore independently
- Record audit logs for rejected requests and aborted SSE streams, and avoid writing ephemeral `HIDE_GO_PORT` overrides back to `config.json`
- Match JSON-escaped vault tokens in the Traffic diff viewer and preserve latest rule toggles across async validation
