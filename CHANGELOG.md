# Changelog

All notable changes to Hide-Go are documented in this file.

## [Unreleased]

### Added
- Audit risk engine (`audit.rs`) detecting telemetry endpoints and payloads, archive/multipart packaging uploads, bulk codebase syncs, oversized outbound payloads, and sensitive values inside telemetry or bulk uploads across HTTP, MITM, and raw `CONNECT` passthrough tunnels
- Per-harness audit summary (`telemetryDetected`, `bulkUploadDetected`, `harnessAudit`) in `GET /api/status`, host risk tags (`telemetry` / `upload-storage`) in `GET /api/mitm/hosts`, and compact Traffic audit strip, signal badges, and telemetry/bulk-upload filters

### Changed
- Manage reversible Windows User Environment Variables (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, and local CA bundle paths via `HKCU\Environment` + `WM_SETTINGCHANGE`) alongside WinInet when `systemProxyChain` is active, so Go/desktop language servers inherit proxy and CA settings and restore cleanly on disconnect, shutdown, console close, logoff, startup recovery, or uninstall
- Include `daily-cloudcode-pa.googleapis.com`, `autopush-cloudcode-pa.googleapis.com`, `staging-cloudcode-pa.googleapis.com`, and `jetski-webchannel.googleapis.com` in built-in AI MITM hosts and Antigravity attribution
- Preserve byte-identical JSON payloads and report `passed` when zero items are masked in `AutoDesensitize`, register Windows path separator and drive-case restoration aliases, and expand OpenAI Responses delta event coverage (`reasoning_text`, `audio_transcript`, `code_interpreter_call_code`)

### Fixed
- Restore split placeholders across Google Cloud Code `{"response":{"candidates":[...]}}` SSE streams and JSON array chunks, keeping `thought` and `text` part channels aligned on transitions
- Protect Google Cloud Code structural keys (`project`, `requestId`, `traceId`, `responseId`), Gemini `functionCall` names, and signed Gemini thought blocks (`thoughtSignature`), and stop skipping arbitrary JSON `"data"` fields during restoration
- Fix Protobuf/gRPC 3+ frame split-placeholder restoration, tighten printable submessage recursion to avoid skipping short IPs or corrupting `": sk-..."` text, clear compressed flags on compression fallback, split dotted gRPC paths for telemetry/indexing classification, and run full audit signal analysis on Protobuf and streaming RPC payloads
- Clear cached `Matcher` snapshots on `PrivacyVault::clear()`, enforce `allow_secret` on non-string JSON secrets, avoid O(N²) eviction scans, fix percent-encoded secret boundary checks, and prevent double-masking current `work/<tag>` path placeholders
- Bound desktop graceful server drain to 1.5s and install Windows console control / Unix `SIGTERM` cleanup handlers so closing Hide-Go never hangs on open streams or leaves system proxy settings behind
- Stop reporting Antigravity as configured on Windows when legacy `settings.json` proxy entries exist without `systemProxyChain` active, and refresh managed user CA environment variables immediately after trusting the local Root CA

## [0.3.0] - 2026-11-22

### Added
- Built-in update check (`GET /api/updates/check` and `auto_check_updates`, enabled by default) with Settings UI controls and sidebar badge
- Standalone single-file Windows Setup executable embedding the setup UI, locales, and SHA-256 verified runtime archive
- Native Win32 API integration for folder picker (`IFileOpenDialog`), shortcuts (`IShellLinkW`), per-user Uninstall registry entries, PE VersionInfo, and application manifests (`asInvoker`, `PerMonitorV2`, `longPathAware`)
- Optional Authenticode signing step for Windows runtime binaries and Setup executable in the release workflow
- Copyable OpenAI-compatible (`/codex/v1`) and Anthropic-compatible (`/claude-code`) Base URL endpoints and transport/CA status badges in Integrations
- Schema-less Protobuf, gRPC (`application/grpc*`), and ConnectRPC (`application/connect+proto`, `application/connect+json`) wire-format outbound desensitization and streaming inbound restoration with full-duplex bidirectional streaming, `gzip`/`deflate` frame support, cross-frame token reassembly, and HTTP/2 trailer preservation
- Reversible Windows WinInet system proxy chaining (`system_proxy_chain`) with pre-Hide-Go upstream proxy preservation and automatic restoration on disconnect, shutdown, or uninstall
- `GET /api/mitm/hosts` endpoint and compact Integrations controls for toggling system proxy chaining, managing custom `mitmExtraHosts`, inspecting recently observed `CONNECT` hosts, and surfacing MITM TLS handshake failures in Traffic logs

### Changed
- Derive outbound placeholders, cover identifiers, and cover comments from per-instance runtime keys and `project_salt`, and strip proxy metadata headers before forwarding
- Prefilter built-in detectors with a `RegexSet` and speed up vault lookups with a 256-entry root trie table and percent-encoded secret remasking
- Route outbound HTTP forwarding and `HTTPS CONNECT` / WebSocket tunnels through active environment or Windows system proxies while bypassing loopback/LAN targets and Hide-Go's own listening port
- Switch OpenAI Codex integration to Base URL reverse-proxy mode (`[model_providers.*].base_url` / `openai_base_url` and `OPENAI_BASE_URL`) without requiring Root CA trust
- Connect Antigravity via reversible system proxy chaining, IDE proxy config, and Protobuf/gRPC/REST MITM across `cloudcode-pa` and `antigravity-pa` Google API hosts
- Compact Settings layout using `Segmented` and `Switch` controls

### Fixed
- Update active `[model_providers.*].base_url` entries in `~/.codex/config.toml` even when top-level `model_provider` is omitted, and chain loopback upstreams through `harness_upstreams` and `allowed_loopback_proxy_targets`
- Stop Claude Code disconnect from writing `settings.json`'s `ANTHROPIC_BASE_URL` into `~/.hide-go/env.ps1`, and clear conflicting managed env entries on connect
- Prevent native `<dialog>` `Esc` dismissal from invoking `onClose` twice, and move `@starting-style` rules to top-level CSS
- Localize Setup launch error dialog titles via OS locale detection instead of hardcoded strings

## [0.2.4] - 2026-11-21

### Added
- Built-in secret detectors for AWS STS (`ASIA`), Google/Firebase (`AIza`), Stripe, GitLab, Slack, HuggingFace, npm, PyPI, Groq, Perplexity, Replicate, SendGrid, Aliyun (`LTAI`), Tencent Cloud (`AKID`), DingTalk/Feishu/WeCom/Discord webhooks, JWTs, `Authorization` headers, authenticated HTTP(S) URLs, and additional database/broker URI schemes
- Support for prefixed and camelCase credential keys (e.g. `GITHUB_WEBHOOK_SECRET`, `stripeWebhookSecret`), WSL2 `/mnt/<drive>/Users/...` paths, forward-slash Windows workspace paths, and Tailscale/CGNAT (`100.64.0.0/10`) private IPs
- Support for `# ` line comments and expanded Rust/TypeScript/Python/Go standard library preservation in All-Hide mode

### Changed
- Replace per-string known-secret rescans with cached, boundary-checked `Matcher::remask_secrets` and record re-masked scope secrets in audit findings
- Match `FileEditsOnly` tool-call content fields case-insensitively (`CodeContent`, `TargetContent`, `ReplacementContent`, `code_edit`, etc.) and add common file-editing tool aliases
- Use scheme-appropriate default ports in database URL placeholders and include the checked resource directory path in missing-resource startup errors

### Fixed
- Inspect the Windows reparse tag via `FindFirstFileW` so `Hide-Go-Setup` and `hide-go-desktop` run normally inside OneDrive Cloud Files and WOF-compressed folders while still blocking symlinks and NTFS junctions
- Reduce coding-agent false positives by ignoring pagination/counter/metadata keys (`nextPageToken`, `max_token`, `secretArn`, `public_key`), env templates (`$VAR`, `${VAR}`), code references (`process.env.*`), `.env.local` / `settings.local.json`, Retina asset filenames (`icon@2x.png`), invalid IPv4 octets, Windows system directories, and trailing JSON quotes after database URLs

## [0.2.3] - 2026-11-21

### Added
- Separate Desktop shortcut and Start Menu / Applications menu toggles in `Hide-Go-Setup`, along with `--no-desktop-shortcut` and `--no-start-menu` CLI flags

### Changed
- Split the application into shared dynamic libraries (`hide_engine` and `hide_chrome`), thin native launcher binaries, and an external `resources/` directory (`ui/`, `setup/`, `locales/`, `icons/`) instead of standalone executables
- Pack desktop binaries and UI assets into a SHA-256 verified `data/app.tar.gz` archive inside the Setup package, reducing the Windows installer archive to ~5.8 MB
- Record installed paths in `install-manifest.json` so uninstall removes shared libraries and empty `resources/` directories without touching unrelated files

### Fixed
- Display the Hide-Go icon on the Windows taskbar and Alt+Tab switcher instead of the default system window icon, and write explicit `,0` icon indices for `.lnk` shortcuts

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
