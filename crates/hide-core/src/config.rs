use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Supported AI Coding Harnesses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessKind {
    ClaudeCode,
    Codex,
    Antigravity,
    Zcode,
    Qoder,
    Cursor,
    GrokBuild,
    Generic,
}

impl HarnessKind {
    pub fn all() -> &'static [HarnessKind] {
        &[
            HarnessKind::ClaudeCode,
            HarnessKind::Codex,
            HarnessKind::Antigravity,
            HarnessKind::Zcode,
            HarnessKind::Qoder,
            HarnessKind::Cursor,
            HarnessKind::GrokBuild,
        ]
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            HarnessKind::ClaudeCode => "Claude Code",
            HarnessKind::Codex => "OpenAI Codex",
            HarnessKind::Antigravity => "Antigravity",
            HarnessKind::Zcode => "ZCode",
            HarnessKind::Qoder => "Qoder",
            HarnessKind::Cursor => "Cursor",
            HarnessKind::GrokBuild => "Grok Build",
            HarnessKind::Generic => "Generic Harness",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            HarnessKind::ClaudeCode => "claude-code",
            HarnessKind::Codex => "codex",
            HarnessKind::Antigravity => "antigravity",
            HarnessKind::Zcode => "zcode",
            HarnessKind::Qoder => "qoder",
            HarnessKind::Cursor => "cursor",
            HarnessKind::GrokBuild => "grok-build",
            HarnessKind::Generic => "generic",
        }
    }
}

/// Classification of incoming Harness network requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrafficCategory {
    /// Active coding conversation / agent inference
    InteractivePrompt,
    /// Background repository vector indexing / codebase upload
    CodebaseIndexing,
    /// Silent telemetry / analytics / event logging
    Telemetry,
    /// Local tool execution output returning project files or shell logs
    ToolExecutionSync,
}

/// Top-level privacy protection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyMode {
    /// Monitor & inspect project data transmission only, do not mutate payload
    AuditOnly,
    /// Reversible semantic desensitization (AI sees structure/placeholders, vendor never sees real secrets/paths/IPs)
    AutoDesensitize,
    /// Full All-Hide protection: vendor sees unreadable gibberish or completely unrelated cover story code
    AllHide,
}

/// Cover domain theme for Isomorphic Camouflage in All-Hide mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverTheme {
    /// Botanical greenhouse & soil watering management system
    BotanicalGarden,
    /// Public library book lending & shelf cataloging system
    LibraryCatalog,
    /// Artisan bakery recipe & oven temperature controller
    BakeryRecipe,
}

/// Sub-mode configuration for All-Hide mode
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AllHideConfig {
    /// Sub-mode A: Transform all identifiers, paths, comments & literals into an unrelated cover domain
    pub enable_isomorphic_camouflage: bool,
    /// Selected cover domain for isomorphic camouflage
    pub cover_theme: CoverTheme,
    /// Sub-mode B: Encode/garble payloads into unreadable cipher blocks (glyph/braille/hex cipher)
    pub enable_cipher_garble: bool,
    /// Sub-mode C: Replace background telemetry & codebase indexing uploads with fake chaff code or gibberish
    pub enable_telemetry_chaff: bool,
    /// Strictness level (true = also obfuscate string literals and comments completely)
    pub strict_literal_masking: bool,
}

impl Default for AllHideConfig {
    fn default() -> Self {
        Self {
            enable_isomorphic_camouflage: true,
            cover_theme: CoverTheme::BotanicalGarden,
            // Cipher blocks are unreadable to the model too; opt-in only.
            enable_cipher_garble: false,
            enable_telemetry_chaff: true,
            strict_literal_masking: true,
        }
    }
}

/// Category of sensitive project data detected in traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    ApiKey,
    PrivateKey,
    DatabaseUrl,
    InternalIp,
    InternalDomain,
    ProjectPath,
    EmailOrPii,
    GitMetadata,
    EnvSecret,
    CustomKeyword,
    ProprietaryCodeSymbol,
}

/// A single sensitive leak or project data transmission finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakFinding {
    pub kind: FindingKind,
    pub label: String,
    pub original_preview: String,
    pub replacement_token: String,
    pub severity: String, // "critical" | "high" | "medium" | "low"
    pub count: usize,
}

/// Custom user-defined desensitization rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub replacement_hint: String,
    pub enabled: bool,
}

/// Whether credential originals may be written back into model-issued tool calls.
/// A prompt-injected model could otherwise exfiltrate a real key by echoing its placeholder
/// into a shell command or URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ToolCallSecretPolicy {
    /// Never restore credentials inside tool-call arguments.
    Never,
    /// Restore credentials only in file-editing fields (`content`, `old_string`, `new_string`, …).
    #[default]
    FileEditsOnly,
    /// Restore credentials everywhere (legacy behaviour).
    Always,
}

/// Global runtime configuration for Hide-Go
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HideConfig {
    pub proxy_port: u16,
    pub mode: PrivacyMode,
    pub all_hide: AllHideConfig,
    pub block_silent_telemetry: bool,
    pub protect_project_paths: bool,
    pub protect_secrets_and_keys: bool,
    pub protect_internal_network: bool,
    pub project_salt: String,
    pub tool_call_secret_policy: ToolCallSecretPolicy,
    pub custom_rules: Vec<CustomRule>,
}

impl Default for HideConfig {
    fn default() -> Self {
        Self {
            proxy_port: 18787,
            mode: PrivacyMode::AutoDesensitize,
            all_hide: AllHideConfig::default(),
            block_silent_telemetry: true,
            protect_project_paths: true,
            protect_secrets_and_keys: true,
            protect_internal_network: true,
            // Per-install random salt: a public constant would let the vendor precompute the
            // camouflage mapping for common identifiers.
            project_salt: format!("hg-{}", Uuid::new_v4().simple()),
            tool_call_secret_policy: ToolCallSecretPolicy::default(),
            custom_rules: vec![
                CustomRule {
                    id: "rule-1".to_string(),
                    name: "核心项目代号 (Project Codename)".to_string(),
                    pattern: "ProjectTitan|AflyCore|QuantumPay".to_string(),
                    replacement_hint: "GreenhouseApp".to_string(),
                    enabled: true,
                },
                CustomRule {
                    id: "rule-2".to_string(),
                    name: "内部私有仓库域名".to_string(),
                    pattern: r"[a-zA-Z0-9-]+\.corp\.internal".to_string(),
                    replacement_hint: "node-01.garden.example".to_string(),
                    enabled: true,
                },
            ],
        }
    }
}

impl HideConfig {
    /// `HIDE_GO_CONFIG`, else the platform config directory (`%APPDATA%\hide-go`,
    /// `~/Library/Application Support/hide-go`, `$XDG_CONFIG_HOME/hide-go` or `~/.config/hide-go`).
    pub fn default_path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("HIDE_GO_CONFIG").filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let base = if cfg!(windows) {
            env("APPDATA")
        } else if cfg!(target_os = "macos") {
            env("HOME").map(|h| h.join("Library/Application Support"))
        } else {
            env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))
        }?;
        Some(base.join("hide-go").join("config.json"))
    }

    /// Load the saved configuration, or create one (with a fresh salt) on first run.
    /// An unreadable file is kept aside as `config.json.corrupt` instead of being overwritten silently.
    pub fn load_or_create(path: &Path) -> HideConfig {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<HideConfig>(&text) {
                Ok(cfg) => return cfg,
                Err(err) => {
                    tracing::warn!("config {} is invalid ({err}); starting from defaults", path.display());
                    let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
                }
            },
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!("cannot read config {}: {err}", path.display());
                return HideConfig::default();
            }
            Err(_) => {}
        }
        let cfg = HideConfig::default();
        if let Err(err) = cfg.save(path) {
            tracing::warn!("cannot write config {}: {err}", path.display());
        }
        cfg
    }

    /// Atomically persist the configuration.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).expect("config serializes"))?;
        std::fs::rename(&tmp, path)
    }
}

/// Recorded audit log entry for a single intercepted Harness request/response cycle.
/// Payload fields are capped (see `proxy::MAX_STORED_PAYLOAD`); `truncated` says so.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficAuditRecord {
    pub id: String,
    pub timestamp: String,
    pub harness: HarnessKind,
    pub category: TrafficCategory,
    pub method: String,
    pub endpoint: String,
    pub upstream_vendor: String,
    pub applied_mode: PrivacyMode,
    /// "passed" | "desensitized" | "strict-literal+all-hide-isomorphic…" | "chaff-injected" | "telemetry-blocked"
    pub action_taken: String,
    /// Upstream HTTP status (0 when answered locally or the connection failed).
    pub status: u16,
    pub latency_ms: u64,
    /// True for records produced by the built-in simulator, not live traffic.
    pub simulated: bool,
    /// Original payload sent by local Harness (contains real project secrets/code)
    pub local_request_payload: String,
    /// Actual payload transmitted to the cloud LLM vendor
    pub vendor_visible_payload: String,
    /// Raw response returned by the cloud LLM vendor
    pub vendor_raw_response: String,
    /// Restored response delivered back to the local Harness
    pub local_restored_response: String,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub truncated: bool,
    /// Detected sensitive project items in this request
    pub findings: Vec<LeakFinding>,
    /// Number of tokens/identifiers mapped and restored
    pub restored_count: usize,
    /// Credential placeholders deliberately left unresolved inside tool-call arguments
    pub withheld_count: usize,
}

/// Payload-free view of an audit record for list rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficAuditSummary {
    pub id: String,
    pub timestamp: String,
    pub harness: HarnessKind,
    pub category: TrafficCategory,
    pub method: String,
    pub endpoint: String,
    pub applied_mode: PrivacyMode,
    pub action_taken: String,
    pub status: u16,
    pub latency_ms: u64,
    pub simulated: bool,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub finding_count: usize,
    pub top_severity: Option<String>,
    pub restored_count: usize,
    pub withheld_count: usize,
}

impl From<&TrafficAuditRecord> for TrafficAuditSummary {
    fn from(r: &TrafficAuditRecord) -> Self {
        let rank = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            _ => 1,
        };
        Self {
            id: r.id.clone(),
            timestamp: r.timestamp.clone(),
            harness: r.harness,
            category: r.category,
            method: r.method.clone(),
            endpoint: r.endpoint.clone(),
            applied_mode: r.applied_mode,
            action_taken: r.action_taken.clone(),
            status: r.status,
            latency_ms: r.latency_ms,
            simulated: r.simulated,
            request_bytes: r.request_bytes,
            response_bytes: r.response_bytes,
            finding_count: r.findings.iter().map(|f| f.count).sum(),
            top_severity: r.findings.iter().map(|f| f.severity.clone()).max_by_key(|s| rank(s)),
            restored_count: r.restored_count,
            withheld_count: r.withheld_count,
        }
    }
}
