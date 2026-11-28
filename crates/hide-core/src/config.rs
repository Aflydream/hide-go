use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    Pi,
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
            HarnessKind::Pi,
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
            HarnessKind::Pi => "Pi",
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
            HarnessKind::Pi => "pi",
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

pub const MIN_UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 30;
pub const MAX_UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 3600;
pub const DEFAULT_UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 900;

pub const MIN_GUARD_THRESHOLD: f32 = 0.50;
pub const MAX_GUARD_THRESHOLD: f32 = 0.95;
pub const DEFAULT_GUARD_THRESHOLD: f32 = 0.80;

fn default_allowed_connect_ports() -> Vec<u16> {
    vec![443, 8443]
}

fn default_upstream_idle_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_IDLE_TIMEOUT_SECS
}

fn default_auto_check_updates() -> bool {
    true
}

fn default_protect_personal_info() -> bool {
    true
}

fn default_guard_model_enabled() -> bool {
    true
}

fn default_guard_threshold() -> f32 {
    DEFAULT_GUARD_THRESHOLD
}

/// Interface language preference persisted in `config.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UiLanguage {
    #[default]
    #[serde(rename = "system")]
    System,
    #[serde(rename = "zh-CN")]
    ZhCn,
    #[serde(rename = "en")]
    En,
}

impl UiLanguage {
    pub fn resolve(&self, system_locale: &'static str) -> &'static str {
        match self {
            UiLanguage::System => system_locale,
            UiLanguage::ZhCn => "zh-CN",
            UiLanguage::En => "en",
        }
    }
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
    #[serde(default = "default_protect_personal_info")]
    pub protect_personal_info: bool,
    #[serde(default = "default_guard_model_enabled")]
    pub guard_model_enabled: bool,
    #[serde(default = "default_guard_threshold")]
    pub guard_threshold: f32,
    pub project_salt: String,
    pub tool_call_secret_policy: ToolCallSecretPolicy,
    pub custom_rules: Vec<CustomRule>,
    #[serde(default)]
    pub language: UiLanguage,
    #[serde(default)]
    pub mitm_extra_hosts: Vec<String>,
    #[serde(default)]
    pub mitm_bypass_hosts: Vec<String>,
    #[serde(default = "default_allowed_connect_ports")]
    pub allowed_connect_ports: Vec<u16>,
    #[serde(default)]
    pub allowed_loopback_proxy_targets: Vec<String>,
    #[serde(default = "default_upstream_idle_timeout_secs")]
    pub upstream_idle_timeout_secs: u64,
    #[serde(default)]
    pub auto_trust_ca: bool,
    #[serde(default = "default_auto_check_updates")]
    pub auto_check_updates: bool,
    #[serde(default)]
    pub system_proxy_chain: bool,
    #[serde(default)]
    pub harness_upstreams: HashMap<String, String>,
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
            protect_personal_info: default_protect_personal_info(),
            guard_model_enabled: default_guard_model_enabled(),
            guard_threshold: default_guard_threshold(),
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
            language: UiLanguage::default(),
            mitm_extra_hosts: Vec::new(),
            mitm_bypass_hosts: Vec::new(),
            allowed_connect_ports: default_allowed_connect_ports(),
            allowed_loopback_proxy_targets: Vec::new(),
            upstream_idle_timeout_secs: default_upstream_idle_timeout_secs(),
            auto_trust_ca: false,
            auto_check_updates: default_auto_check_updates(),
            system_proxy_chain: false,
            harness_upstreams: HashMap::new(),
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
            Ok(text) => match serde_json::from_str::<HideConfig>(text.trim_start_matches('\u{feff}')) {
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

    /// Atomically persist the configuration with private file permissions and serialized locking.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        static CONFIG_SAVE_LOCK: once_cell::sync::Lazy<parking_lot::Mutex<()>> =
            once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(()));
        let _guard = CONFIG_SAVE_LOCK.lock();
        let data = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        crate::ca::atomic_write_private_file(path, &data).map_err(std::io::Error::other)?;
        if let Some(dir) = path.parent() {
            if dir.file_name().is_some_and(|n| n.eq_ignore_ascii_case("hide-go")) {
                let _ = crate::ca::harden_private_dir_permissions(dir);
            }
        }
        Ok(())
    }

    /// Upstream read-idle timeout safely clamped to `[30s, 3600s]`.
    pub fn effective_upstream_idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.upstream_idle_timeout_secs
                .clamp(MIN_UPSTREAM_IDLE_TIMEOUT_SECS, MAX_UPSTREAM_IDLE_TIMEOUT_SECS),
        )
    }

    /// Calibrated guard-model confidence threshold clamped to `[0.50, 0.95]`.
    pub fn effective_guard_threshold(&self) -> f32 {
        if self.guard_threshold.is_finite() {
            self.guard_threshold.clamp(MIN_GUARD_THRESHOLD, MAX_GUARD_THRESHOLD)
        } else {
            DEFAULT_GUARD_THRESHOLD
        }
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
    /// Exact functional purpose classification for this request.
    #[serde(default)]
    pub purpose: crate::audit::RequestPurpose,
    /// Calibrated classifier confidence (`0.0..=1.0`).
    #[serde(default)]
    pub purpose_confidence: f32,
    /// Concise detail describing why this request received its purpose classification.
    #[serde(default)]
    pub purpose_detail: String,
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
    /// Telemetry and bulk-upload audit signals detected for this request
    #[serde(default)]
    pub audit_signals: Vec<crate::audit::AuditSignal>,
    /// Number of tokens/identifiers mapped and restored
    pub restored_count: usize,
    /// Credential placeholders deliberately left unresolved inside tool-call arguments
    pub withheld_count: usize,
    /// Originating local process (or companion process) attributed via TCP socket ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_process: Option<String>,
}

/// Payload-free view of an audit record for list rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficAuditSummary {
    pub id: String,
    pub timestamp: String,
    pub harness: HarnessKind,
    pub category: TrafficCategory,
    /// Exact functional purpose classification for this request.
    #[serde(default)]
    pub purpose: crate::audit::RequestPurpose,
    /// Calibrated classifier confidence (`0.0..=1.0`).
    #[serde(default)]
    pub purpose_confidence: f32,
    /// Concise detail describing why this request received its purpose classification.
    #[serde(default)]
    pub purpose_detail: String,
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
    #[serde(default)]
    pub audit_signals: Vec<crate::audit::AuditSignal>,
    pub restored_count: usize,
    pub withheld_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_process: Option<String>,
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
            purpose: r.purpose,
            purpose_confidence: r.purpose_confidence,
            purpose_detail: r.purpose_detail.clone(),
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
            audit_signals: r.audit_signals.clone(),
            restored_count: r.restored_count,
            withheld_count: r.withheld_count,
            client_process: r.client_process.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_legacy_deserialization_apply_compat_fields() {
        let cfg = HideConfig::default();
        assert_eq!(cfg.allowed_connect_ports, vec![443, 8443]);
        assert!(cfg.allowed_loopback_proxy_targets.is_empty());
        assert_eq!(cfg.upstream_idle_timeout_secs, 900);
        assert_eq!(
            cfg.effective_upstream_idle_timeout(),
            std::time::Duration::from_secs(900)
        );

        let legacy: HideConfig = serde_json::from_str(r#"{"proxyPort": 18787}"#).unwrap();
        assert_eq!(legacy.allowed_connect_ports, vec![443, 8443]);
        assert!(legacy.allowed_loopback_proxy_targets.is_empty());
        assert_eq!(legacy.upstream_idle_timeout_secs, 900);
    }

    #[test]
    fn upstream_idle_timeout_is_clamped_to_safe_bounds() {
        let mut cfg = HideConfig::default();
        cfg.upstream_idle_timeout_secs = 0;
        assert_eq!(
            cfg.effective_upstream_idle_timeout(),
            std::time::Duration::from_secs(30)
        );
        cfg.upstream_idle_timeout_secs = 15;
        assert_eq!(
            cfg.effective_upstream_idle_timeout(),
            std::time::Duration::from_secs(30)
        );
        cfg.upstream_idle_timeout_secs = 99_999;
        assert_eq!(
            cfg.effective_upstream_idle_timeout(),
            std::time::Duration::from_secs(3600)
        );
    }

    #[test]
    fn ui_language_roundtrips_and_defaults_legacy_config_to_system() {
        let legacy: HideConfig = serde_json::from_str(r#"{"proxyPort": 18787}"#).unwrap();
        assert_eq!(legacy.language, UiLanguage::System);
        assert_eq!(legacy.language.resolve("en"), "en");
        assert_eq!(legacy.language.resolve("zh-CN"), "zh-CN");

        for (lang, expected_json) in [
            (UiLanguage::System, r#""system""#),
            (UiLanguage::ZhCn, r#""zh-CN""#),
            (UiLanguage::En, r#""en""#),
        ] {
            let encoded = serde_json::to_string(&lang).unwrap();
            assert_eq!(encoded, expected_json);
            let decoded: UiLanguage = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, lang);
        }
        assert_eq!(UiLanguage::ZhCn.resolve("en"), "zh-CN");
        assert_eq!(UiLanguage::En.resolve("zh-CN"), "en");
    }
}
