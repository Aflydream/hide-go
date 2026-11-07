use serde::{Deserialize, Serialize};

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
#[serde(rename_all = "camelCase")]
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
            enable_cipher_garble: true,
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

/// Global runtime configuration for Hide-Go
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HideConfig {
    pub proxy_port: u16,
    pub mode: PrivacyMode,
    pub all_hide: AllHideConfig,
    pub block_silent_telemetry: bool,
    pub protect_project_paths: bool,
    pub protect_secrets_and_keys: bool,
    pub protect_internal_network: bool,
    pub project_salt: String,
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
            project_salt: "hide-go-quantum-salt-2026".to_string(),
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

/// Recorded audit log entry for a single intercepted Harness request/response cycle
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
    pub action_taken: String, // "passed" | "desensitized" | "all-hide-isomorphic" | "all-hide-cipher" | "chaff-injected"
    pub latency_ms: u64,
    /// Original payload sent by local Harness (contains real project secrets/code)
    pub local_request_payload: String,
    /// Actual payload transmitted to the cloud LLM vendor (desensitized, camouflaged, or unreadable gibberish)
    pub vendor_visible_payload: String,
    /// Raw response returned by the cloud LLM vendor (referencing placeholders/camouflage/cipher)
    pub vendor_raw_response: String,
    /// Restored response delivered back to the local Harness (with real project symbols/secrets seamlessly restored)
    pub local_restored_response: String,
    /// Detected sensitive project items in this request
    pub findings: Vec<LeakFinding>,
    /// Number of tokens/identifiers mapped and restored
    pub restored_count: usize,
}
