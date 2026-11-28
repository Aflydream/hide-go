//! Structural coexistence & redaction-conflict detection for local proxy companions.
//!
//! Distinguishes harmless/compatible local API relays (e.g. local model switchers or
//! chained loopback gateways) from conflicting local privacy/redaction proxies that
//! actively mutate outbound payloads simultaneously with Hide-Go. Detection relies on
//! structural config inspection and live payload/header redaction signatures rather than
//! static brand lists.

use crate::config::{HarnessKind, HideConfig, PrivacyMode};
use crate::harness::HarnessProfile;
use crate::runtime_monitor::{list_local_loopback_listeners, ProcessEntry, ProcessSnapshot};
use axum::http::HeaderMap;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Local loopback relay or API switcher coexisting with Hide-Go.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerRelayInfo {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// `"chained"` (cleanly chained as Hide-Go upstream) or `"overwrote-harness"` (config drift).
    pub status: String,
    #[serde(default)]
    pub affected_harnesses: Vec<HarnessKind>,
}

/// Active redaction conflict detected between Hide-Go and another local masking proxy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConflictAlert {
    pub id: String,
    pub source: String, // "peer-config" | "live-payload"
    pub peer_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub detail: String,
    pub can_stop_peer: bool,
}

/// Combined runtime health, coexistence, and restart-reminder snapshot for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeHealthResponse {
    pub running_harnesses: Vec<crate::runtime_monitor::RunningHarnessNotice>,
    pub peer_relays: Vec<PeerRelayInfo>,
    pub conflicts: Vec<ConflictAlert>,
}

/// Runtime tracker for live payload-level external redaction detections and dismissed alerts.
#[derive(Default)]
pub struct CoexistenceTracker {
    live_conflicts: RwLock<HashMap<String, ConflictAlert>>,
    dismissed_ids: RwLock<HashSet<String>>,
}

impl CoexistenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_live_conflict(&self, alert: ConflictAlert) {
        if self.dismissed_ids.read().contains(&alert.id) {
            return;
        }
        let mut map = self.live_conflicts.write();
        if map.len() >= 16 && !map.contains_key(&alert.id) {
            return;
        }
        map.insert(alert.id.clone(), alert);
    }

    pub fn dismiss(&self, id: &str) {
        self.dismissed_ids.write().insert(id.to_string());
        self.live_conflicts.write().remove(id);
    }

    pub fn clear_live_conflicts(&self) {
        self.live_conflicts.write().clear();
    }

    pub fn active_live_conflicts(&self) -> Vec<ConflictAlert> {
        let dismissed = self.dismissed_ids.read();
        self.live_conflicts
            .read()
            .values()
            .filter(|c| !dismissed.contains(&c.id))
            .cloned()
            .collect()
    }

    pub fn is_dismissed(&self, id: &str) -> bool {
        self.dismissed_ids.read().contains(id)
    }
}

/// Single-pass structural detector for third-party redaction placeholders in live payloads.
static EXTERNAL_REDACTION_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        r"\[\[(?:REDACTED|MASKED|SECRET|PII|TOKEN|API_KEY|EMAIL|PHONE|IP)[A-Z0-9_:-]{1,32}\]\]",
        r"<(?:REDACTED|MASKED|SECRET|PII)_[A-Z0-9_-]{2,32}>",
        r"\{\{(?:REDACTED|MASKED|SECRET|PII)_[A-Z0-9_-]{2,32}\}\}",
        r"\[(?:REDACTED|PII|MASKED)_(?:API_KEY|SECRET|TOKEN|EMAIL|PHONE|IP|PATH|CARD|SSN|ID)[A-Z0-9_#-]{0,16}\]",
        r"__(?:REDACTED|MASKED|PII)_[A-Z0-9_]{3,28}__",
    ])
    .expect("valid external redaction patterns")
});

static EXTERNAL_REDACTION_HEADER_PATTERNS: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        r"(?i)^x-(?:redacted|sanitized|masked|pii|dlp|privacy-proxy)",
        r"(?i)^x-[a-z0-9-]+-(?:redacted|redaction|desensitized|masked)$",
    ])
    .expect("valid external redaction header patterns")
});

static REDACTION_CONFIG_TRUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?im)(?:["']?(?:redaction|desensitize|desensitization|mask_secrets|masking|pii_masking|privacy_masking|auto_redact|scrub_secrets|dlp_enabled)["']?\s*[:=]\s*(?:true|on|"enabled"|"active"|"strict"|"redact"|"mask"))"#,
    )
    .expect("valid redaction config regex")
});

/// Inspect an incoming request's headers and text body for signs that another local privacy
/// proxy has ALREADY redacted/masked the payload before it reached Hide-Go.
pub fn detect_external_redaction_in_request(
    headers: &HeaderMap,
    body_text: Option<&str>,
    is_own_token: impl Fn(&str) -> bool,
) -> Option<String> {
    for name in headers.keys() {
        let lower = name.as_str();
        if !lower.starts_with("x-hide-go-") && EXTERNAL_REDACTION_HEADER_PATTERNS.is_match(lower) {
            return Some(format!("header `{lower}` indicates active upstream/peer redaction"));
        }
    }
    if let Some(body) = body_text {
        // Bound scan to first 32 KB on the hot path.
        let mut end = body.len().min(32 * 1024);
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        let slice = &body[..end];
        if EXTERNAL_REDACTION_PATTERNS.is_match(slice) {
            // Confirm at least one matched token is not owned by Hide-Go's own vault.
            if !is_own_token(slice) {
                return Some("payload already contains external redaction placeholders".to_string());
            }
        }
    }
    None
}

/// Structurally inspect a peer proxy's config file (JSON/TOML/YAML) to determine whether
/// active local redaction/masking is turned on.
pub fn config_text_enables_redaction(raw: &str) -> bool {
    if raw.len() > 256 * 1024 {
        return false;
    }
    if let Ok(val) = serde_json::from_str::<Value>(raw) {
        if json_enables_redaction(&val, 0) {
            return true;
        }
    }
    REDACTION_CONFIG_TRUE_RE.is_match(raw)
}

fn json_enables_redaction(val: &Value, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    let Some(map) = val.as_object() else {
        return false;
    };
    for (k, v) in map {
        let kl = k.to_ascii_lowercase();
        let is_redact_key = kl.contains("redact")
            || kl.contains("desensitiz")
            || kl.contains("masking")
            || kl.contains("pii_mask")
            || kl.contains("scrub")
            || kl == "masksecrets"
            || kl == "mask_secrets";
        if is_redact_key {
            match v {
                Value::Bool(true) => return true,
                Value::String(s)
                    if matches!(
                        s.to_ascii_lowercase().as_str(),
                        "true" | "on" | "enabled" | "active" | "strict" | "mask" | "redact"
                    ) =>
                {
                    return true;
                }
                Value::Object(inner) => {
                    if inner.get("enabled").and_then(Value::as_bool) == Some(true)
                        || inner.get("active").and_then(Value::as_bool) == Some(true)
                    {
                        return true;
                    }
                    if json_enables_redaction(v, depth + 1) {
                        return true;
                    }
                }
                _ => {}
            }
        } else if matches!(kl.as_str(), "privacy" | "proxy" | "security" | "guard" | "filter")
            && v.is_object()
            && json_enables_redaction(v, depth + 1)
        {
            return true;
        }
    }
    false
}

fn candidate_peer_config_files(proc_entry: &ProcessEntry, home_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let stem = proc_entry
        .name
        .trim()
        .to_ascii_lowercase()
        .strip_suffix(".exe")
        .unwrap_or(&proc_entry.name.trim().to_ascii_lowercase())
        .to_string();
    if stem.is_empty()
        || matches!(
            stem.as_str(),
            "svchost" | "system" | "explorer" | "chrome" | "msedge" | "firefox" | "code" | "cursor" | "antigravity"
        )
        || stem.starts_with("hide-go")
    {
        return files;
    }

    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(exe) = proc_entry.exe_path.as_deref() {
        if let Some(parent) = Path::new(exe).parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    if let Some(home) = home_dir {
        dirs.push(home.join(format!(".{stem}")));
        dirs.push(home.join(".config").join(&stem));
        #[cfg(windows)]
        if let Some(appdata) = std::env::var_os("APPDATA") {
            dirs.push(PathBuf::from(appdata).join(&stem));
        }
    }

    const CONFIG_NAMES: &[&str] = &[
        "config.json",
        "settings.json",
        "config.toml",
        "config.yaml",
        "config.yml",
    ];
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for name in CONFIG_NAMES {
            let p = dir.join(name);
            if p.is_file() {
                files.push(p);
            }
        }
    }
    files
}

fn extract_loopback_port(raw_url: &str) -> Option<u16> {
    let parsed = reqwest::Url::parse(raw_url.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_matches(['[', ']']);
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        parsed.port().filter(|&p| p > 0)
    } else {
        None
    }
}

/// Inspect local loopback proxy coexistence (chained API switchers vs conflicting redaction proxies).
pub fn inspect_coexistence(
    cfg: &HideConfig,
    profiles: &[HarnessProfile],
    snap: &ProcessSnapshot,
    tracker: &CoexistenceTracker,
) -> (Vec<PeerRelayInfo>, Vec<ConflictAlert>) {
    let own_pid = std::process::id();
    let own_port = cfg.proxy_port;
    let home_dir = if cfg!(windows) {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    };

    // Map listening local ports -> owning process entry.
    let mut port_owners: HashMap<u16, &ProcessEntry> = HashMap::new();
    for listener in list_local_loopback_listeners() {
        if listener.port == own_port || listener.pid == own_pid {
            continue;
        }
        if let Some(proc_entry) = snap.by_pid.get(&listener.pid) {
            if !proc_entry.name.to_ascii_lowercase().starts_with("hide-go") {
                port_owners.insert(listener.port, proc_entry);
            }
        }
    }

    // 1. Collect all loopback upstream ports chained behind Hide-Go.
    let mut relays_by_port: HashMap<u16, PeerRelayInfo> = HashMap::new();
    for (slug, upstream) in &cfg.harness_upstreams {
        if let Some(port) = extract_loopback_port(upstream) {
            if port == own_port {
                continue;
            }
            let owner = port_owners.get(&port).copied();
            let entry = relays_by_port.entry(port).or_insert_with(|| PeerRelayInfo {
                port,
                process_name: owner.map(|o| o.name.clone()),
                pid: owner.map(|o| o.pid),
                status: "chained".to_string(),
                affected_harnesses: Vec::new(),
            });
            let base_slug = slug.split(':').next().unwrap_or(slug);
            if let Some(kind) = crate::harness_detect::parse_harness_slug(base_slug) {
                if !entry.affected_harnesses.contains(&kind) {
                    entry.affected_harnesses.push(kind);
                }
            }
        }
    }

    // 2. Detect harness config drift where another local relay overwrote a harness Base URL.
    if let Some(home) = home_dir.as_deref() {
        let codex_url = std::fs::read_to_string(home.join(".codex").join("config.toml"))
            .ok()
            .and_then(|raw| {
                raw.lines().find_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') {
                        return None;
                    }
                    let (k, v) = trimmed.split_once('=')?;
                    let key = k.trim();
                    if matches!(key, "base_url" | "openai_base_url") {
                        Some(v.trim().trim_matches(['"', '\'']).to_string())
                    } else {
                        None
                    }
                })
            });
        let checks: Vec<(HarnessKind, Option<String>)> = vec![
            (
                HarnessKind::ClaudeCode,
                std::fs::read_to_string(home.join(".claude").join("settings.json"))
                    .ok()
                    .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                    .and_then(|v| {
                        v.pointer("/env/ANTHROPIC_BASE_URL")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    }),
            ),
            (HarnessKind::Codex, codex_url),
            (
                HarnessKind::Pi,
                std::fs::read_to_string(home.join(".pi").join("agent").join("models.json"))
                    .ok()
                    .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                    .and_then(|v| {
                        v.pointer("/providers/anthropic/baseUrl")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    }),
            ),
        ];
        for (kind, url_opt) in checks {
            let Some(url) = url_opt else { continue };
            let Some(port) = extract_loopback_port(&url) else {
                continue;
            };
            if port == own_port {
                continue;
            }
            let is_configured = profiles.iter().any(|p| p.kind == kind && p.configured);
            if !is_configured {
                let owner = port_owners.get(&port).copied();
                let entry = relays_by_port.entry(port).or_insert_with(|| PeerRelayInfo {
                    port,
                    process_name: owner.map(|o| o.name.clone()),
                    pid: owner.map(|o| o.pid),
                    status: "overwrote-harness".to_string(),
                    affected_harnesses: Vec::new(),
                });
                entry.status = "overwrote-harness".to_string();
                if !entry.affected_harnesses.contains(&kind) {
                    entry.affected_harnesses.push(kind);
                }
            }
        }
    }

    // 3. Structural conflict check: if Hide-Go is actively redacting, inspect listening peer proxies
    //    (especially those chained or sharing loopback proxy ports) for active redaction config.
    let mut conflicts = tracker.active_live_conflicts();
    if cfg.mode != PrivacyMode::AuditOnly {
        let mut seen_pids = HashSet::new();
        for (&port, &proc_entry) in &port_owners {
            if !seen_pids.insert(proc_entry.pid) {
                continue;
            }
            let cfg_files = candidate_peer_config_files(proc_entry, home_dir.as_deref());
            let mut active_redact_file: Option<PathBuf> = None;
            for path in cfg_files {
                if let Ok(raw) = std::fs::read_to_string(&path) {
                    if config_text_enables_redaction(&raw) {
                        active_redact_file = Some(path);
                        break;
                    }
                }
            }
            if let Some(cfg_file) = active_redact_file {
                let id = format!("peer-config:{}:{port}", proc_entry.pid);
                if !tracker.is_dismissed(&id) && !conflicts.iter().any(|c| c.id == id) {
                    conflicts.push(ConflictAlert {
                        id,
                        source: "peer-config".to_string(),
                        peer_name: proc_entry.name.clone(),
                        pid: Some(proc_entry.pid),
                        port: Some(port),
                        detail: format!(
                            "{} (127.0.0.1:{port}) has active local redaction enabled in {}",
                            proc_entry.name,
                            cfg_file.display()
                        ),
                        can_stop_peer: true,
                    });
                }
            }
        }
    }

    let mut relays: Vec<PeerRelayInfo> = relays_by_port.into_values().collect();
    relays.sort_by_key(|r| r.port);
    (relays, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_external_redaction_placeholders_and_headers_without_brand_lists() {
        let mut headers = HeaderMap::new();
        headers.insert("x-privacy-proxy", "active".parse().unwrap());
        assert!(detect_external_redaction_in_request(&headers, None, |_| false).is_some());

        let clean_headers = HeaderMap::new();
        let body = r#"{"messages":[{"role":"user","content":"key is [[REDACTED_API_KEY_01]]"}]}"#;
        assert!(detect_external_redaction_in_request(&clean_headers, Some(body), |_| false).is_some());

        let normal_body = r#"{"messages":[{"role":"user","content":"fn main() { println!(\"hello\"); }"}]}"#;
        assert!(detect_external_redaction_in_request(&clean_headers, Some(normal_body), |_| false).is_none());
    }

    #[test]
    fn structurally_detects_active_redaction_in_peer_proxy_configs() {
        let active_json = r#"{"proxy":{"port":8787,"redaction":{"enabled":true}}}"#;
        assert!(config_text_enables_redaction(active_json));

        let active_toml = "port = 8787\ndesensitize = true\n";
        assert!(config_text_enables_redaction(active_toml));

        let relay_only_json =
            r#"{"proxy":{"port":15721,"upstream":"https://api.anthropic.com","redaction":{"enabled":false}}}"#;
        assert!(!config_text_enables_redaction(relay_only_json));
    }
}
