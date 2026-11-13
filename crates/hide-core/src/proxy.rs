use crate::all_hide::AllHideEngine;
use crate::config::{
    HarnessKind, HideConfig, LeakFinding, PrivacyMode, TrafficAuditRecord, TrafficAuditSummary, TrafficCategory,
};
use crate::desensitizer::SemanticDesensitizer;
use crate::harness::{detect_harness_and_category, get_all_harness_profiles, is_inference_endpoint, HarnessProfile};
use crate::restore::restore_response;
use crate::scanner::{validate_custom_rules, ProjectScanner};
use crate::sse_restorer::SseRestorer;
use crate::vault::{mask_preview, PrivacyVault, VaultEntry};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use chrono::Local;
use futures_util::StreamExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const MAX_AUDIT_LOGS: usize = 200;
/// Each stored payload is capped so 200 records stay within a few tens of MB.
pub const MAX_STORED_PAYLOAD: usize = 64 * 1024;
/// Request bodies above this are rejected (413). Long agent sessions with images fit easily.
pub const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Maximum silence between two upstream body reads. Long generations keep streaming, so
/// there is deliberately no total deadline.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Lifetime counters (survive the 200-record log window).
#[derive(Debug, Default)]
pub struct GatewayStats {
    pub requests: AtomicU64,
    pub findings: AtomicU64,
    pub restored: AtomicU64,
    pub withheld: AtomicU64,
    pub blocked: AtomicU64,
}

/// Shared application state for the Hide-Go gateway
#[derive(Clone)]
pub struct GatewayState {
    pub config: Arc<RwLock<HideConfig>>,
    pub config_path: Option<Arc<PathBuf>>,
    pub vault: PrivacyVault,
    pub audit_logs: Arc<RwLock<VecDeque<TrafficAuditRecord>>>,
    pub stats: Arc<GatewayStats>,
    pub http_client: reqwest::Client,
    pub local_http_client: reqwest::Client,
    pub admin_token: Arc<String>,
    pub started_at: Instant,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self::new(HideConfig::default())
    }
}

fn build_client(local: bool) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_IDLE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if local {
        b = b.no_proxy();
    }
    b.build().unwrap_or_default()
}

impl GatewayState {
    pub fn new(config: HideConfig) -> Self {
        let admin_token = std::env::var("HIDE_GO_ADMIN_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));
        Self {
            config: Arc::new(RwLock::new(config)),
            config_path: None,
            vault: PrivacyVault::new(),
            audit_logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOGS))),
            stats: Arc::new(GatewayStats::default()),
            http_client: build_client(false),
            local_http_client: build_client(true),
            admin_token: Arc::new(admin_token),
            started_at: Instant::now(),
        }
    }

    /// Load (or create) the persisted configuration and keep saving changes to it.
    pub fn with_persisted_config(path: PathBuf) -> Self {
        let mut state = Self::new(HideConfig::load_or_create(&path));
        state.config_path = Some(Arc::new(path));
        state
    }

    pub fn with_admin_token(config: HideConfig, token: impl Into<String>) -> Self {
        let mut s = Self::new(config);
        s.admin_token = Arc::new(token.into());
        s
    }

    pub fn admin_token(&self) -> &str {
        &self.admin_token
    }

    pub fn push_record(&self, record: TrafficAuditRecord) {
        if !record.simulated {
            self.stats.requests.fetch_add(1, Ordering::Relaxed);
            self.stats
                .findings
                .fetch_add(record.findings.iter().map(|f| f.count as u64).sum(), Ordering::Relaxed);
            self.stats
                .restored
                .fetch_add(record.restored_count as u64, Ordering::Relaxed);
            self.stats
                .withheld
                .fetch_add(record.withheld_count as u64, Ordering::Relaxed);
            if matches!(record.action_taken.as_str(), "chaff-injected" | "telemetry-blocked") {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut logs = self.audit_logs.write();
        logs.push_front(record);
        while logs.len() > MAX_AUDIT_LOGS {
            logs.pop_back();
        }
    }

    pub fn get_records(&self) -> Vec<TrafficAuditRecord> {
        self.audit_logs.read().iter().cloned().collect()
    }

    pub fn get_summaries(&self) -> Vec<TrafficAuditSummary> {
        self.audit_logs.read().iter().map(TrafficAuditSummary::from).collect()
    }

    pub fn get_record(&self, id: &str) -> Option<TrafficAuditRecord> {
        self.audit_logs.read().iter().find(|r| r.id == id).cloned()
    }

    pub fn clear_records(&self) {
        self.audit_logs.write().clear();
    }

    pub fn get_config(&self) -> HideConfig {
        self.config.read().clone()
    }

    /// Validate, apply and persist a configuration. Invalid custom rules are rejected rather
    /// than silently skipped at scan time.
    pub fn try_update_config(&self, next: HideConfig) -> Result<HideConfig, String> {
        validate_custom_rules(&next.custom_rules)?;
        if next.project_salt.trim().len() < 8 {
            return Err("项目 Salt 至少需要 8 个字符".to_string());
        }
        *self.config.write() = next.clone();
        if let Some(path) = &self.config_path {
            next.save(path)
                .map_err(|e| format!("配置已生效，但写入 {} 失败：{e}", path.display()))?;
        }
        Ok(next)
    }

    pub fn update_config(&self, next: HideConfig) -> HideConfig {
        match self.try_update_config(next.clone()) {
            Ok(cfg) => cfg,
            Err(err) => {
                tracing::warn!("config update: {err}");
                self.get_config()
            }
        }
    }

    pub fn get_harness_profiles(&self) -> Vec<HarnessProfile> {
        let port = self.config.read().proxy_port;
        let logs = self.audit_logs.read();
        let mut profiles = get_all_harness_profiles(port);
        for p in &mut profiles {
            p.detected_active = logs.iter().any(|r| r.harness == p.kind && !r.simulated);
        }
        profiles
    }

    pub fn get_vault_entries(&self) -> Vec<VaultEntry> {
        self.vault.list_entries()
    }

    pub fn clear_vault(&self) {
        self.vault.clear();
    }

    /// Outbound transformation step shared by live proxy forwarding and simulation
    pub fn transform_outbound_payload(
        &self,
        category: TrafficCategory,
        raw_request: &str,
        cfg: &HideConfig,
    ) -> (String, String, Vec<LeakFinding>) {
        transform_outbound(&self.vault, category, raw_request, cfg)
    }

    /// Simulation pipeline used by the desktop console. Never touches the network.
    pub fn process_payload_cycle(
        &self,
        harness: HarnessKind,
        category: TrafficCategory,
        method: &str,
        endpoint: &str,
        raw_request: &str,
        cfg: &HideConfig,
    ) -> TrafficAuditRecord {
        let start = Instant::now();
        let (vendor_visible_payload, action_taken, findings) =
            self.transform_outbound_payload(category, raw_request, cfg);
        let vendor_raw_response =
            Self::synthesize_vendor_llm_response(harness, category, &vendor_visible_payload, &action_taken);
        let (restored, restored_count, withheld) = if cfg.mode == PrivacyMode::AuditOnly {
            (vendor_raw_response.clone(), 0, 0)
        } else {
            restore_response(&self.vault.matcher(), &vendor_raw_response, cfg.tool_call_secret_policy)
        };
        build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: endpoint.to_string(),
            mode: cfg.mode,
            action_taken,
            status: 200,
            start,
            simulated: true,
            local_request: raw_request,
            vendor_request: &vendor_visible_payload,
            vendor_response: &vendor_raw_response,
            local_response: &restored,
            findings,
            restored_count,
            withheld_count: withheld,
        })
    }

    pub fn simulate_traffic(
        &self,
        harness: HarnessKind,
        category: TrafficCategory,
        custom_payload: Option<String>,
    ) -> TrafficAuditRecord {
        let cfg = self.get_config();
        let endpoint = match (harness, category) {
            (HarnessKind::ClaudeCode, TrafficCategory::Telemetry) => "/claude-code/api/event_logging/batch",
            (HarnessKind::ClaudeCode, _) => "/claude-code/v1/messages",
            (HarnessKind::Codex, _) => "/codex/v1/responses",
            (HarnessKind::Antigravity, _) => "/antigravity/v1beta/models/gemini-2.5-pro:streamGenerateContent",
            (HarnessKind::Zcode, _) => "/zcode/v1/chat/completions",
            (HarnessKind::Qoder, TrafficCategory::CodebaseIndexing) => "/qoder/v1/codebase/index-sync",
            (HarnessKind::Qoder, _) => "/qoder/v1/chat/completions",
            (HarnessKind::Cursor, TrafficCategory::CodebaseIndexing) => "/cursor/repo-service/upload-chunks",
            (HarnessKind::Cursor, _) => "/cursor/v1/chat/completions",
            (HarnessKind::GrokBuild, _) => "/grok-build/v1/chat/completions",
            (HarnessKind::Generic, _) => "/v1/chat/completions",
        };
        let sample = custom_payload
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| Self::default_sample_payload(harness, category));
        let record = self.process_payload_cycle(harness, category, "POST", endpoint, &sample, &cfg);
        self.push_record(record.clone());
        record
    }

    pub fn vendor_for_harness(harness: HarnessKind) -> &'static str {
        match harness {
            HarnessKind::ClaudeCode => "Anthropic (api.anthropic.com)",
            HarnessKind::Codex => "OpenAI (api.openai.com)",
            HarnessKind::Antigravity => "Google Gemini (generativelanguage.googleapis.com)",
            HarnessKind::Zcode => "ZCode (api.zcode.ai)",
            HarnessKind::Qoder => "Qoder (api.qoder.com)",
            HarnessKind::Cursor => "Cursor (api2.cursor.sh)",
            HarnessKind::GrokBuild => "xAI (api.x.ai)",
            HarnessKind::Generic => "Upstream LLM Provider",
        }
    }

    pub fn default_upstream_for_harness(harness: HarnessKind) -> &'static str {
        match harness {
            HarnessKind::ClaudeCode => "https://api.anthropic.com",
            HarnessKind::Codex => "https://api.openai.com",
            HarnessKind::Antigravity => "https://generativelanguage.googleapis.com",
            HarnessKind::Zcode => "https://api.zcode.ai",
            HarnessKind::Qoder => "https://api.qoder.com",
            HarnessKind::Cursor => "https://api2.cursor.sh",
            HarnessKind::GrokBuild => "https://api.x.ai",
            HarnessKind::Generic => "https://api.openai.com",
        }
    }

    fn default_sample_payload(harness: HarnessKind, category: TrafficCategory) -> String {
        match category {
            TrafficCategory::Telemetry => serde_json::json!({
                "harness": harness.slug(),
                "event": "workspace_session_heartbeat",
                "git_remote": "git@gitlab.corp.internal:ProjectTitan/quantum-settlement.git",
                "cwd": "/home/alice/ProjectTitan/src/settlement_engine.rs",
                "user_email": "alice.chen@aflycore.internal",
                "env_snapshot": {
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                    "STRIPE_SECRET_KEY": "sk-live-99887766554433221100aabbccddeeff"
                }
            })
            .to_string(),
            TrafficCategory::CodebaseIndexing => serde_json::json!({
                "harness": harness.slug(),
                "operation": "vector_index_upload",
                "repository": "ProjectTitan",
                "files": [{
                    "path": "/home/alice/ProjectTitan/src/quantum_ledger.rs",
                    "content": "// Core ProjectTitan HFT Margin Liquidation Algorithm\npub async fn execute_margin_liquidation(account_id: &str, db_url: &str) -> Result<u64, String> {\n    let conn = \"postgres://titan_admin:SuperSecretPass99@10.18.44.12:5432/titan_prod\";\n    verify_signature_token(account_id, \"sk-ant-api03-secretkey998877665544332211\")\n}"
                }]
            })
            .to_string(),
            _ => serde_json::to_string_pretty(&serde_json::json!({
                "model": "claude-sonnet-4-5",
                "max_tokens": 4096,
                "system": "Workspace root: /home/alice/ProjectTitan/fintech-core (host: build-node.corp.internal)",
                "messages": [{
                    "role": "user",
                    "content": "请帮我检查这段核心清算代码的重入漏洞：\n// ProjectTitan high-frequency settlement check\npub fn verify_margin_settlement(wallet_secret: &str) -> bool {\n    let db_conn = \"postgres://admin:ProdVaultPass2026@192.168.10.88:5432/quantum_ledger\";\n    let api_key = \"sk-proj-TitanSecretKey889900112233445566\";\n    let node_host = \"vault-primary.corp.internal\";\n    calculate_liquidation_ratio(wallet_secret, db_conn, api_key, node_host)\n}"
                }]
            }))
            .unwrap(),
        }
    }

    /// Local stand-in for a vendor response used by the simulator.
    pub fn synthesize_vendor_llm_response(
        harness: HarnessKind,
        category: TrafficCategory,
        vendor_visible_payload: &str,
        action_taken: &str,
    ) -> String {
        if action_taken == "chaff-injected"
            || action_taken == "telemetry-blocked"
            || matches!(category, TrafficCategory::Telemetry | TrafficCategory::CodebaseIndexing)
        {
            return serde_json::json!({"status": "ok", "accepted": true}).to_string();
        }
        let reply_text = format!(
            "已基于上下文完成分析，修复后的实现如下：\n\n```rust\n{}\n```",
            extract_readable_snippet(vendor_visible_payload)
        );
        serde_json::json!({
            "id": "msg_hidego_simulated",
            "type": "message",
            "role": "assistant",
            "model": harness.slug(),
            "content": [{"type": "text", "text": reply_text}],
            "stop_reason": "end_turn"
        })
        .to_string()
    }
}

/// Mode dispatch shared by the live proxy and the simulator.
pub fn transform_outbound(
    vault: &PrivacyVault,
    category: TrafficCategory,
    raw_request: &str,
    cfg: &HideConfig,
) -> (String, String, Vec<LeakFinding>) {
    match cfg.mode {
        PrivacyMode::AuditOnly => {
            let findings = ProjectScanner::scan_matches(raw_request, cfg)
                .into_iter()
                .map(|(kind, label, raw_val, severity)| LeakFinding {
                    kind,
                    label,
                    original_preview: mask_preview(&raw_val),
                    replacement_token: "未脱敏（仅审计）".to_string(),
                    severity,
                    count: 1,
                })
                .collect();
            (raw_request.to_string(), "passed".to_string(), findings)
        }
        PrivacyMode::AutoDesensitize => {
            let res = SemanticDesensitizer::process(raw_request, cfg, vault);
            (res.transformed_payload, "desensitized".to_string(), res.findings)
        }
        PrivacyMode::AllHide => {
            let out = AllHideEngine::process(raw_request, category, cfg, vault);
            (out.vendor_payload, out.action_taken, out.findings)
        }
    }
}

/// Telemetry is answered locally when the user asked for it to be blocked, in any
/// protecting mode. Inference endpoints are never classified as telemetry.
fn should_block_telemetry(category: TrafficCategory, path: &str, cfg: &HideConfig) -> bool {
    category == TrafficCategory::Telemetry
        && !is_inference_endpoint(path)
        && match cfg.mode {
            PrivacyMode::AuditOnly => false,
            PrivacyMode::AutoDesensitize => cfg.block_silent_telemetry,
            PrivacyMode::AllHide => cfg.block_silent_telemetry || cfg.all_hide.enable_telemetry_chaff,
        }
}

fn extract_readable_snippet(payload: &str) -> String {
    if let Ok(val) = serde_json::from_str::<Value>(payload) {
        if let Some(msgs) = val.get("messages").and_then(|m| m.as_array()) {
            let parts: Vec<String> = msgs
                .iter()
                .filter_map(|m| m.get("content"))
                .flat_map(|c| match c {
                    Value::String(s) => vec![s.clone()],
                    Value::Array(blocks) => blocks
                        .iter()
                        .filter_map(|b| b.get("text").and_then(Value::as_str).map(str::to_owned))
                        .collect(),
                    _ => vec![],
                })
                .collect();
            if !parts.is_empty() {
                return parts.join("\n");
            }
        }
    }
    payload.to_string()
}

fn cap_payload(text: &str, truncated: &mut bool) -> String {
    if text.len() <= MAX_STORED_PAYLOAD {
        return text.to_string();
    }
    *truncated = true;
    let mut end = MAX_STORED_PAYLOAD;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\n… [已截断，原始长度 {} 字节]", &text[..end], text.len())
}

struct RecordInput<'a> {
    harness: HarnessKind,
    category: TrafficCategory,
    method: String,
    endpoint: String,
    mode: PrivacyMode,
    action_taken: String,
    status: u16,
    start: Instant,
    simulated: bool,
    local_request: &'a str,
    vendor_request: &'a str,
    vendor_response: &'a str,
    local_response: &'a str,
    findings: Vec<LeakFinding>,
    restored_count: usize,
    withheld_count: usize,
}

fn build_record(i: RecordInput) -> TrafficAuditRecord {
    let mut truncated = false;
    TrafficAuditRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
        harness: i.harness,
        category: i.category,
        method: i.method,
        endpoint: i.endpoint,
        upstream_vendor: GatewayState::vendor_for_harness(i.harness).to_string(),
        applied_mode: i.mode,
        action_taken: i.action_taken,
        status: i.status,
        latency_ms: i.start.elapsed().as_millis().max(1) as u64,
        simulated: i.simulated,
        request_bytes: i.local_request.len(),
        response_bytes: i.local_response.len(),
        local_request_payload: cap_payload(i.local_request, &mut truncated),
        vendor_visible_payload: cap_payload(i.vendor_request, &mut truncated),
        vendor_raw_response: cap_payload(i.vendor_response, &mut truncated),
        local_restored_response: cap_payload(i.local_response, &mut truncated),
        truncated,
        findings: i.findings,
        restored_count: i.restored_count,
        withheld_count: i.withheld_count,
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateRequest {
    pub harness: HarnessKind,
    pub category: TrafficCategory,
    pub custom_payload: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_secs: u64,
    pub config_path: Option<String>,
    pub total_requests: u64,
    pub total_findings: u64,
    pub total_restored: u64,
    pub total_withheld: u64,
    pub total_blocked: u64,
    pub active_vault_tokens: usize,
}

/// Build the full Axum Router serving both:
/// 1. Authenticated, Same-Origin-only Control & Inspection REST API for the Desktop UI (`/api/*`)
/// 2. Live Reverse Proxy & Harness Gateway endpoints (`/:harness/*path`)
pub fn build_router(state: GatewayState) -> Router {
    let api_router = Router::new()
        .route("/status", get(api_status))
        .route("/config", get(api_get_config).post(api_update_config))
        .route("/logs", get(api_get_logs).delete(api_clear_logs))
        .route("/logs/:id", get(api_get_log))
        .route("/harnesses", get(api_get_harnesses))
        .route("/vault", get(api_get_vault).delete(api_clear_vault))
        .route("/simulate", post(api_simulate))
        .route("/rules/validate", post(api_validate_rule))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_auth));

    Router::new()
        .nest("/api", api_router)
        .route("/:harness/*rest", any(proxy_harness_request))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY))
        .with_state(state)
}

/// Management API security middleware:
/// 1. Blocks cross-site requests (`Sec-Fetch-Site: cross-site` or non-loopback `Origin`).
/// 2. Requires the management token via `X-Hide-Go-Token` or `Authorization: Bearer <token>`.
///    Cookies are deliberately not accepted: browsers send `127.0.0.1` cookies to every
///    local port, so a cookie would leak the token to unrelated local dev servers.
async fn require_admin_auth(State(state): State<GatewayState>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if !is_local_browser_request(headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "cross-origin access is forbidden"})),
        )
            .into_response();
    }
    let expected = state.admin_token();
    let header_token = headers
        .get("x-hide-go-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, t)| t.trim());
    let authenticated = [header_token, bearer]
        .into_iter()
        .flatten()
        .any(|t| constant_time_eq(t, expected));
    if !authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized: valid X-Hide-Go-Token or Authorization Bearer token required"})),
        )
            .into_response();
    }
    next.run(req).await
}

pub fn is_local_browser_request(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = host.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    if !matches!(authority.host(), "127.0.0.1" | "localhost" | "[::1]") {
        return false;
    }
    let Ok(local_url) = reqwest::Url::parse(&format!("http://{authority}")) else {
        return false;
    };
    if let Some(site) = headers.get("sec-fetch-site") {
        if !matches!(site.to_str(), Ok("same-origin" | "none")) {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return false;
        };
        let Ok(origin) = reqwest::Url::parse(origin) else {
            return false;
        };
        if origin.origin() != local_url.origin()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return false;
        }
    }
    true
}

fn is_hop_by_hop(name: &str, headers: &HeaderMap) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || headers.get_all(header::CONNECTION).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.split(',').any(|item| item.trim().eq_ignore_ascii_case(name)))
    })
}

fn upstream_request_headers(headers: &HeaderMap, admin_token: &str) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for (name, value) in headers {
        if is_hop_by_hop(name.as_str(), headers)
            || matches!(
                name.as_str(),
                "host"
                    | "content-length"
                    | "accept-encoding"
                    | "origin"
                    | "referer"
                    | "x-hide-go-upstream"
                    | "x-upstream-url"
                    | "x-target-upstream"
                    | "x-hide-go-token"
            )
            || name.as_str().starts_with("sec-fetch-")
        {
            continue;
        }
        if name == header::COOKIE {
            if let Ok(cookies) = value.to_str() {
                let cookies = cookies
                    .split(';')
                    .filter(|cookie| {
                        cookie
                            .trim()
                            .split_once('=')
                            .is_some_and(|(key, _)| key.trim() != "hide_go_session")
                    })
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Ok(value) = cookies.parse() {
                    if !cookies.is_empty() {
                        forwarded.append(name.clone(), value);
                    }
                }
            }
            continue;
        }
        if name == header::AUTHORIZATION
            && value.to_str().is_ok_and(|value| {
                value.split_once(' ').is_some_and(|(scheme, token)| {
                    scheme.eq_ignore_ascii_case("bearer") && constant_time_eq(token.trim(), admin_token)
                })
            })
        {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }
    forwarded.insert(header::ACCEPT_ENCODING, "identity".parse().unwrap());
    forwarded
}

fn upstream_response_headers(headers: &HeaderMap) -> HeaderMap {
    headers
        .iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name.as_str(), headers)
                && !matches!(
                    name.as_str(),
                    "content-length" | "content-encoding" | "set-cookie" | "etag" | "content-md5" | "digest"
                )
                && !name.as_str().starts_with("access-control-")
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn json_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({"error": code, "message": message.into()})),
    )
        .into_response()
}

async fn api_status(State(state): State<GatewayState>) -> Json<StatusResponse> {
    let s = &state.stats;
    Json(StatusResponse {
        status: "running",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        config_path: state.config_path.as_ref().map(|p| p.display().to_string()),
        total_requests: s.requests.load(Ordering::Relaxed),
        total_findings: s.findings.load(Ordering::Relaxed),
        total_restored: s.restored.load(Ordering::Relaxed),
        total_withheld: s.withheld.load(Ordering::Relaxed),
        total_blocked: s.blocked.load(Ordering::Relaxed),
        active_vault_tokens: state.vault.len(),
    })
}

async fn api_get_config(State(state): State<GatewayState>) -> Json<HideConfig> {
    Json(state.get_config())
}

async fn api_update_config(State(state): State<GatewayState>, Json(next): Json<HideConfig>) -> Response {
    match state.try_update_config(next) {
        Ok(cfg) => Json(cfg).into_response(),
        Err(message) => json_error(StatusCode::BAD_REQUEST, "invalid_config", message),
    }
}

#[derive(Deserialize)]
struct RuleProbe {
    pattern: String,
    sample: Option<String>,
}

async fn api_validate_rule(Json(probe): Json<RuleProbe>) -> Response {
    match crate::scanner::compile_custom_regex(&probe.pattern) {
        Ok(re) => {
            let matches: Vec<String> = probe
                .sample
                .as_deref()
                .map(|s| re.find_iter(s).take(20).map(|m| m.as_str().to_string()).collect())
                .unwrap_or_default();
            Json(serde_json::json!({"valid": true, "matches": matches})).into_response()
        }
        Err(message) => Json(serde_json::json!({"valid": false, "message": message})).into_response(),
    }
}

async fn api_get_logs(State(state): State<GatewayState>) -> Json<Vec<TrafficAuditSummary>> {
    Json(state.get_summaries())
}

async fn api_get_log(State(state): State<GatewayState>, Path(id): Path<String>) -> Response {
    match state.get_record(&id) {
        Some(r) => Json(r).into_response(),
        None => json_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "record has expired from the audit window",
        ),
    }
}

async fn api_clear_logs(State(state): State<GatewayState>) -> StatusCode {
    state.clear_records();
    StatusCode::NO_CONTENT
}

async fn api_get_harnesses(State(state): State<GatewayState>) -> Json<Vec<HarnessProfile>> {
    Json(state.get_harness_profiles())
}

async fn api_get_vault(State(state): State<GatewayState>) -> Json<Vec<VaultEntry>> {
    Json(state.get_vault_entries())
}

async fn api_clear_vault(State(state): State<GatewayState>) -> StatusCode {
    state.clear_vault();
    StatusCode::NO_CONTENT
}

async fn api_simulate(State(state): State<GatewayState>, Json(req): Json<SimulateRequest>) -> Response {
    let result =
        tokio::task::spawn_blocking(move || state.simulate_traffic(req.harness, req.category, req.custom_payload))
            .await;
    match result {
        Ok(record) => Json(record).into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "simulation_failed",
            "simulation task panicked",
        ),
    }
}

fn is_known_harness_prefix(prefix: &str) -> bool {
    matches!(
        prefix.to_ascii_lowercase().as_str(),
        "claude-code" | "codex" | "antigravity" | "zcode" | "qoder" | "cursor" | "grok-build"
    )
}

/// Real reverse-proxy handler for `/:harness/*rest`:
/// 1. Detects the Harness and TrafficCategory (path based).
/// 2. Transforms the outbound payload according to `HideConfig` (CPU work off the async runtime).
/// 3. Forwards to the upstream (`X-Hide-Go-Upstream` / `HIDE_GO_UPSTREAM_URL` / vendor default).
/// 4. Streams SSE or JSON responses back through the restorers.
async fn proxy_harness_request(
    State(state): State<GatewayState>,
    Path((harness_prefix, rest)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_local_browser_request(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let start = Instant::now();
    let cfg = state.get_config();
    let full_path = format!("/{}/{}", harness_prefix, rest);
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());

    let request_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.eq_ignore_ascii_case("identity"));
    let text_body = std::str::from_utf8(&body).ok();
    if cfg.mode != PrivacyMode::AuditOnly && (request_encoding.is_some() || (text_body.is_none() && !body.is_empty())) {
        // A body we cannot read is a body we cannot clean: fail closed.
        let (harness, category) = detect_harness_and_category(&full_path, ua, "");
        let msg =
            "请求体经过压缩或不是 UTF-8 文本，Hide-Go 无法检查其中的敏感数据，已拒绝转发。可切换到“仅审计”模式直通。";
        state.push_record(build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: uri.path().to_string(),
            mode: cfg.mode,
            action_taken: "rejected+uninspectable_request_body".to_string(),
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE.as_u16(),
            start,
            simulated: false,
            local_request: "",
            vendor_request: "",
            vendor_response: "",
            local_response: msg,
            findings: Vec::new(),
            restored_count: 0,
            withheld_count: 0,
        }));
        return json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "uninspectable_request_body", msg);
    }
    let body_text = text_body.unwrap_or_default().to_string();
    let (harness, category) = detect_harness_and_category(&full_path, ua, &body_text);

    if should_block_telemetry(category, &full_path, &cfg) {
        let ack = serde_json::json!({"status": "ok", "accepted": true}).to_string();
        let findings = ProjectScanner::scan_matches(&body_text, &cfg)
            .into_iter()
            .map(|(kind, label, raw, severity)| LeakFinding {
                kind,
                label,
                original_preview: mask_preview(&raw),
                replacement_token: "已拦截（未出境）".to_string(),
                severity,
                count: 1,
            })
            .collect();
        state.push_record(build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: uri.path().to_string(),
            mode: cfg.mode,
            action_taken: "telemetry-blocked".to_string(),
            status: 0,
            start,
            simulated: false,
            local_request: &body_text,
            vendor_request: "",
            vendor_response: "",
            local_response: &ack,
            findings,
            restored_count: 0,
            withheld_count: 0,
        }));
        return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], ack).into_response();
    }

    // 1. Outbound transformation (CPU bound: keep it off the async workers).
    let (vendor_body, action_taken, findings) = if text_body.is_some() {
        let vault = state.vault.clone();
        let (cfg2, text) = (cfg.clone(), body_text.clone());
        match tokio::task::spawn_blocking(move || transform_outbound(&vault, category, &text, &cfg2)).await {
            Ok((vendor, action, findings)) => (Bytes::from(vendor), action, findings),
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "transform_failed",
                    "outbound transformation panicked",
                )
            }
        }
    } else {
        (body.clone(), "passed".to_string(), Vec::new())
    };
    let vendor_visible_payload = String::from_utf8_lossy(&vendor_body).into_owned();
    let record_base =
        |status: u16, vendor_response: &str, local_response: &str, restored: usize, withheld: usize, action: String| {
            build_record(RecordInput {
                harness,
                category,
                method: method.to_string(),
                endpoint: uri.path().to_string(),
                mode: cfg.mode,
                action_taken: action,
                status,
                start,
                simulated: false,
                local_request: &body_text,
                vendor_request: &vendor_visible_payload,
                vendor_response,
                local_response,
                findings: findings.clone(),
                restored_count: restored,
                withheld_count: withheld,
            })
        };

    if serde_json::from_str::<Value>(&body_text).is_ok() && serde_json::from_slice::<Value>(&vendor_body).is_err() {
        let msg = "transformation produced invalid JSON; refusing to forward";
        state.push_record(record_base(
            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            "",
            msg,
            0,
            0,
            format!("{action_taken}+transformation_breaks_upstream_protocol"),
        ));
        return json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "transformation_breaks_upstream_protocol",
            msg,
        );
    }

    // 2. Upstream URL
    let header_upstream = headers
        .get("x-hide-go-upstream")
        .or_else(|| headers.get("x-upstream-url"))
        .or_else(|| headers.get("x-target-upstream"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().trim_end_matches('/').to_string());
    let env_upstream = std::env::var("HIDE_GO_UPSTREAM_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().trim_end_matches('/').to_string());
    let upstream_base = header_upstream
        .or(env_upstream)
        .unwrap_or_else(|| GatewayState::default_upstream_for_harness(harness).to_string());
    let upstream_path = if is_known_harness_prefix(&harness_prefix) {
        format!("/{}", rest.trim_start_matches('/'))
    } else {
        full_path.clone()
    };
    let target_url = match uri.query() {
        Some(query) => format!("{}{}?{}", upstream_base, upstream_path, query),
        None => format!("{}{}", upstream_base, upstream_path),
    };
    let Ok(target_url) = reqwest::Url::parse(&target_url) else {
        let msg = "upstream URL is not valid";
        state.push_record(record_base(
            StatusCode::BAD_REQUEST.as_u16(),
            "",
            msg,
            0,
            0,
            format!("{action_taken}+invalid_upstream"),
        ));
        return json_error(StatusCode::BAD_REQUEST, "invalid_upstream", msg);
    };
    if !matches!(target_url.scheme(), "http" | "https")
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.fragment().is_some()
    {
        let msg = "upstream URL must be plain http(s)";
        state.push_record(record_base(
            StatusCode::BAD_REQUEST.as_u16(),
            "",
            msg,
            0,
            0,
            format!("{action_taken}+invalid_upstream"),
        ));
        return json_error(StatusCode::BAD_REQUEST, "invalid_upstream", msg);
    }
    let is_loopback = matches!(target_url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    let client = if is_loopback {
        &state.local_http_client
    } else {
        &state.http_client
    };

    let upstream_req = client
        .request(method.clone(), target_url)
        .headers(upstream_request_headers(&headers, state.admin_token()))
        .body(vendor_body);

    let upstream_resp = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            let reason = if err.is_timeout() {
                "upstream_timeout"
            } else {
                "upstream_connection_failed"
            };
            state.push_record(record_base(0, "", "", 0, 0, format!("{action_taken}+{reason}")));
            return json_error(StatusCode::BAD_GATEWAY, reason, err.to_string());
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let response_headers = upstream_response_headers(upstream_resp.headers());
    if upstream_resp
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| !value.to_str().is_ok_and(|v| v.trim().eq_ignore_ascii_case("identity")))
    {
        let msg = "upstream ignored Accept-Encoding: identity";
        state.push_record(record_base(
            StatusCode::BAD_GATEWAY.as_u16(),
            "",
            msg,
            0,
            0,
            format!("{action_taken}+unsupported_upstream_encoding"),
        ));
        return json_error(StatusCode::BAD_GATEWAY, "unsupported_upstream_encoding", msg);
    }
    let is_event_stream = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/event-stream"));

    if is_event_stream {
        let restorer = (cfg.mode != PrivacyMode::AuditOnly)
            .then(|| SseRestorer::with_policy(state.vault.clone(), cfg.tool_call_secret_policy));
        let stream_state = ProxyStreamState {
            inner: Box::pin(upstream_resp.bytes_stream()),
            restorer,
            vendor_raw_acc: Vec::new(),
            restored_acc: Vec::new(),
            flushed: false,
            started_at: start,
            state_for_log: state.clone(),
            record: Some(record_base(status.as_u16(), "", "", 0, 0, action_taken.clone())),
            action_taken,
        };
        let out_stream = futures_util::stream::unfold(stream_state, |mut st| async move {
            if st.flushed {
                return None;
            }
            match st.inner.next().await {
                Some(Ok(chunk)) => {
                    st.accumulate_raw(&chunk);
                    let restored = match &mut st.restorer {
                        Some(r) => r.push_bytes(&chunk).map(Bytes::from),
                        None => Ok(chunk),
                    };
                    match restored {
                        Ok(bytes) => {
                            st.accumulate_restored(&bytes);
                            Some((Ok(bytes), st))
                        }
                        Err(error) => {
                            st.finish_record(true);
                            Some((Err(error), st))
                        }
                    }
                }
                Some(Err(err)) => {
                    st.finish_record(true);
                    Some((
                        Err(std::io::Error::other(format!("upstream stream interrupted: {err}"))),
                        st,
                    ))
                }
                None => {
                    let finished = match &mut st.restorer {
                        Some(r) => r.finish().map(|(tail, _)| tail),
                        None => Ok(String::new()),
                    };
                    match finished {
                        Ok(tail) => {
                            st.accumulate_restored(tail.as_bytes());
                            st.finish_record(false);
                            Some((Ok(Bytes::from(tail)), st))
                        }
                        Err(error) => {
                            st.finish_record(true);
                            Some((Err(error), st))
                        }
                    }
                }
            }
        });
        let mut response = Response::new(Body::from_stream(out_stream));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
        return response;
    }

    let vendor_raw = match upstream_resp.text().await {
        Ok(text) => text,
        Err(err) => {
            state.push_record(record_base(
                status.as_u16(),
                "",
                "",
                0,
                0,
                format!("{action_taken}+upstream_body_failed"),
            ));
            return json_error(StatusCode::BAD_GATEWAY, "upstream_body_failed", err.to_string());
        }
    };
    let (restored, restored_count, withheld) = if cfg.mode == PrivacyMode::AuditOnly {
        (vendor_raw.clone(), 0, 0)
    } else {
        let vault = state.vault.clone();
        let (policy, raw) = (cfg.tool_call_secret_policy, vendor_raw.clone());
        tokio::task::spawn_blocking(move || restore_response(&vault.matcher(), &raw, policy))
            .await
            .unwrap_or_else(|_| (vendor_raw.clone(), 0, 0))
    };
    state.push_record(record_base(
        status.as_u16(),
        &vendor_raw,
        &restored,
        restored_count,
        withheld,
        action_taken,
    ));
    let mut response = Response::new(Body::from(restored));
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

struct ProxyStreamState<S> {
    inner: std::pin::Pin<Box<S>>,
    restorer: Option<SseRestorer>,
    vendor_raw_acc: Vec<u8>,
    restored_acc: Vec<u8>,
    flushed: bool,
    started_at: Instant,
    state_for_log: GatewayState,
    record: Option<TrafficAuditRecord>,
    action_taken: String,
}

impl<S> ProxyStreamState<S> {
    fn accumulate_raw(&mut self, bytes: &[u8]) {
        if self.vendor_raw_acc.len() < MAX_STORED_PAYLOAD + 4 {
            self.vendor_raw_acc.extend_from_slice(bytes);
        }
    }

    fn accumulate_restored(&mut self, bytes: &[u8]) {
        if let Some(r) = &mut self.record {
            r.response_bytes += bytes.len();
        }
        if self.restored_acc.len() < MAX_STORED_PAYLOAD + 4 {
            self.restored_acc.extend_from_slice(bytes);
        }
    }

    fn finish_record(&mut self, failed: bool) {
        self.flushed = true;
        let Some(mut record) = self.record.take() else { return };
        let mut truncated = record.truncated;
        record.vendor_raw_response = cap_payload(&String::from_utf8_lossy(&self.vendor_raw_acc), &mut truncated);
        record.local_restored_response = cap_payload(&String::from_utf8_lossy(&self.restored_acc), &mut truncated);
        record.truncated = truncated;
        record.latency_ms = self.started_at.elapsed().as_millis().max(1) as u64;
        if let Some(r) = &mut self.restorer {
            record.restored_count = r.finish().map(|(_, n)| n).unwrap_or_else(|_| r.restored());
            record.withheld_count = r.withheld();
        }
        if failed {
            record.action_taken = format!("{}+stream-error", self.action_taken);
        }
        self.state_for_log.push_record(record);
    }
}

impl<S> Drop for ProxyStreamState<S> {
    fn drop(&mut self) {
        if !self.flushed {
            self.finish_record(true);
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn serve(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    async fn counting_upstream() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let url = serve(
            Router::new()
                .fallback(move |body: Bytes| {
                    let h = h.clone();
                    async move {
                        h.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"type": "message", "echo": String::from_utf8_lossy(&body)}))
                    }
                })
                .layer(DefaultBodyLimit::disable()),
        )
        .await;
        (url, hits)
    }

    #[test]
    fn browser_access_requires_loopback_and_exact_origin() {
        let mut headers = HeaderMap::new();
        assert!(!is_local_browser_request(&headers));
        headers.insert(header::HOST, "127.0.0.1:18787".parse().unwrap());
        assert!(is_local_browser_request(&headers));
        headers.insert(header::ORIGIN, "http://127.0.0.1:18787".parse().unwrap());
        assert!(is_local_browser_request(&headers));
        for origin in [
            "http://127.0.0.1:1420",
            "http://localhost:18787",
            "null",
            "http://127.0.0.1:80@evil.example",
        ] {
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(!is_local_browser_request(&headers), "{origin}");
        }
        headers.remove(header::ORIGIN);
        headers.insert("sec-fetch-site", "same-site".parse().unwrap());
        assert!(!is_local_browser_request(&headers));
        headers.remove("sec-fetch-site");
        headers.insert(header::HOST, "rebound.example:18787".parse().unwrap());
        assert!(!is_local_browser_request(&headers));
    }

    #[test]
    fn forwarding_drops_local_credentials_and_connection_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "provider=keep; hide_go_session=admin-secret".parse().unwrap(),
        );
        headers.insert(header::AUTHORIZATION, "Bearer admin-secret".parse().unwrap());
        headers.insert("x-hide-go-token", "admin-secret".parse().unwrap());
        headers.insert(header::CONNECTION, "x-private".parse().unwrap());
        headers.insert("x-private", "local-only".parse().unwrap());
        headers.insert("x-api-key", "provider-secret".parse().unwrap());
        headers.insert(header::REFERER, "http://localhost/?token=admin-secret".parse().unwrap());
        let forwarded = upstream_request_headers(&headers, "admin-secret");
        assert_eq!(forwarded[header::COOKIE], "provider=keep");
        assert_eq!(forwarded["x-api-key"], "provider-secret");
        assert_eq!(forwarded[header::ACCEPT_ENCODING], "identity");
        for name in ["authorization", "x-hide-go-token", "connection", "x-private", "referer"] {
            assert!(!forwarded.contains_key(name), "{name}");
        }
        headers.insert(header::AUTHORIZATION, "Bearer provider-secret".parse().unwrap());
        assert_eq!(
            upstream_request_headers(&headers, "admin-secret")[header::AUTHORIZATION],
            "Bearer provider-secret"
        );
    }

    #[tokio::test]
    async fn admin_api_rejects_cookie_only_auth() {
        let state = GatewayState::with_admin_token(HideConfig::default(), "tok-123");
        let gateway = serve(build_router(state)).await;
        let res = client()
            .get(format!("{gateway}/api/status"))
            .header("cookie", "hide_go_session=tok-123")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let res = client()
            .get(format!("{gateway}/api/status"))
            .header("authorization", "Bearer tok-123")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn failed_default_upstream_never_returns_simulated_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut state = GatewayState::default();
        state.http_client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("http://{address}")).unwrap())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .json(&serde_json::json!({"stream": true, "messages": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let error = response.json::<Value>().await.unwrap()["error"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            matches!(error.as_str(), "upstream_connection_failed" | "upstream_timeout"),
            "{error}"
        );
        assert!(state.get_records()[0].action_taken.ends_with(&error));
    }

    #[tokio::test]
    async fn upstream_status_and_retry_headers_are_preserved() {
        let upstream = serve(Router::new().fallback(|| async {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    ("retry-after", "12"),
                    ("x-request-id", "req-42"),
                    ("set-cookie", "hide_go_session=untrusted"),
                ],
                "rate limited",
            )
        }))
        .await;
        let gateway = serve(build_router(GatewayState::default())).await;
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-upstream", upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "12");
        assert_eq!(response.headers()["x-request-id"], "req-42");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(response.text().await.unwrap(), "rate limited");
    }

    #[tokio::test]
    async fn audit_mode_does_not_restore_existing_tokens() {
        let upstream =
            serve(Router::new().fallback(|| async { Json(serde_json::json!({"content": "review_placeholder"})) }))
                .await;
        let mut config = HideConfig::default();
        config.mode = PrivacyMode::AuditOnly;
        let state = GatewayState::new(config);
        state
            .vault
            .insert_explicit("local-secret", "review_placeholder", "test");
        let gateway = serve(build_router(state)).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.json::<Value>().await.unwrap()["content"], "review_placeholder");
    }

    #[tokio::test]
    async fn json_response_restoration_escapes_quotes_and_newlines() {
        let upstream =
            serve(Router::new().fallback(|| async { Json(serde_json::json!({"content": "review_placeholder"})) }))
                .await;
        let state = GatewayState::default();
        let original = "quote \" and newline\nC:\\Users\\alice";
        state.vault.insert_explicit(original, "review_placeholder", "test");
        let gateway = serve(build_router(state)).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.json::<Value>().await.unwrap()["content"], original);
    }

    #[tokio::test]
    async fn http_stream_restores_tokens_across_events_and_utf8_bytes() {
        let upstream = serve(Router::new().fallback(|| async {
            let event = |content: &str| {
                format!(
                    "data: {}\n\n",
                    serde_json::json!({"choices": [{"index": 0, "delta": {"content": content}}]})
                )
            };
            let stream = format!("{}{}data: [DONE]\n\n", event("你好 review_place"), event("holder"));
            let chunks = stream
                .into_bytes()
                .into_iter()
                .map(|byte| Ok::<Bytes, std::io::Error>(Bytes::from(vec![byte])));
            Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(futures_util::stream::iter(chunks)))
                .unwrap()
        }))
        .await;
        let state = GatewayState::default();
        state
            .vault
            .insert_explicit("quoted \"secret\"\n", "review_placeholder", "test");
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        let body = response.text().await.unwrap();
        let mut output = String::new();
        let mut done = false;
        for line in body.lines().filter_map(|line| line.strip_prefix("data: ")) {
            if line == "[DONE]" {
                done = true;
                continue;
            }
            assert!(!done, "text must be flushed before DONE");
            let json: Value = serde_json::from_str(line).unwrap();
            if let Some(text) = json["choices"][0]["delta"]["content"].as_str() {
                output.push_str(text);
            }
        }
        assert!(done);
        assert_eq!(output, "你好 quoted \"secret\"\n");
        let record = &state.get_records()[0];
        assert_eq!(record.restored_count, 1);
        assert!(record.response_bytes > 0);
    }

    #[tokio::test]
    async fn truncated_upstream_body_is_not_successful_empty_content() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut input = [0; 4096];
            let _ = connection.read(&mut input).await.unwrap();
            connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"content\":").await.unwrap();
            connection.shutdown().await.unwrap();
        });
        let gateway = serve(build_router(GatewayState::default())).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", format!("http://{address}"))
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn interrupted_sse_is_reported_as_a_stream_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut input = [0; 4096];
            let _ = connection.read(&mut input).await.unwrap();
            connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\nConnection: close\r\n\r\ndata: {\"delta\":").await.unwrap();
            connection.shutdown().await.unwrap();
        });
        let state = GatewayState::default();
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", format!("http://{address}"))
            .body("hello")
            .send()
            .await;
        if let Ok(response) = response {
            assert!(response.text().await.is_err());
        }
        assert!(state
            .get_records()
            .iter()
            .any(|record| record.action_taken.ends_with("+stream-error")));
    }

    #[tokio::test]
    async fn cipher_mode_keeps_requests_valid_json_and_forwards() {
        let (upstream, hits) = counting_upstream().await;
        let mut config = HideConfig::default();
        config.mode = PrivacyMode::AllHide;
        config.all_hide.enable_cipher_garble = true;
        let gateway = serve(build_router(GatewayState::new(config))).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", &upstream)
            .json(&serde_json::json!({"model": "gpt-5", "input": "secret code"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let echo: Value =
            serde_json::from_str(response.json::<Value>().await.unwrap()["echo"].as_str().unwrap()).unwrap();
        assert_eq!(echo["model"], "gpt-5");
    }

    #[tokio::test]
    async fn chat_request_mentioning_event_type_is_forwarded() {
        let (upstream, hits) = counting_upstream().await;
        let gateway = serve(build_router(GatewayState::default())).await;
        let body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "track", "input_schema": {"type": "object", "properties": {"event_type": {"type": "string"}, "telemetry": {}}}}]});
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-upstream", &upstream)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn telemetry_endpoint_is_answered_locally_when_blocking() {
        let (upstream, hits) = counting_upstream().await;
        let state = GatewayState::default();
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/claude-code/api/event_logging/batch"))
            .header("x-hide-go-upstream", &upstream)
            .json(&serde_json::json!({"events": [{"cwd": "/home/alice/x"}]}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(state.get_records()[0].action_taken, "telemetry-blocked");
    }

    #[tokio::test]
    async fn large_requests_up_to_limit_are_accepted() {
        let (upstream, hits) = counting_upstream().await;
        let gateway = serve(build_router(GatewayState::default())).await;
        let big = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "a".repeat(5_000_000)}]});
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-upstream", &upstream)
            .json(&big)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn compressed_request_bodies_fail_closed() {
        let (upstream, hits) = counting_upstream().await;
        let gateway = serve(build_router(GatewayState::default())).await;
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-upstream", &upstream)
            .header("content-encoding", "gzip")
            .body(vec![0x1f, 0x8b, 0x08, 0x00])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_custom_rule_is_rejected_by_config_api() {
        let state = GatewayState::with_admin_token(HideConfig::default(), "t");
        let gateway = serve(build_router(state.clone())).await;
        let mut cfg = HideConfig::default();
        cfg.custom_rules[0].pattern = "Chimera(?!Test)".to_string();
        let res = client()
            .post(format!("{gateway}/api/config"))
            .header("x-hide-go-token", "t")
            .json(&cfg)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(res.json::<Value>().await.unwrap()["message"]
            .as_str()
            .unwrap()
            .contains("look-around"));
        assert_ne!(state.get_config().custom_rules[0].pattern, "Chimera(?!Test)");
    }

    #[tokio::test]
    async fn logs_list_is_payload_free_and_detail_has_payloads() {
        let state = GatewayState::with_admin_token(HideConfig::default(), "t");
        state.simulate_traffic(HarnessKind::ClaudeCode, TrafficCategory::InteractivePrompt, None);
        let gateway = serve(build_router(state.clone())).await;
        let list: Value = client()
            .get(format!("{gateway}/api/logs"))
            .header("x-hide-go-token", "t")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(list[0].get("localRequestPayload").is_none());
        let id = list[0]["id"].as_str().unwrap();
        let detail: Value = client()
            .get(format!("{gateway}/api/logs/{id}"))
            .header("x-hide-go-token", "t")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(detail["localRequestPayload"].as_str().unwrap().contains("ProjectTitan"));
        assert!(!detail["vendorVisiblePayload"]
            .as_str()
            .unwrap()
            .contains("ProdVaultPass2026"));
    }
}
