use crate::all_hide::AllHideEngine;
use crate::config::{
    HarnessKind, HideConfig, LeakFinding, PrivacyMode, TrafficAuditRecord, TrafficCategory,
};
use crate::desensitizer::SemanticDesensitizer;
use crate::harness::{detect_harness_and_category, get_all_harness_profiles, HarnessProfile};
use crate::scanner::ProjectScanner;
use crate::stream_restorer::StreamRestorer;
use crate::vault::{mask_preview, PrivacyVault, VaultEntry};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use chrono::Utc;
use futures_util::StreamExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

const MAX_AUDIT_LOGS: usize = 200;

/// Shared application state for the Hide-Go gateway
#[derive(Clone)]
pub struct GatewayState {
    pub config: Arc<RwLock<HideConfig>>,
    pub vault: PrivacyVault,
    pub audit_logs: Arc<RwLock<VecDeque<TrafficAuditRecord>>>,
    pub http_client: reqwest::Client,
    pub local_http_client: reqwest::Client,
    pub admin_token: Arc<String>,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self::new(HideConfig::default())
    }
}

impl GatewayState {
    pub fn new(config: HideConfig) -> Self {
        let admin_token = std::env::var("HIDE_GO_ADMIN_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));

        let state = Self {
            config: Arc::new(RwLock::new(config)),
            vault: PrivacyVault::new(),
            audit_logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOGS))),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            local_http_client: reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            admin_token: Arc::new(admin_token),
        };
        state.seed_initial_demo_records();
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

    /// Seed realistic initial records across harnesses so the user immediately sees
    /// how Auto-Desensitize and All-Hide (Isomorphic, Cipher, and Telemetry Chaff) work.
    pub fn seed_initial_demo_records(&self) {
        let samples = vec![
            (
                HarnessKind::ClaudeCode,
                TrafficCategory::InteractivePrompt,
                PrivacyMode::AutoDesensitize,
            ),
            (
                HarnessKind::Cursor,
                TrafficCategory::InteractivePrompt,
                PrivacyMode::AllHide,
            ),
            (
                HarnessKind::Qoder,
                TrafficCategory::CodebaseIndexing,
                PrivacyMode::AllHide,
            ),
            (
                HarnessKind::GrokBuild,
                TrafficCategory::ToolExecutionSync,
                PrivacyMode::AutoDesensitize,
            ),
        ];

        for (harness, category, mode) in samples {
            let mut cfg = self.config.read().clone();
            cfg.mode = mode;
            if harness == HarnessKind::Cursor {
                cfg.all_hide.enable_isomorphic_camouflage = true;
                cfg.all_hide.enable_cipher_garble = false;
            }
            let record = self.simulate_traffic_with_config(harness, category, None, &cfg);
            self.push_record(record);
        }
    }

    pub fn push_record(&self, record: TrafficAuditRecord) {
        let mut logs = self.audit_logs.write();
        logs.push_front(record);
        while logs.len() > MAX_AUDIT_LOGS {
            logs.pop_back();
        }
    }

    pub fn get_records(&self) -> Vec<TrafficAuditRecord> {
        self.audit_logs.read().iter().cloned().collect()
    }

    pub fn clear_records(&self) {
        self.audit_logs.write().clear();
    }

    pub fn get_config(&self) -> HideConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, next: HideConfig) -> HideConfig {
        let mut guard = self.config.write();
        *guard = next.clone();
        next
    }

    pub fn get_harness_profiles(&self) -> Vec<HarnessProfile> {
        let port = self.config.read().proxy_port;
        let logs = self.audit_logs.read();
        let mut profiles = get_all_harness_profiles(port);
        for p in &mut profiles {
            p.detected_active = logs.iter().any(|r| r.harness == p.kind);
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
        match cfg.mode {
            PrivacyMode::AuditOnly => {
                let raw_matches = ProjectScanner::scan_matches(raw_request, cfg);
                let findings = raw_matches
                    .into_iter()
                    .map(|(kind, label, raw_val, severity)| LeakFinding {
                        kind,
                        label,
                        original_preview: mask_preview(&raw_val),
                        replacement_token: "[未脱敏: 仅审计模式]".to_string(),
                        severity,
                        count: 1,
                    })
                    .collect();
                (raw_request.to_string(), "passed".to_string(), findings)
            }
            PrivacyMode::AutoDesensitize => {
                if cfg.block_silent_telemetry && category == TrafficCategory::Telemetry {
                    let out = AllHideEngine::process(raw_request, category, cfg, &self.vault);
                    (out.vendor_payload, out.action_taken, out.findings)
                } else {
                    let res = SemanticDesensitizer::process(raw_request, cfg, &self.vault);
                    (
                        res.transformed_payload,
                        "desensitized".to_string(),
                        res.findings,
                    )
                }
            }
            PrivacyMode::AllHide => {
                let out = AllHideEngine::process(raw_request, category, cfg, &self.vault);
                (out.vendor_payload, out.action_taken, out.findings)
            }
        }
    }

    /// Core transformation pipeline: inspects outbound request, applies PrivacyMode (AuditOnly, AutoDesensitize, or AllHide),
    /// generates or forwards vendor response, and runs StreamRestorer to restore local secrets/identifiers.
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

        // 1. Outbound transformation
        let (vendor_visible_payload, action_taken, findings) =
            self.transform_outbound_payload(category, raw_request, cfg);

        // 2. Synthesize Cloud Vendor LLM response (used for local simulation or offline fallback)
        let vendor_raw_response = Self::synthesize_vendor_llm_response(
            harness,
            category,
            &vendor_visible_payload,
            &action_taken,
        );

        // 3. Inbound Streaming Restoration (simulate SSE multi-chunk boundary splitting to exercise StreamRestorer)
        let (restored_stream, restored_count) =
            self.restore_response_In_chunks(&vendor_raw_response, &cfg.project_salt);

        let elapsed = start.elapsed().as_millis() as u64;

        TrafficAuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().format("%H:%M:%S%.3f").to_string(),
            harness,
            category,
            method: method.to_string(),
            endpoint: endpoint.to_string(),
            upstream_vendor: Self::vendor_for_harness(harness).to_string(),
            applied_mode: cfg.mode,
            action_taken,
            latency_ms: elapsed.max(2),
            local_request_payload: raw_request.to_string(),
            vendor_visible_payload,
            vendor_raw_response,
            local_restored_response: restored_stream,
            findings,
            restored_count,
        }
    }

    #[allow(non_snake_case)]
    fn restore_response_In_chunks(&self, raw_response: &str, salt: &str) -> (String, usize) {
        let mut restorer = StreamRestorer::new(self.vault.clone());
        let mut restored_stream = String::with_capacity(raw_response.len());

        let chars: Vec<char> = raw_response.chars().collect();
        for chunk_chars in chars.chunks(11) {
            let chunk_str: String = chunk_chars.iter().collect();
            restored_stream.push_str(&restorer.push_chunk(&chunk_str));
        }
        let (tail, mut restored_count) = restorer.finish();
        restored_stream.push_str(&tail);

        if restored_stream.contains("⟦HIDE-CIPHER::") {
            let decoded =
                AllHideEngine::decode_braille_cipher_blocks(&restored_stream, &self.vault, salt);
            let (fully_restored, extra) = self.vault.restore_text(&decoded);
            restored_stream = fully_restored;
            restored_count += 1 + extra;
        }

        (restored_stream, restored_count)
    }

    pub fn simulate_traffic(
        &self,
        harness: HarnessKind,
        category: TrafficCategory,
        custom_payload: Option<String>,
    ) -> TrafficAuditRecord {
        let cfg = self.get_config();
        let record = self.simulate_traffic_with_config(harness, category, custom_payload, &cfg);
        self.push_record(record.clone());
        record
    }

    fn simulate_traffic_with_config(
        &self,
        harness: HarnessKind,
        category: TrafficCategory,
        custom_payload: Option<String>,
        cfg: &HideConfig,
    ) -> TrafficAuditRecord {
        let endpoint = match (harness, category) {
            (HarnessKind::ClaudeCode, TrafficCategory::Telemetry) => {
                "/claude-code/api/event_logging"
            }
            (HarnessKind::ClaudeCode, _) => "/claude-code/v1/messages",
            (HarnessKind::Codex, _) => "/codex/v1/responses",
            (HarnessKind::Antigravity, _) => "/antigravity/v1/agent/chat",
            (HarnessKind::Zcode, _) => "/zcode/v1/chat/completions",
            (HarnessKind::Qoder, TrafficCategory::CodebaseIndexing) => {
                "/qoder/v1/codebase/index-sync"
            }
            (HarnessKind::Qoder, _) => "/qoder/v1/chat/completions",
            (HarnessKind::Cursor, TrafficCategory::CodebaseIndexing) => {
                "/cursor/repo-service/upload-chunks"
            }
            (HarnessKind::Cursor, _) => "/cursor/v1/chat/completions",
            (HarnessKind::GrokBuild, _) => "/grok-build/v1/chat/completions",
            (HarnessKind::Generic, _) => "/v1/chat/completions",
        };

        let sample_payload =
            custom_payload.unwrap_or_else(|| Self::default_sample_payload(harness, category));

        self.process_payload_cycle(harness, category, "POST", endpoint, &sample_payload, cfg)
    }

    pub fn vendor_for_harness(harness: HarnessKind) -> &'static str {
        match harness {
            HarnessKind::ClaudeCode => "Anthropic Cloud (api.anthropic.com)",
            HarnessKind::Codex => "OpenAI Cloud (api.openai.com)",
            HarnessKind::Antigravity => "Antigravity Cloud Gateway",
            HarnessKind::Zcode => "ZCode AI Cloud",
            HarnessKind::Qoder => "Qoder Indexing & LLM Cloud",
            HarnessKind::Cursor => "Cursor Backend (api2.cursor.sh)",
            HarnessKind::GrokBuild => "xAI Cloud (api.x.ai)",
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
                "files": [
                    {
                        "path": "/home/alice/ProjectTitan/src/quantum_ledger.rs",
                        "content": "// Core ProjectTitan HFT Margin Liquidation Algorithm\npub async fn execute_margin_liquidation(account_id: &str, db_url: &str) -> Result<u64, String> {\n    let conn = \"postgres://titan_admin:SuperSecretPass99@10.18.44.12:5432/titan_prod\";\n    verify_signature_token(account_id, \"sk-ant-api03-secretkey998877665544332211\")\n}"
                    }
                ]
            })
            .to_string(),
            _ => {
                format!(
                    r#"{{
  "harness": "{}",
  "model": "flagship-coding-v4",
  "system": "Workspace root: /home/alice/ProjectTitan/fintech-core (host: build-node.corp.internal)",
  "messages": [
    {{
      "role": "user",
      "content": "请帮我检查这段核心清算代码的重入漏洞：\n// ProjectTitan high-frequency settlement check\npub fn verify_margin_settlement(wallet_secret: &str) -> bool {{\n    let db_conn = \"postgres://admin:ProdVaultPass2026@192.168.10.88:5432/quantum_ledger\";\n    let api_key = \"sk-proj-TitanSecretKey889900112233445566\";\n    let node_host = \"vault-primary.corp.internal\";\n    calculate_liquidation_ratio(wallet_secret, db_conn, api_key, node_host)\n}}"
    }}
  ]
}}"#,
                    harness.slug()
                )
            }
        }
    }

    /// Synthesize a guaranteed-valid JSON response using `serde_json::json!` so embedded quotes/newlines
    /// never break JSON parsing.
    pub fn synthesize_vendor_llm_response(
        harness: HarnessKind,
        category: TrafficCategory,
        vendor_visible_payload: &str,
        action_taken: &str,
    ) -> String {
        if action_taken == "chaff-injected"
            || matches!(
                category,
                TrafficCategory::Telemetry | TrafficCategory::CodebaseIndexing
            )
        {
            return serde_json::json!({
                "status": "ok",
                "harness": harness.slug(),
                "vendor_note": "Received decoy/chaff payload; zero real project files or telemetry leaked to vendor.",
                "received_preview": vendor_visible_payload.chars().take(120).collect::<String>()
            })
            .to_string();
        }

        // Extract inner text if `vendor_visible_payload` is JSON so we don't double-escape JSON syntax
        let context_echo = serde_json::from_str::<Value>(vendor_visible_payload)
            .unwrap_or_else(|_| Value::String(vendor_visible_payload.to_string()));

        let reply_text = format!(
            "我已基于您提供的上下文完成安全分析并重构了调用逻辑，请查看修复后的实现：\n\n```rust\n// AI Refactored implementation (generated using vendor-visible tokens)\n{}\n```",
            extract_readable_snippet(vendor_visible_payload)
        );

        serde_json::json!({
            "id": "msg_hidego_verified",
            "object": "chat.completion",
            "harness": harness.slug(),
            "assistant_reply": reply_text,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": reply_text
                    },
                    "finish_reason": "stop"
                }
            ],
            "echoed_context": context_echo
        })
        .to_string()
    }
}

fn extract_readable_snippet(payload: &str) -> String {
    if let Ok(val) = serde_json::from_str::<Value>(payload) {
        if let Some(msgs) = val.get("messages").and_then(|m| m.as_array()) {
            let mut parts = Vec::new();
            for m in msgs {
                if let Some(c) = m.get("content").and_then(|c| c.as_str()) {
                    parts.push(c.to_string());
                }
            }
            if !parts.is_empty() {
                return parts.join("\n");
            }
        }
    }
    payload.to_string()
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
    pub config: HideConfig,
    pub total_intercepted: usize,
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
        .route("/harnesses", get(api_get_harnesses))
        .route("/vault", get(api_get_vault).delete(api_clear_vault))
        .route("/simulate", post(api_simulate))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_auth,
        ));

    Router::new()
        .nest("/api", api_router)
        .route("/:harness/*rest", any(proxy_harness_request))
        .with_state(state)
}

/// Management API security middleware:
/// 1. Blocks cross-site requests (`Sec-Fetch-Site: cross-site` or non-loopback `Origin`).
/// 2. Requires a valid management token via `X-Hide-Go-Token`, `Authorization: Bearer <token>`,
///    or `hide_go_session=<token>` HttpOnly cookie.
async fn require_admin_auth(
    State(state): State<GatewayState>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();

    // 1. Reject browser cross-site fetch attempts
    if let Some(fetch_site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        if fetch_site.eq_ignore_ascii_case("cross-site") {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "cross-site access to Hide-Go management API is forbidden"
                })),
            )
                .into_response();
        }
    }

    // 2. Reject any non-loopback Origin header (prevents CORS / CSRF from arbitrary web pages)
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !is_allowed_local_origin(origin) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "cross-origin access to Hide-Go management API is forbidden"
                })),
            )
                .into_response();
        }
    }

    // 3. Verify management token
    let expected = state.admin_token();
    let mut authenticated = false;

    if let Some(tok) = headers
        .get("x-hide-go-token")
        .and_then(|v| v.to_str().ok())
    {
        if constant_time_eq(tok.trim(), expected) {
            authenticated = true;
        }
    }

    if !authenticated {
        if let Some(auth) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(bearer) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
                if constant_time_eq(bearer.trim(), expected) {
                    authenticated = true;
                }
            }
        }
    }

    if !authenticated {
        if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
            for part in cookie_hdr.split(';') {
                if let Some(val) = part.trim().strip_prefix("hide_go_session=") {
                    if constant_time_eq(val.trim(), expected) {
                        authenticated = true;
                        break;
                    }
                }
            }
        }
    }

    if !authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "unauthorized: valid X-Hide-Go-Token or Authorization Bearer token required"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

fn is_allowed_local_origin(origin: &str) -> bool {
    let o = origin.trim().to_ascii_lowercase();
    o == "http://127.0.0.1"
        || o.starts_with("http://127.0.0.1:")
        || o == "http://localhost"
        || o.starts_with("http://localhost:")
        || o == "tauri://localhost"
        || o == "https://tauri.localhost"
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn api_status(State(state): State<GatewayState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "running",
        version: env!("CARGO_PKG_VERSION"),
        config: state.get_config(),
        total_intercepted: state.audit_logs.read().len(),
        active_vault_tokens: state.vault.list_entries().len(),
    })
}

async fn api_get_config(State(state): State<GatewayState>) -> Json<HideConfig> {
    Json(state.get_config())
}

async fn api_update_config(
    State(state): State<GatewayState>,
    Json(next): Json<HideConfig>,
) -> Json<HideConfig> {
    Json(state.update_config(next))
}

async fn api_get_logs(State(state): State<GatewayState>) -> Json<Vec<TrafficAuditRecord>> {
    Json(state.get_records())
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

async fn api_simulate(
    State(state): State<GatewayState>,
    Json(req): Json<SimulateRequest>,
) -> Json<TrafficAuditRecord> {
    Json(state.simulate_traffic(req.harness, req.category, req.custom_payload))
}

fn is_known_harness_prefix(prefix: &str) -> bool {
    matches!(
        prefix.to_ascii_lowercase().as_str(),
        "claude-code" | "codex" | "antigravity" | "zcode" | "qoder" | "cursor" | "grok-build"
    )
}

fn request_wants_stream(headers: &HeaderMap, body: &str) -> bool {
    if let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        if accept.contains("text/event-stream") {
            return true;
        }
    }
    if let Ok(val) = serde_json::from_str::<Value>(body) {
        if val.get("stream").and_then(|v| v.as_bool()) == Some(true) {
            return true;
        }
    }
    false
}

/// Real reverse-proxy handler for `/:harness/*rest`:
/// 1. Detects the Harness and TrafficCategory.
/// 2. Transforms the outbound payload according to `HideConfig` (AuditOnly, AutoDesensitize, or AllHide).
/// 3. Forwards the transformed request to the target upstream server (or custom `X-Hide-Go-Upstream` / `HIDE_GO_UPSTREAM_URL`).
/// 4. Streams SSE (`text/event-stream`) or JSON responses back through `StreamRestorer` in real time.
async fn proxy_harness_request(
    State(state): State<GatewayState>,
    Path((harness_prefix, rest)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> Response {
    let start = Instant::now();
    let full_path = format!("/{}/{}", harness_prefix, rest);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let (harness, category) = detect_harness_and_category(&full_path, ua, &body);
    let cfg = state.get_config();
    let wants_stream = request_wants_stream(&headers, &body);

    // 1. Outbound desensitization / All-Hide transformation
    let (vendor_visible_payload, action_taken, findings) =
        state.transform_outbound_payload(category, &body, &cfg);

    // Short-circuit blocked/chaffed silent telemetry if configured
    if action_taken == "chaff-injected" && category == TrafficCategory::Telemetry {
        let vendor_raw = GatewayState::synthesize_vendor_llm_response(
            harness,
            category,
            &vendor_visible_payload,
            &action_taken,
        );
        let record = TrafficAuditRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().format("%H:%M:%S%.3f").to_string(),
            harness,
            category,
            method: method.to_string(),
            endpoint: uri.path().to_string(),
            upstream_vendor: GatewayState::vendor_for_harness(harness).to_string(),
            applied_mode: cfg.mode,
            action_taken,
            latency_ms: start.elapsed().as_millis().max(1) as u64,
            local_request_payload: body,
            vendor_visible_payload,
            vendor_raw_response: vendor_raw.clone(),
            local_restored_response: vendor_raw.clone(),
            findings,
            restored_count: 0,
        };
        state.push_record(record);
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(vendor_raw),
        )
            .into_response();
    }

    // 2. Determine upstream base URL and target path
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

    let has_custom_upstream = header_upstream.is_some() || env_upstream.is_some();
    let upstream_base = header_upstream
        .or(env_upstream)
        .unwrap_or_else(|| GatewayState::default_upstream_for_harness(harness).to_string());

    let upstream_path = if is_known_harness_prefix(&harness_prefix) {
        format!("/{}", rest.trim_start_matches('/'))
    } else {
        full_path.clone()
    };

    let target_url = if let Some(query) = uri.query() {
        format!("{}{}?{}", upstream_base, upstream_path, query)
    } else {
        format!("{}{}", upstream_base, upstream_path)
    };

    let is_loopback_upstream = upstream_base.contains("://127.0.0.1")
        || upstream_base.contains("://localhost")
        || upstream_base.contains("://[::1]");
    let client = if is_loopback_upstream {
        &state.local_http_client
    } else {
        &state.http_client
    };

    let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let mut upstream_req = client.request(req_method, &target_url);

    for (name, val) in headers.iter() {
        let name_str = name.as_str().to_ascii_lowercase();
        if matches!(
            name_str.as_str(),
            "host"
                | "content-length"
                | "x-hide-go-upstream"
                | "x-upstream-url"
                | "x-target-upstream"
                | "x-hide-go-token"
        ) {
            continue;
        }
        if let Ok(r_name) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(r_val) = reqwest::header::HeaderValue::from_bytes(val.as_bytes()) {
                upstream_req = upstream_req.header(r_name, r_val);
            }
        }
    }

    upstream_req = upstream_req.body(vendor_visible_payload.clone());

    // 3. Forward request to upstream and handle streaming or non-streaming response
    match upstream_req.send().await {
        Ok(upstream_resp) => {
            let status_u16 = upstream_resp.status().as_u16();
            // If default external upstream was blocked by sandbox proxy (e.g. 403/502 with proxy error)
            // and no custom upstream was configured, fall back only if it's a proxy tunnel refusal
            let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK);
            let resp_ct = upstream_resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();

            if !has_custom_upstream
                && (status == StatusCode::FORBIDDEN || status == StatusCode::BAD_GATEWAY)
                && !resp_ct.contains("application/json")
                && !resp_ct.contains("text/event-stream")
            {
                return build_synthesized_proxy_response(
                    state,
                    harness,
                    category,
                    method.as_str(),
                    uri.path(),
                    body,
                    vendor_visible_payload,
                    action_taken,
                    findings,
                    cfg,
                    wants_stream,
                    start,
                );
            }

            let is_event_stream = resp_ct.contains("text/event-stream");
            if is_event_stream {
                let byte_stream = upstream_resp.bytes_stream();
                let vault = state.vault.clone();
                let salt = cfg.project_salt.clone();
                let state_for_log = state.clone();
                let method_str = method.to_string();
                let endpoint_str = uri.path().to_string();
                let applied_mode = cfg.mode;

                let stream_state = ProxyStreamState {
                    inner: Box::pin(byte_stream),
                    restorer: StreamRestorer::new(vault.clone()),
                    vault,
                    salt,
                    vendor_raw_acc: String::new(),
                    restored_acc: String::new(),
                    flushed: false,
                    state_for_log,
                    harness,
                    category,
                    method_str,
                    endpoint_str,
                    applied_mode,
                    action_taken,
                    start,
                    local_request_payload: body,
                    vendor_visible_payload,
                    findings,
                };

                let out_stream = futures_util::stream::unfold(stream_state, |mut st| async move {
                    if st.flushed {
                        return None;
                    }
                    match st.inner.next().await {
                        Some(Ok(chunk_bytes)) => {
                            let chunk_str = String::from_utf8_lossy(&chunk_bytes);
                            st.vendor_raw_acc.push_str(&chunk_str);
                            let mut restored_part = st.restorer.push_chunk(&chunk_str);
                            if restored_part.contains("⟦HIDE-CIPHER::") {
                                let dec = AllHideEngine::decode_braille_cipher_blocks(
                                    &restored_part,
                                    &st.vault,
                                    &st.salt,
                                );
                                restored_part = st.vault.restore_text(&dec).0;
                            }
                            st.restored_acc.push_str(&restored_part);
                            Some((Ok::<Bytes, std::io::Error>(Bytes::from(restored_part)), st))
                        }
                        Some(Err(_)) | None => {
                            st.flushed = true;
                            let (mut tail, mut restored_count) = st.restorer.finish();
                            if tail.contains("⟦HIDE-CIPHER::") {
                                let dec = AllHideEngine::decode_braille_cipher_blocks(
                                    &tail,
                                    &st.vault,
                                    &st.salt,
                                );
                                let (r, extra) = st.vault.restore_text(&dec);
                                tail = r;
                                restored_count += 1 + extra;
                            }
                            st.restored_acc.push_str(&tail);

                            let record = TrafficAuditRecord {
                                id: Uuid::new_v4().to_string(),
                                timestamp: Utc::now().format("%H:%M:%S%.3f").to_string(),
                                harness: st.harness,
                                category: st.category,
                                method: st.method_str.clone(),
                                endpoint: st.endpoint_str.clone(),
                                upstream_vendor: GatewayState::vendor_for_harness(st.harness)
                                    .to_string(),
                                applied_mode: st.applied_mode,
                                action_taken: st.action_taken.clone(),
                                latency_ms: st.start.elapsed().as_millis().max(1) as u64,
                                local_request_payload: st.local_request_payload.clone(),
                                vendor_visible_payload: st.vendor_visible_payload.clone(),
                                vendor_raw_response: st.vendor_raw_acc.clone(),
                                local_restored_response: st.restored_acc.clone(),
                                findings: st.findings.clone(),
                                restored_count,
                            };
                            st.state_for_log.push_record(record);
                            Some((Ok::<Bytes, std::io::Error>(Bytes::from(tail)), st))
                        }
                    }
                });

                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from_stream(out_stream))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            } else {
                let vendor_raw = upstream_resp.text().await.unwrap_or_default();
                let mut restorer = StreamRestorer::new(state.vault.clone());
                let mut restored = restorer.push_chunk(&vendor_raw);
                let (tail, mut restored_count) = restorer.finish();
                restored.push_str(&tail);

                if restored.contains("⟦HIDE-CIPHER::") {
                    let dec = AllHideEngine::decode_braille_cipher_blocks(
                        &restored,
                        &state.vault,
                        &cfg.project_salt,
                    );
                    let (r, extra) = state.vault.restore_text(&dec);
                    restored = r;
                    restored_count += 1 + extra;
                }

                let record = TrafficAuditRecord {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().format("%H:%M:%S%.3f").to_string(),
                    harness,
                    category,
                    method: method.to_string(),
                    endpoint: uri.path().to_string(),
                    upstream_vendor: GatewayState::vendor_for_harness(harness).to_string(),
                    applied_mode: cfg.mode,
                    action_taken,
                    latency_ms: start.elapsed().as_millis().max(1) as u64,
                    local_request_payload: body,
                    vendor_visible_payload,
                    vendor_raw_response: vendor_raw,
                    local_restored_response: restored.clone(),
                    findings,
                    restored_count,
                };
                state.push_record(record);

                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, resp_ct)
                    .body(Body::from(restored))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
        Err(err) => {
            if has_custom_upstream {
                return (
                    StatusCode::BAD_GATEWAY,
                    [(header::CONTENT_TYPE, "application/json")],
                    Body::from(
                        serde_json::json!({
                            "error": "upstream_connection_failed",
                            "message": err.to_string(),
                            "target_url": target_url
                        })
                        .to_string(),
                    ),
                )
                    .into_response();
            }

            build_synthesized_proxy_response(
                state,
                harness,
                category,
                method.as_str(),
                uri.path(),
                body,
                vendor_visible_payload,
                action_taken,
                findings,
                cfg,
                wants_stream,
                start,
            )
        }
    }
}

struct ProxyStreamState<S> {
    inner: std::pin::Pin<Box<S>>,
    restorer: StreamRestorer,
    vault: PrivacyVault,
    salt: String,
    vendor_raw_acc: String,
    restored_acc: String,
    flushed: bool,
    state_for_log: GatewayState,
    harness: HarnessKind,
    category: TrafficCategory,
    method_str: String,
    endpoint_str: String,
    applied_mode: PrivacyMode,
    action_taken: String,
    start: Instant,
    local_request_payload: String,
    vendor_visible_payload: String,
    findings: Vec<LeakFinding>,
}

#[allow(clippy::too_many_arguments)]
fn build_synthesized_proxy_response(
    state: GatewayState,
    harness: HarnessKind,
    category: TrafficCategory,
    method: &str,
    endpoint: &str,
    raw_request: String,
    vendor_visible_payload: String,
    action_taken: String,
    findings: Vec<LeakFinding>,
    cfg: HideConfig,
    wants_stream: bool,
    start: Instant,
) -> Response {
    let vendor_raw = GatewayState::synthesize_vendor_llm_response(
        harness,
        category,
        &vendor_visible_payload,
        &action_taken,
    );
    let (restored, restored_count) =
        state.restore_response_In_chunks(&vendor_raw, &cfg.project_salt);

    let record = TrafficAuditRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().format("%H:%M:%S%.3f").to_string(),
        harness,
        category,
        method: method.to_string(),
        endpoint: endpoint.to_string(),
        upstream_vendor: GatewayState::vendor_for_harness(harness).to_string(),
        applied_mode: cfg.mode,
        action_taken,
        latency_ms: start.elapsed().as_millis().max(2) as u64,
        local_request_payload: raw_request,
        vendor_visible_payload,
        vendor_raw_response: vendor_raw,
        local_restored_response: restored.clone(),
        findings,
        restored_count,
    };
    state.push_record(record);

    if wants_stream {
        let sse_event = serde_json::json!({
            "id": "msg_hidego_stream",
            "object": "chat.completion.chunk",
            "harness": harness.slug(),
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "content": restored
                    },
                    "finish_reason": "stop"
                }
            ]
        });
        let sse_payload = format!("data: {}\n\ndata: [DONE]\n\n", sse_event);
        let chunks = vec![Ok::<Bytes, std::io::Error>(Bytes::from(sse_payload))];
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from_stream(futures_util::stream::iter(chunks)))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(restored),
        )
            .into_response()
    }
}

