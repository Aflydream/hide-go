use crate::all_hide::AllHideEngine;
use crate::ca::{CaManager, RealCaTrustAdapter};
use crate::config::{
    HarnessKind, HideConfig, LeakFinding, PrivacyMode, TrafficAuditRecord, TrafficAuditSummary, TrafficCategory,
    MAX_UPSTREAM_IDLE_TIMEOUT_SECS, MIN_UPSTREAM_IDLE_TIMEOUT_SECS,
};
use crate::connect::{
    is_allowed_loopback_proxy_target, is_cloud_metadata_hostname, is_cloud_metadata_ip, is_forbidden_hostname,
    is_forbidden_operator_upstream, is_forbidden_target_host_port, is_loopback_host_str, is_loopback_ip,
    is_non_public_ip,
};
use crate::desensitizer::SemanticDesensitizer;
use crate::harness::{detect_harness_and_category, is_inference_endpoint, HarnessProfile};
use crate::harness_detect::{
    connect_all_detected, connect_harness, detect_all_harness_profiles, disconnect_harness, parse_harness_slug,
};
use crate::protobuf::{
    detect_protobuf_framing, restore_unary_protobuf, transform_protobuf_outbound, GrpcStreamDesensitizer,
    GrpcStreamRestorer, OutboundStreamMetrics, ProtobufFraming,
};
use crate::restore::restore_response;
use crate::scanner::{validate_custom_rules, ProjectScanner};
use crate::sse_restorer::SseRestorer;
use crate::system_proxy::{is_system_proxy_active_for_port, sync_system_proxy_runtime};
use crate::upstream_proxy::detect_upstream_proxy_for_host;
use crate::vault::{mask_preview, PrivacyVault, VaultEntry};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use chrono::Local;
use futures_util::StreamExt;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::Frame;
use parking_lot::RwLock;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use uuid::Uuid;

pub const MAX_AUDIT_LOGS: usize = 200;
/// Each stored payload is capped so 200 records stay within a few tens of MB.
pub const MAX_STORED_PAYLOAD: usize = 64 * 1024;
/// Request bodies above this are rejected (413). Long agent sessions with images fit easily.
pub const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;
/// Maximum buffered non-SSE upstream response body (64 MiB) before failing with 502.
pub const MAX_RESPONSE_BODY: usize = 64 * 1024 * 1024;
/// Maximum incomplete SSE line/event bytes held in memory without a newline boundary.
const MAX_SSE_PENDING_BYTES: usize = 8 * 1024 * 1024;
/// Maximum concurrent HTTP CONNECT tunnels kept open at once.
const MAX_CONCURRENT_CONNECT_TUNNELS: usize = 256;
/// Minimum required length for an operator-supplied `HIDE_GO_ADMIN_TOKEN`.
pub const MIN_ADMIN_TOKEN_LEN: usize = 24;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const UPSTREAM_PROXY_CACHE_TTL: Duration = Duration::from_secs(3);
const UPDATE_RELEASE_API_URL: &str = "https://api.github.com/repos/Aflydream/hide-go/releases/latest";
const UPDATE_RELEASE_FALLBACK_URL: &str = "https://github.com/Aflydream/hide-go/releases/latest";
const UPDATE_CACHE_TTL: Duration = Duration::from_secs(600);
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct PublicOnlyDnsResolver {
    allow_loopback: bool,
}

impl Resolve for PublicOnlyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allow_loopback = self.allow_loopback;
        Box::pin(async move {
            let clean = host.trim_start_matches('[').trim_end_matches(']');
            if is_forbidden_hostname(clean) && !(allow_loopback && is_loopback_host_str(clean)) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("blocked SSRF resolution for host {host}"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }
            if let Ok(ip) = clean.parse::<IpAddr>() {
                let allowed = if is_loopback_ip(ip) {
                    allow_loopback
                } else {
                    !is_non_public_ip(ip)
                };
                if !allowed {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("blocked non-public IP literal {ip}"),
                    )) as Box<dyn std::error::Error + Send + Sync>);
                }
                return Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as Addrs);
            }
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((clean, 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .filter(|sa| {
                    let ip = sa.ip();
                    if is_loopback_ip(ip) {
                        allow_loopback
                    } else {
                        !is_non_public_ip(ip)
                    }
                })
                .collect();
            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("host {host} resolved solely to non-public addresses"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

struct LoopbackOnlyDnsResolver;

impl Resolve for LoopbackOnlyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let clean = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = clean.parse::<IpAddr>() {
                if !is_loopback_ip(ip) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("local client refused non-loopback IP {ip}"),
                    )) as Box<dyn std::error::Error + Send + Sync>);
                }
                return Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as Addrs);
            }
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((clean, 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .filter(|sa| is_loopback_ip(sa.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("local client refused non-loopback host {host}"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

struct OperatorUpstreamDnsResolver;

impl Resolve for OperatorUpstreamDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let clean = host.trim_start_matches('[').trim_end_matches(']');
            if is_cloud_metadata_hostname(clean) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("blocked metadata resolution for host {host}"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }
            if let Ok(ip) = clean.parse::<IpAddr>() {
                if is_cloud_metadata_ip(ip) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("blocked metadata IP {ip}"),
                    )) as Box<dyn std::error::Error + Send + Sync>);
                }
                return Ok(Box::new(std::iter::once(SocketAddr::new(ip, 0))) as Addrs);
            }
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((clean, 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .filter(|sa| !is_cloud_metadata_ip(sa.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("operator upstream host {host} resolved solely to blocked metadata addresses"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Lifetime counters (survive the 200-record log window).
#[derive(Debug, Default)]
pub struct GatewayStats {
    pub requests: AtomicU64,
    pub findings: AtomicU64,
    pub restored: AtomicU64,
    pub withheld: AtomicU64,
    pub blocked: AtomicU64,
}

/// Lightweight metadata for a host observed via `HTTP CONNECT` (hostname/port only, no payload).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedConnectHost {
    pub host: String,
    pub port: u16,
    pub mitm: bool,
    pub tls_failed: bool,
    pub count: u64,
    pub last_seen_at: String,
    #[serde(skip)]
    last_seq: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MitmHostsResponse {
    pub mitm_extra_hosts: Vec<String>,
    pub mitm_bypass_hosts: Vec<String>,
    pub system_proxy_chain: bool,
    pub system_proxy_supported: bool,
    pub system_proxy_active: bool,
    pub observed_hosts: Vec<ObservedConnectHost>,
}

const MAX_OBSERVED_CONNECT_HOSTS: usize = 64;

type UpstreamProxyCache = Arc<RwLock<Option<(Instant, Option<String>, Option<reqwest::Client>)>>>;

/// Shared application state for the Hide-Go gateway
#[derive(Clone)]
pub struct GatewayState {
    pub config: Arc<RwLock<HideConfig>>,
    pub config_path: Option<Arc<PathBuf>>,
    pub vault: PrivacyVault,
    pub ca: Arc<CaManager>,
    pub audit_logs: Arc<RwLock<VecDeque<TrafficAuditRecord>>>,
    pub harness_stats: Arc<RwLock<HashMap<HarnessKind, (u64, String)>>>,
    pub observed_connect_hosts: Arc<RwLock<HashMap<String, ObservedConnectHost>>>,
    pub observed_connect_seq: Arc<AtomicU64>,
    pub stats: Arc<GatewayStats>,
    pub http_client: reqwest::Client,
    pub local_http_client: reqwest::Client,
    pub operator_http_client: reqwest::Client,
    pub upstream_proxy_cache: UpstreamProxyCache,
    pub update_http_client: reqwest::Client,
    pub update_cache: Arc<RwLock<Option<(Instant, UpdateCheckResult)>>>,
    pub admin_token: Arc<String>,
    pub connect_semaphore: Arc<Semaphore>,
    pub allow_loopback_for_tests: bool,
    pub use_system_upstream_proxy: bool,
    pub started_at: Instant,
}

impl Default for GatewayState {
    fn default() -> Self {
        Self::new(HideConfig::default())
    }
}

fn build_client(local: bool, allow_loopback: bool) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        // Upper bound; per-request idle timeout from `cfg.effective_upstream_idle_timeout()`
        // is enforced explicitly via `tokio::time::timeout` so live config updates take effect immediately.
        .read_timeout(Duration::from_secs(MAX_UPSTREAM_IDLE_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if local {
        b = b.dns_resolver(Arc::new(LoopbackOnlyDnsResolver));
    } else if let Some(upstream_proxy) = std::env::var("HIDE_GO_UPSTREAM_PROXY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        if let Ok(proxy) = reqwest::Proxy::all(&upstream_proxy) {
            b = b.proxy(proxy);
        } else {
            b = b.dns_resolver(Arc::new(PublicOnlyDnsResolver { allow_loopback }));
        }
    } else {
        b = b.dns_resolver(Arc::new(PublicOnlyDnsResolver { allow_loopback }));
    }
    b.build().unwrap_or_default()
}

fn build_operator_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(Duration::from_secs(MAX_UPSTREAM_IDLE_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(OperatorUpstreamDnsResolver))
        .build()
        .unwrap_or_default()
}

fn build_proxied_forward_client(proxy_url: &str) -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(Duration::from_secs(MAX_UPSTREAM_IDLE_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy_url).ok()?)
        .build()
        .ok()
}

fn build_update_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(UPDATE_REQUEST_TIMEOUT)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .no_proxy()
        .dns_resolver(Arc::new(PublicOnlyDnsResolver { allow_loopback: false }))
        .build()
        .unwrap_or_default()
}

fn default_ca_manager() -> Arc<CaManager> {
    let adapter = Arc::new(RealCaTrustAdapter);
    if let Some(dir) = CaManager::default_ca_dir() {
        match CaManager::load_or_create(dir, adapter.clone()) {
            Ok(mgr) => return Arc::new(mgr),
            Err(err) => tracing::warn!("failed to initialize persisted CA manager: {err}"),
        }
    }
    Arc::new(CaManager::ephemeral(adapter).expect("ephemeral CA generation must succeed"))
}

impl GatewayState {
    pub fn new(config: HideConfig) -> Self {
        let admin_token = match std::env::var("HIDE_GO_ADMIN_TOKEN") {
            Ok(raw) => {
                let trimmed = raw.trim().to_string();
                if trimmed.len() >= MIN_ADMIN_TOKEN_LEN {
                    trimmed
                } else {
                    if !trimmed.is_empty() {
                        tracing::warn!(
                            "ignoring HIDE_GO_ADMIN_TOKEN shorter than {} characters; generating strong ephemeral token",
                            MIN_ADMIN_TOKEN_LEN
                        );
                    }
                    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
                }
            }
            Err(_) => format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        };
        Self {
            config: Arc::new(RwLock::new(config)),
            config_path: None,
            vault: PrivacyVault::new(),
            ca: default_ca_manager(),
            audit_logs: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOGS))),
            harness_stats: Arc::new(RwLock::new(HashMap::new())),
            observed_connect_hosts: Arc::new(RwLock::new(HashMap::new())),
            observed_connect_seq: Arc::new(AtomicU64::new(1)),
            stats: Arc::new(GatewayStats::default()),
            http_client: build_client(false, false),
            local_http_client: build_client(true, true),
            operator_http_client: build_operator_client(),
            upstream_proxy_cache: Arc::new(RwLock::new(None)),
            update_http_client: build_update_client(),
            update_cache: Arc::new(RwLock::new(None)),
            admin_token: Arc::new(admin_token),
            connect_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECT_TUNNELS)),
            allow_loopback_for_tests: false,
            use_system_upstream_proxy: true,
            started_at: Instant::now(),
        }
    }

    /// Enable loopback upstreams for integration/unit tests targeting local mock servers.
    #[doc(hidden)]
    pub fn with_loopback_for_tests(mut self, allow: bool) -> Self {
        self.allow_loopback_for_tests = allow;
        self.use_system_upstream_proxy = !allow;
        self.http_client = build_client(false, allow);
        self
    }

    /// Replace the outbound `http_client` (disabling host system proxy discovery).
    #[doc(hidden)]
    pub fn with_custom_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = client;
        self.use_system_upstream_proxy = false;
        self
    }

    pub fn with_ca(mut self, ca: Arc<CaManager>) -> Self {
        self.ca = ca;
        self
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

    fn cached_upstream_proxy_client(&self, proxy_url: &str) -> Option<reqwest::Client> {
        {
            let guard = self.upstream_proxy_cache.read();
            if let Some((captured_at, cached_url, cached_client)) = guard.as_ref() {
                if captured_at.elapsed() < UPSTREAM_PROXY_CACHE_TTL && cached_url.as_deref() == Some(proxy_url) {
                    return cached_client.clone();
                }
            }
        }
        let client = build_proxied_forward_client(proxy_url);
        *self.upstream_proxy_cache.write() = Some((Instant::now(), Some(proxy_url.to_string()), client.clone()));
        client
    }

    /// Resolve the outbound `reqwest::Client` for `target_host`, automatically chaining an active
    /// environment or Windows system proxy for external hosts while keeping loopback/LAN direct.
    fn resolve_http_clients(
        &self,
        target_host: &str,
        is_loopback: bool,
        allow_operator_private: bool,
    ) -> (reqwest::Client, Option<reqwest::Client>) {
        let direct = if allow_operator_private {
            self.operator_http_client.clone()
        } else if is_loopback {
            self.local_http_client.clone()
        } else {
            self.http_client.clone()
        };

        if is_loopback || self.allow_loopback_for_tests || !self.use_system_upstream_proxy {
            return (direct, None);
        }

        let own_port = self.config.read().proxy_port;
        if let Some(proxy_url) = detect_upstream_proxy_for_host(own_port, Some(target_host)) {
            if let Some(proxied) = self.cached_upstream_proxy_client(&proxy_url) {
                return (proxied, Some(direct));
            }
        }
        (direct, None)
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
            let mut hstats = self.harness_stats.write();
            let entry = hstats.entry(record.harness).or_insert_with(|| (0, String::new()));
            entry.0 += 1;
            entry.1 = record.timestamp.clone();
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

    /// Record a `CONNECT host:port` destination in memory (hostname/port metadata only).
    pub fn record_connect_host(&self, host: &str, port: u16, mitm: bool, tls_failed: bool) {
        let key = format!("{}:{port}", host.trim().to_ascii_lowercase());
        let seq = self.observed_connect_seq.fetch_add(1, Ordering::Relaxed);
        let now = Local::now().format("%H:%M:%S").to_string();
        let mut map = self.observed_connect_hosts.write();
        if let Some(existing) = map.get_mut(&key) {
            existing.mitm = mitm;
            existing.tls_failed = existing.tls_failed || tls_failed;
            if !tls_failed {
                existing.count = existing.count.saturating_add(1);
            }
            existing.last_seen_at = now;
            existing.last_seq = seq;
            return;
        }
        if map.len() >= MAX_OBSERVED_CONNECT_HOSTS {
            if let Some(oldest_key) = map.iter().min_by_key(|(_, v)| v.last_seq).map(|(k, _)| k.clone()) {
                map.remove(&oldest_key);
            }
        }
        map.insert(
            key,
            ObservedConnectHost {
                host: host.trim().to_ascii_lowercase(),
                port,
                mitm,
                tls_failed,
                count: 1,
                last_seen_at: now,
                last_seq: seq,
            },
        );
    }

    /// Surface a failed MITM TLS handshake as a visible audit entry so untrusted CA or
    /// certificate-pinning issues never fail silently with `0 / 0` logs.
    pub fn record_mitm_tls_failure(&self, host: &str, port: u16, detail: &str) {
        self.record_connect_host(host, port, true, true);
        let harness = detect_harness_for_host(host).unwrap_or(HarnessKind::Generic);
        let cfg = self.get_config();
        let endpoint = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };
        let hint = format!(
            "TLS handshake rejected by client for {host}:{port} ({detail}). Trust the local Hide-Go Root CA in Integrations, or add {host} to mitmBypassHosts if the client pins certificates."
        );
        self.push_record(build_record(RecordInput {
            harness,
            category: TrafficCategory::InteractivePrompt,
            method: "CONNECT".to_string(),
            endpoint,
            mode: cfg.mode,
            action_taken: "tls-handshake-failed".to_string(),
            status: 0,
            start: Instant::now(),
            simulated: false,
            local_request: "",
            vendor_request: "",
            vendor_response: "",
            local_response: &hint,
            findings: Vec::new(),
            restored_count: 0,
            withheld_count: 0,
            upstream_vendor: Some(host.to_string()),
        }));
    }

    pub fn get_config(&self) -> HideConfig {
        self.config.read().clone()
    }

    /// Validate, apply and persist a configuration. Invalid custom rules are rejected rather
    /// than silently skipped at scan time.
    pub fn try_update_config(&self, mut next: HideConfig) -> Result<HideConfig, String> {
        validate_custom_rules(&next.custom_rules)?;
        if next.project_salt.trim().len() < 8 {
            return Err("项目 Salt 至少需要 8 个字符".to_string());
        }
        next.upstream_idle_timeout_secs = next
            .upstream_idle_timeout_secs
            .clamp(MIN_UPSTREAM_IDLE_TIMEOUT_SECS, MAX_UPSTREAM_IDLE_TIMEOUT_SECS);
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
        let stats = self.harness_stats.read().clone();
        detect_all_harness_profiles(port, &stats)
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
        if should_block_telemetry(category, endpoint, cfg) {
            let ack = serde_json::json!({"status": "ok", "accepted": true}).to_string();
            let findings = scan_telemetry_findings(raw_request, cfg);
            return build_record(RecordInput {
                harness,
                category,
                method: method.to_string(),
                endpoint: endpoint.to_string(),
                mode: cfg.mode,
                action_taken: "telemetry-blocked".to_string(),
                status: 0,
                start,
                simulated: true,
                local_request: raw_request,
                vendor_request: "",
                vendor_response: "",
                local_response: &ack,
                findings,
                restored_count: 0,
                withheld_count: 0,
                upstream_vendor: None,
            });
        }
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
            upstream_vendor: None,
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
            (HarnessKind::ClaudeCode, TrafficCategory::Telemetry) => "/claude-code/api/event_logging/batch".to_string(),
            (HarnessKind::Generic, TrafficCategory::Telemetry) => "/v1/telemetry".to_string(),
            (_, TrafficCategory::Telemetry) => format!("/{}/v1/telemetry", harness.slug()),
            (HarnessKind::ClaudeCode, _) => "/claude-code/v1/messages".to_string(),
            (HarnessKind::Codex, _) => "/codex/v1/responses".to_string(),
            (HarnessKind::Antigravity, _) => {
                "/antigravity/v1beta/models/gemini-2.5-pro:streamGenerateContent".to_string()
            }
            (HarnessKind::Zcode, _) => "/zcode/v1/chat/completions".to_string(),
            (HarnessKind::Qoder, TrafficCategory::CodebaseIndexing) => "/qoder/v1/codebase/index-sync".to_string(),
            (HarnessKind::Qoder, _) => "/qoder/v1/chat/completions".to_string(),
            (HarnessKind::Cursor, TrafficCategory::CodebaseIndexing) => {
                "/cursor/repo-service/upload-chunks".to_string()
            }
            (HarnessKind::Cursor, _) => "/cursor/v1/chat/completions".to_string(),
            (HarnessKind::GrokBuild, _) => "/grok-build/v1/chat/completions".to_string(),
            (HarnessKind::Generic, _) => "/v1/chat/completions".to_string(),
        };
        let sample = custom_payload
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| Self::default_sample_payload(harness, category));
        let record = self.process_payload_cycle(harness, category, "POST", &endpoint, &sample, &cfg);
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
    transform_outbound_scoped(vault, category, raw_request, cfg, None)
}

/// Scope-isolated outbound transformation (prevents cross-vendor token/secret reflection).
pub fn transform_outbound_scoped(
    vault: &PrivacyVault,
    category: TrafficCategory,
    raw_request: &str,
    cfg: &HideConfig,
    scope: Option<&str>,
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
            let res = SemanticDesensitizer::process_with_scope(raw_request, cfg, vault, scope);
            (res.transformed_payload, "desensitized".to_string(), res.findings)
        }
        PrivacyMode::AllHide => {
            let out = AllHideEngine::process_with_scope(raw_request, category, cfg, vault, scope);
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

fn scan_telemetry_findings(raw_request: &str, cfg: &HideConfig) -> Vec<LeakFinding> {
    ProjectScanner::scan_matches(raw_request, cfg)
        .into_iter()
        .map(|(kind, label, raw, severity)| LeakFinding {
            kind,
            label,
            original_preview: mask_preview(&raw),
            replacement_token: "已拦截（未出境）".to_string(),
            severity,
            count: 1,
        })
        .collect()
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
    upstream_vendor: Option<String>,
}

fn build_record(i: RecordInput) -> TrafficAuditRecord {
    let mut truncated = false;
    let upstream_vendor = i
        .upstream_vendor
        .unwrap_or_else(|| GatewayState::vendor_for_harness(i.harness).to_string());
    TrafficAuditRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
        harness: i.harness,
        category: i.category,
        method: i.method,
        endpoint: i.endpoint,
        upstream_vendor,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_url: String,
    pub published_at: Option<String>,
    pub checked_at: String,
}

/// Build the full Axum Router serving both:
/// 1. Authenticated, Same-Origin-only Control & Inspection REST API for the Desktop UI (`/api/*`)
/// 2. Live Reverse Proxy & Harness Gateway endpoints (`/:harness/*path`)
pub fn build_router(state: GatewayState) -> Router {
    let api_router = Router::new()
        .route("/status", get(api_status))
        .route(
            "/config",
            get(api_get_config).post(api_update_config).put(api_update_config),
        )
        .route("/logs", get(api_get_logs).delete(api_clear_logs))
        .route("/logs/:id", get(api_get_log))
        .route("/harnesses", get(api_get_harnesses))
        .route("/harnesses/connect-all", post(api_connect_all_harnesses))
        .route("/harnesses/:kind/connect", post(api_connect_harness))
        .route("/harnesses/:kind/disconnect", post(api_disconnect_harness))
        .route("/vault", get(api_get_vault).delete(api_clear_vault))
        .route("/ca/status", get(api_ca_status))
        .route("/ca/trust", post(api_ca_trust).delete(api_ca_untrust))
        .route("/ca/cert", get(api_ca_cert))
        .route("/mitm/hosts", get(api_mitm_hosts))
        .route("/simulate", post(api_simulate))
        .route("/rules/validate", post(api_validate_rule))
        .route("/updates/check", get(api_check_updates))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_auth));

    Router::new()
        .nest("/api", api_router)
        .route("/:harness/*rest", any(proxy_harness_request))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY))
        .with_state(state)
}

pub(crate) fn is_admin_authenticated(headers: &HeaderMap, expected: &str) -> bool {
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
    [header_token, bearer]
        .into_iter()
        .flatten()
        .any(|t| constant_time_eq(t, expected))
}

/// Management API security middleware:
/// 1. Blocks cross-site requests (`Sec-Fetch-Site: cross-site` or non-loopback `Origin`).
/// 2. Requires the management token via `X-Hide-Go-Token` or `Authorization: Bearer <token>`.
///    Cookies are deliberately not accepted: browsers send `127.0.0.1` cookies to every
///    local port, so a cookie would leak the token to unrelated local dev servers.
async fn require_admin_auth(State(state): State<GatewayState>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if !is_local_request(headers, req.uri()) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "cross-origin access is forbidden"})),
        )
            .into_response();
    }
    if !is_admin_authenticated(headers, state.admin_token()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized: valid X-Hide-Go-Token or Authorization Bearer token required"})),
        )
            .into_response();
    }
    next.run(req).await
}

pub fn is_local_browser_request(headers: &HeaderMap) -> bool {
    let mut host_values = headers.get_all(header::HOST).iter();
    let Some(first_host) = host_values.next() else {
        return false;
    };
    if host_values.next().is_some() {
        return false;
    }
    let authority = first_host
        .to_str()
        .ok()
        .and_then(|host| host.parse::<axum::http::uri::Authority>().ok());
    is_local_authority(headers, authority.as_ref())
}

/// Same loopback + exact-origin guard as `is_local_browser_request`, with HTTP/2 `:authority`
/// fallback when the `Host` header is absent.
pub fn is_local_request(headers: &HeaderMap, uri: &Uri) -> bool {
    let mut host_values = headers.get_all(header::HOST).iter();
    let authority = match host_values.next() {
        Some(raw) => {
            if host_values.next().is_some() {
                return false;
            }
            raw.to_str()
                .ok()
                .and_then(|host| host.parse::<axum::http::uri::Authority>().ok())
        }
        None => uri.authority().cloned(),
    };
    is_local_authority(headers, authority.as_ref())
}

fn is_local_authority(headers: &HeaderMap, authority: Option<&axum::http::uri::Authority>) -> bool {
    let Some(authority) = authority else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
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
            | "proxy-connection"
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

/// Hop-by-hop and internal proxy headers removed before forwarding.
fn should_strip_outbound_header(name: &str, headers: &HeaderMap) -> bool {
    is_hop_by_hop(name, headers)
        || matches!(
            name,
            "host"
                | "content-length"
                | "origin"
                | "referer"
                | "x-upstream-url"
                | "x-target-upstream"
                | "via"
                | "forwarded"
                | "x-real-ip"
        )
        || name.starts_with("x-hide-go-")
        || name.starts_with("x-forwarded-")
        || name.starts_with("sec-fetch-")
}

fn filter_forwarded_headers(
    headers: &HeaderMap,
    admin_token: &str,
    strip_accept_encoding: bool,
    strip_content_encoding: bool,
) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.as_str();
        if should_strip_outbound_header(lower, headers)
            || (strip_accept_encoding && name == header::ACCEPT_ENCODING)
            || (strip_content_encoding && name == header::CONTENT_ENCODING)
        {
            continue;
        }
        if name == header::COOKIE {
            if let Ok(cookies) = value.to_str() {
                if let Some(filtered) = filter_hide_go_session_cookie(cookies) {
                    forwarded.append(name.clone(), filtered);
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
    forwarded
}

fn upstream_request_headers(headers: &HeaderMap, admin_token: &str, strip_content_encoding: bool) -> HeaderMap {
    let mut forwarded = filter_forwarded_headers(headers, admin_token, true, strip_content_encoding);
    forwarded.insert(header::ACCEPT_ENCODING, "identity".parse().unwrap());
    forwarded
}

fn is_hide_go_session_set_cookie(value: &axum::http::HeaderValue) -> bool {
    value
        .to_str()
        .ok()
        .and_then(|s| s.split(';').next())
        .and_then(|pair| pair.split_once('='))
        .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("hide_go_session"))
}

fn upstream_response_headers(headers: &HeaderMap, preserve_origin_headers: bool) -> HeaderMap {
    headers
        .iter()
        .filter(|(name, value)| {
            if is_hop_by_hop(name.as_str(), headers)
                || matches!(
                    name.as_str(),
                    "content-length" | "content-encoding" | "etag" | "content-md5" | "digest"
                )
            {
                return false;
            }
            if preserve_origin_headers {
                !(*name == header::SET_COOKIE && is_hide_go_session_set_cookie(value))
            } else {
                *name != header::SET_COOKIE && !name.as_str().starts_with("access-control-")
            }
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

#[derive(Deserialize, Default)]
struct UpdateCheckQuery {
    #[serde(default)]
    force: bool,
}

#[derive(Deserialize)]
struct GithubLatestRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    published_at: Option<String>,
}

fn parse_semver_parts(raw: &str) -> Option<(u64, u64, u64, bool)> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let without_build = trimmed.split('+').next()?.trim();
    if without_build.is_empty() {
        return None;
    }
    let (core, is_prerelease) = match without_build.split_once('-') {
        Some((base, pre)) if !pre.trim().is_empty() => (base, true),
        Some((base, _)) => (base, false),
        None => (without_build, false),
    };
    let mut nums = core.split('.');
    let major: u64 = nums.next()?.parse().ok()?;
    let minor: u64 = nums.next().unwrap_or("0").parse().ok()?;
    let patch: u64 = nums.next().unwrap_or("0").parse().ok()?;
    if nums.next().is_some() {
        return None;
    }
    Some((major, minor, patch, is_prerelease))
}

fn is_newer_version(current: &str, latest: &str) -> bool {
    let Some((cmaj, cmin, cpat, cpre)) = parse_semver_parts(current) else {
        return false;
    };
    let Some((lmaj, lmin, lpat, lpre)) = parse_semver_parts(latest) else {
        return false;
    };
    match (lmaj, lmin, lpat).cmp(&(cmaj, cmin, cpat)) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => cpre && !lpre,
    }
}

fn build_proxied_update_client(proxy_url: &str) -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(UPDATE_REQUEST_TIMEOUT)
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy_url).ok()?)
        .build()
        .ok()
}

#[derive(Debug)]
struct UpdateFetchError {
    is_transport: bool,
    message: String,
}

async fn fetch_latest_release_from(
    client: &reqwest::Client,
    url: &str,
    current_version: &str,
) -> Result<UpdateCheckResult, UpdateFetchError> {
    let resp = client
        .get(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header(header::USER_AGENT, format!("Hide-Go/{current_version}"))
        .send()
        .await
        .map_err(|e| UpdateFetchError {
            is_transport: true,
            message: if e.is_timeout() {
                "request timed out".to_string()
            } else if e.is_connect() {
                "network unreachable".to_string()
            } else {
                "network request failed".to_string()
            },
        })?;

    if !resp.status().is_success() {
        return Err(UpdateFetchError {
            is_transport: false,
            message: format!("upstream returned HTTP {}", resp.status().as_u16()),
        });
    }

    let release: GithubLatestRelease = resp.json().await.map_err(|e| UpdateFetchError {
        is_transport: false,
        message: format!("invalid release metadata: {e}"),
    })?;

    let latest_version = release.tag_name.trim().trim_start_matches(['v', 'V']).to_string();
    if parse_semver_parts(&latest_version).is_none() {
        return Err(UpdateFetchError {
            is_transport: false,
            message: "invalid release version tag".to_string(),
        });
    }

    let candidate_url = release.html_url.trim();
    let release_url = if candidate_url
        .to_ascii_lowercase()
        .starts_with("https://github.com/aflydream/hide-go/")
    {
        candidate_url.to_string()
    } else {
        UPDATE_RELEASE_FALLBACK_URL.to_string()
    };

    Ok(UpdateCheckResult {
        current_version: current_version.trim().trim_start_matches(['v', 'V']).to_string(),
        update_available: is_newer_version(current_version, &latest_version),
        latest_version,
        release_url,
        published_at: release.published_at,
        checked_at: Local::now().to_rfc3339(),
    })
}

async fn api_check_updates(State(state): State<GatewayState>, Query(query): Query<UpdateCheckQuery>) -> Response {
    if !query.force {
        if let Some((captured_at, cached)) = state.update_cache.read().clone() {
            if captured_at.elapsed() < UPDATE_CACHE_TTL {
                return Json(cached).into_response();
            }
        }
    }

    let own_port = state.config.read().proxy_port;
    let res = if let Some(proxied) =
        detect_upstream_proxy_for_host(own_port, Some("api.github.com")).and_then(|p| build_proxied_update_client(&p))
    {
        match fetch_latest_release_from(&proxied, UPDATE_RELEASE_API_URL, env!("CARGO_PKG_VERSION")).await {
            Ok(ok) => Ok(ok),
            Err(err) if err.is_transport => {
                fetch_latest_release_from(
                    &state.update_http_client,
                    UPDATE_RELEASE_API_URL,
                    env!("CARGO_PKG_VERSION"),
                )
                .await
            }
            Err(err) => Err(err),
        }
    } else {
        fetch_latest_release_from(
            &state.update_http_client,
            UPDATE_RELEASE_API_URL,
            env!("CARGO_PKG_VERSION"),
        )
        .await
    };

    match res {
        Ok(result) => {
            *state.update_cache.write() = Some((Instant::now(), result.clone()));
            Json(result).into_response()
        }
        Err(err) => json_error(StatusCode::BAD_GATEWAY, "update_check_failed", err.message),
    }
}

async fn api_get_config(State(state): State<GatewayState>) -> Json<HideConfig> {
    Json(state.get_config())
}

async fn api_update_config(State(state): State<GatewayState>, Json(mut next): Json<HideConfig>) -> Response {
    if next.harness_upstreams.is_empty() {
        next.harness_upstreams = state.config.read().harness_upstreams.clone();
    }
    match state.try_update_config(next) {
        Ok(cfg) => {
            if state.use_system_upstream_proxy && !state.allow_loopback_for_tests {
                sync_system_proxy_runtime(cfg.system_proxy_chain, cfg.proxy_port);
            }
            Json(cfg).into_response()
        }
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

async fn api_get_harnesses(State(state): State<GatewayState>) -> Response {
    match tokio::task::spawn_blocking(move || state.get_harness_profiles()).await {
        Ok(list) => Json(list).into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "detect_failed",
            "harness scan panicked",
        ),
    }
}

fn refresh_harness_upstreams_from_disk(state: &GatewayState) {
    let path = state.config_path.as_deref().cloned().or_else(HideConfig::default_path);
    let Some(path) = path else {
        return;
    };
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(disk_cfg) = serde_json::from_str::<HideConfig>(&text) {
            let (sys_proxy_enabled, proxy_port) = {
                let mut cfg = state.config.write();
                cfg.harness_upstreams = disk_cfg.harness_upstreams;
                cfg.allowed_loopback_proxy_targets = disk_cfg.allowed_loopback_proxy_targets;
                cfg.system_proxy_chain = disk_cfg.system_proxy_chain;
                (cfg.system_proxy_chain, cfg.proxy_port)
            };
            if state.use_system_upstream_proxy && !state.allow_loopback_for_tests {
                sync_system_proxy_runtime(sys_proxy_enabled, proxy_port);
            }
        }
    }
}

async fn api_connect_all_harnesses(State(state): State<GatewayState>) -> Response {
    let port = state.config.read().proxy_port;
    match tokio::task::spawn_blocking(move || connect_all_detected(port)).await {
        Ok(results) => {
            refresh_harness_upstreams_from_disk(&state);
            Json(results).into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connect_failed",
            "harness connect task panicked",
        ),
    }
}

async fn api_connect_harness(State(state): State<GatewayState>, Path(kind): Path<String>) -> Response {
    let Some(parsed) = parse_harness_slug(&kind) else {
        return json_error(StatusCode::BAD_REQUEST, "unknown_harness", "未知的工具标识");
    };
    let port = state.config.read().proxy_port;
    match tokio::task::spawn_blocking(move || connect_harness(parsed, port)).await {
        Ok(res) => {
            refresh_harness_upstreams_from_disk(&state);
            Json(res).into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connect_failed",
            "harness connect task panicked",
        ),
    }
}

async fn api_disconnect_harness(State(state): State<GatewayState>, Path(kind): Path<String>) -> Response {
    let Some(parsed) = parse_harness_slug(&kind) else {
        return json_error(StatusCode::BAD_REQUEST, "unknown_harness", "未知的工具标识");
    };
    match tokio::task::spawn_blocking(move || disconnect_harness(parsed)).await {
        Ok(res) => {
            refresh_harness_upstreams_from_disk(&state);
            Json(res).into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "disconnect_failed",
            "harness disconnect task panicked",
        ),
    }
}

async fn api_get_vault(State(state): State<GatewayState>) -> Json<Vec<VaultEntry>> {
    Json(state.get_vault_entries())
}

async fn api_clear_vault(State(state): State<GatewayState>) -> StatusCode {
    state.clear_vault();
    StatusCode::NO_CONTENT
}

async fn api_ca_status(State(state): State<GatewayState>) -> Response {
    let ca = state.ca.clone();
    match tokio::task::spawn_blocking(move || ca.status()).await {
        Ok(status) => Json(status).into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ca_status_failed",
            "CA status task panicked",
        ),
    }
}

async fn api_ca_trust(State(state): State<GatewayState>) -> Response {
    let ca = state.ca.clone();
    match tokio::task::spawn_blocking(move || ca.install_trust()).await {
        Ok(Ok(status)) => Json(status).into_response(),
        Ok(Err(msg)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "ca_trust_failed", msg),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ca_trust_failed",
            "CA trust task panicked",
        ),
    }
}

async fn api_ca_untrust(State(state): State<GatewayState>) -> Response {
    let ca = state.ca.clone();
    match tokio::task::spawn_blocking(move || ca.remove_trust()).await {
        Ok(Ok(status)) => Json(status).into_response(),
        Ok(Err(msg)) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "ca_untrust_failed", msg),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ca_untrust_failed",
            "CA untrust task panicked",
        ),
    }
}

async fn api_ca_cert(State(state): State<GatewayState>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"hide-go-ca.crt\""),
            (header::CACHE_CONTROL, "no-store"),
        ],
        state.ca.ca_cert_pem().to_string(),
    )
        .into_response()
}

async fn api_mitm_hosts(State(state): State<GatewayState>) -> Json<MitmHostsResponse> {
    let cfg = state.get_config();
    let mut observed: Vec<ObservedConnectHost> = state.observed_connect_hosts.read().values().cloned().collect();
    observed.sort_by_key(|b| std::cmp::Reverse(b.last_seq));
    let system_proxy_supported = cfg!(windows);
    let system_proxy_active =
        system_proxy_supported && !state.allow_loopback_for_tests && is_system_proxy_active_for_port(cfg.proxy_port);
    Json(MitmHostsResponse {
        mitm_extra_hosts: cfg.mitm_extra_hosts,
        mitm_bypass_hosts: cfg.mitm_bypass_hosts,
        system_proxy_chain: cfg.system_proxy_chain,
        system_proxy_supported,
        system_proxy_active,
        observed_hosts: observed,
    })
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

pub(crate) fn is_binary_rpc_content_type(ct: Option<&str>) -> bool {
    let Some(ct) = ct else { return false };
    let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    matches!(mime.as_str(), "application/octet-stream" | "multipart/form-data")
}

fn is_binary_response_content_type(ct: Option<&str>) -> bool {
    let Some(ct) = ct else { return false };
    let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if is_binary_rpc_content_type(Some(&mime)) {
        return true;
    }
    mime.starts_with("image/")
        || mime.starts_with("audio/")
        || mime.starts_with("video/")
        || matches!(
            mime.as_str(),
            "application/pdf" | "application/zip" | "application/gzip" | "application/wasm"
        )
}

fn detect_harness_for_host(host: &str) -> Option<HarnessKind> {
    let h = host.trim().to_ascii_lowercase();
    if h == "api.anthropic.com" {
        Some(HarnessKind::ClaudeCode)
    } else if h == "api.openai.com" || h == "chatgpt.com" || h.ends_with(".openai.azure.com") {
        Some(HarnessKind::Codex)
    } else if h == "generativelanguage.googleapis.com"
        || h == "cloudcode-pa.googleapis.com"
        || h == "cloudaicompanion.googleapis.com"
        || h == "daily-cloudcode-pa.sandbox.googleapis.com"
        || h == "autopush-cloudcode-pa.sandbox.googleapis.com"
        || h == "antigravity-pa.googleapis.com"
        || h == "aiplatform.googleapis.com"
        || h.ends_with("-aiplatform.googleapis.com")
        || h.ends_with("-generativelanguage.googleapis.com")
        || h.ends_with("-cloudaicompanion.googleapis.com")
        || h.ends_with("-cloudcode-pa.googleapis.com")
        || h.ends_with(".cloudcode-pa.googleapis.com")
        || h.ends_with("-cloudcode-pa.sandbox.googleapis.com")
        || h.ends_with("-antigravity-pa.googleapis.com")
        || h.ends_with("-antigravity-pa.sandbox.googleapis.com")
    {
        Some(HarnessKind::Antigravity)
    } else if h.ends_with(".cursor.sh") || h.ends_with(".cursorapi.com") {
        Some(HarnessKind::Cursor)
    } else if h == "api.qoder.com"
        || h.ends_with(".qoder.com")
        || h.ends_with(".qoder.sh")
        || h.ends_with(".qoder.com.cn")
        || h.starts_with("dashscope")
    {
        Some(HarnessKind::Qoder)
    } else if h == "api.x.ai" || h == "cli-chat-proxy.grok.com" {
        Some(HarnessKind::GrokBuild)
    } else if h == "api.zcode.ai" || h == "open.bigmodel.cn" || h == "api.z.ai" {
        Some(HarnessKind::Zcode)
    } else {
        None
    }
}

fn filter_hide_go_session_cookie(raw_cookies: &str) -> Option<axum::http::HeaderValue> {
    let cookies = raw_cookies
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
    if cookies.is_empty() {
        None
    } else {
        cookies.parse().ok()
    }
}

fn upstream_passthrough_request_headers(headers: &HeaderMap, admin_token: &str) -> HeaderMap {
    filter_forwarded_headers(headers, admin_token, false, false)
}

fn upstream_binary_response_headers(headers: &HeaderMap, preserve_origin_headers: bool) -> HeaderMap {
    headers
        .iter()
        .filter(|(name, value)| {
            if is_hop_by_hop(name.as_str(), headers) || *name == header::CONTENT_LENGTH {
                return false;
            }
            if preserve_origin_headers {
                !(*name == header::SET_COOKIE && is_hide_go_session_set_cookie(value))
            } else {
                *name != header::SET_COOKIE && !name.as_str().starts_with("access-control-")
            }
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn resolve_proxy_harness_and_scope(
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
    host: &str,
) -> (HarnessKind, TrafficCategory, Option<String>) {
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());
    let text_preview = std::str::from_utf8(body).ok().unwrap_or("");
    let (mut harness, category) = detect_harness_and_category(path, ua, text_preview);
    if harness == HarnessKind::Generic {
        if let Some(by_host) = detect_harness_for_host(host) {
            harness = by_host;
        }
    }
    let scope = if harness != HarnessKind::Generic {
        Some(format!("harness:{}", harness.slug()))
    } else {
        Some(host.to_string())
    };
    (harness, category, scope)
}

/// Handle a decrypted full-duplex streaming gRPC / ConnectRPC request inside an intercepted TLS
/// `CONNECT` tunnel without buffering the entire request body upfront.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_mitm_streaming_rpc_request(
    state: GatewayState,
    scheme: &str,
    host: &str,
    port: u16,
    framing: ProtobufFraming,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    incoming: hyper::body::Incoming,
) -> Response {
    let start = Instant::now();
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
    let authority = if host.contains(':') {
        if port == default_port {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let target_str = format!("{scheme}://{authority}{path_and_query}");
    let Ok(target_url) = reqwest::Url::parse(&target_str) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_upstream", "invalid MITM target URL");
    };
    let cfg = state.get_config();
    let allow_configured_loopback = is_allowed_loopback_proxy_target(host, port, &cfg);
    let allow_loopback = allow_configured_loopback || state.allow_loopback_for_tests;
    if is_forbidden_target_host_port(host, port, cfg.proxy_port, allow_loopback) {
        return json_error(
            StatusCode::FORBIDDEN,
            "forbidden_target",
            "upstream target host or port is blocked",
        );
    }

    let path_only = uri.path();
    let (harness, category, upstream_vendor) = resolve_proxy_harness_and_scope(path_only, &headers, &[], host);
    let vault_scope = upstream_vendor
        .clone()
        .or_else(|| target_url.host_str().map(str::to_string));
    let idle_timeout = cfg.effective_upstream_idle_timeout();
    let is_loopback = allow_loopback && is_loopback_host_str(host);
    let (client, _fallback_client) = state.resolve_http_clients(host, is_loopback, false);

    let req_ct_str = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/grpc")
        .to_string();
    let frame_enc = headers
        .get(framing.encoding_header_name())
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let metrics = Arc::new(parking_lot::Mutex::new(OutboundStreamMetrics::default()));
    let desensitizer = GrpcStreamDesensitizer::new(
        framing,
        frame_enc,
        category,
        cfg.clone(),
        state.vault.clone(),
        vault_scope.clone(),
        metrics.clone(),
    );

    let outbound_stream = futures_util::stream::unfold(
        (incoming, desensitizer, false),
        |(mut incoming, mut des, done)| async move {
            loop {
                if done {
                    return None;
                }
                match incoming.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(chunk) = frame.into_data() {
                            if chunk.is_empty() {
                                continue;
                            }
                            let out = des.push_chunk(&chunk);
                            if !out.is_empty() {
                                return Some((Ok::<Bytes, std::io::Error>(Bytes::from(out)), (incoming, des, false)));
                            }
                        }
                    }
                    Some(Err(err)) => {
                        return Some((
                            Err(std::io::Error::other(format!("client gRPC stream error: {err}"))),
                            (incoming, des, true),
                        ));
                    }
                    None => {
                        let tail = des.finish();
                        if !tail.is_empty() {
                            return Some((Ok(Bytes::from(tail)), (incoming, des, true)));
                        }
                        return None;
                    }
                }
            }
        },
    );

    let fwd_headers = upstream_protobuf_request_headers(&headers, state.admin_token(), framing, false);
    let endpoint_label = format!("{scheme}://{authority}{path_only}");
    let upstream_resp = match tokio::time::timeout(
        idle_timeout,
        client
            .request(method.clone(), target_url)
            .headers(fwd_headers)
            .body(reqwest::Body::wrap_stream(outbound_stream))
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => {
            let reason = if err.is_timeout() {
                "upstream_timeout"
            } else {
                "upstream_connection_failed"
            };
            let m = metrics.lock();
            let action = format!("{}+{reason}", m.action_taken(cfg.mode));
            let mut rec = build_record(RecordInput {
                harness,
                category,
                method: method.to_string(),
                endpoint: endpoint_label,
                mode: cfg.mode,
                action_taken: action,
                status: 0,
                start,
                simulated: false,
                local_request: &m.local_preview,
                vendor_request: &m.vendor_preview,
                vendor_response: "",
                local_response: "",
                findings: m.findings.clone(),
                restored_count: 0,
                withheld_count: 0,
                upstream_vendor,
            });
            rec.request_bytes = m.request_bytes;
            drop(m);
            state.push_record(rec);
            return json_error(StatusCode::BAD_GATEWAY, reason, err.to_string());
        }
        Err(_) => {
            let reason = "upstream_timeout";
            let m = metrics.lock();
            let action = format!("{}+{reason}", m.action_taken(cfg.mode));
            let mut rec = build_record(RecordInput {
                harness,
                category,
                method: method.to_string(),
                endpoint: endpoint_label,
                mode: cfg.mode,
                action_taken: action,
                status: 0,
                start,
                simulated: false,
                local_request: &m.local_preview,
                vendor_request: &m.vendor_preview,
                vendor_response: "",
                local_response: "",
                findings: m.findings.clone(),
                restored_count: 0,
                withheld_count: 0,
                upstream_vendor,
            });
            rec.request_bytes = m.request_bytes;
            drop(m);
            state.push_record(rec);
            return json_error(
                StatusCode::BAD_GATEWAY,
                reason,
                format!("upstream did not respond within {}s", idle_timeout.as_secs()),
            );
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_ct = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let resp_framing = detect_protobuf_framing(resp_ct.as_deref()).unwrap_or(framing);

    let base_record = build_record(RecordInput {
        harness,
        category,
        method: method.to_string(),
        endpoint: endpoint_label,
        mode: cfg.mode,
        action_taken: "protobuf-passed".to_string(),
        status: status.as_u16(),
        start,
        simulated: false,
        local_request: "",
        vendor_request: "",
        vendor_response: "",
        local_response: "",
        findings: Vec::new(),
        restored_count: 0,
        withheld_count: 0,
        upstream_vendor,
    });

    build_protobuf_upstream_response(
        &state,
        upstream_resp,
        resp_framing,
        status,
        true,
        idle_timeout,
        start,
        &cfg,
        vault_scope.as_deref(),
        base_record,
        "protobuf-passed".to_string(),
        Some((metrics, cfg.mode, req_ct_str)),
    )
    .await
}

/// Handle a decrypted HTTP request inside an intercepted TLS `CONNECT` tunnel.
/// Never exposes `/api/*` admin routes and pins the upstream strictly to `https://{host}[:{port}]`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_mitm_http_request(
    state: GatewayState,
    scheme: &str,
    host: &str,
    port: u16,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
    let authority = if host.contains(':') {
        if port == default_port {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let target_str = format!("{scheme}://{authority}{path_and_query}");
    let Ok(target_url) = reqwest::Url::parse(&target_str) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_upstream", "invalid MITM target URL");
    };
    let cfg = state.get_config();
    let allow_configured_loopback = is_allowed_loopback_proxy_target(host, port, &cfg);
    let path_only = uri.path();
    let (harness, category, upstream_vendor) = resolve_proxy_harness_and_scope(path_only, &headers, &body, host);
    execute_proxy_forward(
        &state,
        ForwardContext {
            harness,
            category,
            target_url,
            endpoint_label: format!("{scheme}://{authority}{path_only}"),
            telemetry_path: path_only.to_string(),
            upstream_vendor,
            cfg,
            allow_configured_loopback,
            allow_operator_private_upstream: false,
            preserve_origin_headers: true,
            start: Instant::now(),
        },
        method,
        headers,
        body,
    )
    .await
}

async fn send_upstream_with_fallback(
    primary: &reqwest::Client,
    fallback: Option<&reqwest::Client>,
    method: Method,
    target_url: reqwest::Url,
    headers: HeaderMap,
    body: Bytes,
    idle_timeout: Duration,
) -> Result<Result<reqwest::Response, reqwest::Error>, tokio::time::error::Elapsed> {
    let first = tokio::time::timeout(
        idle_timeout,
        primary
            .request(method.clone(), target_url.clone())
            .headers(headers.clone())
            .body(body.clone())
            .send(),
    )
    .await;
    if let Some(direct) = fallback {
        let should_retry_direct = match &first {
            Ok(Err(err)) => err.is_connect() || err.is_timeout(),
            Err(_) => true,
            Ok(Ok(_)) => false,
        };
        if should_retry_direct {
            tracing::debug!("proxied upstream request failed for {target_url}; retrying direct");
            return tokio::time::timeout(
                idle_timeout,
                direct.request(method, target_url).headers(headers).body(body).send(),
            )
            .await;
        }
    }
    first
}

/// Handle a plain HTTP forward-proxy request (`HTTP_PROXY`) with an absolute-form URI.
pub(crate) async fn handle_forward_http_request(
    state: GatewayState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    mitm_inspect: bool,
) -> Response {
    let Ok(target_url) = reqwest::Url::parse(&uri.to_string()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_uri",
            "invalid absolute proxy URI",
        );
    };
    if !matches!(target_url.scheme(), "http" | "https")
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.fragment().is_some()
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_scheme",
            "unsupported proxy scheme or credentials",
        );
    }
    let cfg = state.get_config();
    let host = target_url.host_str().unwrap_or_default().to_string();
    let port = target_url.port_or_known_default().unwrap_or(0);
    let explicit_loopback = is_allowed_loopback_proxy_target(&host, port, &cfg);
    let allow_loopback = state.allow_loopback_for_tests || explicit_loopback;
    if is_forbidden_target_host_port(&host, port, cfg.proxy_port, allow_loopback) {
        return json_error(
            StatusCode::FORBIDDEN,
            "forbidden_target",
            "forward proxy connections to private, metadata, or loopback targets are blocked",
        );
    }
    if !mitm_inspect {
        let idle_timeout = cfg.effective_upstream_idle_timeout();
        let is_loopback = allow_loopback && is_loopback_host_str(&host);
        let (client, fallback) = state.resolve_http_clients(&host, is_loopback, false);
        let fwd_headers = upstream_passthrough_request_headers(&headers, state.admin_token());
        return match send_upstream_with_fallback(
            &client,
            fallback.as_ref(),
            method,
            target_url,
            fwd_headers,
            body,
            idle_timeout,
        )
        .await
        {
            Ok(Ok(resp)) => {
                let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                let resp_headers = upstream_binary_response_headers(resp.headers(), true);
                let mut out = Response::new(Body::from_stream(stream_with_idle_timeout(
                    resp.bytes_stream(),
                    idle_timeout,
                )));
                *out.status_mut() = status;
                *out.headers_mut() = resp_headers;
                out
            }
            Ok(Err(err)) => {
                let reason = if err.is_timeout() {
                    "upstream_timeout"
                } else {
                    "upstream_connection_failed"
                };
                json_error(StatusCode::BAD_GATEWAY, reason, err.to_string())
            }
            Err(_) => json_error(
                StatusCode::BAD_GATEWAY,
                "upstream_timeout",
                format!("upstream did not respond within {}s", idle_timeout.as_secs()),
            ),
        };
    }

    let scheme = target_url.scheme().to_string();
    let path_only = target_url.path().to_string();
    let (harness, category, upstream_vendor) = resolve_proxy_harness_and_scope(&path_only, &headers, &body, &host);
    execute_proxy_forward(
        &state,
        ForwardContext {
            harness,
            category,
            target_url: target_url.clone(),
            endpoint_label: format!("{scheme}://{host}{path_only}"),
            telemetry_path: path_only,
            upstream_vendor,
            cfg,
            allow_configured_loopback: explicit_loopback,
            allow_operator_private_upstream: false,
            preserve_origin_headers: true,
            start: Instant::now(),
        },
        method,
        headers,
        body,
    )
    .await
}

struct ForwardContext {
    harness: HarnessKind,
    category: TrafficCategory,
    target_url: reqwest::Url,
    endpoint_label: String,
    telemetry_path: String,
    upstream_vendor: Option<String>,
    cfg: HideConfig,
    allow_configured_loopback: bool,
    allow_operator_private_upstream: bool,
    preserve_origin_headers: bool,
    start: Instant,
}

fn join_upstream_url(upstream_base: &str, upstream_path: &str, query: Option<&str>) -> String {
    let base = upstream_base.trim().trim_end_matches('/');
    let mut path = upstream_path;
    if base.ends_with("/v1") {
        if path == "/v1" {
            path = "";
        } else if let Some(stripped) = path.strip_prefix("/v1/") {
            return match query {
                Some(q) => format!("{base}/{stripped}?{q}"),
                None => format!("{base}/{stripped}"),
            };
        }
    }
    match query {
        Some(q) => format!("{base}{path}?{q}"),
        None => format!("{base}{path}"),
    }
}

/// Real reverse-proxy handler for `/:harness/*rest`:
/// 1. Detects the Harness and TrafficCategory (path based).
/// 2. Transforms the outbound payload according to `HideConfig` (CPU work off the async runtime).
/// 3. Forwards to the upstream (`X-Hide-Go-Upstream` with admin token / `HIDE_GO_UPSTREAM_URL` / config override / vendor default).
/// 4. Streams SSE or JSON responses back through the restorers.
async fn proxy_harness_request(
    State(state): State<GatewayState>,
    Path((harness_prefix, rest)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_local_request(&headers, &uri) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let start = Instant::now();
    let cfg = state.get_config();
    let full_path = format!("/{}/{}", harness_prefix, rest);
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok());
    let text_preview = std::str::from_utf8(&body).ok().unwrap_or("");
    let (harness, category) = detect_harness_and_category(&full_path, ua, text_preview);

    let header_upstream = headers
        .get("x-hide-go-upstream")
        .or_else(|| headers.get("x-upstream-url"))
        .or_else(|| headers.get("x-target-upstream"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().trim_end_matches('/').to_string());
    if header_upstream.is_some() && !is_admin_authenticated(&headers, state.admin_token()) {
        return json_error(
            StatusCode::FORBIDDEN,
            "forbidden_upstream_override",
            "upstream override headers require valid admin authentication",
        );
    }
    let env_upstream = std::env::var("HIDE_GO_UPSTREAM_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().trim_end_matches('/').to_string());
    let config_upstream = cfg
        .harness_upstreams
        .get(harness.slug())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());
    let from_operator_config = header_upstream.is_none() && (env_upstream.is_some() || config_upstream.is_some());
    let upstream_base = header_upstream
        .or(env_upstream)
        .or(config_upstream)
        .unwrap_or_else(|| GatewayState::default_upstream_for_harness(harness).to_string());
    let upstream_path = if is_known_harness_prefix(&harness_prefix) {
        format!("/{}", rest.trim_start_matches('/'))
    } else {
        full_path.clone()
    };
    let target_url_str = join_upstream_url(&upstream_base, &upstream_path, uri.query());
    let Ok(target_url) = reqwest::Url::parse(&target_url_str) else {
        let msg = "upstream URL is not valid";
        state.push_record(build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: uri.path().to_string(),
            mode: cfg.mode,
            action_taken: "invalid_upstream".to_string(),
            status: StatusCode::BAD_REQUEST.as_u16(),
            start,
            simulated: false,
            local_request: "",
            vendor_request: "",
            vendor_response: "",
            local_response: msg,
            findings: Vec::new(),
            restored_count: 0,
            withheld_count: 0,
            upstream_vendor: None,
        }));
        return json_error(StatusCode::BAD_REQUEST, "invalid_upstream", msg);
    };
    if !matches!(target_url.scheme(), "http" | "https")
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.fragment().is_some()
    {
        let msg = "upstream URL must be plain http(s)";
        state.push_record(build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: uri.path().to_string(),
            mode: cfg.mode,
            action_taken: "invalid_upstream".to_string(),
            status: StatusCode::BAD_REQUEST.as_u16(),
            start,
            simulated: false,
            local_request: "",
            vendor_request: "",
            vendor_response: "",
            local_response: msg,
            findings: Vec::new(),
            restored_count: 0,
            withheld_count: 0,
            upstream_vendor: None,
        }));
        return json_error(StatusCode::BAD_REQUEST, "invalid_upstream", msg);
    }

    execute_proxy_forward(
        &state,
        ForwardContext {
            harness,
            category,
            target_url,
            endpoint_label: uri.path().to_string(),
            telemetry_path: full_path,
            upstream_vendor: None,
            cfg,
            allow_configured_loopback: from_operator_config,
            allow_operator_private_upstream: from_operator_config,
            preserve_origin_headers: false,
            start,
        },
        method,
        headers,
        body,
    )
    .await
}

fn decompress_request_body(encoding: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let enc = encoding.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    let max_read = (MAX_REQUEST_BODY + 1) as u64;
    match enc.as_str() {
        "gzip" | "x-gzip" => {
            flate2::read::GzDecoder::new(body)
                .take(max_read)
                .read_to_end(&mut out)
                .map_err(|e| format!("gzip decompression failed: {e}"))?;
        }
        "deflate" => {
            if flate2::read::ZlibDecoder::new(body)
                .take(max_read)
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(body)
                    .take(max_read)
                    .read_to_end(&mut out)
                    .map_err(|e| format!("deflate decompression failed: {e}"))?;
            }
        }
        _ => return Err(format!("unsupported Content-Encoding: {enc}")),
    }
    if out.len() > MAX_REQUEST_BODY {
        return Err("decompressed request body exceeds gateway limit".to_string());
    }
    Ok(out)
}

async fn execute_proxy_forward(
    state: &GatewayState,
    ctx: ForwardContext,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ForwardContext {
        harness,
        category,
        target_url,
        endpoint_label,
        telemetry_path,
        upstream_vendor,
        cfg,
        allow_configured_loopback,
        allow_operator_private_upstream,
        preserve_origin_headers,
        start,
    } = ctx;

    let req_ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    let target_host = target_url.host_str().unwrap_or_default();
    let target_port = target_url.port_or_known_default().unwrap_or(0);
    let allow_loopback = allow_configured_loopback || state.allow_loopback_for_tests;
    let forbidden = if allow_operator_private_upstream {
        is_forbidden_operator_upstream(target_host, target_port, cfg.proxy_port)
    } else {
        is_forbidden_target_host_port(target_host, target_port, cfg.proxy_port, allow_loopback)
    };
    if forbidden {
        return json_error(
            StatusCode::FORBIDDEN,
            "forbidden_target",
            "upstream target host or port is blocked",
        );
    }
    let idle_timeout = cfg.effective_upstream_idle_timeout();
    let is_loopback = allow_loopback && is_loopback_host_str(target_host);
    let (client, fallback_client) =
        state.resolve_http_clients(target_host, is_loopback, allow_operator_private_upstream);
    let vault_scope = upstream_vendor
        .clone()
        .or_else(|| target_url.host_str().map(str::to_string));

    // Schema-less Protobuf, gRPC, and ConnectRPC wire-format desensitization & streaming restoration.
    if let Some(framing) = detect_protobuf_framing(req_ct) {
        return execute_protobuf_forward(
            state,
            ProtobufForwardInput {
                framing,
                harness,
                category,
                method,
                target_url,
                endpoint_label,
                upstream_vendor,
                vault_scope,
                cfg,
                preserve_origin_headers,
                idle_timeout,
                start,
                client,
                fallback_client,
                headers,
                body,
            },
        )
        .await;
    }

    // Truly opaque binary uploads (octet-stream / multipart) stream cleanly untouched.
    if is_binary_rpc_content_type(req_ct) {
        let req_len = body.len();
        let req_note = format!(
            "[binary RPC payload ({}, {} bytes) — passed through untouched]",
            req_ct.unwrap_or("binary"),
            req_len
        );
        let fwd_headers = upstream_passthrough_request_headers(&headers, state.admin_token());
        return match send_upstream_with_fallback(
            &client,
            fallback_client.as_ref(),
            method.clone(),
            target_url,
            fwd_headers,
            body,
            idle_timeout,
        )
        .await
        {
            Ok(Ok(resp)) => {
                let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                let resp_headers = upstream_binary_response_headers(resp.headers(), preserve_origin_headers);
                let resp_ct = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("binary")
                    .to_string();
                let resp_note = format!("[binary RPC response ({resp_ct}) — streamed untouched]");
                let mut rec = build_record(RecordInput {
                    harness,
                    category,
                    method: method.to_string(),
                    endpoint: endpoint_label,
                    mode: cfg.mode,
                    action_taken: "binary-rpc-passthrough".to_string(),
                    status: status.as_u16(),
                    start,
                    simulated: false,
                    local_request: &req_note,
                    vendor_request: &req_note,
                    vendor_response: &resp_note,
                    local_response: &resp_note,
                    findings: Vec::new(),
                    restored_count: 0,
                    withheld_count: 0,
                    upstream_vendor,
                });
                rec.request_bytes = req_len;
                state.push_record(rec);
                let mut out = Response::new(Body::from_stream(stream_with_idle_timeout(
                    resp.bytes_stream(),
                    idle_timeout,
                )));
                *out.status_mut() = status;
                *out.headers_mut() = resp_headers;
                out
            }
            Ok(Err(err)) => {
                let reason = if err.is_timeout() {
                    "upstream_timeout"
                } else {
                    "upstream_connection_failed"
                };
                let mut rec = build_record(RecordInput {
                    harness,
                    category,
                    method: method.to_string(),
                    endpoint: endpoint_label,
                    mode: cfg.mode,
                    action_taken: format!("binary-rpc-passthrough+{reason}"),
                    status: 0,
                    start,
                    simulated: false,
                    local_request: &req_note,
                    vendor_request: &req_note,
                    vendor_response: "",
                    local_response: "",
                    findings: Vec::new(),
                    restored_count: 0,
                    withheld_count: 0,
                    upstream_vendor,
                });
                rec.request_bytes = req_len;
                state.push_record(rec);
                json_error(StatusCode::BAD_GATEWAY, reason, err.to_string())
            }
            Err(_) => {
                let reason = "upstream_timeout";
                let mut rec = build_record(RecordInput {
                    harness,
                    category,
                    method: method.to_string(),
                    endpoint: endpoint_label,
                    mode: cfg.mode,
                    action_taken: format!("binary-rpc-passthrough+{reason}"),
                    status: 0,
                    start,
                    simulated: false,
                    local_request: &req_note,
                    vendor_request: &req_note,
                    vendor_response: "",
                    local_response: "",
                    findings: Vec::new(),
                    restored_count: 0,
                    withheld_count: 0,
                    upstream_vendor,
                });
                rec.request_bytes = req_len;
                state.push_record(rec);
                json_error(
                    StatusCode::BAD_GATEWAY,
                    reason,
                    format!("upstream did not respond within {}s", idle_timeout.as_secs()),
                )
            }
        };
    }

    let request_encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.eq_ignore_ascii_case("identity"));
    let decompressed_text: Option<String> = if let Some(enc) = request_encoding {
        if cfg.mode != PrivacyMode::AuditOnly {
            decompress_request_body(enc, &body)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        } else {
            None
        }
    } else {
        None
    };
    let was_decompressed = decompressed_text.is_some();
    let text_body = if let Some(ref s) = decompressed_text {
        Some(s.as_str())
    } else if request_encoding.is_none() {
        std::str::from_utf8(&body).ok()
    } else {
        None
    };
    if cfg.mode != PrivacyMode::AuditOnly && text_body.is_none() && !body.is_empty() {
        // A body we cannot read or decompress is a body we cannot clean: fail closed.
        let msg =
            "请求体经过不受支持的压缩或不是 UTF-8 文本，Hide-Go 无法检查其中的敏感数据，已拒绝转发。可切换到“仅审计”模式直通。";
        state.push_record(build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: endpoint_label,
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
            upstream_vendor,
        }));
        return json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "uninspectable_request_body", msg);
    }
    let inspectable_text = text_body;
    let body_text = inspectable_text.unwrap_or_default().to_string();

    if should_block_telemetry(category, &telemetry_path, &cfg) {
        let ack = serde_json::json!({"status": "ok", "accepted": true}).to_string();
        let findings = scan_telemetry_findings(&body_text, &cfg);
        state.push_record(build_record(RecordInput {
            harness,
            category,
            method: method.to_string(),
            endpoint: endpoint_label,
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
            upstream_vendor,
        }));
        return (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], ack).into_response();
    }

    // 1. Outbound transformation (CPU bound: keep it off the async workers).
    let (vendor_body, action_taken, findings) = if inspectable_text.is_some() {
        let vault = state.vault.clone();
        let (cfg2, text, scope2) = (cfg.clone(), body_text.clone(), vault_scope.clone());
        match tokio::task::spawn_blocking(move || {
            transform_outbound_scoped(&vault, category, &text, &cfg2, scope2.as_deref())
        })
        .await
        {
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
    let uninspectable_placeholder = if !was_decompressed && request_encoding.is_some() {
        Some(format!(
            "[compressed body ({}, {} bytes) — passed through in audit-only mode]",
            request_encoding.unwrap_or("compressed"),
            body.len()
        ))
    } else if inspectable_text.is_none() && !body.is_empty() {
        Some(format!(
            "[binary non-UTF-8 body ({} bytes) — passed through in audit-only mode]",
            body.len()
        ))
    } else {
        None
    };
    let audit_local_request = uninspectable_placeholder.as_deref().unwrap_or(&body_text);
    let vendor_visible_payload = match &uninspectable_placeholder {
        Some(placeholder) => placeholder.clone(),
        None => String::from_utf8_lossy(&vendor_body).into_owned(),
    };
    let raw_request_len = body.len();
    let record_base =
        |status: u16, vendor_response: &str, local_response: &str, restored: usize, withheld: usize, action: String| {
            let mut rec = build_record(RecordInput {
                harness,
                category,
                method: method.to_string(),
                endpoint: endpoint_label.clone(),
                mode: cfg.mode,
                action_taken: action,
                status,
                start,
                simulated: false,
                local_request: audit_local_request,
                vendor_request: &vendor_visible_payload,
                vendor_response,
                local_response,
                findings: findings.clone(),
                restored_count: restored,
                withheld_count: withheld,
                upstream_vendor: upstream_vendor.clone(),
            });
            rec.request_bytes = raw_request_len;
            rec
        };

    if inspectable_text.is_some()
        && serde_json::from_str::<Value>(&body_text).is_ok()
        && serde_json::from_slice::<Value>(&vendor_body).is_err()
    {
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

    let fwd_headers = upstream_request_headers(&headers, state.admin_token(), was_decompressed);
    let upstream_resp = match send_upstream_with_fallback(
        &client,
        fallback_client.as_ref(),
        method.clone(),
        target_url,
        fwd_headers,
        vendor_body,
        idle_timeout,
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => {
            let reason = if err.is_timeout() {
                "upstream_timeout"
            } else {
                "upstream_connection_failed"
            };
            state.push_record(record_base(0, "", "", 0, 0, format!("{action_taken}+{reason}")));
            return json_error(StatusCode::BAD_GATEWAY, reason, err.to_string());
        }
        Err(_) => {
            let reason = "upstream_timeout";
            state.push_record(record_base(0, "", "", 0, 0, format!("{action_taken}+{reason}")));
            return json_error(
                StatusCode::BAD_GATEWAY,
                reason,
                format!("upstream did not respond within {}s", idle_timeout.as_secs()),
            );
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_ct = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if let Some(resp_framing) = detect_protobuf_framing(resp_ct.as_deref()) {
        return build_protobuf_upstream_response(
            state,
            upstream_resp,
            resp_framing,
            status,
            preserve_origin_headers,
            idle_timeout,
            start,
            &cfg,
            vault_scope.as_deref(),
            record_base(status.as_u16(), "", "", 0, 0, action_taken.clone()),
            action_taken,
            None,
        )
        .await;
    }

    if is_binary_response_content_type(resp_ct.as_deref()) {
        let binary_headers = upstream_binary_response_headers(upstream_resp.headers(), preserve_origin_headers);
        let note = format!(
            "[binary response ({}) — streamed untouched]",
            resp_ct.as_deref().unwrap_or("binary")
        );
        state.push_record(record_base(status.as_u16(), &note, &note, 0, 0, action_taken));
        let mut response = Response::new(Body::from_stream(stream_with_idle_timeout(
            upstream_resp.bytes_stream(),
            idle_timeout,
        )));
        *response.status_mut() = status;
        *response.headers_mut() = binary_headers;
        return response;
    }

    let response_headers = upstream_response_headers(upstream_resp.headers(), preserve_origin_headers);
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
    let is_event_stream = resp_ct
        .as_deref()
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"));

    if is_event_stream {
        let restorer = (cfg.mode != PrivacyMode::AuditOnly).then(|| {
            SseRestorer::with_policy_scoped(state.vault.clone(), vault_scope.clone(), cfg.tool_call_secret_policy)
        });
        let stream_state = ProxyStreamState {
            inner: Box::pin(upstream_resp.bytes_stream()),
            idle_timeout,
            restorer,
            vendor_raw_acc: Vec::new(),
            restored_acc: Vec::new(),
            unterminated_sse_bytes: 0,
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
            match tokio::time::timeout(st.idle_timeout, st.inner.next()).await {
                Ok(Some(Ok(chunk))) => {
                    if let Some(last_nl) = chunk.iter().rposition(|&b| b == b'\n') {
                        st.unterminated_sse_bytes = chunk.len().saturating_sub(last_nl + 1);
                    } else {
                        st.unterminated_sse_bytes = st.unterminated_sse_bytes.saturating_add(chunk.len());
                    }
                    if st.unterminated_sse_bytes > MAX_SSE_PENDING_BYTES {
                        st.finish_record(true);
                        return Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "upstream SSE event line exceeded buffer limit",
                            )),
                            st,
                        ));
                    }
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
                Ok(Some(Err(err))) => {
                    st.finish_record(true);
                    Some((
                        Err(std::io::Error::other(format!("upstream stream interrupted: {err}"))),
                        st,
                    ))
                }
                Ok(None) => {
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
                Err(_) => {
                    st.finish_record(true);
                    Some((
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("upstream SSE stream idle timeout after {}s", st.idle_timeout.as_secs()),
                        )),
                        st,
                    ))
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

    let vendor_raw = match read_limited_upstream_text(upstream_resp, MAX_RESPONSE_BODY, idle_timeout).await {
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
            return json_error(StatusCode::BAD_GATEWAY, "upstream_body_failed", err);
        }
    };
    let (restored, restored_count, withheld) = if cfg.mode == PrivacyMode::AuditOnly {
        (vendor_raw.clone(), 0, 0)
    } else {
        let vault = state.vault.clone();
        let (policy, raw, scope2) = (cfg.tool_call_secret_policy, vendor_raw.clone(), vault_scope.clone());
        tokio::task::spawn_blocking(move || {
            let matcher = vault.matcher_for_scope(scope2.as_deref());
            restore_response(&matcher, &raw, policy)
        })
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

struct ProtobufForwardInput {
    framing: ProtobufFraming,
    harness: HarnessKind,
    category: TrafficCategory,
    method: Method,
    target_url: reqwest::Url,
    endpoint_label: String,
    upstream_vendor: Option<String>,
    vault_scope: Option<String>,
    cfg: HideConfig,
    preserve_origin_headers: bool,
    idle_timeout: Duration,
    start: Instant,
    client: reqwest::Client,
    fallback_client: Option<reqwest::Client>,
    headers: HeaderMap,
    body: Bytes,
}

fn upstream_protobuf_request_headers(
    headers: &HeaderMap,
    admin_token: &str,
    framing: ProtobufFraming,
    strip_content_encoding: bool,
) -> HeaderMap {
    let mut forwarded = filter_forwarded_headers(headers, admin_token, false, strip_content_encoding);
    if framing == ProtobufFraming::Grpc {
        forwarded.insert(header::TE, "trailers".parse().unwrap());
    }
    forwarded
}

async fn execute_protobuf_forward(state: &GatewayState, input: ProtobufForwardInput) -> Response {
    let ProtobufForwardInput {
        framing,
        harness,
        category,
        method,
        target_url,
        endpoint_label,
        upstream_vendor,
        vault_scope,
        cfg,
        preserve_origin_headers,
        idle_timeout,
        start,
        client,
        fallback_client,
        headers,
        body,
    } = input;

    let raw_req_len = body.len();
    let req_ct_str = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/protobuf")
        .to_string();
    let http_enc = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let frame_enc = headers
        .get(framing.encoding_header_name())
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let vault = state.vault.clone();
    let cfg_clone = cfg.clone();
    let scope_clone = vault_scope.clone();
    let body_for_work = body.clone();
    let transformed = match tokio::task::spawn_blocking(move || {
        transform_protobuf_outbound(
            framing,
            &body_for_work,
            http_enc.as_deref(),
            frame_enc.as_deref(),
            category,
            &cfg_clone,
            &vault,
            scope_clone.as_deref(),
        )
    })
    .await
    {
        Ok(res) => res,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "transform_failed",
                "outbound protobuf transformation panicked",
            );
        }
    };

    let local_req_preview = if transformed.local_preview.is_empty() {
        format!("[{req_ct_str}, {raw_req_len} bytes]")
    } else {
        transformed.local_preview
    };
    let vendor_req_preview = if transformed.vendor_preview.is_empty() {
        format!("[{req_ct_str}, {} bytes]", transformed.vendor_body.len())
    } else {
        transformed.vendor_preview
    };
    let action_taken = transformed.action_taken;
    let findings = transformed.findings;

    let make_record =
        |status: u16, vendor_response: &str, local_response: &str, restored: usize, withheld: usize, action: String| {
            let mut rec = build_record(RecordInput {
                harness,
                category,
                method: method.to_string(),
                endpoint: endpoint_label.clone(),
                mode: cfg.mode,
                action_taken: action,
                status,
                start,
                simulated: false,
                local_request: &local_req_preview,
                vendor_request: &vendor_req_preview,
                vendor_response,
                local_response,
                findings: findings.clone(),
                restored_count: restored,
                withheld_count: withheld,
                upstream_vendor: upstream_vendor.clone(),
            });
            rec.request_bytes = raw_req_len;
            rec
        };

    let fwd_headers = upstream_protobuf_request_headers(
        &headers,
        state.admin_token(),
        framing,
        transformed.stripped_content_encoding,
    );
    let upstream_resp = match send_upstream_with_fallback(
        &client,
        fallback_client.as_ref(),
        method.clone(),
        target_url,
        fwd_headers,
        Bytes::from(transformed.vendor_body),
        idle_timeout,
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => {
            let reason = if err.is_timeout() {
                "upstream_timeout"
            } else {
                "upstream_connection_failed"
            };
            state.push_record(make_record(0, "", "", 0, 0, format!("{action_taken}+{reason}")));
            return json_error(StatusCode::BAD_GATEWAY, reason, err.to_string());
        }
        Err(_) => {
            let reason = "upstream_timeout";
            state.push_record(make_record(0, "", "", 0, 0, format!("{action_taken}+{reason}")));
            return json_error(
                StatusCode::BAD_GATEWAY,
                reason,
                format!("upstream did not respond within {}s", idle_timeout.as_secs()),
            );
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_ct = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if let Some(resp_framing) = detect_protobuf_framing(resp_ct.as_deref()) {
        return build_protobuf_upstream_response(
            state,
            upstream_resp,
            resp_framing,
            status,
            preserve_origin_headers,
            idle_timeout,
            start,
            &cfg,
            vault_scope.as_deref(),
            make_record(status.as_u16(), "", "", 0, 0, action_taken.clone()),
            action_taken,
            None,
        )
        .await;
    }

    // Fallback: upstream answered with non-Protobuf (e.g. HTTP error text/JSON).
    let resp_headers = upstream_binary_response_headers(upstream_resp.headers(), preserve_origin_headers);
    let raw_bytes = match read_limited_upstream_bytes(upstream_resp, MAX_RESPONSE_BODY, idle_timeout).await {
        Ok(b) => b,
        Err(err) => {
            state.push_record(make_record(
                status.as_u16(),
                "",
                "",
                0,
                0,
                format!("{action_taken}+upstream_body_failed"),
            ));
            return json_error(StatusCode::BAD_GATEWAY, "upstream_body_failed", err);
        }
    };
    let (out_bytes, vendor_resp_preview, local_resp_preview, restored_count, withheld_count) =
        match String::from_utf8(raw_bytes) {
            Ok(text) => {
                if cfg.mode == PrivacyMode::AuditOnly {
                    let bytes = text.as_bytes().to_vec();
                    (bytes, text.clone(), text, 0, 0)
                } else {
                    let matcher = state.vault.matcher_for_scope(vault_scope.as_deref());
                    let (restored, count, withheld) = restore_response(&matcher, &text, cfg.tool_call_secret_policy);
                    (restored.as_bytes().to_vec(), text, restored, count, withheld)
                }
            }
            Err(err) => {
                let raw_bytes = err.into_bytes();
                let note = format!(
                    "[binary response ({}, {} bytes)]",
                    resp_ct.as_deref().unwrap_or("binary"),
                    raw_bytes.len()
                );
                (raw_bytes, note.clone(), note, 0, 0)
            }
        };
    let mut rec = make_record(
        status.as_u16(),
        &vendor_resp_preview,
        &local_resp_preview,
        restored_count,
        withheld_count,
        action_taken,
    );
    rec.response_bytes = out_bytes.len();
    state.push_record(rec);
    let mut response = Response::new(Body::from(out_bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

#[allow(clippy::too_many_arguments)]
async fn build_protobuf_upstream_response(
    state: &GatewayState,
    upstream_resp: reqwest::Response,
    resp_framing: ProtobufFraming,
    status: StatusCode,
    preserve_origin_headers: bool,
    idle_timeout: Duration,
    start: Instant,
    cfg: &HideConfig,
    vault_scope: Option<&str>,
    mut base_record: TrafficAuditRecord,
    action_taken: String,
    outbound_metrics: Option<(Arc<parking_lot::Mutex<OutboundStreamMetrics>>, PrivacyMode, String)>,
) -> Response {
    let mut resp_headers = upstream_binary_response_headers(upstream_resp.headers(), preserve_origin_headers);
    let resp_ct = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/protobuf")
        .to_string();

    if resp_framing.is_enveloped() {
        let frame_enc = upstream_resp
            .headers()
            .get(resp_framing.encoding_header_name())
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let live_vault =
            (cfg.mode != PrivacyMode::AuditOnly).then(|| (state.vault.clone(), vault_scope.map(str::to_owned)));
        let restorer = GrpcStreamRestorer::with_vault(resp_framing, frame_enc, live_vault, cfg.tool_call_secret_policy);
        let http_resp: axum::http::Response<reqwest::Body> = upstream_resp.into();
        let stream_state = GrpcProxyStreamState {
            body: http_resp.into_body(),
            idle_timeout,
            restorer,
            pending_trailers: None,
            eof_flushed: false,
            flushed: false,
            started_at: start,
            state_for_log: state.clone(),
            record: Some(base_record),
            action_taken,
            resp_ct,
            outbound_metrics,
        };
        let out_stream = futures_util::stream::unfold(stream_state, |mut st| async move {
            loop {
                if let Some(trailers) = st.pending_trailers.take() {
                    st.eof_flushed = true;
                    if !st.flushed {
                        st.finish_record(false);
                    }
                    return Some((Ok::<Frame<Bytes>, std::io::Error>(Frame::trailers(trailers)), st));
                }
                if st.eof_flushed {
                    if !st.flushed {
                        st.finish_record(false);
                    }
                    return None;
                }
                match tokio::time::timeout(st.idle_timeout, st.body.frame()).await {
                    Ok(Some(Ok(frame))) => match frame.into_data() {
                        Ok(chunk) => {
                            let out = st.restorer.push_chunk(&chunk);
                            if !out.is_empty() {
                                st.add_response_bytes(out.len());
                                return Some((Ok(Frame::data(Bytes::from(out))), st));
                            }
                        }
                        Err(frame) => {
                            if let Ok(trailers) = frame.into_trailers() {
                                let tail = st.restorer.finish();
                                if !tail.is_empty() {
                                    st.add_response_bytes(tail.len());
                                    st.pending_trailers = Some(trailers);
                                    return Some((Ok(Frame::data(Bytes::from(tail))), st));
                                }
                                st.eof_flushed = true;
                                if !st.flushed {
                                    st.finish_record(false);
                                }
                                return Some((Ok(Frame::trailers(trailers)), st));
                            }
                        }
                    },
                    Ok(Some(Err(err))) => {
                        st.finish_record(true);
                        return Some((
                            Err(std::io::Error::other(format!(
                                "upstream gRPC stream interrupted: {err}"
                            ))),
                            st,
                        ));
                    }
                    Ok(None) => {
                        st.eof_flushed = true;
                        let tail = st.restorer.finish();
                        if !tail.is_empty() {
                            st.add_response_bytes(tail.len());
                            return Some((Ok(Frame::data(Bytes::from(tail))), st));
                        }
                        st.finish_record(false);
                        return None;
                    }
                    Err(_) => {
                        st.finish_record(true);
                        return Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!("upstream gRPC stream idle timeout after {}s", st.idle_timeout.as_secs()),
                            )),
                            st,
                        ));
                    }
                }
            }
        });
        let mut response = Response::new(Body::new(StreamBody::new(out_stream)));
        *response.status_mut() = status;
        *response.headers_mut() = resp_headers;
        return response;
    }

    // Unary Protobuf response
    let resp_enc = upstream_resp
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let raw_bytes = match read_limited_upstream_bytes(upstream_resp, MAX_RESPONSE_BODY, idle_timeout).await {
        Ok(b) => b,
        Err(err) => {
            base_record.action_taken = format!("{action_taken}+upstream_body_failed");
            state.push_record(base_record);
            return json_error(StatusCode::BAD_GATEWAY, "upstream_body_failed", err);
        }
    };
    let (local_bytes, restored_count, withheld_count, vendor_prev, local_prev, stripped_enc) =
        if cfg.mode == PrivacyMode::AuditOnly {
            let note = format!("[{resp_ct}, {} bytes]", raw_bytes.len());
            (raw_bytes, 0, 0, note.clone(), note, false)
        } else {
            let vault = state.vault.clone();
            let scope_owned = vault_scope.map(str::to_owned);
            let policy = cfg.tool_call_secret_policy;
            let enc_clone = resp_enc.clone();
            let raw_clone = raw_bytes.clone();
            match tokio::task::spawn_blocking(move || {
                let matcher = vault.matcher_for_scope(scope_owned.as_deref());
                restore_unary_protobuf(&raw_clone, enc_clone.as_deref(), &matcher, policy)
            })
            .await
            {
                Ok(res) => (
                    res.local_body,
                    res.restored_count,
                    res.withheld_count,
                    res.vendor_preview,
                    res.local_preview,
                    res.stripped_content_encoding,
                ),
                Err(_) => {
                    let note = format!("[{resp_ct}, {} bytes]", raw_bytes.len());
                    (raw_bytes, 0, 0, note.clone(), note, false)
                }
            }
        };

    if stripped_enc {
        resp_headers.remove(header::CONTENT_ENCODING);
    }
    let mut truncated = base_record.truncated;
    let fallback_note = format!("[{resp_ct}, {} bytes]", local_bytes.len());
    base_record.vendor_raw_response = cap_payload(
        if vendor_prev.is_empty() {
            &fallback_note
        } else {
            &vendor_prev
        },
        &mut truncated,
    );
    base_record.local_restored_response = cap_payload(
        if local_prev.is_empty() {
            &fallback_note
        } else {
            &local_prev
        },
        &mut truncated,
    );
    base_record.truncated = truncated;
    base_record.response_bytes = local_bytes.len();
    base_record.restored_count = restored_count;
    base_record.withheld_count = withheld_count;
    base_record.latency_ms = start.elapsed().as_millis().max(1) as u64;
    state.push_record(base_record);

    let mut response = Response::new(Body::from(local_bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

async fn read_limited_upstream_bytes(
    resp: reqwest::Response,
    max_bytes: usize,
    idle_timeout: Duration,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "upstream response Content-Length ({len} bytes) exceeds limit ({max_bytes} bytes)"
            ));
        }
    }
    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    loop {
        match tokio::time::timeout(idle_timeout, stream.next()).await {
            Ok(Some(chunk_res)) => {
                let chunk = chunk_res.map_err(|err| err.to_string())?;
                if buf.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(format!(
                        "upstream response body exceeded maximum limit ({max_bytes} bytes)"
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(format!(
                    "upstream response body idle timeout after {}s",
                    idle_timeout.as_secs()
                ));
            }
        }
    }
    Ok(buf)
}

struct GrpcProxyStreamState {
    body: reqwest::Body,
    idle_timeout: Duration,
    restorer: GrpcStreamRestorer,
    pending_trailers: Option<HeaderMap>,
    eof_flushed: bool,
    flushed: bool,
    started_at: Instant,
    state_for_log: GatewayState,
    record: Option<TrafficAuditRecord>,
    action_taken: String,
    resp_ct: String,
    outbound_metrics: Option<(Arc<parking_lot::Mutex<OutboundStreamMetrics>>, PrivacyMode, String)>,
}

impl GrpcProxyStreamState {
    fn add_response_bytes(&mut self, n: usize) {
        if let Some(r) = &mut self.record {
            r.response_bytes += n;
        }
    }

    fn finish_record(&mut self, failed: bool) {
        self.flushed = true;
        let Some(mut record) = self.record.take() else { return };
        let mut truncated = record.truncated;
        if let Some((metrics, mode, req_ct)) = &self.outbound_metrics {
            let m = metrics.lock();
            record.request_bytes = m.request_bytes;
            let local_fallback = format!("[{req_ct}, {} bytes]", m.request_bytes);
            let vendor_fallback = format!("[{req_ct}, {} bytes]", m.vendor_bytes);
            record.local_request_payload = cap_payload(
                if m.local_preview.is_empty() {
                    &local_fallback
                } else {
                    &m.local_preview
                },
                &mut truncated,
            );
            record.vendor_visible_payload = cap_payload(
                if m.vendor_preview.is_empty() {
                    &vendor_fallback
                } else {
                    &m.vendor_preview
                },
                &mut truncated,
            );
            record.findings = m.findings.clone();
            self.action_taken = m.action_taken(*mode);
            record.action_taken = self.action_taken.clone();
        }
        let fallback_note = format!("[{}, {} bytes]", self.resp_ct, record.response_bytes);
        let vendor_prev = self.restorer.vendor_preview();
        let local_prev = self.restorer.local_preview();
        record.vendor_raw_response = cap_payload(
            if vendor_prev.is_empty() {
                &fallback_note
            } else {
                vendor_prev
            },
            &mut truncated,
        );
        record.local_restored_response = cap_payload(
            if local_prev.is_empty() {
                &fallback_note
            } else {
                local_prev
            },
            &mut truncated,
        );
        record.truncated = truncated;
        record.latency_ms = self.started_at.elapsed().as_millis().max(1) as u64;
        record.restored_count = self.restorer.restored_count();
        record.withheld_count = self.restorer.withheld_count();
        if failed {
            record.action_taken = format!("{}+stream-error", self.action_taken);
        }
        self.state_for_log.push_record(record);
    }
}

impl Drop for GrpcProxyStreamState {
    fn drop(&mut self) {
        if !self.flushed {
            self.finish_record(true);
        }
    }
}

fn stream_with_idle_timeout<S>(
    stream: S,
    idle_timeout: Duration,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send
where
    S: futures_util::Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
{
    futures_util::stream::unfold(Some((stream, idle_timeout)), |state| async move {
        let (mut stream, idle_timeout) = state?;
        match tokio::time::timeout(idle_timeout, stream.next()).await {
            Ok(Some(Ok(bytes))) => Some((Ok(bytes), Some((stream, idle_timeout)))),
            Ok(Some(Err(err))) => Some((Err(std::io::Error::other(err)), None)),
            Ok(None) => None,
            Err(_) => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("upstream stream idle timeout after {}s", idle_timeout.as_secs()),
                )),
                None,
            )),
        }
    })
}

async fn read_limited_upstream_text(
    resp: reqwest::Response,
    max_bytes: usize,
    idle_timeout: Duration,
) -> Result<String, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "upstream response Content-Length ({len} bytes) exceeds limit ({max_bytes} bytes)"
            ));
        }
    }
    let mut buf = Vec::new();
    let mut stream = resp.bytes_stream();
    loop {
        match tokio::time::timeout(idle_timeout, stream.next()).await {
            Ok(Some(chunk_res)) => {
                let chunk = chunk_res.map_err(|err| err.to_string())?;
                if buf.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(format!(
                        "upstream response body exceeded maximum limit ({max_bytes} bytes)"
                    ));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(format!(
                    "upstream response body idle timeout after {}s",
                    idle_timeout.as_secs()
                ));
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

struct ProxyStreamState<S> {
    inner: std::pin::Pin<Box<S>>,
    idle_timeout: Duration,
    restorer: Option<SseRestorer>,
    vendor_raw_acc: Vec<u8>,
    restored_acc: Vec<u8>,
    unterminated_sse_bytes: usize,
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

    const TEST_TOKEN: &str = "test-admin-token-0123456789abcdef";

    fn test_state(config: HideConfig) -> GatewayState {
        GatewayState::with_admin_token(config, TEST_TOKEN).with_loopback_for_tests(true)
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
        headers.insert(header::HOST, "127.0.0.1:18787".parse().unwrap());
        headers.append(header::HOST, "evil.example".parse().unwrap());
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
        headers.insert("proxy-connection", "keep-alive".parse().unwrap());
        headers.insert("x-private", "local-only".parse().unwrap());
        headers.insert("x-api-key", "provider-secret".parse().unwrap());
        headers.insert(header::REFERER, "http://localhost/?token=admin-secret".parse().unwrap());
        let forwarded = upstream_request_headers(&headers, "admin-secret", false);
        assert_eq!(forwarded[header::COOKIE], "provider=keep");
        assert_eq!(forwarded["x-api-key"], "provider-secret");
        assert_eq!(forwarded[header::ACCEPT_ENCODING], "identity");
        for name in [
            "authorization",
            "x-hide-go-token",
            "connection",
            "proxy-connection",
            "x-private",
            "referer",
        ] {
            assert!(!forwarded.contains_key(name), "{name}");
        }
        let passthrough = upstream_passthrough_request_headers(&headers, "admin-secret");
        assert_eq!(passthrough[header::COOKIE], "provider=keep");
        for name in ["authorization", "x-hide-go-token", "connection", "proxy-connection"] {
            assert!(!passthrough.contains_key(name), "passthrough leaked {name}");
        }
        headers.insert(header::AUTHORIZATION, "Bearer provider-secret".parse().unwrap());
        assert_eq!(
            upstream_request_headers(&headers, "admin-secret", false)[header::AUTHORIZATION],
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
        let mut state = test_state(HideConfig::default());
        state.use_system_upstream_proxy = false;
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
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let state = test_state(config);
        state
            .vault
            .insert_explicit("local-secret", "review_placeholder", "test");
        let gateway = serve(build_router(state)).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let state = test_state(HideConfig::default());
        let original = "quote \" and newline\nC:\\Users\\alice";
        state
            .vault
            .get_or_insert_scoped_with(Some("127.0.0.1"), original, "test", |_| {
                "review_placeholder".to_string()
            });
        let gateway = serve(build_router(state)).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let state = test_state(HideConfig::default());
        state
            .vault
            .get_or_insert_scoped_with(Some("127.0.0.1"), "quoted \"secret\"\n", "test", |_| {
                "review_placeholder".to_string()
            });
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let state = test_state(HideConfig::default());
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let gateway = serve(build_router(test_state(config))).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "track", "input_schema": {"type": "object", "properties": {"event_type": {"type": "string"}, "telemetry": {}}}}]});
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let state = test_state(HideConfig::default());
        let gateway = serve(build_router(state.clone())).await;
        let response = client()
            .post(format!("{gateway}/claude-code/api/event_logging/batch"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let big = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "a".repeat(5_000_000)}]});
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-token", TEST_TOKEN)
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
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-token", TEST_TOKEN)
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

    #[test]
    fn http2_authority_fallback_works_when_host_header_is_absent() {
        let mut headers = HeaderMap::new();
        let loopback_uri: Uri = "https://127.0.0.1:18787/api/status".parse().unwrap();
        assert!(is_local_request(&headers, &loopback_uri));

        headers.insert(header::ORIGIN, "http://127.0.0.1:18787".parse().unwrap());
        assert!(is_local_request(&headers, &loopback_uri));

        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!is_local_request(&headers, &loopback_uri));

        headers.remove(header::ORIGIN);
        let remote_uri: Uri = "https://evil.example:18787/api/status".parse().unwrap();
        assert!(!is_local_request(&headers, &remote_uri));
    }

    #[test]
    fn simulate_traffic_honors_telemetry_blocking_policy() {
        let state = GatewayState::new(HideConfig::default());
        let rec = state.simulate_traffic(HarnessKind::Codex, TrafficCategory::Telemetry, None);
        assert_eq!(rec.action_taken, "telemetry-blocked");
        assert_eq!(rec.status, 0);
        assert!(rec.vendor_visible_payload.is_empty());
        assert!(!rec.findings.is_empty());

        let mut audit_cfg = HideConfig::default();
        audit_cfg.mode = PrivacyMode::AuditOnly;
        state.try_update_config(audit_cfg).unwrap();
        let audit_rec = state.simulate_traffic(HarnessKind::Codex, TrafficCategory::Telemetry, None);
        assert_eq!(audit_rec.action_taken, "passed");
        assert_eq!(audit_rec.status, 200);
    }

    #[tokio::test]
    async fn audit_only_compressed_request_logs_placeholder_and_forwards_raw_bytes() {
        let (upstream, hits) = counting_upstream().await;
        let mut cfg = HideConfig::default();
        cfg.mode = PrivacyMode::AuditOnly;
        let state = test_state(cfg);
        let gateway = serve(build_router(state.clone())).await;
        let payload = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let response = client()
            .post(format!("{gateway}/claude-code/v1/messages"))
            .header("x-hide-go-token", TEST_TOKEN)
            .header("x-hide-go-upstream", &upstream)
            .header("content-encoding", "gzip")
            .body(payload.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let record = &state.get_records()[0];
        assert_eq!(record.action_taken, "passed");
        assert_eq!(record.request_bytes, payload.len());
        assert!(record.local_request_payload.contains("compressed body (gzip, 8 bytes)"));
    }

    #[test]
    fn join_upstream_url_avoids_double_v1_prefix() {
        assert_eq!(
            join_upstream_url("https://agentrouter.org/v1", "/v1/responses", None),
            "https://agentrouter.org/v1/responses"
        );
        assert_eq!(
            join_upstream_url("https://agentrouter.org/v1/", "/responses", Some("stream=true")),
            "https://agentrouter.org/v1/responses?stream=true"
        );
        assert_eq!(
            join_upstream_url("https://agentrouter.org/v1", "/v1", None),
            "https://agentrouter.org/v1"
        );
        assert_eq!(
            join_upstream_url("https://api.openai.com", "/v1/responses", None),
            "https://api.openai.com/v1/responses"
        );
    }

    #[tokio::test]
    async fn api_update_config_preserves_harness_upstreams_when_omitted() {
        let mut cfg = HideConfig::default();
        cfg.harness_upstreams
            .insert("codex".into(), "https://agentrouter.org/v1".into());
        let state = GatewayState::with_admin_token(cfg, "test-admin-token");
        let gateway = serve(build_router(state.clone())).await;

        let partial_payload = serde_json::json!({
            "proxyPort": 18787,
            "mode": "audit-only",
            "projectSalt": "custom-salt-123456"
        });
        let resp = client()
            .post(format!("{gateway}/api/config"))
            .header("x-hide-go-token", "test-admin-token")
            .json(&partial_payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let updated: HideConfig = resp.json().await.unwrap();
        assert_eq!(updated.mode, PrivacyMode::AuditOnly);
        assert_eq!(
            updated.harness_upstreams.get("codex").map(String::as_str),
            Some("https://agentrouter.org/v1")
        );
    }

    #[tokio::test]
    async fn unauthenticated_x_hide_go_upstream_is_rejected() {
        let (upstream, hits) = counting_upstream().await;
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-upstream", &upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn harness_proxy_blocks_ssrf_and_self_loop_targets() {
        let prod_state = GatewayState::with_admin_token(HideConfig::default(), TEST_TOKEN);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        prod_state.config.write().proxy_port = addr.port();
        tokio::spawn(async move { axum::serve(listener, build_router(prod_state)).await.unwrap() });
        let gateway = format!("http://{addr}");
        for target in [
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/internal",
            "http://[::ffff:127.0.0.1]/admin",
            "http://127.0.0.1:80/admin",
            &gateway,
        ] {
            let response = client()
                .post(format!("{gateway}/codex/v1/responses"))
                .header("x-hide-go-token", TEST_TOKEN)
                .header("x-hide-go-upstream", target)
                .body("hello")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "expected 403 for {target}");
        }
    }

    #[tokio::test]
    async fn cross_vendor_vault_tokens_are_not_reflected() {
        let upstream =
            serve(Router::new().fallback(|| async { Json(serde_json::json!({"content": "other_vendor_token"})) }))
                .await;
        let state = test_state(HideConfig::default());
        // Token registered for `api.openai.com` must NEVER restore when talking to `127.0.0.1` upstream.
        state.vault.get_or_insert_scoped_with(
            Some("api.openai.com"),
            "sk-ant-api03-crossvendorsecret999999",
            "test",
            |_| "other_vendor_token".to_string(),
        );
        let gateway = serve(build_router(state)).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
            .header("x-hide-go-upstream", upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.json::<Value>().await.unwrap()["content"], "other_vendor_token");
    }

    #[tokio::test]
    async fn oversized_upstream_response_is_rejected_with_502() {
        let upstream = serve(Router::new().fallback(|| async {
            (
                StatusCode::OK,
                [(header::CONTENT_LENGTH, (MAX_RESPONSE_BODY + 1024).to_string())],
                "tiny",
            )
        }))
        .await;
        let gateway = serve(build_router(test_state(HideConfig::default()))).await;
        let response = client()
            .post(format!("{gateway}/codex/v1/responses"))
            .header("x-hide-go-token", TEST_TOKEN)
            .header("x-hide-go-upstream", upstream)
            .body("hello")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn same_harness_subdomains_share_scope_while_distinct_vendors_remain_isolated() {
        let headers = HeaderMap::new();
        let (h1, _, scope1) =
            resolve_proxy_harness_and_scope("/v1/chat/completions", &headers, b"{}", "api2.cursor.sh");
        let (h2, _, scope2) =
            resolve_proxy_harness_and_scope("/v1/chat/completions", &headers, b"{}", "api3.cursor.sh");
        let (h3, _, scope3) =
            resolve_proxy_harness_and_scope("/repo-service/upload", &headers, b"{}", "repo42.cursor.sh");
        assert_eq!(h1, HarnessKind::Cursor);
        assert_eq!(h2, HarnessKind::Cursor);
        assert_eq!(h3, HarnessKind::Cursor);
        assert_eq!(scope1.as_deref(), Some("harness:cursor"));
        assert_eq!(scope1, scope2);
        assert_eq!(scope2, scope3);

        let (_, _, qoder1) = resolve_proxy_harness_and_scope("/v1/chat/completions", &headers, b"{}", "api1.qoder.sh");
        let (_, _, qoder2) =
            resolve_proxy_harness_and_scope("/v1/chat/completions", &headers, b"{}", "gateway.qoder.com.cn");
        assert_eq!(qoder1.as_deref(), Some("harness:qoder"));
        assert_eq!(qoder1, qoder2);

        let (_, _, claude) = resolve_proxy_harness_and_scope("/v1/messages", &headers, b"{}", "api.anthropic.com");
        let (_, _, codex) = resolve_proxy_harness_and_scope("/v1/responses", &headers, b"{}", "api.openai.com");
        let (_, _, deepseek) =
            resolve_proxy_harness_and_scope("/v1/chat/completions", &headers, b"{}", "api.deepseek.com");
        let (_, _, openrouter) =
            resolve_proxy_harness_and_scope("/v1/chat/completions", &headers, b"{}", "openrouter.ai");
        assert_eq!(claude.as_deref(), Some("harness:claude-code"));
        assert_eq!(codex.as_deref(), Some("harness:codex"));
        assert_eq!(deepseek.as_deref(), Some("api.deepseek.com"));
        assert_eq!(openrouter.as_deref(), Some("openrouter.ai"));

        // Verify vault token registered under Cursor scope restores across Cursor subdomains
        // but is strictly isolated from ClaudeCode, Codex, and Generic hosts.
        let vault = PrivacyVault::new();
        let cfg = HideConfig::default();
        let (masked, _, _) = transform_outbound_scoped(
            &vault,
            TrafficCategory::InteractivePrompt,
            r#"{"msg":"api key sk-ant-api03-cursorsecret1234567890"}"#,
            &cfg,
            scope1.as_deref(),
        );
        assert!(!masked.contains("sk-ant-api03-cursorsecret1234567890"));

        let (restored_cursor, count_cursor, _) = restore_response(
            &vault.matcher_for_scope(scope3.as_deref()),
            &masked,
            cfg.tool_call_secret_policy,
        );
        assert_eq!(count_cursor, 1);
        assert!(restored_cursor.contains("sk-ant-api03-cursorsecret1234567890"));

        for other in [claude.as_deref(), codex.as_deref(), deepseek.as_deref()] {
            let (restored_other, count_other, _) =
                restore_response(&vault.matcher_for_scope(other), &masked, cfg.tool_call_secret_policy);
            assert_eq!(count_other, 0, "cross-vendor leak into scope {other:?}");
            assert!(!restored_other.contains("sk-ant-api03-cursorsecret1234567890"));
        }
    }

    #[test]
    fn try_update_config_clamps_upstream_idle_timeout_secs() {
        let state = GatewayState::new(HideConfig::default());
        let mut low = HideConfig::default();
        low.upstream_idle_timeout_secs = 5;
        let saved_low = state.try_update_config(low).unwrap();
        assert_eq!(saved_low.upstream_idle_timeout_secs, 30);

        let mut high = HideConfig::default();
        high.upstream_idle_timeout_secs = 99_999;
        let saved_high = state.try_update_config(high).unwrap();
        assert_eq!(saved_high.upstream_idle_timeout_secs, 3600);
    }

    #[tokio::test]
    async fn forward_and_mitm_use_local_client_for_allowed_loopback_targets_only() {
        let upstream = serve(Router::new().fallback(|| async { Json(serde_json::json!({"ok": true})) })).await;
        let parsed: reqwest::Url = upstream.parse().unwrap();
        let port = parsed.port().unwrap();

        let mut cfg = HideConfig::default();
        cfg.proxy_port = 18787;
        cfg.allowed_loopback_proxy_targets = vec![format!("127.0.0.1:{port}")];
        // Production-like GatewayState (`allow_loopback_for_tests == false`)
        let state = GatewayState::new(cfg);

        // Allowed loopback target succeeds on forward HTTP via `local_http_client`
        let ok_resp = handle_forward_http_request(
            state.clone(),
            Method::GET,
            format!("http://127.0.0.1:{port}/health").parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
            false,
        )
        .await;
        assert_eq!(ok_resp.status(), StatusCode::OK);

        // Allowed loopback target also succeeds via `handle_mitm_http_request` (HTTP scheme in test)
        let mitm_ok = handle_mitm_http_request(
            state.clone(),
            "http",
            "127.0.0.1",
            port,
            Method::GET,
            "/health".parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        assert_eq!(mitm_ok.status(), StatusCode::OK);

        // Unlisted loopback port stays blocked with 403
        let blocked_resp = handle_forward_http_request(
            state.clone(),
            Method::GET,
            "http://127.0.0.1:6379/".parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
            false,
        )
        .await;
        assert_eq!(blocked_resp.status(), StatusCode::FORBIDDEN);

        let blocked_mitm = handle_mitm_http_request(
            state,
            "http",
            "127.0.0.1",
            18787,
            Method::GET,
            "/api/status".parse().unwrap(),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        assert_eq!(blocked_mitm.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn semver_comparison_handles_prefixes_and_prereleases() {
        assert!(is_newer_version("0.2.4", "v0.2.5"));
        assert!(is_newer_version("v0.2.4", "0.3.0"));
        assert!(is_newer_version("0.2.5-rc.1", "0.2.5"));
        assert!(!is_newer_version("0.2.4", "v0.2.4"));
        assert!(!is_newer_version("0.2.5", "0.2.4"));
        assert!(!is_newer_version("0.2.5", "0.2.5-rc.1"));
        assert!(!is_newer_version("0.2.4", "not-a-version"));
    }

    #[tokio::test]
    async fn fetch_latest_release_parses_release_and_sanitizes_url() {
        let mock_app = Router::new().route(
            "/latest",
            get(|| async {
                Json(serde_json::json!({
                    "tag_name": "v0.9.0",
                    "html_url": "https://github.com/Aflydream/hide-go/releases/tag/v0.9.0",
                    "published_at": "2026-11-21T10:00:00Z"
                }))
            }),
        );
        let base = serve(mock_app).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let res = fetch_latest_release_from(&client, &format!("{base}/latest"), "0.2.4")
            .await
            .unwrap();
        assert_eq!(res.current_version, "0.2.4");
        assert_eq!(res.latest_version, "0.9.0");
        assert!(res.update_available);
        assert_eq!(
            res.release_url,
            "https://github.com/Aflydream/hide-go/releases/tag/v0.9.0"
        );

        let spoofed_app = Router::new().route(
            "/latest",
            get(|| async {
                Json(serde_json::json!({
                    "tag_name": "v0.9.0",
                    "html_url": "https://evil.example/phish.exe"
                }))
            }),
        );
        let spoofed_base = serve(spoofed_app).await;
        let sanitized = fetch_latest_release_from(&client, &format!("{spoofed_base}/latest"), "0.2.4")
            .await
            .unwrap();
        assert_eq!(sanitized.release_url, UPDATE_RELEASE_FALLBACK_URL);
    }

    #[tokio::test]
    async fn api_check_updates_returns_fresh_cache_without_network() {
        use tower::ServiceExt;
        let cfg = HideConfig::default();
        let state = GatewayState::with_admin_token(cfg, "test-admin-token-0123456789abcd");
        let cached = UpdateCheckResult {
            current_version: "0.2.4".to_string(),
            latest_version: "0.2.5".to_string(),
            update_available: true,
            release_url: UPDATE_RELEASE_FALLBACK_URL.to_string(),
            published_at: Some("2026-11-21T10:00:00Z".to_string()),
            checked_at: "2026-11-21T10:01:00+08:00".to_string(),
        };
        *state.update_cache.write() = Some((Instant::now(), cached));

        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/updates/check")
                    .header("host", "127.0.0.1:18787")
                    .header("x-hide-go-token", "test-admin-token-0123456789abcd")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["latestVersion"], "0.2.5");
        assert_eq!(json["updateAvailable"], true);
    }

    #[test]
    fn outbound_headers_strip_proxy_and_gateway_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "sk-user-key".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("x-hide-go-upstream", "https://api.openai.com".parse().unwrap());
        headers.insert("x-hide-go-mode", "all-hide".parse().unwrap());
        headers.insert("via", "1.1 hide-go".parse().unwrap());
        headers.insert("forwarded", "for=127.0.0.1".parse().unwrap());
        headers.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-real-ip", "127.0.0.1".parse().unwrap());

        let clean = upstream_request_headers(&headers, "admin-tok", true);
        assert_eq!(clean["x-api-key"], "sk-user-key");
        assert_eq!(clean["content-type"], "application/json");
        for scrubbed in [
            "x-hide-go-upstream",
            "x-hide-go-mode",
            "via",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
        ] {
            assert!(!clean.contains_key(scrubbed), "header leaked outbound: {scrubbed}");
        }

        let clean_pass = upstream_passthrough_request_headers(&headers, "admin-tok");
        assert!(!clean_pass.contains_key("x-forwarded-for"));
        assert!(!clean_pass.contains_key("via"));
        assert_eq!(clean_pass["x-api-key"], "sk-user-key");
    }

    #[test]
    fn windows_proxy_parser_and_self_loop_guard_work() {
        use crate::upstream_proxy::{is_self_proxy, parse_proxy_server};
        assert_eq!(
            parse_proxy_server("127.0.0.1:7897").as_deref(),
            Some("http://127.0.0.1:7897/")
        );
        assert_eq!(
            parse_proxy_server("http=127.0.0.1:7890;https=127.0.0.1:7891;socks=127.0.0.1:7892").as_deref(),
            Some("http://127.0.0.1:7891/")
        );
        assert_eq!(
            parse_proxy_server("http=127.0.0.1:7890").as_deref(),
            Some("http://127.0.0.1:7890/")
        );
        assert!(parse_proxy_server("socks5://127.0.0.1:7897").is_none());
        assert!(parse_proxy_server("   ").is_none());

        assert!(is_self_proxy("http://127.0.0.1:18787/", 18787));
        assert!(is_self_proxy("http://localhost:18787/", 18787));
        assert!(!is_self_proxy("http://127.0.0.1:7897/", 18787));
        assert!(!is_self_proxy("http://proxy.corp.local:8080/", 18787));
    }

    #[tokio::test]
    async fn grpc_streaming_proxy_desensitizes_restores_and_preserves_http2_trailers() {
        use hyper::service::service_fn;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use std::convert::Infallible;

        // Spawn an HTTP/2-capable (h2c prior knowledge) mock gRPC upstream that asserts
        // outbound desensitization, echoes the masked Protobuf payload in two chunks, and
        // appends `grpc-status: 0` as an HTTP/2 trailer frame.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_seen = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
        let seen_clone = upstream_seen.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = upstream_listener.accept().await else {
                    break;
                };
                let seen = seen_clone.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            *seen.lock() = body.to_vec();

                            let mut trailers = HeaderMap::new();
                            trailers.insert("grpc-status", "0".parse().unwrap());
                            trailers.insert("grpc-message", "ok".parse().unwrap());

                            let mid = body.len() / 2;
                            let part1 = body.slice(..mid);
                            let part2 = body.slice(mid..);
                            let frame_stream = futures_util::stream::iter(vec![
                                Ok::<Frame<Bytes>, Infallible>(Frame::data(part1)),
                                Ok::<Frame<Bytes>, Infallible>(Frame::data(part2)),
                                Ok::<Frame<Bytes>, Infallible>(Frame::trailers(trailers)),
                            ]);
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/grpc+proto")
                                .body(Body::new(StreamBody::new(frame_stream)))
                                .unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let h2_upstream_client = reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        let mut state = test_state(HideConfig::default());
        state.local_http_client = h2_upstream_client;
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = gateway_listener.local_addr().unwrap();
        let app = build_router(state.clone());
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = gateway_listener.accept().await else {
                    break;
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let app = app.clone();
                        async move {
                            use tower::ServiceExt as _;
                            app.oneshot(req.map(Body::new)).await
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        // Build a valid gRPC-framed Protobuf message containing the secret key
        let secret_text = "sk-wbefwubfbsrfrsuf baseurl:linuu.do/v1 是什么";
        let mut pb = vec![0x0A, secret_text.len() as u8];
        pb.extend_from_slice(secret_text.as_bytes());
        let mut grpc_req = vec![0x00];
        grpc_req.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        grpc_req.extend_from_slice(&pb);

        let h2_client = reqwest::Client::builder()
            .no_proxy()
            .http2_prior_knowledge()
            .build()
            .unwrap();
        let resp = h2_client
            .post(format!(
                "http://{gateway_addr}/antigravity/google.internal.cloud.code.v1internal.CodeAssist/StreamGenerateContent"
            ))
            .header("x-hide-go-token", TEST_TOKEN)
            .header("x-hide-go-upstream", format!("http://{upstream_addr}"))
            .header("content-type", "application/grpc+proto")
            .body(grpc_req)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "application/grpc+proto");

        // Verify upstream NEVER saw the real secret key
        let sent = upstream_seen.lock().clone();
        assert!(!String::from_utf8_lossy(&sent).contains("sk-wbefwubfbsrfrsuf"));
        assert!(String::from_utf8_lossy(&sent).contains("baseurl:linuu.do/v1"));

        // Drive response body via `http_body_util::BodyExt::frame()` to verify BOTH restored data AND `grpc-status: 0` trailer!
        let http_resp: axum::http::Response<reqwest::Body> = resp.into();
        let mut body = http_resp.into_body();
        let mut received_data = Vec::new();
        let mut received_trailers = HeaderMap::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.unwrap();
            match frame.into_data() {
                Ok(data) => received_data.extend_from_slice(&data),
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        received_trailers.extend(trailers);
                    }
                }
            }
        }

        assert_eq!(
            received_trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("0"),
            "HTTP/2 grpc-status trailer must be preserved verbatim"
        );
        let frame_len =
            u32::from_be_bytes([received_data[1], received_data[2], received_data[3], received_data[4]]) as usize;
        assert_eq!(frame_len, received_data.len() - 5);
        assert!(
            String::from_utf8_lossy(&received_data[5..]).contains(secret_text),
            "client must receive losslessly restored Protobuf payload"
        );

        let records = state.get_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].harness, HarnessKind::Antigravity);
        assert_eq!(records[0].action_taken, "protobuf-desensitized");
        assert!(!records[0].findings.is_empty());
        assert_eq!(records[0].restored_count, 1);
    }
}
