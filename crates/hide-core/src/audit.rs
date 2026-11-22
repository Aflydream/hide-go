//! Traffic audit heuristics and exact request purpose classification.
//!
//! Runs across every mode (including `audit-only`) to:
//! 1. Detect silent telemetry, analytics, feature-flag tracking, crash diagnostics,
//!    archive/multipart uploads, codebase indexing syncs, oversized outbound payloads,
//!    and sensitive values inside non-interactive uploads across Host, Path/RPC,
//!    Headers, Payload, and raw `CONNECT` tunnels.
//! 2. Classify every request into a precise `RequestPurpose` with a concise explanation
//!    so operators know the exact role of every outbound connection.

use crate::config::{HarnessKind, TrafficCategory};
use crate::connect::is_builtin_ai_mitm_host;
use crate::harness::is_inference_endpoint;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const LARGE_NON_INFERENCE_BYTES: usize = 256 * 1024;
const LARGE_ANY_REQUEST_BYTES: usize = 1024 * 1024;
const OCTET_STREAM_ARCHIVE_THRESHOLD: usize = 16 * 1024;
const MULTIPART_LARGE_THRESHOLD: usize = 64 * 1024;
const PASSTHROUGH_UPLOAD_STORAGE_THRESHOLD: u64 = 64 * 1024;
const PASSTHROUGH_LARGE_UPLOAD_THRESHOLD: u64 = 512 * 1024;
const MAX_TEXT_SCAN_BYTES: usize = 128 * 1024;

/// Risk classification for a destination host seen on `CONNECT` or HTTP forwarding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HostRiskKind {
    Telemetry,
    UploadStorage,
    AiApi,
    General,
}

/// Exact functional role of an outbound request or tunnel.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RequestPurpose {
    /// Active interactive chat or agent model inference.
    ChatInference,
    /// Model inference turn sending back local tool/command/file execution output.
    ToolResultSync,
    /// Fill-in-the-middle / Tab / inline code autocomplete inference.
    InlineCompletion,
    /// Token counting or context window budget estimation.
    TokenCount,
    /// Repository indexing, embeddings, Merkle sync, or batch codebase upload.
    CodebaseIndexing,
    /// Explicit file, archive, multipart, or object-storage upload.
    FileUpload,
    /// Telemetry, analytics, metrics, OTel traces/logs, or usage event reporting.
    Telemetry,
    /// Feature gates, A/B experiments, or remote experiment evaluation.
    FeatureFlags,
    /// Crash dumps, error diagnostics, or feedback/bug reporting.
    CrashReport,
    /// Model catalog discovery, quota lookup, onboarding, or client config sync.
    ModelCatalog,
    /// Authentication, OAuth, session refresh, billing, or account status.
    AuthAccount,
    /// WebChannel, session tunnels, WebSockets, keepalive, or health checks.
    RealtimeSync,
    /// Software update checks, release metadata, or extension marketplace queries.
    UpdateExtension,
    /// Other non-inference API or general network request.
    #[default]
    OtherApi,
}

impl RequestPurpose {
    pub fn is_telemetry_like(self) -> bool {
        matches!(self, Self::Telemetry | Self::FeatureFlags | Self::CrashReport)
    }
}

/// Individual audit finding attached to a `TrafficAuditRecord`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSignalKind {
    TelemetryEndpoint,
    TelemetryPayload,
    TelemetryHeader,
    FeatureFlagTracking,
    CrashDiagnostics,
    ArchiveUpload,
    BulkCodebaseUpload,
    LargeOutboundPayload,
    SensitiveDataExfil,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSeverity {
    Info,
    Warn,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditSignal {
    pub kind: AuditSignalKind,
    pub severity: AuditSeverity,
    pub detail: String,
}

/// Per-harness rollup surfaced in `GET /api/status` so users can immediately see whether
/// each connected tool is sending telemetry, bulk-uploading workspace data, and the
/// exact breakdown of request purposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HarnessAuditSummary {
    pub harness: HarnessKind,
    pub total_requests: u64,
    pub telemetry_events: u64,
    pub bulk_upload_events: u64,
    pub sensitive_exfil_events: u64,
    pub outbound_bytes: u64,
    #[serde(default)]
    pub telemetry_hosts: Vec<String>,
    #[serde(default)]
    pub upload_hosts: Vec<String>,
    #[serde(default)]
    pub purpose_counts: BTreeMap<RequestPurpose, u64>,
}

const FEATURE_FLAG_HOSTS: &[&str] = &[
    "statsig.anthropic.com",
    "statsig.openai.com",
    "statsigapi.net",
    "events.statsigapi.net",
    "featuregates.org",
    "ab.chatgpt.com",
    "launchdarkly.com",
    "events.launchdarkly.com",
    "clientstream.launchdarkly.com",
    "app.launchdarkly.com",
    "split.io",
    "events.split.io",
    "sdk.split.io",
    "growthbook.io",
    "optimizely.com",
    "logx.optimizely.com",
];

const CRASH_DIAGNOSTIC_HOSTS: &[&str] = &[
    "sentry.io",
    "ingest.sentry.io",
    "ingest.us.sentry.io",
    "ingest.de.sentry.io",
    "crashlyticsreports-pa.googleapis.com",
    "clouderrorreporting.googleapis.com",
    "bugsnag.com",
    "notify.bugsnag.com",
    "sessions.bugsnag.com",
    "rollbar.com",
    "backtrace.io",
    "raygun.com",
];

const TELEMETRY_EXACT_OR_SUFFIX_HOSTS: &[&str] = &[
    // Google / Antigravity / Firebase / Clearcut
    "play.googleapis.com",
    "firebaselogging-pa.googleapis.com",
    "firebaselogging.googleapis.com",
    "clientmetrics-pa.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "telemetry.googleapis.com",
    "app-measurement.com",
    "google-analytics.com",
    "analytics.google.com",
    // Anthropic / Claude Code
    "telemetry.anthropic.com",
    // OpenAI / Codex
    "telemetry.openai.com",
    "otel.openai.com",
    "logs.openai.com",
    // Cursor
    "t.cursor.sh",
    "metrics.cursor.sh",
    "telemetry.cursor.sh",
    "analytics.cursor.sh",
    // Qoder / Alibaba Cloud
    "arms-retcode.aliyuncs.com",
    "log.aliyuncs.com",
    "sls.aliyuncs.com",
    "retcode.alicdn.com",
    "gm.mmstat.com",
    "s-gm.mmstat.com",
    "fourier.alibaba.com",
    "umeng.com",
    // xAI / Grok Build & ZCode
    "telemetry.x.ai",
    "metrics.x.ai",
    "events.x.ai",
    "telemetry.zcode.ai",
    "metrics.zcode.ai",
    "telemetry.z.ai",
    // General analytics / APM / OTel / Microsoft VSCode telemetry
    "api.segment.io",
    "cdn.segment.com",
    "segment.io",
    "api.amplitude.com",
    "api2.amplitude.com",
    "amplitude.com",
    "posthog.com",
    "us.i.posthog.com",
    "eu.i.posthog.com",
    "app.posthog.com",
    "mixpanel.com",
    "api-js.mixpanel.com",
    "api.mixpanel.com",
    "dc.services.visualstudio.com",
    "in.applicationinsights.azure.com",
    "livediagnostics.monitor.azure.com",
    "vortex.data.microsoft.com",
    "events.data.microsoft.com",
    "datadoghq.com",
    "datadoghq.eu",
    "browser-intake-datadoghq.com",
    "http-intake.logs.datadoghq.com",
    "api.honeycomb.io",
    "bam.nr-data.net",
    "log-api.newrelic.com",
    "otlp.nr-data.net",
    "heapanalytics.com",
    "fullstory.com",
    "pendo.io",
    "clarity.ms",
    "plausible.io",
    "rudderstack.com",
    "snowplowanalytics.com",
];

const TELEMETRY_HOST_PREFIXES: &[&str] = &[
    "telemetry.",
    "metrics.",
    "analytics.",
    "events.",
    "logging.",
    "crash.",
    "otlp.",
    "otel.",
    "statsig.",
    "sentry.",
    "beacon.",
    "diag.",
    "diagnostics.",
    "traces.",
];

const UPLOAD_STORAGE_EXACT_OR_SUFFIX_HOSTS: &[&str] = &[
    "repo42.cursor.sh",
    "repo1.qoder.sh",
    "repo.qoder.com.cn",
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "r2.cloudflarestorage.com",
];

const AUTH_HOSTS: &[&str] = &[
    "oauth2.googleapis.com",
    "accounts.google.com",
    "auth.openai.com",
    "auth0.openai.com",
    "auth.cursor.sh",
    "login.cursor.sh",
    "auth.qoder.sh",
    "login.qoder.sh",
    "auth.qoder.com",
    "login.qoder.com",
    "auth.qoder.com.cn",
    "login.qoder.com.cn",
    "accounts.x.ai",
];

const UPDATE_HOSTS: &[&str] = &[
    "update.googleapis.com",
    "clients2.google.com",
    "marketplace.visualstudio.com",
    "marketplace.cursorapi.com",
    "downloads.cursor.com",
    "open-vsx.org",
];

const TELEMETRY_PATH_WORDS: &[&str] = &[
    "telemetry",
    "analytics",
    "metrics",
    "metric",
    "traces",
    "trace",
    "rgstr",
    "logevent",
    "logevents",
    "batchlog",
    "clientmetrics",
    "clearcut",
    "otlp",
    "otel",
    "beacon",
    "beacons",
    "snowplow",
    "posthog",
    "mixpanel",
    "amplitude",
    "datadog",
    "rum",
];

const FEATURE_FLAG_PATH_WORDS: &[&str] = &[
    "statsig",
    "featuregates",
    "featuregate",
    "featureflags",
    "featureflag",
    "experiments",
    "experiment",
    "abtest",
    "remoteconfig",
    "launchdarkly",
];

const CRASH_PATH_WORDS: &[&str] = &[
    "crash",
    "crashes",
    "crashlytics",
    "minidump",
    "errorreporting",
    "errorreport",
    "sentry",
    "bugsnag",
    "rollbar",
    "bugreport",
    "feedback",
    "diagnostic",
    "diagnostics",
];

const BULK_UPLOAD_PATH_KEYWORDS: &[&str] = &[
    "upload-chunks",
    "codebase_sync",
    "codebase",
    "merkle",
    "indexing",
    "index-sync",
    "repo-service",
    "repositoryservice",
    "uploadfiles",
    "upload_files",
    "synccodebase",
    "sync_codebase",
    "workspace_upload",
    "workspace/sync",
    "archive",
    "bundle",
];

/// Header names whose presence indicates a telemetry / crash / feature-flag SDK request,
/// even when the body is compressed, binary protobuf, or empty.
const TELEMETRY_HEADER_EXACT: &[&str] = &[
    "x-sentry-auth",
    "sentry-trace",
    "dd-api-key",
    "dd-evp-origin",
    "dd-evp-origin-version",
    "statsig-api-key",
    "statsig-client-time",
    "statsig-sdk-type",
    "statsig-sdk-version",
    "x-honeycomb-team",
    "x-honeycomb-dataset",
    "x-datadog-trace-id",
    "x-datadog-origin",
    "x-segment-anonymous-id",
    "x-amplitude-device-id",
    "x-launchdarkly-event-schema",
    "x-launchdarkly-wrapper",
];

const TELEMETRY_HEADER_PREFIXES: &[&str] = &[
    "x-telemetry-",
    "x-client-telemetry",
    "x-anthropic-telemetry",
    "x-otlp-",
    "x-posthog-",
    "x-mixpanel-",
    "x-amplitude-",
    "x-statsig-",
];

/// High-confidence structural telemetry markers (1 hit on a non-inference endpoint is enough).
const STRONG_TELEMETRY_PAYLOAD_MARKERS: &[&str] = &[
    "\"resourcespans\"",
    "\"resourcemetrics\"",
    "\"resourcelogs\"",
    "\"scopespan\"",
    "\"scopespans\"",
    "\"scopemetrics\"",
    "\"statsigmetadata\"",
    "\"telemetry.sdk.name\"",
    "\"clientmetrics\"",
    "\"client_metrics\"",
    "\"eventbatch\"",
    "\"event_batch\"",
    "\"crashreport\"",
    "\"crash_report\"",
    "\"logsource\"",
];

/// General telemetry / device-fingerprint payload markers (2+ hits on a non-inference endpoint).
const TELEMETRY_PAYLOAD_MARKERS: &[&str] = &[
    "\"machineid\"",
    "\"machine_id\"",
    "\"deviceid\"",
    "\"device_id\"",
    "\"logevent\"",
    "\"log_event\"",
    "\"osversion\"",
    "\"os_version\"",
    "\"telemetry\"",
    "\"statsig\"",
    "\"sentry\"",
    "\"anonymousid\"",
    "\"anonymous_id\"",
    "\"distinct_id\"",
    "\"distinctid\"",
    "\"appversion\"",
    "\"app_version\"",
    "\"event_name\"",
    "\"eventname\"",
    "\"event_type\"",
    "\"eventtype\"",
    "\"exposures\"",
    "\"breadcrumbs\"",
    "\"featuregates\"",
    "\"feature_gates\"",
    "\"dynamicconfigs\"",
    "\"sessionduration\"",
    "\"requesttimems\"",
    "\"sourceextension\"",
];

const BULK_FILE_TREE_MARKERS: &[&str] = &[
    "\"relativepath\"",
    "\"relative_path\"",
    "\"filepath\"",
    "\"file_path\"",
    "\"file_contents\"",
    "\"filecontents\"",
    "\"merkle\"",
    "\"chunks\"",
];

fn normalize_host(raw: &str) -> String {
    raw.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn host_matches_exact_or_sub(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn is_feature_flag_host(host: &str) -> bool {
    FEATURE_FLAG_HOSTS.iter().any(|d| host_matches_exact_or_sub(host, d)) || host.starts_with("statsig.")
}

fn is_crash_diagnostic_host(host: &str) -> bool {
    CRASH_DIAGNOSTIC_HOSTS
        .iter()
        .any(|d| host_matches_exact_or_sub(host, d))
        || host.starts_with("crash.")
        || host.starts_with("sentry.")
}

/// Split a URL path / RPC action into lowercase words, splitting both on punctuation
/// (`/`, `?`, `:`, `.`, `-`, `_`) AND on camelCase / PascalCase boundaries
/// (e.g. `recordCodeAssistMetrics` -> `["record", "code", "assist", "metrics"]`).
pub fn tokenize_path_words(path: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower_or_digit = false;
    let mut prev_upper = false;

    let mut iter = path.chars().peekable();
    while let Some(ch) = iter.next() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            prev_lower_or_digit = false;
            prev_upper = false;
            continue;
        }
        let is_upper = ch.is_ascii_uppercase();
        let next_is_lower = iter.peek().is_some_and(|n| n.is_ascii_lowercase());
        if is_upper
            && ((prev_lower_or_digit && !current.is_empty()) || (prev_upper && next_is_lower && current.len() > 1))
        {
            words.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
        prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        prev_upper = is_upper;
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Classify a destination host into telemetry, upload storage, AI API, or general traffic.
pub fn classify_host_risk(raw_host: &str) -> HostRiskKind {
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return HostRiskKind::General;
    }
    if is_feature_flag_host(&host)
        || is_crash_diagnostic_host(&host)
        || TELEMETRY_EXACT_OR_SUFFIX_HOSTS
            .iter()
            .any(|d| host_matches_exact_or_sub(&host, d))
        || TELEMETRY_HOST_PREFIXES.iter().any(|p| host.starts_with(p))
    {
        return HostRiskKind::Telemetry;
    }
    if UPLOAD_STORAGE_EXACT_OR_SUFFIX_HOSTS
        .iter()
        .any(|d| host_matches_exact_or_sub(&host, d))
        || host.starts_with("upload.")
        || host.starts_with("uploads.")
        || (host.contains(".s3.") && host.ends_with(".amazonaws.com"))
    {
        return HostRiskKind::UploadStorage;
    }
    if is_builtin_ai_mitm_host(&host) {
        return HostRiskKind::AiApi;
    }
    HostRiskKind::General
}

/// Classify a host's primary functional purpose (used for `CONNECT` passthrough tunnels
/// and the Observed Hosts inspector in Integrations).
pub fn classify_host_purpose(raw_host: &str) -> RequestPurpose {
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return RequestPurpose::OtherApi;
    }
    if is_crash_diagnostic_host(&host) {
        return RequestPurpose::CrashReport;
    }
    if is_feature_flag_host(&host) {
        return RequestPurpose::FeatureFlags;
    }
    if TELEMETRY_EXACT_OR_SUFFIX_HOSTS
        .iter()
        .any(|d| host_matches_exact_or_sub(&host, d))
        || TELEMETRY_HOST_PREFIXES.iter().any(|p| host.starts_with(p))
    {
        return RequestPurpose::Telemetry;
    }
    if host == "jetski-webchannel.googleapis.com" || host.contains("webchannel.") || host.starts_with("ws.") {
        return RequestPurpose::RealtimeSync;
    }
    if host == "repo42.cursor.sh" || host == "repo1.qoder.sh" || host == "repo.qoder.com.cn" {
        return RequestPurpose::CodebaseIndexing;
    }
    if classify_host_risk(&host) == HostRiskKind::UploadStorage {
        return RequestPurpose::FileUpload;
    }
    if AUTH_HOSTS.iter().any(|d| host_matches_exact_or_sub(&host, d))
        || host.starts_with("auth.")
        || host.starts_with("login.")
        || host.starts_with("oauth.")
        || host.starts_with("accounts.")
        || host.starts_with("sso.")
    {
        return RequestPurpose::AuthAccount;
    }
    if UPDATE_HOSTS.iter().any(|d| host_matches_exact_or_sub(&host, d))
        || host.starts_with("update.")
        || host.starts_with("updates.")
        || host.starts_with("releases.")
        || host.starts_with("marketplace.")
    {
        return RequestPurpose::UpdateExtension;
    }
    if is_builtin_ai_mitm_host(&host) {
        return RequestPurpose::ChatInference;
    }
    RequestPurpose::OtherApi
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn has_archive_magic(raw: &[u8], content_encoding: Option<&str>) -> Option<&'static str> {
    if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
        return Some("ZIP");
    }
    if raw.len() >= 4 && raw[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Some("ZSTD");
    }
    if raw.len() >= 263 && &raw[257..262] == b"ustar" {
        return Some("TAR");
    }
    let ce_gzip = content_encoding
        .map(|v| v.to_ascii_lowercase().contains("gzip"))
        .unwrap_or(false);
    if !ce_gzip && raw.len() >= 2 && raw[0] == 0x1F && raw[1] == 0x8B {
        return Some("GZIP");
    }
    None
}

fn count_distinct_local_paths(text: &str) -> usize {
    let mut seen = BTreeSet::new();
    for token in text.split(['"', '\'', '\n', '\r', '\t', ',', '{', '}', '[', ']']) {
        let t = token.trim();
        if t.len() < 8 || t.len() > 260 {
            continue;
        }
        let is_win = t.len() >= 3
            && t.as_bytes()[0].is_ascii_alphabetic()
            && t.as_bytes()[1] == b':'
            && (t.as_bytes()[2] == b'\\' || t.as_bytes()[2] == b'/');
        let is_unix = t.starts_with("/Users/") || t.starts_with("/home/") || t.starts_with("/workspace/");
        if is_win || is_unix {
            seen.insert(t);
            if seen.len() >= 5 {
                break;
            }
        }
    }
    seen.len()
}

fn words_contain(words: &[String], targets: &[&str]) -> bool {
    words.iter().any(|w| targets.contains(&w.as_str()))
}

fn words_have_pair(words: &[String], a: &[&str], b: &[&str]) -> bool {
    words_contain(words, a) && words_contain(words, b)
}

/// True when the URL path / RPC method represents a telemetry, metrics, or event-logging endpoint.
pub fn has_telemetry_path(path: &str) -> bool {
    let path_lower = path.to_ascii_lowercase();
    if is_inference_endpoint(&path_lower) {
        return false;
    }
    let words = tokenize_path_words(path);
    words_contain(&words, TELEMETRY_PATH_WORDS)
        || words_have_pair(
            &words,
            &["event", "events", "log", "logs", "logging", "usage", "stats", "audit"],
            &[
                "log", "logs", "logging", "batch", "record", "report", "submit", "send", "ingest", "collect", "track",
            ],
        )
        || path_lower.contains("event_logging")
        || path_lower.contains("/v1/logs")
        || path_lower.contains("/v1/metrics")
        || path_lower.contains("/v1/traces")
        || path_lower.contains("/v1/events")
        || path_lower.contains("/ces/")
        || path_lower.contains("/g/collect")
        || path_lower.contains("/2/httpapi")
        || path_lower.ends_with("/capture")
        || path_lower.ends_with("/capture/")
        || path_lower.ends_with("/track")
        || path_lower.ends_with("/identify")
}

/// True when the URL path / RPC method represents a feature-flag or A/B experiment endpoint.
pub fn has_feature_flag_path(path: &str, host: Option<&str>) -> bool {
    let path_lower = path.to_ascii_lowercase();
    if is_inference_endpoint(&path_lower) {
        return false;
    }
    let words = tokenize_path_words(path);
    if words_contain(&words, FEATURE_FLAG_PATH_WORDS)
        || words_have_pair(
            &words,
            &["feature", "ab", "remote"],
            &["flag", "flags", "gate", "gates", "test", "config"],
        )
    {
        return true;
    }
    if path_lower.ends_with("/v1/initialize") || path_lower.contains("/v1/initialize?") {
        if let Some(h) = host.map(normalize_host) {
            return is_feature_flag_host(&h) || h.contains("anthropic") || h.contains("openai") || h.contains("cursor");
        }
    }
    false
}

/// True when the URL path / RPC method represents a crash, error, or diagnostic report endpoint.
pub fn has_crash_diagnostic_path(path: &str, host: Option<&str>) -> bool {
    let path_lower = path.to_ascii_lowercase();
    if is_inference_endpoint(&path_lower) {
        return false;
    }
    let words = tokenize_path_words(path);
    if words_contain(&words, CRASH_PATH_WORDS)
        || words_have_pair(
            &words,
            &["error", "exception", "bug", "issue"],
            &["report", "reports", "reporting", "log", "submit"],
        )
    {
        return true;
    }
    if (path_lower.contains("/envelope") || path_lower.contains("/store"))
        && host.is_some_and(|h| is_crash_diagnostic_host(&normalize_host(h)))
    {
        return true;
    }
    false
}

fn find_telemetry_headers(headers: &HeaderMap) -> Vec<String> {
    let mut hits = Vec::new();
    for name in headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        if (TELEMETRY_HEADER_EXACT.contains(&lower.as_str())
            || TELEMETRY_HEADER_PREFIXES.iter().any(|p| lower.starts_with(p)))
            && !hits.contains(&lower)
        {
            hits.push(lower);
        }
    }
    hits
}

/// Inspect an HTTP / HTTPS MITM / Protobuf request for telemetry, feature-flag, crash,
/// and bulk data upload signals.
#[allow(clippy::too_many_arguments)]
pub fn inspect_http_audit_signals(
    host: Option<&str>,
    path: &str,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    headers: Option<&HeaderMap>,
    raw_bytes: &[u8],
    body_text: Option<&str>,
    category: TrafficCategory,
    findings_count: usize,
) -> Vec<AuditSignal> {
    let mut signals = Vec::new();
    let path_lower = path.to_ascii_lowercase();
    let ct_lower = content_type.unwrap_or_default().to_ascii_lowercase();
    let host_norm = host.map(normalize_host);
    let host_risk = host_norm
        .as_deref()
        .map(classify_host_risk)
        .unwrap_or(HostRiskKind::General);
    let inference = is_inference_endpoint(&path_lower);

    let mut telemetry_hit = false;
    let mut bulk_hit = false;

    // 1. Crash / diagnostic reporting
    let host_crash = host_norm.as_deref().is_some_and(is_crash_diagnostic_host);
    let path_crash = has_crash_diagnostic_path(path, host_norm.as_deref());
    if host_crash || path_crash {
        telemetry_hit = true;
        let target = if host_crash {
            host_norm.as_deref().unwrap_or(path)
        } else {
            path
        };
        signals.push(AuditSignal {
            kind: AuditSignalKind::CrashDiagnostics,
            severity: AuditSeverity::Warn,
            detail: format!("Crash/diagnostic endpoint: {target}"),
        });
    }

    // 2. Feature flag / A/B experiment tracking
    let host_ff = host_norm.as_deref().is_some_and(is_feature_flag_host);
    let path_ff = has_feature_flag_path(path, host_norm.as_deref());
    if host_ff || path_ff {
        telemetry_hit = true;
        let target = if host_ff {
            host_norm.as_deref().unwrap_or(path)
        } else {
            path
        };
        signals.push(AuditSignal {
            kind: AuditSignalKind::FeatureFlagTracking,
            severity: AuditSeverity::Info,
            detail: format!("Feature flag / experiment endpoint: {target}"),
        });
    }

    // 3. Telemetry endpoint (host or URL path / camelCase RPC action)
    let path_tel = has_telemetry_path(path);
    if category == TrafficCategory::Telemetry
        || (host_risk == HostRiskKind::Telemetry && !host_crash && !host_ff)
        || path_tel
    {
        telemetry_hit = true;
        let target = if path_tel {
            path
        } else {
            host_norm.as_deref().unwrap_or(path)
        };
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryEndpoint,
            severity: AuditSeverity::Warn,
            detail: format!("Telemetry endpoint: {target}"),
        });
    }

    // 4. Telemetry SDK headers (on non-inference endpoints, or dedicated Sentry/Statsig/Datadog headers)
    if !inference {
        if let Some(hdrs) = headers {
            let tel_headers = find_telemetry_headers(hdrs);
            if !tel_headers.is_empty() {
                telemetry_hit = true;
                signals.push(AuditSignal {
                    kind: AuditSignalKind::TelemetryHeader,
                    severity: AuditSeverity::Warn,
                    detail: format!("Telemetry header(s): {}", tel_headers.join(", ")),
                });
            }
        }
    }

    // Prepare bounded lowercase sample for payload heuristics (zero cost on empty bodies).
    let scan_sample_owned: Option<String> = if !raw_bytes.is_empty() {
        if let Some(txt) = body_text {
            let mut end = txt.len().min(MAX_TEXT_SCAN_BYTES);
            while end > 0 && !txt.is_char_boundary(end) {
                end -= 1;
            }
            Some(txt[..end].to_ascii_lowercase())
        } else {
            let slice = &raw_bytes[..raw_bytes.len().min(MAX_TEXT_SCAN_BYTES)];
            Some(String::from_utf8_lossy(slice).to_ascii_lowercase())
        }
    } else {
        None
    };

    // 5. Telemetry payload markers on non-inference endpoints
    if !inference {
        if let Some(sample) = scan_sample_owned.as_deref() {
            let strong_hits = STRONG_TELEMETRY_PAYLOAD_MARKERS
                .iter()
                .filter(|m| sample.contains(**m))
                .count();
            let marker_hits = TELEMETRY_PAYLOAD_MARKERS
                .iter()
                .filter(|m| sample.contains(**m))
                .count();
            if strong_hits >= 1 || marker_hits >= 2 {
                telemetry_hit = true;
                let total = strong_hits + marker_hits;
                signals.push(AuditSignal {
                    kind: AuditSignalKind::TelemetryPayload,
                    severity: AuditSeverity::Warn,
                    detail: format!("Telemetry/device-fingerprint payload ({total} markers)"),
                });
            }
        }
    }

    // 6. Archive / multipart packaging upload
    let archive_ct = [
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/zstd",
        "application/x-7z-compressed",
        "application/vnd.rar",
    ]
    .iter()
    .find(|ct| ct_lower.contains(**ct))
    .copied();

    if let Some(ct) = archive_ct {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::High,
            detail: format!("Archive upload ({ct}, {})", format_bytes(raw_bytes.len() as u64)),
        });
    } else if let Some(magic) = has_archive_magic(raw_bytes, content_encoding) {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::High,
            detail: format!(
                "Packaged {magic} binary upload ({})",
                format_bytes(raw_bytes.len() as u64)
            ),
        });
    } else if ct_lower.contains("multipart/form-data") {
        let filename_count = scan_sample_owned
            .as_deref()
            .map(|s| s.matches("filename=").count())
            .unwrap_or(0);
        if filename_count >= 2 || raw_bytes.len() >= MULTIPART_LARGE_THRESHOLD {
            bulk_hit = true;
            signals.push(AuditSignal {
                kind: AuditSignalKind::ArchiveUpload,
                severity: AuditSeverity::Warn,
                detail: format!(
                    "Multipart file upload ({filename_count} file(s), {})",
                    format_bytes(raw_bytes.len() as u64)
                ),
            });
        }
    } else if ct_lower.contains("application/octet-stream") && raw_bytes.len() >= OCTET_STREAM_ARCHIVE_THRESHOLD {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::Warn,
            detail: format!("Binary octet-stream upload ({})", format_bytes(raw_bytes.len() as u64)),
        });
    }

    // 7. Bulk codebase / multi-file sync upload
    let path_bulk_hit = !inference && BULK_UPLOAD_PATH_KEYWORDS.iter().any(|k| path_lower.contains(k));
    let storage_upload = host_risk == HostRiskKind::UploadStorage && raw_bytes.len() >= 1024;
    let file_tree_markers = if !inference {
        scan_sample_owned
            .as_deref()
            .map(|s| {
                BULK_FILE_TREE_MARKERS
                    .iter()
                    .map(|m| s.matches(*m).count())
                    .sum::<usize>()
            })
            .unwrap_or(0)
    } else {
        0
    };
    let distinct_paths = if !inference {
        body_text
            .map(|t| {
                let mut end = t.len().min(MAX_TEXT_SCAN_BYTES);
                while end > 0 && !t.is_char_boundary(end) {
                    end -= 1;
                }
                count_distinct_local_paths(&t[..end])
            })
            .unwrap_or(0)
    } else {
        0
    };

    if category == TrafficCategory::CodebaseIndexing
        || storage_upload
        || (path_bulk_hit && raw_bytes.len() >= 1024)
        || file_tree_markers >= 5
        || distinct_paths >= 5
    {
        bulk_hit = true;
        let reason = if category == TrafficCategory::CodebaseIndexing {
            "Codebase indexing upload"
        } else if storage_upload {
            "Upload to object/repo storage"
        } else if distinct_paths >= 5 {
            "Multi-file workspace path batch upload"
        } else if file_tree_markers >= 5 {
            "Structured file-tree/chunk batch upload"
        } else {
            "Workspace/archive sync endpoint"
        };
        signals.push(AuditSignal {
            kind: AuditSignalKind::BulkCodebaseUpload,
            severity: AuditSeverity::Warn,
            detail: format!("{reason} ({})", format_bytes(raw_bytes.len() as u64)),
        });
    }

    // 8. Large outbound payload
    if (!inference && raw_bytes.len() >= LARGE_NON_INFERENCE_BYTES) || raw_bytes.len() >= LARGE_ANY_REQUEST_BYTES {
        signals.push(AuditSignal {
            kind: AuditSignalKind::LargeOutboundPayload,
            severity: AuditSeverity::Warn,
            detail: format!("Large outbound payload ({})", format_bytes(raw_bytes.len() as u64)),
        });
    }

    // 9. Sensitive data carried inside telemetry or bulk upload
    if findings_count > 0 && (telemetry_hit || bulk_hit) {
        signals.push(AuditSignal {
            kind: AuditSignalKind::SensitiveDataExfil,
            severity: AuditSeverity::High,
            detail: format!("{findings_count} sensitive item(s) detected in telemetry/upload payload"),
        });
    }

    signals
}

fn last_rpc_or_path_action(path: &str) -> &str {
    let without_query = path.split('?').next().unwrap_or(path);
    if let Some((_, rpc)) = without_query.rsplit_once(':') {
        if !rpc.is_empty() && !rpc.contains('/') {
            return rpc;
        }
    }
    without_query
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or(without_query)
}

/// Classify any HTTP / MITM / Protobuf / WebSocket request into its exact `RequestPurpose`
/// and a concise human-readable detail explaining why it matched.
#[allow(clippy::too_many_arguments)]
pub fn classify_request_purpose(
    method: &str,
    host: Option<&str>,
    path: &str,
    content_type: Option<&str>,
    body_text: Option<&str>,
    category: TrafficCategory,
    signals: &[AuditSignal],
) -> (RequestPurpose, String) {
    let path_lower = path.to_ascii_lowercase();
    let host_norm = host.map(normalize_host);
    let ct_lower = content_type.unwrap_or_default().to_ascii_lowercase();
    let words = tokenize_path_words(path);
    let action = last_rpc_or_path_action(path);

    // 1. WebSocket / explicit realtime transports
    if method.eq_ignore_ascii_case("WS") {
        return (
            RequestPurpose::RealtimeSync,
            format!("WebSocket channel ({})", host_norm.as_deref().unwrap_or(path)),
        );
    }

    // 2. Token counting (must precede generic inference check)
    if path_lower.contains("/count_tokens")
        || path_lower.contains(":counttokens")
        || path_lower.contains("/tokenize")
        || words_have_pair(&words, &["count"], &["token", "tokens"])
    {
        return (RequestPurpose::TokenCount, format!("Token count ({action})"));
    }

    // 3. Inline / Tab / FIM code completion
    if path_lower.contains("/fim/")
        || path_lower.contains("streamcpp")
        || path_lower.contains("cppservice")
        || path_lower.contains("inlinecompletion")
        || path_lower.contains("tab_completion")
        || path_lower.contains("autocomplete")
        || path_lower.contains("completecode")
        || words_have_pair(
            &words,
            &["inline", "tab", "fim"],
            &["completion", "completions", "complete", "predict"],
        )
    {
        return (
            RequestPurpose::InlineCompletion,
            format!("Inline code completion ({action})"),
        );
    }

    // 4. Model inference (Chat / Agent vs Tool execution result sync)
    let is_chat_rpc = is_inference_endpoint(&path_lower)
        || path_lower.contains("aiservice/streamchat")
        || path_lower.contains("streamunifiedchat")
        || path_lower.contains("chatservice/")
        || path_lower.contains(":generatecode");
    if is_chat_rpc {
        let has_tool_output = category == TrafficCategory::ToolExecutionSync
            || body_text.is_some_and(|b| {
                b.contains("\"tool_result\"")
                    || b.contains("\"function_call_output\"")
                    || b.contains("\"functionResponse\"")
                    || b.contains("\"role\":\"tool\"")
                    || b.contains("\"role\": \"tool\"")
            });
        if has_tool_output {
            return (
                RequestPurpose::ToolResultSync,
                format!("Tool execution result sync ({action})"),
            );
        }
        return (RequestPurpose::ChatInference, format!("Model inference ({action})"));
    }

    // 5. Crash / diagnostic reporting
    if signals.iter().any(|s| s.kind == AuditSignalKind::CrashDiagnostics)
        || host_norm.as_deref().is_some_and(is_crash_diagnostic_host)
        || has_crash_diagnostic_path(path, host_norm.as_deref())
    {
        let detail = signals
            .iter()
            .find(|s| s.kind == AuditSignalKind::CrashDiagnostics)
            .map(|s| s.detail.clone())
            .unwrap_or_else(|| format!("Crash/diagnostic report ({action})"));
        return (RequestPurpose::CrashReport, detail);
    }

    // 6. Feature flags / A/B experiments
    if signals.iter().any(|s| s.kind == AuditSignalKind::FeatureFlagTracking)
        || host_norm.as_deref().is_some_and(is_feature_flag_host)
        || has_feature_flag_path(path, host_norm.as_deref())
    {
        let detail = signals
            .iter()
            .find(|s| s.kind == AuditSignalKind::FeatureFlagTracking)
            .map(|s| s.detail.clone())
            .unwrap_or_else(|| format!("Feature flag / experiment ({action})"));
        return (RequestPurpose::FeatureFlags, detail);
    }

    // 7. Telemetry / analytics / metrics / event logging
    if category == TrafficCategory::Telemetry
        || signals.iter().any(|s| {
            matches!(
                s.kind,
                AuditSignalKind::TelemetryEndpoint
                    | AuditSignalKind::TelemetryPayload
                    | AuditSignalKind::TelemetryHeader
            )
        })
        || has_telemetry_path(path)
    {
        let detail = signals
            .iter()
            .find(|s| {
                matches!(
                    s.kind,
                    AuditSignalKind::TelemetryEndpoint
                        | AuditSignalKind::TelemetryHeader
                        | AuditSignalKind::TelemetryPayload
                )
            })
            .map(|s| s.detail.clone())
            .unwrap_or_else(|| format!("Telemetry reporting ({action})"));
        return (RequestPurpose::Telemetry, detail);
    }

    // 8. Codebase indexing / embeddings / Merkle sync (check before generic FileUpload for repo sync hosts)
    let is_indexing_path = category == TrafficCategory::CodebaseIndexing
        || words_contain(
            &words,
            &[
                "embeddings",
                "embedding",
                "merkle",
                "indexing",
                "codebase",
                "vector",
                "vectors",
                "repositoryservice",
                "reposervice",
            ],
        )
        || path_lower.contains("upload-chunks")
        || path_lower.contains("index-sync")
        || path_lower.contains("codebase_sync")
        || path_lower.contains("workspace/sync");
    if is_indexing_path {
        return (
            RequestPurpose::CodebaseIndexing,
            format!("Codebase indexing / embeddings ({action})"),
        );
    }

    // 9. Explicit file / archive / multipart upload
    let is_upload_path = path_lower.contains("/v1/files")
        || path_lower.contains("/v1/uploads")
        || path_lower.contains("/attachments")
        || words_contain(&words, &["upload", "uploads", "archive", "bundle"]);
    if signals.iter().any(|s| s.kind == AuditSignalKind::ArchiveUpload)
        || (is_upload_path && !method.eq_ignore_ascii_case("GET"))
        || ct_lower.contains("multipart/form-data")
        || (host_norm.as_deref().map(classify_host_risk) == Some(HostRiskKind::UploadStorage)
            && !method.eq_ignore_ascii_case("GET"))
    {
        let detail = signals
            .iter()
            .find(|s| s.kind == AuditSignalKind::ArchiveUpload)
            .map(|s| s.detail.clone())
            .unwrap_or_else(|| format!("File/archive upload ({action})"));
        return (RequestPurpose::FileUpload, detail);
    }
    if signals.iter().any(|s| s.kind == AuditSignalKind::BulkCodebaseUpload) {
        let detail = signals
            .iter()
            .find(|s| s.kind == AuditSignalKind::BulkCodebaseUpload)
            .map(|s| s.detail.clone())
            .unwrap_or_else(|| format!("Bulk workspace upload ({action})"));
        return (RequestPurpose::CodebaseIndexing, detail);
    }

    // 10. Realtime channel / session tunnel / heartbeat / health check
    if host_norm
        .as_deref()
        .is_some_and(|h| h == "jetski-webchannel.googleapis.com" || h.contains("webchannel."))
        || path_lower.contains("/v1/tunnels")
        || path_lower.contains("webchannel")
        || path_lower.contains("/realtime")
        || words_contain(
            &words,
            &[
                "tunnel",
                "tunnels",
                "channel",
                "channels",
                "subscribe",
                "heartbeat",
                "keepalive",
                "ping",
                "health",
                "healthz",
                "healthservice",
                "liveness",
                "readiness",
            ],
        )
    {
        return (
            RequestPurpose::RealtimeSync,
            format!("Realtime channel / keepalive ({action})"),
        );
    }

    // 11. Authentication / account / session / billing
    if host_norm
        .as_deref()
        .is_some_and(|h| classify_host_purpose(h) == RequestPurpose::AuthAccount)
        || words_contain(
            &words,
            &[
                "oauth",
                "oauth2",
                "login",
                "logout",
                "signin",
                "signout",
                "auth",
                "authservice",
                "userinfo",
                "whoami",
                "session",
                "sessions",
                "billing",
                "subscription",
                "subscriptions",
                "license",
                "entitlement",
                "entitlements",
                "credits",
                "verify",
            ],
        )
    {
        return (
            RequestPurpose::AuthAccount,
            format!("Auth / account / billing ({action})"),
        );
    }

    // 12. Model catalog / quota / client onboarding / settings
    if path_lower.contains("/v1/models")
        || path_lower.contains("loadcodeassist")
        || path_lower.contains("onboarduser")
        || path_lower.contains("fetchavailablemodels")
        || path_lower.contains("retrieveuserquota")
        || path_lower.contains("getuserstatus")
        || words_contain(
            &words,
            &[
                "models",
                "quota",
                "quotas",
                "capabilities",
                "onboard",
                "onboarding",
                "dashboardservice",
                "settings",
                "preferences",
                "config",
                "configuration",
            ],
        )
    {
        return (
            RequestPurpose::ModelCatalog,
            format!("Model catalog / quota / config ({action})"),
        );
    }

    // 13. Updates / releases / extensions marketplace
    if host_norm
        .as_deref()
        .is_some_and(|h| classify_host_purpose(h) == RequestPurpose::UpdateExtension)
        || words_contain(
            &words,
            &[
                "update",
                "updates",
                "upgrade",
                "releases",
                "release",
                "marketplace",
                "extensions",
                "extension",
                "plugins",
                "vsix",
                "changelog",
                "version",
            ],
        )
    {
        return (
            RequestPurpose::UpdateExtension,
            format!("Update / extension check ({action})"),
        );
    }

    // 14. Fallback: explicit non-inference API call
    let target = if !action.is_empty() && action != "/" {
        action
    } else {
        host_norm.as_deref().unwrap_or(path)
    };
    (
        RequestPurpose::OtherApi,
        format!("{} {}", method.to_uppercase(), target),
    )
}

/// Inspect a raw TCP passthrough `CONNECT` tunnel for telemetry, feature-flag, crash,
/// and bulk-upload risk signals.
pub fn inspect_connect_tunnel_audit(host: &str, bytes_sent: u64) -> Vec<AuditSignal> {
    let mut signals = Vec::new();
    let norm = normalize_host(host);
    let risk = classify_host_risk(&norm);
    let purpose = classify_host_purpose(&norm);
    let sent_label = if bytes_sent > 0 {
        format!(", sent {}", format_bytes(bytes_sent))
    } else {
        String::new()
    };

    if purpose == RequestPurpose::CrashReport {
        signals.push(AuditSignal {
            kind: AuditSignalKind::CrashDiagnostics,
            severity: AuditSeverity::Warn,
            detail: format!("Crash/diagnostic host tunnel ({norm}{sent_label})"),
        });
    } else if purpose == RequestPurpose::FeatureFlags {
        signals.push(AuditSignal {
            kind: AuditSignalKind::FeatureFlagTracking,
            severity: AuditSeverity::Info,
            detail: format!("Feature-flag/experiment host tunnel ({norm}{sent_label})"),
        });
    } else if risk == HostRiskKind::Telemetry {
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryEndpoint,
            severity: AuditSeverity::Warn,
            detail: format!("Telemetry host tunnel ({norm}{sent_label})"),
        });
    } else if risk == HostRiskKind::UploadStorage && bytes_sent >= PASSTHROUGH_UPLOAD_STORAGE_THRESHOLD {
        signals.push(AuditSignal {
            kind: AuditSignalKind::BulkCodebaseUpload,
            severity: AuditSeverity::Warn,
            detail: format!("Upload-storage tunnel ({norm}{sent_label})"),
        });
    }
    if bytes_sent >= PASSTHROUGH_LARGE_UPLOAD_THRESHOLD && risk != HostRiskKind::General {
        signals.push(AuditSignal {
            kind: AuditSignalKind::LargeOutboundPayload,
            severity: AuditSeverity::Warn,
            detail: format!("Large encrypted outbound transfer ({})", format_bytes(bytes_sent)),
        });
    }
    signals
}

pub fn has_telemetry_signal(signals: &[AuditSignal]) -> bool {
    signals.iter().any(|s| {
        matches!(
            s.kind,
            AuditSignalKind::TelemetryEndpoint
                | AuditSignalKind::TelemetryPayload
                | AuditSignalKind::TelemetryHeader
                | AuditSignalKind::FeatureFlagTracking
                | AuditSignalKind::CrashDiagnostics
        )
    })
}

pub fn has_bulk_upload_signal(signals: &[AuditSignal]) -> bool {
    signals.iter().any(|s| {
        matches!(
            s.kind,
            AuditSignalKind::ArchiveUpload
                | AuditSignalKind::BulkCodebaseUpload
                | AuditSignalKind::LargeOutboundPayload
        )
    })
}

pub fn has_sensitive_exfil_signal(signals: &[AuditSignal]) -> bool {
    signals
        .iter()
        .any(|s| matches!(s.kind, AuditSignalKind::SensitiveDataExfil))
}

/// Aggregate per-harness audit summaries across recorded traffic without cloning payload strings.
pub fn summarize_harness_audit<'a>(
    records: impl IntoIterator<Item = &'a crate::config::TrafficAuditRecord>,
) -> (u64, u64, Vec<HarnessAuditSummary>) {
    let mut total_telemetry = 0u64;
    let mut total_bulk = 0u64;

    struct Acc {
        total_requests: u64,
        telemetry_events: u64,
        bulk_upload_events: u64,
        sensitive_exfil_events: u64,
        outbound_bytes: u64,
        telemetry_hosts: BTreeSet<String>,
        upload_hosts: BTreeSet<String>,
        purpose_counts: BTreeMap<RequestPurpose, u64>,
    }

    let mut by_harness: BTreeMap<String, (HarnessKind, Acc)> = BTreeMap::new();

    for rec in records {
        let key = rec.harness.slug().to_string();
        let entry = by_harness.entry(key).or_insert_with(|| {
            (
                rec.harness,
                Acc {
                    total_requests: 0,
                    telemetry_events: 0,
                    bulk_upload_events: 0,
                    sensitive_exfil_events: 0,
                    outbound_bytes: 0,
                    telemetry_hosts: BTreeSet::new(),
                    upload_hosts: BTreeSet::new(),
                    purpose_counts: BTreeMap::new(),
                },
            )
        });
        entry.1.total_requests += 1;
        entry.1.outbound_bytes = entry.1.outbound_bytes.saturating_add(rec.request_bytes as u64);
        *entry.1.purpose_counts.entry(rec.purpose).or_insert(0) += 1;

        let is_tel = rec.category == TrafficCategory::Telemetry
            || rec.purpose.is_telemetry_like()
            || has_telemetry_signal(&rec.audit_signals);
        let is_bulk = rec.category == TrafficCategory::CodebaseIndexing
            || matches!(
                rec.purpose,
                RequestPurpose::CodebaseIndexing | RequestPurpose::FileUpload
            )
            || has_bulk_upload_signal(&rec.audit_signals);
        let is_exfil = has_sensitive_exfil_signal(&rec.audit_signals);

        let host_opt = extract_host_from_endpoint(&rec.endpoint);
        if is_tel {
            total_telemetry += 1;
            entry.1.telemetry_events += 1;
            if let Some(h) = &host_opt {
                entry.1.telemetry_hosts.insert(h.clone());
            }
        }
        if is_bulk {
            total_bulk += 1;
            entry.1.bulk_upload_events += 1;
            if let Some(h) = &host_opt {
                entry.1.upload_hosts.insert(h.clone());
            }
        }
        if is_exfil {
            entry.1.sensitive_exfil_events += 1;
        }
    }

    let mut list: Vec<HarnessAuditSummary> = by_harness
        .into_values()
        .map(|(harness, acc)| HarnessAuditSummary {
            harness,
            total_requests: acc.total_requests,
            telemetry_events: acc.telemetry_events,
            bulk_upload_events: acc.bulk_upload_events,
            sensitive_exfil_events: acc.sensitive_exfil_events,
            outbound_bytes: acc.outbound_bytes,
            telemetry_hosts: acc.telemetry_hosts.into_iter().take(8).collect(),
            upload_hosts: acc.upload_hosts.into_iter().take(8).collect(),
            purpose_counts: acc.purpose_counts,
        })
        .collect();
    list.sort_by_key(|item| {
        std::cmp::Reverse((
            item.sensitive_exfil_events,
            item.bulk_upload_events + item.telemetry_events,
            item.total_requests,
        ))
    });
    (total_telemetry, total_bulk, list)
}

fn extract_host_from_endpoint(endpoint: &str) -> Option<String> {
    let rest = endpoint.split_whitespace().last().unwrap_or(endpoint);
    if let Ok(url) = reqwest::Url::parse(rest) {
        return url.host_str().map(normalize_host);
    }
    if let Some((host, _port)) = rest.split_once(':') {
        let norm = normalize_host(host);
        if norm.contains('.') {
            return Some(norm);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_telemetry_feature_flag_crash_and_upload_hosts() {
        assert_eq!(classify_host_risk("play.googleapis.com"), HostRiskKind::Telemetry);
        assert_eq!(classify_host_purpose("play.googleapis.com"), RequestPurpose::Telemetry);

        assert_eq!(classify_host_risk("statsig.anthropic.com"), HostRiskKind::Telemetry);
        assert_eq!(
            classify_host_purpose("statsig.anthropic.com"),
            RequestPurpose::FeatureFlags
        );

        assert_eq!(classify_host_risk("ab.chatgpt.com"), HostRiskKind::Telemetry);
        assert_eq!(classify_host_purpose("ab.chatgpt.com"), RequestPurpose::FeatureFlags);

        assert_eq!(classify_host_risk("o12345.ingest.sentry.io"), HostRiskKind::Telemetry);
        assert_eq!(
            classify_host_purpose("o12345.ingest.sentry.io"),
            RequestPurpose::CrashReport
        );
        assert_eq!(
            classify_host_purpose("crashlyticsreports-pa.googleapis.com"),
            RequestPurpose::CrashReport
        );

        assert_eq!(classify_host_risk("arms-retcode.aliyuncs.com"), HostRiskKind::Telemetry);
        assert_eq!(classify_host_risk("events.launchdarkly.com"), HostRiskKind::Telemetry);
        assert_eq!(
            classify_host_purpose("jetski-webchannel.googleapis.com"),
            RequestPurpose::RealtimeSync
        );
        assert_eq!(classify_host_risk("repo42.cursor.sh"), HostRiskKind::UploadStorage);
        assert_eq!(
            classify_host_purpose("repo42.cursor.sh"),
            RequestPurpose::CodebaseIndexing
        );
        assert_eq!(
            classify_host_risk("my-bucket.s3.us-east-1.amazonaws.com"),
            HostRiskKind::UploadStorage
        );
        assert_eq!(
            classify_host_purpose("oauth2.googleapis.com"),
            RequestPurpose::AuthAccount
        );
        assert_eq!(classify_host_risk("github.com"), HostRiskKind::General);
    }

    #[test]
    fn detects_camelcase_rpc_telemetry_and_telemetry_headers() {
        let signals = inspect_http_audit_signals(
            Some("daily-cloudcode-pa.googleapis.com"),
            "/v1internal:recordCodeAssistMetrics",
            Some("application/json"),
            None,
            None,
            b"{}",
            Some("{}"),
            TrafficCategory::InteractivePrompt,
            0,
        );
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::TelemetryEndpoint));
        let (purpose, _) = classify_request_purpose(
            "POST",
            Some("daily-cloudcode-pa.googleapis.com"),
            "/v1internal:recordCodeAssistMetrics",
            Some("application/json"),
            Some("{}"),
            TrafficCategory::InteractivePrompt,
            &signals,
        );
        assert_eq!(purpose, RequestPurpose::Telemetry);

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-sentry-auth", "Sentry sentry_version=7".parse().unwrap());
        let hdr_signals = inspect_http_audit_signals(
            Some("custom-collector.example.com"),
            "/api/42/envelope/",
            Some("application/x-sentry-envelope"),
            None,
            Some(&hdrs),
            b"{}",
            Some("{}"),
            TrafficCategory::InteractivePrompt,
            0,
        );
        assert!(hdr_signals.iter().any(|s| s.kind == AuditSignalKind::TelemetryHeader));
    }

    #[test]
    fn classifies_exact_request_purposes_without_mislabeling_non_inference() {
        let cases = [
            (
                "GET",
                Some("api.openai.com"),
                "/v1/tunnels/tunnel_ext2_6adc",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::RealtimeSync,
            ),
            (
                "POST",
                Some("jetski-webchannel.googleapis.com"),
                "/webchannel/channel",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::RealtimeSync,
            ),
            (
                "POST",
                Some("daily-cloudcode-pa.googleapis.com"),
                "/v1internal:loadCodeAssist",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::ModelCatalog,
            ),
            (
                "POST",
                Some("daily-cloudcode-pa.googleapis.com"),
                "/v1internal:streamGenerateContent",
                Some(r#"{"request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}}"#),
                TrafficCategory::InteractivePrompt,
                RequestPurpose::ChatInference,
            ),
            (
                "POST",
                Some("daily-cloudcode-pa.googleapis.com"),
                "/v1internal:streamGenerateContent",
                Some(
                    r#"{"request":{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"read_file"}}]}]}}"#,
                ),
                TrafficCategory::ToolExecutionSync,
                RequestPurpose::ToolResultSync,
            ),
            (
                "POST",
                Some("api.anthropic.com"),
                "/v1/messages/count_tokens",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::TokenCount,
            ),
            (
                "POST",
                Some("api2.cursor.sh"),
                "/aiserver.v1.AiService/StreamCpp",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::InlineCompletion,
            ),
            (
                "POST",
                Some("api.anthropic.com"),
                "/api/event_logging/batch",
                None,
                TrafficCategory::Telemetry,
                RequestPurpose::Telemetry,
            ),
            (
                "GET",
                Some("api.openai.com"),
                "/v1/models",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::ModelCatalog,
            ),
            (
                "POST",
                Some("api.openai.com"),
                "/v1/files",
                None,
                TrafficCategory::InteractivePrompt,
                RequestPurpose::FileUpload,
            ),
        ];

        for (method, host, path, body, cat, expected) in cases {
            let signals = inspect_http_audit_signals(
                host,
                path,
                Some("application/json"),
                None,
                None,
                body.unwrap_or("").as_bytes(),
                body,
                cat,
                0,
            );
            let (purpose, _) =
                classify_request_purpose(method, host, path, Some("application/json"), body, cat, &signals);
            assert_eq!(purpose, expected, "failed for {method} {host:?} {path}");
        }
    }

    #[test]
    fn detects_archive_magic_and_sensitive_exfil_in_audit_mode() {
        let zip_payload = b"PK\x03\x04fake-zip-archive-bytes";
        let signals = inspect_http_audit_signals(
            Some("repo42.cursor.sh"),
            "/upload-chunks",
            Some("application/octet-stream"),
            None,
            None,
            zip_payload,
            None,
            TrafficCategory::CodebaseIndexing,
            2,
        );
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::ArchiveUpload));
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::BulkCodebaseUpload));
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::SensitiveDataExfil));
    }

    #[test]
    fn detects_telemetry_payload_without_false_positive_on_chat_inference() {
        let body = r#"{"machineId":"m1","osVersion":"win11","telemetry":true}"#;
        let chat_signals = inspect_http_audit_signals(
            Some("api.openai.com"),
            "/v1/chat/completions",
            Some("application/json"),
            None,
            None,
            body.as_bytes(),
            Some(body),
            TrafficCategory::InteractivePrompt,
            0,
        );
        assert!(chat_signals.is_empty());

        let tel_signals = inspect_http_audit_signals(
            Some("events.statsigapi.net"),
            "/v1/rgstr",
            Some("application/json"),
            None,
            None,
            body.as_bytes(),
            Some(body),
            TrafficCategory::Telemetry,
            1,
        );
        assert!(tel_signals.iter().any(|s| s.kind == AuditSignalKind::TelemetryEndpoint));
        assert!(tel_signals.iter().any(|s| s.kind == AuditSignalKind::TelemetryPayload));
        assert!(tel_signals
            .iter()
            .any(|s| s.kind == AuditSignalKind::SensitiveDataExfil));
    }

    #[test]
    fn detects_multi_file_workspace_batch_upload() {
        let body =
            r#"{"files":["C:\\work\\a.rs","C:\\work\\b.rs","C:\\work\\c.rs","C:\\work\\d.rs","C:\\work\\e.rs"]}"#;
        let signals = inspect_http_audit_signals(
            Some("api2.cursor.sh"),
            "/workspace/sync",
            Some("application/json"),
            None,
            None,
            body.as_bytes(),
            Some(body),
            TrafficCategory::InteractivePrompt,
            0,
        );
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::BulkCodebaseUpload));
    }
}
