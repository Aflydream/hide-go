//! Traffic audit heuristics for telemetry endpoints and bulk outbound data uploads.
//!
//! Runs across every mode (including `audit-only`) to flag silent telemetry beacons,
//! archive/multipart packaging uploads, codebase indexing syncs, oversized outbound
//! payloads, and sensitive values carried inside non-interactive uploads.

use crate::config::{HarnessKind, TrafficCategory};
use crate::connect::is_builtin_ai_mitm_host;
use crate::harness::is_inference_endpoint;
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

/// Individual audit finding attached to a `TrafficRecord`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSignalKind {
    TelemetryEndpoint,
    TelemetryPayload,
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

/// Per-harness rollup surfaced in `DashboardStats` so users can immediately see whether
/// each connected tool is sending telemetry or bulk-uploading workspace data.
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
}

const TELEMETRY_EXACT_OR_SUFFIX_HOSTS: &[&str] = &[
    "play.googleapis.com",
    "firebaselogging-pa.googleapis.com",
    "firebaselogging.googleapis.com",
    "clientmetrics-pa.googleapis.com",
    "crashlyticsreports-pa.googleapis.com",
    "app-measurement.com",
    "telemetry.anthropic.com",
    "statsig.anthropic.com",
    "statsigapi.net",
    "events.statsigapi.net",
    "featuregates.org",
    "api.segment.io",
    "cdn.segment.com",
    "api.amplitude.com",
    "api2.amplitude.com",
    "us.i.posthog.com",
    "eu.i.posthog.com",
    "app.posthog.com",
    "dc.services.visualstudio.com",
    "vortex.data.microsoft.com",
    "mobile.events.data.microsoft.com",
    "ab.chatgpt.com",
    "t.cursor.sh",
    "metrics.cursor.sh",
    "sentry.io",
    "ingest.sentry.io",
    "ingest.us.sentry.io",
    "ingest.de.sentry.io",
    "logs.datadoghq.com",
    "browser-intake-datadoghq.com",
    "http-intake.logs.datadoghq.com",
];

const TELEMETRY_HOST_PREFIXES: &[&str] = &[
    "telemetry.",
    "metrics.",
    "analytics.",
    "events.",
    "logging.",
    "crash.",
    "otlp.",
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

const TELEMETRY_PATH_SEGMENTS: &[&str] = &[
    "telemetry",
    "event_logging",
    "analytics",
    "metrics",
    "events",
    "traces",
    "logs",
    "rgstr",
    "logevent",
    "batch_log",
    "clientmetrics",
    "featuregates",
    "statsig",
    "clearcut",
];

const BULK_UPLOAD_PATH_KEYWORDS: &[&str] = &[
    "upload-chunks",
    "codebase_sync",
    "codebase",
    "merkle",
    "indexing",
    "index-sync",
    "repo-service",
    "uploadfiles",
    "upload_files",
    "synccodebase",
    "sync_codebase",
    "workspace_upload",
    "archive",
    "bundle",
];

const TELEMETRY_PAYLOAD_MARKERS: &[&str] = &[
    "\"machineid\"",
    "\"machine_id\"",
    "\"deviceid\"",
    "\"device_id\"",
    "\"clientmetrics\"",
    "\"client_metrics\"",
    "\"eventbatch\"",
    "\"event_batch\"",
    "\"logevent\"",
    "\"log_event\"",
    "\"osversion\"",
    "\"os_version\"",
    "\"telemetry\"",
    "\"statsig\"",
    "\"sentry\"",
    "\"anonymousid\"",
    "\"distinct_id\"",
    "\"appversion\"",
    "\"app_version\"",
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

/// Classify a destination host into telemetry, upload storage, AI API, or general traffic.
pub fn classify_host_risk(raw_host: &str) -> HostRiskKind {
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return HostRiskKind::General;
    }
    if TELEMETRY_EXACT_OR_SUFFIX_HOSTS
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

fn has_telemetry_path(path_lower: &str) -> bool {
    path_lower
        .split(['/', '?', ':', '.'])
        .filter(|s| !s.is_empty())
        .any(|seg| TELEMETRY_PATH_SEGMENTS.contains(&seg))
        || path_lower.contains("event_logging")
        || path_lower.contains("logevent")
        || path_lower.contains("telemetryservice")
        || path_lower.contains("recordtelemetry")
}

/// Inspect an HTTP / HTTPS MITM / Protobuf request for telemetry and bulk data upload signals.
#[allow(clippy::too_many_arguments)]
pub fn inspect_http_audit_signals(
    host: Option<&str>,
    path: &str,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
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

    // 1. Telemetry endpoint (host or URL path)
    if category == TrafficCategory::Telemetry || host_risk == HostRiskKind::Telemetry || has_telemetry_path(&path_lower)
    {
        telemetry_hit = true;
        let target = host_norm.as_deref().unwrap_or(path);
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryEndpoint,
            severity: AuditSeverity::Warn,
            detail: format!("Telemetry endpoint: {target}"),
        });
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

    // 2. Telemetry payload markers on non-inference endpoints
    if !inference {
        if let Some(sample) = scan_sample_owned.as_deref() {
            let marker_hits = TELEMETRY_PAYLOAD_MARKERS
                .iter()
                .filter(|m| sample.contains(**m))
                .count();
            if marker_hits >= 2 {
                telemetry_hit = true;
                signals.push(AuditSignal {
                    kind: AuditSignalKind::TelemetryPayload,
                    severity: AuditSeverity::Warn,
                    detail: format!("Telemetry/device-fingerprint payload ({marker_hits} markers)"),
                });
            }
        }
    }

    // 3. Archive / multipart packaging upload
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

    // 4. Bulk codebase / multi-file sync upload
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

    // 5. Large outbound payload
    if (!inference && raw_bytes.len() >= LARGE_NON_INFERENCE_BYTES) || raw_bytes.len() >= LARGE_ANY_REQUEST_BYTES {
        signals.push(AuditSignal {
            kind: AuditSignalKind::LargeOutboundPayload,
            severity: AuditSeverity::Warn,
            detail: format!("Large outbound payload ({})", format_bytes(raw_bytes.len() as u64)),
        });
    }

    // 6. Sensitive data carried inside telemetry or bulk upload
    if findings_count > 0 && (telemetry_hit || bulk_hit) {
        signals.push(AuditSignal {
            kind: AuditSignalKind::SensitiveDataExfil,
            severity: AuditSeverity::High,
            detail: format!("{findings_count} sensitive item(s) detected in telemetry/upload payload"),
        });
    }

    signals
}

/// Inspect a raw TCP passthrough `CONNECT` tunnel once its outbound byte count is known.
pub fn inspect_connect_tunnel_audit(host: &str, bytes_sent: u64) -> Vec<AuditSignal> {
    let mut signals = Vec::new();
    let risk = classify_host_risk(host);
    if risk == HostRiskKind::Telemetry {
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryEndpoint,
            severity: AuditSeverity::Warn,
            detail: format!("Telemetry host tunnel ({host}, sent {})", format_bytes(bytes_sent)),
        });
    } else if risk == HostRiskKind::UploadStorage && bytes_sent >= PASSTHROUGH_UPLOAD_STORAGE_THRESHOLD {
        signals.push(AuditSignal {
            kind: AuditSignalKind::BulkCodebaseUpload,
            severity: AuditSeverity::Warn,
            detail: format!("Upload-storage tunnel ({host}, sent {})", format_bytes(bytes_sent)),
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
            AuditSignalKind::TelemetryEndpoint | AuditSignalKind::TelemetryPayload
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

/// Aggregate per-harness audit summaries across recorded traffic.
pub fn summarize_harness_audit(records: &[crate::config::TrafficAuditRecord]) -> (u64, u64, Vec<HarnessAuditSummary>) {
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
                },
            )
        });
        entry.1.total_requests += 1;
        entry.1.outbound_bytes = entry.1.outbound_bytes.saturating_add(rec.request_bytes as u64);

        let is_tel = rec.category == TrafficCategory::Telemetry || has_telemetry_signal(&rec.audit_signals);
        let is_bulk = rec.category == TrafficCategory::CodebaseIndexing || has_bulk_upload_signal(&rec.audit_signals);
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
    fn classifies_telemetry_and_upload_storage_hosts() {
        assert_eq!(classify_host_risk("play.googleapis.com"), HostRiskKind::Telemetry);
        assert_eq!(
            classify_host_risk("firebaselogging-pa.googleapis.com"),
            HostRiskKind::Telemetry
        );
        assert_eq!(classify_host_risk("o12345.ingest.sentry.io"), HostRiskKind::Telemetry);
        assert_eq!(classify_host_risk("ab.chatgpt.com"), HostRiskKind::Telemetry);
        assert_eq!(classify_host_risk("telemetry.example.com"), HostRiskKind::Telemetry);
        assert_eq!(classify_host_risk("repo42.cursor.sh"), HostRiskKind::UploadStorage);
        assert_eq!(
            classify_host_risk("my-bucket.s3.us-east-1.amazonaws.com"),
            HostRiskKind::UploadStorage
        );
        assert_eq!(classify_host_risk("github.com"), HostRiskKind::General);
    }

    #[test]
    fn detects_archive_magic_and_sensitive_exfil_in_audit_mode() {
        let zip_payload = b"PK\x03\x04fake-zip-archive-bytes";
        let signals = inspect_http_audit_signals(
            Some("repo42.cursor.sh"),
            "/upload-chunks",
            Some("application/octet-stream"),
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
            body.as_bytes(),
            Some(body),
            TrafficCategory::InteractivePrompt,
            0,
        );
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::BulkCodebaseUpload));
    }
}
