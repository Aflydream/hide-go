//! Traffic audit engine backed by the on-device statistical `RequestClassifier`.
//!
//! Runs across every mode (including `audit-only`) to classify every outbound request
//! with calibrated Softmax confidence and emit structured audit signals for telemetry,
//! feature-flag tracking, crash diagnostics, archive/multipart packaging uploads,
//! codebase indexing batches, asymmetric bulk uploads, and sensitive data exfiltration.

use crate::classifier::{ClassificationInput, ClassificationResult, RequestClassifier};
use crate::config::{HarnessKind, TrafficCategory};
use crate::connect::is_builtin_ai_mitm_host;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const LARGE_NON_INFERENCE_BYTES: u64 = 256 * 1024;
const LARGE_ANY_REQUEST_BYTES: u64 = 1024 * 1024;
const OCTET_STREAM_ARCHIVE_THRESHOLD: u64 = 16 * 1024;
const MULTIPART_LARGE_THRESHOLD: u64 = 64 * 1024;
const PASSTHROUGH_UPLOAD_STORAGE_THRESHOLD: u64 = 64 * 1024;
const PASSTHROUGH_ASYMMETRIC_UPLOAD_THRESHOLD: u64 = 256 * 1024;
const PASSTHROUGH_LARGE_UPLOAD_THRESHOLD: u64 = 512 * 1024;

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
    ChatInference,
    ToolResultSync,
    InlineCompletion,
    TokenCount,
    CodebaseIndexing,
    FileUpload,
    Telemetry,
    FeatureFlags,
    CrashReport,
    ModelCatalog,
    AuthAccount,
    RealtimeSync,
    UpdateExtension,
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

/// Unified audit verdict returned by `analyze_http_request` from a single classifier pass.
#[derive(Debug, Clone)]
pub struct HttpAuditVerdict {
    pub purpose: RequestPurpose,
    pub confidence: f32,
    pub detail: String,
    pub signals: Vec<AuditSignal>,
    pub telemetry_prob: f32,
    pub bulk_upload_prob: f32,
    pub inference_prob: f32,
    pub audit_risk_score: f32,
}

/// Per-harness rollup surfaced in `GET /api/status`.
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

fn normalize_host(raw: &str) -> String {
    raw.trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
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

/// Classify a destination host's primary functional role using the statistical classifier.
pub fn classify_host_purpose(raw_host: &str) -> RequestPurpose {
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return RequestPurpose::OtherApi;
    }
    let res = RequestClassifier::classify_host_only(&host);
    if res.purpose == RequestPurpose::OtherApi && is_builtin_ai_mitm_host(&host) {
        return RequestPurpose::ChatInference;
    }
    res.purpose
}

/// Classify a destination host into telemetry, upload storage, AI API, or general traffic.
pub fn classify_host_risk(raw_host: &str) -> HostRiskKind {
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return HostRiskKind::General;
    }
    let res = RequestClassifier::classify_host_only(&host);
    if res.purpose.is_telemetry_like() && res.confidence >= 0.45 {
        return HostRiskKind::Telemetry;
    }
    if matches!(
        res.purpose,
        RequestPurpose::FileUpload | RequestPurpose::CodebaseIndexing
    ) && res.confidence >= 0.45
    {
        return HostRiskKind::UploadStorage;
    }
    if is_builtin_ai_mitm_host(&host) {
        return HostRiskKind::AiApi;
    }
    HostRiskKind::General
}

/// True when the URL path / RPC action classifies strongly as telemetry or metrics logging.
pub fn has_telemetry_path(path: &str) -> bool {
    let res = RequestClassifier::classify(&ClassificationInput {
        method: "POST",
        host: None,
        path,
        content_type: None,
        content_encoding: None,
        headers: None,
        raw_bytes: &[],
        body_text: None,
        bytes_sent_override: None,
        bytes_received_override: None,
        repeat_count: 0,
    });
    res.purpose == RequestPurpose::Telemetry && res.confidence >= 0.60
}

/// True when the URL path / host classifies as feature-flag or A/B experiment configuration.
pub fn has_feature_flag_path(path: &str, host: Option<&str>) -> bool {
    let res = RequestClassifier::classify(&ClassificationInput {
        method: "POST",
        host,
        path,
        content_type: None,
        content_encoding: None,
        headers: None,
        raw_bytes: &[],
        body_text: None,
        bytes_sent_override: None,
        bytes_received_override: None,
        repeat_count: 0,
    });
    res.purpose == RequestPurpose::FeatureFlags && res.confidence >= 0.55
}

/// True when the URL path / host classifies as crash or diagnostic error reporting.
pub fn has_crash_diagnostic_path(path: &str, host: Option<&str>) -> bool {
    let res = RequestClassifier::classify(&ClassificationInput {
        method: "POST",
        host,
        path,
        content_type: None,
        content_encoding: None,
        headers: None,
        raw_bytes: &[],
        body_text: None,
        bytes_sent_override: None,
        bytes_received_override: None,
        repeat_count: 0,
    });
    res.purpose == RequestPurpose::CrashReport && res.confidence >= 0.55
}

/// Single-pass statistical classification + structured audit signal extraction.
#[allow(clippy::too_many_arguments)]
pub fn analyze_http_request(
    method: &str,
    host: Option<&str>,
    path: &str,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    headers: Option<&HeaderMap>,
    raw_bytes: &[u8],
    body_text: Option<&str>,
    category: TrafficCategory,
    findings_count: usize,
    repeat_count: u32,
) -> HttpAuditVerdict {
    let cls = RequestClassifier::classify_with_findings(
        &ClassificationInput {
            method,
            host,
            path,
            content_type,
            content_encoding,
            headers,
            raw_bytes,
            body_text,
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count,
        },
        findings_count,
    );
    let signals = signals_from_classification(&cls, host, path, category, findings_count);
    HttpAuditVerdict {
        purpose: cls.purpose,
        confidence: cls.confidence,
        detail: cls.detail,
        signals,
        telemetry_prob: cls.telemetry_prob,
        bulk_upload_prob: cls.bulk_upload_prob,
        inference_prob: cls.inference_prob,
        audit_risk_score: cls.audit_risk_score,
    }
}

fn signals_from_classification(
    cls: &ClassificationResult,
    host: Option<&str>,
    path: &str,
    category: TrafficCategory,
    findings_count: usize,
) -> Vec<AuditSignal> {
    let mut signals = Vec::new();
    let f = &cls.features;
    let is_inference = cls.inference_prob >= 0.50;
    let target = host.filter(|h| !h.is_empty()).unwrap_or(path);

    let mut telemetry_hit = false;
    let mut bulk_hit = false;

    // 1. Crash / diagnostic reporting
    if cls.purpose == RequestPurpose::CrashReport && cls.confidence >= 0.45 {
        telemetry_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::CrashDiagnostics,
            severity: AuditSeverity::Warn,
            detail: format!("Crash/diagnostic traffic ({target}, {:.0}%)", cls.confidence * 100.0),
        });
    }

    // 2. Feature flag / experiment tracking
    if cls.purpose == RequestPurpose::FeatureFlags && cls.confidence >= 0.45 {
        telemetry_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::FeatureFlagTracking,
            severity: AuditSeverity::Info,
            detail: format!(
                "Feature-flag/experiment traffic ({target}, {:.0}%)",
                cls.confidence * 100.0
            ),
        });
    }

    // 3. Telemetry / analytics / metrics reporting (from trained model probability or explicit category)
    if (cls.purpose == RequestPurpose::Telemetry && cls.confidence >= 0.45)
        || (!is_inference && !telemetry_hit && cls.telemetry_prob >= 0.72)
        || (category == TrafficCategory::Telemetry && !is_inference && !telemetry_hit)
    {
        telemetry_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryEndpoint,
            severity: AuditSeverity::Warn,
            detail: format!(
                "Telemetry/analytics traffic ({path}, {:.0}%)",
                cls.telemetry_prob.max(cls.confidence) * 100.0
            ),
        });
    }

    // 4. Telemetry SDK header morphology
    if !is_inference && !f.telemetry_headers.is_empty() {
        telemetry_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryHeader,
            severity: AuditSeverity::Warn,
            detail: format!("Telemetry header(s): {}", f.telemetry_headers.join(", ")),
        });
    }

    // 5. Structural telemetry payload (OTel / event batch / device fingerprint) on non-inference requests
    if !is_inference && (f.otel_schema > 0.0 || f.event_batch_schema > 0.0 || f.device_fingerprint_score >= 0.6) {
        telemetry_hit = true;
        let kind_desc = if f.otel_schema > 0.0 {
            "OpenTelemetry trace/metric/log envelope"
        } else if f.event_batch_schema > 0.0 {
            "Structured telemetry event batch"
        } else {
            "Device/environment fingerprint payload"
        };
        signals.push(AuditSignal {
            kind: AuditSignalKind::TelemetryPayload,
            severity: AuditSeverity::Warn,
            detail: kind_desc.to_string(),
        });
    }

    // 6. Archive / multipart / high-entropy binary upload
    if let Some(ct) = f.archive_content_type {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::High,
            detail: format!("Archive upload ({ct}, {})", format_bytes(f.payload_bytes)),
        });
    } else if let Some(magic) = f.archive_magic {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::High,
            detail: format!("Packaged {magic} binary upload ({})", format_bytes(f.payload_bytes)),
        });
    } else if f.is_multipart && (f.multipart_file_count >= 2 || f.payload_bytes >= MULTIPART_LARGE_THRESHOLD) {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::Warn,
            detail: format!(
                "Multipart file upload ({} file(s), {})",
                f.multipart_file_count,
                format_bytes(f.payload_bytes)
            ),
        });
    } else if f.is_octet_stream && f.payload_bytes >= OCTET_STREAM_ARCHIVE_THRESHOLD {
        bulk_hit = true;
        signals.push(AuditSignal {
            kind: AuditSignalKind::ArchiveUpload,
            severity: AuditSeverity::Warn,
            detail: format!(
                "Binary octet-stream upload ({}, entropy {:.1} b/B)",
                format_bytes(f.payload_bytes),
                f.shannon_entropy
            ),
        });
    }

    // 7. Bulk codebase / multi-file sync upload
    if !is_inference
        && (category == TrafficCategory::CodebaseIndexing
            || cls.purpose == RequestPurpose::CodebaseIndexing
            || f.codebase_batch_schema > 0.0
            || f.distinct_local_paths >= 5)
    {
        bulk_hit = true;
        let reason = if f.codebase_batch_schema > 0.0 {
            "Structured file-tree/chunk batch upload"
        } else if f.distinct_local_paths >= 5 {
            "Multi-file workspace path batch upload"
        } else {
            "Codebase indexing / repository sync"
        };
        signals.push(AuditSignal {
            kind: AuditSignalKind::BulkCodebaseUpload,
            severity: AuditSeverity::Warn,
            detail: format!("{reason} ({})", format_bytes(f.payload_bytes)),
        });
    }

    // 8. Large outbound payload
    if (!is_inference && f.payload_bytes >= LARGE_NON_INFERENCE_BYTES) || f.payload_bytes >= LARGE_ANY_REQUEST_BYTES {
        signals.push(AuditSignal {
            kind: AuditSignalKind::LargeOutboundPayload,
            severity: AuditSeverity::Warn,
            detail: format!("Large outbound payload ({})", format_bytes(f.payload_bytes)),
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

/// Backward-compatible wrapper returning audit signals for an HTTP/MITM/Protobuf request.
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
    analyze_http_request(
        "POST",
        host,
        path,
        content_type,
        content_encoding,
        headers,
        raw_bytes,
        body_text,
        category,
        findings_count,
        0,
    )
    .signals
}

/// Backward-compatible wrapper returning `(RequestPurpose, detail)`.
#[allow(clippy::too_many_arguments)]
pub fn classify_request_purpose(
    method: &str,
    host: Option<&str>,
    path: &str,
    content_type: Option<&str>,
    body_text: Option<&str>,
    category: TrafficCategory,
    _signals: &[AuditSignal],
) -> (RequestPurpose, String) {
    let verdict = analyze_http_request(
        method,
        host,
        path,
        content_type,
        None,
        None,
        body_text.unwrap_or("").as_bytes(),
        body_text,
        category,
        0,
        0,
    );
    (verdict.purpose, verdict.detail)
}

/// Inspect a raw TCP passthrough `CONNECT` tunnel using host morphology + behavioral
/// upload-asymmetry detection (catches bulk uploads even to previously unseen hosts).
pub fn inspect_connect_tunnel_audit_with_recv(host: &str, bytes_sent: u64, bytes_received: u64) -> Vec<AuditSignal> {
    let mut signals = Vec::new();
    let norm = normalize_host(host);
    let cls = RequestClassifier::classify(&ClassificationInput {
        method: "CONNECT",
        host: Some(&norm),
        path: "",
        content_type: None,
        content_encoding: None,
        headers: None,
        raw_bytes: &[],
        body_text: None,
        bytes_sent_override: Some(bytes_sent),
        bytes_received_override: Some(bytes_received),
        repeat_count: 0,
    });
    let risk = classify_host_risk(&norm);
    let sent_label = if bytes_sent > 0 {
        format!(", sent {}", format_bytes(bytes_sent))
    } else {
        String::new()
    };

    if cls.purpose == RequestPurpose::CrashReport && cls.confidence >= 0.45 {
        signals.push(AuditSignal {
            kind: AuditSignalKind::CrashDiagnostics,
            severity: AuditSeverity::Warn,
            detail: format!("Crash/diagnostic host tunnel ({norm}{sent_label})"),
        });
    } else if cls.purpose == RequestPurpose::FeatureFlags && cls.confidence >= 0.45 {
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
    } else if bytes_sent >= PASSTHROUGH_ASYMMETRIC_UPLOAD_THRESHOLD
        && bytes_sent >= bytes_received.saturating_mul(8)
        && risk != HostRiskKind::AiApi
    {
        signals.push(AuditSignal {
            kind: AuditSignalKind::BulkCodebaseUpload,
            severity: AuditSeverity::Warn,
            detail: format!(
                "Asymmetric bulk encrypted upload ({norm}, sent {}, recv {})",
                format_bytes(bytes_sent),
                format_bytes(bytes_received)
            ),
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

/// Inspect a raw TCP passthrough `CONNECT` tunnel when only outbound bytes are supplied.
pub fn inspect_connect_tunnel_audit(host: &str, bytes_sent: u64) -> Vec<AuditSignal> {
    inspect_connect_tunnel_audit_with_recv(host, bytes_sent, bytes_sent)
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
    fn detects_asymmetric_bulk_upload_on_unseen_passthrough_host() {
        let signals = inspect_connect_tunnel_audit_with_recv("blobs.unseen-vendor.example", 600 * 1024, 4 * 1024);
        assert!(signals.iter().any(|s| s.kind == AuditSignalKind::BulkCodebaseUpload));

        let normal_download = inspect_connect_tunnel_audit_with_recv("github.com", 4 * 1024, 900 * 1024);
        assert!(normal_download.is_empty());
    }

    #[test]
    fn detects_camelcase_rpc_telemetry_and_telemetry_headers() {
        let verdict = analyze_http_request(
            "POST",
            Some("daily-cloudcode-pa.googleapis.com"),
            "/v1internal:recordCodeAssistMetrics",
            Some("application/json"),
            None,
            None,
            b"{}",
            Some("{}"),
            TrafficCategory::InteractivePrompt,
            0,
            0,
        );
        assert_eq!(verdict.purpose, RequestPurpose::Telemetry);
        assert!(verdict
            .signals
            .iter()
            .any(|s| s.kind == AuditSignalKind::TelemetryEndpoint));

        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-sentry-auth", "Sentry sentry_version=7".parse().unwrap());
        let hdr_verdict = analyze_http_request(
            "POST",
            Some("custom-collector.example.com"),
            "/api/42/envelope/",
            Some("application/x-sentry-envelope"),
            None,
            Some(&hdrs),
            b"{}",
            Some("{}"),
            TrafficCategory::InteractivePrompt,
            0,
            0,
        );
        assert_eq!(hdr_verdict.purpose, RequestPurpose::CrashReport);
        assert!(hdr_verdict
            .signals
            .iter()
            .any(|s| s.kind == AuditSignalKind::TelemetryHeader));
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
            let verdict = analyze_http_request(
                method,
                host,
                path,
                Some("application/json"),
                None,
                None,
                body.unwrap_or("").as_bytes(),
                body,
                cat,
                0,
                0,
            );
            assert_eq!(verdict.purpose, expected, "failed for {method} {host:?} {path}");
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
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"machineId osVersion telemetry"}]}"#;
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

        let tel_body = r#"{"machineId":"m1","osVersion":"win11","telemetry":true}"#;
        let tel_signals = inspect_http_audit_signals(
            Some("events.statsigapi.net"),
            "/v1/rgstr",
            Some("application/json"),
            None,
            None,
            tel_body.as_bytes(),
            Some(tel_body),
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
