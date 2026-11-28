//! Lightweight on-device statistical request classifier.
//!
//! Extracts continuous structural, lexical, header, entropy, and behavioral features from
//! each outbound HTTP, MITM, Protobuf, WebSocket, or `CONNECT` request and scores all 14
//! `RequestPurpose` classes with a multi-class linear model + temperature-scaled Softmax.
//! Runs in sub-millisecond time with zero external dependencies and generalizes to unseen
//! hosts and custom API endpoints without relying on brittle domain lists.

use crate::audit::RequestPurpose;
use crate::connect::is_builtin_ai_mitm_host;
use axum::http::HeaderMap;
use serde_json::Value;
use std::collections::BTreeSet;

const NUM_CLASSES: usize = 14;
const SOFTMAX_TEMPERATURE: f64 = 1.15;
const MAX_JSON_INSPECT_BYTES: usize = 64 * 1024;
const MAX_AST_PARSE_BYTES: usize = 128 * 1024;
const MAX_ENTROPY_SAMPLE_BYTES: usize = 16 * 1024;
const MAX_AST_NODES: usize = 1024;

pub const ALL_PURPOSES: [RequestPurpose; NUM_CLASSES] = [
    RequestPurpose::ChatInference,
    RequestPurpose::ToolResultSync,
    RequestPurpose::InlineCompletion,
    RequestPurpose::TokenCount,
    RequestPurpose::CodebaseIndexing,
    RequestPurpose::FileUpload,
    RequestPurpose::Telemetry,
    RequestPurpose::FeatureFlags,
    RequestPurpose::CrashReport,
    RequestPurpose::ModelCatalog,
    RequestPurpose::AuthAccount,
    RequestPurpose::RealtimeSync,
    RequestPurpose::UpdateExtension,
    RequestPurpose::OtherApi,
];

fn class_idx(p: RequestPurpose) -> usize {
    match p {
        RequestPurpose::ChatInference => 0,
        RequestPurpose::ToolResultSync => 1,
        RequestPurpose::InlineCompletion => 2,
        RequestPurpose::TokenCount => 3,
        RequestPurpose::CodebaseIndexing => 4,
        RequestPurpose::FileUpload => 5,
        RequestPurpose::Telemetry => 6,
        RequestPurpose::FeatureFlags => 7,
        RequestPurpose::CrashReport => 8,
        RequestPurpose::ModelCatalog => 9,
        RequestPurpose::AuthAccount => 10,
        RequestPurpose::RealtimeSync => 11,
        RequestPurpose::UpdateExtension => 12,
        RequestPurpose::OtherApi => 13,
    }
}

/// Input view passed to `RequestClassifier::classify`.
pub struct ClassificationInput<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub content_type: Option<&'a str>,
    pub content_encoding: Option<&'a str>,
    pub headers: Option<&'a HeaderMap>,
    pub raw_bytes: &'a [u8],
    pub body_text: Option<&'a str>,
    pub bytes_sent_override: Option<u64>,
    pub bytes_received_override: Option<u64>,
    pub repeat_count: u32,
}

/// Extracted continuous, structural, statistical, and morphological features.
#[derive(Debug, Default, Clone)]
pub struct ExtractedFeatures {
    pub payload_bytes: u64,
    pub shannon_entropy: f32,
    pub printable_ratio: f32,
    pub archive_magic: Option<&'static str>,
    pub archive_content_type: Option<&'static str>,
    pub is_multipart: bool,
    pub multipart_file_count: usize,
    pub is_octet_stream: bool,
    pub is_protobuf: bool,
    pub is_sse_expected: bool,
    pub is_websocket: bool,
    pub is_connect_tunnel: bool,
    pub is_webchannel_query: bool,
    pub upload_asymmetry: f32,
    pub distinct_local_paths: usize,
    pub telemetry_headers: Vec<String>,
    // JSON AST structural scores (0.0 ..= 1.0+)
    pub json_parsed: bool,
    pub conversation_schema: f32,
    pub llm_params_schema: f32,
    pub tool_result_schema: f32,
    pub fim_schema: f32,
    pub event_batch_schema: f32,
    pub device_fingerprint_score: f32,
    pub otel_schema: f32,
    pub feature_flag_schema: f32,
    pub crash_schema: f32,
    pub codebase_batch_schema: f32,
    pub auth_schema: f32,
    pub catalog_schema: f32,
}

/// Output of `RequestClassifier::classify` with calibrated Softmax probabilities.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub purpose: RequestPurpose,
    pub confidence: f32,
    pub telemetry_prob: f32,
    pub bulk_upload_prob: f32,
    pub inference_prob: f32,
    pub detail: String,
    pub features: ExtractedFeatures,
}

/// Lightweight multi-class statistical classifier for outbound harness traffic.
pub struct RequestClassifier;

impl RequestClassifier {
    /// Classify a full HTTP / MITM / Protobuf / WebSocket / `CONNECT` request.
    pub fn classify(input: &ClassificationInput<'_>) -> ClassificationResult {
        let features = extract_features(input);
        let mut logits = [0.0f64; NUM_CLASSES];
        // Slight prior toward OtherApi when zero informative features fire.
        logits[class_idx(RequestPurpose::OtherApi)] = 0.65;

        let mut reasons: Vec<(usize, f64, &'static str)> = Vec::with_capacity(16);
        let mut add = |p: RequestPurpose, weight: f64, tag: &'static str| {
            let idx = class_idx(p);
            logits[idx] += weight;
            if weight > 0.35 && !tag.is_empty() {
                reasons.push((idx, weight, tag));
            }
        };

        // 1. Structural JSON AST signals (highest authority: generalizes across any host/URL)
        if features.conversation_schema > 0.0 {
            let w = 4.6 * features.conversation_schema as f64;
            add(RequestPurpose::ChatInference, w, "conversation schema");
            if features.tool_result_schema > 0.0 {
                let tw = w + 3.4 * features.tool_result_schema as f64;
                add(RequestPurpose::ToolResultSync, tw, "tool result payload");
            }
            // Strong negative coupling: a real chat conversation is not telemetry.
            add(
                RequestPurpose::Telemetry,
                -3.2 * features.conversation_schema as f64,
                "",
            );
            add(
                RequestPurpose::CrashReport,
                -2.4 * features.conversation_schema as f64,
                "",
            );
            add(
                RequestPurpose::FeatureFlags,
                -2.4 * features.conversation_schema as f64,
                "",
            );
        }
        if features.llm_params_schema > 0.0 {
            let w = 2.4 * features.llm_params_schema as f64;
            add(RequestPurpose::ChatInference, w, "model inference parameters");
            if features.tool_result_schema > 0.0 {
                add(RequestPurpose::ToolResultSync, w * 0.9, "");
            }
            if features.fim_schema > 0.0 {
                add(RequestPurpose::InlineCompletion, w * 0.9, "");
            }
        }
        if features.fim_schema > 0.0 {
            add(
                RequestPurpose::InlineCompletion,
                4.8 * features.fim_schema as f64,
                "FIM/cursor completion schema",
            );
        }
        if features.otel_schema > 0.0 {
            add(
                RequestPurpose::Telemetry,
                6.8 * features.otel_schema as f64,
                "OpenTelemetry envelope",
            );
        }
        if features.event_batch_schema > 0.0 {
            add(
                RequestPurpose::Telemetry,
                3.9 * features.event_batch_schema as f64,
                "structured event batch",
            );
        }
        if features.device_fingerprint_score > 0.0 {
            let w = 2.8 * features.device_fingerprint_score as f64;
            add(RequestPurpose::Telemetry, w, "device/env fingerprint fields");
            add(RequestPurpose::FeatureFlags, w * 0.45, "");
            add(RequestPurpose::CrashReport, w * 0.45, "");
        }
        if features.feature_flag_schema > 0.0 {
            add(
                RequestPurpose::FeatureFlags,
                4.6 * features.feature_flag_schema as f64,
                "feature-flag/experiment payload",
            );
        }
        if features.crash_schema > 0.0 {
            add(
                RequestPurpose::CrashReport,
                5.0 * features.crash_schema as f64,
                "crash/stacktrace payload",
            );
        }
        if features.codebase_batch_schema > 0.0 {
            add(
                RequestPurpose::CodebaseIndexing,
                4.8 * features.codebase_batch_schema as f64,
                "multi-file/chunk index batch",
            );
        }
        if features.auth_schema > 0.0 {
            add(
                RequestPurpose::AuthAccount,
                4.4 * features.auth_schema as f64,
                "OAuth/session payload",
            );
        }
        if features.catalog_schema > 0.0 && features.conversation_schema == 0.0 {
            add(
                RequestPurpose::ModelCatalog,
                3.2 * features.catalog_schema as f64,
                "quota/catalog payload",
            );
        }

        // 2. Payload byte statistics, entropy & archive signatures
        if features.archive_magic.is_some() || features.archive_content_type.is_some() {
            add(RequestPurpose::FileUpload, 5.2, "compressed archive payload");
            add(RequestPurpose::CodebaseIndexing, 1.8, "");
        }
        if features.is_multipart {
            let w = if features.multipart_file_count >= 2 { 4.8 } else { 3.6 };
            add(RequestPurpose::FileUpload, w, "multipart file upload");
        }
        if features.is_octet_stream && features.payload_bytes >= 16 * 1024 {
            add(RequestPurpose::FileUpload, 3.4, "binary octet-stream upload");
            if features.shannon_entropy >= 7.2 {
                add(RequestPurpose::FileUpload, 1.4, "high-entropy binary stream");
            }
        }
        if features.distinct_local_paths >= 5 && features.conversation_schema == 0.0 {
            add(RequestPurpose::CodebaseIndexing, 3.8, "multi-file workspace path batch");
        }
        if features.upload_asymmetry >= 0.7
            && features.payload_bytes >= 256 * 1024
            && features.conversation_schema == 0.0
        {
            add(RequestPurpose::FileUpload, 2.2, "asymmetric bulk upload");
            add(RequestPurpose::CodebaseIndexing, 1.8, "");
        }

        // 3. Transport, method & header morphology features
        if features.is_websocket {
            add(RequestPurpose::RealtimeSync, 6.2, "WebSocket transport");
        }
        if features.is_webchannel_query {
            add(RequestPurpose::RealtimeSync, 4.6, "WebChannel transport params");
        }
        if features.is_sse_expected && features.conversation_schema > 0.0 {
            add(RequestPurpose::ChatInference, 1.4, "streaming inference");
            if features.tool_result_schema > 0.0 {
                add(RequestPurpose::ToolResultSync, 1.4, "");
            }
        }
        if !features.telemetry_headers.is_empty() && features.conversation_schema == 0.0 {
            let has_sentry = features.telemetry_headers.iter().any(|h| h.contains("sentry"));
            let has_statsig = features
                .telemetry_headers
                .iter()
                .any(|h| h.contains("statsig") || h.contains("launchdarkly"));
            if has_sentry {
                add(RequestPurpose::CrashReport, 4.4, "crash SDK header");
            } else if has_statsig {
                add(RequestPurpose::FeatureFlags, 4.2, "feature-flag SDK header");
            } else {
                add(RequestPurpose::Telemetry, 4.2, "telemetry SDK header");
            }
        }
        if input.method.eq_ignore_ascii_case("GET") && features.payload_bytes == 0 {
            add(RequestPurpose::ChatInference, -2.2, "");
            add(RequestPurpose::ToolResultSync, -2.5, "");
            add(RequestPurpose::FileUpload, -2.2, "");
            add(RequestPurpose::CodebaseIndexing, -1.2, "");
        }
        if input.repeat_count >= 4
            && features.payload_bytes > 0
            && features.payload_bytes <= 16 * 1024
            && features.conversation_schema == 0.0
        {
            add(RequestPurpose::Telemetry, 0.8, "periodic beacon cadence");
            add(RequestPurpose::RealtimeSync, 0.7, "");
        }

        // 4. Morphological lexical token scoring over host labels and camelCase path tokens
        if let Some(host) = input.host {
            score_host_morphology(host, &mut logits, &mut reasons);
        }
        if !input.path.is_empty() && input.path != "/" {
            score_path_morphology(input.path, input.method, &mut logits, &mut reasons);
        }

        // Tool-result turns and FIM completions travel over the same inference endpoints; let them
        // inherit endpoint inference evidence so they aren't drowned out by generic chat path scores.
        if features.tool_result_schema > 0.0 {
            let chat_idx = class_idx(RequestPurpose::ChatInference);
            let tool_idx = class_idx(RequestPurpose::ToolResultSync);
            if logits[chat_idx] > 0.0 {
                logits[tool_idx] = logits[tool_idx].max(logits[chat_idx] + 3.2 * features.tool_result_schema as f64);
            }
        }
        if features.fim_schema > 0.0 {
            let chat_idx = class_idx(RequestPurpose::ChatInference);
            let fim_idx = class_idx(RequestPurpose::InlineCompletion);
            if logits[chat_idx] > 0.0 {
                logits[fim_idx] = logits[fim_idx].max(logits[chat_idx] + 2.6 * features.fim_schema as f64);
            }
        }

        // 5. Softmax calibration
        let max_logit = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let mut exp_scores = [0.0f64; NUM_CLASSES];
        let mut sum_exp = 0.0f64;
        for i in 0..NUM_CLASSES {
            let e = ((logits[i] - max_logit) / SOFTMAX_TEMPERATURE).exp();
            exp_scores[i] = e;
            sum_exp += e;
        }
        let mut probs = [0.0f64; NUM_CLASSES];
        for i in 0..NUM_CLASSES {
            probs[i] = if sum_exp > 0.0 { exp_scores[i] / sum_exp } else { 0.0 };
        }

        let (best_idx, &best_prob) = probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .unwrap_or((class_idx(RequestPurpose::OtherApi), &1.0));
        let purpose = ALL_PURPOSES[best_idx];

        let telemetry_prob = (probs[class_idx(RequestPurpose::Telemetry)]
            + probs[class_idx(RequestPurpose::FeatureFlags)]
            + probs[class_idx(RequestPurpose::CrashReport)]) as f32;
        let bulk_upload_prob =
            (probs[class_idx(RequestPurpose::CodebaseIndexing)] + probs[class_idx(RequestPurpose::FileUpload)]) as f32;
        let inference_prob = (probs[class_idx(RequestPurpose::ChatInference)]
            + probs[class_idx(RequestPurpose::ToolResultSync)]
            + probs[class_idx(RequestPurpose::InlineCompletion)]) as f32;

        // Build concise human-readable feature explanation from top contributors to the winning class.
        let mut win_reasons: Vec<(f64, &'static str)> = reasons
            .into_iter()
            .filter(|(idx, _, _)| *idx == best_idx)
            .map(|(_, w, tag)| (w, tag))
            .collect();
        win_reasons.sort_by(|a, b| b.0.total_cmp(&a.0));
        let mut top_tags: Vec<&str> = Vec::new();
        for (_, tag) in win_reasons {
            if !top_tags.contains(&tag) {
                top_tags.push(tag);
                if top_tags.len() >= 2 {
                    break;
                }
            }
        }
        let action = last_action_segment(input.path);
        let pct = (best_prob * 100.0).round() as u32;
        let detail = if !top_tags.is_empty() {
            if !action.is_empty() && action != "/" && !features.is_connect_tunnel {
                format!("{} ({action}, {pct}%)", top_tags.join(" + "))
            } else if let Some(h) = input.host.filter(|h| !h.is_empty()) {
                format!("{} ({h}, {pct}%)", top_tags.join(" + "))
            } else {
                format!("{} ({pct}%)", top_tags.join(" + "))
            }
        } else {
            let target = if !action.is_empty() && action != "/" {
                action
            } else {
                input.host.unwrap_or(input.path)
            };
            format!("{} {target} ({pct}%)", input.method.to_uppercase())
        };

        ClassificationResult {
            purpose,
            confidence: best_prob as f32,
            telemetry_prob,
            bulk_upload_prob,
            inference_prob,
            detail,
            features,
        }
    }

    /// Lightweight host-only classification for `CONNECT` authority metadata.
    pub fn classify_host_only(host: &str) -> ClassificationResult {
        Self::classify(&ClassificationInput {
            method: "CONNECT",
            host: Some(host),
            path: "",
            content_type: None,
            content_encoding: None,
            headers: None,
            raw_bytes: &[],
            body_text: None,
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 0,
        })
    }
}

/// Compute Shannon entropy in bits per byte (`0.0..=8.0`) over a bounded prefix.
pub fn shannon_entropy_bits(bytes: &[u8]) -> f32 {
    let sample = &bytes[..bytes.len().min(MAX_ENTROPY_SAMPLE_BYTES)];
    if sample.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let len = sample.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy as f32
}

/// Compute printable UTF-8/ASCII ratio (`0.0..=1.0`) over a bounded prefix.
pub fn printable_byte_ratio(bytes: &[u8]) -> f32 {
    let sample = &bytes[..bytes.len().min(MAX_ENTROPY_SAMPLE_BYTES)];
    if sample.is_empty() {
        return 1.0;
    }
    let printable = sample
        .iter()
        .filter(|&&b| matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) || b >= 0x80)
        .count();
    printable as f32 / sample.len() as f32
}

/// Split a path, host, or camelCase/PascalCase RPC identifier into lowercase tokens.
pub fn tokenize_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut prev_lower_or_digit = false;
    let mut prev_upper = false;

    let mut iter = input.chars().peekable();
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

fn detect_archive_magic(raw: &[u8], content_encoding: Option<&str>) -> Option<&'static str> {
    if raw.len() >= 4 && &raw[..4] == b"PK\x03\x04" {
        return Some("ZIP");
    }
    if raw.len() >= 4 && raw[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Some("ZSTD");
    }
    if raw.len() >= 263 && &raw[257..262] == b"ustar" {
        return Some("TAR");
    }
    let ce_gzip = content_encoding.is_some_and(|v| v.to_ascii_lowercase().contains("gzip"));
    if !ce_gzip && raw.len() >= 2 && raw[0] == 0x1F && raw[1] == 0x8B {
        return Some("GZIP");
    }
    None
}

fn detect_archive_ct(ct_lower: &str) -> Option<&'static str> {
    [
        "application/zip",
        "application/x-tar",
        "application/gzip",
        "application/x-gzip",
        "application/zstd",
        "application/x-7z-compressed",
        "application/vnd.rar",
    ]
    .into_iter()
    .find(|&ct| ct_lower.contains(ct))
}

fn extract_telemetry_headers(headers: &HeaderMap) -> Vec<String> {
    let mut hits = Vec::new();
    for name in headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        let is_sdk_tel = lower.contains("telemetry")
            || lower.contains("sentry")
            || lower.contains("statsig")
            || lower.contains("datadog")
            || lower.starts_with("dd-")
            || lower.contains("otlp")
            || lower.contains("honeycomb")
            || lower.contains("posthog")
            || lower.contains("mixpanel")
            || lower.contains("amplitude")
            || lower.contains("launchdarkly")
            || lower.contains("segment-anonymous")
            || (lower.starts_with("x-") && (lower.ends_with("-device-id") || lower.ends_with("-machine-id")));
        if is_sdk_tel && !hits.contains(&lower) {
            hits.push(lower);
        }
    }
    hits
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
            if seen.len() >= 6 {
                break;
            }
        }
    }
    seen.len()
}

fn extract_features(input: &ClassificationInput<'_>) -> ExtractedFeatures {
    let mut f = ExtractedFeatures {
        payload_bytes: input.bytes_sent_override.unwrap_or(input.raw_bytes.len() as u64),
        shannon_entropy: shannon_entropy_bits(input.raw_bytes),
        printable_ratio: printable_byte_ratio(input.raw_bytes),
        archive_magic: detect_archive_magic(input.raw_bytes, input.content_encoding),
        is_websocket: input.method.eq_ignore_ascii_case("WS"),
        is_connect_tunnel: input.method.eq_ignore_ascii_case("CONNECT"),
        ..Default::default()
    };

    if let (Some(sent), Some(recv)) = (input.bytes_sent_override, input.bytes_received_override) {
        let total = sent.saturating_add(recv);
        if total > 0 {
            f.upload_asymmetry = sent as f32 / total as f32;
        }
    }

    let ct_lower = input.content_type.unwrap_or_default().to_ascii_lowercase();
    f.archive_content_type = detect_archive_ct(&ct_lower);
    f.is_multipart = ct_lower.contains("multipart/form-data");
    f.is_octet_stream = ct_lower.contains("application/octet-stream");
    f.is_protobuf = ct_lower.contains("protobuf") || ct_lower.contains("grpc") || ct_lower.contains("connect+");

    if let Some(hdrs) = input.headers {
        f.telemetry_headers = extract_telemetry_headers(hdrs);
        if hdrs
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"))
        {
            f.is_sse_expected = true;
        }
    }
    let path_lower = input.path.to_ascii_lowercase();
    if path_lower.contains("alt=sse") || path_lower.contains("stream") {
        f.is_sse_expected = true;
    }
    if (path_lower.contains("ver=") && (path_lower.contains("rid=") || path_lower.contains("aid=")))
        || path_lower.contains("webchannel")
    {
        f.is_webchannel_query = true;
    }

    // Bounded text sample for multipart / local path / JSON AST extraction.
    let sample_text: Option<&str> = input.body_text.or_else(|| {
        if !input.raw_bytes.is_empty() && f.printable_ratio > 0.85 {
            std::str::from_utf8(input.raw_bytes).ok()
        } else {
            None
        }
    });

    if let Some(txt) = sample_text {
        let mut end = txt.len().min(MAX_JSON_INSPECT_BYTES);
        while end > 0 && !txt.is_char_boundary(end) {
            end -= 1;
        }
        let slice = &txt[..end];
        if f.is_multipart {
            f.multipart_file_count = slice.to_ascii_lowercase().matches("filename=").count();
        }
        f.distinct_local_paths = count_distinct_local_paths(slice);

        // Parse full JSON AST only up to 128 KB; for huge multi-turn coding payloads, inspect bounded
        // head + tail slices in O(1) time without allocating a multi-megabyte serde_json::Value tree.
        let trimmed = txt.trim();
        if trimmed.starts_with(['{', '[']) && trimmed.len() <= MAX_AST_PARSE_BYTES {
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                f.json_parsed = true;
                extract_json_ast_features(&val, &mut f);
            }
        }
        if !f.json_parsed && !slice.is_empty() {
            let mut head_end = txt.len().min(24 * 1024);
            while head_end > 0 && !txt.is_char_boundary(head_end) {
                head_end -= 1;
            }
            extract_text_structural_fallback(&txt[..head_end], &mut f);
            if txt.len() > head_end {
                let mut tail_start = txt.len().saturating_sub(24 * 1024).max(head_end);
                while tail_start < txt.len() && !txt.is_char_boundary(tail_start) {
                    tail_start += 1;
                }
                if tail_start < txt.len() {
                    extract_text_structural_fallback(&txt[tail_start..], &mut f);
                }
            }
        }
    }

    f
}

/// Walk the parsed JSON AST once to compute structural features across all schemas.
fn extract_json_ast_features(root: &Value, f: &mut ExtractedFeatures) {
    let mut visited = 0usize;
    let mut fingerprint_hits = 0u32;
    let mut event_array_score = 0.0f32;
    let mut file_array_score = 0.0f32;
    let mut ff_hits = 0u32;
    let mut crash_hits = 0u32;
    let mut auth_hits = 0u32;
    let mut catalog_hits = 0u32;

    let mut stack: Vec<(&Value, usize)> = vec![(root, 0)];
    while let Some((node, depth)) = stack.pop() {
        visited += 1;
        if visited > MAX_AST_NODES || depth > 8 {
            break;
        }
        match node {
            Value::Object(map) => {
                // Check conversation containers (`messages`, `contents`, `input`)
                if let Some(Value::Array(msgs)) = map.get("messages").or_else(|| map.get("contents")) {
                    if !msgs.is_empty() {
                        let role_like = msgs
                            .iter()
                            .take(8)
                            .filter(|m| {
                                m.as_object().is_some_and(|o| {
                                    o.contains_key("role") && (o.contains_key("content") || o.contains_key("parts"))
                                })
                            })
                            .count();
                        if role_like > 0 {
                            f.conversation_schema = (f.conversation_schema + 0.85).min(1.2);
                        }
                    }
                    // Detect tool execution outputs inside conversation messages
                    for msg in msgs.iter().rev().take(6) {
                        if contains_tool_result_frame(msg, 0) {
                            f.tool_result_schema = 1.0;
                            break;
                        }
                    }
                }
                if let Some(input_val) = map.get("input") {
                    if map.contains_key("model") || map.contains_key("instructions") {
                        match input_val {
                            Value::String(s) if !s.is_empty() => {
                                f.conversation_schema = (f.conversation_schema + 0.7).min(1.2);
                            }
                            Value::Array(items) if !items.is_empty() => {
                                f.conversation_schema = (f.conversation_schema + 0.85).min(1.2);
                                if items.iter().rev().take(6).any(|it| contains_tool_result_frame(it, 0)) {
                                    f.tool_result_schema = 1.0;
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // FIM / Inline completion schema
                if (map.contains_key("prefix") && map.contains_key("suffix"))
                    || map.contains_key("cursorPosition")
                    || map.contains_key("cursor_position")
                    || map.contains_key("currentFile")
                {
                    f.fim_schema = 1.0;
                }

                // LLM generation parameters
                let mut llm_p = 0u32;
                for k in [
                    "model",
                    "max_tokens",
                    "maxOutputTokens",
                    "temperature",
                    "top_p",
                    "topP",
                    "tools",
                    "functionDeclarations",
                    "systemInstruction",
                    "generationConfig",
                    "thinkingConfig",
                ] {
                    if map.contains_key(k) {
                        llm_p += 1;
                    }
                }
                if map.get("stream").and_then(Value::as_bool) == Some(true) {
                    f.is_sse_expected = true;
                    llm_p += 1;
                }
                if llm_p >= 2 {
                    f.llm_params_schema = (llm_p as f32 / 4.0).min(1.0);
                }

                // Key-level structural indicators (only top few levels to avoid user prose inside nested strings)
                if depth <= 3 {
                    for (k, v) in map {
                        let kl = k.to_ascii_lowercase();
                        // OTel protocol envelope
                        if matches!(
                            kl.as_str(),
                            "resourcespans"
                                | "resourcemetrics"
                                | "resourcelogs"
                                | "scopespans"
                                | "scopemetrics"
                                | "logsource"
                                | "sourceextension"
                        ) {
                            f.otel_schema = 1.0;
                        }
                        // Device / client telemetry fingerprint fields
                        if matches!(
                            kl.as_str(),
                            "machineid"
                                | "machine_id"
                                | "deviceid"
                                | "device_id"
                                | "osversion"
                                | "os_version"
                                | "appversion"
                                | "app_version"
                                | "anonymousid"
                                | "anonymous_id"
                                | "distinct_id"
                                | "distinctid"
                                | "clientmetrics"
                                | "client_metrics"
                                | "eventbatch"
                                | "event_batch"
                                | "logevent"
                                | "log_event"
                                | "telemetry"
                                | "requesttimems"
                                | "sessionduration"
                                | "clientinfo"
                        ) {
                            fingerprint_hits += 1;
                        }
                        // Feature flags / experiments
                        if matches!(
                            kl.as_str(),
                            "statsigmetadata"
                                | "statsig"
                                | "exposures"
                                | "featuregates"
                                | "feature_gates"
                                | "featureflags"
                                | "feature_flags"
                                | "dynamicconfigs"
                                | "experiments"
                                | "gate_value"
                        ) {
                            ff_hits += 1;
                        }
                        // Crash / exception diagnostics
                        if matches!(
                            kl.as_str(),
                            "stacktrace"
                                | "stack_trace"
                                | "exception"
                                | "breadcrumbs"
                                | "crashreport"
                                | "crash_report"
                                | "minidump"
                                | "sentry"
                        ) {
                            crash_hits += 1;
                        }
                        // Auth / OAuth
                        if matches!(
                            kl.as_str(),
                            "grant_type"
                                | "refresh_token"
                                | "client_id"
                                | "id_token"
                                | "code_verifier"
                                | "redirect_uri"
                        ) {
                            auth_hits += 1;
                        }
                        // Model catalog / quota / onboarding
                        if matches!(
                            kl.as_str(),
                            "cloudaicompanionproject" | "tierid" | "quota" | "availablemodels" | "clientmetadata"
                        ) {
                            catalog_hits += 1;
                        }

                        // Homogeneous array analysis: event batches vs file/chunk upload batches
                        if let Value::Array(arr) = v {
                            if !arr.is_empty() {
                                if matches!(
                                    kl.as_str(),
                                    "events" | "batch" | "logs" | "metrics" | "spans" | "log_event" | "logevent"
                                ) && arr.iter().take(4).all(Value::is_object)
                                {
                                    event_array_score = (event_array_score + 0.9).min(1.2);
                                }
                                if matches!(
                                    kl.as_str(),
                                    "files" | "chunks" | "documents" | "blobs" | "nodes" | "entries"
                                ) {
                                    let file_objs = arr
                                        .iter()
                                        .take(8)
                                        .filter(|item| {
                                            item.as_object().is_some_and(|o| {
                                                o.contains_key("path")
                                                    || o.contains_key("relativePath")
                                                    || o.contains_key("relative_path")
                                                    || o.contains_key("filePath")
                                                    || o.contains_key("file_path")
                                                    || o.contains_key("merkle")
                                                    || o.contains_key("contents")
                                                    || o.contains_key("file_contents")
                                            })
                                        })
                                        .count();
                                    if file_objs > 0 {
                                        file_array_score = (file_array_score + 0.9).min(1.2);
                                    }
                                }
                            }
                        }
                        if matches!(
                            kl.as_str(),
                            "merkle" | "roothash" | "root_hash" | "embedding" | "embeddings"
                        ) {
                            file_array_score = (file_array_score + 0.7).min(1.2);
                        }

                        // Only recurse into shallow structural envelopes (never deep user tool schemas)
                        if depth < 3
                            && !matches!(
                                kl.as_str(),
                                "tools" | "functions" | "functiondeclarations" | "systeminstruction"
                            )
                            && (v.is_object() || v.is_array())
                        {
                            stack.push((v, depth + 1));
                        }
                    }
                }
            }
            Value::Array(items) if depth < 2 => {
                // Top-level array of event objects or file objects
                let event_like = items
                    .iter()
                    .take(6)
                    .filter(|it| {
                        it.as_object().is_some_and(|o| {
                            (o.contains_key("event") || o.contains_key("eventName") || o.contains_key("event_name"))
                                && (o.contains_key("timestamp") || o.contains_key("time") || o.contains_key("ts"))
                        })
                    })
                    .count();
                if event_like >= 1 {
                    event_array_score = (event_array_score + 0.9).min(1.2);
                }
                for item in items.iter().take(4) {
                    if item.is_object() {
                        stack.push((item, depth + 1));
                    }
                }
            }
            _ => {}
        }
    }

    f.event_batch_schema = event_array_score;
    f.codebase_batch_schema = file_array_score;
    if fingerprint_hits >= 2 {
        f.device_fingerprint_score = (fingerprint_hits as f32 / 3.0).min(1.2);
    } else if fingerprint_hits == 1 && (event_array_score > 0.0 || f.otel_schema > 0.0) {
        f.device_fingerprint_score = 0.6;
    }
    if ff_hits >= 1 {
        f.feature_flag_schema = (ff_hits as f32 / 2.0).min(1.0);
    }
    if crash_hits >= 2 {
        f.crash_schema = (crash_hits as f32 / 3.0).min(1.0);
    }
    if auth_hits >= 2 {
        f.auth_schema = (auth_hits as f32 / 2.5).min(1.0);
    }
    if catalog_hits >= 1 {
        f.catalog_schema = (catalog_hits as f32 / 2.0).min(1.0);
    }
}

fn contains_tool_result_frame(val: &Value, depth: usize) -> bool {
    if depth > 4 {
        return false;
    }
    match val {
        Value::Object(map) => {
            if map.get("role").and_then(Value::as_str) == Some("tool") {
                return true;
            }
            if matches!(
                map.get("type").and_then(Value::as_str),
                Some("tool_result" | "function_call_output")
            ) {
                return true;
            }
            if map.contains_key("functionResponse") || map.contains_key("function_response") {
                return true;
            }
            if let Some(c) = map.get("content").or_else(|| map.get("parts")) {
                return contains_tool_result_frame(c, depth + 1);
            }
            false
        }
        Value::Array(arr) => arr.iter().take(12).any(|v| contains_tool_result_frame(v, depth + 1)),
        _ => false,
    }
}

fn extract_text_structural_fallback(slice: &str, f: &mut ExtractedFeatures) {
    let lower = slice.to_ascii_lowercase();
    if lower.contains("\"messages\"") || lower.contains("\"contents\"") {
        f.conversation_schema = f.conversation_schema.max(0.85);
    }
    if lower.contains("\"max_tokens\"")
        || lower.contains("\"temperature\"")
        || lower.contains("\"generationconfig\"")
        || lower.contains("\"systeminstruction\"")
    {
        f.llm_params_schema = f.llm_params_schema.max(0.7);
    }
    if lower.contains("\"tool_result\"")
        || lower.contains("\"function_call_output\"")
        || lower.contains("\"functionresponse\"")
        || lower.contains("\"role\":\"tool\"")
        || lower.contains("\"role\": \"tool\"")
    {
        f.tool_result_schema = f.tool_result_schema.max(0.95);
    }
    if lower.contains("resourcespans") || lower.contains("resourcemetrics") || lower.contains("resourcelogs") {
        f.otel_schema = f.otel_schema.max(0.95);
    }
    let fp = [
        "machineid",
        "machine_id",
        "deviceid",
        "device_id",
        "osversion",
        "os_version",
        "clientmetrics",
        "eventbatch",
        "anonymousid",
        "distinct_id",
    ]
    .iter()
    .filter(|m| lower.contains(**m))
    .count();
    if fp >= 2 {
        f.device_fingerprint_score = f.device_fingerprint_score.max((fp as f32 / 3.0).min(1.0));
    }
    let files = [
        "relativepath",
        "relative_path",
        "file_contents",
        "filecontents",
        "merkle",
    ]
    .iter()
    .filter(|m| lower.contains(**m))
    .count();
    if files >= 3 {
        f.codebase_batch_schema = f.codebase_batch_schema.max(0.85);
    }
}

/// Score morphological tokens extracted from destination hostname labels.
fn score_host_morphology(
    raw_host: &str,
    logits: &mut [f64; NUM_CLASSES],
    reasons: &mut Vec<(usize, f64, &'static str)>,
) {
    let host = raw_host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return;
    }
    let mut bump = |p: RequestPurpose, w: f64, tag: &'static str| {
        let idx = class_idx(p);
        logits[idx] += w;
        if w > 0.35 && !tag.is_empty() {
            reasons.push((idx, w, tag));
        }
    };

    let labels: Vec<&str> = host.split('.').collect();
    let first = labels.first().copied().unwrap_or("");
    let tokens = tokenize_words(&host);

    // Host label morphology (generalizes across arbitrary subdomains like `telemetry.newvendor.io`)
    for tok in &tokens {
        match tok.as_str() {
            "telemetry"
            | "metrics"
            | "clientmetrics"
            | "analytics"
            | "firebaselogging"
            | "logging"
            | "otlp"
            | "otel"
            | "datadoghq"
            | "posthog"
            | "segment"
            | "amplitude"
            | "mixpanel"
            | "honeycomb"
            | "newrelic"
            | "applicationinsights"
            | "vortex"
            | "mmstat"
            | "retcode"
            | "umeng"
            | "rudderstack"
            | "snowplowanalytics"
            | "heapanalytics"
            | "fullstory"
            | "pendo"
            | "clarity"
            | "plausible"
            | "measurement"
            | "beacon"
            | "cloudtrace"
            | "monitoring" => {
                bump(RequestPurpose::Telemetry, 4.4, "telemetry host morphology");
            }
            "statsig" | "statsigapi" | "featuregates" | "launchdarkly" | "growthbook" | "optimizely" => {
                bump(RequestPurpose::FeatureFlags, 4.8, "feature-flag host morphology");
            }
            "sentry"
            | "crash"
            | "crashlytics"
            | "crashlyticsreports"
            | "bugsnag"
            | "rollbar"
            | "backtrace"
            | "raygun"
            | "clouderrorreporting"
            | "livediagnostics" => {
                bump(RequestPurpose::CrashReport, 4.8, "crash/diagnostic host morphology");
            }
            "webchannel" | "realtime" | "ws" | "wss" | "socket" => {
                bump(RequestPurpose::RealtimeSync, 4.4, "realtime channel host");
            }
            "oauth" | "oauth2" | "auth" | "auth0" | "login" | "accounts" | "sso" => {
                bump(RequestPurpose::AuthAccount, 4.2, "auth/account host");
            }
            "update" | "updates" | "releases" | "marketplace" | "downloads" | "vsx" => {
                bump(RequestPurpose::UpdateExtension, 4.0, "update/marketplace host");
            }
            "upload" | "uploads" | "storage" | "blob" | "s3" | "cloudflarestorage" => {
                bump(RequestPurpose::FileUpload, 3.6, "object-storage host");
            }
            "repo" | "repo1" | "repo42" => {
                bump(RequestPurpose::CodebaseIndexing, 4.2, "code-sync host");
            }
            _ => {}
        }
    }

    // Specific multi-label morphological patterns
    if first == "ab" && host.contains("chatgpt") {
        bump(RequestPurpose::FeatureFlags, 4.8, "A/B experiment host");
    }
    if first == "play" && host.ends_with(".googleapis.com") {
        bump(RequestPurpose::Telemetry, 4.6, "Clearcut telemetry host");
    }
    if (first == "t" || first == "events")
        && (host.ends_with(".cursor.sh") || host.ends_with(".x.ai") || host.contains("microsoft.com"))
    {
        bump(RequestPurpose::Telemetry, 4.4, "event-collector host");
    }
    if first == "dc" && host.ends_with(".visualstudio.com") {
        bump(RequestPurpose::Telemetry, 4.4, "IDE telemetry host");
    }
    if (first == "events" || first == "logs" || first == "traces" || first == "collector") && labels.len() >= 3 {
        bump(RequestPurpose::Telemetry, 2.8, "event/log collector subdomain");
    }
    if host.contains("split.io") {
        bump(RequestPurpose::FeatureFlags, 4.6, "feature-flag host morphology");
    }
    if is_builtin_ai_mitm_host(&host) && !host.contains("webchannel") && !host.starts_with("repo") {
        // Gentle prior for AI API hosts; path & AST features override easily for non-chat endpoints.
        bump(RequestPurpose::ChatInference, 0.7, "");
    }
}

/// Score morphological tokens extracted from URL path and RPC action names.
fn score_path_morphology(
    path: &str,
    method: &str,
    logits: &mut [f64; NUM_CLASSES],
    reasons: &mut Vec<(usize, f64, &'static str)>,
) {
    let path_only = path.split('?').next().unwrap_or(path);
    let path_lower = path_only.to_ascii_lowercase();
    let words = tokenize_words(path_only);

    let mut bump = |p: RequestPurpose, w: f64, tag: &'static str| {
        let idx = class_idx(p);
        logits[idx] += w;
        if w > 0.35 && !tag.is_empty() {
            reasons.push((idx, w, tag));
        }
    };

    let has = |w: &str| words.iter().any(|t| t == w);

    // Token counting
    if path_lower.contains("count_tokens")
        || path_lower.contains("counttokens")
        || has("tokenize")
        || (has("count") && (has("token") || has("tokens")))
    {
        bump(RequestPurpose::TokenCount, 5.8, "token-count endpoint");
        bump(RequestPurpose::ChatInference, -2.5, "");
        return;
    }

    // Inline / FIM / Tab code completion
    if path_lower.contains("/fim/")
        || path_lower.contains("streamcpp")
        || path_lower.contains("cppservice")
        || path_lower.contains("inlinecompletion")
        || path_lower.contains("autocomplete")
        || path_lower.contains("completecode")
        || ((has("inline") || has("tab") || has("fim")) && (has("completion") || has("completions") || has("complete")))
    {
        bump(RequestPurpose::InlineCompletion, 5.4, "inline-completion endpoint");
        return;
    }

    // Model inference RPC / REST paths
    if path_lower.contains("/v1/messages")
        || path_lower.contains("/chat/completions")
        || path_lower.contains("/v1/completions")
        || path_lower.contains("/v1/responses")
        || path_lower.contains(":generatecontent")
        || path_lower.contains(":streamgeneratecontent")
        || path_lower.contains("/v1/complete")
        || path_lower.contains("streamunifiedchat")
        || path_lower.contains("aiservice/streamchat")
        || path_lower.contains("chatservice/")
    {
        bump(RequestPurpose::ChatInference, 4.4, "inference endpoint");
        return;
    }

    // Lexical feature weights across all non-inference paths & camelCase RPC actions
    for tok in &words {
        match tok.as_str() {
            "telemetry" | "analytics" | "metrics" | "metric" | "traces" | "otlp" | "otel" | "rgstr" | "clearcut"
            | "beacon" | "beacons" | "logevent" | "logevents" | "batchlog" | "clientmetrics" | "capture"
            | "collect" | "track" | "identify" | "ces" => {
                bump(RequestPurpose::Telemetry, 4.4, "telemetry path/RPC token");
            }
            "statsig" | "featuregates" | "featuregate" | "featureflags" | "featureflag" | "experiments"
            | "experiment" | "abtest" | "remoteconfig" | "launchdarkly" => {
                bump(RequestPurpose::FeatureFlags, 4.8, "feature-flag path token");
            }
            "crash" | "crashes" | "crashlytics" | "minidump" | "sentry" | "bugsnag" | "rollbar" | "feedback"
            | "bugreport" | "diagnostic" | "diagnostics" | "errorreporting" | "errorreport" => {
                bump(RequestPurpose::CrashReport, 4.8, "crash/diagnostic path token");
            }
            "embeddings" | "embedding" | "merkle" | "indexing" | "codebase" | "vector" | "vectors"
            | "repositoryservice" | "reposervice" | "chunks" => {
                bump(RequestPurpose::CodebaseIndexing, 4.6, "codebase-indexing path token");
            }
            "files" | "uploads" | "upload" | "attachments" | "archive" | "bundle" => {
                if !method.eq_ignore_ascii_case("GET") {
                    bump(RequestPurpose::FileUpload, 4.0, "file-upload path token");
                }
            }
            "tunnel" | "tunnels" | "webchannel" | "realtime" | "channel" | "channels" | "subscribe" | "heartbeat"
            | "keepalive" | "ping" | "health" | "healthz" | "healthservice" | "liveness" | "readiness" => {
                bump(RequestPurpose::RealtimeSync, 4.6, "realtime/tunnel path token");
            }
            "oauth" | "oauth2" | "login" | "logout" | "signin" | "signout" | "auth" | "authservice" | "userinfo"
            | "whoami" | "billing" | "subscription" | "subscriptions" | "license" | "entitlement" | "entitlements"
            | "credits" | "verify" => {
                bump(RequestPurpose::AuthAccount, 4.4, "auth/account path token");
            }
            "models" | "quota" | "quotas" | "capabilities" | "onboard" | "onboarding" | "loadcodeassist"
            | "dashboardservice" | "preferences" | "settings" => {
                bump(RequestPurpose::ModelCatalog, 4.2, "catalog/quota path token");
            }
            "update" | "updates" | "upgrade" | "releases" | "release" | "marketplace" | "extensions" | "extension"
            | "plugins" | "vsix" | "changelog" => {
                bump(RequestPurpose::UpdateExtension, 4.2, "update/extension path token");
            }
            _ => {}
        }
    }

    // Compositional two-word RPC verb + noun combinations (catches camelCase actions like
    // `recordCodeAssistMetrics`, `logCodeAssistEvent`, `fetchAvailableModels`, `retrieveUserQuota`,
    // `loadCodeAssist`, `checkFeatureFlag`, `reportError`, `syncWorkspace`)
    if (has("event") || has("events") || has("log") || has("logs") || has("logging") || has("usage") || has("stats"))
        && (has("log")
            || has("logs")
            || has("logging")
            || has("batch")
            || has("record")
            || has("report")
            || has("submit")
            || has("send")
            || has("ingest"))
    {
        bump(RequestPurpose::Telemetry, 4.4, "event-logging RPC verb");
    }
    if (has("feature") || has("ab") || has("remote"))
        && (has("flag") || has("flags") || has("gate") || has("gates") || has("test") || has("config"))
    {
        bump(RequestPurpose::FeatureFlags, 4.6, "feature-gate RPC verb");
    }
    if (has("error") || has("exception") || has("bug") || has("issue"))
        && (has("report") || has("reports") || has("reporting") || has("submit") || has("log"))
    {
        bump(RequestPurpose::CrashReport, 4.6, "error-report RPC verb");
    }
    if (has("code") && has("assist") && (has("load") || has("onboard") || has("status")))
        || (has("user") && (has("status") || has("quota")))
        || (has("available") && has("models"))
    {
        bump(RequestPurpose::ModelCatalog, 4.5, "client catalog/quota RPC");
    }
    if (has("workspace") || has("repo") || has("index")) && (has("sync") || has("upload")) {
        bump(RequestPurpose::CodebaseIndexing, 4.4, "workspace sync RPC");
    }
    if path_lower.ends_with("/v1/initialize") && logits[class_idx(RequestPurpose::FeatureFlags)] > 0.0 {
        let idx = class_idx(RequestPurpose::FeatureFlags);
        logits[idx] += 2.2;
        reasons.push((idx, 2.2, "feature-flag init"));
    }
    if path_lower.contains("/envelope") && logits[class_idx(RequestPurpose::CrashReport)] > 0.0 {
        let idx = class_idx(RequestPurpose::CrashReport);
        logits[idx] += 2.2;
        reasons.push((idx, 2.2, "crash envelope"));
    }
}

fn last_action_segment(path: &str) -> &str {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalizes_to_unseen_hosts_via_json_ast_and_statistics() {
        // Brand-new unseen domain sending structured event telemetry batch
        let tel_body = r#"{"events":[{"event":"session_tick","ts":1732200000,"os_version":"win11","device_id":"d-99","app_version":"1.2.3"}]}"#;
        let res = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("pulse.acme-unseen.io"),
            path: "/v2/ingest",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: tel_body.as_bytes(),
            body_text: Some(tel_body),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 5,
        });
        assert_eq!(res.purpose, RequestPurpose::Telemetry);
        assert!(res.confidence > 0.85, "confidence={}", res.confidence);
        assert!(res.telemetry_prob > 0.90);

        // Brand-new unseen domain hosting OpenAI-compatible chat inference
        let chat_body = r#"{"model":"qwen3-coder","stream":true,"temperature":0.2,"messages":[{"role":"user","content":"explain telemetry and machine_id"}]}"#;
        let chat = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("llm-gateway.unseen-corp.dev"),
            path: "/custom/infer",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: chat_body.as_bytes(),
            body_text: Some(chat_body),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(chat.purpose, RequestPurpose::ChatInference);
        assert!(chat.confidence > 0.90, "chat confidence={}", chat.confidence);
        assert!(
            chat.telemetry_prob < 0.05,
            "chat telemetry_prob={}",
            chat.telemetry_prob
        );

        // Brand-new unseen domain receiving multi-file workspace batch
        let batch_body = r#"{"merkle":"abc123","files":[{"relative_path":"src/a.rs","contents":"fn a(){}"},{"relative_path":"src/b.rs","contents":"fn b(){}"}]}"#;
        let batch = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("sync.unseen-ide.dev"),
            path: "/api/push",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: batch_body.as_bytes(),
            body_text: Some(batch_body),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(batch.purpose, RequestPurpose::CodebaseIndexing);
        assert!(batch.bulk_upload_prob > 0.80);
    }

    #[test]
    fn detects_unseen_otel_and_header_telemetry_and_fim_completions() {
        let otel_body = r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"tool.exec"}]}]}]}"#;
        let otel = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("collector.internal-vendor.net"),
            path: "/api/submit",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: otel_body.as_bytes(),
            body_text: Some(otel_body),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(otel.purpose, RequestPurpose::Telemetry);
        assert!(otel.confidence > 0.90);

        let fim_body =
            r#"{"model":"codestral","prefix":"fn add(a: i32, b: i32) -> i32 {","suffix":"}","max_tokens":128}"#;
        let fim = RequestClassifier::classify(&ClassificationInput {
            method: "POST",
            host: Some("api.custom-ai.dev"),
            path: "/complete",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            raw_bytes: fim_body.as_bytes(),
            body_text: Some(fim_body),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        assert_eq!(fim.purpose, RequestPurpose::InlineCompletion);
        assert!(fim.confidence > 0.80);
    }

    #[test]
    fn shannon_entropy_separates_text_from_compressed_binary() {
        let text = b"{\"hello\":\"world\",\"status\":\"ok\",\"count\":42}";
        let mut pseudo_random = [0u8; 256];
        for (i, b) in pseudo_random.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert!(shannon_entropy_bits(text) < 5.0);
        assert!(shannon_entropy_bits(&pseudo_random) > 7.9);
    }
}
