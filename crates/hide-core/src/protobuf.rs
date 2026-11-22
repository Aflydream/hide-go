//! Schema-less Protobuf, gRPC, and ConnectRPC wire-format desensitization and streaming restoration.
//!
//! Enables live outbound desensitization and inbound restoration for AI clients communicating
//! over binary Protobuf (`application/proto`, `application/protobuf`, `application/x-protobuf`),
//! gRPC / gRPC-Web (`application/grpc*`), and ConnectRPC (`application/connect+proto`,
//! `application/connect+json`) without requiring `.proto` descriptors.

use crate::all_hide::AllHideEngine;
use crate::config::{HideConfig, LeakFinding, PrivacyMode, ToolCallSecretPolicy, TrafficCategory};
use crate::desensitizer::SemanticDesensitizer;
use crate::restore::restore_response;
use crate::scanner::ProjectScanner;
use crate::vault::{mask_preview, Matcher, PrivacyVault};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};
use std::sync::Arc;

const MAX_PB_DEPTH: usize = 32;
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const MAX_PREVIEW_BYTES: usize = 48 * 1024;
const MAX_HELD_FRAMES: usize = 8;
const MAX_HELD_BYTES: usize = 256 * 1024;

/// Wire framing mode for binary RPC / Protobuf payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtobufFraming {
    /// Raw Protobuf message in HTTP body (`application/proto`, `application/protobuf`, `application/x-protobuf`).
    Unary,
    /// 5-byte gRPC / gRPC-Web envelope (`application/grpc`, `application/grpc+proto`, `application/grpc-web*`).
    Grpc,
    /// 5-byte ConnectRPC Protobuf envelope (`application/connect+proto`).
    ConnectProto,
    /// 5-byte ConnectRPC JSON envelope (`application/connect+json`).
    ConnectJson,
}

impl ProtobufFraming {
    pub fn is_enveloped(self) -> bool {
        !matches!(self, Self::Unary)
    }

    pub fn encoding_header_name(self) -> &'static str {
        match self {
            Self::Grpc => "grpc-encoding",
            Self::ConnectProto | Self::ConnectJson => "connect-content-encoding",
            Self::Unary => "content-encoding",
        }
    }
}

/// Detect whether an HTTP `Content-Type` header carries a Protobuf, gRPC, or ConnectRPC payload.
pub fn detect_protobuf_framing(content_type: Option<&str>) -> Option<ProtobufFraming> {
    let ct = content_type?;
    let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    match mime.as_str() {
        "application/proto" | "application/protobuf" | "application/x-protobuf" => Some(ProtobufFraming::Unary),
        "application/grpc" | "application/grpc+proto" | "application/grpc-web" | "application/grpc-web+proto" => {
            Some(ProtobufFraming::Grpc)
        }
        "application/connect+proto" => Some(ProtobufFraming::ConnectProto),
        "application/connect+json" => Some(ProtobufFraming::ConnectJson),
        _ => None,
    }
}

/// Result of transforming an outbound Protobuf / gRPC / ConnectRPC request body.
#[derive(Debug)]
pub struct ProtobufOutboundResult {
    pub vendor_body: Vec<u8>,
    pub action_taken: String,
    pub findings: Vec<LeakFinding>,
    pub local_preview: String,
    pub vendor_preview: String,
    pub stripped_content_encoding: bool,
}

/// Result of restoring a unary Protobuf response body.
#[derive(Debug)]
pub struct ProtobufInboundResult {
    pub local_body: Vec<u8>,
    pub restored_count: usize,
    pub withheld_count: usize,
    pub vendor_preview: String,
    pub local_preview: String,
    pub stripped_content_encoding: bool,
}

enum PbValue<'a> {
    Varint(&'a [u8]),
    Fixed64(&'a [u8]),
    Fixed32(&'a [u8]),
    LenDelim(Vec<u8>),
}

struct PbField<'a> {
    tag_bytes: &'a [u8],
    field_num: u32,
    value: PbValue<'a>,
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val: u64 = 0;
    let mut shift = 0u32;
    let start = *pos;
    while *pos < buf.len() {
        let b = buf[*pos];
        *pos += 1;
        if shift == 63 && (b & 0xFE) != 0 {
            return None;
        }
        val |= u64::from(b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            return Some(val);
        }
        shift += 7;
        if *pos - start >= 10 {
            return None;
        }
    }
    None
}

fn write_varint(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Strictly parse a Protobuf wire-format message consuming all bytes to exact EOF.
fn parse_pb_message(bytes: &[u8]) -> Option<Vec<PbField<'_>>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut fields = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let tag_start = pos;
        let tag = read_varint(bytes, &mut pos)?;
        let tag_bytes = &bytes[tag_start..pos];
        let wire_type = (tag & 0x07) as u8;
        let field_num_u64 = tag >> 3;
        if field_num_u64 == 0 || field_num_u64 > 0x1FFF_FFFF {
            return None;
        }
        let field_num = field_num_u64 as u32;
        let value = match wire_type {
            0 => {
                let vstart = pos;
                let _ = read_varint(bytes, &mut pos)?;
                PbValue::Varint(&bytes[vstart..pos])
            }
            1 => {
                if pos + 8 > bytes.len() {
                    return None;
                }
                let slice = &bytes[pos..pos + 8];
                pos += 8;
                PbValue::Fixed64(slice)
            }
            2 => {
                let len = read_varint(bytes, &mut pos)? as usize;
                if len > bytes.len().saturating_sub(pos) {
                    return None;
                }
                let slice = bytes[pos..pos + len].to_vec();
                pos += len;
                PbValue::LenDelim(slice)
            }
            5 => {
                if pos + 4 > bytes.len() {
                    return None;
                }
                let slice = &bytes[pos..pos + 4];
                pos += 4;
                PbValue::Fixed32(slice)
            }
            // Reject deprecated groups (3, 4) and invalid wire types (6, 7).
            _ => return None,
        };
        fields.push(PbField {
            tag_bytes,
            field_num,
            value,
        });
    }
    Some(fields)
}

fn encode_pb_message(fields: &[PbField<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend_from_slice(field.tag_bytes);
        match &field.value {
            PbValue::Varint(b) | PbValue::Fixed64(b) | PbValue::Fixed32(b) => out.extend_from_slice(b),
            PbValue::LenDelim(b) => {
                write_varint(b.len() as u64, &mut out);
                out.extend_from_slice(b);
            }
        }
    }
    out
}

fn is_clean_printable_utf8(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    for &b in bytes {
        if b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r') {
            return None;
        }
        if b == 0x7F {
            return None;
        }
    }
    Some(text)
}

fn looks_like_json_container(text: &str) -> bool {
    let trimmed = text.trim();
    ((trimmed.starts_with('{') && trimmed.ends_with('}')) || (trimmed.starts_with('[') && trimmed.ends_with(']')))
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
}

/// Decide whether a printable UTF-8 length-delimited field is actually a nested Protobuf
/// submessage (e.g. `Part { string text = 1; }` whose tag `0x0A` and ASCII length byte both
/// happen to be printable) rather than plain user prose.
fn should_recurse_printable_submessage(text: &str, fields: &[PbField<'_>], depth: usize) -> bool {
    if fields.is_empty() || depth + 1 >= MAX_PB_DEPTH || looks_like_json_container(text) {
        return false;
    }
    if fields.iter().any(|f| f.field_num > 2048) {
        return false;
    }
    if fields.len() >= 2 {
        return true;
    }
    // Single-field printable message:
    let f = &fields[0];
    if f.field_num == 1 {
        return true;
    }
    if let PbValue::LenDelim(inner) = &f.value {
        if !inner.is_empty() && is_clean_printable_utf8(inner).is_none() && parse_pb_message(inner).is_some() {
            return true;
        }
    }
    if matches!(f.field_num, 2..=7) {
        let bytes = text.as_bytes();
        if bytes.first() == Some(&b'"') && text.ends_with('"') {
            return false;
        }
        if bytes.first() == Some(&b'*') && matches!(bytes.get(1), Some(b' ' | b'*')) {
            return false;
        }
        return true;
    }
    false
}

fn looks_like_secret_prefix(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("sk-")
        || lower.starts_with("ghp_")
        || lower.starts_with("gho_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("glpat-")
        || lower.starts_with("xox")
        || lower.starts_with("xai-")
        || lower.starts_with("aiza")
        || lower.starts_with("eyj")
        || lower.starts_with("hf_")
        || lower.starts_with("npm_")
        || lower.starts_with("pypi-")
        || lower.starts_with("gsk_")
        || lower.starts_with("pplx-")
        || lower.starts_with("sg.")
        || lower.starts_with("-----begin ")
}

/// Skip opaque cryptographic/base64 blobs (such as `thoughtSignature`, session tokens, binary
/// hashes encoded as base64) that carry no user text and must remain byte-exact.
fn is_opaque_pb_string(s: &str) -> bool {
    if s.len() < 80 || looks_like_secret_prefix(s) {
        return false;
    }
    if s.contains("://") || s.contains('/') && s.contains(' ') {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
}

fn is_uuid_like(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit())
}

/// In `AllHide` mode, avoid camouflaging short protocol metadata strings (roles, model names,
/// MIME types, Google Cloud resource paths, UUIDs) unless they match a real sensitive pattern.
fn is_all_hide_pb_metadata(s: &str, cfg: &HideConfig) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return true;
    }
    if !ProjectScanner::scan_matches(trimmed, cfg).is_empty() {
        return false;
    }
    if trimmed.len() < 6 || is_uuid_like(trimmed) {
        return true;
    }
    if matches!(
        trimmed,
        "user"
            | "model"
            | "assistant"
            | "system"
            | "developer"
            | "tool"
            | "function"
            | "STOP"
            | "MAX_TOKENS"
            | "SAFETY"
            | "OK"
            | "text/plain"
            | "application/json"
            | "text/markdown"
            | "image/png"
            | "image/jpeg"
    ) {
        return true;
    }
    if !trimmed.contains(char::is_whitespace)
        && (trimmed.starts_with("projects/")
            || trimmed.starts_with("models/")
            || trimmed.starts_with("locations/")
            || trimmed.starts_with("publishers/")
            || trimmed.starts_with("gemini-")
            || trimmed.starts_with("claude-")
            || trimmed.starts_with("gpt-")
            || trimmed.starts_with("o1-")
            || trimmed.starts_with("o3-")
            || trimmed.starts_with("o4-"))
    {
        return true;
    }
    false
}

fn append_preview(acc: &mut String, text: &str) {
    if text.trim().is_empty() || acc.len() >= MAX_PREVIEW_BYTES {
        return;
    }
    if !acc.is_empty() {
        acc.push('\n');
    }
    let remaining = MAX_PREVIEW_BYTES.saturating_sub(acc.len());
    if text.len() <= remaining {
        acc.push_str(text);
    } else {
        let mut end = remaining;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        acc.push_str(&text[..end]);
    }
}

struct OutboundWalkState<'a> {
    category: TrafficCategory,
    cfg: &'a HideConfig,
    vault: &'a PrivacyVault,
    scope: Option<&'a str>,
    findings: Vec<LeakFinding>,
    local_preview: String,
    vendor_preview: String,
    mutated: bool,
}

fn transform_pb_outbound_recursive(bytes: &[u8], st: &mut OutboundWalkState<'_>, depth: usize) -> Option<Vec<u8>> {
    if depth >= MAX_PB_DEPTH {
        return None;
    }
    let mut fields = parse_pb_message(bytes)?;
    let mut any_changed = false;

    for field in &mut fields {
        let PbValue::LenDelim(ref mut payload) = field.value else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Some(text) = is_clean_printable_utf8(payload) {
            if let Some(sub_fields) = parse_pb_message(payload) {
                if should_recurse_printable_submessage(text, &sub_fields, depth) {
                    if let Some(updated) = transform_pb_outbound_recursive(payload, st, depth + 1) {
                        if updated != *payload {
                            *payload = updated;
                            any_changed = true;
                        }
                    }
                    continue;
                }
            }
            if is_opaque_pb_string(text) {
                continue;
            }
            if text.len() >= 4 {
                append_preview(&mut st.local_preview, text);
            }
            let (replaced, findings) = match st.cfg.mode {
                PrivacyMode::AuditOnly => {
                    let found: Vec<LeakFinding> = ProjectScanner::scan_matches(text, st.cfg)
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
                    (text.to_string(), found)
                }
                PrivacyMode::AutoDesensitize => {
                    let res = SemanticDesensitizer::process_with_scope(text, st.cfg, st.vault, st.scope);
                    (res.transformed_payload, res.findings)
                }
                PrivacyMode::AllHide => {
                    if is_all_hide_pb_metadata(text, st.cfg) {
                        (text.to_string(), Vec::new())
                    } else {
                        let out = AllHideEngine::process_with_scope(text, st.category, st.cfg, st.vault, st.scope);
                        (out.vendor_payload, out.findings)
                    }
                }
            };
            if text.len() >= 4 {
                append_preview(&mut st.vendor_preview, &replaced);
            }
            if !findings.is_empty() {
                st.findings.extend(findings);
            }
            if replaced != text {
                *payload = replaced.into_bytes();
                any_changed = true;
                st.mutated = true;
            }
        } else if let Some(updated) = transform_pb_outbound_recursive(payload, st, depth + 1) {
            if updated != *payload {
                *payload = updated;
                any_changed = true;
            }
        }
    }

    if any_changed {
        Some(encode_pb_message(&fields))
    } else {
        Some(bytes.to_vec())
    }
}

fn gunzip_limited(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(data)
        .take((limit + 1) as u64)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= limit).then_some(out)
}

fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

fn zlib_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

fn decompress_frame_payload(enc: Option<&str>, payload: &[u8], limit: usize) -> Option<Vec<u8>> {
    let lower = enc?.trim().to_ascii_lowercase();
    match lower.as_str() {
        "gzip" | "x-gzip" => gunzip_limited(payload, limit),
        "deflate" => decompress_http_encoding("deflate", payload, limit),
        _ => None,
    }
}

fn compress_frame_payload(enc: Option<&str>, plain: &[u8]) -> Option<Vec<u8>> {
    let lower = enc?.trim().to_ascii_lowercase();
    match lower.as_str() {
        "gzip" | "x-gzip" => gzip_bytes(plain),
        "deflate" => zlib_bytes(plain),
        _ => None,
    }
}

fn decompress_http_encoding(enc: &str, body: &[u8], limit: usize) -> Option<Vec<u8>> {
    let lower = enc.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    let max_read = (limit + 1) as u64;
    match lower.as_str() {
        "gzip" | "x-gzip" => {
            GzDecoder::new(body).take(max_read).read_to_end(&mut out).ok()?;
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
                    .ok()?;
            }
        }
        _ => return None,
    }
    (out.len() <= limit).then_some(out)
}

fn is_non_data_envelope_flag(framing: ProtobufFraming, flags: u8) -> bool {
    if (flags & 0x80) != 0 {
        // gRPC-Web trailer frame
        return true;
    }
    matches!(framing, ProtobufFraming::ConnectProto | ProtobufFraming::ConnectJson) && (flags & 0x02) != 0
}

fn transform_enveloped_outbound(
    framing: ProtobufFraming,
    raw_body: &[u8],
    frame_encoding: Option<&str>,
    st: &mut OutboundWalkState<'_>,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw_body.len());
    let mut pos = 0usize;
    while pos < raw_body.len() {
        if raw_body.len() - pos < 5 {
            return None;
        }
        let flags = raw_body[pos];
        let len = u32::from_be_bytes([
            raw_body[pos + 1],
            raw_body[pos + 2],
            raw_body[pos + 3],
            raw_body[pos + 4],
        ]) as usize;
        pos += 5;
        if len > MAX_FRAME_LEN || len > raw_body.len() - pos {
            return None;
        }
        let payload = &raw_body[pos..pos + len];
        pos += len;

        if is_non_data_envelope_flag(framing, flags) {
            out.push(flags);
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(payload);
            continue;
        }

        let compressed = (flags & 0x01) != 0;
        let plain: std::borrow::Cow<'_, [u8]> = if compressed {
            match decompress_frame_payload(frame_encoding, payload, MAX_FRAME_LEN) {
                Some(v) => std::borrow::Cow::Owned(v),
                None => {
                    // Unknown or undecodable compression algorithm -> preserve frame verbatim.
                    out.push(flags);
                    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                    out.extend_from_slice(payload);
                    continue;
                }
            }
        } else {
            std::borrow::Cow::Borrowed(payload)
        };

        let (transformed_plain, frame_mutated) = match framing {
            ProtobufFraming::ConnectJson => {
                if let Ok(text) = std::str::from_utf8(&plain) {
                    append_preview(&mut st.local_preview, text);
                    let (vendor_str, _, findings) =
                        crate::proxy::transform_outbound_scoped(st.vault, st.category, text, st.cfg, st.scope);
                    append_preview(&mut st.vendor_preview, &vendor_str);
                    st.findings.extend(findings);
                    if vendor_str != text {
                        st.mutated = true;
                        (vendor_str.into_bytes(), true)
                    } else {
                        (plain.into_owned(), false)
                    }
                } else {
                    (plain.into_owned(), false)
                }
            }
            _ => match transform_pb_outbound_recursive(&plain, st, 0) {
                Some(updated) => {
                    let changed = updated.as_slice() != plain.as_ref();
                    (updated, changed)
                }
                None => (plain.into_owned(), false),
            },
        };

        let final_payload = if compressed {
            if !frame_mutated {
                payload.to_vec()
            } else {
                compress_frame_payload(frame_encoding, &transformed_plain).unwrap_or_else(|| payload.to_vec())
            }
        } else {
            transformed_plain
        };

        out.push(flags);
        out.extend_from_slice(&(final_payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&final_payload);
    }
    Some(out)
}

/// Transform an outbound Protobuf / gRPC / ConnectRPC request body in-place (preserving wire framing).
#[allow(clippy::too_many_arguments)]
pub fn transform_protobuf_outbound(
    framing: ProtobufFraming,
    raw_body: &[u8],
    content_encoding: Option<&str>,
    frame_encoding: Option<&str>,
    category: TrafficCategory,
    cfg: &HideConfig,
    vault: &PrivacyVault,
    scope: Option<&str>,
) -> ProtobufOutboundResult {
    let mut st = OutboundWalkState {
        category,
        cfg,
        vault,
        scope,
        findings: Vec::new(),
        local_preview: String::new(),
        vendor_preview: String::new(),
        mutated: false,
    };

    let (vendor_body, stripped_content_encoding) = match framing {
        ProtobufFraming::Unary => {
            if let Some(enc) = content_encoding.filter(|e| !e.eq_ignore_ascii_case("identity")) {
                if let Some(decompressed) = decompress_http_encoding(enc, raw_body, MAX_FRAME_LEN) {
                    match transform_pb_outbound_recursive(&decompressed, &mut st, 0) {
                        Some(transformed) if st.mutated => (transformed, true),
                        _ => (raw_body.to_vec(), false),
                    }
                } else {
                    (raw_body.to_vec(), false)
                }
            } else {
                let transformed =
                    transform_pb_outbound_recursive(raw_body, &mut st, 0).unwrap_or_else(|| raw_body.to_vec());
                (transformed, false)
            }
        }
        ProtobufFraming::Grpc | ProtobufFraming::ConnectProto | ProtobufFraming::ConnectJson => {
            let transformed = transform_enveloped_outbound(framing, raw_body, frame_encoding, &mut st)
                .unwrap_or_else(|| raw_body.to_vec());
            (transformed, false)
        }
    };

    let action_taken = if cfg.mode == PrivacyMode::AuditOnly {
        "protobuf-audited".to_string()
    } else if st.mutated {
        match cfg.mode {
            PrivacyMode::AllHide => "protobuf-all-hide".to_string(),
            PrivacyMode::AutoDesensitize => "protobuf-desensitized".to_string(),
            PrivacyMode::AuditOnly => "protobuf-audited".to_string(),
        }
    } else {
        "protobuf-passed".to_string()
    };

    ProtobufOutboundResult {
        vendor_body,
        action_taken,
        findings: st.findings,
        local_preview: st.local_preview,
        vendor_preview: st.vendor_preview,
        stripped_content_encoding,
    }
}

struct InboundWalkState<'a> {
    matcher: &'a Matcher,
    policy: ToolCallSecretPolicy,
    restored_count: usize,
    withheld_count: usize,
    vendor_preview: String,
    local_preview: String,
    last_text_has_pending_prefix: bool,
    pending_prefix_to_prepend: Option<String>,
}

fn trailing_token_prefix_len(matcher: &Matcher, text: &str) -> usize {
    if matcher.is_empty() || text.is_empty() {
        return 0;
    }
    let max_token_len = matcher.pairs().first().map_or(0, |p| p.token.len());
    if max_token_len <= 1 {
        return 0;
    }
    let max_suffix = (max_token_len - 1).min(text.len());
    let start_bound = text.len().saturating_sub(max_suffix);
    for (idx, _) in text.char_indices() {
        if idx < start_bound {
            continue;
        }
        if matcher.is_strict_prefix(&text[idx..]) {
            return text.len() - idx;
        }
    }
    0
}

fn restore_pb_recursive(bytes: &[u8], st: &mut InboundWalkState<'_>, depth: usize) -> Option<Vec<u8>> {
    if depth >= MAX_PB_DEPTH {
        return None;
    }
    let mut fields = parse_pb_message(bytes)?;
    let mut any_changed = false;

    for field in &mut fields {
        let PbValue::LenDelim(ref mut payload) = field.value else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Some(text) = is_clean_printable_utf8(payload) {
            if let Some(sub_fields) = parse_pb_message(payload) {
                if should_recurse_printable_submessage(text, &sub_fields, depth) {
                    if let Some(updated) = restore_pb_recursive(payload, st, depth + 1) {
                        if updated != *payload {
                            *payload = updated;
                            any_changed = true;
                        }
                    }
                    continue;
                }
            }
            if is_opaque_pb_string(text) {
                continue;
            }
            if text.len() >= 2 {
                append_preview(&mut st.vendor_preview, text);
            }
            let allow_secret = st.policy != ToolCallSecretPolicy::Never;
            let (candidate, used_prefix) = if let Some(prefix) = st.pending_prefix_to_prepend.as_deref() {
                (format!("{prefix}{text}"), true)
            } else {
                (text.to_string(), false)
            };
            let (restored, count, withheld) = if looks_like_json_container(&candidate) {
                restore_response(st.matcher, &candidate, st.policy)
            } else {
                st.matcher.restore(&candidate, None, allow_secret)
            };
            if used_prefix {
                if count > 0 {
                    // Consumed the carried prefix and completed a split placeholder!
                    st.pending_prefix_to_prepend = None;
                    st.restored_count += count;
                    st.withheld_count += withheld;
                    if text.len() >= 2 {
                        append_preview(&mut st.local_preview, &restored);
                    }
                    if trailing_token_prefix_len(st.matcher, &restored) > 0 {
                        st.last_text_has_pending_prefix = true;
                    }
                    *payload = restored.into_bytes();
                    any_changed = true;
                    continue;
                } else {
                    // Prefix did not combine here; restore `text` alone.
                    let (alone_restored, alone_count, alone_withheld) = if looks_like_json_container(text) {
                        restore_response(st.matcher, text, st.policy)
                    } else {
                        st.matcher.restore(text, None, allow_secret)
                    };
                    st.restored_count += alone_count;
                    st.withheld_count += alone_withheld;
                    if text.len() >= 2 {
                        append_preview(&mut st.local_preview, &alone_restored);
                    }
                    if trailing_token_prefix_len(st.matcher, &alone_restored) > 0 {
                        st.last_text_has_pending_prefix = true;
                    }
                    if alone_restored != text {
                        *payload = alone_restored.into_bytes();
                        any_changed = true;
                    }
                    continue;
                }
            }

            st.restored_count += count;
            st.withheld_count += withheld;
            if text.len() >= 2 {
                append_preview(&mut st.local_preview, &restored);
            }
            if trailing_token_prefix_len(st.matcher, &restored) > 0 {
                st.last_text_has_pending_prefix = true;
            }
            if restored != text {
                *payload = restored.into_bytes();
                any_changed = true;
            }
        } else if let Some(updated) = restore_pb_recursive(payload, st, depth + 1) {
            if updated != *payload {
                *payload = updated;
                any_changed = true;
            }
        }
    }

    if any_changed {
        Some(encode_pb_message(&fields))
    } else {
        Some(bytes.to_vec())
    }
}

/// Extract and trim the trailing strict-prefix suffix from the last matching text field in a
/// Protobuf message (used when buffering a streaming delta frame that splits a vault placeholder).
fn split_trailing_prefix_in_pb(bytes: &[u8], matcher: &Matcher, depth: usize) -> Option<(Vec<u8>, String)> {
    if depth >= MAX_PB_DEPTH {
        return None;
    }
    let mut fields = parse_pb_message(bytes)?;
    for field in fields.iter_mut().rev() {
        let PbValue::LenDelim(ref mut payload) = field.value else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Some(text) = is_clean_printable_utf8(payload) {
            if let Some(sub_fields) = parse_pb_message(payload) {
                if should_recurse_printable_submessage(text, &sub_fields, depth) {
                    if let Some((updated, suffix)) = split_trailing_prefix_in_pb(payload, matcher, depth + 1) {
                        *payload = updated;
                        return Some((encode_pb_message(&fields), suffix));
                    }
                    continue;
                }
            }
            if is_opaque_pb_string(text) {
                continue;
            }
            let suffix_len = trailing_token_prefix_len(matcher, text);
            if suffix_len > 0 {
                let split_at = text.len() - suffix_len;
                let suffix = text[split_at..].to_string();
                *payload = text.as_bytes()[..split_at].to_vec();
                return Some((encode_pb_message(&fields), suffix));
            }
        } else if let Some((updated, suffix)) = split_trailing_prefix_in_pb(payload, matcher, depth + 1) {
            *payload = updated;
            return Some((encode_pb_message(&fields), suffix));
        }
    }
    None
}

/// Restore a unary Protobuf response body (`application/proto`, `application/protobuf`, `application/x-protobuf`).
pub fn restore_unary_protobuf(
    raw_body: &[u8],
    content_encoding: Option<&str>,
    matcher: &Matcher,
    policy: ToolCallSecretPolicy,
) -> ProtobufInboundResult {
    let mut st = InboundWalkState {
        matcher,
        policy,
        restored_count: 0,
        withheld_count: 0,
        vendor_preview: String::new(),
        local_preview: String::new(),
        last_text_has_pending_prefix: false,
        pending_prefix_to_prepend: None,
    };

    let (local_body, stripped_content_encoding) =
        if let Some(enc) = content_encoding.filter(|e| !e.eq_ignore_ascii_case("identity")) {
            if let Some(decompressed) = decompress_http_encoding(enc, raw_body, MAX_FRAME_LEN) {
                match restore_pb_recursive(&decompressed, &mut st, 0) {
                    Some(restored) if st.restored_count > 0 => (restored, true),
                    _ => (raw_body.to_vec(), false),
                }
            } else {
                (raw_body.to_vec(), false)
            }
        } else {
            let restored = restore_pb_recursive(raw_body, &mut st, 0).unwrap_or_else(|| raw_body.to_vec());
            (restored, false)
        };

    ProtobufInboundResult {
        local_body,
        restored_count: st.restored_count,
        withheld_count: st.withheld_count,
        vendor_preview: st.vendor_preview,
        local_preview: st.local_preview,
        stripped_content_encoding,
    }
}

struct HeldFrame {
    flags: u8,
    /// Original restored-alone frame payload (emitted unchanged if next frame does not complete the prefix).
    intact_plain: Vec<u8>,
    /// Frame payload with the trailing prefix trimmed off (emitted if the next frame completes the placeholder).
    trimmed_plain: Vec<u8>,
    trailing_prefix: String,
    compressed: bool,
}

/// Incremental, framing-safe restorer for streaming gRPC (`application/grpc*`) and ConnectRPC
/// (`application/connect+proto`, `application/connect+json`) responses.
pub struct GrpcStreamRestorer {
    framing: ProtobufFraming,
    frame_encoding: Option<String>,
    matcher: Option<Arc<Matcher>>,
    live_vault: Option<(PrivacyVault, Option<String>)>,
    policy: ToolCallSecretPolicy,
    in_buf: Vec<u8>,
    held: Vec<HeldFrame>,
    held_bytes: usize,
    restored_count: usize,
    withheld_count: usize,
    vendor_preview: String,
    local_preview: String,
    passthrough_broken: bool,
}

impl GrpcStreamRestorer {
    pub fn new(
        framing: ProtobufFraming,
        frame_encoding: Option<String>,
        matcher: Option<Arc<Matcher>>,
        policy: ToolCallSecretPolicy,
    ) -> Self {
        Self {
            framing,
            frame_encoding,
            matcher,
            live_vault: None,
            policy,
            in_buf: Vec::new(),
            held: Vec::new(),
            held_bytes: 0,
            restored_count: 0,
            withheld_count: 0,
            vendor_preview: String::new(),
            local_preview: String::new(),
            passthrough_broken: false,
        }
    }

    /// Create a restorer backed by a live `PrivacyVault` so bidirectional streams automatically
    /// pick up new tokens inserted by subsequent client frames on the same HTTP/2 stream.
    pub fn with_vault(
        framing: ProtobufFraming,
        frame_encoding: Option<String>,
        vault: Option<(PrivacyVault, Option<String>)>,
        policy: ToolCallSecretPolicy,
    ) -> Self {
        Self {
            framing,
            frame_encoding,
            matcher: None,
            live_vault: vault,
            policy,
            in_buf: Vec::new(),
            held: Vec::new(),
            held_bytes: 0,
            restored_count: 0,
            withheld_count: 0,
            vendor_preview: String::new(),
            local_preview: String::new(),
            passthrough_broken: false,
        }
    }

    fn current_matcher(&self) -> Option<Arc<Matcher>> {
        if let Some((vault, scope)) = &self.live_vault {
            Some(vault.matcher_for_scope(scope.as_deref()))
        } else {
            self.matcher.clone()
        }
    }

    pub fn restored_count(&self) -> usize {
        self.restored_count
    }

    pub fn withheld_count(&self) -> usize {
        self.withheld_count
    }

    pub fn vendor_preview(&self) -> &str {
        &self.vendor_preview
    }

    pub fn local_preview(&self) -> &str {
        &self.local_preview
    }

    fn emit_envelope(&self, out: &mut Vec<u8>, flags: u8, plain: &[u8], compressed: bool) {
        let payload = if compressed {
            compress_frame_payload(self.frame_encoding.as_deref(), plain).unwrap_or_else(|| plain.to_vec())
        } else {
            plain.to_vec()
        };
        out.push(flags);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
    }

    fn flush_held_intact(&mut self, out: &mut Vec<u8>) {
        let held = std::mem::take(&mut self.held);
        for frame in held {
            self.emit_envelope(out, frame.flags, &frame.intact_plain, frame.compressed);
        }
        self.held_bytes = 0;
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.passthrough_broken {
            return chunk.to_vec();
        }
        self.in_buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        loop {
            if self.in_buf.len() < 5 {
                break;
            }
            let flags = self.in_buf[0];
            let frame_len =
                u32::from_be_bytes([self.in_buf[1], self.in_buf[2], self.in_buf[3], self.in_buf[4]]) as usize;
            if frame_len > MAX_FRAME_LEN {
                // Unexpectedly oversized or malformed frame header -> fail safe, pass everything through untouched.
                self.flush_held_intact(&mut out);
                out.extend_from_slice(&self.in_buf);
                self.in_buf.clear();
                self.passthrough_broken = true;
                break;
            }
            if self.in_buf.len() < 5 + frame_len {
                break;
            }

            let raw_frame = self.in_buf.drain(..5 + frame_len).collect::<Vec<u8>>();
            let payload = &raw_frame[5..];

            if is_non_data_envelope_flag(self.framing, flags) {
                self.flush_held_intact(&mut out);
                out.extend_from_slice(&raw_frame);
                continue;
            }

            let compressed = (flags & 0x01) != 0;
            let plain: Vec<u8> = if compressed {
                match decompress_frame_payload(self.frame_encoding.as_deref(), payload, MAX_FRAME_LEN) {
                    Some(v) => v,
                    None => {
                        self.flush_held_intact(&mut out);
                        out.extend_from_slice(&raw_frame);
                        continue;
                    }
                }
            } else {
                payload.to_vec()
            };

            let Some(matcher) = self.current_matcher() else {
                self.flush_held_intact(&mut out);
                out.extend_from_slice(&raw_frame);
                continue;
            };

            if self.framing == ProtobufFraming::ConnectJson {
                self.flush_held_intact(&mut out);
                if let Ok(text) = std::str::from_utf8(&plain) {
                    append_preview(&mut self.vendor_preview, text);
                    let (restored, count, withheld) = restore_response(&matcher, text, self.policy);
                    self.restored_count += count;
                    self.withheld_count += withheld;
                    append_preview(&mut self.local_preview, &restored);
                    if restored != text {
                        self.emit_envelope(&mut out, flags, restored.as_bytes(), compressed);
                    } else {
                        out.extend_from_slice(&raw_frame);
                    }
                } else {
                    out.extend_from_slice(&raw_frame);
                }
                continue;
            }

            // Combine any pending split-placeholder prefix from previously held delta frame(s).
            let carried_prefix = if self.held.is_empty() {
                None
            } else {
                let mut combined = String::new();
                for h in &self.held {
                    combined.push_str(&h.trailing_prefix);
                }
                Some(combined)
            };

            let mut walk = InboundWalkState {
                matcher: &matcher,
                policy: self.policy,
                restored_count: 0,
                withheld_count: 0,
                vendor_preview: String::new(),
                local_preview: String::new(),
                last_text_has_pending_prefix: false,
                pending_prefix_to_prepend: carried_prefix.clone(),
            };

            let restored_plain = restore_pb_recursive(&plain, &mut walk, 0).unwrap_or_else(|| plain.clone());
            self.restored_count += walk.restored_count;
            self.withheld_count += walk.withheld_count;
            append_preview(&mut self.vendor_preview, &walk.vendor_preview);
            append_preview(&mut self.local_preview, &walk.local_preview);

            let prefix_consumed = carried_prefix.is_some() && walk.pending_prefix_to_prepend.is_none();
            if prefix_consumed {
                // Emit previously held frames with their split suffixes trimmed, then emit this frame.
                let held = std::mem::take(&mut self.held);
                for h in held {
                    self.emit_envelope(&mut out, h.flags, &h.trimmed_plain, h.compressed);
                }
                self.held_bytes = 0;
            } else if !self.held.is_empty() {
                // Check whether appending this frame's trimmed text STILL forms a longer strict prefix
                // of a vault token (e.g. a token split across 3+ tiny deltas).
                if let Some((trimmed_cur, cur_suffix)) = split_trailing_prefix_in_pb(&restored_plain, &matcher, 0) {
                    let combined_next = format!("{}{}", carried_prefix.as_deref().unwrap_or_default(), cur_suffix);
                    if matcher.is_strict_prefix(&combined_next)
                        && self.held.len() < MAX_HELD_FRAMES
                        && self.held_bytes + restored_plain.len() <= MAX_HELD_BYTES
                    {
                        self.held_bytes += restored_plain.len();
                        self.held.push(HeldFrame {
                            flags,
                            intact_plain: restored_plain,
                            trimmed_plain: trimmed_cur,
                            trailing_prefix: cur_suffix,
                            compressed,
                        });
                        continue;
                    }
                }
                // Prefix did not match -> release held frames completely intact.
                self.flush_held_intact(&mut out);
            }

            // Does this frame end with a strict prefix of a registered vault token?
            if walk.last_text_has_pending_prefix && self.held.len() < MAX_HELD_FRAMES {
                if let Some((trimmed_plain, trailing_prefix)) =
                    split_trailing_prefix_in_pb(&restored_plain, &matcher, 0)
                {
                    if self.held_bytes + restored_plain.len() <= MAX_HELD_BYTES {
                        self.held_bytes += restored_plain.len();
                        self.held.push(HeldFrame {
                            flags,
                            intact_plain: restored_plain,
                            trimmed_plain,
                            trailing_prefix,
                            compressed,
                        });
                        continue;
                    }
                }
            }

            if restored_plain != plain {
                self.emit_envelope(&mut out, flags, &restored_plain, compressed);
            } else {
                out.extend_from_slice(&raw_frame);
            }
        }

        out
    }

    /// Flush any buffered partial frames or held prefix frames at stream EOF.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.flush_held_intact(&mut out);
        if !self.in_buf.is_empty() {
            out.extend_from_slice(&self.in_buf);
            self.in_buf.clear();
        }
        out
    }
}

/// Shared outbound metrics accumulated incrementally during bidirectional streaming RPCs.
#[derive(Debug, Default)]
pub struct OutboundStreamMetrics {
    pub request_bytes: usize,
    pub vendor_bytes: usize,
    pub findings: Vec<LeakFinding>,
    pub local_preview: String,
    pub vendor_preview: String,
    pub mutated: bool,
}

impl OutboundStreamMetrics {
    pub fn action_taken(&self, mode: PrivacyMode) -> String {
        if mode == PrivacyMode::AuditOnly {
            "protobuf-audited".to_string()
        } else if self.mutated {
            match mode {
                PrivacyMode::AllHide => "protobuf-all-hide".to_string(),
                PrivacyMode::AutoDesensitize => "protobuf-desensitized".to_string(),
                PrivacyMode::AuditOnly => "protobuf-audited".to_string(),
            }
        } else {
            "protobuf-passed".to_string()
        }
    }
}

/// Incremental, framing-safe outbound desensitizer for full-duplex bidirectional streaming
/// gRPC (`application/grpc*`) and ConnectRPC (`application/connect+proto`, `application/connect+json`).
pub struct GrpcStreamDesensitizer {
    framing: ProtobufFraming,
    frame_encoding: Option<String>,
    category: TrafficCategory,
    cfg: HideConfig,
    vault: PrivacyVault,
    scope: Option<String>,
    in_buf: Vec<u8>,
    passthrough_broken: bool,
    metrics: Arc<parking_lot::Mutex<OutboundStreamMetrics>>,
}

impl GrpcStreamDesensitizer {
    pub fn new(
        framing: ProtobufFraming,
        frame_encoding: Option<String>,
        category: TrafficCategory,
        cfg: HideConfig,
        vault: PrivacyVault,
        scope: Option<String>,
        metrics: Arc<parking_lot::Mutex<OutboundStreamMetrics>>,
    ) -> Self {
        Self {
            framing,
            frame_encoding,
            category,
            cfg,
            vault,
            scope,
            in_buf: Vec::new(),
            passthrough_broken: false,
            metrics,
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        {
            let mut m = self.metrics.lock();
            m.request_bytes = m.request_bytes.saturating_add(chunk.len());
        }
        if self.passthrough_broken {
            let mut m = self.metrics.lock();
            m.vendor_bytes = m.vendor_bytes.saturating_add(chunk.len());
            return chunk.to_vec();
        }

        self.in_buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        loop {
            if self.in_buf.len() < 5 {
                break;
            }
            let frame_len =
                u32::from_be_bytes([self.in_buf[1], self.in_buf[2], self.in_buf[3], self.in_buf[4]]) as usize;
            if frame_len > MAX_FRAME_LEN {
                out.extend_from_slice(&self.in_buf);
                self.in_buf.clear();
                self.passthrough_broken = true;
                break;
            }
            if self.in_buf.len() < 5 + frame_len {
                break;
            }

            let raw_frame = self.in_buf.drain(..5 + frame_len).collect::<Vec<u8>>();
            let mut st = OutboundWalkState {
                category: self.category,
                cfg: &self.cfg,
                vault: &self.vault,
                scope: self.scope.as_deref(),
                findings: Vec::new(),
                local_preview: String::new(),
                vendor_preview: String::new(),
                mutated: false,
            };
            let transformed =
                transform_enveloped_outbound(self.framing, &raw_frame, self.frame_encoding.as_deref(), &mut st)
                    .unwrap_or(raw_frame);
            out.extend_from_slice(&transformed);

            let mut m = self.metrics.lock();
            if st.mutated {
                m.mutated = true;
            }
            if !st.findings.is_empty() {
                m.findings.extend(st.findings);
            }
            append_preview(&mut m.local_preview, &st.local_preview);
            append_preview(&mut m.vendor_preview, &st.vendor_preview);
        }

        {
            let mut m = self.metrics.lock();
            m.vendor_bytes = m.vendor_bytes.saturating_add(out.len());
        }
        out
    }

    pub fn finish(&mut self) -> Vec<u8> {
        if self.in_buf.is_empty() {
            return Vec::new();
        }
        let tail = std::mem::take(&mut self.in_buf);
        let mut m = self.metrics.lock();
        m.vendor_bytes = m.vendor_bytes.saturating_add(tail.len());
        tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_string_field(field_num: u32, text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint((u64::from(field_num) << 3) | 2, &mut out);
        write_varint(text.len() as u64, &mut out);
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn encode_bytes_field(field_num: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint((u64::from(field_num) << 3) | 2, &mut out);
        write_varint(data.len() as u64, &mut out);
        out.extend_from_slice(data);
        out
    }

    fn encode_varint_field(field_num: u32, val: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint(u64::from(field_num) << 3, &mut out);
        write_varint(val, &mut out);
        out
    }

    fn wrap_envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(flags);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn extract_all_pb_strings(bytes: &[u8], depth: usize) -> Vec<String> {
        if depth >= MAX_PB_DEPTH {
            return Vec::new();
        }
        let Some(fields) = parse_pb_message(bytes) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for f in fields {
            if let PbValue::LenDelim(data) = f.value {
                if let Some(s) = is_clean_printable_utf8(&data) {
                    if let Some(sub) = parse_pb_message(&data) {
                        if should_recurse_printable_submessage(s, &sub, depth) {
                            out.extend(extract_all_pb_strings(&data, depth + 1));
                            continue;
                        }
                    }
                    out.push(s.to_string());
                } else {
                    out.extend(extract_all_pb_strings(&data, depth + 1));
                }
            }
        }
        out
    }

    #[test]
    fn printable_single_field_part_submessage_masks_and_restores_losslessly() {
        // Construct a nested Gemini-like GenerateContentRequest:
        // Content { Part { text = "sk-wbefwubfbsrfrsuf baseurl:linuu.do/v1 是什么" } (49 bytes = '1'), role = "user" }
        // Note: Part itself is `0x0A 0x31 <utf8>` which is 100% printable UTF-8!
        let secret_prompt = "sk-wbefwubfbsrfrsuf baseurl:linuu.do/v1 是什么";
        assert_eq!(secret_prompt.len(), 49); // 0x31 == '1', printable ASCII!
        let part = encode_string_field(1, secret_prompt);
        assert!(is_clean_printable_utf8(&part).is_some());

        let mut content = Vec::new();
        content.extend(encode_bytes_field(1, &part));
        content.extend(encode_string_field(2, "user"));

        let mut req = Vec::new();
        req.extend(encode_string_field(1, "models/gemini-2.5-pro"));
        req.extend(encode_bytes_field(2, &content));
        req.extend(encode_varint_field(3, 4096));

        let grpc_req = wrap_envelope(0, &req);
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();

        let out = transform_protobuf_outbound(
            ProtobufFraming::Grpc,
            &grpc_req,
            None,
            None,
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
            Some("harness:antigravity"),
        );

        assert_eq!(out.action_taken, "protobuf-desensitized");
        assert!(!out.findings.is_empty());
        assert!(!out.vendor_preview.contains("sk-wbefwubfbsrfrsuf"));

        // Verify the emitted gRPC envelope & nested Protobuf wire format parse strictly to exact EOF!
        let env_len = u32::from_be_bytes([
            out.vendor_body[1],
            out.vendor_body[2],
            out.vendor_body[3],
            out.vendor_body[4],
        ]) as usize;
        assert_eq!(env_len, out.vendor_body.len() - 5);
        let vendor_msg = &out.vendor_body[5..];
        let vendor_strings = extract_all_pb_strings(vendor_msg, 0);
        assert!(vendor_strings.contains(&"models/gemini-2.5-pro".to_string()));
        assert!(vendor_strings.contains(&"user".to_string()));
        let masked_prompt = vendor_strings
            .iter()
            .find(|s| s.contains("baseurl:linuu.do/v1"))
            .expect("masked prompt must remain intact inside Part.text");
        assert!(!masked_prompt.contains("sk-wbefwubfbsrfrsuf"));

        // Now stream the masked prompt back as a gRPC response split arbitrarily at 3-byte chunks!
        let resp_part = encode_string_field(1, masked_prompt);
        let resp_frame = wrap_envelope(0, &encode_bytes_field(1, &resp_part));
        let matcher = vault.matcher_for_scope(Some("harness:antigravity"));
        let mut restorer = GrpcStreamRestorer::new(
            ProtobufFraming::Grpc,
            None,
            Some(matcher),
            ToolCallSecretPolicy::FileEditsOnly,
        );
        let mut restored_wire = Vec::new();
        for chunk in resp_frame.chunks(3) {
            restored_wire.extend(restorer.push_chunk(chunk));
        }
        restored_wire.extend(restorer.finish());

        assert_eq!(restorer.restored_count(), 1);
        let rlen =
            u32::from_be_bytes([restored_wire[1], restored_wire[2], restored_wire[3], restored_wire[4]]) as usize;
        assert_eq!(rlen, restored_wire.len() - 5);
        let restored_strings = extract_all_pb_strings(&restored_wire[5..], 0);
        assert_eq!(restored_strings, vec![secret_prompt.to_string()]);
    }

    #[test]
    fn streaming_grpc_restores_placeholder_split_across_adjacent_delta_frames() {
        let vault = PrivacyVault::new();
        let placeholder =
            vault.get_or_insert_scoped_with(Some("harness:antigravity"), "sk-wbefwubfbsrfrsuf", "ApiKey", |_| {
                "sk-demo-placeholder-998877".to_string()
            });
        assert_eq!(placeholder, "sk-demo-placeholder-998877");

        // Split the placeholder across two consecutive gRPC delta frames!
        let f1 = wrap_envelope(0, &encode_string_field(1, "Key is sk-demo-place"));
        let f2 = wrap_envelope(0, &encode_string_field(1, "holder-998877 in use."));

        let matcher = vault.matcher_for_scope(Some("harness:antigravity"));
        let mut restorer = GrpcStreamRestorer::new(
            ProtobufFraming::Grpc,
            None,
            Some(matcher),
            ToolCallSecretPolicy::FileEditsOnly,
        );

        let mut wire = Vec::new();
        wire.extend(restorer.push_chunk(&f1));
        wire.extend(restorer.push_chunk(&f2));
        wire.extend(restorer.finish());

        assert_eq!(restorer.restored_count(), 1);

        // Decode both output gRPC frames and concatenate their text fields.
        let mut pos = 0;
        let mut combined_text = String::new();
        while pos < wire.len() {
            let flen = u32::from_be_bytes([wire[pos + 1], wire[pos + 2], wire[pos + 3], wire[pos + 4]]) as usize;
            let strings = extract_all_pb_strings(&wire[pos + 5..pos + 5 + flen], 0);
            for s in strings {
                combined_text.push_str(&s);
            }
            pos += 5 + flen;
        }
        assert_eq!(combined_text, "Key is sk-wbefwubfbsrfrsuf in use.");
    }

    #[test]
    fn connect_proto_gzip_and_end_stream_frames_and_opaque_binary_stay_intact() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let opaque_png: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFE, 0x00, 0x01];
        let thought_sig = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".repeat(2);

        let mut msg = Vec::new();
        msg.extend(encode_string_field(
            1,
            "Use db postgres://admin:TopSecret99@10.0.1.2:5432/prod",
        ));
        msg.extend(encode_bytes_field(2, &opaque_png));
        msg.extend(encode_string_field(3, &thought_sig));

        let gz_msg = gzip_bytes(&msg).unwrap();
        let data_frame = wrap_envelope(0x01, &gz_msg);
        let end_frame = wrap_envelope(0x02, br#"{"metadata":{"x-req":"ok"}}"#);

        let mut req_body = Vec::new();
        req_body.extend(&data_frame);
        req_body.extend(&end_frame);

        let out = transform_protobuf_outbound(
            ProtobufFraming::ConnectProto,
            &req_body,
            None,
            Some("gzip"),
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
            Some("harness:cursor"),
        );

        assert_eq!(out.action_taken, "protobuf-desensitized");
        assert!(!out.vendor_preview.contains("TopSecret99"));
        assert!(!out.vendor_preview.contains("10.0.1.2"));

        // Verify frame 1 decompresses cleanly, preserves opaque_png & thought_sig byte-exact, and frame 2 is untouched.
        let f1_len = u32::from_be_bytes([
            out.vendor_body[1],
            out.vendor_body[2],
            out.vendor_body[3],
            out.vendor_body[4],
        ]) as usize;
        assert_eq!(out.vendor_body[0], 0x01);
        let plain1 = gunzip_limited(&out.vendor_body[5..5 + f1_len], MAX_FRAME_LEN).unwrap();
        let fields = parse_pb_message(&plain1).unwrap();
        assert_eq!(fields.len(), 3);
        match &fields[1].value {
            PbValue::LenDelim(b) => assert_eq!(b, &opaque_png),
            _ => panic!("expected bytes field 2"),
        }
        match &fields[2].value {
            PbValue::LenDelim(b) => assert_eq!(b.as_slice(), thought_sig.as_bytes()),
            _ => panic!("expected thought_sig field 3"),
        }
        assert_eq!(&out.vendor_body[5 + f1_len..], end_frame.as_slice());

        // Restore via GrpcStreamRestorer
        let matcher = vault.matcher_for_scope(Some("harness:cursor"));
        let mut restorer = GrpcStreamRestorer::new(
            ProtobufFraming::ConnectProto,
            Some("gzip".to_string()),
            Some(matcher),
            ToolCallSecretPolicy::FileEditsOnly,
        );
        let mut restored = restorer.push_chunk(&out.vendor_body);
        restored.extend(restorer.finish());

        let r1_len = u32::from_be_bytes([restored[1], restored[2], restored[3], restored[4]]) as usize;
        let rplain1 = gunzip_limited(&restored[5..5 + r1_len], MAX_FRAME_LEN).unwrap();
        let rfields = parse_pb_message(&rplain1).unwrap();
        match &rfields[0].value {
            PbValue::LenDelim(b) => {
                assert_eq!(
                    std::str::from_utf8(b).unwrap(),
                    "Use db postgres://admin:TopSecret99@10.0.1.2:5432/prod"
                );
            }
            _ => panic!("expected restored text field"),
        }
        assert_eq!(&restored[5 + r1_len..], end_frame.as_slice());
    }

    #[test]
    fn corrupted_binary_fails_safe_and_passes_through_untouched() {
        let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAB, 0xCD];
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let out = transform_protobuf_outbound(
            ProtobufFraming::Unary,
            &garbage,
            None,
            None,
            TrafficCategory::InteractivePrompt,
            &cfg,
            &vault,
            None,
        );
        assert_eq!(out.vendor_body, garbage);
        assert_eq!(out.action_taken, "protobuf-passed");
    }

    #[test]
    fn incremental_grpc_stream_desensitizer_handles_chunked_and_deflate_frames() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let metrics = Arc::new(parking_lot::Mutex::new(OutboundStreamMetrics::default()));
        let mut des = GrpcStreamDesensitizer::new(
            ProtobufFraming::Grpc,
            Some("deflate".to_string()),
            TrafficCategory::InteractivePrompt,
            cfg,
            vault.clone(),
            Some("harness:antigravity".to_string()),
            metrics.clone(),
        );

        let f1_plain = encode_string_field(1, "First frame with sk-wbefwubfbsrfrsuf");
        let f1 = wrap_envelope(0x01, &zlib_bytes(&f1_plain).unwrap());
        let f2_plain = encode_string_field(1, "Second frame with postgres://u:TopSecret99@10.0.0.5:5432/db");
        let f2 = wrap_envelope(0x00, &f2_plain);

        let mut out_wire = Vec::new();
        for chunk in f1.chunks(5) {
            out_wire.extend(des.push_chunk(chunk));
        }
        // Frame 1 must already have been emitted BEFORE Frame 2 even arrives!
        assert!(!out_wire.is_empty());
        let f1_out_len = u32::from_be_bytes([out_wire[1], out_wire[2], out_wire[3], out_wire[4]]) as usize;
        assert_eq!(out_wire.len(), 5 + f1_out_len);
        let f1_dec = decompress_frame_payload(Some("deflate"), &out_wire[5..], MAX_FRAME_LEN).unwrap();
        assert!(!String::from_utf8_lossy(&f1_dec).contains("sk-wbefwubfbsrfrsuf"));

        let f2_out = des.push_chunk(&f2);
        assert!(!f2_out.is_empty());
        assert!(!String::from_utf8_lossy(&f2_out[5..]).contains("TopSecret99"));
        assert!(des.finish().is_empty());

        let m = metrics.lock();
        assert!(m.mutated);
        assert!(m.findings.len() >= 2);

        // Restore both frames via GrpcStreamRestorer
        let matcher = vault.matcher_for_scope(Some("harness:antigravity"));
        let mut restorer = GrpcStreamRestorer::new(
            ProtobufFraming::Grpc,
            Some("deflate".to_string()),
            Some(matcher),
            ToolCallSecretPolicy::FileEditsOnly,
        );
        let mut restored_wire = restorer.push_chunk(&out_wire);
        restored_wire.extend(restorer.push_chunk(&f2_out));
        restored_wire.extend(restorer.finish());

        let r1_len =
            u32::from_be_bytes([restored_wire[1], restored_wire[2], restored_wire[3], restored_wire[4]]) as usize;
        let r1_dec = decompress_frame_payload(Some("deflate"), &restored_wire[5..5 + r1_len], MAX_FRAME_LEN).unwrap();
        assert!(String::from_utf8_lossy(&r1_dec).contains("sk-wbefwubfbsrfrsuf"));
        let r2_slice = &restored_wire[5 + r1_len..];
        assert!(String::from_utf8_lossy(&r2_slice[5..]).contains("TopSecret99"));
    }
}
