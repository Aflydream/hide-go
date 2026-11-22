use crate::config::{FindingKind, HideConfig, LeakFinding};
use crate::protocol::{is_api_schema_container_key, is_opaque_block, is_structural_key, is_tool_call_object};
use crate::scanner::{
    decode_inline_unicode, is_placeholder_or_template_secret, is_placeholder_token, is_sensitive_secret_key,
    resolve_overlaps, scan_spans_with_scanner, source_span, CompiledScanner, Span,
};
use crate::vault::{
    is_bare_ident_token, is_word_char, mask_preview, reserialize_like, Matcher, PrivacyVault, MAX_JSON_DEPTH,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct DesensitizeResult {
    pub transformed_payload: String,
    pub findings: Vec<LeakFinding>,
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const LOWER_ALNUM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const UPPER_ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

const HOST_ROLES: &[&str] = &[
    "api", "core", "edge", "auth", "sync", "data", "mesh", "node", "gw", "app", "ops", "svc",
];
const FIRST_NAMES: &[&str] = &[
    "alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "quinn", "avery", "drew", "cameron", "devon",
];
const MAIL_DOMAINS: &[&str] = &["mail", "work", "dev", "team", "box", "org"];

struct DesensitizeCtx<'a> {
    raw_payload: &'a str,
    config: &'a HideConfig,
    scanner: &'a CompiledScanner,
    vault: &'a PrivacyVault,
    scope: Option<&'a str>,
    matcher: Option<Arc<Matcher>>,
    findings: &'a mut Vec<LeakFinding>,
    mutated: bool,
}

impl<'a> DesensitizeCtx<'a> {
    fn current_matcher(&mut self) -> Arc<Matcher> {
        if let Some(m) = &self.matcher {
            return m.clone();
        }
        let fresh = self.vault.matcher_for_scope(self.scope);
        self.matcher = Some(fresh.clone());
        fresh
    }

    fn invalidate_matcher(&mut self) {
        self.matcher = None;
    }
}

/// Format-preserving bidirectional semantic desensitizer.
///
/// JSON payloads are walked structurally (protocol identifiers, signed reasoning and binary
/// attachments are left untouched). Every string is rewritten in a single pass over the
/// detected spans, so replacement tokens are never re-scanned and every emitted token is
/// placed where the restorer's boundary rules will find it again.
pub struct SemanticDesensitizer;

impl SemanticDesensitizer {
    pub fn process(payload: &str, config: &HideConfig, vault: &PrivacyVault) -> DesensitizeResult {
        Self::process_with_scope(payload, config, vault, None)
    }

    /// Scope-aware desensitization so each vendor/upstream scope uses isolated
    /// placeholder namespaces and cannot cross-resolve tokens or reflect stored secrets.
    pub fn process_with_scope(
        payload: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
    ) -> DesensitizeResult {
        let mut findings = Vec::new();
        let scanner = CompiledScanner::for_config(config);
        let mut dctx = DesensitizeCtx {
            raw_payload: payload,
            config,
            scanner: &scanner,
            vault,
            scope,
            matcher: None,
            findings: &mut findings,
            mutated: false,
        };
        let trimmed = payload.trim();
        if trimmed.starts_with(['{', '[', '"']) {
            if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                Self::desensitize_json_value_depth(&mut json_val, &mut dctx, 0);
                let transformed_payload = if dctx.mutated || !findings.is_empty() {
                    reserialize_like(trimmed, &json_val)
                } else {
                    payload.to_string()
                };
                return DesensitizeResult {
                    transformed_payload,
                    findings,
                };
            }
        }
        let transformed = Self::desensitize_text_ctx(payload, &mut dctx);
        DesensitizeResult {
            transformed_payload: transformed,
            findings,
        }
    }

    fn desensitize_json_value_depth(val: &mut Value, dctx: &mut DesensitizeCtx<'_>, depth: usize) {
        if depth >= MAX_JSON_DEPTH {
            if let Value::String(s) = val {
                let next = Self::desensitize_text_ctx(s, dctx);
                if next != *s {
                    dctx.mutated = true;
                    *s = next;
                }
            }
            return;
        }
        match val {
            Value::Object(map) => {
                if is_opaque_block(map) {
                    // Signed thinking echoed back by the harness was restored on the way in;
                    // reseal it so it matches its signature again.
                    if map.get("type").and_then(Value::as_str) == Some("thinking") {
                        if let Some(Value::String(t)) = map.get_mut("thinking") {
                            let matcher = dctx.current_matcher();
                            let resealed = matcher.reseal(t);
                            if resealed != *t {
                                dctx.mutated = true;
                                *t = resealed;
                            }
                        }
                    } else if map.get("thought").and_then(Value::as_bool) == Some(true)
                        && (map.contains_key("thoughtSignature") || map.contains_key("thought_signature"))
                    {
                        if let Some(Value::String(t)) = map.get_mut("text") {
                            let matcher = dctx.current_matcher();
                            let resealed = matcher.reseal(t);
                            if resealed != *t {
                                dctx.mutated = true;
                                *t = resealed;
                            }
                        }
                    }
                    return;
                }
                let tool_call = is_tool_call_object(map);
                let protect_secrets = dctx.config.protect_secrets_and_keys;
                for (key, mut value) in std::mem::take(map) {
                    if is_api_schema_container_key(&key)
                        || (is_structural_key(&key) && value.is_string())
                        || (tool_call && key == "name" && value.is_string())
                    {
                        map.insert(key, value);
                        continue;
                    }
                    let sensitive_field = protect_secrets && is_sensitive_secret_key(&key);
                    let new_key = Self::desensitize_text_ctx(&key, dctx);
                    if new_key != key {
                        dctx.mutated = true;
                    }
                    let key = new_key;
                    let secret = match &value {
                        Value::String(raw)
                            if sensitive_field
                                && !raw.trim().is_empty()
                                && !is_placeholder_token(raw)
                                && !is_placeholder_or_template_secret(raw)
                                && !dctx.vault.contains_token_in_scope(raw, dctx.scope)
                                && (!key.eq_ignore_ascii_case("token") || raw.trim().len() >= 6) =>
                        {
                            Some(raw.clone())
                        }
                        Value::Number(_) if sensitive_field && !key.eq_ignore_ascii_case("token") => {
                            Some(value.to_string())
                        }
                        _ => None,
                    };
                    if let Some(raw) = secret {
                        let token = Self::register_finding_token(
                            FindingKind::EnvSecret,
                            "Environment / Config Secret",
                            &raw,
                            "high",
                            1,
                            Some(&value),
                            dctx,
                        );
                        dctx.mutated = true;
                        value = Value::String(token);
                    } else {
                        Self::desensitize_json_value_depth(&mut value, dctx, depth + 1);
                    }
                    map.insert(key, value);
                }
            }
            Value::Array(arr) => arr
                .iter_mut()
                .for_each(|item| Self::desensitize_json_value_depth(item, dctx, depth + 1)),
            Value::String(s) => {
                let st = s.trim();
                if st.starts_with(['{', '[']) && depth + 1 < MAX_JSON_DEPTH {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(st) {
                        let prev_mutated = dctx.mutated;
                        dctx.mutated = false;
                        Self::desensitize_json_value_depth(&mut inner, dctx, depth + 1);
                        let inner_mutated = dctx.mutated;
                        dctx.mutated = prev_mutated || inner_mutated;
                        if inner_mutated {
                            *s = reserialize_like(st, &inner);
                        }
                        return;
                    }
                }
                let next = Self::desensitize_text_ctx(s, dctx);
                if next != *s {
                    dctx.mutated = true;
                    *s = next;
                }
            }
            _ => {}
        }
    }

    fn desensitize_text_ctx(text: &str, dctx: &mut DesensitizeCtx<'_>) -> String {
        if text.len() < 3 && dctx.scanner.custom_rules.is_empty() {
            return text.to_string();
        }
        // Detect on the `\uXXXX`-decoded view, but rewrite the untouched source text.
        let decoded = decode_inline_unicode(text);
        let mut spans: Vec<Span> = match &decoded {
            Some(d) => scan_spans_with_scanner(&d.text, dctx.config, dctx.scanner)
                .into_iter()
                .map(|mut s| {
                    (s.start, s.end) = source_span(d, s.start, s.end, text);
                    s
                })
                .collect(),
            None => scan_spans_with_scanner(text, dctx.config, dctx.scanner),
        };
        let existing = dctx.current_matcher().token_ranges(text);
        let (after_regex, did_replace_spans) = if spans.is_empty() {
            (text.to_string(), false)
        } else {
            spans.retain(|s| !existing.iter().any(|&(a, b)| s.start < b && a < s.end));
            for span in &mut spans {
                Self::extend_to_token_boundary(text, span, dctx.config);
            }
            spans.retain(|s| !existing.iter().any(|&(a, b)| s.start < b && a < s.end));

            let mut out = String::with_capacity(text.len());
            let mut last = 0;
            let mut replaced_any = false;
            for span in resolve_overlaps(spans) {
                let raw = &text[span.start..span.end];
                if raw.len() < 3 {
                    continue;
                }
                let token = Self::register_finding_token(span.kind, &span.label, raw, &span.severity, 1, None, dctx);
                out.push_str(&text[last..span.start]);
                out.push_str(&token);
                last = span.end;
                replaced_any = true;
            }
            out.push_str(&text[last..]);
            (out, replaced_any)
        };

        let matcher = dctx.current_matcher();
        let remask_existing = if did_replace_spans {
            matcher.token_ranges(&after_regex)
        } else {
            existing
        };
        let (remasked, remask_hits) = matcher.remask_secrets(&after_regex, &remask_existing);
        if did_replace_spans || !remask_hits.is_empty() {
            dctx.mutated = true;
        }
        for (raw_secret, token, count) in remask_hits {
            Self::record_finding(
                dctx.findings,
                FindingKind::EnvSecret,
                "Previously Seen Scope Secret",
                &raw_secret,
                &token,
                "high",
                count,
            );
        }
        remasked
    }

    fn record_finding(
        findings: &mut Vec<LeakFinding>,
        kind: FindingKind,
        label: &str,
        raw_val: &str,
        replacement_token: &str,
        severity: &str,
        occurrences: usize,
    ) {
        if let Some(existing) = findings.iter_mut().find(|f| f.replacement_token == replacement_token) {
            existing.count += occurrences;
        } else {
            findings.push(LeakFinding {
                kind,
                label: label.to_string(),
                original_preview: mask_preview(raw_val),
                replacement_token: replacement_token.to_string(),
                severity: severity.to_string(),
                count: occurrences,
            });
        }
    }

    /// A match glued to identifier characters (`ProjectTitanConfig`) would produce a token the
    /// restorer refuses to match. Mask the whole enclosing identifier instead.
    fn extend_to_token_boundary(text: &str, span: &mut Span, config: &HideConfig) {
        let raw = &text[span.start..span.end];
        let sample = Self::format_token(span.kind, raw, &[0u8; 32], config);
        if !is_bare_ident_token(&sample) {
            return;
        }
        while let Some(ch) = text[..span.start].chars().next_back().filter(|&c| is_word_char(c)) {
            span.start -= ch.len_utf8();
        }
        while let Some(ch) = text[span.end..].chars().next().filter(|&c| is_word_char(c)) {
            span.end += ch.len_utf8();
        }
    }

    fn register_finding_token(
        kind: FindingKind,
        label: &str,
        raw_val: &str,
        severity: &str,
        occurrences: usize,
        json_value: Option<&Value>,
        dctx: &mut DesensitizeCtx<'_>,
    ) -> String {
        let category_key = format!("{:?}", kind);
        let domain = format!("sem:{kind:?}");
        let vault = dctx.vault;
        let config = dctx.config;
        let scope = dctx.scope;
        let raw_payload = dctx.raw_payload;

        let generator = |attempt: usize| -> String {
            // Skip any candidate that already appears verbatim in the inbound payload.
            for sub in 0..8usize {
                let effective_attempt = attempt.saturating_mul(8).saturating_add(sub);
                let digest = vault.keyed_bytes(&domain, scope, &config.project_salt, raw_val, effective_attempt);
                let token = Self::format_token(kind, raw_val, &digest, config);
                if !raw_payload.contains(token.as_str()) {
                    return token;
                }
            }
            let digest = vault.keyed_bytes("sem:fallback", scope, &config.project_salt, raw_val, attempt + 1024);
            format!("tok_{}", encode_from_digest(&digest, 24, BASE62, b"fb"))
        };

        let (replacement_token, inserted_new) = match json_value {
            Some(value) => vault.get_or_insert_json_value_scoped_unique(scope, value, &category_key, generator),
            None => vault.get_or_insert_scoped_unique(scope, raw_val, &category_key, generator),
        };
        let mut alias_inserted = false;
        if kind == FindingKind::ProjectPath {
            alias_inserted =
                register_windows_path_restore_aliases(vault, scope, raw_val, &replacement_token, &category_key);
        }
        if inserted_new || alias_inserted {
            dctx.invalidate_matcher();
        }

        Self::record_finding(
            dctx.findings,
            kind,
            label,
            raw_val,
            &replacement_token,
            severity,
            occurrences,
        );
        replacement_token
    }

    /// Generate a deterministic format-preserving placeholder using HMAC/SHA-256 keyed material.
    pub fn generate_semantic_token(kind: FindingKind, raw_val: &str, idx: usize, config: &HideConfig) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"hide-go-preview:");
        hasher.update(config.project_salt.as_bytes());
        hasher.update(b":");
        hasher.update(raw_val.as_bytes());
        hasher.update(idx.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        Self::format_token(kind, raw_val, &digest, config)
    }

    fn format_token(kind: FindingKind, raw_val: &str, digest: &[u8; 32], config: &HideConfig) -> String {
        match kind {
            FindingKind::ApiKey => format_api_key_token(raw_val, digest),
            FindingKind::PrivateKey => format!("key_ref_{}", encode_from_digest(digest, 20, BASE62, b"pk")),
            FindingKind::DatabaseUrl => {
                let scheme = raw_val.split("://").next().unwrap_or("postgres");
                let port = match scheme.to_ascii_lowercase().as_str() {
                    "mysql" | "mariadb" => 3306,
                    "mongodb" | "mongodb+srv" => 27017,
                    "redis" | "rediss" => 6379,
                    "amqp" | "amqps" => 5672,
                    "mssql" | "sqlserver" => 1433,
                    "clickhouse" => 8123,
                    "http" => 80,
                    "https" => 443,
                    _ => 5432,
                };
                let user_tag = encode_from_digest(digest, 6, LOWER_ALNUM, b"du");
                let pass_tag = encode_from_digest(digest, 14, BASE62, b"dp");
                let host_tag = encode_from_digest(digest, 6, LOWER_ALNUM, b"dh");
                let db_tag = encode_from_digest(digest, 5, LOWER_ALNUM, b"dn");
                let role = HOST_ROLES[(digest[0] as usize) % HOST_ROLES.len()];
                format!("{scheme}://svc_{user_tag}:{pass_tag}@{role}-{host_tag}.db.example:{port}/app_{db_tag}")
            }
            FindingKind::InternalIp => {
                let mut raw_u64 = [0u8; 8];
                raw_u64.copy_from_slice(&digest[..8]);
                benchmark_ip_keyed(u64::from_le_bytes(raw_u64))
            }
            FindingKind::InternalDomain => {
                let role = HOST_ROLES[(digest[0] as usize) % HOST_ROLES.len()];
                let tld = if digest[1] & 1 == 0 { "example" } else { "test" };
                let host_tag = encode_from_digest(digest, 6, LOWER_ALNUM, b"id");
                format!("{role}-{host_tag}.{tld}")
            }
            FindingKind::ProjectPath => {
                let mut dir_tag = encode_from_digest(digest, 8, LOWER_ALNUM, b"pp");
                if !dir_tag.bytes().any(|b| b.is_ascii_digit()) {
                    dir_tag.pop();
                    dir_tag.push((b'0' + (digest[30] % 10)) as char);
                } else if !dir_tag.bytes().any(|b| b.is_ascii_lowercase()) {
                    dir_tag.pop();
                    dir_tag.push((b'a' + (digest[31] % 26)) as char);
                }
                if let Some(drive) = raw_val
                    .chars()
                    .next()
                    .filter(|_| raw_val.as_bytes().get(1) == Some(&b':'))
                {
                    let sep = if raw_val.contains("\\\\") {
                        "\\\\"
                    } else if raw_val.contains('/') {
                        "/"
                    } else {
                        "\\"
                    };
                    format!("{drive}:{sep}work{sep}{dir_tag}")
                } else {
                    format!("/opt/work/{dir_tag}")
                }
            }
            FindingKind::EmailOrPii => {
                let first = FIRST_NAMES[(digest[0] as usize) % FIRST_NAMES.len()];
                let domain = MAIL_DOMAINS[(digest[1] as usize) % MAIL_DOMAINS.len()];
                let tag6 = encode_from_digest(digest, 6, LOWER_ALNUM, b"em");
                format!("{first}.{tag6}@{domain}.example")
            }
            FindingKind::GitMetadata => format!("ref_{}", encode_from_digest(digest, 10, LOWER_ALNUM, b"gm")),
            FindingKind::EnvSecret => format!("sec_{}", encode_from_digest(digest, 18, BASE62, b"es")),
            FindingKind::CustomKeyword => {
                for rule in config
                    .custom_rules
                    .iter()
                    .filter(|r| r.enabled && !r.replacement_hint.trim().is_empty())
                {
                    if crate::scanner::compile_custom_regex(&rule.pattern).is_ok_and(|re| re.is_match(raw_val)) {
                        let hint = rule.replacement_hint.trim();
                        let tag = encode_from_digest(digest, 8, LOWER_ALNUM, b"ck");
                        if let Some((first_label, rest)) = hint.split_once('.') {
                            return format!("{first_label}-{tag}.{rest}");
                        }
                        return format!("{hint}_{tag}");
                    }
                }
                format!("ref_{}", encode_from_digest(digest, 10, LOWER_ALNUM, b"cr"))
            }
            FindingKind::ProprietaryCodeSymbol => {
                format!("sym_{}", encode_from_digest(digest, 10, LOWER_ALNUM, b"cs"))
            }
        }
    }
}

fn register_windows_path_restore_aliases(
    vault: &PrivacyVault,
    scope: Option<&str>,
    raw_val: &str,
    token: &str,
    category: &str,
) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return false;
    }
    if raw_val.len() < 3 || !raw_val.as_bytes()[0].is_ascii_alphabetic() || raw_val.as_bytes()[1] != b':' {
        return false;
    }
    let drive = bytes[0] as char;
    let alt_drive = if drive.is_ascii_uppercase() {
        drive.to_ascii_lowercase()
    } else {
        drive.to_ascii_uppercase()
    };
    let tok_rest = &token[2..];
    let raw_rest = &raw_val[2..];
    let tok_slash = tok_rest.replace("\\\\", "/").replace('\\', "/");
    let raw_slash = raw_rest.replace("\\\\", "/").replace('\\', "/");
    let tok_back = tok_slash.replace('/', "\\");
    let raw_back = raw_slash.replace('/', "\\");
    let tok_dback = tok_slash.replace('/', "\\\\");
    let raw_dback = raw_slash.replace('/', "\\\\");

    let mut inserted = false;
    for d in [drive, alt_drive] {
        for (t_body, r_body) in [
            (&tok_slash, &raw_slash),
            (&tok_back, &raw_back),
            (&tok_dback, &raw_dback),
        ] {
            let alias_tok = format!("{d}:{t_body}");
            if alias_tok == token {
                continue;
            }
            let alias_real = format!("{d}:{r_body}");
            if vault.register_restore_alias_scoped(scope, &alias_tok, &alias_real, category) {
                inserted = true;
            }
        }
    }
    inserted
}

fn format_api_key_token(raw_val: &str, digest: &[u8; 32]) -> String {
    if raw_val.starts_with("sk-ant-") {
        format!("sk-ant-api03-{}", encode_from_digest(digest, 24, BASE62, b"ak"))
    } else if raw_val.starts_with("sk-proj-") {
        format!("sk-proj-{}", encode_from_digest(digest, 24, BASE62, b"ak"))
    } else if raw_val.starts_with("sk_live_") || raw_val.starts_with("sk_test_") {
        format!("sk_test_{}", encode_from_digest(digest, 24, BASE62, b"ak"))
    } else if raw_val.starts_with("rk_live_") || raw_val.starts_with("rk_test_") {
        format!("rk_test_{}", encode_from_digest(digest, 24, BASE62, b"ak"))
    } else if raw_val.starts_with("sk-") {
        format!("sk-{}", encode_from_digest(digest, 28, BASE62, b"ak"))
    } else if raw_val.starts_with("github_pat_") {
        format!(
            "github_pat_{}_{}",
            encode_from_digest(digest, 22, BASE62, b"gp1"),
            encode_from_digest(digest, 24, BASE62, b"gp2")
        )
    } else if raw_val.starts_with("ghp_")
        || raw_val.starts_with("gho_")
        || raw_val.starts_with("ghu_")
        || raw_val.starts_with("ghs_")
        || raw_val.starts_with("ghr_")
    {
        let prefix = &raw_val[..4];
        format!("{prefix}{}", encode_from_digest(digest, 36, BASE62, b"gh"))
    } else if let Some(prefix) = ["glpat-", "glrt-", "glptt-", "gloass-"]
        .into_iter()
        .find(|p| raw_val.starts_with(p))
    {
        format!("{prefix}{}", encode_from_digest(digest, 20, BASE62, b"gl"))
    } else if raw_val.starts_with("AKIA") || raw_val.starts_with("ASIA") {
        format!("AKIA{}", encode_from_digest(digest, 16, UPPER_ALNUM, b"aw"))
    } else if raw_val.starts_with("AIza") {
        format!("AIza{}", encode_from_digest(digest, 35, BASE62, b"gg"))
    } else if raw_val.starts_with("xoxb-")
        || raw_val.starts_with("xoxp-")
        || raw_val.starts_with("xoxa-")
        || raw_val.starts_with("xoxr-")
        || raw_val.starts_with("xoxs-")
    {
        let prefix = &raw_val[..5];
        format!(
            "{prefix}{}-{}-{}",
            encode_from_digest(digest, 10, DIGITS, b"sx1"),
            encode_from_digest(digest, 10, DIGITS, b"sx2"),
            encode_from_digest(digest, 24, BASE62, b"sx3")
        )
    } else if raw_val.starts_with("hf_") {
        format!("hf_{}", encode_from_digest(digest, 30, BASE62, b"hf"))
    } else if raw_val.starts_with("npm_") {
        format!("npm_{}", encode_from_digest(digest, 36, BASE62, b"np"))
    } else if raw_val.starts_with("pypi-") {
        format!("pypi-AgEI{}", encode_from_digest(digest, 36, BASE62, b"py"))
    } else if raw_val.starts_with("gsk_") {
        format!("gsk_{}", encode_from_digest(digest, 24, BASE62, b"gs"))
    } else if raw_val.starts_with("pplx-") {
        format!("pplx-{}", encode_from_digest(digest, 28, BASE62, b"px"))
    } else if raw_val.starts_with("r8_") {
        format!("r8_{}", encode_from_digest(digest, 28, BASE62, b"r8"))
    } else if raw_val.starts_with("SG.") {
        format!(
            "SG.{}.{}",
            encode_from_digest(digest, 16, BASE62, b"sg1"),
            encode_from_digest(digest, 20, BASE62, b"sg2")
        )
    } else if raw_val.starts_with("LTAI") {
        format!("LTAI{}", encode_from_digest(digest, 20, BASE62, b"al"))
    } else if raw_val.starts_with("AKID") {
        format!("AKID{}", encode_from_digest(digest, 32, BASE62, b"tc"))
    } else if raw_val.starts_with("xai-") {
        format!("xai-{}", encode_from_digest(digest, 28, BASE62, b"xa"))
    } else if raw_val.starts_with("eyJ") {
        format!(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ{}In0.{}",
            encode_from_digest(digest, 16, BASE62, b"jw1"),
            encode_from_digest(digest, 24, BASE62, b"jw2")
        )
    } else if raw_val.starts_with("https://hooks.slack.com/") {
        format!(
            "https://hooks.slack.com/services/T{}/B{}/{}",
            encode_from_digest(digest, 8, UPPER_ALNUM, b"wh1"),
            encode_from_digest(digest, 8, UPPER_ALNUM, b"wh2"),
            encode_from_digest(digest, 24, BASE62, b"wh3")
        )
    } else if raw_val.starts_with("https://") {
        format!(
            "https://webhook.example/hook/{}",
            encode_from_digest(digest, 24, BASE62, b"wb")
        )
    } else {
        format!("tok_{}", encode_from_digest(digest, 24, BASE62, b"ak"))
    }
}

fn encode_from_digest(digest: &[u8; 32], len: usize, alphabet: &[u8], domain_tag: &[u8]) -> String {
    let mut out = String::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(domain_tag);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        for &b in block.as_slice() {
            if out.len() >= len {
                break;
            }
            out.push(alphabet[(b as usize) % alphabet.len()] as char);
        }
        counter += 1;
    }
    out
}

/// Map a keyed 64-bit value onto 198.18.0.0/15 (RFC 2544), skipping .0 and .255 host octets.
fn benchmark_ip_keyed(keyed: u64) -> String {
    let host = (keyed % 254) + 1;
    let third = (keyed >> 8) % 256;
    let second = 18 + ((keyed >> 16) % 2);
    format!("198.{second}.{third}.{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(input: &str) -> (String, String) {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let out = SemanticDesensitizer::process(input, &cfg, &vault).transformed_payload;
        let restored = vault.restore_text(&out).0;
        (out, restored)
    }

    #[test]
    fn kebab_case_words_are_not_api_keys() {
        let input = "Rename the crate risk-assessment-engine-v2 please";
        assert_eq!(roundtrip(input), (input.to_string(), input.to_string()));
    }

    #[test]
    fn codename_inside_identifier_masks_whole_identifier_and_restores() {
        let (out, restored) = roundtrip("struct ProjectTitanConfig { retries: u8 }");
        assert!(!out.contains("Titan"), "{out}");
        assert_eq!(restored, "struct ProjectTitanConfig { retries: u8 }");
    }

    #[test]
    fn real_value_in_placeholder_namespace_does_not_merge() {
        let input = "primary=10.200.200.200 backup=10.254.100.2 dr=198.18.0.1";
        let (out, restored) = roundtrip(input);
        assert!(
            !out.contains("10.200.200.200") && !out.contains("10.254.100.2"),
            "{out}"
        );
        assert_eq!(restored, input);
    }

    #[test]
    fn unicode_escapes_outside_matches_are_preserved() {
        let input = "let s = \"\\u0041\"; let k = \"\\u0073k-ant-api03-abcdefghijklmnop1234\";";
        let (out, restored) = roundtrip(input);
        assert!(
            out.contains("\\u0041") && !out.contains("abcdefghijklmnop1234"),
            "{out}"
        );
        assert_eq!(restored, input);
    }

    #[test]
    fn paths_keep_structure_and_new_children_restore() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let input = "cwd: /home/alice/titan\nfiles: /home/alice/titan/src/a.rs C:\\Users\\alice\\titan\\b.rs";
        let out = SemanticDesensitizer::process(input, &cfg, &vault).transformed_payload;
        assert!(
            !out.contains("/home/alice") && !out.contains("C:\\Users\\alice"),
            "{out}"
        );
        assert!(out.contains("/opt/work/") && out.contains("\\work\\"), "{out}");
        let unix_prefix = out
            .lines()
            .next()
            .unwrap()
            .trim_start_matches("cwd: ")
            .trim_end_matches("/titan");
        let reply = format!("Created {unix_prefix}/titan/src/new_module.rs");
        assert_eq!(
            vault.restore_text(&reply).0,
            "Created /home/alice/titan/src/new_module.rs"
        );
    }

    #[test]
    fn thinking_blocks_and_ids_are_byte_exact() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let body = serde_json::json!({"messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": "host 10.0.0.5", "signature": "sig=="},
            {"type": "tool_use", "id": "toolu_10.0.0.5", "name": "Bash", "input": {"command": "ssh 10.0.0.5"}}
        ]}]});
        let out: Value =
            serde_json::from_str(&SemanticDesensitizer::process(&body.to_string(), &cfg, &vault).transformed_payload)
                .unwrap();
        assert_eq!(out["messages"][0]["content"][0], body["messages"][0]["content"][0]);
        assert_eq!(out["messages"][0]["content"][1]["id"], "toolu_10.0.0.5");
        let cmd = out["messages"][0]["content"][1]["input"]["command"].as_str().unwrap();
        assert!(
            cmd.starts_with("ssh 198.18.") || cmd.starts_with("ssh 198.19."),
            "{cmd}"
        );
        assert!(!cmd.contains("10.0.0.5"), "{cmd}");
    }

    #[test]
    fn restored_thinking_is_resealed_to_the_signed_text() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        // Turn 1: the user's IP is masked; the model thinks about the placeholder.
        let masked_ip = SemanticDesensitizer::process("ssh 10.0.0.5", &cfg, &vault)
            .transformed_payload
            .trim_start_matches("ssh ")
            .to_string();
        let signed_thinking = format!("connect to {masked_ip} first");
        // The harness shows (and sends back) the restored thinking.
        let restored = vault.restore_plain_text(&signed_thinking).0;
        assert_eq!(restored, "connect to 10.0.0.5 first");
        let body = serde_json::json!({"messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": restored, "signature": "sig"}]}]});
        let out: Value =
            serde_json::from_str(&SemanticDesensitizer::process(&body.to_string(), &cfg, &vault).transformed_payload)
                .unwrap();
        assert_eq!(out["messages"][0]["content"][0]["thinking"], signed_thinking);
    }

    #[test]
    fn scopes_isolate_placeholders_and_remask_known_secrets() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let secret_payload = serde_json::json!({"client_secret": "very-secret-nonregex-value"}).to_string();
        let masked_a = SemanticDesensitizer::process_with_scope(&secret_payload, &cfg, &vault, Some("vendor-a"))
            .transformed_payload;
        let tok_a: Value = serde_json::from_str(&masked_a).unwrap();
        let placeholder_a = tok_a["client_secret"].as_str().unwrap();

        // Scope B must neither restore Scope A's token nor leave Scope B's own secret exposed later.
        assert_eq!(
            vault
                .matcher_for_scope(Some("vendor-b"))
                .restore(placeholder_a, None, true)
                .0,
            placeholder_a
        );
        let plain_echo = "Oops, my secret is very-secret-nonregex-value";
        let masked_plain =
            SemanticDesensitizer::process_with_scope(plain_echo, &cfg, &vault, Some("vendor-a")).transformed_payload;
        assert!(!masked_plain.contains("very-secret-nonregex-value"), "{masked_plain}");
        assert!(masked_plain.contains(placeholder_a), "{masked_plain}");
    }

    #[test]
    fn deep_json_does_not_overflow_stack() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let mut payload = String::new();
        for _ in 0..110 {
            payload.push_str("{\"a\":");
        }
        payload.push_str("\"10.0.0.1\"");
        for _ in 0..110 {
            payload.push('}');
        }
        let res = SemanticDesensitizer::process(&payload, &cfg, &vault);
        assert!(!res.transformed_payload.is_empty());
    }

    #[test]
    fn prefixed_camel_case_secrets_bcrypt_db_ports_and_remask_findings_work() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let scope = Some("claude-code:api.anthropic.com");

        let json_req = serde_json::json!({
            "stripeWebhookSecret": "whsec_real_secret_value_12345",
            "nextPageToken": "cursor_not_a_secret",
            "maxToken": 4096,
            "token": 42,
            "password": "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
            "db": "mysql://dbadmin:MySqlPass99@10.0.0.12:3306/orders",
            "win_fwd": "C:/Users/alice/my-repo/src/main.rs"
        })
        .to_string();

        let res = SemanticDesensitizer::process_with_scope(&json_req, &cfg, &vault, scope);
        let parsed: Value = serde_json::from_str(&res.transformed_payload).unwrap();
        assert_eq!(parsed["nextPageToken"], "cursor_not_a_secret");
        assert_eq!(parsed["maxToken"], 4096);
        assert_eq!(parsed["token"], 42);
        assert_ne!(parsed["stripeWebhookSecret"], "whsec_real_secret_value_12345");
        assert_ne!(
            parsed["password"],
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
        );
        let masked_db = parsed["db"].as_str().unwrap();
        assert!(
            masked_db.starts_with("mysql://") && masked_db.contains(":3306/"),
            "{masked_db}"
        );
        let masked_win = parsed["win_fwd"].as_str().unwrap();
        assert!(masked_win.starts_with("C:/work/") && masked_win.ends_with("/my-repo/src/main.rs"));

        let restored = vault
            .matcher_for_scope(scope)
            .restore_document(&res.transformed_payload, true)
            .0;
        let restored_val: Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(restored_val["stripeWebhookSecret"], "whsec_real_secret_value_12345");
        assert_eq!(
            restored_val["password"],
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
        );
        assert_eq!(restored_val["win_fwd"], "C:/Users/alice/my-repo/src/main.rs");

        // Plain-text reappearance records an audit finding and preserves boundary safety
        let followup =
            SemanticDesensitizer::process_with_scope("Repeat whsec_real_secret_value_12345 now", &cfg, &vault, scope);
        assert!(!followup.transformed_payload.contains("whsec_real_secret_value_12345"));
        assert!(!followup.findings.is_empty());
    }

    #[test]
    fn keyed_tokens_isolate_across_vaults_and_roundtrip_cleanly() {
        let cfg = HideConfig::default();
        let join = |a: &str, b: &str| format!("{a}{b}");
        let sample = format!(
            "key={} ghp={} mail=alice@internal-ops.corp db=postgres://admin:RealPass99@10.20.30.40:5432/prod dom=auth.corp.internal path=/home/alice/app",
            join("sk-ant-api03-", "RealSecretValue0123456789"),
            join("ghp_", "0123456789abcdef0123456789abcdef1234"),
        );

        let v1 = PrivacyVault::new();
        let v2 = PrivacyVault::new();
        let out1 = SemanticDesensitizer::process_with_scope(&sample, &cfg, &v1, Some("harness:claude-code"))
            .transformed_payload;
        let out2 = SemanticDesensitizer::process_with_scope(&sample, &cfg, &v2, Some("harness:claude-code"))
            .transformed_payload;
        let out_other_scope =
            SemanticDesensitizer::process_with_scope(&sample, &cfg, &v1, Some("harness:codex")).transformed_payload;

        for marker in [
            "sk-sem-",
            "HIDE_",
            "placeholder",
            "svc-node-",
            "/workspace/user_",
            "dev_member_",
            "RealSecretValue0123456789",
            "RealPass99",
            "alice@internal-ops.corp",
            "10.20.30.40",
        ] {
            assert!(!out1.contains(marker), "found marker {marker} in {out1}");
        }
        assert_ne!(out1, out2, "distinct ephemeral vault keys must produce distinct tokens");
        assert_ne!(out1, out_other_scope, "distinct scopes must produce distinct tokens");

        // Double-pass inside the same vault must be 100% idempotent
        let second = SemanticDesensitizer::process_with_scope(&out1, &cfg, &v1, Some("harness:claude-code"));
        assert!(
            second.findings.is_empty(),
            "unexpected findings on second pass: {:?}",
            second.findings
        );
        assert_eq!(second.transformed_payload, out1);

        // Full roundtrip restoration
        let restored = v1
            .matcher_for_scope(Some("harness:claude-code"))
            .restore(&out1, None, true)
            .0;
        assert_eq!(restored, sample);
    }

    #[test]
    fn untouched_json_stays_byte_identical_and_cloud_code_fields_and_path_aliases_work() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();

        // 1. Clean JSON with non-alphabetical keys stays byte-identical (no key sorting churn)
        let clean = r#"{"z_key":1,"a_key":"hello world"}"#;
        let clean_res = SemanticDesensitizer::process_with_scope(clean, &cfg, &vault, Some("harness:antigravity"));
        assert!(clean_res.findings.is_empty());
        assert_eq!(clean_res.transformed_payload, clean);

        // 2. Cloud Code envelope preserves `project`, `requestId`, `functionCall.name`, and reseals signed thoughts
        vault.insert_explicit("sk-real-key-9876543210", "sk-masked-token-112233", "ApiKey");
        let cc_req = r#"{"project":"my-internal.corp.internal","requestId":"req-123","request":{"contents":[{"role":"model","parts":[{"thought":true,"text":"considering sk-real-key-9876543210","thoughtSignature":"sig-xyz"},{"functionCall":{"name":"write_file","args":{"path":"E:\\Aflydream\\1AI\\hidegoqo\\src\\main.rs"}}}]}]}}"#;
        let cc_res = SemanticDesensitizer::process_with_scope(cc_req, &cfg, &vault, None);
        let parsed: Value = serde_json::from_str(&cc_res.transformed_payload).unwrap();
        assert_eq!(parsed["project"], "my-internal.corp.internal");
        assert_eq!(parsed["requestId"], "req-123");
        assert_eq!(
            parsed["request"]["contents"][0]["parts"][0]["text"],
            "considering sk-masked-token-112233"
        );
        assert_eq!(
            parsed["request"]["contents"][0]["parts"][1]["functionCall"]["name"],
            "write_file"
        );
        let masked_path = parsed["request"]["contents"][0]["parts"][1]["functionCall"]["args"]["path"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!masked_path.contains("Aflydream"), "masked_path={masked_path}");

        // 3. Restoring Windows path works across `/` and lowercase drive letter variants!
        let slash_variant = masked_path.replace('\\', "/").replacen("E:", "e:", 1);
        let m = vault.matcher();
        assert_eq!(
            m.restore(&slash_variant, None, true).0,
            "e:/Aflydream/1AI/hidegoqo/src/main.rs"
        );

        // 4. Generated `work/<tag>` placeholder is recognized even in a fresh vault (no double-masking)
        let fresh_vault = PrivacyVault::new();
        let rescan = SemanticDesensitizer::process_with_scope(&masked_path, &cfg, &fresh_vault, None);
        assert!(
            rescan.findings.is_empty(),
            "placeholder path must not double-mask: {:?}",
            rescan.findings
        );
    }
}
