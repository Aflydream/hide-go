use crate::config::{FindingKind, HideConfig, LeakFinding};
use crate::protocol::{is_api_schema_container_key, is_opaque_block, is_structural_key, is_tool_call_object};
use crate::scanner::{
    compile_custom_regex, decode_inline_unicode, is_placeholder_token, is_sensitive_secret_key, resolve_overlaps,
    scan_spans, source_span, Span,
};
use crate::vault::{is_bare_ident_token, is_word_char, mask_preview, reserialize_like, PrivacyVault};
use serde_json::Value;

pub struct DesensitizeResult {
    pub transformed_payload: String,
    pub findings: Vec<LeakFinding>,
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
        let mut findings = Vec::new();
        let trimmed = payload.trim();
        if trimmed.starts_with(['{', '[', '"']) {
            if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                Self::desensitize_json_value(&mut json_val, payload, config, vault, &mut findings);
                return DesensitizeResult {
                    transformed_payload: reserialize_like(trimmed, &json_val),
                    findings,
                };
            }
        }
        let transformed = Self::desensitize_text(payload, payload, config, vault, &mut findings);
        DesensitizeResult {
            transformed_payload: transformed,
            findings,
        }
    }

    pub(crate) fn desensitize_json_value(
        val: &mut Value,
        ctx: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        findings: &mut Vec<LeakFinding>,
    ) {
        match val {
            Value::Object(map) => {
                if is_opaque_block(map) {
                    // Signed thinking echoed back by the harness was restored on the way in;
                    // reseal it so it matches its signature again.
                    if map.get("type").and_then(Value::as_str) == Some("thinking") {
                        if let Some(Value::String(t)) = map.get_mut("thinking") {
                            *t = vault.matcher().reseal(t);
                        }
                    }
                    return;
                }
                let tool_call = is_tool_call_object(map);
                for (key, mut value) in std::mem::take(map) {
                    if is_api_schema_container_key(&key)
                        || (is_structural_key(&key) && value.is_string())
                        || (tool_call && key == "name" && value.is_string())
                    {
                        map.insert(key, value);
                        continue;
                    }
                    let sensitive_field = config.protect_secrets_and_keys && is_sensitive_secret_key(&key);
                    let key = Self::desensitize_text(&key, ctx, config, vault, findings);
                    let secret = match &value {
                        Value::String(raw)
                            if sensitive_field && !raw.trim().is_empty() && !is_placeholder_token(raw) =>
                        {
                            Some(raw.clone())
                        }
                        Value::Number(_) | Value::Bool(_) if sensitive_field => Some(value.to_string()),
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
                            ctx,
                            config,
                            vault,
                            findings,
                        );
                        value = Value::String(token);
                    } else {
                        Self::desensitize_json_value(&mut value, ctx, config, vault, findings);
                    }
                    map.insert(key, value);
                }
            }
            Value::Array(arr) => arr
                .iter_mut()
                .for_each(|item| Self::desensitize_json_value(item, ctx, config, vault, findings)),
            Value::String(s) => {
                let st = s.trim();
                if st.starts_with(['{', '[']) {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(st) {
                        Self::desensitize_json_value(&mut inner, ctx, config, vault, findings);
                        *s = reserialize_like(st, &inner);
                        return;
                    }
                }
                *s = Self::desensitize_text(s, ctx, config, vault, findings);
            }
            _ => {}
        }
    }

    /// Mask one plain-text string in a single pass.
    pub(crate) fn desensitize_text(
        text: &str,
        ctx: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        findings: &mut Vec<LeakFinding>,
    ) -> String {
        if text.len() < 3 {
            return text.to_string();
        }
        // Detect on the `\uXXXX`-decoded view, but rewrite the untouched source text.
        let decoded = decode_inline_unicode(text);
        let mut spans: Vec<Span> = match &decoded {
            Some(d) => scan_spans(&d.text, config)
                .into_iter()
                .map(|mut s| {
                    (s.start, s.end) = source_span(d, s.start, s.end, text);
                    s
                })
                .collect(),
            None => scan_spans(text, config),
        };
        if spans.is_empty() {
            return text.to_string();
        }

        let existing = vault.matcher().token_ranges(text);
        spans.retain(|s| !existing.iter().any(|&(a, b)| s.start < b && a < s.end));
        for span in &mut spans {
            Self::extend_to_token_boundary(text, span, config);
        }

        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for span in resolve_overlaps(spans) {
            let raw = &text[span.start..span.end];
            if raw.len() < 3 {
                continue;
            }
            let token = Self::register_finding_token(
                span.kind,
                &span.label,
                raw,
                &span.severity,
                1,
                None,
                ctx,
                config,
                vault,
                findings,
            );
            out.push_str(&text[last..span.start]);
            out.push_str(&token);
            last = span.end;
        }
        out.push_str(&text[last..]);
        out
    }

    /// A match glued to identifier characters (`ProjectTitanConfig`) would produce a token the
    /// restorer refuses to match. Mask the whole enclosing identifier instead.
    fn extend_to_token_boundary(text: &str, span: &mut Span, config: &HideConfig) {
        let raw = &text[span.start..span.end];
        let sample = Self::generate_semantic_token(span.kind, raw, 1, config);
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

    #[allow(clippy::too_many_arguments)]
    fn register_finding_token(
        kind: FindingKind,
        label: &str,
        raw_val: &str,
        severity: &str,
        occurrences: usize,
        json_value: Option<&Value>,
        ctx: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        findings: &mut Vec<LeakFinding>,
    ) -> String {
        let category_key = format!("{:?}", kind);
        // Never emit a token that already occurs verbatim in the outbound payload.
        let generator = |idx: usize| {
            let mut k = idx;
            loop {
                let token = Self::generate_semantic_token(kind, raw_val, k, config);
                if !ctx.contains(token.as_str()) {
                    return token;
                }
                k += 10_000;
            }
        };
        let replacement_token = match json_value {
            Some(value) => vault.get_or_insert_json_value_with(value, &category_key, generator),
            None => vault.get_or_insert_with(raw_val, &category_key, generator),
        };

        if let Some(existing) = findings.iter_mut().find(|f| f.replacement_token == replacement_token) {
            existing.count += occurrences;
        } else {
            findings.push(LeakFinding {
                kind,
                label: label.to_string(),
                original_preview: mask_preview(raw_val),
                replacement_token: replacement_token.clone(),
                severity: severity.to_string(),
                count: occurrences,
            });
        }
        replacement_token
    }

    /// Placeholders live in namespaces real data does not use (RFC 2544 benchmark addresses,
    /// `example.*` domains), so a real value can never be mistaken for a token.
    pub fn generate_semantic_token(kind: FindingKind, raw_val: &str, idx: usize, config: &HideConfig) -> String {
        match kind {
            FindingKind::ApiKey => format!("sk-sem-placeholder-key-{:04}", idx),
            FindingKind::PrivateKey => format!("<<HIDE_PEM_PRIVATE_KEY_{:03}>>", idx),
            FindingKind::DatabaseUrl => {
                let scheme = raw_val.split("://").next().unwrap_or("postgres");
                format!(
                    "{}://db_user_{:02}:db_pass_placeholder_{:02}@db-{:02}.example.internal:5432/app_schema_{:02}",
                    scheme, idx, idx, idx, idx
                )
            }
            FindingKind::InternalIp => benchmark_ip(idx),
            FindingKind::InternalDomain => format!("svc-node-{:02}.example.internal", idx),
            FindingKind::ProjectPath => {
                if let Some(drive) = raw_val
                    .chars()
                    .next()
                    .filter(|_| raw_val.as_bytes().get(1) == Some(&b':'))
                {
                    let sep = if raw_val.contains("\\\\") { "\\\\" } else { "\\" };
                    format!("{drive}:{sep}workspace{sep}user_{idx:02}")
                } else {
                    format!("/workspace/user_{idx:02}")
                }
            }
            FindingKind::EmailOrPii => format!("dev_member_{:02}@sandbox.example.org", idx),
            FindingKind::GitMetadata => format!("git-ref-placeholder-{:02}", idx),
            FindingKind::EnvSecret => format!("<<ENV_SECRET_TOKEN_{:03}>>", idx),
            FindingKind::CustomKeyword => {
                for rule in config
                    .custom_rules
                    .iter()
                    .filter(|r| r.enabled && !r.replacement_hint.is_empty())
                {
                    if compile_custom_regex(&rule.pattern).is_ok_and(|re| re.is_match(raw_val)) {
                        return format!("{}_{:02}", rule.replacement_hint, idx);
                    }
                }
                format!("CustomConcept_{:02}", idx)
            }
            FindingKind::ProprietaryCodeSymbol => format!("sym_entity_{:02}", idx),
        }
    }
}

/// Map an index onto 198.18.0.0/15 (RFC 2544), skipping .0 and .255 host octets.
fn benchmark_ip(idx: usize) -> String {
    let n = idx.saturating_sub(1);
    let host = n % 254 + 1;
    let third = (n / 254) % 256;
    let second = 18 + (n / 254 / 256) % 2;
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
        assert_eq!(
            out,
            "cwd: /workspace/user_01/titan\nfiles: /workspace/user_01/titan/src/a.rs C:\\workspace\\user_02\\titan\\b.rs"
        );
        let reply = "Created /workspace/user_01/titan/src/new_module.rs";
        assert_eq!(
            vault.restore_text(reply).0,
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
        assert_eq!(out["messages"][0]["content"][1]["input"]["command"], "ssh 198.18.0.1");
    }

    #[test]
    fn restored_thinking_is_resealed_to_the_signed_text() {
        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        // Turn 1: the user's IP is masked; the model thinks about the placeholder.
        SemanticDesensitizer::process("ssh 10.0.0.5", &cfg, &vault);
        let signed_thinking = "connect to 198.18.0.1 first";
        // The harness shows (and sends back) the restored thinking.
        let restored = vault.restore_plain_text(signed_thinking).0;
        assert_eq!(restored, "connect to 10.0.0.5 first");
        let body = serde_json::json!({"messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": restored, "signature": "sig"}]}]});
        let out: Value =
            serde_json::from_str(&SemanticDesensitizer::process(&body.to_string(), &cfg, &vault).transformed_payload)
                .unwrap();
        assert_eq!(out["messages"][0]["content"][0]["thinking"], signed_thinking);
    }
}
