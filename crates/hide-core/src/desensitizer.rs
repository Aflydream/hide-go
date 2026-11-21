use crate::config::{FindingKind, HideConfig, LeakFinding};
use crate::protocol::{is_api_schema_container_key, is_opaque_block, is_structural_key, is_tool_call_object};
use crate::scanner::{
    compile_custom_regex, decode_inline_unicode, is_placeholder_or_template_secret, is_placeholder_token,
    is_sensitive_secret_key, resolve_overlaps, scan_spans, source_span, Span,
};
use crate::vault::{is_bare_ident_token, is_word_char, mask_preview, reserialize_like, PrivacyVault, MAX_JSON_DEPTH};
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
        let trimmed = payload.trim();
        if trimmed.starts_with(['{', '[', '"']) {
            if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                Self::desensitize_json_value_depth(&mut json_val, payload, config, vault, scope, &mut findings, 0);
                return DesensitizeResult {
                    transformed_payload: reserialize_like(trimmed, &json_val),
                    findings,
                };
            }
        }
        let transformed = Self::desensitize_text_scoped(payload, payload, config, vault, scope, &mut findings);
        DesensitizeResult {
            transformed_payload: transformed,
            findings,
        }
    }

    pub(crate) fn desensitize_json_value_depth(
        val: &mut Value,
        ctx: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
        findings: &mut Vec<LeakFinding>,
        depth: usize,
    ) {
        if depth >= MAX_JSON_DEPTH {
            if let Value::String(s) = val {
                *s = Self::desensitize_text_scoped(s, ctx, config, vault, scope, findings);
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
                            *t = vault.matcher_for_scope(scope).reseal(t);
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
                    let key = Self::desensitize_text_scoped(&key, ctx, config, vault, scope, findings);
                    let secret = match &value {
                        Value::String(raw)
                            if sensitive_field
                                && !raw.trim().is_empty()
                                && !is_placeholder_token(raw)
                                && !is_placeholder_or_template_secret(raw)
                                && !vault.contains_token_in_scope(raw, scope)
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
                            ctx,
                            config,
                            vault,
                            scope,
                            findings,
                        );
                        value = Value::String(token);
                    } else {
                        Self::desensitize_json_value_depth(&mut value, ctx, config, vault, scope, findings, depth + 1);
                    }
                    map.insert(key, value);
                }
            }
            Value::Array(arr) => arr.iter_mut().for_each(|item| {
                Self::desensitize_json_value_depth(item, ctx, config, vault, scope, findings, depth + 1)
            }),
            Value::String(s) => {
                let st = s.trim();
                if st.starts_with(['{', '[']) && depth + 1 < MAX_JSON_DEPTH {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(st) {
                        Self::desensitize_json_value_depth(&mut inner, ctx, config, vault, scope, findings, depth + 1);
                        *s = reserialize_like(st, &inner);
                        return;
                    }
                }
                *s = Self::desensitize_text_scoped(s, ctx, config, vault, scope, findings);
            }
            _ => {}
        }
    }

    /// Mask one plain-text string in a single pass.
    pub(crate) fn desensitize_text_scoped(
        text: &str,
        ctx: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
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
        let existing = vault.matcher_for_scope(scope).token_ranges(text);
        let (after_regex, did_replace_spans) = if spans.is_empty() {
            (text.to_string(), false)
        } else {
            spans.retain(|s| !existing.iter().any(|&(a, b)| s.start < b && a < s.end));
            for span in &mut spans {
                Self::extend_to_token_boundary(text, span, config);
            }

            let mut out = String::with_capacity(text.len());
            let mut last = 0;
            let mut replaced_any = false;
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
                    scope,
                    findings,
                );
                out.push_str(&text[last..span.start]);
                out.push_str(&token);
                last = span.end;
                replaced_any = true;
            }
            out.push_str(&text[last..]);
            (out, replaced_any)
        };

        let matcher = vault.matcher_for_scope(scope);
        let remask_existing = if did_replace_spans {
            matcher.token_ranges(&after_regex)
        } else {
            existing
        };
        let (remasked, remask_hits) = matcher.remask_secrets(&after_regex, &remask_existing);
        for (raw_secret, token, count) in remask_hits {
            Self::record_finding(
                findings,
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
        scope: Option<&str>,
        findings: &mut Vec<LeakFinding>,
    ) -> String {
        let category_key = format!("{:?}", kind);
        // Never emit a token that already occurs verbatim in the outbound payload.
        let generator = |idx: usize| {
            for attempt in 0..64usize {
                let token = Self::generate_semantic_token_scoped(kind, raw_val, idx, attempt, config, vault, scope);
                if !ctx.contains(token.as_str()) {
                    return token;
                }
            }
            let fallback_tag = vault.keyed_tag("fallback", scope, idx, 16);
            format!("<<HIDE_REDACTED_{fallback_tag}_{idx:04}>>")
        };
        let replacement_token = match json_value {
            Some(value) => vault.get_or_insert_json_value_scoped_with(scope, value, &category_key, generator),
            None => vault.get_or_insert_scoped_with(scope, raw_val, &category_key, generator),
        };

        Self::record_finding(
            findings,
            kind,
            label,
            raw_val,
            &replacement_token,
            severity,
            occurrences,
        );
        replacement_token
    }

    /// Placeholders live in namespaces real data does not use (RFC 2544 benchmark addresses,
    /// `example.*` domains) and embed per-vault/per-scope HMAC tags so tokens cannot be guessed
    /// or collided across vendors or sessions.
    pub fn generate_semantic_token(kind: FindingKind, raw_val: &str, idx: usize, config: &HideConfig) -> String {
        let fallback_ip = benchmark_ip(idx);
        Self::format_semantic_token(kind, raw_val, idx, "000000000000", "00000000", &fallback_ip, config)
    }

    fn generate_semantic_token_scoped(
        kind: FindingKind,
        raw_val: &str,
        idx: usize,
        attempt: usize,
        config: &HideConfig,
        vault: &PrivacyVault,
        scope: Option<&str>,
    ) -> String {
        let salt_idx = idx.wrapping_add(attempt.wrapping_mul(10_007));
        let tag12 = vault.keyed_tag(&format!("{kind:?}"), scope, salt_idx, 12);
        let tag8 = &tag12[..8];
        let ip_num = vault.keyed_u64("InternalIp", scope, salt_idx);
        let ip = benchmark_ip_keyed(ip_num, idx.wrapping_add(attempt));
        Self::format_semantic_token(kind, raw_val, idx, &tag12, tag8, &ip, config)
    }

    fn format_semantic_token(
        kind: FindingKind,
        raw_val: &str,
        idx: usize,
        tag12: &str,
        tag8: &str,
        ip: &str,
        config: &HideConfig,
    ) -> String {
        match kind {
            FindingKind::ApiKey => format!("sk-sem-{tag12}-{idx:04}"),
            FindingKind::PrivateKey => format!("<<HIDE_PEM_PRIVATE_KEY_{tag12}_{idx:03}>>"),
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
                format!(
                    "{scheme}://db_user_{tag8}_{idx:02}:db_pass_placeholder_{tag12}_{idx:02}@db-{tag8}-{idx:02}.example.internal:{port}/app_schema_{idx:02}"
                )
            }
            FindingKind::InternalIp => ip.to_string(),
            FindingKind::InternalDomain => format!("svc-node-{tag8}-{idx:02}.example.internal"),
            FindingKind::ProjectPath => {
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
                    format!("{drive}:{sep}workspace{sep}user_{tag8}_{idx:02}")
                } else {
                    format!("/workspace/user_{tag8}_{idx:02}")
                }
            }
            FindingKind::EmailOrPii => format!("dev_member_{tag8}_{idx:02}@sandbox.example.org"),
            FindingKind::GitMetadata => format!("git-ref-placeholder-{tag8}-{idx:02}"),
            FindingKind::EnvSecret => format!("<<ENV_SECRET_TOKEN_{tag12}_{idx:03}>>"),
            FindingKind::CustomKeyword => {
                for rule in config
                    .custom_rules
                    .iter()
                    .filter(|r| r.enabled && !r.replacement_hint.is_empty())
                {
                    if compile_custom_regex(&rule.pattern).is_ok_and(|re| re.is_match(raw_val)) {
                        return format!("{}_{tag8}_{idx:02}", rule.replacement_hint);
                    }
                }
                format!("CustomConcept_{tag8}_{idx:02}")
            }
            FindingKind::ProprietaryCodeSymbol => format!("sym_entity_{tag8}_{idx:02}"),
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

/// Map a keyed 64-bit value onto 198.18.0.0/15 (RFC 2544), skipping .0 and .255 host octets.
fn benchmark_ip_keyed(keyed: u64, salt: usize) -> String {
    let mixed = keyed ^ (salt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let host = (mixed % 254) + 1;
    let third = (mixed >> 8) % 256;
    let second = 18 + ((mixed >> 16) % 2);
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
        assert!(
            out.contains("/workspace/user_") && out.contains("\\workspace\\user_"),
            "{out}"
        );
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
        assert!(masked_win.starts_with("C:/workspace/user_") && masked_win.ends_with("/my-repo/src/main.rs"));

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
}
