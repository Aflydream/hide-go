use crate::config::{FindingKind, HideConfig, LeakFinding};
use crate::scanner::{
    is_placeholder_token, is_sensitive_secret_key, unescape_inline_unicode, ProjectScanner,
};
use crate::vault::{mask_preview, PrivacyVault};
use serde_json::Value;
use std::collections::HashSet;

pub struct DesensitizeResult {
    pub transformed_payload: String,
    pub findings: Vec<LeakFinding>,
}

/// Format-preserving bidirectional semantic desensitizer.
/// Parses JSON payloads structurally first so escaped strings, Windows paths, `{"PASSWORD":"s3cr3t"}`
/// key-value secrets, and database URLs containing quotes are accurately detected and replaced
/// without ever corrupting JSON syntax.
pub struct SemanticDesensitizer;

impl SemanticDesensitizer {
    pub fn process(
        payload: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
    ) -> DesensitizeResult {
        let trimmed = payload.trim();
        if (trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"'))
            && serde_json::from_str::<Value>(trimmed).is_ok()
        {
            if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                let mut findings = Vec::new();
                Self::desensitize_json_value(&mut json_val, config, vault, &mut findings);

                let is_pretty = trimmed.starts_with("{\n") || trimmed.starts_with("[\n");
                let serialized = if is_pretty {
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|_| payload.to_string())
                } else {
                    serde_json::to_string(&json_val).unwrap_or_else(|_| payload.to_string())
                };

                return DesensitizeResult {
                    transformed_payload: serialized,
                    findings,
                };
            }
        }

        let mut findings = Vec::new();
        let transformed = Self::desensitize_plain_text(payload, config, vault, false, &mut findings);
        DesensitizeResult {
            transformed_payload: transformed,
            findings,
        }
    }

    fn desensitize_json_value(
        val: &mut Value,
        config: &HideConfig,
        vault: &PrivacyVault,
        findings: &mut Vec<LeakFinding>,
    ) {
        match val {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if config.protect_secrets_and_keys && is_sensitive_secret_key(k) {
                        if let Value::String(secret_str) = v {
                            let s = secret_str.trim();
                            if !s.is_empty() && !is_placeholder_token(s) {
                                let raw_val = secret_str.clone();
                                let token = Self::register_finding_token(
                                    FindingKind::EnvSecret,
                                    "Environment / Config Secret",
                                    &raw_val,
                                    "high",
                                    1,
                                    true,
                                    config,
                                    vault,
                                    findings,
                                );
                                *secret_str = token;
                                continue;
                            }
                        }
                    }
                    Self::desensitize_json_value(v, config, vault, findings);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    Self::desensitize_json_value(item, config, vault, findings);
                }
            }
            Value::String(s) => {
                let st = s.trim();
                if (st.starts_with('{') || st.starts_with('['))
                    && serde_json::from_str::<Value>(st).is_ok()
                {
                    if let Ok(mut inner_val) = serde_json::from_str::<Value>(st) {
                        let inner_pretty = st.starts_with("{\n") || st.starts_with("[\n");
                        Self::desensitize_json_value(&mut inner_val, config, vault, findings);
                        if let Ok(reserialized) = if inner_pretty {
                            serde_json::to_string_pretty(&inner_val)
                        } else {
                            serde_json::to_string(&inner_val)
                        } {
                            *s = reserialized;
                            return;
                        }
                    }
                }
                *s = Self::desensitize_plain_text(s, config, vault, true, findings);
            }
            _ => {}
        }
    }

    fn desensitize_plain_text(
        payload: &str,
        config: &HideConfig,
        vault: &PrivacyVault,
        in_json: bool,
        findings: &mut Vec<LeakFinding>,
    ) -> String {
        let decoded_unicode = unescape_inline_unicode(payload);
        let working_input = decoded_unicode.as_deref().unwrap_or(payload);

        let mut raw_matches = Vec::new();
        let mut seen = HashSet::new();
        ProjectScanner::scan_plain_text_into(working_input, config, &mut raw_matches, &mut seen);

        if raw_matches.is_empty() {
            return payload.to_string();
        }

        let mut transformed = working_input.to_string();

        // Sort matches by raw value length descending so longer paths/URLs are replaced before inner substrings
        raw_matches.sort_by(|a, b| b.2.len().cmp(&a.2.len()));

        for (kind, label, raw_val, severity) in raw_matches {
            if raw_val.len() < 3 || !transformed.contains(&raw_val) {
                continue;
            }

            let occurrences = transformed.matches(&raw_val).count();
            if occurrences == 0 {
                continue;
            }

            let replacement_token = Self::register_finding_token(
                kind,
                &label,
                &raw_val,
                &severity,
                occurrences,
                in_json,
                config,
                vault,
                findings,
            );

            transformed = transformed.replace(&raw_val, &replacement_token);
        }

        transformed
    }

    #[allow(clippy::too_many_arguments)]
    fn register_finding_token(
        kind: FindingKind,
        label: &str,
        raw_val: &str,
        severity: &str,
        occurrences: usize,
        in_json: bool,
        config: &HideConfig,
        vault: &PrivacyVault,
        findings: &mut Vec<LeakFinding>,
    ) -> String {
        let category_key = format!("{:?}", kind);
        let escaped_raw = json_escape_contents(raw_val);
        let raw_needs_json_escape = in_json && (escaped_raw != raw_val);

        let replacement_token = vault.get_or_insert_with(raw_val, &category_key, |idx| {
            let base_tok = Self::generate_semantic_token(kind, raw_val, idx, config);
            if raw_needs_json_escape && !base_tok.contains('\\') {
                // Embed a backslash marker so JSON serialization escapes it to `\\`,
                // allowing StreamRestorer to distinguish JSON-escaped context from raw text.
                if let Some(stripped) = base_tok.strip_suffix(">>") {
                    format!("{}\\>>", stripped)
                } else {
                    format!("{}\\j", base_tok)
                }
            } else {
                base_tok
            }
        });

        // If serialized inside JSON, register the JSON-escaped token -> JSON-escaped raw value as well
        // so raw JSON/SSE stream restoration produces 100% valid JSON syntax!
        let escaped_tok = json_escape_contents(&replacement_token);
        if escaped_tok != replacement_token || escaped_raw != raw_val {
            vault.insert_explicit(&escaped_raw, &escaped_tok, &category_key);
        }

        if let Some(existing) = findings
            .iter_mut()
            .find(|f| f.replacement_token == replacement_token)
        {
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

    fn generate_semantic_token(
        kind: FindingKind,
        raw_val: &str,
        idx: usize,
        config: &HideConfig,
    ) -> String {
        match kind {
            FindingKind::ApiKey => format!("sk-sem-placeholder-key-{:04}", idx),
            FindingKind::PrivateKey => format!("<<HIDE_PEM_PRIVATE_KEY_{:03}>>", idx),
            FindingKind::DatabaseUrl => {
                let scheme = raw_val.split("://").next().unwrap_or("postgres");
                format!(
                    "{}://db_user_{:02}:db_pass_placeholder_{:02}@10.254.0.{}:5432/app_schema_{:02}",
                    scheme,
                    idx,
                    idx,
                    (idx % 250) + 1,
                    idx
                )
            }
            FindingKind::InternalIp => format!("10.254.100.{}", (idx % 250) + 1),
            FindingKind::InternalDomain => format!("svc-node-{:02}.example.internal", idx),
            FindingKind::ProjectPath => {
                // Preserve file extension so the AI knows the language/file type!
                let ext = raw_val
                    .rsplit(['.', '/', '\\'])
                    .next()
                    .filter(|e| {
                        raw_val.contains('.')
                            && e.len() <= 6
                            && e.chars().all(|c| c.is_alphanumeric())
                    })
                    .unwrap_or("src");
                if raw_val.contains('\\') {
                    format!("C:\\workspace\\sandbox_proj\\module_{:02}.{}", idx, ext)
                } else {
                    format!("/workspace/sandbox_proj/src/module_{:02}.{}", idx, ext)
                }
            }
            FindingKind::EmailOrPii => format!("dev_member_{:02}@sandbox.example.org", idx),
            FindingKind::GitMetadata => format!("git-ref-placeholder-{:02}", idx),
            FindingKind::EnvSecret => format!("<<ENV_SECRET_TOKEN_{:03}>>", idx),
            FindingKind::CustomKeyword => {
                for rule in &config.custom_rules {
                    if rule.enabled && !rule.replacement_hint.is_empty() {
                        if let Ok(re) = regex::Regex::new(&rule.pattern) {
                            if re.is_match(raw_val) {
                                return format!("{}_{:02}", rule.replacement_hint, idx);
                            }
                        }
                    }
                }
                format!("CustomConcept_{:02}", idx)
            }
            FindingKind::ProprietaryCodeSymbol => format!("sym_entity_{:02}", idx),
        }
    }
}

/// Return the JSON-escaped interior of a string (without surrounding quotes)
pub(crate) fn json_escape_contents(s: &str) -> String {
    match serde_json::to_string(s) {
        Ok(quoted) if quoted.len() >= 2 => quoted[1..quoted.len() - 1].to_string(),
        _ => s.to_string(),
    }
}

