use crate::config::{FindingKind, HideConfig};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;

struct BuiltinRule {
    kind: FindingKind,
    label: &'static str,
    severity: &'static str,
    regex: Regex,
    capture_group: usize,
}

static BUILTIN_RULES: Lazy<Vec<BuiltinRule>> = Lazy::new(|| {
    vec![
        // Private Key (Full multi-line PEM block or unclosed PEM header+body)
        BuiltinRule {
            kind: FindingKind::PrivateKey,
            label: "PEM Private Key",
            severity: "critical",
            regex: Regex::new(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[A-Za-z0-9+/=\r\n\t \\]*)",
            )
            .expect("valid regex"),
            capture_group: 0,
        },
        // API Keys
        BuiltinRule {
            kind: FindingKind::ApiKey,
            label: "Anthropic API Key",
            severity: "critical",
            regex: Regex::new(r"sk-ant-[a-zA-Z0-9_-]{16,}").expect("valid regex"),
            capture_group: 0,
        },
        BuiltinRule {
            kind: FindingKind::ApiKey,
            label: "OpenAI / Generic Secret Key",
            severity: "critical",
            regex: Regex::new(r"sk-[a-zA-Z0-9_-]{16,}").expect("valid regex"),
            capture_group: 0,
        },
        BuiltinRule {
            kind: FindingKind::ApiKey,
            label: "AWS Access Key ID",
            severity: "critical",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"),
            capture_group: 0,
        },
        BuiltinRule {
            kind: FindingKind::ApiKey,
            label: "GitHub Personal Access Token",
            severity: "critical",
            regex: Regex::new(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}")
                .expect("valid regex"),
            capture_group: 0,
        },
        BuiltinRule {
            kind: FindingKind::ApiKey,
            label: "xAI Grok API Key",
            severity: "critical",
            regex: Regex::new(r"xai-[a-zA-Z0-9_-]{16,}").expect("valid regex"),
            capture_group: 0,
        },
        // Database URL
        BuiltinRule {
            kind: FindingKind::DatabaseUrl,
            label: "Database Connection URI",
            severity: "critical",
            regex: Regex::new(
                r#"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss)://[^\s'`]+"#,
            )
            .expect("valid regex"),
            capture_group: 0,
        },
        // Env Secret (supports both ENV=val and JSON {"PASSWORD": "val"} syntax)
        BuiltinRule {
            kind: FindingKind::EnvSecret,
            label: "Environment / Config Secret",
            severity: "high",
            regex: Regex::new(
                r#"(?i)["']?\b(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|DB_PASS|DB_PASSWORD|ACCESS_KEY|API_KEY|APIKEY|CLIENT_SECRET)\b["']?\s*[=:]\s*["']?([^"'\s,}\]]+)"#,
            )
            .expect("valid regex"),
            capture_group: 1,
        },
        // Internal IP
        BuiltinRule {
            kind: FindingKind::InternalIp,
            label: "Private Intranet IPv4",
            severity: "high",
            regex: Regex::new(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b",
            )
            .expect("valid regex"),
            capture_group: 0,
        },
        // Internal Domain
        BuiltinRule {
            kind: FindingKind::InternalDomain,
            label: "Internal Corporate Domain",
            severity: "medium",
            regex: Regex::new(r"\b[a-zA-Z0-9.-]+\.(?:internal|corp|local|lan|intranet)\b")
                .expect("valid regex"),
            capture_group: 0,
        },
        // Project Path (Linux, macOS, and Windows single/double-backslash paths)
        BuiltinRule {
            kind: FindingKind::ProjectPath,
            label: "Local Workspace Path",
            severity: "medium",
            regex: Regex::new(
                r#"(?:/home/[a-zA-Z0-9._-]+/[^\s"'`:,<>\\]+|/Users/[a-zA-Z0-9._-]+/[^\s"'`:,<>\\]+|[a-zA-Z]:(?:\\\\|\\)[a-zA-Z0-9._-]+(?:(?:\\\\|\\)[a-zA-Z0-9._-]+)+)"#,
            )
            .expect("valid regex"),
            capture_group: 0,
        },
        // Email or PII
        BuiltinRule {
            kind: FindingKind::EmailOrPii,
            label: "Developer Email / Identity",
            severity: "medium",
            regex: Regex::new(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
                .expect("valid regex"),
            capture_group: 0,
        },
    ]
});

/// Check if a JSON object property key represents a sensitive secret / credential field
pub fn is_sensitive_secret_key(key: &str) -> bool {
    let lower = key.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "secret"
            | "secret_key"
            | "secretkey"
            | "client_secret"
            | "clientsecret"
            | "token"
            | "access_token"
            | "accesstoken"
            | "auth_token"
            | "authtoken"
            | "refresh_token"
            | "private_key"
            | "privatekey"
            | "api_key"
            | "apikey"
            | "access_key"
            | "accesskey"
            | "aws_access_key_id"
            | "aws_secret_access_key"
            | "stripe_secret_key"
            | "db_pass"
            | "db_password"
            | "database_password"
    )
}

/// Check if a value is already a Hide-Go placeholder token
pub fn is_placeholder_token(val: &str) -> bool {
    let trimmed = val.trim();
    (trimmed.starts_with("<<") && trimmed.ends_with(">>"))
        || trimmed.starts_with("⟦HIDE-CIPHER::")
        || trimmed.starts_with("⟦HG_LIT_")
        || trimmed.starts_with("sk-sem-placeholder-key-")
        || trimmed.contains("db_pass_placeholder_")
        || trimmed.contains("/workspace/sandbox_proj/")
        || trimmed.contains("\\workspace\\sandbox_proj\\")
        || trimmed.ends_with(".example.internal")
        || trimmed.ends_with("@sandbox.example.org")
}

/// Clean trailing quote/punctuation from a matched Database URL when it was enclosed in quotes in prose
pub fn clean_database_url_match(raw: &str) -> &str {
    let mut s = raw;
    while let Some(last) = s.chars().last() {
        if matches!(last, '"' | ',' | ';' | ')' | ']' | '}') {
            s = &s[..s.len() - last.len_utf8()];
        } else {
            break;
        }
    }
    // If raw had a trailing `\` from raw JSON `\"` before unescaping, strip that trailing `\`
    if s.ends_with('\\') && !raw.ends_with("\\\\") {
        s = &s[..s.len() - 1];
    }
    s
}

/// Project-level sensitive data scanner powered by compiled regular expressions and JSON-aware traversal.
pub struct ProjectScanner;

impl ProjectScanner {
    /// Scans `payload` against enabled `HideConfig` protections and custom rules.
    /// If `payload` is valid JSON, traverses the parsed JSON structure (including unescaped strings
    /// and sensitive key-value pairs) so escaped values and `{"PASSWORD":"s3cr3t"}` are never missed.
    /// Returns `(kind, label, matched_raw_value, severity)` deduplicated by `matched_raw_value` while preserving order.
    #[allow(non_snake_case)]
    pub fn scan_Matches(
        payload: &str,
        config: &HideConfig,
    ) -> Vec<(FindingKind, String, String, String)> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        let trimmed = payload.trim();
        if (trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"'))
            && serde_json::from_str::<Value>(trimmed).is_ok()
        {
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                Self::scan_json_value(&val, config, &mut results, &mut seen);
                return results;
            }
        }

        Self::scan_plain_text_into(payload, config, &mut results, &mut seen);
        results
    }

    fn scan_json_value(
        val: &Value,
        config: &HideConfig,
        results: &mut Vec<(FindingKind, String, String, String)>,
        seen: &mut HashSet<String>,
    ) {
        match val {
            Value::Object(map) => {
                for (k, v) in map {
                    if config.protect_secrets_and_keys && is_sensitive_secret_key(k) {
                        if let Value::String(secret_val) = v {
                            let s = secret_val.trim();
                            if !s.is_empty()
                                && !is_placeholder_token(s)
                                && seen.insert(secret_val.clone())
                            {
                                results.push((
                                    FindingKind::EnvSecret,
                                    "Environment / Config Secret".to_string(),
                                    secret_val.clone(),
                                    "high".to_string(),
                                ));
                            }
                        }
                    }
                    Self::scan_json_value(v, config, results, seen);
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    Self::scan_json_value(item, config, results, seen);
                }
            }
            Value::String(s) => {
                let st = s.trim();
                if (st.starts_with('{') || st.starts_with('['))
                    && serde_json::from_str::<Value>(st).is_ok()
                {
                    if let Ok(inner) = serde_json::from_str::<Value>(st) {
                        Self::scan_json_value(&inner, config, results, seen);
                    }
                }
                Self::scan_plain_text_into(s, config, results, seen);
            }
            _ => {}
        }
    }

    pub(crate) fn scan_plain_text_into(
        payload: &str,
        config: &HideConfig,
        results: &mut Vec<(FindingKind, String, String, String)>,
        seen: &mut HashSet<String>,
    ) {
        // If payload contains literal `\u00` JSON-style unicode escapes inside raw text, also scan decoded form
        let decoded_unicode = unescape_inline_unicode(payload);
        let target = decoded_unicode.as_deref().unwrap_or(payload);

        // 1. Evaluate custom user rules first so high-priority project codenames / domains are captured
        for rule in &config.custom_rules {
            if !rule.enabled || rule.pattern.trim().is_empty() {
                continue;
            }
            if let Ok(re) = Regex::new(&rule.pattern) {
                for mat in re.find_iter(target) {
                    let raw = mat.as_str().to_string();
                    if !raw.is_empty() && !is_placeholder_token(&raw) && seen.insert(raw.clone()) {
                        results.push((
                            FindingKind::CustomKeyword,
                            rule.name.clone(),
                            raw,
                            "high".to_string(),
                        ));
                    }
                }
            }
        }

        // 2. Evaluate built-in pattern detectors gated by HideConfig flags
        for rule in BUILTIN_RULES.iter() {
            let allowed = match rule.kind {
                FindingKind::ApiKey
                | FindingKind::PrivateKey
                | FindingKind::DatabaseUrl
                | FindingKind::EnvSecret => config.protect_secrets_and_keys,
                FindingKind::InternalIp | FindingKind::InternalDomain => {
                    config.protect_internal_network
                }
                FindingKind::ProjectPath | FindingKind::EmailOrPii => config.protect_project_paths,
                _ => true,
            };

            if !allowed {
                continue;
            }

            if rule.capture_group == 0 {
                for mat in rule.regex.find_iter(target) {
                    let matched_str = if rule.kind == FindingKind::DatabaseUrl {
                        clean_database_url_match(mat.as_str())
                    } else {
                        mat.as_str()
                    };
                    let raw = matched_str.to_string();
                    if !raw.is_empty() && !is_placeholder_token(&raw) && seen.insert(raw.clone()) {
                        results.push((
                            rule.kind,
                            rule.label.to_string(),
                            raw,
                            rule.severity.to_string(),
                        ));
                    }
                }
            } else {
                for caps in rule.regex.captures_iter(target) {
                    if let Some(m) = caps.get(rule.capture_group) {
                        let raw = m.as_str().to_string();
                        if !raw.is_empty()
                            && !is_placeholder_token(&raw)
                            && seen.insert(raw.clone())
                        {
                            results.push((
                                rule.kind,
                                rule.label.to_string(),
                                raw,
                                rule.severity.to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Snake-case alias for `scan_Matches`.
    pub fn scan_matches(
        payload: &str,
        config: &HideConfig,
    ) -> Vec<(FindingKind, String, String, String)> {
        Self::scan_Matches(payload, config)
    }
}

/// Unescape `\uXXXX` sequences in raw non-JSON text if present
pub(crate) fn unescape_inline_unicode(input: &str) -> Option<String> {
    if !input.contains("\\u00") && !input.contains("\\u0") {
        return None;
    }
    static UNICODE_ESC_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap());
    let mut changed = false;
    let out = UNICODE_ESC_RE.replace_all(input, |caps: &regex::Captures| {
        if let Ok(code) = u32::from_str_radix(&caps[1], 16) {
            if let Some(ch) = char::from_u32(code) {
                changed = true;
                return ch.to_string();
            }
        }
        caps[0].to_string()
    });
    if changed {
        Some(out.into_owned())
    } else {
        None
    }
}

/// Top-level convenience function matching `ProjectScanner::scan_Matches`.
#[allow(non_snake_case)]
pub fn scan_Matches(
    payload: &str,
    config: &HideConfig,
) -> Vec<(FindingKind, String, String, String)> {
    ProjectScanner::scan_Matches(payload, config)
}

/// Top-level snake_case convenience function matching `ProjectScanner::scan_Matches`.
pub fn scan_matches(
    payload: &str,
    config: &HideConfig,
) -> Vec<(FindingKind, String, String, String)> {
    ProjectScanner::scan_Matches(payload, config)
}

