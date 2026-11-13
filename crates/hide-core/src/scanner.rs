use crate::config::{CustomRule, FindingKind, HideConfig};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

struct BuiltinRule {
    kind: FindingKind,
    label: &'static str,
    severity: &'static str,
    regex: Regex,
    capture_group: usize,
}

fn rule(kind: FindingKind, label: &'static str, severity: &'static str, re: &str, capture_group: usize) -> BuiltinRule {
    BuiltinRule {
        kind,
        label,
        severity,
        regex: Regex::new(re).expect("valid builtin regex"),
        capture_group,
    }
}

static BUILTIN_RULES: Lazy<Vec<BuiltinRule>> = Lazy::new(|| {
    use FindingKind::*;
    vec![
        rule(
            PrivateKey,
            "PEM Private Key",
            "critical",
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[A-Za-z0-9+/=\r\n\t \\]*)",
            0,
        ),
        // `\b` keeps kebab-case words such as `risk-assessment` from matching `sk-…`.
        rule(
            ApiKey,
            "Anthropic API Key",
            "critical",
            r"\bsk-ant-[a-zA-Z0-9_-]{16,}",
            0,
        ),
        rule(
            ApiKey,
            "OpenAI / Generic Secret Key",
            "critical",
            r"\bsk-[a-zA-Z0-9_-]{16,}",
            0,
        ),
        rule(ApiKey, "AWS Access Key ID", "critical", r"\bAKIA[0-9A-Z]{16}\b", 0),
        rule(
            ApiKey,
            "GitHub Personal Access Token",
            "critical",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{20,}|\bgithub_pat_[a-zA-Z0-9_]{20,}",
            0,
        ),
        rule(ApiKey, "xAI Grok API Key", "critical", r"\bxai-[a-zA-Z0-9_-]{16,}", 0),
        rule(
            DatabaseUrl,
            "Database Connection URI",
            "critical",
            r#"\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss)://[^\s'`]+"#,
            0,
        ),
        rule(
            EnvSecret,
            "Environment / Config Secret",
            "high",
            r#"(?i)["']?\b(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|DB_PASS|DB_PASSWORD|ACCESS_KEY|API_KEY|APIKEY|CLIENT_SECRET)\b["']?\s*[=:]\s*"([^"\r\n]+)""#,
            1,
        ),
        rule(
            EnvSecret,
            "Environment / Config Secret",
            "high",
            r#"(?i)["']?\b(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|DB_PASS|DB_PASSWORD|ACCESS_KEY|API_KEY|APIKEY|CLIENT_SECRET)\b["']?\s*[=:]\s*'([^'\r\n]+)'"#,
            1,
        ),
        rule(
            EnvSecret,
            "Environment / Config Secret",
            "high",
            r#"(?i)["']?\b(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|DB_PASS|DB_PASSWORD|ACCESS_KEY|API_KEY|APIKEY|CLIENT_SECRET)\b["']?\s*[=:]\s*([^\s,;\}\]"']+)"#,
            1,
        ),
        rule(
            InternalIp,
            "Private Intranet IPv4",
            "high",
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b",
            0,
        ),
        rule(
            InternalDomain,
            "Internal Corporate Domain",
            "medium",
            r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:internal|corp|local|lan|intranet)\b",
            0,
        ),
        // Only the identifying root (`/home/<user>`, `C:\Users\<user>`, `D:\<first>`) is masked,
        // so directory structure and file names stay intact for the model and new paths restore.
        rule(
            ProjectPath,
            "Local Workspace Path",
            "medium",
            r"(?:^|[^A-Za-z0-9._/~-])(/(?:home|Users)/[A-Za-z0-9._-]+)",
            1,
        ),
        rule(
            ProjectPath,
            "Local Workspace Path",
            "medium",
            r"\b([A-Za-z]:(?:\\\\|\\)[Uu]sers(?:\\\\|\\)[A-Za-z0-9._-]+)",
            1,
        ),
        rule(
            ProjectPath,
            "Local Workspace Path",
            "medium",
            r"\b([A-Za-z]:(?:\\\\|\\)[A-Za-z0-9._-]+)(?:\\\\|\\)[A-Za-z0-9._-]",
            1,
        ),
        rule(
            EmailOrPii,
            "Developer Email / Identity",
            "medium",
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            0,
        ),
    ]
});

const CUSTOM_REGEX_SIZE_LIMIT: usize = 1 << 20;

static CUSTOM_REGEX_CACHE: Lazy<Mutex<HashMap<String, Result<Regex, String>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Compile (and cache) a user rule with the same engine the gateway uses at runtime.
pub fn compile_custom_regex(pattern: &str) -> Result<Regex, String> {
    let mut cache = CUSTOM_REGEX_CACHE.lock();
    if let Some(hit) = cache.get(pattern) {
        return hit.clone();
    }
    let compiled = RegexBuilder::new(pattern)
        .size_limit(CUSTOM_REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| {
            e.to_string()
                .lines()
                .last()
                .unwrap_or("invalid regex")
                .trim()
                .to_string()
        })
        .and_then(|re| {
            if re.is_match("") {
                Err("pattern matches the empty string".to_string())
            } else {
                Ok(re)
            }
        });
    if cache.len() > 512 {
        cache.clear();
    }
    cache.insert(pattern.to_string(), compiled.clone());
    compiled
}

/// Reject rules the runtime engine cannot apply, instead of silently skipping them.
pub fn validate_custom_rules(rules: &[CustomRule]) -> Result<(), String> {
    for rule in rules {
        if rule.pattern.trim().is_empty() {
            return Err(format!("规则「{}」的正则表达式为空", rule.name));
        }
        compile_custom_regex(&rule.pattern).map_err(|e| format!("规则「{}」无法编译：{}", rule.name, e))?;
    }
    Ok(())
}

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
        || trimmed.starts_with("sk-sem-placeholder-key-")
        || trimmed.contains("db_pass_placeholder_")
        || trimmed.contains("/workspace/user_")
        || trimmed.contains("workspace\\user_")
        || trimmed.contains("workspace\\\\user_")
        || trimmed.ends_with(".example.internal")
        || trimmed.ends_with("@sandbox.example.org")
}

fn is_non_secret_env_token(raw: &str, is_quoted: bool) -> bool {
    if is_quoted {
        return false;
    }
    if raw.starts_with(['&', '<', '[', '(', '{']) || raw.contains("->") || raw.ends_with(['>', ']', ')']) {
        return true;
    }
    matches!(
        raw.to_ascii_lowercase().as_str(),
        "string"
            | "str"
            | "int"
            | "integer"
            | "int32"
            | "int64"
            | "uint"
            | "usize"
            | "i32"
            | "i64"
            | "u32"
            | "u64"
            | "f32"
            | "f64"
            | "number"
            | "float"
            | "double"
            | "bool"
            | "boolean"
            | "true"
            | "false"
            | "null"
            | "none"
            | "nil"
            | "undefined"
            | "any"
            | "unknown"
            | "never"
            | "void"
            | "object"
            | "bytes"
            | "byte"
            | "char"
            | "optional"
            | "required"
            | "readonly"
            | "please"
    )
}

fn is_placeholder_windows_workspace(raw: &str, tail: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    (lower.ends_with(":\\workspace") || lower.ends_with(":\\\\workspace"))
        && (tail.starts_with("\\user_") || tail.starts_with("\\\\user_"))
}

/// Clean trailing quote/punctuation from a matched Database URL when it was enclosed in quotes in prose
pub fn clean_database_url_match(raw: &str) -> &str {
    let mut s = raw;
    while let Some(last) = s.chars().last() {
        if matches!(last, '"' | ',' | ';' | ')' | ']' | '}' | '.') {
            s = &s[..s.len() - last.len_utf8()];
        } else {
            break;
        }
    }
    if s.ends_with('\\') && !raw.ends_with("\\\\") {
        s = &s[..s.len() - 1];
    }
    s
}

/// A sensitive match located in the scanned text.
#[derive(Debug, Clone)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub kind: FindingKind,
    pub label: String,
    pub severity: String,
}

fn rule_enabled(kind: FindingKind, config: &HideConfig) -> bool {
    match kind {
        FindingKind::ApiKey | FindingKind::PrivateKey | FindingKind::DatabaseUrl | FindingKind::EnvSecret => {
            config.protect_secrets_and_keys
        }
        FindingKind::InternalIp | FindingKind::InternalDomain => config.protect_internal_network,
        FindingKind::ProjectPath | FindingKind::EmailOrPii => config.protect_project_paths,
        _ => true,
    }
}

/// Positional scan of plain text. Spans may overlap; callers resolve overlaps.
/// Custom rules come first so project codenames win ties against generic detectors.
pub fn scan_spans(text: &str, config: &HideConfig) -> Vec<Span> {
    let mut spans = Vec::new();
    for rule in config
        .custom_rules
        .iter()
        .filter(|r| r.enabled && !r.pattern.trim().is_empty())
    {
        if let Ok(re) = compile_custom_regex(&rule.pattern) {
            for m in re.find_iter(text) {
                if !m.as_str().is_empty() && !is_placeholder_token(m.as_str()) {
                    spans.push(Span {
                        start: m.start(),
                        end: m.end(),
                        kind: FindingKind::CustomKeyword,
                        label: rule.name.clone(),
                        severity: "high".to_string(),
                    });
                }
            }
        }
    }
    for rule in BUILTIN_RULES.iter().filter(|r| rule_enabled(r.kind, config)) {
        for caps in rule.regex.captures_iter(text) {
            let Some(m) = caps.get(rule.capture_group) else {
                continue;
            };
            let mut end = m.end();
            if rule.kind == FindingKind::DatabaseUrl {
                end = m.start() + clean_database_url_match(m.as_str()).len();
            }
            let raw = &text[m.start()..end];
            if raw.len() < 3 || is_placeholder_token(raw) {
                continue;
            }
            if rule.kind == FindingKind::EnvSecret {
                let is_quoted =
                    matches!(text.as_bytes().get(m.start().wrapping_sub(1)), Some(b'"' | b'\'')) && m.start() > 0;
                if is_non_secret_env_token(raw, is_quoted) {
                    continue;
                }
            }
            if rule.kind == FindingKind::ProjectPath && is_placeholder_windows_workspace(raw, &text[end..]) {
                continue;
            }
            spans.push(Span {
                start: m.start(),
                end,
                kind: rule.kind,
                label: rule.label.to_string(),
                severity: rule.severity.to_string(),
            });
        }
    }
    spans
}

/// Pick non-overlapping spans: earliest start first, longer span on ties, custom rules on equal extent.
pub fn resolve_overlaps(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| a.start.cmp(&b.start).then((b.end - b.start).cmp(&(a.end - a.start))));
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        if out.last().is_some_and(|last| s.start < last.end) {
            continue;
        }
        out.push(s);
    }
    out
}

/// Project-level sensitive data scanner powered by compiled regular expressions and JSON-aware traversal.
pub struct ProjectScanner;

impl ProjectScanner {
    /// Returns `(kind, label, matched_raw_value, severity)` deduplicated by raw value, preserving order.
    #[allow(non_snake_case)]
    pub fn scan_Matches(payload: &str, config: &HideConfig) -> Vec<(FindingKind, String, String, String)> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();
        let trimmed = payload.trim();
        if trimmed.starts_with(['{', '[', '"']) {
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
                    Self::scan_plain_text_into(k, config, results, seen);
                    if config.protect_secrets_and_keys && is_sensitive_secret_key(k) {
                        let raw = match v {
                            Value::String(s) if !s.trim().is_empty() && !is_placeholder_token(s) => Some(s.clone()),
                            Value::Number(_) | Value::Bool(_) => Some(v.to_string()),
                            _ => None,
                        };
                        if let Some(raw) = raw {
                            if seen.insert(raw.clone()) {
                                results.push((
                                    FindingKind::EnvSecret,
                                    "Environment / Config Secret".to_string(),
                                    raw,
                                    "high".to_string(),
                                ));
                            }
                            continue;
                        }
                    }
                    Self::scan_json_value(v, config, results, seen);
                }
            }
            Value::Array(arr) => arr
                .iter()
                .for_each(|item| Self::scan_json_value(item, config, results, seen)),
            Value::String(s) => {
                let st = s.trim();
                if st.starts_with(['{', '[']) {
                    if let Ok(inner) = serde_json::from_str::<Value>(st) {
                        Self::scan_json_value(&inner, config, results, seen);
                        return;
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
        let decoded = decode_inline_unicode(payload);
        let target = decoded.as_ref().map_or(payload, |d| d.text.as_str());
        for span in resolve_overlaps(scan_spans(target, config)) {
            let raw = target[span.start..span.end].to_string();
            if seen.insert(raw.clone()) {
                results.push((span.kind, span.label, raw, span.severity));
            }
        }
    }

    /// Snake-case alias for `scan_Matches`.
    pub fn scan_matches(payload: &str, config: &HideConfig) -> Vec<(FindingKind, String, String, String)> {
        Self::scan_Matches(payload, config)
    }
}

/// Text with `\uXXXX` escapes decoded, plus a map from decoded byte offsets back to the source.
pub struct DecodedText {
    pub text: String,
    /// `origin[i]` is the source byte offset of decoded byte `i`; one extra trailing entry.
    origin: Vec<usize>,
}

impl DecodedText {
    pub fn source_offset(&self, decoded: usize) -> usize {
        self.origin[decoded]
    }
}

/// Decode inline `\uXXXX` escapes for detection only. Returns `None` when there are none.
pub fn decode_inline_unicode(input: &str) -> Option<DecodedText> {
    if !input.contains("\\u") {
        return None;
    }
    static UNICODE_ESC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap());
    let mut text = String::with_capacity(input.len());
    let mut origin = Vec::with_capacity(input.len() + 1);
    let mut last = 0;
    let mut changed = false;
    for caps in UNICODE_ESC_RE.captures_iter(input) {
        let m = caps.get(0).unwrap();
        let Some(ch) = u32::from_str_radix(&caps[1], 16).ok().and_then(char::from_u32) else {
            continue;
        };
        text.push_str(&input[last..m.start()]);
        origin.extend(last..m.start());
        origin.extend(std::iter::repeat_n(m.start(), ch.len_utf8()));
        text.push(ch);
        last = m.end();
        changed = true;
    }
    if !changed {
        return None;
    }
    text.push_str(&input[last..]);
    origin.extend(last..input.len());
    origin.push(input.len());
    Some(DecodedText { text, origin })
}

/// Map a decoded span end to the source: an escape ending the span covers all of its source bytes.
pub fn source_span(decoded: &DecodedText, start: usize, end: usize, source: &str) -> (usize, usize) {
    let s = decoded.source_offset(start);
    let e = if end >= decoded.text.len() {
        source.len()
    } else {
        decoded.source_offset(end)
    };
    (s, e.max(s))
}

/// Top-level convenience function matching `ProjectScanner::scan_Matches`.
#[allow(non_snake_case)]
pub fn scan_Matches(payload: &str, config: &HideConfig) -> Vec<(FindingKind, String, String, String)> {
    ProjectScanner::scan_Matches(payload, config)
}

/// Top-level snake_case convenience function matching `ProjectScanner::scan_Matches`.
pub fn scan_matches(payload: &str, config: &HideConfig) -> Vec<(FindingKind, String, String, String)> {
    ProjectScanner::scan_Matches(payload, config)
}
