use crate::config::{CustomRule, FindingKind, HideConfig};
use crate::vault::MAX_JSON_DEPTH;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::{Regex, RegexBuilder, RegexSet};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

struct BuiltinRule {
    kind: FindingKind,
    label: &'static str,
    severity: &'static str,
    pattern: String,
    regex: Regex,
    capture_group: usize,
    key_group: Option<usize>,
}

fn rule(kind: FindingKind, label: &'static str, severity: &'static str, re: &str, capture_group: usize) -> BuiltinRule {
    BuiltinRule {
        kind,
        label,
        severity,
        pattern: re.to_string(),
        regex: Regex::new(re).expect("valid builtin regex"),
        capture_group,
        key_group: None,
    }
}

fn kv_rule(label: &'static str, severity: &'static str, re: &str, key_group: usize, value_group: usize) -> BuiltinRule {
    BuiltinRule {
        kind: FindingKind::EnvSecret,
        label,
        severity,
        pattern: re.to_string(),
        regex: Regex::new(re).expect("valid builtin regex"),
        capture_group: value_group,
        key_group: Some(key_group),
    }
}

const ENV_SECRET_KEYS_RE: &str = r"(?:[A-Z0-9_]{1,40}_)?(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|ACCESS_TOKEN|AUTH_TOKEN|REFRESH_TOKEN|BOT_TOKEN|BEARER_TOKEN|PRIVATE_KEY|DB_PASS|DB_PASSWORD|ACCESS_KEY|API_KEY|APIKEY|CLIENT_SECRET|SIGNING_KEY|ENCRYPTION_KEY|WEBHOOK_SECRET)";

static BUILTIN_RULES: Lazy<Vec<BuiltinRule>> = Lazy::new(|| {
    use FindingKind::*;
    vec![
        rule(
            PrivateKey,
            "PEM Private Key",
            "critical",
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|[A-Za-z0-9+/=\r\n\t \\]{0,16384})",
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
        rule(
            ApiKey,
            "AWS Access Key ID",
            "critical",
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            0,
        ),
        rule(
            ApiKey,
            "GitHub Personal Access Token",
            "critical",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{20,}|\bgithub_pat_[a-zA-Z0-9_]{20,}",
            0,
        ),
        rule(
            ApiKey,
            "GitLab Token",
            "critical",
            r"\bgl(?:pat|rt|ptt|oass)-[0-9A-Za-z_-]{20,}\b",
            0,
        ),
        rule(
            ApiKey,
            "Google / Firebase API Key",
            "critical",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            0,
        ),
        rule(
            ApiKey,
            "Stripe API Key",
            "critical",
            r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}\b",
            0,
        ),
        rule(
            ApiKey,
            "Slack Token",
            "critical",
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
            0,
        ),
        rule(
            ApiKey,
            "Slack Webhook URL",
            "critical",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            0,
        ),
        rule(
            ApiKey,
            "Enterprise IM / Discord Webhook",
            "critical",
            r"https://(?:oapi\.dingtalk\.com/robot/send\?access_token=[A-Za-z0-9_-]{20,}|open\.feishu\.cn/open-apis/bot/v2/hook/[A-Za-z0-9_-]{16,}|qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[A-Za-z0-9_-]{16,}|(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{16,22}/[A-Za-z0-9_-]{40,})",
            0,
        ),
        rule(ApiKey, "HuggingFace Token", "critical", r"\bhf_[A-Za-z0-9]{20,}\b", 0),
        rule(ApiKey, "npm Access Token", "critical", r"\bnpm_[A-Za-z0-9]{30,}\b", 0),
        rule(
            ApiKey,
            "PyPI API Token",
            "critical",
            r"\bpypi-AgEI[A-Za-z0-9_-]{40,}\b",
            0,
        ),
        rule(ApiKey, "Groq API Key", "critical", r"\bgsk_[A-Za-z0-9]{20,}\b", 0),
        rule(
            ApiKey,
            "Perplexity API Key",
            "critical",
            r"\bpplx-[A-Za-z0-9]{24,}\b",
            0,
        ),
        rule(ApiKey, "Replicate API Token", "critical", r"\br8_[A-Za-z0-9]{24,}\b", 0),
        rule(
            ApiKey,
            "SendGrid API Key",
            "critical",
            r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
            0,
        ),
        rule(
            ApiKey,
            "Aliyun AccessKey ID",
            "critical",
            r"\bLTAI[A-Za-z0-9]{16,24}\b",
            0,
        ),
        rule(
            ApiKey,
            "Tencent Cloud SecretId",
            "critical",
            r"\bAKID[A-Za-z0-9]{28,40}\b",
            0,
        ),
        rule(ApiKey, "xAI Grok API Key", "critical", r"\bxai-[a-zA-Z0-9_-]{16,}", 0),
        rule(
            ApiKey,
            "JSON Web Token",
            "high",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            0,
        ),
        rule(
            DatabaseUrl,
            "Database Connection URI",
            "critical",
            r#"\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|mssql|sqlserver|clickhouse|cockroachdb|nats|kafka)://[^\s'`<>]+"#,
            0,
        ),
        rule(
            DatabaseUrl,
            "Authenticated Service URL",
            "critical",
            r#"\bhttps?://[^:\s/@"'`<>]+:[^@\s/"'`<>]+@[^\s'`<>]+"#,
            0,
        ),
        rule(
            EnvSecret,
            "HTTP Authorization Header",
            "high",
            r"(?i)\bAuthorization\s*[:=]\s*(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{16,})",
            1,
        ),
        kv_rule(
            "Environment / Config Secret",
            "high",
            &format!(r#"(?i)["']?\b({ENV_SECRET_KEYS_RE})\b["']?\s*[=:]\s*"([^"\r\n]+)""#),
            1,
            2,
        ),
        kv_rule(
            "Environment / Config Secret",
            "high",
            &format!(r#"(?i)["']?\b({ENV_SECRET_KEYS_RE})\b["']?\s*[=:]\s*'([^'\r\n]+)'"#),
            1,
            2,
        ),
        kv_rule(
            "Environment / Config Secret",
            "high",
            &format!(r#"(?i)["']?\b({ENV_SECRET_KEYS_RE})\b["']?\s*[=:]\s*([^\s,;\}}\]"']+)"#),
            1,
            2,
        ),
        rule(
            InternalIp,
            "Private Intranet IPv4",
            "high",
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b",
            0,
        ),
        rule(
            InternalDomain,
            "Internal Corporate Domain",
            "medium",
            r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:internal|corp|local|lan|intranet|localdomain|home\.arpa)\b",
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
            r"(?:^|[^A-Za-z0-9._/~-])(/mnt/[a-zA-Z]/[Uu]sers/[A-Za-z0-9._-]+)",
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
            r"\b([A-Za-z]:/[Uu]sers/[A-Za-z0-9._-]+)",
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
            ProjectPath,
            "Local Workspace Path",
            "medium",
            r"\b([A-Za-z]:/[A-Za-z0-9._-]+)/[A-Za-z0-9._-]",
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

static BUILTIN_PREFILTER_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new(BUILTIN_RULES.iter().map(|r| r.pattern.as_str())).expect("valid builtin regex prefilter")
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

fn normalize_key_snake(key: &str) -> String {
    let trimmed = key
        .trim()
        .trim_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');
    let mut out = String::with_capacity(trimmed.len() + 4);
    let mut prev_sep = true;
    let mut prev_lower_or_digit = false;
    for ch in trimmed.chars() {
        if matches!(ch, '-' | '.' | ' ' | '_') {
            if !prev_sep && !out.is_empty() {
                out.push('_');
            }
            prev_sep = true;
            prev_lower_or_digit = false;
        } else if ch.is_ascii_uppercase() {
            if prev_lower_or_digit && !prev_sep {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
            prev_lower_or_digit = false;
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
            prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn is_non_secret_normalized_key(norm: &str) -> bool {
    matches!(
        norm,
        "page_token"
            | "next_page_token"
            | "prev_page_token"
            | "previous_page_token"
            | "continuation_token"
            | "sync_token"
            | "resume_token"
            | "cancel_token"
            | "cancellation_token"
            | "abort_token"
            | "max_token"
            | "min_token"
            | "prompt_token"
            | "completion_token"
            | "input_token"
            | "output_token"
            | "total_token"
            | "budget_token"
            | "thinking_token"
            | "token_count"
            | "token_limit"
            | "token_type"
            | "token_url"
            | "token_endpoint"
            | "token_prefix"
            | "token_header"
            | "token_field"
            | "token_name"
            | "ast_token"
            | "lex_token"
            | "lexer_token"
            | "syntax_token"
            | "eof_token"
            | "eos_token"
            | "bos_token"
            | "pad_token"
            | "unk_token"
            | "sep_token"
            | "cls_token"
            | "mask_token"
            | "stop_token"
            | "special_token"
            | "secret_name"
            | "secret_arn"
            | "secret_id"
            | "secret_ref"
            | "secret_path"
            | "secret_version"
            | "password_field"
            | "password_min_length"
            | "password_hash_algo"
            | "public_key"
            | "key_type"
            | "key_name"
            | "key_path"
            | "csrf_token_name"
    ) || norm.ends_with("_page_token")
        || norm.ends_with("_secret_name")
        || norm.ends_with("_secret_arn")
        || norm.ends_with("_secret_id")
        || norm.ends_with("_secret_ref")
        || norm.ends_with("_secret_path")
        || norm.ends_with("_public_key")
}

/// Keys that look superficially like credentials (e.g. `nextPageToken`, `max_token`,
/// `secret_name`, `public_key`) but identify pagination cursors, counters, or metadata.
pub fn is_non_secret_key_name(key: &str) -> bool {
    let norm = normalize_key_snake(key);
    !norm.is_empty() && is_non_secret_normalized_key(&norm)
}

/// Check if a JSON object property key represents a sensitive secret / credential field
pub fn is_sensitive_secret_key(key: &str) -> bool {
    let norm = normalize_key_snake(key);
    if norm.is_empty() || is_non_secret_normalized_key(&norm) {
        return false;
    }
    matches!(
        norm.as_str(),
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
            | "refreshtoken"
            | "bot_token"
            | "bearer_token"
            | "private_key"
            | "privatekey"
            | "api_key"
            | "apikey"
            | "access_key"
            | "accesskey"
            | "aws_access_key_id"
            | "aws_secret_access_key"
            | "db_pass"
            | "db_password"
            | "database_password"
            | "signing_key"
            | "encryption_key"
            | "webhook_secret"
    ) || [
        "_password",
        "_passwd",
        "_pwd",
        "_secret",
        "_secret_key",
        "_api_key",
        "_apikey",
        "_access_key",
        "_private_key",
        "_auth_token",
        "_access_token",
        "_refresh_token",
        "_bot_token",
        "_bearer_token",
        "_signing_key",
        "_encryption_key",
        "_webhook_secret",
        "_db_pass",
        "_client_secret",
        "_token",
    ]
    .iter()
    .any(|suffix| norm.ends_with(suffix))
}

/// True when `s` is an RFC 2544 benchmark IPv4 address (`198.18.0.0/15`) used for IP placeholders.
fn is_benchmark_ipv4(s: &str) -> bool {
    let mut parts = s.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("198"), Some(b), Some(c), Some(d), None)
            if matches!(b, "18" | "19") && c.parse::<u8>().is_ok() && d.parse::<u8>().is_ok()
    )
}

/// Check if a value is already a Hide-Go placeholder token
pub fn is_placeholder_token(val: &str) -> bool {
    let trimmed = val.trim();
    (trimmed.starts_with("<<") && trimmed.ends_with(">>"))
        || trimmed.starts_with("⟦HIDE-CIPHER::")
        || trimmed.starts_with("sk-sem-")
        || trimmed.contains("db_pass_placeholder_")
        || trimmed.contains("/workspace/user_")
        || trimmed.contains("workspace/user_")
        || trimmed.contains("workspace\\user_")
        || trimmed.contains("workspace\\\\user_")
        || trimmed.ends_with(".example.internal")
        || trimmed.ends_with("@sandbox.example.org")
        || trimmed.starts_with("git-ref-placeholder-")
        || trimmed.starts_with("CustomConcept_")
        || trimmed.starts_with("sym_entity_")
        || is_benchmark_ipv4(trimmed)
}

/// Reject environment variable expansions, template placeholders, and redaction masks
/// even when enclosed in quotes.
pub fn is_placeholder_or_template_secret(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return true;
    }
    if let Some(after_dollar) = trimmed.strip_prefix('$') {
        if let Some(inner) = after_dollar.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if !inner.is_empty() {
                return true;
            }
        }
        let mut chars = after_dollar.chars();
        if chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return true;
        }
    }
    if (trimmed.starts_with('%') && trimmed.ends_with('%') && trimmed.len() >= 3)
        || (trimmed.starts_with("{{") && trimmed.ends_with("}}") && trimmed.len() >= 5)
    {
        return true;
    }
    if trimmed.starts_with('<') && trimmed.ends_with('>') && trimmed.len() >= 3 {
        let inner = &trimmed[1..trimmed.len() - 1];
        if !inner.contains(char::is_whitespace) || inner.to_ascii_lowercase().starts_with("your") {
            return true;
        }
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "changeme"
            | "change_me"
            | "change-me"
            | "replace_me"
            | "replace-me"
            | "your_api_key"
            | "your-api-key"
            | "your_api_key_here"
            | "your-api-key-here"
            | "your_secret"
            | "your-secret"
            | "your_secret_here"
            | "your-secret-here"
            | "your_token"
            | "your-token"
            | "your_token_here"
            | "your-token-here"
            | "your_password"
            | "your-password"
            | "example"
            | "placeholder"
            | "dummy"
            | "redacted"
            | "todo"
    ) {
        return true;
    }
    trimmed.chars().all(|c| matches!(c, '*' | 'x' | 'X' | '•' | '.'))
}

fn is_non_secret_env_token(raw: &str, is_quoted: bool) -> bool {
    if is_placeholder_or_template_secret(raw) {
        return true;
    }
    if is_quoted {
        return false;
    }
    if raw.starts_with(['$', '%', '&', '<', '[', '(', '{'])
        || raw.contains("->")
        || raw.contains("::")
        || raw.contains(['(', ')'])
        || raw.ends_with(['>', ']', ')'])
    {
        return true;
    }
    let lower = raw.to_ascii_lowercase();
    const CODE_REF_PREFIXES: &[&str] = &[
        "process.env.",
        "os.environ",
        "self.",
        "this.",
        "req.",
        "res.",
        "ctx.",
        "cfg.",
        "config.",
        "args.",
        "params.",
        "opts.",
        "options.",
        "props.",
        "state.",
        "settings.",
        "env.",
        "input.",
        "payload.",
        "headers.",
        "body.",
    ];
    if CODE_REF_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    matches!(
        lower.as_str(),
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
    (lower.ends_with(":\\workspace") || lower.ends_with(":\\\\workspace") || lower.ends_with(":/workspace"))
        && (tail.starts_with("\\user_") || tail.starts_with("\\\\user_") || tail.starts_with("/user_"))
}

fn is_system_windows_dir(raw: &str) -> bool {
    if raw.as_bytes().get(1) != Some(&b':') {
        return false;
    }
    let trimmed = raw[2..].trim_start_matches(['\\', '/']);
    let first = trimmed.split(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    matches!(
        first.as_str(),
        "windows" | "programdata" | "program files" | "program files (x86)" | "system32" | "msys64" | "cygwin64"
    )
}

fn is_valid_ipv4_span(raw: &str, after: &str) -> bool {
    if after.starts_with('.') && after.as_bytes().get(1).is_some_and(u8::is_ascii_digit) {
        return false;
    }
    let mut parts = raw.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), Some(d), None)
            if a.parse::<u8>().is_ok()
                && b.parse::<u8>().is_ok()
                && c.parse::<u8>().is_ok()
                && d.parse::<u8>().is_ok()
    )
}

fn is_false_positive_internal_domain(text: &str, start: usize, end: usize) -> bool {
    if start > 0 && text.as_bytes()[start - 1] == b'.' {
        return true;
    }
    let after = &text[end..];
    if after.starts_with('(') {
        return true;
    }
    if let Some(ext_rest) = after.strip_prefix('.') {
        let ext: String = ext_rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "json"
                | "yaml"
                | "yml"
                | "toml"
                | "env"
                | "js"
                | "ts"
                | "tsx"
                | "jsx"
                | "mjs"
                | "cjs"
                | "rs"
                | "py"
                | "go"
                | "md"
                | "txt"
                | "ini"
                | "conf"
                | "cfg"
                | "xml"
                | "sh"
                | "ps1"
                | "bat"
                | "lock"
                | "example"
                | "sample"
                | "dist"
                | "bak"
                | "template"
        ) {
            return true;
        }
    }
    let raw_lower = text[start..end].to_ascii_lowercase();
    if raw_lower == "localhost.localdomain" {
        return true;
    }
    if raw_lower.bytes().filter(|&b| b == b'.').count() == 1 {
        let root = raw_lower.split('.').next().unwrap_or("");
        if matches!(
            root,
            "this"
                | "self"
                | "super"
                | "crate"
                | "env"
                | "config"
                | "settings"
                | "window"
                | "document"
                | "global"
                | "process"
                | "thread"
                | "storage"
                | "session"
                | "state"
                | "ctx"
                | "context"
                | "app"
                | "module"
                | "package"
                | "docker-compose"
                | "compose"
                | "makefile"
                | "tsconfig"
                | "vite"
                | "webpack"
                | "next"
                | "nuxt"
                | "cargo"
                | "npm"
                | "yarn"
                | "pnpm"
                | "git"
                | "ssh"
                | "k8s"
                | "helm"
                | "terraform"
                | "pytest"
                | "jest"
                | "vitest"
                | "eslint"
                | "prettier"
                | "localhost"
                | "example"
        ) {
            return true;
        }
    }
    false
}

fn is_false_positive_email(raw: &str) -> bool {
    let Some((_, tld)) = raw.rsplit_once('.') else {
        return false;
    };
    matches!(
        tld.to_ascii_lowercase().as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "webp"
            | "gif"
            | "svg"
            | "ico"
            | "avif"
            | "bmp"
            | "tiff"
            | "tif"
            | "css"
            | "scss"
            | "less"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "json"
            | "toml"
            | "yaml"
            | "yml"
            | "rs"
            | "go"
            | "py"
            | "java"
            | "kt"
            | "swift"
            | "cpp"
            | "hpp"
            | "txt"
            | "md"
            | "lock"
            | "map"
            | "wasm"
            | "exe"
            | "dll"
            | "dylib"
            | "pdf"
            | "zip"
            | "tar"
            | "gz"
    )
}

/// Clean trailing quote/punctuation from a matched Database URL when it was enclosed in quotes in prose.
/// Preserves embedded quotes inside credentials (before the authority `@`) while truncating before quotes
/// that close a JSON string or follow the authority/host section.
pub fn clean_database_url_match(raw: &str) -> &str {
    let mut s = raw;
    if let Some(scheme_end) = s.find("://") {
        let rest_start = scheme_end + 3;
        let rest = &s[rest_start..];
        let auth_end = rest.find('/').unwrap_or(rest.len());
        let search_from = rest[..auth_end].rfind('@').map_or(rest_start, |at| rest_start + at + 1);
        if let Some(quote_rel) = s[search_from..].find('"') {
            s = &s[..search_from + quote_rel];
        }
    }
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

pub struct CompiledCustomRule {
    pub name: String,
    pub replacement_hint: String,
    pub regex: Regex,
}

/// Pre-compiled custom rules + `RegexSet` prefilter cached per active rule signature.
pub struct CompiledScanner {
    pub custom_rules: Vec<CompiledCustomRule>,
    custom_set: Option<RegexSet>,
}

type ScannerCacheKey = Vec<(String, String, String)>;
type CompiledScannerMap = HashMap<ScannerCacheKey, Arc<CompiledScanner>>;

static COMPILED_SCANNER_CACHE: Lazy<Mutex<CompiledScannerMap>> = Lazy::new(|| Mutex::new(HashMap::new()));

impl CompiledScanner {
    pub fn for_config(config: &HideConfig) -> Arc<Self> {
        let key: Vec<(String, String, String)> = config
            .custom_rules
            .iter()
            .filter(|r| r.enabled && !r.pattern.trim().is_empty())
            .map(|r| (r.name.clone(), r.pattern.clone(), r.replacement_hint.clone()))
            .collect();
        let mut cache = COMPILED_SCANNER_CACHE.lock();
        if let Some(hit) = cache.get(&key) {
            return hit.clone();
        }
        let mut custom_rules = Vec::with_capacity(key.len());
        let mut patterns = Vec::with_capacity(key.len());
        for (name, pattern, replacement_hint) in &key {
            if let Ok(re) = compile_custom_regex(pattern) {
                custom_rules.push(CompiledCustomRule {
                    name: name.clone(),
                    replacement_hint: replacement_hint.clone(),
                    regex: re,
                });
                patterns.push(pattern.as_str());
            }
        }
        let custom_set = if patterns.is_empty() {
            None
        } else {
            RegexSet::new(patterns).ok()
        };
        if cache.len() > 64 {
            cache.clear();
        }
        let compiled = Arc::new(Self {
            custom_rules,
            custom_set,
        });
        cache.insert(key, compiled.clone());
        compiled
    }
}

/// Positional scan of plain text. Spans may overlap; callers resolve overlaps.
/// Custom rules come first so project codenames win ties against generic detectors.
pub fn scan_spans(text: &str, config: &HideConfig) -> Vec<Span> {
    let compiled = CompiledScanner::for_config(config);
    scan_spans_with_scanner(text, config, &compiled)
}

/// Positional scan using a pre-compiled scanner and `RegexSet` single-pass prefilter.
pub fn scan_spans_with_scanner(text: &str, config: &HideConfig, scanner: &CompiledScanner) -> Vec<Span> {
    let custom_hits = scanner.custom_set.as_ref().map(|set| set.matches(text));
    let builtin_hits = BUILTIN_PREFILTER_SET.matches(text);
    if !builtin_hits.matched_any() && !custom_hits.as_ref().is_some_and(|m| m.matched_any()) {
        return Vec::new();
    }

    let mut spans = Vec::new();
    if let Some(hits) = custom_hits {
        for idx in hits {
            let rule = &scanner.custom_rules[idx];
            for m in rule.regex.find_iter(text) {
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
    for idx in builtin_hits {
        let rule = &BUILTIN_RULES[idx];
        if !rule_enabled(rule.kind, config) {
            continue;
        }
        for caps in rule.regex.captures_iter(text) {
            if let Some(kg) = rule.key_group {
                if caps.get(kg).is_some_and(|k| {
                    is_non_secret_key_name(k.as_str()) || (k.start() > 0 && text.as_bytes()[k.start() - 1] == b':')
                }) {
                    continue;
                }
            }
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
                let is_quoted = m.start() > 0 && matches!(text.as_bytes().get(m.start() - 1), Some(b'"' | b'\''));
                if is_non_secret_env_token(raw, is_quoted) {
                    continue;
                }
            }
            if rule.kind == FindingKind::InternalIp && !is_valid_ipv4_span(raw, &text[end..]) {
                continue;
            }
            if rule.kind == FindingKind::InternalDomain && is_false_positive_internal_domain(text, m.start(), end) {
                continue;
            }
            if rule.kind == FindingKind::EmailOrPii && is_false_positive_email(raw) {
                continue;
            }
            if rule.kind == FindingKind::ProjectPath
                && (is_placeholder_windows_workspace(raw, &text[end..]) || is_system_windows_dir(raw))
            {
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
        let scanner = CompiledScanner::for_config(config);
        let trimmed = payload.trim();
        if trimmed.starts_with(['{', '[', '"']) {
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                Self::scan_json_value_depth(&val, config, &scanner, &mut results, &mut seen, 0);
                return results;
            }
        }
        Self::scan_plain_text_into(payload, config, &scanner, &mut results, &mut seen);
        results
    }

    fn scan_json_value_depth(
        val: &Value,
        config: &HideConfig,
        scanner: &CompiledScanner,
        results: &mut Vec<(FindingKind, String, String, String)>,
        seen: &mut HashSet<String>,
        depth: usize,
    ) {
        if depth >= MAX_JSON_DEPTH {
            if let Value::String(s) = val {
                Self::scan_plain_text_into(s, config, scanner, results, seen);
            }
            return;
        }
        match val {
            Value::Object(map) => {
                for (k, v) in map {
                    Self::scan_plain_text_into(k, config, scanner, results, seen);
                    if config.protect_secrets_and_keys && is_sensitive_secret_key(k) {
                        let raw = match v {
                            Value::String(s)
                                if !s.trim().is_empty()
                                    && !is_placeholder_token(s)
                                    && !is_placeholder_or_template_secret(s)
                                    && (!k.eq_ignore_ascii_case("token") || s.trim().len() >= 6) =>
                            {
                                Some(s.clone())
                            }
                            Value::Number(_) if !k.eq_ignore_ascii_case("token") => Some(v.to_string()),
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
                    Self::scan_json_value_depth(v, config, scanner, results, seen, depth + 1);
                }
            }
            Value::Array(arr) => arr
                .iter()
                .for_each(|item| Self::scan_json_value_depth(item, config, scanner, results, seen, depth + 1)),
            Value::String(s) => {
                let st = s.trim();
                if depth + 1 < MAX_JSON_DEPTH && st.starts_with(['{', '[']) {
                    if let Ok(inner) = serde_json::from_str::<Value>(st) {
                        Self::scan_json_value_depth(&inner, config, scanner, results, seen, depth + 1);
                        return;
                    }
                }
                Self::scan_plain_text_into(s, config, scanner, results, seen);
            }
            _ => {}
        }
    }

    pub(crate) fn scan_plain_text_into(
        payload: &str,
        config: &HideConfig,
        scanner: &CompiledScanner,
        results: &mut Vec<(FindingKind, String, String, String)>,
        seen: &mut HashSet<String>,
    ) {
        let decoded = decode_inline_unicode(payload);
        let target = decoded.as_ref().map_or(payload, |d| d.text.as_str());
        for span in resolve_overlaps(scan_spans_with_scanner(target, config, scanner)) {
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

const MAX_INLINE_UNICODE_DECODE_BYTES: usize = 32 * 1024 * 1024;

/// Text with `\uXXXX` escapes decoded, plus a map from decoded byte offsets back to the source.
pub struct DecodedText {
    pub text: String,
    /// `origin[i]` is the source byte offset of decoded byte `i`; one extra trailing entry.
    origin: Vec<u32>,
}

impl DecodedText {
    pub fn source_offset(&self, decoded: usize) -> usize {
        self.origin[decoded] as usize
    }
}

/// Decode inline `\uXXXX` escapes for detection only. Returns `None` when there are none.
pub fn decode_inline_unicode(input: &str) -> Option<DecodedText> {
    if input.len() > MAX_INLINE_UNICODE_DECODE_BYTES || !input.contains("\\u") {
        return None;
    }
    static UNICODE_ESC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap());
    let mut text = String::with_capacity(input.len());
    let mut origin = Vec::with_capacity(input.len() + 1);
    let mut last = 0;
    let mut changed = false;
    for caps in UNICODE_ESC_RE.captures_iter(input) {
        let Some(m) = caps.get(0) else {
            continue;
        };
        let Some(ch) = u32::from_str_radix(&caps[1], 16).ok().and_then(char::from_u32) else {
            continue;
        };
        text.push_str(&input[last..m.start()]);
        origin.extend((last..m.start()).map(|i| i as u32));
        origin.extend(std::iter::repeat_n(m.start() as u32, ch.len_utf8()));
        text.push(ch);
        last = m.end();
        changed = true;
    }
    if !changed {
        return None;
    }
    text.push_str(&input[last..]);
    origin.extend((last..input.len()).map(|i| i as u32));
    origin.push(input.len() as u32);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expanded_cloud_ai_and_webhook_detectors_match() {
        let cfg = HideConfig::default();
        let join = |prefix: &str, body: &str| format!("{prefix}{body}");
        let samples = [
            join("aws=AS", "IAIOSFODNN7EXAMPLE"),
            join("google=AI", "zaSyDummyKeyValueForTesting1234567890"),
            join("stripe=sk_live_", "51N9xYzDummyStripeSecretKeyForTests12345"),
            join("gitlab=gl", "pat-xxxxxxxxxxxxxxxxxxxx1234"),
            join("slack=xo", "xb-1234567890-1234567890123-abcdefghij"),
            join(
                "hook=https://hooks.slack.com/",
                "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            ),
            join(
                "discord=https://discord.com/api/",
                "webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
            ),
            join("hf=hf_", "abcdefghijklmnopqrstuvwxyz1234"),
            join("npm=npm_", "abcdefghijklmnopqrstuvwxyz123456"),
            join(
                "pypi=pypi-AgEI",
                "cHlwaS5vcmcCJGYwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMA",
            ),
            join("groq=gsk_", "abcdefghijklmnopqrstuvwxyz1234"),
            join("pplx=pplx-", "abcdefghijklmnopqrstuvwxyz1234"),
            join("rep=r8_", "abcdefghijklmnopqrstuvwxyz1234"),
            join("sg=SG.", "abcdefghijklmnop.qrstuvwxyz1234567890"),
            join("ali=LTAI", "5tDummyAliyunAccessKey"),
            join("tencent=AKID", "DummyTencentSecretId1234567890abcdef"),
            join(
                "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            ),
            join("Authorization: Bearer ", "verySecretBearerTokenValue123456"),
            join("GITHUB_WEBHOOK_SECRET=\"", "whsec_super_real_value_123\""),
            join("https://deploy_bot:", "SecretPass99@git.corp.internal/repo.git"),
            join("amqps://mq_user:", "mq_pass@10.2.3.4:5671/vhost"),
        ];
        for sample in samples {
            let found = scan_matches(&sample, &cfg);
            assert!(!found.is_empty(), "expected finding for sample: {sample}");
        }
    }

    #[test]
    fn compact_json_database_url_does_not_swallow_adjacent_element() {
        let raw = "[\"postgres://user:pass@10.0.0.1:5432/db\",\"next\"]";
        let cfg = HideConfig::default();
        let found = scan_matches(raw, &cfg);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].2, "postgres://user:pass@10.0.0.1:5432/db");
    }

    #[test]
    fn false_positive_guards_skip_non_secrets_config_files_assets_and_bad_ips() {
        let cfg = HideConfig::default();
        let safe_inputs = [
            // Pagination, usage counters, and metadata keys
            r#"{"nextPageToken":"abc123456789","max_token":4096,"token":42,"public_key":"ssh-ed25519 AAAA","secret_name":"prod/api/key","secretArn":"arn:aws:secretsmanager:us-east-1:123:secret:foo"}"#,
            "next_page_token = \"cursor_xyz_12345\"",
            // Env templates & redaction masks
            "GITHUB_TOKEN=\"$GITHUB_TOKEN\"\nAPI_KEY=\"${OPENAI_API_KEY}\"\nSECRET=\"<your-secret-here>\"\nPASSWORD=\"********\"\nCLIENT_SECRET=\"placeholder\"",
            // Code references & expressions
            "api_key = process.env.OPENAI_API_KEY\ntoken = os.getenv(\"API_TOKEN\")\nsecret = self.config.secret",
            // Config filenames & code identifiers looking like .local/.internal
            "Edit .env.local and settings.local.json and docker-compose.local.yml and this.internal() and localhost.localdomain",
            // Retina assets looking like email
            "Load icon@2x.png, logo@3x.webp, and sprite@2x.svg from public/assets",
            // Invalid octets, 5-part OIDs, Windows system paths
            "Build 10.0.26100.1234 OID 10.1.2.3.4 path C:\\Windows\\System32\\cmd.exe and D:/ProgramData/cache/a.dat",
        ];
        for input in safe_inputs {
            let found = scan_matches(input, &cfg);
            assert!(found.is_empty(), "unexpected false positive in `{input}`: {found:?}");
        }
    }

    #[test]
    fn tailscale_ips_wsl2_and_forward_slash_windows_paths_are_detected() {
        let cfg = HideConfig::default();
        let tailscale = scan_matches("peer 100.88.12.34:22", &cfg);
        assert_eq!(tailscale.len(), 1);
        assert_eq!(tailscale[0].0, FindingKind::InternalIp);
        assert_eq!(tailscale[0].2, "100.88.12.34");

        let wsl = scan_matches("open /mnt/c/Users/alice/work/main.rs", &cfg);
        assert_eq!(wsl.len(), 1);
        assert_eq!(wsl[0].2, "/mnt/c/Users/alice");

        let fwd = scan_matches("edit D:/Projects/secret-app/src/lib.rs", &cfg);
        assert_eq!(fwd.len(), 1);
        assert_eq!(fwd[0].2, "D:/Projects");
    }
}
