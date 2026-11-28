//! Hybrid on-device privacy guard model combining deterministic validators with a compact
//! 2-layer contextual MLP scorer over bilingual (Chinese/English/code-mixed) sliding windows.
//!
//! Two responsibilities:
//! 1. **Recall expansion**: propose contextual PII and secrets that static regexes miss
//!    (Chinese/international phones, GB 11643-1999 Resident IDs, Luhn payment cards,
//!    physical addresses, contextual personal names, account handles, prose passwords,
//!    HTTP cookies, and CLI credentials).
//! 2. **Precision gating**: evaluate every candidate span against its surrounding `[-72..+72]`
//!    character context window, suppressing coding-agent false positives (UI token counters,
//!    ISO timestamps, commit SHAs, UUIDs, semver strings, base64 data URIs, and test placeholders)
//!    via a calibrated probability threshold (`guard_threshold`, default `0.80`).
//!
//! Hot-path performance guarantees:
//! - Single-pass `RegexSet` DFA prefilter (`GUARD_PROPOSER_SET`) skips all 13 proposers in one
//!   O(N) scan when no candidate pattern matches.
//! - Precompiled `RegexSet` (`NEG_METADATA_SET`) replaces 47+ substring loops per candidate.
//! - Zero-allocation stack buffers in mathematical validators and boundary checks.
//! - O(K log K) `BTreeMap` interval overlap resolution and bounded candidate/minified-blob caps.

use crate::classifier::shannon_entropy_bits;
use crate::config::{FindingKind, HideConfig};
use crate::scanner::{is_placeholder_or_template_secret, is_placeholder_token, Span};
use once_cell::sync::Lazy;
use regex::{Regex, RegexSet, RegexSetBuilder};
use std::collections::BTreeMap;

/// Sliding window radius in UTF-8 characters inspected on each side of a candidate span.
const CONTEXT_WINDOW_CHARS: usize = 72;

/// Hard upper bound on guard-model candidates evaluated per string to bound worst-case latency.
const MAX_GUARD_CANDIDATES_PER_STRING: usize = 512;

/// Single-string byte length above which dense unsegmented blobs (minified JS, raw base64 dumps)
/// skip heavy prose/PII proposers while preserving deterministic rule scanning.
const MAX_UNSEGMENTED_BLOB_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardEntity {
    Secret,
    Phone,
    IdCard,
    PaymentCard,
    Email,
    Person,
    Address,
    Account,
    InternalIp,
    Other,
}

#[derive(Debug, Clone)]
pub struct ScoredSpan {
    pub span: Span,
    pub entity: GuardEntity,
    pub confidence: f32,
    pub priority: u8,
}

/// 16-dimensional normalized feature vector extracted for a candidate span and its sliding context.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpanFeatures(pub [f32; 16]);

// ---- Exact mathematical validators (zero heap allocations) ----

/// Validate a Chinese 18-digit Resident Identity Card number (GB 11643-1999 / ISO 7064 Mod 11-2).
pub fn is_valid_cn_resident_id(raw: &str) -> bool {
    let b = raw.as_bytes();
    if b.len() != 18 {
        return false;
    }
    if !b[..17].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let last = b[17].to_ascii_uppercase();
    if !(last.is_ascii_digit() || last == b'X') {
        return false;
    }
    let prov = (b[0] - b'0') * 10 + (b[1] - b'0');
    let valid_prov = matches!(
        prov,
        11..=15 | 21..=23 | 31..=37 | 41..=46 | 50..=54 | 61..=65 | 71 | 81 | 82
    );
    if !valid_prov {
        return false;
    }
    let year =
        (b[6] - b'0') as u16 * 1000 + (b[7] - b'0') as u16 * 100 + (b[8] - b'0') as u16 * 10 + (b[9] - b'0') as u16;
    let month = (b[10] - b'0') * 10 + (b[11] - b'0');
    let day = (b[12] - b'0') * 10 + (b[13] - b'0');
    if !(1900..=2099).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day < 1 || day > max_day {
        return false;
    }
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK: &[u8; 11] = b"10X98765432";
    let sum: u32 = b[..17]
        .iter()
        .enumerate()
        .map(|(i, &c)| (c - b'0') as u32 * WEIGHTS[i])
        .sum();
    CHECK[(sum % 11) as usize] == last
}

/// Compute the ISO 7064 Mod 11-2 check character for a 17-digit Resident ID prefix.
pub fn cn_id_check_char(prefix17: &[u8; 17]) -> char {
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK: &[u8; 11] = b"10X98765432";
    let sum: u32 = prefix17
        .iter()
        .enumerate()
        .map(|(i, &c)| (c.saturating_sub(b'0')) as u32 * WEIGHTS[i])
        .sum();
    CHECK[(sum % 11) as usize] as char
}

/// Validate a payment / bank card number via IIN/BIN prefix and exact Luhn Mod 10 checksum.
pub fn is_valid_luhn_payment_card(raw: &str) -> bool {
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    for b in raw.bytes() {
        if b.is_ascii_digit() {
            if n >= digits.len() {
                return false;
            }
            digits[n] = b - b'0';
            n += 1;
        }
    }
    if !(13..=19).contains(&n) {
        return false;
    }
    let slice = &digits[..n];
    if slice.iter().all(|&d| d == slice[0]) {
        return false;
    }
    let prefix6: u32 = slice[..6].iter().fold(0u32, |acc, &d| acc * 10 + d as u32);
    if prefix6 == 400000 || prefix6 == 620000 || prefix6 == 123456 {
        return false;
    }
    let p2 = slice[0] as u16 * 10 + slice[1] as u16;
    let p4 = slice[..4].iter().fold(0u16, |acc, &d| acc * 10 + d as u16);
    let valid_bin = slice[0] == 4 // Visa
        || (51..=55).contains(&p2) // MasterCard
        || (2221..=2720).contains(&p4) // MasterCard 2-series
        || p2 == 62 // UnionPay
        || ((p2 == 34 || p2 == 37) && n == 15) // Amex
        || (3528..=3589).contains(&p4) // JCB
        || p4 == 6011
        || p2 == 65; // Discover
    if !valid_bin {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in slice.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Compute Luhn check digit for a partial card digit sequence (so synthetic cards remain valid).
pub fn luhn_check_digit(prefix_digits: &[u8]) -> u8 {
    let mut sum = 0u32;
    let mut double = true;
    for &d in prefix_digits.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Check whether a candidate Chinese mobile number is valid and non-dummy (zero allocations).
fn is_valid_cn_mobile(raw: &str) -> bool {
    let mut buf = [0u8; 16];
    let mut n = 0usize;
    for b in raw.bytes() {
        if b.is_ascii_digit() {
            if n >= buf.len() {
                return false;
            }
            buf[n] = b;
            n += 1;
        }
    }
    let core = if n == 13 && buf[0] == b'8' && buf[1] == b'6' {
        &buf[2..13]
    } else if n == 11 {
        &buf[..11]
    } else {
        return false;
    };
    if core[0] != b'1' || !(b'3'..=b'9').contains(&core[1]) {
        return false;
    }
    if matches!(
        core,
        b"13800138000" | b"13900139000" | b"13812345678" | b"13912345678" | b"18888888888" | b"13000000000"
    ) || core.starts_with(b"19900")
    {
        return false;
    }
    let mut counts = [0u8; 10];
    for &c in core {
        counts[(c - b'0') as usize] += 1;
    }
    !counts.iter().any(|&c| c >= 8)
}

#[inline]
fn has_phone_formatting(raw: &str) -> bool {
    raw.starts_with('+') || raw.contains('-') || raw.contains(' ')
}

// ---- Sliding context extraction ----

fn left_context(text: &str, start: usize, max_chars: usize) -> &str {
    let prefix = &text[..start.min(text.len())];
    let mut cut = prefix.len();
    for (n, (idx, _)) in prefix.char_indices().rev().enumerate() {
        cut = idx;
        if n + 1 >= max_chars {
            break;
        }
    }
    &prefix[cut..]
}

fn right_context(text: &str, end: usize, max_chars: usize) -> &str {
    let suffix = &text[end.min(text.len())..];
    let mut cut = suffix.len();
    for (n, (idx, ch)) in suffix.char_indices().enumerate() {
        cut = idx + ch.len_utf8();
        if n + 1 >= max_chars {
            break;
        }
    }
    &suffix[..cut]
}

fn suffix_chars(s: &str, max_chars: usize) -> &str {
    let mut cut = s.len();
    for (n, (idx, _)) in s.char_indices().rev().enumerate() {
        cut = idx;
        if n + 1 >= max_chars {
            break;
        }
    }
    &s[cut..]
}

fn prefix_chars(s: &str, max_chars: usize) -> &str {
    let mut cut = s.len();
    for (n, (idx, ch)) in s.char_indices().enumerate() {
        cut = idx + ch.len_utf8();
        if n + 1 >= max_chars {
            break;
        }
    }
    &s[..cut]
}

fn contains_any_ci(haystack_lower: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack_lower.contains(n))
}

fn count_any_ci(haystack_lower: &str, needles: &[&str]) -> usize {
    let mut count = 0usize;
    for n in needles {
        if haystack_lower.contains(*n) {
            count += 1;
            if count >= 2 {
                break;
            }
        }
    }
    count
}

fn is_pure_hex_hash_or_uuid(raw: &str) -> bool {
    let t = raw.trim();
    if matches!(t.len(), 32 | 40 | 64) && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if t.len() == 36 {
        let b = t.as_bytes();
        if b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-' {
            return b
                .iter()
                .enumerate()
                .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit());
        }
    }
    false
}

fn looks_like_placeholder_value(raw: &str, entity: GuardEntity) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_placeholder_token(raw) || is_placeholder_or_template_secret(raw) {
        return true;
    }
    let unquoted = trimmed.trim_matches(['"', '\'', ' ']);
    if unquoted.len() >= 6
        && unquoted
            .bytes()
            .all(|b| b.eq_ignore_ascii_case(&unquoted.as_bytes()[0]))
    {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("changeme")
        || lower.contains("your_api_key")
        || lower.contains("your-api-key")
        || lower.contains("your_secret")
        || lower.contains("your-secret")
        || lower.contains("your_token")
        || lower.contains("your-token")
        || lower.contains("your_password")
        || lower.contains("your-password")
        || lower.contains("replace_me")
        || lower.contains("replace-me")
        || lower.contains("insert_here")
        || lower.contains("dummy_key")
        || lower.contains("fake_key")
        || lower.contains("test_secret_placeholder")
        || lower.starts_with("sk-your-")
        || lower.starts_with("sk-xxx")
        || lower.starts_with("sk-000000")
        || lower.starts_with("ghp_000000")
        || lower.starts_with("ghp_xxxx")
    {
        return true;
    }
    match entity {
        GuardEntity::Email => {
            if let Some((_, domain)) = lower.split_once('@') {
                if matches!(
                    domain,
                    "example.com"
                        | "example.org"
                        | "example.net"
                        | "test.com"
                        | "localhost"
                        | "localhost.localdomain"
                        | "users.noreply.github.com"
                        | "noreply.github.com"
                        | "invalid"
                ) || domain.ends_with(".example")
                    || domain.ends_with(".example.com")
                    || lower.starts_with("noreply@")
                    || lower.starts_with("no-reply@")
                    || lower.starts_with("donotreply@")
                    || lower.starts_with("dependabot")
                {
                    return true;
                }
            }
            false
        }
        GuardEntity::InternalIp => {
            lower == "0.0.0.0"
                || lower == "127.0.0.1"
                || lower.starts_with("255.255.")
                || lower.starts_with("192.0.2.")
                || lower.starts_with("198.51.100.")
                || lower.starts_with("203.0.113.")
                || lower.starts_with("198.18.")
                || lower.starts_with("198.19.")
        }
        GuardEntity::Person => matches!(
            lower.as_str(),
            "john doe" | "jane doe" | "foo bar" | "test user" | "admin user" | "张三" | "李四" | "王五"
        ),
        _ => false,
    }
}

fn looks_like_timestamp_or_version(raw: &str, left_lower: &str, right_lower: &str, entity: GuardEntity) -> bool {
    if entity == GuardEntity::InternalIp
        && (left_lower.ends_with('v')
            || left_lower.ends_with("v.")
            || contains_any_ci(
                left_lower,
                &[
                    "version",
                    "semver",
                    "release",
                    "build",
                    "sdk",
                    "protocol",
                    "schema_version",
                    "api_version",
                ],
            ))
    {
        return true;
    }
    if matches!(
        entity,
        GuardEntity::Phone | GuardEntity::PaymentCard | GuardEntity::Account
    ) {
        let mut digit_count = 0usize;
        let mut d0 = 0u8;
        let mut d1 = 0u8;
        for b in raw.bytes() {
            if b.is_ascii_digit() {
                if digit_count == 0 {
                    d0 = b;
                } else if digit_count == 1 {
                    d1 = b;
                }
                digit_count += 1;
            }
        }
        if digit_count == 13 && d0 == b'1' && matches!(d1, b'6' | b'7') {
            return true;
        }
        if contains_any_ci(
            left_lower,
            &[
                "timestamp",
                "created_at",
                "updated_at",
                "expires_at",
                "epoch",
                "millis",
                "datetime",
                "date=",
            ],
        ) || (right_lower.starts_with('t') && right_lower.contains(':'))
        {
            return true;
        }
    }
    false
}

fn is_inside_xml_counter_or_data_uri(left_lower: &str, right_lower: &str) -> bool {
    let left_trimmed = left_lower.trim_end();
    let right_trimmed = right_lower.trim_start();
    if left_trimmed.ends_with('>') && right_trimmed.starts_with("</") {
        if let Some(open_pos) = left_trimmed.rfind('<') {
            let tag = &left_trimmed[open_pos + 1..left_trimmed.len() - 1];
            if contains_any_ci(
                tag,
                &[
                    "token",
                    "usage",
                    "count",
                    "metric",
                    "duration",
                    "latency",
                    "timestamp",
                    "bytes",
                    "size",
                    "line",
                    "id",
                ],
            ) {
                return true;
            }
        }
    }
    left_lower.contains("data:image/")
        || left_lower.contains("data:font/")
        || left_lower.contains("data:audio/")
        || left_lower.contains("data:video/")
        || left_lower.contains(";base64,")
}

fn is_in_long_base64_blob(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let is_b64 = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
    let mut l = start;
    while l > 0 && is_b64(bytes[l - 1]) && start - l < 200 {
        l -= 1;
    }
    let mut r = end;
    while r < bytes.len() && is_b64(bytes[r]) && r - end < 200 {
        r += 1;
    }
    (start - l) + (r - end) >= 128
}

fn is_code_identifier_shape(raw: &str) -> bool {
    if raw.len() < 4 || raw.contains(' ') {
        return false;
    }
    if raw.contains('<') && raw.ends_with('>') {
        return true;
    }
    if raw.contains('.') && !raw.starts_with("eyJ") {
        let mut count = 0usize;
        let all_valid = raw.split('.').all(|s| {
            count += 1;
            !s.is_empty()
                && s.as_bytes()[0].is_ascii_alphabetic()
                && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        });
        if count >= 2 && all_valid {
            return true;
        }
    }
    let bytes = raw.as_bytes();
    let all_lower_sep = bytes.iter().all(|b| b.is_ascii_lowercase() || matches!(b, b'_' | b'-'));
    if all_lower_sep && (raw.contains('_') || raw.contains('-')) {
        return true;
    }
    false
}

fn has_clean_boundaries(text: &str, start: usize, end: usize, entity: GuardEntity) -> bool {
    let prev = text[..start].chars().next_back();
    let next = text[end..].chars().next();
    match entity {
        GuardEntity::InternalIp => {
            let left_ok = prev.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '.');
            let right_ok = next.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '.');
            left_ok && right_ok
        }
        GuardEntity::Person | GuardEntity::Address => true,
        _ => {
            let left_ok = prev.is_none_or(|c| !c.is_ascii_alphanumeric());
            let right_ok = next.is_none_or(|c| !c.is_ascii_alphanumeric());
            left_ok && right_ok
        }
    }
}

fn positive_cues_for(entity: GuardEntity) -> &'static [&'static str] {
    match entity {
        GuardEntity::Secret => &[
            "password",
            "passwd",
            "pwd",
            "passphrase",
            "secret",
            "api_key",
            "apikey",
            "access_key",
            "auth_token",
            "access_token",
            "refresh_token",
            "bearer",
            "cookie",
            "set-cookie",
            "authorization",
            "private_key",
            "client_secret",
            "signing_key",
            "webhook_secret",
            "token",
            "credential",
            "密码",
            "口令",
            "密钥",
            "秘钥",
            "令牌",
            "授权码",
            "私钥",
            "通行证",
        ],
        GuardEntity::Phone => &[
            "phone",
            "mobile",
            "tel",
            "telephone",
            "cell",
            "contact",
            "whatsapp",
            "sms",
            "call",
            "手机",
            "手机号",
            "电话",
            "联系电话",
            "联系方式",
            "座机",
            "来电",
        ],
        GuardEntity::IdCard => &[
            "id_card",
            "idcard",
            "identity",
            "citizen",
            "national_id",
            "resident",
            "身份证",
            "身份证号",
            "证件号",
            "证件号码",
            "公民身份",
        ],
        GuardEntity::PaymentCard => &[
            "card",
            "credit",
            "debit",
            "visa",
            "mastercard",
            "unionpay",
            "amex",
            "payment",
            "billing",
            "pan",
            "bank",
            "银行卡",
            "卡号",
            "信用卡",
            "储蓄卡",
            "借记卡",
            "付款卡",
            "收款卡",
        ],
        GuardEntity::Email => &[
            "email",
            "e-mail",
            "mail",
            "mailto",
            "contact",
            "from",
            "to",
            "cc",
            "author",
            "邮箱",
            "邮件",
            "联系邮箱",
            "电子邮箱",
        ],
        GuardEntity::Person => &[
            "name",
            "full_name",
            "fullname",
            "customer",
            "recipient",
            "contact",
            "patient",
            "employee",
            "cardholder",
            "姓名",
            "联系人",
            "收件人",
            "寄件人",
            "持卡人",
            "法人",
            "客户",
            "患者",
            "员工",
            "我叫",
        ],
        GuardEntity::Address => &[
            "address",
            "addr",
            "street",
            "shipping",
            "billing",
            "residence",
            "home",
            "location",
            "地址",
            "住址",
            "收货地址",
            "家庭住址",
            "联系地址",
            "办公地址",
            "寄送至",
            "位于",
        ],
        GuardEntity::Account => &[
            "wechat",
            "weixin",
            "vx",
            "qq",
            "alipay",
            "employee_id",
            "member_id",
            "account",
            "微信",
            "微信号",
            "qq号",
            "支付宝",
            "工号",
            "会员号",
            "账号",
            "账户",
        ],
        GuardEntity::InternalIp => &[
            "host",
            "ip",
            "server",
            "endpoint",
            "redis",
            "postgres",
            "mysql",
            "mongo",
            "ssh",
            "http://",
            "https://",
            "bind",
            "listen",
            "addr",
            "upstream",
            "proxy",
            "db",
            "内网",
            "服务器",
            "节点",
            "主机",
        ],
        GuardEntity::Other => &[],
    }
}

/// Precompiled single-pass DFA for negative metadata/code suppression cues.
static NEG_METADATA_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSetBuilder::new([
        "sha256",
        "sha512",
        "sha1",
        "md5",
        "checksum",
        "digest",
        "commit",
        "revision",
        "etag",
        "uuid",
        "guid",
        "trace_id",
        "traceid",
        "request_id",
        "requestid",
        "span_id",
        "spanid",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "prompt_tokens",
        "completion_tokens",
        "max_tokens",
        "token_count",
        "cache_read",
        "cache_creation",
        "timestamp",
        "created_at",
        "updated_at",
        "expires_at",
        "order_id",
        "order_no",
        "tracking",
        "invoice",
        "version",
        "semver",
        "build_id",
        "next_page",
        "page_token",
        "cursor",
        "fixture",
        "mock_",
        "dummy_",
        "sample_",
        "example_",
        "placeholder",
        "schema",
        "thought_signature",
        "thoughtsignature",
    ])
    .case_insensitive(false)
    .build()
    .expect("valid neg metadata regex set")
});

fn extract_span_features(
    text: &str,
    start: usize,
    end: usize,
    entity: GuardEntity,
    exact_validator: bool,
) -> SpanFeatures {
    let raw = &text[start..end];
    let left = left_context(text, start, CONTEXT_WINDOW_CHARS);
    let right = right_context(text, end, CONTEXT_WINDOW_CHARS);
    let left_lower = left.to_ascii_lowercase();
    let right_lower = right.to_ascii_lowercase();

    let entropy_norm = (shannon_entropy_bits(raw.as_bytes()) / 6.0).clamp(0.0, 1.0);
    let mut has_l = false;
    let mut has_u = false;
    let mut has_d = false;
    let mut has_s = false;
    for &b in raw.as_bytes() {
        if b.is_ascii_lowercase() {
            has_l = true;
        } else if b.is_ascii_uppercase() {
            has_u = true;
        } else if b.is_ascii_digit() {
            has_d = true;
        } else if b.is_ascii_punctuation() || b >= 0x80 {
            has_s = true;
        }
    }
    let classes = has_l as u8 + has_u as u8 + has_d as u8 + has_s as u8;
    let char_class_balance = classes as f32 / 4.0;

    let char_len = raw.chars().count();
    let length_score = match entity {
        GuardEntity::Secret => ((char_len as f32 - 5.0) / 24.0).clamp(0.0, 1.0),
        GuardEntity::Phone => {
            if (10..=18).contains(&char_len) {
                1.0
            } else {
                0.3
            }
        }
        GuardEntity::IdCard => {
            if char_len == 18 {
                1.0
            } else {
                0.0
            }
        }
        GuardEntity::PaymentCard => {
            if (13..=23).contains(&char_len) {
                1.0
            } else {
                0.2
            }
        }
        GuardEntity::Address => ((char_len as f32 - 6.0) / 14.0).clamp(0.0, 1.0),
        _ => (char_len as f32 / 16.0).clamp(0.0, 1.0),
    };

    let cues = positive_cues_for(entity);
    let pos_left = (count_any_ci(&left_lower, cues) as f32).min(2.0) / 2.0;
    let pos_right = (count_any_ci(&right_lower, cues) as f32).min(2.0) / 2.0;

    let tight_left = suffix_chars(&left_lower, 36);
    let tight_right = prefix_chars(&right_lower, 24);
    let neg_hits = NEG_METADATA_SET.matches(tight_left).iter().take(2).count()
        + NEG_METADATA_SET.matches(tight_right).iter().take(2).count();
    let neg_metadata = (neg_hits as f32).min(2.0) / 2.0;

    let placeholder_or_dummy = if looks_like_placeholder_value(raw, entity) {
        1.0
    } else {
        0.0
    };
    let effective_exact = exact_validator && placeholder_or_dummy == 0.0;
    let is_hex_or_uuid = if is_pure_hex_hash_or_uuid(raw) { 1.0 } else { 0.0 };
    let is_ts_or_ver = if looks_like_timestamp_or_version(raw, tight_left, tight_right, entity) {
        1.0
    } else {
        0.0
    };
    let is_xml_or_uri = if is_inside_xml_counter_or_data_uri(tight_left, tight_right) {
        1.0
    } else {
        0.0
    };
    let left_trimmed = left.trim_end_matches([' ', '\t', '"', '\'']);
    let code_assign = if left_trimmed.ends_with(['=', ':', '：', '是', '为']) {
        1.0
    } else {
        0.0
    };
    let code_ident_shape = if entity == GuardEntity::Secret && is_code_identifier_shape(raw) {
        1.0
    } else {
        0.0
    };
    let template_ref = if raw.starts_with('$')
        || raw.starts_with("${")
        || tight_left.ends_with("process.env.")
        || tight_left.ends_with("os.environ[")
    {
        1.0
    } else {
        0.0
    };
    let in_b64_blob = if is_in_long_base64_blob(text, start, end) {
        1.0
    } else {
        0.0
    };
    let boundary_clean = if has_clean_boundaries(text, start, end, entity) {
        1.0
    } else {
        0.0
    };

    SpanFeatures([
        entropy_norm,                            // 0
        char_class_balance,                      // 1
        length_score,                            // 2
        if effective_exact { 1.0 } else { 0.0 }, // 3
        pos_left,                                // 4
        pos_right,                               // 5
        neg_metadata,                            // 6
        placeholder_or_dummy,                    // 7
        is_hex_or_uuid,                          // 8
        is_ts_or_ver,                            // 9
        is_xml_or_uri,                           // 10
        code_assign,                             // 11
        code_ident_shape,                        // 12
        template_ref,                            // 13
        in_b64_blob,                             // 14
        boundary_clean,                          // 15
    ])
}

#[inline]
fn relu(x: f32) -> f32 {
    x.max(0.0)
}

#[inline]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// Compact 2-layer MLP + residual skip scorer producing calibrated sensitivity probability `(0, 1)`.
pub fn score_features(entity: GuardEntity, f: &SpanFeatures) -> f32 {
    let x = &f.0;

    let h0 = relu(1.2 * x[0] + 0.8 * x[1] + 1.5 * x[4] + 0.6 * x[11] + 0.5 * x[15] - 1.4 * x[6] - 1.6 * x[12] - 1.0);
    let h1 = relu(2.4 * x[3] + 0.7 * x[4] + 0.5 * x[15] - 2.6 * x[7] - 1.5 * x[10] - 0.8);
    let h2 = relu(2.2 * x[6] + 2.5 * x[7] + 1.8 * x[8] + 2.4 * x[9] + 2.8 * x[10] + 2.2 * x[13] + 2.0 * x[14] - 0.9);
    let h3 = relu(1.2 - 1.8 * x[3] - 1.6 * x[4] - 0.9 * x[5] + 1.1 * x[12]);

    let logit = match entity {
        GuardEntity::Secret => {
            let base = -0.35
                + 1.35 * x[0]
                + 0.75 * x[1]
                + 0.55 * x[2]
                + 2.75 * x[3]
                + 1.85 * x[4]
                + 0.45 * x[5]
                + 0.85 * x[11]
                + 0.65 * x[15]
                - 2.60 * x[6]
                - 5.60 * x[7]
                - 1.80 * x[8]
                - 2.20 * x[9]
                - 3.40 * x[10]
                - 3.20 * x[12]
                - 3.40 * x[13]
                - 2.80 * x[14];
            base + 0.85 * h0 + 1.10 * h1 - 1.15 * h2 - 0.75 * h3
        }
        GuardEntity::IdCard => {
            let base = -0.60 + 3.30 * x[3] + 1.40 * x[4] + 0.50 * x[5] + 0.75 * x[15]
                - 2.60 * x[6]
                - 4.20 * x[7]
                - 2.60 * x[9]
                - 3.20 * x[10];
            base + 1.10 * h1 - 1.05 * h2
        }
        GuardEntity::PaymentCard => {
            let base = -1.10 + 2.55 * x[3] + 2.20 * x[4] + 0.65 * x[5] + 0.55 * x[11] + 0.75 * x[15]
                - 2.80 * x[6]
                - 4.40 * x[7]
                - 2.80 * x[9]
                - 3.20 * x[10];
            base + 0.90 * h1 - 1.25 * h2 - 0.60 * h3
        }
        GuardEntity::Phone => {
            let base = -0.55 + 1.55 * x[3] + 2.40 * x[4] + 0.80 * x[5] + 0.65 * x[11] + 0.85 * x[15]
                - 2.90 * x[6]
                - 4.20 * x[7]
                - 3.20 * x[9]
                - 3.40 * x[10];
            base + 0.75 * h1 - 1.20 * h2 - 0.55 * h3
        }
        GuardEntity::Email => {
            let base = 0.65 + 1.30 * x[3] + 1.10 * x[4] + 0.65 * x[15]
                - 1.60 * x[6]
                - 4.60 * x[7]
                - 2.60 * x[10]
                - 2.20 * x[14];
            base + 0.70 * h1 - 1.05 * h2
        }
        GuardEntity::Person => {
            let base = -1.35 + 0.90 * x[3] + 2.80 * x[4] + 0.50 * x[5] + 1.05 * x[11] + 0.45 * x[15]
                - 2.60 * x[6]
                - 4.50 * x[7]
                - 2.80 * x[10];
            base + 0.85 * h0 - 1.25 * h2 - 1.10 * h3
        }
        GuardEntity::Address => {
            let base = -0.35 + 2.15 * x[3] + 0.65 * x[2] + 1.60 * x[4] + 0.55 * x[11] + 0.45 * x[15]
                - 2.20 * x[6]
                - 3.80 * x[7]
                - 2.80 * x[10];
            base + 0.90 * h1 - 1.10 * h2
        }
        GuardEntity::Account => {
            let base = -1.25 + 0.90 * x[3] + 2.75 * x[4] + 0.50 * x[5] + 1.00 * x[11] + 0.65 * x[15]
                - 2.90 * x[6]
                - 4.20 * x[7]
                - 2.60 * x[9]
                - 3.00 * x[10];
            base + 0.80 * h0 - 1.20 * h2 - 1.05 * h3
        }
        GuardEntity::InternalIp => {
            let base = 0.75 + 1.15 * x[3] + 1.05 * x[4] + 0.65 * x[15]
                - 1.40 * x[6]
                - 4.20 * x[7]
                - 3.40 * x[9]
                - 2.40 * x[10];
            base + 0.65 * h1 - 1.05 * h2
        }
        GuardEntity::Other => 1.80 - 3.60 * x[7] - 2.40 * x[10],
    };

    sigmoid(logit)
}

// ---- Single-pass RegexSet prefilter + individual proposer regexes ----

const PAT_CN_PROSE_SECRET: &str = r#"(?:密码|口令|密钥|秘钥|令牌|授权码|私钥|通行证)(?:\s*(?:是|为|[:：=])\s*)["'「『]?([A-Za-z0-9!@#$%^&*+=._~/?-]{6,96})["'」』]?"#;
const PAT_EN_PROSE_SECRET: &str = r#"(?i)\b(?:password|passphrase|secret|auth\s+token|api\s+token|access\s+token|pin\s+code)\s+(?:is|=|:)\s*["']?([A-Za-z0-9!@#$%^&*+=._~/?-]{6,96})["']?"#;
const PAT_COOKIE_SECRET: &str = r"(?i)\b(?:session_id|sessionid|jsessionid|phpsessid|connect\.sid|auth_token|access_token|refresh_token|csrftoken|_session|sid)=([A-Za-z0-9._~+/=%-]{12,160})";
const PAT_CLI_CREDENTIAL: &str =
    r#"(?i)(?:\bcurl\b[^\n]{0,120}\s(?:-u|--user)\s+|\b--password[=\s]+)["']?([^\s"']{6,96})["']?"#;
const PAT_CN_ID_CARD: &str = r"\b[1-8]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b";
const PAT_PAYMENT_CARD: &str = r"\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|62\d{2}|3[47]\d{2}|35\d{2}|6011|65\d{2})(?:[\s-]?\d{4}){2,3}(?:[\s-]?\d{1,3})?\b";
const PAT_CN_MOBILE: &str = r"(?:\+?86[\s-]?)?1[3-9]\d(?:[\s-]?\d{4}){2}";
const PAT_INTL_PHONE: &str = r"\+(?:1|44|49|33|81|82|65|61|852|853|886)[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}";
const PAT_CN_ADDRESS: &str = r"[\p{Han}]{2,6}(?:省|自治区|市)[\p{Han}]{1,6}(?:市|区|县|旗)[\p{Han}A-Za-z0-9\-]{2,36}(?:路|街|大道|道|巷|弄|社区|广场|大厦|公寓|小区|园区|号院|号楼|号|栋|单元|室)(?:[\p{Han}A-Za-z0-9\-]{0,20}(?:座|栋|楼|单元|层|室|号))?";
const PAT_EN_ADDRESS: &str = r"\b\d{1,5}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,3}\s+(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?)\b";
const PAT_CN_PERSON: &str = r#"(?:姓名|联系人|收件人|寄件人|持卡人|法人|客户姓名|员工姓名|患者姓名|我叫)(?:\s*[:：=是]?\s*)["']?([\p{Han}]{2,4})["']?"#;
const PAT_EN_PERSON: &str = r#"(?i)\b(?:full_name|customer_name|recipient_name|contact_name|cardholder|patient_name|legal_name)\s*[:=]\s*["']?([A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20})["']?"#;
const PAT_ACCOUNT_ID: &str = r#"(?i)(?:微信号|微信|vx|wechat|wechat_id|qq号|qq_number|支付宝|工号|employee_id|会员号|member_id)(?:\s*[:：=是]?\s*)["']?([A-Za-z0-9_-]{5,32})["']?"#;

const IDX_CN_PROSE_SECRET: usize = 0;
const IDX_EN_PROSE_SECRET: usize = 1;
const IDX_COOKIE_SECRET: usize = 2;
const IDX_CLI_CREDENTIAL: usize = 3;
const IDX_CN_ID_CARD: usize = 4;
const IDX_PAYMENT_CARD: usize = 5;
const IDX_CN_MOBILE: usize = 6;
const IDX_INTL_PHONE: usize = 7;
const IDX_CN_ADDRESS: usize = 8;
const IDX_EN_ADDRESS: usize = 9;
const IDX_CN_PERSON: usize = 10;
const IDX_EN_PERSON: usize = 11;
const IDX_ACCOUNT_ID: usize = 12;

/// Single-pass DFA prefilter across all 13 guard proposers.
static GUARD_PROPOSER_SET: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        PAT_CN_PROSE_SECRET,
        PAT_EN_PROSE_SECRET,
        PAT_COOKIE_SECRET,
        PAT_CLI_CREDENTIAL,
        PAT_CN_ID_CARD,
        PAT_PAYMENT_CARD,
        PAT_CN_MOBILE,
        PAT_INTL_PHONE,
        PAT_CN_ADDRESS,
        PAT_EN_ADDRESS,
        PAT_CN_PERSON,
        PAT_EN_PERSON,
        PAT_ACCOUNT_ID,
    ])
    .expect("valid guard proposer regex set")
});

static CN_PROSE_SECRET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_CN_PROSE_SECRET).expect("valid regex"));
static EN_PROSE_SECRET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_EN_PROSE_SECRET).expect("valid regex"));
static COOKIE_SECRET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_COOKIE_SECRET).expect("valid regex"));
static CLI_CREDENTIAL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_CLI_CREDENTIAL).expect("valid regex"));
static CN_ID_CARD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_CN_ID_CARD).expect("valid regex"));
static PAYMENT_CARD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_PAYMENT_CARD).expect("valid regex"));
static CN_MOBILE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_CN_MOBILE).expect("valid regex"));
static INTL_PHONE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_INTL_PHONE).expect("valid regex"));
static CN_ADDRESS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_CN_ADDRESS).expect("valid regex"));
static EN_ADDRESS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_EN_ADDRESS).expect("valid regex"));
static CN_PERSON_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_CN_PERSON).expect("valid regex"));
static EN_PERSON_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_EN_PERSON).expect("valid regex"));
static ACCOUNT_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(PAT_ACCOUNT_ID).expect("valid regex"));

const NON_PERSON_CJK_WORDS: &[&str] = &[
    "系统",
    "用户",
    "管理员",
    "测试",
    "未知",
    "默认",
    "示例",
    "客服",
    "暂无",
    "空值",
    "字段",
    "参数",
    "名称",
    "配置",
    "服务",
    "接口",
    "模块",
    "公司",
    "部门",
    "团队",
    "账号",
    "密码",
    "地址",
    "信息",
];

fn is_dense_unsegmented_blob(text: &str) -> bool {
    if text.len() <= MAX_UNSEGMENTED_BLOB_BYTES {
        return false;
    }
    let sample = &text.as_bytes()[..4096];
    sample.iter().filter(|&&b| b == b'\n').count() < 4
}

/// Hybrid guard model entry point.
pub struct SpanGuardModel;

impl SpanGuardModel {
    fn classify_rule_span(span: &Span, raw: &str) -> (GuardEntity, bool, u8) {
        match span.kind {
            FindingKind::CustomKeyword => (GuardEntity::Other, true, 5),
            FindingKind::PrivateKey => (GuardEntity::Secret, true, 5),
            FindingKind::DatabaseUrl => (GuardEntity::Secret, true, 4),
            FindingKind::ProjectPath => (GuardEntity::Other, true, 4),
            FindingKind::ApiKey => {
                let strong_prefix = raw.starts_with("sk-ant-")
                    || raw.starts_with("sk-proj-")
                    || raw.starts_with("sk-")
                    || raw.starts_with("AKIA")
                    || raw.starts_with("ASIA")
                    || raw.starts_with("ghp_")
                    || raw.starts_with("gho_")
                    || raw.starts_with("github_pat_")
                    || raw.starts_with("glpat-")
                    || raw.starts_with("AIza")
                    || raw.starts_with("xox")
                    || raw.starts_with("eyJ")
                    || raw.starts_with("hf_")
                    || raw.starts_with("npm_")
                    || raw.starts_with("pypi-")
                    || raw.starts_with("LTAI")
                    || raw.starts_with("AKID")
                    || raw.starts_with("SG.")
                    || raw.starts_with("https://");
                (GuardEntity::Secret, strong_prefix, 4)
            }
            FindingKind::EnvSecret => {
                let is_high_entropy = span.label == "High-Entropy Credential";
                (GuardEntity::Secret, is_high_entropy, 3)
            }
            FindingKind::EmailOrPii => (GuardEntity::Email, raw.contains('@'), 3),
            FindingKind::InternalIp => (GuardEntity::InternalIp, true, 3),
            FindingKind::InternalDomain => (GuardEntity::Other, true, 3),
            FindingKind::GitMetadata => (GuardEntity::Other, true, 3),
            FindingKind::ProprietaryCodeSymbol => (GuardEntity::Other, true, 2),
        }
    }

    /// Score an arbitrary candidate span in `text` and return its calibrated sensitivity probability.
    pub fn score_span(text: &str, start: usize, end: usize, entity: GuardEntity, exact_validator: bool) -> f32 {
        let features = extract_span_features(text, start, end, entity, exact_validator);
        score_features(entity, &features)
    }

    /// Propose additional bilingual contextual PII & secret spans using a single-pass `RegexSet` prefilter.
    pub fn propose_spans(text: &str, config: &HideConfig) -> Vec<ScoredSpan> {
        if text.len() < 6 || (!config.protect_secrets_and_keys && !config.protect_personal_info) {
            return Vec::new();
        }
        if is_dense_unsegmented_blob(text) {
            return Vec::new();
        }

        let hits = GUARD_PROPOSER_SET.matches(text);
        if !hits.matched_any() {
            return Vec::new();
        }

        let mut proposed = Vec::new();
        let threshold = config.effective_guard_threshold();
        let secrets_on = config.protect_secrets_and_keys;
        let pii_on = config.protect_personal_info;

        for idx in hits {
            if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                break;
            }
            match idx {
                IDX_CN_PROSE_SECRET if secrets_on => {
                    for caps in CN_PROSE_SECRET_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let raw = m.as_str();
                            if raw.len() >= 6 && !is_placeholder_token(raw) {
                                let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Secret, false);
                                if conf >= threshold {
                                    proposed.push(ScoredSpan {
                                        span: Span {
                                            start: m.start(),
                                            end: m.end(),
                                            kind: FindingKind::EnvSecret,
                                            label: "Contextual Secret (Guard)".to_string(),
                                            severity: "high".to_string(),
                                        },
                                        entity: GuardEntity::Secret,
                                        confidence: conf,
                                        priority: 3,
                                    });
                                }
                            }
                        }
                    }
                }
                IDX_EN_PROSE_SECRET if secrets_on => {
                    for caps in EN_PROSE_SECRET_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let raw = m.as_str();
                            if raw.len() >= 6 && !is_placeholder_token(raw) && !is_code_identifier_shape(raw) {
                                let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Secret, false);
                                if conf >= threshold {
                                    proposed.push(ScoredSpan {
                                        span: Span {
                                            start: m.start(),
                                            end: m.end(),
                                            kind: FindingKind::EnvSecret,
                                            label: "Contextual Secret (Guard)".to_string(),
                                            severity: "high".to_string(),
                                        },
                                        entity: GuardEntity::Secret,
                                        confidence: conf,
                                        priority: 3,
                                    });
                                }
                            }
                        }
                    }
                }
                IDX_COOKIE_SECRET if secrets_on => {
                    for caps in COOKIE_SECRET_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let raw = m.as_str();
                            if raw.len() >= 12 && !is_placeholder_token(raw) {
                                let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Secret, true);
                                if conf >= threshold {
                                    proposed.push(ScoredSpan {
                                        span: Span {
                                            start: m.start(),
                                            end: m.end(),
                                            kind: FindingKind::EnvSecret,
                                            label: "Session Cookie Token (Guard)".to_string(),
                                            severity: "high".to_string(),
                                        },
                                        entity: GuardEntity::Secret,
                                        confidence: conf,
                                        priority: 4,
                                    });
                                }
                            }
                        }
                    }
                }
                IDX_CLI_CREDENTIAL if secrets_on => {
                    for caps in CLI_CREDENTIAL_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let raw = m.as_str();
                            if raw.len() >= 6 && !is_placeholder_token(raw) {
                                let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Secret, true);
                                if conf >= threshold {
                                    proposed.push(ScoredSpan {
                                        span: Span {
                                            start: m.start(),
                                            end: m.end(),
                                            kind: FindingKind::EnvSecret,
                                            label: "CLI Credential (Guard)".to_string(),
                                            severity: "high".to_string(),
                                        },
                                        entity: GuardEntity::Secret,
                                        confidence: conf,
                                        priority: 4,
                                    });
                                }
                            }
                        }
                    }
                }
                IDX_CN_ID_CARD if pii_on => {
                    for m in CN_ID_CARD_RE.find_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if is_valid_cn_resident_id(m.as_str()) {
                            let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::IdCard, true);
                            if conf >= threshold {
                                proposed.push(ScoredSpan {
                                    span: Span {
                                        start: m.start(),
                                        end: m.end(),
                                        kind: FindingKind::EmailOrPii,
                                        label: "National ID Card (Guard)".to_string(),
                                        severity: "high".to_string(),
                                    },
                                    entity: GuardEntity::IdCard,
                                    confidence: conf,
                                    priority: 4,
                                });
                            }
                        }
                    }
                }
                IDX_PAYMENT_CARD if pii_on => {
                    for m in PAYMENT_CARD_RE.find_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        let raw = m.as_str();
                        if is_valid_luhn_payment_card(raw) {
                            let formatted = raw.contains(' ') || raw.contains('-');
                            let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::PaymentCard, formatted);
                            if conf >= threshold {
                                proposed.push(ScoredSpan {
                                    span: Span {
                                        start: m.start(),
                                        end: m.end(),
                                        kind: FindingKind::EmailOrPii,
                                        label: "Payment Card Number (Guard)".to_string(),
                                        severity: "high".to_string(),
                                    },
                                    entity: GuardEntity::PaymentCard,
                                    confidence: conf,
                                    priority: 4,
                                });
                            }
                        }
                    }
                }
                IDX_CN_MOBILE if pii_on => {
                    for m in CN_MOBILE_RE.find_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        let raw = m.as_str();
                        if !is_valid_cn_mobile(raw) {
                            continue;
                        }
                        let formatted = has_phone_formatting(raw);
                        let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Phone, formatted);
                        if conf >= threshold {
                            proposed.push(ScoredSpan {
                                span: Span {
                                    start: m.start(),
                                    end: m.end(),
                                    kind: FindingKind::EmailOrPii,
                                    label: "Phone Number (Guard)".to_string(),
                                    severity: "medium".to_string(),
                                },
                                entity: GuardEntity::Phone,
                                confidence: conf,
                                priority: 3,
                            });
                        }
                    }
                }
                IDX_INTL_PHONE if pii_on => {
                    for m in INTL_PHONE_RE.find_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        let raw = m.as_str();
                        let digits = raw.bytes().filter(u8::is_ascii_digit).count();
                        if !(10..=15).contains(&digits) {
                            continue;
                        }
                        let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Phone, true);
                        if conf >= threshold {
                            proposed.push(ScoredSpan {
                                span: Span {
                                    start: m.start(),
                                    end: m.end(),
                                    kind: FindingKind::EmailOrPii,
                                    label: "Phone Number (Guard)".to_string(),
                                    severity: "medium".to_string(),
                                },
                                entity: GuardEntity::Phone,
                                confidence: conf,
                                priority: 3,
                            });
                        }
                    }
                }
                IDX_CN_ADDRESS if pii_on => {
                    for m in CN_ADDRESS_RE.find_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        let raw = m.as_str();
                        if raw.chars().count() >= 9 {
                            let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Address, true);
                            if conf >= threshold {
                                proposed.push(ScoredSpan {
                                    span: Span {
                                        start: m.start(),
                                        end: m.end(),
                                        kind: FindingKind::EmailOrPii,
                                        label: "Physical Address (Guard)".to_string(),
                                        severity: "medium".to_string(),
                                    },
                                    entity: GuardEntity::Address,
                                    confidence: conf,
                                    priority: 3,
                                });
                            }
                        }
                    }
                }
                IDX_EN_ADDRESS if pii_on => {
                    for m in EN_ADDRESS_RE.find_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Address, true);
                        if conf >= threshold {
                            proposed.push(ScoredSpan {
                                span: Span {
                                    start: m.start(),
                                    end: m.end(),
                                    kind: FindingKind::EmailOrPii,
                                    label: "Physical Address (Guard)".to_string(),
                                    severity: "medium".to_string(),
                                },
                                entity: GuardEntity::Address,
                                confidence: conf,
                                priority: 3,
                            });
                        }
                    }
                }
                IDX_CN_PERSON if pii_on => {
                    for caps in CN_PERSON_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let name = m.as_str();
                            if NON_PERSON_CJK_WORDS.contains(&name) {
                                continue;
                            }
                            let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Person, true);
                            if conf >= threshold {
                                proposed.push(ScoredSpan {
                                    span: Span {
                                        start: m.start(),
                                        end: m.end(),
                                        kind: FindingKind::EmailOrPii,
                                        label: "Personal Name (Guard)".to_string(),
                                        severity: "medium".to_string(),
                                    },
                                    entity: GuardEntity::Person,
                                    confidence: conf,
                                    priority: 3,
                                });
                            }
                        }
                    }
                }
                IDX_EN_PERSON if pii_on => {
                    for caps in EN_PERSON_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Person, true);
                            if conf >= threshold {
                                proposed.push(ScoredSpan {
                                    span: Span {
                                        start: m.start(),
                                        end: m.end(),
                                        kind: FindingKind::EmailOrPii,
                                        label: "Personal Name (Guard)".to_string(),
                                        severity: "medium".to_string(),
                                    },
                                    entity: GuardEntity::Person,
                                    confidence: conf,
                                    priority: 3,
                                });
                            }
                        }
                    }
                }
                IDX_ACCOUNT_ID if pii_on => {
                    for caps in ACCOUNT_ID_RE.captures_iter(text) {
                        if proposed.len() >= MAX_GUARD_CANDIDATES_PER_STRING {
                            break;
                        }
                        if let Some(m) = caps.get(1) {
                            let raw = m.as_str();
                            if !is_placeholder_token(raw) {
                                let conf = Self::score_span(text, m.start(), m.end(), GuardEntity::Account, true);
                                if conf >= threshold {
                                    proposed.push(ScoredSpan {
                                        span: Span {
                                            start: m.start(),
                                            end: m.end(),
                                            kind: FindingKind::EmailOrPii,
                                            label: "Account Identifier (Guard)".to_string(),
                                            severity: "medium".to_string(),
                                        },
                                        entity: GuardEntity::Account,
                                        confidence: conf,
                                        priority: 3,
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        proposed
    }

    /// Hybrid fusion: verify rule-based spans with the contextual guard model, merge with
    /// model-proposed spans, and resolve overlaps in O(K log K) via a disjoint interval tree.
    pub fn fuse_and_filter(text: &str, rule_spans: Vec<Span>, config: &HideConfig) -> Vec<Span> {
        let proposed = Self::propose_spans(text, config);
        if rule_spans.is_empty() && proposed.is_empty() {
            return Vec::new();
        }

        let threshold = config.effective_guard_threshold();
        let mut fused: Vec<ScoredSpan> = Vec::with_capacity(rule_spans.len() + proposed.len());

        for span in rule_spans {
            if span.start >= span.end || span.end > text.len() {
                continue;
            }
            let raw = &text[span.start..span.end];
            let (entity, exact, priority) = Self::classify_rule_span(&span, raw);

            if matches!(
                span.kind,
                FindingKind::CustomKeyword
                    | FindingKind::PrivateKey
                    | FindingKind::ProjectPath
                    | FindingKind::DatabaseUrl
                    | FindingKind::InternalDomain
                    | FindingKind::GitMetadata
            ) {
                fused.push(ScoredSpan {
                    span,
                    entity,
                    confidence: 0.99,
                    priority,
                });
                continue;
            }

            let conf = Self::score_span(text, span.start, span.end, entity, exact);
            let gate = if span.kind == FindingKind::ApiKey && exact {
                (threshold - 0.15).max(0.50)
            } else {
                threshold
            };
            if conf >= gate {
                fused.push(ScoredSpan {
                    span,
                    entity,
                    confidence: conf,
                    priority,
                });
            }
        }

        fused.extend(proposed);
        if fused.len() <= 1 {
            return fused.into_iter().map(|s| s.span).collect();
        }

        fused.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.confidence.total_cmp(&a.confidence))
                .then_with(|| (b.span.end - b.span.start).cmp(&(a.span.end - a.span.start)))
                .then_with(|| a.span.start.cmp(&b.span.start))
        });

        let mut intervals: BTreeMap<usize, usize> = BTreeMap::new();
        let mut accepted: Vec<Span> = Vec::with_capacity(fused.len());
        for cand in fused {
            let s = cand.span.start;
            let e = cand.span.end;
            let overlaps_prev = intervals
                .range(..=s)
                .next_back()
                .is_some_and(|(_, &prev_end)| prev_end > s);
            if overlaps_prev {
                continue;
            }
            let overlaps_next = intervals.range(s..e).next().is_some();
            if overlaps_next {
                continue;
            }
            intervals.insert(s, e);
            accepted.push(cand.span);
        }
        accepted.sort_by_key(|s| s.start);
        accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::scan_spans;

    #[test]
    fn validates_cn_resident_id_and_luhn_payment_cards_exactly() {
        assert!(is_valid_cn_resident_id("11010519491231002X"));
        assert!(!is_valid_cn_resident_id("110105194912310021"));
        assert!(!is_valid_cn_resident_id("990105199001010018"));
        assert!(!is_valid_cn_resident_id("11010519900230001X"));

        assert!(is_valid_luhn_payment_card("4532 0151 1283 0366"));
        assert!(!is_valid_luhn_payment_card("4532 0151 1283 0367"));
        assert!(!is_valid_luhn_payment_card("4000 0012 3456 7897"));
        assert!(!is_valid_luhn_payment_card("4444 4444 4444 4444"));
    }

    #[test]
    fn guard_model_catches_bilingual_pii_and_contextual_secrets_without_misses() {
        let cfg = HideConfig::default();
        let sample = concat!(
            "联系人：林晓峰，手机号 139-8765-4321，身份证 11010519491231002X，",
            "银行卡 4532 0151 1283 0366，收货地址：北京市朝阳区建国路88号院A座1203室，",
            "微信号：wx_linxiaofeng88，密码是 K8#mP2xQ9vZ3，",
            "Cookie: session_id=9f8a7b6c5d4e3f2a1b0c9d8e"
        );
        let spans = scan_spans(sample, &cfg);
        let values: Vec<&str> = spans.iter().map(|s| &sample[s.start..s.end]).collect();

        assert!(values.contains(&"林晓峰"), "missed person name: {values:?}");
        assert!(values.contains(&"139-8765-4321"), "missed cn phone: {values:?}");
        assert!(values.contains(&"11010519491231002X"), "missed cn id: {values:?}");
        assert!(values.contains(&"4532 0151 1283 0366"), "missed card: {values:?}");
        assert!(
            values.iter().any(|v| v.contains("北京市朝阳区建国路88号")),
            "missed address: {values:?}"
        );
        assert!(values.contains(&"wx_linxiaofeng88"), "missed account: {values:?}");
        assert!(values.contains(&"K8#mP2xQ9vZ3"), "missed cn prose password: {values:?}");
        assert!(
            values.contains(&"9f8a7b6c5d4e3f2a1b0c9d8e"),
            "missed cookie session token: {values:?}"
        );
    }

    #[test]
    fn guard_model_suppresses_coding_agent_false_positives() {
        let cfg = HideConfig::default();
        let benign = concat!(
            "<total_tokens>13987654321</total_tokens>\n",
            "\"timestamp\": 1732756125000\n",
            "\"order_id\": \"13987654321\"\n",
            "\"version\": \"10.0.1.2\"\n",
            "\"email\": \"developer@example.com\"\n",
            "\"password\": \"changeme\"\n",
            "\"api_key\": \"sk-your-api-key-here-000000\"\n",
            "\"sha256\": \"a3f5c8e1d9b20476a1e3c5b7d9f0123456789abcdef0123456789abcdef01234\"\n",
            "\"test_phone\": \"13800138000\"\n",
            "img = \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\"\n"
        );
        let spans = scan_spans(benign, &cfg);
        let values: Vec<&str> = spans.iter().map(|s| &benign[s.start..s.end]).collect();
        assert!(
            values.is_empty(),
            "expected zero false positives on benign coding-agent metadata, got: {values:?}"
        );
    }

    #[test]
    fn threshold_controls_strict_vs_balanced_recall_on_ambiguous_bare_numbers() {
        let bare = "call back at 13987654321 tomorrow";
        let mut balanced = HideConfig::default();
        balanced.guard_threshold = 0.80;
        let mut strict = HideConfig::default();
        strict.guard_threshold = 0.65;

        let balanced_hits = scan_spans(bare, &balanced);
        let strict_hits = scan_spans(bare, &strict);
        assert!(
            strict_hits.len() >= balanced_hits.len(),
            "strict threshold should have >= recall of balanced"
        );
        assert!(
            strict_hits.iter().any(|s| &bare[s.start..s.end] == "13987654321"),
            "strict threshold should catch bare mobile number"
        );
    }

    #[test]
    fn hybrid_guard_desensitize_and_restore_roundtrip_is_lossless_and_format_preserving() {
        use crate::desensitizer::SemanticDesensitizer;
        use crate::vault::PrivacyVault;

        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let raw = concat!(
            "联系人：林晓峰，手机号 139-8765-4321，身份证 11010519491231002X，",
            "银行卡 4532 0151 1283 0366，地址：北京市朝阳区建国路88号院A座1203室，",
            "微信号：wx_linxiaofeng88，密码是 K8#mP2xQ9vZ3"
        );
        let res = SemanticDesensitizer::process(raw, &cfg, &vault);
        for secret in [
            "林晓峰",
            "139-8765-4321",
            "11010519491231002X",
            "4532 0151 1283 0366",
            "北京市朝阳区建国路88号",
            "wx_linxiaofeng88",
            "K8#mP2xQ9vZ3",
        ] {
            assert!(
                !res.transformed_payload.contains(secret),
                "leaked {secret} in {}",
                res.transformed_payload
            );
        }
        assert!(
            res.transformed_payload.contains("199-00"),
            "{}",
            res.transformed_payload
        );
        assert!(
            res.transformed_payload.contains("99010119900101"),
            "{}",
            res.transformed_payload
        );
        assert!(
            res.transformed_payload.contains("4000 00"),
            "{}",
            res.transformed_payload
        );
        assert!(res.transformed_payload.contains("acct_"), "{}", res.transformed_payload);

        let (restored, count) = vault.restore_text(&res.transformed_payload);
        assert!(count >= 7, "expected >=7 restored tokens, got {count}");
        assert_eq!(restored, raw);
    }

    #[test]
    fn guard_model_and_classifier_stay_fast_on_256kb_coding_agent_payload() {
        use crate::classifier::{ClassificationInput, RequestClassifier};
        use crate::desensitizer::SemanticDesensitizer;
        use crate::vault::PrivacyVault;
        use std::time::Instant;

        let mut messages = Vec::new();
        let code_chunk = "pub fn compute_route(node_id: u64, retry_count: usize) -> Result<usize, &'static str> {\n    let version = \"10.0.1.2\";\n    let timestamp = 1732756125000u64;\n    if retry_count > 16 { return Err(\"max retries exceeded\"); }\n    Ok((node_id as usize).wrapping_add(retry_count))\n}\n";
        let repeated_code = code_chunk.repeat(40);
        for i in 0..24 {
            messages.push(serde_json::json!({
                "role": if i % 2 == 0 { "user" } else { "assistant" },
                "content": format!("Turn {i} <total_tokens>13987654321</total_tokens>\n```rust\n{repeated_code}\n```")
            }));
        }
        messages.push(serde_json::json!({
            "role": "user",
            "content": "联系人：林晓峰，手机号 139-8765-4321，密码是 K8#mP2xQ9vZ3"
        }));
        let payload = serde_json::json!({
            "model": "claude-sonnet-4-5",
            "max_tokens": 4096,
            "messages": messages,
        })
        .to_string();
        assert!(payload.len() >= 200 * 1024, "len={}", payload.len());

        let t_cls = Instant::now();
        let verdict = RequestClassifier::classify(&ClassificationInput {
            host: Some("api.anthropic.com"),
            path: "/v1/messages",
            method: "POST",
            content_type: Some("application/json"),
            content_encoding: None,
            headers: None,
            body_text: Some(&payload),
            raw_bytes: payload.as_bytes(),
            bytes_sent_override: None,
            bytes_received_override: None,
            repeat_count: 1,
        });
        let cls_ms = t_cls.elapsed().as_millis();
        assert_eq!(verdict.purpose, crate::audit::RequestPurpose::ChatInference);
        assert!(cls_ms < 250, "classifier too slow on 256KB payload: {cls_ms}ms");

        let cfg = HideConfig::default();
        let vault = PrivacyVault::new();
        let t_des = Instant::now();
        let res = SemanticDesensitizer::process(&payload, &cfg, &vault);
        let des_ms = t_des.elapsed().as_millis();
        assert!(!res.transformed_payload.contains("139-8765-4321"));
        assert!(!res.transformed_payload.contains("K8#mP2xQ9vZ3"));
        assert!(res
            .transformed_payload
            .contains("<total_tokens>13987654321</total_tokens>"));
        assert!(res.transformed_payload.contains("10.0.1.2"));
        assert_eq!(vault.restore_text(&res.transformed_payload).0, payload);
        assert!(
            des_ms < 1500,
            "desensitizer+guard too slow on 256KB payload: {des_ms}ms"
        );
    }
}
