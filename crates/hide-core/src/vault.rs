use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

/// Upper bound on live mappings. Older, least recently used entries are evicted first.
pub const MAX_VAULT_ENTRIES: usize = 50_000;
const EVICT_BATCH: usize = 5_000;

/// A single entry in the bidirectional semantic vault
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub token: String,
    pub original_masked: String,
    pub original_raw: String,
    pub category: String,
    pub hit_count: usize,
    /// True when the original contains credential material (keys, passwords, DB URLs).
    pub secret: bool,
    #[serde(skip)]
    last_used: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum DerivedContext {
    PlainText,
    JsonPayload,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum RegistrationKey {
    Original(String),
    Json(String),
    Derived(String, String, bool),
}

/// Categories whose originals are credentials.
pub fn is_secret_category(category: &str) -> bool {
    matches!(
        category,
        "ApiKey" | "PrivateKey" | "DatabaseUrl" | "EnvSecret" | "CipherGarble"
    )
}

#[derive(Debug)]
struct VaultInner {
    source_to_token: HashMap<RegistrationKey, String>,
    token_to_real: HashMap<String, VaultEntry>,
    json_values: HashMap<String, Value>,
    counters: HashMap<String, usize>,
    secret_key: [u8; 32],
    generation: u64,
    tick: u64,
}

impl Default for VaultInner {
    fn default() -> Self {
        Self {
            source_to_token: HashMap::new(),
            token_to_real: HashMap::new(),
            json_values: HashMap::new(),
            counters: HashMap::new(),
            secret_key: generate_ephemeral_key(),
            generation: 0,
            tick: 0,
        }
    }
}

fn generate_ephemeral_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(Uuid::new_v4().as_bytes());
    hasher.update(Uuid::new_v4().as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// One token -> original mapping as seen by the restorer.
#[derive(Debug, Clone)]
pub struct Pair {
    pub token: String,
    pub original: String,
    pub secret: bool,
}

/// Immutable lookup structure built from a vault snapshot. Tokens are indexed by their
/// first byte and kept longest-first, so restoration costs O(text * candidates-per-byte).
#[derive(Debug, Default)]
pub struct Matcher {
    pairs: Vec<Pair>,
    by_first: HashMap<u8, Vec<usize>>,
    max_len: usize,
    json_values: HashMap<String, Value>,
    /// Indices into `pairs`, longest original first, grouped by the original's first byte.
    by_original_first: HashMap<u8, Vec<usize>>,
}

impl Matcher {
    fn build(inner: &VaultInner) -> Self {
        let mut pairs: Vec<Pair> = inner
            .token_to_real
            .values()
            .filter(|e| e.token.len() >= 2)
            .map(|e| Pair {
                token: e.token.clone(),
                original: e.original_raw.clone(),
                secret: e.secret,
            })
            .collect();
        pairs.sort_by(|a, b| b.token.len().cmp(&a.token.len()).then_with(|| a.token.cmp(&b.token)));
        let mut by_first: HashMap<u8, Vec<usize>> = HashMap::new();
        for (i, p) in pairs.iter().enumerate() {
            by_first.entry(p.token.as_bytes()[0]).or_default().push(i);
        }
        let max_len = pairs.first().map_or(0, |p| p.token.len());
        let mut by_orig: Vec<usize> = (0..pairs.len()).filter(|&i| pairs[i].original.len() >= 3).collect();
        by_orig.sort_by(|&a, &b| pairs[b].original.len().cmp(&pairs[a].original.len()));
        let mut by_original_first: HashMap<u8, Vec<usize>> = HashMap::new();
        for i in by_orig {
            by_original_first
                .entry(pairs[i].original.as_bytes()[0])
                .or_default()
                .push(i);
        }
        Self {
            pairs,
            by_first,
            max_len,
            json_values: inner.json_values.clone(),
            by_original_first,
        }
    }

    pub fn json_value(&self, token: &str) -> Option<&Value> {
        self.json_values.get(token)
    }

    /// Exact inverse of restoration: put tokens back where their originals appear. Used for
    /// signed reasoning blocks echoed back by the harness, whose signature covers the text the
    /// vendor produced (with tokens), not the restored text.
    pub fn reseal(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        while pos < text.len() {
            let rem = &text[pos..];
            let hit = self.by_original_first.get(&rem.as_bytes()[0]).and_then(|idx| {
                idx.iter().map(|&i| &self.pairs[i]).find(|p| {
                    rem.starts_with(p.original.as_str())
                        && is_valid_token_boundary_with_left(text, pos, &p.original, None)
                })
            });
            match hit {
                Some(p) => {
                    out.push_str(&p.token);
                    pos += p.original.len();
                }
                None => {
                    let ch = rem.chars().next().unwrap();
                    out.push(ch);
                    pos += ch.len_utf8();
                }
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn pairs(&self) -> &[Pair] {
        &self.pairs
    }

    /// Longest token at `text[pos..]` that respects identifier/number boundaries.
    pub fn find_at(&self, text: &str, pos: usize, left: Option<char>) -> Option<&Pair> {
        let first = *text.as_bytes().get(pos)?;
        let rem = &text[pos..];
        self.by_first
            .get(&first)?
            .iter()
            .map(|&i| &self.pairs[i])
            .find(|p| rem.starts_with(p.token.as_str()) && is_valid_token_boundary_with_left(text, pos, &p.token, left))
    }

    /// True if `rem` could still grow into a registered token.
    pub fn is_strict_prefix(&self, rem: &str) -> bool {
        if rem.is_empty() || rem.len() >= self.max_len {
            return false;
        }
        self.by_first.get(&rem.as_bytes()[0]).is_some_and(|idx| {
            idx.iter()
                .map(|&i| &self.pairs[i])
                .any(|p| p.token.len() > rem.len() && p.token.starts_with(rem))
        })
    }

    /// Byte ranges of registered tokens already present in `text` (never re-masked).
    pub fn token_ranges(&self, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        if self.pairs.is_empty() {
            return out;
        }
        let mut pos = 0;
        while pos < text.len() {
            if let Some(p) = self.find_at(text, pos, None) {
                out.push((pos, pos + p.token.len()));
                pos += p.token.len();
            } else {
                pos += text[pos..].chars().next().unwrap().len_utf8();
            }
        }
        out
    }

    /// Single-pass restoration. Replacement values are never re-scanned. Secret originals
    /// are only emitted when `allow_secret` is set; otherwise the token stays in place.
    pub fn restore(&self, text: &str, left: Option<char>, allow_secret: bool) -> (String, usize, usize) {
        if self.pairs.is_empty() || text.is_empty() {
            return (text.to_string(), 0, 0);
        }
        let mut output = String::with_capacity(text.len());
        let (mut count, mut withheld, mut pos) = (0, 0, 0);
        while pos < text.len() {
            if let Some(p) = self.find_at(text, pos, left) {
                if p.secret && !allow_secret {
                    output.push_str(&p.token);
                    withheld += 1;
                } else {
                    output.push_str(&p.original);
                    count += 1;
                }
                pos += p.token.len();
            } else {
                let ch = text[pos..].chars().next().unwrap();
                output.push(ch);
                pos += ch.len_utf8();
            }
        }
        (output, count, withheld)
    }

    /// Restore keys and string values of a JSON document structurally.
    pub fn restore_json_value(&self, value: &mut Value, allow_secret: bool) -> usize {
        match value {
            Value::Object(map) => {
                let mut count = 0;
                for (key, mut item) in std::mem::take(map) {
                    let (key, n, _) = self.restore(&key, None, allow_secret);
                    count += n + self.restore_json_value(&mut item, allow_secret);
                    map.insert(key, item);
                }
                count
            }
            Value::Array(items) => items.iter_mut().map(|v| self.restore_json_value(v, allow_secret)).sum(),
            Value::String(text) => {
                if let Some(original) = self.json_values.get(text.as_str()) {
                    *value = original.clone();
                    return 1;
                }
                let trimmed = text.trim_start();
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(text) {
                        let n = self.restore_json_value(&mut inner, allow_secret);
                        if n > 0 {
                            *text = reserialize_like(text, &inner);
                        }
                        return n;
                    }
                }
                let (restored, n, _) = self.restore(text, None, allow_secret);
                *text = restored;
                n
            }
            _ => 0,
        }
    }

    /// JSON-aware restore of a full document, falling back to plain text.
    pub fn restore_document(&self, text: &str, allow_secret: bool) -> (String, usize) {
        if text.is_empty() || self.pairs.is_empty() {
            return (text.to_string(), 0);
        }
        if let Ok(mut value) = serde_json::from_str::<Value>(text) {
            let count = self.restore_json_value(&mut value, allow_secret);
            if count == 0 {
                return (text.to_string(), 0);
            }
            return (reserialize_like(text, &value), count);
        }
        let (out, n, _) = self.restore(text, None, allow_secret);
        (out, n)
    }
}

/// Serialize `value` compactly or pretty-printed, matching the style of `original`.
pub fn reserialize_like(original: &str, value: &Value) -> String {
    let t = original.trim_start();
    if t.starts_with("{\n") || t.starts_with("[\n") || t.starts_with("{\r\n") {
        serde_json::to_string_pretty(value).expect("JSON value serializes")
    } else {
        serde_json::to_string(value).expect("JSON value serializes")
    }
}

/// Thread-safe bidirectional mapping vault ("AI sees semantic tokens, Vendor never sees real values")
#[derive(Debug, Clone, Default)]
pub struct PrivacyVault {
    inner: Arc<RwLock<VaultInner>>,
    matcher: Arc<Mutex<Option<CachedMatcher>>>,
}

/// Matcher snapshot tagged with the vault generation it was built from.
type CachedMatcher = (u64, Arc<Matcher>);

impl PrivacyVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the vault's ephemeral 256-bit secret key
    pub fn secret_key(&self) -> [u8; 32] {
        self.inner.read().secret_key
    }

    /// Cached restorer view of the current mappings.
    pub fn matcher(&self) -> Arc<Matcher> {
        let generation = self.inner.read().generation;
        let mut cache = self.matcher.lock();
        if let Some((g, m)) = cache.as_ref() {
            if *g == generation {
                return m.clone();
            }
        }
        let inner = self.inner.read();
        let m = Arc::new(Matcher::build(&inner));
        *cache = Some((inner.generation, m.clone()));
        m
    }

    /// Look up the original raw value for an exact token if registered in this vault
    pub fn get_raw_by_token(&self, token: &str) -> Option<String> {
        self.inner
            .read()
            .token_to_real
            .get(token)
            .map(|e| e.original_raw.clone())
    }

    /// Register or retrieve an existing semantic placeholder token for a sensitive value
    pub fn get_or_insert_with<F>(&self, raw_value: &str, category: &str, generator: F) -> String
    where
        F: FnOnce(usize) -> String,
    {
        if raw_value.trim().is_empty() {
            return raw_value.to_string();
        }
        self.register_with(
            raw_value,
            category,
            RegistrationKey::Original(raw_value.to_string()),
            None,
            is_secret_category(category),
            generator,
        )
    }

    /// Register an original value without interpreting any token-looking content.
    pub fn insert_explicit(&self, raw_value: &str, token: &str, category: &str) -> String {
        if raw_value.is_empty() || token.is_empty() || raw_value == token {
            return token.to_string();
        }
        self.get_or_insert_with(raw_value, category, |_| token.to_string())
    }

    /// Register a later layer, folding earlier tokens exactly once at registration time,
    /// so every entry maps straight to the final original.
    pub fn register_derived_with<F>(
        &self,
        transformed_value: &str,
        category: &str,
        context: DerivedContext,
        generator: F,
    ) -> String
    where
        F: FnOnce(usize) -> String,
    {
        if transformed_value.is_empty() {
            return String::new();
        }
        let matcher = self.matcher();
        let folds_secret = matcher
            .pairs
            .iter()
            .any(|p| p.secret && transformed_value.contains(p.token.as_str()));
        let original = match context {
            DerivedContext::PlainText => matcher.restore(transformed_value, None, true).0,
            DerivedContext::JsonPayload => matcher.restore_document(transformed_value, true).0,
        };
        let json_value = matcher.json_values.get(transformed_value).cloned();
        let key = RegistrationKey::Derived(category.to_string(), original.clone(), json_value.is_some());
        self.register_with(
            &original,
            category,
            key,
            json_value,
            folds_secret || is_secret_category(category),
            generator,
        )
    }

    /// Preserve the exact JSON type; ordinary string registrations remain strings.
    pub fn get_or_insert_json_value_with<F>(&self, value: &Value, category: &str, generator: F) -> String
    where
        F: FnOnce(usize) -> String,
    {
        if let Value::String(raw) = value {
            return self.get_or_insert_with(raw, category, generator);
        }
        let raw = value.to_string();
        self.register_with(
            &raw,
            category,
            RegistrationKey::Json(raw.clone()),
            Some(value.clone()),
            is_secret_category(category),
            generator,
        )
    }

    fn register_with<F>(
        &self,
        raw_value: &str,
        category: &str,
        key: RegistrationKey,
        json_value: Option<Value>,
        secret: bool,
        generator: F,
    ) -> String
    where
        F: FnOnce(usize) -> String,
    {
        let mut guard = self.inner.write();
        guard.tick += 1;
        let tick = guard.tick;
        if let Some(existing) = guard.source_to_token.get(&key).cloned() {
            if let Some(entry) = guard.token_to_real.get_mut(&existing) {
                entry.hit_count += 1;
                entry.last_used = tick;
            }
            return existing;
        }
        let index = *guard
            .counters
            .entry(category.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let token = disambiguate_token(&guard.token_to_real, &generator(index), index);
        guard.source_to_token.insert(key, token.clone());
        if let Some(value) = json_value {
            guard.json_values.insert(token.clone(), value);
        }
        guard.token_to_real.insert(
            token.clone(),
            VaultEntry {
                token: token.clone(),
                original_masked: mask_preview(raw_value),
                original_raw: raw_value.to_string(),
                category: category.to_string(),
                hit_count: 1,
                secret,
                last_used: tick,
            },
        );
        guard.generation += 1;
        if guard.token_to_real.len() > MAX_VAULT_ENTRIES {
            evict_least_recent(&mut guard, &token);
        }
        token
    }

    /// Restore JSON values and keys structurally, falling back to single-pass plain text.
    pub fn restore_text(&self, text: &str) -> (String, usize) {
        self.matcher().restore_document(text, true)
    }

    /// Restore logical text once, without JSON parsing or re-scanning replacement values.
    pub fn restore_plain_text(&self, text: &str) -> (String, usize) {
        let (out, n, _) = self.matcher().restore(text, None, true);
        (out, n)
    }

    /// Return all active token -> final original pairs sorted by token length descending.
    pub fn snapshot_pairs(&self) -> Vec<(String, String)> {
        self.matcher()
            .pairs
            .iter()
            .map(|p| (p.token.clone(), p.original.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().token_to_real.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return all VaultEntry items for UI inspection
    pub fn list_entries(&self) -> Vec<VaultEntry> {
        let guard = self.inner.read();
        let mut entries: Vec<VaultEntry> = guard.token_to_real.values().cloned().collect();
        entries.sort_by(|a, b| b.hit_count.cmp(&a.hit_count).then(a.token.cmp(&b.token)));
        entries
    }

    pub fn clear(&self) {
        let mut guard = self.inner.write();
        guard.source_to_token.clear();
        guard.token_to_real.clear();
        guard.json_values.clear();
        guard.counters.clear();
        guard.secret_key = generate_ephemeral_key();
        guard.generation += 1;
    }
}

fn evict_least_recent(guard: &mut VaultInner, keep: &str) {
    let mut by_age: Vec<(u64, String)> = guard
        .token_to_real
        .values()
        .filter(|e| e.token != keep)
        .map(|e| (e.last_used, e.token.clone()))
        .collect();
    by_age.sort();
    let evicted: HashSet<String> = by_age.into_iter().take(EVICT_BATCH).map(|(_, t)| t).collect();
    guard.token_to_real.retain(|t, _| !evicted.contains(t));
    guard.json_values.retain(|t, _| !evicted.contains(t));
    guard.source_to_token.retain(|_, t| !evicted.contains(t));
    guard.generation += 1;
}

fn disambiguate_token(token_to_real: &HashMap<String, VaultEntry>, candidate: &str, start_idx: usize) -> String {
    if !token_to_real.contains_key(candidate) {
        return candidate.to_string();
    }
    let mut step = start_idx.max(2);
    loop {
        let next_candidate = if candidate.starts_with("// [") {
            if let Some(bracket_end) = candidate.find(']') {
                let prefix = &candidate[..bracket_end];
                let rest = &candidate[bracket_end..];
                if let Some(dash_pos) = prefix.rfind('-') {
                    format!("{}-{:02}{}", &prefix[..dash_pos], step, rest)
                } else {
                    format!("{}-{:02}{}", prefix, step, rest)
                }
            } else {
                format!("{} (#{})", candidate, step)
            }
        } else if candidate.starts_with('"') && candidate.ends_with('"') && candidate.len() >= 2 {
            format!("\"{}_{:02}\"", &candidate[1..candidate.len() - 1], step)
        } else if candidate.ends_with('⟧') {
            format!("{}#{}⟧", &candidate[..candidate.len() - '⟧'.len_utf8()], step)
        } else if let Some(stem) = candidate.strip_suffix(">>") {
            format!("{}_{:02}>>", stem, step)
        } else {
            format!("{}_{:02}", candidate, step)
        };

        if !token_to_real.contains_key(&next_candidate) {
            return next_candidate;
        }
        step += 1;
    }
}

/// Characters that make up an identifier for boundary purposes.
pub(crate) fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// True if the token behaves like a bare identifier (needs word boundaries on both sides).
pub(crate) fn is_bare_ident_token(token: &str) -> bool {
    let (Some(first), Some(last)) = (token.chars().next(), token.chars().next_back()) else {
        return false;
    };
    (first.is_alphabetic() || first == '_')
        && is_word_char(last)
        && !token.contains("://")
        && !token.contains(['/', '\\', '@', '.'])
}

/// Check whether a token match at `text[pos..pos + token.len()]` respects number/identifier
/// boundaries; `left` is the character preceding `text` (streaming).
pub(crate) fn is_valid_token_boundary_with_left(text: &str, pos: usize, token: &str, left: Option<char>) -> bool {
    let Some(first) = token.chars().next() else {
        return false;
    };
    let last = token.chars().next_back().unwrap();
    let previous = text[..pos].chars().next_back().or(left);
    let next = text[pos + token.len()..].chars().next();
    if (first.is_numeric() && previous.is_some_and(|ch| ch.is_numeric()))
        || (last.is_numeric() && next.is_some_and(|ch| ch.is_numeric()))
    {
        return false;
    }
    !is_bare_ident_token(token) || (!previous.is_some_and(is_word_char) && !next.is_some_and(is_word_char))
}

pub fn mask_preview(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let len = chars.len();
    if len <= 6 {
        let first = chars.first().copied().unwrap_or('*');
        return format!("{}***", first);
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars.iter().skip(len.saturating_sub(3)).collect();
    format!("{}••••{}", prefix, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_keeps_vault_bounded_and_newest_entry_alive() {
        let vault = PrivacyVault::new();
        for i in 0..(MAX_VAULT_ENTRIES + 10) {
            vault.insert_explicit(&format!("raw-{i}"), &format!("TOK_{i}"), "test");
        }
        assert!(vault.len() <= MAX_VAULT_ENTRIES);
        let last = MAX_VAULT_ENTRIES + 9;
        assert_eq!(
            vault.get_raw_by_token(&format!("TOK_{last}")).as_deref(),
            Some(format!("raw-{last}").as_str())
        );
        assert!(vault.get_raw_by_token("TOK_0").is_none());
    }

    #[test]
    fn secret_tokens_can_be_withheld() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("sk-real", "sk-sem-placeholder-key-0001", "ApiKey");
        vault.insert_explicit("/home/a", "/workspace/proj_01", "ProjectPath");
        let (out, n, withheld) =
            vault
                .matcher()
                .restore("sk-sem-placeholder-key-0001 /workspace/proj_01/x", None, false);
        assert_eq!(out, "sk-sem-placeholder-key-0001 /home/a/x");
        assert_eq!((n, withheld), (1, 1));
    }

    #[test]
    fn derived_entries_inherit_secret_flag() {
        let vault = PrivacyVault::new();
        let tok = vault.insert_explicit("sk-real-123", "sk-sem-placeholder-key-0001", "ApiKey");
        let lit = vault.register_derived_with(
            &format!("key={tok} x"),
            "StrictStringLiteral",
            DerivedContext::PlainText,
            |i| format!("<<HIDE_STR_{i:03}>>"),
        );
        let entry = vault.list_entries().into_iter().find(|e| e.token == lit).unwrap();
        assert!(entry.secret);
        assert_eq!(entry.original_raw, "key=sk-real-123 x");
    }
}
