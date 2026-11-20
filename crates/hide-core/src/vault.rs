use parking_lot::{Mutex, RwLock};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Upper bound on live mappings. Older, least recently used non-secret entries are evicted first.
pub const MAX_VAULT_ENTRIES: usize = 50_000;
/// Hard ceiling even for credential-pinned entries so memory stays bounded under sustained load.
const HARD_MAX_VAULT_ENTRIES: usize = 100_000;
const EVICT_BATCH: usize = 5_000;
/// Maximum JSON nesting depth (including nested JSON-encoded strings) to prevent stack overflow.
pub(crate) const MAX_JSON_DEPTH: usize = 64;

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
    #[serde(skip)]
    pub(crate) scope: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum DerivedContext {
    PlainText,
    JsonPayload,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum RegistrationKey {
    Original(Option<String>, String),
    Json(Option<String>, String),
    Derived(Option<String>, String, String, bool),
}

/// Categories whose originals are credentials.
pub fn is_secret_category(category: &str) -> bool {
    matches!(
        category,
        "ApiKey" | "PrivateKey" | "DatabaseUrl" | "EnvSecret" | "CipherGarble"
    )
}

#[derive(Debug)]
struct SecretKey([u8; 32]);

impl Default for SecretKey {
    fn default() -> Self {
        Self(generate_ephemeral_key())
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

#[derive(Debug, Default)]
struct VaultInner {
    source_to_token: HashMap<RegistrationKey, String>,
    token_to_real: HashMap<String, VaultEntry>,
    json_values: HashMap<String, Value>,
    counters: HashMap<String, usize>,
    generation: u64,
    tick: u64,
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid mutable reference to an initialized `u8`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn generate_ephemeral_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let rng = SystemRandom::new();
    if rng.fill(&mut key).is_ok() {
        return key;
    }
    let mut hasher = Sha256::new();
    hasher.update(Uuid::new_v4().as_bytes());
    hasher.update(Uuid::new_v4().as_bytes());
    let digest = hasher.finalize();
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

#[derive(Debug, Default)]
struct TrieNode {
    next: Vec<(u8, usize)>,
    pair_idx: Option<usize>,
}

impl TrieNode {
    fn child(&self, b: u8) -> Option<usize> {
        self.next
            .binary_search_by_key(&b, |&(k, _)| k)
            .ok()
            .map(|idx| self.next[idx].1)
    }

    fn insert_edge(&mut self, b: u8, child: usize) {
        match self.next.binary_search_by_key(&b, |&(k, _)| k) {
            Ok(idx) => self.next[idx].1 = child,
            Err(idx) => self.next.insert(idx, (b, child)),
        }
    }
}

/// Immutable lookup structure built from a vault snapshot. Tokens are indexed by a compact
/// byte trie, so matching and prefix checks take O(|token|) per position regardless of vault size.
#[derive(Debug, Default)]
pub struct Matcher {
    pairs: Vec<Pair>,
    trie: Vec<TrieNode>,
    max_len: usize,
    json_values: HashMap<String, Value>,
    /// Indices into `pairs`, longest original first, grouped by the original's first byte.
    by_original_first: HashMap<u8, Vec<usize>>,
}

impl Matcher {
    fn from_entries<'a>(
        entries: impl Iterator<Item = &'a VaultEntry>,
        all_json_values: &HashMap<String, Value>,
    ) -> Self {
        let mut pairs: Vec<Pair> = entries
            .filter(|e| e.token.len() >= 2)
            .map(|e| Pair {
                token: e.token.clone(),
                original: e.original_raw.clone(),
                secret: e.secret,
            })
            .collect();
        pairs.sort_by(|a, b| b.token.len().cmp(&a.token.len()).then_with(|| a.token.cmp(&b.token)));

        let mut trie = vec![TrieNode::default()];
        for (i, p) in pairs.iter().enumerate() {
            let mut node = 0usize;
            for &b in p.token.as_bytes() {
                if let Some(next_node) = trie[node].child(b) {
                    node = next_node;
                } else {
                    let next_node = trie.len();
                    trie.push(TrieNode::default());
                    trie[node].insert_edge(b, next_node);
                    node = next_node;
                }
            }
            if trie[node].pair_idx.is_none() {
                trie[node].pair_idx = Some(i);
            }
        }

        let max_len = pairs.first().map_or(0, |p| p.token.len());
        let mut json_values = HashMap::new();
        for p in &pairs {
            if let Some(v) = all_json_values.get(&p.token) {
                json_values.insert(p.token.clone(), v.clone());
            }
        }

        let mut by_orig: Vec<usize> = (0..pairs.len()).filter(|&i| pairs[i].original.len() >= 3).collect();
        by_orig.sort_by(|&a, &b| pairs[b].original.len().cmp(&pairs[a].original.len()));
        let mut by_original_first: HashMap<u8, Vec<usize>> = HashMap::new();
        for i in by_orig {
            if let Some(&first_b) = pairs[i].original.as_bytes().first() {
                by_original_first.entry(first_b).or_default().push(i);
            }
        }
        Self {
            pairs,
            trie,
            max_len,
            json_values,
            by_original_first,
        }
    }

    fn build(inner: &VaultInner) -> Self {
        Self::from_entries(inner.token_to_real.values(), &inner.json_values)
    }

    fn build_scoped(inner: &VaultInner, scope: Option<&str>) -> Self {
        Self::from_entries(
            inner.token_to_real.values().filter(|e| e.scope.as_deref() == scope),
            &inner.json_values,
        )
    }

    fn build_allowed(inner: &VaultInner, allowed: &HashSet<String>) -> Self {
        Self::from_entries(
            inner.token_to_real.values().filter(|e| allowed.contains(&e.token)),
            &inner.json_values,
        )
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
            let hit = rem
                .as_bytes()
                .first()
                .and_then(|b| self.by_original_first.get(b))
                .and_then(|idx| {
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
                    let Some(ch) = rem.chars().next() else { break };
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
        if self.trie.is_empty() || pos >= text.len() {
            return None;
        }
        let bytes = &text.as_bytes()[pos..];
        let mut node = 0usize;
        let mut matched: Option<&Pair> = None;
        for &b in bytes {
            let Some(next) = self.trie[node].child(b) else {
                break;
            };
            node = next;
            if let Some(pair_idx) = self.trie[node].pair_idx {
                let p = &self.pairs[pair_idx];
                if is_valid_token_boundary_with_left(text, pos, &p.token, left) {
                    matched = Some(p);
                }
            }
        }
        matched
    }

    /// True if `rem` could still grow into a registered token.
    pub fn is_strict_prefix(&self, rem: &str) -> bool {
        if rem.is_empty() || rem.len() >= self.max_len || self.trie.is_empty() {
            return false;
        }
        let mut node = 0usize;
        for &b in rem.as_bytes() {
            let Some(next) = self.trie[node].child(b) else {
                return false;
            };
            node = next;
        }
        !self.trie[node].next.is_empty()
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
                let Some(ch) = text[pos..].chars().next() else { break };
                pos += ch.len_utf8();
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
                let Some(ch) = text[pos..].chars().next() else { break };
                output.push(ch);
                pos += ch.len_utf8();
            }
        }
        (output, count, withheld)
    }

    /// Restore keys and string values of a JSON document structurally.
    pub fn restore_json_value(&self, value: &mut Value, allow_secret: bool) -> usize {
        self.restore_json_value_depth(value, allow_secret, 0)
    }

    fn restore_json_value_depth(&self, value: &mut Value, allow_secret: bool, depth: usize) -> usize {
        if depth >= MAX_JSON_DEPTH {
            if let Value::String(text) = value {
                let (restored, n, _) = self.restore(text, None, allow_secret);
                *text = restored;
                return n;
            }
            return 0;
        }
        match value {
            Value::Object(map) => {
                let mut count = 0;
                for (orig_key, mut item) in std::mem::take(map) {
                    let (restored_key, n, _) = self.restore(&orig_key, None, allow_secret);
                    count += n + self.restore_json_value_depth(&mut item, allow_secret, depth + 1);
                    let insert_key = if map.contains_key(&restored_key) {
                        orig_key
                    } else {
                        restored_key
                    };
                    map.insert(insert_key, item);
                }
                count
            }
            Value::Array(items) => items
                .iter_mut()
                .map(|v| self.restore_json_value_depth(v, allow_secret, depth + 1))
                .sum(),
            Value::String(text) => {
                if let Some(original) = self.json_values.get(text.as_str()) {
                    *value = original.clone();
                    return 1;
                }
                let trimmed = text.trim_start();
                if depth + 1 < MAX_JSON_DEPTH && (trimmed.starts_with('{') || trimmed.starts_with('[')) {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(text) {
                        let n = self.restore_json_value_depth(&mut inner, allow_secret, depth + 1);
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
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
    }
}

/// Thread-safe bidirectional mapping vault ("AI sees semantic tokens, Vendor never sees real values")
#[derive(Debug, Clone, Default)]
pub struct PrivacyVault {
    inner: Arc<RwLock<VaultInner>>,
    matcher: Arc<Mutex<Option<CachedMatcher>>>,
    scoped_matchers: Arc<Mutex<HashMap<Option<String>, CachedMatcher>>>,
    secret_key: Arc<RwLock<SecretKey>>,
}

/// Matcher snapshot tagged with the vault generation it was built from.
type CachedMatcher = (u64, Arc<Matcher>);

impl PrivacyVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the vault's ephemeral 256-bit secret key without locking `VaultInner`.
    pub fn secret_key(&self) -> [u8; 32] {
        self.secret_key.read().0
    }

    /// Derive a keyed, unguessable hex tag from the vault's secret key.
    pub fn keyed_tag(&self, domain: &str, scope: Option<&str>, index: usize, hex_len: usize) -> String {
        let key_bytes = self.secret_key();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(b"hide-go-token-v1:");
        ctx.update(domain.as_bytes());
        ctx.update(b":");
        ctx.update(scope.unwrap_or("").as_bytes());
        ctx.update(b":");
        ctx.update(&index.to_le_bytes());
        let tag = ctx.sign();
        let full_hex = hex::encode(tag.as_ref());
        full_hex[..hex_len.min(full_hex.len())].to_string()
    }

    /// Derive a keyed 64-bit value from the vault's secret key (e.g. for RFC 2544 IP mapping).
    pub fn keyed_u64(&self, domain: &str, scope: Option<&str>, index: usize) -> u64 {
        let key_bytes = self.secret_key();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(b"hide-go-u64-v1:");
        ctx.update(domain.as_bytes());
        ctx.update(b":");
        ctx.update(scope.unwrap_or("").as_bytes());
        ctx.update(b":");
        ctx.update(&index.to_le_bytes());
        let tag = ctx.sign();
        let bytes = tag.as_ref();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    /// Cached restorer view of all current mappings.
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

    /// Restorer view restricted strictly to entries registered under `scope`, cached by `(generation, scope)`.
    pub fn matcher_for_scope(&self, scope: Option<&str>) -> Arc<Matcher> {
        let generation = self.inner.read().generation;
        let key = scope.map(str::to_string);
        {
            let cache = self.scoped_matchers.lock();
            if let Some((g, m)) = cache.get(&key) {
                if *g == generation {
                    return m.clone();
                }
            }
        }
        let inner = self.inner.read();
        let current_gen = inner.generation;
        let m = Arc::new(Matcher::build_scoped(&inner, scope));
        drop(inner);
        let mut cache = self.scoped_matchers.lock();
        if cache.len() >= 64 {
            cache.retain(|_, (g, _)| *g == current_gen);
            if cache.len() >= 64 {
                cache.clear();
            }
        }
        cache.insert(key, (current_gen, m.clone()));
        m
    }

    /// Restorer view restricted strictly to an explicit outbound token allowlist.
    pub fn matcher_for_tokens(&self, allowed_tokens: &HashSet<String>) -> Arc<Matcher> {
        let inner = self.inner.read();
        Arc::new(Matcher::build_allowed(&inner, allowed_tokens))
    }

    /// True if `token` is registered in this vault under `scope` (or any scope if `scope` is `None`).
    pub fn contains_token_in_scope(&self, token: &str, scope: Option<&str>) -> bool {
        let inner = self.inner.read();
        inner.token_to_real.get(token).is_some_and(|e| match scope {
            Some(s) => e.scope.as_deref() == Some(s),
            None => true,
        })
    }

    /// Return `(raw_secret, token)` pairs for credential entries in `scope` (length >= 6)
    /// so context-only secrets (e.g. from JSON keys) can be re-masked if echoed in plain text.
    pub fn secret_raw_entries(&self, scope: Option<&str>) -> Vec<(String, String)> {
        let inner = self.inner.read();
        let mut out: Vec<(String, String)> = inner
            .token_to_real
            .values()
            .filter(|e| e.secret && e.original_raw.len() >= 6 && (scope.is_none() || e.scope.as_deref() == scope))
            .map(|e| (e.original_raw.clone(), e.token.clone()))
            .collect();
        out.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
        out
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
        self.get_or_insert_scoped_with(None, raw_value, category, generator)
    }

    /// Scoped variant isolating mappings per vendor/harness/session namespace.
    pub fn get_or_insert_scoped_with<F>(
        &self,
        scope: Option<&str>,
        raw_value: &str,
        category: &str,
        generator: F,
    ) -> String
    where
        F: FnOnce(usize) -> String,
    {
        if raw_value.trim().is_empty() {
            return raw_value.to_string();
        }
        let owned_scope = scope.map(str::to_string);
        self.register_with(
            raw_value,
            category,
            RegistrationKey::Original(owned_scope.clone(), raw_value.to_string()),
            None,
            is_secret_category(category),
            owned_scope,
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
        self.register_derived_scoped_with(None, transformed_value, category, context, generator)
    }

    /// Scoped variant of `register_derived_with`.
    pub fn register_derived_scoped_with<F>(
        &self,
        scope: Option<&str>,
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
        let matcher = if scope.is_some() {
            self.matcher_for_scope(scope)
        } else {
            self.matcher()
        };
        let folds_secret = matcher
            .pairs
            .iter()
            .any(|p| p.secret && transformed_value.contains(p.token.as_str()));
        let original = match context {
            DerivedContext::PlainText => matcher.restore(transformed_value, None, true).0,
            DerivedContext::JsonPayload => matcher.restore_document(transformed_value, true).0,
        };
        let json_value = matcher.json_values.get(transformed_value).cloned();
        let owned_scope = scope.map(str::to_string);
        let key = RegistrationKey::Derived(
            owned_scope.clone(),
            category.to_string(),
            original.clone(),
            json_value.is_some(),
        );
        self.register_with(
            &original,
            category,
            key,
            json_value,
            folds_secret || is_secret_category(category),
            owned_scope,
            generator,
        )
    }

    /// Preserve the exact JSON type; ordinary string registrations remain strings.
    pub fn get_or_insert_json_value_with<F>(&self, value: &Value, category: &str, generator: F) -> String
    where
        F: FnOnce(usize) -> String,
    {
        self.get_or_insert_json_value_scoped_with(None, value, category, generator)
    }

    /// Scoped variant of `get_or_insert_json_value_with`.
    pub fn get_or_insert_json_value_scoped_with<F>(
        &self,
        scope: Option<&str>,
        value: &Value,
        category: &str,
        generator: F,
    ) -> String
    where
        F: FnOnce(usize) -> String,
    {
        if let Value::String(raw) = value {
            return self.get_or_insert_scoped_with(scope, raw, category, generator);
        }
        let raw = value.to_string();
        let owned_scope = scope.map(str::to_string);
        self.register_with(
            &raw,
            category,
            RegistrationKey::Json(owned_scope.clone(), raw.clone()),
            Some(value.clone()),
            is_secret_category(category),
            owned_scope,
            generator,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_with<F>(
        &self,
        raw_value: &str,
        category: &str,
        key: RegistrationKey,
        json_value: Option<Value>,
        secret: bool,
        scope: Option<String>,
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
        let counter_key = match &scope {
            Some(s) => format!("{s}::{category}"),
            None => category.to_string(),
        };
        let index = *guard.counters.entry(counter_key).and_modify(|c| *c += 1).or_insert(1);
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
                scope,
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
        {
            let mut key_guard = self.secret_key.write();
            zeroize_bytes(&mut key_guard.0);
            key_guard.0 = generate_ephemeral_key();
        }
        guard.generation += 1;
    }
}

fn evict_least_recent(guard: &mut VaultInner, keep: &str) {
    // Prefer evicting non-secret entries so credentials stay restorable across long sessions.
    let mut non_secret: Vec<(u64, String)> = guard
        .token_to_real
        .values()
        .filter(|e| !e.secret && e.token != keep)
        .map(|e| (e.last_used, e.token.clone()))
        .collect();
    non_secret.sort();
    let mut evicted: HashSet<String> = non_secret.into_iter().take(EVICT_BATCH).map(|(_, t)| t).collect();

    if evicted.is_empty() && guard.token_to_real.len() > HARD_MAX_VAULT_ENTRIES {
        let mut all_oldest: Vec<(u64, String)> = guard
            .token_to_real
            .values()
            .filter(|e| e.token != keep)
            .map(|e| (e.last_used, e.token.clone()))
            .collect();
        all_oldest.sort();
        evicted.extend(all_oldest.into_iter().take(EVICT_BATCH).map(|(_, t)| t));
    }

    if evicted.is_empty() {
        return;
    }
    guard.token_to_real.retain(|t, _| !evicted.contains(t));
    guard.json_values.retain(|t, _| !evicted.contains(t));
    guard.source_to_token.retain(|_, t| !evicted.contains(t));
    guard.generation += 1;
}

fn is_ipv4_literal(s: &str) -> bool {
    let mut parts = s.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), Some(d), None)
            if a.parse::<u8>().is_ok()
                && b.parse::<u8>().is_ok()
                && c.parse::<u8>().is_ok()
                && d.parse::<u8>().is_ok()
    )
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
        } else if let Some(stem) = candidate.strip_suffix('⟧') {
            format!("{}#{}⟧", stem, step)
        } else if let Some(stem) = candidate.strip_suffix(">>") {
            format!("{}_{:02}>>", stem, step)
        } else if is_ipv4_literal(candidate) {
            let n = step.saturating_sub(1);
            let host = n % 254 + 1;
            let third = (n / 254) % 256;
            let second = 18 + (n / 254 / 256) % 2;
            format!("198.{second}.{third}.{host}")
        } else if let Some((local, domain)) = candidate.split_once('@') {
            format!("{local}_{step:02}@{domain}")
        } else if let Some(stem) = candidate.strip_suffix(".example.internal") {
            format!("{stem}-{step:02}.example.internal")
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
    let Some(last) = token.chars().next_back() else {
        return false;
    };
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
    if len < 12 {
        return "****".to_string();
    }
    let prefix: String = chars.iter().take(2).collect();
    let suffix: String = chars.iter().skip(len.saturating_sub(2)).collect();
    format!("{}••••{}", prefix, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_keeps_vault_bounded_and_preserves_secrets() {
        let vault = PrivacyVault::new();
        let secret_tok = vault.insert_explicit("sk-ant-real-secret-9999", "sk-sem-keep-0001", "ApiKey");
        for i in 0..(MAX_VAULT_ENTRIES + 10) {
            vault.insert_explicit(&format!("raw-{i}"), &format!("TOK_{i}"), "ProjectPath");
        }
        assert!(vault.len() <= MAX_VAULT_ENTRIES);
        assert_eq!(
            vault.get_raw_by_token(&secret_tok).as_deref(),
            Some("sk-ant-real-secret-9999")
        );
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

    #[test]
    fn scoped_matcher_isolates_cross_vendor_tokens() {
        let vault = PrivacyVault::new();
        let tok_a = vault.get_or_insert_scoped_with(Some("vendor-a"), "sk-secret-a", "ApiKey", |_| {
            "sk-sem-aaaa1111-0001".to_string()
        });
        let tok_b = vault.get_or_insert_scoped_with(Some("vendor-b"), "sk-secret-b", "ApiKey", |_| {
            "sk-sem-bbbb2222-0001".to_string()
        });
        let matcher_b = vault.matcher_for_scope(Some("vendor-b"));
        let (out, n, _) = matcher_b.restore(&format!("a={tok_a} b={tok_b}"), None, true);
        assert_eq!(out, format!("a={tok_a} b=sk-secret-b"));
        assert_eq!(n, 1);
    }

    #[test]
    fn mask_preview_withholds_short_secrets() {
        assert_eq!(mask_preview("123456"), "****");
        assert_eq!(mask_preview("P@ssw0rd123"), "****");
        assert_eq!(mask_preview("P@ssw0rd1234"), "P@••••34");
    }
}
