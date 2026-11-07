use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// A single entry in the bidirectional semantic vault
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub token: String,
    pub original_masked: String,
    pub original_raw: String,
    pub category: String,
    pub hit_count: usize,
}

#[derive(Debug)]
struct VaultInner {
    /// Real sensitive string -> Placeholder/Camouflage token sent to vendor
    real_to_token: HashMap<String, String>,
    /// Placeholder/Camouflage token -> Real sensitive string for local restoration
    token_to_real: HashMap<String, VaultEntry>,
    /// Per-category sequential counter for readable semantic placeholders
    counters: HashMap<String, usize>,
    /// Ephemeral per-vault cryptographic secret key for keyed cipher blocks
    secret_key: [u8; 32],
}

impl Default for VaultInner {
    fn default() -> Self {
        Self {
            real_to_token: HashMap::new(),
            token_to_real: HashMap::new(),
            counters: HashMap::new(),
            secret_key: generate_ephemeral_key(),
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

/// Thread-safe bidirectional mapping vault ("AI sees semantic tokens, Vendor never sees real values")
#[derive(Debug, Clone, Default)]
pub struct PrivacyVault {
    inner: Arc<RwLock<VaultInner>>,
}

impl PrivacyVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the vault's ephemeral 256-bit secret key
    pub fn secret_key(&self) -> [u8; 32] {
        self.inner.read().secret_key
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

        let mut guard = self.inner.write();
        if let Some(existing_token) = guard.real_to_token.get(raw_value).cloned() {
            if let Some(entry) = guard.token_to_real.get_mut(&existing_token) {
                entry.hit_count += 1;
            }
            return existing_token;
        }

        let counter = guard
            .counters
            .entry(category.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let index = *counter;
        let candidate = generator(index);

        let token = disambiguate_token(&guard.token_to_real, &candidate, index);

        let masked = mask_preview(raw_value);
        guard
            .real_to_token
            .insert(raw_value.to_string(), token.clone());
        guard.token_to_real.insert(
            token.clone(),
            VaultEntry {
                token: token.clone(),
                original_masked: masked,
                original_raw: raw_value.to_string(),
                category: category.to_string(),
                hit_count: 1,
            },
        );

        token
    }

    /// Explicitly register a bidirectional pair (used by All-Hide Isomorphic Camouflage & Cipher modes).
    /// Guarantees 1-to-1 bijection: never overwrites an existing `token_to_real` entry for a different `raw_value`,
    /// returning the actual unique token registered in the vault.
    pub fn insert_explicit(&self, raw_value: &str, token: &str, category: &str) -> String {
        if raw_value.is_empty() || token.is_empty() || raw_value == token {
            return token.to_string();
        }
        let mut guard = self.inner.write();
        if let Some(existing) = guard.real_to_token.get(raw_value).cloned() {
            if let Some(entry) = guard.token_to_real.get_mut(&existing) {
                entry.hit_count += 1;
            }
            return existing;
        }

        let counter = guard
            .counters
            .entry(category.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let index = *counter;

        let unique_token = disambiguate_token(&guard.token_to_real, token, index);
        let masked = mask_preview(raw_value);
        guard
            .real_to_token
            .insert(raw_value.to_string(), unique_token.clone());
        guard.token_to_real.insert(
            unique_token.clone(),
            VaultEntry {
                token: unique_token.clone(),
                original_masked: masked,
                original_raw: raw_value.to_string(),
                category: category.to_string(),
                hit_count: 1,
            },
        );
        unique_token
    }

    /// Restore all known placeholder/camouflage tokens in a complete text back to their original local values.
    /// Uses single-pass leftmost-longest matching with token boundary checks so shorter prefix tokens never
    /// corrupt longer tokens or re-scan already restored text.
    /// Returns `(restored_text, replacement_count)`.
    pub fn restore_text(&self, text: &str) -> (String, usize) {
        let pairs = self.snapshot_pairs();
        if pairs.is_empty() || text.is_empty() {
            return (text.to_string(), 0);
        }
        restore_with_sorted_pairs(text, &pairs)
    }

    /// Return all active token -> real pairs sorted by token length descending
    pub fn snapshot_pairs(&self) -> Vec<(String, String)> {
        let guard = self.inner.read();
        let mut pairs: Vec<(String, String)> = guard
            .token_to_real
            .iter()
            .map(|(k, v)| (k.clone(), v.original_raw.clone()))
            .collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        pairs
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
        guard.real_to_token.clear();
        guard.token_to_real.clear();
        guard.counters.clear();
        guard.secret_key = generate_ephemeral_key();
    }
}

fn disambiguate_token(
    token_to_real: &HashMap<String, VaultEntry>,
    candidate: &str,
    start_idx: usize,
) -> String {
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
        } else {
            format!("{}_{:02}", candidate, step)
        };

        if !token_to_real.contains_key(&next_candidate) {
            return next_candidate;
        }
        step += 1;
    }
}

/// Check whether a token match at `text[pos..pos + token.len()]` respects number/identifier boundaries.
pub(crate) fn is_valid_token_boundary(text: &str, pos: usize, token: &str) -> bool {
    let bytes = text.as_bytes();
    let tok_bytes = token.as_bytes();
    if tok_bytes.is_empty() {
        return false;
    }
    let end = pos + tok_bytes.len();
    let last_byte = tok_bytes[tok_bytes.len() - 1];

    // If token ends with an ASCII digit (e.g. IP `10.254.100.1`), the next char cannot be an ASCII digit
    if last_byte.is_ascii_digit() {
        if let Some(&next_b) = bytes.get(end) {
            if next_b.is_ascii_digit() {
                return false;
            }
        }
    }

    // If token is a bare identifier (starts and ends with ASCII alphanumeric/underscore), enforce word boundaries
    let first_byte = tok_bytes[0];
    let is_bare_ident = (first_byte.is_ascii_alphabetic() || first_byte == b'_')
        && (last_byte.is_ascii_alphanumeric() || last_byte == b'_')
        && !token.contains("://")
        && !token.contains('/')
        && !token.contains('\\')
        && !token.contains('@')
        && !token.contains('.');

    if is_bare_ident {
        if pos > 0 {
            let prev_b = bytes[pos - 1];
            if prev_b.is_ascii_alphanumeric() || prev_b == b'_' {
                return false;
            }
        }
        if let Some(&next_b) = bytes.get(end) {
            if next_b.is_ascii_alphanumeric() || next_b == b'_' {
                return false;
            }
        }
    }

    true
}

pub(crate) fn restore_with_sorted_pairs(
    text: &str,
    pairs: &[(String, String)],
) -> (String, usize) {
    let mut current = text.to_string();
    let mut total_restored = 0usize;

    // Up to 4 passes to unwrap nested layers (e.g. CipherGarble -> IsomorphicCamouflage -> StrictLiteral -> SemanticDesensitizer)
    for _pass in 0..4 {
        let mut output = String::with_capacity(current.len());
        let mut pass_restored = 0usize;
        let mut pos = 0usize;

        while pos < current.len() {
            let rem = &current[pos..];
            let mut matched: Option<(&str, &str)> = None;

            for (token, real_val) in pairs {
                if token.len() < 2 || token.len() > rem.len() {
                    continue;
                }
                if rem.starts_with(token.as_str()) && is_valid_token_boundary(&current, pos, token)
                {
                    matched = Some((token.as_str(), real_val.as_str()));
                    break;
                }
            }

            if let Some((token, real_val)) = matched {
                output.push_str(real_val);
                pass_restored += 1;
                pos += token.len();
            } else {
                let ch = rem.chars().next().unwrap();
                output.push(ch);
                pos += ch.len_utf8();
            }
        }

        current = output;
        total_restored += pass_restored;
        if pass_restored == 0 {
            break;
        }
    }

    (current, total_restored)
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
