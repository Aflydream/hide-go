use crate::vault::{Matcher, PrivacyVault};
use std::sync::Arc;

/// Hard upper bound on lookahead bytes retained across incomplete stream chunks.
pub(crate) const MAX_PENDING_BUFFER_BYTES: usize = 1024 * 1024;

/// Streaming restorer with sliding-window lookahead.
///
/// Produces exactly what a one-shot `Matcher::restore` would produce over the concatenated
/// stream: a token split across chunks (`198.18.0.1` + `9`) is held back until it can be
/// decided, replacement values are never re-scanned, and the character just before the
/// emitted prefix is remembered so identifier/number boundaries hold across chunks.
pub struct StreamRestorer {
    vault: PrivacyVault,
    scope: Option<String>,
    matcher: Arc<Matcher>,
    pending_buffer: String,
    left: Option<char>,
    allow_secret: bool,
    total_restored: usize,
    withheld: usize,
}

impl StreamRestorer {
    pub fn new(vault: PrivacyVault) -> Self {
        Self::with_secret_policy(vault, true)
    }

    /// `allow_secret = false` keeps credential placeholders unresolved (tool-call arguments).
    pub fn with_secret_policy(vault: PrivacyVault, allow_secret: bool) -> Self {
        Self::with_secret_policy_scoped(vault, None, allow_secret)
    }

    /// Scope-aware streaming restorer so only tokens bound to `scope` are matched.
    pub fn with_secret_policy_scoped(vault: PrivacyVault, scope: Option<String>, allow_secret: bool) -> Self {
        let matcher = vault.matcher_for_scope(scope.as_deref());
        Self {
            vault,
            scope,
            matcher,
            pending_buffer: String::new(),
            left: None,
            allow_secret,
            total_restored: 0,
            withheld: 0,
        }
    }

    /// Placeholders that were left in place because they stand for credentials.
    pub fn withheld(&self) -> usize {
        self.withheld
    }

    fn refresh(&mut self) {
        self.matcher = self.vault.matcher_for_scope(self.scope.as_deref());
    }

    /// Push a new incoming stream chunk and return the safely restored prefix that can be emitted immediately.
    pub fn push_chunk(&mut self, chunk: &str) -> String {
        self.refresh();
        self.pending_buffer.push_str(chunk);
        if self.matcher.is_empty() {
            self.left = self.pending_buffer.chars().next_back().or(self.left);
            return std::mem::take(&mut self.pending_buffer);
        }

        let buf = std::mem::take(&mut self.pending_buffer);
        let mut output = String::with_capacity(buf.len());
        let mut pos = 0usize;
        while pos < buf.len() {
            let rem = &buf[pos..];
            if rem.len() <= MAX_PENDING_BUFFER_BYTES && self.matcher.is_strict_prefix(rem) {
                break;
            }
            if let Some(pair) = self.matcher.find_at(&buf, pos, self.left) {
                // A word/digit-final token at the very end could still be the start of a longer
                // identifier or number: wait for the next chunk.
                let at_tail = pos + pair.token.len() == buf.len();
                let word_final = pair
                    .token
                    .bytes()
                    .last()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
                if at_tail && word_final && rem.len() <= MAX_PENDING_BUFFER_BYTES {
                    break;
                }
                if pair.secret && !self.allow_secret {
                    output.push_str(&pair.token);
                    self.withheld += 1;
                } else {
                    output.push_str(&pair.original);
                    self.total_restored += 1;
                }
                pos += pair.token.len();
            } else {
                let Some(ch) = rem.chars().next() else {
                    break;
                };
                output.push(ch);
                pos += ch.len_utf8();
            }
        }
        if pos > 0 {
            self.left = buf[..pos].chars().next_back();
        }
        self.pending_buffer = buf[pos..].to_string();
        output
    }

    /// Flush remaining buffered content when the stream ends.
    pub fn finish(&mut self) -> (String, usize) {
        self.refresh();
        let remaining = std::mem::take(&mut self.pending_buffer);
        let (restored, count, withheld) = self.matcher.restore(&remaining, self.left, self.allow_secret);
        self.total_restored += count;
        self.withheld += withheld;
        (restored, self.total_restored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(vault: &PrivacyVault, chunks: &[&str]) -> String {
        let mut s = StreamRestorer::new(vault.clone());
        let mut out: String = chunks.iter().map(|c| s.push_chunk(c)).collect();
        out.push_str(&s.finish().0);
        out
    }

    #[test]
    fn streaming_matches_batch_without_rescanning_originals() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("note: TOKEN_B", "TOKEN_A", "x");
        vault.insert_explicit("real-b", "TOKEN_B", "x");
        assert_eq!(stream(&vault, &["TOKEN_A "]), vault.restore_plain_text("TOKEN_A ").0);
        assert_eq!(stream(&vault, &["TOKEN_A "]), "note: TOKEN_B ");
    }

    #[test]
    fn identifier_boundary_holds_across_chunks() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("real", "MASK", "x");
        assert_eq!(stream(&vault, &["XX", "MASK done"]), "XXMASK done");
        assert_eq!(stream(&vault, &["XX ", "MASK done"]), "XX real done");
    }

    #[test]
    fn every_split_point_equals_batch() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("10.0.0.10", "198.18.0.1", "InternalIp");
        vault.insert_explicit("10.0.0.19", "198.18.0.19", "InternalIp");
        vault.insert_explicit("real_fn", "fern_moss_100", "IsomorphicSymbol");
        let text = "at 198.18.0.19:80 and 198.18.0.1 call fern_moss_100() not xfern_moss_100";
        let batch = vault.restore_plain_text(text).0;
        for i in 0..text.len() {
            if text.is_char_boundary(i) {
                assert_eq!(stream(&vault, &[&text[..i], &text[i..]]), batch, "split at {i}");
            }
        }
    }
}
