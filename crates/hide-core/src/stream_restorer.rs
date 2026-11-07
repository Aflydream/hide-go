use crate::vault::{is_valid_token_boundary, restore_with_sorted_pairs, PrivacyVault};

/// Streaming SSE / chunked response restorer with sliding window lookahead.
/// Ensures that even if a semantic token or All-Hide camouflage identifier is split across
/// two or more network chunks (e.g. Chunk 1 ends with `10.254.100.1` and Chunk 2 starts with `9`),
/// it is seamlessly reassembled and restored to the local secret without premature short-token replacement.
pub struct StreamRestorer {
    vault: PrivacyVault,
    pending_buffer: String,
    total_restored: usize,
}

impl StreamRestorer {
    pub fn new(vault: PrivacyVault) -> Self {
        Self {
            vault,
            pending_buffer: String::new(),
            total_restored: 0,
        }
    }

    /// Push a new incoming stream chunk and return the safely restored prefix that can be emitted immediately.
    pub fn push_chunk(&mut self, chunk: &str) -> String {
        self.pending_buffer.push_str(chunk);

        let pairs = self.vault.snapshot_pairs();
        if pairs.is_empty() || self.pending_buffer.is_empty() {
            return std::mem::take(&mut self.pending_buffer);
        }

        let buf_len = self.pending_buffer.len();
        let mut output = String::with_capacity(buf_len);
        let mut pos = 0usize;

        while pos < buf_len {
            let rem = &self.pending_buffer[pos..];

            // 1. If the remaining tail `rem` is a strict prefix of ANY registered token,
            // we MUST hold `rem` back until more chunks arrive (or `finish()` is called).
            let is_strict_prefix = pairs.iter().any(|(tok, _)| {
                tok.len() > rem.len() && tok.as_bytes().starts_with(rem.as_bytes())
            });
            if is_strict_prefix {
                break;
            }

            // 2. Find the longest matching token at `pos` (`pairs` is sorted by token length descending)
            let mut matched: Option<(&str, &str)> = None;
            for (token, real_val) in &pairs {
                if token.len() < 2 || token.len() > rem.len() {
                    continue;
                }
                if rem.starts_with(token.as_str())
                    && is_valid_token_boundary(&self.pending_buffer, pos, token)
                {
                    matched = Some((token.as_str(), real_val.as_str()));
                    break;
                }
            }

            if let Some((token, real_val)) = matched {
                // If this token match reaches the exact end of `pending_buffer` AND ends with an
                // ASCII alphanumeric/underscore char, hold it back in case the next chunk continues
                // a longer number/identifier (e.g. `10.254.100.1` followed by `9` in next chunk).
                let ends_at_buffer_tail = pos + token.len() == buf_len;
                let ends_with_word_or_digit = token
                    .as_bytes()
                    .last()
                    .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    .unwrap_or(false);

                if ends_at_buffer_tail && ends_with_word_or_digit {
                    break;
                }

                let (unwrapped, extra) = restore_with_sorted_pairs(real_val, &pairs);
                output.push_str(&unwrapped);
                self.total_restored += 1 + extra;
                pos += token.len();
            } else {
                let ch = rem.chars().next().unwrap();
                output.push(ch);
                pos += ch.len_utf8();
            }
        }

        if pos >= buf_len {
            self.pending_buffer.clear();
        } else if pos > 0 {
            self.pending_buffer = self.pending_buffer[pos..].to_string();
        }

        output
    }

    /// Flush remaining buffered content when the stream ends.
    pub fn finish(&mut self) -> (String, usize) {
        let remaining = std::mem::take(&mut self.pending_buffer);
        let (restored, count) = self.vault.restore_text(&remaining);
        self.total_restored += count;
        (restored, self.total_restored)
    }
}

