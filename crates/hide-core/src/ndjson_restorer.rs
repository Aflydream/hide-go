//! Line-by-line streaming restorer for NDJSON / JSONL responses (`application/x-ndjson`,
//! `application/jsonl`, `application/stream+json`).
//!
//! Complete lines are emitted as soon as their newline arrives, avoiding full-body buffering on
//! streaming upstreams such as Ollama (`/api/chat`, `/api/generate`). Text delta fields
//! (`message.content`, `message.thinking`, and top-level `response`) use independent
//! `StreamRestorer`s so placeholders split across consecutive frames restore seamlessly.

use crate::config::ToolCallSecretPolicy;
use crate::restore::{restore_response, restore_value};
use crate::stream_restorer::StreamRestorer;
use crate::vault::PrivacyVault;
use serde_json::{json, Value};
use std::io::{self, ErrorKind};

const MAX_NDJSON_PENDING_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TextField {
    MessageContent,
    MessageThinking,
    TopResponse,
}

struct TextChannel {
    restorer: StreamRestorer,
    last_envelope: Value,
    had_unflushed: bool,
}

impl TextChannel {
    fn new(vault: PrivacyVault, scope: Option<String>) -> Self {
        Self {
            restorer: StreamRestorer::with_secret_policy_scoped(vault, scope, true),
            last_envelope: Value::Null,
            had_unflushed: false,
        }
    }
}

pub struct NdjsonRestorer {
    vault: PrivacyVault,
    scope: Option<String>,
    policy: ToolCallSecretPolicy,
    pending: Vec<u8>,
    msg_content: Option<TextChannel>,
    msg_thinking: Option<TextChannel>,
    top_response: Option<TextChannel>,
    restored_non_channel: usize,
    withheld_non_channel: usize,
    finished: bool,
    failed: bool,
}

impl NdjsonRestorer {
    pub fn with_policy_scoped(vault: PrivacyVault, scope: Option<String>, policy: ToolCallSecretPolicy) -> Self {
        Self {
            vault,
            scope,
            policy,
            pending: Vec::new(),
            msg_content: None,
            msg_thinking: None,
            top_response: None,
            restored_non_channel: 0,
            withheld_non_channel: 0,
            finished: false,
            failed: false,
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> io::Result<String> {
        if self.failed {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "NDJSON stream previously failed",
            ));
        }
        if self.finished {
            return Ok(String::new());
        }
        if self.pending.len().saturating_add(bytes.len()) > MAX_NDJSON_PENDING_BYTES {
            self.failed = true;
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "upstream NDJSON line exceeded buffer limit",
            ));
        }
        self.pending.extend_from_slice(bytes);

        let mut out = String::new();
        let mut cursor = 0usize;
        while let Some(rel_nl) = self.pending[cursor..].iter().position(|&b| b == b'\n') {
            let line_end = cursor + rel_nl;
            let (raw_slice, eol) = if line_end > cursor && self.pending[line_end - 1] == b'\r' {
                (&self.pending[cursor..line_end - 1], "\r\n")
            } else {
                (&self.pending[cursor..line_end], "\n")
            };
            let line_str = String::from_utf8_lossy(raw_slice).into_owned();
            self.process_line(&line_str, eol, &mut out);
            cursor = line_end + 1;
        }
        if cursor > 0 {
            self.pending.drain(..cursor);
        }
        Ok(out)
    }

    pub fn finish(&mut self) -> io::Result<(String, usize)> {
        if self.failed {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "NDJSON stream previously failed",
            ));
        }
        if self.finished {
            return Ok((String::new(), self.restored()));
        }
        self.finished = true;

        let mut out = String::new();
        if !self.pending.is_empty() {
            let tail_bytes = std::mem::take(&mut self.pending);
            let line_str = String::from_utf8_lossy(&tail_bytes);
            self.process_line(&line_str, "", &mut out);
        }

        // Flush any remaining lookahead held by active text channels when upstream ended without `done: true`.
        for field in [
            TextField::MessageThinking,
            TextField::MessageContent,
            TextField::TopResponse,
        ] {
            let chan = match field {
                TextField::MessageContent => self.msg_content.as_mut(),
                TextField::MessageThinking => self.msg_thinking.as_mut(),
                TextField::TopResponse => self.top_response.as_mut(),
            };
            if let Some(ch) = chan {
                let (tail, _) = ch.restorer.finish();
                ch.had_unflushed = false;
                if !tail.is_empty() {
                    if let Some(frame) = synthesize_tail_frame(&ch.last_envelope, field, &tail) {
                        out.push_str(&frame);
                        out.push('\n');
                    }
                }
            }
        }

        Ok((out, self.restored()))
    }

    pub fn restored(&self) -> usize {
        self.restored_non_channel
            + self.msg_content.as_ref().map_or(0, |c| c.restorer.restored())
            + self.msg_thinking.as_ref().map_or(0, |c| c.restorer.restored())
            + self.top_response.as_ref().map_or(0, |c| c.restorer.restored())
    }

    pub fn withheld(&self) -> usize {
        self.withheld_non_channel
            + self.msg_content.as_ref().map_or(0, |c| c.restorer.withheld())
            + self.msg_thinking.as_ref().map_or(0, |c| c.restorer.withheld())
            + self.top_response.as_ref().map_or(0, |c| c.restorer.withheld())
    }

    fn channel_mut(&mut self, field: TextField) -> &mut TextChannel {
        let vault = self.vault.clone();
        let scope = self.scope.clone();
        let slot = match field {
            TextField::MessageContent => &mut self.msg_content,
            TextField::MessageThinking => &mut self.msg_thinking,
            TextField::TopResponse => &mut self.top_response,
        };
        slot.get_or_insert_with(|| TextChannel::new(vault, scope))
    }

    fn process_line(&mut self, line: &str, eol: &str, out: &mut String) {
        if line.trim().is_empty() {
            out.push_str(line);
            out.push_str(eol);
            return;
        }
        let matcher = self.vault.matcher_for_scope(self.scope.as_deref());
        let Ok(mut val) = serde_json::from_str::<Value>(line) else {
            let (restored, count, withheld) = restore_response(&matcher, line, self.policy);
            self.restored_non_channel += count;
            self.withheld_non_channel += withheld;
            out.push_str(&restored);
            out.push_str(eol);
            return;
        };

        let is_done = val.get("done").and_then(Value::as_bool) == Some(true);
        let mut extracted_msg_content: Option<String> = None;
        let mut extracted_msg_thinking: Option<String> = None;
        let mut extracted_top_response: Option<String> = None;

        if let Some(obj) = val.as_object_mut() {
            if let Some(msg) = obj.get_mut("message").and_then(Value::as_object_mut) {
                if let Some(Value::String(s)) = msg.get_mut("content") {
                    extracted_msg_content = Some(std::mem::take(s));
                }
                if let Some(Value::String(s)) = msg.get_mut("thinking") {
                    extracted_msg_thinking = Some(std::mem::take(s));
                }
            }
            if let Some(Value::String(s)) = obj.get_mut("response") {
                extracted_top_response = Some(std::mem::take(s));
            }
        }

        // Restore all non-delta fields (tool_calls, metadata, generic JSONL objects) in one shot.
        let (count, withheld) = restore_value(&matcher, &mut val, self.policy);
        self.restored_non_channel += count;
        self.withheld_non_channel += withheld;

        // Re-insert streaming text fields through dedicated cross-chunk StreamRestorers.
        if let Some(text) = extracted_msg_content {
            let envelope = val.clone();
            let ch = self.channel_mut(TextField::MessageContent);
            let mut restored = ch.restorer.push_chunk(&text);
            ch.last_envelope = envelope;
            ch.had_unflushed = true;
            if is_done {
                let (tail, _) = ch.restorer.finish();
                restored.push_str(&tail);
                ch.had_unflushed = false;
            }
            if let Some(msg) = val.get_mut("message").and_then(Value::as_object_mut) {
                msg.insert("content".to_string(), Value::String(restored));
            }
        } else if is_done {
            if let Some(ch) = self.msg_content.as_mut().filter(|c| c.had_unflushed) {
                let (tail, _) = ch.restorer.finish();
                ch.had_unflushed = false;
                if !tail.is_empty() {
                    if let Some(msg) = val.get_mut("message").and_then(Value::as_object_mut) {
                        msg.insert("content".to_string(), Value::String(tail));
                    } else if let Some(frame) =
                        synthesize_tail_frame(&ch.last_envelope, TextField::MessageContent, &tail)
                    {
                        out.push_str(&frame);
                        out.push_str(eol);
                    }
                }
            }
        }

        if let Some(text) = extracted_msg_thinking {
            let envelope = val.clone();
            let ch = self.channel_mut(TextField::MessageThinking);
            let mut restored = ch.restorer.push_chunk(&text);
            ch.last_envelope = envelope;
            ch.had_unflushed = true;
            if is_done {
                let (tail, _) = ch.restorer.finish();
                restored.push_str(&tail);
                ch.had_unflushed = false;
            }
            if let Some(msg) = val.get_mut("message").and_then(Value::as_object_mut) {
                msg.insert("thinking".to_string(), Value::String(restored));
            }
        } else if is_done {
            if let Some(ch) = self.msg_thinking.as_mut().filter(|c| c.had_unflushed) {
                let (tail, _) = ch.restorer.finish();
                ch.had_unflushed = false;
                if !tail.is_empty() {
                    if let Some(msg) = val.get_mut("message").and_then(Value::as_object_mut) {
                        msg.insert("thinking".to_string(), Value::String(tail));
                    } else if let Some(frame) =
                        synthesize_tail_frame(&ch.last_envelope, TextField::MessageThinking, &tail)
                    {
                        out.push_str(&frame);
                        out.push_str(eol);
                    }
                }
            }
        }

        if let Some(text) = extracted_top_response {
            let envelope = val.clone();
            let ch = self.channel_mut(TextField::TopResponse);
            let mut restored = ch.restorer.push_chunk(&text);
            ch.last_envelope = envelope;
            ch.had_unflushed = true;
            if is_done {
                let (tail, _) = ch.restorer.finish();
                restored.push_str(&tail);
                ch.had_unflushed = false;
            }
            if let Some(obj) = val.as_object_mut() {
                obj.insert("response".to_string(), Value::String(restored));
            }
        } else if is_done {
            if let Some(ch) = self.top_response.as_mut().filter(|c| c.had_unflushed) {
                let (tail, _) = ch.restorer.finish();
                ch.had_unflushed = false;
                if !tail.is_empty() {
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert("response".to_string(), Value::String(tail));
                    }
                }
            }
        }

        if let Ok(serialized) = serde_json::to_string(&val) {
            out.push_str(&serialized);
        } else {
            out.push_str(line);
        }
        out.push_str(eol);
    }
}

fn synthesize_tail_frame(envelope: &Value, field: TextField, tail: &str) -> Option<String> {
    let mut obj = envelope.as_object().cloned().unwrap_or_default();
    obj.insert("done".to_string(), Value::Bool(false));
    match field {
        TextField::MessageContent => {
            let msg = obj
                .entry("message")
                .or_insert_with(|| json!({"role": "assistant"}))
                .as_object_mut()?;
            msg.remove("thinking");
            msg.insert("content".to_string(), Value::String(tail.to_string()));
        }
        TextField::MessageThinking => {
            let msg = obj
                .entry("message")
                .or_insert_with(|| json!({"role": "assistant"}))
                .as_object_mut()?;
            msg.remove("content");
            msg.insert("thinking".to_string(), Value::String(tail.to_string()));
        }
        TextField::TopResponse => {
            obj.insert("response".to_string(), Value::String(tail.to_string()));
        }
    }
    serde_json::to_string(&Value::Object(obj)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_split_ollama_chat_placeholder_across_ndjson_lines() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("sk-live-secret-9999999999", "sk-sem-placeholder-key-001", "ApiKey");

        let mut restorer = NdjsonRestorer::with_policy_scoped(vault, None, ToolCallSecretPolicy::Always);
        let c1 = restorer
            .push_bytes(b"{\"model\":\"qwen\",\"message\":{\"role\":\"assistant\",\"content\":\"key=sk-sem-\"},\"done\":false}\n")
            .unwrap();
        let c2 = restorer
            .push_bytes(b"{\"model\":\"qwen\",\"message\":{\"role\":\"assistant\",\"content\":\"placeholder-key-001\"},\"done\":false}\n")
            .unwrap();
        let c3 = restorer
            .push_bytes(b"{\"model\":\"qwen\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n")
            .unwrap();
        let (tail, total) = restorer.finish().unwrap();

        let full = format!("{c1}{c2}{c3}{tail}");
        let mut assembled = String::new();
        for line in full.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            assembled.push_str(v["message"]["content"].as_str().unwrap_or(""));
        }
        assert_eq!(assembled, "key=sk-live-secret-9999999999");
        assert_eq!(total, 1);
    }

    #[test]
    fn restores_ollama_generate_split_chunks_and_partial_lines() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("10.10.2.8", "198.18.0.42", "InternalIp");

        let mut restorer = NdjsonRestorer::with_policy_scoped(vault, None, ToolCallSecretPolicy::Always);
        // Split right in the middle of a JSON line AND across two NDJSON frames.
        let p1 = restorer.push_bytes(b"{\"response\":\"host 198.18.").unwrap();
        assert!(p1.is_empty());
        let p2 = restorer
            .push_bytes(b"0.\",\"done\":false}\n{\"response\":\"42 ready\",\"done\":true}\n")
            .unwrap();
        let (tail, total) = restorer.finish().unwrap();

        let full = format!("{p2}{tail}");
        let mut assembled = String::new();
        for line in full.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            assembled.push_str(v["response"].as_str().unwrap_or(""));
        }
        assert_eq!(assembled, "host 10.10.2.8 ready");
        assert_eq!(total, 1);
    }

    #[test]
    fn flushes_unmatched_prefix_tail_on_eof_without_done_flag() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("secret-val", "sk-sem-placeholder-key-001", "ApiKey");

        let mut restorer = NdjsonRestorer::with_policy_scoped(vault, None, ToolCallSecretPolicy::Always);
        let c1 = restorer
            .push_bytes(b"{\"model\":\"qwen\",\"message\":{\"role\":\"assistant\",\"content\":\"prefix sk-sem\"},\"done\":false}\n")
            .unwrap();
        let (tail, total) = restorer.finish().unwrap();

        let full = format!("{c1}{tail}");
        let mut assembled = String::new();
        for line in full.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            assembled.push_str(v["message"]["content"].as_str().unwrap_or(""));
        }
        assert_eq!(assembled, "prefix sk-sem");
        assert_eq!(total, 0);
    }
}
