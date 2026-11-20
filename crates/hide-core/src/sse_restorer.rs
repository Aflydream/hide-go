//! SSE framing is decoded only after a complete LF/CRLF-delimited event arrives.
//! Text deltas use independent StreamRestorers; nested JSON / tool-argument deltas are
//! buffered until their channel ends and restored once with the protocol-aware restorer.
//!
//! Every other string in a JSON event (snapshots such as `content_block_start`, Responses
//! `.done`/`.completed` summaries, Gemini `functionCall` parts) is restored in one shot with
//! the protocol-aware restorer, so tool names and final summaries never leak placeholders.
//! Tool-call arguments follow `ToolCallSecretPolicy`.
//!
//! Boundaries: bare-CR framing, oversized pending frames/buffers, and unterminated events at
//! EOF are rejected; routing IDs must be stable (a missing `index` defaults to the array
//! position). Synthetic deltas do not replay SSE id/retry/comments or Responses sequence_number.

use crate::config::ToolCallSecretPolicy;
use crate::restore::{is_file_edit_tool, restore_tool_args_for_tool, restore_value};
use crate::{stream_restorer::StreamRestorer, vault::PrivacyVault};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, ErrorKind};

const MAX_SSE_PENDING_BYTES: usize = 8 * 1024 * 1024;
const MAX_SSE_JSON_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const MAX_SSE_CHANNELS: usize = 256;
const MAX_SSE_ENDED: usize = 1024;

pub struct SseRestorer {
    vault: PrivacyVault,
    scope: Option<String>,
    policy: ToolCallSecretPolicy,
    withheld: usize,
    pending: Vec<u8>,
    scanned: usize,
    line_start: usize,
    channels: BTreeMap<Key, Channel>,
    tool_names: BTreeMap<ToolSlot, String>,
    ended: Vec<End>,
    restored: usize,
    length_truncated: bool,
    finished: bool,
    failed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ToolSlot {
    Chat(u64, u64),
    Anthropic(u64),
    ResponsesId(String),
    ResponsesIdx(u64),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Chat(u64, Option<u64>, &'static str),
    Anthropic(u64, &'static str),
    Responses {
        item_id: Option<String>,
        output_index: Option<u64>,
        content_index: u64,
        field: &'static str,
    },
    Gemini(u64, u64, &'static str),
}

// JSON fragments must NOT pass through a plain-text restorer: replacement values
// can contain quotes, backslashes and newlines. Restore the complete JSON exactly
// once, then serialize it as the outer delta's string value.
enum Buffer {
    Text(StreamRestorer),
    Json { buf: String, strict_json: bool },
}

struct Channel {
    buffer: Buffer,
    envelope: Value,
    event: Option<String>,
    newline: &'static str,
}

struct Target {
    key: Key,
    pointer: String,
    nested_json: bool,
    strict_json: bool,
    allow_secret_text: bool,
}

#[derive(Clone)]
enum End {
    All,
    Chat(u64),
    Anthropic(u64),
    Gemini(u64),
    Responses {
        item_id: Option<String>,
        output_index: Option<u64>,
        content_index: Option<u64>,
        field: Option<&'static str>,
    },
}

impl End {
    fn matches(&self, key: &Key) -> bool {
        match (self, key) {
            (Self::All, _) => true,
            (Self::Chat(a), Key::Chat(b, _, _)) => a == b,
            (Self::Anthropic(a), Key::Anthropic(b, _)) => a == b,
            (Self::Gemini(a), Key::Gemini(b, _, _)) => a == b,
            (
                Self::Responses {
                    item_id,
                    output_index,
                    content_index,
                    field,
                },
                Key::Responses {
                    item_id: other_id,
                    output_index: other_index,
                    content_index: other_content,
                    field: other_field,
                },
            ) => {
                // A done event may omit one of the two routing identifiers, but
                // must share at least one and must not contradict the other.
                let shared_id = item_id.is_some() && item_id == other_id;
                let shared_index = output_index.is_some() && output_index == other_index;
                let conflicting_id = item_id.is_some() && other_id.is_some() && item_id != other_id;
                let conflicting_index = output_index.is_some() && other_index.is_some() && output_index != other_index;
                (shared_id || shared_index)
                    && !conflicting_id
                    && !conflicting_index
                    && content_index.is_none_or(|i| i == *other_content)
                    && field.is_none_or(|f| f == *other_field)
            }
            _ => false,
        }
    }
}

impl SseRestorer {
    pub fn new(vault: PrivacyVault) -> Self {
        Self::with_policy(vault, ToolCallSecretPolicy::default())
    }

    pub fn with_policy(vault: PrivacyVault, policy: ToolCallSecretPolicy) -> Self {
        Self::with_policy_scoped(vault, None, policy)
    }

    pub fn with_policy_scoped(vault: PrivacyVault, scope: Option<String>, policy: ToolCallSecretPolicy) -> Self {
        Self {
            vault,
            scope,
            policy,
            withheld: 0,
            pending: Vec::new(),
            scanned: 0,
            line_start: 0,
            channels: BTreeMap::new(),
            tool_names: BTreeMap::new(),
            ended: Vec::new(),
            restored: 0,
            length_truncated: false,
            finished: false,
            failed: false,
        }
    }

    /// Credential placeholders deliberately left unresolved in tool-call arguments.
    pub fn withheld(&self) -> usize {
        self.withheld
    }

    /// Total placeholder tokens restored across streamed chunks so far.
    pub fn restored(&self) -> usize {
        self.restored
    }

    /// Returns complete events only. An error poisons this instance; callers must
    /// abort the response, not continue with lossy decoding or the original bytes.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> io::Result<String> {
        if self.failed || self.finished {
            return Err(io::Error::new(ErrorKind::InvalidInput, "SSE restorer is closed"));
        }
        let result = self.push_inner(bytes);
        self.failed = result.is_err();
        result
    }

    fn push_inner(&mut self, bytes: &[u8]) -> io::Result<String> {
        if self.pending.len().saturating_add(bytes.len()) > MAX_SSE_PENDING_BYTES {
            return Err(invalid("SSE pending event exceeds size limit"));
        }
        self.pending.extend_from_slice(bytes);
        let mut consumed = 0;
        let mut output = String::new();
        while self.scanned < self.pending.len() {
            let i = self.scanned;
            self.scanned += 1;
            if self.pending[i] != b'\n' {
                continue;
            }
            let line = &self.pending[self.line_start..i];
            let blank = line.is_empty() || line == b"\r";
            self.line_start = self.scanned;
            if blank {
                let raw = std::str::from_utf8(&self.pending[consumed..self.scanned])
                    .map_err(invalid)?
                    .to_owned();
                output.push_str(&self.event(&raw)?);
                consumed = self.scanned;
            }
        }
        if consumed != 0 {
            self.pending.drain(..consumed);
            self.scanned -= consumed;
            self.line_start -= consumed;
        }
        Ok(output)
    }

    /// Flushes open channels at EOF and returns the cumulative replacement count.
    /// Repeated successful calls return an empty tail and the same count.
    pub fn finish(&mut self) -> io::Result<(String, usize)> {
        if self.failed {
            return Err(invalid("SSE restorer previously failed"));
        }
        if self.finished {
            return Ok((String::new(), self.restored));
        }
        let result = (|| {
            let mut prefix = String::new();
            if !self.pending.is_empty() {
                let pending_str = std::str::from_utf8(&self.pending).map_err(invalid)?.to_owned();
                let is_benign_eof = pending_str.lines().all(|l| {
                    let t = l.trim();
                    t.is_empty() || t.starts_with(':') || t == "data: [DONE]" || t == "data:[DONE]"
                });
                if is_benign_eof {
                    self.pending.clear();
                    self.scanned = 0;
                    self.line_start = 0;
                    let mut normalized = pending_str;
                    if !normalized.ends_with('\n') {
                        normalized.push('\n');
                    }
                    normalized.push('\n');
                    prefix = self.event(&normalized)?;
                } else {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "unterminated SSE event"));
                }
            }
            let tail = self.flush(&[End::All])?;
            prefix.push_str(&tail);
            Ok((prefix, self.restored))
        })();
        self.failed = result.is_err();
        self.finished = result.is_ok();
        result
    }

    fn event(&mut self, raw: &str) -> io::Result<String> {
        let event = Event::parse(raw);
        let data = match &event.data {
            Some(data) => data.trim(),
            None => return Ok(raw.to_owned()),
        };
        if data == "[DONE]" {
            let mut output = self.flush(&[End::All])?;
            self.ended.push(End::All);
            output.push_str(raw);
            return Ok(output);
        }
        let mut value: Value = match serde_json::from_str(data) {
            Ok(value) => value,
            Err(error) if looks_json(data) || protocol_event(event.name.unwrap_or("")) => {
                return Err(invalid(error));
            }
            Err(_) => return Ok(raw.to_owned()),
        };
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .or(event.name)
            .unwrap_or("")
            .to_owned();
        if is_length_truncation_event(&value, &kind) {
            self.length_truncated = true;
        }
        let mut output = String::new();
        let mut changed = false;

        // Some providers put a last delta and finish_reason in the SAME choice.
        // Move that delta (including role/tool metadata) into a nonterminal event
        // first, so neither its prefix nor its buffered tail follows the finish.
        let envelope = chat_envelope(&value);
        let mut prelude_choices = Vec::new();
        if let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                if nonnull(choice, "finish_reason")
                    && choice
                        .get("delta")
                        .and_then(Value::as_object)
                        .is_some_and(|delta| !delta.is_empty())
                {
                    let index = optional_index(choice, "index")?.unwrap_or(0);
                    let delta = std::mem::replace(&mut choice["delta"], json!({}));
                    prelude_choices.push(json!({"index": index, "delta": delta, "finish_reason": null}));
                }
            }
        }
        if !prelude_choices.is_empty() {
            let mut prelude = envelope;
            prelude["choices"] = Value::Array(prelude_choices);
            output.push_str(&self.event(&encode(&prelude, event.name, event.newline))?);
            changed = true;
        }

        self.observe_tool_names(&value, &kind)?;
        let targets = targets(&value, &kind)?;
        // Restore every non-delta string once (snapshots, tool names, summaries). Delta
        // strings are blanked first so they only go through their streaming channel.
        let mut inputs = Vec::with_capacity(targets.len());
        for t in &targets {
            match value.pointer_mut(&t.pointer).map(std::mem::take) {
                Some(Value::String(s)) => inputs.push(s),
                _ => return Err(invalid("delta must be a JSON string")),
            }
            if let Some(slot) = value.pointer_mut(&t.pointer) {
                *slot = Value::String(String::new());
            }
        }
        let matcher = self.vault.matcher_for_scope(self.scope.as_deref());
        let (snapshot_restored, snapshot_withheld) = restore_value(&matcher, &mut value, self.policy);
        self.restored += snapshot_restored;
        self.withheld += snapshot_withheld;
        changed |= snapshot_restored > 0;

        let ends = endings(&value, &kind)?;
        for (target, input) in targets.into_iter().zip(inputs) {
            if self.ended.iter().any(|end| end.matches(&target.key)) {
                return Err(invalid("text delta received after its channel ended"));
            }
            if !self.channels.contains_key(&target.key) && self.channels.len() >= MAX_SSE_CHANNELS {
                return Err(invalid("too many active SSE channels"));
            }
            let envelope = chat_envelope(&value);
            let vault = &self.vault;
            let scope = &self.scope;
            let channel = self.channels.entry(target.key.clone()).or_insert_with(|| Channel {
                buffer: if target.nested_json {
                    Buffer::Json {
                        buf: String::new(),
                        strict_json: target.strict_json,
                    }
                } else {
                    Buffer::Text(StreamRestorer::with_secret_policy_scoped(
                        vault.clone(),
                        scope.clone(),
                        target.allow_secret_text,
                    ))
                },
                envelope,
                event: event.name.map(str::to_owned),
                newline: event.newline,
            });
            let is_text = matches!(channel.buffer, Buffer::Text(_));
            let mut restored = match &mut channel.buffer {
                Buffer::Text(stream) => stream.push_chunk(&input),
                Buffer::Json { buf, .. } => {
                    if buf.len().saturating_add(input.len()) > MAX_SSE_JSON_BUFFER_BYTES {
                        return Err(invalid("SSE nested JSON buffer exceeds size limit"));
                    }
                    buf.push_str(&input);
                    String::new()
                }
            };
            // A channel that ends in this same event (Gemini `finishReason` next to the last
            // text) gets its held-back tail appended here, keeping text before the finish.
            if is_text && ends.iter().any(|end| end.matches(&target.key)) {
                if let Some(Channel {
                    buffer: Buffer::Text(mut stream),
                    ..
                }) = self.channels.remove(&target.key)
                {
                    let (tail, total) = stream.finish();
                    self.restored += total;
                    self.withheld += stream.withheld();
                    restored.push_str(&tail);
                }
            }
            changed |= restored != input;
            if let Some(slot) = value.pointer_mut(&target.pointer) {
                *slot = Value::String(restored);
            }
        }
        output.push_str(&self.flush(&ends)?);
        if self.ended.len().saturating_add(ends.len()) <= MAX_SSE_ENDED {
            self.ended.extend(ends);
        } else if !self.ended.iter().any(|e| matches!(e, End::All)) {
            self.ended.extend(ends.into_iter().filter(|e| matches!(e, End::All)));
        }
        output.push_str(&if changed {
            event.replace_data(&value)
        } else {
            raw.to_owned()
        });
        Ok(output)
    }

    fn observe_tool_names(&mut self, value: &Value, kind: &str) -> io::Result<()> {
        if let Some(choices) = value.get("choices").and_then(Value::as_array) {
            for (position, choice) in choices.iter().enumerate() {
                let choice_index = optional_index(choice, "index")?.unwrap_or(position as u64);
                if let Some(tools) = choice.pointer("/delta/tool_calls").and_then(Value::as_array) {
                    for (pos_tool, tool) in tools.iter().enumerate() {
                        if let Some(name_chunk) = tool.pointer("/function/name").and_then(Value::as_str) {
                            let tool_index = optional_index(tool, "index")?.unwrap_or(pos_tool as u64);
                            self.tool_names
                                .entry(ToolSlot::Chat(choice_index, tool_index))
                                .or_default()
                                .push_str(name_chunk);
                        }
                    }
                }
            }
        }
        if kind == "content_block_start" {
            let block = index(value, "index")?;
            if let Some(name) = value.pointer("/content_block/name").and_then(Value::as_str) {
                self.tool_names
                    .entry(ToolSlot::Anthropic(block))
                    .or_default()
                    .push_str(name);
            }
        }
        if kind == "response.output_item.added" {
            if let Some(name) = value
                .pointer("/item/name")
                .or_else(|| value.pointer("/item/tool_name"))
                .and_then(Value::as_str)
            {
                if let Some(id) = value.pointer("/item/id").and_then(Value::as_str) {
                    self.tool_names
                        .insert(ToolSlot::ResponsesId(id.to_owned()), name.to_owned());
                }
                if let Some(out_idx) = optional_index(value, "output_index")? {
                    self.tool_names.insert(ToolSlot::ResponsesIdx(out_idx), name.to_owned());
                }
            }
        }
        Ok(())
    }

    fn tool_name_for(&self, key: &Key) -> Option<&str> {
        match key {
            Key::Chat(c, Some(t), _) => self.tool_names.get(&ToolSlot::Chat(*c, *t)).map(String::as_str),
            Key::Anthropic(idx, _) => self.tool_names.get(&ToolSlot::Anthropic(*idx)).map(String::as_str),
            Key::Responses {
                item_id, output_index, ..
            } => item_id
                .as_ref()
                .and_then(|id| self.tool_names.get(&ToolSlot::ResponsesId(id.clone())))
                .or_else(|| output_index.and_then(|idx| self.tool_names.get(&ToolSlot::ResponsesIdx(idx))))
                .map(String::as_str),
            _ => None,
        }
    }

    fn flush(&mut self, ends: &[End]) -> io::Result<String> {
        let keys: Vec<Key> = self
            .channels
            .keys()
            .filter(|key| ends.iter().any(|end| end.matches(key)))
            .cloned()
            .collect();
        let mut output = String::new();
        for key in keys {
            let Some(mut channel) = self.channels.remove(&key) else {
                continue;
            };
            let tool_name = self.tool_name_for(&key).map(str::to_owned);
            let matcher = self.vault.matcher_for_scope(self.scope.as_deref());
            let (tail, count) = match &mut channel.buffer {
                Buffer::Text(stream) => {
                    let result = stream.finish();
                    self.withheld += stream.withheld();
                    result
                }
                Buffer::Json { buf, .. } if buf.is_empty() => (String::new(), 0),
                Buffer::Json { buf, strict_json } => {
                    if *strict_json || buf.trim_start().starts_with(['{', '[']) {
                        match serde_json::from_str::<Value>(buf) {
                            Ok(mut parsed) => {
                                let (count, withheld) = restore_tool_args_for_tool(
                                    &matcher,
                                    &mut parsed,
                                    self.policy,
                                    tool_name.as_deref(),
                                );
                                self.withheld += withheld;
                                (parsed.to_string(), count)
                            }
                            Err(_) if self.length_truncated => {
                                // Model hit max_tokens/length mid-tool-call: degrade gracefully so the
                                // harness still receives the finish_reason event instead of a stream abort.
                                let allow_secret = match self.policy {
                                    ToolCallSecretPolicy::Always => true,
                                    ToolCallSecretPolicy::Never => false,
                                    ToolCallSecretPolicy::FileEditsOnly => {
                                        tool_name.as_deref().is_some_and(is_file_edit_tool)
                                    }
                                };
                                let (restored, count, withheld) = matcher.restore(buf, None, allow_secret);
                                self.withheld += withheld;
                                (restored, count)
                            }
                            Err(err) => return Err(invalid(err)),
                        }
                    } else {
                        // Free-form custom tool input (e.g. non-JSON patch/command text): apply tool policy.
                        let allow_secret = match self.policy {
                            ToolCallSecretPolicy::Always => true,
                            ToolCallSecretPolicy::Never => false,
                            ToolCallSecretPolicy::FileEditsOnly => tool_name.as_deref().is_some_and(is_file_edit_tool),
                        };
                        let (restored, count, withheld) = matcher.restore(buf, None, allow_secret);
                        self.withheld += withheld;
                        (restored, count)
                    }
                }
            };
            self.restored += count;
            if !tail.is_empty() {
                let delta = key.delta(channel.envelope, tail);
                output.push_str(&encode(&delta, channel.event.as_deref(), channel.newline));
            }
        }
        Ok(output)
    }
}

impl Key {
    fn delta(&self, mut envelope: Value, text: String) -> Value {
        match self {
            Self::Chat(choice, tool, field) => {
                let delta = match tool {
                    Some(tool) => {
                        json!({"tool_calls": [{"index": tool, "function": {(*field): text}}]})
                    }
                    None => json!({(*field): text}),
                };
                envelope["choices"] = json!([{"index": choice, "delta": delta, "finish_reason": null}]);
                envelope
            }
            Self::Anthropic(index, field) => json!({
                "type": "content_block_delta", "index": index,
                "delta": {"type": match *field { "text" => "text_delta", "thinking" => "thinking_delta", _ => "input_json_delta" },
                    (*field): text}
            }),
            Self::Gemini(index, _part_position, field) => {
                let mut part = json!({"text": text});
                if *field == "thought" {
                    part["thought"] = json!(true);
                }
                envelope["candidates"] = json!([{"index": index, "content": {"role": "model", "parts": [part]}}]);
                envelope
            }
            Self::Responses {
                item_id,
                output_index,
                content_index,
                field,
            } => {
                let mut delta = json!({"type": format!("response.{}.delta", field), "delta": text});
                if let Some(id) = item_id {
                    delta["item_id"] = json!(id);
                }
                if let Some(index) = output_index {
                    delta["output_index"] = json!(index);
                }
                if *field == "output_text" {
                    delta["content_index"] = json!(content_index);
                }
                delta
            }
        }
    }
}

fn targets(value: &Value, kind: &str) -> io::Result<Vec<Target>> {
    let mut targets = Vec::new();
    let mut add = |key, pointer: String, nested_json, strict_json, allow_secret_text| -> io::Result<()> {
        if let Some(node) = value.pointer(&pointer).filter(|node| !node.is_null()) {
            if !node.is_string() {
                return Err(invalid("delta must be a JSON string"));
            }
            targets.push(Target {
                key,
                pointer,
                nested_json,
                strict_json,
                allow_secret_text,
            });
        }
        Ok(())
    };
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for (position, choice) in choices.iter().enumerate() {
            let choice_index = optional_index(choice, "index")?.unwrap_or(position as u64);
            for field in ["content", "reasoning_content"] {
                add(
                    Key::Chat(choice_index, None, field),
                    format!("/choices/{position}/delta/{field}"),
                    false,
                    false,
                    true,
                )?;
            }
            if let Some(tools) = choice.pointer("/delta/tool_calls").and_then(Value::as_array) {
                for (position_tool, tool) in tools.iter().enumerate() {
                    let tool_index = optional_index(tool, "index")?.unwrap_or(position_tool as u64);
                    for field in ["name", "arguments"] {
                        add(
                            Key::Chat(choice_index, Some(tool_index), field),
                            format!("/choices/{position}/delta/tool_calls/{position_tool}/function/{field}"),
                            field == "arguments",
                            field == "arguments",
                            false,
                        )?;
                    }
                }
            }
        }
    }
    if kind == "content_block_delta" {
        let block = index(value, "index")?;
        for field in ["text", "thinking", "partial_json"] {
            add(
                Key::Anthropic(block, field),
                format!("/delta/{field}"),
                field == "partial_json",
                field == "partial_json",
                true,
            )?;
        }
    }
    if let Some(candidates) = value.get("candidates").and_then(Value::as_array) {
        for (position, candidate) in candidates.iter().enumerate() {
            let candidate_index = optional_index(candidate, "index")?.unwrap_or(position as u64);
            if let Some(parts) = candidate.pointer("/content/parts").and_then(Value::as_array) {
                for (part_position, part) in parts.iter().enumerate() {
                    if part.get("text").is_some_and(Value::is_string) {
                        let field = if part.get("thought").and_then(Value::as_bool) == Some(true) {
                            "thought"
                        } else {
                            "text"
                        };
                        add(
                            Key::Gemini(candidate_index, part_position as u64, field),
                            format!("/candidates/{position}/content/parts/{part_position}/text"),
                            false,
                            false,
                            true,
                        )?;
                    }
                }
            }
        }
    }
    let response_field = match kind {
        "response.output_text.delta" => Some(("output_text", false, false)),
        "response.reasoning_summary_text.delta" => Some(("reasoning_summary_text", false, false)),
        "response.refusal.delta" => Some(("refusal", false, false)),
        "response.function_call_arguments.delta" => Some(("function_call_arguments", true, true)),
        "response.mcp_call_arguments.delta" => Some(("mcp_call_arguments", true, true)),
        "response.custom_tool_call_input.delta" => Some(("custom_tool_call_input", true, false)),
        _ => None,
    };
    if let Some((field, nested_json, strict_json)) = response_field {
        let (item_id, output_index) = response_id(value)?;
        let content_index = optional_index(value, "content_index")?.unwrap_or(0);
        add(
            Key::Responses {
                item_id,
                output_index,
                content_index,
                field,
            },
            "/delta".to_owned(),
            nested_json,
            strict_json,
            !nested_json,
        )?;
    }
    Ok(targets)
}

fn endings(value: &Value, kind: &str) -> io::Result<Vec<End>> {
    let mut ends = Vec::new();
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for (position, choice) in choices.iter().enumerate() {
            if nonnull(choice, "finish_reason") {
                ends.push(End::Chat(optional_index(choice, "index")?.unwrap_or(position as u64)));
            }
        }
    }
    if let Some(candidates) = value.get("candidates").and_then(Value::as_array) {
        for (position, candidate) in candidates.iter().enumerate() {
            if nonnull(candidate, "finishReason") {
                ends.push(End::Gemini(
                    optional_index(candidate, "index")?.unwrap_or(position as u64),
                ));
            }
        }
    }
    match kind {
        "message_stop"
        | "response.done"
        | "response.completed"
        | "response.failed"
        | "response.incomplete"
        | "response.cancelled" => ends.push(End::All),
        "content_block_stop" => ends.push(End::Anthropic(index(value, "index")?)),
        "response.output_text.done"
        | "response.reasoning_summary_text.done"
        | "response.refusal.done"
        | "response.function_call_arguments.done"
        | "response.mcp_call_arguments.done"
        | "response.custom_tool_call_input.done"
        | "response.content_part.done"
        | "response.output_item.done" => {
            let (item_id, output_index) = response_id(value)?;
            let field = match kind {
                "response.output_text.done" | "response.content_part.done" => Some("output_text"),
                "response.reasoning_summary_text.done" => Some("reasoning_summary_text"),
                "response.refusal.done" => Some("refusal"),
                "response.function_call_arguments.done" => Some("function_call_arguments"),
                "response.mcp_call_arguments.done" => Some("mcp_call_arguments"),
                "response.custom_tool_call_input.done" => Some("custom_tool_call_input"),
                _ => None,
            };
            let content_index = if field == Some("output_text") {
                Some(optional_index(value, "content_index")?.unwrap_or(0))
            } else {
                None
            };
            ends.push(End::Responses {
                item_id,
                output_index,
                content_index,
                field,
            });
        }
        _ => {}
    }
    Ok(ends)
}

fn index(value: &Value, field: &str) -> io::Result<u64> {
    optional_index(value, field)?.ok_or_else(|| invalid(format!("missing routing {field}")))
}

fn optional_index(value: &Value, field: &str) -> io::Result<Option<u64>> {
    value
        .get(field)
        .map(|v| v.as_u64().ok_or_else(|| invalid(format!("invalid routing {field}"))))
        .transpose()
}

fn response_id(value: &Value) -> io::Result<(Option<String>, Option<u64>)> {
    let item_id = value
        .get("item_id")
        .or_else(|| value.pointer("/item/id"))
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid response item_id"))
        })
        .transpose()?;
    let output_index = optional_index(value, "output_index")?;
    if item_id.is_none() && output_index.is_none() {
        return Err(invalid("response delta/done requires item_id or output_index"));
    }
    Ok((item_id, output_index))
}

fn nonnull(value: &Value, field: &str) -> bool {
    value.get(field).is_some_and(|v| !v.is_null())
}

fn is_length_truncation_event(value: &Value, kind: &str) -> bool {
    kind == "response.incomplete"
        || value.pointer("/delta/stop_reason").and_then(Value::as_str) == Some("max_tokens")
        || value.get("stop_reason").and_then(Value::as_str) == Some("max_tokens")
        || value.get("choices").and_then(Value::as_array).is_some_and(|cs| {
            cs.iter()
                .any(|c| c.get("finish_reason").and_then(Value::as_str) == Some("length"))
        })
        || value.get("candidates").and_then(Value::as_array).is_some_and(|cs| {
            cs.iter()
                .any(|c| c.get("finishReason").and_then(Value::as_str) == Some("MAX_TOKENS"))
        })
}

fn chat_envelope(value: &Value) -> Value {
    let mut envelope = json!({});
    for field in ["id", "object", "created", "model", "system_fingerprint", "service_tier"] {
        if let Some(v) = value.get(field) {
            envelope[field] = v.clone();
        }
    }
    envelope
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.to_string())
}

fn looks_json(data: &str) -> bool {
    matches!(data.as_bytes().first(), Some(b'{' | b'[' | b'"' | b'-' | b'0'..=b'9'))
        || ["true", "false", "null"].iter().any(|prefix| data.starts_with(*prefix))
}

fn protocol_event(name: &str) -> bool {
    name.starts_with("response.")
        || matches!(
            name,
            "message_start"
                | "message_delta"
                | "message_stop"
                | "content_block_start"
                | "content_block_delta"
                | "content_block_stop"
        )
}

struct Event<'a> {
    raw: &'a str,
    data: Option<String>,
    name: Option<&'a str>,
    newline: &'static str,
}

// Strip exactly the one optional space specified by SSE, not arbitrary whitespace.
fn sse_field(line: &str) -> (&str, &str) {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let (name, value) = line.split_once(':').unwrap_or((line, ""));
    (name, value.strip_prefix(' ').unwrap_or(value))
}

impl<'a> Event<'a> {
    fn parse(raw: &'a str) -> Self {
        let mut data = None::<String>;
        let mut name = None;
        for line in raw.split_inclusive('\n') {
            let (field, value) = sse_field(line);
            match field {
                "data" => {
                    if let Some(data) = &mut data {
                        data.push('\n');
                        data.push_str(value);
                    } else {
                        data = Some(value.to_owned());
                    }
                }
                "event" => name = Some(value),
                _ => {}
            }
        }
        Self {
            raw,
            data,
            name,
            newline: if raw.contains("\r\n") { "\r\n" } else { "\n" },
        }
    }

    fn replace_data(&self, value: &Value) -> String {
        let mut output = String::new();
        let mut written = false;
        for line in self.raw.split_inclusive('\n') {
            if sse_field(line).0 == "data" {
                if !written {
                    // Collapse multiline JSON data to one line; all non-data
                    // lines (including comments between data lines) stay verbatim.
                    let prefix = if line.starts_with("data: ") { "data: " } else { "data:" };
                    output.push_str(prefix);
                    output.push_str(&value.to_string());
                    output.push_str(if line.ends_with("\r\n") { "\r\n" } else { "\n" });
                    written = true;
                }
            } else {
                output.push_str(line);
            }
        }
        output
    }
}

fn encode(value: &Value, event: Option<&str>, newline: &str) -> String {
    let mut output = String::new();
    if let Some(event) = event {
        output.push_str("event: ");
        output.push_str(event);
        output.push_str(newline);
    }
    output.push_str("data: ");
    output.push_str(&value.to_string());
    output.push_str(newline);
    output.push_str(newline);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(value: Value) -> String {
        encode(&value, None, "\n")
    }

    fn chat(choice: u64, text: &str) -> String {
        frame(json!({"id": "chat_1", "choices": [{"index": choice, "delta": {"content": text}}]}))
    }

    fn values(sse: &str) -> Vec<Value> {
        sse.replace("\r\n", "\n")
            .split("\n\n")
            .filter_map(|raw| Event::parse(raw).data)
            .filter(|data| data.trim() != "[DONE]")
            .map(|data| serde_json::from_str(&data).expect("every JSON event must remain valid"))
            .collect()
    }

    fn chat_text(sse: &str, choice: u64, field: &str) -> String {
        let mut text = String::new();
        for value in values(sse) {
            if let Some(choices) = value["choices"].as_array() {
                for c in choices {
                    if c["index"] == json!(choice) {
                        if let Some(s) = c["delta"][field].as_str() {
                            text.push_str(s);
                        }
                    }
                }
            }
        }
        text
    }

    #[test]
    fn every_byte_utf8_chinese_and_braille() {
        let text = "中文网络分片 ⟦⠁⠃⣀⣿⟧ 完整";
        let input = chat(0, text) + "data: [DONE]\n\n";
        let mut restorer = SseRestorer::new(PrivacyVault::new());
        let mut output = String::new();
        for byte in input.as_bytes() {
            output.push_str(&restorer.push_bytes(&[*byte]).unwrap());
        }
        let (tail, count) = restorer.finish().unwrap();
        output.push_str(&tail);
        assert_eq!(chat_text(&output, 0, "content"), text);
        assert_eq!(count, 0);
        assert!(output.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn split_token_is_escaped_and_content_is_incremental() {
        let vault = PrivacyVault::new();
        let secret = "原文\"quoted\"\n下一行";
        vault.insert_explicit(secret, "MASK_SECRET", "test");
        let mut restorer = SseRestorer::new(vault);
        let first = restorer.push_bytes(chat(0, "hello MASK_").as_bytes()).unwrap();
        assert_eq!(chat_text(&first, 0, "content"), "hello ");
        let second = restorer.push_bytes(chat(0, "SECRET !").as_bytes()).unwrap();
        let done = restorer.push_bytes(b"data: [DONE]\n\n").unwrap();
        let (tail, count) = restorer.finish().unwrap();
        assert_eq!(
            chat_text(&(first + &second + &done + &tail), 0, "content"),
            format!("hello {secret} !")
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn choices_and_reasoning_never_share_token_prefixes() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("secret", "MASK_SECRET", "test");
        let mut restorer = SseRestorer::new(vault);
        let input = chat(4, "MASK_")
            + &frame(json!({"choices": [
                {"index": 9, "delta": {"content": "SECRET"}},
                {"index": 4, "delta": {"reasoning_content": "SECRET"}}
            ]}))
            + "data: [DONE]\n\n";
        let output = restorer.push_bytes(input.as_bytes()).unwrap();
        assert_eq!(chat_text(&output, 4, "content"), "MASK_");
        assert_eq!(chat_text(&output, 9, "content"), "SECRET");
        assert_eq!(chat_text(&output, 4, "reasoning_content"), "SECRET");
        assert_eq!(restorer.finish().unwrap().1, 0);
    }

    #[test]
    fn done_and_eof_flush_tail_before_termination() {
        for with_done in [false, true] {
            let vault = PrivacyVault::new();
            vault.insert_explicit("real", "MASK_SECRET", "test");
            let mut restorer = SseRestorer::new(vault);
            let mut output = restorer.push_bytes(chat(0, "MASK_").as_bytes()).unwrap();
            if with_done {
                output.push_str(&restorer.push_bytes(b"data: [DONE]\n\n").unwrap());
            }
            let (tail, count) = restorer.finish().unwrap();
            output.push_str(&tail);
            assert_eq!(chat_text(&output, 0, "content"), "MASK_");
            assert_eq!(count, 0);
            if with_done {
                assert!(tail.is_empty());
                assert!(output.find("MASK_").unwrap() < output.find("[DONE]").unwrap());
            }
            assert_eq!(restorer.finish().unwrap(), (String::new(), 0));
        }
    }

    #[test]
    fn final_delta_precedes_finish_reason_without_replaying_role() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("real", "MASK_SECRET", "test");
        let mut restorer = SseRestorer::new(vault);
        let input = frame(json!({"id": "chat_1", "choices": [{"index": 0,
            "delta": {"role": "assistant", "content": "prefix MASK_SECRET"}, "finish_reason": "stop"}]}));
        let output = restorer.push_bytes(input.as_bytes()).unwrap();
        assert_eq!(chat_text(&output, 0, "content"), "prefix real");
        let events = values(&output);
        assert_eq!(events.last().unwrap()["choices"][0]["finish_reason"], "stop");
        assert_eq!(
            events
                .iter()
                .filter(|v| v["choices"][0]["delta"].get("role").is_some())
                .count(),
            1
        );
        assert_eq!(restorer.finish().unwrap(), (String::new(), 1));
    }

    #[test]
    fn anthropic_json_fragments_restore_windows_paths_structurally() {
        let vault = PrivacyVault::new();
        let path = "C:\\Users\\alice\\\"private\"\nfile.rs";
        vault.insert_explicit(path, "MASK_PATH", "test");
        let mut restorer = SseRestorer::new(vault);
        let mut input = String::new();
        for fragment in ["{\"path\":\"MASK_", "PATH\",\"unchanged\":\"C:\\\\Temp\"}"] {
            input.push_str(&encode(
                &json!({"type": "content_block_delta", "index": 3,
                "delta": {"type": "input_json_delta", "partial_json": fragment}}),
                Some("content_block_delta"),
                "\n",
            ));
        }
        input.push_str(&encode(
            &json!({"type": "content_block_stop", "index": 3}),
            Some("content_block_stop"),
            "\n",
        ));
        input.push_str(&frame(json!({"type": "message_stop"})));
        let output = restorer.push_bytes(input.as_bytes()).unwrap();
        let events = values(&output);
        let arguments: String = events
            .iter()
            .filter_map(|v| v["delta"]["partial_json"].as_str())
            .collect();
        let parsed: Value = serde_json::from_str(&arguments).unwrap();
        assert_eq!(parsed["path"], path);
        assert_eq!(parsed["unchanged"], "C:\\Temp");
        assert!(output.find("private").unwrap() < output.find("event: content_block_stop").unwrap());
        assert_eq!(restorer.finish().unwrap(), (String::new(), 1));
    }

    #[test]
    fn tool_names_arguments_and_tools_are_independent() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("C:\\Users\\alice\\file.rs", "MASK_PATH", "test");
        vault.insert_explicit("read_file", "MASK_TOOL", "test");
        let mut restorer = SseRestorer::new(vault);
        let mut input = frame(json!({"choices": [{"index": 2, "delta": {"tool_calls": [
            {"index": 0, "id": "call_0", "type": "function", "function": {"name": "MASK_", "arguments": "{\"path\":\"MASK_"}},
            {"index": 1, "id": "call_1", "type": "function", "function": {"name": "TOOL", "arguments": "{\"path\":\"PATH\"}"}}
        ]}}]}));
        input.push_str(&frame(json!({"choices": [{"index": 2, "delta": {"tool_calls": [
            {"index": 0, "function": {"name": "TOOL", "arguments": "PATH\"}"}}
        ]}, "finish_reason": "tool_calls"}]})));
        let output = restorer.push_bytes(input.as_bytes()).unwrap();
        let mut args = [String::new(), String::new()];
        let mut names = [String::new(), String::new()];
        let mut ids = 0;
        for value in values(&output) {
            if let Some(tools) = value["choices"][0]["delta"]["tool_calls"].as_array() {
                for tool in tools {
                    let i = tool["index"].as_u64().unwrap() as usize;
                    args[i].push_str(tool["function"]["arguments"].as_str().unwrap_or(""));
                    names[i].push_str(tool["function"]["name"].as_str().unwrap_or(""));
                    ids += usize::from(tool.get("id").is_some());
                }
            }
        }
        assert_eq!(
            serde_json::from_str::<Value>(&args[0]).unwrap()["path"],
            "C:\\Users\\alice\\file.rs"
        );
        assert_eq!(serde_json::from_str::<Value>(&args[1]).unwrap()["path"], "PATH");
        assert_eq!(names, ["read_file", "TOOL"]);
        assert_eq!(ids, 2);
        assert_eq!(restorer.finish().unwrap(), (String::new(), 2));
    }

    #[test]
    fn responses_route_by_item_output_and_content_and_flush_scoped_done() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("secret", "MASK_SECRET", "test");
        let mut restorer = SseRestorer::new(vault);
        let mut input = String::new();
        for (id, output, content, delta) in [("a", 0, 0, "MASK_"), ("b", 1, 0, "SECRET"), ("a", 0, 1, "SECRET")] {
            input.push_str(&encode(
                &json!({"type": "response.output_text.delta", "item_id": id,
                "output_index": output, "content_index": content, "delta": delta}),
                Some("response.output_text.delta"),
                "\n",
            ));
        }
        input.push_str(&frame(
            json!({"type": "response.output_text.done", "item_id": "b", "output_index": 1, "content_index": 0}),
        ));
        input.push_str(&frame(json!({"type": "response.output_text.delta", "item_id": "a", "output_index": 0, "content_index": 0, "delta": "SECRET"})));
        input.push_str(&frame(
            json!({"type": "response.output_item.done", "output_index": 0, "item": {"id": "a"}}),
        ));
        let output = restorer.push_bytes(input.as_bytes()).unwrap();
        let events = values(&output);
        let mut texts = BTreeMap::<(String, u64), String>::new();
        for v in &events {
            if v["type"] == "response.output_text.delta" {
                texts
                    .entry((
                        v["item_id"].as_str().unwrap().to_owned(),
                        v["content_index"].as_u64().unwrap(),
                    ))
                    .or_default()
                    .push_str(v["delta"].as_str().unwrap());
            }
        }
        assert_eq!(texts[&("a".to_owned(), 0)], "secret");
        assert_eq!(texts[&("a".to_owned(), 1)], "SECRET");
        assert_eq!(texts[&("b".to_owned(), 0)], "SECRET");
        assert_eq!(events.last().unwrap()["type"], "response.output_item.done");
        assert_eq!(restorer.finish().unwrap(), (String::new(), 1));
    }

    #[test]
    fn responses_arguments_are_json_aware() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("C:\\private\\\"quoted\"", "MASK_PATH", "test");
        let mut restorer = SseRestorer::new(vault);
        let mut input = String::new();
        for fragment in ["{\"path\":\"MASK_", "PATH\"}"] {
            input.push_str(&frame(json!({"type": "response.function_call_arguments.delta",
                "item_id": "call", "delta": fragment})));
        }
        input.push_str(&frame(
            json!({"type": "response.function_call_arguments.done", "item_id": "call"}),
        ));
        let output = restorer.push_bytes(input.as_bytes()).unwrap();
        let arguments: String = values(&output).iter().filter_map(|v| v["delta"].as_str()).collect();
        assert_eq!(
            serde_json::from_str::<Value>(&arguments).unwrap()["path"],
            "C:\\private\\\"quoted\""
        );
        assert_eq!(restorer.finish().unwrap().1, 1);
    }

    #[test]
    fn unknown_events_comments_metadata_and_crlf_are_preserved() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("real", "MASK_SECRET", "test");
        let mut restorer = SseRestorer::new(vault);
        let unknown = ": keepalive\r\nevent: custom\r\nid: 17\r\nretry: 2000\r\ndata: plain 中文\r\ndata: second line\r\n\r\nevent: custom\r\ndata: {\"unknown\":\"MASK_SECRET\"}\r\n\r\n";
        // Non-JSON data and metadata pass through verbatim; JSON strings in unknown events are
        // restored too, so unfamiliar provider events never leak placeholders.
        assert_eq!(
            restorer.push_bytes(unknown.as_bytes()).unwrap(),
            unknown.replace("{\"unknown\":\"MASK_SECRET\"}", "{\"unknown\":\"real\"}")
        );
        let known = "event: message\r\nid: 18\r\nretry: 3000\r\ndata: {\"choices\":[{\"index\":0,\r\n: between data lines\r\ndata: \"delta\":{\"content\":\"MASK_SECRET!\"}}]}\r\n\r\n";
        let output = restorer.push_bytes(known.as_bytes()).unwrap();
        assert!(output.contains("event: message\r\nid: 18\r\nretry: 3000\r\n"));
        assert!(output.contains(": between data lines\r\n"));
        assert!(!output.replace("\r\n", "").contains('\n'));
        assert_eq!(chat_text(&output, 0, "content"), "real!");
        assert_eq!(restorer.finish().unwrap().1, 2);
    }

    #[test]
    fn anthropic_snapshots_thinking_and_tool_secrets() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("10.0.0.5", "198.18.0.1", "InternalIp");
        vault.insert_explicit("sk-ant-real-0123456789abcdef", "sk-sem-placeholder-key-0001", "ApiKey");
        vault.insert_explicit("deploy_titan", "fern_moss_100", "IsomorphicSymbol");
        let mut r = SseRestorer::new(vault);
        let ev = |v: Value| {
            encode(
                &v,
                v["type"].as_str(),
                "
",
            )
        };
        let mut input = String::new();
        input += &ev(
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}),
        );
        input += &ev(
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "host 198.18.0"}}),
        );
        input += &ev(
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": ".1 ok"}}),
        );
        input += &ev(
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "sig198.18.0.1"}}),
        );
        input += &ev(json!({"type": "content_block_stop", "index": 0}));
        input += &ev(
            json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "fern_moss_100", "input": {}}}),
        );
        input += &ev(
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta",
            "partial_json": "{\"command\": \"curl -H k:sk-sem-placeholder-key-0001 198.18.0.1\"}"}}),
        );
        input += &ev(json!({"type": "content_block_stop", "index": 1}));
        input += &ev(json!({"type": "message_stop"}));
        let out = r.push_bytes(input.as_bytes()).unwrap();
        let events = values(&out);
        let thinking: String = events.iter().filter_map(|v| v["delta"]["thinking"].as_str()).collect();
        assert_eq!(thinking, "host 10.0.0.5 ok");
        assert!(out.contains("\"signature\":\"sig198.18.0.1\""));
        assert!(events.iter().any(|v| v["content_block"]["name"] == "deploy_titan"));
        let args: String = events
            .iter()
            .filter_map(|v| v["delta"]["partial_json"].as_str())
            .collect();
        let args: Value = serde_json::from_str(&args).unwrap();
        assert_eq!(args["command"], "curl -H k:sk-sem-placeholder-key-0001 10.0.0.5");
        assert_eq!(r.withheld(), 1);
    }

    #[test]
    fn gemini_stream_restores_text_and_final_chunk() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("real-secret", "MASK_SECRET", "test");
        let mut r = SseRestorer::new(vault);
        let input = frame(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "a MASK_"}]}}]}))
            + &frame(
                json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "SECRET b"}]}, "finishReason": "STOP"}]}),
            );
        let out = r.push_bytes(input.as_bytes()).unwrap();
        let text: String = values(&out)
            .iter()
            .flat_map(|v| {
                v["candidates"][0]["content"]["parts"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|p| p["text"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(text, "a real-secret b");
        assert_eq!(values(&out).last().unwrap()["candidates"][0]["finishReason"], "STOP");
    }

    #[test]
    fn chat_chunks_without_index_are_accepted() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("real", "MASK_SECRET", "test");
        let mut r = SseRestorer::new(vault);
        let out = r
            .push_bytes(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"MASK_SECRET \"}}]}

",
            )
            .unwrap();
        assert_eq!(values(&out)[0]["choices"][0]["delta"]["content"], "real ");
    }

    #[test]
    fn malformed_utf8_json_and_truncated_streams_return_errors() {
        for bytes in [
            b"data: {bad}\n\n".as_slice(),
            b"data: \xff\n\n".as_slice(),
            b"event: content_block_delta\ndata: not-json\n\n".as_slice(),
        ] {
            let mut restorer = SseRestorer::new(PrivacyVault::new());
            assert_eq!(restorer.push_bytes(bytes).unwrap_err().kind(), ErrorKind::InvalidData);
            assert!(restorer.finish().is_err());
        }
        let mut restorer = SseRestorer::new(PrivacyVault::new());
        assert!(restorer.push_bytes(b"data: {\"x\":1}\n").unwrap().is_empty());
        assert_eq!(restorer.finish().unwrap_err().kind(), ErrorKind::UnexpectedEof);
        let mut restorer = SseRestorer::new(PrivacyVault::new());
        assert!(restorer.push_bytes(b"data: \xe4").unwrap().is_empty());
        assert_eq!(restorer.finish().unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn incomplete_nested_json_errors_before_stop_or_at_eof() {
        for stop in [false, true] {
            let mut restorer = SseRestorer::new(PrivacyVault::new());
            let input = frame(json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"x\":\""}}));
            restorer.push_bytes(input.as_bytes()).unwrap();
            if stop {
                let end = frame(json!({"type": "content_block_stop", "index": 0}));
                assert_eq!(
                    restorer.push_bytes(end.as_bytes()).unwrap_err().kind(),
                    ErrorKind::InvalidData
                );
            }
            assert!(restorer.finish().is_err());
        }
    }

    #[test]
    fn responses_custom_tool_call_input_withholds_secrets_for_non_edit_tools() {
        let vault = PrivacyVault::new();
        vault.insert_explicit("sk-real-secret-999", "sk-sem-placeholder-key-0001", "ApiKey");
        let mut restorer = SseRestorer::with_policy(vault, ToolCallSecretPolicy::FileEditsOnly);
        let added = frame(json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {"id": "ct_1", "type": "custom_tool_call", "name": "Bash"}
        }));
        let d1 = frame(json!({
            "type": "response.custom_tool_call_input.delta",
            "item_id": "ct_1",
            "output_index": 0,
            "delta": "{\"content\":\"curl "
        }));
        let d2 = frame(json!({
            "type": "response.custom_tool_call_input.delta",
            "item_id": "ct_1",
            "output_index": 0,
            "delta": "sk-sem-placeholder-key-0001\"}"
        }));
        let done = frame(json!({
            "type": "response.custom_tool_call_input.done",
            "item_id": "ct_1",
            "output_index": 0
        }));
        let mut out = String::new();
        for ev in [added, d1, d2, done] {
            out.push_str(&restorer.push_bytes(ev.as_bytes()).unwrap());
        }
        assert!(!out.contains("sk-real-secret-999"), "{out}");
        assert_eq!(restorer.withheld(), 1);
    }

    #[test]
    fn oversized_sse_pending_event_is_rejected() {
        let mut restorer = SseRestorer::new(PrivacyVault::new());
        let big = vec![b'a'; MAX_SSE_PENDING_BYTES + 1];
        assert_eq!(restorer.push_bytes(&big).unwrap_err().kind(), ErrorKind::InvalidData);
    }
}
