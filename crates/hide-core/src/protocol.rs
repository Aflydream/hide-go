//! Shared knowledge of LLM wire protocols (Anthropic Messages, OpenAI Chat / Responses,
//! Gemini). Transformations must leave protocol structure byte-exact: identifiers that pair
//! requests with results, signed reasoning blocks, binary attachments and tool schemas.

use serde_json::{Map, Value};

/// Keys whose string values are protocol identifiers or enums. Never rewritten.
pub fn is_structural_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "type"
            | "role"
            | "model"
            | "object"
            | "tool_use_id"
            | "tool_call_id"
            | "call_id"
            | "item_id"
            | "response_id"
            | "previous_response_id"
            | "signature"
            | "encrypted_content"
            | "stop_reason"
            | "finish_reason"
            | "finishReason"
            | "media_type"
            | "mimeType"
            | "mime_type"
            | "status"
            | "service_tier"
            | "system_fingerprint"
            | "cache_control"
            | "harness"
    )
}

/// Request sections that describe the API surface rather than user content. All-Hide leaves
/// them alone so tool names, parameter names and `required` lists keep matching.
pub fn is_schema_key(key: &str) -> bool {
    matches!(
        key,
        "tools"
            | "functions"
            | "tool_choice"
            | "function_call"
            | "response_format"
            | "input_schema"
            | "parameters"
            | "generationConfig"
            | "generation_config"
            | "safetySettings"
            | "toolConfig"
            | "metadata"
            | "stop"
            | "stop_sequences"
            | "name"
            | "format"
            | "reasoning"
            | "include"
    )
}

/// API-surface schema/config containers whose keys and strings describe protocol
/// definitions (e.g. tool definitions, parameter schemas, generation settings) rather
/// than user content. Semantic desensitizer leaves them verbatim.
pub fn is_api_schema_container_key(key: &str) -> bool {
    matches!(
        key,
        "tools"
            | "functions"
            | "tool_choice"
            | "function_call"
            | "response_format"
            | "input_schema"
            | "parameters"
            | "generationConfig"
            | "generation_config"
            | "safetySettings"
            | "toolConfig"
            | "stop"
            | "stop_sequences"
            | "reasoning"
            | "include"
    )
}

/// Returns true when `map` represents a tool/function invocation or response block
/// whose `"name"` field identifies a tool name rather than user text.
pub fn is_tool_call_object(map: &Map<String, Value>) -> bool {
    matches!(
        map.get("type").and_then(Value::as_str),
        Some("tool_use" | "server_tool_use" | "function" | "function_call" | "custom_tool_call")
    ) || map.contains_key("tool_use_id")
        || map.contains_key("tool_call_id")
        || map.contains_key("call_id")
        || (map.contains_key("name") && map.contains_key("arguments"))
        || (map.contains_key("name") && map.contains_key("input"))
        || (map.contains_key("name") && map.contains_key("response"))
}

/// Blocks that must be forwarded verbatim: signed reasoning and binary attachments.
pub fn is_opaque_block(map: &Map<String, Value>) -> bool {
    if map.contains_key("signature") || map.contains_key("encrypted_content") {
        return true;
    }
    if map.contains_key("inlineData") || map.contains_key("inline_data") {
        return true;
    }
    matches!(
        map.get("type").and_then(Value::as_str),
        Some(
            "thinking"
                | "redacted_thinking"
                | "image"
                | "input_image"
                | "document"
                | "input_file"
                | "reasoning"
                | "base64"
        )
    )
}

/// Keys under which a string may hold a nested JSON document (tool arguments).
pub fn is_nested_json_key(key: &str) -> bool {
    matches!(key, "arguments" | "partial_json")
}
