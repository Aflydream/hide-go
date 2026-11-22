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
            | "modelVersion"
            | "object"
            | "project"
            | "requestId"
            | "traceId"
            | "responseId"
            | "sessionId"
            | "session_id"
            | "tool_use_id"
            | "tool_call_id"
            | "call_id"
            | "item_id"
            | "response_id"
            | "previous_response_id"
            | "signature"
            | "thoughtSignature"
            | "thought_signature"
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
            | "functionDeclarations"
            | "function_declarations"
            | "tool_choice"
            | "function_call"
            | "response_format"
            | "input_schema"
            | "parameters"
            | "parametersJsonSchema"
            | "generationConfig"
            | "generation_config"
            | "thinkingConfig"
            | "thinking_config"
            | "safetySettings"
            | "toolConfig"
            | "clientMetadata"
            | "enabledCreditTypes"
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
            | "functionDeclarations"
            | "function_declarations"
            | "tool_choice"
            | "function_call"
            | "response_format"
            | "input_schema"
            | "parameters"
            | "parametersJsonSchema"
            | "generationConfig"
            | "generation_config"
            | "thinkingConfig"
            | "thinking_config"
            | "safetySettings"
            | "toolConfig"
            | "clientMetadata"
            | "enabledCreditTypes"
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
        || (map.contains_key("name") && map.contains_key("args"))
        || (map.contains_key("name") && map.contains_key("input"))
        || (map.contains_key("name") && map.contains_key("response"))
}

/// Blocks that must be forwarded verbatim: signed reasoning and binary attachments.
/// Checks both block type and required protocol shape so arbitrary user JSON objects
/// containing a `"signature"` or `"type": "document"` field cannot bypass desensitization.
pub fn is_opaque_block(map: &Map<String, Value>) -> bool {
    if map
        .get("inlineData")
        .or_else(|| map.get("inline_data"))
        .is_some_and(Value::is_object)
    {
        return true;
    }
    if map.get("thought").and_then(Value::as_bool) == Some(true)
        && (map.get("thoughtSignature").is_some_and(Value::is_string)
            || map.get("thought_signature").is_some_and(Value::is_string))
    {
        return true;
    }
    if map.get("encrypted_content").is_some_and(Value::is_string) && !map.contains_key("messages") {
        return true;
    }
    match map.get("type").and_then(Value::as_str) {
        Some("thinking") => map.contains_key("thinking") || map.contains_key("signature"),
        Some("redacted_thinking") => map.contains_key("data"),
        Some("reasoning") => map.contains_key("encrypted_content") || map.contains_key("summary"),
        Some("image" | "document") => map.contains_key("source"),
        Some("input_image" | "input_file") => {
            map.contains_key("image_url")
                || map.contains_key("file_data")
                || map.contains_key("file_id")
                || map.contains_key("file_url")
        }
        Some("base64") => map.contains_key("data") && map.contains_key("media_type"),
        _ => false,
    }
}

/// Keys under which a string may hold a nested JSON document (tool arguments).
pub fn is_nested_json_key(key: &str) -> bool {
    matches!(key, "arguments" | "partial_json")
}
