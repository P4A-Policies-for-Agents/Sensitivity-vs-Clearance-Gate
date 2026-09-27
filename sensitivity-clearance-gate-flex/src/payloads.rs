// Copyright 2026 Salesforce, Inc. All rights reserved.
//! `ai-payloads` subset (inlined; lift into the shared crate later): the minimal
//! typed views this policy needs. C1 classifies a *response* on the outbound leg, so
//! the views here are: an MCP `tools/call` result (reused from the S1 shape), a
//! REST/HTTP JSON-or-text body (optionally narrowed to a set of JSON pointers), and
//! an OpenAI-compatible LLM chat completion (so a block can become a schema-preserving
//! safe reply). Plus a JWT payload decoder used on the request leg to read the
//! caller's clearance claim. Every parser is tolerant: unknown fields are ignored and
//! a parse failure surfaces as `None`.

use serde_json::Value;

// ─── request-leg: MCP request detection + JWT claim ──────────────────────────

/// What we learn from the REQUEST body (to thread to the response leg).
#[derive(Clone, Debug, Default)]
pub struct McpRequest {
    pub method: Option<String>,
    pub tool_name: Option<String>,
}

/// Detect a JSON-RPC (MCP) envelope and, for `tools/call`, the tool name.
pub fn parse_mcp_request(body: &[u8]) -> Option<McpRequest> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let obj = first_rpc(&v)?;
    let method = obj.get("method").and_then(Value::as_str).map(str::to_string);
    let tool_name = if method.as_deref() == Some("tools/call") {
        obj.pointer("/params/name").and_then(Value::as_str).map(str::to_string)
    } else {
        None
    };
    Some(McpRequest { method, tool_name })
}

fn first_rpc(v: &Value) -> Option<&Value> {
    match v {
        Value::Object(_) => Some(v),
        Value::Array(a) => a.iter().find(|e| e.is_object()),
        _ => None,
    }
}

/// Decode a JWT payload WITHOUT verifying the signature and return a top-level claim
/// as a string (numbers/bools stringified). Verification is out of scope: this is
/// only called when `trustUnverifiedClaims` is on, i.e. a JWT-validation policy is
/// expected to run before this one. A `Bearer ` prefix is tolerated.
pub fn jwt_claim(token: &str, claim: &str) -> Option<String> {
    let token = token.strip_prefix("Bearer ").or_else(|| token.strip_prefix("bearer ")).unwrap_or(token).trim();
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload = b64url_decode(payload_b64)?;
    let v: Value = serde_json::from_slice(&payload).ok()?;
    match v.get(claim)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Minimal, dependency-free base64url decoder (no padding required). Returns `None`
/// on any invalid character so a malformed token simply fails to resolve a claim.
fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in &bytes {
        let v = val(b)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// ─── response-leg: text to classify ──────────────────────────────────────────

/// Text to classify for a REST/HTTP body. If `json_paths` is non-empty and the body
/// parses as JSON, only the pointed-to values are joined and classified (e.g.
/// `/data/notes`); otherwise the whole body text is classified as-is.
pub fn rest_text(body: &str, json_paths: &[String]) -> String {
    if json_paths.is_empty() {
        return body.to_string();
    }
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return body.to_string();
    };
    let mut parts: Vec<String> = Vec::new();
    for p in json_paths {
        if let Some(node) = v.pointer(p) {
            parts.push(stringify(node));
        }
    }
    if parts.is_empty() {
        body.to_string()
    } else {
        parts.join("\n\n")
    }
}

fn stringify(node: &Value) -> String {
    match node {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

// ─── response-leg: LLM chat completion (safe-reply) ──────────────────────────

/// A view over an OpenAI-compatible chat completion we may rewrite into a safe reply.
#[derive(Clone, Debug)]
pub struct LlmView {
    /// The parsed completion (mutated in place when rewriting).
    pub value: Value,
    /// The concatenated assistant text across choices — what we classify.
    pub assistant_text: String,
}

/// Recognise an OpenAI-compatible chat completion (`choices[].message.content`).
/// Returns `None` for anything that is not that shape, so a plain REST body falls
/// through to the 403 path instead of the safe-reply path.
pub fn llm_view(body: &str) -> Option<LlmView> {
    let v: Value = serde_json::from_str(body).ok()?;
    let choices = v.get("choices")?.as_array()?;
    if choices.is_empty() {
        return None;
    }
    let mut texts: Vec<String> = Vec::new();
    for c in choices {
        if let Some(t) = c.pointer("/message/content").and_then(Value::as_str) {
            texts.push(t.to_string());
        }
    }
    if texts.is_empty() {
        return None;
    }
    Some(LlmView { value: v, assistant_text: texts.join("\n\n") })
}

/// Replace every `choices[].message.content` with `safe`, preserving the rest of the
/// completion's schema (ids, model, role, usage, finish_reason). Returns whether it
/// changed anything.
pub fn replace_assistant_content(v: &mut Value, safe: &str) -> bool {
    let mut changed = false;
    if let Some(choices) = v.get_mut("choices").and_then(Value::as_array_mut) {
        for c in choices {
            if let Some(msg) = c.get_mut("message").and_then(Value::as_object_mut) {
                if msg.contains_key("content") {
                    msg.insert("content".to_string(), Value::String(safe.to_string()));
                    changed = true;
                }
            }
        }
    }
    changed
}

// ─── MCP tools/call result (reused shape from S1) ────────────────────────────

#[derive(Clone, Debug)]
pub struct ToolResult {
    pub id: Value,
    pub text: String,
    pub is_error: bool,
    pub has_text: bool,
}

pub fn text_of_content(content: &Value, include_resource_text: bool) -> (String, bool) {
    let mut parts: Vec<String> = Vec::new();
    let mut had_text = false;
    if let Some(arr) = content.as_array() {
        for item in arr {
            match item.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = item.get("text").and_then(Value::as_str) {
                        had_text = true;
                        parts.push(t.to_string());
                    }
                }
                Some("image") => parts.push("[image omitted]".to_string()),
                Some("resource") => {
                    if include_resource_text {
                        if let Some(t) = item.pointer("/resource/text").and_then(Value::as_str) {
                            had_text = true;
                            parts.push(t.to_string());
                        } else {
                            parts.push("[binary resource omitted]".to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (parts.join("\n\n"), had_text)
}

pub fn tool_result_view(msg: &Value, include_resource_text: bool) -> Option<ToolResult> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    if msg.get("error").is_some() {
        return None;
    }
    let result = msg.get("result")?;
    let is_error = result.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let (mut text, has_text) = match result.get("content") {
        Some(c) => text_of_content(c, include_resource_text),
        None => (String::new(), false),
    };
    if let Some(sc) = result.get("structuredContent") {
        if !sc.is_null() {
            let serialised = serde_json::to_string(sc).unwrap_or_default();
            if !serialised.is_empty() && serialised != "null" {
                if !text.is_empty() {
                    text.push_str("\n\n");
                }
                text.push_str(&serialised);
            }
        }
    }
    Some(ToolResult { id, text, is_error, has_text })
}

/// Build the MCP "withheld" replacement result, preserving the JSON-RPC id.
pub fn withhold_result(id: &Value, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "isError": true,
            "content": [{ "type": "text", "text": message }]
        }
    })
}

// ─── SSE (single-shot MCP/LLM responses) ─────────────────────────────────────

pub fn sse_first_json(text: &str) -> Option<Value> {
    let mut data_lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            if !data_lines.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&data_lines.join("\n")) {
                    return Some(v);
                }
                data_lines.clear();
            }
            continue;
        }
        if let Some(payload) = line.strip_prefix("data:") {
            data_lines.push(payload.strip_prefix(' ').unwrap_or(payload).to_string());
        }
    }
    if !data_lines.is_empty() {
        if let Ok(v) = serde_json::from_str::<Value>(&data_lines.join("\n")) {
            return Some(v);
        }
    }
    None
}

pub fn wrap_sse(json_str: &str) -> String {
    format!("event: message\ndata: {json_str}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_tools_call_request() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_record","arguments":{}}}"#;
        let r = parse_mcp_request(body).unwrap();
        assert_eq!(r.method.as_deref(), Some("tools/call"));
        assert_eq!(r.tool_name.as_deref(), Some("get_record"));
    }

    #[test]
    fn jwt_claim_decodes_unverified_payload() {
        // header {"alg":"none"} . payload {"data_clearance":"restricted","sub":"u1"} . sig
        // payload base64url (no padding):
        let payload = "eyJkYXRhX2NsZWFyYW5jZSI6InJlc3RyaWN0ZWQiLCJzdWIiOiJ1MSJ9";
        let token = format!("eyJhbGciOiJub25lIn0.{payload}.sig");
        assert_eq!(jwt_claim(&token, "data_clearance").as_deref(), Some("restricted"));
        assert_eq!(jwt_claim(&token, "sub").as_deref(), Some("u1"));
        assert_eq!(jwt_claim(&token, "missing"), None);
        // Bearer prefix tolerated.
        assert_eq!(jwt_claim(&format!("Bearer {token}"), "data_clearance").as_deref(), Some("restricted"));
    }

    #[test]
    fn jwt_claim_rejects_garbage() {
        assert_eq!(jwt_claim("not-a-jwt", "x"), None);
        assert_eq!(jwt_claim("a.b", "x"), None); // payload "b" isn't JSON
    }

    #[test]
    fn rest_text_whole_body_when_no_paths() {
        assert_eq!(rest_text("hello world", &[]), "hello world");
    }

    #[test]
    fn rest_text_narrows_to_json_pointers() {
        let body = r#"{"id":1,"data":{"notes":"call me at 555-1212","meta":"public"}}"#;
        let out = rest_text(body, &["/data/notes".to_string()]);
        assert_eq!(out, "call me at 555-1212");
        assert!(!out.contains("public"));
    }

    #[test]
    fn rest_text_falls_back_when_pointer_missing() {
        let body = r#"{"a":1}"#;
        // No pointer matches → classify the whole body rather than nothing.
        assert_eq!(rest_text(body, &["/nope".to_string()]), body);
    }

    #[test]
    fn llm_view_extracts_and_replaces_content_preserving_schema() {
        let body = r#"{"id":"cmpl-1","model":"gpt","choices":[{"index":0,"message":{"role":"assistant","content":"SSN is 123-45-6789"},"finish_reason":"stop"}],"usage":{"total_tokens":9}}"#;
        let mut view = llm_view(body).unwrap();
        assert!(view.assistant_text.contains("123-45-6789"));
        assert!(replace_assistant_content(&mut view.value, "I can't share that information."));
        // schema preserved: id, model, role, finish_reason, usage all intact.
        assert_eq!(view.value["id"], json!("cmpl-1"));
        assert_eq!(view.value["choices"][0]["message"]["role"], json!("assistant"));
        assert_eq!(view.value["choices"][0]["message"]["content"], json!("I can't share that information."));
        assert_eq!(view.value["choices"][0]["finish_reason"], json!("stop"));
        assert_eq!(view.value["usage"]["total_tokens"], json!(9));
    }

    #[test]
    fn llm_view_rejects_plain_rest_body() {
        assert!(llm_view(r#"{"id":1,"name":"widget"}"#).is_none());
    }

    #[test]
    fn extracts_mcp_tool_result_text() {
        let msg = json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"patient record"}]}});
        let tr = tool_result_view(&msg, true).unwrap();
        assert!(tr.text.contains("patient record"));
        assert!(!tr.is_error);
    }
}
