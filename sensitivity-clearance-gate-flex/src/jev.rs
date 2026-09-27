// Copyright 2026 Salesforce, Inc. All rights reserved.
//! `jev-client` subset (inlined; lift into the shared crate later): a single
//! abstraction for calling a System-One judge. The judge is a *classifier* — it
//! returns typed probabilities, never generated prose. For this policy it answers a
//! **score** question (a probability distribution over sensitivity levels) and a
//! **noul** question (personal data yes/no). All comparison and mutation stays in
//! Rust; the judge is never asked to compare the sensitivity to a clearance level.
//! Providers: TypeSafe Jev (noul/choice/score API), any OpenAI-compatible chat
//! endpoint driven as a JSON classifier, and a deterministic in-policy Mock.

use std::time::Duration;

use pdk::hl::*;
use serde_json::Value;

use crate::screen::Signals;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Mock,
    TypeSafe,
    OpenAi,
    OpenRouter,
    LiteLlm,
    Cloudflare,
    Custom,
}

impl Provider {
    pub fn parse(s: &str) -> Provider {
        match s {
            "mock" => Provider::Mock,
            "openai" => Provider::OpenAi,
            "openrouter" => Provider::OpenRouter,
            "litellm" => Provider::LiteLlm,
            "cloudflare" => Provider::Cloudflare,
            "custom" => Provider::Custom,
            _ => Provider::TypeSafe,
        }
    }
    /// Whether this provider speaks the OpenAI chat-completions contract.
    fn is_openai_compat(self) -> bool {
        matches!(self, Provider::OpenAi | Provider::OpenRouter | Provider::LiteLlm | Provider::Custom)
    }
    fn default_path(self) -> &'static str {
        match self {
            Provider::OpenAi => "/v1/chat/completions",
            Provider::OpenRouter => "/api/v1/chat/completions",
            Provider::LiteLlm | Provider::Custom => "/v1/chat/completions",
            Provider::TypeSafe => "/api/alpha/decisions",
            Provider::Cloudflare => "/client/v4/accounts",
            Provider::Mock => "",
        }
    }
}

#[derive(Clone, Debug)]
pub struct JevSettings {
    pub provider: Provider,
    pub model: String,
    pub path: String,
    pub api_key: String,
    pub custom_auth_header: String,
    pub timeout_ms: u64,
    pub max_state_tokens: usize,
    pub cloudflare_account_id: Option<String>,
}

impl JevSettings {
    pub fn resolved_path(&self) -> String {
        if !self.path.is_empty() {
            self.path.clone()
        } else if self.provider == Provider::Cloudflare {
            format!(
                "/client/v4/accounts/{}/ai/run/{}",
                self.cloudflare_account_id.as_deref().unwrap_or(""),
                self.model
            )
        } else {
            self.provider.default_path().to_string()
        }
    }
}

#[derive(Clone, Debug)]
pub enum JevError {
    Timeout,
    RateLimited,
    Overloaded,
    Auth,
    Upstream(u16),
    Decode(String),
    Disabled,
}

pub struct JevResult {
    pub signals: Signals,
    pub model: String,
}

/// Approximate token budget on the classified text (chars/4, conservative). Keeps
/// the head (70%) and tail (30%) with a gateway marker so padding cannot push the
/// payload past the judge. Returns (text, truncated).
pub fn budget_state(text: &str, max_tokens: usize) -> (String, bool) {
    let max_chars = max_tokens.saturating_mul(4);
    if text.chars().count() <= max_chars || max_chars == 0 {
        return (text.to_string(), false);
    }
    let head_chars = (max_chars * 7) / 10;
    let tail_chars = max_chars - head_chars;
    let chars: Vec<char> = text.chars().collect();
    let head: String = chars[..head_chars].iter().collect();
    let tail: String = chars[chars.len() - tail_chars..].iter().collect();
    (format!("{head}\n[… truncated by gateway …]\n{tail}"), true)
}

// ─── C1 question set + signal parsing ────────────────────────────────────────

/// Build the classifier system prompt for OpenAI-compatible providers, listing the
/// configured levels and their descriptions so the JSON answer keys are stable.
fn chat_system(levels: &[String], level_descriptions: &[String]) -> String {
    let mut lines = String::new();
    for (i, lvl) in levels.iter().enumerate() {
        let desc = level_descriptions.get(i).map(String::as_str).unwrap_or("");
        lines.push_str(&format!("- \"{lvl}\": {desc}\n"));
    }
    let keys = levels.iter().map(|l| format!("\"{l}\": number 0..1")).collect::<Vec<_>>().join(", ");
    format!(
        "You are a data-sensitivity classifier for an API gateway. You are given the text of a \
response an API is about to return. Classify HOW SENSITIVE it is, using these levels (least to \
most sensitive):\n{lines}\nReply with ONLY a JSON object, no prose, with keys: \
\"sensitivity\": an object giving the probability the content belongs to each level, {{{keys}}} \
(the values should sum to about 1), and \"has_personal_data\": number 0..1 (probability the \
content contains personal data about an identifiable person — names with contact details, \
government ids, financial or health data, etc.). Do NOT decide who may see it; only classify it."
    )
}

/// OpenAI-compatible chat request that drives the model as a JSON classifier.
pub fn build_chat_body(model: &str, levels: &[String], level_descriptions: &[String], state_text: &str) -> Value {
    let user = format!("content:\n{state_text}");
    serde_json::json!({
        "model": model,
        "temperature": 0,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": chat_system(levels, level_descriptions) },
            { "role": "user", "content": user }
        ]
    })
}

/// TypeSafe Jev decisions request: a `score` question over the configured levels and
/// a `noul` question for personal data. The score question's `legend` carries the
/// ordered levels and the criteria carry their descriptions.
pub fn build_typesafe_body(model: &str, levels: &[String], level_descriptions: &[String], state_text: &str) -> Value {
    // The real TypeSafe decisions API requires a `score` question's `criteria` to be
    // an ARRAY (one entry per legend position, least to most sensitive) — an object
    // keyed by level name is rejected with HTTP 400 `expected array, received object`
    // (confirmed live). The response's `probabilities` are keyed by this same
    // positional index (stringified), not by level name — see `probabilities_from`.
    let criteria: Vec<Value> = levels
        .iter()
        .enumerate()
        .map(|(i, lvl)| Value::String(level_descriptions.get(i).map(String::as_str).unwrap_or(lvl).to_string()))
        .collect();
    serde_json::json!({
        "model": model,
        "state": {
            "content_origin": "The text of a response an API is about to return to a caller.",
            "content": state_text
        },
        "questions": {
            "sensitivity": {
                "type": "score",
                "instructions": "How sensitive is `content`? Score it against the ordered levels in the legend (least to most sensitive). Judge the content itself; do not consider who is asking for it.",
                "legend": levels,
                "criteria": Value::Array(criteria)
            },
            "has_personal_data": {
                "type": "noul",
                "instructions": "Does `content` contain personal data about an identifiable person (a name together with contact details, a government id, financial data, or health data)?",
                "criteria": {
                    "true": "It contains personal data about an identifiable person.",
                    "false": "It contains no personal data, or only non-identifying information."
                }
            }
        }
    })
}

/// Read the per-level probability mass, index-aligned to `levels`. The real
/// TypeSafe decisions API keys the score question's `probabilities` object by the
/// positional legend INDEX (stringified: `"0"`,`"1"`,… — confirmed live), so read
/// that first; fall back to a level-name key for the OpenAI-compatible chat shape.
/// Never falls back to the interpolated scalar `score`, which is only weakly
/// calibrated as a number.
fn probabilities_from(node: &Value, levels: &[String]) -> Vec<f64> {
    let probs = node
        .pointer("/probabilities")
        .or_else(|| node.pointer("/probs"))
        .or_else(|| node.get("probabilities"));
    let mut out = vec![0.0; levels.len()];
    if let Some(map) = probs.and_then(Value::as_object) {
        for (i, lvl) in levels.iter().enumerate() {
            // index key ("0","1",…) first, then level name for the chat shape
            if let Some(p) = map.get(&i.to_string()).and_then(Value::as_f64) {
                out[i] = p.clamp(0.0, 1.0);
            } else if let Some(p) = map.get(lvl).and_then(Value::as_f64) {
                out[i] = p.clamp(0.0, 1.0);
            }
        }
    }
    out
}

/// noul p(true), reading `noul` first, then `p_yes`, then `probabilities.true`
/// (load-bearing ordering — a real decisions host returns `noul`; reading only
/// `p_yes` would score every answer 0).
fn noul_of(node: &Value) -> f64 {
    node.pointer("/noul")
        .or_else(|| node.pointer("/p_yes"))
        .or_else(|| node.pointer("/probabilities/true"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0)
}

/// Parse a TypeSafe decisions response into our signals.
pub fn parse_typesafe_signals(body: &[u8], levels: &[String]) -> Result<Signals, JevError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| JevError::Decode(e.to_string()))?;
    let answers = v.get("answers").unwrap_or(&v);
    let sensitivity = answers.get("sensitivity").unwrap_or(&Value::Null);
    let probabilities = probabilities_from(sensitivity, levels);
    let has_personal_data = noul_of(answers.get("has_personal_data").unwrap_or(&Value::Null));
    Ok(Signals { probabilities, has_personal_data })
}

/// Parse an OpenAI-compatible chat completion whose message content is the
/// classifier JSON (`{"sensitivity":{...}, "has_personal_data":n}`).
pub fn parse_chat_signals(body: &[u8], levels: &[String]) -> Result<Signals, JevError> {
    let v: Value = serde_json::from_slice(body).map_err(|e| JevError::Decode(e.to_string()))?;
    let content = v
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| JevError::Decode("no choices[0].message.content".into()))?;
    let parsed: Value =
        serde_json::from_str(content).map_err(|e| JevError::Decode(format!("content not JSON: {e}")))?;
    let mut out = vec![0.0; levels.len()];
    if let Some(map) = parsed.get("sensitivity").and_then(Value::as_object) {
        for (i, lvl) in levels.iter().enumerate() {
            if let Some(p) = map.get(lvl).and_then(Value::as_f64) {
                out[i] = p.clamp(0.0, 1.0);
            }
        }
    }
    let has_personal_data = parsed.get("has_personal_data").and_then(Value::as_f64).unwrap_or(0.0).clamp(0.0, 1.0);
    Ok(Signals { probabilities: out, has_personal_data })
}

/// Distribute `mass` on the `chosen` level and the rest evenly across the others.
fn distribute(n: usize, chosen: usize, mass: f64) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }
    let chosen = chosen.min(n - 1);
    if n == 1 {
        return vec![1.0];
    }
    let rest = (1.0 - mass) / ((n - 1) as f64);
    let mut v = vec![rest; n];
    v[chosen] = mass;
    v
}

/// Deterministic in-policy judge for tests and offline demos. It mirrors what a real
/// classifier would conclude from obvious lexical signals — a document full of
/// personal / restricted markers classifies high; a public blurb classifies low — so
/// a demo without any external key still shows allow-vs-block behaviour. Never
/// enabled unless `allowMock: true`. `levels` sets the distribution length.
pub fn mock_signals(state_text: &str, levels: &[String]) -> Signals {
    let n = levels.len().max(1);
    let lower = state_text.to_lowercase();
    let any = |ps: &[&str]| ps.iter().any(|p| lower.contains(p));

    let restricted = any(&[
        "ssn", "social security", "passport", "medical", "diagnosis", "health record", "patient",
        "password", "credential", "secret key", "private key", "credit card",
    ]);
    let confidential = any(&[
        "salary", "customer", "account number", "date of birth", "dob", "home address",
        "phone number", "contract", "personal", "@",
    ]);
    let internal = any(&["internal", "employee", "roadmap", "memo", "do not distribute", "confidential-internal"]);

    // Highest matched marker wins; map onto the configured level count (top index is
    // the most sensitive level).
    let top = n - 1;
    let chosen = if restricted {
        top
    } else if confidential {
        top.saturating_sub(1)
    } else if internal {
        top.saturating_sub(2).min(1)
    } else {
        0
    };

    let has_personal_data = if any(&[
        "ssn", "social security", "date of birth", "dob", "passport", "medical", "patient",
        "credit card", "phone number", "home address", "salary", "@",
    ]) {
        0.9
    } else {
        0.05
    };

    Signals { probabilities: distribute(n, chosen, 0.72), has_personal_data }
}

/// Call the judge. `state_text` is already budgeted by the caller.
pub async fn evaluate(
    client: &HttpClient,
    service: &Service,
    s: &JevSettings,
    levels: &[String],
    level_descriptions: &[String],
    state_text: &str,
) -> Result<JevResult, JevError> {
    if s.provider == Provider::Mock {
        return Ok(JevResult { signals: mock_signals(state_text, levels), model: "mock".to_string() });
    }
    if s.api_key.trim().is_empty() {
        return Err(JevError::Auth);
    }

    let (body, is_openai) = if s.provider.is_openai_compat() {
        (build_chat_body(&s.model, levels, level_descriptions, state_text), true)
    } else {
        (build_typesafe_body(&s.model, levels, level_descriptions, state_text), false)
    };
    let payload = serde_json::to_vec(&body).map_err(|e| JevError::Decode(e.to_string()))?;

    let auth_header = if s.provider == Provider::Custom { s.custom_auth_header.as_str() } else { "Authorization" };
    let auth_value = if auth_header.eq_ignore_ascii_case("authorization") {
        format!("Bearer {}", s.api_key)
    } else {
        s.api_key.clone()
    };

    let resp = client
        .request(service)
        .path(&s.resolved_path())
        .headers(vec![(auth_header, auth_value.as_str()), ("Content-Type", "application/json")])
        .body(&payload)
        .timeout(Duration::from_millis(s.timeout_ms))
        .post()
        .await
        .map_err(|_| JevError::Timeout)?;

    let status = resp.status_code() as u16;
    match status {
        200..=299 => {}
        401 | 403 => return Err(JevError::Auth),
        429 => return Err(JevError::RateLimited),
        529 => return Err(JevError::Overloaded),
        other => return Err(JevError::Upstream(other)),
    }

    let signals = if is_openai {
        parse_chat_signals(resp.body(), levels)?
    } else {
        parse_typesafe_signals(resp.body(), levels)?
    };
    Ok(JevResult { signals, model: s.model.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn levels() -> Vec<String> {
        ["public", "internal", "confidential", "restricted"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn budget_truncates_head_and_tail() {
        let text = "a".repeat(1000);
        let (out, truncated) = budget_state(&text, 100); // 400 char budget
        assert!(truncated);
        assert!(out.contains("[… truncated by gateway …]"));
        assert!(out.chars().count() < 1000);
    }

    #[test]
    fn parses_typesafe_score_probabilities_and_noul() {
        // Decisions envelope: score question returns a per-level probabilities object,
        // noul question returns `noul` (read first).
        let body = br#"{"model":"typesafe/jev-1.13","answers":{
            "sensitivity":{"type":"score","score":2.7,"legend":["public","internal","confidential","restricted"],
                "probabilities":{"public":0.02,"internal":0.08,"confidential":0.20,"restricted":0.70}},
            "has_personal_data":{"type":"noul","noul":0.93}}}"#;
        let sig = parse_typesafe_signals(body, &levels()).unwrap();
        assert!((sig.probabilities[3] - 0.70).abs() < 1e-9);
        assert!((sig.probabilities[2] - 0.20).abs() < 1e-9);
        assert!((sig.has_personal_data - 0.93).abs() < 1e-9);
    }

    #[test]
    fn typesafe_reads_noul_first_not_p_yes() {
        // If both are present the live `noul` must win (S1 bug: reading only p_yes → 0).
        let body = br#"{"answers":{"sensitivity":{"probabilities":{"public":1.0,"internal":0,"confidential":0,"restricted":0}},
            "has_personal_data":{"noul":0.88,"p_yes":0.0}}}"#;
        let sig = parse_typesafe_signals(body, &levels()).unwrap();
        assert!((sig.has_personal_data - 0.88).abs() < 1e-9);
    }

    #[test]
    fn parses_openai_classifier_content() {
        let body = br#"{"choices":[{"message":{"content":"{\"sensitivity\":{\"public\":0.05,\"internal\":0.1,\"confidential\":0.15,\"restricted\":0.7},\"has_personal_data\":0.8}"}}]}"#;
        let sig = parse_chat_signals(body, &levels()).unwrap();
        assert!((sig.probabilities[3] - 0.7).abs() < 1e-9);
        assert!((sig.has_personal_data - 0.8).abs() < 1e-9);
    }

    #[test]
    fn mock_classifies_restricted_pii_high_and_public_low() {
        let restricted = mock_signals("Patient SSN 123-45-6789, diagnosis on file, contact jane@x.com", &levels());
        assert_eq!(crate::screen::argmax_level(&restricted.probabilities), 3);
        assert!(restricted.has_personal_data > 0.5);

        let public = mock_signals("Our flagship blender ships in three colours and whips soup in 30 seconds.", &levels());
        assert_eq!(crate::screen::argmax_level(&public.probabilities), 0);
        assert!(public.has_personal_data < 0.5);
    }

    #[test]
    fn mock_distribution_sums_to_one() {
        let s = mock_signals("nothing special here", &levels());
        let sum: f64 = s.probabilities.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cloudflare_path_includes_account_and_model() {
        let s = JevSettings {
            provider: Provider::Cloudflare,
            model: "@cf/m".into(),
            path: String::new(),
            api_key: "k".into(),
            custom_auth_header: "Authorization".into(),
            timeout_ms: 600,
            max_state_tokens: 24000,
            cloudflare_account_id: Some("acc123".into()),
        };
        assert_eq!(s.resolved_path(), "/client/v4/accounts/acc123/ai/run/@cf/m");
    }
}
