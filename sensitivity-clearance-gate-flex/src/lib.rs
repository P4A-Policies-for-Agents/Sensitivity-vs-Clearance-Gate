// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Sensitivity vs Clearance Gate — a response-leg Omni/Flex Gateway policy.
//!
//! Classifies how sensitive an outbound response is with a typed "System 1" Jev
//! judge (a probability distribution over sensitivity levels + a personal-data
//! probability — never generated text), then compares that distribution to the
//! *caller's clearance* and blocks the response when it is too sensitive for them.
//! The comparison — probability MASS above the caller's clearance — is computed in
//! Rust; the judge is never asked to compare a sensitivity to a clearance.
//!
//! Two legs:
//! - REQUEST: strip client `x-jev-*` headers, resolve the caller's clearance
//!   (JWT claim → header → default), resolve any per-route floor, and record scope.
//!   No judge call.
//! - RESPONSE: extract the classifiable text (MCP `tools/call` result, an
//!   OpenAI-compatible LLM completion, or a REST/HTTP body — optionally narrowed to
//!   `jsonPaths`), call the judge, compute `p_exceeds`, decide, and act per `mode`:
//!   REST → an `insufficient_clearance` error body; LLM → a schema-preserving safe
//!   reply; MCP → a withheld result. Errors honour `failMode` (open passes through).
//!
//! Response-leg header/status note: this policy uses the split event-flow response
//! path (headers freeze before the body is read), which is the runtime-safe choice —
//! the combined `into_headers_body_state()` that would let us also set HTTP `:status`
//! 403 / add the `x-jev-sensitivity` header is subject to a response-leg hang on some
//! Omni/Flex versions (1.12.1). So a block replaces the *body* with a machine-readable
//! error object (HTTP status left unchanged) and a flag is recorded in the decision
//! log. See `demo/WALKTHROUGH.md` for how to opt into the combined state.

mod common;
mod generated;
mod jev;
mod payloads;
mod screen;

use std::rc::Rc;

use pdk::hl::*;
use pdk::logger;
use serde_json::Value;

use crate::common::{fnv1a_64, path_prefix_match, sampled_in, Bands, Decision, FailMode, Mode};
use crate::generated::config::Config;
use crate::jev::{budget_state, evaluate, JevError, JevSettings, Provider};
use crate::payloads::{
    jwt_claim, llm_view, parse_mcp_request, replace_assistant_content, rest_text, sse_first_json,
    tool_result_view, withhold_result, wrap_sse,
};
use crate::screen::{argmax_level, decide, p_exceeds, reason_str, DecideInput, Reason, Signals};

const POLICY: &str = "sensitivity-clearance-gate";
const HDR: &str = "x-jev-sensitivity";
const WITHHELD_MSG: &str =
    "The gateway withheld this result because it is more sensitive than the caller is cleared to receive (policy: sensitivity-clearance-gate).";

const DEFAULT_LEVELS: &[&str] = &["public", "internal", "confidential", "restricted"];

/// Threaded from the request leg to the response leg.
#[derive(Clone, Debug, Default)]
struct Ctx {
    /// Whether this response is in scope to classify.
    screen: bool,
    /// JSON-RPC (MCP) vs REST/HTTP/LLM.
    is_rpc: bool,
    /// Caller's clearance ordinal (index into the configured levels).
    clearance_ordinal: usize,
    /// Caller's clearance label, for the decision log.
    clearance_label: String,
    /// Per-route floor ordinal (`routeFloor`), if the request path matched one.
    route_floor_ordinal: Option<usize>,
}

// ─── config helpers ──────────────────────────────────────────────────────────

fn levels(cfg: &Config) -> Vec<String> {
    cfg.levels
        .as_ref()
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_LEVELS.iter().map(|s| s.to_string()).collect())
}

fn level_descriptions(cfg: &Config) -> Vec<String> {
    cfg.level_descriptions.clone().unwrap_or_default()
}

/// Ordinal (index) of a clearance/sensitivity label, case-insensitive.
fn level_ordinal(levels: &[String], name: &str) -> Option<usize> {
    let name = name.trim();
    levels.iter().position(|l| l.eq_ignore_ascii_case(name))
}

fn bands(cfg: &Config) -> Bands {
    Bands::new(cfg.flag_at.unwrap_or(0.3), cfg.block_at.unwrap_or(0.6))
}

fn jev_settings(cfg: &Config) -> JevSettings {
    JevSettings {
        provider: Provider::parse(cfg.jev_provider.as_deref().unwrap_or("typesafe")),
        model: cfg.jev_model.clone().unwrap_or_else(|| "~typesafe/jev-latest".to_string()),
        path: cfg.jev_path.clone().unwrap_or_default(),
        api_key: cfg.jev_api_key.clone().unwrap_or_default(),
        custom_auth_header: cfg.custom_auth_header.clone().unwrap_or_else(|| "Authorization".to_string()),
        timeout_ms: cfg.jev_timeout_ms.unwrap_or(600).max(1) as u64,
        max_state_tokens: cfg.max_state_tokens.unwrap_or(24000).max(256) as usize,
        cloudflare_account_id: cfg.cloudflare_account_id.clone(),
    }
}

fn fail_mode(cfg: &Config) -> FailMode {
    FailMode::parse(cfg.fail_mode.as_deref().unwrap_or("open"))
}

/// Ordinal below which a caller may not see personal data (`personalDataMinClearance`).
fn personal_data_min_ordinal(cfg: &Config, levels: &[String]) -> usize {
    let name = cfg.personal_data_min_clearance.as_deref().unwrap_or("confidential");
    level_ordinal(levels, name).unwrap_or_else(|| levels.len().saturating_sub(2))
}

/// Resolve the most restrictive per-route floor ordinal for `path` from the
/// `"pathPrefix=level"` entries (most sensitive floor wins on overlap).
fn route_floor_ordinal(entries: &[String], levels: &[String], path: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    for e in entries {
        if let Some((prefix, lvl)) = e.split_once('=') {
            let prefix = prefix.trim();
            if !prefix.is_empty() && path_prefix_match(&[prefix.to_string()], path) {
                if let Some(ord) = level_ordinal(levels, lvl) {
                    best = Some(best.map_or(ord, |b| b.max(ord)));
                }
            }
        }
    }
    best
}

/// Resolve the caller's clearance: JWT claim (only when `trustUnverifiedClaims`),
/// then the clearance header, then `defaultClearance`. Returns (ordinal, label).
fn resolve_clearance(
    cfg: &Config,
    levels: &[String],
    authorization: Option<&str>,
    header_clearance: Option<&str>,
) -> (usize, String) {
    let default = cfg.default_clearance.clone().unwrap_or_else(|| "internal".to_string());
    let claim = cfg.clearance_claim.as_deref().unwrap_or("data_clearance");

    let mut label: Option<String> = None;
    // 1. JWT claim — decoded without verifying the signature, so only when the
    //    operator has opted in (a JWT-validation policy is expected to run first).
    if cfg.trust_unverified_claims.unwrap_or(false) {
        if let Some(auth) = authorization {
            label = jwt_claim(auth, claim);
        }
    }
    // 2. Header fallback.
    if label.is_none() {
        label = header_clearance.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    }
    // 3. Default.
    let label = label.unwrap_or_else(|| default.clone());
    let ord = level_ordinal(levels, &label)
        .or_else(|| level_ordinal(levels, &default))
        .unwrap_or(0);
    (ord, label)
}

// ─── request leg ───────────────────────────────────────────────────────────────

async fn request_filter(request_state: RequestState, cfg: Rc<Config>) -> Flow<Ctx> {
    let mode = Mode::parse(cfg.mode.as_deref().unwrap_or("shadow"));
    let headers = request_state.into_headers_state().await;

    if cfg.strip_client_jev_headers.unwrap_or(true) {
        headers.handler().remove_header(HDR);
    }
    if mode == Mode::Off {
        return Flow::Continue(Ctx::default());
    }

    let lvls = levels(&cfg);
    let clearance_header_name = cfg.clearance_header.as_deref().unwrap_or("x-data-clearance");
    let asset = cfg.asset_type.as_deref().unwrap_or("auto");

    let (ct, path, has_body, authorization, header_clearance) = {
        let h = headers.handler();
        (
            h.header("content-type").unwrap_or_default(),
            h.header(":path").unwrap_or_default(),
            headers.contains_body(),
            h.header("authorization"),
            h.header(clearance_header_name),
        )
    };

    let (clearance_ordinal, clearance_label) =
        resolve_clearance(&cfg, &lvls, authorization.as_deref(), header_clearance.as_deref());
    let route_floor = route_floor_ordinal(cfg.route_floor.as_deref().unwrap_or(&[]), &lvls, &path);

    // Detect MCP JSON-RPC vs REST and (for scope) the request path.
    let mut is_rpc = matches!(asset, "mcp");
    if (asset == "mcp" || asset == "auto") && ct.starts_with("application/json") && has_body {
        let body_state = headers.into_body_state().await;
        if let Some(req) = parse_mcp_request(&body_state.handler().body()) {
            if req.method.is_some() {
                is_rpc = true;
            }
        }
    }

    let in_scope = path_prefix_match(cfg.routes.as_deref().unwrap_or(&[]), &path);
    Flow::Continue(Ctx {
        screen: in_scope,
        is_rpc,
        clearance_ordinal,
        clearance_label,
        route_floor_ordinal: route_floor,
    })
}

// ─── response leg ────────────────────────────────────────────────────────────

/// What we may rewrite on a block.
enum Target {
    /// MCP tools/call result — rewrite to a withheld result preserving the id.
    Mcp { id: Value },
    /// OpenAI-compatible LLM completion — rewrite assistant content to the safe reply.
    Llm { value: Value },
    /// Plain REST/HTTP body — rewrite to an error object.
    Rest,
}

async fn response_filter(
    response_state: ResponseState,
    request_data: RequestData<Ctx>,
    cfg: Rc<Config>,
    client: Rc<HttpClient>,
) {
    let RequestData::Continue(ctx) = request_data else { return };
    if !ctx.screen {
        return;
    }

    let mode = Mode::parse(cfg.mode.as_deref().unwrap_or("shadow"));
    let headers = response_state.into_headers_state().await;
    let status = headers.status_code();
    if !(200..300).contains(&status) || !headers.contains_body() {
        return; // never classify error/bodiless responses
    }
    let ct = headers.handler().header("content-type").unwrap_or_default().to_ascii_lowercase();
    let is_sse = ct.contains("text/event-stream");
    let content_types = cfg
        .content_types
        .clone()
        .unwrap_or_else(|| vec!["application/json".to_string(), "text/".to_string()]);
    let ct_ok = is_sse || content_types.iter().any(|p| ct.starts_with(&p.to_ascii_lowercase()));
    if !ct_ok {
        return; // content-type not in scope — pass through
    }

    let mutating = mode.mutates();

    // Split event-flow: drop content-length now (headers freeze once we read the body).
    headers.handler().remove_header("content-length");
    let body_state = headers.into_body_state().await;
    let orig = body_state.handler().body();

    // SSE streaming: skip by default (classifying a stream needs buffering).
    if is_sse && cfg.streaming_mode.as_deref().unwrap_or("skip") == "skip" {
        let _ = body_state.handler().set_body(&orig);
        return;
    }

    let max_bytes = cfg.max_body_bytes.unwrap_or(1_048_576).max(0) as usize;
    if orig.len() > max_bytes {
        if mutating && cfg.on_oversize.as_deref().unwrap_or("skip") == "block" {
            let bytes = rest_block_bytes(reason_str(Reason::MassExceeds));
            if body_state.handler().set_body(&bytes).is_err() {
                let _ = body_state.handler().set_body(&orig);
            }
        } else {
            let _ = body_state.handler().set_body(&orig);
        }
        return;
    }

    let Ok(text) = std::str::from_utf8(&orig) else {
        let _ = body_state.handler().set_body(&orig);
        return;
    };

    let lvls = levels(&cfg);
    let json_paths = cfg.json_paths.clone().unwrap_or_default();

    // Locate the classifiable text and the rewrite target.
    let (screen_text, target) = if ctx.is_rpc {
        let parsed: Option<Value> = if is_sse { sse_first_json(text) } else { serde_json::from_str(text).ok() };
        match parsed.as_ref().and_then(|m| tool_result_view(m, true)) {
            Some(tr) if !tr.is_error && (tr.has_text || !tr.text.is_empty()) => {
                (tr.text.clone(), Target::Mcp { id: tr.id })
            }
            _ => {
                let _ = body_state.handler().set_body(&orig);
                return;
            }
        }
    } else if let Some(view) = llm_view(text) {
        (view.assistant_text.clone(), Target::Llm { value: view.value })
    } else {
        (rest_text(text, &json_paths), Target::Rest)
    };

    // Sampling gate (deterministic per content).
    let fp = fnv1a_64(screen_text.as_bytes());
    if !sampled_in(fp, cfg.sample_rate.unwrap_or(1.0)) {
        let _ = body_state.handler().set_body(&orig);
        return;
    }
    if cfg.log_state_sample.unwrap_or(false) {
        let sample: String = screen_text.chars().take(200).collect();
        logger::debug!("c1: state_fp={fp:x} sample={sample:?}");
    }

    let bands = bands(&cfg);
    let pd_min = personal_data_min_ordinal(&cfg, &lvls);
    let settings = jev_settings(&cfg);

    // A route floor below the caller's clearance blocks without calling the judge.
    let floor_blocks = ctx
        .route_floor_ordinal
        .map(|floor| ctx.clearance_ordinal < floor)
        .unwrap_or(false);

    let (decision, reason, p_exc, argmax, judge_model, judge_status) = if floor_blocks {
        (Decision::Block, Reason::RouteFloor, 1.0, ctx.route_floor_ordinal.unwrap_or(0), "route_floor".to_string(), "route_floor")
    } else if settings.provider == Provider::Mock && !cfg.allow_mock.unwrap_or(false) {
        let (d, _) = apply_fail(fail_mode(&cfg));
        (d, if d == Decision::Block { Reason::MassExceeds } else { Reason::Within }, if d == Decision::Block { 1.0 } else { 0.0 }, 0, "-".to_string(), "disabled")
    } else {
        let (budgeted, truncated) = budget_state(&screen_text, settings.max_state_tokens);
        match evaluate(&client, &cfg.jev_service, &settings, &lvls, &level_descriptions(&cfg), &budgeted).await {
            Ok(res) => {
                let sig: Signals = res.signals;
                let pe = p_exceeds(&sig.probabilities, ctx.clearance_ordinal);
                let am = argmax_level(&sig.probabilities);
                let (d, r) = decide(&DecideInput {
                    p_exceeds: pe,
                    has_personal_data: sig.has_personal_data,
                    clearance_ordinal: ctx.clearance_ordinal,
                    personal_data_min_ordinal: pd_min,
                    route_floor_ordinal: ctx.route_floor_ordinal,
                    bands: &bands,
                });
                logger::debug!(
                    "c1: clearance={} p_exceeds={pe:.2} personal_data={:.2} argmax={} truncated={truncated} -> {}",
                    ctx.clearance_label, sig.has_personal_data, am, d.as_str()
                );
                (d, r, pe, am, res.model, "ok")
            }
            Err(e) => {
                let (d, _) = apply_fail_err(fail_mode(&cfg), e);
                (d, if d == Decision::Block { Reason::MassExceeds } else { Reason::Within }, if d == Decision::Block { 1.0 } else { 0.0 }, 0, "-".to_string(), "unavailable")
            }
        }
    };

    let argmax_label = lvls.get(argmax).cloned().unwrap_or_default();
    logger::info!(
        "c1: mode={:?} decision={} reason={} p_exceeds={p_exc:.2} clearance={} argmax={} rpc={} model={judge_model} status={judge_status} state_fp={fp:x}",
        mode, decision.as_str(), reason_str(reason), ctx.clearance_label, argmax_label, ctx.is_rpc
    );

    // Shadow/off: never mutate. Enforce: act on Block only (Flag passes through — the
    // x-jev-sensitivity header would need the combined headers+body state; see the
    // module note / WALKTHROUGH.md — so a flag is recorded in the log here).
    let out: Option<Vec<u8>> = if !mutating || decision != Decision::Block {
        None
    } else {
        match target {
            Target::Mcp { id } => Some(mcp_block_bytes(&id, is_sse)),
            Target::Llm { mut value } => {
                let safe = cfg.safe_reply_text.as_deref().unwrap_or("I can't share that information.");
                if replace_assistant_content(&mut value, safe) {
                    Some(llm_bytes(&value, is_sse))
                } else {
                    Some(rest_block_bytes(reason_str(reason)))
                }
            }
            Target::Rest => Some(rest_block_bytes(reason_str(reason))),
        }
    };

    match out {
        Some(bytes) => {
            if body_state.handler().set_body(&bytes).is_err() {
                let _ = body_state.handler().set_body(&orig);
            }
        }
        None => {
            let _ = body_state.handler().set_body(&orig);
        }
    }
}

fn apply_fail(fm: FailMode) -> (Decision, &'static str) {
    match fm {
        FailMode::Open => (Decision::Allow, "unavailable"),
        FailMode::Closed => (Decision::Block, "decision_unavailable"),
    }
}

fn apply_fail_err(fm: FailMode, e: JevError) -> (Decision, &'static str) {
    logger::warn!("c1: judge error {e:?} failMode={fm:?}");
    apply_fail(fm)
}

/// REST/HTTP block body — a machine-readable error object. (HTTP status is left as-is
/// on the response leg; see the module note.)
fn rest_block_bytes(reason: &str) -> Vec<u8> {
    serde_json::json!({
        "error": "insufficient_clearance",
        "policy": POLICY,
        "reason": reason
    })
    .to_string()
    .into_bytes()
}

/// MCP block body — a valid JSON-RPC result with `isError:true`, preserving the id.
fn mcp_block_bytes(id: &Value, is_sse: bool) -> Vec<u8> {
    let json = withhold_result(id, WITHHELD_MSG).to_string();
    if is_sse {
        wrap_sse(&json).into_bytes()
    } else {
        json.into_bytes()
    }
}

/// LLM block body — the (already safe-replaced) completion, rewrapped as SSE if needed.
fn llm_bytes(v: &Value, is_sse: bool) -> Vec<u8> {
    let json = v.to_string();
    if is_sse {
        wrap_sse(&json).into_bytes()
    } else {
        json.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lvls() -> Vec<String> {
        DEFAULT_LEVELS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn level_ordinal_is_case_insensitive() {
        let l = lvls();
        assert_eq!(level_ordinal(&l, "public"), Some(0));
        assert_eq!(level_ordinal(&l, "Restricted"), Some(3));
        assert_eq!(level_ordinal(&l, "  confidential "), Some(2));
        assert_eq!(level_ordinal(&l, "nope"), None);
    }

    #[test]
    fn clearance_resolution_order_jwt_then_header_then_default() {
        // trustUnverifiedClaims off → JWT ignored, header wins.
        let cfg: Config = serde_json::from_value(json!({
            "jevService": "https://example.invalid",
            "trustUnverifiedClaims": false
        }))
        .unwrap();
        let l = lvls();
        // payload {"data_clearance":"restricted"}
        let jwt = "eyJhbGciOiJub25lIn0.eyJkYXRhX2NsZWFyYW5jZSI6InJlc3RyaWN0ZWQifQ.sig";
        let (ord, label) = resolve_clearance(&cfg, &l, Some(jwt), Some("confidential"));
        assert_eq!(label, "confidential");
        assert_eq!(ord, 2);

        // No header, no trust → default internal.
        let (ord2, label2) = resolve_clearance(&cfg, &l, Some(jwt), None);
        assert_eq!(label2, "internal");
        assert_eq!(ord2, 1);

        // trustUnverifiedClaims on → JWT claim wins over header.
        let cfg_trust: Config = serde_json::from_value(json!({
            "jevService": "https://example.invalid",
            "trustUnverifiedClaims": true
        }))
        .unwrap();
        let (ord3, label3) = resolve_clearance(&cfg_trust, &l, Some(jwt), Some("public"));
        assert_eq!(label3, "restricted");
        assert_eq!(ord3, 3);
    }

    #[test]
    fn route_floor_picks_most_restrictive_match() {
        let l = lvls();
        let entries = vec!["/hr=confidential".to_string(), "/hr/medical=restricted".to_string()];
        // /hr/medical/42 matches both — restricted (higher) wins.
        assert_eq!(route_floor_ordinal(&entries, &l, "/hr/medical/42"), Some(3));
        // /hr/roster matches only the confidential floor.
        assert_eq!(route_floor_ordinal(&entries, &l, "/hr/roster"), Some(2));
        // /catalog matches neither.
        assert_eq!(route_floor_ordinal(&entries, &l, "/catalog"), None);
    }

    #[test]
    fn rest_block_body_is_the_documented_shape() {
        let bytes = rest_block_bytes("sensitivity_exceeds_clearance");
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], json!("insufficient_clearance"));
        assert_eq!(v["policy"], json!("sensitivity-clearance-gate"));
    }

    #[test]
    fn mcp_block_body_preserves_id_and_is_error() {
        let bytes = mcp_block_bytes(&json!(9), false);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["id"], json!(9));
        assert_eq!(v["result"]["isError"], json!(true));
        // SSE framing.
        let framed = String::from_utf8(mcp_block_bytes(&json!(1), true)).unwrap();
        assert!(framed.starts_with("event: message\ndata: "));
    }

    #[test]
    fn llm_block_body_is_schema_preserving_safe_reply() {
        let mut v: Value = json!({
            "id": "cmpl-1", "model": "gpt",
            "choices": [{"index":0,"message":{"role":"assistant","content":"SSN 123-45-6789"},"finish_reason":"stop"}]
        });
        assert!(replace_assistant_content(&mut v, "I can't share that information."));
        let bytes = llm_bytes(&v, false);
        let back: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back["choices"][0]["message"]["content"], json!("I can't share that information."));
        assert_eq!(back["choices"][0]["message"]["role"], json!("assistant"));
        assert_eq!(back["id"], json!("cmpl-1"));
    }

    #[test]
    fn fail_open_allows_fail_closed_blocks() {
        assert_eq!(apply_fail(FailMode::Open).0, Decision::Allow);
        assert_eq!(apply_fail(FailMode::Closed).0, Decision::Block);
    }
}

// ─── launch ─────────────────────────────────────────────────────────────────

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration, client: HttpClient) -> anyhow::Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow::anyhow!("Failed to parse configuration '{}'. Cause: {}", String::from_utf8_lossy(&bytes), err)
    })?;
    let config = Rc::new(config);
    let client = Rc::new(client);

    let cfg_req = config.clone();
    let filter = on_request(move |rs| {
        let c = cfg_req.clone();
        async move { request_filter(rs, c).await }
    })
    .on_response(move |rs, rd| {
        let c = config.clone();
        let cl = client.clone();
        async move { response_filter(rs, rd, c, cl).await }
    });
    launcher.launch(filter).await?;
    Ok(())
}
