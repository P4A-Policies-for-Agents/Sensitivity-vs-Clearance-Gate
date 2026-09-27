use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "allowMock")]
    pub allow_mock: Option<bool>,
    #[serde(alias = "assetType")]
    pub asset_type: Option<String>,
    #[serde(alias = "blockAt")]
    pub block_at: Option<f64>,
    #[serde(alias = "clearanceClaim")]
    pub clearance_claim: Option<String>,
    #[serde(alias = "clearanceHeader")]
    pub clearance_header: Option<String>,
    #[serde(alias = "cloudflareAccountId")]
    pub cloudflare_account_id: Option<String>,
    #[serde(alias = "contentTypes")]
    pub content_types: Option<Vec<String>>,
    #[serde(alias = "customAuthHeader")]
    pub custom_auth_header: Option<String>,
    #[serde(alias = "defaultClearance")]
    pub default_clearance: Option<String>,
    #[serde(alias = "failMode")]
    pub fail_mode: Option<String>,
    #[serde(alias = "flagAt")]
    pub flag_at: Option<f64>,
    #[serde(alias = "jevApiKey")]
    pub jev_api_key: Option<String>,
    #[serde(alias = "jevModel")]
    pub jev_model: Option<String>,
    #[serde(alias = "jevPath")]
    pub jev_path: Option<String>,
    #[serde(alias = "jevProvider")]
    pub jev_provider: Option<String>,
    #[serde(alias = "jevService", deserialize_with = "pdk::serde::deserialize_service")]
    pub jev_service: pdk::hl::Service,
    #[serde(alias = "jevTimeoutMs")]
    pub jev_timeout_ms: Option<i64>,
    #[serde(alias = "jsonPaths")]
    pub json_paths: Option<Vec<String>>,
    #[serde(alias = "levelDescriptions")]
    pub level_descriptions: Option<Vec<String>>,
    #[serde(alias = "levels")]
    pub levels: Option<Vec<String>>,
    #[serde(alias = "logStateSample")]
    pub log_state_sample: Option<bool>,
    #[serde(alias = "maxBodyBytes")]
    pub max_body_bytes: Option<i64>,
    #[serde(alias = "maxStateTokens")]
    pub max_state_tokens: Option<i64>,
    #[serde(alias = "minConfidence")]
    pub min_confidence: Option<f64>,
    #[serde(alias = "mode")]
    pub mode: Option<String>,
    #[serde(alias = "onOversize")]
    pub on_oversize: Option<String>,
    #[serde(alias = "personalDataMinClearance")]
    pub personal_data_min_clearance: Option<String>,
    #[serde(alias = "routeFloor")]
    pub route_floor: Option<Vec<String>>,
    #[serde(alias = "routes")]
    pub routes: Option<Vec<String>>,
    #[serde(alias = "safeReplyText")]
    pub safe_reply_text: Option<String>,
    #[serde(alias = "sampleRate")]
    pub sample_rate: Option<f64>,
    #[serde(alias = "streamingMode")]
    pub streaming_mode: Option<String>,
    #[serde(alias = "stripClientJevHeaders")]
    pub strip_client_jev_headers: Option<bool>,
    #[serde(alias = "trustUnverifiedClaims")]
    pub trust_unverified_claims: Option<bool>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    abi.service_create(config.jev_service)?;
    abi.setup()?;
    Ok(())
}
