use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct RegistrationPayload {
    pub txid:                   String,
    pub vout:                   u32,
    pub claim_txs:              Vec<String>,
    pub protected_node_pubkey:  String,
    pub cltv_expiry:            u32,
    pub amount_sats:            u64,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    pub success: bool,
    pub txid:    Option<String>,
    pub message: Option<String>,
    pub error:   Option<String>,
}

/// Register an HTLC with a sentinel (authenticated)
pub async fn register_htlc(
    url: &str,
    payload: &RegistrationPayload,
    api_key: &str,
) -> Result<RegistrationResponse> {
    let endpoint = format!("{url}/register");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mut req = client.post(&endpoint)
        .header("Content-Type", "application/json");
    if !api_key.is_empty() {
        req = req.header("X-Sentinel-Key", api_key);
    }

    let resp = req.json(payload).send().await
        .with_context(|| format!("Cannot reach sentinel at {url}"))?;

    let status = resp.status();
    let body: RegistrationResponse = resp.json().await
        .context("Failed to parse sentinel response")?;

    if !status.is_success() {
        anyhow::bail!("Sentinel {status}: {}", body.error.unwrap_or_default());
    }
    Ok(body)
}

/// Check sentinel health (no auth required)
pub async fn check_sentinel_status(url: &str) -> Result<serde_json::Value> {
    Ok(reqwest::get(format!("{url}/status")).await?.json().await?)
}
