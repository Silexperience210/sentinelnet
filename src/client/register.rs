use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Serialize)]
pub struct RegistrationPayload {
    pub txid: String,
    pub vout: u32,
    pub claim_txs: Vec<String>,
    pub protected_node_pubkey: String,
    pub cltv_expiry: u32,
    pub amount_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    pub success: bool,
    pub txid: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

/// Register an HTLC with a sentinel node
pub async fn register_htlc(
    sentinel_url: &str,
    payload: &RegistrationPayload,
) -> Result<RegistrationResponse> {
    let url = format!("{sentinel_url}/register");
    debug!("POST {url} | txid: {}", &payload.txid[..16.min(payload.txid.len())]);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(payload)
        .send()
        .await
        .with_context(|| format!("Failed to connect to sentinel at {url}"))?;

    let status = resp.status();
    let body: RegistrationResponse = resp.json().await
        .with_context(|| "Failed to parse sentinel response")?;

    if !status.is_success() {
        anyhow::bail!(
            "Sentinel returned {}: {}",
            status,
            body.error.unwrap_or_default()
        );
    }

    Ok(body)
}

/// Check if a sentinel is reachable and get its status
pub async fn check_sentinel_status(sentinel_url: &str) -> Result<serde_json::Value> {
    let url = format!("{sentinel_url}/status");
    let resp = reqwest::get(&url).await?
        .json::<serde_json::Value>().await?;
    Ok(resp)
}
