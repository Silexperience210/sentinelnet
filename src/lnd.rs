use crate::config::LndConfig;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{
    Certificate, Client, ClientBuilder,
};
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{debug, info};

/// LND REST API client
pub struct LndClient {
    client: Client,
    base_url: String,
    macaroon_hex: String,
}

// ─── Request/Response types ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct KeysendRequest {
    pub dest: String,       // hex pubkey
    pub amt: String,        // sats (as string for LND API)
    pub payment_hash: String,
    pub dest_custom_records: std::collections::HashMap<String, String>,
    pub timeout_seconds: u32,
    pub fee_limit_sat: String,
}

#[derive(Debug, Deserialize)]
pub struct PaymentResponse {
    pub payment_hash: Option<String>,
    pub payment_error: Option<String>,
    pub payment_preimage: Option<String>,
    pub payment_route: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub identity_pubkey: String,
    pub alias: String,
    pub num_active_channels: u32,
    pub num_peers: u32,
    pub block_height: u32,
    pub synced_to_chain: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChannelsResponse {
    pub channels: Vec<Channel>,
}

#[derive(Debug, Deserialize)]
pub struct Channel {
    pub channel_point: String,
    pub remote_pubkey: String,
    pub capacity: String,
    pub local_balance: String,
    pub remote_balance: String,
    pub active: bool,
}

// ─── Client implementation ───────────────────────────────────────────────────

impl LndClient {
    pub fn new(config: &LndConfig) -> Result<Self> {
        // Load TLS cert (LND uses self-signed)
        let cert_path = shellexpand::tilde(&config.tls_cert_path).to_string();
        let cert_pem = fs::read(&cert_path)
            .with_context(|| format!("Cannot read LND TLS cert: {cert_path}"))?;
        let cert = Certificate::from_pem(&cert_pem)
            .context("Failed to parse LND TLS certificate")?;

        let client = ClientBuilder::new()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true) // self-signed
            .build()
            .context("Failed to build HTTP client")?;

        Ok(LndClient {
            client,
            base_url: config.rest_url.clone(),
            macaroon_hex: config.macaroon_hex.clone(),
        })
    }

    /// Get node info
    pub async fn get_info(&self) -> Result<NodeInfo> {
        let url = format!("{}/v1/getinfo", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .send()
            .await?
            .json::<NodeInfo>()
            .await?;
        Ok(resp)
    }

    /// Get all channels
    pub async fn list_channels(&self) -> Result<Vec<Channel>> {
        let url = format!("{}/v1/channels", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .send()
            .await?
            .json::<ChannelsResponse>()
            .await?;
        Ok(resp.channels)
    }

    /// Send a keysend payment (spontaneous payment — bounty for defense)
    ///
    /// Keysend uses dest_custom_records with key 5482373484 containing the preimage.
    /// The payment_hash = SHA256(preimage).
    pub async fn send_keysend(
        &self,
        dest_pubkey: &str,
        amount_sats: u64,
        message: &str,
    ) -> Result<String> {
        // Generate random preimage
        let preimage = generate_random_preimage();
        let payment_hash = sha256_hex(&preimage);

        // Custom records:
        // 5482373484 = keysend preimage key
        // 34349334   = message key (text)
        let mut custom_records = std::collections::HashMap::new();
        custom_records.insert(
            "5482373484".to_string(),
            BASE64.encode(&preimage),
        );
        custom_records.insert(
            "34349334".to_string(),
            BASE64.encode(message.as_bytes()),
        );

        let request = KeysendRequest {
            dest: dest_pubkey.to_string(),
            amt: amount_sats.to_string(),
            payment_hash,
            dest_custom_records: custom_records,
            timeout_seconds: 60,
            fee_limit_sat: "1000".to_string(), // max 1000 sats routing fee
        };

        let url = format!("{}/v1/channels/transactions", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Grpc-Metadata-macaroon", &self.macaroon_hex)
            .json(&request)
            .send()
            .await
            .context("Failed to send keysend request")?
            .json::<PaymentResponse>()
            .await
            .context("Failed to parse keysend response")?;

        if let Some(err) = &resp.payment_error {
            if !err.is_empty() {
                anyhow::bail!("Keysend payment failed: {err}");
            }
        }

        let payment_hash_result = resp
            .payment_hash
            .unwrap_or_else(|| "unknown".to_string());

        info!(
            "💸 Keysend bounty sent! {} sats → {dest_pubkey} | hash: {payment_hash_result}",
            amount_sats
        );

        Ok(payment_hash_result)
    }

    /// Check if LND is reachable
    pub async fn health_check(&self) -> bool {
        self.get_info().await.is_ok()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn generate_random_preimage() -> Vec<u8> {
    use rand::RngCore;
    let mut preimage = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    preimage
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
