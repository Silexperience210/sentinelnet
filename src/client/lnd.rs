use super::ClientConfig;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{Certificate, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::fs;

// ─── LND REST response types ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChannelsResponse {
    pub channels: Option<Vec<LndChannel>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LndChannel {
    pub channel_point: String,
    pub remote_pubkey: String,
    pub capacity: String,
    pub local_balance: String,
    pub remote_balance: String,
    pub active: bool,
    pub pending_htlcs: Option<Vec<LndHtlc>>,
    pub commit_fee: Option<String>,
    pub chan_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LndHtlc {
    pub incoming: bool,
    pub amount: String,    // sats
    pub hash_lock: String, // hex
    pub expiration_height: u32,
}

/// Processed channel with HTLCs — enriched with outpoint info
#[derive(Debug, Clone)]
pub struct ChannelWithHtlcs {
    pub channel_point: String,
    pub chan_id: String,
    pub remote_pubkey: String,
    pub pending_htlcs: Vec<PendingHtlc>,
}

#[derive(Debug, Clone)]
pub struct PendingHtlc {
    pub incoming: bool,
    pub amount_msat: u64,
    pub hash_lock: String,
    pub expiration_height: u32,
    pub outpoint_txid: String,
    pub outpoint_index: u32,
}

#[derive(Debug, Deserialize)]
pub struct SignResponse {
    pub raw_sig: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub identity_pubkey: String,
    pub alias: String,
    pub block_height: u32,
    pub synced_to_chain: bool,
}

#[derive(Debug, Deserialize)]
pub struct FeeEstimateResponse {
    pub feerate: Option<FeeRate>,
    pub min_relay_feerate: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct FeeRate {
    pub sat_per_vbyte: Option<String>,
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub struct LndRestClient {
    client: reqwest::Client,
    base_url: String,
    macaroon_hex: String,
}

impl LndRestClient {
    pub fn new(config: &super::LndConfig) -> Result<Self> {
        let cert_path = shellexpand::tilde(&config.tls_cert_path).to_string();
        let cert_pem = fs::read(&cert_path)
            .with_context(|| format!("Cannot read LND TLS cert: {cert_path}"))?;
        let cert = Certificate::from_pem(&cert_pem)?;

        let client = ClientBuilder::new()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(LndRestClient {
            client,
            base_url: config.rest_url.clone(),
            macaroon_hex: config.macaroon_hex.clone(),
        })
    }

    fn mac_header(&self) -> (&'static str, String) {
        ("Grpc-Metadata-macaroon", self.macaroon_hex.clone())
    }

    pub async fn get_info(&self) -> Result<NodeInfo> {
        let (hk, hv) = self.mac_header();
        Ok(self.client
            .get(format!("{}/v1/getinfo", self.base_url))
            .header(hk, hv)
            .send().await?
            .json::<NodeInfo>().await?)
    }

    /// List all active channels, filtering those with pending HTLCs
    pub async fn list_channels_with_htlcs(&self) -> Result<Vec<ChannelWithHtlcs>> {
        let (hk, hv) = self.mac_header();
        let resp: ChannelsResponse = self.client
            .get(format!("{}/v1/channels", self.base_url))
            .header(hk, hv)
            .send().await?
            .json().await?;

        let channels = resp.channels.unwrap_or_default();
        let mut result = Vec::new();

        for ch in channels {
            let htlcs = ch.pending_htlcs.unwrap_or_default();
            if htlcs.is_empty() {
                continue;
            }

            // Parse channel_point into txid:vout
            let (cp_txid, cp_vout) = parse_channel_point(&ch.channel_point)?;

            let pending: Vec<PendingHtlc> = htlcs.iter().map(|h| {
                let amount_sats: u64 = h.amount.parse().unwrap_or(0);
                PendingHtlc {
                    incoming: h.incoming,
                    amount_msat: amount_sats * 1000,
                    hash_lock: h.hash_lock.clone(),
                    expiration_height: h.expiration_height,
                    // HTLC outpoint = funding txid : vout (simplified for proto)
                    outpoint_txid: cp_txid.clone(),
                    outpoint_index: cp_vout,
                }
            }).collect();

            result.push(ChannelWithHtlcs {
                channel_point: ch.channel_point,
                chan_id: ch.chan_id.unwrap_or_default(),
                remote_pubkey: ch.remote_pubkey,
                pending_htlcs: pending,
            });
        }

        Ok(result)
    }

    /// Estimate current fee rate (sat/vbyte) for a given confirmation target
    pub async fn estimate_fee_rate(&self, conf_target: u32) -> Result<f64> {
        let (hk, hv) = self.mac_header();
        let resp: FeeEstimateResponse = self.client
            .get(format!(
                "{}/v1/transactions/fee?target_conf={conf_target}&amount=100000",
                self.base_url
            ))
            .header(hk, hv)
            .send().await?
            .json().await
            .unwrap_or(FeeEstimateResponse { feerate: None, min_relay_feerate: None });

        if let Some(fr) = resp.feerate {
            if let Some(spv) = fr.sat_per_vbyte {
                if let Ok(rate) = spv.parse::<f64>() {
                    return Ok(rate);
                }
            }
        }
        Ok(10.0) // safe fallback
    }

    /// Sign a raw transaction using LND's wallet
    pub async fn sign_raw_tx(&self, raw_tx_hex: &str) -> Result<String> {
        let (hk, hv) = self.mac_header();
        let body = serde_json::json!({ "raw_tx_bytes": BASE64.encode(hex::decode(raw_tx_hex)?) });
        let resp: serde_json::Value = self.client
            .post(format!("{}/v2/wallet/tx/sign", self.base_url))
            .header(hk, hv)
            .json(&body)
            .send().await?
            .json().await?;

        resp["signed_transaction"].as_str()
            .map(|s| s.to_string())
            .context("No signed_transaction in response")
    }
}

fn parse_channel_point(cp: &str) -> Result<(String, u32)> {
    let parts: Vec<&str> = cp.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid channel_point format: {cp}");
    }
    let vout: u32 = parts[1].parse().context("Invalid vout")?;
    Ok((parts[0].to_string(), vout))
}
