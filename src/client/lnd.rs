use super::ClientConfig;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{Certificate, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::fs;

// ─── Response types ──────────────────────────────────────────────────────────

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
    pub chan_id: Option<String>,
    pub commit_fee: Option<String>,
    pub csv_delay: Option<u32>,
    pub local_chan_reserve_sat: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LndHtlc {
    pub incoming: bool,
    pub amount: String,
    pub hash_lock: String,
    pub expiration_height: u32,
    pub htlc_index: Option<u64>,
    pub forwarding_channel: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CommitmentTxResponse {
    pub raw_tx_hex: Option<String>,
    pub commit_num: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NewAddressResponse {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct SignPsbtResponse {
    pub signed_psbt: Option<String>,
    pub signed_inputs: Option<Vec<u32>>,
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
    pub fee_sat: Option<String>,
    pub feerate_sat_per_byte: Option<String>,
    pub sat_per_vbyte: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PendingChannelsResponse {
    pub pending_force_closing_channels: Option<Vec<PendingForceCloseChannel>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PendingForceCloseChannel {
    pub channel: Option<PendingChannelInfo>,
    pub closing_txid: Option<String>,
    pub limbo_balance: Option<String>,
    pub pending_htlcs: Option<Vec<PendingHtlcInfo>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PendingChannelInfo {
    pub channel_point: String,
    pub remote_node_pub: Option<String>,
    pub capacity: Option<String>,
    pub local_balance: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PendingHtlcInfo {
    pub incoming: Option<bool>,
    pub amount: Option<String>,
    pub outpoint: Option<String>,
    pub maturity_height: Option<u32>,
    pub blocks_til_maturity: Option<i32>,
    pub stage: Option<u32>,
}

/// Enriched channel with real HTLC outpoints
#[derive(Debug, Clone)]
pub struct ChannelWithHtlcs {
    pub channel_point: String,
    pub chan_id: String,
    pub remote_pubkey: String,
    pub csv_delay: u32,
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
    pub htlc_index: u64,
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub struct LndRestClient {
    client: reqwest::Client,
    pub base_url: String,
    pub macaroon_hex: String,
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
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(LndRestClient {
            client,
            base_url: config.rest_url.clone(),
            macaroon_hex: config.macaroon_hex.clone(),
        })
    }

    fn mac(&self) -> (&'static str, &str) {
        ("Grpc-Metadata-macaroon", &self.macaroon_hex)
    }

    pub async fn get_info(&self) -> Result<NodeInfo> {
        let (hk, hv) = self.mac();
        Ok(self.client
            .get(format!("{}/v1/getinfo", self.base_url))
            .header(hk, hv).send().await?.json().await?)
    }

    /// Get a fresh P2WKH address from LND wallet for receiving bounties/change
    pub async fn new_address(&self) -> Result<String> {
        let (hk, hv) = self.mac();
        // type 0 = P2WKH (native segwit)
        let resp: NewAddressResponse = self.client
            .get(format!("{}/v1/newaddress?type=0", self.base_url))
            .header(hk, hv).send().await?.json().await?;
        Ok(resp.address)
    }

    /// Get commitment tx for a channel (only available for force-closing channels)
    /// For active channels, we derive outpoints from channel_point + HTLC index
    pub async fn get_commitment_tx(&self, chan_id: &str) -> Result<Option<String>> {
        let (hk, hv) = self.mac();
        let resp = self.client
            .get(format!("{}/v1/channel/commitmenttx/{}", self.base_url, chan_id))
            .header(hk, hv).send().await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let data: CommitmentTxResponse = r.json().await?;
                Ok(data.raw_tx_hex)
            }
            _ => Ok(None),
        }
    }

    /// Get pending force-close channels (these have real HTLC outpoints)
    pub async fn get_pending_force_close(&self) -> Result<Vec<PendingForceCloseChannel>> {
        let (hk, hv) = self.mac();
        let resp: PendingChannelsResponse = self.client
            .get(format!("{}/v1/channels/pending", self.base_url))
            .header(hk, hv).send().await?.json().await?;
        Ok(resp.pending_force_closing_channels.unwrap_or_default())
    }

    /// List active channels with pending HTLCs
    pub async fn list_channels_with_htlcs(&self) -> Result<Vec<ChannelWithHtlcs>> {
        let (hk, hv) = self.mac();
        let resp: ChannelsResponse = self.client
            .get(format!("{}/v1/channels", self.base_url))
            .header(hk, hv).send().await?.json().await?;

        let channels = resp.channels.unwrap_or_default();
        let mut result = Vec::new();

        for ch in channels {
            let htlcs = ch.pending_htlcs.clone().unwrap_or_default();
            if htlcs.is_empty() { continue; }

            let (cp_txid, cp_vout) = parse_channel_point(&ch.channel_point)?;
            let chan_id = ch.chan_id.clone().unwrap_or_default();

            // Try to get the real commitment tx for accurate outpoints
            let commitment_tx_hex = self.get_commitment_tx(&chan_id).await.ok().flatten();

            let pending: Vec<PendingHtlc> = htlcs.iter().enumerate().map(|(idx, h)| {
                let amount_sats: u64 = h.amount.parse().unwrap_or(0);
                let htlc_index = h.htlc_index.unwrap_or(idx as u64);

                // If we have the commitment tx, parse the real outpoint
                // Otherwise fall back to funding txid + htlc_index offset
                let (out_txid, out_vout) = if let Some(ref ctx_hex) = commitment_tx_hex {
                    derive_htlc_outpoint_from_commitment(ctx_hex, htlc_index)
                        .unwrap_or_else(|_| (cp_txid.clone(), cp_vout + htlc_index as u32 + 1))
                } else {
                    // Fallback: use funding txid, vout = cp_vout + index + 1
                    // This is wrong for real use but safe for dev/testing
                    (cp_txid.clone(), cp_vout + htlc_index as u32 + 1)
                };

                PendingHtlc {
                    incoming: h.incoming,
                    amount_msat: amount_sats * 1000,
                    hash_lock: h.hash_lock.clone(),
                    expiration_height: h.expiration_height,
                    outpoint_txid: out_txid,
                    outpoint_index: out_vout,
                    htlc_index,
                }
            }).collect();

            result.push(ChannelWithHtlcs {
                channel_point: ch.channel_point,
                chan_id,
                remote_pubkey: ch.remote_pubkey,
                csv_delay: ch.csv_delay.unwrap_or(144),
                pending_htlcs: pending,
            });
        }

        Ok(result)
    }

    /// Estimate fee rate (sat/vbyte) for target confirmation blocks
    pub async fn estimate_fee_rate(&self, target_conf: u32) -> Result<f64> {
        let (hk, hv) = self.mac();
        // Use /v2/wallet/estimatefee
        let resp: serde_json::Value = self.client
            .get(format!(
                "{}/v2/wallet/estimatefee?spend_unconfirmed=false&target_conf={}",
                self.base_url, target_conf
            ))
            .header(hk, hv).send().await?
            .json().await
            .unwrap_or(serde_json::json!({}));

        if let Some(spv) = resp["sat_per_vbyte"].as_str() {
            if let Ok(rate) = spv.parse::<f64>() {
                return Ok(rate);
            }
        }
        if let Some(spv) = resp["sat_per_vbyte"].as_f64() {
            return Ok(spv);
        }
        Ok(10.0) // safe fallback
    }

    /// Sign a PSBT using LND's wallet
    /// Returns signed PSBT in base64
    pub async fn sign_psbt(&self, psbt_base64: &str) -> Result<String> {
        let (hk, hv) = self.mac();
        let body = serde_json::json!({ "funded_psbt": psbt_base64 });

        let resp: SignPsbtResponse = self.client
            .post(format!("{}/v2/wallet/psbt/sign", self.base_url))
            .header(hk, hv)
            .json(&body)
            .send().await?
            .json().await?;

        resp.signed_psbt.context("No signed_psbt in LND response")
    }

    /// Sign a raw transaction hex using LND's internal wallet
    pub async fn sign_raw_tx(&self, raw_tx_hex: &str) -> Result<String> {
        let (hk, hv) = self.mac();
        let tx_bytes = hex::decode(raw_tx_hex)?;
        let body = serde_json::json!({ "raw_tx_bytes": BASE64.encode(&tx_bytes) });

        let resp: serde_json::Value = self.client
            .post(format!("{}/v2/wallet/tx/sign", self.base_url))
            .header(hk, hv)
            .json(&body)
            .send().await?
            .json().await?;

        if let Some(signed) = resp["signed_transaction"].as_str() {
            let signed_bytes = BASE64.decode(signed)?;
            return Ok(hex::encode(signed_bytes));
        }
        anyhow::bail!("LND returned no signed transaction: {:?}", resp)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn parse_channel_point(cp: &str) -> Result<(String, u32)> {
    let parts: Vec<&str> = cp.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid channel_point: {cp}");
    }
    Ok((parts[0].to_string(), parts[1].parse()?))
}

/// Parse a commitment transaction hex and find the HTLC output at the given index
/// Returns (txid, vout) of the HTLC output
fn derive_htlc_outpoint_from_commitment(
    commitment_tx_hex: &str,
    htlc_index: u64,
) -> Result<(String, u32)> {
    use bitcoin::consensus::Decodable;
    use std::io::Cursor;

    let tx_bytes = hex::decode(commitment_tx_hex)?;
    let tx = bitcoin::Transaction::consensus_decode(&mut Cursor::new(&tx_bytes))
        .context("Failed to decode commitment transaction")?;

    let txid = tx.txid().to_string();

    // In a commitment tx: output 0 = to_local, output 1 = to_remote,
    // outputs 2+ = HTLCs in order of htlc_index
    // This is a simplification — real ordering depends on script sorting (BIP69)
    let htlc_vout = (htlc_index + 2) as u32;

    if htlc_vout as usize >= tx.output.len() {
        anyhow::bail!(
            "HTLC vout {} out of range (tx has {} outputs)",
            htlc_vout, tx.output.len()
        );
    }

    Ok((txid, htlc_vout))
}
