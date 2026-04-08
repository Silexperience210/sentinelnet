//! LND REST client for sentinel-client.
//!
//! Scope: channel scanning, fee estimation, address generation,
//! HTLC signing via `/v2/signer/computeinputscript`.
//!
//! Note on HTLC key material
//! --------------------------
//! LND does NOT expose per-HTLC keys through any public REST endpoint.
//! `computeinputscript` works when LND can look the key up internally
//! via a KeyLocator (family + index).  For HTLC outputs specifically,
//! LND uses key family 2 (htlcKeyFamily); the key_index is the
//! per-channel commitment index stored internally.
//!
//! For active (non-force-closing) channels the commitment tx is never
//! broadcast, so outpoints are hypothetical until a close happens.
//! `sentinel-client` therefore operates in two modes:
//!
//!  Mode A – Pre-register  : runs alongside LND, signs sample claim txs
//!                            at current channel state (best-effort).
//!  Mode B – React on close: watches `/v1/channels/pending`; once a
//!                            force-close is detected LND exposes real
//!                            outpoints and the client re-registers with
//!                            fully accurate signed txs.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{Certificate, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{debug, warn};

// ─── Config re-export ────────────────────────────────────────────────────────

pub use super::{ClientConfig, LndConfig};

// ─── REST response types ─────────────────────────────────────────────────────

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
    pub csv_delay: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LndHtlc {
    pub incoming: bool,
    /// Amount in sats (LND returns this as a string)
    pub amount: String,
    pub hash_lock: String,
    pub expiration_height: u32,
    pub htlc_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct PendingChannelsResponse {
    pub pending_force_closing_channels: Option<Vec<ForceCloseChannel>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForceCloseChannel {
    pub channel: Option<ForceCloseChannelInfo>,
    pub closing_txid: Option<String>,
    pub pending_htlcs: Option<Vec<ForceCloseHtlc>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForceCloseChannelInfo {
    pub channel_point: String,
    pub remote_node_pub: Option<String>,
    pub local_balance: Option<String>,
}

/// HTLC from a force-closing channel — has REAL outpoints
#[derive(Debug, Deserialize, Clone)]
pub struct ForceCloseHtlc {
    pub incoming: Option<bool>,
    pub amount: Option<String>,
    /// "txid:vout" — the REAL spendable outpoint once commitment tx confirmed
    pub outpoint: Option<String>,
    pub maturity_height: Option<u32>,
    pub blocks_til_maturity: Option<i32>,
    pub stage: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct NewAddressResponse {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub identity_pubkey: String,
    pub alias: String,
    pub block_height: u32,
    pub synced_to_chain: bool,
}

/// Response from `/v2/signer/computeinputscript`
#[derive(Debug, Deserialize)]
pub struct InputScriptResponse {
    pub input_scripts: Option<Vec<InputScript>>,
}

#[derive(Debug, Deserialize)]
pub struct InputScript {
    /// Each witness stack item as base64
    pub witness: Option<Vec<String>>,
    pub sig_script: Option<String>,
}

// ─── Enriched domain types ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ChannelWithHtlcs {
    pub channel_point: String,
    pub chan_id: String,
    pub remote_pubkey: String,
    pub csv_delay: u32,
    pub pending_htlcs: Vec<PendingHtlc>,
    /// `true` = outpoints are from a real force-close commitment tx
    pub outpoints_confirmed: bool,
}

#[derive(Debug, Clone)]
pub struct PendingHtlc {
    pub incoming: bool,
    pub amount_sats: u64,
    pub hash_lock: String,
    pub expiration_height: u32,
    pub outpoint_txid: String,
    pub outpoint_index: u32,
    pub htlc_index: u64,
}

// ─── LND REST client ─────────────────────────────────────────────────────────

pub struct LndRestClient {
    client: reqwest::Client,
    pub base_url: String,
    pub macaroon_hex: String,
}

impl LndRestClient {
    pub fn new(config: &LndConfig) -> Result<Self> {
        let cert_path = shellexpand::tilde(&config.tls_cert_path).to_string();
        let cert_pem = fs::read(&cert_path)
            .with_context(|| format!("Cannot read TLS cert: {cert_path}"))?;
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

    /// Get a fresh P2WPKH address from the LND wallet
    pub async fn new_address(&self) -> Result<String> {
        let (hk, hv) = self.mac();
        let resp: NewAddressResponse = self.client
            .get(format!("{}/v1/newaddress?type=0", self.base_url))
            .header(hk, hv).send().await?.json().await?;
        Ok(resp.address)
    }

    /// Estimate fee rate in sat/vbyte for the given confirmation target
    pub async fn estimate_fee_rate(&self, target_conf: u32) -> Result<f64> {
        let (hk, hv) = self.mac();
        let resp: serde_json::Value = self.client
            .get(format!(
                "{}/v2/wallet/estimatefee?target_conf={target_conf}",
                self.base_url
            ))
            .header(hk, hv).send().await?
            .json().await
            .unwrap_or_default();

        // LND returns sat_per_vbyte as either string or number depending on version
        if let Some(v) = resp["sat_per_vbyte"].as_f64() { return Ok(v); }
        if let Some(s) = resp["sat_per_vbyte"].as_str() {
            if let Ok(v) = s.parse::<f64>() { return Ok(v); }
        }
        Ok(10.0) // safe fallback
    }

    // ─── Active channel HTLCs (Mode A — pre-register) ────────────────────────

    /// List active channels that have pending HTLCs.
    /// Outpoints are derived (best-effort) — not confirmed until force-close.
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

            // Best-effort outpoints: funding txid + htlc_index offset.
            // These are WRONG for real broadcast but serve as registration
            // placeholders until a force-close gives us real outpoints.
            let pending: Vec<PendingHtlc> = htlcs.iter().enumerate().map(|(idx, h)| {
                let amount_sats = h.amount.parse::<u64>().unwrap_or(0);
                let htlc_index = h.htlc_index.unwrap_or(idx as u64);
                PendingHtlc {
                    incoming: h.incoming,
                    amount_sats,
                    hash_lock: h.hash_lock.clone(),
                    expiration_height: h.expiration_height,
                    outpoint_txid: cp_txid.clone(),
                    outpoint_index: cp_vout + htlc_index as u32 + 1, // placeholder
                    htlc_index,
                }
            }).collect();

            result.push(ChannelWithHtlcs {
                channel_point: ch.channel_point,
                chan_id,
                remote_pubkey: ch.remote_pubkey,
                csv_delay: ch.csv_delay.unwrap_or(144),
                pending_htlcs: pending,
                outpoints_confirmed: false,
            });
        }

        Ok(result)
    }

    // ─── Force-closing HTLCs (Mode B — react on close) ───────────────────────

    /// Returns HTLCs from force-closing channels with REAL confirmed outpoints.
    /// This is the high-fidelity path — called after a force-close is detected.
    pub async fn list_force_close_htlcs(&self) -> Result<Vec<ChannelWithHtlcs>> {
        let (hk, hv) = self.mac();
        let resp: PendingChannelsResponse = self.client
            .get(format!("{}/v1/channels/pending", self.base_url))
            .header(hk, hv).send().await?.json().await?;

        let force_close = resp.pending_force_closing_channels.unwrap_or_default();
        let mut result = Vec::new();

        for fc in force_close {
            let htlcs_raw = fc.pending_htlcs.unwrap_or_default();
            if htlcs_raw.is_empty() { continue; }

            let chan_info = fc.channel.unwrap_or_else(|| ForceCloseChannelInfo {
                channel_point: String::new(),
                remote_node_pub: None,
                local_balance: None,
            });

            let mut pending = Vec::new();
            for (idx, h) in htlcs_raw.iter().enumerate() {
                let outpoint_str = match &h.outpoint {
                    Some(op) => op.clone(),
                    None => { warn!("HTLC {idx} has no outpoint — skipping"); continue; }
                };

                let (txid, vout) = parse_channel_point(&outpoint_str)
                    .unwrap_or_else(|_| (String::new(), 0));

                let amount_sats = h.amount.as_deref()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                let expiry = h.maturity_height.unwrap_or(0);

                pending.push(PendingHtlc {
                    incoming: h.incoming.unwrap_or(false),
                    amount_sats,
                    hash_lock: format!("htlc_{idx}"), // LND doesn't expose hash here
                    expiration_height: expiry,
                    outpoint_txid: txid,
                    outpoint_index: vout,
                    htlc_index: idx as u64,
                });
            }

            if !pending.is_empty() {
                result.push(ChannelWithHtlcs {
                    channel_point: chan_info.channel_point.clone(),
                    chan_id: fc.closing_txid.clone().unwrap_or_default(),
                    remote_pubkey: chan_info.remote_node_pub.clone().unwrap_or_default(),
                    csv_delay: 144,
                    pending_htlcs: pending,
                    outpoints_confirmed: true, // real outpoints from confirmed commitment tx
                });
            }
        }

        Ok(result)
    }

    // ─── Signing ─────────────────────────────────────────────────────────────

    /// Sign an input using LND's signer subserver.
    ///
    /// `witness_script` must be the HTLC redeemscript (BOLT#3).
    /// `output_value`   is the value of the UTXO being spent (sats).
    /// `output_script`  is the P2WSH scriptpubkey of the UTXO.
    /// `key_family`     = 2 (htlcKeyFamily) for HTLC inputs.
    /// `key_index`      = per-channel index (0 for prototype; enumerate properly in prod).
    ///
    /// Returns the complete witness stack as a vector of hex strings, or
    /// the unsigned tx hex if LND signing fails (dev/regtest fallback).
    pub async fn compute_input_script(
        &self,
        raw_tx_hex: &str,
        input_index: u32,
        output_value: i64,
        output_script: &[u8],
        witness_script: &[u8],
        key_family: i32,
        key_index: i32,
    ) -> Result<Vec<Vec<u8>>> {
        let (hk, hv) = self.mac();

        let tx_b64 = BASE64.encode(hex::decode(raw_tx_hex)?);
        let ws_b64 = BASE64.encode(witness_script);
        let ps_b64 = BASE64.encode(output_script);

        let body = serde_json::json!({
            "raw_tx_bytes": tx_b64,
            "sign_descs": [{
                "key_desc": {
                    "key_loc": {
                        "key_family": key_family,
                        "key_index":  key_index
                    }
                },
                "witness_script": ws_b64,
                "output": {
                    "value":     output_value,
                    "pk_script": ps_b64
                },
                "sighash": 1,
                "input_index": input_index
            }]
        });

        let resp = self.client
            .post(format!("{}/v2/signer/computeinputscript", self.base_url))
            .header(hk, hv)
            .json(&body)
            .send().await?
            .json::<InputScriptResponse>().await?;

        let script = resp.input_scripts
            .and_then(|v| v.into_iter().next())
            .context("No input_scripts in response")?;

        let witness = script.witness.unwrap_or_default();
        let decoded: Vec<Vec<u8>> = witness.iter()
            .map(|b64| BASE64.decode(b64).unwrap_or_default())
            .collect();

        debug!("ComputeInputScript returned {} witness items", decoded.len());
        Ok(decoded)
    }

    /// Sign a raw transaction for a standard wallet output (P2WPKH/P2TR).
    /// Falls back to unsigned if LND cannot sign (HTLC-specific path).
    pub async fn sign_raw_tx(&self, raw_tx_hex: &str) -> Result<String> {
        let (hk, hv) = self.mac();
        let body = serde_json::json!({
            "raw_tx_bytes": BASE64.encode(hex::decode(raw_tx_hex)?)
        });

        let resp: serde_json::Value = self.client
            .post(format!("{}/v2/wallet/tx/sign", self.base_url))
            .header(hk, hv).json(&body).send().await?
            .json().await?;

        if let Some(signed) = resp["signed_transaction"].as_str() {
            let bytes = BASE64.decode(signed)?;
            return Ok(hex::encode(bytes));
        }
        anyhow::bail!("No signed_transaction in LND response: {resp:?}")
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn parse_channel_point(cp: &str) -> Result<(String, u32)> {
    let mut parts = cp.splitn(2, ':');
    let txid = parts.next().context("Missing txid")?;
    let vout: u32 = parts.next().context("Missing vout")?.parse()?;
    Ok((txid.to_string(), vout))
}
