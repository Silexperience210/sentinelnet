use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub sentinel: SentinelConfig,
    pub bitcoin: BitcoinConfig,
    pub lnd: LndConfig,
    pub gossip: GossipConfig,
    pub defense: DefenseConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SentinelConfig {
    pub name: String,
    pub data_dir: String,
    pub api_port: u16,
    pub advertised_addr: String,
    /// API key for protected endpoints (POST /register, GET /htlcs)
    /// Leave empty to disable auth (dev only!)
    pub api_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitcoinConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub poll_interval_secs: u64,
    pub cltv_safe_margin: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LndConfig {
    pub rest_url: String,
    pub tls_cert_path: String,
    pub macaroon_hex: String,
    pub node_pubkey: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GossipConfig {
    pub port: u16,
    pub peers: Vec<String>,
    pub broadcast_interval_secs: u64,
    /// Shared HMAC secret — all sentinels in a mesh must use the same value
    /// Generate with: openssl rand -hex 32
    pub shared_secret: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefenseConfig {
    pub fee_multiplier: f64,
    pub min_bounty_sats: u64,
    pub max_bounty_sats: u64,
    pub availability_fee_sats_per_hour: u64,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Cannot read config: {path}"))?;
        toml::from_str(&contents).context("Failed to parse config TOML")
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sentinel: SentinelConfig {
                name: "SentinelNet-Node-1".to_string(),
                data_dir: "./sentinel_data".to_string(),
                api_port: 9000,
                advertised_addr: "YOUR_IP:9001".to_string(),
                api_key: "CHANGE_ME_generate_with_openssl_rand_hex_32".to_string(),
            },
            bitcoin: BitcoinConfig {
                rpc_url: "http://127.0.0.1:8332".to_string(),
                rpc_user: "bitcoinrpc".to_string(),
                rpc_password: "changeme".to_string(),
                poll_interval_secs: 5,
                cltv_safe_margin: 144,
            },
            lnd: LndConfig {
                rest_url: "https://localhost:8080".to_string(),
                tls_cert_path: "~/.lnd/tls.cert".to_string(),
                macaroon_hex: String::new(),
                node_pubkey: String::new(),
            },
            gossip: GossipConfig {
                port: 9001,
                peers: vec![],
                broadcast_interval_secs: 30,
                shared_secret: "CHANGE_ME_generate_with_openssl_rand_hex_32".to_string(),
            },
            defense: DefenseConfig {
                fee_multiplier: 1.5,
                min_bounty_sats: 500,
                max_bounty_sats: 50_000,
                availability_fee_sats_per_hour: 2,
            },
        }
    }
}
