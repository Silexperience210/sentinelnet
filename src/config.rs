use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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
    /// Human-readable name for this sentinel node
    pub name: String,
    /// Data directory for the sled database
    pub data_dir: String,
    /// REST API port for registering HTLCs
    pub api_port: u16,
    /// This sentinel's advertised address (for gossip discovery)
    pub advertised_addr: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitcoinConfig {
    /// Bitcoin Core / Knots RPC URL
    pub rpc_url: String,
    /// RPC username
    pub rpc_user: String,
    /// RPC password
    pub rpc_password: String,
    /// How often to poll the mempool (seconds)
    pub poll_interval_secs: u64,
    /// Number of blocks before CLTV expiry to trigger defense
    pub cltv_safe_margin: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LndConfig {
    /// LND REST API base URL (e.g. https://localhost:8080)
    pub rest_url: String,
    /// Path to LND's TLS certificate
    pub tls_cert_path: String,
    /// LND macaroon (hex-encoded) — invoices macaroon is sufficient for keysend
    pub macaroon_hex: String,
    /// This sentinel's LND node pubkey (for gossip announcements)
    pub node_pubkey: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GossipConfig {
    /// TCP port for gossip mesh
    pub port: u16,
    /// Known peer addresses (host:port)
    pub peers: Vec<String>,
    /// Gossip broadcast interval (seconds)
    pub broadcast_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefenseConfig {
    /// Fee rate multiplier when fee-bumping (vs current mempool median)
    pub fee_multiplier: f64,
    /// Minimum bounty to pay for a successful defense (sats)
    pub min_bounty_sats: u64,
    /// Maximum bounty (sats) — caps the performance multiplier
    pub max_bounty_sats: u64,
    /// Availability fee per watched HTLC per hour (sats)
    pub availability_fee_sats_per_hour: u64,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Cannot read config file: {path}"))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| "Failed to parse config TOML")?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sentinel: SentinelConfig {
                name: "SentinelNet-Node-1".to_string(),
                data_dir: "./sentinel_data".to_string(),
                api_port: 9000,
                advertised_addr: "127.0.0.1:9001".to_string(),
            },
            bitcoin: BitcoinConfig {
                rpc_url: "http://127.0.0.1:8332".to_string(),
                rpc_user: "bitcoinrpc".to_string(),
                rpc_password: "changeme".to_string(),
                poll_interval_secs: 5,
                cltv_safe_margin: 144, // ~1 day
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
