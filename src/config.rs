use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub sentinel: SentinelConfig,
    pub bitcoin:  BitcoinConfig,
    pub lnd:      LndConfig,
    pub gossip:   GossipConfig,
    pub defense:  DefenseConfig,
    pub storage:  StorageConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SentinelConfig {
    pub name:            String,
    pub data_dir:        String,
    pub api_port:        u16,
    pub advertised_addr: String,
    pub api_key:         String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BitcoinConfig {
    pub rpc_url:            String,
    pub rpc_user:           String,
    pub rpc_password:       String,
    pub poll_interval_secs: u64,
    pub cltv_safe_margin:   u32,
    /// Blocks to wait before CPFP fee-bumping a stuck defense tx
    pub fee_bump_after_blocks: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LndConfig {
    pub rest_url:      String,
    pub tls_cert_path: String,
    pub macaroon_hex:  String,
    pub node_pubkey:   String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GossipConfig {
    pub port:                    u16,
    pub peers:                   Vec<String>,
    pub broadcast_interval_secs: u64,
    pub shared_secret:           String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefenseConfig {
    pub fee_multiplier:                 f64,
    pub min_bounty_sats:                u64,
    pub max_bounty_sats:                u64,
    pub availability_fee_sats_per_hour: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Encrypt DB values at rest (AES-256-GCM). Uses api_key as seed.
    pub encrypt_db:          bool,
    /// Backup interval in seconds (0 = disabled)
    pub backup_interval_secs: u64,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let s = fs::read_to_string(path)
            .with_context(|| format!("Cannot read {path}"))?;
        toml::from_str(&s).context("Failed to parse config")
    }

    /// Returns the encryption secret if enabled
    pub fn encryption_secret(&self) -> Option<String> {
        if self.storage.encrypt_db && !self.sentinel.api_key.is_empty() {
            Some(self.sentinel.api_key.clone())
        } else {
            None
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sentinel: SentinelConfig {
                name: "SentinelNet-Node-1".into(),
                data_dir: "./sentinel_data".into(),
                api_port: 9000,
                advertised_addr: "YOUR_IP:9001".into(),
                api_key: "CHANGE_ME_openssl_rand_hex_32".into(),
            },
            bitcoin: BitcoinConfig {
                rpc_url: "http://127.0.0.1:8332".into(),
                rpc_user: "bitcoinrpc".into(),
                rpc_password: "changeme".into(),
                poll_interval_secs: 5,
                cltv_safe_margin: 144,
                fee_bump_after_blocks: 6,
            },
            lnd: LndConfig {
                rest_url: "https://localhost:8080".into(),
                tls_cert_path: "~/.lnd/tls.cert".into(),
                macaroon_hex: String::new(),
                node_pubkey: String::new(),
            },
            gossip: GossipConfig {
                port: 9001,
                peers: vec![],
                broadcast_interval_secs: 30,
                shared_secret: "CHANGE_ME_openssl_rand_hex_32".into(),
            },
            defense: DefenseConfig {
                fee_multiplier: 1.5,
                min_bounty_sats: 500,
                max_bounty_sats: 50_000,
                availability_fee_sats_per_hour: 2,
            },
            storage: StorageConfig {
                encrypt_db: false,
                backup_interval_secs: 3600,
            },
        }
    }
}
