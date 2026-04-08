/// sentinel-client
///
/// Runs on the PROTECTED node side.
/// 1. Connects to local LND (REST)
/// 2. Scans active channels for pending HTLCs
/// 3. Pre-signs claim transactions at N fee tiers
/// 4. Registers them with one or more SentinelNet nodes
/// 5. Runs in watch-loop, re-registering on channel updates

mod htlc_builder;
mod lnd;
mod register;
mod signer;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "sentinel-client",
    about = "SentinelNet Client — registers your HTLCs with sentinel nodes",
    version = "0.1.0"
)]
struct Cli {
    #[arg(short, long, default_value = "client.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the registration daemon (watches for new HTLCs continuously)
    Watch,
    /// One-shot: register all current HTLCs then exit
    Register,
    /// Generate default client config
    Init {
        #[arg(short, long, default_value = "client.toml")]
        output: String,
    },
    /// Show registration status
    Status,
}

// ─── Config ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub lnd: LndConfig,
    pub sentinels: Vec<SentinelEndpoint>,
    pub fees: FeeConfig,
    pub watch: WatchConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LndConfig {
    pub rest_url: String,
    pub tls_cert_path: String,
    pub macaroon_hex: String,
    /// This node's pubkey (for keysend bounty receipt)
    pub node_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEndpoint {
    pub name: String,
    pub url: String, // e.g. http://192.168.1.10:9000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Base fee rate for claim tx (sat/vbyte)
    pub base_fee_rate: f64,
    /// Fee tiers as multipliers of base (e.g. [1.0, 2.0, 5.0, 10.0])
    pub fee_tiers: Vec<f64>,
    /// CLTV safety margin: how many blocks before expiry to pre-sign
    pub cltv_margin: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    /// How often to scan for new HTLCs (seconds)
    pub scan_interval_secs: u64,
    /// Re-register HTLCs this many blocks before CLTV expiry
    pub reregister_margin: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            lnd: LndConfig {
                rest_url: "https://localhost:8080".to_string(),
                tls_cert_path: "~/.lnd/tls.cert".to_string(),
                macaroon_hex: String::new(),
                node_pubkey: String::new(),
            },
            sentinels: vec![
                SentinelEndpoint {
                    name: "primary".to_string(),
                    url: "http://127.0.0.1:9000".to_string(),
                },
            ],
            fees: FeeConfig {
                base_fee_rate: 10.0,
                fee_tiers: vec![1.0, 2.0, 5.0, 10.0],
                cltv_margin: 288, // 2 days
            },
            watch: WatchConfig {
                scan_interval_secs: 30,
                reregister_margin: 50,
            },
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinel_client=info,warn"));
    fmt().with_env_filter(filter).with_target(false).compact().init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Watch) {
        Commands::Init { output } => {
            let cfg = ClientConfig::default();
            let toml_str = toml::to_string_pretty(&cfg)?;
            fs::write(&output, &toml_str)?;
            println!("✅ Default client config written to {output}");
            return Ok(());
        }
        Commands::Status => {
            println!("Use: curl http://localhost:9000/htlcs");
            return Ok(());
        }
        Commands::Register => {
            let cfg = load_config(&cli.config)?;
            let lnd = lnd::LndRestClient::new(&cfg.lnd)?;
            run_once(&cfg, &lnd).await?;
        }
        Commands::Watch => {
            let cfg = load_config(&cli.config)?;
            let lnd = lnd::LndRestClient::new(&cfg.lnd)?;
            run_watch_loop(&cfg, &lnd).await?;
        }
    }

    Ok(())
}

fn load_config(path: &str) -> Result<ClientConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Cannot read client config: {path}"))?;
    toml::from_str(&contents).context("Failed to parse client config")
}

/// One-shot: scan + register all HTLCs
async fn run_once(cfg: &ClientConfig, lnd: &lnd::LndRestClient) -> Result<()> {
    info!("Scanning LND for pending HTLCs...");
    let htlcs = scan_and_register(cfg, lnd).await?;
    info!("Registered {} HTLCs with {} sentinels", htlcs, cfg.sentinels.len());
    Ok(())
}

/// Continuous watch loop
async fn run_watch_loop(cfg: &ClientConfig, lnd: &lnd::LndRestClient) -> Result<()> {
    info!("SentinelNet Client — watch loop started");
    info!("Scanning every {}s across {} sentinels",
        cfg.watch.scan_interval_secs, cfg.sentinels.len());

    let mut ticker = interval(Duration::from_secs(cfg.watch.scan_interval_secs));

    loop {
        ticker.tick().await;
        match scan_and_register(cfg, lnd).await {
            Ok(count) => {
                if count > 0 {
                    info!("Registered/refreshed {count} HTLCs");
                }
            }
            Err(e) => error!("Scan error: {e}"),
        }
    }
}

/// Core logic: scan LND, build claim txs, register with sentinels
async fn scan_and_register(cfg: &ClientConfig, lnd: &lnd::LndRestClient) -> Result<usize> {
    // 1. Get all channels with pending HTLCs
    let channels = lnd.list_channels_with_htlcs().await?;
    let mut registered = 0;

    for channel in &channels {
        for htlc in &channel.pending_htlcs {
            // Only care about incoming HTLCs (we are the potential victim)
            if !htlc.incoming {
                continue;
            }

            // Build pre-signed claim transactions at each fee tier
            let claim_txs = match htlc_builder::build_claim_txs(
                &channel.channel_point,
                htlc,
                &cfg.fees,
                lnd,
            ).await {
                Ok(txs) => txs,
                Err(e) => {
                    warn!("Failed to build claim txs for HTLC {}: {e}", htlc.hash_lock);
                    continue;
                }
            };

            // Register with all configured sentinels
            let payload = register::RegistrationPayload {
                txid: htlc.outpoint_txid.clone(),
                vout: htlc.outpoint_index,
                claim_txs,
                protected_node_pubkey: cfg.lnd.node_pubkey.clone(),
                cltv_expiry: htlc.expiration_height,
                amount_sats: htlc.amount_msat / 1000,
            };

            for sentinel in &cfg.sentinels {
                match register::register_htlc(&sentinel.url, &payload).await {
                    Ok(_) => {
                        info!("✅ HTLC {} registered with sentinel [{}]",
                            &htlc.hash_lock[..16], sentinel.name);
                        registered += 1;
                    }
                    Err(e) => {
                        warn!("Failed to register with sentinel [{}]: {e}", sentinel.name);
                    }
                }
            }
        }
    }

    Ok(registered)
}
