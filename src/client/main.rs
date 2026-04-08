mod htlc_builder;
mod lnd;
mod register;
mod signer;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

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
    pub node_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEndpoint {
    pub name: String,
    pub url: String,
    /// API key for this sentinel's protected endpoints
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Base fee rate (sat/vbyte) — overridden by LND estimate if available
    pub base_fee_rate: f64,
    /// Fee tier multipliers: [1.0, 2.0, 5.0, 10.0] = 4 pre-signed txs per HTLC
    pub fee_tiers: Vec<f64>,
    pub cltv_margin: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    pub scan_interval_secs: u64,
    /// Blocks before CLTV at which we force-re-register with latest fee tiers
    pub reregister_margin: u32,
    /// Also scan force-closing channels (Mode B — accurate outpoints)
    pub scan_force_closing: bool,
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
            sentinels: vec![SentinelEndpoint {
                name: "primary".to_string(),
                url: "http://127.0.0.1:9000".to_string(),
                api_key: "CHANGE_ME".to_string(),
            }],
            fees: FeeConfig {
                base_fee_rate: 10.0,
                fee_tiers: vec![1.0, 2.0, 5.0, 10.0],
                cltv_margin: 288,
            },
            watch: WatchConfig {
                scan_interval_secs: 30,
                reregister_margin: 50,
                scan_force_closing: true,
            },
        }
    }
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "sentinel-client", about = "SentinelNet Client — registers HTLCs with sentinels", version = "0.1.0")]
struct Cli {
    #[arg(short, long, default_value = "client.toml")]
    config: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Watch continuously — re-registers on channel changes
    Watch,
    /// Register all current HTLCs once and exit
    Register,
    /// Generate default config file
    Init {
        #[arg(short, long, default_value = "client.toml")]
        output: String,
    },
    /// Show sentinel status pages
    Status,
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
            fs::write(&output, toml::to_string_pretty(&ClientConfig::default())?)?;
            println!("✅ Client config written to {output}");
            return Ok(());
        }
        Commands::Status => {
            let cfg = load_config(&cli.config)?;
            for s in &cfg.sentinels {
                match register::check_sentinel_status(&s.url).await {
                    Ok(v) => println!("[{}] {}", s.name, serde_json::to_string_pretty(&v)?),
                    Err(e) => println!("[{}] ❌ {e}", s.name),
                }
            }
            return Ok(());
        }
        Commands::Register => {
            let cfg = load_config(&cli.config)?;
            let lnd = lnd::LndRestClient::new(&cfg.lnd)?;
            let n = scan_and_register(&cfg, &lnd).await?;
            info!("Registered {n} HTLCs");
        }
        Commands::Watch => {
            let cfg = load_config(&cli.config)?;
            let lnd = lnd::LndRestClient::new(&cfg.lnd)?;

            // Verify LND connectivity
            match lnd.get_info().await {
                Ok(info) => info!("LND: {} | block {}", info.alias, info.block_height),
                Err(e) => warn!("LND unreachable: {e}"),
            }

            let cancel = CancellationToken::new();
            let c2 = cancel.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                info!("Shutting down client…");
                c2.cancel();
            });

            run_watch_loop(&cfg, &lnd, cancel).await?;
        }
    }

    Ok(())
}

fn load_config(path: &str) -> Result<ClientConfig> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("Cannot read {path}"))?;
    toml::from_str(&s).context("Failed to parse client config")
}

async fn run_watch_loop(
    cfg: &ClientConfig,
    lnd: &lnd::LndRestClient,
    cancel: CancellationToken,
) -> Result<()> {
    info!("Watch loop started — scan every {}s | {} sentinels",
        cfg.watch.scan_interval_secs, cfg.sentinels.len());
    let mut ticker = interval(Duration::from_secs(cfg.watch.scan_interval_secs));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match scan_and_register(cfg, lnd).await {
                    Ok(n) if n > 0 => info!("Registered/refreshed {n} HTLCs"),
                    Ok(_) => {},
                    Err(e) => error!("Scan error: {e}"),
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
    Ok(())
}

/// Scan LND for HTLCs and register them with all configured sentinels.
/// Handles both Mode A (active channels) and Mode B (force-closing).
async fn scan_and_register(cfg: &ClientConfig, lnd: &lnd::LndRestClient) -> Result<usize> {
    let mut all_channels = lnd.list_channels_with_htlcs().await?;

    // Mode B: also include force-closing channels (real outpoints)
    if cfg.watch.scan_force_closing {
        let force_close = lnd.list_force_close_htlcs().await.unwrap_or_default();
        if !force_close.is_empty() {
            info!("⚠️  {} force-closing channels detected — registering with real outpoints",
                force_close.len());
            all_channels.extend(force_close);
        }
    }

    let mut registered = 0;
    for channel in &all_channels {
        for htlc in &channel.pending_htlcs {
            if !htlc.incoming { continue; } // Only protect incoming HTLCs

            if !channel.outpoints_confirmed {
                warn!("HTLC {} uses placeholder outpoints (active channel — will update on close)",
                    &htlc.hash_lock[..16.min(htlc.hash_lock.len())]);
            }

            let claim_txs = match htlc_builder::build_claim_txs(
                &channel.channel_point, htlc, &cfg.fees, lnd,
            ).await {
                Ok(txs) => txs,
                Err(e) => {
                    warn!("Failed to build claim txs for {}: {e}",
                        &htlc.hash_lock[..16.min(htlc.hash_lock.len())]);
                    continue;
                }
            };

            let payload = register::RegistrationPayload {
                txid:                   htlc.outpoint_txid.clone(),
                vout:                   htlc.outpoint_index,
                claim_txs,
                protected_node_pubkey:  cfg.lnd.node_pubkey.clone(),
                cltv_expiry:            htlc.expiration_height,
                amount_sats:            htlc.amount_sats,
            };

            for sentinel in &cfg.sentinels {
                match register::register_htlc(&sentinel.url, &payload, &sentinel.api_key).await {
                    Ok(_) => {
                        info!("✅ {} → sentinel [{}] ({})",
                            &htlc.hash_lock[..16.min(htlc.hash_lock.len())],
                            sentinel.name,
                            if channel.outpoints_confirmed { "confirmed" } else { "placeholder" });
                        registered += 1;
                    }
                    Err(e) => warn!("Failed to register with [{}]: {e}", sentinel.name),
                }
            }
        }
    }
    Ok(registered)
}
