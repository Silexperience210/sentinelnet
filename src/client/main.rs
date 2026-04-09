mod channel_events;
mod htlc_builder;
mod lnd;
mod register;
mod signer;

use anyhow::{Context, Result};
use channel_events::ChannelEvent;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub lnd:       LndConfig,
    pub sentinels: Vec<SentinelEndpoint>,
    pub fees:      FeeConfig,
    pub watch:     WatchConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LndConfig {
    pub rest_url:      String,
    pub tls_cert_path: String,
    pub macaroon_hex:  String,
    pub node_pubkey:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEndpoint {
    pub name:    String,
    pub url:     String,
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    pub base_fee_rate: f64,
    pub fee_tiers:     Vec<f64>,
    pub cltv_margin:   u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    pub scan_interval_secs:  u64,
    pub reregister_margin:   u32,
    pub scan_force_closing:  bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            lnd: LndConfig {
                rest_url: "https://localhost:8080".into(),
                tls_cert_path: "~/.lnd/tls.cert".into(),
                macaroon_hex: String::new(),
                node_pubkey: String::new(),
            },
            sentinels: vec![SentinelEndpoint {
                name: "primary".into(),
                url: "http://127.0.0.1:9000".into(),
                api_key: "CHANGE_ME".into(),
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

#[derive(Parser)]
#[command(name = "sentinel-client", version = "0.1.0")]
struct Cli {
    #[arg(short, long, default_value = "client.toml")]
    config: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Watch,
    Register,
    Init { #[arg(short, long, default_value = "client.toml")] output: String },
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinel_client=info,warn"));
    fmt().with_env_filter(filter).with_target(false).compact().init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Watch) {
        Commands::Init { output } => {
            fs::write(&output, toml::to_string_pretty(&ClientConfig::default())?)?;
            println!("✅ {output}");
            return Ok(());
        }
        Commands::Status => {
            let cfg = load_cfg(&cli.config)?;
            for s in &cfg.sentinels {
                match register::check_sentinel_status(&s.url).await {
                    Ok(v)  => println!("[{}] {}", s.name, serde_json::to_string_pretty(&v)?),
                    Err(e) => println!("[{}] ❌ {e}", s.name),
                }
            }
            return Ok(());
        }
        Commands::Register => {
            let cfg = load_cfg(&cli.config)?;
            let lnd = lnd::LndRestClient::new(&cfg.lnd)?;
            info!("One-shot register: {} HTLCs", scan_and_register(&cfg, &lnd).await?);
        }
        Commands::Watch => {
            let cfg = load_cfg(&cli.config)?;
            let lnd = lnd::LndRestClient::new(&cfg.lnd)?;
            match lnd.get_info().await {
                Ok(i) => info!("LND: {} | block {}", i.alias, i.block_height),
                Err(e) => warn!("LND unreachable: {e}"),
            }
            run_watch(&cfg, lnd).await?;
        }
    }
    Ok(())
}

fn load_cfg(path: &str) -> Result<ClientConfig> {
    toml::from_str(&fs::read_to_string(path).with_context(|| format!("Cannot read {path}"))?)
        .context("Parse config")
}

async fn run_watch(cfg: &ClientConfig, lnd: lnd::LndRestClient) -> Result<()> {
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down sentinel-client…");
        c2.cancel();
    });

    // Fix 1: subscribe to channel events for reactive scanning
    let (event_tx, mut event_rx) = mpsc::channel::<ChannelEvent>(64);
    {
        let lnd2   = lnd::LndRestClient::new(&cfg.lnd).unwrap();
        let etx    = event_tx.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            channel_events::watch_loop(lnd2, etx, cancel).await;
        });
    }

    let mut ticker = interval(Duration::from_secs(cfg.watch.scan_interval_secs));
    info!("Watch loop: scan every {}s + reactive on channel events", cfg.watch.scan_interval_secs);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match scan_and_register(cfg, &lnd).await {
                    Ok(n) if n > 0 => info!("Registered/refreshed {n} HTLCs"),
                    Ok(_) => {},
                    Err(e) => error!("Scan: {e}"),
                }
            }
            Some(event) = event_rx.recv() => {
                match event {
                    ChannelEvent::Rescan => {
                        info!("🔔 Channel event → immediate re-scan");
                        match scan_and_register(cfg, &lnd).await {
                            Ok(n) => info!("Reactive scan: {n} HTLCs updated"),
                            Err(e) => error!("Reactive scan: {e}"),
                        }
                    }
                    ChannelEvent::ForceClosed { channel_point } => {
                        info!("⚠️  Force-close detected: {channel_point} — scanning force-close HTLCs");
                        match scan_force_close(cfg, &lnd).await {
                            Ok(n) => info!("Force-close scan: {n} real outpoints registered"),
                            Err(e) => error!("Force-close scan: {e}"),
                        }
                    }
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
    Ok(())
}

async fn scan_and_register(cfg: &ClientConfig, lnd: &lnd::LndRestClient) -> Result<usize> {
    let channels = lnd.list_channels_with_htlcs().await?;
    let mut n = 0;
    for ch in &channels {
        for htlc in ch.pending_htlcs.iter().filter(|h| h.incoming) {
            n += register_htlc(cfg, lnd, &ch.channel_point, htlc, false).await;
        }
    }
    Ok(n)
}

async fn scan_force_close(cfg: &ClientConfig, lnd: &lnd::LndRestClient) -> Result<usize> {
    let channels = lnd.list_force_close_htlcs().await?;
    let mut n = 0;
    for ch in &channels {
        for htlc in ch.pending_htlcs.iter().filter(|h| h.incoming) {
            n += register_htlc(cfg, lnd, &ch.channel_point, htlc, true).await;
        }
    }
    Ok(n)
}

async fn register_htlc(
    cfg: &ClientConfig,
    lnd: &lnd::LndRestClient,
    channel_point: &str,
    htlc: &lnd::PendingHtlc,
    confirmed: bool,
) -> usize {
    let claim_txs = match htlc_builder::build_claim_txs(channel_point, htlc, &cfg.fees, lnd).await {
        Ok(t)  => t,
        Err(e) => { warn!("build_claim_txs: {e}"); return 0; }
    };
    let payload = register::RegistrationPayload {
        txid: htlc.outpoint_txid.clone(), vout: htlc.outpoint_index,
        claim_txs, protected_node_pubkey: cfg.lnd.node_pubkey.clone(),
        cltv_expiry: htlc.expiration_height, amount_sats: htlc.amount_sats,
    };
    let mut registered = 0;
    for s in &cfg.sentinels {
        match register::register_htlc(&s.url, &payload, &s.api_key).await {
            Ok(_)  => {
                info!("✅ {} → [{}] ({})",
                    &htlc.hash_lock[..16.min(htlc.hash_lock.len())],
                    s.name, if confirmed { "real outpoint" } else { "placeholder" });
                registered += 1;
            }
            Err(e) => warn!("Register [{}]: {e}", s.name),
        }
    }
    registered
}
