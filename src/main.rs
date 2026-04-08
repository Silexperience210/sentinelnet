mod api;
mod bounty;
mod config;
mod defense;
mod gossip;
mod lnd;
mod proof;
mod store;
mod watcher;

use anyhow::{Context, Result};
use bitcoincore_rpc::{Auth, Client as BtcClient};
use clap::{Parser, Subcommand};
use std::fs;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "sentinel", about = "SentinelNet — Incentivized Lightning Network Watchtower", version = "0.1.0")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Init {
        #[arg(short, long, default_value = "config.toml")]
        output: String,
    },
    Watch {
        #[arg(long)] txid: String,
        #[arg(long, default_value = "0")] vout: u32,
        #[arg(long)] claim_tx: String,
        #[arg(long)] pubkey: String,
        #[arg(long)] cltv: u32,
        #[arg(long)] amount: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinelnet=info,warn"));
    fmt().with_env_filter(filter).with_target(false).compact().init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Start) {
        Commands::Init { output } => {
            fs::write(&output, toml::to_string_pretty(&config::Config::default())?)?;
            println!("✅ Config written to {output}");
            println!("   Generate secrets: openssl rand -hex 32");
            return Ok(());
        }
        Commands::Watch { txid, vout, claim_tx, pubkey, cltv, amount } => {
            let cfg = config::Config::load(&cli.config)?;
            let store = store::HtlcStore::open(&cfg.sentinel.data_dir)?;
            store.register(&store::WatchedHtlc::new(txid.clone(), vout, vec![claim_tx], pubkey, cltv, amount))?;
            println!("✅ Registered HTLC {txid}");
            return Ok(());
        }
        Commands::Start => {}
    }

    let cfg = config::Config::load(&cli.config)?;
    fs::create_dir_all(&cfg.sentinel.data_dir)?;

    // Warn on default secrets
    if cfg.sentinel.api_key.contains("CHANGE_ME") {
        warn!("⚠️  API key is default — set sentinel.api_key in config.toml!");
    }
    if cfg.gossip.shared_secret.contains("CHANGE_ME") {
        warn!("⚠️  Gossip secret is default — set gossip.shared_secret in config.toml!");
    }

    info!("╔══════════════════════════════════════════╗");
    info!("║          SentinelNet v0.1.0               ║");
    info!("║  Always Watching. Never Sleeping.         ║");
    info!("╚══════════════════════════════════════════╝");
    info!("Node:   {}", cfg.sentinel.name);
    info!("API:    http://0.0.0.0:{} (auth: {})", cfg.sentinel.api_port,
        if cfg.sentinel.api_key.is_empty() { "disabled" } else { "X-Sentinel-Key" });
    info!("Gossip: 0.0.0.0:{} | {} peers | HMAC: {}",
        cfg.gossip.port, cfg.gossip.peers.len(),
        if cfg.gossip.shared_secret.contains("CHANGE_ME") { "⚠️ default" } else { "✅ custom" });

    let store = store::HtlcStore::open(&cfg.sentinel.data_dir)?;
    let stats = store.stats()?;
    info!("Store: {} HTLCs | {} defended | {} bounties pending",
        stats.total, stats.defended, stats.bounties_pending);

    // Shared Bitcoin RPC client
    let rpc = Arc::new(BtcClient::new(
        &cfg.bitcoin.rpc_url,
        Auth::UserPass(cfg.bitcoin.rpc_user.clone(), cfg.bitcoin.rpc_password.clone()),
    )?);

    // LND client
    let lnd_client = lnd::LndClient::new(&cfg.lnd)?;
    match lnd_client.get_info().await {
        Ok(info) => {
            info!("LND: {} ({})", info.alias, &info.identity_pubkey[..16]);
            if !info.synced_to_chain { warn!("⚠️  LND not synced"); }
        }
        Err(e) => warn!("⚠️  LND unreachable: {e}"),
    }

    // Channels
    let (mempool_tx, mempool_rx) = mpsc::channel::<watcher::MempoolEvent>(1024);
    let (defense_tx, defense_rx) = mpsc::channel::<defense::DefenseResult>(256);
    let (gossip_bcast_tx, _) = broadcast::channel::<gossip::GossipMessage>(256);
    let gossip_rx_client = gossip_bcast_tx.subscribe();

    // Tasks
    let t1 = {
        let w = watcher::MempoolWatcher::new(cfg.bitcoin.clone(), store.clone(), mempool_tx)?;
        tokio::spawn(async move { if let Err(e) = w.run().await { error!("Watcher: {e}"); } })
    };

    let t2 = {
        let mut engine = defense::DefenseEngine::new(
            cfg.bitcoin.clone(), cfg.defense.clone(),
            store.clone(), mempool_rx, defense_tx,
        )?;
        tokio::spawn(async move { if let Err(e) = engine.run().await { error!("Defense: {e}"); } })
    };

    let t3 = {
        let mut bp = bounty::BountyProcessor::new(
            cfg.defense.clone(), store.clone(), lnd_client,
            rpc.clone(), defense_rx, cfg.lnd.node_pubkey.clone(),
        );
        tokio::spawn(async move { if let Err(e) = bp.run().await { error!("Bounty: {e}"); } })
    };

    let t4 = {
        let server = gossip::GossipServer::new(
            cfg.gossip.port, store.clone(),
            cfg.lnd.node_pubkey.clone(),
            cfg.gossip.shared_secret.clone(),
            gossip_bcast_tx.clone(),
        );
        tokio::spawn(async move { if let Err(e) = server.run().await { error!("GossipServer: {e}"); } })
    };

    let t5 = {
        let client = gossip::GossipClient::new(
            cfg.gossip.peers.clone(),
            cfg.lnd.node_pubkey.clone(),
            cfg.sentinel.advertised_addr.clone(),
            cfg.gossip.shared_secret.clone(),
            store.clone(),
            cfg.gossip.broadcast_interval_secs,
            gossip_rx_client,
        );
        tokio::spawn(async move { if let Err(e) = client.run().await { error!("GossipClient: {e}"); } })
    };

    let t6 = {
        let server = api::ApiServer::new(cfg.sentinel.api_port, store.clone(), cfg.sentinel.api_key.clone());
        tokio::spawn(async move { if let Err(e) = server.run().await { error!("API: {e}"); } })
    };

    info!("🟢 SentinelNet online — POST http://0.0.0.0:{}/register", cfg.sentinel.api_port);

    tokio::select! {
        _ = t1 => error!("Watcher exited"),
        _ = t2 => error!("Defense exited"),
        _ = t3 => error!("Bounty exited"),
        _ = t4 => error!("GossipServer exited"),
        _ = t5 => error!("GossipClient exited"),
        _ = t6 => error!("API exited"),
        _ = tokio::signal::ctrl_c() => info!("Shutting down"),
    }
    Ok(())
}
