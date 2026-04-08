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
use clap::{Parser, Subcommand};
use std::fs;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "sentinel",
    about = "SentinelNet — Incentivized Lightning Network Watchtower",
    version = "0.1.0"
)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sentinel daemon
    Start,
    /// Generate a default config file
    Init {
        #[arg(short, long, default_value = "config.toml")]
        output: String,
    },
    /// Show current status
    Status,
    /// Register an HTLC for watching (CLI shortcut)
    Watch {
        #[arg(long)]
        txid: String,
        #[arg(long, default_value = "0")]
        vout: u32,
        #[arg(long)]
        claim_tx: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        cltv: u32,
        #[arg(long)]
        amount: u64,
    },
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Init logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinelnet=info,warn"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Start) {
        Commands::Init { output } => {
            let default_config = config::Config::default();
            let toml_str = toml::to_string_pretty(&default_config)?;
            fs::write(&output, toml_str)?;
            println!("✅ Default config written to {output}");
            println!("   Edit it then run: sentinel start");
            return Ok(());
        }

        Commands::Status => {
            println!("Use: curl http://localhost:9000/status");
            return Ok(());
        }

        Commands::Watch { txid, vout, claim_tx, pubkey, cltv, amount } => {
            let cfg = config::Config::load(&cli.config)?;
            let store = store::HtlcStore::open(&cfg.sentinel.data_dir)?;
            let htlc = store::WatchedHtlc::new(
                txid.clone(),
                vout,
                vec![claim_tx],
                pubkey,
                cltv,
                amount,
            );
            store.register(&htlc)?;
            println!("✅ HTLC {txid} registered for watching");
            return Ok(());
        }

        Commands::Start => {}
    }

    // ─── Load config ──────────────────────────────────────────────────────────
    let cfg = config::Config::load(&cli.config)
        .with_context(|| format!("Failed to load config from {}", cli.config))?;

    // Create data directory
    fs::create_dir_all(&cfg.sentinel.data_dir)?;

    info!("╔══════════════════════════════════════════╗");
    info!("║          SentinelNet v0.1.0               ║");
    info!("║  Always Watching. Never Sleeping.         ║");
    info!("╚══════════════════════════════════════════╝");
    info!("Node: {}", cfg.sentinel.name);
    info!("Data: {}", cfg.sentinel.data_dir);
    info!("API:  http://0.0.0.0:{}", cfg.sentinel.api_port);
    info!("Gossip port: {}", cfg.gossip.port);
    info!("Peers: {}", cfg.gossip.peers.len());

    // ─── Open store ──────────────────────────────────────────────────────────
    let store = store::HtlcStore::open(&cfg.sentinel.data_dir)?;
    let stats = store.stats()?;
    info!(
        "Store loaded: {} HTLCs total ({} watching, {} defended)",
        stats.total, stats.watching, stats.defended
    );

    // ─── Init LND client ─────────────────────────────────────────────────────
    let lnd_client = lnd::LndClient::new(&cfg.lnd)?;

    // Verify LND connectivity
    match lnd_client.get_info().await {
        Ok(info) => {
            info!("LND connected: {} ({})", info.alias, &info.identity_pubkey[..16]);
            if !info.synced_to_chain {
                warn!("⚠️  LND not synced to chain — defense may be impaired");
            }
        }
        Err(e) => {
            warn!("⚠️  LND not reachable: {e} — bounty payments will fail");
        }
    }

    // ─── Channel setup ───────────────────────────────────────────────────────
    // mempool events: watcher → defense engine
    let (mempool_tx, mempool_rx) = mpsc::channel::<watcher::MempoolEvent>(1024);
    // defense results: defense engine → bounty processor
    let (defense_tx, defense_rx) = mpsc::channel::<defense::DefenseResult>(256);
    // gossip broadcast: between gossip components
    let (gossip_tx, gossip_rx) = broadcast::channel::<gossip::GossipMessage>(256);
    let gossip_rx2 = gossip_tx.subscribe();

    // ─── Spawn tasks ─────────────────────────────────────────────────────────

    // Task 1: Mempool watcher
    let watcher_task = {
        let watcher = watcher::MempoolWatcher::new(
            cfg.bitcoin.clone(),
            store.clone(),
            mempool_tx,
        )?;
        tokio::spawn(async move {
            if let Err(e) = watcher.run().await {
                error!("MempoolWatcher crashed: {e}");
            }
        })
    };

    // Task 2: Defense engine
    let defense_task = {
        let mut engine = defense::DefenseEngine::new(
            cfg.bitcoin.clone(),
            cfg.defense.clone(),
            store.clone(),
            mempool_rx,
            defense_tx,
        )?;
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                error!("DefenseEngine crashed: {e}");
            }
        })
    };

    // Task 3: Bounty processor
    let bounty_task = {
        let mut processor = bounty::BountyProcessor::new(
            cfg.defense.clone(),
            store.clone(),
            lnd_client,
            defense_rx,
            cfg.lnd.node_pubkey.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = processor.run().await {
                error!("BountyProcessor crashed: {e}");
            }
        })
    };

    // Task 4: Gossip server (accepts incoming)
    let gossip_server_task = {
        let server = gossip::GossipServer::new(
            cfg.gossip.port,
            store.clone(),
            cfg.lnd.node_pubkey.clone(),
            gossip_tx.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("GossipServer crashed: {e}");
            }
        })
    };

    // Task 5: Gossip client (connects to peers)
    let gossip_client_task = {
        let client = gossip::GossipClient::new(
            cfg.gossip.peers.clone(),
            cfg.lnd.node_pubkey.clone(),
            cfg.sentinel.advertised_addr.clone(),
            store.clone(),
            cfg.gossip.broadcast_interval_secs,
            gossip_rx2,
        );
        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                error!("GossipClient crashed: {e}");
            }
        })
    };

    // Task 6: REST API server
    let api_task = {
        let server = api::ApiServer::new(cfg.sentinel.api_port, store.clone());
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                error!("ApiServer crashed: {e}");
            }
        })
    };

    info!("🟢 All tasks started — SentinelNet is online");
    info!("   Register HTLCs: POST http://0.0.0.0:{}/register", cfg.sentinel.api_port);
    info!("   Status:         GET  http://0.0.0.0:{}/status", cfg.sentinel.api_port);

    // Wait for any task to finish (they all run forever)
    tokio::select! {
        _ = watcher_task => error!("Watcher task exited"),
        _ = defense_task => error!("Defense task exited"),
        _ = bounty_task  => error!("Bounty task exited"),
        _ = gossip_server_task => error!("Gossip server exited"),
        _ = gossip_client_task => error!("Gossip client exited"),
        _ = api_task     => error!("API task exited"),
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received — shutting down");
        }
    }

    Ok(())
}
