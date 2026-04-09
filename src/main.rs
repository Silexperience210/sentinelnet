mod api; mod backup; mod bounty; mod config; mod defense; mod fee_bump;
mod gossip; mod lnd; mod metrics; mod proof; mod rate_limit; mod store; mod watcher;

use anyhow::{Context, Result};
use bitcoincore_rpc::{Auth, Client as BtcClient};
use clap::{Parser, Subcommand};
use std::fs;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name="sentinel", about="SentinelNet — Incentivized Lightning Network Watchtower", version="0.1.0")]
struct Cli {
    #[arg(short, long, default_value="config.toml")] config: String,
    #[command(subcommand)] command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Start,
    Init { #[arg(short,long,default_value="config.toml")] output: String },
    Watch {
        #[arg(long)] txid: String, #[arg(long,default_value="0")] vout: u32,
        #[arg(long)] claim_tx: String, #[arg(long)] pubkey: String,
        #[arg(long)] cltv: u32, #[arg(long)] amount: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinelnet=info,warn"));
    fmt().with_env_filter(filter).with_target(false).compact().init();

    // Init Prometheus metrics registry early
    metrics::init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Start) {
        Commands::Init { output } => {
            fs::write(&output, toml::to_string_pretty(&config::Config::default())?)?;
            println!("✅ {output}  — generate secrets: openssl rand -hex 32");
            return Ok(());
        }
        Commands::Watch { txid, vout, claim_tx, pubkey, cltv, amount } => {
            let cfg = config::Config::load(&cli.config)?;
            let store = store::HtlcStore::open(&cfg.sentinel.data_dir, cfg.encryption_secret().as_deref())?;
            store.register(&store::WatchedHtlc::new(txid.clone(),vout,vec![claim_tx],pubkey,cltv,amount))?;
            println!("✅ {txid}");
            return Ok(());
        }
        Commands::Start => {}
    }

    let cfg = config::Config::load(&cli.config)
        .with_context(|| format!("Config: {}", cli.config))?;
    fs::create_dir_all(&cfg.sentinel.data_dir)?;

    if cfg.sentinel.api_key.contains("CHANGE_ME") { warn!("⚠️  api_key is default!"); }
    if cfg.gossip.shared_secret.contains("CHANGE_ME") { warn!("⚠️  gossip.shared_secret is default!"); }

    info!("╔══════════════════════════════════════════╗");
    info!("║          SentinelNet v0.1.0               ║");
    info!("║  Always Watching. Never Sleeping.         ║");
    info!("╚══════════════════════════════════════════╝");
    info!("API:     http://0.0.0.0:{} | Metrics: /metrics", cfg.sentinel.api_port);
    info!("Storage: {} | encrypted: {} | backup: {}s",
        cfg.sentinel.data_dir, cfg.storage.encrypt_db, cfg.storage.backup_interval_secs);

    let store = store::HtlcStore::open(&cfg.sentinel.data_dir, cfg.encryption_secret().as_deref())?;
    let stats = store.stats()?;
    metrics::get().htlcs_watching.set(stats.watching as f64);
    info!("Store: {} HTLCs | {} defended | {} bounties pending",
        stats.total, stats.defended, stats.bounties_pending);

    let rpc = Arc::new(BtcClient::new(
        &cfg.bitcoin.rpc_url,
        Auth::UserPass(cfg.bitcoin.rpc_user.clone(), cfg.bitcoin.rpc_password.clone()),
    )?);

    let lnd_client = lnd::LndClient::new(&cfg.lnd)?;
    match lnd_client.get_info().await {
        Ok(i) => { info!("LND: {} ({})", i.alias, &i.identity_pubkey[..16]); }
        Err(e) => warn!("⚠️  LND: {e}"),
    }

    let cancel = CancellationToken::new();

    let (mempool_tx, mempool_rx) = mpsc::channel::<watcher::MempoolEvent>(1024);
    let (defense_tx, defense_rx) = mpsc::channel::<defense::DefenseResult>(256);
    let (gossip_bcast, _) = broadcast::channel::<gossip::GossipMessage>(256);
    let gossip_rx2 = gossip_bcast.subscribe();

    macro_rules! task {
        ($name:expr, $cancel:expr, $body:expr) => {{
            let c = $cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    r = $body => { if let Err(e) = r { error!("{}: {e}", $name); } }
                    _ = c.cancelled() => { info!("{} stopped", $name); }
                }
            })
        }};
    }

    // Clone all config values before moving into tasks
    let (btc1, btc2)   = (cfg.bitcoin.clone(), cfg.bitcoin.clone());
    let (def1, def2)   = (cfg.defense.clone(), cfg.defense.clone());
    let (store1, store2, store3, store4, store5, store6) = (
        store.clone(), store.clone(), store.clone(),
        store.clone(), store.clone(), store.clone(),
    );
    let (pk1, pk2, pk3) = (cfg.lnd.node_pubkey.clone(), cfg.lnd.node_pubkey.clone(), cfg.lnd.node_pubkey.clone());
    let (sec1, sec2)   = (cfg.gossip.shared_secret.clone(), cfg.gossip.shared_secret.clone());
    let (peers, addr)  = (cfg.gossip.peers.clone(), cfg.sentinel.advertised_addr.clone());
    let (port_api, api_key) = (cfg.sentinel.api_port, cfg.sentinel.api_key.clone());
    let gossip_port    = cfg.gossip.port;
    let bcast_interval = cfg.gossip.broadcast_interval_secs;

    let t1 = task!("Watcher",      cancel, async move {
        watcher::MempoolWatcher::new(btc1, store1, mempool_tx)?.run().await
    });
    let t2 = task!("Defense",      cancel, async move {
        defense::DefenseEngine::new(btc2, def1, store2, mempool_rx, defense_tx)?.run().await
    });
    let t3 = task!("Bounty",       cancel, async move {
        bounty::BountyProcessor::new(def2, store3, lnd_client, rpc.clone(), defense_rx, pk1).run().await
    });
    let t4 = task!("GossipServer", cancel, async move {
        gossip::GossipServer::new(gossip_port, store4, pk2, sec1, gossip_bcast.clone()).run().await
    });
    let t5 = task!("GossipClient", cancel, async move {
        gossip::GossipClient::new(peers, pk3, addr, sec2, store5, bcast_interval, gossip_rx2).run().await
    });
    let t6 = task!("API",          cancel, async move {
        api::ApiServer::new(port_api, store6, api_key).run().await
    });

    // Fix 11: backup task
    let t7 = if cfg.storage.backup_interval_secs > 0 {
        let s = store.clone(); let d = cfg.sentinel.data_dir.clone();
        let i = cfg.storage.backup_interval_secs; let c2 = cancel.clone();
        tokio::spawn(async move { backup::backup_loop(s, d, i, c2).await; })
    } else {
        tokio::spawn(async {})
    };

    info!("🟢 SentinelNet online — {} total tasks", 7);
    info!("   POST /register  GET /status  GET /metrics  GET /htlcs");

    tokio::signal::ctrl_c().await?;
    info!("Ctrl-C — graceful shutdown (5s drain)…");
    cancel.cancel();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async { let _ = tokio::join!(t1,t2,t3,t4,t5,t6,t7); },
    ).await.ok();
    info!("✅ Clean shutdown");
    Ok(())
}
