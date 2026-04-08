use crate::config::BitcoinConfig;
use crate::store::{HtlcStatus, HtlcStore, WatchedHtlc};
use anyhow::Result;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use chrono::Utc;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Events emitted by the mempool watcher
#[derive(Debug, Clone)]
pub enum MempoolEvent {
    /// HTLC appeared in mempool
    HtlcSeen { txid: String },
    /// HTLC disappeared from mempool before confirmation — replacement cycling suspected
    HtlcDisappeared { txid: String, reason: DisappearReason },
    /// HTLC confirmed — no defense needed
    HtlcConfirmed { txid: String, block_height: u32 },
    /// HTLC approaching CLTV expiry — defense pre-emptive trigger
    HtlcCltvWarning { txid: String, blocks_remaining: u32 },
    /// Current block height update
    BlockUpdate { height: u32 },
}

#[derive(Debug, Clone)]
pub enum DisappearReason {
    ReplacementCycling, // was in mempool, now gone, not confirmed
    Unknown,
}

pub struct MempoolWatcher {
    config: BitcoinConfig,
    store: HtlcStore,
    rpc: Arc<Client>,
    event_tx: mpsc::Sender<MempoolEvent>,
}

impl MempoolWatcher {
    pub fn new(
        config: BitcoinConfig,
        store: HtlcStore,
        event_tx: mpsc::Sender<MempoolEvent>,
    ) -> Result<Self> {
        let rpc = Client::new(
            &config.rpc_url,
            Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        )?;
        Ok(MempoolWatcher {
            config,
            store,
            rpc: Arc::new(rpc),
            event_tx,
        })
    }

    /// Main watcher loop
    pub async fn run(&self) -> Result<()> {
        info!("MempoolWatcher started — polling every {}s", self.config.poll_interval_secs);

        let mut ticker = interval(Duration::from_secs(self.config.poll_interval_secs));
        let mut previously_in_mempool: HashSet<String> = HashSet::new();
        let mut last_block_height: u32 = 0;

        loop {
            ticker.tick().await;

            // --- Get current state ---
            let current_height = match self.get_block_height() {
                Ok(h) => h,
                Err(e) => {
                    error!("RPC error getting block height: {e}");
                    continue;
                }
            };

            if current_height != last_block_height {
                last_block_height = current_height;
                let _ = self.event_tx.send(MempoolEvent::BlockUpdate { height: current_height }).await;
                debug!("Block height: {current_height}");
            }

            // --- Get current mempool ---
            let mempool_txids: HashSet<String> = match self.get_mempool_txids() {
                Ok(txids) => txids,
                Err(e) => {
                    error!("RPC error getting mempool: {e}");
                    continue;
                }
            };

            // --- Check all active HTLCs ---
            let active_htlcs = match self.store.get_active() {
                Ok(htlcs) => htlcs,
                Err(e) => {
                    error!("Store error: {e}");
                    continue;
                }
            };

            for htlc in active_htlcs {
                self.process_htlc(
                    &htlc,
                    &mempool_txids,
                    &previously_in_mempool,
                    current_height,
                )
                .await;
            }

            // Update mempool snapshot
            previously_in_mempool = mempool_txids;
        }
    }

    async fn process_htlc(
        &self,
        htlc: &WatchedHtlc,
        current_mempool: &HashSet<String>,
        previous_mempool: &HashSet<String>,
        current_height: u32,
    ) {
        let txid = &htlc.txid;
        let in_mempool_now = current_mempool.contains(txid);
        let was_in_mempool = previous_mempool.contains(txid);

        // Check if confirmed
        if self.is_confirmed(txid) {
            if !matches!(htlc.status, HtlcStatus::Confirmed { .. }) {
                info!("HTLC {txid} confirmed on-chain ✅");
                let _ = self.event_tx.send(MempoolEvent::HtlcConfirmed {
                    txid: txid.clone(),
                    block_height: current_height,
                }).await;
            }
            return;
        }

        // Just appeared in mempool
        if in_mempool_now && !was_in_mempool {
            if matches!(htlc.status, HtlcStatus::Watching) {
                info!("HTLC {txid} appeared in mempool 👁");
                let _ = self.event_tx.send(MempoolEvent::HtlcSeen { txid: txid.clone() }).await;
            }
        }

        // CLTV expiry warning
        if current_height + self.config.cltv_safe_margin >= htlc.cltv_expiry {
            let blocks_remaining = htlc.cltv_expiry.saturating_sub(current_height);
            warn!(
                "HTLC {txid} approaching CLTV expiry! {blocks_remaining} blocks remaining ⚠️"
            );
            let _ = self.event_tx.send(MempoolEvent::HtlcCltvWarning {
                txid: txid.clone(),
                blocks_remaining,
            }).await;
        }

        // CRITICAL: was in mempool, now gone, and not confirmed
        // This is the replacement cycling signature
        if was_in_mempool && !in_mempool_now {
            warn!(
                "🚨 HTLC {txid} DISAPPEARED from mempool! Possible replacement cycling attack!"
            );
            let _ = self.event_tx.send(MempoolEvent::HtlcDisappeared {
                txid: txid.clone(),
                reason: DisappearReason::ReplacementCycling,
            }).await;
        }
    }

    fn get_block_height(&self) -> Result<u32> {
        let info = self.rpc.get_blockchain_info()?;
        Ok(info.blocks as u32)
    }

    fn get_mempool_txids(&self) -> Result<HashSet<String>> {
        let raw = self.rpc.get_raw_mempool()?;
        Ok(raw.iter().map(|txid| txid.to_string()).collect())
    }

    fn is_confirmed(&self, txid: &str) -> bool {
        let txid_parsed = match txid.parse::<bitcoin::Txid>() {
            Ok(t) => t,
            Err(_) => return false,
        };
        match self.rpc.get_raw_transaction_info(&txid_parsed, None) {
            Ok(info) => info.confirmations.unwrap_or(0) > 0,
            Err(_) => false,
        }
    }

    /// Get current fee rate estimate (sat/vbyte) at given confirmation target
    pub fn estimate_fee_rate(&self, conf_target: u16) -> Result<f64> {
        match self.rpc.estimate_smart_fee(conf_target, None) {
            Ok(result) => {
                if let Some(fee_rate) = result.fee_rate {
                    // fee_rate is in BTC/kB, convert to sat/vbyte
                    let sat_per_vbyte = fee_rate.to_btc() * 100_000_000.0 / 1000.0;
                    Ok(sat_per_vbyte)
                } else {
                    Ok(10.0) // fallback
                }
            }
            Err(_) => Ok(10.0), // fallback if estimation fails
        }
    }
}
