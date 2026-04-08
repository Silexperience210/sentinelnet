use crate::config::{BitcoinConfig, DefenseConfig};
use crate::store::{HtlcStatus, HtlcStore, WatchedHtlc};
use crate::watcher::{DisappearReason, MempoolEvent};
use anyhow::{Context, Result};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Result of a defense attempt
#[derive(Debug, Clone)]
pub struct DefenseResult {
    pub txid: String,
    pub defense_txid: String,
    pub triggered_by: TriggerReason,
    pub fee_tier_used: usize,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub enum TriggerReason {
    ReplacementCycling,
    CltvExpiry { blocks_remaining: u32 },
    ManualTrigger,
}

/// Defense engine — listens for events and broadcasts claim transactions
pub struct DefenseEngine {
    btc_config: BitcoinConfig,
    defense_config: DefenseConfig,
    store: HtlcStore,
    rpc: Arc<Client>,
    event_rx: mpsc::Receiver<MempoolEvent>,
    defense_tx: mpsc::Sender<DefenseResult>,
}

impl DefenseEngine {
    pub fn new(
        btc_config: BitcoinConfig,
        defense_config: DefenseConfig,
        store: HtlcStore,
        event_rx: mpsc::Receiver<MempoolEvent>,
        defense_tx: mpsc::Sender<DefenseResult>,
    ) -> Result<Self> {
        let rpc = Client::new(
            &btc_config.rpc_url,
            Auth::UserPass(btc_config.rpc_user.clone(), btc_config.rpc_password.clone()),
        )?;
        Ok(DefenseEngine {
            btc_config,
            defense_config,
            store,
            rpc: Arc::new(rpc),
            event_rx,
            defense_tx,
        })
    }

    /// Main defense loop — reacts to mempool events
    pub async fn run(&mut self) -> Result<()> {
        info!("DefenseEngine started — awaiting mempool events");

        while let Some(event) = self.event_rx.recv().await {
            match event {
                MempoolEvent::HtlcSeen { txid } => {
                    self.handle_htlc_seen(&txid).await;
                }
                MempoolEvent::HtlcDisappeared { txid, reason } => {
                    self.handle_htlc_disappeared(&txid, reason).await;
                }
                MempoolEvent::HtlcConfirmed { txid, block_height } => {
                    self.handle_htlc_confirmed(&txid, block_height).await;
                }
                MempoolEvent::HtlcCltvWarning { txid, blocks_remaining } => {
                    self.handle_cltv_warning(&txid, blocks_remaining).await;
                }
                MempoolEvent::BlockUpdate { height } => {
                    debug_block_update(height);
                }
            }
        }
        Ok(())
    }

    async fn handle_htlc_seen(&self, txid: &str) {
        if let Ok(Some(mut htlc)) = self.store.get(txid) {
            htlc.status = HtlcStatus::InMempool { first_seen: Utc::now() };
            if let Err(e) = self.store.update(&htlc) {
                error!("Failed to update HTLC status: {e}");
            }
        }
    }

    async fn handle_htlc_disappeared(&self, txid: &str, reason: DisappearReason) {
        warn!("🚨 Defense triggered for HTLC {txid} — reason: {reason:?}");

        let htlc = match self.store.get(txid) {
            Ok(Some(h)) => h,
            Ok(None) => {
                warn!("HTLC {txid} not found in store — ignoring");
                return;
            }
            Err(e) => {
                error!("Store error: {e}");
                return;
            }
        };

        match reason {
            DisappearReason::ReplacementCycling | DisappearReason::Unknown => {
                self.execute_defense(htlc, TriggerReason::ReplacementCycling).await;
            }
        }
    }

    async fn handle_cltv_warning(&self, txid: &str, blocks_remaining: u32) {
        // Only trigger if very close to expiry (within 10 blocks)
        if blocks_remaining > 10 {
            return;
        }

        warn!("⏰ CLTV defense triggered for {txid} — {blocks_remaining} blocks left");

        if let Ok(Some(htlc)) = self.store.get(txid) {
            // Don't re-trigger if already defending
            if matches!(htlc.status, HtlcStatus::DefensePending { .. } | HtlcStatus::Defended { .. }) {
                return;
            }
            self.execute_defense(htlc, TriggerReason::CltvExpiry { blocks_remaining }).await;
        }
    }

    async fn handle_htlc_confirmed(&self, txid: &str, block_height: u32) {
        if let Ok(Some(mut htlc)) = self.store.get(txid) {
            info!("✅ HTLC {txid} confirmed at block {block_height} — no defense needed");
            htlc.status = HtlcStatus::Confirmed { at_block: block_height };
            let _ = self.store.update(&htlc);
        }
    }

    /// Core defense execution — broadcasts the pre-signed claim transaction
    async fn execute_defense(&self, mut htlc: WatchedHtlc, trigger: TriggerReason) {
        let txid = htlc.txid.clone();
        info!("⚔️  Executing defense for HTLC {txid} (fee tier {})", htlc.current_fee_tier);

        // Update status
        htlc.status = HtlcStatus::DefensePending { triggered_by: Utc::now() };
        htlc.defense_attempts += 1;
        let _ = self.store.update(&htlc);

        // Get the appropriate pre-signed claim transaction
        let claim_tx_hex = match htlc.current_claim_tx() {
            Some(tx) => tx.to_string(),
            None => {
                error!("No claim tx available for HTLC {txid}");
                return;
            }
        };

        // Broadcast via Bitcoin Knots RPC
        match self.broadcast_transaction(&claim_tx_hex) {
            Ok(defense_txid) => {
                info!("✅ Defense tx broadcast! txid: {defense_txid}");

                // Build proof of defense
                let proof_hash = crate::proof::build_proof(
                    &txid,
                    &defense_txid,
                    &trigger,
                    htlc.defense_attempts,
                );

                htlc.status = HtlcStatus::Defended {
                    at_block: 0, // will be updated when confirmed
                    defense_txid: defense_txid.clone(),
                    proof_hash: proof_hash.clone(),
                };
                let _ = self.store.update(&htlc);

                // Notify bounty processor
                let result = DefenseResult {
                    txid: txid.clone(),
                    defense_txid,
                    triggered_by: trigger,
                    fee_tier_used: htlc.current_fee_tier,
                    success: true,
                };
                let _ = self.defense_tx.send(result).await;
            }
            Err(e) => {
                warn!("Failed to broadcast defense tx (tier {}): {e}", htlc.current_fee_tier);

                // Escalate fee tier and retry on next cycle
                htlc.escalate_fee();
                htlc.status = HtlcStatus::DefensePending { triggered_by: Utc::now() };
                let _ = self.store.update(&htlc);

                if htlc.current_fee_tier >= htlc.claim_txs.len() {
                    error!("All fee tiers exhausted for HTLC {txid} — defense failed!");
                }
            }
        }
    }

    fn broadcast_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let tx_bytes = hex::decode(raw_tx_hex)
            .with_context(|| "Failed to decode raw transaction hex")?;

        let txid = self.rpc.send_raw_transaction(raw_tx_hex)
            .with_context(|| "Failed to broadcast transaction via RPC")?;

        Ok(txid.to_string())
    }
}

fn debug_block_update(height: u32) {
    if height % 10 == 0 {
        tracing::debug!("Block height checkpoint: {height}");
    }
}
