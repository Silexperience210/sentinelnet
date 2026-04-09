use crate::config::{BitcoinConfig, DefenseConfig};
use crate::store::{HtlcStatus, HtlcStore, WatchedHtlc};
use crate::watcher::{DisappearReason, MempoolEvent};
use anyhow::Result;
use bitcoincore_rpc::{Auth, Client as BtcClient, RpcApi};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct DefenseResult {
    pub txid:          String,
    pub defense_txid:  String,
    pub triggered_by:  TriggerReason,
    pub fee_tier_used: usize,
    pub success:       bool,
}

#[derive(Debug, Clone)]
pub enum TriggerReason {
    ReplacementCycling,
    CltvExpiry { blocks_remaining: u32 },
    ManualTrigger,
}

pub struct DefenseEngine {
    _btc_config:    BitcoinConfig,
    _defense_config: DefenseConfig,
    store:          HtlcStore,
    rpc:            Arc<BtcClient>,
    event_rx:       mpsc::Receiver<MempoolEvent>,
    defense_tx:     mpsc::Sender<DefenseResult>,
    current_block:  u32,
}

impl DefenseEngine {
    pub fn new(btc: BitcoinConfig, def: DefenseConfig, store: HtlcStore,
               event_rx: mpsc::Receiver<MempoolEvent>,
               defense_tx: mpsc::Sender<DefenseResult>) -> Result<Self> {
        let rpc = Arc::new(BtcClient::new(
            &btc.rpc_url, Auth::UserPass(btc.rpc_user.clone(), btc.rpc_password.clone()),
        )?);
        Ok(DefenseEngine { _btc_config: btc, _defense_config: def,
                           store, rpc, event_rx, defense_tx, current_block: 0 })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("DefenseEngine started");
        while let Some(event) = self.event_rx.recv().await {
            match event {
                MempoolEvent::HtlcSeen { txid }   => self.on_seen(&txid).await,
                MempoolEvent::HtlcDisappeared { txid, reason } => self.on_disappeared(&txid, reason).await,
                MempoolEvent::HtlcConfirmed { txid, block_height } => self.on_confirmed(&txid, block_height).await,
                MempoolEvent::HtlcCltvWarning { txid, blocks_remaining } => self.on_cltv(&txid, blocks_remaining).await,
                MempoolEvent::BlockUpdate { height } => self.current_block = height,
            }
        }
        Ok(())
    }

    async fn on_seen(&self, txid: &str) {
        if let Ok(Some(mut h)) = self.store.get(txid) {
            h.status = HtlcStatus::InMempool { first_seen: Utc::now() };
            let _ = self.store.update(&h);
        }
    }

    async fn on_disappeared(&self, txid: &str, _reason: DisappearReason) {
        warn!("🚨 HTLC {txid} disappeared from mempool");
        if let Ok(Some(h)) = self.store.get(txid) {
            if !matches!(h.status, HtlcStatus::Defended { .. } | HtlcStatus::Confirmed { .. }) {
                self.execute_defense(h, TriggerReason::ReplacementCycling).await;
            }
        }
    }

    async fn on_cltv(&self, txid: &str, blocks_remaining: u32) {
        if blocks_remaining > 10 { return; }
        warn!("⏰ CLTV warning: {txid} — {blocks_remaining} blocks left");
        if let Ok(Some(h)) = self.store.get(txid) {
            if !matches!(h.status, HtlcStatus::DefensePending { .. } | HtlcStatus::Defended { .. }) {
                self.execute_defense(h, TriggerReason::CltvExpiry { blocks_remaining }).await;
            }
        }
    }

    async fn on_confirmed(&self, txid: &str, block_height: u32) {
        info!("✅ HTLC {txid} confirmed at block {block_height}");
        if let Ok(Some(mut h)) = self.store.get(txid) {
            h.status = HtlcStatus::Confirmed { at_block: block_height };
            let _ = self.store.update(&h);
            crate::metrics::get().htlcs_confirmed_clean.inc();
        }
    }

    async fn execute_defense(&self, mut htlc: WatchedHtlc, trigger: TriggerReason) {
        let txid = htlc.txid.clone();
        info!("⚔️  Defending {txid} (tier {})", htlc.current_fee_tier);

        htlc.status = HtlcStatus::DefensePending { triggered_by: Utc::now() };
        htlc.defense_attempts += 1;
        let _ = self.store.update(&htlc);
        crate::metrics::get().defense_attempts.inc();

        let claim_hex = match htlc.current_claim_tx() {
            Some(h) => h.to_string(),
            None    => { error!("No claim tx for {txid}"); return; }
        };

        match self.broadcast(&claim_hex) {
            Ok(defense_txid) => {
                info!("✅ Defense broadcast: {defense_txid}");
                let proof = crate::proof::build_proof(
                    &txid, &defense_txid, &trigger, htlc.defense_attempts,
                );
                htlc.status = HtlcStatus::Defended {
                    at_block:       self.current_block,
                    defense_txid:   defense_txid.clone(),
                    proof_hash:     proof.clone(),
                    broadcast_block: self.current_block,
                };
                let _ = self.store.update(&htlc);
                crate::metrics::get().htlcs_defended.inc();

                let _ = self.defense_tx.send(DefenseResult {
                    txid, defense_txid,
                    triggered_by: trigger,
                    fee_tier_used: htlc.current_fee_tier,
                    success: true,
                }).await;
            }
            Err(e) => {
                warn!("Broadcast failed (tier {}): {e}", htlc.current_fee_tier);
                htlc.escalate_fee();
                htlc.status = HtlcStatus::DefensePending { triggered_by: Utc::now() };
                let _ = self.store.update(&htlc);
            }
        }
    }

    fn broadcast(&self, hex: &str) -> Result<String> {
        Ok(self.rpc.send_raw_transaction(hex)?.to_string())
    }
}
