use crate::config::DefenseConfig;
use crate::defense::{DefenseResult, TriggerReason};
use crate::lnd::LndClient;
use crate::proof::build_full_proof;
use crate::store::{HtlcStore, PendingBounty};
use anyhow::Result;
use bitcoincore_rpc::{Auth, Client as BtcClient, RpcApi};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

const REQUIRED_CONFIRMATIONS: u32 = 1;
const RETRY_CHECK_INTERVAL_SECS: u64 = 60;

pub struct BountyProcessor {
    config: DefenseConfig,
    store: HtlcStore,
    lnd: LndClient,
    rpc: Arc<BtcClient>,
    defense_rx: mpsc::Receiver<DefenseResult>,
    sentinel_pubkey: String,
}

impl BountyProcessor {
    pub fn new(
        config: DefenseConfig,
        store: HtlcStore,
        lnd: LndClient,
        rpc: Arc<BtcClient>,
        defense_rx: mpsc::Receiver<DefenseResult>,
        sentinel_pubkey: String,
    ) -> Self {
        BountyProcessor { config, store, lnd, rpc, defense_rx, sentinel_pubkey }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("BountyProcessor started (confirmation check + retry enabled)");
        let mut retry_ticker = interval(Duration::from_secs(RETRY_CHECK_INTERVAL_SECS));

        loop {
            tokio::select! {
                Some(result) = self.defense_rx.recv() => {
                    if result.success {
                        self.queue_bounty(result).await;
                    }
                }
                _ = retry_ticker.tick() => {
                    self.process_retry_queue().await;
                }
            }
        }
    }

    /// Queue a bounty — waits for on-chain confirmation before paying
    async fn queue_bounty(&self, result: DefenseResult) {
        let htlc = match self.store.get(&result.txid) {
            Ok(Some(h)) => h,
            _ => return,
        };

        let proof = build_full_proof(
            &result.txid,
            &result.defense_txid,
            &result.triggered_by,
            1,
            &self.sentinel_pubkey,
        );

        let bounty_sats = self.calculate_bounty(&result, htlc.amount_sats);

        let bounty = PendingBounty::new(
            result.txid.clone(),
            result.defense_txid.clone(),
            htlc.protected_node_pubkey.clone(),
            bounty_sats,
            proof.proof_hash.clone(),
        );

        if let Err(e) = self.store.save_bounty(&bounty) {
            error!("Failed to save pending bounty: {e}");
            return;
        }

        info!(
            "💾 Bounty queued: {} sats for defense of {} (awaiting {} confirmation(s))",
            bounty_sats, &result.txid[..16], REQUIRED_CONFIRMATIONS
        );

        // Try to pay immediately — will retry later if it fails
        self.try_pay_bounty(&bounty).await;
    }

    /// Retry queue — processes all pending unpaid bounties
    async fn process_retry_queue(&self) {
        let pending = match self.store.get_pending_bounties() {
            Ok(b) => b,
            Err(e) => { error!("Failed to load pending bounties: {e}"); return; }
        };

        if !pending.is_empty() {
            info!("🔄 Retry queue: {} pending bounties", pending.len());
        }

        for bounty in pending {
            self.try_pay_bounty(&bounty).await;
        }
    }

    async fn try_pay_bounty(&self, bounty: &PendingBounty) {
        // Step 1: Verify the defense tx is confirmed on-chain
        match self.is_confirmed(&bounty.defense_txid) {
            Ok(true) => {
                info!("✅ Defense tx {} confirmed on-chain", &bounty.defense_txid[..16]);
            }
            Ok(false) => {
                info!("⏳ Defense tx {} not yet confirmed — will retry", &bounty.defense_txid[..16]);
                return;
            }
            Err(e) => {
                warn!("RPC error checking confirmation for {}: {e}", &bounty.defense_txid[..16]);
                return;
            }
        }

        // Step 2: Build keysend message
        let message = format!(
            "SentinelNet bounty | htlc:{} | proof:{}",
            &bounty.htlc_txid[..16],
            &bounty.proof_hash[..16]
        );

        // Step 3: Send keysend
        match self.lnd.send_keysend(&bounty.recipient_pubkey, bounty.amount_sats, &message).await {
            Ok(payment_hash) => {
                info!(
                    "💸 Bounty PAID! {} sats → {} | payment: {}",
                    bounty.amount_sats,
                    &bounty.recipient_pubkey[..16],
                    &payment_hash[..16.min(payment_hash.len())]
                );
                if let Err(e) = self.store.mark_bounty_paid(&bounty.id) {
                    error!("Failed to mark bounty paid: {e}");
                }
            }
            Err(e) => {
                warn!(
                    "Keysend failed for {} sats → {} (attempt {}): {e}",
                    bounty.amount_sats,
                    &bounty.recipient_pubkey[..16],
                    bounty.attempts + 1
                );
                // Update attempt count
                let mut updated = bounty.clone();
                updated.attempts += 1;
                updated.last_attempt = Some(chrono::Utc::now());
                let _ = self.store.save_bounty(&updated);

                if updated.attempts >= 10 {
                    error!(
                        "❌ Bounty for {} exhausted all retries. Manual recovery needed.",
                        &bounty.htlc_txid[..16]
                    );
                    error!("   Proof: {}", bounty.proof_hash);
                    error!("   Amount: {} sats", bounty.amount_sats);
                    error!("   Recipient: {}", bounty.recipient_pubkey);
                }
            }
        }
    }

    /// Check if a txid has at least REQUIRED_CONFIRMATIONS on-chain
    fn is_confirmed(&self, txid: &str) -> Result<bool> {
        let txid_parsed: bitcoin::Txid = txid.parse()?;
        match self.rpc.get_raw_transaction_info(&txid_parsed, None) {
            Ok(info) => Ok(info.confirmations.unwrap_or(0) >= REQUIRED_CONFIRMATIONS),
            Err(bitcoincore_rpc::Error::JsonRpc(
                bitcoincore_rpc::jsonrpc::Error::Rpc(ref e))) if e.code == -5 => {
                // -5 = "No such mempool or blockchain transaction" — not confirmed
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn calculate_bounty(&self, result: &DefenseResult, amount_defended: u64) -> u64 {
        let base = (amount_defended / 1000).max(self.config.min_bounty_sats);
        let trigger_mult = match &result.triggered_by {
            TriggerReason::ReplacementCycling => 2.0,
            TriggerReason::CltvExpiry { blocks_remaining } => {
                if *blocks_remaining < 3 { 3.0 } else { 1.5 }
            }
            TriggerReason::ManualTrigger => 1.0,
        };
        let speed_mult = match result.fee_tier_used {
            0 => 1.5,
            1 => 1.2,
            2 => 1.0,
            _ => 0.8,
        };
        ((base as f64 * trigger_mult * speed_mult) as u64)
            .min(self.config.max_bounty_sats)
    }
}
