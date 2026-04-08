use crate::config::DefenseConfig;
use crate::defense::{DefenseResult, TriggerReason};
use crate::lnd::LndClient;
use crate::proof::build_full_proof;
use crate::store::HtlcStore;
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Bounty processor — listens for successful defenses and pays keysend
pub struct BountyProcessor {
    config: DefenseConfig,
    store: HtlcStore,
    lnd: LndClient,
    defense_rx: mpsc::Receiver<DefenseResult>,
    sentinel_pubkey: String,
}

impl BountyProcessor {
    pub fn new(
        config: DefenseConfig,
        store: HtlcStore,
        lnd: LndClient,
        defense_rx: mpsc::Receiver<DefenseResult>,
        sentinel_pubkey: String,
    ) -> Self {
        BountyProcessor {
            config,
            store,
            lnd,
            defense_rx,
            sentinel_pubkey,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("BountyProcessor started — awaiting defense results");

        while let Some(result) = self.defense_rx.recv().await {
            if result.success {
                self.process_bounty(result).await;
            }
        }
        Ok(())
    }

    async fn process_bounty(&self, result: DefenseResult) {
        let htlc = match self.store.get(&result.txid) {
            Ok(Some(h)) => h,
            Ok(None) => {
                warn!("HTLC {} not found for bounty processing", result.txid);
                return;
            }
            Err(e) => {
                error!("Store error during bounty processing: {e}");
                return;
            }
        };

        // Build the full proof for this defense
        let proof = build_full_proof(
            &result.txid,
            &result.defense_txid,
            &result.triggered_by,
            1,
            &self.sentinel_pubkey,
        );

        // Calculate bounty amount
        let bounty_sats = self.calculate_bounty(&result, htlc.amount_sats);

        info!(
            "💰 Calculating bounty for HTLC {} | defended {}sats | bounty: {}sats",
            result.txid, htlc.amount_sats, bounty_sats
        );

        // Build the keysend message with proof embedded
        let message = format!(
            "SentinelNet defense proof | htlc:{} | defense:{} | proof:{}",
            &result.txid[..8],
            &result.defense_txid[..8],
            &proof.proof_hash[..16]
        );

        // Send keysend bounty to the protected node
        match self
            .lnd
            .send_keysend(&htlc.protected_node_pubkey, bounty_sats, &message)
            .await
        {
            Ok(payment_hash) => {
                info!(
                    "✅ Bounty paid! {} sats → {} | payment_hash: {}",
                    bounty_sats, &htlc.protected_node_pubkey[..16], payment_hash
                );
            }
            Err(e) => {
                // Node may be offline — retry will be needed in production
                warn!(
                    "Failed to send bounty to {}: {e}",
                    &htlc.protected_node_pubkey[..16]
                );
                warn!("Proof for manual recovery: {}", serde_json::to_string(&proof).unwrap_or_default());
            }
        }
    }

    /// Calculate bounty based on:
    /// - Amount defended
    /// - Trigger reason (cycling = higher reward)
    /// - Fee tier used (faster response = higher reward)
    fn calculate_bounty(&self, result: &DefenseResult, amount_defended: u64) -> u64 {
        // Base bounty: 0.1% of amount defended, capped
        let base = (amount_defended / 1000).max(self.config.min_bounty_sats);

        // Trigger multiplier
        let trigger_mult = match &result.triggered_by {
            TriggerReason::ReplacementCycling => 2.0,   // hardest attack = double reward
            TriggerReason::CltvExpiry { blocks_remaining } => {
                if *blocks_remaining < 3 { 3.0 } else { 1.5 }
            }
            TriggerReason::ManualTrigger => 1.0,
        };

        // Speed multiplier: lower fee tier = faster response = more sats
        let speed_mult = match result.fee_tier_used {
            0 => 1.5, // responded immediately at base fee
            1 => 1.2,
            2 => 1.0,
            _ => 0.8, // had to escalate many times
        };

        let bounty = (base as f64 * trigger_mult * speed_mult) as u64;
        bounty.min(self.config.max_bounty_sats)
    }
}
