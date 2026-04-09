//! Bounty processor — confirmation check, retry queue, availability fee, proof verification.

use crate::config::DefenseConfig;
use crate::defense::{DefenseResult, TriggerReason};
use crate::lnd::LndClient;
use crate::proof::{build_full_proof, verify_proof};
use crate::store::{HtlcStatus, HtlcStore, PendingBounty};
use anyhow::Result;
use bitcoincore_rpc::{Client as BtcClient, RpcApi};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const REQUIRED_CONFIRMATIONS: u32     = 1;
const RETRY_INTERVAL_SECS:    u64     = 60;

pub struct BountyProcessor {
    config:          DefenseConfig,
    store:           HtlcStore,
    lnd:             LndClient,
    rpc:             Arc<BtcClient>,
    defense_rx:      mpsc::Receiver<DefenseResult>,
    sentinel_pubkey: String,
}

impl BountyProcessor {
    pub fn new(config: DefenseConfig, store: HtlcStore, lnd: LndClient,
               rpc: Arc<BtcClient>, defense_rx: mpsc::Receiver<DefenseResult>,
               sentinel_pubkey: String) -> Self {
        BountyProcessor { config, store, lnd, rpc, defense_rx, sentinel_pubkey }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("BountyProcessor started (confirmation + availability fee + proof verification)");
        let mut retry = interval(Duration::from_secs(RETRY_INTERVAL_SECS));

        loop {
            tokio::select! {
                Some(result) = self.defense_rx.recv() => {
                    if result.success { self.queue_defense_bounty(result).await; }
                }
                _ = retry.tick() => {
                    self.process_retry_queue().await;
                    self.check_availability_fees().await;  // Fix 4
                }
            }
        }
    }

    // ── Defense bounty ───────────────────────────────────────────────────────

    async fn queue_defense_bounty(&self, result: DefenseResult) {
        let htlc = match self.store.get(&result.txid) {
            Ok(Some(h)) => h, _ => return,
        };

        // Fix 8: build proof and verify it before queuing payment
        let proof = build_full_proof(
            &result.txid, &result.defense_txid,
            &result.triggered_by, htlc.defense_attempts,
            &self.sentinel_pubkey,
        );
        if !verify_proof(&proof, &self.sentinel_pubkey) {
            error!("🚨 Self-generated proof failed verification for {} — not queuing bounty",
                &result.txid[..16]);
            return;
        }

        let sats = self.calculate_bounty(&result, htlc.amount_sats);
        let mut b = PendingBounty::new(
            result.txid.clone(), result.defense_txid.clone(),
            htlc.protected_node_pubkey.clone(), sats, proof.proof_hash.clone(),
        );
        b.is_availability_fee = false;

        if let Err(e) = self.store.save_bounty(&b) {
            error!("Failed to save bounty: {e}"); return;
        }
        info!("💾 Defense bounty queued: {sats} sats for {}", &result.txid[..16]);
        self.try_pay(&b).await;
    }

    // ── Fix 4: Availability fee ───────────────────────────────────────────────

    async fn check_availability_fees(&self) {
        let fee_per_hour = self.config.availability_fee_sats_per_hour;
        if fee_per_hour == 0 { return; }

        let htlcs = match self.store.get_all() {
            Ok(h) => h, Err(_) => return,
        };

        for htlc in htlcs {
            // Only charge for HTLCs that resolved cleanly (no attack)
            if !matches!(&htlc.status, HtlcStatus::Confirmed { .. }) { continue; }

            // Check if we already raised this availability fee
            let fee_id = format!("avail_{}", &htlc.txid[..16]);
            if self.store.get_all_bounties().ok()
                .map(|bs| bs.iter().any(|b| b.id == fee_id))
                .unwrap_or(false) {
                continue;
            }

            let hours  = htlc.hours_watched().max(1);
            let amount = (hours * fee_per_hour).min(self.config.max_bounty_sats / 10);
            if amount < 10 { continue; }

            let mut b = PendingBounty::new(
                htlc.txid.clone(), "availability".into(),
                htlc.protected_node_pubkey.clone(),
                amount,
                format!("availability_fee_{}", htlc.txid),
            );
            b.id = fee_id;
            b.is_availability_fee = true;

            if let Err(e) = self.store.save_bounty(&b) {
                error!("Failed to save availability fee: {e}");
            } else {
                info!("📋 Availability fee queued: {amount} sats ({hours}h × {fee_per_hour} sats/h) for {}",
                    &htlc.txid[..16]);
                self.try_pay(&b).await;
            }
        }
    }

    // ── Retry queue ───────────────────────────────────────────────────────────

    async fn process_retry_queue(&self) {
        let pending = match self.store.get_pending_bounties() {
            Ok(b) => b, Err(e) => { error!("Load pending: {e}"); return; }
        };
        if !pending.is_empty() {
            info!("🔄 Retry queue: {} pending", pending.len());
        }
        for b in pending { self.try_pay(&b).await; }
    }

    async fn try_pay(&self, bounty: &PendingBounty) {
        // Skip availability fees: no defense tx to confirm
        if !bounty.is_availability_fee {
            match self.is_confirmed(&bounty.defense_txid) {
                Ok(true)  => {},
                Ok(false) => { return; } // not yet confirmed
                Err(e)    => { warn!("RPC check: {e}"); return; }
            }
        }

        let kind = if bounty.is_availability_fee { "availability" } else { "defense" };
        let msg  = format!("SentinelNet {kind} | htlc:{} | proof:{}",
            &bounty.htlc_txid[..16.min(bounty.htlc_txid.len())],
            &bounty.proof_hash[..16.min(bounty.proof_hash.len())]);

        match self.lnd.send_keysend(&bounty.recipient_pubkey, bounty.amount_sats, &msg).await {
            Ok(hash) => {
                info!("💸 Paid {} sats ({kind}) → {} | {}", bounty.amount_sats,
                    &bounty.recipient_pubkey[..16], &hash[..16.min(hash.len())]);
                crate::metrics::get().bounties_paid_sats.inc_by(bounty.amount_sats as f64);
                let _ = self.store.mark_bounty_paid(&bounty.id);
            }
            Err(e) => {
                warn!("Keysend failed (attempt {}): {e}", bounty.attempts + 1);
                let mut upd = bounty.clone();
                upd.attempts += 1;
                upd.last_attempt = Some(chrono::Utc::now());
                let _ = self.store.save_bounty(&upd);
                if upd.attempts >= 10 {
                    crate::metrics::get().bounties_failed.inc();
                    error!("❌ Bounty exhausted retries. Manual recovery:");
                    error!("   Proof:     {}", bounty.proof_hash);
                    error!("   Amount:    {} sats", bounty.amount_sats);
                    error!("   Recipient: {}", bounty.recipient_pubkey);
                }
            }
        }
    }

    fn is_confirmed(&self, txid: &str) -> Result<bool> {
        let t: bitcoin::Txid = txid.parse()?;
        match self.rpc.get_raw_transaction_info(&t, None) {
            Ok(info) => Ok(info.confirmations.unwrap_or(0) >= REQUIRED_CONFIRMATIONS),
            Err(bitcoincore_rpc::Error::JsonRpc(
                bitcoincore_rpc::jsonrpc::Error::Rpc(ref e))) if e.code == -5 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn calculate_bounty(&self, r: &DefenseResult, amount: u64) -> u64 {
        let base  = (amount / 1000).max(self.config.min_bounty_sats);
        let tmult = match &r.triggered_by {
            TriggerReason::ReplacementCycling => 2.0,
            TriggerReason::CltvExpiry { blocks_remaining } => if *blocks_remaining < 3 { 3.0 } else { 1.5 },
            TriggerReason::ManualTrigger => 1.0,
        };
        let smult = match r.fee_tier_used { 0=>1.5, 1=>1.2, 2=>1.0, _=>0.8 };
        ((base as f64 * tmult * smult) as u64).min(self.config.max_bounty_sats)
    }
}
