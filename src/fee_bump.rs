//! CPFP fee-bumping for stuck defense transactions.
//!
//! When a defense tx has been in the mempool for more than
//! `stuck_after_blocks` blocks without confirming, we create
//! a Child-Pays-For-Parent (CPFP) transaction spending one of
//! its outputs at a higher fee rate.

use anyhow::{Context, Result};
use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Auth, Client as BtcClient, RpcApi};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};

pub struct FeeBumper {
    rpc: Arc<BtcClient>,
    /// Multiplier applied to current 90th-percentile fee rate
    bump_multiplier: f64,
    /// Number of blocks a tx may be pending before we bump
    stuck_after_blocks: u32,
}

impl FeeBumper {
    pub fn new(rpc: Arc<BtcClient>, bump_multiplier: f64, stuck_after_blocks: u32) -> Self {
        FeeBumper { rpc, bump_multiplier, stuck_after_blocks }
    }

    /// Check if a txid is stuck in the mempool and needs bumping.
    /// Returns Some(cpfp_txid) if a bump was performed.
    pub fn maybe_bump(
        &self,
        defense_txid: &str,
        current_block: u32,
        broadcast_block: u32,
        dest_script: &ScriptBuf,
    ) -> Option<String> {
        if current_block.saturating_sub(broadcast_block) < self.stuck_after_blocks {
            return None; // Not stuck yet
        }

        // Verify it's still in mempool (not confirmed)
        let txid = Txid::from_str(defense_txid).ok()?;
        let tx_info = self.rpc.get_raw_transaction_info(&txid, None).ok()?;

        if tx_info.confirmations.unwrap_or(0) > 0 {
            return None; // Already confirmed — no bump needed
        }

        let raw_tx = self.rpc.get_raw_transaction(&txid, None).ok()?;

        // Find the first non-dust output to use as CPFP parent
        let (parent_vout, parent_value) = raw_tx.output.iter().enumerate()
            .find(|(_, out)| out.value > Amount::from_sat(2000))
            .map(|(i, out)| (i as u32, out.value))?;

        let target_fee_rate = self.estimate_target_fee_rate();
        let cpfp_vsize = 110u64; // P2WPKH input + P2WPKH output estimate
        let total_fee_needed = (target_fee_rate * (cpfp_vsize + 150) as f64) as u64;

        let cpfp_output = parent_value.to_sat().saturating_sub(total_fee_needed);
        if cpfp_output < 546 {
            warn!("CPFP would produce dust output ({cpfp_output} sats) — skipping bump");
            return None;
        }

        let cpfp_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: parent_vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(cpfp_output),
                script_pubkey: dest_script.clone(),
            }],
        };

        // NOTE: This CPFP tx needs signing by our wallet before broadcast.
        // In production: sign via LND /v2/wallet/tx/sign before sendrawtransaction.
        let cpfp_hex = hex::encode(serialize(&cpfp_tx));

        match self.rpc.send_raw_transaction(cpfp_hex.as_str()) {
            Ok(cpfp_txid) => {
                crate::metrics::get().fee_bumps.inc();
                info!("⚡ CPFP fee bump broadcast: {cpfp_txid} (parent: {defense_txid})");
                Some(cpfp_txid.to_string())
            }
            Err(e) => {
                warn!("CPFP broadcast failed: {e}");
                None
            }
        }
    }

    fn estimate_target_fee_rate(&self) -> f64 {
        match self.rpc.estimate_smart_fee(2, None) {
            Ok(est) => {
                if let Some(rate) = est.fee_rate {
                    let sat_per_vbyte = rate.to_btc() * 100_000_000.0 / 1000.0;
                    return sat_per_vbyte * self.bump_multiplier;
                }
                20.0 * self.bump_multiplier
            }
            Err(_) => 20.0 * self.bump_multiplier,
        }
    }
}
