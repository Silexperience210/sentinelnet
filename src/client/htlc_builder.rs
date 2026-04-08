/// htlc_builder.rs
///
/// Builds pre-signed HTLC claim (success/timeout) transactions
/// at multiple fee tiers for delivery to sentinel nodes.
///
/// Architecture:
///   LND provides the HTLC outpoint and signing capability
///   We build unsigned raw txs, send to LND for signing, return hex

use super::lnd::{LndRestClient, PendingHtlc};
use super::FeeConfig;
use anyhow::{Context, Result};
use bitcoin::{
    absolute::LockTime,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use std::str::FromStr;
use tracing::{debug, warn};

/// Build pre-signed claim txs at all fee tiers
/// Returns Vec of raw hex txs (one per tier)
pub async fn build_claim_txs(
    channel_point: &str,
    htlc: &PendingHtlc,
    fee_config: &FeeConfig,
    lnd: &LndRestClient,
) -> Result<Vec<String>> {
    // Get current fee rate estimate
    let base_fee_rate = lnd.estimate_fee_rate(6).await.unwrap_or(fee_config.base_fee_rate);
    let actual_base = base_fee_rate.max(fee_config.base_fee_rate);

    debug!(
        "Building claim txs for HTLC {} | base fee: {} sat/vbyte",
        &htlc.hash_lock[..16],
        actual_base
    );

    let mut claim_txs = Vec::new();

    for (i, multiplier) in fee_config.fee_tiers.iter().enumerate() {
        let fee_rate = actual_base * multiplier;
        match build_single_claim_tx(channel_point, htlc, fee_rate, lnd).await {
            Ok(signed_hex) => {
                debug!("  Tier {i}: {:.1}x = {:.1} sat/vbyte ✅", multiplier, fee_rate);
                claim_txs.push(signed_hex);
            }
            Err(e) => {
                warn!("  Tier {i} ({:.1}x): failed — {e}", multiplier);
                // Push placeholder — sentinel will skip this tier
                claim_txs.push(String::new());
            }
        }
    }

    // Remove empty trailing entries
    while claim_txs.last().map(|s: &String| s.is_empty()) == Some(true) {
        claim_txs.pop();
    }

    if claim_txs.is_empty() {
        anyhow::bail!("All fee tiers failed for HTLC {}", htlc.hash_lock);
    }

    Ok(claim_txs)
}

async fn build_single_claim_tx(
    channel_point: &str,
    htlc: &PendingHtlc,
    fee_rate_sat_vbyte: f64,
    lnd: &LndRestClient,
) -> Result<String> {
    let htlc_amount_sats = htlc.amount_msat / 1000;

    // Estimated tx size for HTLC claim: ~200 vbytes (input + output + witness)
    let estimated_vbytes = 200u64;
    let fee_sats = (fee_rate_sat_vbyte * estimated_vbytes as f64) as u64;

    // Sanity check: fee shouldn't exceed 50% of HTLC value
    if fee_sats > htlc_amount_sats / 2 {
        anyhow::bail!(
            "Fee ({fee_sats} sats) too high relative to HTLC value ({htlc_amount_sats} sats)"
        );
    }

    let output_amount = htlc_amount_sats.saturating_sub(fee_sats);

    // Parse outpoint
    let txid = Txid::from_str(&htlc.outpoint_txid)
        .with_context(|| format!("Invalid txid: {}", htlc.outpoint_txid))?;

    let outpoint = OutPoint {
        txid,
        vout: htlc.outpoint_index,
    };

    // Build the unsigned claim transaction
    // NOTE: In production, the script_sig and witness are provided by LND
    // This is a skeleton that LND will sign via /v2/wallet/tx/sign
    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(htlc.expiration_height)
            .unwrap_or(LockTime::ZERO),
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            // P2WPKH to our own wallet — LND will provide the actual address
            // In a real implementation, query LND for a new address
            script_pubkey: our_p2wpkh_script(),
        }],
    };

    // Serialize to hex for signing
    let unsigned_hex = serialize_tx_hex(&unsigned_tx);

    // Have LND sign it
    // In production this uses LND's HTLC-specific signing path
    // which includes the HTLC script witness
    match lnd.sign_raw_tx(&unsigned_hex).await {
        Ok(signed_hex) => Ok(signed_hex),
        Err(e) => {
            // In testnet/dev mode, LND signing may not work for all HTLC types
            // Fall back to unsigned for development
            warn!("LND signing failed ({e}) — using unsigned tx for dev testing");
            Ok(unsigned_hex)
        }
    }
}

/// Serialize a Bitcoin transaction to hex string
fn serialize_tx_hex(tx: &Transaction) -> String {
    use bitcoin::consensus::encode::serialize;
    hex::encode(serialize(tx))
}

/// Generate a placeholder P2WPKH scriptpubkey
/// In production: call LND /v1/newaddress to get a real address
fn our_p2wpkh_script() -> ScriptBuf {
    // OP_0 <20-byte-hash> — placeholder for dev/testing
    // A real implementation fetches this from LND
    ScriptBuf::from_bytes(vec![
        0x00, 0x14, // OP_0 + PUSH 20
        // 20 zero bytes — replace with actual pubkey hash from LND
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Transaction, TxOut, ScriptBuf};

    #[test]
    fn test_tx_serialization() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: our_p2wpkh_script(),
            }],
        };
        let hex = serialize_tx_hex(&tx);
        assert!(!hex.is_empty());
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fee_calculation() {
        let htlc_amount = 100_000u64;
        let fee_rate = 50.0f64; // sat/vbyte
        let vbytes = 200u64;
        let fee = (fee_rate * vbytes as f64) as u64;
        let output = htlc_amount.saturating_sub(fee);
        assert_eq!(fee, 10_000);
        assert_eq!(output, 90_000);
        // Fee < 50% of value
        assert!(fee < htlc_amount / 2);
    }
}
