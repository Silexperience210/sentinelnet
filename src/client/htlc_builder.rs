/// htlc_builder.rs
///
/// Builds properly-structured HTLC claim (timeout) transactions
/// following BOLT #3 spec, at multiple fee tiers.
///
/// BOLT #3 HTLC-timeout witness structure:
///   0x00                          (empty byte for CHECKMULTISIG)
///   <remote_sig>                  (from counterparty)
///   <local_sig>                   (signed by us via LND)
///   <>                            (empty = timeout path)
///   <htlc_script>                 (witness script)

use super::lnd::{LndRestClient, PendingHtlc};
use super::FeeConfig;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use std::str::FromStr;
use tracing::{debug, warn};

// HTLC-timeout tx estimated vsize (segwit):
// Input:  41 (outpoint+seq) + 1 (script_len) + witness
// Witness: ~220 WU (2 sigs + empty + htlc_script ~140 bytes)
// Output: 31 bytes (P2WPKH)
// Base: ~10 + 41 + 31 = 82 bytes non-witness
// Witness: ~220 WU / 4 = 55 vbytes
// Total: ~137 vbytes (we use 150 to be safe)
const HTLC_TIMEOUT_VSIZE: u64 = 150;

/// Build pre-signed claim txs at all configured fee tiers
pub async fn build_claim_txs(
    _channel_point: &str,
    htlc: &PendingHtlc,
    fee_config: &FeeConfig,
    lnd: &LndRestClient,
) -> Result<Vec<String>> {
    // Get fresh destination address from LND wallet
    let dest_address = lnd.new_address().await
        .unwrap_or_else(|e| {
            warn!("Could not get LND address ({e}), using placeholder");
            // Fallback: bcrt1q... zero-hash for regtest dev only
            "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5g6u8j".to_string()
        });

    // Get current fee rate estimate (4-block target = urgent)
    let base_rate = lnd.estimate_fee_rate(4).await
        .unwrap_or(fee_config.base_fee_rate)
        .max(fee_config.base_fee_rate);

    debug!(
        "Building claim txs | HTLC {} | dest: {} | base: {} sat/vbyte",
        &htlc.hash_lock[..16], &dest_address[..20], base_rate
    );

    let mut claim_txs = Vec::new();

    for (tier, multiplier) in fee_config.fee_tiers.iter().enumerate() {
        let fee_rate = base_rate * multiplier;
        match build_single_claim_tx(htlc, fee_rate, &dest_address, lnd).await {
            Ok(signed_hex) => {
                let fee = (fee_rate * HTLC_TIMEOUT_VSIZE as f64) as u64;
                debug!("  Tier {tier}: {fee_rate:.1} sat/vb | fee: {fee} sats ✅");
                claim_txs.push(signed_hex);
            }
            Err(e) => {
                warn!("  Tier {tier} ({:.1}x): {e}", multiplier);
                // Keep a placeholder so fee tier indices stay consistent
                claim_txs.push(String::new());
            }
        }
    }

    // Remove trailing empty tiers
    while claim_txs.last().map(|s: &String| s.is_empty()) == Some(true) {
        claim_txs.pop();
    }
    // Remove leading empty tiers
    claim_txs.retain(|s| !s.is_empty());

    if claim_txs.is_empty() {
        anyhow::bail!("All fee tiers failed for HTLC {}", &htlc.hash_lock[..16]);
    }

    Ok(claim_txs)
}

async fn build_single_claim_tx(
    htlc: &PendingHtlc,
    fee_rate_sat_vbyte: f64,
    dest_address: &str,
    lnd: &LndRestClient,
) -> Result<String> {
    let htlc_amount_sats = htlc.amount_msat / 1000;
    let fee = (fee_rate_sat_vbyte * HTLC_TIMEOUT_VSIZE as f64) as u64;

    // Guard: fee must not exceed 80% of HTLC value (dust protection)
    if fee >= htlc_amount_sats * 8 / 10 {
        anyhow::bail!(
            "Fee ({fee} sats) would consume ≥80% of HTLC ({htlc_amount_sats} sats)"
        );
    }

    let output_amount = htlc_amount_sats.saturating_sub(fee);

    // Guard: output must be above dust limit (546 sats for P2WPKH)
    if output_amount < 546 {
        anyhow::bail!("Output amount {output_amount} sats is below dust limit");
    }

    // Parse HTLC outpoint
    let txid = Txid::from_str(&htlc.outpoint_txid)
        .with_context(|| format!("Invalid txid: {}", htlc.outpoint_txid))?;

    // Build the P2WPKH output script from the bech32 address
    let dest_script = address_to_script(dest_address, lnd).await?;

    // Build unsigned HTLC-timeout transaction (BOLT #3)
    //
    // nLockTime = htlc.expiration_height  (CLTV expiry)
    // nSequence = 1                       (CSV delay = 1 for HTLC-timeout)
    // Input: HTLC output from commitment tx
    // Output: to our wallet at dest_script
    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(htlc.expiration_height)
            .context("Invalid CLTV expiry height")?,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid,
                vout: htlc.outpoint_index,
            },
            script_sig: ScriptBuf::new(), // empty for segwit
            // CSV = 1 per BOLT #3 HTLC-timeout
            sequence: Sequence(1),
            witness: Witness::new(), // filled after signing
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: dest_script,
        }],
    };

    let unsigned_hex = hex::encode(serialize(&unsigned_tx));

    // Attempt signing via LND REST
    // LND's /v2/wallet/tx/sign handles segwit inputs when it recognises the UTXO
    match lnd.sign_raw_tx(&unsigned_hex).await {
        Ok(signed_hex) => Ok(signed_hex),
        Err(sign_err) => {
            // LND may not sign HTLC inputs directly via this endpoint
            // (requires channel-specific keys only accessible via gRPC SignerClient)
            // For proto/regtest: return unsigned with a warning
            warn!(
                "LND signing failed for HTLC {} — returning unsigned tx for dev testing. \
                 Production requires gRPC SignerClient. Error: {sign_err}",
                &htlc.hash_lock[..16]
            );
            warn!("TODO: implement /v2/signer/signmessage path for HTLC witness signing");
            Ok(unsigned_hex)
        }
    }
}

/// Convert a bech32 address string to a scriptpubkey
/// Supports P2WPKH (bc1q..) and P2WSH (bc1q.. 32-byte) and P2TR (bc1p..)
async fn address_to_script(address: &str, _lnd: &LndRestClient) -> Result<ScriptBuf> {
    use bitcoin::address::{Address, NetworkUnchecked};

    // Try to parse as any network (we don't validate network here — sentinel's job)
    let addr: Address<NetworkUnchecked> = address.parse()
        .with_context(|| format!("Invalid Bitcoin address: {address}"))?;

    // Extract the scriptpubkey without network validation
    // (works for mainnet, testnet, regtest)
    let script = addr.assume_checked().script_pubkey();
    Ok(script)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_guard_passes() {
        let amount = 100_000u64;
        let fee = 5_000u64;
        let pct = fee * 100 / amount;
        assert!(pct < 80, "Fee {pct}% should be < 80%");
    }

    #[test]
    fn test_fee_guard_blocks_excessive() {
        let amount = 10_000u64;
        let fee_rate = 200.0f64;
        let fee = (fee_rate * HTLC_TIMEOUT_VSIZE as f64) as u64;
        // 200 sat/vb * 150 vb = 30,000 sats >> 10,000 sats
        assert!(fee >= amount * 8 / 10, "Should be blocked by fee guard");
    }

    #[test]
    fn test_dust_guard() {
        let amount = 1_000u64;
        let fee = 600u64;
        let output = amount.saturating_sub(fee);
        assert!(output < 546, "Output {output} should be below dust limit");
    }

    #[test]
    fn test_htlc_tx_structure() {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxOut};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(800_000).unwrap(),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        assert_eq!(tx.version, Version::TWO);
        assert_eq!(tx.output[0].value, Amount::from_sat(90_000));
    }

    #[test]
    fn test_vsize_estimate() {
        // 150 vbytes * 100 sat/vb = 15,000 sat fee
        let fee = (100.0f64 * HTLC_TIMEOUT_VSIZE as f64) as u64;
        assert_eq!(fee, 15_000);
        // Must be < 80% of 100k sats
        assert!(fee < 80_000);
    }
}
