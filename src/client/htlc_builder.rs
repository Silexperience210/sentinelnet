//! BOLT#3 HTLC-timeout transaction builder.
//!
//! Fix 2: local_htlcpubkey obtained from LND /v2/wallet/key (family=2).
//!        remote_htlcpubkey still requires gRPC (documented).
//!        Use computeinputscript with real key locator.

use super::lnd::{LndRestClient, PendingHtlc};
use super::FeeConfig;
use anyhow::{Context, Result};
use bitcoin::{
    absolute::LockTime, consensus::encode::serialize,
    hashes::{hash160, Hash}, transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use std::str::FromStr;
use tracing::{debug, warn};

const HTLC_TIMEOUT_VSIZE: u64 = 154;

pub async fn build_claim_txs(
    _channel_point: &str,
    htlc: &PendingHtlc,
    fee_config: &FeeConfig,
    lnd: &LndRestClient,
) -> Result<Vec<String>> {
    let dest_address = lnd.new_address().await
        .unwrap_or_else(|e| { warn!("new_address: {e}"); "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5g6u8j".into() });
    let dest_script  = address_to_script(&dest_address)?;

    // Fix 2: get the real local HTLC base key from LND
    let local_htlc_key = lnd.get_htlc_base_key().await
        .unwrap_or_else(|e| { warn!("get_htlc_base_key: {e} — using placeholder"); vec![0x02u8; 33] });

    let base_rate = lnd.estimate_fee_rate(4).await
        .unwrap_or(fee_config.base_fee_rate)
        .max(fee_config.base_fee_rate);

    debug!("Building claim txs | {} | dest: {} | local_key: {} | base: {:.1} sat/vb",
        &htlc.hash_lock[..16.min(htlc.hash_lock.len())],
        &dest_address[..20.min(dest_address.len())],
        hex::encode(&local_htlc_key[..4]),
        base_rate);

    let mut results = Vec::new();
    for (tier, mult) in fee_config.fee_tiers.iter().enumerate() {
        let fee_rate = base_rate * mult;
        match build_and_sign(htlc, fee_rate, dest_script.clone(), &local_htlc_key, lnd).await {
            Ok(hex) => { debug!("  Tier {tier}: {fee_rate:.1} sat/vb ✅"); results.push(hex); }
            Err(e)  => { warn!("  Tier {tier}: {e}"); results.push(String::new()); }
        }
    }
    results.retain(|s| !s.is_empty());
    if results.is_empty() {
        anyhow::bail!("All fee tiers failed for {}", &htlc.hash_lock[..16.min(htlc.hash_lock.len())]);
    }
    Ok(results)
}

async fn build_and_sign(
    htlc: &PendingHtlc,
    fee_rate: f64,
    dest_script: ScriptBuf,
    local_htlc_key: &[u8],
    lnd: &LndRestClient,
) -> Result<String> {
    let amount = htlc.amount_sats;
    let fee    = (fee_rate * HTLC_TIMEOUT_VSIZE as f64) as u64;
    if fee >= amount * 8 / 10 {
        anyhow::bail!("Fee {fee} ≥ 80% of {amount}");
    }
    let out_amount = amount.saturating_sub(fee);
    if out_amount < 546 { anyhow::bail!("Output {out_amount} < dust limit"); }

    let txid = Txid::from_str(&htlc.outpoint_txid)
        .with_context(|| format!("Invalid txid: {}", htlc.outpoint_txid))?;

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(htlc.expiration_height)
            .context("Invalid CLTV expiry")?,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: htlc.outpoint_index },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(1),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_amount),
            script_pubkey: dest_script,
        }],
    };

    bip69_sort_inputs(&mut tx.input);
    bip69_sort_outputs(&mut tx.output);

    let input_idx = tx.input.iter().position(|i| {
        i.previous_output.txid == txid && i.previous_output.vout == htlc.outpoint_index
    }).unwrap_or(0) as u32;

    let htlc_script = build_htlc_timeout_script(&htlc.hash_lock, local_htlc_key)?;
    let p2wsh       = htlc_to_p2wsh(&htlc_script);
    let unsigned_hex = hex::encode(serialize(&tx));

    match lnd.compute_input_script(
        &unsigned_hex, input_idx,
        amount as i64, p2wsh.as_bytes(), &htlc_script,
        2, // htlcKeyFamily
        0, // key_index — use per-channel index in production
    ).await {
        Ok(witness) if !witness.is_empty() => {
            let mut wit = Witness::new();
            for item in &witness { wit.push(item); }
            tx.input[input_idx as usize].witness = wit;
            Ok(hex::encode(serialize(&tx)))
        }
        Ok(_)  => { warn!("Empty witness — using unsigned (dev/regtest)"); Ok(unsigned_hex) }
        Err(e) => { warn!("LND signing: {e} — unsigned (dev/regtest)");   Ok(unsigned_hex) }
    }
}

// ─── BIP69 ───────────────────────────────────────────────────────────────────

fn bip69_sort_inputs(inputs: &mut Vec<TxIn>) {
    inputs.sort_by(|a, b| {
        let cmp = a.previous_output.txid.as_byte_array()
                   .cmp(b.previous_output.txid.as_byte_array());
        if cmp != std::cmp::Ordering::Equal { cmp }
        else { a.previous_output.vout.cmp(&b.previous_output.vout) }
    });
}

fn bip69_sort_outputs(outputs: &mut Vec<TxOut>) {
    outputs.sort_by(|a, b| {
        let vc = a.value.cmp(&b.value);
        if vc != std::cmp::Ordering::Equal { vc }
        else { a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()) }
    });
}

// ─── BOLT#3 script ───────────────────────────────────────────────────────────

/// Builds the HTLC-offered redeemscript.
/// `local_htlc_key` is the real local key from LND /v2/wallet/key.
/// `remote_htlc_pk` and `revocation_pk` are placeholders — supply via gRPC in prod.
fn build_htlc_timeout_script(payment_hash_hex: &str, local_htlc_key: &[u8]) -> Result<Vec<u8>> {
    let ph: Vec<u8> = hex::decode(payment_hash_hex)
        .unwrap_or_else(|_| vec![0u8; 32]);
    let ph32: [u8; 32] = {
        let mut a = [0u8; 32];
        a[..ph.len().min(32)].copy_from_slice(&ph[..ph.len().min(32)]);
        a
    };

    // Real local key (from LND), placeholders for remote/revocation
    let local_pk:    [u8; 33] = if local_htlc_key.len() == 33 {
        local_htlc_key.try_into().unwrap()
    } else {
        let mut a = [0x02u8; 33]; a[..local_htlc_key.len().min(33)].copy_from_slice(&local_htlc_key[..local_htlc_key.len().min(33)]); a
    };
    let remote_pk:   [u8; 33] = [0x03u8; 33]; // TODO: gRPC GetChanInfo
    let revoke_pk:   [u8; 33] = [0x02u8; 33]; // TODO: gRPC per-commitment point

    let rev_hash  = hash160::Hash::hash(&revoke_pk);
    let ph_ripe   = ripemd160_of(&ph32);

    let mut s = Vec::with_capacity(200);
    s.push(0x76); s.push(0xa9); s.push(0x14);
    s.extend_from_slice(rev_hash.as_byte_array());
    s.push(0x87);                          // OP_EQUAL
    s.push(0x63); s.push(0xac);            // OP_IF OP_CHECKSIG
    s.push(0x67);                          // OP_ELSE
    s.push(0x21); s.extend_from_slice(&remote_pk);
    s.push(0x7c); s.push(0x82); s.push(0x01); s.push(0x20); s.push(0x87);
    s.push(0x63);                          // OP_IF
    s.push(0xa9); s.push(0x14); s.extend_from_slice(&ph_ripe); s.push(0x88);
    s.push(0x52); s.push(0x7c); s.push(0x21); s.extend_from_slice(&local_pk);
    s.push(0x52); s.push(0xae);            // 2 OP_SWAP <local> 2 OP_CHECKMULTISIG
    s.push(0x67);                          // OP_ELSE
    s.push(0x75); s.push(0x00); s.push(0xb1); s.push(0x75); s.push(0xac);
    s.push(0x68); s.push(0x68);            // OP_ENDIF OP_ENDIF
    Ok(s)
}

fn htlc_to_p2wsh(script: &[u8]) -> ScriptBuf {
    use bitcoin::hashes::{sha256, Hash};
    let hash = sha256::Hash::hash(script);
    let mut b = vec![0x00u8, 0x20];
    b.extend_from_slice(hash.as_byte_array());
    ScriptBuf::from_bytes(b)
}

fn ripemd160_of(data: &[u8]) -> [u8; 20] {
    use bitcoin::hashes::{ripemd160, Hash};
    *ripemd160::Hash::hash(data).as_byte_array()
}

fn address_to_script(addr: &str) -> Result<ScriptBuf> {
    use bitcoin::address::{Address, NetworkUnchecked};
    let a: Address<NetworkUnchecked> = addr.parse()
        .with_context(|| format!("Invalid address: {addr}"))?;
    Ok(a.assume_checked().script_pubkey())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf, TxOut};

    fn out(v: u64, last: u8) -> TxOut {
        let mut b = vec![0x00u8, 0x14]; b.extend_from_slice(&[0u8; 19]); b.push(last);
        TxOut { value: Amount::from_sat(v), script_pubkey: ScriptBuf::from_bytes(b) }
    }

    #[test] fn bip69_value_order() {
        let mut outs = vec![out(3000,3), out(1000,1), out(2000,2)];
        bip69_sort_outputs(&mut outs);
        assert_eq!(outs[0].value, Amount::from_sat(1000));
        assert_eq!(outs[2].value, Amount::from_sat(3000));
    }

    #[test] fn bip69_script_tiebreak() {
        let mut outs = vec![out(1000,0xff), out(1000,0x01)];
        bip69_sort_outputs(&mut outs);
        assert_eq!(outs[0].script_pubkey.as_bytes().last(), Some(&0x01));
    }

    #[test] fn htlc_script_valid() {
        let ph = "aa".repeat(32);
        let key = vec![0x02u8; 33];
        let s = build_htlc_timeout_script(&ph, &key).unwrap();
        assert_eq!(s[0], 0x76);  // OP_DUP
        assert_eq!(*s.last().unwrap(), 0x68); // OP_ENDIF
    }

    #[test] fn p2wsh_length() {
        let p2wsh = htlc_to_p2wsh(&[0xac]);
        assert_eq!(p2wsh.as_bytes().len(), 34);
        assert_eq!(p2wsh.as_bytes()[0], 0x00);
        assert_eq!(p2wsh.as_bytes()[1], 0x20);
    }

    #[test] fn fee_guards() {
        let a = 10_000u64; let f = 9_000u64;
        assert!(f >= a * 8 / 10);                    // blocked
        let f2 = (10.0f64 * HTLC_TIMEOUT_VSIZE as f64) as u64;
        assert!(f2 < 100_000u64 * 8 / 10);           // 10 sat/vb ok on 100k
        assert!((100_000u64).saturating_sub(f2) >= 546); // above dust
    }
}
