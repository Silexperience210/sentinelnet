use crate::defense::TriggerReason;
use chrono::Utc;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// A cryptographic proof that a sentinel successfully defended an HTLC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDefense {
    /// The original HTLC txid that was being attacked
    pub htlc_txid: String,
    /// The defense transaction txid broadcast by this sentinel
    pub defense_txid: String,
    /// Unix timestamp of the defense action
    pub timestamp: i64,
    /// Number of defense attempts before success
    pub attempt_number: u32,
    /// What triggered the defense
    pub trigger: String,
    /// SHA256 hash chain: hash(htlc_txid || defense_txid || timestamp || attempt)
    pub proof_hash: String,
    /// Second-level hash for verification: hash(proof_hash || sentinel_signature)
    pub verification_hash: String,
}

/// Build a compact proof hash (stored in HTLC record)
pub fn build_proof(
    htlc_txid: &str,
    defense_txid: &str,
    trigger: &TriggerReason,
    attempt: u32,
) -> String {
    let timestamp = Utc::now().timestamp();
    let trigger_str = format!("{trigger:?}");

    let mut hasher = Sha256::new();
    hasher.update(htlc_txid.as_bytes());
    hasher.update(b"||");
    hasher.update(defense_txid.as_bytes());
    hasher.update(b"||");
    hasher.update(timestamp.to_string().as_bytes());
    hasher.update(b"||");
    hasher.update(attempt.to_string().as_bytes());
    hasher.update(b"||");
    hasher.update(trigger_str.as_bytes());

    let result = hasher.finalize();
    hex::encode(result)
}

/// Build a full verifiable proof (sent to protected node for bounty release)
pub fn build_full_proof(
    htlc_txid: &str,
    defense_txid: &str,
    trigger: &TriggerReason,
    attempt: u32,
    sentinel_pubkey: &str,
) -> ProofOfDefense {
    let timestamp = Utc::now().timestamp();
    let trigger_str = format!("{trigger:?}");

    // Layer 1: core proof
    let proof_hash = build_proof(htlc_txid, defense_txid, trigger, attempt);

    // Layer 2: bind to sentinel identity
    let mut hasher2 = Sha256::new();
    hasher2.update(proof_hash.as_bytes());
    hasher2.update(b"||");
    hasher2.update(sentinel_pubkey.as_bytes());
    hasher2.update(b"||");
    hasher2.update(timestamp.to_string().as_bytes());
    let verification_hash = hex::encode(hasher2.finalize());

    ProofOfDefense {
        htlc_txid: htlc_txid.to_string(),
        defense_txid: defense_txid.to_string(),
        timestamp,
        attempt_number: attempt,
        trigger: trigger_str,
        proof_hash,
        verification_hash,
    }
}

/// Verify a proof of defense
/// The protected node calls this before releasing the bounty
pub fn verify_proof(proof: &ProofOfDefense, sentinel_pubkey: &str) -> bool {
    // Recompute layer 1
    let trigger = proof.trigger.clone();
    let mut hasher = Sha256::new();
    hasher.update(proof.htlc_txid.as_bytes());
    hasher.update(b"||");
    hasher.update(proof.defense_txid.as_bytes());
    hasher.update(b"||");
    hasher.update(proof.timestamp.to_string().as_bytes());
    hasher.update(b"||");
    hasher.update(proof.attempt_number.to_string().as_bytes());
    hasher.update(b"||");
    hasher.update(trigger.as_bytes());
    let expected_proof_hash = hex::encode(hasher.finalize());

    if expected_proof_hash != proof.proof_hash {
        return false;
    }

    // Recompute layer 2
    let mut hasher2 = Sha256::new();
    hasher2.update(proof.proof_hash.as_bytes());
    hasher2.update(b"||");
    hasher2.update(sentinel_pubkey.as_bytes());
    hasher2.update(b"||");
    hasher2.update(proof.timestamp.to_string().as_bytes());
    let expected_verification = hex::encode(hasher2.finalize());

    expected_verification == proof.verification_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defense::TriggerReason;

    #[test]
    fn test_proof_roundtrip() {
        let htlc_txid = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";
        let defense_txid = "def456abc123def456abc123def456abc123def456abc123def456abc123def4";
        let sentinel_pubkey = "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
        let trigger = TriggerReason::ReplacementCycling;

        let proof = build_full_proof(htlc_txid, defense_txid, &trigger, 1, sentinel_pubkey);
        assert!(verify_proof(&proof, sentinel_pubkey));
        assert!(!verify_proof(&proof, "wrong_pubkey"));
    }

    #[test]
    fn test_proof_tamper_detection() {
        let htlc_txid = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";
        let defense_txid = "def456abc123def456abc123def456abc123def456abc123def456abc123def4";
        let sentinel_pubkey = "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678";
        let trigger = TriggerReason::ReplacementCycling;

        let mut proof = build_full_proof(htlc_txid, defense_txid, &trigger, 1, sentinel_pubkey);
        // Tamper with the defense txid
        proof.defense_txid = "tampered".to_string();
        assert!(!verify_proof(&proof, sentinel_pubkey));
    }
}
