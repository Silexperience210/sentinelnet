//! Persistent HTLC + bounty store backed by sled.
//! Optionally encrypts values at rest using AES-256-GCM.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

// ─── Domain types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HtlcStatus {
    Watching,
    InMempool       { first_seen: DateTime<Utc> },
    DefensePending  { triggered_by: DateTime<Utc> },
    Defended        { at_block: u32, defense_txid: String, proof_hash: String,
                      broadcast_block: u32 },
    Confirmed       { at_block: u32 },
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedHtlc {
    pub txid:                   String,
    pub vout:                   u32,
    pub claim_txs:              Vec<String>,
    pub protected_node_pubkey:  String,
    pub cltv_expiry:            u32,
    pub amount_sats:            u64,
    pub registered_at:          DateTime<Utc>,
    pub status:                 HtlcStatus,
    pub defense_attempts:       u32,
    pub current_fee_tier:       usize,
}

impl WatchedHtlc {
    pub fn new(txid: String, vout: u32, claim_txs: Vec<String>,
               protected_node_pubkey: String, cltv_expiry: u32, amount_sats: u64) -> Self {
        WatchedHtlc {
            txid, vout, claim_txs, protected_node_pubkey,
            cltv_expiry, amount_sats,
            registered_at: Utc::now(),
            status: HtlcStatus::Watching,
            defense_attempts: 0, current_fee_tier: 0,
        }
    }
    pub fn current_claim_tx(&self) -> Option<&str> {
        self.claim_txs.get(self.current_fee_tier).map(|s| s.as_str())
    }
    pub fn escalate_fee(&mut self) {
        if self.current_fee_tier + 1 < self.claim_txs.len() {
            self.current_fee_tier += 1;
        }
    }
    pub fn hours_watched(&self) -> u64 {
        Utc::now().signed_duration_since(self.registered_at)
            .num_hours().max(0) as u64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBounty {
    pub id:                 String,
    pub htlc_txid:          String,
    pub defense_txid:       String,
    pub recipient_pubkey:   String,
    pub amount_sats:        u64,
    pub proof_hash:         String,
    pub created_at:         DateTime<Utc>,
    pub attempts:           u32,
    pub last_attempt:       Option<DateTime<Utc>>,
    pub paid:               bool,
    pub is_availability_fee: bool,
}

impl PendingBounty {
    pub fn new(htlc_txid: String, defense_txid: String, recipient_pubkey: String,
               amount_sats: u64, proof_hash: String) -> Self {
        let id = format!("{}_{}",
            &htlc_txid[..16.min(htlc_txid.len())], Utc::now().timestamp());
        PendingBounty {
            id, htlc_txid, defense_txid, recipient_pubkey,
            amount_sats, proof_hash,
            created_at: Utc::now(),
            attempts: 0, last_attempt: None,
            paid: false, is_availability_fee: false,
        }
    }
    pub fn should_retry(&self) -> bool {
        if self.paid || self.attempts >= 10 { return false; }
        match self.last_attempt {
            None => true,
            Some(last) => Utc::now().signed_duration_since(last).num_seconds() > 300,
        }
    }
}

// ─── Encryption helpers ───────────────────────────────────────────────────────

fn derive_aes_key(secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"sentinelnet-db-v1", &mut key).expect("HKDF expand");
    key
}

/// Deterministic nonce from the db key (12 bytes of SHA256(key))
fn nonce_from_db_key(db_key: &[u8]) -> [u8; 12] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(db_key);
    hash[..12].try_into().unwrap()
}

fn encrypt(plaintext: &[u8], db_key: &[u8], aes_key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
    let nonce  = Nonce::from(nonce_from_db_key(db_key));
    cipher.encrypt(&nonce, plaintext).map_err(|e| anyhow::anyhow!("Encrypt: {e}"))
}

fn decrypt(ciphertext: &[u8], db_key: &[u8], aes_key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key));
    let nonce  = Nonce::from(nonce_from_db_key(db_key));
    cipher.decrypt(&nonce, ciphertext).map_err(|e| anyhow::anyhow!("Decrypt: {e}"))
}

// ─── Store ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct HtlcStore {
    htlcs:    Arc<sled::Tree>,
    bounties: Arc<sled::Tree>,
    aes_key:  Option<[u8; 32]>,
}

impl HtlcStore {
    pub fn open(data_dir: &str, encryption_secret: Option<&str>) -> Result<Self> {
        let db      = sled::open(format!("{}/db", data_dir))
            .with_context(|| format!("Cannot open sled at {data_dir}"))?;
        let htlcs   = db.open_tree("htlcs")?;
        let bounties= db.open_tree("bounties")?;
        let aes_key = encryption_secret.map(derive_aes_key);
        if aes_key.is_some() {
            tracing::info!("Store: AES-256-GCM encryption enabled");
        }
        Ok(HtlcStore { htlcs: Arc::new(htlcs), bounties: Arc::new(bounties), aes_key })
    }

    fn encode(&self, key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
        match &self.aes_key {
            Some(k) => encrypt(value, key, k),
            None    => Ok(value.to_vec()),
        }
    }

    fn decode(&self, key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
        match &self.aes_key {
            Some(k) => decrypt(value, key, k),
            None    => Ok(value.to_vec()),
        }
    }

    // ── HTLC ─────────────────────────────────────────────────────────────────

    pub fn register(&self, htlc: &WatchedHtlc) -> Result<()> {
        let key   = htlc.txid.as_bytes().to_vec();
        let plain = serde_json::to_vec(htlc)?;
        let value = self.encode(&key, &plain)?;
        self.htlcs.insert(key, value)?;
        self.htlcs.flush()?;
        Ok(())
    }

    pub fn get(&self, txid: &str) -> Result<Option<WatchedHtlc>> {
        match self.htlcs.get(txid.as_bytes())? {
            Some(v) => {
                let plain = self.decode(txid.as_bytes(), &v)?;
                Ok(Some(serde_json::from_slice(&plain)?))
            }
            None => Ok(None),
        }
    }

    pub fn update(&self, htlc: &WatchedHtlc) -> Result<()> { self.register(htlc) }

    pub fn get_active(&self) -> Result<Vec<WatchedHtlc>> {
        self.get_all()?.into_iter().filter(|h| matches!(
            &h.status,
            HtlcStatus::Watching | HtlcStatus::InMempool { .. } | HtlcStatus::DefensePending { .. }
        )).collect::<Vec<_>>().pipe_ok()
    }

    pub fn get_all(&self) -> Result<Vec<WatchedHtlc>> {
        let mut result = Vec::new();
        for item in self.htlcs.iter() {
            let (k, v) = item?;
            let plain  = self.decode(&k, &v)?;
            result.push(serde_json::from_slice::<WatchedHtlc>(&plain)?);
        }
        Ok(result)
    }

    // ── Bounty ───────────────────────────────────────────────────────────────

    pub fn save_bounty(&self, b: &PendingBounty) -> Result<()> {
        let key   = b.id.as_bytes().to_vec();
        let plain = serde_json::to_vec(b)?;
        let value = self.encode(&key, &plain)?;
        self.bounties.insert(key, value)?;
        self.bounties.flush()?;
        Ok(())
    }

    pub fn get_pending_bounties(&self) -> Result<Vec<PendingBounty>> {
        self.get_all_bounties()?.into_iter()
            .filter(|b| !b.paid && b.should_retry())
            .collect::<Vec<_>>().pipe_ok()
    }

    pub fn get_all_bounties(&self) -> Result<Vec<PendingBounty>> {
        let mut result = Vec::new();
        for item in self.bounties.iter() {
            let (k, v) = item?;
            let plain  = self.decode(&k, &v)?;
            result.push(serde_json::from_slice::<PendingBounty>(&plain)?);
        }
        Ok(result)
    }

    pub fn mark_bounty_paid(&self, id: &str) -> Result<()> {
        if let Some(v) = self.bounties.get(id.as_bytes())? {
            let plain = self.decode(id.as_bytes(), &v)?;
            let mut b: PendingBounty = serde_json::from_slice(&plain)?;
            b.paid = true;
            self.save_bounty(&b)?;
        }
        Ok(())
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    pub fn stats(&self) -> Result<StoreStats> {
        let all      = self.get_all()?;
        let bounties = self.get_all_bounties()?;
        let mut s    = StoreStats { total: all.len(), ..Default::default() };
        for h in &all {
            match &h.status {
                HtlcStatus::Watching           => s.watching        += 1,
                HtlcStatus::InMempool { .. }   => s.in_mempool      += 1,
                HtlcStatus::DefensePending {..}=> s.defense_pending += 1,
                HtlcStatus::Defended { .. }    => s.defended        += 1,
                HtlcStatus::Confirmed { .. }   => s.confirmed       += 1,
                HtlcStatus::Expired            => s.expired         += 1,
            }
        }
        s.bounties_paid    = bounties.iter().filter(|b|  b.paid).count();
        s.bounties_pending = bounties.iter().filter(|b| !b.paid).count();
        Ok(s)
    }
}

// Tiny helper to avoid .collect::<Vec<_>>().into_iter() boilerplate
trait PipeOk: Sized { fn pipe_ok(self) -> Result<Self> { Ok(self) } }
impl<T> PipeOk for Vec<T> {}

#[derive(Debug, Default)]
pub struct StoreStats {
    pub total: usize, pub watching: usize, pub in_mempool: usize,
    pub defense_pending: usize, pub defended: usize, pub confirmed: usize,
    pub expired: usize, pub bounties_paid: usize, pub bounties_pending: usize,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_store(encrypt: bool) -> (HtlcStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let secret = if encrypt { Some("test_secret") } else { None };
        (HtlcStore::open(dir.path().to_str().unwrap(), secret).unwrap(), dir)
    }

    fn sample_htlc(txid: &str) -> WatchedHtlc {
        WatchedHtlc::new(txid.to_string(), 0, vec!["deadbeef".into()],
            "02".repeat(33), 800_000, 100_000)
    }

    #[test] fn test_register_and_get() {
        let (store, _d) = temp_store(false);
        let h = sample_htlc(&"a".repeat(64));
        store.register(&h).unwrap();
        let got = store.get(&"a".repeat(64)).unwrap().unwrap();
        assert_eq!(got.amount_sats, 100_000);
    }

    #[test] fn test_encrypted_roundtrip() {
        let (store, _d) = temp_store(true);
        let h = sample_htlc(&"b".repeat(64));
        store.register(&h).unwrap();
        let got = store.get(&"b".repeat(64)).unwrap().unwrap();
        assert_eq!(got.cltv_expiry, 800_000);
    }

    #[test] fn test_active_filter() {
        let (store, _d) = temp_store(false);
        store.register(&sample_htlc(&"c".repeat(64))).unwrap();
        let mut expired = sample_htlc(&"d".repeat(64));
        expired.status = HtlcStatus::Expired;
        store.register(&expired).unwrap();
        let active = store.get_active().unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test] fn test_bounty_retry_logic() {
        let b = PendingBounty::new("htlc".into(), "def".into(), "pub".into(), 500, "hash".into());
        assert!(b.should_retry()); // New bounty should be tried
        let mut exhausted = b.clone();
        exhausted.attempts = 10;
        assert!(!exhausted.should_retry());
        let mut paid = b.clone();
        paid.paid = true;
        assert!(!paid.should_retry());
    }
}
