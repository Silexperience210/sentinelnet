use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HtlcStatus {
    Watching,
    InMempool { first_seen: DateTime<Utc> },
    DefensePending { triggered_by: DateTime<Utc> },
    Defended { at_block: u32, defense_txid: String, proof_hash: String },
    Confirmed { at_block: u32 },
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedHtlc {
    pub txid: String,
    pub vout: u32,
    pub claim_txs: Vec<String>,
    pub protected_node_pubkey: String,
    pub cltv_expiry: u32,
    pub amount_sats: u64,
    pub registered_at: DateTime<Utc>,
    pub status: HtlcStatus,
    pub defense_attempts: u32,
    pub current_fee_tier: usize,
}

impl WatchedHtlc {
    pub fn new(txid: String, vout: u32, claim_txs: Vec<String>,
               protected_node_pubkey: String, cltv_expiry: u32, amount_sats: u64) -> Self {
        WatchedHtlc {
            txid, vout, claim_txs, protected_node_pubkey,
            cltv_expiry, amount_sats,
            registered_at: Utc::now(),
            status: HtlcStatus::Watching,
            defense_attempts: 0,
            current_fee_tier: 0,
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
}

/// Pending bounty — persisted for retry if first keysend fails
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBounty {
    pub id: String,
    pub htlc_txid: String,
    pub defense_txid: String,
    pub recipient_pubkey: String,
    pub amount_sats: u64,
    pub proof_hash: String,
    pub created_at: DateTime<Utc>,
    pub attempts: u32,
    pub last_attempt: Option<DateTime<Utc>>,
    pub paid: bool,
}

impl PendingBounty {
    pub fn new(htlc_txid: String, defense_txid: String, recipient_pubkey: String,
               amount_sats: u64, proof_hash: String) -> Self {
        let id = format!("{}_{}", &htlc_txid[..16], Utc::now().timestamp());
        PendingBounty {
            id, htlc_txid, defense_txid, recipient_pubkey,
            amount_sats, proof_hash,
            created_at: Utc::now(),
            attempts: 0,
            last_attempt: None,
            paid: false,
        }
    }

    /// Should we retry? Wait 5min between attempts, max 10 attempts
    pub fn should_retry(&self) -> bool {
        if self.paid || self.attempts >= 10 { return false; }
        match self.last_attempt {
            None => true,
            Some(last) => Utc::now().signed_duration_since(last).num_seconds() > 300,
        }
    }
}

#[derive(Clone)]
pub struct HtlcStore {
    htlcs: Arc<sled::Tree>,
    bounties: Arc<sled::Tree>,
}

impl HtlcStore {
    pub fn open(data_dir: &str) -> Result<Self> {
        let db = sled::open(format!("{}/db", data_dir))
            .with_context(|| format!("Failed to open sled DB at {data_dir}"))?;
        let htlcs = db.open_tree("htlcs")?;
        let bounties = db.open_tree("bounties")?;
        Ok(HtlcStore { htlcs: Arc::new(htlcs), bounties: Arc::new(bounties) })
    }

    // ── HTLC operations ──────────────────────────────────────────────────────

    pub fn register(&self, htlc: &WatchedHtlc) -> Result<()> {
        let key = htlc.txid.as_bytes().to_vec();
        self.htlcs.insert(key, serde_json::to_vec(htlc)?)?;
        self.htlcs.flush()?;
        Ok(())
    }

    pub fn get(&self, txid: &str) -> Result<Option<WatchedHtlc>> {
        match self.htlcs.get(txid.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    pub fn update(&self, htlc: &WatchedHtlc) -> Result<()> {
        self.register(htlc)
    }

    pub fn get_active(&self) -> Result<Vec<WatchedHtlc>> {
        let mut result = Vec::new();
        for item in self.htlcs.iter() {
            let (_, v) = item?;
            let htlc: WatchedHtlc = serde_json::from_slice(&v)?;
            if matches!(&htlc.status,
                HtlcStatus::Watching | HtlcStatus::InMempool { .. } | HtlcStatus::DefensePending { .. }) {
                result.push(htlc);
            }
        }
        Ok(result)
    }

    pub fn get_all(&self) -> Result<Vec<WatchedHtlc>> {
        self.htlcs.iter()
            .map(|r| r.map_err(Into::into).and_then(|(_, v)| Ok(serde_json::from_slice(&v)?)))
            .collect()
    }

    // ── Bounty operations ────────────────────────────────────────────────────

    pub fn save_bounty(&self, bounty: &PendingBounty) -> Result<()> {
        self.bounties.insert(bounty.id.as_bytes(), serde_json::to_vec(bounty)?)?;
        self.bounties.flush()?;
        Ok(())
    }

    pub fn get_pending_bounties(&self) -> Result<Vec<PendingBounty>> {
        let mut result = Vec::new();
        for item in self.bounties.iter() {
            let (_, v) = item?;
            let b: PendingBounty = serde_json::from_slice(&v)?;
            if !b.paid && b.should_retry() {
                result.push(b);
            }
        }
        Ok(result)
    }

    pub fn mark_bounty_paid(&self, id: &str) -> Result<()> {
        if let Some(v) = self.bounties.get(id.as_bytes())? {
            let mut b: PendingBounty = serde_json::from_slice(&v)?;
            b.paid = true;
            self.bounties.insert(id.as_bytes(), serde_json::to_vec(&b)?)?;
        }
        Ok(())
    }

    // ── Stats ────────────────────────────────────────────────────────────────

    pub fn stats(&self) -> Result<StoreStats> {
        let all = self.get_all()?;
        let mut s = StoreStats::default();
        s.total = all.len();
        for h in &all {
            match &h.status {
                HtlcStatus::Watching => s.watching += 1,
                HtlcStatus::InMempool { .. } => s.in_mempool += 1,
                HtlcStatus::DefensePending { .. } => s.defense_pending += 1,
                HtlcStatus::Defended { .. } => s.defended += 1,
                HtlcStatus::Confirmed { .. } => s.confirmed += 1,
                HtlcStatus::Expired => s.expired += 1,
            }
        }
        let all_bounties: Vec<_> = self.bounties.iter()
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| serde_json::from_slice::<PendingBounty>(&v).ok())
            .collect();
        s.bounties_paid = all_bounties.iter().filter(|b| b.paid).count();
        s.bounties_pending = all_bounties.iter().filter(|b| !b.paid).count();
        Ok(s)
    }
}

#[derive(Debug, Default)]
pub struct StoreStats {
    pub total: usize,
    pub watching: usize,
    pub in_mempool: usize,
    pub defense_pending: usize,
    pub defended: usize,
    pub confirmed: usize,
    pub expired: usize,
    pub bounties_paid: usize,
    pub bounties_pending: usize,
}
