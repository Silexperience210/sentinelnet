use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Status of a watched HTLC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HtlcStatus {
    /// Actively being monitored
    Watching,
    /// Seen in mempool, tracking
    InMempool { first_seen: DateTime<Utc> },
    /// Disappeared from mempool before confirmation — defense triggered
    DefensePending { triggered_by: DateTime<Utc> },
    /// Defense tx broadcast successfully
    Defended {
        at_block: u32,
        defense_txid: String,
        proof_hash: String,
    },
    /// HTLC confirmed on-chain normally — no defense needed
    Confirmed { at_block: u32 },
    /// HTLC expired without defense (failure case)
    Expired,
}

/// A registered HTLC that this sentinel is watching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedHtlc {
    /// Transaction ID of the HTLC output transaction
    pub txid: String,
    /// Output index in that transaction
    pub vout: u32,
    /// Pre-signed claim transactions at increasing fee rates
    /// Index 0 = base fee, 1 = 2x, 2 = 5x, 3 = 10x
    pub claim_txs: Vec<String>, // raw hex
    /// Protected node's LND pubkey (for bounty payment)
    pub protected_node_pubkey: String,
    /// CLTV expiry block height
    pub cltv_expiry: u32,
    /// Amount at stake (sats)
    pub amount_sats: u64,
    /// When this HTLC was registered with this sentinel
    pub registered_at: DateTime<Utc>,
    /// Current status
    pub status: HtlcStatus,
    /// Number of defense attempts
    pub defense_attempts: u32,
    /// Fee tier currently in use (index into claim_txs)
    pub current_fee_tier: usize,
}

impl WatchedHtlc {
    pub fn new(
        txid: String,
        vout: u32,
        claim_txs: Vec<String>,
        protected_node_pubkey: String,
        cltv_expiry: u32,
        amount_sats: u64,
    ) -> Self {
        WatchedHtlc {
            txid,
            vout,
            claim_txs,
            protected_node_pubkey,
            cltv_expiry,
            amount_sats,
            registered_at: Utc::now(),
            status: HtlcStatus::Watching,
            defense_attempts: 0,
            current_fee_tier: 0,
        }
    }

    /// Get the claim tx for current fee tier (escalates on retries)
    pub fn current_claim_tx(&self) -> Option<&str> {
        self.claim_txs.get(self.current_fee_tier).map(|s| s.as_str())
    }

    /// Escalate to next fee tier
    pub fn escalate_fee(&mut self) {
        if self.current_fee_tier + 1 < self.claim_txs.len() {
            self.current_fee_tier += 1;
        }
    }
}

/// Thread-safe HTLC store backed by sled
#[derive(Clone)]
pub struct HtlcStore {
    db: Arc<sled::Db>,
}

impl HtlcStore {
    pub fn open(data_dir: &str) -> Result<Self> {
        let db_path = format!("{}/htlc_store", data_dir);
        let db = sled::open(&db_path)
            .with_context(|| format!("Failed to open sled DB at {db_path}"))?;
        Ok(HtlcStore { db: Arc::new(db) })
    }

    /// Register a new HTLC for watching
    pub fn register(&self, htlc: &WatchedHtlc) -> Result<()> {
        let key = htlc.txid.as_bytes().to_vec();
        let value = serde_json::to_vec(htlc)?;
        self.db.insert(key, value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get an HTLC by txid
    pub fn get(&self, txid: &str) -> Result<Option<WatchedHtlc>> {
        match self.db.get(txid.as_bytes())? {
            Some(bytes) => {
                let htlc: WatchedHtlc = serde_json::from_slice(&bytes)?;
                Ok(Some(htlc))
            }
            None => Ok(None),
        }
    }

    /// Update an HTLC's status
    pub fn update(&self, htlc: &WatchedHtlc) -> Result<()> {
        self.register(htlc)
    }

    /// Get all actively watched HTLCs
    pub fn get_active(&self) -> Result<Vec<WatchedHtlc>> {
        let mut result = Vec::new();
        for item in self.db.iter() {
            let (_, value) = item?;
            let htlc: WatchedHtlc = serde_json::from_slice(&value)?;
            match &htlc.status {
                HtlcStatus::Watching
                | HtlcStatus::InMempool { .. }
                | HtlcStatus::DefensePending { .. } => result.push(htlc),
                _ => {}
            }
        }
        Ok(result)
    }

    /// Get all HTLCs (for stats/debug)
    pub fn get_all(&self) -> Result<Vec<WatchedHtlc>> {
        let mut result = Vec::new();
        for item in self.db.iter() {
            let (_, value) = item?;
            let htlc: WatchedHtlc = serde_json::from_slice(&value)?;
            result.push(htlc);
        }
        Ok(result)
    }

    /// Count HTLCs by status type
    pub fn stats(&self) -> Result<StoreStats> {
        let all = self.get_all()?;
        let mut stats = StoreStats::default();
        stats.total = all.len();
        for htlc in &all {
            match &htlc.status {
                HtlcStatus::Watching => stats.watching += 1,
                HtlcStatus::InMempool { .. } => stats.in_mempool += 1,
                HtlcStatus::DefensePending { .. } => stats.defense_pending += 1,
                HtlcStatus::Defended { .. } => stats.defended += 1,
                HtlcStatus::Confirmed { .. } => stats.confirmed += 1,
                HtlcStatus::Expired => stats.expired += 1,
            }
        }
        Ok(stats)
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
}
