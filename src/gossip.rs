//! Authenticated gossip mesh.
//!
//! Fixes applied:
//!  5  – WatchRequest actually registers HTLC in local store
//!  7  – Reconnection retry loop for offline peers
//!  12 – Version field in envelope; mismatched versions rejected

use crate::store::{HtlcStore, WatchedHtlc};
use anyhow::Result;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{interval, sleep, Duration};
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

const GOSSIP_VERSION: u32   = 1;
const MAX_MSG_SIZE: usize   = 65536;
const REPLAY_WINDOW_SECS: i64 = 60;
const RECONNECT_INTERVAL_SECS: u64 = 300; // 5 min

// ─── Envelope ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipEnvelope {
    /// Protocol version — reject if != GOSSIP_VERSION
    pub version:   u32,
    pub payload:   String,
    pub hmac:      String,
    pub sender:    String,
    pub timestamp: i64,
}

impl GossipEnvelope {
    pub fn sign(msg: &GossipMessage, sender: &str, secret: &str) -> Result<Self> {
        let timestamp = Utc::now().timestamp();
        let payload   = serde_json::to_string(msg)?;
        let hmac      = compute_hmac(&payload, timestamp, secret);
        Ok(GossipEnvelope { version: GOSSIP_VERSION, payload, hmac, sender: sender.into(), timestamp })
    }

    pub fn verify_and_open(&self, secret: &str) -> Result<GossipMessage> {
        if self.version != GOSSIP_VERSION {
            anyhow::bail!("Gossip version mismatch: got {}, want {GOSSIP_VERSION}", self.version);
        }
        let age = (Utc::now().timestamp() - self.timestamp).abs();
        if age > REPLAY_WINDOW_SECS {
            anyhow::bail!("Message too old: {age}s");
        }
        let expected = compute_hmac(&self.payload, self.timestamp, secret);
        if !ct_eq(&expected, &self.hmac) {
            anyhow::bail!("Invalid HMAC from {}", self.sender);
        }
        Ok(serde_json::from_str(&self.payload)?)
    }
}

fn compute_hmac(payload: &str, ts: i64, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    mac.update(b"||");
    mac.update(ts.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ─── Messages ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GossipMessage {
    Hello {
        sentinel_pubkey: String, sentinel_addr: String,
        htlcs_watching: usize, timestamp: i64,
    },
    AttackAlert {
        htlc_txid: String, reporter_pubkey: String,
        attack_type: String, timestamp: i64,
    },
    DefenseAnnouncement {
        htlc_txid: String, defense_txid: String,
        defender_pubkey: String, proof_hash: String, timestamp: i64,
    },
    /// Fix 5: WatchRequest now actually registered by recipient
    WatchRequest {
        htlc_txid: String, claim_tx_hex: String,
        cltv_expiry: u32, amount_sats: u64,
        protected_node_pubkey: String,
    },
    Pong { sentinel_pubkey: String },
}

// ─── Server ──────────────────────────────────────────────────────────────────

pub struct GossipServer {
    port:           u16,
    store:          HtlcStore,
    sentinel_pubkey: String,
    shared_secret:  String,
    broadcast_tx:   broadcast::Sender<GossipMessage>,
}

impl GossipServer {
    pub fn new(port: u16, store: HtlcStore, sentinel_pubkey: String,
               shared_secret: String, broadcast_tx: broadcast::Sender<GossipMessage>) -> Self {
        GossipServer { port, store, sentinel_pubkey, shared_secret, broadcast_tx }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        info!("Gossip server on :{} (v{GOSSIP_VERSION}, HMAC-SHA256)", self.port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let store  = self.store.clone();
                    let pubkey = self.sentinel_pubkey.clone();
                    let secret = self.shared_secret.clone();
                    let tx     = self.broadcast_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_peer(stream, addr, store, pubkey, secret, tx).await {
                            debug!("Peer {addr}: {e}");
                        }
                    });
                }
                Err(e) => error!("Accept: {e}"),
            }
        }
    }
}

async fn handle_peer(
    mut stream: TcpStream,
    addr: SocketAddr,
    store: HtlcStore,
    pubkey: String,
    secret: String,
    tx: broadcast::Sender<GossipMessage>,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_MSG_SIZE];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 { break; }

        let env: GossipEnvelope = match serde_json::from_slice(&buf[..n]) {
            Ok(e) => e,
            Err(e) => { warn!("Bad envelope from {addr}: {e}"); continue; }
        };

        let msg = match env.verify_and_open(&secret) {
            Ok(m)  => { crate::metrics::get().gossip_messages_rx.with_label_values(&[msg_type(&m)]).inc(); m }
            Err(e) => { warn!("⚠️  Rejected from {addr}: {e}"); continue; }
        };

        match &msg {
            GossipMessage::Hello { sentinel_addr, htlcs_watching, .. } => {
                info!("👋 {sentinel_addr} watching {htlcs_watching} HTLCs");
                let pong = GossipMessage::Pong { sentinel_pubkey: pubkey.clone() };
                if let Ok(env) = GossipEnvelope::sign(&pong, &pubkey, &secret) {
                    let _ = stream.write_all(&serde_json::to_vec(&env)?).await;
                }
            }

            // Fix 5: actually register the HTLC
            GossipMessage::WatchRequest { htlc_txid, claim_tx_hex, cltv_expiry, amount_sats, protected_node_pubkey } => {
                info!("📋 WatchRequest for {}", &htlc_txid[..16.min(htlc_txid.len())]);
                if let Ok(None) = store.get(htlc_txid) {
                    let htlc = WatchedHtlc::new(
                        htlc_txid.clone(), 0,
                        vec![claim_tx_hex.clone()],
                        protected_node_pubkey.clone(),
                        *cltv_expiry, *amount_sats,
                    );
                    if let Err(e) = store.register(&htlc) {
                        error!("Failed to register gossiped HTLC: {e}");
                    } else {
                        crate::metrics::get().htlcs_registered.inc();
                    }
                }
                let _ = tx.send(msg.clone());
            }

            GossipMessage::AttackAlert { htlc_txid, attack_type, reporter_pubkey, .. } => {
                warn!("🚨 Alert from {}: {attack_type} on {}",
                    &reporter_pubkey[..16.min(reporter_pubkey.len())],
                    &htlc_txid[..16.min(htlc_txid.len())]);
                let _ = tx.send(msg.clone());
            }

            GossipMessage::DefenseAnnouncement { htlc_txid, defender_pubkey, .. } => {
                info!("🛡️  Defense from {} on {}",
                    &defender_pubkey[..16.min(defender_pubkey.len())],
                    &htlc_txid[..16.min(htlc_txid.len())]);
                let _ = tx.send(msg.clone());
            }
            _ => {}
        }
    }
    Ok(())
}

// ─── Client (Fix 7: reconnection) ────────────────────────────────────────────

pub struct GossipClient {
    peers:           Vec<String>,
    pubkey:          String,
    addr:            String,
    secret:          String,
    store:           HtlcStore,
    bcast_interval:  u64,
    rx:              broadcast::Receiver<GossipMessage>,
    failed_peers:    Arc<Mutex<HashSet<String>>>,
}

impl GossipClient {
    pub fn new(peers: Vec<String>, pubkey: String, addr: String,
               secret: String, store: HtlcStore, bcast_interval: u64,
               rx: broadcast::Receiver<GossipMessage>) -> Self {
        GossipClient { peers, pubkey, addr, secret, store, bcast_interval, rx,
                       failed_peers: Arc::new(Mutex::new(HashSet::new())) }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("GossipClient: {} peers (v{GOSSIP_VERSION})", self.peers.len());
        let mut heartbeat  = interval(Duration::from_secs(self.bcast_interval));
        let mut reconnect  = interval(Duration::from_secs(RECONNECT_INTERVAL_SECS));

        loop {
            tokio::select! {
                _ = heartbeat.tick() => self.broadcast_hello().await,
                _ = reconnect.tick() => self.retry_failed_peers().await,
                Ok(msg) = self.rx.recv() => self.broadcast_to_peers(&msg).await,
            }
        }
    }

    async fn broadcast_hello(&self) {
        let n = self.store.get_active().map(|h| h.len()).unwrap_or(0);
        let hello = GossipMessage::Hello {
            sentinel_pubkey: self.pubkey.clone(), sentinel_addr: self.addr.clone(),
            htlcs_watching: n, timestamp: Utc::now().timestamp(),
        };
        crate::metrics::get().gossip_messages_tx.with_label_values(&["Hello"]).inc();
        self.broadcast_to_peers(&hello).await;
    }

    // Fix 7: retry peers that were offline
    async fn retry_failed_peers(&self) {
        let failed: Vec<String> = self.failed_peers.lock().unwrap().iter().cloned().collect();
        if failed.is_empty() { return; }
        info!("Retrying {} offline gossip peer(s)…", failed.len());
        for peer in &failed {
            if TcpStream::connect(peer).await.is_ok() {
                info!("Peer {peer} back online ✅");
                self.failed_peers.lock().unwrap().remove(peer);
            }
        }
    }

    async fn broadcast_to_peers(&self, msg: &GossipMessage) {
        let env = match GossipEnvelope::sign(msg, &self.pubkey, &self.secret) {
            Ok(e)  => e,
            Err(e) => { error!("Sign error: {e}"); return; }
        };
        let bytes = match serde_json::to_vec(&env) {
            Ok(b)  => b,
            Err(e) => { error!("Serialize: {e}"); return; }
        };

        for peer in &self.peers {
            match TcpStream::connect(peer).await {
                Ok(mut s) => {
                    if let Err(e) = s.write_all(&bytes).await {
                        debug!("Send to {peer}: {e}");
                    } else {
                        crate::metrics::get()
                            .gossip_messages_tx.with_label_values(&[msg_type(msg)]).inc();
                        // Peer responded — remove from failed list
                        self.failed_peers.lock().unwrap().remove(peer);
                    }
                }
                Err(_) => {
                    debug!("Peer {peer} unreachable — marking failed");
                    self.failed_peers.lock().unwrap().insert(peer.clone());
                }
            }
        }
    }
}

fn msg_type(m: &GossipMessage) -> &'static str {
    match m {
        GossipMessage::Hello {..}               => "Hello",
        GossipMessage::AttackAlert {..}         => "AttackAlert",
        GossipMessage::DefenseAnnouncement {..} => "Defense",
        GossipMessage::WatchRequest {..}        => "WatchRequest",
        GossipMessage::Pong {..}               => "Pong",
    }
}
