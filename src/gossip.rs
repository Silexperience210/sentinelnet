use crate::store::HtlcStore;
use anyhow::Result;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

const MAX_MESSAGE_SIZE: usize = 65536;

// ─── Wire format ─────────────────────────────────────────────────────────────

/// Authenticated gossip envelope — wraps any GossipMessage with an HMAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipEnvelope {
    /// Base64-encoded JSON of the inner GossipMessage
    pub payload: String,
    /// HMAC-SHA256(shared_secret, payload) as hex
    pub hmac: String,
    /// Sender pubkey (for dedup / logging)
    pub sender: String,
    /// Unix timestamp (for replay protection — reject if >60s old)
    pub timestamp: i64,
}

impl GossipEnvelope {
    /// Sign and create an envelope
    pub fn sign(msg: &GossipMessage, sender: &str, shared_secret: &str) -> Result<Self> {
        let timestamp = Utc::now().timestamp();
        let payload = serde_json::to_string(msg)?;
        let hmac = compute_hmac(&payload, timestamp, shared_secret);
        Ok(GossipEnvelope {
            payload,
            hmac,
            sender: sender.to_string(),
            timestamp,
        })
    }

    /// Verify the HMAC and timestamp, return the inner message
    pub fn verify_and_open(&self, shared_secret: &str) -> Result<GossipMessage> {
        // Replay protection: reject messages older than 60 seconds
        let now = Utc::now().timestamp();
        let age = (now - self.timestamp).abs();
        if age > 60 {
            anyhow::bail!("Gossip message too old: {age}s (max 60s)");
        }

        // Verify HMAC
        let expected = compute_hmac(&self.payload, self.timestamp, shared_secret);
        if !constant_time_eq(&expected, &self.hmac) {
            anyhow::bail!("Invalid gossip HMAC from {}", self.sender);
        }

        let msg: GossipMessage = serde_json::from_str(&self.payload)?;
        Ok(msg)
    }
}

fn compute_hmac(payload: &str, timestamp: i64, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    mac.update(b"||");
    mac.update(timestamp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time string comparison (prevents timing attacks)
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ─── Message types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GossipMessage {
    Hello {
        sentinel_pubkey: String,
        sentinel_addr: String,
        htlcs_watching: usize,
        timestamp: i64,
    },
    AttackAlert {
        htlc_txid: String,
        reporter_pubkey: String,
        attack_type: String,
        timestamp: i64,
    },
    DefenseAnnouncement {
        htlc_txid: String,
        defense_txid: String,
        defender_pubkey: String,
        proof_hash: String,
        timestamp: i64,
    },
    WatchRequest {
        htlc_txid: String,
        claim_tx_hex: String,
        cltv_expiry: u32,
        amount_sats: u64,
        protected_node_pubkey: String,
    },
    Pong {
        sentinel_pubkey: String,
    },
}

// ─── Server ──────────────────────────────────────────────────────────────────

pub struct GossipServer {
    port: u16,
    store: HtlcStore,
    sentinel_pubkey: String,
    shared_secret: String,
    broadcast_tx: broadcast::Sender<GossipMessage>,
}

impl GossipServer {
    pub fn new(
        port: u16,
        store: HtlcStore,
        sentinel_pubkey: String,
        shared_secret: String,
        broadcast_tx: broadcast::Sender<GossipMessage>,
    ) -> Self {
        GossipServer { port, store, sentinel_pubkey, shared_secret, broadcast_tx }
    }

    pub async fn run(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Gossip server listening on {addr} (HMAC-SHA256 authenticated)");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let store = self.store.clone();
                    let pubkey = self.sentinel_pubkey.clone();
                    let secret = self.shared_secret.clone();
                    let tx = self.broadcast_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_peer(stream, peer_addr, store, pubkey, secret, tx).await {
                            debug!("Peer {peer_addr} disconnected: {e}");
                        }
                    });
                }
                Err(e) => error!("Gossip accept error: {e}"),
            }
        }
    }
}

async fn handle_peer(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    _store: HtlcStore,
    sentinel_pubkey: String,
    shared_secret: String,
    broadcast_tx: broadcast::Sender<GossipMessage>,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 { break; }

        // Deserialize envelope
        let envelope: GossipEnvelope = match serde_json::from_slice(&buf[..n]) {
            Ok(e) => e,
            Err(e) => {
                warn!("Bad envelope from {peer_addr}: {e}");
                continue;
            }
        };

        // Verify HMAC + timestamp
        let msg = match envelope.verify_and_open(&shared_secret) {
            Ok(m) => m,
            Err(e) => {
                warn!("⚠️  Rejected gossip from {peer_addr}: {e}");
                continue;
            }
        };

        debug!("✉️  Verified gossip from {} via {peer_addr}", &envelope.sender[..16.min(envelope.sender.len())]);

        match &msg {
            GossipMessage::Hello { sentinel_addr, htlcs_watching, .. } => {
                info!("👋 Peer {sentinel_addr} online, watching {htlcs_watching} HTLCs");
                let pong = GossipMessage::Pong { sentinel_pubkey: sentinel_pubkey.clone() };
                if let Ok(env) = GossipEnvelope::sign(&pong, &sentinel_pubkey, &shared_secret) {
                    let _ = stream.write_all(&serde_json::to_vec(&env)?).await;
                }
            }
            GossipMessage::AttackAlert { htlc_txid, attack_type, reporter_pubkey, .. } => {
                warn!("🚨 Attack alert from {}: {attack_type} on {}", &reporter_pubkey[..16.min(reporter_pubkey.len())], &htlc_txid[..16.min(htlc_txid.len())]);
                let _ = broadcast_tx.send(msg.clone());
            }
            GossipMessage::DefenseAnnouncement { htlc_txid, defender_pubkey, .. } => {
                info!("🛡️  Defense from {} on {}", &defender_pubkey[..16.min(defender_pubkey.len())], &htlc_txid[..16.min(htlc_txid.len())]);
                let _ = broadcast_tx.send(msg.clone());
            }
            GossipMessage::WatchRequest { htlc_txid, .. } => {
                info!("📋 Watch request for HTLC {}", &htlc_txid[..16.min(htlc_txid.len())]);
                let _ = broadcast_tx.send(msg.clone());
            }
            _ => {}
        }
    }
    Ok(())
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub struct GossipClient {
    peers: Vec<String>,
    sentinel_pubkey: String,
    sentinel_addr: String,
    shared_secret: String,
    store: HtlcStore,
    broadcast_interval_secs: u64,
    outbound_rx: broadcast::Receiver<GossipMessage>,
}

impl GossipClient {
    pub fn new(
        peers: Vec<String>,
        sentinel_pubkey: String,
        sentinel_addr: String,
        shared_secret: String,
        store: HtlcStore,
        broadcast_interval_secs: u64,
        outbound_rx: broadcast::Receiver<GossipMessage>,
    ) -> Self {
        GossipClient { peers, sentinel_pubkey, sentinel_addr, shared_secret,
                       store, broadcast_interval_secs, outbound_rx }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("GossipClient started with {} peers (HMAC auth enabled)", self.peers.len());
        let mut heartbeat = interval(Duration::from_secs(self.broadcast_interval_secs));
        loop {
            tokio::select! {
                _ = heartbeat.tick() => self.broadcast_hello().await,
                Ok(msg) = self.outbound_rx.recv() => self.broadcast_to_peers(&msg).await,
            }
        }
    }

    async fn broadcast_hello(&self) {
        let watching = self.store.get_active().map(|h| h.len()).unwrap_or(0);
        let hello = GossipMessage::Hello {
            sentinel_pubkey: self.sentinel_pubkey.clone(),
            sentinel_addr: self.sentinel_addr.clone(),
            htlcs_watching: watching,
            timestamp: Utc::now().timestamp(),
        };
        self.broadcast_to_peers(&hello).await;
    }

    async fn broadcast_to_peers(&self, msg: &GossipMessage) {
        let envelope = match GossipEnvelope::sign(msg, &self.sentinel_pubkey, &self.shared_secret) {
            Ok(e) => e,
            Err(e) => { error!("Failed to sign gossip: {e}"); return; }
        };
        let msg_bytes = match serde_json::to_vec(&envelope) {
            Ok(b) => b,
            Err(e) => { error!("Serialize error: {e}"); return; }
        };

        for peer in &self.peers {
            match TcpStream::connect(peer).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(&msg_bytes).await {
                        debug!("Failed to send to {peer}: {e}");
                    }
                }
                Err(_) => debug!("Peer {peer} unreachable"),
            }
        }
    }
}
