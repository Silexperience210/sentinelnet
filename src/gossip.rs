use crate::store::HtlcStore;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Messages exchanged between sentinel nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GossipMessage {
    /// Announce this sentinel is alive and watching
    Hello {
        sentinel_pubkey: String,
        sentinel_addr: String,
        htlcs_watching: usize,
        timestamp: i64,
    },
    /// Alert: HTLC disappeared from mempool
    AttackAlert {
        htlc_txid: String,
        reporter_pubkey: String,
        attack_type: String,
        timestamp: i64,
    },
    /// Announce a successful defense
    DefenseAnnouncement {
        htlc_txid: String,
        defense_txid: String,
        defender_pubkey: String,
        proof_hash: String,
        timestamp: i64,
    },
    /// Request to watch an HTLC (forwarded registration)
    WatchRequest {
        htlc_txid: String,
        claim_tx_hex: String,
        cltv_expiry: u32,
        amount_sats: u64,
        protected_node_pubkey: String,
    },
    /// Pong response to a hello
    Pong { sentinel_pubkey: String },
}

/// Gossip server — accepts connections from other sentinels
pub struct GossipServer {
    port: u16,
    store: HtlcStore,
    sentinel_pubkey: String,
    broadcast_tx: broadcast::Sender<GossipMessage>,
}

impl GossipServer {
    pub fn new(
        port: u16,
        store: HtlcStore,
        sentinel_pubkey: String,
        broadcast_tx: broadcast::Sender<GossipMessage>,
    ) -> Self {
        GossipServer { port, store, sentinel_pubkey, broadcast_tx }
    }

    pub async fn run(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Gossip server listening on {addr}");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let store = self.store.clone();
                    let pubkey = self.sentinel_pubkey.clone();
                    let tx = self.broadcast_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_peer(stream, peer_addr, store, pubkey, tx).await {
                            debug!("Peer {peer_addr} disconnected: {e}");
                        }
                    });
                }
                Err(e) => error!("Accept error: {e}"),
            }
        }
    }
}

async fn handle_peer(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    store: HtlcStore,
    sentinel_pubkey: String,
    broadcast_tx: broadcast::Sender<GossipMessage>,
) -> Result<()> {
    debug!("New gossip peer: {peer_addr}");
    let mut buf = vec![0u8; 65536];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let msg: GossipMessage = serde_json::from_slice(&buf[..n])?;
        debug!("Gossip rx from {peer_addr}: {msg:?}");

        match &msg {
            GossipMessage::Hello { sentinel_addr, htlcs_watching, .. } => {
                info!("👋 Peer {sentinel_addr} online, watching {htlcs_watching} HTLCs");
                // Respond with pong
                let pong = GossipMessage::Pong {
                    sentinel_pubkey: sentinel_pubkey.clone(),
                };
                let pong_bytes = serde_json::to_vec(&pong)?;
                stream.write_all(&pong_bytes).await?;
            }
            GossipMessage::AttackAlert { htlc_txid, attack_type, reporter_pubkey, .. } => {
                warn!("🚨 Attack alert from {reporter_pubkey}: {attack_type} on {htlc_txid}");
                // Forward to local defense engine via broadcast
                let _ = broadcast_tx.send(msg.clone());
            }
            GossipMessage::DefenseAnnouncement { htlc_txid, defender_pubkey, .. } => {
                info!("🛡️  Defense announcement from {defender_pubkey}: HTLC {htlc_txid} defended");
                let _ = broadcast_tx.send(msg.clone());
            }
            GossipMessage::WatchRequest { htlc_txid, .. } => {
                info!("📋 Watch request for HTLC {htlc_txid} from mesh peer");
                let _ = broadcast_tx.send(msg.clone());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Gossip client — connects to known peers and broadcasts alerts
pub struct GossipClient {
    peers: Vec<String>,
    sentinel_pubkey: String,
    sentinel_addr: String,
    store: HtlcStore,
    broadcast_interval_secs: u64,
    outbound_rx: broadcast::Receiver<GossipMessage>,
}

impl GossipClient {
    pub fn new(
        peers: Vec<String>,
        sentinel_pubkey: String,
        sentinel_addr: String,
        store: HtlcStore,
        broadcast_interval_secs: u64,
        outbound_rx: broadcast::Receiver<GossipMessage>,
    ) -> Self {
        GossipClient {
            peers,
            sentinel_pubkey,
            sentinel_addr,
            store,
            broadcast_interval_secs,
            outbound_rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("GossipClient started with {} peers", self.peers.len());

        let mut heartbeat = interval(Duration::from_secs(self.broadcast_interval_secs));

        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    self.broadcast_hello().await;
                }
                Ok(msg) = self.outbound_rx.recv() => {
                    self.broadcast_to_peers(&msg).await;
                }
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
        let msg_bytes = match serde_json::to_vec(msg) {
            Ok(b) => b,
            Err(e) => { error!("Serialize error: {e}"); return; }
        };

        for peer in &self.peers {
            match TcpStream::connect(peer).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(&msg_bytes).await {
                        debug!("Failed to send to peer {peer}: {e}");
                    }
                }
                Err(_) => {
                    debug!("Peer {peer} unreachable");
                }
            }
        }
    }
}
