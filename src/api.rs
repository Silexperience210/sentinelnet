use crate::store::{HtlcStore, WatchedHtlc};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};

/// Request to register a new HTLC for watching
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub txid: String,
    pub vout: u32,
    /// Pre-signed claim transactions at escalating fee rates (hex)
    pub claim_txs: Vec<String>,
    pub protected_node_pubkey: String,
    pub cltv_expiry: u32,
    pub amount_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub txid: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub total: usize,
    pub watching: usize,
    pub in_mempool: usize,
    pub defense_pending: usize,
    pub defended: usize,
    pub confirmed: usize,
    pub expired: usize,
}

/// Minimal HTTP server (no external framework — pure tokio)
pub struct ApiServer {
    port: u16,
    store: HtlcStore,
}

impl ApiServer {
    pub fn new(port: u16, store: HtlcStore) -> Self {
        ApiServer { port, store }
    }

    pub async fn run(self) -> Result<()> {
        let addr: SocketAddr = format!("0.0.0.0:{}", self.port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("SentinelNet API server listening on http://0.0.0.0:{}", self.port);

        let store = Arc::new(self.store);

        loop {
            let (mut stream, peer) = listener.accept().await?;
            let store = store.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let request = String::from_utf8_lossy(&buf[..n]);
                        let response = handle_request(&request, &store).await;
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    _ => {}
                }
            });
        }
    }
}

async fn handle_request(request: &str, store: &HtlcStore) -> String {
    let lines: Vec<&str> = request.lines().collect();
    let first_line = lines.first().unwrap_or(&"");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        return http_response(400, "Bad Request", r#"{"error":"invalid request"}"#);
    }

    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        // ── GET /status ──────────────────────────────────────────────────────
        ("GET", "/status") => {
            match store.stats() {
                Ok(stats) => {
                    let body = serde_json::json!({
                        "status": "ok",
                        "total": stats.total,
                        "watching": stats.watching,
                        "in_mempool": stats.in_mempool,
                        "defense_pending": stats.defense_pending,
                        "defended": stats.defended,
                        "confirmed": stats.confirmed,
                        "expired": stats.expired,
                    });
                    http_response(200, "OK", &body.to_string())
                }
                Err(e) => http_response(500, "Internal Server Error", &format!(r#"{{"error":"{e}"}}"#)),
            }
        }

        // ── GET /htlcs ───────────────────────────────────────────────────────
        ("GET", "/htlcs") => {
            match store.get_all() {
                Ok(htlcs) => {
                    let list: Vec<serde_json::Value> = htlcs.iter().map(|h| {
                        serde_json::json!({
                            "txid": h.txid,
                            "vout": h.vout,
                            "cltv_expiry": h.cltv_expiry,
                            "amount_sats": h.amount_sats,
                            "protected_node": &h.protected_node_pubkey[..16],
                            "status": format!("{:?}", h.status),
                            "registered_at": h.registered_at.to_rfc3339(),
                        })
                    }).collect();
                    let body = serde_json::json!({ "htlcs": list });
                    http_response(200, "OK", &body.to_string())
                }
                Err(e) => http_response(500, "Internal Server Error", &format!(r#"{{"error":"{e}"}}"#)),
            }
        }

        // ── POST /register ───────────────────────────────────────────────────
        ("POST", "/register") => {
            // Extract body (after double newline)
            let body = extract_body(request);
            match serde_json::from_str::<RegisterRequest>(body) {
                Ok(req) => {
                    if req.claim_txs.is_empty() {
                        return http_response(400, "Bad Request", r#"{"error":"claim_txs required"}"#);
                    }
                    let htlc = WatchedHtlc::new(
                        req.txid.clone(),
                        req.vout,
                        req.claim_txs,
                        req.protected_node_pubkey,
                        req.cltv_expiry,
                        req.amount_sats,
                    );
                    match store.register(&htlc) {
                        Ok(_) => {
                            info!("Registered HTLC {} for watching", req.txid);
                            let resp = serde_json::json!({
                                "success": true,
                                "txid": req.txid,
                                "message": "HTLC registered for watching"
                            });
                            http_response(201, "Created", &resp.to_string())
                        }
                        Err(e) => http_response(500, "Internal Server Error",
                            &format!(r#"{{"error":"{e}"}}"#))
                    }
                }
                Err(e) => http_response(400, "Bad Request", &format!(r#"{{"error":"parse error: {e}"}}"#)),
            }
        }

        // ── GET / ────────────────────────────────────────────────────────────
        ("GET", "/") => {
            let body = serde_json::json!({
                "name": "SentinelNet",
                "version": "0.1.0",
                "description": "Incentivized Lightning Network Watchtower",
                "endpoints": ["/status", "/htlcs", "/register"]
            });
            http_response(200, "OK", &body.to_string())
        }

        _ => http_response(404, "Not Found", r#"{"error":"not found"}"#),
    }
}

fn http_response(status: u16, status_text: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn extract_body(request: &str) -> &str {
    if let Some(pos) = request.find("\r\n\r\n") {
        &request[pos + 4..]
    } else if let Some(pos) = request.find("\n\n") {
        &request[pos + 2..]
    } else {
        ""
    }
}
