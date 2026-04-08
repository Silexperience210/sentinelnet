use crate::store::{HtlcStore, WatchedHtlc};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub txid: String,
    pub vout: u32,
    pub claim_txs: Vec<String>,
    pub protected_node_pubkey: String,
    pub cltv_expiry: u32,
    pub amount_sats: u64,
}

pub struct ApiServer {
    port: u16,
    store: HtlcStore,
    api_key: String,
}

impl ApiServer {
    pub fn new(port: u16, store: HtlcStore, api_key: String) -> Self {
        ApiServer { port, store, api_key }
    }

    pub async fn run(self) -> Result<()> {
        let addr: SocketAddr = format!("0.0.0.0:{}", self.port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("SentinelNet API on http://0.0.0.0:{} (X-Sentinel-Key required)", self.port);

        let store = Arc::new(self.store);
        let api_key = Arc::new(self.api_key);

        loop {
            let (mut stream, _peer) = listener.accept().await?;
            let store = store.clone();
            let key = api_key.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                if let Ok(n) = stream.read(&mut buf).await {
                    if n > 0 {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let resp = handle_request(&req, &store, &key).await;
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            });
        }
    }
}

async fn handle_request(request: &str, store: &HtlcStore, api_key: &str) -> String {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return http(400, r#"{"error":"bad request"}"#);
    }
    let (method, path) = (parts[0], parts[1]);

    // ── Public endpoints (no auth) ────────────────────────────────────────────
    if method == "GET" && (path == "/" || path == "/status") {
        return handle_public(path, store).await;
    }

    // ── Auth check ────────────────────────────────────────────────────────────
    if !api_key.is_empty() {
        let provided_key = extract_header(request, "X-Sentinel-Key");
        if provided_key.as_deref() != Some(api_key) {
            warn!("⛔ Unauthorized API request to {path}");
            return http(401, r#"{"error":"unauthorized — X-Sentinel-Key required"}"#);
        }
    }

    // ── Protected endpoints ───────────────────────────────────────────────────
    match (method, path) {
        ("POST", "/register") => {
            let body = extract_body(request);
            match serde_json::from_str::<RegisterRequest>(body) {
                Ok(req) => {
                    if req.claim_txs.is_empty() {
                        return http(400, r#"{"error":"claim_txs cannot be empty"}"#);
                    }
                    if req.txid.len() != 64 {
                        return http(400, r#"{"error":"txid must be 64 hex chars"}"#);
                    }
                    if req.amount_sats == 0 {
                        return http(400, r#"{"error":"amount_sats must be > 0"}"#);
                    }
                    let htlc = WatchedHtlc::new(
                        req.txid.clone(), req.vout,
                        req.claim_txs, req.protected_node_pubkey,
                        req.cltv_expiry, req.amount_sats,
                    );
                    match store.register(&htlc) {
                        Ok(_) => {
                            info!("Registered HTLC {}", &req.txid[..16]);
                            let body = serde_json::json!({
                                "success": true,
                                "txid": req.txid,
                                "message": "HTLC registered"
                            });
                            http(201, &body.to_string())
                        }
                        Err(e) => http(500, &format!(r#"{{"error":"{e}"}}"#)),
                    }
                }
                Err(e) => http(400, &format!(r#"{{"error":"parse error: {e}"}}"#)),
            }
        }
        ("GET", "/htlcs") => {
            match store.get_all() {
                Ok(htlcs) => {
                    let list: Vec<_> = htlcs.iter().map(|h| serde_json::json!({
                        "txid": h.txid,
                        "cltv_expiry": h.cltv_expiry,
                        "amount_sats": h.amount_sats,
                        "status": format!("{:?}", h.status),
                        "fee_tiers": h.claim_txs.len(),
                    })).collect();
                    http(200, &serde_json::json!({ "htlcs": list }).to_string())
                }
                Err(e) => http(500, &format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        _ => http(404, r#"{"error":"not found"}"#),
    }
}

async fn handle_public(path: &str, store: &HtlcStore) -> String {
    match path {
        "/" => http(200, r#"{"name":"SentinelNet","version":"0.1.0","auth":"X-Sentinel-Key header required for write endpoints"}"#),
        "/status" => {
            match store.stats() {
                Ok(s) => http(200, &serde_json::json!({
                    "status": "ok",
                    "htlcs": { "total": s.total, "watching": s.watching,
                                "defended": s.defended, "confirmed": s.confirmed },
                    "bounties": { "paid": s.bounties_paid, "pending": s.bounties_pending }
                }).to_string()),
                Err(e) => http(500, &format!(r#"{{"error":"{e}"}}"#)),
            }
        }
        _ => http(404, r#"{"error":"not found"}"#),
    }
}

fn http(status: u16, body: &str) -> String {
    let status_text = match status {
        200 => "OK", 201 => "Created", 400 => "Bad Request",
        401 => "Unauthorized", 404 => "Not Found", 500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn extract_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    let search = format!("{name}: ");
    request.lines()
        .find(|l| l.to_lowercase().starts_with(&search.to_lowercase()))
        .map(|l| l[search.len()..].trim())
}

fn extract_body(request: &str) -> &str {
    if let Some(pos) = request.find("\r\n\r\n") { &request[pos + 4..] }
    else if let Some(pos) = request.find("\n\n") { &request[pos + 2..] }
    else { "" }
}
