//! REST API server with auth, rate limiting, and /metrics endpoint.

use crate::metrics;
use crate::rate_limit::RateLimiter;
use crate::store::{HtlcStore, WatchedHtlc};
use anyhow::Result;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub txid: String, pub vout: u32,
    pub claim_txs: Vec<String>,
    pub protected_node_pubkey: String,
    pub cltv_expiry: u32, pub amount_sats: u64,
}

pub struct ApiServer {
    port:    u16,
    store:   HtlcStore,
    api_key: String,
    rl:      RateLimiter,
}

impl ApiServer {
    pub fn new(port: u16, store: HtlcStore, api_key: String) -> Self {
        ApiServer { port, store, api_key, rl: RateLimiter::new() }
    }

    pub async fn run(self) -> Result<()> {
        let addr: SocketAddr = format!("0.0.0.0:{}", self.port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("API on http://0.0.0.0:{} (auth: {}, /metrics enabled)",
            self.port, if self.api_key.is_empty() { "off ⚠️" } else { "X-Sentinel-Key" });

        let store   = Arc::new(self.store);
        let api_key = Arc::new(self.api_key);
        let rl      = Arc::new(self.rl);

        loop {
            let (mut stream, peer) = listener.accept().await?;
            let store   = store.clone();
            let api_key = api_key.clone();
            let rl      = rl.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                if let Ok(n) = stream.read(&mut buf).await {
                    if n > 0 {
                        let req  = String::from_utf8_lossy(&buf[..n]).to_string();
                        let ip   = peer.ip().to_string();
                        let resp = handle(&req, &ip, &store, &api_key, &rl).await;
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            });
        }
    }
}

async fn handle(req: &str, ip: &str, store: &HtlcStore, api_key: &str, rl: &RateLimiter) -> String {
    let first  = req.lines().next().unwrap_or("");
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 { return http(400, r#"{"error":"bad request"}"#, "GET", "/", "400"); }
    let (method, path) = (parts[0], parts[1]);

    // ── Public (no auth) ──────────────────────────────────────────────────────
    match (method, path) {
        ("GET", "/" | "/status") => return public_status(path, store).await,
        ("GET", "/metrics") => {
            let body = metrics::render();
            return format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
        }
        _ => {}
    }

    // ── Rate limit (Fix 6) ────────────────────────────────────────────────────
    if !rl.check(ip) {
        warn!("Rate limited: {ip}");
        metrics::get().api_requests.with_label_values(&[method, path, "429"]).inc();
        return http(429, r#"{"error":"rate limited — try again later"}"#, method, path, "429");
    }

    // ── Auth ──────────────────────────────────────────────────────────────────
    if !api_key.is_empty() {
        let provided = extract_header(req, "X-Sentinel-Key");
        if provided.as_deref() != Some(api_key) {
            warn!("Unauthorized from {ip}");
            metrics::get().api_requests.with_label_values(&[method, path, "401"]).inc();
            return http(401, r#"{"error":"unauthorized"}"#, method, path, "401");
        }
    }

    // ── Protected endpoints ───────────────────────────────────────────────────
    let resp = match (method, path) {
        ("POST", "/register") => handle_register(req, store).await,
        ("GET",  "/htlcs")    => handle_htlcs(store).await,
        _ => http(404, r#"{"error":"not found"}"#, method, path, "404"),
    };
    metrics::get().api_requests.with_label_values(&[method, path, "2xx"]).inc();
    resp
}

async fn handle_register(req: &str, store: &HtlcStore) -> String {
    let body = extract_body(req);
    match serde_json::from_str::<RegisterRequest>(body) {
        Ok(r) => {
            // Validation
            if r.txid.len() != 64      { return http(400, r#"{"error":"txid must be 64 hex chars"}"#, "POST", "/register", "400"); }
            if r.claim_txs.is_empty()  { return http(400, r#"{"error":"claim_txs required"}"#, "POST", "/register", "400"); }
            if r.amount_sats == 0      { return http(400, r#"{"error":"amount_sats must be > 0"}"#, "POST", "/register", "400"); }
            if r.cltv_expiry == 0      { return http(400, r#"{"error":"cltv_expiry required"}"#, "POST", "/register", "400"); }

            let htlc = WatchedHtlc::new(
                r.txid.clone(), r.vout, r.claim_txs,
                r.protected_node_pubkey, r.cltv_expiry, r.amount_sats,
            );
            match store.register(&htlc) {
                Ok(_) => {
                    info!("Registered {}", &r.txid[..16]);
                    crate::metrics::get().htlcs_registered.inc();
                    let body = serde_json::json!({"success":true,"txid":r.txid}).to_string();
                    http(201, &body, "POST", "/register", "201")
                }
                Err(e) => http(500, &format!(r#"{{"error":"{e}"}}"#), "POST", "/register", "500"),
            }
        }
        Err(e) => http(400, &format!(r#"{{"error":"parse: {e}"}}"#), "POST", "/register", "400"),
    }
}

async fn handle_htlcs(store: &HtlcStore) -> String {
    match store.get_all() {
        Ok(all) => {
            let list: Vec<_> = all.iter().map(|h| serde_json::json!({
                "txid": h.txid, "amount_sats": h.amount_sats,
                "cltv_expiry": h.cltv_expiry,
                "status": format!("{:?}", h.status),
                "fee_tiers": h.claim_txs.len(),
            })).collect();
            http(200, &serde_json::json!({"htlcs":list}).to_string(), "GET", "/htlcs", "200")
        }
        Err(e) => http(500, &format!(r#"{{"error":"{e}"}}"#), "GET", "/htlcs", "500"),
    }
}

async fn public_status(path: &str, store: &HtlcStore) -> String {
    if path == "/" {
        return http(200, r#"{"name":"SentinelNet","version":"0.1.0","endpoints":["/status","/metrics","/register","/htlcs"]}"#, "GET", "/", "200");
    }
    match store.stats() {
        Ok(s) => http(200, &serde_json::json!({
            "status":"ok",
            "htlcs":{"total":s.total,"watching":s.watching,"defended":s.defended},
            "bounties":{"paid":s.bounties_paid,"pending":s.bounties_pending}
        }).to_string(), "GET", "/status", "200"),
        Err(e) => http(500, &format!(r#"{{"error":"{e}"}}"#), "GET", "/status", "500"),
    }
}

fn http(status: u16, body: &str, _m: &str, _p: &str, _s: &str) -> String {
    let txt = match status {
        200=>"OK",201=>"Created",400=>"Bad Request",401=>"Unauthorized",
        404=>"Not Found",429=>"Too Many Requests",500=>"Internal Server Error",_=>"Unknown"
    };
    format!("HTTP/1.1 {status} {txt}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

fn extract_header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    let search = format!("{}: ", name);
    req.lines().find(|l| l.to_lowercase().starts_with(&search.to_lowercase()))
       .map(|l| l[search.len()..].trim())
}

fn extract_body(req: &str) -> &str {
    if let Some(p) = req.find("\r\n\r\n") { &req[p+4..] }
    else if let Some(p) = req.find("\n\n") { &req[p+2..] }
    else { "" }
}
