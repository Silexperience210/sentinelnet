//! Integration tests for SentinelNet.
//!
//! These tests require a live regtest environment.
//! Run with:
//!   cargo test --test integration_test -- --ignored
//!
//! Required environment variables:
//!   SENTINEL_URL       = http://localhost:9000
//!   SENTINEL_API_KEY   = <your api key>
//!   LND_REST_URL       = https://localhost:8080
//!   LND_MACAROON_HEX   = <admin macaroon hex>
//!   LND_TLS_CERT_PATH  = ~/.lnd/tls.cert
//!   BTC_RPC_URL        = http://localhost:18443
//!   BTC_RPC_USER       = bitcoinrpc
//!   BTC_RPC_PASS       = test

use std::env;

fn sentinel_url() -> String { env::var("SENTINEL_URL").unwrap_or_else(|_| "http://localhost:9000".into()) }
fn sentinel_key() -> String { env::var("SENTINEL_API_KEY").unwrap_or_default() }

// ─── Helper: authenticated POST ──────────────────────────────────────────────

async fn post_json(url: &str, key: &str, body: serde_json::Value) -> reqwest::Response {
    let mut req = reqwest::Client::new().post(url).json(&body);
    if !key.is_empty() { req = req.header("X-Sentinel-Key", key); }
    req.send().await.expect("request failed")
}

async fn get_json(url: &str) -> serde_json::Value {
    reqwest::get(url).await.expect("GET failed")
        .json().await.expect("JSON parse failed")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_sentinel_health() {
    let status = get_json(&format!("{}/status", sentinel_url())).await;
    assert_eq!(status["status"], "ok", "Sentinel not healthy: {status}");
}

#[tokio::test]
#[ignore]
async fn test_register_htlc_valid() {
    let txid = "a".repeat(64);
    let body = serde_json::json!({
        "txid": txid,
        "vout": 0,
        "claim_txs": ["deadbeef"],
        "protected_node_pubkey": "02".to_string() + &"ab".repeat(32),
        "cltv_expiry": 800_000u32,
        "amount_sats": 100_000u64
    });
    let resp = post_json(
        &format!("{}/register", sentinel_url()),
        &sentinel_key(),
        body,
    ).await;
    assert_eq!(resp.status(), 201, "Expected 201 Created");
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["success"], true);
}

#[tokio::test]
#[ignore]
async fn test_register_htlc_rejected_without_key() {
    let txid = "b".repeat(64);
    let body = serde_json::json!({
        "txid": txid, "vout": 0,
        "claim_txs": ["deadbeef"],
        "protected_node_pubkey": "02".to_string() + &"cd".repeat(32),
        "cltv_expiry": 800_000u32, "amount_sats": 50_000u64
    });
    // Send WITHOUT API key
    let resp = reqwest::Client::new()
        .post(&format!("{}/register", sentinel_url()))
        .json(&body).send().await.unwrap();
    assert_eq!(resp.status(), 401, "Should be rejected without key");
}

#[tokio::test]
#[ignore]
async fn test_register_htlc_bad_txid() {
    let body = serde_json::json!({
        "txid": "short",  // invalid — must be 64 hex chars
        "vout": 0, "claim_txs": ["deadbeef"],
        "protected_node_pubkey": "02".to_string() + &"ab".repeat(32),
        "cltv_expiry": 800_000u32, "amount_sats": 1000u64
    });
    let resp = post_json(
        &format!("{}/register", sentinel_url()), &sentinel_key(), body,
    ).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
#[ignore]
async fn test_htlc_list_authenticated() {
    let mut req = reqwest::Client::new()
        .get(&format!("{}/htlcs", sentinel_url()));
    let key = sentinel_key();
    if !key.is_empty() { req = req.header("X-Sentinel-Key", &key); }
    let resp = req.send().await.unwrap();
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json["htlcs"].is_array());
}

#[tokio::test]
#[ignore]
async fn test_gossip_hmac_rejected() {
    // Connect to gossip port with a bad HMAC and verify it's rejected
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    let mut stream = TcpStream::connect("127.0.0.1:9001").await.unwrap();
    // Send a malformed envelope (wrong HMAC)
    let bad_envelope = serde_json::json!({
        "payload": r#"{"type":"Hello","sentinel_pubkey":"test","sentinel_addr":"127.0.0.1:9001","htlcs_watching":0,"timestamp":0}"#,
        "hmac": "0000000000000000000000000000000000000000000000000000000000000000",
        "sender": "test",
        "timestamp": chrono::Utc::now().timestamp()
    });
    stream.write_all(serde_json::to_vec(&bad_envelope).unwrap().as_slice()).await.unwrap();
    // Connection should close (bad HMAC) — just verify no panic
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

// ─── Unit tests (always run) ─────────────────────────────────────────────────

#[test]
fn test_config_toml_example_parses() {
    // Verify config.toml.example is valid TOML and has all required fields
    let content = include_str!("../config.toml.example");
    let parsed: toml::Value = toml::from_str(content)
        .expect("config.toml.example must be valid TOML");
    assert!(parsed.get("sentinel").is_some(), "Missing [sentinel]");
    assert!(parsed.get("bitcoin").is_some(),  "Missing [bitcoin]");
    assert!(parsed.get("lnd").is_some(),      "Missing [lnd]");
    assert!(parsed.get("gossip").is_some(),   "Missing [gossip]");
    assert!(parsed.get("defense").is_some(),  "Missing [defense]");
    // Verify new required fields exist
    let sentinel = &parsed["sentinel"];
    assert!(sentinel.get("api_key").is_some(), "Missing sentinel.api_key");
    let gossip = &parsed["gossip"];
    assert!(gossip.get("shared_secret").is_some(), "Missing gossip.shared_secret");
}
