//! Fix 1: LND SubscribeChannelEvents — streaming endpoint.
//!
//! Subscribes to GET /v1/channels/subscribe which streams JSON objects,
//! one per line, representing channel state changes.
//! On ACTIVE_CHANNEL or OPEN_CHANNEL events, triggers a re-scan.
//! On FULLY_RESOLVED_CHANNEL, logs the closure.

use super::lnd::LndRestClient;
use anyhow::Result;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelEventUpdate {
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub open_channel:           Option<serde_json::Value>,
    pub closed_channel:         Option<serde_json::Value>,
    pub active_channel:         Option<serde_json::Value>,
    pub fully_resolved_channel: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// New/updated channel — re-scan all HTLCs
    Rescan,
    /// Channel closed — check force-close HTLCs
    ForceClosed { channel_point: String },
}

/// Subscribe to LND channel events and forward them.
/// This runs as a long-lived async task.
pub async fn subscribe(
    lnd: &LndRestClient,
    tx: mpsc::Sender<ChannelEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    info!("Subscribing to LND channel events via /v1/channels/subscribe");

    let url = format!("{}/v1/channels/subscribe", lnd.base_url);

    let resp = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(0)) // no timeout for streaming
        .build()?
        .get(&url)
        .header("Grpc-Metadata-macaroon", &lnd.macaroon_hex)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("LND channel subscribe returned {}", resp.status());
    }

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    loop {
        tokio::select! {
            chunk = stream.next() => {
                match chunk {
                    None => {
                        info!("LND channel event stream ended — will reconnect");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("Stream error: {e}");
                        break;
                    }
                    Some(Ok(bytes)) => {
                        buf.push_str(&String::from_utf8_lossy(&bytes));
                        // Process complete JSON lines
                        while let Some(nl) = buf.find('\n') {
                            let line = buf[..nl].trim().to_string();
                            buf = buf[nl+1..].to_string();
                            if line.is_empty() { continue; }
                            process_event_line(&line, &tx).await;
                        }
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("Channel event subscriber shutting down");
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn process_event_line(line: &str, tx: &mpsc::Sender<ChannelEvent>) {
    // LND wraps the result: {"result": {...}} or {"error": {...}}
    let outer: serde_json::Value = match serde_json::from_str(line) {
        Ok(v)  => v,
        Err(e) => { debug!("Parse event line: {e}"); return; }
    };

    let inner = match outer.get("result") {
        Some(v) => v.clone(),
        None    => {
            if let Some(err) = outer.get("error") {
                warn!("LND stream error: {err}");
            }
            return;
        }
    };

    let event: ChannelEventUpdate = match serde_json::from_value(inner) {
        Ok(e)  => e,
        Err(e) => { debug!("Deserialize event: {e}"); return; }
    };

    let etype = event.event_type.as_deref().unwrap_or("unknown");
    debug!("Channel event: {etype}");

    match etype {
        "OPEN_CHANNEL" | "ACTIVE_CHANNEL" | "PENDING_OPEN_CHANNEL" => {
            info!("📡 Channel event {etype} — triggering HTLC re-scan");
            let _ = tx.send(ChannelEvent::Rescan).await;
        }
        "FULLY_RESOLVED_CHANNEL" | "CLOSED_CHANNEL" => {
            let cp = event.closed_channel
                .or(event.fully_resolved_channel)
                .and_then(|v| v["channel"]["channel_point"].as_str().map(|s| s.to_string()))
                .unwrap_or_default();
            info!("🔒 Channel closed/resolved: {cp} — checking force-close HTLCs");
            let _ = tx.send(ChannelEvent::ForceClosed { channel_point: cp }).await;
        }
        _ => {}
    }
}

/// Watch loop: subscribe with auto-reconnect on disconnect.
pub async fn watch_loop(
    lnd: LndRestClient,
    tx: mpsc::Sender<ChannelEvent>,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() { break; }

        match subscribe(&lnd, tx.clone(), cancel.clone()).await {
            Ok(_)  => {},
            Err(e) => warn!("Channel subscribe error: {e} — reconnecting in 30s"),
        }

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {},
            _ = cancel.cancelled() => break,
        }
    }
    info!("Channel event watch loop exited");
}
