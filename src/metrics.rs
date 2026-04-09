//! Prometheus metrics for SentinelNet.
//! Exposed via GET /metrics on the API port.

use prometheus::{
    register_counter, register_counter_vec, register_gauge,
    Counter, CounterVec, Gauge, Encoder, TextEncoder,
};
use std::sync::OnceLock;

pub struct Metrics {
    pub htlcs_registered:     Counter,
    pub htlcs_defended:        Counter,
    pub htlcs_confirmed_clean: Counter,
    pub htlcs_expired:         Counter,
    pub defense_attempts:      Counter,
    pub bounties_paid_sats:    Counter,
    pub bounties_failed:       Counter,
    pub gossip_messages_rx:    CounterVec,
    pub gossip_messages_tx:    CounterVec,
    pub api_requests:          CounterVec,
    pub mempool_polls:         Counter,
    pub fee_bumps:             Counter,
    pub htlcs_watching:        Gauge,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

fn build() -> Metrics {
    Metrics {
        htlcs_registered:     register_counter!("sentinelnet_htlcs_registered_total",     "Total HTLCs registered").unwrap(),
        htlcs_defended:        register_counter!("sentinelnet_htlcs_defended_total",        "Total HTLCs defended").unwrap(),
        htlcs_confirmed_clean: register_counter!("sentinelnet_htlcs_confirmed_clean_total", "HTLCs confirmed without attack").unwrap(),
        htlcs_expired:         register_counter!("sentinelnet_htlcs_expired_total",         "HTLCs expired undefended").unwrap(),
        defense_attempts:      register_counter!("sentinelnet_defense_attempts_total",      "Defense broadcast attempts").unwrap(),
        bounties_paid_sats:    register_counter!("sentinelnet_bounties_paid_sats_total",    "Sats paid as bounties").unwrap(),
        bounties_failed:       register_counter!("sentinelnet_bounties_failed_total",       "Bounties that exhausted retries").unwrap(),
        gossip_messages_rx:    register_counter_vec!("sentinelnet_gossip_rx_total",  "Gossip messages received", &["type"]).unwrap(),
        gossip_messages_tx:    register_counter_vec!("sentinelnet_gossip_tx_total",  "Gossip messages sent",     &["type"]).unwrap(),
        api_requests:          register_counter_vec!("sentinelnet_api_requests_total","API requests",            &["method","path","status"]).unwrap(),
        mempool_polls:         register_counter!("sentinelnet_mempool_polls_total",  "Mempool poll cycles").unwrap(),
        fee_bumps:             register_counter!("sentinelnet_fee_bumps_total",      "CPFP fee bumps").unwrap(),
        htlcs_watching:        register_gauge!("sentinelnet_htlcs_watching",         "Active HTLCs being watched").unwrap(),
    }
}

pub fn init()                  { get(); }
pub fn get() -> &'static Metrics { METRICS.get_or_init(build) }

pub fn render() -> String {
    let encoder = TextEncoder::new();
    let mut buf = Vec::new();
    encoder.encode(&prometheus::gather(), &mut buf).unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}
