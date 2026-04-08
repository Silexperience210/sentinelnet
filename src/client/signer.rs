/// signer.rs
///
/// Signing strategies for HTLC claim transactions.
/// Currently delegates to LND, but designed to support:
///   - LND (via REST /v2/wallet/tx/sign)
///   - External HSM (future)
///   - Cold signing workflow (future)

use anyhow::Result;

pub enum SignerBackend {
    Lnd,
    // HardwareSecurityModule(HsmConfig),
    // ColdSigning { export_path: String },
}

/// Sign a raw transaction hex using the configured backend
pub async fn sign_transaction(raw_hex: &str, backend: &SignerBackend) -> Result<String> {
    match backend {
        SignerBackend::Lnd => {
            // Handled directly in htlc_builder via LndRestClient::sign_raw_tx
            // This module exists for future extensibility
            Ok(raw_hex.to_string())
        }
    }
}
