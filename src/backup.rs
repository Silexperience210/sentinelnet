//! Periodic sled backup — exports all DB entries to a JSON file.
//! Runs as a background task, keeps the last N backups.

use crate::store::HtlcStore;
use anyhow::Result;
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const MAX_BACKUPS: usize = 10;

pub async fn backup_loop(
    store: HtlcStore,
    data_dir: String,
    interval_secs: u64,
    cancel: CancellationToken,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs));
    info!("Backup task started (every {interval_secs}s, keep {MAX_BACKUPS})");

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = run_backup(&store, &data_dir) {
                    error!("Backup failed: {e}");
                } else {
                    cleanup_old_backups(&data_dir);
                }
            }
            _ = cancel.cancelled() => {
                info!("Backup task shutting down — running final backup");
                let _ = run_backup(&store, &data_dir);
                break;
            }
        }
    }
}

fn run_backup(store: &HtlcStore, data_dir: &str) -> Result<()> {
    let backup_dir = PathBuf::from(data_dir).join("backups");
    fs::create_dir_all(&backup_dir)?;

    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let path = backup_dir.join(format!("backup_{timestamp}.json"));

    let all_htlcs  = store.get_all()?;
    let bounties   = store.get_all_bounties()?;

    let export = serde_json::json!({
        "exported_at": Utc::now().to_rfc3339(),
        "htlcs":       all_htlcs,
        "bounties":    bounties,
    });

    fs::write(&path, serde_json::to_string_pretty(&export)?)?;
    info!("✅ Backup saved: {} ({} HTLCs, {} bounties)",
        path.display(), all_htlcs.len(), bounties.len());
    Ok(())
}

fn cleanup_old_backups(data_dir: &str) {
    let backup_dir = PathBuf::from(data_dir).join("backups");
    let mut files: Vec<_> = match fs::read_dir(&backup_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
            .collect(),
        Err(_) => return,
    };

    files.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
    while files.len() > MAX_BACKUPS {
        let oldest = files.remove(0);
        if let Err(e) = fs::remove_file(oldest.path()) {
            warn!("Could not remove old backup: {e}");
        }
    }
}
