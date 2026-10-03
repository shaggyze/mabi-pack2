// Remembers session imports that came back expired, so the same dead session is
// not imported again and again.
//
// When an import from another launcher (e.g. the Nexon Launcher's cookie store)
// yields a session that can no longer be refreshed, the source is flagged with
// its file's modification time and the target profile's session expiry. The
// next import from that source is skipped until either
//   - the source file changed (the user logged in to that launcher again), or
//   - the profile's own mabi-patcher session expiry changed (it was renewed and
//     has since expired again, so importing is worth another try).
// A successful import clears the flag.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub struct Flag {
    /// Source file mtime (unix seconds) when the expired session was imported.
    pub source_mtime: u64,
    /// Target profile's `session_expires_at` at that time (0 = none).
    pub profile_expires_at: u64,
    /// When the flag was set (unix seconds), for messages.
    pub flagged_at: u64,
}

fn store_path() -> PathBuf {
    crate::launcher::profile::data_dir().join("import_flags.json")
}

fn load() -> HashMap<String, Flag> {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(map: &HashMap<String, Flag>) {
    let path = store_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(text) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write(path, text);
    }
}

/// Modification time of `path` in unix seconds (0 when unreadable).
pub fn file_mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether `flag` still blocks an import given the source's current mtime and
/// the profile's current session expiry.
pub fn blocks(flag: &Flag, source_mtime: u64, profile_expires_at: u64) -> bool {
    source_mtime <= flag.source_mtime && profile_expires_at == flag.profile_expires_at
}

/// The flag blocking an import from `source`, if any.
pub fn blocked(source: &str, source_mtime: u64, profile_expires_at: u64) -> Option<Flag> {
    load().get(source).copied().filter(|f| blocks(f, source_mtime, profile_expires_at))
}

/// Record that `source` produced an expired session.
pub fn flag(source: &str, source_mtime: u64, profile_expires_at: u64) {
    let mut map = load();
    let flagged_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    map.insert(source.to_string(), Flag { source_mtime, profile_expires_at, flagged_at });
    save(&map);
}

/// Forget the flag for `source` (after a good import).
pub fn clear(source: &str) {
    let mut map = load();
    if map.remove(source).is_some() {
        save(&map);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_source_and_profile_stay_blocked() {
        let f = Flag { source_mtime: 100, profile_expires_at: 500, flagged_at: 1 };
        assert!(blocks(&f, 100, 500));
    }

    #[test]
    fn newer_source_file_unblocks() {
        let f = Flag { source_mtime: 100, profile_expires_at: 500, flagged_at: 1 };
        assert!(!blocks(&f, 101, 500));
    }

    #[test]
    fn changed_profile_expiry_unblocks() {
        let f = Flag { source_mtime: 100, profile_expires_at: 500, flagged_at: 1 };
        assert!(!blocks(&f, 100, 900));
    }
}
