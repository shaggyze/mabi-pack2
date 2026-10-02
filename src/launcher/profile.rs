// Multi-account profile manager.
//
// Profiles store per-account launcher configuration and session tokens so
// users can switch between Nexon accounts or Mabinogi installs without
// re-entering credentials each time.
//
// Storage: JSON file at %APPDATA%\mabi-patcher\profiles.json (Windows)
// or ~/.config/mabi-patcher/profiles.json (Linux/Mac — future use).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Profile model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// UUID v4 — stable identifier across renames.
    pub id: String,
    /// User-visible display name (e.g. "Main Account", "Alt").
    pub name: String,
    /// Nexon email address.
    pub email: String,
    /// NxLSession cookie — empty if not remembered.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_token: String,
    /// Seconds until session_token expires (unix epoch).
    #[serde(default)]
    pub session_expires_at: u64,
    /// Mabinogi installation directory containing Client.exe.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_dir: String,
    /// Whether to auto-login with saved session on profile selection.
    #[serde(default)]
    pub auto_login: bool,
    /// Unix timestamp of profile creation.
    pub created_at: u64,
    /// Unix timestamp of last login.
    #[serde(default)]
    pub last_login_at: u64,
    /// Profile origin: "nexon", "hyddwn", "kanan", or "manual".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_type: String,
    /// Per-profile device-id tag (a per-profile DeviceId). Hashed with the
    /// machine id to form this profile's deviceId, so two profiles never share
    /// one (which would make them invalidate each other). Empty = the legacy
    /// machine-only id, so pre-existing profiles keep working unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_tag: String,
    /// Login server IP (for custom/private servers).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_ip: String,
    /// Login server port.
    #[serde(default)]
    pub login_port: u16,
    /// Chat server IP.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chat_ip: String,
    /// Chat server port.
    #[serde(default)]
    pub chat_port: u16,
    /// Whether this profile uses the official Nexon servers.
    #[serde(default)]
    pub is_official: bool,
    /// Full cookie session (AToken/g_AToken/NexonUserID...). Needed for browser/SSO
    /// accounts, which can't be refreshed from NxLSession alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<crate::launcher::auth::NexonSession>,
}

impl Profile {
    pub fn new(name: &str, email: &str) -> Self {
        Self {
            id: new_uuid(),
            name: name.to_string(),
            email: email.to_string(),
            session_token: String::new(),
            session_expires_at: 0,
            client_dir: String::new(),
            auto_login: false,
            created_at: unix_now(),
            last_login_at: 0,
            profile_type: "nexon".to_string(),
            // New profiles get a distinct device-id tag (their name); legacy
            // profiles loaded from disk keep the empty tag → machine-only id.
            device_tag: name.to_string(),
            login_ip: String::new(),
            login_port: 0,
            chat_ip: String::new(),
            chat_port: 0,
            is_official: true,
            session: None,
        }
    }

    /// This profile's deviceId: the machine id hashed with [`Self::device_tag`].
    /// An empty tag yields the legacy machine-only id.
    pub fn device_id(&self) -> String {
        crate::launcher::auth::device_id(&self.device_tag)
    }

    /// True when the stored session is known to have expired (its recorded
    /// expiry has passed). An unknown expiry (0) is never "expired": callers
    /// then try the session and let the server decide.
    pub fn session_expired(&self) -> bool {
        self.session_expires_at != 0 && unix_now() >= self.session_expires_at
    }

    pub fn is_session_valid(&self) -> bool {
        !self.session_token.is_empty() && {
            let now = unix_now();
            // Allow a 60-second grace window for clock skew
            self.session_expires_at > now.saturating_sub(60)
        }
    }
}

// ── Profile store ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProfileStore {
    pub profiles: Vec<Profile>,
    /// ID of the last-used profile (auto-selected on launch).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub active_id: String,
}

/// Session secret kept in the OS keychain instead of profiles.json: the
/// NxLSession token and the full session struct. Matches the reference launcher's cookie blob.
#[derive(Serialize, Deserialize, Default)]
struct KeySecret {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    session_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<crate::launcher::auth::NexonSession>,
}

impl ProfileStore {
    pub fn load() -> Result<Self> {
        let path = profiles_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Cannot read profiles.json: {}", e))?;
        let mut store: ProfileStore =
            serde_json::from_str(&text).map_err(|e| anyhow!("Corrupt profiles.json: {}", e))?;
        // Keychain-backed sessions: hydrate secrets out of the OS store, and
        // transparently migrate any plaintext tokens still sitting in the file.
        if crate::launcher::keystore::available() {
            let mut has_plaintext = false;
            for p in &mut store.profiles {
                if !p.session_token.is_empty() || p.session.is_some() {
                    // Plaintext secret still in the file: migrated below.
                    has_plaintext = true;
                } else if let Some(blob) = crate::launcher::keystore::load_secret(&p.id) {
                    if let Ok(secret) = serde_json::from_str::<KeySecret>(&blob) {
                        p.session_token = secret.session_token;
                        p.session = secret.session;
                    }
                }
            }
            if has_plaintext {
                // First-load migration: move plaintext secrets into the keychain
                // and rewrite the file. Per profile, a secret is only blanked in
                // the file once its own keychain write succeeded, so a failed
                // write keeps it in the file (retried next load) instead of
                // losing it. Non-fatal if the rewrite fails (hydrated anyway).
                let _ = store.write_file(true);
            }
        }
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        self.write_file(crate::launcher::keystore::available())
    }

    /// Write profiles.json. When `strip_secrets` is set (keychain available),
    /// session tokens are written to the keychain and blanked in the file.
    fn write_file(&self, strip_secrets: bool) -> Result<()> {
        let path = profiles_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = if strip_secrets {
            serde_json::to_string_pretty(&self.stripped_copy(crate::launcher::keystore::store_secret))?
        } else {
            serde_json::to_string_pretty(self)?
        };
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Persist each profile's secret via `store` (the keychain) and return a
    /// copy for profiles.json. Only profiles whose own write succeeded have
    /// their secrets blanked; any other keeps them in the file, so a failed
    /// keychain write never loses a session.
    fn stripped_copy(&self, mut store: impl FnMut(&str, &str) -> Result<(), String>) -> ProfileStore {
        let mut out = ProfileStore { active_id: self.active_id.clone(), profiles: Vec::with_capacity(self.profiles.len()) };
        for p in &self.profiles {
            let mut copy = p.clone();
            if !p.session_token.is_empty() || p.session.is_some() {
                let secret = KeySecret { session_token: p.session_token.clone(), session: p.session.clone() };
                let stored = serde_json::to_string(&secret)
                    .map_err(|e| e.to_string())
                    .and_then(|blob| store(&p.id, &blob))
                    .is_ok();
                if stored {
                    copy.session_token = String::new();
                    copy.session = None;
                }
            }
            out.profiles.push(copy);
        }
        out
    }

    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    pub fn upsert(&mut self, profile: Profile) {
        if let Some(existing) = self.get_mut(&profile.id) {
            *existing = profile;
        } else {
            self.profiles.push(profile);
        }
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.active_id == id {
            self.active_id = self.profiles.first().map(|p| p.id.clone()).unwrap_or_default();
        }
        self.profiles.len() < before
    }

    pub fn active(&self) -> Option<&Profile> {
        if self.active_id.is_empty() {
            self.profiles.first()
        } else {
            self.get(&self.active_id)
        }
    }
}

// ── Public operations ─────────────────────────────────────────────────────────

/// List all saved profiles (without exposing session tokens).
pub fn list_profiles() -> Result<Vec<ProfileSummary>> {
    let store = ProfileStore::load()?;
    Ok(store.profiles.iter().map(ProfileSummary::from).collect())
}

/// Create or update a profile. Returns the profile ID.
pub fn save_profile(profile: Profile) -> Result<String> {
    let mut store = ProfileStore::load()?;
    let id = profile.id.clone();
    store.upsert(profile);
    store.save()?;
    Ok(id)
}

/// Delete a profile by ID.
pub fn delete_profile(id: &str) -> Result<bool> {
    let mut store = ProfileStore::load()?;
    let deleted = store.delete(id);
    if deleted {
        // Remove the keychain-held session too, so it doesn't linger.
        crate::launcher::keystore::delete_secret(id);
    }
    store.save()?;
    Ok(deleted)
}

/// Load the full profile (including session token) by ID.
pub fn load_profile(id: &str) -> Result<Profile> {
    let store = ProfileStore::load()?;
    store.get(id).cloned().ok_or_else(|| anyhow!("Profile '{}' not found", id))
}

/// Set the active profile and persist.
pub fn set_active_profile(id: &str) -> Result<()> {
    let mut store = ProfileStore::load()?;
    if store.get(id).is_none() {
        return Err(anyhow!("Profile '{}' not found", id));
    }
    store.active_id = id.to_string();
    store.save()
}

/// Update session token + expiry on a profile after login.
pub fn update_session(id: &str, session_token: &str, expires_in_secs: i32) -> Result<()> {
    let mut store = ProfileStore::load()?;
    let profile = store.get_mut(id).ok_or_else(|| anyhow!("Profile '{}' not found", id))?;
    profile.session_token = session_token.to_string();
    // Keep the stored full session in step, so it doesn't override the newer token.
    if let Some(s) = profile.session.as_mut() {
        s.session_token = session_token.to_string();
    }
    profile.session_expires_at = unix_now() + expires_in_secs.max(0) as u64;
    profile.last_login_at = unix_now();
    store.save()
}

/// Store a full session (and its NxLSession) on a profile after login/refresh.
pub fn save_session(id: &str, session: &crate::launcher::auth::NexonSession, expires_in_secs: i32) -> Result<()> {
    let mut store = ProfileStore::load()?;
    let profile = store.get_mut(id).ok_or_else(|| anyhow!("Profile not found: {}", id))?;
    profile.session_token = session.session_token.clone();
    // 0 = "unknown": use the expiry of an in-place refresh, if one happened.
    let expires_in_secs = if expires_in_secs > 0 {
        expires_in_secs
    } else {
        session.refreshed_expires_in.unwrap_or(0)
    };
    profile.session = Some(crate::launcher::auth::NexonSession { refreshed_expires_in: None, ..session.clone() });
    if expires_in_secs > 0 {
        profile.session_expires_at = unix_now() + expires_in_secs as u64;
    }
    profile.last_login_at = unix_now();
    store.save()
}

// ── Summary (safe for IPC — no session token) ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub email: String,
    pub client_dir: String,
    pub auto_login: bool,
    pub has_session: bool,
    pub session_valid: bool,
    /// Unix time the stored session (NxLSession) expires; 0 = unknown / none.
    #[serde(default)]
    pub session_expires_at: u64,
    pub created_at: u64,
    pub last_login_at: u64,
    pub profile_type: String,
    pub login_ip: String,
    pub login_port: u16,
    pub chat_ip: String,
    pub chat_port: u16,
    pub is_official: bool,
}

impl From<&Profile> for ProfileSummary {
    fn from(p: &Profile) -> Self {
        Self {
            id: p.id.clone(),
            name: p.name.clone(),
            email: p.email.clone(),
            client_dir: p.client_dir.clone(),
            auto_login: p.auto_login,
            has_session: !p.session_token.is_empty(),
            session_valid: p.is_session_valid(),
            session_expires_at: if p.session_token.is_empty() { 0 } else { p.session_expires_at },
            created_at: p.created_at,
            last_login_at: p.last_login_at,
            profile_type: p.profile_type.clone(),
            login_ip: p.login_ip.clone(),
            login_port: p.login_port,
            chat_ip: p.chat_ip.clone(),
            chat_port: p.chat_port,
            is_official: p.is_official,
        }
    }
}

/// Compact time left until `expires_at` (unix seconds) at `now`: "29d 4h",
/// "2h 15m", "45m", "<1m" or "Expired". `None` when the expiry is unknown (0).
/// The GUI shows the same countdown (gui/src/app.ts `formatExpiry`).
pub fn format_expiry(expires_at: u64, now: u64) -> Option<String> {
    if expires_at == 0 {
        return None;
    }
    if now >= expires_at {
        return Some("Expired".into());
    }
    let left = expires_at - now;
    let (d, h, m) = (left / 86_400, left % 86_400 / 3_600, left % 3_600 / 60);
    Some(if d > 0 {
        format!("{}d {}h", d, h)
    } else if h > 0 {
        format!("{}h {}m", h, m)
    } else if m > 0 {
        format!("{}m", m)
    } else {
        "<1m".into()
    })
}

/// [`format_expiry`] of this profile's session, now.
pub fn session_time_left(p: &Profile) -> Option<String> {
    format_expiry(p.session_expires_at, unix_now())
}

// ── Storage path ──────────────────────────────────────────────────────────────

fn profiles_path() -> Result<PathBuf> {
    Ok(data_dir().join("profiles.json"))
}

/// `%APPDATA%\mabi-patcher` on Windows, `~/.config/mabi-patcher` elsewhere.
pub fn data_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        dirs_next()
    };
    base.join("mabi-patcher")
}

#[cfg(windows)]
fn dirs_next() -> PathBuf { PathBuf::from(".") }
#[cfg(not(windows))]
fn dirs_next() -> PathBuf {
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".config"))
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_uuid() -> String {
    // Simple UUID v4 without external crate.
    // Seeds with the time in nanoseconds, the pid, a per-process counter and a stack
    // address, so ids created in the same second (or the same call site) differ.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = nanos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let dummy = 0u64;
    let addr = &dummy as *const _ as u64;
    let seed = (t ^ addr ^ ((std::process::id() as u64) << 32) ^ count.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1;
    let mut state = seed;
    let mut next = || -> u8 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state & 0xff) as u8
    };
    let mut b = [0u8; 16];
    for byte in &mut b { *byte = next(); }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_countdown_format() {
        let now = 1_700_000_000;
        assert_eq!(format_expiry(0, now), None);
        assert_eq!(format_expiry(now - 5, now).as_deref(), Some("Expired"));
        assert_eq!(format_expiry(now, now).as_deref(), Some("Expired"));
        assert_eq!(format_expiry(now + 30, now).as_deref(), Some("<1m"));
        assert_eq!(format_expiry(now + 45 * 60 + 59, now).as_deref(), Some("45m"));
        assert_eq!(format_expiry(now + 2 * 3600 + 15 * 60, now).as_deref(), Some("2h 15m"));
        assert_eq!(format_expiry(now + 3600, now).as_deref(), Some("1h 0m"));
        assert_eq!(format_expiry(now + 29 * 86400 + 4 * 3600 + 59 * 60, now).as_deref(), Some("29d 4h"));
        assert_eq!(format_expiry(now + 86400, now).as_deref(), Some("1d 0h"));
    }

    #[test]
    fn session_expired_only_when_known() {
        let mut p = Profile::new("x", "x@example.com");
        assert!(!p.session_expired(), "unknown expiry");
        p.session_expires_at = unix_now() - 10;
        assert!(p.session_expired());
        p.session_expires_at = unix_now() + 3600;
        assert!(!p.session_expired());
        p.session_token = "tok".into();
        assert_eq!(ProfileSummary::from(&p).session_expires_at, p.session_expires_at);
        p.session_token.clear();
        assert_eq!(ProfileSummary::from(&p).session_expires_at, 0, "no session, no countdown");
    }

    #[test]
    fn stripped_copy_keeps_secrets_whose_keychain_write_failed() {
        let mut ok = Profile::new("ok", "a@example.com");
        ok.session_token = "tok-a".into();
        let mut bad = Profile::new("bad", "b@example.com");
        bad.session_token = "tok-b".into();
        let none = Profile::new("none", "c@example.com");
        let bad_id = bad.id.clone();
        let store = ProfileStore { profiles: vec![ok, bad, none], active_id: String::new() };

        let mut written = Vec::new();
        let out = store.stripped_copy(|id, blob| {
            if id == bad_id { return Err("blob too large".into()); }
            written.push((id.to_string(), blob.to_string()));
            Ok(())
        });

        assert_eq!(out.profiles[0].session_token, "", "stored secret is blanked");
        assert_eq!(out.profiles[1].session_token, "tok-b", "failed write keeps the secret in the file");
        assert_eq!(out.profiles[2].session_token, "");
        assert_eq!(written.len(), 1, "profiles without a secret are not written");
        assert!(written[0].1.contains("tok-a"));
    }
}
