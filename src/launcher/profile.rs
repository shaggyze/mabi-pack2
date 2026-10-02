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
            login_ip: String::new(),
            login_port: 0,
            chat_ip: String::new(),
            chat_port: 0,
            is_official: true,
        }
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

impl ProfileStore {
    pub fn load() -> Result<Self> {
        let path = profiles_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Cannot read profiles.json: {}", e))?;
        serde_json::from_str(&text).map_err(|e| anyhow!("Corrupt profiles.json: {}", e))
    }

    pub fn save(&self) -> Result<()> {
        let path = profiles_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(())
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
    profile.session_expires_at = unix_now() + expires_in_secs.max(0) as u64;
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
    // Seeds with current time + stack address for uniqueness without rand crate.
    let t = unix_now().wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    let dummy = 0u64;
    let addr = &dummy as *const _ as u64;
    let seed = t ^ addr;
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
