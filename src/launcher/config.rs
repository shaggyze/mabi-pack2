// Patcher settings shared by the CLI: update ignore list and event hooks.
//
// Stored as JSON next to profiles.json (`profile::data_dir()`), mirroring
// Rua's config.ini [Ignore] and [Hooks] sections.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::profile;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hooks {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub before_patch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub after_patch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub before_launch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub after_launch: String,
}

impl Hooks {
    pub const EVENTS: [&'static str; 4] = ["before-patch", "after-patch", "before-launch", "after-launch"];

    /// Command slot for an event name like `before-patch`.
    pub fn slot(&mut self, event: &str) -> Result<&mut String> {
        Ok(match event.to_ascii_lowercase().replace('_', "-").as_str() {
            "before-patch" => &mut self.before_patch,
            "after-patch" => &mut self.after_patch,
            "before-launch" => &mut self.before_launch,
            "after-launch" => &mut self.after_launch,
            other => return Err(anyhow!("Unknown hook '{}'; use one of {}", other, Self::EVENTS.join(", "))),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Paths or `*`/`?` wildcards the patcher never touches (local mods).
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Shell commands run (fire-and-forget) around patching and launching.
    /// `%PROFILE%` expands to the profile name.
    #[serde(default)]
    pub hooks: Hooks,
}

impl Config {
    pub fn path() -> PathBuf {
        profile::data_dir().join("config.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| anyhow!("Cannot read {}: {}", path.display(), e))?;
        serde_json::from_str(&text).map_err(|e| anyhow!("Corrupt {}: {}", path.display(), e))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_slots_and_roundtrip() {
        let mut c = Config::default();
        *c.hooks.slot("Before_Patch").unwrap() = "echo %PROFILE%".into();
        assert!(c.hooks.slot("bogus").is_err());
        c.ignore.push("mods/*".into());
        let back: Config = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back.hooks.before_patch, "echo %PROFILE%");
        assert_eq!(back.ignore, vec!["mods/*".to_string()]);
        assert!(serde_json::from_str::<Config>("{}").is_ok());
    }
}
