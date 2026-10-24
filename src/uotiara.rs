//! The uotiara mod installer's registry record (Tiara's Moonshine Mod).
//!
//! The NSIS installer is 32-bit, so its key sits in the WOW6432Node view:
//! `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\UO Tiaras Moonshine Mod`
//! with `DisplayVersion` ("514.0.74.83"), `InstallSource`, `UninstallString`
//! and one `Components\MOD<n>` subkey per mod. Each subkey's default value is
//! the mod name and its `Installed` DWORD (1/0) is the checkbox state the
//! installer restores on its next run (`InitSection` in uotiara.nsi).
//! MOD numbers are the same ids as the website catalog's `id`.

use anyhow::Result;
use serde::Serialize;

pub const UNINSTALL_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\UO Tiaras Moonshine Mod";

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct UotiaraMod {
    pub id: u32,
    pub name: String,
    pub installed: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct UotiaraInstall {
    /// `DisplayVersion`, for example "480.0.73.81".
    pub version: String,
    /// The game version the build targets: the first number of `version`.
    pub game_version: u32,
    pub install_source: String,
    pub uninstaller: String,
    pub mods: Vec<UotiaraMod>,
}

/// `"MOD123"` → 123. Other subkeys (and `MOD12?3` variants) are skipped.
pub fn mod_id(subkey: &str) -> Option<u32> {
    subkey.strip_prefix("MOD").filter(|r| !r.is_empty()).and_then(|r| r.parse().ok())
}

/// `"480.0.73.81"` → 480.
pub fn game_version(display_version: &str) -> u32 {
    display_version.split('.').next().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// Latest uotiara release on GitHub as `(version, page url)`, for example
/// `("514.0.74.82", "https://github.com/shaggyze/uotiara/releases/tag/V514.0.74.82")`.
pub fn latest_release() -> Result<(String, String)> {
    let v: serde_json::Value = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("mabi-patcher")
        .build()?
        .get("https://api.github.com/repos/shaggyze/uotiara/releases/latest")
        .send()?
        .error_for_status()?
        .json()?;
    let tag = v["tag_name"].as_str().unwrap_or_default();
    let version = tag.trim_start_matches(['V', 'v']).to_string();
    if version.is_empty() {
        anyhow::bail!("the latest uotiara release has no tag");
    }
    Ok((version, v["html_url"].as_str().unwrap_or_default().to_string()))
}

#[cfg(windows)]
fn open_key(flags: u32) -> std::io::Result<winreg::RegKey> {
    use winreg::{enums::*, RegKey};
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey_with_flags(UNINSTALL_KEY, flags | KEY_WOW64_32KEY)
        .or_else(|_| hklm.open_subkey_with_flags(UNINSTALL_KEY, flags | KEY_WOW64_64KEY))
}

/// The installed uotiara record, or `None` when the installer never ran.
#[cfg(windows)]
pub fn read_install() -> Result<Option<UotiaraInstall>> {
    use winreg::enums::*;
    let key = match open_key(KEY_READ) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let version: String = key.get_value("DisplayVersion").unwrap_or_default();
    let mut mods = Vec::new();
    if let Ok(comps) = key.open_subkey_with_flags("Components", KEY_READ) {
        for name in comps.enum_keys().flatten() {
            let Some(id) = mod_id(&name) else { continue };
            let Ok(sub) = comps.open_subkey_with_flags(&name, KEY_READ) else { continue };
            let installed: u32 = sub.get_value("Installed").unwrap_or(0);
            mods.push(UotiaraMod { id, name: sub.get_value("").unwrap_or_default(), installed: installed == 1 });
        }
    }
    mods.sort_by_key(|m| m.id);
    Ok(Some(UotiaraInstall {
        game_version: game_version(&version),
        version,
        install_source: key.get_value("InstallSource").unwrap_or_default(),
        uninstaller: key.get_value("UninstallString").unwrap_or_default(),
        mods,
    }))
}

/// Set the installer's checkbox state for `ids`. Writing HKLM needs
/// administrator rights. Returns how many mod subkeys were updated (ids the
/// installer has no subkey for are skipped).
#[cfg(windows)]
pub fn set_installed(ids: &[u32], installed: bool) -> Result<usize> {
    use winreg::enums::*;
    let key = open_key(KEY_READ).map_err(|e| anyhow::anyhow!("uotiara is not installed ({})", e))?;
    let comps = key.open_subkey_with_flags("Components", KEY_READ | KEY_WRITE).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow::anyhow!("changing the uotiara installer's mod list needs administrator rights")
        } else {
            anyhow::anyhow!("uotiara Components key: {}", e)
        }
    })?;
    let mut n = 0;
    for id in ids {
        if let Ok(sub) = comps.open_subkey_with_flags(format!("MOD{}", id), KEY_READ | KEY_WRITE) {
            sub.set_value("Installed", &(installed as u32))?;
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(not(windows))]
pub fn read_install() -> Result<Option<UotiaraInstall>> {
    Ok(None)
}

#[cfg(not(windows))]
pub fn set_installed(_ids: &[u32], _installed: bool) -> Result<usize> {
    anyhow::bail!("the uotiara installer only exists on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mod_ids_and_versions() {
        assert_eq!(mod_id("MOD1"), Some(1));
        assert_eq!(mod_id("MOD459"), Some(459));
        assert_eq!(mod_id("MOD"), None);
        assert_eq!(mod_id("MOD12?3"), None);
        assert_eq!(mod_id("Sections"), None);
        assert_eq!(game_version("480.0.73.81"), 480);
        assert_eq!(game_version("514.0.74.83"), 514);
        assert_eq!(game_version(""), 0);
    }

    /// Reads this PC's uotiara record and GitHub's latest release (network).
    #[test]
    #[ignore]
    fn live_install_and_latest() {
        if let Some(i) = read_install().unwrap() {
            let ticked = i.mods.iter().filter(|m| m.installed).count();
            println!("installed {} (game {}), {} of {} mods ticked", i.version, i.game_version, ticked, i.mods.len());
        }
        println!("latest {:?}", latest_release().unwrap());
    }
}
