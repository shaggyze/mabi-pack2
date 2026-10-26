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

/// One file of a catalog revision (`/api/mods/catalog` → `versions[].files[]`).
#[derive(serde::Deserialize, Clone, Debug)]
pub struct CatalogFile {
    pub path: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub sha256: String,
}

/// Raw URL of a mod file in the uotiara repository at `commit`.
pub fn github_file_url(commit: &str, path: &str) -> String {
    let enc: String = format!("Tiara's Moonshine Mod/{}", path.trim_start_matches(['/', '\\']).replace('\\', "/"))
        .split('/')
        .map(|seg| seg.bytes().map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'\'' => (b as char).to_string(),
            _ => format!("%{:02X}", b),
        }).collect::<String>())
        .collect::<Vec<_>>()
        .join("/");
    format!("https://raw.githubusercontent.com/shaggyze/uotiara/{}/{}", commit, enc)
}

/// Build one catalog revision without the website: download every file from
/// GitHub at `commit`, check its sha256, and pack them into `dest` (`.it` with
/// `salt`, or a legacy `.pack` with `pack_version`). Revisions that delete game
/// files, or have no commit, need the website's builder instead.
pub fn build_from_github(commit: &str, files: &[CatalogFile], dest: &std::path::Path, salt: &str, pack_version: u32) -> Result<()> {
    use sha2::{Digest, Sha256};
    anyhow::ensure!(!commit.is_empty(), "this version has no GitHub source; sign in to build it on the website");
    anyhow::ensure!(!files.is_empty(), "this version has no files");
    anyhow::ensure!(files.iter().all(|f| f.action.is_empty() || f.action == "replace"),
        "this version deletes game files; sign in to build it on the website");
    let tmp = std::env::temp_dir().join(format!("mabi-patcher-mod-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    let result = (|| -> Result<()> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent("mabi-patcher")
            .build()?;
        for f in files {
            let rel = f.path.trim_start_matches(['/', '\\']).replace('\\', "/");
            anyhow::ensure!(!rel.split('/').any(|s| s == ".." || s.is_empty()) && rel.starts_with("data/"),
                "unsafe path in catalog: {}", f.path);
            let bytes = client.get(github_file_url(commit, &rel)).send()?.error_for_status()
                .map_err(|e| anyhow::anyhow!("{}: {}", rel, e))?.bytes()?;
            if !f.sha256.is_empty() {
                let got = format!("{:x}", Sha256::digest(&bytes));
                anyhow::ensure!(got.eq_ignore_ascii_case(&f.sha256), "{}: sha256 mismatch (got {}, catalog {})", rel, got, f.sha256);
            }
            let out = tmp.join(&rel);
            std::fs::create_dir_all(out.parent().unwrap())?;
            std::fs::write(&out, &bytes)?;
        }
        if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent)?; }
        // The .it header offset is derived from the file name: pack under the final name.
        let out_dir = tmp.with_extension("out");
        std::fs::create_dir_all(&out_dir)?;
        let staged = out_dir.join(dest.file_name().ok_or_else(|| anyhow::anyhow!("bad destination"))?);
        let staged_s = staged.to_string_lossy().to_string();
        let is_pack = dest.extension().map_or(false, |e| e.eq_ignore_ascii_case("pack"));
        if is_pack {
            crate::pack_v1::run_pack_v1(&tmp.join("data").to_string_lossy(), &staged_s, pack_version)?;
        } else {
            crate::pack::run_pack(&tmp.to_string_lossy(), &staged_s, salt, vec![], false, 0, None, None)?;
        }
        std::fs::rename(&staged, dest).or_else(|_| { std::fs::copy(&staged, dest)?; std::fs::remove_file(&staged) })?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(tmp.with_extension("out"));
    result
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

    #[test]
    fn github_urls_keep_the_apostrophe_and_encode_spaces() {
        assert_eq!(github_file_url("abc", "data/db/a b.xml"),
            "https://raw.githubusercontent.com/shaggyze/uotiara/abc/Tiara's%20Moonshine%20Mod/data/db/a%20b.xml");
    }

    /// Builds MOD1 (Artifact Discovery Cutscene Removal) at uotiara commit
    /// cab53a5 from GitHub as .it and .pack, then lists both back (network).
    #[test]
    #[ignore]
    fn live_build_mod1_from_github() {
        let files = vec![CatalogFile {
            path: "data/db/cutscene/C2/iria_finding.xml".into(),
            action: "replace".into(),
            sha256: "7caa188f365f4e14aed807b6400d8d5cb43ba886a7eb16150d2bddbef57a2828".into(),
        }];
        let dir = std::env::temp_dir().join("mp-gh-build-test");
        let it = dir.join("MOD0001.it");
        build_from_github("cab53a5a077e405e64e000845613cda6cfaab875", &files, &it, "})wWb4?-sVGHNoPKpc", 999).unwrap();
        println!("built {}", it.display());

        let pk = dir.join("MOD0001.pack");
        build_from_github("cab53a5a077e405e64e000845613cda6cfaab875", &files, &pk, "", 999).unwrap();
        let names = crate::pack_v1::run_list_v1(&pk.to_string_lossy()).unwrap();
        println!("pack entries: {:?}", names);
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
