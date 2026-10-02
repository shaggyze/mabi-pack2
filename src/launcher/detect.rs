// Find an existing Mabinogi install (game-exe search).
//
// Order: Nexon Launcher's appconfig.json, Windows uninstall entries, then
// well-known install folders on every fixed drive. Off Windows the same
// folders are searched inside Wine prefixes (~/.wine*, Lutris ~/Games,
// Bottles, Steam/Proton compatdata).

use std::path::{Path, PathBuf};

const PRODUCT_ID: &str = "10200";

const INSTALL_DIRS: [&str; 7] = [
    "Nexon/Library/mabinogi",
    "Program Files/Nexon/Library/mabinogi",
    "Program Files (x86)/Nexon/Library/mabinogi",
    "Nexon/Mabinogi",
    "Program Files/Nexon/Mabinogi",
    "Program Files (x86)/Nexon/Mabinogi",
    "Program Files (x86)/Mabinogi",
];

/// Path to Client.exe of the first install found.
pub fn find_game_exe() -> Option<PathBuf> {
    from_nexon_config()
        .or_else(from_uninstall)
        .or_else(|| roots().iter().find_map(|r| INSTALL_DIRS.iter().find_map(|d| exe_in_dir(&r.join(d)))))
}

/// Every distinct Mabinogi install found (Nexon config, uninstall entries and the
/// well-known folders on each drive/prefix). Used by the multi-folder check
/// (`update --all-folders`). De-duplicated, order-preserving.
pub fn find_all_game_exes() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: Option<PathBuf>| {
        if let Some(p) = p {
            let c = std::fs::canonicalize(&p).unwrap_or(p);
            if !out.contains(&c) { out.push(c); }
        }
    };
    push(from_nexon_config());
    push(from_uninstall());
    for r in roots() {
        for d in INSTALL_DIRS {
            push(exe_in_dir(&r.join(d)));
        }
    }
    out
}

/// Client.exe in an install folder: under appdata/ or directly.
pub fn exe_in_dir(dir: &Path) -> Option<PathBuf> {
    ["appdata/Client.exe", "Client.exe"].iter().map(|s| dir.join(s)).find(|p| p.is_file())
}

fn from_nexon_config() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    let text = std::fs::read_to_string(Path::new(&appdata).join("Nexon Launcher").join("appconfig.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let app = &v["installedApps"][PRODUCT_ID];
    let exe = Path::new(app["installPath"].as_str()?).join(app["exePath"].as_str()?);
    exe.is_file().then_some(exe)
}

#[cfg(windows)]
fn from_uninstall() -> Option<PathBuf> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    use winreg::RegKey;
    const UNINST: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let Ok(key) = RegKey::predef(root).open_subkey_with_flags(UNINST, KEY_READ | view) else { continue };
            for name in key.enum_keys().flatten() {
                let Ok(sub) = key.open_subkey_with_flags(&name, KEY_READ | view) else { continue };
                let display: String = sub.get_value("DisplayName").unwrap_or_default();
                if !display.to_lowercase().contains("mabinogi") {
                    continue;
                }
                let loc: String = sub.get_value("InstallLocation").unwrap_or_default();
                if let Some(exe) = exe_in_dir(Path::new(&loc)) {
                    return Some(exe);
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn from_uninstall() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn roots() -> Vec<PathBuf> {
    (b'C'..=b'Y').map(|d| PathBuf::from(format!("{}:\\", d as char))).filter(|p| p.is_dir()).collect()
}

#[cfg(not(windows))]
fn roots() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return Vec::new() };
    let mut out = Vec::new();
    if let Some(prefix) = std::env::var_os("WINEPREFIX") {
        out.push(PathBuf::from(prefix).join("drive_c"));
    }
    let mut add = |parent: PathBuf, name_prefix: &str, inner: &str| {
        if let Ok(entries) = std::fs::read_dir(&parent) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().starts_with(name_prefix) {
                    out.push(e.path().join(inner).join("drive_c"));
                }
            }
        }
    };
    add(home.clone(), ".wine", "");
    add(home.join("Games"), "", "");
    add(home.join(".local/share/bottles/bottles"), "", "");
    for steam in [
        ".local/share/Steam/steamapps/compatdata",
        ".steam/steam/steamapps/compatdata",
        ".var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/compatdata",
    ] {
        add(home.join(steam), "", "pfx");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_client_under_appdata_or_directly() {
        let dir = std::env::temp_dir().join(format!("detect-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/appdata")).unwrap();
        std::fs::create_dir_all(dir.join("b")).unwrap();
        std::fs::write(dir.join("a/appdata/Client.exe"), b"").unwrap();
        std::fs::write(dir.join("b/Client.exe"), b"").unwrap();
        assert_eq!(exe_in_dir(&dir.join("a")), Some(dir.join("a/appdata/Client.exe")));
        assert_eq!(exe_in_dir(&dir.join("b")), Some(dir.join("b/Client.exe")));
        assert_eq!(exe_in_dir(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
