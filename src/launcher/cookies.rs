// Import Nexon session cookies from the user's installed browsers.
//
// Browser cookie import:
//   - Firefox   : plaintext SQLite (`cookies.sqlite`, table `moz_cookies`).
//   - Chrome / Edge / Brave (Windows) : encrypted SQLite (`Network/Cookies`),
//     AES-256-GCM `v10` cookies decrypted with the master key from `Local State`,
//     legacy (no prefix) cookies via DPAPI. Reuses `cookie_dec`.
//
// The Chrome 127+ `v20` app-bound scheme moves the key into a privileged
// service; it cannot be decrypted from outside the browser, and the in-process
// memory-scan fallback some tools use is intentionally NOT implemented. When `v20`
// cookies are seen they are reported (`v20_found`) so the UI can tell the user
// to use the browser (SSO) login instead.
//
// We collect every nexon.com cookie, then hand them to
// `auth::session_from_browser_cookies` (NxLSession directly, else a TpaSession
// exchange) exactly like the WebView2 / Nexon-Launcher import paths.

use anyhow::{anyhow, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::auth::{self, NexonSession};

/// A browser we know how to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    Firefox,
    Chrome,
    Edge,
    Brave,
}

impl Browser {
    pub fn name(self) -> &'static str {
        match self {
            Browser::Firefox => "Firefox",
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Brave => "Brave",
        }
    }
}

/// Outcome of a browser scan.
#[derive(Debug, Default, Serialize)]
pub struct BrowserImport {
    /// The session built from the cookies, if a usable one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<NexonSession>,
    /// Which browser the session came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<&'static str>,
    /// True when Chrome 127+ app-bound (`v20`) cookies were seen but could not be
    /// decrypted — the user should use the browser (SSO) login instead.
    pub v20_found: bool,
    /// Human-readable notes per browser (what was found / why it was skipped).
    pub notes: Vec<String>,
}

/// Scan all supported browsers in priority order (Firefox, Chrome, Edge, Brave)
/// for a Nexon session. Stops at the first browser that yields a usable session.
/// `device_id` is used for a TpaSession exchange when no NxLSession is present.
pub fn import_from_browsers(device_id: &str) -> Result<BrowserImport> {
    let mut out = BrowserImport::default();
    for browser in [Browser::Firefox, Browser::Chrome, Browser::Edge, Browser::Brave] {
        match read_browser(browser) {
            Ok(scan) => {
                if scan.v20_found {
                    out.v20_found = true;
                }
                if scan.cookies.is_empty() {
                    if scan.v20_found {
                        out.notes.push(format!(
                            "{}: Chrome 127+ app-bound (v20) cookies found but not decryptable — use the browser login.",
                            browser.name()
                        ));
                    }
                    continue;
                }
                match auth::session_from_browser_cookies(&scan.cookies, device_id) {
                    Ok(Some(session)) => {
                        out.notes.push(format!("{}: session imported.", browser.name()));
                        out.session = Some(session);
                        out.browser = Some(browser.name());
                        return Ok(out);
                    }
                    Ok(None) => out.notes.push(format!(
                        "{}: nexon.com cookies found but no NxLSession/TpaSession yet.",
                        browser.name()
                    )),
                    Err(e) => out.notes.push(format!("{}: cookie exchange failed: {}", browser.name(), e)),
                }
            }
            Err(e) => out.notes.push(format!("{}: {}", browser.name(), e)),
        }
    }
    Ok(out)
}

/// Cookies read from one browser, plus whether undecryptable v20 cookies were seen.
struct BrowserScan {
    cookies: HashMap<String, String>,
    v20_found: bool,
}

fn read_browser(browser: Browser) -> Result<BrowserScan> {
    match browser {
        Browser::Firefox => read_firefox(),
        Browser::Chrome | Browser::Edge | Browser::Brave => read_chromium(browser),
    }
}

// ── Firefox (plaintext SQLite) ─────────────────────────────────────────────────

fn firefox_root() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Mozilla").join("Firefox"))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".mozilla").join("firefox"))
    }
}

/// Firefox profile dir, from profiles.ini: an `[Install*] Default=` entry first,
/// then a `[Profile*] Default=1`, then any profile holding `cookies.sqlite`.
pub fn find_firefox_profile() -> Option<PathBuf> {
    find_firefox_profile_in(&firefox_root()?)
}

/// [`find_firefox_profile`] under an explicit Firefox root (holding profiles.ini).
fn find_firefox_profile_in(root: &Path) -> Option<PathBuf> {
    let ini = std::fs::read_to_string(root.join("profiles.ini")).ok()?;
    let rel = |p: &str| {
        let p = p.trim();
        if p.is_empty() { None } else { Some(root.join(p)) }
    };
    // Parse into (section, key→value) groups.
    let mut sections: Vec<(String, HashMap<String, String>)> = Vec::new();
    for line in ini.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            sections.push((name.to_string(), HashMap::new()));
        } else if let Some((k, v)) = line.split_once('=') {
            if let Some((_, map)) = sections.last_mut() {
                map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
    }
    // 1. [Install*] Default= (the active installation's profile path).
    for (name, map) in &sections {
        if name.to_ascii_lowercase().starts_with("install") {
            if let Some(p) = map.get("default").and_then(|p| rel(p)) {
                if p.join("cookies.sqlite").is_file() { return Some(p); }
            }
        }
    }
    // 2. [Profile*] with Default=1.
    for (name, map) in &sections {
        if name.to_ascii_lowercase().starts_with("profile") && map.get("default").map(|v| v == "1").unwrap_or(false) {
            if let Some(p) = map.get("path").and_then(|p| rel(p)) {
                if p.join("cookies.sqlite").is_file() { return Some(p); }
            }
        }
    }
    // 3. Any profile that actually has cookies.sqlite.
    for (name, map) in &sections {
        if name.to_ascii_lowercase().starts_with("profile") {
            if let Some(p) = map.get("path").and_then(|p| rel(p)) {
                if p.join("cookies.sqlite").is_file() { return Some(p); }
            }
        }
    }
    None
}

fn read_firefox() -> Result<BrowserScan> {
    let profile = find_firefox_profile().ok_or_else(|| anyhow!("no Firefox profile with cookies found"))?;
    let db = profile.join("cookies.sqlite");
    // Copy first (Firefox may hold a lock, even in WAL mode); the -wal/-shm
    // sidecars come along so recent, not-yet-checkpointed cookies are seen.
    let copy = PrivateDbCopy::new(&db).map_err(|e| anyhow!("copy cookies.sqlite: {}", e))?;
    let result = (|| -> Result<HashMap<String, String>> {
        let conn = rusqlite::Connection::open(&copy.db)?;
        let mut stmt = conn.prepare(&format!("SELECT name, value FROM moz_cookies WHERE {}", nexon_host_filter("host")))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut map = HashMap::new();
        for row in rows.flatten() {
            if !row.1.is_empty() { map.insert(row.0, row.1); }
        }
        Ok(map)
    })();
    drop(copy);
    Ok(BrowserScan { cookies: result?, v20_found: false })
}

// ── Chromium (Chrome / Edge / Brave) ───────────────────────────────────────────

fn chromium_user_data(browser: Browser) -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")?;
    let base = PathBuf::from(local);
    let sub = match browser {
        Browser::Chrome => base.join("Google").join("Chrome").join("User Data"),
        Browser::Edge => base.join("Microsoft").join("Edge").join("User Data"),
        Browser::Brave => base.join("BraveSoftware").join("Brave-Browser").join("User Data"),
        Browser::Firefox => return None,
    };
    Some(sub)
}

fn read_chromium(browser: Browser) -> Result<BrowserScan> {
    let user_data = chromium_user_data(browser).ok_or_else(|| anyhow!("LOCALAPPDATA not set"))?;
    let db = user_data.join("Default").join("Network").join("Cookies");
    if !db.exists() {
        return Err(anyhow!("{} not installed or no cookie store", browser.name()));
    }
    let key = super::cookie_dec::get_chromium_key(&user_data.join("Local State")).ok();

    let copy = PrivateDbCopy::new(&db).map_err(|e| anyhow!("copy Cookies db: {}", e))?;
    let result = (|| -> Result<(HashMap<String, String>, bool)> {
        let conn = rusqlite::Connection::open(&copy.db)?;
        let db_version = chromium_db_version(&conn);
        let mut stmt = conn.prepare(&format!(
            "SELECT name, value, encrypted_value FROM cookies WHERE {}",
            nexon_host_filter("host_key")
        ))?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
        })?;
        let mut map = HashMap::new();
        let mut v20 = false;
        for row in rows.flatten() {
            let (name, plain, enc) = row;
            let value = if !plain.is_empty() {
                plain
            } else if enc.len() >= 3 && &enc[0..3] == b"v20" {
                // App-bound (Chrome 127+): not decryptable from outside the browser.
                v20 = true;
                String::new()
            } else if let (false, Some(k)) = (enc.is_empty(), key.as_deref()) {
                super::cookie_dec::decrypt_cookie(&enc, k, db_version).unwrap_or_default()
            } else if !enc.is_empty() {
                super::cookie_dec::dpapi_decrypt(&enc)
                    .ok()
                    .and_then(|b| String::from_utf8(super::cookie_dec::strip_host_hash(&b, db_version).to_vec()).ok())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            if !value.is_empty() { map.insert(name, value); }
        }
        Ok((map, v20))
    })();
    drop(copy);
    let (cookies, v20_found) = result?;
    Ok(BrowserScan { cookies, v20_found })
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

/// SQL condition matching nexon.com and its subdomains only (a bare
/// `LIKE '%nexon.com'` would also match e.g. `evilnexon.com`).
pub(crate) fn nexon_host_filter(col: &str) -> String {
    format!("({c} = 'nexon.com' OR {c} = '.nexon.com' OR {c} LIKE '%.nexon.com')", c = col)
}

/// Chromium cookie DB schema version (`meta.version`), 0 if unknown.
pub(crate) fn chromium_db_version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'version'", [], |r| r.get(0))
        .unwrap_or(0)
}

/// A private copy of a browser cookie DB (plus its `-wal` / `-shm` sidecars,
/// when present) in a fresh, uniquely named temp dir that only we can access
/// (0700 / files 0600 on unix, created exclusively so nothing pre-planted in
/// the shared temp dir is followed). Removed on drop.
pub(crate) struct PrivateDbCopy {
    dir: PathBuf,
    pub db: PathBuf,
}

impl PrivateDbCopy {
    pub(crate) fn new(src: &Path) -> std::io::Result<Self> {
        Self::new_in(&std::env::temp_dir(), src)
    }

    fn new_in(parent: &Path, src: &Path) -> std::io::Result<Self> {
        let dir = create_private_dir(parent)?;
        let copy = PrivateDbCopy { db: dir.join("cookies.db"), dir };
        copy_private(src, &copy.db)?;
        for suffix in ["-wal", "-shm"] {
            let side = PathBuf::from(format!("{}{}", src.display(), suffix));
            if side.is_file() {
                copy_private(&side, &PathBuf::from(format!("{}{}", copy.db.display(), suffix)))?;
            }
        }
        Ok(copy)
    }
}

impl Drop for PrivateDbCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn create_private_dir(parent: &Path) -> std::io::Result<PathBuf> {
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for _ in 0..16 {
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = parent.join(format!("mabi-cookies-{}-{:08x}-{}", std::process::id(), nanos, seq));
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "could not create a private temp dir"))
}

fn copy_private(src: &Path, dest: &Path) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut out = opts.open(dest)?;
    std::io::copy(&mut std::fs::File::open(src)?, &mut out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_profile_parsing_prefers_install_then_default() {
        let dir = std::env::temp_dir().join(format!("mabi_ff_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let base = dir.join("firefox");
        std::fs::create_dir_all(base.join("inst.default")).unwrap();
        std::fs::create_dir_all(base.join("def.profile")).unwrap();
        std::fs::write(base.join("inst.default/cookies.sqlite"), b"").unwrap();
        std::fs::write(base.join("def.profile/cookies.sqlite"), b"").unwrap();
        std::fs::write(base.join("profiles.ini"),
            "[Install123]\nDefault=inst.default\n\n[Profile0]\nPath=def.profile\nDefault=1\n").unwrap();
        let got = find_firefox_profile_in(&base);
        assert_eq!(got, Some(base.join("inst.default")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_filter_matches_nexon_and_subdomains_only() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE c (host TEXT);").unwrap();
        for h in ["nexon.com", ".nexon.com", "www.nexon.com", ".login.nexon.com", "evilnexon.com", "nexon.com.evil.io"] {
            conn.execute("INSERT INTO c VALUES (?1)", [h]).unwrap();
        }
        let mut stmt = conn.prepare(&format!("SELECT host FROM c WHERE {} ORDER BY host", nexon_host_filter("host"))).unwrap();
        let hosts: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(hosts, [".login.nexon.com", ".nexon.com", "nexon.com", "www.nexon.com"]);
    }

    #[test]
    fn chromium_meta_version_is_read() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert_eq!(chromium_db_version(&conn), 0, "no meta table");
        conn.execute_batch("CREATE TABLE meta (key TEXT, value LONGVARCHAR); INSERT INTO meta VALUES ('version', '24');").unwrap();
        assert_eq!(chromium_db_version(&conn), 24);
    }

    #[test]
    fn private_copy_includes_sidecars_and_is_removed() {
        let dir = std::env::temp_dir().join(format!("mabi_cookie_copy_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("cookies.sqlite");
        std::fs::write(&src, b"db").unwrap();
        std::fs::write(dir.join("cookies.sqlite-wal"), b"wal").unwrap();
        let copy = PrivateDbCopy::new_in(&dir, &src).unwrap();
        assert_eq!(std::fs::read(&copy.db).unwrap(), b"db");
        assert_eq!(std::fs::read(format!("{}-wal", copy.db.display())).unwrap(), b"wal");
        assert!(!PathBuf::from(format!("{}-shm", copy.db.display())).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&copy.dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(&copy.db).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let copy_dir = copy.dir.clone();
        drop(copy);
        assert!(!copy_dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
