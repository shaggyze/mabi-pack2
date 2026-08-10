// Nexon NA authentication for Mabinogi launcher.
//
// Auth flow mirrors Hyddwn Launcher (https://github.com/Hyddwn/HyddwnLauncher):
//   1. Build device ID: SHA256(WMI_UUID + MachineGuid)
//   2. Hash password:   SHA512(password) → lowercase hex
//   3. POST /api/regional-auth/v1.0/no-auth/login/validate  (arena session init)
//   4. POST /api/regional-auth/v1.0/no-auth/launcher/email/login  → cookies
//   5. Persist NxLSession; refresh via autologin on next launch.
//
// Captcha: Hyddwn's default (non-admin) path sends a random 256-char string.
// Nexon accepts this for launcher auth. A real reCAPTCHA v3 bypass (hosts-file
// redirect + local web server, admin-only) is left as future work.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

const NEXON_BASE: &str = "https://www.nexon.com";
const CLIENT_ID: &str = "7853644408";
const SCOPE: &str = "us.launcher.all";
const PRODUCT_ID: &str = "10200";

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexonSession {
    pub access_token: String,
    pub g_access_token: String,
    /// NxLSession cookie — store this and pass to `autologin` on next launch.
    pub session_token: String,
    pub hashed_user_id: String,
}

impl NexonSession {
    pub fn cookie_header(&self) -> String {
        format!(
            "AToken={}; g_AToken={}; NxLSession={}; NexonUserID={}",
            self.access_token, self.g_access_token, self.session_token, self.hashed_user_id
        )
    }
}

#[derive(Debug)]
pub struct LoginResult {
    pub session: NexonSession,
    /// Seconds until NxLSession expires (from response body)
    pub session_expires_in: i32,
}

// ── Request / response structs ────────────────────────────────────────────────

#[derive(Serialize)]
struct ValidateReq<'a> {
    id: &'a str,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
}

#[derive(Serialize)]
struct LoginReq<'a> {
    #[serde(rename = "autoLogin")]
    auto_login: bool,
    #[serde(rename = "captchaToken")]
    captcha_token: String,
    #[serde(rename = "captchaVersion")]
    captcha_version: &'static str,
    #[serde(rename = "clientId")]
    client_id: &'static str,
    #[serde(rename = "deviceId")]
    device_id: String,
    id: &'a str,
    #[serde(rename = "localTime")]
    local_time: u64,
    password: String,
    scope: &'static str,
    #[serde(rename = "timeOffset")]
    time_offset: i64,
}

#[derive(Serialize)]
struct AutoLoginReq {
    #[serde(rename = "deviceId")]
    device_id: String,
}

#[derive(Deserialize, Default)]
struct LoginBody {
    #[serde(rename = "hashedUserNo")]
    hashed_user_no: Option<String>,
    #[serde(rename = "loginSessionExpiresIn")]
    login_session_expires_in: Option<i32>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Full login with username + password. Returns session and expiry.
pub fn login(username: &str, password: &str, remember: bool) -> Result<LoginResult> {
    let dev = device_id("");
    let hashed_pw = hash_password(password);
    let captcha = random_token(256);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let client = build_client()?;

    // Arena session init (fire and forget — failure is non-fatal)
    let _ = client
        .post(format!("{}/api/regional-auth/v1.0/no-auth/login/validate", NEXON_BASE))
        .json(&ValidateReq { id: username, device_id: &dev })
        .send();

    // Main login
    let resp = client
        .post(format!("{}/api/regional-auth/v1.0/no-auth/launcher/email/login", NEXON_BASE))
        .json(&LoginReq {
            auto_login: remember,
            captcha_token: captcha,
            captcha_version: "v3",
            client_id: CLIENT_ID,
            device_id: dev,
            id: username,
            local_time: now_ms,
            password: hashed_pw,
            scope: SCOPE,
            time_offset: 0,
        })
        .send()?;

    parse_login_response(resp)
}

/// Refresh session using a stored NxLSession cookie (no password needed).
/// Call this on launch when a valid saved token exists.
pub fn autologin(session_token: &str) -> Result<LoginResult> {
    let dev = device_id("");
    let client = build_client()?;

    let resp = client
        .post(format!("{}/api/account/v1/no-auth/login/launcher/autologin", NEXON_BASE))
        .header("Cookie", format!("NxLSession={}", session_token))
        .json(&AutoLoginReq { device_id: dev })
        .send()?;

    parse_login_response(resp)
}

/// Check if the game is accessible with this session.
pub fn is_playable(session: &NexonSession) -> Result<bool> {
    #[derive(Serialize)]
    struct Req<'a> { #[serde(rename = "productId")] product_id: &'a str }

    let resp = build_client()?
        .post(format!("{}/api/game-auth2/v1/playable", NEXON_BASE))
        .header("Cookie", session.cookie_header())
        .json(&Req { product_id: PRODUCT_ID })
        .send()?;

    Ok(resp.status().is_success())
}

/// Get a passport token needed as the `/P:` argument when launching Client.exe.
pub fn get_passport(session: &NexonSession) -> Result<String> {
    #[derive(Serialize)]
    struct Req<'a> { #[serde(rename = "productId")] product_id: &'a str }
    #[derive(Deserialize)]
    struct Resp { passport: Option<String> }

    // Confirm the account can play before requesting the passport
    if !is_playable(session)? {
        return Err(anyhow!("Account is not playable (maintenance or subscription issue)"));
    }

    let resp = build_client()?
        .post(format!("{}/api/passport/v2/passport", NEXON_BASE))
        .header("Cookie", session.cookie_header())
        .json(&Req { product_id: PRODUCT_ID })
        .send()?;

    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if !status.is_success() {
        return Err(anyhow!("Passport request failed ({}): {}", status, body));
    }

    let parsed: Resp = serde_json::from_str(&body)
        .map_err(|e| anyhow!("Passport parse error ({}): body={}", e, body))?;

    parsed.passport.ok_or_else(|| anyhow!("Passport response has no passport field"))
}

/// Import session tokens from the running Nexon Launcher's cookie store.
/// Reads %APPDATA%\NexonLauncher\Network\Cookies (SQLite) via Python.
pub fn import_from_nexon_launcher() -> Result<NexonSession> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| anyhow!("APPDATA not set"))?;

    let cookies_db = std::path::PathBuf::from(&appdata)
        .join("NexonLauncher").join("Network").join("Cookies");

    if !cookies_db.exists() {
        return Err(anyhow!("Nexon Launcher not installed or not found"));
    }

    // Copy to temp to avoid SQLite lock conflicts
    let tmp_db = std::env::temp_dir().join("nx_import_cookies.db");
    std::fs::copy(&cookies_db, &tmp_db)
        .map_err(|e| anyhow!("Failed to copy cookie DB: {}", e))?;

    let py = "import sqlite3,json,sys\nconn=sqlite3.connect(sys.argv[1])\nc=conn.cursor()\nc.execute(\"SELECT name,value FROM cookies WHERE host_key LIKE '%nexon%' AND name IN ('AToken','g_AToken','NxLSession','NxGUN')\")\nd={r[0]:r[1] or '' for r in c.fetchall()}\nconn.close()\nprint(json.dumps(d))";

    let tmp_py = std::env::temp_dir().join("nx_read_cookies.py");
    std::fs::write(&tmp_py, py)
        .map_err(|e| anyhow!("Write script failed: {}", e))?;

    let out = std::process::Command::new("python")
        .arg(&tmp_py)
        .arg(tmp_db.to_string_lossy().as_ref())
        .output();

    let _ = std::fs::remove_file(&tmp_py);
    let _ = std::fs::remove_file(&tmp_db);

    let out = out.map_err(|e| anyhow!("Python not available: {}", e))?;

    if !out.status.success() {
        return Err(anyhow!("Cookie read failed: {}", String::from_utf8_lossy(&out.stderr)));
    }

    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let data: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow!("Parse error: {}", e))?;

    let a_token = data["AToken"].as_str().unwrap_or("").to_string();
    let g_token = data["g_AToken"].as_str().unwrap_or("").to_string();
    let session = data["NxLSession"].as_str().unwrap_or("").to_string();
    let user_id = data["NxGUN"].as_str().unwrap_or("").to_string();

    if a_token.is_empty() || session.is_empty() {
        return Err(anyhow!("Nexon Launcher is not logged in (no valid session found)"));
    }

    Ok(NexonSession {
        access_token: a_token.clone(),
        g_access_token: if g_token.is_empty() { a_token } else { g_token },
        session_token: session,
        hashed_user_id: user_id,
    })
}

// ── Device ID ─────────────────────────────────────────────────────────────────

/// Stable per-machine identifier matching Hyddwn's GetDeviceUuid algorithm.
/// SHA256( WMI_UUID + MachineGuid [+ tag] ) → lowercase hex.
pub fn device_id(tag: &str) -> String {
    let mut raw = String::new();

    // Try wmic (available on Windows 10; deprecated but functional)
    if let Some(uuid) = wmi_uuid_via_wmic() {
        raw.push_str(&uuid);
    }

    // Fallback: PowerShell WMI (Windows 11 removed wmic.exe)
    if raw.is_empty() {
        if let Some(uuid) = wmi_uuid_via_powershell() {
            raw.push_str(&uuid);
        }
    }

    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    if let Some(guid) = machine_guid() {
        raw.push_str(&guid);
    }

    if raw.is_empty() {
        // No machine identifiers available — return a session-stable random string.
        // This will change each process launch; store the result in config if needed.
        return random_token(64);
    }

    if !tag.is_empty() {
        raw.push_str(tag);
    }

    let hash = Sha256::digest(raw.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Password hashing ──────────────────────────────────────────────────────────

/// SHA512(password bytes) → lowercase hex string (matches Hyddwn HashPassword).
pub fn hash_password(password: &str) -> String {
    let hash = Sha512::digest(password.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0")
        .build()?)
}

/// Parse a login or autologin response, extracting cookies and body fields.
fn parse_login_response(resp: reqwest::blocking::Response) -> Result<LoginResult> {
    let status = resp.status();

    // Extract Set-Cookie headers BEFORE consuming the body.
    // `resp.headers()` borrows resp; extract owned strings and the borrow ends.
    let (access_token, g_access_token, session_token) = extract_cookies(resp.headers());

    let body_text = resp.text().unwrap_or_default();

    if !status.is_success() {
        return Err(anyhow!("Nexon auth failed ({}): {}", status, body_text));
    }

    if access_token.is_empty() {
        return Err(anyhow!("Auth succeeded but AToken cookie was not set"));
    }

    let body: LoginBody = serde_json::from_str(&body_text).unwrap_or_default();

    Ok(LoginResult {
        session: NexonSession {
            access_token,
            g_access_token,
            session_token,
            hashed_user_id: body.hashed_user_no.unwrap_or_default(),
        },
        session_expires_in: body.login_session_expires_in.unwrap_or(86400),
    })
}

/// Parse AToken, g_AToken, NxLSession from Set-Cookie response headers.
fn extract_cookies(headers: &reqwest::header::HeaderMap) -> (String, String, String) {
    let mut a_token = String::new();
    let mut g_token = String::new();
    let mut nx_session = String::new();

    for value in headers.get_all("set-cookie") {
        if let Ok(s) = value.to_str() {
            // Each Set-Cookie looks like: "Name=Value; Path=/; Domain=..."
            let name_val = s.split(';').next().unwrap_or("").trim();
            if let Some((name, val)) = name_val.split_once('=') {
                match name.trim() {
                    "AToken" => a_token = val.trim().to_string(),
                    "g_AToken" => g_token = val.trim().to_string(),
                    "NxLSession" => nx_session = val.trim().to_string(),
                    _ => {}
                }
            }
        }
    }

    (a_token, g_token, nx_session)
}

/// Get WMI UUID via `wmic csproduct get uuid /format:list`.
fn wmi_uuid_via_wmic() -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("wmic")
            .args(["csproduct", "get", "uuid", "/format:list"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(uuid) = line.strip_prefix("UUID=") {
                let uuid = uuid.trim().to_string();
                if !uuid.is_empty()
                    && !uuid.starts_with("FFFFFFFF")
                    && uuid != "03000200-0400-0500-0006-000700080009"
                {
                    return Some(uuid);
                }
            }
        }
    }
    None
}

/// Get WMI UUID via PowerShell (fallback when wmic.exe is absent).
fn wmi_uuid_via_powershell() -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                "(Get-WmiObject Win32_ComputerSystemProduct).UUID"])
            .creation_flags(0x08000000)
            .output()
            .ok()?;
        let uuid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !uuid.is_empty() && !uuid.starts_with("FFFFFFFF") {
            return Some(uuid);
        }
    }
    None
}

/// Read MachineGuid from Windows registry.
fn machine_guid() -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            .ok()?;
        key.get_value::<String, _>("MachineGuid").ok()
    }
    #[cfg(not(windows))]
    None
}

/// Random alphanumeric+punctuation string (Hyddwn's captcha token fallback).
fn random_token(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789_-";
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as usize;
    (0..len)
        .map(|i| {
            let idx = seed
                .wrapping_add(i * 6364136223846793005_usize)
                .wrapping_add(i)
                % CHARS.len();
            CHARS[idx] as char
        })
        .collect()
}
