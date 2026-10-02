// Nexon NA authentication for the Mabinogi launcher.
//
// Endpoints match the current NXL launcher:
//   Email/password : POST /api/account/v1/no-auth/login/launcher       (206 = MFA)
//   OTP            : POST /api/account/v1/no-auth/login/launcher/otp
//   Browser (TPA)  : POST /api/account/v1/no-auth/login/tpa/launcher   (TpaSession cookie)
//   Refresh        : POST /api/regional-auth/v1.0/no-auth/login/launcher/autologin
//                    (email/password accounts only; TPA returns 20182)
//   Launch chain   : GET  /api/account/v1/account        (merges refreshed cookies)
//                    POST /api/game-auth2/v1/access       (isPlayable verdict)
//                    POST /api/game-auth2/v1/playable     (sets server-side flag)
//                    POST /api/passport/v2/passport       (Bearer g_AToken)
//
// Any call that returns 401 is retried once after an autologin refresh.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default Nexon product id (Mabinogi NA). The active id is a process-global
/// (see [`product_id`]) so `--product-id` / the API field can retarget patch
/// and launch without threading it through every signature.
pub const PRODUCT_ID: &str = "10200";
/// Default product id as a number.
pub const DEFAULT_PRODUCT_ID: u32 = 10200;

static PRODUCT_ID_CELL: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(DEFAULT_PRODUCT_ID);

/// The active product id (default 10200). Set once per invocation with
/// [`set_product_id`]; read by every patch/launch/auth call.
pub fn product_id() -> u32 {
    PRODUCT_ID_CELL.load(std::sync::atomic::Ordering::Relaxed)
}

/// The active product id as a decimal string (for request bodies).
pub fn product_id_str() -> String {
    product_id().to_string()
}

/// Set the active product id for this process. 0 resets to the default.
pub fn set_product_id(id: u32) {
    PRODUCT_ID_CELL.store(if id == 0 { DEFAULT_PRODUCT_ID } else { id }, std::sync::atomic::Ordering::Relaxed);
}

pub const API_BASE: &str = "https://www.nexon.com/api";
const CLIENT_ID: &str = "7853644408";
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) NexonLauncher/4.7.9 Chrome/108.0.5359.215 Electron/22.3.27 Safari/537.36";
const ARENA_VER: &str = "nxl-v2.71.0-c228c50d";
const CAPTCHA_CODES: [i64; 3] = [1013, 70018, 70019];
/// Nexon error code for "trust this device" (verify via email / official launcher).
pub const ERR_DEVICE_TRUST: i64 = 20027;
/// Nexon error code returned by autologin for TPA (Google/social) sessions.
pub const ERR_TPA_NO_AUTOLOGIN: i64 = 20182;
/// Device-trust (20027) retry attempts, matching the NXL launcher (up to 4 tries with
/// a growing delay, in case the user just completed verification out-of-band).
pub const DEVICE_TRUST_RETRIES: u32 = 4;

/// Delay before device-trust retry `attempt` (0-based): 2s, 4s, 6s …
fn device_trust_delay(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(2 * (attempt as u64 + 1))
}

/// Run a login closure, retrying on `DeviceTrustRequired` up to
/// [`DEVICE_TRUST_RETRIES`] times with a growing delay (NXL launcher behaviour).
fn with_device_trust_retry(
    mut f: impl FnMut() -> Result<LoginResult>,
    mut sleep: impl FnMut(std::time::Duration),
) -> Result<LoginResult> {
    for attempt in 0..DEVICE_TRUST_RETRIES {
        match f() {
            Err(e) if is_device_trust(&e) && attempt + 1 < DEVICE_TRUST_RETRIES => {
                log::info!("device trust (20027) — retry {}/{}", attempt + 1, DEVICE_TRUST_RETRIES);
                sleep(device_trust_delay(attempt));
            }
            other => return other,
        }
    }
    unreachable!("loop returns on the last attempt")
}

/// True if `e` is a typed `AuthError::DeviceTrustRequired`.
pub fn is_device_trust(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<AuthError>(), Some(AuthError::DeviceTrustRequired))
}

/// Random per-process launcher session id sent as `x-nxl-session-id`.
static NXL_SESSION_ID: Lazy<String> = Lazy::new(|| {
    let seed = format!(
        "{}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
        std::process::id()
    );
    hex(&Sha256::digest(seed.as_bytes()))[..32].to_string()
});

/// Shared client so every call reuses connections. Cookies are handled manually.
static CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()
        .expect("failed to build HTTP client")
});

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NexonSession {
    pub access_token: String,
    pub g_access_token: String,
    /// NxLSession cookie — long-lived; used to refresh AToken.
    pub session_token: String,
    pub hashed_user_id: String,
    #[serde(default)]
    pub nx_gun: String,
    #[serde(default)]
    pub id_token: String,
    /// True for browser/TPA (Google, social) sessions — autologin is not supported.
    #[serde(default)]
    pub tpa: bool,
    /// Device id this session logged in with. Carried so every refresh reuses the
    /// same per-profile device id (a per-profile DeviceId). Empty = the legacy
    /// machine-only id (`device_id("")`), so existing sessions keep working.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_id: String,
    /// NxLSession lifetime in seconds from the last in-place refresh (autologin),
    /// so whoever persists the session can store the new expiry. Cleared by
    /// `profile::save_session`; carried through the Linux→Wine session file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshed_expires_in: Option<i32>,
}

impl NexonSession {
    pub fn cookie_header(&self) -> String {
        let mut parts = Vec::new();
        for (name, val) in [
            ("NxLSession", &self.session_token),
            ("AToken", &self.access_token),
            ("g_AToken", &self.g_access_token),
            ("NexonUserID", &self.hashed_user_id),
            ("NxGUN", &self.nx_gun),
            ("id_token", &self.id_token),
        ] {
            if !val.is_empty() {
                parts.push(format!("{}={}", name, val));
            }
        }
        parts.join("; ")
    }

    /// Game-auth endpoints want the game-scoped token; fall back to AToken.
    pub fn game_token(&self) -> &str {
        if self.g_access_token.is_empty() { &self.access_token } else { &self.g_access_token }
    }

    /// Take `other`'s non-empty cookies (and its refresh expiry, if any), keeping
    /// the fields `other` doesn't carry (e.g. NxGUN / id_token after an autologin).
    pub fn merge_from(&mut self, other: &NexonSession) {
        for (name, val) in [
            ("NxLSession", &other.session_token),
            ("AToken", &other.access_token),
            ("g_AToken", &other.g_access_token),
            ("NexonUserID", &other.hashed_user_id),
            ("NxGUN", &other.nx_gun),
            ("id_token", &other.id_token),
        ] {
            self.set_cookie(name, val.clone());
        }
        if other.refreshed_expires_in.is_some() {
            self.refreshed_expires_in = other.refreshed_expires_in;
        }
    }

    /// Update fields from `Set-Cookie` response headers (empty values are ignored).
    pub fn merge_set_cookies(&mut self, headers: &reqwest::header::HeaderMap) {
        for (name, val) in parse_set_cookies(headers) {
            self.set_cookie(&name, val);
        }
    }

    /// Update fields from a `Name=Value; Name2=Value2` cookie string.
    pub fn merge_cookie_string(&mut self, cookies: &str) {
        for part in cookies.split(';') {
            if let Some((n, v)) = part.trim().split_once('=') {
                self.set_cookie(n.trim(), v.trim().to_string());
            }
        }
    }

    fn set_cookie(&mut self, name: &str, val: String) {
        if val.is_empty() {
            return;
        }
        match name {
            "NxLSession" => self.session_token = val,
            "AToken" => self.access_token = val,
            "g_AToken" => self.g_access_token = val,
            "NexonUserID" => self.hashed_user_id = val,
            "NxGUN" => self.nx_gun = val,
            "id_token" => self.id_token = val,
            _ => {}
        }
    }
}

#[derive(Debug)]
pub struct LoginResult {
    pub session: NexonSession,
    /// Seconds until NxLSession expires (from response body, default 24h).
    pub session_expires_in: i32,
}

/// Errors callers may want to handle specifically (downcast from `anyhow::Error`).
#[derive(Debug, Clone)]
pub enum AuthError {
    /// HTTP 206 from login — submit an OTP with `login_otp`.
    MfaRequired { mfa_key: String, mfa_type: String },
    /// CAPTCHA required — only the browser login can get past it.
    CaptchaRequired(i64),
    /// Nexon wants this device verified (email link / official launcher).
    DeviceTrustRequired,
    /// Session expired and could not be refreshed — log in again.
    SessionExpired(String),
    /// The game is not playable right now (maintenance / region block).
    NotPlayable(String),
    /// Any other HTTP failure.
    Http { status: u16, code: i64, body: String },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MfaRequired { mfa_type, .. } => write!(f, "MFA required ({})", mfa_type),
            AuthError::CaptchaRequired(c) => write!(f, "CAPTCHA required (code {}) — use the browser login", c),
            AuthError::DeviceTrustRequired => write!(
                f,
                "Nexon requires device verification (code 20027). Check your email for Nexon's \
                 verification link or log in once with the official Nexon Launcher, then try again."
            ),
            AuthError::SessionExpired(m) => write!(f, "Session expired (401). Re-login and try again. {}", m),
            AuthError::NotPlayable(m) => write!(f, "{}", m),
            AuthError::Http { status, code, body } => {
                write!(f, "HTTP {} (code {}): {}", status, code, truncate(body, 300))
            }
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AccessInfo {
    pub http_status: u16,
    pub is_playable: bool,
    pub is_developer: bool,
    pub ip_blocked: bool,
    pub required_2fa: bool,
}

// ── Login paths ───────────────────────────────────────────────────────────────

/// Email/password login. On 206 returns `AuthError::MfaRequired` (call `login_otp`).
/// Device-trust (20027) rejections are retried up to [`DEVICE_TRUST_RETRIES`] times.
pub fn login(email: &str, password: &str, device_id: &str) -> Result<LoginResult> {
    with_device_trust_retry(|| login_once(email, password, device_id), std::thread::sleep)
}

fn login_once(email: &str, password: &str, device_id: &str) -> Result<LoginResult> {
    let body = serde_json::json!({
        "id": email,
        "password": password,
        "deviceId": device_id,
        "deviceType": "PC",
        "locale": "en",
    });
    let resp = request(reqwest::Method::POST, "/account/v1/no-auth/login/launcher", None)
        .json(&body)
        .send()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().unwrap_or_default();

    match status {
        200 => login_result_from(&headers, &text, false, device_id),
        206 => {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            Err(AuthError::MfaRequired {
                mfa_key: v["mfaKey"].as_str().unwrap_or("").to_string(),
                mfa_type: v["mfaType"].as_str().unwrap_or("email").to_string(),
            }
            .into())
        }
        _ => Err(login_error(status, error_code(&headers, &text), text)),
    }
}

/// Map a failed login/OTP response to a typed error: CAPTCHA and device-trust
/// codes get their own variants so callers can react (browser login / retry).
fn login_error(status: u16, code: i64, text: String) -> anyhow::Error {
    if CAPTCHA_CODES.contains(&code) || text.contains("captchaToken") {
        AuthError::CaptchaRequired(code).into()
    } else if code == ERR_DEVICE_TRUST {
        AuthError::DeviceTrustRequired.into()
    } else {
        AuthError::Http { status, code, body: text }.into()
    }
}

/// Submit the one-time password after `login` returned `MfaRequired`.
pub fn login_otp(mfa_key: &str, otp: &str, device_id: &str) -> Result<LoginResult> {
    with_device_trust_retry(|| login_otp_once(mfa_key, otp, device_id), std::thread::sleep)
}

fn login_otp_once(mfa_key: &str, otp: &str, device_id: &str) -> Result<LoginResult> {
    let body = serde_json::json!({
        "mfaKey": mfa_key,
        "otp": otp,
        "deviceId": device_id,
        "deviceType": "PC",
        "locale": "en",
    });
    let resp = request(reqwest::Method::POST, "/account/v1/no-auth/login/launcher/otp", None)
        .json(&body)
        .send()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().unwrap_or_default();
    if status != 200 {
        return Err(login_error(status, error_code(&headers, &text), text));
    }
    login_result_from(&headers, &text, false, device_id)
}

/// Exchange a browser `TpaSession` cookie for NxLSession + AToken.
/// TpaSession is single-use and expires within seconds — call immediately.
pub fn exchange_tpa(tpa_session: &str, device_id: &str) -> Result<LoginResult> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let body = serde_json::json!({
        "clientId": CLIENT_ID,
        "deviceId": device_id,
        "localTime": now.as_millis() as u64,
        "timeOffset": tz_bias_minutes(),
        "autoLogin": true,
    });
    let resp = request(reqwest::Method::POST, "/account/v1/no-auth/login/tpa/launcher", None)
        .header("Cookie", format!("TpaSession={}", tpa_session))
        .json(&body)
        .send()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().unwrap_or_default();
    if status != 200 {
        let code = error_code(&headers, &text);
        if code == ERR_DEVICE_TRUST {
            return Err(AuthError::DeviceTrustRequired.into());
        }
        return Err(AuthError::Http { status, code, body: text }.into());
    }
    login_result_from(&headers, &text, true, device_id)
}

/// Refresh a session from a stored NxLSession cookie (email/password accounts only).
pub fn autologin(session_token: &str) -> Result<LoginResult> {
    autologin_with(session_token, &device_id(""))
}

pub fn autologin_with(session_token: &str, device_id: &str) -> Result<LoginResult> {
    let body = serde_json::json!({ "deviceId": device_id, "deviceType": "PC", "locale": "en" });
    // The 2024 reorg moved autologin under regional-auth; /account/v1/... returns 404.
    let resp = request(reqwest::Method::POST, "/regional-auth/v1.0/no-auth/login/launcher/autologin", None)
        .header("Cookie", format!("NxLSession={}", session_token))
        .json(&body)
        .send()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().unwrap_or_default();
    if status != 200 {
        let code = error_code(&headers, &text);
        if code == ERR_TPA_NO_AUTOLOGIN {
            return Err(AuthError::SessionExpired(
                "Browser (Google/SSO) sessions can't be refreshed — use the browser login again.".into(),
            )
            .into());
        }
        return Err(AuthError::SessionExpired(format!("autologin HTTP {} code {}", status, code)).into());
    }
    let mut result = login_result_from(&headers, &text, false, device_id)?;
    if result.session.session_token.is_empty() {
        result.session.session_token = session_token.to_string();
    }
    Ok(result)
}

/// Refresh `session` in place. TPA sessions cannot be refreshed.
pub fn refresh(session: &mut NexonSession) -> Result<()> {
    refresh_with_expiry(session).map(|_| ())
}

/// [`refresh`], returning the new NxLSession lifetime in seconds.
pub fn refresh_with_expiry(session: &mut NexonSession) -> Result<i32> {
    if session.tpa {
        return Err(AuthError::SessionExpired(
            "Browser (Google/SSO) sessions can't be refreshed — use the browser login again.".into(),
        )
        .into());
    }
    if session.session_token.is_empty() {
        return Err(AuthError::SessionExpired("no NxLSession stored".into()).into());
    }
    // Refresh with the session's own device id (per-profile), falling back to the
    // legacy machine-only id so older stored sessions keep working.
    let dev = if session.device_id.is_empty() { device_id("") } else { session.device_id.clone() };
    let fresh = autologin_with(&session.session_token, &dev)?;
    // Overwrite only what autologin returned; NxGUN, id_token etc. survive.
    session.merge_from(&fresh.session);
    session.device_id = dev;
    session.tpa = false;
    session.refreshed_expires_in = Some(fresh.session_expires_in);
    Ok(fresh.session_expires_in)
}

// ── Session / launch chain ────────────────────────────────────────────────────

/// GET /account/v1/account. Returns the HTTP status (200 = session valid).
pub fn check_session(session: &mut NexonSession) -> Result<u16> {
    let resp = request(reqwest::Method::GET, "/account/v1/account", Some(session))
        .bearer_auth(session.access_token.clone())
        .send()?;
    let status = resp.status().as_u16();
    session.merge_set_cookies(resp.headers());
    Ok(status)
}

/// Official launcher order: account → access → playable → passport.
/// Refreshes once on 401. Returns the passport (ticket) for `/P:` and the pipe.
pub fn prepare_launch(session: &mut NexonSession) -> Result<String> {
    with_refresh(session, |s| {
        let status = check_session(s)?;
        if status == 401 {
            return Err(AuthError::SessionExpired("account check".into()).into());
        }
        let access = fetch_access(s)?;
        if access.http_status == 401 {
            return Err(AuthError::SessionExpired("access".into()).into());
        }
        if access.ip_blocked {
            return Err(AuthError::NotPlayable(
                "Access blocked from your region/IP — the official launcher denies this game to your location.".into(),
            )
            .into());
        }
        if access.http_status == 200 && !access.is_playable {
            return Err(AuthError::NotPlayable(
                "Mabinogi is currently unavailable (under maintenance or not yet open). Try again later.".into(),
            )
            .into());
        }
        let playable = check_playable(s)?;
        if playable == 401 {
            return Err(AuthError::SessionExpired("playable".into()).into());
        }
        if playable == 400 {
            return Err(AuthError::NotPlayable("Product not playable for this account (HTTP 400)".into()).into());
        }
        fetch_passport(s)
    })
}

/// Compatibility wrapper: run the full launch chain on a copy of the session.
pub fn get_passport(session: &NexonSession) -> Result<String> {
    let mut s = session.clone();
    prepare_launch(&mut s)
}

/// POST /game-auth2/v1/access — cookie-only (Bearer here causes 401 on scope mismatch).
pub fn fetch_access(session: &mut NexonSession) -> Result<AccessInfo> {
    let resp = request(reqwest::Method::POST, "/game-auth2/v1/access", Some(session))
        .json(&serde_json::json!({ "productId": product_id_str() }))
        .send()?;
    let mut info = AccessInfo { http_status: resp.status().as_u16(), ..Default::default() };
    session.merge_set_cookies(resp.headers());
    if info.http_status == 200 {
        let v: serde_json::Value = resp.json().unwrap_or_default();
        info.is_playable = v["isPlayable"].as_bool().unwrap_or(false);
        info.is_developer = v["isDeveloper"].as_bool().unwrap_or(false);
        info.ip_blocked = v["ipBlocked"].as_bool().unwrap_or(false);
        info.required_2fa = v["required2FA"].as_bool().unwrap_or(false);
    }
    Ok(info)
}

/// POST /game-auth2/v1/playable — cookie-only. Returns the HTTP status (400 = not playable).
pub fn check_playable(session: &NexonSession) -> Result<u16> {
    let resp = request(reqwest::Method::POST, "/game-auth2/v1/playable", Some(session))
        .json(&serde_json::json!({ "productId": product_id_str() }))
        .send()?;
    Ok(resp.status().as_u16())
}

/// Kept for callers that only want a yes/no.
pub fn is_playable(session: &NexonSession) -> Result<bool> {
    Ok(check_playable(session)? != 400)
}

/// POST /passport/v2/passport with `Bearer g_AToken`.
pub fn fetch_passport(session: &NexonSession) -> Result<String> {
    let resp = request(reqwest::Method::POST, "/passport/v2/passport", Some(session))
        .bearer_auth(session.game_token().to_string())
        .json(&serde_json::json!({ "productId": product_id_str() }))
        .send()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let text = resp.text().unwrap_or_default();
    if status == 401 {
        return Err(AuthError::SessionExpired("passport".into()).into());
    }
    if status != 200 {
        return Err(AuthError::Http { status, code: error_code(&headers, &text), body: text }.into());
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| anyhow!("Passport parse error ({}): {}", e, truncate(&text, 200)))?;
    v["passport"]
        .as_str()
        .filter(|p| !p.is_empty())
        .map(String::from)
        .ok_or_else(|| anyhow!("No passport in response: {}", truncate(&text, 200)))
}

/// Run `f`; if it fails with `SessionExpired`, refresh the session and retry once.
pub fn with_refresh<T>(
    session: &mut NexonSession,
    mut f: impl FnMut(&mut NexonSession) -> Result<T>,
) -> Result<T> {
    match f(session) {
        Err(e) if is_session_expired(&e) => {
            log::info!("401 — refreshing session and retrying");
            refresh_with_expiry(session).map_err(|re| refresh_failed(&e, &re))?;
            f(session)
        }
        other => other,
    }
}

/// Like [`with_refresh`] for calls that only read the session, but also hands
/// back the new NxLSession expiry (seconds) when a refresh happened, so callers
/// can persist it. `Ok((value, None))` means no refresh was needed.
pub fn with_session_retry<T, F>(session: &mut NexonSession, mut f: F) -> Result<(T, Option<i32>)>
where
    F: FnMut(&NexonSession) -> Result<T>,
{
    match f(session) {
        Err(e) if is_session_expired(&e) => {
            log::info!("401 — refreshing session and retrying");
            let expires = refresh_with_expiry(session).map_err(|re| refresh_failed(&e, &re))?;
            let value = f(session)?;
            Ok((value, Some(expires)))
        }
        other => other.map(|v| (v, None)),
    }
}

/// A 401 whose refresh failed stays a typed `SessionExpired` (the API answers 401).
fn refresh_failed(e: &anyhow::Error, re: &anyhow::Error) -> anyhow::Error {
    AuthError::SessionExpired(format!("{} (refresh failed: {})", e, re)).into()
}

/// True if `e` is a typed expired-session error: `AuthError::SessionExpired`
/// or `AuthError::Http { status: 401, .. }`. Error text is never inspected.
pub fn is_session_expired(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<AuthError>(),
        Some(AuthError::SessionExpired(_)) | Some(AuthError::Http { status: 401, .. })
    )
}

// ── Cookie imports ────────────────────────────────────────────────────────────

/// Build a session from raw cookies read from a browser/WebView store.
/// Uses NxLSession directly if present; otherwise exchanges TpaSession.
/// Returns Ok(None) when the user hasn't finished logging in yet.
pub fn session_from_browser_cookies(
    cookies: &std::collections::HashMap<String, String>,
    device_id: &str,
) -> Result<Option<NexonSession>> {
    let get = |n: &str| cookies.get(n).cloned().unwrap_or_default();
    let nxl = get("NxLSession");
    let a_token = get("AToken");
    if !nxl.is_empty() && !a_token.is_empty() {
        let mut s = NexonSession { tpa: true, device_id: device_id.to_string(), ..Default::default() };
        for (k, v) in cookies {
            s.set_cookie(k, v.clone());
        }
        return Ok(Some(s));
    }
    let tpa = get("TpaSession");
    if !tpa.is_empty() {
        let mut result = exchange_tpa(&tpa, device_id)?;
        result.session.tpa = true;
        return Ok(Some(result.session));
    }
    Ok(None)
}

/// Import session tokens from the official Nexon Launcher's cookie store.
/// `device_id` is stamped on the session (the target profile's id; `device_id("")`
/// for the legacy machine-only id).
pub fn import_from_nexon_launcher(device_id: &str) -> Result<NexonSession> {
    let appdata = std::env::var("APPDATA").map_err(|_| anyhow!("APPDATA not set"))?;
    let db = std::path::PathBuf::from(&appdata).join("NexonLauncher").join("Network").join("Cookies");
    if !db.exists() {
        return Err(anyhow!("Nexon Launcher not installed or not found"));
    }
    let map = read_cookie_db(&db, None)?;
    match session_from_browser_cookies(&map, device_id)? {
        Some(mut s) => {
            // The official launcher's session is a launcher session, so autologin works.
            s.tpa = false;
            Ok(s)
        }
        None => Err(anyhow!("Nexon Launcher is not logged in (no valid session found)")),
    }
}

/// Import from mabi-patcher's own WebView2 cookie store (after `nexon_login_webview`).
pub fn import_from_tauri_webview(device_id: &str) -> Result<NexonSession> {
    poll_tauri_webview(device_id)?.ok_or_else(|| anyhow!("Not logged in yet — no session cookies in WebView2 store"))
}

/// Like `import_from_tauri_webview` but distinguishes "not yet" (Ok(None)) from hard
/// failures such as a rejected TPA exchange, so the login window can stop polling.
/// `device_id` is stamped on the session, as for [`import_from_nexon_launcher`].
pub fn poll_tauri_webview(device_id: &str) -> Result<Option<NexonSession>> {
    use crate::launcher::cookie_dec;
    let localappdata = std::env::var("LOCALAPPDATA").map_err(|_| anyhow!("LOCALAPPDATA not set"))?;
    let db = std::path::PathBuf::from(&localappdata)
        .join("com.shaggyze.mabi-patcher")
        .join("EBWebView")
        .join("Default")
        .join("Network")
        .join("Cookies");
    if !db.exists() {
        return Ok(None);
    }
    let key = cookie_dec::get_webview2_key().map_err(|e| anyhow!("Failed to read WebView2 key: {}", e))?;
    let map = read_cookie_db(&db, Some(&key))?;
    session_from_browser_cookies(&map, device_id)
}

fn read_cookie_db(
    db: &std::path::Path,
    key: Option<&[u8]>,
) -> Result<std::collections::HashMap<String, String>> {
    use crate::launcher::cookie_dec;
    // Copy to a private temp dir to avoid SQLite lock conflicts with the running browser.
    let copy = crate::launcher::cookies::PrivateDbCopy::new(db)
        .map_err(|e| anyhow!("Failed to copy cookie DB: {}", e))?;
    let result = (|| -> Result<std::collections::HashMap<String, String>> {
        let conn = rusqlite::Connection::open(&copy.db)?;
        let db_version = crate::launcher::cookies::chromium_db_version(&conn);
        let mut stmt = conn.prepare(&format!(
            "SELECT name, value, encrypted_value FROM cookies WHERE {}",
            crate::launcher::cookies::nexon_host_filter("host_key")
        ))?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?))
        })?;
        let mut map = std::collections::HashMap::new();
        for row in rows.flatten() {
            let (name, plain, enc) = row;
            let value = if !plain.is_empty() {
                plain
            } else if let (false, Some(k)) = (enc.is_empty(), key) {
                cookie_dec::decrypt_cookie(&enc, k, db_version).unwrap_or_default()
            } else if !enc.is_empty() {
                cookie_dec::dpapi_decrypt(&enc)
                    .ok()
                    .and_then(|b| String::from_utf8(cookie_dec::strip_host_hash(&b, db_version).to_vec()).ok())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            if !value.is_empty() {
                map.insert(name, value);
            }
        }
        Ok(map)
    })();
    drop(copy);
    result
}

// ── Device ID ─────────────────────────────────────────────────────────────────

/// Stable per-machine identifier matching the Nexon Launcher's algorithm:
/// SHA256( WMI_UUID + MachineGuid [+ tag] ) → lowercase hex.
pub fn device_id(tag: &str) -> String {
    static CACHE: Lazy<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        Lazy::new(Default::default);
    if let Some(id) = CACHE.lock().unwrap().get(tag) {
        return id.clone();
    }
    let mut raw = String::new();
    if let Some(uuid) = wmi_uuid_via_wmic().or_else(wmi_uuid_via_powershell) {
        raw.push_str(&uuid);
    }
    if let Some(guid) = machine_guid() {
        raw.push_str(&guid);
    }
    let id = if raw.is_empty() {
        // Non-Windows: derive from the systemd / dbus machine id so the id is
        // stable across runs (like MachineGuid).
        let mid = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .find(|s| !s.is_empty())
            .unwrap_or_default();
        hex(&Sha256::digest(format!("{}{}", mid.trim(), tag).as_bytes()))
    } else {
        raw.push_str(tag);
        hex(&Sha256::digest(raw.as_bytes()))
    };
    CACHE.lock().unwrap().insert(tag.to_string(), id.clone());
    id
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn request(
    method: reqwest::Method,
    path: &str,
    session: Option<&NexonSession>,
) -> reqwest::blocking::RequestBuilder {
    let mut rb = CLIENT
        .request(method, format!("{}{}", API_BASE, path))
        .header("Accept", "application/json, text/plain, */*")
        .header("Accept-Language", "en-GB")
        .header("x-arena-fe-version", ARENA_VER)
        .header("x-nxl-session-id", NXL_SESSION_ID.as_str());
    if let Some(s) = session {
        let c = s.cookie_header();
        if !c.is_empty() {
            rb = rb.header("Cookie", c);
        }
    }
    rb
}

fn login_result_from(headers: &reqwest::header::HeaderMap, body: &str, tpa: bool, device_id: &str) -> Result<LoginResult> {
    let mut session = NexonSession { tpa, device_id: device_id.to_string(), ..Default::default() };
    session.merge_set_cookies(headers);
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    if session.hashed_user_id.is_empty() {
        if let Some(h) = v["hashedUserNo"].as_str() {
            session.hashed_user_id = h.to_string();
        }
    }
    if session.access_token.is_empty() && session.session_token.is_empty() {
        return Err(anyhow!("Login succeeded but no NxLSession/AToken cookie was set"));
    }
    let expires = v["loginSessionExpiresIn"].as_i64().unwrap_or(86400) as i32;
    Ok(LoginResult { session, session_expires_in: expires })
}

fn parse_set_cookies(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|s| {
            let nv = s.split(';').next()?.trim();
            let (n, v) = nv.split_once('=')?;
            Some((n.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Nexon error code from `x-arena-web-errorcode` header or JSON `code` field.
fn error_code(headers: &reqwest::header::HeaderMap, body: &str) -> i64 {
    if let Some(c) = headers
        .get("x-arena-web-errorcode")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
    {
        return c;
    }
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v["code"].as_i64().or_else(|| v["code"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0)
}

/// Minutes west of UTC (Windows TIME_ZONE_INFORMATION.Bias semantics).
fn tz_bias_minutes() -> i64 {
    use chrono::Offset;
    -(chrono::Local::now().offset().fix().local_minus_utc() as i64) / 60
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn truncate(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

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
                if !uuid.is_empty() {
                    return Some(uuid);
                }
            }
        }
    }
    None
}

fn wmi_uuid_via_powershell() -> Option<String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"])
            .creation_flags(0x08000000)
            .output()
            .ok()?;
        let uuid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !uuid.is_empty() {
            return Some(uuid);
        }
    }
    None
}

fn machine_guid() -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        use winreg::RegKey;
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags("SOFTWARE\\Microsoft\\Cryptography", KEY_READ | KEY_WOW64_64KEY)
            .ok()?;
        key.get_value::<String, _>("MachineGuid").ok()
    }
    #[cfg(not(windows))]
    None
}

#[cfg(test)]
mod tests {

    #[test]
    fn login_error_maps_captcha_and_device_trust() {
        for code in CAPTCHA_CODES {
            let e = login_error(400, code, String::new());
            assert!(matches!(e.downcast_ref::<AuthError>(), Some(AuthError::CaptchaRequired(c)) if *c == code));
        }
        let e = login_error(400, 0, r#"{"captchaToken":"x"}"#.into());
        assert!(matches!(e.downcast_ref::<AuthError>(), Some(AuthError::CaptchaRequired(_))));
        assert!(is_device_trust(&login_error(400, ERR_DEVICE_TRUST, String::new())));
        let e = login_error(401, 1, "bad otp".into());
        assert!(matches!(e.downcast_ref::<AuthError>(), Some(AuthError::Http { status: 401, code: 1, .. })));
    }

    use super::*;

    #[test]
    fn device_trust_retries_then_gives_up() {
        use std::sync::atomic::{AtomicU32, Ordering};
        // Always rejects with 20027: retried DEVICE_TRUST_RETRIES times, then returns it.
        let calls = AtomicU32::new(0);
        let delays = std::cell::RefCell::new(Vec::new());
        let r = with_device_trust_retry(
            || { calls.fetch_add(1, Ordering::SeqCst); Err(AuthError::DeviceTrustRequired.into()) },
            |d| delays.borrow_mut().push(d),
        );
        assert!(is_device_trust(&r.unwrap_err()));
        assert_eq!(calls.load(Ordering::SeqCst), DEVICE_TRUST_RETRIES);
        // One fewer delay than attempts, and growing (2s, 4s, 6s …).
        assert_eq!(delays.borrow().len() as u32, DEVICE_TRUST_RETRIES - 1);
        assert_eq!(delays.borrow()[0], std::time::Duration::from_secs(2));

        // Succeeds on the 2nd try: no give-up, exactly one delay.
        let calls = AtomicU32::new(0);
        let r = with_device_trust_retry(
            || if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(AuthError::DeviceTrustRequired.into())
            } else {
                Ok(LoginResult { session: NexonSession::default(), session_expires_in: 1 })
            },
            |_| {},
        );
        assert!(r.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn product_id_global_defaults_and_sets() {
        set_product_id(0);
        assert_eq!(product_id(), DEFAULT_PRODUCT_ID);
        set_product_id(70200);
        assert_eq!(product_id_str(), "70200");
        set_product_id(0); // restore for other tests
    }

    #[test]
    fn session_expired_is_typed_only() {
        assert!(is_session_expired(&AuthError::SessionExpired("x".into()).into()));
        assert!(is_session_expired(&AuthError::Http { status: 401, code: 0, body: String::new() }.into()));
        assert!(!is_session_expired(&AuthError::Http { status: 500, code: 0, body: "401".into() }.into()));
        assert!(!is_session_expired(&anyhow!("HTTP 401 from somewhere")));
        assert!(!is_session_expired(&anyhow!("downloaded 401 files")));
    }

    #[test]
    fn failed_refresh_stays_session_expired() {
        let e = refresh_failed(&AuthError::SessionExpired("passport".into()).into(), &anyhow!("autologin HTTP 500"));
        assert!(is_session_expired(&e));
        assert!(e.to_string().contains("refresh failed: autologin HTTP 500"));
        // A TPA session can't refresh: with_refresh must still return a typed error.
        let mut s = NexonSession { tpa: true, ..Default::default() };
        let r: Result<()> = with_refresh(&mut s, |_| Err(AuthError::SessionExpired("x".into()).into()));
        assert!(is_session_expired(&r.unwrap_err()));
    }

    #[test]
    fn merge_keeps_fields_the_refresh_did_not_return() {
        let mut s = NexonSession {
            access_token: "old-a".into(),
            session_token: "old-nxl".into(),
            hashed_user_id: "user".into(),
            nx_gun: "gun".into(),
            id_token: "idt".into(),
            ..Default::default()
        };
        let fresh = NexonSession {
            access_token: "new-a".into(),
            g_access_token: "new-g".into(),
            refreshed_expires_in: Some(3600),
            ..Default::default()
        };
        s.merge_from(&fresh);
        assert_eq!(s.access_token, "new-a");
        assert_eq!(s.g_access_token, "new-g");
        assert_eq!(s.session_token, "old-nxl");
        assert_eq!(s.hashed_user_id, "user");
        assert_eq!(s.nx_gun, "gun");
        assert_eq!(s.id_token, "idt");
        assert_eq!(s.refreshed_expires_in, Some(3600));
    }
}
