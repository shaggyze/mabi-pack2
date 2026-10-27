//! shaggyze.website account and the in-app Browser tab.
//!
//! The website keeps its login in an httpOnly `mabipatcher_session` cookie. The
//! Browser tab is a child webview of the main window, so both share one WebView2
//! cookie store: a login on the website page in the Browser tab signs in the Mods
//! tab, and a login from the Mods tab form also signs in the Browser tab.
//! Account requests run in Rust (ureq). The site's `safeOrigin` check refuses
//! foreign `Origin` headers, and ureq sends none.

use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};

pub const SITE: &str = "https://shaggyze.website";
pub const SITE_HOST: &str = "shaggyze.website";
pub const SITE_HOME: &str = "https://shaggyze.website/mabipatcher/";
const SESSION_COOKIE: &str = "mabipatcher_session";
const BROWSER: &str = "browser";
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Exe theme colors last sent by the page, as a JSON object. The Browser tab's
/// start script reads it on every page load; `browser_set_theme` updates it.
static THEME_JSON: Mutex<String> = Mutex::new(String::new());

fn main_webview(app: &AppHandle) -> Result<tauri::Webview, String> {
    app.get_webview("main").ok_or_else(|| "no main webview".to_string())
}

/// The website session token from the shared cookie store, if signed in.
/// Cookie reads deadlock on the main thread with WebView2, so this blocks a worker.
pub async fn session_token(app: &AppHandle) -> Option<String> {
    let wv = main_webview(app).ok()?;
    let url: tauri::Url = SITE.parse().ok()?;
    let cookies = tauri::async_runtime::spawn_blocking(move || wv.cookies_for_url(url))
        .await
        .ok()?
        .ok()?;
    cookies.into_iter()
        .find(|c| c.name() == SESSION_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty())
}

async fn store_session_cookie(app: &AppHandle, token: Option<String>) -> Result<(), String> {
    use tauri::webview::cookie::{time::Duration, Cookie};
    let wv = main_webview(app)?;
    tauri::async_runtime::spawn_blocking(move || {
        let c = Cookie::build((SESSION_COOKIE, token.clone().unwrap_or_default()))
            .domain(SITE_HOST)
            .path("/")
            .secure(true)
            .http_only(true)
            .max_age(if token.is_some() { Duration::days(30) } else { Duration::ZERO })
            .build();
        if token.is_some() { wv.set_cookie(c) } else { wv.delete_cookie(c) }
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

/// `Set-Cookie: mabipatcher_session=<token>; …` → token.
fn token_from_set_cookie(headers: &[String]) -> Option<String> {
    headers.iter().find_map(|h| {
        let first = h.split(';').next()?.trim();
        let (k, v) = first.split_once('=')?;
        (k.trim() == SESSION_COOKIE && !v.is_empty()).then(|| v.trim().to_string())
    })
}

/// Text of an error reply: the site answers `{"error": "…"}`.
fn site_error(code: u16, body: String) -> String {
    let msg = serde_json::from_str::<serde_json::Value>(&body).ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| body.chars().take(200).collect());
    format!("HTTP {}: {}", code, msg.trim())
}

/// Authenticated JSON request. `Ok(None)` = HTTP 401 (signed out or session expired).
fn site_json(method: &str, path: &str, token: &str, body: Option<&serde_json::Value>) -> Result<Option<serde_json::Value>, String> {
    let req = ureq::request(method, &format!("{}{}", SITE, path))
        .timeout(HTTP_TIMEOUT)
        .set("Cookie", &format!("{}={}", SESSION_COOKIE, token));
    let resp = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => req.call(),
    };
    match resp {
        Ok(r) => r.into_string().map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map(Some).map_err(|e| e.to_string())),
        Err(ureq::Error::Status(401, _)) => Ok(None),
        Err(ureq::Error::Status(code, r)) => Err(site_error(code, r.into_string().unwrap_or_default())),
        Err(e) => Err(e.to_string()),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

/// The signed-in website account (`/api/auth/me`), or null when signed out.
/// A session the site refuses is removed from the cookie store.
#[tauri::command]
pub async fn site_account(app: AppHandle) -> Result<Option<serde_json::Value>, String> {
    let Some(token) = session_token(&app).await else { return Ok(None) };
    let me = blocking(move || site_json("GET", "/api/auth/me", &token, None)).await?;
    if me.is_none() { let _ = store_session_cookie(&app, None).await; }
    Ok(me)
}

/// Sign in to the website with a username and password. Stores the session
/// cookie in the shared store (Browser tab included) and returns the account.
#[tauri::command]
pub async fn site_login(app: AppHandle, username: String, password: String) -> Result<serde_json::Value, String> {
    let (account, token) = blocking(move || {
        let body = serde_json::json!({ "username": username, "password": password });
        match ureq::post(&format!("{}/api/auth/login", SITE))
            .timeout(HTTP_TIMEOUT)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(r) => {
                let cookies: Vec<String> = r.all("set-cookie").into_iter().map(str::to_string).collect();
                let token = token_from_set_cookie(&cookies).ok_or("the website did not return a session")?;
                let account: serde_json::Value = serde_json::from_str(&r.into_string().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                Ok((account, token))
            }
            Err(ureq::Error::Status(code, r)) => Err(site_error(code, r.into_string().unwrap_or_default())),
            Err(e) => Err(e.to_string()),
        }
    }).await?;
    store_session_cookie(&app, Some(token)).await?;
    log::info!("[Site] Signed in as {}", account.get("username").and_then(|u| u.as_str()).unwrap_or("?"));
    Ok(account)
}

/// Sign out on the website and remove the session cookie.
#[tauri::command]
pub async fn site_logout(app: AppHandle) -> Result<(), String> {
    if let Some(token) = session_token(&app).await {
        let _ = blocking(move || site_json("POST", "/api/auth/logout", &token, Some(&serde_json::json!({})))).await;
    }
    store_session_cookie(&app, None).await?;
    log::info!("[Site] Signed out");
    Ok(())
}

/// The account's saved mod picks: `{ selections: {"<mod id>": "<revision id>"}, updatedAt }`.
/// `updatedAt` is null until the account first saves. Errors when signed out.
#[tauri::command]
pub async fn site_get_selections(app: AppHandle) -> Result<serde_json::Value, String> {
    let token = session_token(&app).await.ok_or("sign in to the website first")?;
    blocking(move || site_json("GET", "/api/account/selections", &token, None)).await?
        .ok_or_else(|| "the website session expired; sign in again".to_string())
}

/// Replace the account's saved mod picks.
#[tauri::command]
pub async fn site_put_selections(app: AppHandle, selections: serde_json::Value) -> Result<serde_json::Value, String> {
    let token = session_token(&app).await.ok_or("sign in to the website first")?;
    let body = serde_json::json!({ "selections": selections });
    blocking(move || site_json("PUT", "/api/account/selections", &token, Some(&body))).await?
        .ok_or_else(|| "the website session expired; sign in again".to_string())
}

/// Upload a local file (a `.mod`, `.it` or `.pack`) as a community mod on the
/// account: `start`, 512 KiB `chunk`s, then `complete`, like the site's Upload page.
/// Returns the item's status ("published" or "pending" admin approval).
#[tauri::command]
pub async fn site_upload_mod(app: AppHandle, path: String, title: String, creator: String, description: String, version: String, category: String) -> Result<String, String> {
    let token = session_token(&app).await.ok_or("sign in to the website first")?;
    blocking(move || {
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {}", path, e))?;
        let filename = std::path::Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let start = serde_json::json!({
            "title": title, "creator": creator, "description": description, "version": version,
            "category": category, "filename": filename, "size": bytes.len(),
        });
        let item = site_json("POST", "/api/community/mods/start", &token, Some(&start))?
            .ok_or("the website session expired; sign in again")?;
        let id = item.pointer("/item/id").map(|v| v.to_string().trim_matches('"').to_string())
            .ok_or("the website did not return an upload id")?;
        let mut offset = 0usize;
        while offset < bytes.len() {
            let end = (offset + 512 * 1024).min(bytes.len());
            let r = ureq::post(&format!("{}/api/community/mods/{}/chunk?offset={}", SITE, id, offset))
                .timeout(std::time::Duration::from_secs(120))
                .set("Cookie", &format!("{}={}", SESSION_COOKIE, token))
                .set("Content-Type", "application/octet-stream")
                .send_bytes(&bytes[offset..end]);
            let next = match r {
                Ok(resp) => serde_json::from_str::<serde_json::Value>(&resp.into_string().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?
                    .get("offset").and_then(|o| o.as_u64()).ok_or("chunk reply has no offset")? as usize,
                // 409: the site already holds bytes up to `offset`; resume there.
                Err(ureq::Error::Status(409, resp)) => resp.into_string().ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                    .and_then(|v| v.get("offset").and_then(|o| o.as_u64())).map(|o| o as usize)
                    .filter(|o| *o <= bytes.len()).ok_or("upload offset conflict")?,
                Err(ureq::Error::Status(code, resp)) => return Err(site_error(code, resp.into_string().unwrap_or_default())),
                Err(e) => return Err(e.to_string()),
            };
            if next <= offset && next != bytes.len() { return Err("the website did not accept the chunk".into()); }
            offset = next;
        }
        let done = site_json("POST", &format!("/api/community/mods/{}/complete", id), &token, Some(&serde_json::json!({})))?
            .ok_or("the website session expired; sign in again")?;
        let status = done.pointer("/item/status").and_then(|s| s.as_str()).unwrap_or("published").to_string();
        log::info!("[Site] Uploaded {} ({} bytes): {}", filename, bytes.len(), status);
        Ok(status)
    }).await
}
// ── Browser tab ─────────────────────────────────────────────────────────────

/// Runs before every page script in the Browser tab. On shaggyze.website it maps
/// the exe theme (THEME_JSON) onto the site's CSS variables; elsewhere it does
/// nothing. `window.__mpApplyTheme(json)` re-applies it when the exe theme changes.
fn browser_start_script() -> String {
    let theme = THEME_JSON.lock().unwrap().clone();
    let theme = if theme.is_empty() { "null".to_string() } else { theme };
    format!(r##"(function(){{
  if (location.hostname !== "{host}") return;
  function css(t){{
    if(!t) return "";
    var v = function(k,f){{ return t[k] || f; }};
    return ":root,:root body{{" +
      "--bg:"+v("bg","#16171d")+";--text:"+v("muted","#9ca3af")+";--text-h:"+v("text","#f3f4f6")+";" +
      "--border:"+v("border","#2e303a")+";--code-bg:"+v("input","#1f2028")+";--surface:"+v("surface","#25252d")+";" +
      "--bg-surface:"+v("surface","#25252d")+";--bg-card:"+v("surface","#25252d")+";--text-primary:"+v("text","#f3f4f6")+";" +
      "--accent:"+v("accent","#c084fc")+";--accent-bg:"+v("accentBg","#c084fc26")+";--accent-border:"+v("accentBorder","#c084fc80")+";" +
      "--social-bg:"+v("input","#2f303a")+";" + (t.font ? "--sans:"+t.font+";--heading:"+t.font+";" : "") +
      "color-scheme:"+(t.dark ? "dark" : "light")+"}}" +
      "body{{background:"+v("bg","#16171d")+";color:"+v("muted","#9ca3af")+"}}";
  }}
  function apply(t){{
    var s = document.getElementById("mp-exe-theme");
    if(!s){{ s = document.createElement("style"); s.id = "mp-exe-theme"; }}
    s.textContent = css(t);
    var root = document.head || document.documentElement;
    if (s.parentNode !== root || root.lastChild !== s) root.appendChild(s);
  }}
  var theme = {theme};
  window.__mpApplyTheme = function(t){{ theme = t; apply(t); }};
  apply(theme);
  // The site's own stylesheets load after this script: keep the override last in <head>.
  var keepLast = new MutationObserver(function(){{
    var s = document.getElementById("mp-exe-theme");
    if (s && document.head && document.head.lastChild !== s) document.head.appendChild(s);
  }});
  document.addEventListener("DOMContentLoaded", function(){{
    apply(theme);
    if (document.head) keepLast.observe(document.head, {{childList:true}});
  }});
}})();"##, host = SITE_HOST, theme = theme)
}


/// One Browser-tab page. Each is its own child webview of the main window
/// (labels `browser`, `browser-1`, …); only the active one is shown.
struct Tab { label: String, title: String }

struct Tabs {
    list: Vec<Tab>,
    active: Option<String>,
    next: u32,
    /// Last page rectangle (physical pixels) and whether the Browser tab is showing.
    rect: Option<(f64, f64, f64, f64)>,
    visible: bool,
}

static TABS: Mutex<Tabs> = Mutex::new(Tabs { list: Vec::new(), active: None, next: 0, rect: None, visible: false });

fn browser(app: &AppHandle) -> Option<tauri::Webview> {
    let label = TABS.lock().unwrap().active.clone()?;
    app.get_webview(&label)
}

/// Label and address of the page shown in the Browser tab.
pub fn active_tab(app: &AppHandle) -> Option<(String, String)> {
    let wv = browser(app)?;
    Some((wv.label().to_string(), wv.url().ok()?.to_string()))
}

fn parse_url(url: &str) -> Result<tauri::Url, String> {
    let u = url.trim();
    let full = if u.contains("://") { u.to_string() } else { format!("https://{}", u) };
    let parsed: tauri::Url = full.parse().map_err(|e| format!("invalid address: {}", e))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" { return Err("only http(s) addresses open in the Browser tab".into()); }
    Ok(parsed)
}

/// Page rectangle in physical pixels (CSS pixels × devicePixelRatio, which also
/// covers the page zoom) → webview position and size.
fn physical(x: f64, y: f64, width: f64, height: f64) -> (tauri::PhysicalPosition<i32>, tauri::PhysicalSize<u32>) {
    (tauri::PhysicalPosition::new(x.round() as i32, y.round() as i32),
     tauri::PhysicalSize::new(width.round().max(1.0) as u32, height.round().max(1.0) as u32))
}

fn tabs_json(app: &AppHandle) -> serde_json::Value {
    // Copy out first: Webview::url() waits for the main thread, which may be
    // waiting for TABS in a page callback.
    let (tabs, active) = {
        let t = TABS.lock().unwrap();
        (t.list.iter().map(|x| (x.label.clone(), x.title.clone())).collect::<Vec<_>>(), t.active.clone())
    };
    let list: Vec<serde_json::Value> = tabs.into_iter().map(|(label, title)| {
        let url = app.get_webview(&label).and_then(|w| w.url().ok()).map(|u| u.to_string()).unwrap_or_default();
        serde_json::json!({ "label": label, "title": title, "url": url })
    }).collect();
    serde_json::json!({ "tabs": list, "active": active })
}

fn emit_tabs(app: &AppHandle) { let _ = app.emit("browser-tabs", tabs_json(app)); }

/// Show `label`, hide the other tabs (all of them while the Browser tab is hidden).
fn show_only(app: &AppHandle, label: &str) {
    let (labels, rect, visible) = {
        let mut t = TABS.lock().unwrap();
        t.active = Some(label.to_string());
        (t.list.iter().map(|x| x.label.clone()).collect::<Vec<_>>(), t.rect, t.visible)
    };
    for l in labels {
        let Some(wv) = app.get_webview(&l) else { continue };
        if l == label && visible {
            if let Some((x, y, w, h)) = rect {
                let (pos, size) = physical(x, y, w, h);
                let _ = wv.set_bounds(tauri::Rect { position: pos.into(), size: size.into() });
            }
            let _ = wv.show();
            let _ = wv.set_focus();
        } else {
            let _ = wv.hide();
        }
    }
}

/// Open `url` in a new Browser tab (switched to when `activate`). Must not run on
/// the main thread: `add_child` waits for it.
pub fn open_tab(app: &AppHandle, url: tauri::Url, activate: bool) -> Result<String, String> {
    use tauri::{WebviewBuilder, WebviewUrl};
    let window = app.get_window("main").ok_or("no main window")?;
    let (label, rect, shown) = {
        let mut t = TABS.lock().unwrap();
        let label = if t.next == 0 { BROWSER.to_string() } else { format!("{}-{}", BROWSER, t.next) };
        t.next += 1;
        (label, t.rect, t.visible && (activate || t.active.is_none()))
    };
    // A tab that will not be shown starts as one pixel, so it does not flash over
    // the other app tabs before hide(); show_only sizes it when it is switched to.
    let (pos, size) = match rect { Some((x, y, w, h)) if shown => physical(x, y, w, h), _ => physical(0.0, 0.0, 1.0, 1.0) };
    let app_nav = app.clone();
    let app_title = app.clone();
    let app_load = app.clone();
    let builder = WebviewBuilder::new(&label, WebviewUrl::External(url.clone()))
        .initialization_script(browser_start_script())
        .initialization_script(crate::userscripts::bootstrap_script())
        // "Open in new tab/window", target=_blank links and window.open → a new tab.
        .on_new_window(move |url, _| {
            let app = app_nav.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = open_tab(&app, url, true) { log::warn!("[Browser] New tab failed: {}", e); }
            });
            tauri::webview::NewWindowResponse::Deny
        })
        .on_document_title_changed(move |wv, title| {
            {
                let mut t = TABS.lock().unwrap();
                if let Some(tab) = t.list.iter_mut().find(|x| x.label == wv.label()) { tab.title = title.clone(); }
            }
            if TABS.lock().unwrap().active.as_deref() == Some(wv.label()) {
                let _ = app_title.emit("browser-title", title);
            }
            emit_tabs(&app_title);
        })
        .on_page_load(move |wv, payload| {
            let finished = matches!(payload.event(), tauri::webview::PageLoadEvent::Finished);
            if !finished { crate::userscripts::page_started(wv.label()); }
            // The start script carries the theme from when the webview was created;
            // a later theme change reaches new pages here.
            if finished {
                let json = THEME_JSON.lock().unwrap().clone();
                if !json.is_empty() { let _ = wv.eval(format!("window.__mpApplyTheme && window.__mpApplyTheme({})", json)); }
            }
            let active = TABS.lock().unwrap().active.as_deref() == Some(wv.label());
            if active {
                let _ = app_load.emit("browser-load", serde_json::json!({ "url": payload.url().as_str(), "finished": finished }));
            }
            emit_tabs(&app_load);
        });
    let wv = window.add_child(builder, pos, size).map_err(|e| e.to_string())?;
    {
        let mut t = TABS.lock().unwrap();
        // A new tab opens to the right of the active one.
        let at = t.active.as_ref().and_then(|a| t.list.iter().position(|x| &x.label == a)).map(|i| i + 1).unwrap_or(t.list.len());
        t.list.insert(at, Tab { label: label.clone(), title: String::new() });
    }
    let first = TABS.lock().unwrap().active.is_none();
    if activate || first { show_only(app, &label); } else { let _ = wv.hide(); }
    emit_tabs(app);
    log::info!("[Browser] Opened tab {}", url);
    Ok(label)
}

/// Show the Browser tab's page over the page rectangle (physical pixels of the
/// main window). Opens the first tab on first use at `url` (default: the
/// website); afterwards `url` navigates the active tab only when given.
#[tauri::command]
pub async fn browser_show(app: AppHandle, url: Option<String>, x: f64, y: f64, width: f64, height: f64) -> Result<(), String> {
    {
        let mut t = TABS.lock().unwrap();
        t.rect = Some((x, y, width, height));
        t.visible = true;
    }
    // Own statement: a guard in the match scrutinee would stay locked through
    // the arms, and show_only/open_tab lock TABS again (self-deadlock).
    let active = TABS.lock().unwrap().active.clone();
    match active {
        Some(label) => {
            show_only(&app, &label);
            if let (Some(u), Some(wv)) = (url, app.get_webview(&label)) { wv.navigate(parse_url(&u)?).map_err(|e| e.to_string())?; }
            Ok(())
        }
        None => open_tab(&app, parse_url(url.as_deref().unwrap_or(SITE_HOME))?, true).map(|_| ()),
    }
}

/// Move/resize the Browser tab's page (page layout changed). Physical pixels.
#[tauri::command]
pub fn browser_set_bounds(app: AppHandle, x: f64, y: f64, width: f64, height: f64) -> Result<(), String> {
    TABS.lock().unwrap().rect = Some((x, y, width, height));
    let Some(wv) = browser(&app) else { return Ok(()) };
    let (pos, size) = physical(x, y, width, height);
    wv.set_bounds(tauri::Rect { position: pos.into(), size: size.into() }).map_err(|e| e.to_string())
}

/// Hide every Browser tab page (another app tab is shown, or a panel covers the
/// page area). The pages keep running.
#[tauri::command]
pub fn browser_hide(app: AppHandle) -> Result<(), String> {
    let labels: Vec<String> = {
        let mut t = TABS.lock().unwrap();
        t.visible = false;
        t.list.iter().map(|x| x.label.clone()).collect()
    };
    for l in labels { if let Some(wv) = app.get_webview(&l) { let _ = wv.hide(); } }
    Ok(())
}

#[tauri::command]
pub fn browser_navigate(app: AppHandle, url: String) -> Result<String, String> {
    let wv = browser(&app).ok_or("the Browser tab is not open")?;
    let u = parse_url(&url)?;
    wv.navigate(u.clone()).map_err(|e| e.to_string())?;
    Ok(u.to_string())
}

/// `back` | `forward` | `reload` | `stop`.
#[tauri::command]
pub fn browser_action(app: AppHandle, action: String) -> Result<(), String> {
    let wv = browser(&app).ok_or("the Browser tab is not open")?;
    let js = match action.as_str() {
        "back" => "history.back()",
        "forward" => "history.forward()",
        "reload" => "location.reload()",
        "stop" => "window.stop()",
        _ => return Err(format!("unknown browser action {}", action)),
    };
    wv.eval(js).map_err(|e| e.to_string())
}

/// Current address and title of the active tab (the address bar polls this:
/// single-page sites change the address with history.pushState, which raises no load event).
#[tauri::command]
pub fn browser_state(app: AppHandle) -> Option<serde_json::Value> {
    let wv = browser(&app)?;
    let url = wv.url().ok()?.to_string();
    let title = TABS.lock().unwrap().list.iter().find(|x| x.label == wv.label()).map(|x| x.title.clone()).unwrap_or_default();
    Some(serde_json::json!({ "url": url, "title": title }))
}

/// `{tabs: [{label, title, url}], active}`.
#[tauri::command]
pub fn browser_tabs(app: AppHandle) -> serde_json::Value { tabs_json(&app) }

/// New tab at `url` (default: the website), switched to.
#[tauri::command]
pub async fn browser_new_tab(app: AppHandle, url: Option<String>) -> Result<String, String> {
    open_tab(&app, parse_url(url.as_deref().unwrap_or(SITE_HOME))?, true)
}

#[tauri::command]
pub fn browser_switch_tab(app: AppHandle, label: String) -> Result<(), String> {
    if !TABS.lock().unwrap().list.iter().any(|x| x.label == label) { return Err("no such tab".into()); }
    show_only(&app, &label);
    emit_tabs(&app);
    Ok(())
}

/// Close one tab. Closing the last tab opens the website in a fresh one.
#[tauri::command]
pub async fn browser_close_tab(app: AppHandle, label: String) -> Result<(), String> {
    let next = {
        let mut t = TABS.lock().unwrap();
        let Some(i) = t.list.iter().position(|x| x.label == label) else { return Ok(()) };
        t.list.remove(i);
        if t.active.as_deref() == Some(label.as_str()) {
            t.active = None;
            t.list.get(i).or_else(|| t.list.get(i.wrapping_sub(1))).map(|x| x.label.clone())
        } else {
            t.active.clone()
        }
    };
    if let Some(wv) = app.get_webview(&label) { let _ = wv.close(); }
    crate::userscripts::tab_closed(&label);
    match next {
        Some(l) => { show_only(&app, &l); emit_tabs(&app); }
        None => { open_tab(&app, parse_url(SITE_HOME)?, true)?; }
    }
    Ok(())
}

/// Exe theme colors for the website (`{bg, surface, input, text, muted, border,
/// accent, accentBg, accentBorder, font, dark}`). Applied now and on every later page load.
#[tauri::command]
pub fn browser_set_theme(app: AppHandle, theme: serde_json::Value) -> Result<(), String> {
    let mut clean = serde_json::Map::new();
    if let Some(obj) = theme.as_object() {
        for (k, v) in obj {
            match v {
                // Colors/fonts land inside a <style>: refuse anything that could close the rule.
                serde_json::Value::String(s) if s.len() <= 200 && !s.contains(['{', '}', '<', ';', '\\']) => { clean.insert(k.clone(), v.clone()); }
                serde_json::Value::Bool(_) => { clean.insert(k.clone(), v.clone()); }
                _ => {}
            }
        }
    }
    let json = serde_json::Value::Object(clean).to_string();
    *THEME_JSON.lock().unwrap() = json.clone();
    // Only the first page load reads THEME_JSON via the start script, so push it to the live pages.
    let labels: Vec<String> = TABS.lock().unwrap().list.iter().map(|x| x.label.clone()).collect();
    for l in labels {
        if let Some(wv) = app.get_webview(&l) {
            let _ = wv.eval(format!("window.__mpApplyTheme && window.__mpApplyTheme({})", json));
        }
    }
    Ok(())
}
