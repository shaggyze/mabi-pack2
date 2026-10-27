//! Tampermonkey-compatible userscripts for the Browser tab.
//!
//! Scripts live in `userscripts/` beside the exe in Tampermonkey's backup layout
//! (`<name>.user.js`, `<name>.options.json`, `<name>.storage.json`, and
//! `<name>.user.js-<hash>-<file>` + `.requires.json`/`.resources.json` for
//! `@require`/`@resource`), so a Tampermonkey backup zip imports as-is.
//!
//! Injection: every Browser tab page runs `bootstrap_script()` first, which calls
//! `page_ready`. That picks the enabled scripts whose `@match`/`@include` fit the
//! page and runs them with `Webview::eval` (WebView2 ExecuteScript, which page
//! CSP does not block): first `userscripts_runtime.js` (the GM_* API), then one
//! eval per script so a broken script cannot stop the others.
//!
//! Pages reach Rust only through `page_ready` and `gm` (inline plugin
//! `userscripts`, capabilities/userscripts.json). `gm` also needs the random
//! token that `page_ready` put inside the runtime, and only acts for scripts
//! injected into that page.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, Webview};

const RUNTIME_JS: &str = include_str!("userscripts_runtime.js");
/// Parameters of every script wrapper, in the order `__mpUS.run` passes them.
const PARAMS: &str = "GM_info,GM,unsafeWindow,GM_getValue,GM_setValue,GM_deleteValue,GM_listValues,GM_getValues,GM_setValues,GM_deleteValues,GM_addValueChangeListener,GM_removeValueChangeListener,GM_addStyle,GM_addElement,GM_getResourceText,GM_getResourceURL,GM_registerMenuCommand,GM_unregisterMenuCommand,GM_openInTab,GM_setClipboard,GM_notification,GM_xmlhttpRequest,GM_download,GM_log,GM_cookie,__mpSandbox";
const MAX_BODY: u64 = 100 << 20;

pub fn dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("userscripts")))
        .unwrap_or_else(|| PathBuf::from("userscripts"))
}

#[derive(Clone, Serialize)]
pub struct Script {
    /// File stem: `<id>.user.js`.
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub matches: Vec<String>,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub requires: Vec<String>,
    pub resources: Vec<(String, String)>,
    pub run_at: String,
    pub grants: Vec<String>,
    /// `@connect` hosts GM_xmlhttpRequest/GM_download may reach besides the page's own site.
    pub connects: Vec<String>,
    pub enabled: bool,
    pub position: i64,
    #[serde(skip)]
    meta_str: String,
    #[serde(skip)]
    include_set: Arc<Option<regex::RegexSet>>,
    #[serde(skip)]
    exclude_set: Arc<Option<regex::RegexSet>>,
}

impl Script {
    pub fn matches_url(&self, url: &str) -> bool {
        let hit = match &*self.include_set { Some(s) => s.is_match(url), None => false };
        hit && !matches!(&*self.exclude_set, Some(s) if s.is_match(url))
    }
    /// Tampermonkey runs `@grant none` (and scripts with no `@grant`) in the page;
    /// any other grant gets the sandboxed `window`.
    fn sandboxed(&self) -> bool {
        self.grants.iter().any(|g| g != "none" && g != "unsafeWindow")
    }
    /// `@grant GM_setValue` and `@grant GM.setValue` both grant `setvalue`.
    fn granted(&self, apis: &[&str]) -> bool {
        self.grants.iter().any(|g| {
            let g = g.to_ascii_lowercase();
            let g = g.strip_prefix("gm_").or_else(|| g.strip_prefix("gm.")).unwrap_or(&g).to_string();
            apis.contains(&g.as_str())
        })
    }
    /// Tampermonkey's rule: the page's own site, plus `@connect` hosts
    /// (`*` = any, `self` = the page's host, a domain also covers its subdomains).
    fn may_connect(&self, page_host: &str, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let site = |h: &str| h.strip_prefix("www.").unwrap_or(h).to_string();
        let within = |d: &str| host == d || host.ends_with(&format!(".{}", d));
        if !page_host.is_empty() && within(&site(&page_host.to_ascii_lowercase())) { return true; }
        self.connects.iter().any(|c| {
            let c = c.trim().to_ascii_lowercase();
            c == "*" || (c == "self" && host == page_host.to_ascii_lowercase()) || (!c.is_empty() && within(&c))
        })
    }
}

/// `// @key value` lines of the `==UserScript==` block, plus the block itself.
fn parse_meta(code: &str) -> (Vec<(String, String)>, String) {
    let mut out = Vec::new();
    let mut block = String::new();
    let mut inside = false;
    for line in code.lines() {
        let t = line.trim();
        if t.starts_with("//") && t.contains("==UserScript==") { inside = true; block.push_str(line); block.push('\n'); continue; }
        if !inside { continue; }
        block.push_str(line);
        block.push('\n');
        if t.starts_with("//") && t.contains("==/UserScript==") { break; }
        let Some(rest) = t.strip_prefix("//") else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('@') else { continue };
        let (key, val) = match rest.find(char::is_whitespace) {
            Some(i) => (&rest[..i], rest[i..].trim()),
            None => (rest, ""),
        };
        out.push((key.to_string(), val.to_string()));
    }
    (out, block)
}

/// One `@match`/`@include`/`@exclude` pattern → anchored regex source.
/// `/regex/` is used as written; otherwise `*` is a wildcard, `*://` is http(s),
/// and a `*.host` matches the host and its subdomains.
fn pattern_regex(p: &str) -> Option<String> {
    let p = p.trim();
    if p.is_empty() { return None; }
    if p == "*" || p == "<all_urls>" || p == "*://*/*" { return Some("^https?://.*$".into()); }
    if p.len() > 2 && p.starts_with('/') {
        if let Some(end) = p.rfind('/') {
            if end > 0 {
                let flags = &p[end + 1..];
                let body = &p[1..end];
                return Some(if flags.contains('i') { format!("(?i){}", body) } else { body.to_string() });
            }
        }
    }
    let glob = |s: &str, star: &str| regex::escape(s).replace("\\*", star);
    let Some(i) = p.find("://") else { return Some(format!("^{}$", glob(p, ".*"))) };
    let scheme = &p[..i];
    let rest = &p[i + 3..];
    let scheme_re = if scheme == "*" { "https?".to_string() } else { glob(scheme, ".*") };
    let (host, path) = match rest.find('/') { Some(j) => (&rest[..j], &rest[j..]), None => (rest, "") };
    let host_re = if let Some(h) = host.strip_prefix("*.") {
        format!("(?:[^/]*\\.)?{}", glob(h, "[^/]*"))
    } else {
        glob(host, "[^/]*")
    };
    let path_re = if path.is_empty() { "(?:[/?#].*)?".to_string() } else { glob(path, ".*") };
    Some(format!("(?i:^{}://{}(?::\\d+)?){}$", scheme_re, host_re, path_re))
}

fn regex_set(patterns: &[String]) -> Option<regex::RegexSet> {
    let srcs: Vec<String> = patterns.iter().filter_map(|p| pattern_regex(p)).collect();
    if srcs.is_empty() { return None; }
    regex::RegexSetBuilder::new(&srcs).size_limit(64 << 20).build().ok().or_else(|| {
        // One bad pattern must not drop the rest.
        let ok: Vec<&String> = srcs.iter().filter(|s| regex::Regex::new(s).is_ok()).collect();
        regex::RegexSetBuilder::new(ok).size_limit(64 << 20).build().ok()
    })
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn str_list(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn load_script(dir: &Path, id: &str) -> Option<Script> {
    let code = std::fs::read_to_string(dir.join(format!("{}.user.js", id))).ok()?;
    let (meta, meta_str) = parse_meta(&code);
    let get = |k: &str| meta.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let all = |k: &str| meta.iter().filter(|(a, _)| a == k).map(|(_, v)| v.clone()).collect::<Vec<_>>();
    let opts = read_json(&dir.join(format!("{}.options.json", id)));
    let ov = opts.as_ref().and_then(|o| o.pointer("/options/override"));
    // Tampermonkey's per-script overrides: user lists, merged with the header unless switched off.
    let merged = |header: Vec<String>, key: &str| -> Vec<String> {
        let merge = ov.and_then(|o| o.get(format!("merge_{}", key))).and_then(|b| b.as_bool()).unwrap_or(true);
        let mut list = if merge { header } else { Vec::new() };
        list.extend(str_list(ov.and_then(|o| o.get(format!("use_{}", key)))));
        list
    };
    let matches = merged(all("match"), "matches");
    let includes = merged(all("include"), "includes");
    let excludes = merged([all("exclude"), all("exclude-match")].concat(), "excludes");
    let mut inc_all = matches.clone();
    inc_all.extend(includes.iter().cloned());
    let resources = all("resource").into_iter().filter_map(|r| {
        let mut it = r.splitn(2, char::is_whitespace);
        Some((it.next()?.to_string(), it.next()?.trim().to_string()))
    }).collect();
    let name = { let n = get("name"); if n.is_empty() { id.to_string() } else { n } };
    let run_at = { let r = get("run-at"); if r.is_empty() { "document-idle".into() } else { r.replace('_', "-") } };
    Some(Script {
        id: id.to_string(),
        name,
        namespace: get("namespace"),
        version: get("version"),
        description: get("description"),
        author: get("author"),
        include_set: Arc::new(regex_set(&inc_all)),
        exclude_set: Arc::new(regex_set(&excludes)),
        matches,
        includes,
        excludes,
        requires: all("require"),
        resources,
        run_at,
        grants: all("grant"),
        connects: all("connect"),
        enabled: opts.as_ref().and_then(|o| o.pointer("/settings/enabled")).and_then(|b| b.as_bool()).unwrap_or(true),
        position: opts.as_ref().and_then(|o| o.pointer("/settings/position")).and_then(|n| n.as_i64()).unwrap_or(i64::MAX),
        meta_str,
    })
}

static CACHE: Mutex<Option<Arc<Vec<Script>>>> = Mutex::new(None);

/// Every installed script, in Tampermonkey's order. Cached until the folder changes here.
pub fn load() -> Arc<Vec<Script>> {
    if let Some(c) = CACHE.lock().unwrap().as_ref() { return c.clone(); }
    let d = dir();
    let mut list: Vec<Script> = std::fs::read_dir(&d).map(|rd| rd.flatten().filter_map(|e| {
        let n = e.file_name().to_string_lossy().to_string();
        let id = n.strip_suffix(".user.js")?;
        load_script(&d, id)
    }).collect()).unwrap_or_default();
    list.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    let list = Arc::new(list);
    *CACHE.lock().unwrap() = Some(list.clone());
    list
}

fn invalidate() { *CACHE.lock().unwrap() = None; }

// ── @require / @resource files ─────────────────────────────────────────────

fn strip_fragment(u: &str) -> &str { u.split('#').next().unwrap_or(u) }

/// Local copy of a script's `@require`/`@resource` URL: Tampermonkey's backup
/// files first, else downloaded once and stored the same way.
fn dependency(d: &Path, id: &str, url: &str, kind: &str) -> Result<(Vec<u8>, String), String> {
    let prefix = format!("{}.user.js-", id);
    let want = strip_fragment(url);
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if !n.starts_with(&prefix) { continue; }
            let Some(data_name) = n.strip_suffix(".requires.json").or_else(|| n.strip_suffix(".resources.json")) else { continue };
            let Some(meta) = read_json(&e.path()) else { continue };
            if meta.get("url").and_then(|u| u.as_str()).map(strip_fragment) != Some(want) { continue; }
            if let Ok(bytes) = std::fs::read(d.join(data_name)) {
                let mime = meta.get("mimetype").and_then(|m| m.as_str()).unwrap_or("").to_string();
                return Ok((bytes, mime));
            }
        }
    }
    if !want.starts_with("https://") && !want.starts_with("http://") {
        return Err(format!("{} is not an http(s) address", want));
    }
    let resp = ureq::get(want).timeout(std::time::Duration::from_secs(30)).call().map_err(|e| format!("{}: {}", want, e))?;
    let mime = resp.content_type().to_string();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), MAX_BODY), &mut bytes).map_err(|e| e.to_string())?;
    use sha1::Digest;
    let hash = format!("{:x}", sha1::Sha1::digest(want.as_bytes()));
    let file = format!("{}dl{}-{}", prefix, &hash[..12], kind);
    let _ = std::fs::write(d.join(&file), &bytes);
    let _ = std::fs::write(d.join(format!("{}.{}.json", file, kind)),
        serde_json::json!({ "url": want, "mimetype": mime, "ts": 0 }).to_string());
    log::info!("[Userscripts] Downloaded {} for {}", want, id);
    Ok((bytes, mime))
}

// ── Storage (GM_setValue) ──────────────────────────────────────────────────

static STORAGE_LOCK: Mutex<()> = Mutex::new(());

fn storage_path(id: &str) -> PathBuf { dir().join(format!("{}.storage.json", id)) }

/// Values as Tampermonkey stores them: type letter + text (`s`, `n`, `b`, `o` JSON).
fn read_storage(id: &str) -> serde_json::Map<String, serde_json::Value> {
    read_json(&storage_path(id)).and_then(|v| v.get("data").and_then(|d| d.as_object()).cloned()).unwrap_or_default()
}

fn update_storage(id: &str, f: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> Result<(), String> {
    let _g = STORAGE_LOCK.lock().unwrap();
    let mut data = read_storage(id);
    f(&mut data);
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let body = serde_json::json!({ "ts": ts, "data": data }).to_string();
    let path = storage_path(id);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

// ── Pages ──────────────────────────────────────────────────────────────────

struct Session { label: String, scripts: Vec<String> }

#[derive(Clone, Serialize)]
pub struct MenuItem { token: String, script: String, id: u64, caption: String }

/// Token → page that `page_ready` injected into (newest last, oldest dropped).
static SESSIONS: Mutex<VecDeque<(String, Session)>> = Mutex::new(VecDeque::new());
/// Page-load ids already handled (a page cannot ask twice).
static DOCS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
/// Browser tab label → menu commands its scripts registered.
static MENUS: Mutex<Option<HashMap<String, Vec<MenuItem>>>> = Mutex::new(None);
/// Browser tab label → script id → its latest error on this page (Scripts panel).
static ERRORS: Mutex<Option<HashMap<String, HashMap<String, String>>>> = Mutex::new(None);

fn set_error(label: &str, script: &str, name: &str, text: &str) {
    log::error!("[Userscripts] {}: {}", name, text);
    ERRORS.lock().unwrap().get_or_insert_with(HashMap::new).entry(label.to_string()).or_default().insert(script.to_string(), text.to_string());
}

fn new_token() -> String {
    use std::hash::{BuildHasher, Hasher};
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut out = String::new();
    for _ in 0..2 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// Browser tab label → whether the current page load already used `page_ready`.
static READY_USED: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);

/// A Browser tab started loading a new page (or closed): the old page's tokens
/// and menu commands go, and the new page may call `page_ready` once.
/// WebView2 raises ContentLoading (tauri's Started) before any document-created
/// script runs, so this always precedes the new page's `page_ready`.
pub fn page_started(label: &str) {
    if let Some(m) = MENUS.lock().unwrap().as_mut() { m.remove(label); }
    if let Some(m) = ERRORS.lock().unwrap().as_mut() { m.remove(label); }
    SESSIONS.lock().unwrap().retain(|(_, s)| s.label != label);
    READY_USED.lock().unwrap().get_or_insert_with(HashMap::new).insert(label.to_string(), false);
}

/// The tab is gone: forget it entirely.
pub fn tab_closed(label: &str) {
    page_started(label);
    if let Some(m) = READY_USED.lock().unwrap().as_mut() { m.remove(label); }
}

/// Runs first in every Browser tab page (main frame): asks `page_ready` for this
/// page's scripts. The page-load id stops a script being injected into a later page.
pub fn bootstrap_script() -> String {
    r#"(function(){
  if (window.top !== window) return;
  var doc = Math.random().toString(36).slice(2) + Date.now().toString(36);
  try { Object.defineProperty(window, "__mpUSDoc", { value: doc }); } catch (e) { return; }
  var tries = 0;
  (function ask(){
    var t = window.__TAURI_INTERNALS__;
    if (!t || !t.invoke) { if (++tries < 100) setTimeout(ask, 10); return; }
    t.invoke("plugin:userscripts|page_ready", { url: location.href, doc: doc })
      .catch(function(e){ console.warn("[userscripts]", e); });
  })();
})();"#.to_string()
}

fn script_payload(s: &Script, d: &Path) -> serde_json::Value {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut resources = serde_json::Map::new();
    for (name, url) in &s.resources {
        match dependency(d, &s.id, url, "resources") {
            Ok((bytes, mime)) => { resources.insert(name.clone(), serde_json::json!({ "b64": b64.encode(bytes), "mime": if mime.is_empty() { "application/octet-stream".to_string() } else { mime }, "url": url })); }
            Err(e) => log::warn!("[Userscripts] {}: resource {}: {}", s.name, name, e),
        }
    }
    serde_json::json!({
        "id": s.id,
        "runAt": s.run_at,
        "sandbox": s.sandboxed(),
        "storage": read_storage(&s.id),
        "resources": resources,
        "info": {
            "script": {
                "name": s.name, "namespace": s.namespace, "version": s.version, "description": s.description,
                "author": s.author, "matches": s.matches, "includes": s.includes, "excludes": s.excludes,
                "grant": s.grants, "run-at": s.run_at, "runAt": s.run_at,
                "resources": s.resources.iter().map(|(n, u)| serde_json::json!({ "name": n, "url": u })).collect::<Vec<_>>(),
                "header": s.meta_str,
            },
            "scriptMetaStr": s.meta_str,
            "scriptHandler": "Tampermonkey",
            "version": "5.3.0",
            "mabiPatcher": env!("CARGO_PKG_VERSION"),
        },
    })
}

/// Wrapper for one script: its `@require`s then its code, in one function so
/// they share scope, inside `with (sandbox)` when the script has grants.
fn script_source(s: &Script, d: &Path, doc: &str) -> Result<String, String> {
    let mut body = String::new();
    for url in &s.requires {
        let (bytes, _) = dependency(d, &s.id, url, "requires")?;
        body.push_str(&String::from_utf8_lossy(&bytes));
        body.push_str("\n;\n");
    }
    body.push_str(&std::fs::read_to_string(d.join(format!("{}.user.js", s.id))).map_err(|e| e.to_string())?);
    let inner = if s.sandboxed() {
        format!("with(__mpSandbox){{(function(){{\n{}\n}}).call(__mpSandbox);}}", body)
    } else {
        format!("(function(){{\n{}\n}}).call(window);", body)
    };
    Ok(format!(
        "if(window.__mpUSDoc==={doc}&&window.__mpUS){{window.__mpUS.run({payload},function({params}){{{inner}\n}});}}\n//# sourceURL=userscript:{name}",
        doc = serde_json::to_string(doc).unwrap(),
        payload = script_payload(s, d),
        params = PARAMS,
        inner = inner,
        name = s.id.replace(char::is_whitespace, "_"),
    ))
}

#[tauri::command]
async fn page_ready(webview: Webview, url: String, doc: String) -> Result<(), String> {
    let _ = url;
    let label = webview.label().to_string();
    if !label.starts_with("browser") { return Err("not a Browser tab".into()); }
    if doc.len() > 64 { return Err("bad page id".into()); }
    {
        // One injection per page load: a page cannot re-run page_ready with new ids.
        let mut used = READY_USED.lock().unwrap();
        let used = used.get_or_insert_with(HashMap::new).entry(label.clone()).or_insert(false);
        if *used { return Ok(()); }
        *used = true;
    }
    {
        let mut docs = DOCS.lock().unwrap();
        if docs.contains(&doc) { return Ok(()); }
        docs.push_back(doc.clone());
        while docs.len() > 500 { docs.pop_front(); }
    }
    // The page's real address, not what it says.
    let page_url = webview.url().map_err(|e| e.to_string())?.to_string();
    let scripts: Vec<Script> = load().iter().filter(|s| s.enabled && s.matches_url(&page_url)).cloned().collect();
    if scripts.is_empty() { return Ok(()); }
    let token = new_token();
    {
        let mut sessions = SESSIONS.lock().unwrap();
        sessions.push_back((token.clone(), Session { label: label.clone(), scripts: scripts.iter().map(|s| s.id.clone()).collect() }));
        while sessions.len() > 300 { sessions.pop_front(); }
    }
    let runtime = RUNTIME_JS
        .replace("\"__MP_DOC__\"", &serde_json::to_string(&doc).unwrap())
        .replace("\"__MP_TOKEN__\"", &serde_json::to_string(&token).unwrap());
    webview.eval(runtime).map_err(|e| e.to_string())?;
    let d = dir();
    for s in &scripts {
        let src = {
            let (s, d, doc) = (s.clone(), d.clone(), doc.clone());
            tauri::async_runtime::spawn_blocking(move || script_source(&s, &d, &doc)).await.map_err(|e| e.to_string())?
        };
        match src {
            Ok(js) => {
                let _ = webview.eval(format!("window.__mpUS&&window.__mpUS.expect({})", serde_json::to_string(&s.id).unwrap()));
                let _ = webview.eval(js);
            }
            Err(e) => set_error(&label, &s.id, &s.name, &format!("not run: {}", e)),
        }
    }
    log::info!("[Userscripts] {} script(s) on {}", scripts.len(), page_url);
    Ok(())
}

/// Every `gm` call: the runtime's token, the calling script, an operation and its arguments.
#[tauri::command]
async fn gm(webview: Webview, token: String, script: String, op: String, args: serde_json::Value) -> Result<serde_json::Value, String> {
    let label = webview.label().to_string();
    let allowed = SESSIONS.lock().unwrap().iter().any(|(t, s)| t == &token && s.label == label && s.scripts.contains(&script));
    if !allowed { return Err("not allowed".into()); }
    // The page shares the runtime's JS context and could read the token, so each
    // operation also needs the script's own @grant (and @connect for requests).
    let meta = load().iter().find(|s| s.id == script).cloned().ok_or("not allowed")?;
    let need: &[&str] = match op.as_str() {
        "set" | "delete" => &["setvalue", "deletevalue", "setvalues", "deletevalues"],
        "menu" => &["registermenucommand", "unregistermenucommand"],
        "xhr" => &["xmlhttprequest"],
        "download" => &["download"],
        "open_tab" => &["openintab"],
        _ => &[],
    };
    if !need.is_empty() && !meta.granted(need) { return Err(format!("{} needs @grant for {}", script, op)); }
    let arg = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let page_host = webview.url().ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
    let allow = { let (m, p) = (meta.clone(), page_host.clone()); move |h: &str| m.may_connect(&p, h) };
    if op == "xhr" || (op == "download" && args.get("body").is_none()) {
        let target: tauri::Url = arg("url").parse().map_err(|e| format!("invalid address: {}", e))?;
        if !meta.may_connect(&page_host, target.host_str().unwrap_or("")) {
            return Err(format!("{} has no @connect for {}", script, target.host_str().unwrap_or("")));
        }
    }
    match op.as_str() {
        "set" => {
            let (key, value) = (arg("key"), args.get("value").cloned().unwrap_or(serde_json::Value::Null));
            update_storage(&script, |m| { m.insert(key, value); })?;
            Ok(serde_json::Value::Null)
        }
        "delete" => {
            let key = arg("key");
            update_storage(&script, |m| { m.remove(&key); })?;
            Ok(serde_json::Value::Null)
        }
        "menu" => {
            let items: Vec<MenuItem> = args.get("items").and_then(|i| i.as_array()).map(|a| a.iter().filter_map(|i| Some(MenuItem {
                token: token.clone(),
                script: script.clone(),
                id: i.get("id")?.as_u64()?,
                caption: i.get("caption")?.as_str()?.chars().take(200).collect(),
            })).collect()).unwrap_or_default();
            let mut menus = MENUS.lock().unwrap();
            let list = menus.get_or_insert_with(HashMap::new).entry(label).or_default();
            list.retain(|m| m.script != script);
            list.extend(items);
            Ok(serde_json::Value::Null)
        }
        "xhr" => {
            let cookie = if args.get("anonymous").and_then(|a| a.as_bool()).unwrap_or(false) { None } else { cookie_header(&webview, &arg("url")) };
            tauri::async_runtime::spawn_blocking(move || http_request(&args, cookie, &allow)).await.map_err(|e| e.to_string())?
        }
        "download" => {
            let name = arg("name");
            let cookie = cookie_header(&webview, &arg("url"));
            tauri::async_runtime::spawn_blocking(move || download(&args, &name, cookie, &allow)).await.map_err(|e| e.to_string())?
        }
        "open_tab" => {
            let url: tauri::Url = arg("url").parse().map_err(|e| format!("invalid address: {}", e))?;
            if url.scheme() != "https" && url.scheme() != "http" { return Err("only http(s) addresses open in a tab".into()); }
            let background = args.get("background").and_then(|b| b.as_bool()).unwrap_or(false);
            crate::site::open_tab(webview.app_handle(), url, !background).map(serde_json::Value::String)
        }
        "error" => {
            set_error(&label, &script, &meta.name, &arg("text").chars().take(1000).collect::<String>());
            Ok(serde_json::Value::Null)
        }
        "log" => {
            log::info!("[Userscripts] {}: {}", script, arg("text").chars().take(2000).collect::<String>());
            Ok(serde_json::Value::Null)
        }
        _ => Err(format!("unknown operation {}", op)),
    }
}

/// The Browser tab's cookies for `url`, as a Cookie header (what Tampermonkey sends).
fn cookie_header(webview: &Webview, url: &str) -> Option<String> {
    let u: tauri::Url = url.parse().ok()?;
    let cookies = webview.cookies_for_url(u).ok()?;
    if cookies.is_empty() { return None; }
    Some(cookies.iter().map(|c| format!("{}={}", c.name(), c.value())).collect::<Vec<_>>().join("; "))
}

fn http_url(args: &serde_json::Value) -> Result<String, String> {
    let url = args.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string();
    if !url.starts_with("https://") && !url.starts_with("http://") { return Err(format!("{} is not an http(s) address", url)); }
    Ok(url)
}

/// GM_xmlhttpRequest: `{method, url, headers, body (base64), timeout, ua, redirect}` →
/// `{status, statusText, headers, finalUrl, body (base64)}`.
fn http_request(args: &serde_json::Value, cookie: Option<String>, allow: &(dyn Fn(&str) -> bool + Send + Sync)) -> Result<serde_json::Value, String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let url = http_url(args)?;
    let method = args.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_uppercase();
    let timeout = args.get("timeout").and_then(|t| t.as_u64()).filter(|t| *t > 0).unwrap_or(120_000);
    let manual = args.get("redirect").and_then(|r| r.as_str()) == Some("manual");
    // Redirects are followed here: the page's cookies must not follow a redirect to another host.
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_millis(timeout))
        .redirects(0)
        .build();
    let mut body = match args.get("body").and_then(|b| b.as_str()) {
        Some(s) => Some(b64.decode(s).map_err(|e| e.to_string())?),
        None => None,
    };
    // Cookies and credentials go only to the first address's exact origin (scheme, host, port).
    let origin = |u: &str| tauri::Url::parse(u).ok().map(|u| (u.scheme().to_string(), u.host_str().map(String::from), u.port_or_known_default()));
    let first_origin = origin(&url);
    let (mut url, mut method, mut hops) = (url, method, 0);
    let resp = loop {
        let mut req = agent.request(&method, &url);
        let mut has_ua = false;
        let mut has_cookie = false;
        let same_host = origin(&url) == first_origin;
        if let Some(h) = args.get("headers").and_then(|h| h.as_object()) {
            for (k, v) in h {
                let lk = k.to_ascii_lowercase();
                if lk == "host" || lk == "content-length" || lk == "connection" { continue; }
                if (lk == "cookie" || lk == "authorization") && !same_host { continue; }
                if lk == "user-agent" { has_ua = true; }
                if lk == "cookie" { has_cookie = true; }
                if let Some(s) = v.as_str() { req = req.set(k, s); }
            }
        }
        if !has_ua {
            if let Some(ua) = args.get("ua").and_then(|u| u.as_str()) { req = req.set("User-Agent", ua); }
        }
        if let (false, true, Some(c)) = (has_cookie, same_host, cookie.as_ref()) { req = req.set("Cookie", c); }
        let result = match &body { Some(b) => req.send_bytes(b), None => req.call() };
        let resp = match result {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        };
        let code = resp.status();
        let next = resp.header("location").and_then(|l| tauri::Url::parse(&url).ok()?.join(l).ok());
        match next {
            Some(n) if !manual && (300..400).contains(&code) && hops < 10 && (n.scheme() == "https" || n.scheme() == "http") => {
                // A redirect must stay within the script's @connect hosts too.
                if !allow(n.host_str().unwrap_or("")) { return Err(format!("redirect to {} is not allowed by @connect", n.host_str().unwrap_or(""))); }
                if matches!(code, 301 | 302 | 303) && method != "HEAD" { method = "GET".into(); body = None; }
                url = n.to_string();
                hops += 1;
            }
            _ => break resp,
        }
    };
    let mut headers = String::new();
    for name in resp.headers_names() {
        for v in resp.all(&name) { headers.push_str(&format!("{}: {}\r\n", name, v)); }
    }
    let (status, status_text, final_url) = (resp.status(), resp.status_text().to_string(), resp.get_url().to_string());
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), MAX_BODY), &mut bytes).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "status": status, "statusText": status_text, "headers": headers, "finalUrl": final_url, "body": b64.encode(bytes) }))
}

/// GM_download into the Downloads folder: `{url}` fetched here, or `{body}` (base64)
/// for blob:/data: addresses the page already read. Returns the saved path.
fn download(args: &serde_json::Value, name: &str, cookie: Option<String>, allow: &(dyn Fn(&str) -> bool + Send + Sync)) -> Result<serde_json::Value, String> {
    use base64::Engine;
    // Tampermonkey's default download whitelist idea: media, documents, archives.
    // Never programs or shortcuts (.exe, .bat, .ps1, .lnk, .url, …).
    const SAFE: &[&str] = &[
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "avif", "ico", "tif", "tiff",
        "mp4", "webm", "mkv", "mov", "avi", "m4v", "mp3", "m4a", "ogg", "opus", "wav", "flac", "aac",
        "txt", "json", "csv", "tsv", "xml", "md", "pdf", "epub", "srt", "ass", "vtt",
        "zip", "7z", "rar", "tar", "gz", "cbz", "cbr", "torrent",
    ];
    let ext = Path::new(name).extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if !SAFE.contains(&ext.as_str()) {
        return Err(format!("downloads of .{} files are not allowed", if ext.is_empty() { "(none)" } else { ext.as_str() }));
    }
    let bytes = match args.get("body").and_then(|b| b.as_str()) {
        Some(b) => base64::engine::general_purpose::STANDARD.decode(b).map_err(|e| e.to_string())?,
        None => {
            let r = http_request(args, cookie, allow)?;
            if r["status"].as_u64().unwrap_or(0) >= 400 { return Err(format!("HTTP {}", r["status"])); }
            base64::engine::general_purpose::STANDARD.decode(r["body"].as_str().unwrap_or("")).map_err(|e| e.to_string())?
        }
    };
    let downloads = directories::UserDirs::new().and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
        .ok_or("no Downloads folder")?;
    // Keep any sub-folders the script asked for, but never above Downloads.
    let rel: PathBuf = name.split(['/', '\\']).filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .map(|p| p.chars().map(|c| if "<>:\"|?*".contains(c) || c.is_control() { '_' } else { c }).collect::<String>())
        .collect();
    let rel = if rel.as_os_str().is_empty() { PathBuf::from("download") } else { rel };
    let mut dest = downloads.join(&rel);
    if let Some(p) = dest.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }
    let (stem, ext) = (
        dest.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        dest.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default(),
    );
    let mut n = 1;
    while dest.exists() {
        dest = dest.with_file_name(format!("{} ({}){}", stem, n, ext));
        n += 1;
    }
    std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;
    log::info!("[Userscripts] Downloaded {}", dest.display());
    Ok(serde_json::Value::String(dest.to_string_lossy().to_string()))
}

pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("userscripts")
        .invoke_handler(tauri::generate_handler![page_ready, gm])
        .build()
}

// ── Commands for the Browser tab's Scripts panel ───────────────────────────

/// Installed scripts; `active` marks those running on the Browser tab's page, with their menu commands.
#[tauri::command]
pub fn userscripts_list(app: AppHandle) -> serde_json::Value {
    let page = crate::site::active_tab(&app);
    let menus = MENUS.lock().unwrap();
    let errors = ERRORS.lock().unwrap();
    let list: Vec<serde_json::Value> = load().iter().map(|s| {
        let active = s.enabled && page.as_ref().map(|(_, u)| s.matches_url(u)).unwrap_or(false);
        let menu: Vec<&MenuItem> = page.as_ref()
            .and_then(|(l, _)| menus.as_ref().and_then(|m| m.get(l)))
            .map(|items| items.iter().filter(|m| m.script == s.id).collect())
            .unwrap_or_default();
        serde_json::json!({
            "id": s.id, "name": s.name, "version": s.version, "description": s.description,
            "enabled": s.enabled, "active": active, "menu": menu,
            "error": page.as_ref().and_then(|(l, _)| errors.as_ref()?.get(l)?.get(&s.id).cloned()),
        })
    }).collect();
    serde_json::json!({ "dir": dir(), "scripts": list })
}

#[tauri::command]
pub fn userscripts_set_enabled(id: String, enabled: bool) -> Result<(), String> {
    let d = dir();
    if !d.join(format!("{}.user.js", id)).is_file() { return Err("no such script".into()); }
    let path = d.join(format!("{}.options.json", id));
    let mut opts = read_json(&path).unwrap_or_else(|| serde_json::json!({}));
    if !opts.get("settings").map(|s| s.is_object()).unwrap_or(false) { opts["settings"] = serde_json::json!({}); }
    opts["settings"]["enabled"] = serde_json::Value::Bool(enabled);
    std::fs::write(&path, opts.to_string()).map_err(|e| e.to_string())?;
    invalidate();
    Ok(())
}

/// Run a script's menu command (GM_registerMenuCommand) in the page that registered it.
#[tauri::command]
pub fn userscripts_run_menu(app: AppHandle, token: String, script: String, id: u64) -> Result<(), String> {
    let label = SESSIONS.lock().unwrap().iter().find(|(t, _)| t == &token).map(|(_, s)| s.label.clone()).ok_or("the page has changed")?;
    let wv = app.get_webview(&label).ok_or("the tab is closed")?;
    wv.eval(format!("window.__mpUS&&window.__mpUS.menu({},{},{})",
        serde_json::to_string(&token).unwrap(), serde_json::to_string(&script).unwrap(), id)).map_err(|e| e.to_string())
}

/// Import a Tampermonkey backup zip (Tampermonkey's .txt backup is the same zip)
/// or one `.user.js`. Existing files of the same name are replaced.
/// Returns the number of scripts imported.
#[tauri::command]
pub async fn userscripts_import(path: String) -> Result<usize, String> {
    tauri::async_runtime::spawn_blocking(move || import(Path::new(&path))).await.map_err(|e| e.to_string())?
}

fn safe_name(n: &str) -> bool {
    !n.is_empty() && !n.contains(['/', '\\', ':']) && n != "." && n != ".." && !n.starts_with('.')
}

fn import(path: &Path) -> Result<usize, String> {
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if !bytes.starts_with(b"PK") {
        // A single script.
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let text = String::from_utf8(bytes).map_err(|_| "not a userscript or Tampermonkey backup".to_string())?;
        if !text.contains("==UserScript==") { return Err("not a userscript or Tampermonkey backup".into()); }
        let (meta, _) = parse_meta(&text);
        let title = meta.iter().find(|(k, _)| k == "name").map(|(_, v)| v.clone()).unwrap_or_else(|| name.trim_end_matches(".js").trim_end_matches(".user").to_string());
        let id: String = title.chars().map(|c| if "<>:\"/\\|?*".contains(c) || c.is_control() { '_' } else { c }).collect();
        if !safe_name(&id) { return Err("bad script name".into()); }
        std::fs::write(d.join(format!("{}.user.js", id)), text).map_err(|e| e.to_string())?;
        invalidate();
        return Ok(1);
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| format!("not a Tampermonkey backup: {}", e))?;
    let mut scripts = 0;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        if f.is_dir() { continue; }
        let name = f.name().to_string();
        // Tampermonkey backups are flat; anything with a folder or odd name is skipped.
        if !safe_name(&name) { continue; }
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(&mut f, MAX_BODY), &mut out).map_err(|e| e.to_string())?;
        std::fs::write(d.join(&name), out).map_err(|e| e.to_string())?;
        if name.ends_with(".user.js") { scripts += 1; }
    }
    invalidate();
    log::info!("[Userscripts] Imported {} script(s) from {}", scripts, path.display());
    Ok(scripts)
}

#[tauri::command]
pub fn userscripts_dir() -> Result<String, String> {
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    invalidate();
    Ok(d.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(p: &[&str]) -> regex::RegexSet { regex_set(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap() }

    #[test]
    fn grants_and_connect() {
        let dir = std::env::temp_dir().join(format!("mp-us-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("t.user.js"), "// ==UserScript==\n// @grant GM.xmlHttpRequest\n// @grant GM_setValue\n// @connect api.jikan.moe\n// ==/UserScript==\n").unwrap();
        let s = load_script(&dir, "t").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(s.granted(&["xmlhttprequest"]));
        assert!(s.granted(&["setvalue", "deletevalue"]));
        assert!(!s.granted(&["download"]));
        assert!(s.may_connect("myanimelist.net", "myanimelist.net"));
        assert!(s.may_connect("www.myanimelist.net", "cdn.myanimelist.net"));
        assert!(s.may_connect("myanimelist.net", "api.jikan.moe"));
        assert!(s.may_connect("myanimelist.net", "v4.api.jikan.moe"));
        assert!(!s.may_connect("myanimelist.net", "evil.example"));
        assert!(!s.may_connect("myanimelist.net", "jikan.moe"));
    }

    #[test]
    fn match_patterns() {
        let s = set(&["*://myanimelist.net/anime/*"]);
        assert!(s.is_match("https://myanimelist.net/anime/1/Cowboy_Bebop"));
        assert!(!s.is_match("https://myanimelist.net/manga/1"));
        let s = set(&["*://*.crunchyroll.com/*"]);
        assert!(s.is_match("https://www.crunchyroll.com/watch/x"));
        assert!(s.is_match("https://crunchyroll.com/"));
        assert!(!s.is_match("https://evilcrunchyroll.com/"));
        let s = set(&["/^https?://(www\\.)?nyaa\\.si/.*$/"]);
        assert!(s.is_match("https://nyaa.si/?q=x"));
        let s = set(&["https://myanimelist.net*"]);
        assert!(s.is_match("https://myanimelist.net/profile/x"));
        let s = set(&["*"]);
        assert!(s.is_match("http://example.com/"));
    }

    #[test]
    fn meta_block() {
        let (m, block) = parse_meta("// ==UserScript==\n// @name  Test\n// @match *://a.com/*\n// @grant GM_setValue\n// ==/UserScript==\nalert(1)");
        assert!(m.contains(&("name".into(), "Test".into())));
        assert!(m.contains(&("match".into(), "*://a.com/*".into())));
        assert!(block.ends_with("==/UserScript==\n"));
    }
    /// Builds every script of a Tampermonkey backup folder (`MP_US_DIR`) into
    /// `MP_US_OUT/<id>.js` for a syntax check with `node --check`.
    #[test]
    #[ignore]
    fn backup_scripts_build() {
        let d = PathBuf::from(std::env::var("MP_US_DIR").expect("MP_US_DIR"));
        let out = PathBuf::from(std::env::var("MP_US_OUT").expect("MP_US_OUT"));
        std::fs::create_dir_all(&out).unwrap();
        let mut ok = 0;
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            let Some(id) = n.strip_suffix(".user.js") else { continue };
            let s = load_script(&d, id).expect(id);
            match script_source(&s, &d, "doc") {
                Ok(js) => { std::fs::write(out.join(format!("{}.js", ok)), js).unwrap(); ok += 1; }
                Err(e) => println!("FAIL {}: {}", id, e),
            }
        }
        println!("built {}", ok);
    }
}