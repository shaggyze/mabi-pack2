/// mabi-patcher HTTP REST API server.
///
/// Binds on 127.0.0.1:7331 by default (loopback only, never exposed to LAN).
/// Designed to be the backend microservice for the UOTiara WebUI.
///
/// Routes:
///   GET  /api/v1/status
///   POST /api/v1/extract
///   POST /api/v1/pack
///   POST /api/v1/list
///   POST /api/v1/mod/apply
///   GET  /api/v1/mods
///   GET  /api/v1/mod-template
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tiny_http::{Header, Method, Request, Response, Server};

pub const DEFAULT_PORT: u16 = 7331;

fn cors_headers() -> Vec<Header> {
    vec![
        Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap(),
        Header::from_bytes("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap(),
        Header::from_bytes("Access-Control-Allow-Headers", "Content-Type").unwrap(),
        Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap(),
    ]
}

fn ok(data: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = json!({ "success": true, "data": data, "error": null }).to_string();
    let mut r = Response::from_string(body);
    for h in cors_headers() { r.add_header(h); }
    r
}

fn err(msg: &str, code: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = json!({ "success": false, "data": null, "error": msg }).to_string();
    let mut r = Response::from_string(body).with_status_code(code);
    for h in cors_headers() { r.add_header(h); }
    r
}

fn read_body(req: &mut Request) -> Result<String> {
    let mut body = String::new();
    req.as_reader().read_to_string(&mut body)?;
    Ok(body)
}

fn parse_json_body(req: &mut Request) -> Result<Value, Response<std::io::Cursor<Vec<u8>>>> {
    let raw = read_body(req).map_err(|e| err(&e.to_string(), 400))?;
    serde_json::from_str(&raw).map_err(|e| err(&format!("Invalid JSON: {}", e), 400))
}

// ---- handlers ---------------------------------------------------------------

fn handle_status() -> Response<std::io::Cursor<Vec<u8>>> {
    ok(json!({
        "app":     "mabi-patcher",
        "version": env!("CARGO_PKG_VERSION"),
        "api":     "v1",
        "port":    DEFAULT_PORT,
    }))
}

fn handle_extract(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'archive' is required", 400),
    };
    let output = match body["output"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'output' is required", 400),
    };
    let key = body["key"].as_str().map(String::from);
    let filters: Vec<String> = body["filters"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let auto_png  = body["auto_convert_png"].as_bool().unwrap_or(false);
    let auto_feat = body["auto_convert_features"].as_bool().unwrap_or(false);
    let auto_pmg  = body["auto_convert_pmg"].as_bool().unwrap_or(false);

    let salts = crate::load_salts();
    match crate::extract::run_extract_with_key_search(
        &archive, &output, key, &salts, filters, None,
        auto_png, auto_feat, auto_pmg, None,
    ) {
        Ok(salt) => ok(json!({ "archive": archive, "output": output, "salt_used": salt })),
        Err(e)   => err(&e.to_string(), 500),
    }
}

fn handle_pack(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let source = match body["source"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'source' is required", 400),
    };
    let output = match body["output"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'output' is required", 400),
    };
    let key = match body["key"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'key' is required", 400),
    };
    let wrap_data = body["wrap_data"].as_bool().unwrap_or(false);
    let prefix    = if wrap_data { Some("data") } else { None };

    match crate::pack::run_pack(&source, &output, &key, vec![], false, 0, prefix, None) {
        Ok(_)  => ok(json!({ "source": source, "output": output })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_list(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'archive' is required", 400),
    };
    let key  = body["key"].as_str().map(String::from);
    let salts = crate::load_salts();

    // list writes to a file path or stdout; capture via temp file
    let tmp = std::env::temp_dir().join(format!("mabi_api_list_{}.txt", std::process::id()));
    let tmp_str = tmp.to_string_lossy().to_string();
    match crate::list::run_list_with_key_search(&archive, key, &salts, Some(&tmp_str)) {
        Ok(_) => {
            let text = std::fs::read_to_string(&tmp).unwrap_or_default();
            let _ = std::fs::remove_file(&tmp);
            let entries: Vec<Value> = text.lines()
                .filter(|l| !l.is_empty())
                .map(|l| json!({ "name": l }))
                .collect();
            ok(json!({ "archive": archive, "count": entries.len(), "entries": entries }))
        }
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_mod_apply(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };

    let toml_src = match body["mod_toml"].as_str().or(body["mod"].as_str()) {
        Some(s) => s.to_string(),
        None => return err("'mod_toml' (TOML string) is required", 400),
    };
    let archive = match body["archive"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'archive' (path to .it/.pack) is required", 400),
    };
    let key = body["key"].as_str().map(String::from);
    // Base dir for resolving relative source= paths in [[files]] entries
    let mod_dir: std::path::PathBuf = body["mod_dir"].as_str()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir());

    let pkg = match crate::mod_file::ModPackage::from_str(&toml_src) {
        Ok(p) => p,
        Err(e) => return err(&e.to_string(), 400),
    };

    match apply_mod_to_archive(&pkg, &archive, key.as_deref(), &mod_dir) {
        Ok(stats) => ok(json!({
            "name":     pkg.meta.name,
            "version":  pkg.meta.version,
            "archive":  archive,
            "replaced": stats.replaced,
            "deleted":  stats.deleted,
            "patched":  stats.patched,
            "skipped":  stats.skipped,
            "status":   "applied",
        })),
        Err(e) => err(&format!("mod apply failed: {}", e), 500),
    }
}

#[derive(Default)]
struct ApplyStats { replaced: usize, deleted: usize, patched: usize, skipped: usize }

fn apply_mod_to_archive(
    pkg: &crate::mod_file::ModPackage,
    archive_path: &str,
    key: Option<&str>,
    mod_dir: &std::path::Path,
) -> anyhow::Result<ApplyStats> {
    use crate::mod_file::FileAction;
    use std::path::Path;

    let tmp_dir = std::env::temp_dir().join(format!("mabi_mod_{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;

    let tmp_str = tmp_dir.to_string_lossy().to_string();
    let salts = crate::load_salts();

    // 1. Extract the whole archive to a temp folder
    let salt_used = crate::extract::run_extract_with_key_search(
        archive_path, &tmp_str, key.map(String::from), &salts,
        vec![], None, false, false, false, None,
    )?;

    // 2. Apply each [[files]] instruction
    let mut stats = ApplyStats::default();
    for entry in &pkg.files {
        // Normalise the archive path separator to the OS path separator
        let rel = entry.archive_path.replace('\\', std::path::MAIN_SEPARATOR_STR);
        // Strip a leading "data\" prefix that the extractor may add
        let rel = rel.trim_start_matches("data/").trim_start_matches("data\\").to_string();
        let dest = tmp_dir.join(&rel);

        match entry.action {
            FileAction::Delete => {
                if dest.exists() {
                    std::fs::remove_file(&dest)?;
                    stats.deleted += 1;
                } else {
                    stats.skipped += 1;
                }
            }
            FileAction::Replace => {
                if let Some(src) = &entry.source {
                    let src_path = if Path::new(src).is_absolute() {
                        Path::new(src).to_path_buf()
                    } else {
                        mod_dir.join(src)
                    };
                    if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent)?; }
                    std::fs::copy(&src_path, &dest)?;
                    stats.replaced += 1;
                } else {
                    stats.skipped += 1;
                }
            }
            FileAction::Patch => {
                // Apply byte-level patches then optionally overlay source file
                if let Some(patches) = &entry.patches {
                    let mut data = if dest.exists() {
                        std::fs::read(&dest)?
                    } else {
                        Vec::new()
                    };
                    for patch in patches {
                        let offset = u64::from_str_radix(
                            patch.offset.trim_start_matches("0x").trim_start_matches("0X"), 16
                        ).map_err(|_| anyhow::anyhow!("invalid offset: {}", patch.offset))?;
                        let patched_bytes = decode_hex(&patch.patched)
                            .map_err(|_| anyhow::anyhow!("invalid hex in patched: {}", patch.patched))?;
                        let end = offset as usize + patched_bytes.len();
                        if end > data.len() { data.resize(end, 0); }
                        data[offset as usize..end].copy_from_slice(&patched_bytes);
                    }
                    if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent)?; }
                    std::fs::write(&dest, &data)?;
                    stats.patched += 1;
                } else if let Some(src) = &entry.source {
                    let src_path = if Path::new(src).is_absolute() {
                        Path::new(src).to_path_buf()
                    } else {
                        mod_dir.join(src)
                    };
                    if let Some(parent) = dest.parent() { std::fs::create_dir_all(parent)?; }
                    std::fs::copy(&src_path, &dest)?;
                    stats.patched += 1;
                } else {
                    stats.skipped += 1;
                }
            }
        }
    }

    // 3. Repack the modified folder back over the original archive
    let key_str = key.unwrap_or(&salt_used);
    // Detect wrap-data prefix from archive name (same heuristic as GUI)
    let archive_name = Path::new(archive_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let needs_wrap = archive_name.to_lowercase().ends_with(".pack");
    let prefix = if needs_wrap { Some("data") } else { None };

    crate::pack::run_pack(&tmp_str, archive_path, key_str, vec![], false, 0, prefix, None)?;

    // 4. Cleanup temp dir
    let _ = std::fs::remove_dir_all(&tmp_dir);

    Ok(stats)
}

fn handle_list_mods() -> Response<std::io::Cursor<Vec<u8>>> {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("mods")))
        .unwrap_or_else(|| std::path::Path::new("mods").to_path_buf());

    let results = crate::mod_file::scan_mods(&dir);
    let mods: Vec<Value> = results.iter().map(|(path, pkg)| {
        match pkg {
            Ok(p) => json!({
                "file":      path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "name":      p.meta.name,
                "version":   p.meta.version,
                "author":    p.meta.author,
                "tags":      p.meta.tags,
                "public":    p.is_api_public(),
                "files":     p.file_count(),
                "error":     null,
            }),
            Err(e) => json!({
                "file":  path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
                "error": e.to_string(),
            }),
        }
    }).collect();
    ok(json!({ "dir": dir.to_string_lossy(), "count": mods.len(), "mods": mods }))
}

fn handle_mod_template() -> Response<std::io::Cursor<Vec<u8>>> {
    ok(json!({ "template": crate::mod_file::template() }))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 { return Err(()); }
    (0..s.len()).step_by(2).map(|i| {
        u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ())
    }).collect()
}

// ---- router -----------------------------------------------------------------

fn route(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let url = req.url().to_string();
    let method = req.method().clone();

    // CORS preflight
    if method == Method::Options {
        let mut r = Response::from_string("").with_status_code(204);
        for h in cors_headers() { r.add_header(h); }
        return r;
    }

    match (&method, url.as_str()) {
        (Method::Get,  "/api/v1/status")       => handle_status(),
        (Method::Post, "/api/v1/extract")      => handle_extract(req),
        (Method::Post, "/api/v1/pack")         => handle_pack(req),
        (Method::Post, "/api/v1/list")         => handle_list(req),
        (Method::Post, "/api/v1/mod/apply")    => handle_mod_apply(req),
        (Method::Get,  "/api/v1/mods")         => handle_list_mods(),
        (Method::Get,  "/api/v1/mod-template") => handle_mod_template(),
        _ => err(&format!("Not found: {} {}", method, url), 404),
    }
}

// ---- server -----------------------------------------------------------------

/// Start the API server. Blocks until `stop` is set.
/// `host` defaults to `"127.0.0.1"` (loopback); pass `"0.0.0.0"` for Docker/container use.
pub fn run_server(host: &str, port: u16, stop: Arc<AtomicBool>) -> Result<()> {
    let addr = format!("{}:{}", host, port);
    let server = Server::http(&addr)
        .map_err(|e| anyhow::anyhow!("API server bind failed on {}: {}", addr, e))?;
    log::info!("[API] Listening on http://{}", addr);
    loop {
        if stop.load(Ordering::Relaxed) { break; }
        match server.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(Some(mut req)) => {
                let resp = route(&mut req);
                let _ = req.respond(resp);
            }
            Ok(None) => {}
            Err(e) => log::warn!("[API] recv error: {}", e),
        }
    }
    log::info!("[API] Server stopped");
    Ok(())
}

/// Spawn the API server on a background thread (loopback only). Returns the stop flag.
pub fn spawn(port: u16) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    std::thread::spawn(move || {
        if let Err(e) = run_server("127.0.0.1", port, stop2) {
            log::error!("[API] {}", e);
        }
    });
    stop
}

// ---- CLI ----

#[derive(Debug, Serialize, Deserialize)]
pub struct ServeArgs {
    pub port: u16,
}
