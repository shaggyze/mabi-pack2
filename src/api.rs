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
    match crate::mod_file::ModPackage::from_str(&toml_src) {
        Ok(pkg) => ok(json!({
            "name":       pkg.meta.name,
            "version":    pkg.meta.version,
            "file_count": pkg.file_count(),
            "status":     "parsed_ok",
            "note":       "apply pipeline not yet implemented — use CLI for now",
        })),
        Err(e) => err(&e.to_string(), 400),
    }
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

/// Start the API server on the given port. Blocks until `stop` is set.
/// Typically called on a background thread.
pub fn run_server(port: u16, stop: Arc<AtomicBool>) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
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

/// Spawn the API server on a background thread. Returns the stop flag.
pub fn spawn(port: u16) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    std::thread::spawn(move || {
        if let Err(e) = run_server(port, stop2) {
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
