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
///   GET  /api/v1/salts
///   POST /api/v1/fs/check-data-folder
///   GET  /api/v1/mods
///   GET  /api/v1/mod-template
///   GET  /api/v1/mabi-version
///   POST /api/v1/extract/stream  (SSE progress stream)
///   POST /api/v1/launcher/login               { email, password }  → session | mfa_required | captcha_required
///   POST /api/v1/launcher/login/otp           { mfa_key, otp }
///   POST /api/v1/launcher/login/tpa           { tpa_session }      (browser/SSO cookie exchange)
///   POST /api/v1/launcher/autologin           { session_token }
///   POST /api/v1/launcher/session/check       { session }          (refreshes on 401)
///   POST /api/v1/launcher/passport            { session }
///   POST /api/v1/launcher/maintenance         { session }
///   POST /api/v1/launcher/version             { session }
///   POST /api/v1/launcher/update/check        { game_path, session? }
///   POST /api/v1/launcher/update              { game_path, mode: update|verify|force_all, max_workers?, ignore? }
///   GET  /api/v1/launcher/update/status
///   POST /api/v1/launcher/update/cancel
///   POST /api/v1/launcher/update/pause
///   POST /api/v1/launcher/update/resume
///   POST /api/v1/launcher/update/scan         { game_path, mode?, ignore?, only?, session? }
///   POST /api/v1/launcher/folders/check       { folders[] | all_folders, session? }
///   GET  /api/v1/launcher/config              (shared hooks + ignore list)
///   POST /api/v1/launcher/config              { ignore?, hooks? }
///   POST /api/v1/launcher/import/cookies      { profile? }  (Firefox/Chrome/Edge/Brave)
///   GET  /api/v1/launcher/news                (?product_id=)
///   GET  /api/v1/launcher/profiles
///   POST /api/v1/launcher/profile/save
///   POST /api/v1/launcher/profile/delete
///   POST /api/v1/launcher/profile/activate
///   POST /api/v1/launcher/profile/load
///   POST /api/v1/launcher/profile/session
///   POST /api/v1/launcher/launch              { session, client_exe | client_dir }  (Windows/Wine)
///   POST /api/v1/mod/vfs/apply
///   POST /api/v1/mod/pending/save
///   GET  /api/v1/mod/pending
///   GET  /api/v1/mod-file      (raw .mod file text, for apply_mod's mod_toml param)
///   POST /api/v1/features/get
///   POST /api/v1/features/save
///   POST /api/v1/patch/create
///   POST /api/v1/preview       (image/text/mml/pmg/rgn/area/set/audio/binary)
///   POST /api/v1/convert       (DDS<->PNG etc, matches the `convert` CLI subcommand)
///   POST /api/v1/pmg/export    (PMG -> OBJ, matches the pmg_export CLI tool)
///
/// Auth: loopback (127.0.0.1) binds need no token but only accept a loopback
/// Host/Origin on the bound port (DNS-rebinding guard). Binding to any other
/// host (e.g. "0.0.0.0" for Docker/LAN) requires `MABI_API_TOKEN` to be set;
/// requests must then send `Authorization: Bearer <token>`. See `run_server`.
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
        Header::from_bytes("Access-Control-Allow-Headers", "Content-Type, Authorization").unwrap(),
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

fn handle_status(port: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    ok(json!({
        "app":     "mabi-patcher",
        "version": env!("CARGO_PKG_VERSION"),
        "api":     "v1",
        "port":    port,
    }))
}

fn handle_salts() -> Response<std::io::Cursor<Vec<u8>>> {
    ok(json!(crate::load_salts()))
}

/// Mirrors the Tauri `check_data_folder` command: does `path` contain (or is
/// it named) a `data` subfolder? Used by the Pack tab to decide whether to
/// offer wrapping the archive under a virtual `data/` root.
fn handle_check_data_folder(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let path = match body["path"].as_str() { Some(s) => s, None => return err("'path' is required", 400) };
    let p = std::path::Path::new(path);

    let is_data_itself = p.file_name()
        .map(|n| n.to_string_lossy().to_lowercase() == "data")
        .unwrap_or(false);
    let has_data_child = std::fs::read_dir(p).ok().map(|entries| {
        entries.filter_map(|e| e.ok()).any(|e| {
            e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && e.file_name().to_string_lossy().to_lowercase() == "data"
        })
    }).unwrap_or(false);

    ok(json!({ "has_data_folder": is_data_itself || has_data_child }))
}

fn handle_mabi_version() -> Response<std::io::Cursor<Vec<u8>>> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let paths = [
            "SOFTWARE\\WOW6432Node\\Nexon\\Mabinogi",
            "SOFTWARE\\Nexon\\Mabinogi",
        ];
        for path in &paths {
            if let Ok(key) = hklm.open_subkey(path) {
                let installed: String = key.get_value("Version").unwrap_or_default();
                let client_dir: String = key.get_value("ExePath")
                    .or_else(|_| key.get_value("InstallLocation"))
                    .unwrap_or_default();
                if !installed.is_empty() {
                    return ok(json!({
                        "installed_version": installed,
                        "client_dir": client_dir,
                        "registry_key": path,
                    }));
                }
            }
        }
        err("Mabinogi registry key not found", 404)
    }
    #[cfg(not(target_os = "windows"))]
    err("mabi-version only available on Windows", 501)
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

    // Legacy .pack (unencrypted PACK/MABI header) uses a completely different
    // writer than the modern .it format — mirrors create_archive's branch in
    // gui/src-tauri/src/lib.rs, which is the only other caller of these two
    // functions in the whole codebase.
    if output.to_lowercase().ends_with(".pack") {
        let version = body["pack_v1_version"].as_u64().map(|v| v as u32).unwrap_or(999);
        return match crate::pack_v1::run_pack_v1(&source, &output, version) {
            Ok(_)  => ok(json!({ "source": source, "output": output, "format": "pack_v1" })),
            Err(e) => err(&e.to_string(), 500),
        };
    }

    let formats: Vec<String> = body["formats"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let fmts: Vec<&str> = formats.iter().map(|s| s.as_str()).collect();
    let auto_dds = body["auto_convert_dds"].as_bool().unwrap_or(false);
    let iv = body["iv"].as_u64().unwrap_or(0) as u32;
    // `path_prefix` takes precedence; `wrap_data: true` is shorthand for `path_prefix: "data"`.
    let wrap_data = body["wrap_data"].as_bool().unwrap_or(false);
    let prefix = body["path_prefix"].as_str()
        .map(String::from)
        .or_else(|| if wrap_data { Some("data".to_string()) } else { None });

    match crate::pack::run_pack(&source, &output, &key, fmts, auto_dds, iv, prefix.as_deref(), None) {
        Ok(_)  => ok(json!({ "source": source, "output": output, "format": "it" })),
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
        let dest = crate::common::safe_join(&tmp_dir, &rel)?;

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

    // 2b. Apply feature flag toggles if any are specified
    let has_feat_changes = pkg.features.enable.as_ref().map_or(false, |v| !v.is_empty())
        || pkg.features.disable.as_ref().map_or(false, |v| !v.is_empty());
    if has_feat_changes {
        // Find features.xml.compiled in the temp tree
        let feat_path = walkdir::WalkDir::new(&tmp_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("features.xml.compiled"))
            .map(|e| e.path().to_path_buf());

        if let Some(fp) = feat_path {
            let raw = std::fs::read(&fp)?;
            if let Some(mut fd) = crate::common_ext::parse_features_compiled(&raw) {
                let parse_hash = |s: &str| -> Option<u32> {
                    u32::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
                };
                if let Some(enables) = &pkg.features.enable {
                    for hex in enables {
                        if let Some(h) = parse_hash(hex) {
                            if let Some(feat) = fd.features.iter_mut().find(|f| f.hash == h) {
                                feat.conditions.retain(|c| !c.is_empty());
                            }
                        }
                    }
                }
                if let Some(disables) = &pkg.features.disable {
                    for hex in disables {
                        if let Some(h) = parse_hash(hex) {
                            if let Some(feat) = fd.features.iter_mut().find(|f| f.hash == h) {
                                feat.conditions = vec!["FALSE".to_string()];
                            }
                        }
                    }
                }
                let encoded = crate::common_ext::encode_features_compiled(&fd);
                std::fs::write(&fp, encoded)?;
                stats.patched += 1;
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

/// The local mods folder: `mods/` next to the exe, else `mods/` in the cwd.
fn mods_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("mods")))
        .unwrap_or_else(|| std::path::Path::new("mods").to_path_buf())
}

/// Resolve a mod-file request path (a name relative to `mods_dir`, or a full
/// path) and refuse anything that doesn't resolve to a file inside `mods_dir`.
fn resolve_mod_file(mods: &std::path::Path, path: &str) -> Result<std::path::PathBuf, String> {
    let candidate = if std::path::Path::new(path).is_absolute() {
        std::path::PathBuf::from(path)
    } else {
        crate::common::safe_join(mods, path).map_err(|e| e.to_string())?
    };
    let root = mods.canonicalize().map_err(|e| format!("mods folder {}: {}", mods.display(), e))?;
    let full = candidate.canonicalize().map_err(|e| format!("{}: {}", path, e))?;
    if !full.starts_with(&root) || !full.is_file() {
        return Err(format!("'{}' is not a file in the mods folder", path));
    }
    Ok(full)
}

fn handle_list_mods() -> Response<std::io::Cursor<Vec<u8>>> {
    let dir = mods_dir();

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

/// Decode `%XX` escapes in a query-string value. Decodes to
/// bytes first so multi-byte UTF-8 sequences (`%C3%A9`) come out intact.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 { return Err(()); }
    (0..s.len()).step_by(2).map(|i| {
        u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ())
    }).collect()
}

// ---- launcher handlers ------------------------------------------------------
// Launcher routes: login, profiles, patching and launch over loopback HTTP.

type Resp = Response<std::io::Cursor<Vec<u8>>>;

/// Map launcher errors to responses; MFA/CAPTCHA are reported as data, not failures.
fn auth_err(e: anyhow::Error) -> Resp {
    use crate::launcher::auth::AuthError;
    match e.downcast_ref::<AuthError>() {
        Some(AuthError::MfaRequired { mfa_key, mfa_type }) => {
            ok(json!({ "mfa_required": true, "mfa_key": mfa_key, "mfa_type": mfa_type }))
        }
        Some(AuthError::CaptchaRequired(code)) => {
            ok(json!({ "captcha_required": true, "code": code, "message": e.to_string() }))
        }
        Some(AuthError::SessionExpired(_)) => err(&e.to_string(), 401),
        Some(AuthError::NotPlayable(_)) => err(&e.to_string(), 503),
        Some(AuthError::DeviceTrustRequired) => err(&e.to_string(), 403),
        _ => err(&e.to_string(), 500),
    }
}

fn login_ok(result: crate::launcher::auth::LoginResult) -> Resp {
    ok(json!({ "session": result.session, "expiresIn": result.session_expires_in }))
}

fn device_id_from(body: &Value) -> String {
    body["device_id"].as_str().map(String::from)
        .unwrap_or_else(|| crate::launcher::auth::device_id(body["profile"].as_str().unwrap_or("")))
}

fn handle_launcher_login(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let email = match body["email"].as_str().or(body["username"].as_str()) { Some(s) => s, None => return err("'email' is required", 400) };
    let password = match body["password"].as_str() { Some(s) => s, None => return err("'password' is required", 400) };
    match crate::launcher::auth::login(email, password, &device_id_from(&body)) {
        Ok(r) => login_ok(r),
        Err(e) => auth_err(e),
    }
}

fn handle_launcher_login_otp(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let key = match body["mfa_key"].as_str() { Some(s) => s, None => return err("'mfa_key' is required", 400) };
    let otp = match body["otp"].as_str() { Some(s) => s, None => return err("'otp' is required", 400) };
    match crate::launcher::auth::login_otp(key, otp, &device_id_from(&body)) {
        Ok(r) => login_ok(r),
        Err(e) => auth_err(e),
    }
}

fn handle_launcher_login_tpa(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let tpa = match body["tpa_session"].as_str() { Some(s) => s, None => return err("'tpa_session' is required", 400) };
    match crate::launcher::auth::exchange_tpa(tpa, &device_id_from(&body)) {
        Ok(r) => login_ok(r),
        Err(e) => auth_err(e),
    }
}

fn handle_launcher_autologin(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session_token = match body["session_token"].as_str() { Some(s) => s, None => return err("'session_token' is required", 400) };
    match crate::launcher::auth::autologin(session_token) {
        Ok(r) => login_ok(r),
        Err(e) => auth_err(e),
    }
}

fn parse_session(body: &Value) -> Result<crate::launcher::auth::NexonSession, Resp> {
    serde_json::from_value(body["session"].clone())
        .map_err(|e| err(&format!("'session' is invalid: {}", e), 400))
}

fn handle_launcher_session_check(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let mut session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    let mut status = match crate::launcher::auth::check_session(&mut session) { Ok(s) => s, Err(e) => return auth_err(e) };
    let mut refreshed = false;
    if status == 401 && crate::launcher::auth::refresh(&mut session).is_ok() {
        refreshed = true;
        status = crate::launcher::auth::check_session(&mut session).unwrap_or(status);
    }
    ok(json!({ "valid": status == 200, "status": status, "refreshed": refreshed, "session": session }))
}

fn handle_launcher_passport(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let mut session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    match crate::launcher::auth::prepare_launch(&mut session) {
        Ok(passport) => ok(json!({ "passport": passport, "session": session })),
        Err(e) => auth_err(e),
    }
}

fn handle_launcher_maintenance(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    match crate::launcher::patch::is_maintenance(&session) {
        Ok(maintenance) => ok(json!({ "maintenance": maintenance })),
        Err(e) => auth_err(e),
    }
}

fn handle_launcher_version(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let mut session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    match crate::launcher::patch::fetch_manifest(&mut session) {
        Ok(info) => ok(json!({ "version": info.version, "manifest_url": info.manifest_url, "session": session })),
        Err(e) => auth_err(e),
    }
}

fn handle_launcher_update_check(req: &mut Request) -> Resp {
    use crate::launcher::patch;
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let game_path = match body["game_path"].as_str() { Some(s) => s, None => return err("'game_path' is required", 400) };
    if let Some(pid) = body["product_id"].as_u64() { crate::launcher::auth::set_product_id(pid as u32); }
    let mut session = parse_session(&body).ok();
    let roots = patch::GameRoots::resolve(game_path);
    match patch::check_update(&roots, session.as_mut()) {
        Ok(c) => ok(json!({ "check": c, "roots": roots, "session": session })),
        Err(e) => auth_err(e),
    }
}

/// Background patch job state (one at a time), polled via /launcher/update/status.
#[derive(Default, Serialize, Clone)]
struct PatchJob {
    running: bool,
    log: Vec<String>,
    files_done: usize,
    files_total: usize,
    bytes: u64,
    bytes_total: u64,
    speed_bps: u64,
    scan_done: usize,
    scan_total: usize,
    result: Option<crate::launcher::patch::PatchResult>,
    error: Option<String>,
    /// The session after the job (refreshed if a 401 forced an autologin).
    session: Option<crate::launcher::auth::NexonSession>,
}

static PATCH_JOB: once_cell::sync::Lazy<std::sync::Mutex<PatchJob>> = once_cell::sync::Lazy::new(Default::default);
static PATCH_CANCEL: once_cell::sync::Lazy<std::sync::Mutex<Arc<AtomicBool>>> = once_cell::sync::Lazy::new(Default::default);
static PATCH_PAUSE: once_cell::sync::Lazy<std::sync::Mutex<Arc<AtomicBool>>> = once_cell::sync::Lazy::new(Default::default);

fn handle_launcher_update(req: &mut Request) -> Resp {
    use crate::launcher::patch::{self, PatchEvent, PatchMode, PatchOptions};
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let game_path = match body["game_path"].as_str() { Some(s) => s.to_string(), None => return err("'game_path' is required", 400) };
    if let Some(pid) = body["product_id"].as_u64() { crate::launcher::auth::set_product_id(pid as u32); }
    let mode = match body["mode"].as_str().unwrap_or("update") {
        "verify" => PatchMode::Verify,
        "force_all" | "force" => PatchMode::ForceAll,
        _ => PatchMode::Update,
    };
    {
        let mut job = PATCH_JOB.lock().unwrap();
        if job.running { return err("a patch job is already running", 409); }
        *job = PatchJob { running: true, ..Default::default() };
    }
    let cancel = Arc::new(AtomicBool::new(false));
    *PATCH_CANCEL.lock().unwrap() = cancel.clone();
    let pause = Arc::new(AtomicBool::new(false));
    *PATCH_PAUSE.lock().unwrap() = pause.clone();
    // Run the before/after-patch hooks around a real (non-scan) patch, from the
    // shared config — the GUI runs its own hooks, so run_patcher never does.
    let run_hooks = !body["scan_only"].as_bool().unwrap_or(false);
    let profile_name = body["profile"].as_str().unwrap_or("").to_string();
    let opts = PatchOptions {
        mode,
        max_workers: (body["max_workers"].as_u64().unwrap_or(8) as usize).clamp(1, patch::MAX_WORKERS),
        ignore: body["ignore"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        scan_only: body["scan_only"].as_bool().unwrap_or(false),
        manifest_hash: None,
        cancel,
        only: body["only"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>()),
        pause: pause.clone(),
    };
    let session = parse_session(&body).ok();
    std::thread::spawn(move || {
        // A panic anywhere in the job must not leave PATCH_JOB "running"
        // forever (that would 409 every later /launcher/update).
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let roots = patch::GameRoots::resolve(&game_path);
            let cfg = crate::launcher::config::Config::load().unwrap_or_default();
            if run_hooks {
                crate::launcher::launch::spawn_hook(&cfg.hooks.before_patch, &profile_name, &roots.install_root);
            }
            let on_event = |ev: PatchEvent| {
                let mut job = PATCH_JOB.lock().unwrap();
                match ev {
                    PatchEvent::Log { message } => { job.log.push(message); }
                    PatchEvent::Scan { done, total, .. } => { job.scan_done = done; job.scan_total = total; }
                    PatchEvent::Download { files_done, files_total, bytes, bytes_total, speed_bps, .. } => {
                        job.files_done = files_done; job.files_total = files_total;
                        job.bytes = bytes; job.bytes_total = bytes_total; job.speed_bps = speed_bps;
                    }
                    PatchEvent::Worker { .. } => {}
                }
            };
            let mut session = session;
            let res = patch::run_patcher(&roots, session.as_mut(), &opts, &on_event);
            if run_hooks {
                if let Ok(r) = &res {
                    if r.errors.is_empty() && !r.cancelled {
                        crate::launcher::launch::spawn_hook(&cfg.hooks.after_patch, &profile_name, &roots.install_root);
                    }
                }
            }
            (session, res)
        }));
        let mut job = PATCH_JOB.lock().unwrap_or_else(|e| e.into_inner());
        PATCH_JOB.clear_poison();
        job.running = false;
        match outcome {
            Ok((session, res)) => {
                job.session = session;
                match res {
                    Ok(r) => { job.files_total = job.files_total.max(r.need.len()); job.result = Some(r); }
                    Err(e) => job.error = Some(e.to_string()),
                }
            }
            Err(_) => job.error = Some("patch job crashed unexpectedly".to_string()),
        }
    });
    ok(json!({ "started": true }))
}

fn handle_launcher_update_pause() -> Resp {
    PATCH_PAUSE.lock().unwrap().store(true, Ordering::Relaxed);
    ok(json!({ "paused": PATCH_JOB.lock().unwrap().running }))
}

fn handle_launcher_update_resume() -> Resp {
    PATCH_PAUSE.lock().unwrap().store(false, Ordering::Relaxed);
    ok(json!({ "resumed": PATCH_JOB.lock().unwrap().running }))
}

/// Scan an install (no download): list files that need updating with status + size.
fn handle_launcher_update_scan(req: &mut Request) -> Resp {
    use crate::launcher::patch::{self, PatchMode, PatchOptions};
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let game_path = match body["game_path"].as_str() { Some(s) => s, None => return err("'game_path' is required", 400) };
    if let Some(pid) = body["product_id"].as_u64() { crate::launcher::auth::set_product_id(pid as u32); }
    let mode = match body["mode"].as_str().unwrap_or("update") {
        "verify" => PatchMode::Verify,
        "force_all" | "force" => PatchMode::ForceAll,
        _ => PatchMode::Update,
    };
    let mut session = parse_session(&body).ok();
    let roots = patch::GameRoots::resolve(game_path);
    let opts = PatchOptions {
        mode,
        ignore: body["ignore"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        only: body["only"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>()),
        ..Default::default()
    };
    match patch::scan(&roots, session.as_mut(), &opts) {
        Ok(need) => ok(json!({ "roots": roots, "need": need, "session": session })),
        Err(e) => auth_err(e),
    }
}

/// Check several game folders against the current manifest (multi-install).
fn handle_launcher_folders_check(req: &mut Request) -> Resp {
    use crate::launcher::patch;
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    if let Some(pid) = body["product_id"].as_u64() { crate::launcher::auth::set_product_id(pid as u32); }
    let mut folders: Vec<std::path::PathBuf> = body["folders"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(std::path::PathBuf::from)).collect())
        .unwrap_or_default();
    if body["all_folders"].as_bool().unwrap_or(false) {
        for exe in crate::launcher::detect::find_all_game_exes() {
            folders.push(exe);
        }
    }
    if folders.is_empty() { return err("'folders' (array) or 'all_folders': true is required", 400); }
    let mut session = parse_session(&body).ok();
    let statuses = patch::check_folders(&folders, session.as_mut());
    ok(json!({ "folders": statuses, "session": session }))
}

fn handle_launcher_update_status() -> Resp {
    let job = PATCH_JOB.lock().unwrap().clone();
    ok(serde_json::to_value(job).unwrap_or_default())
}

fn handle_launcher_update_cancel() -> Resp {
    PATCH_CANCEL.lock().unwrap().store(true, Ordering::Relaxed);
    ok(json!({ "cancelling": PATCH_JOB.lock().unwrap().running }))
}

fn handle_launcher_profiles_list() -> Resp {
    match crate::launcher::profile::list_profiles() {
        Ok(summaries) => ok(json!({ "profiles": summaries })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_launcher_profile_save(req: &mut Request) -> Resp {
    use crate::launcher::profile::{Profile, ProfileStore};

    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let name = match body["name"].as_str() { Some(s) => s, None => return err("'name' is required", 400) };
    let email = match body["email"].as_str() { Some(s) => s, None => return err("'email' is required", 400) };
    let client_dir = body["client_dir"].as_str().unwrap_or("").to_string();
    let auto_login = body["auto_login"].as_bool().unwrap_or(false);
    let id = body["id"].as_str().map(String::from);

    let mut store = match ProfileStore::load() { Ok(s) => s, Err(e) => return err(&e.to_string(), 500) };
    let mut profile = match &id {
        Some(existing_id) => store.get(existing_id).cloned().unwrap_or_else(|| Profile::new(name, email)),
        None => Profile::new(name, email),
    };
    profile.name = name.to_string();
    profile.email = email.to_string();
    profile.client_dir = client_dir;
    profile.auto_login = auto_login;
    let profile_id = profile.id.clone();
    store.upsert(profile);
    match store.save() {
        Ok(_) => ok(json!({ "id": profile_id })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_launcher_profile_delete(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    match crate::launcher::profile::delete_profile(id) {
        Ok(deleted) => ok(json!({ "deleted": deleted })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_launcher_profile_activate(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    match crate::launcher::profile::set_active_profile(id) {
        Ok(_) => ok(json!({ "activated": id })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_launcher_profile_load(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    let profile = match crate::launcher::profile::load_profile(id) { Ok(p) => p, Err(e) => return err(&e.to_string(), 404) };
    let summary = crate::launcher::profile::ProfileSummary::from(&profile);
    let mut val = match serde_json::to_value(&summary) { Ok(v) => v, Err(e) => return err(&e.to_string(), 500) };
    if profile.auto_login && profile.is_session_valid() {
        val["session_token_for_autologin"] = Value::String(profile.session_token.clone());
    }
    ok(val)
}

fn handle_launcher_profile_session(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    let session_token = match body["session_token"].as_str() { Some(s) => s, None => return err("'session_token' is required", 400) };
    let expires_in = body["expires_in"].as_i64().unwrap_or(0) as i32;
    match crate::launcher::profile::update_session(id, session_token, expires_in) {
        Ok(_) => ok(json!({ "updated": true })),
        Err(e) => err(&e.to_string(), 500),
    }
}

/// Official launch: body { session, client_dir | client_exe | game_path }.
fn handle_launcher_launch(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    if let Some(pid) = body["product_id"].as_u64() { crate::launcher::auth::set_product_id(pid as u32); }
    let mut session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    let path = match body["client_exe"].as_str().or(body["client_dir"].as_str()).or(body["game_path"].as_str()) {
        Some(s) => s, None => return err("'client_exe' or 'client_dir' is required", 400),
    };
    let exe = crate::launcher::patch::GameRoots::resolve(path).client_exe();
    match crate::launcher::launch::launch_official(&mut session, &exe, false) {
        Ok(info) => ok(json!({
            "pid": info.pid,
            "executable": info.executable,
            "argumentCount": info.argument_count,
            "patchAvailable": info.patch_available,
            "sessionExpiresIn": info.session_expires_in,
            "session": session,
        })),
        Err(e) => auth_err(e),
    }
}

// ---- shared config (hooks + ignore list) -------------------------------------

/// Get the shared patcher config (the 4 hooks + the ignore list). Same store the
/// CLI uses, so the GUI and CLI share one set of hooks/ignores.
fn handle_launcher_config_get() -> Resp {
    match crate::launcher::config::Config::load() {
        Ok(cfg) => ok(serde_json::to_value(&cfg).unwrap_or_default()),
        Err(e) => err(&e.to_string(), 500),
    }
}

/// Replace the shared config. Body: `{ ignore: [...], hooks: { before_patch, after_patch, before_launch, after_launch } }`.
/// Any field omitted keeps the current value.
fn handle_launcher_config_set(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let mut cfg = match crate::launcher::config::Config::load() { Ok(c) => c, Err(e) => return err(&e.to_string(), 500) };
    if let Some(arr) = body["ignore"].as_array() {
        cfg.ignore = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
    }
    let hooks = &body["hooks"];
    for (key, slot) in [
        ("before_patch", &mut cfg.hooks.before_patch),
        ("after_patch", &mut cfg.hooks.after_patch),
        ("before_launch", &mut cfg.hooks.before_launch),
        ("after_launch", &mut cfg.hooks.after_launch),
    ] {
        if let Some(v) = hooks.get(key).and_then(Value::as_str) {
            *slot = v.to_string();
        }
    }
    match cfg.save() {
        Ok(_) => ok(serde_json::to_value(&cfg).unwrap_or_default()),
        Err(e) => err(&e.to_string(), 500),
    }
}

/// Import a Nexon session from the user's browsers (Firefox/Chrome/Edge/Brave).
/// Reports `v20_found` when Chrome 127+ app-bound cookies block decryption.
fn handle_launcher_import_cookies(req: &mut Request) -> Resp {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let dev = device_id_from(&body);
    match crate::launcher::cookies::import_from_browsers(&dev) {
        Ok(imp) => {
            let imported = imp.session.is_some();
            ok(json!({
                "session": imp.session,
                "browser": imp.browser,
                "v20_found": imp.v20_found,
                "notes": imp.notes,
                "imported": imported,
            }))
        }
        Err(e) => err(&e.to_string(), 500),
    }
}

/// Nexon Mabinogi news feed (title, url, date, image). Public; no session.
fn handle_launcher_news(req: &mut Request) -> Resp {
    let url = req.url().to_string();
    if let Some(pid) = url.split('?').nth(1)
        .and_then(|qs| qs.split('&').find(|p| p.starts_with("product_id=")))
        .and_then(|p| p[11..].parse::<u32>().ok())
    {
        crate::launcher::auth::set_product_id(pid);
    }
    match crate::launcher::news::fetch_news() {
        Ok(items) => ok(json!({ "items": items })),
        Err(e) => err(&e.to_string(), 502),
    }
}

// ---- mod VFS / pending-changes handlers --------------------------------------

/// VFS change descriptor — one op per file operation. Mirrors the Tauri-side
/// `VfsChange` enum in gui/src-tauri/src/lib.rs (kept independent on purpose,
/// same convention as handle_mod_apply vs. GUI apply_mod).
#[derive(Deserialize, Debug)]
#[serde(tag = "op", rename_all = "lowercase")]
enum VfsChange {
    Delete { path: String },
    Rename { from: String, to: String },
    Add { dest: String, local_src: String },
    Merge { src_archive: String, src_key: Option<String> },
}

fn handle_mod_vfs_apply(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    use std::path::Path;

    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() { Some(s) => s.to_string(), None => return err("'archive' is required", 400) };
    let key = body["key"].as_str().map(String::from);
    let changes: Vec<VfsChange> = match serde_json::from_value(body["changes"].clone()) {
        Ok(c) => c,
        Err(e) => return err(&format!("'changes' is invalid: {}", e), 400),
    };

    let salts = crate::load_salts();
    let tmp_dir = std::env::temp_dir().join(format!("mabi_api_vfs_{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) { return err(&e.to_string(), 500); }
    let tmp_str = tmp_dir.to_string_lossy().to_string();

    let salt_used = match crate::extract::run_extract_with_key_search(
        &archive, &tmp_str, key.clone(), &salts, vec![], None, false, false, false, None,
    ) {
        Ok(s) => s,
        Err(e) => { let _ = std::fs::remove_dir_all(&tmp_dir); return err(&e.to_string(), 500); }
    };

    let mut stats = json!({ "deleted": 0, "renamed": 0, "added": 0, "merged": 0 });
    // Resolve an edit path inside the extracted tree; rejects `..`, absolute and
    // drive paths, and names the game can't load (see validate_entry_path).
    let target = |p: &str| -> anyhow::Result<std::path::PathBuf> {
        crate::common::validate_entry_path(p)?;
        crate::common::safe_join(&tmp_dir, p)
    };

    for change in &changes {
        let result: anyhow::Result<()> = (|| {
            match change {
                VfsChange::Delete { path } => {
                    let target = target(path)?;
                    if target.exists() {
                        std::fs::remove_file(&target)?;
                        stats["deleted"] = (stats["deleted"].as_i64().unwrap_or(0) + 1).into();
                    }
                }
                VfsChange::Rename { from, to } => {
                    let src = target(from)?;
                    let dst = target(to)?;
                    if let Some(p) = dst.parent() { std::fs::create_dir_all(p)?; }
                    if src.exists() {
                        std::fs::rename(&src, &dst)?;
                        stats["renamed"] = (stats["renamed"].as_i64().unwrap_or(0) + 1).into();
                    }
                }
                VfsChange::Add { dest, local_src } => {
                    let dst = target(dest)?;
                    if let Some(p) = dst.parent() { std::fs::create_dir_all(p)?; }
                    std::fs::copy(Path::new(local_src), &dst)?;
                    stats["added"] = (stats["added"].as_i64().unwrap_or(0) + 1).into();
                }
                VfsChange::Merge { src_archive, src_key } => {
                    let merge_tmp = std::env::temp_dir().join(format!("mabi_api_vfs_merge_{}", std::process::id()));
                    std::fs::create_dir_all(&merge_tmp)?;
                    let merge_str = merge_tmp.to_string_lossy().to_string();
                    crate::extract::run_extract_with_key_search(
                        src_archive, &merge_str, src_key.clone(), &salts, vec![], None, false, false, false, None,
                    )?;
                    let mut count = 0i64;
                    for entry in walkdir::WalkDir::new(&merge_tmp).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            let rel = entry.path().strip_prefix(&merge_tmp).unwrap();
                            let dst = tmp_dir.join(rel);
                            if let Some(p) = dst.parent() { std::fs::create_dir_all(p)?; }
                            std::fs::copy(entry.path(), &dst)?;
                            count += 1;
                        }
                    }
                    let _ = std::fs::remove_dir_all(&merge_tmp);
                    stats["merged"] = (stats["merged"].as_i64().unwrap_or(0) + count).into();
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return err(&e.to_string(), 500);
        }
    }

    let key_str = key.as_deref().unwrap_or(&salt_used);
    let archive_name = Path::new(&archive).file_name().and_then(|n| n.to_str()).unwrap_or("");
    let prefix = if archive_name.to_lowercase().ends_with(".pack") { Some("data") } else { None };
    let pack_result = crate::pack::run_pack(&tmp_str, &archive, key_str, vec![], false, 0, prefix, None);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    match pack_result {
        Ok(_) => ok(json!({ "archive": archive, "changes": changes.len(), "stats": stats })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_mod_pending_save(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() { Some(s) => s, None => return err("'archive' is required", 400) };
    let changes = body["changes"].as_array().cloned().unwrap_or_default();
    let pending_path = format!("{}.pending.json", archive);

    let result = if changes.is_empty() {
        if std::path::Path::new(&pending_path).exists() {
            std::fs::remove_file(&pending_path)
        } else {
            Ok(())
        }
    } else {
        serde_json::to_string_pretty(&changes)
            .map_err(std::io::Error::other)
            .and_then(|json| std::fs::write(&pending_path, json))
    };

    match result {
        Ok(_) => ok(json!({ "archive": archive, "count": changes.len() })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_mod_pending_load(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let url = req.url().to_string();
    let archive = match url.split('?').nth(1)
        .and_then(|qs| qs.split('&').find(|p| p.starts_with("archive=")))
        .map(|p| percent_decode(&p[8..]))
    {
        Some(a) => a,
        None => return err("'archive' query param is required", 400),
    };
    let pending_path = format!("{}.pending.json", archive);
    if !std::path::Path::new(&pending_path).exists() {
        return ok(json!({ "archive": archive, "changes": [] }));
    }
    match std::fs::read_to_string(&pending_path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(changes) => ok(json!({ "archive": archive, "changes": changes })),
            Err(e) => err(&format!("corrupt pending changes file: {}", e), 500),
        },
        Err(e) => err(&e.to_string(), 500),
    }
}

/// Read a .mod file's raw TOML text by path — mirrors the (now-fixed) Tauri
/// `load_mod_file` command. Callers pass this straight to apply_mod's
/// mod_toml param, so this must return the raw file content, not JSON.
fn handle_mod_file_read(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let url = req.url().to_string();
    let path = match url.split('?').nth(1)
        .and_then(|qs| qs.split('&').find(|p| p.starts_with("path=")))
        .map(|p| percent_decode(&p[5..]))
    {
        Some(p) => p,
        None => return err("'path' query param is required", 400),
    };
    let full = match resolve_mod_file(&mods_dir(), &path) {
        Ok(p) => p,
        Err(e) => return err(&e, 403),
    };
    match std::fs::read_to_string(&full) {
        Ok(content) => ok(json!({ "path": path, "content": content })),
        Err(e) => err(&e.to_string(), 500),
    }
}

// ---- features.xml handlers ---------------------------------------------------

fn handle_features_get(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    use walkdir::WalkDir;

    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() { Some(s) => s.to_string(), None => return err("'archive' is required", 400) };
    let key = body["key"].as_str().map(String::from);
    let salts = crate::load_salts();

    let tmp_dir = std::env::temp_dir().join(format!("mabi_api_feat_get_{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) { return err(&e.to_string(), 500); }
    let tmp_str = tmp_dir.to_string_lossy().to_string();

    if let Err(e) = crate::extract::run_extract_with_key_search(
        &archive, &tmp_str, key, &salts,
        vec!["features.xml.compiled".to_string()], None, false, false, false, None,
    ) {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return err(&e.to_string(), 500);
    }

    let feat_path = WalkDir::new(&tmp_dir).into_iter().filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().to_lowercase() == "features.xml.compiled")
        .map(|e| e.into_path());

    let data = match feat_path {
        Some(p) => match std::fs::read(&p) { Ok(d) => d, Err(e) => { let _ = std::fs::remove_dir_all(&tmp_dir); return err(&e.to_string(), 500); } },
        None => { let _ = std::fs::remove_dir_all(&tmp_dir); return err("features.xml.compiled not found in archive", 404); }
    };
    let _ = std::fs::remove_dir_all(&tmp_dir);

    match crate::common_ext::parse_features_compiled(&data) {
        Some(parsed) => match serde_json::to_value(&parsed) {
            Ok(v) => ok(v),
            Err(e) => err(&e.to_string(), 500),
        },
        None => err("failed to parse features.xml.compiled binary format", 500),
    }
}

fn handle_features_save(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() { Some(s) => s.to_string(), None => return err("'archive' is required", 400) };
    let key = body["key"].as_str().map(String::from);
    let features_json = match body["features_json"].as_str() { Some(s) => s, None => return err("'features_json' is required", 400) };

    let features_data: crate::common_ext::FeaturesData = match serde_json::from_str(features_json) {
        Ok(f) => f,
        Err(e) => return err(&format!("invalid features_json: {}", e), 400),
    };
    let binary = crate::common_ext::encode_features_compiled(&features_data);

    let salts = crate::load_salts();
    let tmp_dir = std::env::temp_dir().join(format!("mabi_api_feat_save_{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) { return err(&e.to_string(), 500); }
    let tmp_str = tmp_dir.to_string_lossy().to_string();

    let salt_used = match crate::extract::run_extract_with_key_search(
        &archive, &tmp_str, key.clone(), &salts, vec![], None, false, false, false, None,
    ) {
        Ok(s) => s,
        Err(e) => { let _ = std::fs::remove_dir_all(&tmp_dir); return err(&e.to_string(), 500); }
    };

    let candidates = [
        tmp_dir.join("data").join("xml").join("features.xml.compiled"),
        tmp_dir.join("xml").join("features.xml.compiled"),
        tmp_dir.join("features.xml.compiled"),
    ];
    let dest = match candidates.iter().find(|p| p.exists()) {
        Some(p) => p,
        None => { let _ = std::fs::remove_dir_all(&tmp_dir); return err("could not find features.xml.compiled in extracted data", 500); }
    };
    if let Err(e) = std::fs::write(dest, &binary) {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return err(&e.to_string(), 500);
    }

    let key_str = key.as_deref().unwrap_or(&salt_used);
    let is_pack = archive.to_lowercase().ends_with(".pack");
    let prefix = if is_pack { Some("data") } else { None };
    let pack_result = crate::pack::run_pack(&tmp_str, &archive, key_str, vec![], false, 0, prefix, None);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    match pack_result {
        Ok(_) => ok(json!({
            "archive": archive,
            "features": features_data.features.len(),
            "servers": features_data.servers.len(),
            "bytes": binary.len(),
            "status": "saved",
        })),
        Err(e) => err(&e.to_string(), 500),
    }
}

// ---- diff / patch handler -----------------------------------------------------

fn handle_patch_create(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let base_dir = match body["base_dir"].as_str() { Some(s) => s, None => return err("'base_dir' is required", 400) };
    let modified_dir = match body["modified_dir"].as_str() { Some(s) => s, None => return err("'modified_dir' is required", 400) };
    let output = match body["output"].as_str() { Some(s) => s, None => return err("'output' is required", 400) };
    let key = match body["key"].as_str() { Some(s) => s, None => return err("'key' is required", 400) };
    let iv = body["iv"].as_u64().unwrap_or(0) as u32;

    match crate::patch::create_patch(base_dir, modified_dir, output, key, iv) {
        Ok(_) => ok(json!({ "base_dir": base_dir, "modified_dir": modified_dir, "output": output })),
        Err(e) => err(&e.to_string(), 500),
    }
}

// ---- rich preview (image/text/mml/pmg/rgn/area/set/audio/binary) ------------

const PREVIEW_MAX_HEX_BYTES: usize = 32 * 1024;
const PREVIEW_MAX_AUDIO_BYTES: usize = 8 * 1024 * 1024;
const PREVIEW_MAX_ADPCM_INPUT: usize = 2 * 1024 * 1024;

/// `.set` (animation) file header — mirrors the Tauri `parse_set_header` command.
struct SetHeaderInfo { magic: String, version: u32, bone_count: u32, frame_count: u32, duration_ms: u32, is_xml: bool }

fn parse_set_header_inner(bytes: &[u8]) -> Result<SetHeaderInfo, String> {
    if bytes.len() < 4 {
        return Err(format!("File too small ({} bytes)", bytes.len()));
    }
    if bytes.starts_with(b"<?") || bytes.starts_with(b"<") {
        return Ok(SetHeaderInfo {
            magic: String::from_utf8_lossy(&bytes[..4.min(bytes.len())]).into_owned(),
            version: 0, bone_count: 0, frame_count: 0, duration_ms: 0, is_xml: true,
        });
    }
    let magic = format!("{:02X}{:02X}{:02X}{:02X}", bytes[0], bytes[1], bytes[2], bytes[3]);
    if bytes.len() < 20 {
        return Err(format!("Header too small ({} bytes, need 20)", bytes.len()));
    }
    let r32 = |off: usize| -> u32 { u32::from_le_bytes([bytes[off], bytes[off+1], bytes[off+2], bytes[off+3]]) };
    Ok(SetHeaderInfo { magic, version: r32(4), bone_count: r32(8), frame_count: r32(12), duration_ms: r32(16), is_xml: false })
}

/// Parses a PMG's highest-vertex-count renderable LOD into Three.js-ready
/// geometry JSON, including per-vertex colors (empty array when every vertex
/// is the Mabinogi-default all-white, meaning "no tint").
fn build_pmg_geometry_json(data: &[u8]) -> Result<Value, String> {
    use crate::pmg::PmgFile;
    if data.is_empty() {
        return Err("Empty file (0 bytes — stub entry)".to_string());
    }
    let pmg = PmgFile::parse(data).map_err(|e| e.to_string())?;
    let lod = pmg.groups.iter()
        .flat_map(|g| g.lods.iter())
        .filter(|l| !l.vertices.is_empty() && (!l.face_indices.is_empty() || !l.strip_indices.is_empty()))
        .max_by_key(|l| l.vertices.len())
        .ok_or_else(|| {
            let total: usize = pmg.groups.iter().flat_map(|g| g.lods.iter()).map(|l| l.vertices.len()).sum();
            format!("No renderable LOD ({} groups, {} total verts, {} submeshes)",
                pmg.groups.len(), total, pmg.groups.iter().map(|g| g.lods.len()).sum::<usize>())
        })?;

    let mut positions = Vec::with_capacity(lod.vertices.len() * 3);
    let mut uvs = Vec::with_capacity(lod.vertices.len() * 2);
    for v in &lod.vertices {
        positions.extend_from_slice(&[v.x, v.y, v.z]);
        uvs.extend_from_slice(&[v.u, 1.0 - v.v]);
    }

    let all_white = lod.vertices.iter().all(|v| v.r == 255 && v.g == 255 && v.b == 255);
    let (mut r_sum, mut g_sum, mut b_sum) = (0f32, 0f32, 0f32);
    let mut vertex_colors: Vec<f32> = if all_white { Vec::new() } else { Vec::with_capacity(lod.vertices.len() * 3) };
    for v in &lod.vertices {
        let (r, g, b) = (v.r as f32 / 255.0, v.g as f32 / 255.0, v.b as f32 / 255.0);
        r_sum += r; g_sum += g; b_sum += b;
        if !all_white { vertex_colors.extend_from_slice(&[r, g, b]); }
    }
    let n = lod.vertices.len().max(1) as f32;
    let avg_color = [r_sum / n, g_sum / n, b_sum / n];

    let indices: Vec<u32> = if !lod.face_indices.is_empty() {
        lod.face_indices.iter().map(|&i| i as u32).collect()
    } else {
        crate::common_ext::strip_to_triangles(&lod.strip_indices).iter().map(|&i| i as u32).collect()
    };
    let face_count = indices.len() / 3;

    Ok(json!({
        "positions": positions,
        "normals": Vec::<f32>::new(),
        "uvs": uvs,
        "indices": indices,
        "mesh_name": lod.mesh_name,
        "texture_name": lod.texture_name,
        "vertex_count": lod.vertices.len(),
        "face_count": face_count,
        "vertex_colors": vertex_colors,
        "avg_color": avg_color,
    }))
}

fn handle_preview(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() { Some(s) => s.to_string(), None => return err("'archive' is required", 400) };
    let entry_name = match body["entry_name"].as_str() { Some(s) => s.to_string(), None => return err("'entry_name' is required", 400) };
    let key = body["key"].as_str().map(String::from);

    let (mut raw_bytes, _iv0, _mode, ent) = match crate::common_ext::get_entry_data(&archive, &entry_name, key.clone()) {
        Ok(v) => v,
        Err(e) => return err(&e.to_string(), 500),
    };

    let full_preview_size = raw_bytes.len() as u64;
    let mut file_type = crate::common_ext::get_preview_ext(&entry_name).unwrap_or("unknown").to_string();
    let mut content_text: Option<String> = None;
    let mut content_image: Option<String> = None;
    let mut pmg_geometry: Option<Value> = None;
    let mut rgn_data: Option<Value> = None;
    let mut area_data: Option<Value> = None;
    let mut truncated = false;

    match file_type.as_str() {
        "image" => match crate::common_ext::get_preview_base64_from_data(&entry_name, &raw_bytes) {
            Ok(b64) => content_image = Some(b64),
            Err(e) => { file_type = "error".to_string(); content_text = Some(format!("Image decode failed: {}", e)); }
        },
        "text" | "mml" => {
            let slice = if raw_bytes.len() > PREVIEW_MAX_HEX_BYTES {
                truncated = true;
                &raw_bytes[..PREVIEW_MAX_HEX_BYTES]
            } else {
                &raw_bytes[..]
            };
            content_text = Some(crate::common_ext::decode_text_bytes(slice));
            if file_type == "mml" { raw_bytes = Vec::new(); }
        }
        "pmg" => {
            match build_pmg_geometry_json(&raw_bytes) {
                Ok(geo) => pmg_geometry = Some(geo),
                Err(e) => content_text = Some(format!("PMG parse failed: {}", e)),
            }
            raw_bytes = Vec::new();
        }
        "rgn" => {
            match crate::rgn::parse_rgn(&raw_bytes) {
                Some(rgn) => rgn_data = Some(serde_json::to_value(&rgn).unwrap_or(Value::Null)),
                None => content_text = Some("RGN parse failed — unknown format (see Hex View)".to_string()),
            }
            raw_bytes = Vec::new();
        }
        "area" => {
            match crate::area::parse_area(&raw_bytes) {
                Some(area) => area_data = Some(serde_json::to_value(&area).unwrap_or(Value::Null)),
                None => content_text = Some("AREA parse failed — unknown format (see Hex View)".to_string()),
            }
        }
        "set" => {
            content_text = Some(match parse_set_header_inner(&raw_bytes) {
                Ok(h) if h.is_xml => "XML-format .set file".to_string(),
                Ok(h) => format!(
                    "Animation: {} frames, {} bones, {}ms duration\nMagic: {}  Version: {}",
                    h.frame_count, h.bone_count, h.duration_ms, h.magic, h.version
                ),
                Err(e) => format!("Unknown .set format: {}", e),
            });
        }
        "audio" => {
            if entry_name.to_lowercase().ends_with(".wav") {
                if raw_bytes.len() <= PREVIEW_MAX_ADPCM_INPUT {
                    if let Some(pcm_wav) = crate::common_ext::decode_ima_adpcm_wav(&raw_bytes) {
                        raw_bytes = pcm_wav;
                    }
                } else if crate::common_ext::is_adpcm_wav(&raw_bytes) {
                    let mb = raw_bytes.len() as f64 / 1_048_576.0;
                    content_text = Some(format!(
                        "ADPCM audio ({:.1} MB compressed) — too large for in-app preview. Extract and open externally.", mb
                    ));
                    raw_bytes = Vec::new();
                }
            }
        }
        "binary" if entry_name.to_lowercase().ends_with(".compiled") => {
            if let Some(xml_text) = crate::common_ext::try_decode_xml_compiled(&raw_bytes) {
                file_type = "text".to_string();
                content_text = Some(xml_text);
            }
        }
        _ => {}
    }

    let limit = match file_type.as_str() {
        "audio" => PREVIEW_MAX_AUDIO_BYTES,
        "pmg" | "rgn" => 0,
        _ => PREVIEW_MAX_HEX_BYTES,
    };
    if raw_bytes.len() > limit {
        truncated = true;
        raw_bytes.truncate(limit);
    }

    ok(json!({
        "name": entry_name,
        "size": ent.original_size,
        "raw_size": ent.raw_size,
        "offset": ent.offset,
        "checksum": ent.checksum,
        "flags": ent.flags,
        "file_type": file_type,
        "content_text": content_text,
        "content_image": content_image,
        "raw_bytes": raw_bytes,
        "source": std::path::Path::new(&archive).file_name().and_then(|n| n.to_str()).unwrap_or(""),
        "salt": key.as_deref().unwrap_or("Search/Default"),
        "full_preview_size": full_preview_size,
        "truncated": truncated,
        "pmg_geometry": pmg_geometry,
        "rgn_data": rgn_data,
        "area_data": area_data,
    }))
}

// ---- convert / pmg export -----------------------------------------------------

fn handle_convert(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let input = match body["input"].as_str() { Some(s) => s.to_string(), None => return err("'input' is required", 400) };
    let output = match body["output"].as_str() { Some(s) => s.to_string(), None => return err("'output' is required", 400) };
    let key = body["key"].as_str().map(String::from);
    let wrap_data = body["wrap_data"].as_bool().unwrap_or(false);

    match crate::common_ext::convert(&input, &output, key, wrap_data) {
        Ok(_) => ok(json!({ "input": input, "output": output })),
        Err(e) => err(&e.to_string(), 500),
    }
}

fn handle_pmg_export(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    use crate::pmg::{ObjExportOptions, PmgFile};

    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let archive = match body["archive"].as_str() { Some(s) => s.to_string(), None => return err("'archive' is required", 400) };
    let entry_name = match body["entry_name"].as_str() { Some(s) => s.to_string(), None => return err("'entry_name' is required", 400) };
    let key = body["key"].as_str().map(String::from);
    let output = body["output"].as_str().map(String::from);

    let mut opts = ObjExportOptions::default();
    if let Some(g) = body["group"].as_u64() { opts.group = Some(g as usize); }
    if body["no_colors"].as_bool().unwrap_or(false) { opts.vertex_colors = false; }
    if body["no_transform"].as_bool().unwrap_or(false) { opts.full_transform = false; }

    let (data, _iv0, _mode, _ent) = match crate::common_ext::get_entry_data(&archive, &entry_name, key) {
        Ok(v) => v,
        Err(e) => return err(&e.to_string(), 500),
    };
    let pmg = match PmgFile::parse(&data) {
        Ok(p) => p,
        Err(e) => return err(&format!("PMG parse failed: {}", e), 500),
    };
    let obj = pmg.to_obj_with(&opts);

    match output {
        Some(path) => match std::fs::write(&path, &obj) {
            Ok(_) => ok(json!({ "output": path, "bytes": obj.len() })),
            Err(e) => err(&e.to_string(), 500),
        },
        None => ok(json!({ "obj": obj, "bytes": obj.len() })),
    }
}

// ---- SSE streaming ----------------------------------------------------------

fn handle_extract_stream(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    // Parse body synchronously first, then stream events
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

    // Channels: main thread → SSE reader; worker → main thread
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let salts = crate::load_salts();

    std::thread::spawn(move || {
        let tx2 = tx.clone();
        let cb: Box<crate::extract::ProgressFn> = Box::new(move |done, total, name| {
            let pct = if total > 0 { done * 100 / total } else { 0 };
            let msg = format!("event: progress\ndata: {{\"done\":{},\"total\":{},\"pct\":{},\"name\":\"{}\"}}\n\n",
                done, total, pct, name.replace('"', "\\\""));
            let _ = tx2.send(msg);
        });
        let result = crate::extract::run_extract_with_key_search(
            &archive, &output, key, &salts,
            filters, None, false, false, false, Some(&*cb),
        );
        let final_msg = match result {
            Ok(salt) => format!("event: done\ndata: {{\"success\":true,\"salt\":\"{}\"}}\n\n", salt),
            Err(e)   => format!("event: error\ndata: {{\"success\":false,\"error\":\"{}\"}}\n\n",
                e.to_string().replace('"', "\\\"")),
        };
        let _ = tx.send(final_msg);
        // tx + tx2 drop here → SseReader gets EOF
    });

    // Tiny SSE response — we cannot stream through tiny_http's normal API,
    // so we collect all events synchronously (wait for worker to finish).
    // For true streaming the caller should poll the worker thread result.
    // This implementation collects then returns in one response.
    // TODO: replace with a real async HTTP server if streaming latency matters.
    let rx_blocking = rx;
    let mut body = String::new();
    for line in rx_blocking {
        body.push_str(&line);
    }
    let mut r = Response::from_string(body);
    r.add_header(Header::from_bytes("Content-Type", "text/event-stream; charset=utf-8").unwrap());
    r.add_header(Header::from_bytes("Cache-Control", "no-cache").unwrap());
    for h in cors_headers().into_iter().filter(|h| h.field.to_string().to_lowercase() != "content-type") {
        r.add_header(h);
    }
    r
}

// ---- router -----------------------------------------------------------------

fn route(req: &mut Request, port: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let url = req.url().to_string();
    let method = req.method().clone();

    // CORS preflight
    if method == Method::Options {
        let mut r = Response::from_string("").with_status_code(204);
        for h in cors_headers() { r.add_header(h); }
        return r;
    }

    // Strip query string so routes match regardless of query params
    let path = url.split('?').next().unwrap_or(&url).to_string();

    match (&method, path.as_str()) {
        (Method::Get,  "/api/v1/status")          => handle_status(port),
        (Method::Post, "/api/v1/extract")         => handle_extract(req),
        (Method::Post, "/api/v1/pack")            => handle_pack(req),
        (Method::Post, "/api/v1/list")            => handle_list(req),
        (Method::Post, "/api/v1/mod/apply")       => handle_mod_apply(req),
        (Method::Get,  "/api/v1/salts")           => handle_salts(),
        (Method::Post, "/api/v1/fs/check-data-folder") => handle_check_data_folder(req),
        (Method::Get,  "/api/v1/mods")            => handle_list_mods(),
        (Method::Get,  "/api/v1/mod-template")    => handle_mod_template(),
        (Method::Get,  "/api/v1/mabi-version")    => handle_mabi_version(),
        (Method::Post, "/api/v1/extract/stream")  => handle_extract_stream(req),

        (Method::Post, "/api/v1/mod/vfs/apply")     => handle_mod_vfs_apply(req),
        (Method::Post, "/api/v1/mod/pending/save")  => handle_mod_pending_save(req),
        (Method::Get,  "/api/v1/mod/pending")       => handle_mod_pending_load(req),
        (Method::Get,  "/api/v1/mod-file")          => handle_mod_file_read(req),
        (Method::Post, "/api/v1/features/get")      => handle_features_get(req),
        (Method::Post, "/api/v1/features/save")     => handle_features_save(req),
        (Method::Post, "/api/v1/patch/create")      => handle_patch_create(req),
        (Method::Post, "/api/v1/preview")           => handle_preview(req),
        (Method::Post, "/api/v1/convert")           => handle_convert(req),
        (Method::Post, "/api/v1/pmg/export")        => handle_pmg_export(req),

        (Method::Post, "/api/v1/launcher/login")             => handle_launcher_login(req),
        (Method::Post, "/api/v1/launcher/login/otp")         => handle_launcher_login_otp(req),
        (Method::Post, "/api/v1/launcher/login/tpa")         => handle_launcher_login_tpa(req),
        (Method::Post, "/api/v1/launcher/autologin")         => handle_launcher_autologin(req),
        (Method::Post, "/api/v1/launcher/session/check")     => handle_launcher_session_check(req),
        (Method::Post, "/api/v1/launcher/passport")          => handle_launcher_passport(req),
        (Method::Post, "/api/v1/launcher/maintenance")       => handle_launcher_maintenance(req),
        (Method::Post, "/api/v1/launcher/version")           => handle_launcher_version(req),
        (Method::Post, "/api/v1/launcher/update/check")      => handle_launcher_update_check(req),
        (Method::Post, "/api/v1/launcher/update")            => handle_launcher_update(req),
        (Method::Get,  "/api/v1/launcher/update/status")     => handle_launcher_update_status(),
        (Method::Post, "/api/v1/launcher/update/cancel")     => handle_launcher_update_cancel(),
        (Method::Post, "/api/v1/launcher/update/pause")      => handle_launcher_update_pause(),
        (Method::Post, "/api/v1/launcher/update/resume")     => handle_launcher_update_resume(),
        (Method::Post, "/api/v1/launcher/update/scan")       => handle_launcher_update_scan(req),
        (Method::Post, "/api/v1/launcher/folders/check")     => handle_launcher_folders_check(req),
        (Method::Get,  "/api/v1/launcher/config")            => handle_launcher_config_get(),
        (Method::Post, "/api/v1/launcher/config")            => handle_launcher_config_set(req),
        (Method::Post, "/api/v1/launcher/import/cookies")    => handle_launcher_import_cookies(req),
        (Method::Get,  "/api/v1/launcher/news")              => handle_launcher_news(req),
        (Method::Get,  "/api/v1/launcher/profiles")          => handle_launcher_profiles_list(),
        (Method::Post, "/api/v1/launcher/profile/save")      => handle_launcher_profile_save(req),
        (Method::Post, "/api/v1/launcher/profile/delete")    => handle_launcher_profile_delete(req),
        (Method::Post, "/api/v1/launcher/profile/activate")  => handle_launcher_profile_activate(req),
        (Method::Post, "/api/v1/launcher/profile/load")      => handle_launcher_profile_load(req),
        (Method::Post, "/api/v1/launcher/profile/session")   => handle_launcher_profile_session(req),
        (Method::Post, "/api/v1/launcher/launch")            => handle_launcher_launch(req),

        // Anything else under /api/ is a genuine 404; anything not under /api/
        // falls through to the WebUI static bundle (`mabi-patcher serve` hosts
        // both from one port — see webui_dir()).
        (Method::Get, p) if !p.starts_with("/api/") => handle_static(p),
        _ => err(&format!("Not found: {} {}", method, url), 404),
    }
}

// ---- WebUI static file serving ------------------------------------------------

/// Resolve where the built WebUI (gui/dist) lives, checked in order:
/// `MABI_WEBUI_DIR` env var, a `webui/` folder next to the running exe
/// (production layout), or `gui/dist` relative to the cwd (dev via `cargo run`).
fn webui_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("MABI_WEBUI_DIR") {
        let p = std::path::PathBuf::from(dir);
        if p.is_dir() { return Some(p); }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("webui");
            if candidate.is_dir() { return Some(candidate); }
        }
    }
    let dev_candidate = std::path::PathBuf::from("gui/dist");
    if dev_candidate.is_dir() { return Some(dev_candidate); }
    None
}

fn content_type_for(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn handle_static(path: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let dir = match webui_dir() {
        Some(d) => d,
        None => return err(
            "WebUI static files not found. Build gui/dist (npm run build) or set MABI_WEBUI_DIR.",
            404,
        ),
    };

    let rel = path.trim_start_matches('/');
    // Reject path traversal — this serves an untrusted client-supplied path.
    if rel.split(['/', '\\']).any(|seg| seg == "..") {
        return err("invalid path", 400);
    }

    let mut file_path = if rel.is_empty() { dir.join("index.html") } else { dir.join(rel) };
    if !file_path.is_file() {
        file_path = dir.join("index.html"); // SPA fallback for client-side routes
    }

    match std::fs::read(&file_path) {
        Ok(bytes) => {
            let mut r = Response::from_data(bytes);
            r.add_header(Header::from_bytes("Content-Type", content_type_for(&file_path)).unwrap());
            r
        }
        Err(_) => err("WebUI index.html not found in the resolved webui dir", 404),
    }
}

fn is_loopback_bind(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// The `host:port` authorities a loopback-bound server answers to.
fn loopback_authorities(port: u16) -> [String; 3] {
    [format!("127.0.0.1:{}", port), format!("localhost:{}", port), format!("[::1]:{}", port)]
}

/// DNS-rebinding guard for loopback binds: the Host header must name the
/// loopback interface on the bound port. A rebinding page reaches us as
/// `attacker.example:port`, which is rejected here. A missing Host is
/// allowed (browsers always send one; only bare non-browser clients omit it).
fn loopback_host_ok(request_host: Option<&str>, port: u16) -> bool {
    let h = match request_host {
        Some(h) => h.trim().to_ascii_lowercase(),
        None => return true,
    };
    if loopback_authorities(port).contains(&h) { return true; }
    port == 80 && matches!(h.as_str(), "127.0.0.1" | "localhost" | "[::1]")
}

/// Whether a browser `Origin` may call this API. Tauri webviews are always
/// allowed. On a loopback bind only the loopback origins on the bound port
/// are accepted (not "whatever Host the request claims", which a rebinding
/// page controls); otherwise the Origin must match the request's own Host.
fn origin_ok(origin: &str, request_host: &str, loopback_port: Option<u16>) -> bool {
    if origin.starts_with("tauri://") { return true; }
    let origin = origin.trim().to_ascii_lowercase();
    let authority = match origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) {
        Some(a) => a,
        None => return false,
    };
    match loopback_port {
        Some(port) => loopback_authorities(port).iter().any(|a| a == authority),
        None => authority == request_host.trim().to_ascii_lowercase(),
    }
}

/// Request guard run before routing.
///
/// Loopback binds (127.0.0.1/localhost/::1) need no token, but are protected
/// against DNS rebinding and malicious tabs: the Host header must be a
/// loopback authority on the bound port and any Origin must be one of those
/// loopback origins (or a Tauri webview). Any other bind address (Docker
/// "0.0.0.0", LAN) requires `MABI_API_TOKEN` to be set and matched against
/// `Authorization: Bearer <token>` — launcher credentials and mod-apply are
/// too sensitive to leave open once reachable off-box.
fn check_auth(req: &Request, host: &str, port: u16) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    let header = |name: &str| req.headers().iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string());
    let loopback = is_loopback_bind(host);
    let request_host = header("host");

    if loopback && !loopback_host_ok(request_host.as_deref(), port) {
        return Some(err("Invalid Host header", 403));
    }

    if *req.method() == Method::Options {
        return None; // let CORS preflight through regardless of auth
    }

    // Reject cross-origin browser requests regardless of bind address. The
    // CORS preflight answers with a permissive header (needed for the Tauri
    // app), which on its own would let ANY webpage's JS call this API via the
    // user's own browser — loopback-bind trust only defends against remote
    // network attackers, not a malicious tab the user has open.
    if let Some(origin) = header("origin") {
        let lp = if loopback { Some(port) } else { None };
        if !origin_ok(&origin, request_host.as_deref().unwrap_or(""), lp) {
            return Some(err("Cross-origin requests are not allowed", 403));
        }
    }

    if loopback {
        return None;
    }
    let required = match std::env::var("MABI_API_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            return Some(err(
                "MABI_API_TOKEN must be set when the API is bound to a non-loopback address",
                503,
            ))
        }
    };
    let provided = req.headers().iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("authorization"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    if provided == format!("Bearer {}", required) {
        None
    } else {
        Some(err("Unauthorized: missing or invalid bearer token", 401))
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
    serve(&server, host, &stop);
    Ok(())
}

/// Start the API server on a free loopback port in the background.
/// Returns the port and the stop flag (used by the built-in MCP server).
pub fn spawn_ephemeral() -> Result<(u16, Arc<AtomicBool>)> {
    let server = Server::http("127.0.0.1:0")
        .map_err(|e| anyhow::anyhow!("API server bind failed: {}", e))?;
    let port = server.server_addr().to_ip()
        .map(|a| a.port())
        .ok_or_else(|| anyhow::anyhow!("API server has no TCP address"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    std::thread::spawn(move || serve(&server, "127.0.0.1", &stop2));
    Ok((port, stop))
}

/// Routes that can run for seconds to minutes (network scans, game launch);
/// served on their own thread instead of the single accept loop.
fn is_long_running(req: &Request) -> bool {
    *req.method() == Method::Post
        && matches!(
            req.url().split('?').next().unwrap_or(""),
            "/api/v1/launcher/update/scan" | "/api/v1/launcher/launch"
        )
}

/// Cap on concurrently running long requests (each holds a thread).
const MAX_LONG_REQUESTS: usize = 4;
static LONG_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One slot of `MAX_LONG_REQUESTS`; released on drop (also on panic).
struct LongSlot;

impl LongSlot {
    fn acquire() -> Option<LongSlot> {
        LONG_IN_FLIGHT
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_LONG_REQUESTS).then_some(n + 1))
            .ok()
            .map(|_| LongSlot)
    }
}

impl Drop for LongSlot {
    fn drop(&mut self) {
        LONG_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve(server: &Server, host: &str, stop: &AtomicBool) {
    // The port actually bound (differs from the requested one for port 0).
    let port = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(0);
    loop {
        if stop.load(Ordering::Relaxed) { break; }
        match server.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(Some(mut req)) => {
                if let Some(unauthorized) = check_auth(&req, host, port) {
                    let _ = req.respond(unauthorized);
                    continue;
                }
                if is_long_running(&req) {
                    // Off the accept loop so status/cancel/pause/MCP stay responsive.
                    match LongSlot::acquire() {
                        Some(slot) => {
                            std::thread::spawn(move || {
                                let _slot = slot;
                                let resp = route(&mut req, port);
                                let _ = req.respond(resp);
                            });
                        }
                        None => { let _ = req.respond(err("Server busy, try again shortly", 503)); }
                    }
                    continue;
                }
                let resp = route(&mut req, port);
                let _ = req.respond(resp);
            }
            Ok(None) => {}
            Err(e) => log::warn!("[API] recv error: {}", e),
        }
    }
    log::info!("[API] Server stopped");
}

/// Bind `host:port` now (so bind errors are reported) and serve on a background
/// thread. Returns the bound port and the stop flag.
pub fn spawn_bound(host: &str, port: u16) -> Result<(u16, Arc<AtomicBool>)> {
    let addr = format!("{}:{}", host, port);
    let server = Server::http(&addr)
        .map_err(|e| anyhow::anyhow!("API server bind failed on {}: {}", addr, e))?;
    let bound = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(port);
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let host = host.to_string();
    std::thread::spawn(move || serve(&server, &host, &stop2));
    Ok((bound, stop))
}

/// `serve [--host HOST] [-p|--port PORT]` for executables without a full clap
/// CLI (the GUI exe). Runs until killed, or until Enter in an interactive terminal.
pub fn serve_from_args(args: &[String]) -> Result<()> {
    let mut host = "127.0.0.1".to_string();
    let mut port = DEFAULT_PORT;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--host" => host = it.next().cloned().ok_or_else(|| anyhow::anyhow!("--host needs a value"))?,
            "-p" | "--port" => port = it.next().and_then(|v| v.parse().ok()).ok_or_else(|| anyhow::anyhow!("--port needs a number"))?,
            other => return Err(anyhow::anyhow!("unknown serve argument: {}", other)),
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            let stop2 = Arc::clone(&stop);
            std::thread::spawn(move || {
                let _ = std::io::stdin().read_line(&mut String::new());
                stop2.store(true, Ordering::Relaxed);
            });
        }
    }
    run_server(&host, port, stop)
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_utf8_and_edges() {
        assert_eq!(percent_decode("C%3A%5Cmods%5Ca.mod"), "C:\\mods\\a.mod");
        assert_eq!(percent_decode("caf%C3%A9%20%ED%95%9C"), "café 한");
        assert_eq!(percent_decode("%41"), "A");
        assert_eq!(percent_decode("ab%4"), "ab%4");
        assert_eq!(percent_decode("ab%"), "ab%");
        assert_eq!(percent_decode("%zz%+1"), "%zz%+1");
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
    }

    #[test]
    fn mod_file_restricted_to_mods_folder() {
        let dir = std::env::temp_dir().join(format!("mabi_api_modfile_{}", std::process::id()));
        let mods = dir.join("mods");
        std::fs::create_dir_all(mods.join("sub")).unwrap();
        std::fs::write(mods.join("a.mod"), "x").unwrap();
        std::fs::write(mods.join("sub").join("b.mod"), "y").unwrap();
        std::fs::write(dir.join("secret.txt"), "s").unwrap();

        assert!(resolve_mod_file(&mods, "a.mod").is_ok());
        assert!(resolve_mod_file(&mods, "sub/b.mod").is_ok());
        assert!(resolve_mod_file(&mods, mods.join("a.mod").to_str().unwrap()).is_ok());
        assert!(resolve_mod_file(&mods, "../secret.txt").is_err());
        assert!(resolve_mod_file(&mods, dir.join("secret.txt").to_str().unwrap()).is_err());
        assert!(resolve_mod_file(&mods, mods.join("..").join("secret.txt").to_str().unwrap()).is_err());
        assert!(resolve_mod_file(&mods, "sub").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cors_allows_authorization_header() {
        let h = cors_headers().into_iter()
            .find(|h| h.field.equiv("Access-Control-Allow-Headers")).unwrap();
        assert!(h.value.as_str().contains("Authorization"));
    }

    #[test]
    fn loopback_host_header_must_be_loopback_on_bound_port() {
        assert!(loopback_host_ok(Some("127.0.0.1:7331"), 7331));
        assert!(loopback_host_ok(Some("LOCALHOST:7331"), 7331));
        assert!(loopback_host_ok(Some("[::1]:7331"), 7331));
        assert!(loopback_host_ok(None, 7331));
        assert!(!loopback_host_ok(Some("evil.example:7331"), 7331));
        assert!(!loopback_host_ok(Some("127.0.0.1:8080"), 7331));
        assert!(!loopback_host_ok(Some("127.0.0.1"), 7331));
        assert!(loopback_host_ok(Some("localhost"), 80));
    }

    #[test]
    fn origin_rules() {
        // Loopback bind: only loopback origins on the bound port.
        assert!(origin_ok("http://127.0.0.1:7331", "127.0.0.1:7331", Some(7331)));
        assert!(origin_ok("http://localhost:7331", "127.0.0.1:7331", Some(7331)));
        assert!(origin_ok("tauri://localhost", "127.0.0.1:7331", Some(7331)));
        assert!(!origin_ok("http://evil.example:7331", "evil.example:7331", Some(7331)));
        assert!(!origin_ok("http://localhost:5173", "127.0.0.1:7331", Some(7331)));
        assert!(!origin_ok("null", "127.0.0.1:7331", Some(7331)));
        // Non-loopback bind: same-origin with the request's Host.
        assert!(origin_ok("http://10.0.0.5:7331", "10.0.0.5:7331", None));
        assert!(!origin_ok("http://evil.example", "10.0.0.5:7331", None));
    }

    #[test]
    fn rebinding_requests_are_rejected() {
        let (port, stop) = spawn_ephemeral().unwrap();
        let client = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let url = format!("http://127.0.0.1:{}/api/v1/status", port);
        let status = |host: Option<String>, origin: Option<&str>| {
            let mut rb = client.get(&url);
            if let Some(h) = host { rb = rb.header("Host", h); }
            if let Some(o) = origin { rb = rb.header("Origin", o); }
            rb.send().unwrap().status().as_u16()
        };
        let r_ok = status(None, None);
        let r_local_origin = status(None, Some(&format!("http://localhost:{}", port)));
        let r_rebound = status(Some(format!("evil.example:{}", port)), None);
        let r_cross = status(None, Some("http://evil.example"));
        let r_rebound_origin = status(
            Some(format!("evil.example:{}", port)),
            Some(&format!("http://evil.example:{}", port)),
        );
        stop.store(true, Ordering::Relaxed);
        assert_eq!(r_ok, 200);
        assert_eq!(r_local_origin, 200);
        assert_eq!(r_rebound, 403);
        assert_eq!(r_cross, 403);
        assert_eq!(r_rebound_origin, 403);
    }

    #[test]
    fn long_slots_are_bounded_and_released() {
        let slots: Vec<_> = std::iter::from_fn(LongSlot::acquire).take(MAX_LONG_REQUESTS + 1).collect();
        assert!(slots.len() <= MAX_LONG_REQUESTS);
        drop(slots);
        assert!(LongSlot::acquire().is_some());
    }

    #[test]
    fn status_reports_bound_port() {
        let (port, stop) = spawn_ephemeral().unwrap();
        let body = reqwest::blocking::Client::builder().no_proxy().build().unwrap()
            .get(format!("http://127.0.0.1:{}/api/v1/status", port)).send().unwrap().text().unwrap();
        stop.store(true, Ordering::Relaxed);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["data"]["port"].as_u64(), Some(port as u64));
    }
}
