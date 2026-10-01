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
///   GET  /api/v1/uotiara/mods
///   POST /api/v1/uotiara/build
///   GET  /api/v1/mabi-version
///   POST /api/v1/extract/stream  (SSE progress stream)
///   POST /api/v1/launcher/login              (Windows only)
///   POST /api/v1/launcher/autologin           (Windows only)
///   POST /api/v1/launcher/passport            (Windows only)
///   POST /api/v1/launcher/maintenance         (Windows only)
///   POST /api/v1/launcher/version             (Windows only)
///   GET  /api/v1/launcher/profiles            (Windows only)
///   POST /api/v1/launcher/profile/save        (Windows only)
///   POST /api/v1/launcher/profile/delete      (Windows only)
///   POST /api/v1/launcher/profile/activate    (Windows only)
///   POST /api/v1/launcher/profile/load        (Windows only)
///   POST /api/v1/launcher/profile/session     (Windows only)
///   POST /api/v1/launcher/launch              (Windows only)
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
/// Auth: loopback (127.0.0.1) binds are always open. Binding to any other
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

// ---- uotiara helpers (NSI-based) --------------------------------------------

/// Extract the first double-quoted string from an NSIS line.
fn nsi_quoted(line: &str) -> Option<String> {
    let start = line.find('"')?;
    let rest = &line[start+1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parse `Section "Name" MOD###` → (name, id).  Returns None for unnamed sections.
fn parse_nsi_section(line: &str) -> Option<(String, u32)> {
    let name = nsi_quoted(line)?;
    let after_quote = &line[line.rfind('"')? + 1..].trim();
    let id_str = after_quote.strip_prefix("MOD")?;
    let id: u32 = id_str.trim().parse().ok()?;
    Some((name, id))
}

/// Parse uotiara.nsi and return every data mod (installs to `$INSTDIR\data\`).
///
/// Each entry: `{ id, name, group, files: [{src, dest}] }` where
///   - `src`  = relative to nsi directory (e.g. `Tiara's Moonshine Mod/data/db/foo.xml`)
///   - `dest` = relative to game `data/`   (e.g. `db/foo.xml`)
pub fn parse_uotiara_nsi(nsi_path: &str) -> anyhow::Result<Vec<Value>> {
    let text = std::fs::read_to_string(nsi_path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", nsi_path, e))?;

    let mut result: Vec<Value> = Vec::new();
    let mut group_stack: Vec<String> = Vec::new();

    let mut in_section = false;
    let mut cur_name = String::new();
    let mut cur_id: u32 = 0;
    let mut cur_set_out = String::new();   // full NSIS SetOutPath value
    let mut cur_files: Vec<Value> = Vec::new();

    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with(';') { continue; }   // NSIS comment

        // Track SectionGroup nesting for group metadata
        if t.starts_with("SectionGroup") && !t.contains("SectionGroupEnd") {
            if let Some(name) = nsi_quoted(t) {
                group_stack.push(name);
            }
            continue;
        }
        if t == "SectionGroupEnd" {
            group_stack.pop();
            continue;
        }

        // Section header: must have MOD### constant
        if t.starts_with("Section ")
            && !t.starts_with("SectionGroup")
            && !t.starts_with("SectionEnd")
            && !t.starts_with("SectionIn")
        {
            if let Some((name, id)) = parse_nsi_section(t) {
                in_section = true;
                cur_name = name;
                cur_id = id;
                cur_set_out.clear();
                cur_files.clear();
            }
            continue;
        }

        if t == "SectionEnd" {
            if in_section && !cur_files.is_empty() {
                result.push(json!({
                    "id":    cur_id,
                    "name":  cur_name,
                    "group": group_stack.join("/"),
                    "files": cur_files,
                }));
            }
            in_section = false;
            cur_files.clear();
            cur_set_out.clear();
            continue;
        }

        if !in_section { continue; }

        // SetOutPath — update current destination prefix
        if t.starts_with("SetOutPath ") {
            if let Some(path) = nsi_quoted(t) {
                cur_set_out = path;
            }
            continue;
        }

        // Delete — installer-time delete inside data\ (e.g. MOD89 "Dark Knight Sound")
        if t.starts_with("Delete ") {
            if let Some(target) = nsi_quoted(t) {
                let is_data = target == "$INSTDIR\\data"
                    || target.starts_with("$INSTDIR\\data\\");
                if is_data {
                    let dest_rel = target
                        .trim_start_matches("$INSTDIR\\data\\")
                        .trim_start_matches("$INSTDIR\\data")
                        .replace('\\', "/");
                    if !dest_rel.is_empty() {
                        cur_files.push(json!({ "action": "delete", "dest": dest_rel }));
                    }
                }
            }
            continue;
        }

        // File — only collect if destination is under $INSTDIR\data\
        if t.starts_with("File ") {
            let is_data = cur_set_out == "$INSTDIR\\data"
                || cur_set_out.starts_with("$INSTDIR\\data\\");
            if !is_data { continue; }
            if let Some(src) = nsi_quoted(t) {
                // Strip ${srcdir}\ prefix; normalise to forward slashes
                let src_rel = src
                    .trim_start_matches("${srcdir}\\")
                    .replace('\\', "/");
                let filename = src_rel.split('/').last().unwrap_or("").to_string();

                let dest_base = cur_set_out
                    .trim_start_matches("$INSTDIR\\data\\")
                    .trim_start_matches("$INSTDIR\\data")
                    .replace('\\', "/");
                let dest_rel = if dest_base.is_empty() {
                    filename
                } else {
                    format!("{}/{}", dest_base, filename)
                };

                cur_files.push(json!({ "action": "replace", "src": src_rel, "dest": dest_rel }));
            }
        }
    }

    Ok(result)
}

fn default_nsi_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("uotiara.nsi")))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "uotiara.nsi".to_string())
}

fn handle_uotiara_list(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let url = req.url().to_string();
    let nsi_path = url.split('?').nth(1)
        .and_then(|qs| qs.split('&').find(|p| p.starts_with("nsi=")))
        .map(|p| p[4..].to_string())
        .map(|s| percent_decode(&s))
        .unwrap_or_else(default_nsi_path);

    match parse_uotiara_nsi(&nsi_path) {
        Ok(mods) => ok(json!({ "nsi": nsi_path, "count": mods.len(), "mods": mods })),
        Err(e)   => err(&e.to_string(), 500),
    }
}

fn handle_uotiara_build(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };

    let nsi_path = match body["nsi"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'nsi' (path to uotiara.nsi) is required", 400),
    };
    let output = match body["output"].as_str() {
        Some(s) => s.to_string(),
        None => return err("'output' (destination .it path) is required", 400),
    };
    let key = body["key"].as_str().map(String::from);
    let selected: std::collections::HashSet<u64> = body["selected"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();

    if selected.is_empty() {
        return err("'selected' must be a non-empty array of mod IDs", 400);
    }

    let all_mods = match parse_uotiara_nsi(&nsi_path) {
        Ok(m) => m,
        Err(e) => return err(&e.to_string(), 500),
    };

    // Base directory is the folder containing the NSI file
    let nsi_dir = std::path::Path::new(&nsi_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    // Stage files into tmp_dir/data/<dest_rel> so the pack preserves data\ prefix
    let tmp_dir = std::env::temp_dir()
        .join(format!("mabi_uotiara_{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        return err(&format!("cannot create temp dir: {}", e), 500);
    }

    let mut copied = 0usize;
    for m in &all_mods {
        let id = m["id"].as_u64().unwrap_or(0);
        if !selected.contains(&id) { continue; }
        if let Some(files) = m["files"].as_array() {
            for f in files {
                let src_rel  = match f["src"].as_str()  { Some(s) => s, None => continue };
                let dest_rel = match f["dest"].as_str() { Some(s) => s, None => continue };

                let src_path  = nsi_dir.join(src_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
                let dest_path = tmp_dir.join("data").join(dest_rel.replace('/', std::path::MAIN_SEPARATOR_STR));

                if let Some(parent) = dest_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::copy(&src_path, &dest_path) {
                    Ok(_) => copied += 1,
                    Err(e) => eprintln!("warning: skip {:?}: {}", src_path, e),
                }
            }
        }
    }

    if copied == 0 {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return err("no files copied — verify nsi path and that mod source files exist", 400);
    }

    let tmp_str = tmp_dir.to_string_lossy().to_string();
    let key_str = key.as_deref().unwrap_or("})wWb4?-sVGHNoPKpc");
    let result = crate::pack::run_pack(&tmp_str, &output, key_str, vec![], false, 0, None, None);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    match result {
        Ok(_) => ok(json!({
            "nsi":          nsi_path,
            "output":       output,
            "selected":     selected.len(),
            "files_copied": copied,
        })),
        Err(e) => err(&format!("pack failed: {}", e), 500),
    }
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i+1..i+3]).unwrap_or(""), 16) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    if s.len() % 2 != 0 { return Err(()); }
    (0..s.len()).step_by(2).map(|i| {
        u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ())
    }).collect()
}

// ---- launcher handlers (Windows only) ---------------------------------------

#[cfg(target_os = "windows")]
fn handle_launcher_login(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let username = match body["username"].as_str() { Some(s) => s, None => return err("'username' is required", 400) };
    let password = match body["password"].as_str() { Some(s) => s, None => return err("'password' is required", 400) };
    let remember = body["remember"].as_bool().unwrap_or(false);

    match crate::launcher::auth::login(username, password, remember) {
        Ok(result) => ok(json!({
            "session": result.session,
            "expiresIn": result.session_expires_in,
        })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_autologin(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session_token = match body["session_token"].as_str() { Some(s) => s, None => return err("'session_token' is required", 400) };

    match crate::launcher::auth::autologin(session_token) {
        Ok(result) => ok(json!({
            "session": result.session,
            "expiresIn": result.session_expires_in,
        })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn parse_session(body: &Value) -> Result<crate::launcher::auth::NexonSession, Response<std::io::Cursor<Vec<u8>>>> {
    serde_json::from_value(body["session"].clone())
        .map_err(|e| err(&format!("'session' is invalid: {}", e), 400))
}

#[cfg(target_os = "windows")]
fn handle_launcher_passport(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    match crate::launcher::auth::get_passport(&session) {
        Ok(passport) => ok(json!({ "passport": passport })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_maintenance(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    match crate::launcher::patch::is_maintenance(&session) {
        Ok(maintenance) => ok(json!({ "maintenance": maintenance })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_version(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    match crate::launcher::patch::get_latest_version(&session) {
        Ok(version) => ok(json!({ "version": version })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_profiles_list() -> Response<std::io::Cursor<Vec<u8>>> {
    match crate::launcher::profile::list_profiles() {
        Ok(summaries) => ok(json!({ "profiles": summaries })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_profile_save(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
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

#[cfg(target_os = "windows")]
fn handle_launcher_profile_delete(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    match crate::launcher::profile::delete_profile(id) {
        Ok(deleted) => ok(json!({ "deleted": deleted })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_profile_activate(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    match crate::launcher::profile::set_active_profile(id) {
        Ok(_) => ok(json!({ "activated": id })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_profile_load(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
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

#[cfg(target_os = "windows")]
fn handle_launcher_profile_session(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let id = match body["id"].as_str() { Some(s) => s, None => return err("'id' is required", 400) };
    let session_token = match body["session_token"].as_str() { Some(s) => s, None => return err("'session_token' is required", 400) };
    let expires_in = body["expires_in"].as_i64().unwrap_or(0) as i32;
    match crate::launcher::profile::update_session(id, session_token, expires_in) {
        Ok(_) => ok(json!({ "updated": true })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(target_os = "windows")]
fn handle_launcher_launch(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    use crate::launcher::{auth, launch};

    let body = match parse_json_body(req) { Ok(v) => v, Err(r) => return r };
    let session = match parse_session(&body) { Ok(s) => s, Err(r) => return r };
    let client_dir = match body["client_dir"].as_str() { Some(s) => s, None => return err("'client_dir' is required", 400) };

    let config = match launch::fetch_launch_config(&session) { Ok(c) => c, Err(e) => return err(&e.to_string(), 500) };
    let passport = match auth::get_passport(&session) { Ok(p) => p, Err(e) => return err(&e.to_string(), 500) };
    let summary = launch::LaunchSummary::from(&config);

    match config.spawn_client(std::path::Path::new(client_dir), &passport) {
        Ok(_child) => ok(json!({
            "executable": summary.executable,
            "argumentCount": summary.argument_count,
            "patchAvailable": summary.patch_available,
        })),
        Err(e) => err(&e.to_string(), 500),
    }
}

#[cfg(not(target_os = "windows"))]
fn launcher_unavailable() -> Response<std::io::Cursor<Vec<u8>>> {
    err("launcher endpoints are only available on Windows", 501)
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
    let normalize = |p: &str| -> String { p.replace('\\', "/").trim_start_matches('/').to_string() };

    for change in &changes {
        let result: anyhow::Result<()> = (|| {
            match change {
                VfsChange::Delete { path } => {
                    let target = tmp_dir.join(normalize(path));
                    if target.exists() {
                        std::fs::remove_file(&target)?;
                        stats["deleted"] = (stats["deleted"].as_i64().unwrap_or(0) + 1).into();
                    }
                }
                VfsChange::Rename { from, to } => {
                    let src = tmp_dir.join(normalize(from));
                    let dst = tmp_dir.join(normalize(to));
                    if let Some(p) = dst.parent() { std::fs::create_dir_all(p)?; }
                    if src.exists() {
                        std::fs::rename(&src, &dst)?;
                        stats["renamed"] = (stats["renamed"].as_i64().unwrap_or(0) + 1).into();
                    }
                }
                VfsChange::Add { dest, local_src } => {
                    let dst = tmp_dir.join(normalize(dest));
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
    match std::fs::read_to_string(&path) {
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

fn route(req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
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
        (Method::Get,  "/api/v1/status")          => handle_status(),
        (Method::Post, "/api/v1/extract")         => handle_extract(req),
        (Method::Post, "/api/v1/pack")            => handle_pack(req),
        (Method::Post, "/api/v1/list")            => handle_list(req),
        (Method::Post, "/api/v1/mod/apply")       => handle_mod_apply(req),
        (Method::Get,  "/api/v1/salts")           => handle_salts(),
        (Method::Post, "/api/v1/fs/check-data-folder") => handle_check_data_folder(req),
        (Method::Get,  "/api/v1/mods")            => handle_list_mods(),
        (Method::Get,  "/api/v1/mod-template")    => handle_mod_template(),
        (Method::Get,  "/api/v1/uotiara/mods")    => handle_uotiara_list(req),
        (Method::Post, "/api/v1/uotiara/build")   => handle_uotiara_build(req),
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

        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/login")             => handle_launcher_login(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/autologin")         => handle_launcher_autologin(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/passport")          => handle_launcher_passport(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/maintenance")       => handle_launcher_maintenance(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/version")           => handle_launcher_version(req),
        #[cfg(target_os = "windows")]
        (Method::Get,  "/api/v1/launcher/profiles")          => handle_launcher_profiles_list(),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/profile/save")      => handle_launcher_profile_save(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/profile/delete")    => handle_launcher_profile_delete(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/profile/activate")  => handle_launcher_profile_activate(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/profile/load")      => handle_launcher_profile_load(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/profile/session")   => handle_launcher_profile_session(req),
        #[cfg(target_os = "windows")]
        (Method::Post, "/api/v1/launcher/launch")            => handle_launcher_launch(req),

        #[cfg(not(target_os = "windows"))]
        (_, p) if p.starts_with("/api/v1/launcher/") => launcher_unavailable(),

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

/// Bearer-token check for non-loopback binds. Loopback (127.0.0.1/localhost)
/// is always trusted since it's the same machine. Any other bind address
/// (Docker "0.0.0.0", LAN) requires `MABI_API_TOKEN` to be set and matched
/// against `Authorization: Bearer <token>` — launcher credentials and
/// mod-apply are too sensitive to leave open once reachable off-box.
fn check_auth(req: &Request, host: &str) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if *req.method() == Method::Options {
        return None; // let CORS preflight through regardless of auth
    }

    // Reject cross-origin browser requests regardless of bind address. The
    // CORS preflight below answers with a permissive header (needed for the
    // Tauri app / a dev Vite server on a different port), which on its own
    // would let ANY webpage's JS silently call this API via the user's own
    // browser on localhost — loopback-bind trust only defends against
    // remote network attackers, not a malicious tab the user has open. A
    // same-origin request either sends no Origin header, or one matching
    // this request's own Host header; anything else is rejected here before
    // it reaches a handler, independent of whether a token is configured.
    if let Some(origin) = req.headers().iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("origin"))
        .map(|h| h.value.as_str().to_string())
    {
        let request_host = req.headers().iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("host"))
            .map(|h| h.value.as_str().to_string())
            .unwrap_or_default();
        let same_origin = origin.strip_prefix("http://").map(|rest| rest == request_host).unwrap_or(false)
            || origin.strip_prefix("https://").map(|rest| rest == request_host).unwrap_or(false)
            || origin.starts_with("tauri://");
        if !same_origin {
            return Some(err("Cross-origin requests are not allowed", 403));
        }
    }

    if host == "127.0.0.1" || host == "localhost" || host == "::1" {
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
    loop {
        if stop.load(Ordering::Relaxed) { break; }
        match server.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(Some(mut req)) => {
                let resp = match check_auth(&req, host) {
                    Some(unauthorized) => unauthorized,
                    None => route(&mut req),
                };
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

