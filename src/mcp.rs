//! Built-in MCP (Model Context Protocol) server: `mabi-patcher mcp`.
//!
//! Speaks JSON-RPC 2.0 over stdio and exposes every local API endpoint
//! (`api.rs`) as an MCP tool, so an AI client can extract, pack, mod, patch and
//! launch through the same binary — no separate server to install.
//!
//! Launcher tools that need a Nexon session take it from the saved profile
//! (`profile` argument, else the active one) when no `session` is passed, and
//! any refreshed session in a response is saved back to that profile. Session
//! tokens are stripped from tool results so they never reach the model.

use crate::launcher::{auth::NexonSession, cli, profile};
use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2025-06-18";

/// How a tool reaches the API.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// POST with the arguments as the JSON body.
    Post,
    /// GET with the arguments as a query string.
    Get,
    /// POST that needs a Nexon session (filled from the profile when absent).
    Session,
    /// POST that logs in; the returned session is stored on a profile.
    Login,
    /// Runs in this process by chaining other tools (`path` is unused).
    Local,
}

struct Tool {
    name: &'static str,
    path: &'static str,
    kind: Kind,
    description: &'static str,
    /// (name, JSON type, required, description)
    params: &'static [(&'static str, &'static str, bool, &'static str)],
}

const KEY: (&str, &str, bool, &str) = ("key", "string", false, "Archive salt/key; omit to auto-detect");
const ARCHIVE: (&str, &str, bool, &str) = ("archive", "string", true, "Path to a .it or .pack archive");
const PROFILE: (&str, &str, bool, &str) = ("profile", "string", false, "Saved profile name, id or email (default: the active profile)");
const GAME_PATH: (&str, &str, bool, &str) = ("game_path", "string", false, "Mabinogi install folder (default: the profile's folder)");

const TOOLS: &[Tool] = &[
    Tool { name: "status", path: "/api/v1/status", kind: Kind::Get,
        description: "Server and build status.", params: &[] },
    Tool { name: "list_archive", path: "/api/v1/list", kind: Kind::Post,
        description: "List the entries of a .it/.pack archive.", params: &[ARCHIVE, KEY] },
    Tool { name: "extract", path: "/api/v1/extract", kind: Kind::Post,
        description: "Extract files from an archive to a folder.",
        params: &[ARCHIVE, ("output", "string", true, "Destination folder"), KEY,
            ("filters", "array", false, "Regular expressions matched against entry paths (default: all)"),
            ("auto_convert_png", "boolean", false, "Also convert DDS textures to PNG"),
            ("auto_convert_pmg", "boolean", false, "Also export PMG models to OBJ"),
            ("auto_convert_features", "boolean", false, "Also decode features files")] },
    Tool { name: "pack", path: "/api/v1/pack", kind: Kind::Post,
        description: "Build a .it/.pack archive from a folder.",
        params: &[("source", "string", true, "Folder to pack"), ("output", "string", true, "Archive to write"), KEY,
            ("formats", "array", false, "Extra file extensions to compress in a .it, e.g. [\".ini\"]; the output format follows the output file extension"), ("iv", "integer", false, "Header IV"),
            ("path_prefix", "string", false, "Prefix for entry paths"), ("wrap_data", "boolean", false, "Wrap entries under data/"),
            ("auto_convert_dds", "boolean", false, "Convert PNG back to DDS"), ("pack_v1_version", "integer", false, "Legacy .pack version")] },
    Tool { name: "preview", path: "/api/v1/preview", kind: Kind::Post,
        description: "Preview one archive entry (text, image, PMG geometry, region data).",
        params: &[ARCHIVE, ("entry_name", "string", true, "Entry path inside the archive"), KEY] },
    Tool { name: "convert", path: "/api/v1/convert", kind: Kind::Post,
        description: "Convert an archive between the .it and .pack formats.",
        params: &[("input", "string", true, "Input file"), ("output", "string", true, "Output file"), KEY,
            ("wrap_data", "boolean", false, "Wrap entries under data/")] },
    Tool { name: "pmg_export", path: "/api/v1/pmg/export", kind: Kind::Post,
        description: "Export a PMG model from an archive to OBJ.",
        params: &[ARCHIVE, ("entry_name", "string", true, "PMG entry path"), ("output", "string", true, "OBJ file to write"), KEY,
            ("group", "integer", false, "Only this mesh group index"), ("no_colors", "boolean", false, "Skip vertex colours"),
            ("no_transform", "boolean", false, "Skip the mesh transform")] },
    Tool { name: "salts", path: "/api/v1/salts", kind: Kind::Get,
        description: "Known archive salts.", params: &[] },
    Tool { name: "check_data_folder", path: "/api/v1/fs/check-data-folder", kind: Kind::Post,
        description: "Check whether a folder looks like a Mabinogi data folder.",
        params: &[("path", "string", true, "Folder to check")] },
    Tool { name: "mabi_version", path: "/api/v1/mabi-version", kind: Kind::Get,
        description: "Installed Mabinogi client version, read from the Windows registry.", params: &[] },
    Tool { name: "list_mods", path: "/api/v1/mods", kind: Kind::Get,
        description: "Mods in the local mods folder.", params: &[] },
    Tool { name: "mod_template", path: "/api/v1/mod-template", kind: Kind::Get,
        description: "Template for a new mod file.", params: &[] },
    Tool { name: "read_mod_file", path: "/api/v1/mod-file", kind: Kind::Get,
        description: "Read a mod file's raw TOML text from the local mods folder.", params: &[("path", "string", true, "Mod file name, or a path inside the mods folder")] },
    Tool { name: "apply_mod", path: "/api/v1/mod/apply", kind: Kind::Post,
        description: "Apply a mod to an archive.",
        params: &[ARCHIVE, KEY, ("mod", "string", false, "Mod definition as TOML text (alias of mod_toml)"),
            ("mod_dir", "string", false, "Folder that relative source paths resolve against"),
            ("mod_toml", "string", false, "Mod definition as TOML text (use read_mod_file to load one)")] },
    Tool { name: "apply_vfs_changes", path: "/api/v1/mod/vfs/apply", kind: Kind::Post,
        description: "Apply queued virtual-filesystem edits (add/replace/delete/merge) to an archive.",
        params: &[ARCHIVE, ("changes", "array", true, "List of change objects"), KEY] },
    Tool { name: "save_pending_changes", path: "/api/v1/mod/pending/save", kind: Kind::Post,
        description: "Save queued archive edits without applying them.",
        params: &[ARCHIVE, ("changes", "array", true, "List of change objects")] },
    Tool { name: "load_pending_changes", path: "/api/v1/mod/pending", kind: Kind::Get,
        description: "Load queued archive edits.", params: &[ARCHIVE] },
    Tool { name: "get_features", path: "/api/v1/features/get", kind: Kind::Post,
        description: "Read the features file from an archive as JSON.", params: &[ARCHIVE, KEY] },
    Tool { name: "save_features", path: "/api/v1/features/save", kind: Kind::Post,
        description: "Write the features file back into an archive.",
        params: &[ARCHIVE, ("features_json", "string", true, "Features as JSON text"), KEY] },
    Tool { name: "create_patch", path: "/api/v1/patch/create", kind: Kind::Post,
        description: "Build a patch archive from the difference of two folders.",
        params: &[("base_dir", "string", true, "Original folder"), ("modified_dir", "string", true, "Modified folder"),
            ("output", "string", true, "Patch archive to write"), KEY, ("iv", "integer", false, "Header IV")] },
    Tool { name: "nexon_login", path: "/api/v1/launcher/login", kind: Kind::Login,
        description: "Log in to Nexon and save the session on a profile. May answer mfa_required (then call nexon_login_otp) or captcha_required.",
        params: &[("email", "string", true, "Nexon account email"), ("password", "string", true, "Nexon password"), PROFILE] },
    Tool { name: "nexon_login_otp", path: "/api/v1/launcher/login/otp", kind: Kind::Login,
        description: "Finish a two-factor login with the code from the authenticator or email. May answer captcha_required like nexon_login.",
        params: &[("mfa_key", "string", true, "mfa_key from nexon_login"), ("otp", "string", true, "One-time code"),
            ("email", "string", false, "Account email, to name the profile"), PROFILE] },
    Tool { name: "nexon_login_tpa", path: "/api/v1/launcher/login/tpa", kind: Kind::Login,
        description: "Log in with a Steam/SSO TPA session.",
        params: &[("tpa_session", "string", true, "TPA session string"), PROFILE] },
    Tool { name: "nexon_session_check", path: "/api/v1/launcher/session/check", kind: Kind::Session,
        description: "Check (and refresh if needed) the saved Nexon session.", params: &[PROFILE] },
    Tool { name: "nexon_maintenance", path: "/api/v1/launcher/maintenance", kind: Kind::Session,
        description: "Whether Mabinogi is in maintenance.", params: &[PROFILE] },
    Tool { name: "nexon_version", path: "/api/v1/launcher/version", kind: Kind::Session,
        description: "Latest Mabinogi build from Nexon.", params: &[PROFILE] },
    Tool { name: "check_update", path: "/api/v1/launcher/update/check", kind: Kind::Session,
        description: "Compare the install with Nexon's current manifest.", params: &[PROFILE, GAME_PATH] },
    Tool { name: "update", path: "/api/v1/launcher/update", kind: Kind::Session,
        description: "Start patching the game in the background; poll update_status.",
        params: &[PROFILE, GAME_PATH, ("mode", "string", false, "update (default) | force | verify"),
            ("scan_only", "boolean", false, "Only list what would change"), ("max_workers", "integer", false, "Parallel files"),
            ("ignore", "array", false, "Glob patterns to leave alone")] },
    Tool { name: "update_status", path: "/api/v1/launcher/update/status", kind: Kind::Get,
        description: "Progress of the running update.", params: &[] },
    Tool { name: "update_cancel", path: "/api/v1/launcher/update/cancel", kind: Kind::Post,
        description: "Cancel the running update.", params: &[] },
    Tool { name: "update_pause", path: "/api/v1/launcher/update/pause", kind: Kind::Post,
        description: "Pause the running update (workers block before the next file).", params: &[] },
    Tool { name: "update_resume", path: "/api/v1/launcher/update/resume", kind: Kind::Post,
        description: "Resume a paused update.", params: &[] },
    Tool { name: "scan_update", path: "/api/v1/launcher/update/scan", kind: Kind::Session,
        description: "List the files that need updating (status New/SizeChanged/ContentChanged + size) without downloading.",
        params: &[PROFILE, GAME_PATH, ("mode", "string", false, "update (default) | force | verify"),
            ("ignore", "array", false, "Glob patterns to leave alone"),
            ("only", "array", false, "Allow-list: only consider these manifest paths"),
            ("product_id", "integer", false, "Nexon product id (default 10200)")] },
    Tool { name: "check_folders", path: "/api/v1/launcher/folders/check", kind: Kind::Session,
        description: "Check several game folders against the current manifest (up to date / update available).",
        params: &[PROFILE, ("folders", "array", false, "Game folder paths to check"),
            ("all_folders", "boolean", false, "Check every auto-detected install"),
            ("product_id", "integer", false, "Nexon product id (default 10200)")] },
    Tool { name: "get_config", path: "/api/v1/launcher/config", kind: Kind::Get,
        description: "Read the shared patcher config: the 4 hooks and the ignore list.", params: &[] },
    Tool { name: "set_config", path: "/api/v1/launcher/config", kind: Kind::Post,
        description: "Update the shared patcher config (hooks + ignore list); omitted fields keep their value.",
        params: &[("ignore", "array", false, "Ignore patterns"), ("hooks", "object", false, "before_patch/after_patch/before_launch/after_launch commands")] },
    Tool { name: "import_cookies", path: "/api/v1/launcher/import/cookies", kind: Kind::Login,
        description: "Import a Nexon session from the user's browsers (Firefox/Chrome/Edge/Brave) and save it to a profile. Reports v20_found when Chrome 127+ blocks decryption.",
        params: &[PROFILE] },
    Tool { name: "news", path: "/api/v1/launcher/news", kind: Kind::Get,
        description: "Nexon Mabinogi news feed (title, url, date, image).",
        params: &[("product_id", "integer", false, "Nexon product id (default 10200)")] },
    Tool { name: "launch", path: "/api/v1/launcher/launch", kind: Kind::Session,
        description: "Launch Mabinogi with the saved session (no Nexon launcher needed).",
        params: &[PROFILE, GAME_PATH, ("client_dir", "string", false, "Folder holding Client.exe"),
            ("client_exe", "string", false, "Client executable path")] },
    Tool { name: "profiles", path: "/api/v1/launcher/profiles", kind: Kind::Get,
        description: "Saved launcher profiles (no secrets).", params: &[] },
    Tool { name: "profile_save", path: "/api/v1/launcher/profile/save", kind: Kind::Post,
        description: "Create or update a profile.",
        params: &[("name", "string", true, "Profile name"), ("id", "string", false, "Existing profile id"),
            ("email", "string", true, "Account email"), ("client_dir", "string", false, "Game folder"),
            ("auto_login", "boolean", false, "Log in automatically")] },
    Tool { name: "profile_delete", path: "/api/v1/launcher/profile/delete", kind: Kind::Post,
        description: "Delete a profile.", params: &[("id", "string", true, "Profile id")] },
    Tool { name: "test_mod_for_crash", path: "", kind: Kind::Local,
        description: "One crash-test trial: extract the archive, drop entries matching the regexes, repack it in place, \
launch Mabinogi with the saved session and watch the Windows event log for a client.exe crash. \
Binary-search a broken mod by calling it with different remove_entries sets. Overwrites the archive; keep a backup. \
A .pack archive is rewritten as a MABI legacy pack (version 999) and its salt_used is a format marker such as LEGACY_PACK, not a salt.",
        params: &[ARCHIVE, ("remove_entries", "array", true, "Regexes; extracted entries whose path matches any are removed"), KEY,
            PROFILE, GAME_PATH, ("client_dir", "string", false, "Folder holding Client.exe"),
            ("survive_seconds", "integer", false, "How long the client must run without crashing (default 90)")] },
    Tool { name: "profile_activate", path: "/api/v1/launcher/profile/activate", kind: Kind::Post,
        description: "Make a profile the active one.", params: &[("id", "string", true, "Profile id")] },
];

/// Names of response fields that carry credentials; removed before results reach the client.
const SECRET_FIELDS: &[&str] = &["session", "session_token", "sessionToken", "access_token", "accessToken", "passport", "id_token", "nx_gun"];

fn tool_list() -> Value {
    let tools: Vec<Value> = TOOLS.iter().map(|t| {
        let mut props = Map::new();
        let mut required = Vec::new();
        for (name, ty, req, desc) in t.params {
            props.insert((*name).into(), json!({ "type": ty, "description": desc }));
            if *req { required.push(*name); }
        }
        json!({
            "name": t.name,
            "description": t.description,
            "inputSchema": { "type": "object", "properties": props, "required": required },
        })
    }).collect();
    json!({ "tools": tools })
}

fn strip_secrets(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for f in SECRET_FIELDS { m.remove(*f); }
            for x in m.values_mut() { strip_secrets(x); }
        }
        Value::Array(a) => a.iter_mut().for_each(strip_secrets),
        _ => {}
    }
}

struct Server {
    base: String,
    http: reqwest::blocking::Client,
}

impl Server {
    fn request(&self, tool: &Tool, args: &Value) -> Result<(u16, Value)> {
        let url = format!("{}{}", self.base, tool.path);
        let resp = if tool.kind == Kind::Get {
            let query: Vec<(String, String)> = args.as_object().into_iter().flatten()
                .map(|(k, v)| (k.clone(), v.as_str().map(String::from).unwrap_or_else(|| v.to_string())))
                .collect();
            self.http.get(&url).query(&query).send()?
        } else {
            self.http.post(&url).json(args).send()?
        };
        let status = resp.status().as_u16();
        let text = resp.text()?;
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Ok((status, body))
    }

    fn call(&self, name: &str, mut args: Value) -> Result<(bool, Value)> {
        let tool = TOOLS.iter().find(|t| t.name == name).ok_or_else(|| anyhow!("Unknown tool: {}", name))?;
        if !args.is_object() { args = json!({}); }
        if tool.kind == Kind::Local {
            return self.test_mod_for_crash(&args);
        }
        let profile_arg = args.get("profile").and_then(Value::as_str).map(String::from);

        let mut used_profile = None;
        if tool.kind == Kind::Session && args.get("session").is_none() {
            let (p, s) = cli::profile_session(profile_arg.as_ref())?;
            args["session"] = serde_json::to_value(&s)?;
            if args.get("game_path").is_none() && !p.client_dir.is_empty() {
                args["game_path"] = json!(p.client_dir);
            }
            used_profile = Some(p);
        }

        let (status, mut body) = self.request(tool, &args)?;
        let ok = status < 400;

        // Persist sessions before stripping them from the result.
        if ok {
            if let Some(s) = body.get("session").and_then(|v| serde_json::from_value::<NexonSession>(v.clone()).ok()) {
                let expires = body.get("expiresIn").and_then(Value::as_i64).unwrap_or(0) as i32;
                let saved = match (tool.kind, &used_profile) {
                    (Kind::Login, _) => {
                        let email = args.get("email").and_then(Value::as_str).unwrap_or("");
                        cli::store_session(profile_arg.as_ref(), email, &s, expires, None).map(|p| p.name)
                    }
                    (_, Some(p)) => profile::save_session(&p.id, &s, expires).map(|_| p.name.clone()),
                    _ => Err(anyhow!("no profile to save the session to")),
                };
                match saved {
                    Ok(name) => body["session_saved_to_profile"] = json!(name),
                    Err(e) => body["session_not_saved"] = json!(e.to_string()),
                }
            }
        }
        strip_secrets(&mut body);
        Ok((ok, json!({ "status": status, "result": body })))
    }

    /// Call a tool and fail unless it succeeded; returns its `result`.
    fn call_ok(&self, name: &str, args: Value) -> Result<Value> {
        let (ok, v) = self.call(name, args)?;
        if !ok {
            return Err(anyhow!("{} failed: {}", name, v["result"]));
        }
        Ok(v["result"].clone())
    }

    fn test_mod_for_crash(&self, args: &Value) -> Result<(bool, Value)> {
        let archive = args["archive"].as_str().ok_or_else(|| anyhow!("'archive' is required"))?;
        let patterns = args["remove_entries"].as_array().ok_or_else(|| anyhow!("'remove_entries' is required"))?
            .iter()
            .map(|p| p.as_str().ok_or_else(|| anyhow!("remove_entries must be strings")).and_then(|p| Ok(regex::Regex::new(p)?)))
            .collect::<Result<Vec<_>>>()?;
        let survive = args["survive_seconds"].as_u64().unwrap_or(90);
        if !cfg!(windows) {
            return Err(anyhow!("test_mod_for_crash reads the Windows event log, so it only runs on Windows"));
        }

        let tmp = std::env::temp_dir().join(format!("mabi_crashtest_{}_{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis()));
        let archive_path = std::path::Path::new(archive);
        let readonly = std::fs::metadata(archive_path)?.permissions().readonly();
        let set_readonly = |ro: bool| -> Result<()> {
            let mut perm = std::fs::metadata(archive_path)?.permissions();
            perm.set_readonly(ro);
            Ok(std::fs::set_permissions(archive_path, perm)?)
        };

        let trial = || -> Result<Value> {
            let mut extract = json!({ "archive": archive, "output": tmp.to_string_lossy() });
            if let Some(k) = args.get("key") { extract["key"] = k.clone(); }
            let extracted = self.call_ok("extract", extract)?;
            let key = extracted["salt_used"].as_str().ok_or_else(|| anyhow!("extract did not report the key it used"))?.to_string();

            let mut removed = 0usize;
            for entry in walkdir::WalkDir::new(&tmp).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_type().is_file()) {
                let rel = entry.path().strip_prefix(&tmp)?.to_string_lossy().replace('\\', "/");
                if patterns.iter().any(|p| p.is_match(&rel)) {
                    std::fs::remove_file(entry.path())?;
                    removed += 1;
                }
            }
            if removed == 0 {
                return Err(anyhow!("No extracted entries matched remove_entries; nothing to test"));
            }

            if readonly { set_readonly(false)?; }
            self.call_ok("pack", json!({ "source": tmp.to_string_lossy(), "output": archive, "key": key }))?;

            let mut launch = json!({});
            for f in ["profile", "game_path", "client_dir"] {
                if let Some(v) = args.get(f) { launch[f] = v.clone(); }
            }
            let started = std::time::Instant::now();
            self.call_ok("launch", launch)?;
            let event = watch_for_crash(started, survive)?;
            Ok(json!({
                "verdict": if event.is_some() { "crashed" } else { "survived" },
                "removed_count": removed,
                "event": event,
            }))
        };
        let result = trial();
        let _ = std::fs::remove_dir_all(&tmp);
        if readonly { let _ = set_readonly(true); }
        Ok((true, json!({ "status": 200, "result": result? })))
    }

    fn handle(&self, msg: &Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        // Notifications (no id) get no response.
        let id = id?;
        let result = match method {
            "initialize" => {
                let version = msg.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mabi-patcher", "version": env!("CARGO_PKG_VERSION") },
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tool_list()),
            "tools/call" => {
                let name = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
                let args = msg.pointer("/params/arguments").cloned().unwrap_or_else(|| json!({}));
                Ok(match self.call(name, args) {
                    Ok((ok, v)) => json!({
                        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
                        "isError": !ok,
                    }),
                    Err(e) => json!({ "content": [{ "type": "text", "text": e.to_string() }], "isError": true }),
                })
            }
            _ => Err(json!({ "code": -32601, "message": format!("Method not found: {}", method) })),
        };
        Some(match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
        })
    }
}

/// Poll the Application event log for an Event 1000 (application crash) naming
/// client.exe, newer than `since`, for up to `seconds`.
fn watch_for_crash(since: std::time::Instant, seconds: u64) -> Result<Option<Value>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        let window = since.elapsed().as_secs() + 5;
        let script = format!(
            "Get-WinEvent -FilterHashtable @{{LogName='Application'; Id=1000; StartTime=(Get-Date).AddSeconds(-{})}} \
             -ErrorAction SilentlyContinue | Where-Object {{ $_.Message -match 'client\\.exe' }} \
             | Select-Object -First 1 -Property TimeCreated, Message | ConvertTo-Json -Compress",
            window);
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(std::process::Stdio::null())
            .output()?;
        if let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) {
            return Ok(Some(v));
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    Ok(None)
}

/// Entry point shared by both executables: when the first argument is `mcp`,
/// serve MCP on stdio (logging to stderr only, since stdout carries the
/// protocol) and exit. Returns otherwise.
pub fn run_if_requested() {
    if std::env::args().nth(1).as_deref() != Some("mcp") {
        return;
    }
    use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
    let _ = TermLogger::init(LevelFilter::Warn, ConfigBuilder::new().build(), TerminalMode::Stderr, ColorChoice::Never);
    let code = match run_stdio() {
        Ok(()) => 0,
        Err(e) => { eprintln!("mcp: {}", e); 1 }
    };
    std::process::exit(code);
}

/// Run the MCP server on stdin/stdout until stdin closes.
pub fn run_stdio() -> Result<()> {
    let (port, stop) = crate::api::spawn_ephemeral()?;
    let server = Server {
        base: format!("http://127.0.0.1:{}", port),
        http: reqwest::blocking::Client::builder().timeout(None).build()?,
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) => {
                let r: Vec<Value> = batch.iter().filter_map(|m| server.handle(m)).collect();
                if r.is_empty() { None } else { Some(Value::Array(r)) }
            }
            Ok(msg) => server.handle(&msg),
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } })),
        };
        if let Some(r) = reply {
            writeln!(out, "{}", r)?;
            out.flush()?;
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_a_route_and_unique_name() {
        let api = include_str!("api.rs");
        let mut names = std::collections::HashSet::new();
        for t in TOOLS {
            assert!(names.insert(t.name), "duplicate tool {}", t.name);
            if t.kind == Kind::Local { continue; }
            assert!(api.contains(&format!("\"{}\")", t.path)), "no API route for {}", t.path);
        }
    }

    #[test]
    fn secrets_are_stripped_recursively() {
        let mut v = json!({ "session": {"a": 1}, "ok": true, "nested": [{ "session_token": "x", "keep": 1 }] });
        strip_secrets(&mut v);
        assert_eq!(v, json!({ "ok": true, "nested": [{ "keep": 1 }] }));
    }

    #[test]
    fn initialize_list_and_unknown_method() {
        let s = Server { base: "http://127.0.0.1:9".into(), http: reqwest::blocking::Client::new() };
        let init = s.handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}})).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(s.handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        let list = s.handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), TOOLS.len());
        let bad = s.handle(&json!({"jsonrpc":"2.0","id":3,"method":"nope"})).unwrap();
        assert_eq!(bad["error"]["code"], -32601);
    }

    #[test]
    fn tools_call_reaches_the_api() {
        let (port, stop) = crate::api::spawn_ephemeral().unwrap();
        let s = Server { base: format!("http://127.0.0.1:{}", port), http: reqwest::blocking::Client::new() };
        let r = s.handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}})).unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(r["result"]["isError"], false, "{}", r);
    }
}
