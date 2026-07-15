use mabi_pack2::{load_salts, extract, pack_v1, common_ext, pack, patch, encryption};
use encoding_rs::{WINDOWS_1252, SHIFT_JIS, EUC_KR, BIG5};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::path::{PathBuf, Path};
use tauri::{Manager, Emitter};
use log::{debug, info, warn};
use std::io::Write;
use std::sync::{Arc, Mutex};

struct LogFilePath(PathBuf);

// Buffer for log messages emitted before the JS listener is registered.
// Drained once when the frontend calls drain_log_buffer().
static FRONTEND_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PENDING_LOGS: std::sync::OnceLock<std::sync::Mutex<Vec<(String, String)>>> = std::sync::OnceLock::new();
fn pending_logs() -> &'static std::sync::Mutex<Vec<(String, String)>> {
    PENDING_LOGS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

struct TauriEventWriter {
    app_handle: tauri::AppHandle,
    buffer: Arc<Mutex<String>>,
}

impl Write for TauriEventWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.push_str(&String::from_utf8_lossy(buf));
        
        if buffer.contains('\n') {
            let parts: Vec<&str> = buffer.split('\n').collect();
            let last = parts.last().unwrap_or(&"").to_string();
            let remainder = last;
            
            for part in parts.iter().rev().skip(1).rev() {
                let trimmed = part.trim().to_string();
                if !trimmed.is_empty() {
                    let level = if trimmed.contains("ERROR") { "error" }
                                else if trimmed.contains("WARN") { "warn" }
                                else if trimmed.contains("DEBUG") { "debug" }
                                else if trimmed.contains("TRACE") { "trace" }
                                else { "info" };

                    if !FRONTEND_READY.load(std::sync::atomic::Ordering::Relaxed) {
                        if let Ok(mut buf) = pending_logs().lock() {
                            buf.push((trimmed.clone(), level.to_string()));
                        }
                    }

                    let handle = self.app_handle.clone();
                    let level_s = level.to_string();
                    tauri::async_runtime::spawn(async move {
                        let _ = handle.emit("log-message", serde_json::json!({
                            "message": trimmed,
                            "level": level_s
                        }));
                    });
                }
            }
            *buffer = remainder;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        if !buffer.is_empty() {
            let trimmed = buffer.trim().to_string();
            if !trimmed.is_empty() {
                let handle = self.app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = handle.emit("log-message", serde_json::json!({
                        "message": trimmed,
                        "level": "info"
                    }));
                });
            }
            buffer.clear();
        }
        Ok(())
    }
}

fn default_true() -> bool { true }
fn default_select_mode() -> String { "none".to_string() }
fn default_write_salt() -> String { "})wWb4?-sVGHNoPKpc".to_string() }
fn default_wrap_mode() -> String { "ask".to_string() }
fn default_pack_v1_version() -> u32 { 999 }

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    theme: String,
    locale: String,
    log_level: String,
    associate_it: bool,
    associate_pack: bool,
    associate_it_full: bool,
    startup_auto_extract: bool,
    startup_auto_switch: bool,
    salt_history: Vec<String>,
    last_key: String,
    region_key: String,
    suppress_admin_warning: bool,
    auto_convert_png: bool,
    auto_convert_dds: bool,
    list_full_sequence: bool,
    pack_wrap_data: bool,
    #[serde(default = "default_true")]
    list_auto_expand: bool,
    #[serde(default = "default_select_mode")]
    list_auto_select: String,
    #[serde(default)]
    startup_path: String,
    #[serde(default = "default_write_salt")]
    write_salt: String,
    #[serde(default)]
    audio_autoplay: bool,
    #[serde(default)]
    audio_loop: bool,
    #[serde(default = "default_wrap_mode")]
    pack_wrap_mode: String,
    #[serde(default)]
    associate_dds: bool,
    #[serde(default)]
    associate_pmg: bool,
    #[serde(default)]
    associate_xmlcompiled: bool,
    #[serde(default = "default_pack_v1_version")]
    pack_v1_version: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "neon-fog-dark".to_string(),
            locale: "en".to_string(),
            log_level: "error".to_string(),
            associate_it: true,
            associate_pack: false,
            associate_it_full: false,
            startup_auto_extract: true,
            startup_auto_switch: true,
            salt_history: vec!["@6QeTuOaDgJlZcBm#9".to_string()],
            last_key: "@6QeTuOaDgJlZcBm#9".to_string(),
            region_key: "data.it".to_string(),
            suppress_admin_warning: false,
            auto_convert_png: false,
            auto_convert_dds: false,
            list_full_sequence: false,
            pack_wrap_data: true,
            list_auto_expand: true,
            list_auto_select: "none".to_string(),
            startup_path: String::new(),
            write_salt: "})wWb4?-sVGHNoPKpc".to_string(),
            audio_autoplay: false,
            audio_loop: false,
            pack_wrap_mode: "ask".to_string(),
            associate_dds: false,
            associate_pmg: false,
            associate_xmlcompiled: false,
            pack_v1_version: 999,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AggregateEntry {
    pub name: String,
    pub source_archive: String,
    pub salt_used: String,
    pub entries_salt_used: String,
    pub size: u64,
    pub raw_size: u32,
    pub offset: u32,
    pub checksum: u32,
    pub flags: u32,
    pub iv0: u32,
    pub h_off: u64,
    pub mode: String, // "Sub" or "Xor"
}

struct FlushOnWrite<W: Write>(W);
impl<W: Write> Write for FlushOnWrite<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.0.write(buf)?;
        let _ = self.0.flush();
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.0.flush() }
}

fn init_logging(app: &tauri::AppHandle, level: &str) {
    let filter = match level.to_lowercase().as_str() {
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };

    let mut loggers: Vec<Box<dyn simplelog::SharedLogger>> = Vec::new();
    let config = simplelog::ConfigBuilder::new()
        .set_thread_level(log::LevelFilter::Off)
        .set_target_level(log::LevelFilter::Off)
        .set_location_level(log::LevelFilter::Off)
        .build();
    
    // Console
    loggers.push(simplelog::TermLogger::new(filter, config.clone(), simplelog::TerminalMode::Mixed, simplelog::ColorChoice::Auto));
    
    // UI Terminal
    let buffer = Arc::new(Mutex::new(String::new()));
    loggers.push(simplelog::WriteLogger::new(filter, config.clone(), TauriEventWriter { app_handle: app.clone(), buffer }));
    
    // Persistent log.txt next to the executable — always at Info so all activity is captured
    let log_path_result = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("log.txt")));
    if let Some(ref log_path) = log_path_result {
        match OpenOptions::new().append(true).create(true).open(log_path) {
            Ok(mut f) => {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0);
                let _ = writeln!(f, "\n========== mabi-pack2 started (unix={}) log={} ==========", secs, log_path.display());
                loggers.push(simplelog::WriteLogger::new(log::LevelFilter::Info, config, FlushOnWrite(f)));
            }
            Err(e) => eprintln!("[mabi-pack2] Cannot open log.txt at {:?}: {}", log_path, e),
        }
    }

    let _ = simplelog::CombinedLogger::init(loggers);

    // Store log path in app state so log_to_file command can append JS-side messages directly
    if let Some(log_path) = log_path_result {
        app.manage(LogFilePath(log_path));
    }
}

fn get_config_path(app: &tauri::AppHandle) -> PathBuf {
    let mut path = app.path().app_config_dir().unwrap_or_else(|_| {
        // Fallback to home dir .mabi-pack2
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".into())).join("mabi-pack2")
        }
        #[cfg(not(target_os = "windows"))]
        {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".mabi-pack2")
        }
    });
    
    let _ = fs::create_dir_all(&path);
    path.push("config.json");
    path
}

#[tauri::command]
fn get_config(app: tauri::AppHandle) -> Config {
    let path = get_config_path(&app);
    if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str(&content).unwrap_or_else(|_| Config::default())
    } else {
        Config::default()
    }
}

#[tauri::command]
fn save_config(app: tauri::AppHandle, config: Config) {
    let path = get_config_path(&app);
    if let Ok(content) = serde_json::to_string_pretty(&config) {
        let _ = fs::write(path, content);
    }
}

#[tauri::command]
fn set_config(app: tauri::AppHandle, config: Config) {
    // Keep max_level at Info so the file logger (always at Info) continues to receive messages
    // regardless of the UI log level the user selected.
    log::set_max_level(log::LevelFilter::Info);
    save_config(app, config);
}

#[tauri::command]
fn drain_log_buffer() -> Vec<(String, String)> {
    FRONTEND_READY.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut buf = pending_logs().lock().unwrap();
    std::mem::take(&mut *buf)
}

#[tauri::command]
fn log_to_file(app: tauri::AppHandle, level: String, message: String) {
    if let Some(state) = app.try_state::<LogFilePath>() {
        if let Ok(mut f) = OpenOptions::new().append(true).create(true).open(&state.0) {
            let _ = writeln!(f, "[UI][{}] {}", level.to_uppercase(), message);
            let _ = f.flush();
        }
    }
}

#[tauri::command]
fn is_ran_as_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::ptr;
        use winapi::um::processthreadsapi::OpenProcessToken;
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

        let mut token = ptr::null_mut();
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
                let mut elevation: winapi::um::winnt::TOKEN_ELEVATION = std::mem::zeroed();
                let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
                if GetTokenInformation(token, TokenElevation, &mut elevation as *mut _ as *mut _, size, &mut size) != 0 {
                    return elevation.TokenIsElevated != 0;
                }
            }
        }
    }
    false
}

#[tauri::command]
async fn register_associations(it: bool, pack: bool, it_full: bool, it_desc: String, pack_desc: String, it_full_desc: String, dds: bool, pmg: bool, xmlcompiled: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::RegKey;
        use winreg::enums::*;

        let is_admin = is_ran_as_admin();
        let root = if is_admin {
            RegKey::predef(HKEY_LOCAL_MACHINE)
        } else {
            RegKey::predef(HKEY_CURRENT_USER)
        };

        let base_path = "Software\\Classes";

        let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_str = exe_path.to_string_lossy();

        let icon_val = format!("\"{}\",0", exe_str);
        let open_cmd_val = format!("\"{}\" \"%1\"", exe_str);

        if it {
            let (key, _) = root.create_subkey(format!("{}\\.it", base_path)).map_err(|e| e.to_string())?;
            key.set_value("", &"mabi-pack2.archive").map_err(|e| e.to_string())?;
            let (prog_key, _) = root.create_subkey(format!("{}\\mabi-pack2.archive", base_path)).map_err(|e| e.to_string())?;
            prog_key.set_value("", &it_desc).map_err(|e| e.to_string())?;
            prog_key.set_value("DefaultIcon", &icon_val).map_err(|e| e.to_string())?;
            let (open_verb, _) = prog_key.create_subkey("shell\\open").map_err(|e| e.to_string())?;
            open_verb.set_value("", &it_desc).map_err(|e| e.to_string())?;
            open_verb.set_value("Icon", &icon_val).map_err(|e| e.to_string())?;
            let (open_cmd, _) = open_verb.create_subkey("command").map_err(|e| e.to_string())?;
            open_cmd.set_value("", &open_cmd_val).map_err(|e| e.to_string())?;

            if it_full {
                let (full_key, _) = prog_key.create_subkey("shell\\open_full").map_err(|e| e.to_string())?;
                full_key.set_value("", &it_full_desc).map_err(|e| e.to_string())?;
                full_key.set_value("Icon", &icon_val).map_err(|e| e.to_string())?;
                let (full_cmd_key, _) = full_key.create_subkey("command").map_err(|e| e.to_string())?;
                full_cmd_key.set_value("", &format!("\"{}\" \"%1\" --full", exe_str)).map_err(|e| e.to_string())?;
            } else {
                let _ = prog_key.delete_subkey_all("shell\\open_full");
            }
        }
        if pack {
            let (key, _) = root.create_subkey(format!("{}\\.pack", base_path)).map_err(|e| e.to_string())?;
            key.set_value("", &"mabi-pack2.archive.v1").map_err(|e| e.to_string())?;
            let (prog_key, _) = root.create_subkey(format!("{}\\mabi-pack2.archive.v1", base_path)).map_err(|e| e.to_string())?;
            prog_key.set_value("", &pack_desc).map_err(|e| e.to_string())?;
            prog_key.set_value("DefaultIcon", &icon_val).map_err(|e| e.to_string())?;
            let (open_verb, _) = prog_key.create_subkey("shell\\open").map_err(|e| e.to_string())?;
            open_verb.set_value("", &pack_desc).map_err(|e| e.to_string())?;
            open_verb.set_value("Icon", &icon_val).map_err(|e| e.to_string())?;
            let (open_cmd, _) = open_verb.create_subkey("command").map_err(|e| e.to_string())?;
            open_cmd.set_value("", &open_cmd_val).map_err(|e| e.to_string())?;
        }

        for (enabled, ext, progid, desc) in [
            (dds, ".dds", "mabi-pack2.dds", "Mabinogi DDS Texture"),
            (pmg, ".pmg", "mabi-pack2.pmg", "Mabinogi PMG Model"),
            (xmlcompiled, ".compiled", "mabi-pack2.compiled", "Mabinogi Compiled XML"),
        ] {
            if enabled {
                let (key, _) = root.create_subkey(format!("{}\\{}", base_path, ext)).map_err(|e| e.to_string())?;
                key.set_value("", &progid).map_err(|e| e.to_string())?;
                let (prog_key, _) = root.create_subkey(format!("{}\\{}", base_path, progid)).map_err(|e| e.to_string())?;
                prog_key.set_value("", &desc).map_err(|e| e.to_string())?;
                prog_key.set_value("DefaultIcon", &icon_val).map_err(|e| e.to_string())?;
                let (open_verb, _) = prog_key.create_subkey("shell\\open").map_err(|e| e.to_string())?;
                open_verb.set_value("", &desc).map_err(|e| e.to_string())?;
                open_verb.set_value("Icon", &icon_val).map_err(|e| e.to_string())?;
                let (open_cmd, _) = open_verb.create_subkey("command").map_err(|e| e.to_string())?;
                open_cmd.set_value("", &open_cmd_val).map_err(|e| e.to_string())?;
            }
        }

        #[link(name = "shell32")]
        extern "system" {
            fn SHChangeNotify(wEventId: i32, uFlags: u32, dwItem1: *const std::ffi::c_void, dwItem2: *const std::ffi::c_void);
        }
        const SHCNE_ASSOCCHANGED: i32 = 0x08000000;
        const SHCNF_IDLIST: u32 = 0x0000;

        unsafe {
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, std::ptr::null(), std::ptr::null());
        }
    }
    Ok(())
}

#[tauri::command]
fn request_elevation() {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::shellapi::ShellExecuteW;
        use winapi::um::winuser::SW_SHOWNORMAL;

        if let Ok(exe) = std::env::current_exe() {
            let args: Vec<String> = std::env::args().skip(1).collect();
            let args_str = args.join(" ");
            
            let operation: Vec<u16> = std::ffi::OsStr::new("runas").encode_wide().chain(Some(0)).collect();
            let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
            let parameters: Vec<u16> = std::ffi::OsStr::new(&args_str).encode_wide().chain(Some(0)).collect();

            unsafe {
                ShellExecuteW(
                    std::ptr::null_mut(),
                    operation.as_ptr(),
                    file.as_ptr(),
                    parameters.as_ptr(),
                    std::ptr::null(),
                    SW_SHOWNORMAL,
                );
            }
            std::process::exit(0);
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ArchiveDetails {
    pub file_count: u32,
    pub salt: String,
    pub iv0: u32,
    pub header_offset: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PackListResponse {
    pub entries: Vec<AggregateEntry>,
    pub details: ArchiveDetails,
}

#[tauri::command]
async fn list_sequence_contents(app: tauri::AppHandle, folder: String, key: Option<String>) -> Result<PackListResponse, String> {
    let f_path = if folder.is_empty() { ".".to_string() } else { folder };
    info!("[GUI] Listing sequence set in: {}", f_path);
    let config = get_config(app.clone());
    let salts = load_salts();
    let mut all_entries = Vec::new();

    if let Ok(paths) = fs::read_dir(&f_path) {
        let mut files: Vec<_> = paths.filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_lowercase();
                n.ends_with(".it") || n.ends_with(".pack")
            })
            .collect();
        files.sort_by_key(|e| e.file_name());
        let total = files.len();

        use tauri::Emitter;
        for (i, entry) in files.iter().enumerate() {
            let path = entry.path();
            let path_str = path.to_string_lossy().into_owned();
            let fname = entry.file_name().to_string_lossy().into_owned();
            let is_it = path_str.to_lowercase().ends_with(".it");

            let _ = app.emit("progress", ProgressPayload {
                current: i + 1,
                total,
                msg: format!("Scanning {} ({}/{})", fname, i + 1, total),
            });

            if is_it {
                let cli_key = if key.as_ref().map_or(true, |k| k.is_empty()) { None } else { key.clone() };
                if let Ok((entries, salt, entries_salt, iv0, h_off, mode, _c_off)) = common_ext::run_list_with_key_search_data(&path_str, cli_key, &salts, Some(config.region_key.clone())) {
                    let mode_str = match mode {
                        encryption::Snow2Mode::Sub => "Sub",
                        encryption::Snow2Mode::Xor => "Xor",
                        encryption::Snow2Mode::ModernBE => "ModernBE",
                        encryption::Snow2Mode::ModernLE => "ModernLE",
                        encryption::Snow2Mode::LegacyBE => "LegacyBE",
                        encryption::Snow2Mode::LegacyLE => "LegacyLE",
                    };
                    for e in entries {
                        all_entries.push(AggregateEntry {
                            name: e.name, source_archive: path_str.clone(), salt_used: salt.clone(), entries_salt_used: entries_salt.clone(),
                            size: e.original_size as u64, raw_size: e.raw_size,
                            offset: e.offset, checksum: e.checksum, flags: e.flags,
                            iv0, h_off, mode: mode_str.to_string(),
                        });
                    }
                }
            } else {
                if let Ok(entries) = pack_v1::run_list_v1_data(&path_str) {
                    for e in entries {
                        all_entries.push(AggregateEntry {
                            name: e.name, source_archive: path_str.clone(), salt_used: "N/A".into(), entries_salt_used: "N/A".into(),
                            size: e.original_size as u64, raw_size: e.raw_size,
                            offset: e.offset, checksum: e.checksum, flags: e.flags,
                            iv0: 0, h_off: 0, mode: "Sub".to_string(),
                        });
                    }
                }
            }
        }
    }

    // Deduplicate: archives were processed in ascending name order (data.it → data_001.it → data_002.it…)
    // so later entries overwrite earlier ones, meaning the highest-numbered archive's copy wins.
    // Normalize backslashes → forward slashes so duplicate entries with mixed separators collapse.
    let mut deduped: std::collections::HashMap<String, AggregateEntry> = std::collections::HashMap::new();
    for mut entry in all_entries {
        if entry.name.contains('\\') { entry.name = entry.name.replace('\\', "/"); }
        let key = entry.name.clone();
        deduped.insert(key, entry);
    }
    let mut all_entries: Vec<AggregateEntry> = deduped.into_values().collect();
    all_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let count = all_entries.len() as u32;
    Ok(PackListResponse {
        entries: all_entries,
        details: ArchiveDetails { file_count: count, salt: "SEQUENCE".into(), iv0: 0, header_offset: 0 }
    })
}

#[tauri::command]
async fn list_pack_contents(app: tauri::AppHandle, input: String, key: Option<String>) -> Result<PackListResponse, String> {
    info!("[GUI] Listing archive: {}", input);
    let config = get_config(app);
    let salts = load_salts();
    
    if input.to_lowercase().ends_with(".pack") { 
        match pack_v1::run_list_v1_data(&input) {
            Ok(data_entries) => {
                let entries = data_entries.into_iter().map(|e| AggregateEntry {
                    name: e.name, source_archive: input.clone(), salt_used: "N/A".into(), entries_salt_used: "N/A".into(),
                    size: e.original_size as u64, raw_size: e.raw_size, offset: e.offset, checksum: e.checksum, flags: e.flags,
                    iv0: 0, h_off: 0, mode: "Sub".to_string()
                }).collect::<Vec<_>>();
                let count = entries.len() as u32;
                return Ok(PackListResponse {
                    entries,
                    details: ArchiveDetails { file_count: count, salt: "UNENCRYPTED".into(), iv0: 0, header_offset: 0 }
                });
            },
            Err(e) => return Err(format!("Failed to list legacy .pack: {}", e))
        }
    }
    
    let cli_key = if key.as_ref().map_or(true, |k| k.is_empty()) { None } else { key };
    
    match common_ext::run_list_with_key_search_data(&input, cli_key, &salts, Some(config.region_key)) {
        Ok((entries, salt, entries_salt, iv0, h_off, mode, _c_off)) => {
            let mode_str = match mode {
                encryption::Snow2Mode::Sub => "Sub",
                encryption::Snow2Mode::Xor => "Xor",
                encryption::Snow2Mode::ModernBE => "ModernBE",
                encryption::Snow2Mode::ModernLE => "ModernLE",
                encryption::Snow2Mode::LegacyBE => "LegacyBE",
                encryption::Snow2Mode::LegacyLE => "LegacyLE",
            };
            let agg_entries: Vec<AggregateEntry> = entries.into_iter().map(|e| {
                let name = if e.name.contains('\\') { e.name.replace('\\', "/") } else { e.name };
                AggregateEntry {
                    name, source_archive: input.clone(), salt_used: salt.clone(), entries_salt_used: entries_salt.clone(),
                    size: e.original_size as u64, raw_size: e.raw_size,
                    offset: e.offset, checksum: e.checksum, flags: e.flags,
                    iv0, h_off, mode: mode_str.to_string(),
                }
            }).collect();
            let count = agg_entries.len() as u32;
            Ok(PackListResponse {
                entries: agg_entries,
                details: ArchiveDetails { file_count: count, salt, iv0, header_offset: h_off }
            })
        },
        Err(e) => Err(format!("Regional Unlock Failure: {}", e))
    }
}

#[derive(serde::Serialize, Clone)]
struct ProgressPayload {
    current: usize,
    total: usize,
    msg: String,
}

#[tauri::command]
fn check_data_folder(path: String) -> bool {
    let p = Path::new(&path);
    if p.file_name().map(|n| n.to_string_lossy().to_lowercase() == "data").unwrap_or(false) {
        return true;
    }
    if let Ok(entries) = fs::read_dir(p) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if entry.file_name().to_string_lossy().to_lowercase() == "data" {
                    return true;
                }
            }
        }
    }
    false
}

#[tauri::command]
fn detect_data_prefix(path: String) -> Option<String> {
    let normalized = path.replace('/', "\\");
    let lower = normalized.to_lowercase();
    // Match \data\ segment anywhere in the path
    if let Some(idx) = lower.find("\\data\\") {
        let from_data = &normalized[idx + 1..]; // "data\gfx\gui\..."
        return Some(from_data.trim_end_matches('\\').to_string());
    }
    // Path ends with \data (the selected folder itself is named "data")
    if lower.ends_with("\\data") || lower == "data" {
        return Some("data".to_string());
    }
    None
}

#[tauri::command]
async fn create_archive(app: tauri::AppHandle, input: String, output: String, key: String, formats: Vec<String>, iv: Option<u32>, path_prefix: Option<String>) -> Result<(), String> {
    let config = get_config(app.clone());
    let prefix = path_prefix.as_deref();
    info!("[GUI] Creating archive: {} -> {} (IV={:?}, Prefix={:?})", input, output, iv, prefix);
    let fmts: Vec<&str> = formats.iter().map(|s| s.as_str()).collect();
    let actual_iv = iv.unwrap_or(0);

    use tauri::Emitter;
    let app_clone = app.clone();
    let cb = move |current: usize, total: usize, msg: &str| {
        let _ = app_clone.emit("progress", ProgressPayload { current, total, msg: msg.to_string() });        
    };

    if let Some(parent) = Path::new(&output).parent() {
        let _ = fs::create_dir_all(parent);
    }

    if output.to_lowercase().ends_with(".pack") {
        pack_v1::run_pack_v1(&input, &output, config.pack_v1_version).map_err(|e: anyhow::Error| {
            log::error!("[GUI] .pack creation failed: {}", e);
            e.to_string()
        })
    } else {
        pack::run_pack(&input, &output, &key, fmts, config.auto_convert_dds, actual_iv, prefix, Some(&cb)).map_err(|e: anyhow::Error| {
            log::error!("[GUI] .it creation failed: {}", e);
            e.to_string()
        })
    }
}

#[tauri::command]
async fn extract_file_to(archive: String, entry: String, dest: String, key: Option<String>) -> Result<(), String> {
    if let Some(parent) = Path::new(&dest).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let (data, _iv0, _mode, _) = common_ext::get_entry_data(&archive, &entry, key).map_err(|e| e.to_string())?;
    std::fs::write(&dest, data).map_err(|e| e.to_string())
}

#[tauri::command]
async fn extract_pack_to(app: tauri::AppHandle, input: String, output: String, key: Option<String>, filters: Vec<String>) -> Result<(), String> {
    let config = get_config(app.clone());
    let salts = load_salts();
    use tauri::Emitter;
    let app_clone = app.clone();
    let cb = move |current: usize, total: usize, msg: &str| {
        let _ = app_clone.emit("progress", ProgressPayload { current, total, msg: msg.to_string() });        
    };

    let _ = fs::create_dir_all(&output);

    if input.to_lowercase().ends_with(".pack") {
        pack_v1::run_extract_v1(&input, &output).map_err(|e| format!("Legacy .pack extraction failed: {}", e))
    } else {
        extract::run_extract_with_key_search(&input, &output, key, &salts, filters, Some(config.region_key), config.auto_convert_png, Some(&cb)).map(|_| ()).map_err(|e| format!("Extraction failed: {}", e))
    }
}

fn try_decode_xml_compiled(data: &[u8]) -> Option<String> {
    fn r16(d: &[u8], p: usize) -> Option<u16> {
        if p + 2 > d.len() { return None; }
        Some(u16::from_le_bytes([d[p], d[p + 1]]))
    }
    fn r32(d: &[u8], p: usize) -> Option<u32> {
        if p + 4 > d.len() { return None; }
        Some(u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]]))
    }
    fn xdec(d: &[u8], pos: usize, len: usize) -> Option<String> {
        if pos + len > d.len() { return None; }
        let ok = d[pos..pos + len].iter().all(|&b| {
            let c = b ^ 0x80;
            c >= 0x20 && c <= 0x7E
        });
        if len > 0 && !ok { return None; }
        Some(d[pos..pos + len].iter().map(|&b| (b ^ 0x80) as char).collect())
    }
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    let mut pos = 0usize;
    let server_count = r16(data, pos)? as usize;
    pos += 2;
    if server_count == 0 || server_count > 200 { return None; }

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<features_compiled>\n");
    xml.push_str(&format!("  <servers count=\"{}\">\n", server_count));

    for _ in 0..server_count {
        let nl = r16(data, pos)? as usize; pos += 2;
        let name = xdec(data, pos, nl)?; pos += nl;
        let rl = r16(data, pos)? as usize; pos += 2;
        let region = xdec(data, pos, rl)?; pos += rl;
        let sid = r16(data, pos)?; pos += 2;
        if pos >= data.len() { return None; }
        let ch = data[pos]; pos += 1;
        xml.push_str(&format!(
            "    <server name=\"{}\" region=\"{}\" server_id=\"{}\" channel=\"{}\"/>\n",
            esc(&name), esc(&region), sid, ch
        ));
    }
    xml.push_str("  </servers>\n");

    let feature_count = r16(data, pos)? as usize;
    pos += 2;
    if feature_count > 100_000 { return None; }

    xml.push_str(&format!("  <features count=\"{}\">\n", feature_count));

    const LEN_THRESHOLD: usize = 500;
    for _ in 0..feature_count {
        let hash = r32(data, pos)?;
        pos += 4;
        let mut conds: Vec<String> = Vec::new();
        loop {
            if pos + 2 > data.len() { break; }
            let clen = r16(data, pos)? as usize;
            if clen > LEN_THRESHOLD { break; }
            // Check printability BEFORE advancing pos (mirrors Python: break, not error)
            if clen > 0 {
                if pos + 2 + clen > data.len() { break; }
                let printable = data[pos + 2..pos + 2 + clen].iter().all(|&b| {
                    let c = b ^ 0x80;
                    c >= 0x20 && c <= 0x7E
                });
                if !printable { break; }
            }
            pos += 2;
            let s: String = data[pos..pos + clen].iter().map(|&b| (b ^ 0x80) as char).collect();
            pos += clen;
            conds.push(s);
        }
        xml.push_str(&format!("    <feature hash=\"{:#010x}\">\n", hash));
        for (i, c) in conds.iter().enumerate() {
            if !c.is_empty() {
                xml.push_str(&format!("      <cond index=\"{}\">{}</cond>\n", i, esc(c)));
            }
        }
        xml.push_str("    </feature>\n");
    }
    xml.push_str("  </features>\n</features_compiled>\n");
    Some(xml)
}

fn decode_text_bytes(bytes: &[u8]) -> String {
    // Try UTF-8 first (no replacement chars = clean decode)
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    // Detect BOM / try common game encodings in order
    let encodings: &[&encoding_rs::Encoding] = &[SHIFT_JIS, EUC_KR, BIG5, WINDOWS_1252];
    for enc in encodings {
        let (cow, _, had_errors) = enc.decode(bytes);
        if !had_errors {
            return cow.into_owned();
        }
    }
    // Last resort: Latin-1 (every byte is a valid codepoint)
    bytes.iter().map(|&b| b as char).collect()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreviewData {
    pub name: String,
    pub size: u64,
    pub raw_size: u32,
    pub offset: u32,
    pub checksum: u32,
    pub flags: u32,
    pub file_key: Vec<u8>,
    pub file_type: String,
    pub content_text: Option<String>,
    pub content_image: Option<String>,
    pub raw_bytes: Vec<u8>,
    pub source: String,
    pub salt: String,
    pub full_preview_size: u64,
    pub truncated: bool,
    pub pmg_geometry: Option<PmgGeometry>,
}

#[tauri::command]
async fn get_preview_ext(
    archive_path: String,
    entry_name: String,
    key: Option<String>,
    entries_key: Option<String>,
    iv0: Option<u32>,
    h_off: Option<u64>,
    mode: Option<String>
) -> Result<PreviewData, String> {
    let actual_key = match key {
        Some(k) if k.is_empty() || k == "Search/Default" || k == "N/A" || k == "UNENCRYPTED" => None,
        Some(k) => Some(k),
        None => None,
    };
    let actual_entries_key = match entries_key {
        Some(k) if k.is_empty() || k == "Search/Default" || k == "N/A" || k == "UNENCRYPTED" => None,
        Some(k) => Some(k),
        None => None,
    };

    // Use provided metadata if available to bypass search
    let (mut raw_bytes, _discovered_iv0, _actual_mode, ent) = if let (Some(iv), Some(off), Some(m_str)) = (iv0, h_off, mode) {
        let m = match m_str.as_str() {
            "Xor"      => encryption::Snow2Mode::Xor,
            "ModernBE" => encryption::Snow2Mode::ModernBE,
            "ModernLE" => encryption::Snow2Mode::ModernLE,
            "LegacyBE" => encryption::Snow2Mode::LegacyBE,
            "LegacyLE" => encryption::Snow2Mode::LegacyLE,
            _          => encryption::Snow2Mode::Sub,
        };
        common_ext::get_entry_data_exact(&archive_path, &entry_name, actual_key.clone(), actual_entries_key.clone(), iv, off, m).map_err(|e| e.to_string())?
    } else {
        common_ext::get_entry_data(&archive_path, &entry_name, actual_key.clone()).map_err(|e| e.to_string())?
    };

    const MAX_HEX_BYTES: usize = 32 * 1024;         // 32 KB for hex view
    const MAX_AUDIO_BYTES: usize = 8 * 1024 * 1024; // 8 MB for audio playback
    const MAX_ADPCM_INPUT: usize = 2 * 1024 * 1024; // 2 MB ADPCM input → ~8 MB PCM

    let full_preview_size = raw_bytes.len() as u64;
    let file_type_str = common_ext::get_preview_ext(&entry_name).unwrap_or("unknown").to_string();

    let mut preview = PreviewData {
        name: entry_name.clone(),
        size: ent.original_size as u64,
        raw_size: ent.raw_size,
        offset: ent.offset,
        checksum: ent.checksum,
        flags: ent.flags,
        file_key: ent.key.to_vec(),
        file_type: file_type_str,
        content_text: None,
        content_image: None,
        raw_bytes: Vec::new(), // filled after processing below
        source: Path::new(&archive_path).file_name().unwrap_or_default().to_string_lossy().into(),
        salt: actual_key.as_deref().unwrap_or("Search/Default").into(),
        full_preview_size,
        truncated: false,
        pmg_geometry: None,
    };

    if preview.file_type == "image" {
        match common_ext::get_preview_base64_from_data(&entry_name, &raw_bytes) {
            Ok(b64) => { preview.content_image = Some(b64); },
            Err(e) => {
                warn!("[GUI] Image conversion failed for {}: {}", entry_name, e);
                preview.file_type = "error".to_string();
                preview.content_text = Some(format!("Image decode failed: {}", e));
            }
        }
    } else if preview.file_type == "text" {
        preview.content_text = Some(decode_text_bytes(&raw_bytes));
    } else if preview.file_type == "pmg" {
        match parse_pmg_bytes(&raw_bytes) {
            Ok(geo) => {
                info!("[PMG] {}  ·  {} verts  {} faces", if geo.mesh_name.is_empty() { &entry_name } else { &geo.mesh_name }, geo.vertex_count, geo.face_count);
                preview.pmg_geometry = Some(geo);
            },
            Err(e)  => {
                warn!("[GUI] PMG parse failed for {}: {}", entry_name, e);
                preview.content_text = Some(format!("PMG parse failed: {}", e));
            }
        }
        raw_bytes = Vec::new(); // geometry is in pmg_geometry; no need to ship raw bytes over IPC
    } else if preview.file_type == "audio" {
        if entry_name.to_lowercase().ends_with(".wav") {
            if raw_bytes.len() <= MAX_ADPCM_INPUT {
                if let Some(pcm_wav) = decode_ima_adpcm_wav(&raw_bytes) {
                    debug!("[GUI] ADPCM decoded {} → {} bytes for {}", raw_bytes.len(), pcm_wav.len(), entry_name);
                    raw_bytes = pcm_wav;
                }
                // else: PCM format, pass through unchanged
            } else if is_adpcm_wav(&raw_bytes) {
                // Large ADPCM: browser can't play ADPCM natively, don't send unplayable bytes
                let mb = raw_bytes.len() as f64 / 1_048_576.0;
                let msg = format!(
                    "ADPCM audio ({:.1} MB compressed) — too large for in-app preview. Extract and open externally.",
                    mb
                );
                warn!("[GUI] Audio {}: {}", entry_name, msg);
                preview.content_text = Some(msg);
                raw_bytes = Vec::new();
            }
            // else: large PCM WAV — send first 8 MB, browser handles it natively
        }
    } else if preview.file_type == "binary" && entry_name.to_lowercase().ends_with(".compiled") {
        if let Some(xml_text) = try_decode_xml_compiled(&raw_bytes) {
            preview.file_type = "text".to_string();
            preview.content_text = Some(xml_text);
            // keep raw_bytes so Hex View still shows the binary data
        }
    }

    // Cap raw_bytes transferred over IPC to avoid saturating the JSON bridge
    let limit = match preview.file_type.as_str() {
        "audio" => MAX_AUDIO_BYTES,
        "pmg"   => 0, // raw bytes cleared above; geometry is in pmg_geometry
        _       => MAX_HEX_BYTES,
    };
    if raw_bytes.len() > limit {
        preview.truncated = true;
        preview.raw_bytes = raw_bytes[..limit].to_vec();
    } else {
        preview.raw_bytes = raw_bytes;
    }

    debug!("[GUI] Preview for {} — {} bytes (truncated={})", entry_name, preview.full_preview_size, preview.truncated);
    Ok(preview)
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PmgGeometry {
    positions: Vec<f32>,
    normals: Vec<f32>,
    uvs: Vec<f32>,
    indices: Vec<u32>,
    mesh_name: String,
    texture_name: String,
    vertex_count: usize,
    face_count: usize,
}

/// Converts a triangle strip index list to a triangle list.
/// Degenerate triangles (repeated indices) are skipped.
fn strip_to_triangles(strip: &[u16]) -> Vec<u16> {
    let mut tris = Vec::new();
    for i in 0..strip.len().saturating_sub(2) {
        let (a, b, c) = (strip[i], strip[i + 1], strip[i + 2]);
        if a == b || b == c || a == c { continue; }
        if i % 2 == 0 {
            tris.extend_from_slice(&[a, b, c]);
        } else {
            tris.extend_from_slice(&[b, a, c]); // swap to preserve winding
        }
    }
    tris
}

fn parse_pmg_bytes(data: &[u8]) -> Result<PmgGeometry, String> {
    use mabi_pack2::pmg::PmgFile;
    if data.is_empty() {
        return Err("Empty file (0 bytes — stub entry)".to_string());
    }
    let pmg = PmgFile::parse(data).map_err(|e| e.to_string())?;
    // Accept LODs with face_indices OR strip_indices; pick highest vertex count
    let lod = pmg.groups.iter()
        .flat_map(|g| g.lods.iter())
        .filter(|l| !l.vertices.is_empty() && (!l.face_indices.is_empty() || !l.strip_indices.is_empty()))
        .max_by_key(|l| l.vertices.len())
        .ok_or_else(|| {
            let total: usize = pmg.groups.iter().flat_map(|g| g.lods.iter()).map(|l| l.vertices.len()).sum();
            format!("No renderable LOD ({} groups, {} total verts, {} submeshes)",
                pmg.groups.len(),
                total,
                pmg.groups.iter().map(|g| g.lods.len()).sum::<usize>())
        })?;
    // Pass raw local-space positions — Three.js geometry.center() will normalize placement
    let mut positions = Vec::with_capacity(lod.vertices.len() * 3);
    let mut uvs       = Vec::with_capacity(lod.vertices.len() * 2);
    for v in &lod.vertices {
        positions.extend_from_slice(&[v.x, v.y, v.z]);
        uvs.extend_from_slice(&[v.u, 1.0 - v.v]);
    }
    // Prefer face_indices (triangle list); fall back to strip_indices converted to triangles
    let indices: Vec<u32> = if !lod.face_indices.is_empty() {
        lod.face_indices.iter().map(|&i| i as u32).collect()
    } else {
        strip_to_triangles(&lod.strip_indices).iter().map(|&i| i as u32).collect()
    };
    let face_count = indices.len() / 3;
    Ok(PmgGeometry {
        positions,
        normals: Vec::new(), // computed by Three.js computeVertexNormals()
        uvs,
        indices,
        mesh_name: lod.mesh_name.clone(),
        texture_name: lod.texture_name.clone(),
        vertex_count: lod.vertices.len(),
        face_count,
    })
}

#[tauri::command]
fn parse_pmg_geometry(bytes: Vec<u8>) -> Result<PmgGeometry, String> {
    parse_pmg_bytes(&bytes)
}

/// Checks if a WAV buffer uses IMA ADPCM (format 0x0011) without fully decoding it.
fn is_adpcm_wav(data: &[u8]) -> bool {
    if data.len() < 12 { return false; }
    if &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" { return false; }
    let mut pos = 12usize;
    while pos + 8 <= data.len() {
        let csz = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]) as usize;
        if &data[pos..pos+4] == b"fmt " && pos + 10 <= data.len() {
            return u16::from_le_bytes([data[pos+8], data[pos+9]]) == 0x0011;
        }
        pos = pos.saturating_add(8 + ((csz + 1) & !1));
    }
    false
}

fn decode_adpcm_nibble(nibble: u8, predictor: &mut i32, step_index: &mut i32) -> i16 {
    const STEP_TABLE: [i32; 89] = [7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,118,130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,876,963,1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,15289,16818,18500,20350,22385,24623,27086,29794,32767];
    const INDEX_TABLE: [i32; 16] = [-1,-1,-1,-1,2,4,6,8,-1,-1,-1,-1,2,4,6,8];
    let step = STEP_TABLE[(*step_index).clamp(0, 88) as usize];
    let mut diff = step >> 3;
    if nibble & 4 != 0 { diff += step; }
    if nibble & 2 != 0 { diff += step >> 1; }
    if nibble & 1 != 0 { diff += step >> 2; }
    if nibble & 8 != 0 { diff = -diff; }
    *predictor = (*predictor + diff).clamp(-32768, 32767);
    *step_index = (*step_index + INDEX_TABLE[(nibble & 0xF) as usize]).clamp(0, 88);
    *predictor as i16
}

/// Decodes a Microsoft IMA ADPCM WAV (fmt format 0x0011) to 16-bit PCM WAV.
/// Scans RIFF chunks so it handles files with JUNK/INFO/fact chunks before data.
/// Returns None if the input is not IMA ADPCM or is malformed.
fn decode_ima_adpcm_wav(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 20 { return None; }
    if &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" { return None; }

    // Scan all RIFF sub-chunks for "fmt " and "data"
    let mut pos = 12usize;
    let mut fmt_off: Option<usize> = None;
    let mut data_offset: usize = 0;
    let mut data_size:   usize = 0;
    while pos + 8 <= data.len() {
        let tag = &data[pos..pos+4];
        let csz = u32::from_le_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]) as usize;
        let body = pos + 8;
        if tag == b"fmt " && fmt_off.is_none() { fmt_off = Some(body); }
        if tag == b"data" && data_size == 0    {
            data_offset = body;
            data_size   = csz.min(data.len().saturating_sub(body));
        }
        // RIFF chunks are word-aligned (odd sizes get a pad byte)
        pos = pos.checked_add(8 + ((csz + 1) & !1))?;
    }

    let fmt = fmt_off?;
    if fmt + 14 > data.len() || data_size == 0 { return None; }
    if u16::from_le_bytes([data[fmt],   data[fmt+1]])  != 0x0011 { return None; }
    let channels    = u16::from_le_bytes([data[fmt+2],  data[fmt+3]])  as usize;
    let sample_rate = u32::from_le_bytes([data[fmt+4],  data[fmt+5],  data[fmt+6],  data[fmt+7]]);
    let block_align = u16::from_le_bytes([data[fmt+12], data[fmt+13]]) as usize;
    if channels == 0 || block_align < 4 * channels { return None; }

    let data_offset = data_offset;
    let data_size   = data_size;

    let compressed = &data[data_offset .. data_offset + data_size];
    let mut pcm: Vec<i16> = Vec::new();

    for block in compressed.chunks(block_align) {
        if block.len() < 4 * channels { break; }
        let mut predictors = vec![0i32; channels];
        let mut step_idx   = vec![0i32; channels];
        for c in 0..channels {
            let b = c * 4;
            predictors[c] = i16::from_le_bytes([block[b], block[b+1]]) as i32;
            step_idx[c]   = (block[b+2] as i32).clamp(0, 88);
            // block[b+3] reserved
        }
        // Emit the header sample for each channel (interleaved)
        for c in 0..channels { pcm.push(predictors[c] as i16); }

        let payload = &block[4 * channels..];
        if channels == 1 {
            for &byte in payload {
                pcm.push(decode_adpcm_nibble(byte & 0xF, &mut predictors[0], &mut step_idx[0]));
                pcm.push(decode_adpcm_nibble(byte >> 4,  &mut predictors[0], &mut step_idx[0]));
            }
        } else {
            // Stereo: alternating 4-byte (8-sample) groups per channel
            let group = 4;
            let mut i = 0;
            while i + group * channels <= payload.len() {
                let mut bufs: Vec<Vec<i16>> = vec![Vec::with_capacity(8); channels];
                for c in 0..channels {
                    for &byte in &payload[i + c*group .. i + c*group + group] {
                        bufs[c].push(decode_adpcm_nibble(byte & 0xF, &mut predictors[c], &mut step_idx[c]));
                        bufs[c].push(decode_adpcm_nibble(byte >> 4,  &mut predictors[c], &mut step_idx[c]));
                    }
                }
                let n = bufs[0].len();
                for s in 0..n { for c in 0..channels { pcm.push(bufs[c][s]); } }
                i += group * channels;
            }
        }
    }

    if pcm.is_empty() { return None; }

    // Rebuild as standard 16-bit PCM WAV
    let pcm_bytes: Vec<u8> = pcm.iter().flat_map(|&s| s.to_le_bytes()).collect();
    let data_len  = pcm_bytes.len() as u32;
    let byte_rate = (sample_rate * channels as u32 * 2) as u32;
    let blk_out   = (channels * 2) as u16;
    let mut wav = Vec::with_capacity(44 + pcm_bytes.len());
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&(channels as u16).to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&blk_out.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(&pcm_bytes);
    Some(wav)
}

#[tauri::command]
async fn create_patch(_app: tauri::AppHandle, base: String, modified: String, output: String, key: String) -> Result<(), String> {
    patch::create_patch(&base, &modified, &output, &key, 1).map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_convert(input: String, output: String, key: Option<String>, wrap_data: Option<bool>) -> Result<(), String> {
    common_ext::convert(&input, &output, key, wrap_data.unwrap_or(false)).map_err(|e| e.to_string())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub net_down_kbps: u64,
    pub net_up_kbps: u64,
    pub net_link_max_kbps: u64,
    pub disk_used_gb: f64,
    pub disk_total_gb: f64,
}

use once_cell::sync::Lazy;
use sysinfo::{System, Networks, Disks};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static CPU_UTIL_CENTS: AtomicU32 = AtomicU32::new(0); // % * 100, written by PDH background thread
static NET_LINK_MAX_KBPS: AtomicU64 = AtomicU64::new(125_000); // KB/s, written once at startup

struct StatsState {
    sys: System,
    nets: Networks,
    net_down_kbps: u64,
    net_up_kbps: u64,
    disk_used_gb: f64,
    disk_total_gb: f64,
    disk_tick: u8,
}

static STATS: Lazy<Mutex<StatsState>> = Lazy::new(|| {
    let mut sys = System::new();
    sys.refresh_memory();
    let nets = Networks::new_with_refreshed_list();
    let (used, total) = disk_space_gb();
    Mutex::new(StatsState {
        sys, nets,
        net_down_kbps: 0, net_up_kbps: 0,
        disk_used_gb: used, disk_total_gb: total, disk_tick: 0,
    })
});

/// Read CPU % Processor Utility via typeperf -sc 1 (matches Task Manager, frequency-adjusted).
/// Blocks ~1 s while typeperf collects one sample.
fn read_cpu_pct() -> Option<f32> {
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut cmd = std::process::Command::new("typeperf");
    cmd.args([r"\Processor Information(_Total)\% Processor Utility", "-sc", "1"]);
    cmd.current_dir(std::env::temp_dir()); // output.csv goes to %TEMP%, not cwd
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Output has a leading blank line before the CSV header, so find the data line explicitly:
    // it starts with a quoted timestamp and is not the header "(PDH-CSV..." line.
    let data = text.lines()
        .find(|l| l.starts_with('"') && l.contains(',') && !l.starts_with("\"(PDH"))?;
    let mut fields = data.split(',');
    fields.next()?; // skip timestamp
    let val: f64 = fields.next()?.trim().trim_matches('"').parse().ok()?;
    Some(val.max(0.0).min(100.0) as f32)
}

/// Runs once in a background thread — detects adapter link speed via PowerShell.
/// Stored in NET_LINK_MAX_KBPS atomic; JS reads it from get_system_info response.
fn start_net_link_detect_thread() {
    std::thread::spawn(|| {
        #[cfg(windows)]
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut cmd = std::process::Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command",
                  "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Measure-Object -Property Speed -Sum).Sum"]);
        cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
        #[cfg(windows)] cmd.creation_flags(CREATE_NO_WINDOW);
        if let Ok(out) = cmd.output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(bits) = s.parse::<u64>() {
                if bits > 0 { NET_LINK_MAX_KBPS.store(bits / 8 / 1024, Ordering::Relaxed); }
            }
        }
    });
}

fn disk_space_gb() -> (f64, f64) {
    let disks = Disks::new_with_refreshed_list();
    disks.iter().filter(|d| !d.is_removable() && d.total_space() > 0)
        .fold((0.0, 0.0), |(u, t), d| (
            u + (d.total_space().saturating_sub(d.available_space())) as f64 / 1_073_741_824.0,
            t + d.total_space() as f64 / 1_073_741_824.0,
        ))
}

pub fn start_stats_refresher() {
    drop(STATS.lock()); // Force Lazy init
    start_net_link_detect_thread();
    std::thread::spawn(|| {
        const INTERVAL_MS: u64 = 2000;

        std::thread::sleep(std::time::Duration::from_millis(INTERVAL_MS));
        loop {
            if let Some(pct) = read_cpu_pct() {
                CPU_UTIL_CENTS.store((pct * 100.0) as u32, Ordering::Relaxed);
            }

            if let Ok(mut s) = STATS.lock() {
                s.sys.refresh_memory();
                s.nets.refresh(false);
                let down: u64 = s.nets.iter().map(|(_, d)| d.received()).sum();
                let up:   u64 = s.nets.iter().map(|(_, d)| d.transmitted()).sum();
                s.net_down_kbps = down * 1000 / (INTERVAL_MS * 1024);
                s.net_up_kbps   = up   * 1000 / (INTERVAL_MS * 1024);
                s.disk_tick = s.disk_tick.wrapping_add(1);
                if s.disk_tick % 5 == 0 {
                    let (u, t) = disk_space_gb();
                    s.disk_used_gb = u; s.disk_total_gb = t;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(INTERVAL_MS));
        }
    });
}

#[tauri::command]
async fn get_system_info() -> SystemStats {
    let s = STATS.lock().unwrap();
    SystemStats {
        cpu_usage: CPU_UTIL_CENTS.load(Ordering::Relaxed) as f32 / 100.0,
        memory_used_mb: s.sys.used_memory() / 1024 / 1024,
        memory_total_mb: s.sys.total_memory() / 1024 / 1024,
        net_down_kbps: s.net_down_kbps,
        net_up_kbps: s.net_up_kbps,
        net_link_max_kbps: NET_LINK_MAX_KBPS.load(Ordering::Relaxed),
        disk_used_gb: s.disk_used_gb,
        disk_total_gb: s.disk_total_gb,
    }
}

#[tauri::command]
fn get_app_exe_dir() -> String {
    std::env::current_exe().ok() 
        .and_then(|p| p.parent().map(|par| par.to_string_lossy().into_owned()))
        .unwrap_or_else(|| ".".into())
}

#[tauri::command]
fn get_all_salts() -> Vec<String> {
    load_salts()
}

#[tauri::command]
async fn open_log_file() -> Result<(), String> {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let log_path = exe_dir.join("log.txt");
            if log_path.exists() {
                #[cfg(target_os = "windows")]
                let _ = std::process::Command::new("notepad.exe").arg(log_path).spawn();
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn execute_terminal_command(command: String) -> Result<String, String> {
    info!("[CONSOLE] Executing: {}", command);
    let output = if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(&["/C", &command])
            .output()
    } else {
        std::process::Command::new("sh")
            .args(&["-c", &command])
            .output()
    };
    
    match output {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).into_owned();
            let e = String::from_utf8_lossy(&out.stderr).into_owned();
            Ok(format!("{}{}", s, e))
        },
        Err(err) => Err(format!("Spawn error: {}", err))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct InitialFile {
    pub path: String,
    pub full_sequence: bool,
}

#[tauri::command]
fn get_initial_file() -> Option<InitialFile> {
    let args: Vec<String> = std::env::args().collect();
    let mut path = None;
    let mut full_sequence = false;
    
    for arg in args.iter().skip(1) {
        if arg == "--full" {
            full_sequence = true;
        } else if Path::new(arg).exists() {
            path = Some(arg.clone());
        }
    }
    
    path.map(|p| InitialFile { path: p, full_sequence })
}

fn version_to_u64(v: &str) -> u64 {
    let parts: Vec<u64> = v.split('.').filter_map(|p| p.parse().ok()).collect();
    parts.get(0).copied().unwrap_or(0) * 1_000_000
        + parts.get(1).copied().unwrap_or(0) * 1_000
        + parts.get(2).copied().unwrap_or(0)
}

fn auto_register_associations_silent(config: &Config) {
    if !config.associate_it && !config.associate_pack && !config.associate_dds && !config.associate_pmg && !config.associate_xmlcompiled { return; }
    #[cfg(target_os = "windows")]
    {
        use winreg::RegKey;
        use winreg::enums::*;

        let current_ver = env!("CARGO_PKG_VERSION");
        let current_ver_num = version_to_u64(current_ver);

        // Skip if a newer version is already registered (prefer newer release)
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey("Software\\Classes\\mabi-pack2.archive") {
            if let Ok(reg_ver) = key.get_value::<String, _>("AppVersion") {
                if version_to_u64(&reg_ver) > current_ver_num {
                    return;
                }
            }
        }

        let exe_path = match std::env::current_exe() { Ok(p) => p, Err(_) => return };
        let exe_str = exe_path.to_string_lossy();
        let icon_val = format!("\"{}\",0", exe_str);
        let base = "Software\\Classes";

        if config.associate_it {
            if let Ok((k, _)) = hkcu.create_subkey(format!("{}\\.it", base)) {
                let _ = k.set_value("", &"mabi-pack2.archive");
            }
            if let Ok((pk, _)) = hkcu.create_subkey(format!("{}\\mabi-pack2.archive", base)) {
                let _ = pk.set_value("", &"Mabinogi Archive (.it)");
                let _ = pk.set_value("DefaultIcon", &icon_val);
                let _ = pk.set_value("AppVersion", &current_ver.to_string());
                if let Ok((ov, _)) = pk.create_subkey("shell\\open") {
                    let _ = ov.set_value("", &"Open with mabi-pack2");
                    let _ = ov.set_value("Icon", &icon_val);
                    if let Ok((oc, _)) = ov.create_subkey("command") {
                        let _ = oc.set_value("", &format!("\"{}\" \"%1\"", exe_str));
                    }
                }
                if config.associate_it_full {
                    if let Ok((fk, _)) = pk.create_subkey("shell\\open_full") {
                        let _ = fk.set_value("", &"Open as Full .it Sequence Set");
                        let _ = fk.set_value("Icon", &icon_val);
                        if let Ok((fc, _)) = fk.create_subkey("command") {
                            let _ = fc.set_value("", &format!("\"{}\" \"%1\" --full", exe_str));
                        }
                    }
                } else {
                    let _ = pk.delete_subkey_all("shell\\open_full");
                }
            }
        }
        if config.associate_pack {
            if let Ok((k, _)) = hkcu.create_subkey(format!("{}\\.pack", base)) {
                let _ = k.set_value("", &"mabi-pack2.archive.v1");
            }
            if let Ok((pk, _)) = hkcu.create_subkey(format!("{}\\mabi-pack2.archive.v1", base)) {
                let _ = pk.set_value("", &"Mabinogi Archive (.pack)");
                let _ = pk.set_value("DefaultIcon", &icon_val);
                if let Ok((ov, _)) = pk.create_subkey("shell\\open") {
                    let _ = ov.set_value("", &"Open with mabi-pack2");
                    let _ = ov.set_value("Icon", &icon_val);
                    if let Ok((oc, _)) = ov.create_subkey("command") {
                        let _ = oc.set_value("", &format!("\"{}\" \"%1\"", exe_str));
                    }
                }
            }
        }

        for (enabled, ext, progid, desc) in [
            (config.associate_dds, ".dds", "mabi-pack2.dds", "Mabinogi DDS Texture"),
            (config.associate_pmg, ".pmg", "mabi-pack2.pmg", "Mabinogi PMG Model"),
            (config.associate_xmlcompiled, ".compiled", "mabi-pack2.compiled", "Mabinogi Compiled XML"),
        ] {
            if enabled {
                if let Ok((k, _)) = hkcu.create_subkey(format!("{}\\{}", base, ext)) {
                    let _ = k.set_value("", &progid);
                }
                if let Ok((pk, _)) = hkcu.create_subkey(format!("{}\\{}", base, progid)) {
                    let _ = pk.set_value("", &desc);
                    let _ = pk.set_value("DefaultIcon", &icon_val);
                    if let Ok((ov, _)) = pk.create_subkey("shell\\open") {
                        let _ = ov.set_value("", &"Open with mabi-pack2");
                        let _ = ov.set_value("Icon", &icon_val);
                        if let Ok((oc, _)) = ov.create_subkey("command") {
                            let _ = oc.set_value("", &format!("\"{}\" \"%1\"", exe_str));
                        }
                    }
                }
            }
        }

        #[link(name = "shell32")]
        extern "system" {
            fn SHChangeNotify(wEventId: i32, uFlags: u32, dwItem1: *const std::ffi::c_void, dwItem2: *const std::ffi::c_void);
        }
        unsafe { SHChangeNotify(0x08000000, 0x0000, std::ptr::null(), std::ptr::null()); }
    }
}

#[tauri::command]
async fn preview_loose_file(path: String) -> Result<PreviewData, String> {
    let file_path = Path::new(&path);
    let entry_name = file_path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    let mut raw_bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    let file_size = raw_bytes.len() as u64;
    let file_type_str = common_ext::get_preview_ext(&entry_name).unwrap_or("unknown").to_string();

    const MAX_HEX_BYTES: usize = 32 * 1024;
    const MAX_AUDIO_BYTES: usize = 8 * 1024 * 1024;
    const MAX_ADPCM_INPUT: usize = 2 * 1024 * 1024;

    let mut preview = PreviewData {
        name: entry_name.clone(),
        size: file_size,
        raw_size: 0,
        offset: 0,
        checksum: 0,
        flags: 0,
        file_key: Vec::new(),
        file_type: file_type_str,
        content_text: None,
        content_image: None,
        raw_bytes: Vec::new(),
        source: "Loose File".to_string(),
        salt: "N/A".to_string(),
        full_preview_size: file_size,
        truncated: false,
        pmg_geometry: None,
    };

    if preview.file_type == "image" {
        match common_ext::get_preview_base64_from_data(&entry_name, &raw_bytes) {
            Ok(b64) => { preview.content_image = Some(b64); },
            Err(e) => {
                warn!("[GUI] Loose image conversion failed for {}: {}", entry_name, e);
                preview.file_type = "error".to_string();
                preview.content_text = Some(format!("Image decode failed: {}", e));
            }
        }
    } else if preview.file_type == "text" {
        preview.content_text = Some(decode_text_bytes(&raw_bytes));
    } else if preview.file_type == "pmg" {
        match parse_pmg_bytes(&raw_bytes) {
            Ok(geo) => { preview.pmg_geometry = Some(geo); },
            Err(e) => { preview.content_text = Some(format!("PMG parse failed: {}", e)); }
        }
        raw_bytes = Vec::new();
    } else if preview.file_type == "audio" {
        if entry_name.to_lowercase().ends_with(".wav") {
            if raw_bytes.len() <= MAX_ADPCM_INPUT {
                if let Some(pcm_wav) = decode_ima_adpcm_wav(&raw_bytes) {
                    raw_bytes = pcm_wav;
                }
            } else if is_adpcm_wav(&raw_bytes) {
                let mb = raw_bytes.len() as f64 / 1_048_576.0;
                preview.content_text = Some(format!(
                    "ADPCM audio ({:.1} MB compressed) — too large for in-app preview. Extract and open externally.", mb
                ));
                raw_bytes = Vec::new();
            }
        }
    } else if preview.file_type == "binary" && entry_name.to_lowercase().ends_with(".compiled") {
        if let Some(xml_text) = try_decode_xml_compiled(&raw_bytes) {
            preview.file_type = "text".to_string();
            preview.content_text = Some(xml_text);
            // keep raw_bytes so Hex View still shows the binary data
        }
    }

    let limit = match preview.file_type.as_str() {
        "audio" => MAX_AUDIO_BYTES,
        "pmg"   => 0,
        _       => MAX_HEX_BYTES,
    };
    if raw_bytes.len() > limit {
        preview.truncated = true;
        preview.raw_bytes = raw_bytes[..limit].to_vec();
    } else {
        preview.raw_bytes = raw_bytes;
    }

    Ok(preview)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = app.handle();
            let config = get_config(handle.clone());
            init_logging(&handle, &config.log_level);
            warn!("[GUI] mabi-pack2 started, log_level={}", config.log_level);
            start_stats_refresher();
            auto_register_associations_silent(&config);

            // Handle CLI arguments (e.g. drag and drop onto EXE)
            let args: Vec<String> = std::env::args().collect();
            let full_sequence = args.contains(&"--full".to_string());
            for arg in args.iter().skip(1) {
                if arg != "--gui" && arg != "--full" && Path::new(arg).exists() {
                    debug!("[GUI] Auto-loading CLI argument: {} (full={})", arg, full_sequence);
                    use tauri::Emitter;
                    let _ = handle.emit("open-file", InitialFile { path: arg.clone(), full_sequence });
                    break;
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_pack_contents, create_archive, extract_pack_to,
            extract_file_to, create_patch, list_sequence_contents,
            get_preview_ext, parse_pmg_geometry, get_config, set_config,
            get_system_info, run_convert, get_app_exe_dir, open_log_file,
            get_all_salts, is_ran_as_admin, register_associations, request_elevation,
            execute_terminal_command, get_initial_file, check_data_folder, detect_data_prefix, log_to_file, drain_log_buffer,
            preview_loose_file
        ])

        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
