use mabi_pack2::{api, load_salts, extract, mod_file, pack_v1, common_ext, pack, patch, encryption, rgn as rgn_lib};

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



fn default_hyddwn_url() -> String { "http://127.0.0.1:11000".to_string() }

fn default_max_workers() -> u32 { 10 }



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

    #[serde(default)]

    sequence_ignore_list: Vec<String>,

    #[serde(default)]

    auto_convert_features: bool,

    #[serde(default)]

    auto_convert_pmg: bool,

    #[serde(default)]

    theme_overrides: serde_json::Value,

    #[serde(default)]

    custom_themes: serde_json::Value,

    #[serde(default)]

    kanan_cfg_path: String,

    #[serde(default)]

    patcher_game_path: String,

    #[serde(default)]

    patcher_hyddwn_enabled: bool,

    #[serde(default = "default_hyddwn_url")]

    patcher_hyddwn_url: String,
    #[serde(default)]

    patcher_auto_update: bool,

    #[serde(default)]

    patcher_focus_on_start: bool,

    #[serde(default = "default_max_workers")]

    patcher_max_workers: u32,

    #[serde(default)]

    patcher_run_elevated: bool,

    #[serde(default)]

    launch_use_nexon_launcher: bool,

    #[serde(default)]

    launch_cmd_override: String,

    #[serde(default)]

    pre_patch_cmd: String,

    #[serde(default = "default_true")]

    parallel_ops: bool,

}



impl Default for Config {

    fn default() -> Self {

        Self {

            theme: "sky-dark".to_string(),

            locale: "en".to_string(),

            log_level: "info".to_string(),

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

            sequence_ignore_list: Vec::new(),

            auto_convert_features: false,

            auto_convert_pmg: false,

            theme_overrides: serde_json::Value::Object(serde_json::Map::new()),

            custom_themes: serde_json::Value::Object(serde_json::Map::new()),

            kanan_cfg_path: String::new(),

            patcher_game_path: String::new(),

            patcher_hyddwn_enabled: false,

            patcher_hyddwn_url: default_hyddwn_url(),
            patcher_auto_update: false,

            patcher_focus_on_start: false,

            patcher_max_workers: 10,

            patcher_run_elevated: false,

            launch_use_nexon_launcher: false,

            launch_cmd_override: String::new(),

            pre_patch_cmd: String::new(),

            parallel_ops: true,

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

    

    // Persistent log.txt next to the executable â€” always at Info so all activity is captured

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

    // Portable mode: if config.json exists next to the exe, use it.

    if let Ok(exe) = std::env::current_exe() {

        let portable = exe.with_file_name("config.json");

        if portable.exists() {

            return portable;

        }

    }

    // AppData default

    let mut path = app.path().app_config_dir().unwrap_or_else(|_| {

        #[cfg(target_os = "windows")]

        { PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".into())).join("mabi-pack2") }

        #[cfg(not(target_os = "windows"))]

        { PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".mabi-pack2") }

    });

    let _ = fs::create_dir_all(&path);

    path.push("config.json");

    path

}



#[tauri::command]

fn get_config_path_str(app: tauri::AppHandle) -> String {

    get_config_path(&app).to_string_lossy().to_string()

}



#[tauri::command]

fn get_appdata_config_path(app: tauri::AppHandle) -> String {

    let mut path = app.path().app_config_dir().unwrap_or_else(|_| {

        PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".into())).join("mabi-pack2")

    });

    let _ = fs::create_dir_all(&path);

    path.push("config.json");

    path.to_string_lossy().to_string()

}



#[tauri::command]

fn get_portable_config_path() -> String {

    std::env::current_exe()

        .map(|p| p.with_file_name("config.json").to_string_lossy().to_string())

        .unwrap_or_default()

}



#[tauri::command]

fn is_portable_mode() -> bool {

    std::env::current_exe()

        .map(|p| p.with_file_name("config.json").exists())

        .unwrap_or(false)

}



#[tauri::command]

fn set_portable_mode(app: tauri::AppHandle, enable: bool) -> Result<(), String> {

    let appdata_path = {

        let mut p = app.path().app_config_dir().unwrap_or_else(|_| {

            PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".into())).join("mabi-pack2")

        });

        let _ = fs::create_dir_all(&p);

        p.push("config.json");

        p

    };

    let portable_path = std::env::current_exe()

        .map(|p| p.with_file_name("config.json"))

        .map_err(|e| e.to_string())?;



    if enable {

        // Move config to exe dir (portable)

        if appdata_path.exists() && !portable_path.exists() {

            fs::copy(&appdata_path, &portable_path).map_err(|e| e.to_string())?;

        } else if !portable_path.exists() {

            // Write defaults to portable path

            let content = serde_json::to_string_pretty(&Config::default()).map_err(|e| e.to_string())?;

            fs::write(&portable_path, content).map_err(|e| e.to_string())?;

        }

    } else {

        // Move config back to AppData

        if portable_path.exists() {

            fs::copy(&portable_path, &appdata_path).map_err(|e| e.to_string())?;

            fs::remove_file(&portable_path).map_err(|e| e.to_string())?;

        }

    }

    Ok(())

}



#[tauri::command]

fn reset_config(app: tauri::AppHandle) {

    let path = get_config_path(&app);

    if let Ok(content) = serde_json::to_string_pretty(&Config::default()) {

        let _ = fs::write(path, content);

    }

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

fn wipe_registry_associations() -> Result<(), String> {

    #[cfg(target_os = "windows")]

    {

        use winreg::RegKey;

        use winreg::enums::*;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        let base = "Software\\Classes";

        for key in [".it", ".pack", ".dds", ".pmg", ".compiled",

                    "mabi-pack2.archive", "mabi-pack2.archive.v1",

                    "mabi-pack2.dds", "mabi-pack2.pmg", "mabi-pack2.compiled"] {

            let _ = hkcu.delete_subkey_all(format!("{}\\{}", base, key));

        }

        #[link(name = "shell32")]

        extern "system" { fn SHChangeNotify(wEventId: i32, uFlags: u32, dwItem1: *const std::ffi::c_void, dwItem2: *const std::ffi::c_void); }

        unsafe { SHChangeNotify(0x08000000i32, 0x0000u32, std::ptr::null(), std::ptr::null()); }

    }

    Ok(())

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



    let ignore_set: std::collections::HashSet<String> = config.sequence_ignore_list.iter()

        .map(|s| s.trim().to_lowercase())

        .filter(|s| !s.is_empty())

        .collect();



    if let Ok(paths) = fs::read_dir(&f_path) {

        let mut files: Vec<_> = paths.filter_map(|e| e.ok())

            .filter(|e| {

                let n = e.file_name().to_string_lossy().to_lowercase();

                (n.ends_with(".it") || n.ends_with(".pack")) && !ignore_set.contains(&n)

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



    // Deduplicate: archives were processed in ascending name order (data.it â†’ data_001.it â†’ data_002.itâ€¦)

    // so later entries overwrite earlier ones, meaning the highest-numbered archive's copy wins.

    // Normalize backslashes â†’ forward slashes so duplicate entries with mixed separators collapse.

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

        extract::run_extract_with_key_search(&input, &output, key, &salts, filters, Some(config.region_key), config.auto_convert_png, config.auto_convert_features, config.auto_convert_pmg, Some(&cb)).map(|_| ()).map_err(|e| format!("Extraction failed: {}", e))

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

    pub rgn_data: Option<rgn_lib::RgnData>,

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

    const MAX_ADPCM_INPUT: usize = 2 * 1024 * 1024; // 2 MB ADPCM input â†’ ~8 MB PCM



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

        rgn_data: None,

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

    } else if preview.file_type == "text" || preview.file_type == "mml" {

        let text_slice = if raw_bytes.len() > MAX_HEX_BYTES {

            preview.truncated = true;

            &raw_bytes[..MAX_HEX_BYTES]

        } else {

            &raw_bytes[..]

        };

        preview.content_text = Some(decode_text_bytes(text_slice));

        if preview.file_type == "mml" { raw_bytes = Vec::new(); }

    } else if preview.file_type == "set" {

        preview.content_text = Some(match parse_set_header_inner(&raw_bytes) {

            Ok(h) if h.is_xml => "XML-format .set file".to_string(),

            Ok(h) => format!(

                "Animation: {} frames, {} bones, {}ms duration\nMagic: {}  Version: {}",

                h.frame_count, h.bone_count, h.duration_ms, h.magic, h.version

            ),

            Err(e) => format!("Unknown .set format: {}", e),

        });

    } else if preview.file_type == "pmg" {

        match parse_pmg_bytes(&raw_bytes) {

            Ok(geo) => {

                info!("[PMG] {}  Â·  {} verts  {} faces", if geo.mesh_name.is_empty() { &entry_name } else { &geo.mesh_name }, geo.vertex_count, geo.face_count);

                preview.pmg_geometry = Some(geo);

            },

            Err(e)  => {

                warn!("[GUI] PMG parse failed for {}: {}", entry_name, e);

                preview.content_text = Some(format!("PMG parse failed: {}", e));

            }

        }

        raw_bytes = Vec::new(); // geometry is in pmg_geometry; no need to ship raw bytes over IPC

    } else if preview.file_type == "rgn" {

        match rgn_lib::parse_rgn(&raw_bytes) {

            Some(rgn) => {

                info!("[RGN] {} v{}  .  {}x{} px  ({} areas)", entry_name, rgn.version, rgn.width, rgn.height, rgn.area_count);

                preview.rgn_data = Some(rgn);

            }

            None => {

                warn!("[GUI] RGN parse failed for {}", entry_name);

                preview.content_text = Some("RGN parse failed - unknown format (see Hex View)".to_string());

            }

        }

        raw_bytes = Vec::new(); // heights are in rgn_data; no need to ship raw bytes over IPC

    } else if preview.file_type == "audio" {

        if entry_name.to_lowercase().ends_with(".wav") {

            if raw_bytes.len() <= MAX_ADPCM_INPUT {

                if let Some(pcm_wav) = decode_ima_adpcm_wav(&raw_bytes) {

                    debug!("[GUI] ADPCM decoded {} â†’ {} bytes for {}", raw_bytes.len(), pcm_wav.len(), entry_name);

                    raw_bytes = pcm_wav;

                }

                // else: PCM format, pass through unchanged

            } else if is_adpcm_wav(&raw_bytes) {

                // Large ADPCM: browser can't play ADPCM natively, don't send unplayable bytes

                let mb = raw_bytes.len() as f64 / 1_048_576.0;

                let msg = format!(

                    "ADPCM audio ({:.1} MB compressed) â€” too large for in-app preview. Extract and open externally.",

                    mb

                );

                warn!("[GUI] Audio {}: {}", entry_name, msg);

                preview.content_text = Some(msg);

                raw_bytes = Vec::new();

            }

            // else: large PCM WAV â€” send first 8 MB, browser handles it natively

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

        "pmg" | "rgn" => 0, // raw bytes cleared above; parsed data in pmg_geometry / rgn_data

        _       => MAX_HEX_BYTES,

    };

    if raw_bytes.len() > limit {

        preview.truncated = true;

        preview.raw_bytes = raw_bytes[..limit].to_vec();

    } else {

        preview.raw_bytes = raw_bytes;

    }



    debug!("[GUI] Preview for {} â€” {} bytes (truncated={})", entry_name, preview.full_preview_size, preview.truncated);

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

    /// Per-vertex RGB colors (r0,g0,b0, r1,g1,b1, …), normalized 0-1.

    /// Empty when all vertices carry the default all-white (255,255,255) colour,

    /// which means "no meaningful per-vertex tint" in most Mabinogi meshes.

    vertex_colors: Vec<f32>,

    /// Average of all per-vertex RGB colours, normalized 0-1.

    /// Always present; gives a single representative diffuse tint even when

    /// vertex_colors is empty.

    avg_color: [f32; 3],

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

        return Err("Empty file (0 bytes â€” stub entry)".to_string());

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

    // Pass raw local-space positions â€” Three.js geometry.center() will normalize placement

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



    // Extract per-vertex BGRA colours and compute the average.

    // "All white" (255,255,255) is the Mabinogi default meaning "no tint" —

    // omit the per-vertex array in that case so the viewer uses the accent colour.

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



    Ok(PmgGeometry {

        positions,

        normals: Vec::new(), // computed by Three.js computeVertexNormals()

        uvs,

        indices,

        mesh_name: lod.mesh_name.clone(),

        texture_name: lod.texture_name.clone(),

        vertex_count: lod.vertices.len(),

        face_count,

        vertex_colors,

        avg_color,

    })

}



#[tauri::command]

fn parse_pmg_geometry(bytes: Vec<u8>) -> Result<PmgGeometry, String> {

    parse_pmg_bytes(&bytes)

}



#[tauri::command]

fn parse_rgn(bytes: Vec<u8>) -> Result<rgn_lib::RgnData, String> {

    rgn_lib::parse_rgn(&bytes).ok_or_else(|| "RGN parse failed — unrecognised format or version".to_string())

}



#[derive(Serialize)]

struct SetHeaderInfo {

    magic: String,

    version: u32,

    bone_count: u32,

    frame_count: u32,

    duration_ms: u32,

    is_xml: bool,

}



fn parse_set_header_inner(bytes: &[u8]) -> Result<SetHeaderInfo, String> {

    if bytes.len() < 4 {

        return Err(format!("File too small ({} bytes)", bytes.len()));

    }

    if bytes.starts_with(b"<?") || bytes.starts_with(b"<") {

        return Ok(SetHeaderInfo {

            magic: String::from_utf8_lossy(&bytes[..4.min(bytes.len())]).into_owned(),

            version: 0, bone_count: 0, frame_count: 0, duration_ms: 0,

            is_xml: true,

        });

    }

    let magic = format!("{:02X}{:02X}{:02X}{:02X}", bytes[0], bytes[1], bytes[2], bytes[3]);

    if bytes.len() < 20 {

        return Err(format!("Header too small ({} bytes, need 20)", bytes.len()));

    }

    let r32 = |off: usize| -> u32 {

        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])

    };

    Ok(SetHeaderInfo {

        magic,

        version: r32(4),

        bone_count: r32(8),

        frame_count: r32(12),

        duration_ms: r32(16),

        is_xml: false,

    })

}



#[tauri::command]

fn parse_set_header(bytes: Vec<u8>) -> Result<SetHeaderInfo, String> {

    parse_set_header_inner(&bytes)

}



#[tauri::command]

fn parse_area(bytes: Vec<u8>) -> Result<mabi_pack2::area::AreaData, String> {

    mabi_pack2::area::parse_area(&bytes)

        .ok_or_else(|| "No recognizable prop data found in .area file".to_string())

}



#[derive(Serialize)]

struct AniEventEntry {

    frame: u32,

    event_type: String,

    anim_name: String,

    params: String,

}



#[derive(Serialize)]

struct AnieventData {

    set_name: String,

    animation_count: usize,

    event_count: usize,

    events: Vec<AniEventEntry>,

}



#[tauri::command]

fn parse_anievent(bytes: Vec<u8>) -> Result<AnieventData, String> {

    let text = std::str::from_utf8(&bytes)

        .map(|s| s.to_string())

        .unwrap_or_else(|_| {

            let (decoded, _, _) = EUC_KR.decode(&bytes);

            decoded.into_owned()

        });



    let mut set_name = String::new();

    let mut current_anim = String::new();

    let mut seen_anims: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut events: Vec<AniEventEntry> = Vec::new();



    for line in text.lines() {

        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("//") {

            continue;

        }

        if let Some(rest) = trimmed.strip_prefix("set(") {

            if let Some(inner) = rest.strip_prefix('"').and_then(|s| s.split('"').next()) {

                set_name = inner.to_string();

            }

            continue;

        }

        if trimmed.starts_with("folder(") {

            continue;

        }

        if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() > 2 {

            current_anim = trimmed[1..trimmed.len() - 1].to_string();

            seen_anims.insert(current_anim.clone());

            continue;

        }

        if let Some(colon) = trimmed.find(':') {

            let frame_str = trimmed[..colon].trim();

            if let Ok(frame) = frame_str.parse::<u32>() {

                let rest = trimmed[colon + 1..].trim();

                let (event_type, params) = if let Some(paren) = rest.find('(') {

                    (rest[..paren].trim().to_string(), rest[paren..].trim().to_string())

                } else {

                    (rest.to_string(), String::new())

                };

                if !event_type.is_empty() {

                    events.push(AniEventEntry {

                        frame,

                        event_type,

                        anim_name: current_anim.clone(),

                        params,

                    });

                }

            }

        }

    }



    if events.is_empty() && set_name.is_empty() {

        return Err("No recognisable anievent data found".to_string());

    }



    let animation_count = seen_anims.len();

    let event_count = events.len();

    Ok(AnieventData { set_name, animation_count, event_count, events })

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



/// Runs once in a background thread â€” detects adapter link speed via PowerShell.

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



        let exe_path = match std::env::current_exe() { Ok(p) => p, Err(_) => return };

        let exe_str = exe_path.to_string_lossy();



        // Skip if same-or-newer version is already registered at this exact exe path.

        // Re-register only when the exe moved or a new version is being applied.

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        if let Ok(key) = hkcu.open_subkey("Software\\Classes\\mabi-pack2.archive") {

            let reg_ver = key.get_value::<String, _>("AppVersion").unwrap_or_default();

            let reg_exe = key.get_value::<String, _>("RegisteredExe").unwrap_or_default();

            if version_to_u64(&reg_ver) >= current_ver_num && reg_exe == exe_str.as_ref() {

                return;

            }

        }

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

                let _ = pk.set_value("RegisteredExe", &exe_str.as_ref());

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

        rgn_data: None,

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

    } else if preview.file_type == "text" || preview.file_type == "mml" {

        let text_slice = if raw_bytes.len() > MAX_HEX_BYTES {

            preview.truncated = true;

            &raw_bytes[..MAX_HEX_BYTES]

        } else {

            &raw_bytes[..]

        };

        preview.content_text = Some(decode_text_bytes(text_slice));

        if preview.file_type == "mml" { raw_bytes = Vec::new(); }

    } else if preview.file_type == "set" {

        preview.content_text = Some(match parse_set_header_inner(&raw_bytes) {

            Ok(h) if h.is_xml => "XML-format .set file".to_string(),

            Ok(h) => format!(

                "Animation: {} frames, {} bones, {}ms duration\nMagic: {}  Version: {}",

                h.frame_count, h.bone_count, h.duration_ms, h.magic, h.version

            ),

            Err(e) => format!("Unknown .set format: {}", e),

        });

    } else if preview.file_type == "pmg" {

        match parse_pmg_bytes(&raw_bytes) {

            Ok(geo) => { preview.pmg_geometry = Some(geo); },

            Err(e) => { preview.content_text = Some(format!("PMG parse failed: {}", e)); }

        }

        raw_bytes = Vec::new();

    } else if preview.file_type == "rgn" {

        match rgn_lib::parse_rgn(&raw_bytes) {

            Some(rgn) => {

                info!("[RGN] {} v{}  .  {}x{} px  ({} areas)", entry_name, rgn.version, rgn.width, rgn.height, rgn.area_count);

                preview.rgn_data = Some(rgn);

            }

            None => {

                warn!("[GUI] RGN parse failed for {}", entry_name);

                preview.content_text = Some("RGN parse failed - unknown format (see Hex View)".to_string());

            }

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

                    "ADPCM audio ({:.1} MB compressed) â€” too large for in-app preview. Extract and open externally.", mb

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

        "pmg" | "rgn" => 0,

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



// ---- Mod file commands -------------------------------------------------------



#[derive(Serialize, Deserialize)]

pub struct ModInfo {

    pub file: String,

    pub name: String,

    pub version: Option<String>,

    pub author: Option<String>,

    pub description: Option<String>,

    pub tags: Option<Vec<String>>,

    pub file_count: usize,

    pub is_public: bool,

    pub error: Option<String>,

}



/// Return the path to the mods/ directory next to the exe.

#[tauri::command]

fn get_mods_dir() -> String {

    std::env::current_exe()

        .ok()

        .and_then(|p| p.parent().map(|d| d.join("mods").to_string_lossy().to_string()))

        .unwrap_or_else(|| "mods".to_string())

}



/// Scan the mods/ directory for .mod files and return metadata.

#[tauri::command]

fn list_mod_files() -> Vec<ModInfo> {

    let dir = std::env::current_exe()

        .ok()

        .and_then(|p| p.parent().map(|d| d.join("mods")))

        .unwrap_or_else(|| std::path::Path::new("mods").to_path_buf());



    mod_file::scan_mods(&dir)

        .into_iter()

        .map(|(path, result)| {

            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();

            match result {

                Ok(pkg) => ModInfo {

                    file: fname,

                    name: pkg.meta.name.clone(),

                    version: pkg.meta.version.clone(),

                    author: pkg.meta.author.clone(),

                    description: pkg.meta.description.clone(),

                    tags: pkg.meta.tags.clone(),

                    file_count: pkg.file_count(),

                    is_public: pkg.is_api_public(),

                    error: None,

                },

                Err(e) => ModInfo {

                    file: fname,

                    name: String::new(),

                    version: None,

                    author: None,

                    description: None,

                    tags: None,

                    file_count: 0,

                    is_public: false,

                    error: Some(e.to_string()),

                },

            }

        })

        .collect()

}



/// Read a .mod file's raw TOML text (both apply_mod call sites pass this

/// straight through to apply_mod's mod_toml param, which parses TOML — this

/// must return the raw file content, not a JSON re-serialization of it).

#[tauri::command]

fn load_mod_file(path: String) -> Result<String, String> {

    std::fs::read_to_string(&path).map_err(|e| e.to_string())

}



/// Return the blank .mod template string.

#[tauri::command]

fn get_mod_template() -> String {

    mod_file::template().to_string()

}



/// Return the current API server port.

#[tauri::command]

fn get_api_port() -> u16 {

    api::DEFAULT_PORT

}



// â”€â”€ Nexon NA Launcher commands â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€



/// Serializable session snapshot passed between frontend and commands.
/// Same shape as the core NexonSession (extra cookies default when absent).
pub type SessionInfo = mabi_pack2::launcher::auth::NexonSession;

/// Map launcher errors to a frontend-friendly value: MFA/CAPTCHA come back as data.
fn login_response(r: anyhow::Result<mabi_pack2::launcher::auth::LoginResult>) -> Result<serde_json::Value, String> {
    use mabi_pack2::launcher::auth::AuthError;
    match r {
        Ok(result) => Ok(serde_json::json!({ "session": result.session, "expiresIn": result.session_expires_in })),
        Err(e) => match e.downcast_ref::<AuthError>() {
            Some(AuthError::MfaRequired { mfa_key, mfa_type }) => Ok(serde_json::json!({
                "mfa_required": true, "mfa_key": mfa_key, "mfa_type": mfa_type,
            })),
            Some(AuthError::CaptchaRequired(code)) => Ok(serde_json::json!({
                "captcha_required": true, "code": code, "message": e.to_string(),
            })),
            _ => Err(e.to_string()),
        },
    }
}

fn delete_webview_cookies() {
    let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
    if localappdata.is_empty() { return; }
    let cookies_db = std::path::PathBuf::from(&localappdata)
        .join("com.shaggyze.mabi-patcher")
        .join("EBWebView")
        .join("Default")
        .join("Network")
        .join("Cookies");
    let _ = std::fs::remove_file(&cookies_db);
}

/// Browser (SSO / Google / email) login in an embedded WebView. Polls the WebView2
/// cookie store; NxLSession is used directly, TpaSession is exchanged (Rua path A).
#[tauri::command]
async fn nexon_login_webview(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

    delete_webview_cookies();
    let window = WebviewWindowBuilder::new(
        &app,
        "nexon_login",
        WebviewUrl::External("https://www.nexon.com/account/en/login".parse().unwrap())
    )
    .title("Nexon Login")
    .inner_size(500.0, 800.0)
    .resizable(true)
    .build()
    .map_err(|e| e.to_string())?;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if app.get_webview_window("nexon_login").is_none() {
            return Err("Login window closed".to_string());
        }
        let polled = tauri::async_runtime::spawn_blocking(mabi_pack2::launcher::auth::poll_tauri_webview)
            .await
            .map_err(|e| e.to_string())?;
        match polled {
            Ok(Some(session)) => {
                let _ = window.close();
                return Ok(serde_json::json!({ "session": session, "expiresIn": 86400 }));
            }
            Ok(None) => {}
            // A rejected TpaSession exchange is final (single-use cookie) — stop and report.
            Err(e) => {
                let _ = window.close();
                return Err(e.to_string());
            }
        }
    }
}

/// Import session from the official Nexon Launcher's cookie store.
#[tauri::command]
fn launcher_import_session() -> Result<serde_json::Value, String> {
    let session = mabi_pack2::launcher::auth::import_from_nexon_launcher().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "session": session }))
}

/// Email/password login. Returns {session} or {mfa_required, mfa_key} or {captcha_required}.
#[tauri::command]
async fn launcher_login(username: String, password: String, _remember: Option<bool>, _verification_code: Option<String>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dev = mabi_pack2::launcher::auth::device_id("");
        login_response(mabi_pack2::launcher::auth::login(&username, &password, &dev))
    }).await.map_err(|e| e.to_string())?
}

/// Submit the emailed / authenticator code after an MFA challenge.
#[tauri::command]
async fn launcher_login_otp(mfa_key: String, otp: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dev = mabi_pack2::launcher::auth::device_id("");
        login_response(mabi_pack2::launcher::auth::login_otp(&mfa_key, &otp, &dev))
    }).await.map_err(|e| e.to_string())?
}

/// Refresh using a stored NxLSession (email/password accounts only).
#[tauri::command]
async fn launcher_autologin(session_token: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        login_response(mabi_pack2::launcher::auth::autologin(&session_token))
    }).await.map_err(|e| e.to_string())?
}

/// Fetch a passport (runs the full account → access → playable → passport chain).
#[tauri::command]
async fn launcher_get_passport(session: SessionInfo) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        mabi_pack2::launcher::auth::get_passport(&session).map_err(|e| e.to_string())
    }).await.map_err(|e| e.to_string())?
}

/// Check if the game is in maintenance.
#[tauri::command]
async fn launcher_check_maintenance(session: SessionInfo) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        mabi_pack2::launcher::patch::is_maintenance(&session).map_err(|e| e.to_string())
    }).await.map_err(|e| e.to_string())?
}

/// Latest game version: current manifest (branch API) → buildtime → managed version number.
#[tauri::command]
async fn launcher_get_version(session: SessionInfo) -> Result<i32, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use mabi_pack2::launcher::patch;
        let hash = patch::remote_manifest_hash(Some(&session)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        use std::io::Read;
        ureq::get(&format!("{}{}", patch::CDN_BASE, hash))
            .timeout(std::time::Duration::from_secs(30))
            .call().map_err(|e| e.to_string())?
            .into_reader().read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let m = patch::Manifest::parse(&hash, &bytes).map_err(|e| e.to_string())?;
        get_managed_version(m.buildtime.round() as i64)
            .map(|v| v as i32)
            .ok_or_else(|| "version lookup failed".to_string())
    }).await.map_err(|e| e.to_string())?
}



// ── Profile commands ──────────────────────────────────────────────────────────



#[tauri::command]

fn launcher_list_profiles() -> Result<serde_json::Value, String> {

    #[cfg(not(target_os = "windows"))]

    return Err("launcher only available on Windows".to_string());

    #[cfg(target_os = "windows")]

    {

        let store = mabi_pack2::launcher::profile::ProfileStore::load().map_err(|e| e.to_string())?;

        let active_id = store.active_id.clone();

        let summaries: Vec<mabi_pack2::launcher::profile::ProfileSummary> = store.profiles.iter()

            .map(mabi_pack2::launcher::profile::ProfileSummary::from)

            .collect();

        serde_json::to_value(serde_json::json!({

            "profiles": summaries,

            "active_id": active_id

        })).map_err(|e| e.to_string())

    }

}



#[tauri::command]

fn launcher_save_profile(

    id: Option<String>,

    name: String,

    email: String,

    client_dir: String,

    auto_login: bool,

    profile_type: Option<String>,

    login_ip: Option<String>,

    login_port: Option<u16>,

    chat_ip: Option<String>,

    chat_port: Option<u16>,

    is_official: Option<bool>,

) -> Result<String, String> {

    #[cfg(not(target_os = "windows"))]

    return Err("launcher only available on Windows".to_string());

    #[cfg(target_os = "windows")]

    {

        use mabi_pack2::launcher::profile::{Profile, ProfileStore};

        let mut store = ProfileStore::load().map_err(|e| e.to_string())?;

        // Deduplicate: if creating new and same email exists, update that profile
        let resolved_id = if id.is_none() && !email.is_empty() {
            store.profiles.iter().find(|p| p.email.eq_ignore_ascii_case(&email)).map(|p| p.id.clone())
        } else {
            id.clone()
        };

        let mut profile = if let Some(ref existing_id) = resolved_id {

            store.get(existing_id).cloned().unwrap_or_else(|| Profile::new(&name, &email))

        } else {

            Profile::new(&name, &email)

        };

        profile.name = name;

        profile.email = email;

        profile.client_dir = client_dir;

        profile.auto_login = auto_login;

        if let Some(v) = profile_type { profile.profile_type = v; }

        if let Some(v) = login_ip { profile.login_ip = v; }

        if let Some(v) = login_port { profile.login_port = v; }

        if let Some(v) = chat_ip { profile.chat_ip = v; }

        if let Some(v) = chat_port { profile.chat_port = v; }

        if let Some(v) = is_official { profile.is_official = v; }

        let profile_id = profile.id.clone();

        store.upsert(profile);

        store.save().map_err(|e| e.to_string())?;

        Ok(profile_id)

    }

}



#[tauri::command]

fn launcher_delete_profile(id: String) -> Result<bool, String> {

    #[cfg(not(target_os = "windows"))]

    return Err("launcher only available on Windows".to_string());

    #[cfg(target_os = "windows")]

    {

        mabi_pack2::launcher::profile::delete_profile(&id).map_err(|e| e.to_string())

    }

}



#[tauri::command]

fn launcher_set_active_profile(id: String) -> Result<(), String> {

    #[cfg(not(target_os = "windows"))]

    return Err("launcher only available on Windows".to_string());

    #[cfg(target_os = "windows")]

    {

        mabi_pack2::launcher::profile::set_active_profile(&id).map_err(|e| e.to_string())

    }

}



#[tauri::command]

fn launcher_load_profile(id: String) -> Result<serde_json::Value, String> {

    #[cfg(not(target_os = "windows"))]

    return Err("launcher only available on Windows".to_string());

    #[cfg(target_os = "windows")]

    {

        let profile = mabi_pack2::launcher::profile::load_profile(&id).map_err(|e| e.to_string())?;

        // Return summary (no session token) + whether session is valid

        let summary = mabi_pack2::launcher::profile::ProfileSummary::from(&profile);

        let mut val = serde_json::to_value(summary).map_err(|e| e.to_string())?;

        // Include session_token only for autologin use — strip from normal display

        if profile.auto_login && profile.is_session_valid() {

            val["session_token_for_autologin"] = serde_json::Value::String(profile.session_token.clone());

        }

        Ok(val)

    }

}



#[tauri::command]

fn launcher_update_profile_session(

    id: String,

    session_token: String,

    expires_in: i32,

) -> Result<(), String> {

    #[cfg(not(target_os = "windows"))]

    return Err("launcher only available on Windows".to_string());

    #[cfg(target_os = "windows")]

    {

        mabi_pack2::launcher::profile::update_session(&id, &session_token, expires_in)

            .map_err(|e| e.to_string())

    }

}



/// Fetch launch config and spawn Client.exe. Returns launch argument info.

/// When login_ip is provided (custom/hyddwn server): skips Nexon auth API entirely.
/// Supports pre/post hook commands, custom launch command override, and Nexon Launcher passthrough.

#[tauri::command]

async fn launcher_launch(

    session: Option<SessionInfo>,

    client_dir: String,

    login_ip: Option<String>,

    login_port: Option<u16>,

    pre_launch_cmd: Option<String>,

    post_launch_cmd: Option<String>,

    launch_cmd_override: Option<String>,

    use_nexon_launcher: Option<bool>,

) -> Result<serde_json::Value, String> {

    use std::path::Path;

    use mabi_pack2::launcher::launch as launcher_mod;

    let dir = Path::new(&client_dir);

    if !dir.join("Client.exe").exists() {

        return Err(format!("Client.exe not found in: {}", client_dir));

    }

    // Run pre-launch hook
    if let Some(ref cmd) = pre_launch_cmd.as_ref().filter(|s| !s.trim().is_empty()) {

        launcher_mod::run_hook_cmd(cmd, dir).map_err(|e| format!("Pre-launch hook failed: {}", e))?;

    }

    let result = if let Some(ip) = login_ip.as_ref().filter(|s| !s.is_empty()) {

        let port = login_port.unwrap_or(11000);

        let args = vec![
            format!("/login {}:{}", ip, port),
            "/P:0".to_string(),
        ];

        launcher_mod::launch_direct(dir, "0", &args, launch_cmd_override.as_deref())
            .map_err(|e| e.to_string())?;

        serde_json::json!({
            "executable": "Client.exe",
            "argumentCount": 2,
            "patchAvailable": false,
        })

    } else if use_nexon_launcher.unwrap_or(false) {

        let launcher_paths = [
            std::env::var("LOCALAPPDATA").unwrap_or_default() + r"\Programs\Nexon\Nexon Launcher\NexonLauncher.exe",
            r"C:\Program Files (x86)\Nexon\Nexon Launcher\NexonLauncher.exe".to_string(),
        ];

        let launcher_exe = launcher_paths.iter()
            .find(|p| std::path::Path::new(p.as_str()).exists())
            .ok_or_else(|| "Nexon Launcher not found. Install it or use Direct mode.".to_string())?;

        std::process::Command::new(launcher_exe)
            .arg("--game=10200")
            .spawn()
            .map_err(|e| format!("Failed to start Nexon Launcher: {}", e))?;

        serde_json::json!({
            "executable": "NexonLauncher.exe",
            "argumentCount": 1,
            "patchAvailable": false,
        })

    } else {

        let mut nexon_session = session.ok_or_else(|| "Login required for official Nexon server".to_string())?;
        // Rua flow: account → access → playable → passport (401 → autologin + retry),
        // then the nexon_client.exe stub + nexon_x64.dll shim + SDK pipe so Client.exe
        // can fetch its ticket the way it does from the official launcher.
        let exe = dir.join("Client.exe");
        let info = launcher_mod::launch_official(&mut nexon_session, &exe, false)
            .map_err(|e| e.to_string())?;
        serde_json::json!({
            "executable": info.executable,
            "argumentCount": info.argument_count,
            "patchAvailable": info.patch_available,
            "pid": info.pid,
            "session": nexon_session,
        })

    };

    // Run post-launch hook
    if let Some(ref cmd) = post_launch_cmd.as_ref().filter(|s| !s.trim().is_empty()) {

        launcher_mod::run_hook_cmd(cmd, dir).map_err(|e| format!("Post-launch hook failed: {}", e))?;

    }

    Ok(result)

}



// ── Launcher detection ────────────────────────────────────────────────────────



#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]

struct HyddwnServerProfile {

    #[serde(rename = "Name", default)]

    name: String,

    #[serde(rename = "LoginIp", default)]

    login_ip: String,

    #[serde(rename = "LoginPort", default)]

    login_port: u16,

    #[serde(rename = "ChatIp", default)]

    chat_ip: String,

    #[serde(rename = "ChatPort", default)]

    chat_port: u16,

    #[serde(rename = "IsOfficial", default)]

    is_official: bool,

}



#[derive(serde::Serialize, serde::Deserialize, Default)]

struct HyddwnClientProfile {

    #[serde(rename = "Name", default)]

    name: String,

    #[serde(rename = "Location", default)]

    location: String,

}



#[derive(serde::Serialize)]

struct DetectedProfile {

    source: String,

    name: String,

    client_dir: String,

    login_ip: String,

    login_port: u16,

    chat_ip: String,

    chat_port: u16,

    is_official: bool,

}



#[tauri::command]

fn detect_launcher_profiles() -> Result<Vec<DetectedProfile>, String> {

    let mut detected: Vec<DetectedProfile> = Vec::new();



    // 1. Nexon Launcher

    let nexon_exe = r"C:\Program Files (x86)\Nexon\Nexon Launcher\nexon_launcher.exe";

    if std::path::Path::new(nexon_exe).exists() {

        let client_exe = r"C:\Nexon\Library\mabinogi\appdata\Client.exe";

        let client_dir = if std::path::Path::new(client_exe).exists() {

            r"C:\Nexon\Library\mabinogi\appdata".to_string()

        } else {

            String::new()

        };

        detected.push(DetectedProfile {

            source: "nexon".to_string(),

            name: "Nexon NA (Official)".to_string(),

            client_dir,

            login_ip: "208.85.109.35".to_string(),

            login_port: 11000,

            chat_ip: "208.85.109.37".to_string(),

            chat_port: 8002,

            is_official: true,

        });

    }



    // 2. HyddwnLauncher server + client profiles

    if let Ok(local) = std::env::var("LOCALAPPDATA") {

        let base = std::path::PathBuf::from(&local).join("Hyddwn Launcher");

        let server_json = base.join("serverprofiles.json");

        if server_json.exists() {

            let client_dir = {

                let cj = base.join("clientprofiles.json");

                std::fs::read_to_string(&cj)

                    .ok()

                    .and_then(|t| serde_json::from_str::<Vec<HyddwnClientProfile>>(&t).ok())

                    .and_then(|v| v.into_iter().next())

                    .map(|p| {

                        std::path::Path::new(&p.location)

                            .parent()

                            .map(|d| d.to_string_lossy().to_string())

                            .unwrap_or_default()

                    })

                    .unwrap_or_default()

            };

            if let Ok(text) = std::fs::read_to_string(&server_json) {

                if let Ok(profiles) = serde_json::from_str::<Vec<HyddwnServerProfile>>(&text) {

                    for p in profiles {

                        if p.is_official { continue; }

                        detected.push(DetectedProfile {

                            source: "hyddwn".to_string(),

                            name: if p.name.is_empty() { "HyddwnLauncher Server".to_string() } else { p.name },

                            client_dir: client_dir.clone(),

                            login_ip: p.login_ip,

                            login_port: p.login_port,

                            chat_ip: p.chat_ip,

                            chat_port: p.chat_port,

                            is_official: false,

                        });

                    }

                }

            }

        }

    }



    // 3. Cichol (Kanan) launcher

    if let Ok(local) = std::env::var("LOCALAPPDATA") {

        let cichol = std::path::PathBuf::from(&local).join("Cichol").join("Cichol.exe");

        if cichol.exists() {

            detected.push(DetectedProfile {

                source: "kanan".to_string(),

                name: "Kanan".to_string(),

                client_dir: String::new(),

                login_ip: String::new(),

                login_port: 0,

                chat_ip: String::new(),

                chat_port: 0,

                is_official: false,

            });

        }

    }



    Ok(detected)

}



// ── Features.xml.compiled editor commands ─────────────────────────────────────



/// Extract and parse features.xml.compiled from an archive into structured JSON.

#[tauri::command]

fn get_features_from_archive(archive: String, key: Option<String>) -> Result<serde_json::Value, String> {

    use walkdir::WalkDir;

    let salts = mabi_pack2::load_salts();



    // Extract only features.xml.compiled to a temp dir, then parse

    let tmp_dir = std::env::temp_dir().join(format!("mabi_feat_load_{}", std::process::id()));

    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

    let tmp_str = tmp_dir.to_string_lossy().to_string();



    let _salt = mabi_pack2::extract::run_extract_with_key_search(

        &archive, &tmp_str, key,

        &salts,

        vec!["features.xml.compiled".to_string()],

        None, false, false, false, None,

    ).map_err(|e| { let _ = std::fs::remove_dir_all(&tmp_dir); e.to_string() })?;



    // Walk to find extracted file (path structure varies)

    let feat_path = WalkDir::new(&tmp_dir)

        .into_iter()

        .filter_map(|e| e.ok())

        .find(|e| e.file_name().to_string_lossy().to_lowercase() == "features.xml.compiled")

        .map(|e| e.into_path());



    let data = match feat_path {

        Some(p) => std::fs::read(&p).map_err(|e| e.to_string())?,

        None => {

            let _ = std::fs::remove_dir_all(&tmp_dir);

            return Err("features.xml.compiled not found in archive".to_string());

        }

    };



    let _ = std::fs::remove_dir_all(&tmp_dir);



    let parsed = mabi_pack2::common_ext::parse_features_compiled(&data)

        .ok_or_else(|| "Failed to parse features.xml.compiled binary format".to_string())?;



    serde_json::to_value(&parsed).map_err(|e| e.to_string())

}



/// Re-encode modified features and write back to archive.

#[tauri::command]

fn save_features_to_archive(

    archive: String,

    key: Option<String>,

    features_json: String,

) -> Result<serde_json::Value, String> {

    let features_data: mabi_pack2::common_ext::FeaturesData =

        serde_json::from_str(&features_json).map_err(|e| format!("Invalid JSON: {}", e))?;



    let binary = mabi_pack2::common_ext::encode_features_compiled(&features_data);



    // Extract archive to temp dir, overwrite features.xml.compiled, repack

    let salts = mabi_pack2::load_salts();

    let tmp_dir = std::env::temp_dir().join(format!("mabi_feat_{}", std::process::id()));

    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

    let tmp_str = tmp_dir.to_string_lossy().to_string();



    let salt_used = mabi_pack2::extract::run_extract_with_key_search(

        &archive, &tmp_str, key.clone(), &salts,

        vec![], None, false, false, false, None,

    ).map_err(|e| { let _ = std::fs::remove_dir_all(&tmp_dir); e.to_string() })?;



    // Write the re-encoded features.xml.compiled

    let candidates = [

        tmp_dir.join("data").join("xml").join("features.xml.compiled"),

        tmp_dir.join("xml").join("features.xml.compiled"),

        tmp_dir.join("features.xml.compiled"),

    ];

    let dest = candidates.iter()

        .find(|p| p.exists())

        .ok_or_else(|| "Could not find features.xml.compiled in extracted data".to_string())?;



    std::fs::write(dest, &binary).map_err(|e| e.to_string())?;



    // Repack

    let key_str = key.as_deref().unwrap_or(&salt_used);

    let is_pack = archive.to_lowercase().ends_with(".pack");

    let prefix = if is_pack { Some("data") } else { None };



    mabi_pack2::pack::run_pack(&tmp_str, &archive, key_str, vec![], false, 0, prefix, None)

        .map_err(|e| { let _ = std::fs::remove_dir_all(&tmp_dir); e.to_string() })?;



    let _ = std::fs::remove_dir_all(&tmp_dir);



    Ok(serde_json::json!({

        "archive": archive,

        "features": features_data.features.len(),

        "servers": features_data.servers.len(),

        "bytes": binary.len(),

        "status": "saved",

    }))

}



/// Read locally installed Mabinogi version from Windows registry.

#[tauri::command]

fn get_mabi_version_local() -> Option<serde_json::Value> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        use winreg::RegKey;
        let client_dir = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("SOFTWARE\\Nexon\\Mabinogi")
            .ok()
            .and_then(|k| k.get_value::<String, _>("").ok())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                for path in &["SOFTWARE\\WOW6432Node\\Nexon\\Mabinogi", "SOFTWARE\\Nexon\\Mabinogi"] {
                    if let Ok(k) = hklm.open_subkey(path) {
                        let dir: String = k.get_value("InstallLocation").unwrap_or_default();
                        if !dir.is_empty() { return Some(dir); }
                    }
                }
                None
            })?;
        let ver_path = std::path::Path::new(&client_dir).join("version.dat");
        let version_str = std::fs::read(&ver_path).ok()
            .filter(|b| b.len() >= 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string());
        Some(serde_json::json!({
            "installed_version": version_str.unwrap_or_default(),
            "client_dir": client_dir,
        }))
    }
    #[cfg(not(target_os = "windows"))]
    None
}





/// Fetch latest Mabinogi version from Nexon public branch API (no login required).

#[tauri::command]

fn get_mabi_version_remote() -> Result<serde_json::Value, String> {

    let url = "https://www.nexon.com/api/game-build/v1/branch/games/10200/public";

    let ps_script = format!(

        "try {{ $r = Invoke-RestMethod -Uri '{}' -TimeoutSec 10; ConvertTo-Json $r -Depth 3 -Compress }} catch {{ Write-Error $_.Exception.Message }}",

        url

    );

    let output = std::process::Command::new("powershell")

        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])

        .output()

        .map_err(|e| e.to_string())?;

    if !output.status.success() {

        let err = String::from_utf8_lossy(&output.stderr).to_string();

        return Err(format!("HTTP error: {}", err));

    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let body: serde_json::Value = serde_json::from_str(stdout.trim())

        .map_err(|e| format!("Parse error: {}", e))?;

    let manifest_url = body.get("manifestUrl")

        .and_then(|v| v.as_str()).unwrap_or("").to_string();

    let remote_version: i32 = manifest_url.split("/")

        .find(|s| s.ends_with("R") && s[..s.len().saturating_sub(1)].chars().all(|c| c.is_ascii_digit()))

        .and_then(|s| s[..s.len()-1].parse().ok())

        .unwrap_or(0);

    Ok(serde_json::json!({

        "remote_version": remote_version,

        "manifest_url": manifest_url,

    }))

}





/// Read cached game version from Nexon Launcher HTTP cache (no auth required).

#[tauri::command]

fn get_mabi_version_from_launcher_cache() -> Result<serde_json::Value, String> {

    #[cfg(target_os = "windows")]

    {

        let appdata = std::env::var("APPDATA").map_err(|e| e.to_string())?;

        let cache_path = std::path::PathBuf::from(&appdata)

            .join("NexonLauncher").join("Cache").join("Cache_Data").join("data_1");

        let (cached_version, cached_manifest_url): (Option<i32>, Option<String>) = if cache_path.exists() {

            let bytes = std::fs::read(&cache_path).unwrap_or_default();

            let text = String::from_utf8_lossy(&bytes);

            if let Some(pos) = text.find("\"manifestUrl\":\"http") {

                let start = pos + "\"manifestUrl\":\"".len();

                let rest = &text[start..];

                let end = rest.find('"').unwrap_or(rest.len());

                let url = rest[..end].to_string();

                let ver: Option<i32> = url.split('/')

                    .find(|s| s.ends_with('R') && s.len() > 1 && s[..s.len()-1].chars().all(|c| c.is_ascii_digit()))

                    .and_then(|s| s[..s.len()-1].parse().ok());

                (ver, Some(url))

            } else { (None, None) }

        } else { (None, None) };

        let local_manifest_hash: Option<String> = {

            let db_path = std::path::PathBuf::from(&appdata).join("NexonLauncher").join("installed-apps.db");

            std::fs::read_to_string(&db_path).ok()

                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())

                .and_then(|db| {

                    db["installedApps"]["10200"]["localManifest"]

                        .as_str()

                        .and_then(|p| std::fs::read_to_string(p).ok())

                        .map(|s| s.trim().to_string())

                })

        };

        let cdn_cmd = "try{(Invoke-WebRequest -Uri 'http://download2.nexon.net/Game/nxl/games/10200/10200.manifest.hash' -TimeoutSec 8 -UseBasicParsing).Content.Trim()}catch{''}";

        let cdn_out = std::process::Command::new("powershell")

            .args(["-NoProfile", "-NonInteractive", "-Command", cdn_cmd])

            .output().ok();

        let cdn_hash: Option<String> = cdn_out

            .filter(|o| o.status.success())

            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())

            .filter(|s| s.len() == 40);

        let update_available = match (&local_manifest_hash, &cdn_hash) {

            (Some(l), Some(c)) => Some(l != c),

            _ => None,

        };

        Ok(serde_json::json!({

            "cached_version": cached_version,

            "cached_manifest_url": cached_manifest_url,

            "local_manifest_hash": local_manifest_hash,

            "cdn_manifest_hash": cdn_hash,

            "update_available": update_available,

        }))

    }

    #[cfg(not(target_os = "windows"))]

    Err("Windows only".to_string())

}


/// Apply a .mod TOML file to an archive in-place.

#[tauri::command]

fn apply_mod(

    mod_toml: String,

    archive: String,

    key: Option<String>,

    mod_dir: Option<String>,

) -> Result<serde_json::Value, String> {

    let pkg = mabi_pack2::mod_file::ModPackage::from_str(&mod_toml)

        .map_err(|e| e.to_string())?;

    let dir = mod_dir

        .map(std::path::PathBuf::from)

        .unwrap_or_else(std::env::temp_dir);

    // Re-use the same logic as the REST API via a thin FFI through the core crate

    // Inline here to avoid coupling to src/api.rs internal helpers

    let salts = mabi_pack2::load_salts();

    let tmp = std::env::temp_dir().join(format!("mabi_mod_gui_{}", std::process::id()));

    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;

    let tmp_str = tmp.to_string_lossy().to_string();

    let salt_used = mabi_pack2::extract::run_extract_with_key_search(

        &archive, &tmp_str, key.clone(), &salts,

        vec![], None, false, false, false, None,

    ).map_err(|e| { let _ = std::fs::remove_dir_all(&tmp); e.to_string() })?;



    let mut replaced = 0usize; let mut deleted = 0usize; let mut patched = 0usize; let mut skipped = 0usize;

    use mabi_pack2::mod_file::FileAction;

    for entry in &pkg.files {

        let rel = entry.archive_path.replace('\\', std::path::MAIN_SEPARATOR_STR);

        let rel = rel.trim_start_matches("data/").trim_start_matches("data\\").to_string();

        let dest = tmp.join(&rel);

        match entry.action {

            FileAction::Delete => { if dest.exists() { std::fs::remove_file(&dest).ok(); deleted += 1; } else { skipped += 1; } }

            FileAction::Replace => {

                if let Some(src) = &entry.source {

                    let sp = if std::path::Path::new(src).is_absolute() { std::path::PathBuf::from(src) } else { dir.join(src) };

                    if let Some(p) = dest.parent() { std::fs::create_dir_all(p).ok(); }

                    std::fs::copy(&sp, &dest).map_err(|e| e.to_string())?; replaced += 1;

                } else { skipped += 1; }

            }

            FileAction::Patch => { skipped += 1; } // simplified; full logic is in api.rs

        }

    }



    // features toggle

    let has_feat = pkg.features.enable.as_ref().map_or(false, |v| !v.is_empty())

        || pkg.features.disable.as_ref().map_or(false, |v| !v.is_empty());

    if has_feat {

        if let Some(fp) = walkdir::WalkDir::new(&tmp).into_iter().filter_map(|e| e.ok())

            .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("features.xml.compiled"))

            .map(|e| e.path().to_path_buf())

        {

            if let Ok(raw) = std::fs::read(&fp) {

                if let Some(mut fd) = mabi_pack2::common_ext::parse_features_compiled(&raw) {

                    let ph = |s: &str| u32::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok();

                    for h in pkg.features.enable.iter().flatten().filter_map(|s| ph(s)) {

                        if let Some(f) = fd.features.iter_mut().find(|f| f.hash == h) { f.conditions.retain(|c| !c.is_empty()); }

                    }

                    for h in pkg.features.disable.iter().flatten().filter_map(|s| ph(s)) {

                        if let Some(f) = fd.features.iter_mut().find(|f| f.hash == h) { f.conditions = vec!["FALSE".to_string()]; }

                    }

                    let _ = std::fs::write(&fp, mabi_pack2::common_ext::encode_features_compiled(&fd));

                    patched += 1;

                }

            }

        }

    }



    let ks = key.as_deref().unwrap_or(&salt_used);

    let pref = if std::path::Path::new(&archive).file_name().and_then(|n| n.to_str())

        .map(|n| n.to_lowercase().ends_with(".pack")).unwrap_or(false) { Some("data") } else { None };

    mabi_pack2::pack::run_pack(&tmp_str, &archive, ks, vec![], false, 0, pref, None)

        .map_err(|e| { let _ = std::fs::remove_dir_all(&tmp); e.to_string() })?;

    let _ = std::fs::remove_dir_all(&tmp);



    Ok(serde_json::json!({

        "name": pkg.meta.name, "version": pkg.meta.version,

        "archive": archive,

        "replaced": replaced, "deleted": deleted, "patched": patched, "skipped": skipped,

    }))

}



/// Generate a .mod TOML file from selected entries in a uotiaralist.ini.

/// `ini_path`: path to uotiaralist.ini

/// `it_path`: path to the source uotiara .it archive (written into [[files]] source fields)

/// `selected_ids`: array of mod IDs (1-based) to include

/// Returns the TOML string of the generated .mod file.

#[tauri::command]

fn ini_to_mod(ini_path: String, it_path: String, selected_ids: Vec<u32>) -> Result<String, String> {

    let text = std::fs::read_to_string(&ini_path)

        .map_err(|e| format!("cannot read {}: {}", ini_path, e))?;



    // Minimal INI parser (duplicates the api.rs helper — keep them independent)

    let mut sections: std::collections::HashMap<String, std::collections::HashMap<String, String>> = Default::default();

    let mut section = String::new();

    for line in text.lines() {

        let line = line.trim();

        if line.is_empty() || line.starts_with(';') || line.starts_with('#') { continue; }

        if line.starts_with('[') && line.ends_with(']') {

            section = line[1..line.len()-1].to_string();

        } else if let Some(eq) = line.find('=') {

            sections.entry(section.clone()).or_default()

                .insert(line[..eq].trim().to_string(), line[eq+1..].trim().to_string());

        }

    }



    let mods_sec = sections.get("Mods").cloned().unwrap_or_default();

    let selected_set: std::collections::HashSet<u32> = selected_ids.iter().cloned().collect();



    let mut toml = format!(

        "[meta]\nname = \"uotiara-custom\"\nversion = \"1.0.0\"\nauthor = \"uotiara\"\ndescription = \"Auto-generated from {}\"\n\n",

        std::path::Path::new(&ini_path).file_name().and_then(|n| n.to_str()).unwrap_or("uotiaralist.ini")

    );



    for id in &selected_ids {

        let name = match mods_sec.get(&id.to_string()) {

            Some(n) if !n.is_empty() => n.clone(),

            _ => continue,

        };

        let file_sec = sections.get(&name).cloned().unwrap_or_default();

        if file_sec.is_empty() { continue; }



        toml.push_str(&format!("# Mod {}: {}\n", id, name));

        let mut file_nums: Vec<u32> = file_sec.keys()

            .filter_map(|k| k.strip_prefix("File").and_then(|n| n.parse().ok()))

            .collect();

        file_nums.sort_unstable();



        for fnum in file_nums {

            if let Some(path) = file_sec.get(&format!("File{}", fnum)) {

                let norm = path.replace('\\', "/").trim_start_matches('/').to_string();

                toml.push_str(&format!(

                    "[[files]]\narchive_path = \"{}\"\nop = \"replace\"\nsource = \"{}\"\n\n",

                    norm, it_path.replace('\\', "/")

                ));

            }

        }

    }

    let _ = selected_set; // suppress unused warning

    Ok(toml)

}



/// VFS change descriptor — one op per file operation.

#[derive(serde::Deserialize, Debug)]

#[serde(tag = "op", rename_all = "lowercase")]

enum VfsChange {

    Delete { path: String },

    Rename { from: String, to: String },

    Add { dest: String, local_src: String },

    Merge { src_archive: String, src_key: Option<String> },

}



/// Apply a list of VFS changes (delete/rename/add/merge) to an archive in-place.

#[tauri::command]

fn apply_vfs_changes(

    archive: String,

    key: Option<String>,

    changes: Vec<VfsChange>,

) -> Result<serde_json::Value, String> {

    use std::path::Path;



    let salts = mabi_pack2::load_salts();

    let tmp_dir = std::env::temp_dir().join(format!("mabi_vfs_{}", std::process::id()));

    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

    let tmp_str = tmp_dir.to_string_lossy().to_string();



    // Extract entire archive

    let salt_used = mabi_pack2::extract::run_extract_with_key_search(

        &archive, &tmp_str, key.clone(), &salts,

        vec![], None, false, false, false, None,

    ).map_err(|e| { let _ = std::fs::remove_dir_all(&tmp_dir); e.to_string() })?;



    let mut stats = serde_json::json!({ "deleted": 0, "renamed": 0, "added": 0, "merged": 0 });



    let normalize = |p: &str| -> String {

        p.replace('\\', "/").trim_start_matches('/').to_string()

    };



    for change in &changes {

        match change {

            VfsChange::Delete { path } => {

                let rel = normalize(path);

                let target = tmp_dir.join(&rel);

                if target.exists() {

                    std::fs::remove_file(&target).map_err(|e| e.to_string())?;

                    stats["deleted"] = (stats["deleted"].as_i64().unwrap_or(0) + 1).into();

                }

            }

            VfsChange::Rename { from, to } => {

                let src = tmp_dir.join(normalize(from));

                let dst = tmp_dir.join(normalize(to));

                if let Some(p) = dst.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }

                if src.exists() {

                    std::fs::rename(&src, &dst).map_err(|e| e.to_string())?;

                    stats["renamed"] = (stats["renamed"].as_i64().unwrap_or(0) + 1).into();

                }

            }

            VfsChange::Add { dest, local_src } => {

                let dst = tmp_dir.join(normalize(dest));

                if let Some(p) = dst.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }

                std::fs::copy(Path::new(local_src), &dst).map_err(|e| e.to_string())?;

                stats["added"] = (stats["added"].as_i64().unwrap_or(0) + 1).into();

            }

            VfsChange::Merge { src_archive, src_key } => {

                let merge_tmp = std::env::temp_dir().join(format!("mabi_vfs_merge_{}", std::process::id()));

                std::fs::create_dir_all(&merge_tmp).map_err(|e| e.to_string())?;

                let merge_str = merge_tmp.to_string_lossy().to_string();

                mabi_pack2::extract::run_extract_with_key_search(

                    src_archive, &merge_str, src_key.clone(), &salts,

                    vec![], None, false, false, false, None,

                ).map_err(|e| { let _ = std::fs::remove_dir_all(&merge_tmp); e.to_string() })?;

                // Copy all files from merge_tmp into tmp_dir (overwrite = newer wins)

                let mut count = 0u32;

                for entry in walkdir::WalkDir::new(&merge_tmp).into_iter().filter_map(|e| e.ok()) {

                    if entry.file_type().is_file() {

                        let rel = entry.path().strip_prefix(&merge_tmp).unwrap();

                        let dst = tmp_dir.join(rel);

                        if let Some(p) = dst.parent() { std::fs::create_dir_all(p).map_err(|e| e.to_string())?; }

                        std::fs::copy(entry.path(), &dst).map_err(|e| e.to_string())?;

                        count += 1;

                    }

                }

                let _ = std::fs::remove_dir_all(&merge_tmp);

                stats["merged"] = (stats["merged"].as_i64().unwrap_or(0) + count as i64).into();

            }

        }

    }



    // Repack modified tree back into archive

    let key_str = key.as_deref().unwrap_or(&salt_used);

    let archive_name = Path::new(&archive).file_name()

        .and_then(|n| n.to_str()).unwrap_or("");

    let prefix = if archive_name.to_lowercase().ends_with(".pack") { Some("data") } else { None };

    mabi_pack2::pack::run_pack(&tmp_str, &archive, key_str, vec![], false, 0, prefix, None)

        .map_err(|e| { let _ = std::fs::remove_dir_all(&tmp_dir); e.to_string() })?;

    let _ = std::fs::remove_dir_all(&tmp_dir);



    Ok(serde_json::json!({ "archive": archive, "changes": changes.len(), "stats": stats }))

}





/// Convert a uotiaralist.ini (or .nsi) into a .mod TOML — frontend-facing alias.

/// it_path defaults to empty; the [[files]] source field can be edited manually.

#[tauri::command]

fn nsi_to_mod(nsi_path: String, selected_ids: Vec<u32>) -> Result<String, String> {

    ini_to_mod(nsi_path, String::new(), selected_ids)

}



/// Persist pending VFS changes to <archive>.pending.json.

/// Passing an empty array deletes the file.

#[tauri::command]

fn save_pending_changes(archive: String, changes: Vec<serde_json::Value>) -> Result<(), String> {

    let pending_path = format!("{}.pending.json", archive);

    if changes.is_empty() {

        if Path::new(&pending_path).exists() {

            let _ = fs::remove_file(&pending_path);

        }

    } else {

        let json = serde_json::to_string_pretty(&changes).map_err(|e| e.to_string())?;

        fs::write(&pending_path, &json).map_err(|e| e.to_string())?;

    }

    Ok(())

}



/// Load pending VFS changes from <archive>.pending.json.

#[tauri::command]

fn load_pending_changes(archive: String) -> Result<Vec<serde_json::Value>, String> {

    let pending_path = format!("{}.pending.json", archive);

    if !Path::new(&pending_path).exists() {

        return Ok(Vec::new());

    }

    let raw = fs::read_to_string(&pending_path).map_err(|e| e.to_string())?;

    Ok(serde_json::from_str(&raw).unwrap_or_default())

}



/// Kanan LibLoader mod entry.

#[derive(Serialize, Deserialize, Clone)]

pub struct KananMod {

    pub name: String,

    pub enabled: bool,

}



/// Read a Kanan LibLoader Loader.cfg (INI-style) and return mod list.

#[tauri::command]

fn read_kanan_cfg(path: String) -> Result<Vec<KananMod>, String> {

    let content = fs::read_to_string(&path).map_err(|e| format!("Cannot read {}: {}", path, e))?;

    let mut mods: Vec<KananMod> = Vec::new();

    let mut current_name: Option<String> = None;

    for line in content.lines() {

        let line = line.trim();

        if line.starts_with('[') && line.ends_with(']') {

            current_name = Some(line[1..line.len() - 1].trim().to_string());

        } else if let Some(ref name) = current_name {

            if let Some(rest) = line.strip_prefix("Enabled=") {

                let enabled = rest.trim().eq_ignore_ascii_case("true");

                mods.push(KananMod { name: name.clone(), enabled });

                current_name = None;

            }

        }

    }

    Ok(mods)

}



/// Write updated mod list back to a Kanan LibLoader Loader.cfg.

#[tauri::command]

fn write_kanan_cfg(path: String, mods: Vec<KananMod>) -> Result<(), String> {

    let mut out = String::new();

    for m in &mods {

        out.push('[');

        out.push_str(&m.name);

        out.push_str("]\r\nEnabled=");

        out.push_str(if m.enabled { "true" } else { "false" });

        out.push_str("\r\n\r\n");

    }

    fs::write(&path, out.trim_end()).map_err(|e| format!("Cannot write {}: {}", path, e))

}



#[tauri::command]

fn convert_xml_compiled(archive_path: String, entry_path: String, key: Option<String>) -> Result<String, String> {

    let salts = mabi_pack2::load_salts();

    let tmp_dir = std::env::temp_dir().join(format!("mabi_feat_xml_{}", std::process::id()));

    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

    let clean = || { let _ = std::fs::remove_dir_all(&tmp_dir); };



    let fname = std::path::Path::new(&entry_path)

        .file_name()

        .map(|f| f.to_string_lossy().to_string())

        .unwrap_or_else(|| entry_path.clone());



    mabi_pack2::extract::run_extract_with_key_search(

        &archive_path, &tmp_dir.to_string_lossy(), key,

        &salts, vec![fname.clone()], None, false, false, false, None,

    ).map_err(|e| { clean(); e.to_string() })?;



    let extracted = walkdir::WalkDir::new(&tmp_dir).into_iter()

        .filter_map(|e| e.ok())

        .find(|e| e.file_name().to_string_lossy().to_lowercase() == fname.to_lowercase())

        .map(|e| e.into_path());



    let data = match extracted {

        Some(p) => std::fs::read(&p).map_err(|e| { clean(); e.to_string() })?,

        None => { clean(); return Err(format!("{} not found in archive", fname)); }

    };

    clean();



    let parsed = mabi_pack2::common_ext::parse_features_compiled(&data)

        .ok_or_else(|| "Failed to parse features.xml.compiled".to_string())?;



    // Emit as human-readable XML. FeatureEntry only carries hash/hash_hex/

    // conditions (no name field) — a feature with no conditions listed is

    // enabled by default; ["FALSE"] is how apply_mod/handle_features_save

    // represent "disabled" (see their feature-toggle logic).

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<features>\n");

    for f in &parsed.features {

        let enabled = !f.conditions.iter().any(|c| c.eq_ignore_ascii_case("FALSE"));

        if f.conditions.is_empty() {

            xml.push_str(&format!("  <feature hash=\"{}\" enabled=\"{}\" />\n",

                f.hash_hex, enabled));

        } else {

            xml.push_str(&format!("  <feature hash=\"{}\" enabled=\"{}\">\n",

                f.hash_hex, enabled));

            for c in &f.conditions {

                xml.push_str(&format!("    <condition>{}</condition>\n", c));

            }

            xml.push_str("  </feature>\n");

        }

    }

    xml.push_str("</features>\n");

    Ok(xml)

}



#[tauri::command]

fn export_pmg_obj(archive_path: String, entry_path: String, key: Option<String>) -> Result<String, String> {

    let salts = mabi_pack2::load_salts();

    let tmp_dir = std::env::temp_dir().join(format!("mabi_pmg_obj_{}", std::process::id()));

    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;

    let clean = || { let _ = std::fs::remove_dir_all(&tmp_dir); };



    let fname = std::path::Path::new(&entry_path)

        .file_name()

        .map(|f| f.to_string_lossy().to_string())

        .unwrap_or_else(|| entry_path.clone());



    mabi_pack2::extract::run_extract_with_key_search(

        &archive_path, &tmp_dir.to_string_lossy(), key,

        &salts, vec![fname.clone()], None, false, false, false, None,

    ).map_err(|e| { clean(); e.to_string() })?;



    let extracted = walkdir::WalkDir::new(&tmp_dir).into_iter()

        .filter_map(|e| e.ok())

        .find(|e| e.file_name().to_string_lossy().to_lowercase() == fname.to_lowercase())

        .map(|e| e.into_path());



    let data = match extracted {

        Some(p) => std::fs::read(&p).map_err(|e| { clean(); e.to_string() })?,

        None => { clean(); return Err(format!("{} not found in archive", fname)); }

    };

    clean();



    let geo = parse_pmg_bytes(&data)?;

    let mut obj = String::from("# Exported by mabi-patcher\n");

    // `positions` is the flat local-space xyz array (see PmgGeometry / parse_pmg_bytes).

    let verts: Vec<[f32;3]> = geo.positions.chunks_exact(3)

        .map(|c| [c[0], c[1], c[2]]).collect();

    for v in &verts {

        obj.push_str(&format!("v {} {} {}\n", v[0], v[1], v[2]));

    }

    if geo.normals.len() == geo.positions.len() {

        for n in geo.normals.chunks_exact(3) {

            obj.push_str(&format!("vn {} {} {}\n", n[0], n[1], n[2]));

        }

    }

    if geo.uvs.len() / 2 == geo.positions.len() / 3 {

        for uv in geo.uvs.chunks_exact(2) {

            obj.push_str(&format!("vt {} {}\n", uv[0], uv[1]));

        }

    }

    for tri in geo.indices.chunks_exact(3) {

        let (a,b,c) = (tri[0]+1, tri[1]+1, tri[2]+1);

        if !geo.uvs.is_empty() && geo.normals.len() == geo.positions.len() {

            obj.push_str(&format!("f {0}/{0}/{0} {1}/{1}/{1} {2}/{2}/{2}\n", a, b, c));

        } else if geo.normals.len() == geo.positions.len() {

            obj.push_str(&format!("f {0}//{0} {1}//{1} {2}//{2}\n", a, b, c));

        } else {

            obj.push_str(&format!("f {} {} {}\n", a, b, c));

        }

    }

    Ok(obj)

}





#[derive(serde::Serialize, Clone)]
struct PatchProgressEvent {
    phase: String,
    current_file: String,
    parts_done: usize,
    parts_total: usize,
    files_done: usize,
    files_total: usize,
    pct: f64,
    speed_bps: Option<u64>,
    error: Option<String>,
}

#[derive(serde::Serialize, Clone)]
struct PatchWorkerEvent {
    worker_id: usize,
    phase: String,
    file_name: String,
    parts_done: usize,
    parts_total: usize,
}

/// Cancel flag for the running patch (Stop button).
static PATCH_CANCEL: once_cell::sync::Lazy<std::sync::Mutex<std::sync::Arc<std::sync::atomic::AtomicBool>>> =
    once_cell::sync::Lazy::new(Default::default);

#[tauri::command]
fn patch_cancel() -> bool {
    PATCH_CANCEL.lock().unwrap().store(true, std::sync::atomic::Ordering::Relaxed);
    true
}

/// Local vs. remote manifest. `game_path` may be the install root, appdata, patchdata
/// or Client.exe. The remote check needs a session (branch API).
#[tauri::command]
async fn check_patch_version(game_path: String, session: Option<SessionInfo>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use mabi_pack2::launcher::patch;
        let roots = patch::GameRoots::resolve(&game_path);
        let local_hash = roots.local_hash();
        let local_manifest = local_hash.as_ref()
            .and_then(|h| std::fs::read(roots.patchdata.join(h)).ok().and_then(|b| patch::Manifest::parse(h, &b).ok()));
        let local_version = local_manifest.as_ref().and_then(|m| get_managed_version(m.buildtime.round() as i64));

        let (remote_hash, remote_version, remote_error) = match patch::remote_manifest_hash(session.as_ref()) {
            Ok(h) if Some(&h) == local_hash.as_ref() => (Some(h), local_version, None),
            Ok(h) => {
                let v = patch::load_manifest(&roots, &h).ok()
                    .and_then(|m| get_managed_version(m.buildtime.round() as i64));
                (Some(h), v, None)
            }
            Err(e) => (None, None, Some(e.to_string())),
        };
        let needs_update = match (&local_hash, &remote_hash) {
            (_, None) => false,
            (Some(l), Some(r)) => l != r,
            (None, Some(_)) => true,
        };
        Ok(serde_json::json!({
            "local_version": local_version,
            "remote_version": remote_version,
            "local_hash": local_hash,
            "remote_hash": remote_hash,
            "needs_update": needs_update,
            "error": remote_error,
        }))
    }).await.map_err(|e| e.to_string())?
}

/// Patch the game from Nexon's NXL CDN (core launcher::patch — ported from Rua).
#[tauri::command]
async fn patch_game_files(
    game_path: String,
    max_workers: Option<u32>,
    force_repair: Option<bool>,
    verify: Option<bool>,
    _parallel_ops: Option<bool>,
    ignore: Option<Vec<String>>,
    session: Option<SessionInfo>,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    use mabi_pack2::launcher::patch::{self, PatchEvent, PatchMode, PatchOptions};
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    *PATCH_CANCEL.lock().unwrap() = cancel.clone();
    let opts = PatchOptions {
        mode: if force_repair == Some(true) { PatchMode::ForceAll }
              else if verify == Some(true) { PatchMode::Verify }
              else { PatchMode::Update },
        max_workers: max_workers.unwrap_or(8).clamp(1, 32) as usize,
        ignore: ignore.unwrap_or_default(),
        scan_only: false,
        manifest_hash: None,
        cancel,
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let roots = patch::GameRoots::resolve(&game_path);
        let last_emit = std::sync::atomic::AtomicU64::new(0);
        let on_event = |ev: PatchEvent| {
            match ev {
                PatchEvent::Log { message } => log::info!("[Patcher] {}", message),
                PatchEvent::Scan { done, total, need, file } => {
                    let _ = app.emit("patch-progress", PatchProgressEvent {
                        phase: "scanning".into(), current_file: file,
                        parts_done: done, parts_total: total, files_done: need, files_total: total,
                        pct: done as f64 / total.max(1) as f64 * 10.0, speed_bps: None, error: None,
                    });
                }
                PatchEvent::Download { files_done, files_total, bytes, bytes_total, speed_bps, file } => {
                    // Rate-limit to ~10/s so WebView2 isn't flooded.
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let prev = last_emit.load(std::sync::atomic::Ordering::Relaxed);
                    if files_done == files_total || now.saturating_sub(prev) >= 100 {
                        last_emit.store(now, std::sync::atomic::Ordering::Relaxed);
                        let _ = app.emit("patch-progress", PatchProgressEvent {
                            phase: "installing".into(), current_file: file,
                            parts_done: files_done, parts_total: files_total, files_done, files_total,
                            pct: 10.0 + bytes as f64 / bytes_total.max(1) as f64 * 90.0,
                            speed_bps: Some(speed_bps), error: None,
                        });
                    }
                }
                PatchEvent::Worker { worker_id, phase, file, parts_done, parts_total } => {
                    let phase = if phase == "downloading" && parts_done > 0 { "assembling".to_string() } else { phase };
                    let _ = app.emit("patch-worker", PatchWorkerEvent {
                        worker_id, phase, file_name: file, parts_done, parts_total,
                    });
                }
            }
        };
        let r = patch::run_patcher(&roots, session.as_ref(), &opts, &on_event);
        (r, app)
    }).await.map_err(|e| e.to_string())?;
    let (r, app) = result;

    let done = |err: Option<String>| {
        let _ = app.emit("patch-progress", PatchProgressEvent {
            phase: if err.is_some() { "error".into() } else { "done".into() },
            current_file: String::new(), parts_done: 0, parts_total: 0, files_done: 0, files_total: 0,
            pct: 100.0, speed_bps: None, error: err,
        });
    };
    let r = match r {
        Ok(r) => { done(None); r }
        Err(e) => { done(Some(e.to_string())); return Err(e.to_string()); }
    };
    let managed_version = get_managed_version(r.buildtime.round() as i64).unwrap_or(0);
    let message = if r.cancelled { Some("Patch cancelled — run Update again to resume".to_string()) }
        else if r.need.is_empty() { Some("Game is already up to date".to_string()) }
        else { None };
    Ok(serde_json::json!({
        "ok": r.errors.is_empty() && !r.cancelled,
        "patched": r.patched,
        "need": r.need.len(),
        "managed_version": managed_version,
        "manifest_hash": r.manifest_hash,
        "errors": r.errors,
        "cancelled": r.cancelled,
        "needs_elevation": r.needs_elevation,
        "message": message,
    }))
}


#[tauri::command]
fn clear_patch_cache(game_path: String) -> Result<serde_json::Value, String> {
    let patchdata = mabi_pack2::launcher::patch::GameRoots::resolve(&game_path).patchdata;
    let cache = patchdata.join("Patch");
    if cache.exists() {
        std::fs::remove_dir_all(&cache).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "ok": true, "deleted": true }))
    } else {
        Ok(serde_json::json!({ "ok": true, "deleted": false }))
    }
}
fn get_managed_version(buildtime: i64) -> Option<i64> {
    let body = format!("Action=CV&buildtime={}", buildtime);
    let resp = ureq::post("http://theproffessorslaboratory.net/api.php")
        .timeout(std::time::Duration::from_secs(10))
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)
        .ok()?;
    let text = resp.into_string().ok()?;
    text.trim().parse::<i64>().ok()
}

#[tauri::command]
fn verify_game_files(game_path: String) -> Result<serde_json::Value, String> {
    use mabi_pack2::launcher::patch;
    let roots = patch::GameRoots::resolve(&game_path);
    let fail = |msg: String| Ok(serde_json::json!({ "ok": false, "version": 0, "error": msg, "missing": [], "mismatched": [] }));
    if !roots.patchdata.exists() {
        return fail(format!("patchdata directory not found ({})", roots.patchdata.display()));
    }
    let hash = match roots.local_hash() { Some(h) => h, None => return fail("no manifest hash found".into()) };
    let manifest = match std::fs::read(roots.patchdata.join(&hash)) {
        Ok(b) => patch::Manifest::parse(&hash, &b).map_err(|e| e.to_string())?,
        Err(_) => return fail(format!("manifest {} not in patchdata", &hash[..12.min(hash.len())])),
    };
    let root = manifest.content_root(&roots);
    let mut missing: Vec<String> = Vec::new();
    let mut mismatched: Vec<serde_json::Value> = Vec::new();
    let mut ok_count = 0u64;
    for e in manifest.entries.iter().filter(|e| !e.is_dir) {
        match std::fs::metadata(root.join(&e.path)) {
            Err(_) => missing.push(e.path.clone()),
            Ok(m) if e.fsize > 0 && m.len() != e.fsize => {
                mismatched.push(serde_json::json!({ "path": e.path, "expected": e.fsize, "actual": m.len() }));
            }
            _ => ok_count += 1,
        }
    }
    let version = std::fs::read(roots.appdata.join("version.dat")).ok()
        .filter(|b| b.len() >= 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
    let managed_version = get_managed_version(manifest.buildtime.round() as i64).unwrap_or(version as i64);
    Ok(serde_json::json!({
        "ok": missing.is_empty() && mismatched.is_empty(),
        "local_version": version,
        "managed_version": managed_version,
        "version": managed_version,
        "buildtime": manifest.buildtime,
        "manifest_hash": hash,
        "files_ok": ok_count,
        "files_missing": missing.len(),
        "files_mismatched": mismatched.len(),
        "missing": &missing[..missing.len().min(50)],
        "mismatched": &mismatched[..mismatched.len().min(50)],
    }))
}

#[tauri::command]
fn repair_game_files(game_path: String) -> Result<serde_json::Value, String> {
    let game_dir = std::path::Path::new(&game_path);
    let mabdown = game_dir.join("MabiTDown.exe");
    if mabdown.exists() {
        std::process::Command::new(&mabdown)
            .arg("/repair")
            .current_dir(game_dir)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(serde_json::json!({ "action": "mabitydown_launched" }));
    }
    let nexon_launchers: &[&str] = &[
        r"C:\Program Files\Nexon\Nexon Client\NGMDll.exe",
        r"C:\Program Files (x86)\Nexon\Nexon Client\NGMDll.exe",
        r"C:\Program Files\Nexon\NXL\NGMDll.exe",
        r"C:\Program Files (x86)\Nexon\NXL\NGMDll.exe",
    ];
    for launcher in nexon_launchers {
        if std::path::Path::new(launcher).exists() {
            std::process::Command::new(launcher)
                .spawn()
                .map_err(|e| e.to_string())?;
            return Ok(serde_json::json!({ "action": "nexon_launcher_started", "path": launcher }));
        }
    }
    let mut result = verify_game_files(game_path)?;
    result["action"] = serde_json::json!("verify_only");
    Ok(result)
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

            get_preview_ext, parse_pmg_geometry, parse_set_header, parse_rgn, parse_area, parse_anievent, get_config, set_config,

            get_config_path_str, get_appdata_config_path, get_portable_config_path,

            is_portable_mode, set_portable_mode, reset_config, wipe_registry_associations,

            get_system_info, run_convert, get_app_exe_dir, open_log_file,

            get_all_salts, is_ran_as_admin, register_associations, request_elevation,

            execute_terminal_command, get_initial_file, check_data_folder, detect_data_prefix, log_to_file, drain_log_buffer,

            preview_loose_file,

            get_mods_dir, list_mod_files, load_mod_file, get_mod_template, get_api_port, nexon_login_webview,

            launcher_import_session, launcher_login, launcher_autologin, launcher_get_passport,

            launcher_check_maintenance, launcher_get_version, launcher_launch, launcher_login_otp, patch_cancel,

            launcher_list_profiles, launcher_save_profile, launcher_delete_profile,

            launcher_set_active_profile, launcher_load_profile, launcher_update_profile_session,

            detect_launcher_profiles,

            get_features_from_archive, save_features_to_archive,

            apply_vfs_changes,

            ini_to_mod, nsi_to_mod,

            save_pending_changes, load_pending_changes,

            read_kanan_cfg, write_kanan_cfg,

            apply_mod,

            get_mabi_version_local, get_mabi_version_remote, get_mabi_version_from_launcher_cache,

            convert_xml_compiled, export_pmg_obj, verify_game_files, repair_game_files, patch_game_files, check_patch_version, clear_patch_cache

        ])



        .run(tauri::generate_context!())

        .expect("error while running tauri application");

}





