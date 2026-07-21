// main.rs - Hybrid CLI/GUI
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;
use std::fs::OpenOptions;
use std::path::Path;
use clap::{Command, Arg, ArgAction};
use anyhow::Result;
use simplelog::{CombinedLogger, WriteLogger, TermLogger, LevelFilter, ConfigBuilder, TerminalMode, ColorChoice, SharedLogger};
use log::{debug, info, warn, trace};

// Fixed library name
use mabi_pack2::{load_salts, list, extract, pack, pack_v1};

#[cfg(target_os = "windows")]
extern "C" {
    fn AttachConsole(dwProcessId: u32) -> i32;
    fn FreeConsole() -> i32;
}

#[cfg(target_os = "windows")]
fn is_webview2_installed() -> bool {
    use winreg::RegKey;
    use winreg::enums::*;
    let guid = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    let checks: &[(_, &str)] = &[
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\EdgeUpdate\\Clients"),
        (HKEY_CURRENT_USER,  "Software\\Microsoft\\EdgeUpdate\\Clients"),
    ];
    for (hive, base) in checks {
        if RegKey::predef(*hive).open_subkey(format!("{}\\{}", base, guid)).is_ok() {
            return true;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn show_webview2_missing_dialog() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    extern "system" {
        fn MessageBoxW(hwnd: *mut std::ffi::c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
        fn ShellExecuteW(hwnd: *mut std::ffi::c_void, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
    }
    fn wide(s: &str) -> Vec<u16> { OsStr::new(s).encode_wide().chain(Some(0)).collect() }

    let caption = wide("mabi-pack2 \u{2014} WebView2 Required");
    let text = wide(
        "Microsoft WebView2 Runtime is not installed.\n\
         mabi-pack2 requires WebView2 to display its GUI.\n\n\
         [Yes]    Auto-install (downloads ~1 MB bootstrapper and installs silently)\n\
         [No]     Open download page (install manually, then restart)\n\
         [Cancel] Exit"
    );
    let choice = unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 3 /* MB_YESNOCANCEL */)
    };

    match choice {
        6 /* IDYES */ => {
            // Download bootstrapper to temp, run /silent /install, wait
            let tmp = std::env::temp_dir().join("webview2setup.exe");
            let dl = std::process::Command::new("powershell")
                .args([
                    "-NoProfile", "-NonInteractive", "-Command",
                    &format!(
                        "Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile '{}'",
                        tmp.display()
                    ),
                ])
                .status();
            if dl.map(|s| s.success()).unwrap_or(false) {
                let installed = std::process::Command::new(&tmp)
                    .args(["/silent", "/install"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                let _ = std::fs::remove_file(&tmp);
                if installed {
                    return true; // caller should re-check and launch GUI
                }
            }
            // Install failed — tell user to try manually
            let err = wide("WebView2 installation failed.\nPlease download and install it manually from:\nhttps://developer.microsoft.com/microsoft-edge/webview2/");
            unsafe { MessageBoxW(std::ptr::null_mut(), err.as_ptr(), caption.as_ptr(), 0 /* MB_OK */); }
            false
        }
        7 /* IDNO */ => {
            let url  = wide("https://developer.microsoft.com/microsoft-edge/webview2/");
            let open = wide("open");
            unsafe { ShellExecuteW(std::ptr::null_mut(), open.as_ptr(), url.as_ptr(), std::ptr::null(), std::ptr::null(), 1); }
            false
        }
        _ /* IDCANCEL / closed */ => false,
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        let first_arg = &args[1];
        let known_cmds = ["extract", "pack", "list", "batch", "--convert", "--extract-all", "--extract-all-near", "--extract-here"];

        let is_explicit_cli = known_cmds.contains(&first_arg.as_str()) || (first_arg.starts_with('-') && !Path::new(first_arg).exists() && first_arg != "--gui" && first_arg != "--full");

        if is_explicit_cli {
            #[cfg(target_os = "windows")]
            unsafe { AttachConsole(0xFFFFFFFF); }

            println!("[mabi-pack2] Starting CLI mode...");
            let res = run_cli_logic();

            #[cfg(target_os = "windows")]
            unsafe { FreeConsole(); }

            return res;
        }
    }

    #[cfg(target_os = "windows")]
    if !is_webview2_installed() {
        let installed = show_webview2_missing_dialog();
        if !installed {
            return Ok(());
        }
        // Fall through — auto-install succeeded, launch GUI below
    }

    mabi_pack2_gui_lib::run();
    Ok(())
}

fn run_cli_logic() -> Result<()> {
    // Check for implicit file argument (drag and drop / double click)
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let file = &args[1];
        if file.to_lowercase().ends_with(".it") || file.to_lowercase().ends_with(".pack") {
            if Path::new(file).exists() {
                // Initialize a basic logger for implicit extraction
                let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();
                loggers.push(TermLogger::new(LevelFilter::Info, ConfigBuilder::new().build(), TerminalMode::Mixed, ColorChoice::Auto));
                let _ = CombinedLogger::init(loggers);

                info!("[CLI] Implicit extraction requested for: {}", file);
                let p = Path::new(file);
                let out = p.with_extension("");
                let out_str = out.to_str().unwrap();
                let salts = load_salts();
                if file.to_lowercase().ends_with(".it") {
                    return extract::run_extract_with_key_search(file, out_str, None, &salts, vec![], None, false, None).map(|_| ());
                } else {
                    return pack_v1::run_extract_v1(file, out_str);
                }
            }
        }
    }

    let matches = Command::new("mabi-pack2")
        .version("1.4.1")
        .author("regomne <fallingsunz@gmail.com>")
        .arg(Arg::new("verbose").short('v').long("verbose").action(ArgAction::Count))
        .subcommand(
            Command::new("pack")
                .about("Create archive")
                .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("PACK_NAME").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT"))
                .arg(Arg::new("auto-dds").long("auto-dds").action(ArgAction::SetTrue))
                .arg(Arg::new("pack-version").long("pack-version").value_name("VERSION").default_value("999"))
                .arg(Arg::new("additional_data").long("additional_data").action(ArgAction::SetTrue))
                .arg(Arg::new("wrap-data").long("wrap-data").action(ArgAction::SetTrue).help("Wrap files in virtual 'data/' root"))
                .arg(Arg::new("compress-format").short('f').long("compress-format").value_name("EXTENSION").action(ArgAction::Append))
        )
        .subcommand(
            Command::new("extract")
                .about("Extract archive")
                .arg(Arg::new("input").short('i').long("input").value_name("PACK_NAME").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("FOLDER").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT"))
                .arg(Arg::new("filter").short('f').long("filter").value_name("FILTER").action(ArgAction::Append))
                .arg(Arg::new("check_additional").short('c').long("check_additional").action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("list")
                .about("List archive")
                .arg(Arg::new("input").short('i').long("input").value_name("PACK_NAME").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT"))
                .arg(Arg::new("output").short('o').long("output").value_name("FILE"))
                .arg(Arg::new("check_additional").short('c').long("check_additional").action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("batch")
                .about("Extract all .it/.pack archives in a folder into one merged output tree. Use --no-merge to keep each archive in its own subfolder.")
                .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").required(true).help("Folder containing .it/.pack archives"))
                .arg(Arg::new("output").short('o').long("output").value_name("OUT_FOLDER").required(true).help("Destination folder"))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Salt to try first (auto-detected if omitted)"))
                .arg(Arg::new("no-merge").long("no-merge").action(ArgAction::SetTrue).help("Extract each archive into its own named subfolder instead of merging"))
                .arg(Arg::new("filter").short('f').long("filter").value_name("FILTER").action(ArgAction::Append).help("Only extract files matching this regex"))
                .arg(Arg::new("jobs").short('j').long("jobs").value_name("N").default_value("1")
                    .help("Archives to extract in parallel (0 = auto: 2x CPU cores)"))
        )
        .arg(Arg::new("convert").long("convert").value_name("FILE"))
        .arg(Arg::new("extract-all-near").long("extract-all-near").value_name("FILE"))
        .arg(Arg::new("extract-here").long("extract-here").value_name("FILE"))
        .get_matches();

    let verbose_level = matches.get_count("verbose");
    let (console_level, file_level) = match verbose_level {
        0 => (LevelFilter::Warn, LevelFilter::Info), 
        1 => (LevelFilter::Info, LevelFilter::Info),
        2 => (LevelFilter::Debug, LevelFilter::Debug),
        _ => (LevelFilter::Trace, LevelFilter::Trace),
    };
    
    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();
    loggers.push(TermLogger::new(console_level, ConfigBuilder::new().build(), TerminalMode::Mixed, ColorChoice::Auto));
    if let Ok(f) = OpenOptions::new().append(true).create(true).open("log.txt") {
        loggers.push(WriteLogger::new(file_level, ConfigBuilder::new().build(), f));
    }
    let _ = CombinedLogger::init(loggers);

    trace!("[CLI] Initializing logic with verbose level: {}", verbose_level);
    let salts = load_salts();
    debug!("[CLI] Loaded {} salts for matching.", salts.len());

    // Try to load last key from GUI config as a fallback
    let mut gui_last_key = None;
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "shaggyze", "mabi-pack2") {
        let config_path = proj_dirs.config_dir().join("config.json");
        if config_path.exists() {
            if let Ok(content) = std::fs::read_to_string(config_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(k) = v["last_key"].as_str() {
                        debug!("[CLI] Found GUI last_key: {}", k);
                        gui_last_key = Some(k.to_string());
                    }
                }
            }
        }
    }

    if let Some(file) = matches.get_one::<String>("convert") {
        info!("[CLI] Conversion requested for: {}", file);
        let p = Path::new(file);
        let new_ext = if p.extension().map_or(false, |e| e == "it") { "pack" } else { "it" };
        let out = p.with_extension(new_ext);
        trace!("[CLI] Target output path: {:?}", out);
        return mabi_pack2::common_ext::convert(file, out.to_str().unwrap(), gui_last_key, true);
    }

    if let Some(file) = matches.get_one::<String>("extract-here") {
        info!("[CLI] Extract-here requested for: {}", file);
        let p = Path::new(file);
        let out = p.with_extension("");
        let out_str = out.to_str().unwrap();
        if file.to_lowercase().ends_with(".it") {
            debug!("[CLI] Running .it search-extraction to: {}", out_str);
            return extract::run_extract_with_key_search(file, out_str, None, &salts, vec![], None, false, None).map(|_| ());
        } else {
            debug!("[CLI] Running legacy .pack extraction to: {}", out_str);
            return pack_v1::run_extract_v1(file, out_str);
        }
    }

    if let Some(file) = matches.get_one::<String>("extract-all-near") {
        info!("[CLI] Batch extraction requested near: {}", file);
        let p = Path::new(file);
        if let Some(parent) = p.parent() {
            let dir = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
            debug!("[CLI] Scanning directory: {:?}", dir);
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(Result::ok) {
                    let path = entry.path();
                    if path.is_file() {
                        let ext = path.extension().unwrap_or_default().to_string_lossy().to_lowercase();
                        if ext == "it" || ext == "pack" {
                            let out = path.with_extension("");
                            let out_str = out.to_str().unwrap();
                            let path_str = path.to_str().unwrap();
                            trace!("[CLI] Auto-extracting neighbor: {}", path_str);
                            if ext == "it" {
                                let _ = extract::run_extract_with_key_search(path_str, out_str, None, &salts, vec![], None, false, None).map(|_| ());
                            } else {
                                let _ = pack_v1::run_extract_v1(path_str, out_str);
                            }
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    if let Some(sub_matches) = matches.subcommand_matches("extract") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let output = sub_matches.get_one::<String>("output").unwrap();
        let key = sub_matches.get_one::<String>("key").cloned();
        info!("[CLI] Subcommand 'extract': Input={}, Output={}", input, output);
        if input.to_lowercase().ends_with(".pack") {
            debug!("[CLI] Handling legacy .pack input.");
            return pack_v1::run_extract_v1(input, output);
        } else {
            let filters: Vec<String> = sub_matches.get_many::<String>("filter").map_or(Vec::new(), |v| v.map(|s| s.clone()).collect());
            debug!("[CLI] Handling .it input with {} regex filters.", filters.len());
            return extract::run_extract_with_key_search(input, output, key, &salts, filters, None, false, None).map(|_| ());
        }
    }

    if let Some(sub_matches) = matches.subcommand_matches("pack") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let output = sub_matches.get_one::<String>("output").unwrap();
        info!("[CLI] Subcommand 'pack': Input={}, Output={}", input, output);
        if output.to_lowercase().ends_with(".pack") {
            let ver = sub_matches.get_one::<String>("pack-version").unwrap().parse().unwrap_or(999);
            debug!("[CLI] Packing legacy v1 with version header {}.", ver);
            return pack_v1::run_pack_v1(input, output, ver);
        } else {
            let key = sub_matches.get_one::<String>("key").expect("Key required for .it");
            let filters: Vec<&str> = sub_matches.get_many::<String>("compress-format").map_or(Vec::new(), |v| v.map(|s| s.as_str()).collect());
            debug!("[CLI] Packing modern .it with key {} and {} compression overrides.", key, filters.len());
            let wrap = sub_matches.get_flag("wrap-data");
            let path_prefix = if wrap { Some("data") } else { None };
            return pack::run_pack(input, output, key, filters, false, 0, path_prefix, None);
        }
    }

    if let Some(sub_matches) = matches.subcommand_matches("list") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let key = sub_matches.get_one::<String>("key").cloned();
        let output = sub_matches.get_one::<String>("output").map(|s| s.as_str());
        info!("[CLI] Subcommand 'list': Input={}, Output={:?}", input, output);
        if input.to_lowercase().ends_with(".pack") {
            debug!("[CLI] Listing legacy .pack.");
            let names = pack_v1::run_list_v1(input)?;
            for name in names { println!("{}", name); }
            return Ok(());
        } else {
            debug!("[CLI] Listing modern .it with search.");
            return list::run_list_with_key_search(input, key, &salts, output);
        }
    }

    if let Some(sub) = matches.subcommand_matches("batch") {
        let input = sub.get_one::<String>("input").unwrap();
        let output = sub.get_one::<String>("output").unwrap();
        let key = sub.get_one::<String>("key").cloned();
        let no_merge = sub.get_flag("no-merge");
        let filters: Vec<String> = sub.get_many::<String>("filter").map_or(Vec::new(), |v| v.map(|s| s.to_string()).collect());
        let jobs: usize = sub.get_one::<String>("jobs")
            .and_then(|s| s.parse::<usize>().ok())
            .map(|n| if n == 0 { std::thread::available_parallelism().map(|n| n.get() * 2).unwrap_or(8) } else { n })
            .unwrap_or(1);
        return mabi_pack2::common_ext::run_batch_extract(input, output, key, no_merge, filters, jobs);
    }

    warn!("[CLI] No valid subcommand provided. Use --help for usage.");
    Ok(())
}
