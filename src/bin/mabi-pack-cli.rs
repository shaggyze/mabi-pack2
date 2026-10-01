// main.rs (CLI Binary)

use clap::{Command, Arg, ArgAction};
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rayon::prelude::*;
use simplelog::{CombinedLogger, WriteLogger, TermLogger, LevelFilter, ConfigBuilder, TerminalMode, ColorChoice, SharedLogger};
use log::{debug, info};

// Correct library name from Cargo.toml
use mabi_pack2::{api, load_salts, extract, list, mod_file, pack};
#[cfg(windows)]
use mabi_pack2::launcher::{auth, launch, patch};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Update the Windows shell context menu to point at this exe.
/// Runs on every launch so the "Open with mabi-pack2" entry always uses the binary that was last run.
#[cfg(windows)]
fn register_shell_menu() {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return,
    };

    let open_cmd = format!("\"{}\" extract -i \"%1\"", exe_path);
    let icon_val = format!("{},0", exe_path);

    let types = [
        "Mabinogi IT Archive",
        "Mabinogi PACK Archive",
    ];

    for file_type in &types {
        let cmd_key = format!("HKCU\\Software\\Classes\\{}\\shell\\open\\command", file_type);
        let icon_key = format!("HKCU\\Software\\Classes\\{}\\DefaultIcon", file_type);

        let _ = std::process::Command::new("reg")
            .args(["add", &cmd_key, "/ve", "/d", &open_cmd, "/f"])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output();

        let _ = std::process::Command::new("reg")
            .args(["add", &icon_key, "/ve", "/d", &icon_val, "/f"])
            .creation_flags(0x08000000)
            .output();
    }
}

fn num_cpus() -> usize {
    // 2× logical cores: Snow2 decrypt + zlib decompress is CPU+IO mixed,
    // so doubling threads over cores lets IO waits overlap with CPU work.
    std::thread::available_parallelism().map(|n| n.get() * 2).unwrap_or(8)
}

fn main() -> Result<()> {
    #[cfg(windows)]
    register_shell_menu();
    let matches = Command::new("mabi-pack2")
        .version("1.3.7")
        .author("regomne <fallingsunz@gmail.com>")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("Sets the verbosity level"),
        )
        .subcommand(
            Command::new("pack")
                .about("Create a .it pack")
                .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").help("Set the input folder to pack").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("PACK_NAME").help("Set the output .it file name").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Set the key for the .it file encryption").required(true))
                .arg(
                    Arg::new("iv")
                        .long("iv")
                        .value_name("IV")
                        .help("Initial vector (0 or 1, default: 0)")
                        .default_value("0")
                )
                .arg(
                    Arg::new("compress-format")
                        .short('f')
                        .long("compress-format")
                        .value_name("EXTENSION")
                        .help("Add an extension to compress in .it")
                        .required(false)
                        .action(ArgAction::Append)
                )
                .arg(
                    Arg::new("wrap-data")
                        .long("wrap-data")
                        .action(ArgAction::SetTrue)
                        .help("Automatically wrap files in a virtual 'data/' root folder")
                )
        )
        .subcommand(
            Command::new("extract")
                .about("Extract a .it pack.")
                .arg(Arg::new("input").short('i').long("input").value_name("PACK_NAME").help("Set the input pack name to extract").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("FOLDER").help("Set the output folder (optional, auto-generated if omitted)").required(false))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Specific key to try first (optional).").required(false))
                .arg(
                    Arg::new("filter")
                        .short('f')
                        .long("filter")
                        .value_name("FILTER")
                        .help("Set a filter when extracting")
                        .required(false)
                        .action(ArgAction::Append)
                ),
        )
        .subcommand(
            Command::new("list")
                .about("Output the file list of a .it pack.")
                .arg(Arg::new("input").short('i').long("input").value_name("PACK_NAME").help("Set the input pack name").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Specific key to try first (optional).").required(false))
                .arg(Arg::new("output").short('o').long("output").value_name("LIST_FILE_NAME").help("Output to file (optional)").required(false))
        )
        .subcommand(
            Command::new("convert")
                .about("Convert between .it and .pack formats.")
                .arg(Arg::new("input").short('i').long("input").value_name("INPUT").help("Source archive path").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("OUTPUT").help("Destination archive path").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY").help("Key for .it archives").required(false))
        )
        .subcommand(
            Command::new("full-sequence")
                .about("Extract all archives in a folder in order and pack into one.")
                .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").help("Folder containing multiple archives").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("ALL_DATA.IT").help("Output single archive path").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY").help("Specific salt for the final .it").required(false))
        )
        .subcommand(
            Command::new("serve")
                .about("Run mabi-patcher as an HTTP API server (for UOTiara WebUI integration)")
                .arg(
                    Arg::new("port")
                        .short('p')
                        .long("port")
                        .value_name("PORT")
                        .help("Port to listen on (default: 7331)")
                        .default_value("7331")
                )
                .arg(
                    Arg::new("host")
                        .long("host")
                        .value_name("HOST")
                        .help("Address to bind (default: 127.0.0.1; use 0.0.0.0 for Docker/LXC)")
                        .default_value("127.0.0.1")
                )
        )
        .subcommand(
            Command::new("mod")
                .about("Work with .mod instruction files")
                .subcommand(
                    Command::new("inspect")
                        .about("Parse and display a .mod file")
                        .arg(Arg::new("file").short('f').long("file").value_name("MOD_FILE").help(".mod file to inspect").required(true))
                )
                .subcommand(
                    Command::new("template")
                        .about("Print a blank .mod template to stdout")
                )
                .subcommand(
                    Command::new("list")
                        .about("List .mod files in a directory")
                        .arg(Arg::new("dir").short('d').long("dir").value_name("DIR").help("Directory to scan (default: mods/)").default_value("mods"))
                )
        )
        .subcommand(
            Command::new("launch")
                .about("Login to Nexon NA and launch Mabinogi (Windows only)")
                .arg(Arg::new("username").short('u').long("username").value_name("EMAIL").help("Nexon account email").required(true))
                .arg(Arg::new("password").short('p').long("password").value_name("PASSWORD").help("Nexon account password").required(true))
                .arg(Arg::new("client").short('c').long("client").value_name("DIR").help("Mabinogi installation directory (contains Client.exe)").required(true))
                .arg(Arg::new("remember").long("remember").action(ArgAction::SetTrue).help("Save session token for future auto-login"))
                .arg(Arg::new("version").long("version").action(ArgAction::SetTrue).help("Print the latest game version and exit (no launch)"))
        )
        .subcommand(
            Command::new("batch")
                .about("Extract all .it/.pack archives in a folder, merging output into one directory.")
                .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").help("Folder containing .it/.pack archives").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("OUT_FOLDER").help("Destination folder; archives are merged into a single folder tree by default").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Salt to try first; auto-detected from first archive if omitted").required(false))
                .arg(Arg::new("no-merge").long("no-merge").action(ArgAction::SetTrue).help("Extract each archive into its own named subdirectory (folder structure preserved inside each)"))
                .arg(
                    Arg::new("filter")
                        .short('f')
                        .long("filter")
                        .value_name("FILTER")
                        .help("Only extract files matching this regex pattern")
                        .required(false)
                        .action(ArgAction::Append)
                )
                .arg(
                    Arg::new("jobs")
                        .short('j')
                        .long("jobs")
                        .value_name("N")
                        .help("Number of archives to extract in parallel (default: 1; use 0 for CPU count)")
                        .required(false)
                        .default_value("1")
                )
        )
        .get_matches();

    let verbose_level = matches.get_count("verbose");
    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();

    let (console_log_level, file_log_level) = match verbose_level {
        0 => (LevelFilter::Info, LevelFilter::Off),
        1 => (LevelFilter::Info, LevelFilter::Info),
        2 => (LevelFilter::Debug, LevelFilter::Debug),
        _ => (LevelFilter::Trace, LevelFilter::Trace),
    };

    loggers.push(TermLogger::new(
        console_log_level,
        ConfigBuilder::new().build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ));

    if file_log_level > LevelFilter::Off {
        if let Ok(log_file) = OpenOptions::new().append(true).create(true).open("log.txt") {
            loggers.push(WriteLogger::new(file_log_level, ConfigBuilder::new().build(), log_file));
        }
    }
    
    let _ = CombinedLogger::init(loggers);

    let mut all_salts: Vec<String> = Vec::new();
    if matches.subcommand_matches("extract").is_some()
        || matches.subcommand_matches("list").is_some()
        || matches.subcommand_matches("batch").is_some()
    {
        all_salts = load_salts();
    }

    if let Some(sub_matches) = matches.subcommand_matches("list") {
        let cli_key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        let input_fname = sub_matches.get_one::<String>("input").unwrap();
        let output_path = sub_matches.get_one::<String>("output").map(|s| s.as_str());
        
        list::run_list_with_key_search(input_fname, cli_key, &all_salts, output_path)?;
    } else if let Some(sub_matches) = matches.subcommand_matches("extract") {
        let cli_key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        let input_fname = sub_matches.get_one::<String>("input").unwrap();
        let output_arg = sub_matches.get_one::<String>("output");
        
        // Auto-generate output folder if missing
        let output_path = match output_arg {
            Some(o) => o.to_string(),
            None => {
                let p = Path::new(input_fname);
                let stem = p.file_stem().unwrap_or_default().to_string_lossy();
                stem.into_owned()
            }
        };
        
        let filters: Vec<String> = sub_matches.get_many::<String>("filter").map_or(Vec::new(), |v| v.map(|s| s.to_string()).collect());
        
        extract::run_extract_with_key_search(
            input_fname,
            &output_path,
            cli_key,
            &all_salts,
            filters,
            None,
            false,
            false,
            false,
            None
        )?;
    } else if let Some(sub_matches) = matches.subcommand_matches("pack") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let output = sub_matches.get_one::<String>("output").unwrap();
        
        if output.to_lowercase().ends_with(".pack") {
            info!("[CLI] Creating legacy .pack archive: {}", output);
            mabi_pack2::pack_v1::run_pack_v1(input, output, 1)?;
        } else {
            let iv = sub_matches.get_one::<String>("iv").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            let wrap = sub_matches.get_flag("wrap-data");
            let path_prefix = if wrap { Some("data") } else { None };
            pack::run_pack(
                input,
                output,
                sub_matches.get_one::<String>("key").expect("Key required"),
                sub_matches.get_many::<String>("compress-format").map_or(Vec::new(), |v| v.map(|s| s.as_str()).collect()),
                false,
                iv,
                path_prefix,
                None
            )?;
        }
    } else if let Some(sub_matches) = matches.subcommand_matches("convert") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let output = sub_matches.get_one::<String>("output").unwrap();
        let key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        mabi_pack2::common_ext::convert(input, output, key, true)?;
    } else if let Some(sub_matches) = matches.subcommand_matches("full-sequence") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let output = sub_matches.get_one::<String>("output").unwrap();
        let key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        mabi_pack2::common_ext::run_full_sequence(input, output, key)?;
    } else if let Some(sub_matches) = matches.subcommand_matches("batch") {
        let input = sub_matches.get_one::<String>("input").unwrap();
        let output = sub_matches.get_one::<String>("output").unwrap();
        let cli_key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        let no_merge = sub_matches.get_flag("no-merge");
        let filters: Vec<String> = sub_matches
            .get_many::<String>("filter")
            .map_or(Vec::new(), |v| v.map(|s| s.to_string()).collect());
        let jobs: usize = sub_matches.get_one::<String>("jobs")
            .and_then(|s| s.parse::<usize>().ok())
            .map(|n| if n == 0 { num_cpus() } else { n })
            .unwrap_or(1);

        let mut archives: Vec<_> = std::fs::read_dir(input)?
            .filter_map(Result::ok)
            .filter(|e| {
                let ext = e.path().extension().unwrap_or_default().to_string_lossy().to_lowercase();
                ext == "it" || ext == "pack"
            })
            .collect();
        archives.sort_by_key(|e| e.file_name());

        let total = archives.len();
        if total == 0 {
            info!("No .it or .pack archives found in '{}'", input);
            return Ok(());
        }

        std::fs::create_dir_all(output)?;
        info!("Batch extracting {} archives from '{}' -> '{}' (jobs={})", total, input, output, jobs);

        if jobs <= 1 {
            // Sequential: show per-file progress with \r, cache salt across archives
            let mut cached_salt: Option<String> = cli_key.clone();

            for (idx, entry) in archives.iter().enumerate() {
                let path = entry.path();
                let fname = path.to_str().unwrap();
                let archive_name = entry.file_name().to_string_lossy().to_string();

                let out_dir = if no_merge {
                    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                    format!("{}/{}", output, stem)
                } else {
                    output.to_string()
                };
                std::fs::create_dir_all(&out_dir)?;

                let arc_label = archive_name.clone();
                let progress_cb: &extract::ProgressFn = &move |done, count, _msg| {
                    if count > 0 {
                        let pct = done * 100 / count;
                        print!("\r  [{}/{}] {} — {}%   ", idx + 1, total, arc_label, pct);
                        let _ = std::io::stdout().flush();
                    }
                };

                print!("[{}/{}] {} ...", idx + 1, total, archive_name);
                let _ = std::io::stdout().flush();

                match extract::run_extract_with_key_search(
                    fname,
                    &out_dir,
                    cached_salt.clone(),
                    &all_salts,
                    filters.clone(),
                    None,
                    false,
                    false,
                    false,
                    Some(progress_cb),
                ) {
                    Ok(found_salt) => {
                        if found_salt != "LEGACY_MABI" && found_salt != "LEGACY_PACK" && found_salt != "LOGUE_PACK" {
                            cached_salt = Some(found_salt);
                        }
                        println!("\r[{}/{}] {} done                    ", idx + 1, total, archive_name);
                    }
                    Err(e) => {
                        println!("\r[{}/{}] {} ERROR: {}          ", idx + 1, total, archive_name, e);
                    }
                }
            }
        } else {
            // Parallel: N archives at once, completion-only output to avoid garbled lines
            let completed = Arc::new(AtomicUsize::new(0));
            let salts_ref = &all_salts;
            let filters_ref = &filters;
            let output_ref = output.as_str();

            rayon::ThreadPoolBuilder::new()
                .num_threads(jobs)
                .build()?
                .install(|| {
                    archives.par_iter().for_each(|entry| {
                        let path = entry.path();
                        let fname = path.to_str().unwrap();
                        let archive_name = entry.file_name().to_string_lossy().to_string();

                        let out_dir = if no_merge {
                            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                            format!("{}/{}", output_ref, stem)
                        } else {
                            output_ref.to_string()
                        };
                        let _ = std::fs::create_dir_all(&out_dir);

                        let result = extract::run_extract_with_key_search(
                            fname,
                            &out_dir,
                            cli_key.clone(),
                            salts_ref,
                            filters_ref.clone(),
                            None,
                            false,
                            false,
                            false,
                            None, // no per-file progress in parallel mode
                        );

                        let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        match result {
                            Ok(_)  => println!("[{}/{}] {} done", n, total, archive_name),
                            Err(e) => println!("[{}/{}] {} ERROR: {}", n, total, archive_name, e),
                        }
                    });
                });
        }

        info!("Batch complete: {} archives -> '{}'", total, output);
    } else if let Some(sub) = matches.subcommand_matches("serve") {
        let port: u16 = sub.get_one::<String>("port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(api::DEFAULT_PORT);
        let host = sub.get_one::<String>("host").map(String::as_str).unwrap_or("127.0.0.1");
        info!("[SERVE] Starting mabi-patcher API server on http://{}:{}", host, port);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let stop2 = stop.clone();
            ctrlc_handler(move || { stop2.store(true, std::sync::atomic::Ordering::Relaxed); });
        }
        api::run_server(host, port, stop)?;
    } else if let Some(sub) = matches.subcommand_matches("mod") {
        if let Some(ins) = sub.subcommand_matches("inspect") {
            let path = std::path::Path::new(ins.get_one::<String>("file").unwrap());
            match mod_file::ModPackage::load(path) {
                Ok(pkg) => println!("{}", serde_json::to_string_pretty(&pkg).unwrap_or_default()),
                Err(e)  => { eprintln!("Error: {}", e); std::process::exit(1); }
            }
        } else if sub.subcommand_matches("template").is_some() {
            print!("{}", mod_file::template());
        } else if let Some(ls) = sub.subcommand_matches("list") {
            let dir = std::path::Path::new(ls.get_one::<String>("dir").unwrap());
            let mods = mod_file::scan_mods(dir);
            if mods.is_empty() {
                println!("No .mod files found in {}", dir.display());
            } else {
                for (path, result) in mods {
                    match result {
                        Ok(p)  => println!("[OK]  {}  — {} v{}", path.display(), p.meta.name, p.meta.version.as_deref().unwrap_or("?")),
                        Err(e) => println!("[ERR] {} — {}", path.display(), e),
                    }
                }
            }
        }
    } else if let Some(sub) = matches.subcommand_matches("launch") {
        #[cfg(not(windows))]
        { let _ = sub; return Err(anyhow::anyhow!("The 'launch' command is only available on Windows")); }

        #[cfg(windows)]
        {
            let username = sub.get_one::<String>("username").unwrap();
            let password = sub.get_one::<String>("password").unwrap();
            let client_dir = std::path::Path::new(sub.get_one::<String>("client").unwrap());
            let remember = sub.get_flag("remember");
            let version_only = sub.get_flag("version");

            info!("[LAUNCH] Logging in as {}...", username);
            let result = auth::login(username, password, remember, None)
                .map_err(|e| anyhow::anyhow!("Login failed: {}", e))?;

            let session = result.session.as_ref().unwrap();
            info!("[LAUNCH] Login OK. Session expires in {}s", result.session_expires_in);

            if version_only {
                let ver = patch::get_latest_version(session)
                    .map_err(|e| anyhow::anyhow!("Version check failed: {}", e))?;
                println!("Latest Mabinogi version: {}", ver);
                return Ok(());
            }

            info!("[LAUNCH] Fetching launch config...");
            let config = launch::fetch_launch_config(session)
                .map_err(|e| anyhow::anyhow!("Launch config error: {}", e))?;

            if config.patch_available {
                info!("[LAUNCH] Note: a game patch is available");
            }

            info!("[LAUNCH] Requesting passport...");
            let passport = auth::get_passport(session)
                .map_err(|e| anyhow::anyhow!("Passport error: {}", e))?;

            info!("[LAUNCH] Spawning {}...", config.executable_path);
            let _child = config.spawn_client(client_dir, &passport)
                .map_err(|e| anyhow::anyhow!("Spawn failed: {}", e))?;

            info!("[LAUNCH] Mabinogi launched.");
        }
    } else {
        info!("No subcommand provided. Use --help for usage information.");
    }

    debug!("completed successfully.");
    Ok(())
}

fn ctrlc_handler(f: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let _ = std::io::stdin().read_line(&mut String::new());
        f();
    });
}

