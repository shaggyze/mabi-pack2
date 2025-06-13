use clap::{Command, Arg, ArgAction};
use anyhow::Result;
use std::fs::File as StdFile;
use std::io::{BufReader as StdBufReader, BufRead};
use std::path::Path;
use std::fs::OpenOptions;

use simplelog::{CombinedLogger, WriteLogger, TermLogger, LevelFilter, ConfigBuilder, TerminalMode, ColorChoice, SharedLogger};
use log::{debug, error, info, warn};

mod common;
mod encryption;
mod extract;
mod list;
mod pack;

const SALTS_URL: &str = "https://shaggyze.website/files/salts.txt";

fn load_salts() -> Vec<String> {
    let mut salts = Vec::new();
    let local_path = Path::new("salts.txt");

    if local_path.exists() {
        debug!("Loading salts from local salts.txt");
        if let Ok(file) = StdFile::open(local_path) {
            let reader = StdBufReader::new(file);
            for line in reader.lines() {
                if let Ok(salt) = line {
                    if !salt.trim().is_empty() && !salt.starts_with('#') {
                        salts.push(salt.trim().to_string());
                    }
                }
            }
        }
        if !salts.is_empty() {
            debug!("Loaded {} salts from local file.", salts.len());
            return salts;
        } else {
            warn!("Local salts.txt was empty or unreadable. Attempting download...");
        }
    }

    debug!("Attempting to download salts from {}", SALTS_URL);
    match reqwest::blocking::get(SALTS_URL) {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(text) = response.text() {
                    for line in text.lines() {
                        if !line.trim().is_empty() && !line.starts_with('#') {
                            salts.push(line.trim().to_string());
                        }
                    }
                    if !salts.is_empty() {
                        debug!("Successfully downloaded and loaded {} salts.", salts.len());
                    } else {
                        warn!("Downloaded salts content was empty.");
                    }
                } else {
                    warn!("Failed to read text from downloaded salts response.");
                }
            } else {
                warn!("Failed to download salts: HTTP Status {}", response.status());
            }
        }
        Err(e) => {
            warn!("Error downloading salts: {}. Please ensure salts.txt is available locally or network is accessible.", e);
        }
    }
    if salts.is_empty() {
        error!("No salts loaded! Extraction will likely fail if a key is required and not provided via CLI.");
    }
    salts
}


fn main() {
    // --- Argument Parsing ---
    let matches = Command::new("Mabinogi pack utilities 2")
        .version("v1.3.5")
        .author("regomne <fallingsunz@gmail.com>")
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("Enables detailed file logging to log.txt (-v) and more verbose console output (-vv)."),
        )
        // ... (rest of clap commands as before) ...
        .subcommand(
            Command::new("pack")
                .about("Create a .it pack")
                .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").help("Set the input folder to pack").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("PACK_NAME").help("Set the output .it file name").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Set the key for the .it file encryption").required(true))
                .arg(Arg::new("additional_data").long("additional_data").help("DEPRECATED: Add original filename to package").hide(true).action(ArgAction::SetTrue))
                .arg(
                    Arg::new("compress-format")
                        .short('f')
                        .long("compress-format")
                        .value_name("EXTENSION")
                        .help("Add an extension to compress in .it (Default: txt xml dds pmg set raw)")
                        .required(false)
                        .action(ArgAction::Append)
                )
        )
        .subcommand(
            Command::new("extract")
                .about("Extract a .it pack. Will try known salts if --key is not provided.")
                .arg(Arg::new("input").short('i').long("input").value_name("PACK_NAME").help("Set the input pack name to extract").required(true))
                .arg(Arg::new("output").short('o').long("output").value_name("FOLDER").help("Set the output folder").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Specific key to try first (optional). If not given, all known salts are tried.").required(false))
                .arg(
                    Arg::new("filter")
                        .short('f')
                        .long("filter")
                        .value_name("FILTER")
                        .help("Set a filter when extracting, in regexp, multiple occurrences mean OR")
                        .required(false)
                        .action(ArgAction::Append)
                )
                .arg(Arg::new("check_additional").short('c').long("check_additional").help("DEPRECATED: check additional data of filename").hide(true).action(ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("list")
                .about("Output the file list of a .it pack. Will try known salts if --key is not provided.")
                .arg(Arg::new("input").short('i').long("input").value_name("PACK_NAME").help("Set the input pack name to extract").required(true))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Specific key to try first (optional). If not given, all known salts are tried.").required(false))
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("LIST_FILE_NAME")
                        .help("Set the list file name, output to stdout if not set")
                        .required(false)
                )
                .arg(Arg::new("check_additional").short('c').long("check_additional").help("DEPRECATED: check additional data of filename").hide(true).action(ArgAction::SetTrue)),
        )
        .get_matches();

    // --- Logger Setup ---
    let verbose_level = matches.get_count("verbose");
    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();

    // Console logger is always Info level unless -vv or more is passed.
    // -v on its own will not make the console more verbose, but it will enable the log file.
    let console_log_level = match verbose_level {
        0 | 1 => LevelFilter::Info, // Default and -v are both INFO on console
        2 => LevelFilter::Debug,    // -vv is DEBUG on console
        _ => LevelFilter::Trace,    // -vvv or more is TRACE on console
    };
    
    // Setup console logger with its determined level
    loggers.push(TermLogger::new(
        console_log_level,
        ConfigBuilder::new()
            .set_location_level(LevelFilter::Error) // Only show file/line for errors on console
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    ));

    // If any verbose flag is present (-v, -vv, etc.), enable file logging to log.txt at TRACE level.
    if verbose_level > 0 {
        // We use an initial info! call that will only be seen if the final `CombinedLogger::init`
        // is set up with a level that permits it (which it will be).
        // It's better to log *after* the logger is initialized.
        let file_logger = WriteLogger::new(
            LevelFilter::Trace, // Log EVERYTHING to the file
            ConfigBuilder::new()
                .set_time_format_rfc3339() // Consistent time format for file logs
                .build(),
            OpenOptions::new()
                .append(true) // Keep appending to the same log file
                .create(true) // Create if it doesn't exist
                .open("log.txt")
                .expect("Failed to open log.txt for appending"),
        );
        loggers.push(file_logger);
    }

    if CombinedLogger::init(loggers).is_err() {
        eprintln!("Failed to initialize the logger!");
    }
    
    // Log verbose status *after* logger is initialized.
    if verbose_level > 0 {
        info!("Verbose logging to log.txt enabled. Console level is {:?}.", console_log_level);
    }
    // --- End Logger Setup ---

    // --- Load Salts & Handle Commands (same as before) ---
    // ... (rest of main function is identical to your last working version) ...
    let mut all_salts: Vec<String> = Vec::new();
    if matches.subcommand_matches("extract").is_some() || matches.subcommand_matches("list").is_some() {
        all_salts = load_salts();
    }

    let operation_result: Result<()> = if let Some(sub_matches) = matches.subcommand_matches("list") {
        let cli_key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        let input_fname = sub_matches.get_one::<String>("input").unwrap();
        let output_path = sub_matches.get_one::<String>("output").map(|s| s.as_str());
        
        if let Some(key) = cli_key {
            info!("list for: '{}' with specific key.", input_fname);
            list::run_list(input_fname, &key, output_path)
        } else {
            info!("list for: '{}' with key search.", input_fname);
            list::run_list_with_key_search(input_fname, None, &all_salts, output_path)
        }
    } else if let Some(sub_matches) = matches.subcommand_matches("extract") {
        let cli_key = sub_matches.get_one::<String>("key").map(|s| s.to_string());
        info!("extract for: '{}' to output: '{}'",
            sub_matches.get_one::<String>("input").map_or("N/A", |s| s.as_str()),
            sub_matches.get_one::<String>("output").map_or("N/A", |s| s.as_str()));
        extract::run_extract_with_key_and_offset_search(
            sub_matches.get_one::<String>("input").unwrap(),
            sub_matches.get_one::<String>("output").unwrap(),
            cli_key,
            &all_salts,
            sub_matches.get_many::<String>("filter").map_or(Vec::new(), |v| v.map(|s| s.as_str()).collect()),
        )
    } else if let Some(sub_matches) = matches.subcommand_matches("pack") {
        if sub_matches.get_flag("additional_data") {
            warn!("DEPRECATED: --additional_data argument is ignored.");
        }
        info!("pack for: '{}' to output file: '{}'",
            sub_matches.get_one::<String>("input").map_or("N/A", |s| s.as_str()),
            sub_matches.get_one::<String>("output").map_or("N/A", |s| s.as_str()));
        pack::run_pack(
            sub_matches.get_one::<String>("input").unwrap(),
            sub_matches.get_one::<String>("output").unwrap(),
            sub_matches.get_one::<String>("key").expect("Key is required for pack operation"),
            sub_matches.get_many::<String>("compress-format").map_or(Vec::new(), |v| v.map(|s| s.as_str()).collect()),
        )
    } else {
        info!("No subcommand provided. Use --help for usage information.");
        Ok(())
    };

    match operation_result {
        Ok(()) => {
            info!("completed successfully.");
            std::process::exit(0);
        }
        Err(e) => {
            error!("failed: {}", e);
            let mut cause = e.source();
            while let Some(inner_cause) = cause {
                error!("  caused by: {}", inner_cause);
                cause = inner_cause.source();
            }
            std::process::exit(1);
        }
    };
}