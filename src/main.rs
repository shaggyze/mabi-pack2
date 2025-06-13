// src/main.rs
use clap::Command;

use log::{error, info, warn};
use env_logger;
use anyhow::Result; // Using anyhow::Result directly

mod common;
mod encryption;
mod extract;
mod list;
mod pack;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Command::new("Mabinogi pack utilities 2")
        .version("v1.3.3")
        .author("regomne <fallingsunz@gmail.com>")
        .subcommand(
            Command::new("pack")
                .about("Create a .it pack")
                .arg(clap::Arg::new("input").short('i').long("input").value_name("FOLDER").help("Set the input folder to pack").required(true).takes_value(true))
                .arg(clap::Arg::new("output").short('o').long("output").value_name("PACK_NAME").help("Set the output .it file name").required(true).takes_value(true))
                .arg(clap::Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Set the key for the .it file encryption").required(true).takes_value(true))
                .arg(clap::Arg::new("additional_data").long("additional_data").help("DEPRECATED: Add original filename to package").hide(true).action(clap::ArgAction::SetTrue))
                .arg(
                    clap::Arg::new("compress-format")
                        .short('f')
                        .long("compress-format")
                        .value_name("EXTENSION")
                        .help("Add an extension to compress in .it (Default: txt xml dds pmg set raw)")
                        .required(false)
                        .takes_value(true)
                        .multiple_occurrences(true)
                        .number_of_values(1)
                )
        )
        .subcommand(
            Command::new("extract")
                .about("Extract a .it pack")
                .arg(clap::Arg::new("input").short('i').long("input").value_name("PACK_NAME").help("Set the input pack name to extract").required(true).takes_value(true))
                .arg(clap::Arg::new("output").short('o').long("output").value_name("FOLDER").help("Set the output folder").required(true).takes_value(true))
                .arg(clap::Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Set the key for the .it file encryption").required(true).takes_value(true))
                .arg(
                    clap::Arg::new("filter")
                        .short('f')
                        .long("filter")
                        .value_name("FILTER")
                        .help("Set a filter when extracting, in regexp, multiple occurrences mean OR")
                        .required(false)
                        .takes_value(true)
                        .multiple_occurrences(true)
                        .number_of_values(1)
                )
                .arg(clap::Arg::new("check_additional").short('c').long("check_additional").help("DEPRECATED: check additional data of filename").hide(true).action(clap::ArgAction::SetTrue)),
        )
        .subcommand(
            Command::new("list")
                .about("Output the file list of a .it pack")
                .arg(clap::Arg::new("input").short('i').long("input").value_name("PACK_NAME").help("Set the input pack name to extract").required(true).takes_value(true))
                .arg(clap::Arg::new("key").short('k').long("key").value_name("KEY_SALT").help("Set the key for the .it file encryption").required(true).takes_value(true))
                .arg(
                    clap::Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("LIST_FILE_NAME")
                        .help("Set the list file name, output to stdout if not set")
                        .required(false)
                        .takes_value(true)
                )
                .arg(clap::Arg::new("check_additional").short('c').long("check_additional").help("DEPRECATED: check additional data of filename").hide(true).action(clap::ArgAction::SetTrue)),
        )
        .get_matches();

    let operation_result: Result<()> = if let Some(matches) = args.subcommand_matches("list") {
        info!("Running list operation for input: '{}'", matches.value_of("input").unwrap_or("N/A"));
        list::run_list(
            matches.value_of("input").unwrap(),
            matches.value_of("key").unwrap(),
            matches.value_of("output"),
        )
    } else if let Some(matches) = args.subcommand_matches("extract") {
        info!("Running extract operation for input: '{}' to output: '{}'",
            matches.value_of("input").unwrap_or("N/A"),
            matches.value_of("output").unwrap_or("N/A"));
        extract::run_extract(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
            matches.value_of("key").unwrap(),
            matches
                .values_of("filter")
                .map_or(Vec::new(), |v| v.collect()),
        )
    } else if let Some(matches) = args.subcommand_matches("pack") {
        if matches.is_present("additional_data") {
            warn!("DEPRECATED: --additional_data argument is ignored.");
        }
        info!("Running pack operation for input folder: '{}' to output file: '{}'",
            matches.value_of("input").unwrap_or("N/A"),
            matches.value_of("output").unwrap_or("N/A"));
        pack::run_pack(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
            matches.value_of("key").unwrap(),
            matches
                .values_of("compress-format")
                .map_or(Vec::new(), |v| v.collect()),
        )
    } else {
        info!("No subcommand provided. Use --help for usage information.");
        Ok(())
    };

    match operation_result {
        Ok(()) => {
            info!("Operation completed successfully.");
            std::process::exit(0);
        }
        Err(e) => {
            error!("Operation failed: {}", e); // Log the main error message from anyhow
            for cause in e.chain().skip(1) { // Iterate over the cause chain from anyhow
                error!("  Caused by: {}", cause);
            }
            std::process::exit(1);
        }
    };
}