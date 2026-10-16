//! Archive subcommands shared by the standalone CLI (`src/bin/mabi-pack-cli.rs`)
//! and the GUI exe's command-line mode (`gui/src-tauri/src/main.rs`), so both
//! binaries accept the same commands.

use anyhow::Result;
use clap::{Arg, ArgMatches, Command};

use crate::{common_ext, mod_file};

/// Subcommand names handled by [`run`].
pub const NAMES: [&str; 3] = ["convert", "full-sequence", "mod"];

pub fn commands() -> Vec<Command<'static>> {
    vec![
        Command::new("convert")
            .about("Convert between .it and .pack formats.")
            .arg(Arg::new("input").short('i').long("input").value_name("INPUT").help("Source archive path").required(true))
            .arg(Arg::new("output").short('o').long("output").value_name("OUTPUT").help("Destination archive path").required(true))
            .arg(Arg::new("key").short('k').long("key").value_name("KEY").help("Key for .it archives").required(false)),
        Command::new("full-sequence")
            .about("Extract all archives in a folder in order and pack into one.")
            .arg(Arg::new("input").short('i').long("input").value_name("FOLDER").help("Folder containing multiple archives").required(true))
            .arg(Arg::new("output").short('o').long("output").value_name("ALL_DATA.IT").help("Output single archive path").required(true))
            .arg(Arg::new("key").short('k').long("key").value_name("KEY").help("Specific salt for the final .it").required(false)),
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
            ),
    ]
}

/// Runs one of the [`NAMES`] subcommands.
pub fn run(name: &str, sub: &ArgMatches) -> Result<()> {
    match name {
        "convert" => {
            let input = sub.get_one::<String>("input").unwrap();
            let output = sub.get_one::<String>("output").unwrap();
            let key = sub.get_one::<String>("key").cloned();
            common_ext::convert(input, output, key, true)?;
        }
        "full-sequence" => {
            let input = sub.get_one::<String>("input").unwrap();
            let output = sub.get_one::<String>("output").unwrap();
            let key = sub.get_one::<String>("key").cloned();
            common_ext::run_full_sequence(input, output, key)?;
        }
        "mod" => {
            if let Some(ins) = sub.subcommand_matches("inspect") {
                let path = std::path::Path::new(ins.get_one::<String>("file").unwrap());
                let pkg = mod_file::ModPackage::load(path)?;
                println!("{}", serde_json::to_string_pretty(&pkg).unwrap_or_default());
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
        }
        _ => anyhow::bail!("unknown archive command: {}", name),
    }
    Ok(())
}
