use crate::common;
 

use anyhow::Error;
use rayon::prelude::*;
use std::fs::File as StdFile;
use std::io::{self, Cursor, Write};
use log::{debug, info, warn};
use memmap2::Mmap;

pub fn perform_listing(writer: &mut dyn Write, names: &[String]) -> Result<(), Error> {
    for name in names {
        writeln!(writer, "{}", name)?;
    }
    Ok(())
}

pub fn run_list_with_key_search(
    input: &str,
    cli_key: Option<String>,
    loaded_salts: &[String],
    output_file_path: Option<&str>,
) -> Result<(), Error> {
    debug!("[LIST_SEARCH] Starting search for archive: '{}'", input);

    let mut keys_to_try: Vec<String> = Vec::new();
    if let Some(ref key) = cli_key { keys_to_try.push(key.clone()); }
    for salt in loaded_salts {
        if !keys_to_try.contains(salt) { keys_to_try.push(salt.clone()); }
    }

    let file = StdFile::open(input)?;
    let mmap = unsafe { Mmap::map(&file)? };

    if mmap.len() >= 4 {
        if &mmap[0..4] == b"MABI" {
            debug!("[LIST_SEARCH] Legacy MABI detected.");
            let entries = crate::pack_v1::run_list_v1_data(input)?;
            let mut writer: Box<dyn Write> = if let Some(out_path) = output_file_path {
                Box::new(StdFile::create(out_path)?)
            } else {
                Box::new(io::stdout())
            };
            let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
            return perform_listing(&mut writer, &names);
        }
        if &mmap[0..4] == b"PACK" {
            // Try Logue format first
            if let Ok(entries) = crate::pack_v1::run_list_logue_data(input) {
                debug!("[LIST_SEARCH] Logue/MabinogiResource .pack detected.");
                let mut writer: Box<dyn Write> = if let Some(out_path) = output_file_path {
                    Box::new(StdFile::create(out_path)?)
                } else {
                    Box::new(io::stdout())
                };
                let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
                return perform_listing(&mut writer, &names);
            }
            
            // Standard .pack
            debug!("[LIST_SEARCH] Legacy Standard .pack detected.");
            let entries = crate::pack_v1::run_list_v1_data(input)?;
            let mut writer: Box<dyn Write> = if let Some(out_path) = output_file_path {
                Box::new(StdFile::create(out_path)?)
            } else {
                Box::new(io::stdout())
            };
            let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
            return perform_listing(&mut writer, &names);
        }
    }

    let it_name = common::get_final_file_name(input).unwrap_or_default();
    let name_variants = vec![it_name.clone(), "data.it".to_string(), "".to_string()];

    let fname_for_log = input;

    // Two-phase search helper: header key located, now find the entries salt.
    // Tries header_skey first (common case), then all other salts.
    let try_entries = |name: &str, header_skey: &str, h_off: u64, iv0: u32, mode: crate::encryption::Snow2Mode| -> Option<(Vec<crate::common::FileEntry>, String, String)> {
        debug!("[LIST_SEARCH] Header VALIDATED with skey: '{}'. Now trying entries...", header_skey);
        let entries_candidates: Vec<&str> = std::iter::once(header_skey)
            .chain(keys_to_try.iter().filter(|s| s.as_str() != header_skey).map(|s| s.as_str()))
            .collect();
        for entries_skey in entries_candidates {
            let mut rd2 = Cursor::new(&mmap[..]);
            if let Ok((_, entries, _)) = common::read_meta_iv_mode_two_key(name, header_skey, entries_skey, &mut rd2, h_off, iv0, mode) {
                return Some((entries, header_skey.to_string(), entries_skey.to_string()));
            }
        }
        None
    };

    debug!("[LIST_SEARCH] Will attempt listing with {} unique salt key(s).", keys_to_try.len());

    // Phase 1: Try CLI key specifically if provided (Highest Priority)
    let result = if let Some(ref specific_key) = cli_key {
        debug!("[LIST_SEARCH] Prioritizing provided key: {}", specific_key);
        name_variants.iter().find_map(|name| {
            debug!("[LIST_SEARCH] Trying HEADER skey: '{}' for file '{}'", specific_key, fname_for_log);
            let mut rd = Cursor::new(&mmap[..]);
            if let Ok(Some((_header, h_off, iv0, mode))) = common::find_header_only(&mut rd, name, specific_key) {
                if let Some((entries, h_key, e_key)) = try_entries(name, specific_key, h_off, iv0, mode) {
                    return Some((entries, h_key, e_key, h_off, name.clone(), iv0));
                }
            }
            None
        })
    } else {
        None
    };

    // Phase 2: Exhaustive parallel search
    let result = result.or_else(|| {
        name_variants.into_iter().find_map(|name| {
            keys_to_try.par_iter().find_map_any(|header_skey| {
                debug!("[LIST_SEARCH] Trying HEADER skey: '{}' for file '{}'", header_skey, fname_for_log);
                let mut rd = Cursor::new(&mmap[..]);
                if let Ok(Some((_header, h_off, iv0, mode))) = common::find_header_only(&mut rd, &name, header_skey) {
                    if let Some((entries, h_key, e_key)) = try_entries(&name, header_skey, h_off, iv0, mode) {
                        return Some((entries, h_key, e_key, h_off, name.clone(), iv0));
                    }
                }
                None
            })
        })
    });

    if let Some((entries, h_key, e_key, final_offset, _variant, iv0)) = result {
        info!("[LIST_SEARCH] >>> SUCCESS! HEADER='{}', ENTRIES='{}', Offset=0x{:X}, IV={}", h_key, e_key, final_offset, iv0);
        let mut writer: Box<dyn Write> = if let Some(out_path) = output_file_path {
            Box::new(StdFile::create(out_path)?)
        } else {
            Box::new(io::stdout())
        };
        let names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
        return perform_listing(&mut writer, &names);
    }

    warn!("[LIST_SEARCH] FAILED: Search exhausted all combinations.");
    Err(Error::msg("Failed to find valid header/key combination"))
}
