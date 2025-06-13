// list.rs

use crate::common::{self, FileHeader};
use crate::encryption; // Import encryption to use gen_header_offset

use anyhow::{Context, Error};
use std::fs::File as StdFile;
use std::io::{self, BufReader as StdBufReader, Write};
use log::{debug, info, trace};

fn perform_listing(
    writer: &mut dyn Write,
    entries: &[common::FileEntry],
) -> Result<(), Error> {
    info!("[LIST_CORE] Writing {} file entries to output.", entries.len());
    for ent in entries {
        writeln!(writer, "{}", ent.name)
            .with_context(|| format!("Failed to write entry name '{}' to list output", ent.name))?;
        trace!("[LIST_CORE] Listed: Name='{}', Checksum=0x{:X}, Flags=0x{:X}, Offset_Blocks={}, Orig_Size={}, Raw_Size={}",
               ent.name, ent.checksum, ent.flags, ent.offset, ent.original_size, ent.raw_size);
    }
    writer.flush().context("Failed to flush list output stream")?;
    Ok(())
}

pub fn run_list_with_key_search(
    fname_str: &str,
    cli_skey: Option<String>,
    loaded_salts: &[String],
    output_file_path: Option<&str>,
) -> Result<(), Error> {
    info!("[LIST_SEARCH] Starting key search for listing: '{}'", fname_str);

    let mut keys_to_try: Vec<String> = Vec::new();
    if let Some(key) = cli_skey {
        info!("[LIST_SEARCH] Prioritizing CLI provided key: '{}'", key);
        if !keys_to_try.contains(&key) {
            keys_to_try.push(key);
        }
    }
    for salt in loaded_salts {
        if !keys_to_try.contains(salt) {
            keys_to_try.push(salt.clone());
        }
    }

    if keys_to_try.is_empty() {
        return Err(Error::msg("No salt keys provided or loaded for listing."));
    }
    info!("[LIST_SEARCH] Will attempt listing with {} unique salt key(s).", keys_to_try.len());

    let final_file_name_for_key_derivation = common::get_final_file_name(fname_str)?;
    debug!("[LIST_SEARCH] Using base name for key derivation: '{}'", final_file_name_for_key_derivation);

    let mut output_writer: Box<dyn Write> = if let Some(out_path) = output_file_path {
        Box::new(StdFile::create(out_path).with_context(|| format!("Failed to create output list file: {}", out_path))?)
    } else {
        Box::new(io::stdout())
    };

    // --- START OF FIX ---
    // This function doesn't search offsets, it only uses the one from the formula.
    // We calculate it once here to pass to read_header.
    let formula_offset = encryption::gen_header_offset(&final_file_name_for_key_derivation) as u64;

    for header_skey_candidate in &keys_to_try {
        info!("[LIST_SEARCH] Trying HEADER skey: '{}' for file '{}'", header_skey_candidate, fname_str);
        
        let mut rd_for_header_attempt = StdBufReader::new(StdFile::open(fname_str)?);
        
        // Pass the calculated offset to read_header
        let header: FileHeader = match common::read_header(&final_file_name_for_key_derivation, header_skey_candidate, &mut rd_for_header_attempt, formula_offset) {
            Ok(h) => h,
            Err(_) => continue, 
        };
    // --- END OF FIX ---

        if common::validate_header(&header).is_err() {
            debug!("[LIST_SEARCH] Header validation failed for skey '{}'.", header_skey_candidate);
            continue; 
        }
        info!("[LIST_SEARCH] Header VALIDATED with skey: '{}'. Now trying entries...", header_skey_candidate);
        
        let mut entries_keys_to_try: Vec<&String> = Vec::new();
        entries_keys_to_try.push(header_skey_candidate);
        for salt in &keys_to_try { if salt != header_skey_candidate { entries_keys_to_try.push(salt); } }

        for entries_skey_candidate in entries_keys_to_try {
            let mut rd_for_entries = StdBufReader::new(StdFile::open(fname_str)?);
            
            if let Ok(entries) = common::read_entries(&final_file_name_for_key_derivation, &header, entries_skey_candidate, &mut rd_for_entries, false) {
                if common::validate_entries(&entries).is_ok() {
                    info!("[LIST_SEARCH] >>> SUCCESS! Found working keys for listing '{}': HEADER='{}', ENTRIES='{}'",
                          fname_str, header_skey_candidate, entries_skey_candidate);
                    
                    perform_listing(&mut output_writer, &entries)?;
                    return Ok(());
                }
            }
        } 
    } 

    Err(Error::msg(format!("Exhausted all key combinations for listing '{}'.", fname_str)))
}

pub fn run_list(fname: &str, skey: &str, output_file_path: Option<&str>) -> Result<(), Error> {
    info!("[LIST_DIRECT] Listing with directly provided skey: '{}'", skey);
    let mut rd = StdBufReader::new(StdFile::open(fname)?);
    let final_file_name = common::get_final_file_name(fname)?;
    
    // --- START OF FIX ---
    // Calculate the offset and pass it to read_header.
    let offset = encryption::gen_header_offset(&final_file_name) as u64;
    let header = common::read_header(&final_file_name, skey, &mut rd, offset)
        .with_context(|| format!("Reading header failed with skey: {}", skey))?;
    // --- END OF FIX ---
        
    common::validate_header(&header)?;
    if header.version != 2 {
        return Err(Error::msg(format!("Header version {} not supported", header.version)));
    }
    info!("[LIST_DIRECT] Header validated with skey '{}'.", skey);

    let entries = common::read_entries(&final_file_name, &header, skey, &mut rd, false)?;
    common::validate_entries(&entries)?;
    info!("[LIST_DIRECT] Entries validated. {} entries found.", entries.len());

    let mut writer: Box<dyn Write> = if let Some(out_path) = output_file_path {
        Box::new(StdFile::create(out_path)?)
    } else {
        Box::new(io::stdout())
    };

    perform_listing(&mut writer, &entries)?;
    
    Ok(())
}