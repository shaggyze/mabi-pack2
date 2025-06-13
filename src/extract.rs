use crate::common::{self, FileEntry, FLAG_ALL_ENCRYPTED, FLAG_COMPRESSED, FLAG_HEAD_ENCRYPTED};
use crate::encryption;
use anyhow::{Context, Error};
use miniz_oxide::inflate::decompress_to_vec_zlib;
use regex::Regex;
use std::fs::{self, File as StdFile};
use std::io::{BufReader as StdBufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path};

use log::{debug, error, trace, info};

// write_file, extract_file, make_regex functions remain unchanged...
fn write_file(root_dir: &str, rel_path: &str, content: Vec<u8>) -> Result<(), Error> {
    trace!("[EXTRACT_WRITE] Preparing to write {} bytes to {}/{}", content.len(), root_dir, rel_path);
    let fname = Path::new(root_dir).join(rel_path.replace(['/', '\\'], &std::path::MAIN_SEPARATOR.to_string()));
    debug!("[EXTRACT_WRITE] Full path for '{}': {:?}", rel_path, fname);
    let par = fname.parent().ok_or_else(|| {
        error!("[EXTRACT_WRITE] Could not get parent directory for {:?}", fname);
        Error::msg(format!("unrecognized path: {}", fname.to_string_lossy()))
    })?;
    fs::create_dir_all(par).context(format!("Failed to create directory {:?}", par))?;
    fs::write(&fname, &content).context(format!("Failed to write file {:?}", fname))?;
    debug!("[EXTRACT_WRITE] Successfully wrote '{}' to {}", rel_path, root_dir);
    Ok(())
}

fn extract_file<RMF: Read + Seek>(
    main_file_reader: &mut RMF,
    content_data_start_offset: u64,
    ent: &FileEntry,
    root_dir: &str,
) -> Result<(), Error> {
    trace!("[EXTRACT_FILE] Extracting file entry: '{}' (Raw Size: {}, Original Size: {})", ent.name, ent.raw_size, ent.original_size);
    trace!("[EXTRACT_FILE] Details - entry='{}', data_block_offset_idx={}, raw_size={}, original_size={}, flags=0x{:X}, key='{:?}'",
        ent.name, ent.offset, ent.raw_size, ent.original_size, ent.flags, ent.key);
    let target_seek_pos_absolute = content_data_start_offset + (ent.offset as u64 * 1024);
    debug!("[EXTRACT_FILE] For '{}': Seeking main_file_reader to data block's absolute offset 0x{:X} (content_data_start_offset 0x{:X} + entry_data_block_idx {} * 1024)",
        ent.name, target_seek_pos_absolute, content_data_start_offset, ent.offset);
    main_file_reader.seek(SeekFrom::Start(target_seek_pos_absolute))
        .context(format!("Failed to seek main_file_reader to data offset 0x{:X} for entry '{}'", target_seek_pos_absolute, ent.name))?;
    let mut content = vec![0u8; ent.raw_size as usize];
    trace!("[EXTRACT_FILE] For '{}': Allocated buffer of size {} for raw content.", ent.name, ent.raw_size);
    let fkey = encryption::gen_file_key(&ent.name, &ent.key);
    trace!("[EXTRACT_FILE] For '{}': Generated file_key (first 4 bytes): {:?}", ent.name, &fkey[..std::cmp::min(fkey.len(), 4)]);
    if (ent.flags & FLAG_ALL_ENCRYPTED) != 0 {
        debug!("[EXTRACT_FILE] For '{}': File is fully encrypted. Decrypting {} bytes...", ent.name, content.len());
        let mut dec_stm = encryption::Snow2Decoder::new(&fkey, main_file_reader);
        dec_stm.read_exact(&mut content).context(format!("Failed to read/decrypt fully encrypted file data for '{}'", ent.name))?;
        trace!("[EXTRACT_FILE] For '{}': Finished decrypting fully encrypted data. Dec_stm final pos: ~0x{:X}", ent.name, dec_stm.stream_position());
    } else {
        trace!("[EXTRACT_FILE] For '{}': File is not fully encrypted. Reading {} raw bytes directly from main_file_reader...", ent.name, content.len());
        main_file_reader.read_exact(&mut content).context(format!("Failed to read raw file data for '{}'", ent.name))?;
        trace!("[EXTRACT_FILE] For '{}': Finished reading raw data.", ent.name);
    }
    if (ent.flags & FLAG_HEAD_ENCRYPTED) != 0 {
        debug!("[EXTRACT_FILE] For '{}': File has head portion encrypted. Decrypting relevant part of in-memory content...", ent.name);
        let dec_len = std::cmp::min(ent.raw_size as usize, 1024);
        if dec_len > 0 {
            let head_to_redecrypt = content[..dec_len].to_vec();
            let mut head_cursor = Cursor::new(head_to_redecrypt.as_slice());
            let mut temp_dec_stm = encryption::Snow2Decoder::new(&fkey, &mut head_cursor);
            let mut decrypted_head_output = vec![0u8; dec_len];
            trace!("[EXTRACT_FILE] For '{}': Re-decrypting head portion ({} bytes) from in-memory data using temp_dec_stm.", ent.name, dec_len);
            temp_dec_stm.read_exact(&mut decrypted_head_output)
                .context(format!("Failed to read/re-decrypt head portion for '{}' from in-memory content", ent.name))?;
            content[..dec_len].copy_from_slice(&decrypted_head_output);
            trace!("[EXTRACT_FILE] For '{}': Finished re-decrypting head portion of in-memory data. Temp_dec_stm final pos: ~0x{:X}", ent.name, temp_dec_stm.stream_position());
        } else {
            trace!("[EXTRACT_FILE] For '{}': Head portion to re-decrypt has zero length (raw_size is likely 0), skipping head re-decryption.", ent.name);
        }
    }
    let final_content = if (ent.flags & FLAG_COMPRESSED) != 0 {
        if ent.raw_size == 0 {
            debug!("[EXTRACT_FILE] For '{}': File is flagged as compressed but raw_size is 0. Treating as an empty file.", ent.name);
            Vec::new() // Return an empty vector, effectively creating an empty file.
        } else {
            debug!("[EXTRACT_FILE] For '{}': File is compressed. Decompressing {} bytes to expected {} bytes...",
                ent.name, content.len(), ent.original_size);
            let v = decompress_to_vec_zlib(&content).map_err(|e| {
                error!("[EXTRACT_FILE] For '{}': ZLIB Decompression failed: {:?}", ent.name, e);
                Error::msg(format!("zlib decompress failed for {}: {:?}", ent.name, e))
            })?;
            trace!("[EXTRACT_FILE] For '{}': Decompressed from {} to {} bytes.", ent.name, content.len(), v.len());
            if v.len() != ent.original_size as usize {
                error!("[EXTRACT_FILE] For '{}': Original size mismatch after decompression. Expected: {}, Got: {}. File might be corrupted or key/compression wrong.",
                    ent.name, ent.original_size, v.len());
                return Err(Error::msg(format!("original size not match for {}. Expected {}, got {}", ent.name, ent.original_size, v.len())));
            }
            v
        }
    } else {
        trace!("[EXTRACT_FILE] For '{}': File is not compressed. Using raw content ({} bytes).", ent.name, content.len());
        content
    };
    write_file(root_dir, &ent.name, final_content)
        .context(format!("While writing extracted file '{}' to disk", ent.name))
}

fn make_regex(strs: Vec<&str>) -> Result<Vec<Regex>, Error> {
    debug!("[REGEX] Compiling {} filter strings into regex.", strs.len());
    strs.into_iter()
        .map(|s| {
            trace!("[REGEX] Compiling regex for filter: '{}'", s);
            Regex::new(&s).map_err(|e| {
                error!("[REGEX] Invalid regex string '{}': {}", s, e);
                Error::msg(format!("Invalid regex: {}, {}", s, e))
            })
        })
        .collect()
}


// --- This is the corrected implementation ---
pub fn run_extract_with_key_and_offset_search(
    fname_str: &str,
    output_folder_str: &str,
    cli_skey: Option<String>,
    loaded_salts: &[String],
    filters_cli: Vec<&str>,
) -> Result<(), Error> {
    debug!("[EXTRACT_SEARCH] Starting search for keys and header offset for: '{}'", fname_str);

    let mut keys_to_try: Vec<String> = Vec::new();
    if let Some(key) = cli_skey {
        debug!("[EXTRACT_SEARCH] Prioritizing CLI provided key: '{}'", key);
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
        return Err(Error::msg("No salt keys provided or loaded. Cannot attempt extraction."));
    }
    debug!("[EXTRACT_SEARCH] Will attempt extraction with {} unique salt key(s).", keys_to_try.len());

    let fname_for_key_derivation = common::get_final_file_name(fname_str)?;
    debug!("[EXTRACT_SEARCH] Using base name for key derivation: '{}'", fname_for_key_derivation);

    let filters = make_regex(filters_cli)?;

    // Main Search Loop
    for header_skey_candidate in &keys_to_try {
        let mut rd = StdBufReader::new(StdFile::open(fname_str)?);
        
        let formula_offset = encryption::gen_header_offset(&fname_for_key_derivation) as u64;
        
        // --- NEW STRATEGY ---
        let mut candidate_offsets: Vec<u64> = vec![
            // 1. Add a list of common, fixed offsets found in many file formats.
            // These are just examples; you might find others through analysis.
            0x20,  // 32
            0x30,  // 48
            0x40,  // 64
            0x60,  // 96
            0x80,  // 128
            0x100, // 256

            // 2. Keep your original formula-based heuristic.
            formula_offset,
        ];
        
        // Add variations around the formula offset, just like before.
        if formula_offset > 8 {
            candidate_offsets.push(formula_offset - 8);
            candidate_offsets.push(formula_offset - 4);
        }
        candidate_offsets.push(formula_offset + 4);
        candidate_offsets.push(formula_offset + 8);
        
        // 3. Clean up the list to ensure we don't test the same offset twice.
        candidate_offsets.sort_unstable();
        candidate_offsets.dedup();
        
        trace!("[EXTRACT_SEARCH] Trying HEADER skey '{}' with candidate offsets: {:?}", header_skey_candidate, &candidate_offsets);

        for offset in candidate_offsets {
            rd.seek(SeekFrom::Start(0))?; // Reset reader for each offset test

            if let Ok(Some((header, _))) = common::try_read_and_validate_header(&mut rd, &fname_for_key_derivation, header_skey_candidate, offset) {
                debug!("[EXTRACT_SEARCH] Header VALIDATED with skey='{}' at custom offset 0x{:X}. Now trying all skeys for ENTRIES...", header_skey_candidate, offset);
                
                let mut entries_keys_to_try: Vec<&String> = Vec::new();
                entries_keys_to_try.push(header_skey_candidate);
                for salt in &keys_to_try { if salt != header_skey_candidate { entries_keys_to_try.push(salt); } }

                for entries_skey_candidate in entries_keys_to_try {
                    debug!("[EXTRACT_SEARCH]   Trying ENTRIES skey: '{}'", entries_skey_candidate);
                    let mut rd_for_entries = StdBufReader::new(StdFile::open(fname_str)?);
                    
                    if let Ok(entries) = common::read_entries(&fname_for_key_derivation, &header, entries_skey_candidate, &mut rd_for_entries, false) {
                        if common::validate_entries(&entries).is_ok() {
                            info!("SUCCESS! File '{}' Header key '{}' (at offset 0x{:X}) Entries key '{}'", fname_for_key_derivation, header_skey_candidate, offset, entries_skey_candidate);

                            let pos_after_meta = rd_for_entries.stream_position()?;
                            let content_offset = (pos_after_meta + 1023) & !1023u64;
                            for ent in &entries {
                                if filters.is_empty() || filters.iter().any(|re| re.find(&ent.name).is_some()) {
                                    extract_file(&mut rd_for_entries, content_offset, ent, output_folder_str)?;
                                }
                            }
                            return Ok(());
                        }
                    }
                }
                debug!("[EXTRACT_SEARCH] Found valid header for skey '{}' at offset 0x{:X}, but no working entries key/offset was found. Trying next HEADER skey.", header_skey_candidate, offset);
            }
        } 
    } 

    Err(Error::msg(format!("Exhausted all key and header offset combinations for '{}'. No working set of parameters found.", fname_str)))
}