// extract.rs - Robust Multi-Stage Archive Extraction

use crate::common::{self, FileEntry, FLAG_ALL_ENCRYPTED, FLAG_COMPRESSED, FLAG_HEAD_ENCRYPTED};
use crate::encryption;
use anyhow::Error;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use rayon::prelude::*;
use regex::Regex;
use std::fs::File as StdFile;
use std::io::{BufReader as StdBufReader, Cursor, Read, Seek, SeekFrom};
use log::{info, debug, warn, trace};
use memmap2::Mmap;
use flate2::read::ZlibDecoder;

pub type ProgressFn = dyn Fn(usize, usize, &str) + Send + Sync;

pub fn extract_single_file_to_memory(
    mmap: &Mmap,
    content_data_start_offset: u64,
    ent: &FileEntry,
    iv0: u32,
    mode: encryption::Snow2Mode,
) -> Result<Vec<u8>, Error> {
    let target_seek_pos_absolute = content_data_start_offset + (ent.offset as u64 * 1024);
    let end_pos = target_seek_pos_absolute + ent.raw_size as u64;

    if end_pos > mmap.len() as u64 {
        return Err(Error::msg(format!("Raw size for '{}' extends beyond archive length.", ent.name)));
    }

    let mut content = mmap[target_seek_pos_absolute as usize .. end_pos as usize].to_vec();
    let fkey = encryption::gen_file_key(&ent.name, &ent.key);

    if (ent.flags & FLAG_ALL_ENCRYPTED) != 0 {
        encryption::snow2_decrypt_mode(&fkey, iv0, mode, &mut content);
    } else if (ent.flags & FLAG_HEAD_ENCRYPTED) != 0 {
        let len = std::cmp::min(content.len(), 1024);
        if len > 0 {
            encryption::snow2_decrypt_mode(&fkey, iv0, mode, &mut content[..len]);
        }
    }

    if (ent.flags & FLAG_COMPRESSED) != 0 {
        let mut decoder = ZlibDecoder::new(&content[..]);
        let mut decompressed = Vec::with_capacity(ent.original_size as usize);
        if decoder.read_to_end(&mut decompressed).is_err() {
            // Fallback for some regional variants
            let mut fallback = content.clone();
            encryption::snow2_decrypt_mode(&fkey, iv0, mode, &mut fallback);
            let mut dec2 = ZlibDecoder::new(&fallback[..]);
            let mut d2 = Vec::with_capacity(ent.original_size as usize);
            dec2.read_to_end(&mut d2).map_err(|_| Error::msg(format!("Zlib fail: {}", ent.name)))?;
            Ok(d2)
        } else {
            Ok(decompressed)
        }
    } else {
        Ok(content)
    }
}

fn extract_file<R: Read + Seek>(
    main_file_reader: &mut R,
    content_data_start_offset: u64,
    ent: &FileEntry,
    root_dir: &str,
    iv0: u32,
    mode: encryption::Snow2Mode,
    auto_convert_png: bool,
) -> Result<(), Error> {
    let entry_abs_offset = content_data_start_offset + (ent.offset as u64 * 1024);
    main_file_reader.seek(SeekFrom::Start(entry_abs_offset))?;

    let mut content = vec![0u8; ent.raw_size as usize];
    main_file_reader.read_exact(&mut content)?;

    let original_content = content.clone();
    let fkey = encryption::gen_file_key(&ent.name, &ent.key);

    if (ent.flags & FLAG_ALL_ENCRYPTED) != 0 {
        encryption::snow2_decrypt_mode(&fkey, iv0, mode, &mut content);
    } else if (ent.flags & FLAG_HEAD_ENCRYPTED) != 0 {
        let len = std::cmp::min(content.len(), 1024);
        if len > 0 {
            encryption::snow2_decrypt_mode(&fkey, iv0, mode, &mut content[..len]);
        }
    }

    let mut final_content = if (ent.flags & FLAG_COMPRESSED) != 0 {
        if ent.raw_size == 0 { Vec::new() }
        else {
            match decompress_to_vec_zlib(&content) {
                Ok(v) => v,
                Err(e) => {
                    let mut fallback_content = original_content.clone();
                    if (ent.flags & FLAG_ALL_ENCRYPTED) == 0 {
                        encryption::snow2_decrypt_mode(&fkey, iv0, mode, &mut fallback_content);
                    }
                    match decompress_to_vec_zlib(&fallback_content) {
                        Ok(dec) => dec,
                        Err(_) => return Err(Error::msg(format!("Decompression failed for {}: {:?}", ent.name, e))),
                    }
                }
            }
        }
    } else {
        content
    };

    let mut final_name = ent.name.clone();
    if auto_convert_png && final_name.to_lowercase().ends_with(".dds") {
        if let Ok(dds) = image_dds::ddsfile::Dds::read(&mut Cursor::new(&final_content)) {
            if let Ok(img) = image_dds::image_from_dds(&dds, 0) {
                let mut buf = std::io::Cursor::new(Vec::new());
                if img.write_to(&mut buf, image::ImageFormat::Png).is_ok() {
                    final_content = buf.into_inner();
                    final_name = final_name.replace(".dds", ".png").replace(".DDS", ".png");
                }
            }
        }
    }

    common::write_file_to_disk(root_dir, &final_name, &final_content)
}

fn make_regex(filters: Vec<String>) -> Result<Vec<Regex>, Error> {
    filters.into_iter().map(|s| Regex::new(&s).map_err(Error::new)).collect()
}

pub fn run_extract_with_key_search(
    fname_str: &str,
    output_folder_str: &str,
    cli_skey: Option<String>,
    loaded_salts: &[String],
    filters_cli: Vec<String>,
    region_key_override: Option<String>,
    auto_convert_png: bool,
    progress_cb: Option<&ProgressFn>,
) -> Result<String, Error> {
    debug!("[EXTRACT_SEARCH] Sequence: User Key -> Regional Filename -> Hardcoded Salts -> Salts.txt");
    let filters = make_regex(filters_cli)?;

    let mut keys_to_try: Vec<String> = Vec::new();
    if let Some(ref key) = cli_skey {
        debug!("[SALTS] Using user-provided salt: {}", key);
        keys_to_try.push(key.clone());
    }
    for salt in loaded_salts {
        if !keys_to_try.contains(salt) { keys_to_try.push(salt.clone()); }
    }

    let file = StdFile::open(fname_str)?;
    let mmap = unsafe { Mmap::map(&file)? };
    
    // Check for Legacy PACK/MABI magic signature
    if mmap.len() >= 4 {
        if &mmap[0..4] == b"MABI" {
            debug!("[EXTRACT_SEARCH] Legacy MABI .pack detected.");
            crate::pack_v1::run_extract_v1(fname_str, output_folder_str)?;
            if let Some(cb) = progress_cb { cb(1, 1, "Complete"); }
            return Ok("LEGACY_MABI".to_string());
        }
        if &mmap[0..4] == b"PACK" {
            // Try Logue format first
            if let Ok(_) = crate::pack_v1::run_list_logue_data(fname_str) {
                 debug!("[EXTRACT_SEARCH] Logue/MabinogiResource .pack detected.");
                 crate::pack_v1::run_extract_logue(fname_str, output_folder_str)?;
                 if let Some(cb) = progress_cb { cb(1, 1, "Complete"); }
                 return Ok("LOGUE_PACK".to_string());
            }

            debug!("[EXTRACT_SEARCH] Legacy Standard .pack detected.");
            crate::pack_v1::run_extract_v1(fname_str, output_folder_str)?;
            if let Some(cb) = progress_cb { cb(1, 1, "Complete"); }
            return Ok("LEGACY_PACK".to_string());
        }
    }
    
    let final_fname = common::get_final_file_name(fname_str)?;
    let mut name_variants = vec![final_fname.clone()];
    if let Some(r) = region_key_override {
        if !name_variants.contains(&r) { name_variants.push(r); }
    }
    name_variants.push("data.it".to_string());
    name_variants.push("".to_string());

    debug!("[EXTRACT_SEARCH] Will attempt extraction with {} unique salt key(s).", keys_to_try.len());

    // Two-phase helper: header validated at (h_off, iv0, mode), now find entries salt.
    let try_entries_extract = |name: &str, header_skey: &str, h_off: u64, iv0: u32, mode: crate::encryption::Snow2Mode|
        -> Option<(Vec<common::FileEntry>, String, String, u64)>
    {
        debug!("[EXTRACT_SEARCH] Header VALIDATED with skey: '{}'. Now trying entries...", header_skey);
        let entries_candidates: Vec<&str> = std::iter::once(header_skey)
            .chain(keys_to_try.iter().filter(|s| s.as_str() != header_skey).map(|s| s.as_str()))
            .collect();
        for entries_skey in entries_candidates {
            let mut rd2 = Cursor::new(&mmap[..]);
            if let Ok((_, entries, c_off)) = common::read_meta_iv_mode_two_key(name, header_skey, entries_skey, &mut rd2, h_off, iv0, mode) {
                trace!("[EXTRACT_SEARCH] Entries validated with skey: '{}'", entries_skey);
                return Some((entries, header_skey.to_string(), entries_skey.to_string(), c_off));
            }
        }
        None
    };

    // Phase 1: Try CLI key specifically if provided (Highest Priority)
    if let Some(ref specific_key) = cli_skey {
        debug!("[EXTRACT_SEARCH] Prioritizing provided key: {}", specific_key);
        let cli_result = name_variants.iter().find_map(|name| {
            debug!("[EXTRACT_SEARCH] Trying HEADER skey: '{}' for file '{}'", specific_key, fname_str);
            let mut rd = Cursor::new(&mmap[..]);
            if let Ok(Some((_header, h_off, iv0, mode))) = common::find_header_only(&mut rd, name, specific_key) {
                if let Some((entries, h_key, e_key, c_off)) = try_entries_extract(name, specific_key, h_off, iv0, mode) {
                    return Some((entries, h_key, e_key, h_off, name.clone(), iv0, mode, c_off));
                }
            }
            None
        });

        if let Some((entries, h_key, e_key, _final_offset, _name_variant, final_iv0, mode, content_offset)) = cli_result {
            info!("[EXTRACT_SEARCH] >>> SUCCESS (CLI)! HEADER='{}', ENTRIES='{}', Offset=0x{:X}, IV={}, Mode={:?}", h_key, e_key, _final_offset, final_iv0, mode);

            let total = entries.len();
            for (i, ent) in entries.iter().enumerate() {
                if filters.is_empty() || filters.iter().any(|re| re.find(&ent.name).is_some()) {
                    if let Some(cb) = progress_cb { cb(i, total, ""); }
                    let mut rd_for_content = StdBufReader::new(StdFile::open(fname_str)?);
                    if let Err(e) = extract_file(&mut rd_for_content, content_offset, ent, output_folder_str, final_iv0, mode, auto_convert_png) {
                        warn!("[EXTRACT] Failed to extract {}: {}", ent.name, e);
                    }
                }
            }
            if let Some(cb) = progress_cb { cb(total, total, "Complete"); }
            return Ok(h_key);
        }
        warn!("[EXTRACT_SEARCH] Provided key failed. Proceeding to exhaustive search...");
    }

    // Phase 2: Exhaustive two-phase parallel search
    let result = name_variants.into_iter().find_map(|name| {
        debug!("[PROBE] Testing derivation variant: '{}'", name);
        keys_to_try.par_iter().find_map_any(|header_skey| {
            debug!("[EXTRACT_SEARCH] Trying HEADER skey: '{}' for file '{}'", header_skey, fname_str);
            let mut rd = Cursor::new(&mmap[..]);
            if let Ok(Some((_header, h_off, iv0, mode))) = common::find_header_only(&mut rd, &name, header_skey) {
                if let Some((entries, h_key, e_key, c_off)) = try_entries_extract(&name, header_skey, h_off, iv0, mode) {
                    return Some((entries, h_key, e_key, h_off, name.clone(), iv0, mode, c_off));
                }
            }
            None
        })
    });

    if let Some((entries, h_key, e_key, final_offset, name_variant, final_iv0, mode, content_offset)) = result {
        info!("[EXTRACT_SEARCH] >>> SUCCESS! Variant={}, HEADER='{}', ENTRIES='{}', Offset=0x{:X}, IV={}, Mode={:?}", name_variant, h_key, e_key, final_offset, final_iv0, mode);
        
        let total = entries.len();
        for (i, ent) in entries.iter().enumerate() {
            if filters.is_empty() || filters.iter().any(|re| re.find(&ent.name).is_some()) {
                if let Some(cb) = progress_cb { cb(i, total, ""); }
                let mut rd_for_content = StdBufReader::new(StdFile::open(fname_str)?);
                if let Err(e) = extract_file(&mut rd_for_content, content_offset, ent, output_folder_str, final_iv0, mode, auto_convert_png) {
                    warn!("[EXTRACT] Failed to extract {}: {}", ent.name, e);
                }
            }
        }
        if let Some(cb) = progress_cb { cb(total, total, "Complete"); }
        return Ok(h_key);
    }

    Err(Error::msg(format!("Exhausted all key combinations for '{}'. No working set of parameters found.", fname_str)))
}
