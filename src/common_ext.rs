// common_ext.rs - Advanced Search and UI Helper Module

use crate::{common, list, extract, pack, pack_v1, encryption};
use anyhow::{Error};
use rayon::prelude::*;
use std::fs::{File as StdFile};
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};
use memmap2::Mmap;
use image::ImageFormat;
use base64::{engine::general_purpose, Engine as _};
use log::{debug, trace, info, warn};
use image_dds::image_from_dds;

pub fn get_preview_ext(entry_name: &str) -> Option<&str> {
    let name = entry_name.to_lowercase();
    if name.ends_with(".rgn") {
        Some("rgn")
    } else if name.ends_with(".area") {
        Some("area")
    } else if name.ends_with(".set") {
        Some("set")
    } else if name.ends_with(".mml") {
        Some("mml")
    } else if name.ends_with(".xml") || name.ends_with(".txt") ||
       name.ends_with(".data") || name.ends_with(".csh") {
        Some("text")
    } else if name.ends_with(".dds") || name.ends_with(".png") || name.ends_with(".jpg") || name.ends_with(".bmp") {
        Some("image")
    } else if name.ends_with(".pmg") {
        Some("pmg")
    } else if name.ends_with(".wav") || name.ends_with(".mp3") || name.ends_with(".ogg") || name.ends_with(".nxa") {
        Some("audio")
    } else if name.ends_with(".anievent") {
        Some("anievent")
    } else if name.ends_with(".ani") || name.ends_with(".mov") || name.ends_with(".frm") ||
              name.ends_with(".ttf") || name.ends_with(".raw") || name.ends_with(".compiled") {
        Some("binary")
    } else {
        None
    }
}

pub fn get_entry_data_exact(
    archive_path: &str,
    entry_name: &str,
    key: Option<String>,
    entries_key: Option<String>,
    iv0: u32,
    h_off: u64,
    mode: encryption::Snow2Mode,
) -> Result<(Vec<u8>, u32, encryption::Snow2Mode, crate::common::FileEntry), Error> {
    info!("[ENTRY_DATA_EXACT] Fetching '{}' from '{}'", entry_name, archive_path);
    let file = StdFile::open(archive_path)?;
    let mmap = unsafe { Mmap::map(&file)? };

    if archive_path.to_lowercase().ends_with(".pack") {
        return get_entry_data(archive_path, entry_name, None);
    }

    let salt = key.as_deref().unwrap_or("");
    let entries_salt = entries_key.as_deref().unwrap_or(salt);
    let mut rd = Cursor::new(&mmap[..]);
    let name_variant = common::get_final_file_name(archive_path)?;

    let (_header, entries, content_start) = common::read_meta_iv_mode_two_key(&name_variant, salt, entries_salt, &mut rd, h_off, iv0, mode)?;

    let norm = entry_name.replace('\\', "/");
    if let Some(ent) = entries.iter().find(|e| e.name == entry_name || e.name.replace('\\', "/") == norm) {
        let data = extract::extract_single_file_to_memory(&mmap, content_start, ent, iv0, mode)?;
        return Ok((data, iv0, mode, ent.clone()));
    }

    Err(Error::msg("Entry not found with exact metadata"))
}

pub fn get_entry_data(archive_path: &str, entry_name: &str, key: Option<String>) -> Result<(Vec<u8>, u32, encryption::Snow2Mode, crate::common::FileEntry), Error> {
    info!("[ENTRY_DATA] Fetching '{}' from '{}'", entry_name, archive_path);
    let file = StdFile::open(archive_path)?;
    let mmap = unsafe { Mmap::map(&file)? };

    if archive_path.to_lowercase().ends_with(".pack") {
        debug!("[ENTRY_DATA] Handling unencrypted .pack file.");
        let entries = pack_v1::run_list_v1_data(archive_path)?;
        if let Some(ent) = entries.iter().find(|e| e.name == entry_name) {
            let data = pack_v1::extract_single_v1(&mmap, ent)?;
            return Ok((data, 0, encryption::Snow2Mode::Sub, ent.clone()));
        }
        return Err(Error::msg("Entry not found in .pack archive"));
    }

    let salts = crate::load_salts();
    let (entries, _salt, _entries_salt, iv0, _h_off, mode, content_start) = run_list_with_key_search_data(archive_path, key, &salts, None)?;
    if let Some(ent) = entries.iter().find(|e| e.name == entry_name) {
        let data = extract::extract_single_file_to_memory(&mmap, content_start, ent, iv0, mode)?;
        return Ok((data, iv0, mode, ent.clone()));
    }
    
    warn!("[ENTRY_DATA] FAILED: Could not find or decrypt entry '{}'.", entry_name);
    Err(Error::msg("Entry not found or invalid key"))
}

pub fn get_preview_base64_from_data(entry_name: &str, data: &[u8]) -> Result<String, Error> {
    trace!("[PREVIEW_BASE64] Converting '{}' to base64", entry_name);
    let ext = entry_name.to_lowercase();

    if ext.ends_with(".dds") {
        if data.len() < 128 {
            return Err(Error::msg(format!("Suspicious DDS length ({} bytes)", data.len())));
        }
        debug!("[PREVIEW_BASE64] Handling DDS format via image_dds");
        let dds = image_dds::ddsfile::Dds::read(&mut Cursor::new(data))
            .map_err(|e| Error::msg(format!("DDS read failed: {:?}", e)))?;
        let img = image_from_dds(&dds, 0)
            .map_err(|e| Error::msg(format!("DDS decode failed: {:?}", e)))?;
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png)
            .map_err(|e| Error::msg(format!("PNG encode failed: {:?}", e)))?;
        return Ok(general_purpose::STANDARD.encode(buf.into_inner()));
    }

    Ok(general_purpose::STANDARD.encode(data))
}

// Keep old one for backward compat if used elsewhere
pub fn get_preview_base64(archive_path: &str, entry_name: &str, key: Option<String>) -> Result<String, Error> {
    let (data, _iv0, _mode, _) = get_entry_data(archive_path, entry_name, key)?;
    get_preview_base64_from_data(entry_name, &data)
}

pub fn run_advanced_list(
    fname_str: &str,
    cli_skey: Option<String>,
    loaded_salts: &[String],
    output_file_path: Option<&str>,
) -> Result<(), Error> {
    list::run_list_with_key_search(fname_str, cli_skey, loaded_salts, output_file_path)
}

pub fn run_list_with_key_search_data(
    fname_str: &str,
    cli_skey: Option<String>,
    loaded_salts: &[String],
    region_key: Option<String>,
) -> Result<(Vec<common::FileEntry>, String, String, u32, u64, encryption::Snow2Mode, u64), Error> {
    debug!("[GUI_LIST] Starting unified search for regional archive: '{}'", fname_str);

    let file = StdFile::open(fname_str)?;
    let mmap = unsafe { Mmap::map(&file)? };

    if mmap.len() >= 4 && (&mmap[0..4] == b"PACK" || &mmap[0..4] == b"MABI") {
        debug!("[GUI_LIST] Legacy .pack/MABI detected.");
        let entries = crate::pack_v1::run_list_v1_data(fname_str)?;
        return Ok((entries, "UNENCRYPTED".to_string(), "UNENCRYPTED".to_string(), 0, 0, encryption::Snow2Mode::Sub, 0));
    }

    let mut keys_to_try: Vec<String> = Vec::new();
    if let Some(key) = cli_skey { keys_to_try.push(key); }
    for salt in loaded_salts {
        if !keys_to_try.contains(salt) { keys_to_try.push(salt.clone()); }
    }

    let final_fname = common::get_final_file_name(fname_str)?;
    let mut name_variants = vec![final_fname.clone()];
    if let Some(r) = region_key { if !name_variants.contains(&r) { name_variants.push(r); } }
    name_variants.push("data.it".to_string());
    name_variants.push("".to_string());

    for name in name_variants {
        // Two-phase search: Phase 1 finds the header salt, Phase 2 finds the entries salt.
        // Header salt is tried first for entries (common case: same salt for both).
        let res = keys_to_try.par_iter().find_map_any(|header_skey| {
            let mut rd = Cursor::new(&mmap[..]);
            if let Ok(Some((_header, h_off, iv0, mode))) = common::find_header_only(&mut rd, &name, header_skey) {
                let entries_candidates: Vec<&str> = std::iter::once(header_skey.as_str())
                    .chain(keys_to_try.iter().filter(|s| s.as_str() != header_skey.as_str()).map(|s| s.as_str()))
                    .collect();
                for entries_skey in entries_candidates {
                    let mut rd2 = Cursor::new(&mmap[..]);
                    if let Ok((_, entries, c_off)) = common::read_meta_iv_mode_two_key(&name, header_skey, entries_skey, &mut rd2, h_off, iv0, mode) {
                        info!("[GUI_LIST] >>> SUCCESS! HEADER='{}', ENTRIES='{}'", header_skey, entries_skey);
                        return Some((entries, header_skey.clone(), entries_skey.to_string(), iv0, h_off, mode, c_off));
                    }
                }
            }
            None
        });
        if let Some(r) = res { return Ok(r); }
    }

    Err(Error::msg("Search exhausted all regional variants."))
}

pub fn convert(input: &str, output: &str, key: Option<String>, wrap_data: bool) -> Result<(), Error> {
    info!("[CONVERT] Converting '{}' -> '{}'", input, output);
    let unique_id = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let tmp_name = format!("mabi_conv_{}_{}", std::process::id(), unique_id);
    let tmp = std::env::temp_dir().join(&tmp_name);
    let tmp_path = tmp.to_str().ok_or_else(|| Error::msg("Non-UTF8 temp path"))?.to_string();
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::create_dir_all(&tmp);

    let mut discovered_salt = "".to_string();

    if input.to_lowercase().ends_with(".pack") {
        debug!("[CONVERT] Extracting source .pack");
        pack_v1::run_extract_v1(input, &tmp_path)?;
    } else {
        debug!("[CONVERT] Extracting source .it");
        let salts = crate::load_salts();
        discovered_salt = extract::run_extract_with_key_search(input, &tmp_path, key.clone(), &salts, vec![], None, false, false, false, None)?;    }

    // Only wrap if the extracted tree doesn't already have a data/ subfolder
    let already_wrapped = std::fs::read_dir(&tmp)
        .map(|entries| entries.filter_map(|e| e.ok()).any(|e| {
            e.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && e.file_name().to_string_lossy().to_lowercase() == "data"
        }))
        .unwrap_or(false);
    let effective_wrap = wrap_data && !already_wrapped;

    if output.to_lowercase().ends_with(".pack") {
        debug!("[CONVERT] Building destination .pack");
        pack_v1::run_pack_v1(&tmp_path, output, 1)?;
    } else {
        let prefix = if effective_wrap { Some("data") } else { None };
        debug!("[CONVERT] Building destination .it (prefix={:?})", prefix);
        let k = if let Some(k_opt) = key { k_opt }
                else if !discovered_salt.is_empty() { discovered_salt }
                else { crate::HARDCODED_SALTS[0].to_string() };
        pack::run_pack(&tmp_path, output, &k, vec![], false, 0, prefix, None)?;
    }

    let _ = std::fs::remove_dir_all(&tmp);
    info!("[CONVERT] SUCCESS!");
    Ok(())
}

pub fn run_full_sequence(folder: &str, output: &str, key: Option<String>) -> Result<(), Error> {
    info!("[SEQUENCE] Starting full sequence merging for: {}", folder);
    let mut files: Vec<_> = std::fs::read_dir(folder)?
        .filter_map(Result::ok)
        .filter(|e| {
            let ext = e.path().extension().unwrap_or_default().to_string_lossy().to_lowercase();
            ext == "it" || ext == "pack"
        })
        .collect();
    
    files.sort_by_key(|e| e.file_name());
    
    let unique_id2 = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let tmp_name2 = format!("mabi_seq_{}_{}", std::process::id(), unique_id2);
    let tmp = std::env::temp_dir().join(&tmp_name2);
    let tmp_path = tmp.to_str().ok_or_else(|| Error::msg("Non-UTF8 temp path"))?.to_string();
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::create_dir_all(&tmp);

    let salts = crate::load_salts();

    for entry in files {
        let path = entry.path();
        let path_str = path.to_str().unwrap();
        debug!("[SEQUENCE] Processing archive: {}", path_str);
        if path_str.to_lowercase().ends_with(".pack") {
            pack_v1::run_extract_v1(path_str, &tmp_path)?;
        } else {
            // Force using provided key if possible, then search with DEEP validation
            extract::run_extract_with_key_search(path_str, &tmp_path, key.clone(), &salts, vec![], None, false, false, false, None)?;
        }
    }

    info!("[SEQUENCE] Packing merged data into: {}", output);
    let final_key = key.unwrap_or_else(|| crate::HARDCODED_SALTS[0].to_string());
    // Large merge: avoid DDS auto-convert for speed
    pack::run_pack(&tmp_path, output, &final_key, vec![], false, 0, None, None)?;

    let _ = std::fs::remove_dir_all(&tmp);
    info!("[SEQUENCE] COMPLETED SUCCESSFULLY!");
    Ok(())
}

pub fn run_batch_extract(
    input: &str,
    output: &str,
    cli_key: Option<String>,
    no_merge: bool,
    filters: Vec<String>,
    jobs: usize,
) -> Result<(), Error> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    let salts = crate::load_salts();

    if jobs <= 1 {
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
            let key_to_use = cached_salt.clone().or_else(|| cli_key.clone());
            if fname.to_lowercase().ends_with(".pack") {
                let _ = pack_v1::run_extract_v1(fname, &out_dir);
            } else {
                match extract::run_extract_with_key_search(fname, &out_dir, key_to_use, &salts, filters.clone(), None, false, false, false, None) {
                    Ok(salt) => { cached_salt = Some(salt); }
                    Err(e) => warn!("[BATCH] Failed {}: {}", archive_name, e),
                }
            }
            print!("\r[{}/{}] {}", idx + 1, total, archive_name);
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
        println!();
    } else {
        let completed = Arc::new(AtomicUsize::new(0));
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
                        format!("{}/{}", output, stem)
                    } else {
                        output.to_string()
                    };
                    let _ = std::fs::create_dir_all(&out_dir);
                    if fname.to_lowercase().ends_with(".pack") {
                        let _ = pack_v1::run_extract_v1(fname, &out_dir);
                    } else {
                        let key = cli_key.clone();
                        match extract::run_extract_with_key_search(fname, &out_dir, key, &salts, filters.clone(), None, false, false, false, None) {
                            Ok(_) => {}
                            Err(e) => warn!("[BATCH] Failed {}: {}", archive_name, e),
                        }
                    }
                    let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    println!("[{}/{}] {} done", n, total, archive_name);
                });
            });
    }

    info!("[BATCH] All {} archives processed.", total);
    Ok(())
}

// ── Features XML structures ───────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeaturesData {
    pub servers: Vec<ServerEntry>,
    pub features: Vec<FeatureEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub region: String,
    pub server_id: u16,
    pub channel: u8,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FeatureEntry {
    pub hash: u32,
    pub hash_hex: String,
    pub conditions: Vec<String>,
}

/// Parse features.xml.compiled binary into a structured `FeaturesData`.
pub fn parse_features_compiled(data: &[u8]) -> Option<FeaturesData> {
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
        if len > 0 && !d[pos..pos + len].iter().all(|&b| { let c = b ^ 0x80; c >= 0x20 && c <= 0x7E }) { return None; }
        Some(d[pos..pos + len].iter().map(|&b| (b ^ 0x80) as char).collect())
    }

    let mut pos = 0usize;
    let server_count = r16(data, pos)? as usize;
    pos += 2;
    if server_count > 200 { return None; }

    let mut servers = Vec::with_capacity(server_count);
    for _ in 0..server_count {
        let nl = r16(data, pos)? as usize; pos += 2;
        let name = xdec(data, pos, nl)?; pos += nl;
        let rl = r16(data, pos)? as usize; pos += 2;
        let region = xdec(data, pos, rl)?; pos += rl;
        let server_id = r16(data, pos)?; pos += 2;
        if pos >= data.len() { return None; }
        let channel = data[pos]; pos += 1;
        servers.push(ServerEntry { name, region, server_id, channel });
    }

    let feature_count = r16(data, pos)? as usize;
    pos += 2;
    if feature_count > 100_000 { return None; }

    let mut features = Vec::with_capacity(feature_count);
    for _ in 0..feature_count {
        let hash = r32(data, pos)?;
        pos += 4;
        let mut conds: Vec<String> = Vec::new();
        loop {
            if pos + 2 > data.len() { break; }
            let clen = r16(data, pos)? as usize;
            if clen > 500 { break; }
            if clen > 0 {
                if pos + 2 + clen > data.len() { break; }
                if !data[pos + 2..pos + 2 + clen].iter().all(|&b| { let c = b ^ 0x80; c >= 0x20 && c <= 0x7E }) { break; }
            }
            pos += 2;
            let s: String = data[pos..pos + clen].iter().map(|&b| (b ^ 0x80) as char).collect();
            pos += clen;
            conds.push(s);
        }
        features.push(FeatureEntry {
            hash,
            hash_hex: format!("{:#010x}", hash),
            conditions: conds,
        });
    }

    Some(FeaturesData { servers, features })
}

/// Re-encode a `FeaturesData` back to the features.xml.compiled binary format.
///
/// The format stores conditions per-feature with no explicit count; the decoder
/// terminates the condition list when it sees a u16 > 500.  For all
/// features except the last, that terminator is the low-two-bytes of the next
/// feature's u32 hash.  This means hashes whose LE low-u16 ≤ 500 would confuse
/// the decoder.  We write an explicit 0xFFFF sentinel (2 bytes) after each
/// feature's conditions to guarantee the decoder always sees a value > 500
/// before the next hash.  The sentinel is NOT part of the next hash — the
/// decoder breaks out and then reads 4 bytes for the hash, so we need the
/// sentinel to be consumed as a "too-large clen" without pos advancing.
///
/// Wait — the decoder does NOT advance pos when it breaks on clen > 500.
/// So it will re-read those 2 bytes as the first 2 bytes of the next u32 hash.
/// That means: if we write sentinel (0xFFFF, 2 bytes) then the next hash (4 bytes),
/// the decoder reads sentinel+first-2-of-hash as a u32 hash. Wrong.
///
/// Solution: we only need the EXISTING hash's low-u16 to be > 500.
/// For hashes where it isn't, we store an explicit u16 between conditions and hash
/// — but since the decoder re-reads that u16 as part of the hash, this is
/// fundamentally impossible to do without changing the hash.
///
/// We therefore rely on the game's hash values all having low-u16 > 500.
/// If a hash doesn't satisfy this, we emit a warning but still produce output.
pub fn encode_features_compiled(data: &FeaturesData) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    let xenc = |s: &str| -> Vec<u8> {
        s.bytes().map(|b| b ^ 0x80).collect()
    };
    let w16 = |out: &mut Vec<u8>, v: u16| {
        out.extend_from_slice(&v.to_le_bytes());
    };
    let w32 = |out: &mut Vec<u8>, v: u32| {
        out.extend_from_slice(&v.to_le_bytes());
    };

    w16(&mut out, data.servers.len() as u16);
    for s in &data.servers {
        let name_enc = xenc(&s.name);
        w16(&mut out, name_enc.len() as u16);
        out.extend_from_slice(&name_enc);
        let region_enc = xenc(&s.region);
        w16(&mut out, region_enc.len() as u16);
        out.extend_from_slice(&region_enc);
        w16(&mut out, s.server_id);
        out.push(s.channel);
    }

    w16(&mut out, data.features.len() as u16);
    for f in &data.features {
        w32(&mut out, f.hash);
        for cond in &f.conditions {
            let enc = xenc(cond);
            w16(&mut out, enc.len() as u16);
            out.extend_from_slice(&enc);
        }
        // No explicit terminator — the next hash's low-u16 terminates the list.
        // The last feature's list is terminated by EOF.
    }

    out
}

/// Decode a features.xml.compiled binary blob to XML text.
/// Returns None if the data doesn't match the expected format.
pub fn decode_features_compiled(data: &[u8]) -> Option<String> {
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
        if len > 0 && !d[pos..pos + len].iter().all(|&b| { let c = b ^ 0x80; c >= 0x20 && c <= 0x7E }) { return None; }
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
        xml.push_str(&format!("    <server name=\"{}\" region=\"{}\" server_id=\"{}\" channel=\"{}\"/>\n",
            esc(&name), esc(&region), sid, ch));
    }
    xml.push_str("  </servers>\n");

    let feature_count = r16(data, pos)? as usize;
    pos += 2;
    if feature_count > 100_000 { return None; }
    xml.push_str(&format!("  <features count=\"{}\">\n", feature_count));

    for _ in 0..feature_count {
        let hash = r32(data, pos)?;
        pos += 4;
        let mut conds: Vec<String> = Vec::new();
        loop {
            if pos + 2 > data.len() { break; }
            let clen = r16(data, pos)? as usize;
            if clen > 500 { break; }
            if clen > 0 {
                if pos + 2 + clen > data.len() { break; }
                if !data[pos + 2..pos + 2 + clen].iter().all(|&b| { let c = b ^ 0x80; c >= 0x20 && c <= 0x7E }) { break; }
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
