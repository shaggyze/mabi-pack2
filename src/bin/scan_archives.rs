/// scan_archives.rs — bulk analysis of all .it/.pack files in a directory.
///
/// Reports: filename, size, fs_created, fs_modified, salt, iv0, mode, version,
/// file_count, header_method (footer/formula/fixed), header_offset.
///
/// Usage:
///   cargo run --features debug --bin scan_archives -- <dir> [--csv]
///
/// Output: tab-separated or CSV table sorted by filesystem created date.

use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use memmap2::Mmap;
use rayon::prelude::*;
use mabi_pack2::{
    common::{self, FileHeader},
    encryption::{self, Snow2Mode, gen_header_key, gen_header_offset},
    load_salts,
};

#[derive(Debug)]
struct ArchiveRecord {
    path: PathBuf,
    size_bytes: u64,
    fs_created_secs: u64,
    fs_modified_secs: u64,
    salt: String,
    iv0: u32,
    mode: String,
    version: u8,
    file_count: u32,
    header_method: String,
    header_offset: u64,
    // Raw fingerprint bytes (hex) at the formula offset and EOF-4
    formula_offset: u64,
    raw_footer_4: String,
    raw_at_formula_9: String,
}

fn ts(t: std::io::Result<SystemTime>) -> u64 {
    t.ok()
        .and_then(|st| st.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fmt_ts(secs: u64) -> String {
    if secs == 0 { return "unknown".into(); }
    let s = secs;
    let (y, mo, d, h, mi, sec) = {
        // Simple Gregorian calendar decomposition (no leap-second handling needed)
        let days = s / 86400;
        let time = s % 86400;
        let h = time / 3600;
        let mi = (time % 3600) / 60;
        let sec = time % 60;
        // Days since 1970-01-01
        let (y, mo, d) = days_to_ymd(days);
        (y, mo, d, h, mi, sec)
    };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, sec)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let dy = if leap { 366 } else { 365 };
        if days < dy { break; }
        days -= dy;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [31u64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for &m in &months {
        if days < m { break; }
        days -= m;
        month += 1;
    }
    (year, month, days + 1)
}

fn hex4(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("")
}

fn scan_one(path: &Path, salts: &[String]) -> Option<ArchiveRecord> {
    let meta = fs::metadata(path).ok()?;
    let size_bytes = meta.len();
    let fs_created_secs = ts(meta.created());
    let fs_modified_secs = ts(meta.modified());

    let fname = path.file_name()?.to_str()?.to_owned();
    let ext = path.extension()?.to_str()?.to_lowercase();

    // .pack files: unencrypted, report separately
    if ext == "pack" {
        let entries = mabi_pack2::pack_v1::run_list_v1_data(path.to_str()?).ok()?;
        return Some(ArchiveRecord {
            path: path.to_path_buf(),
            size_bytes,
            fs_created_secs,
            fs_modified_secs,
            salt: "UNENCRYPTED".into(),
            iv0: 0,
            mode: "N/A".into(),
            version: 0,
            file_count: entries.len() as u32,
            header_method: "pack_v1".into(),
            header_offset: 0,
            formula_offset: 0,
            raw_footer_4: String::new(),
            raw_at_formula_9: String::new(),
        });
    }

    if ext != "it" { return None; }

    let file = File::open(path).ok()?;
    let mmap = unsafe { Mmap::map(&file).ok()? };
    let size = mmap.len() as u64;
    if size < 20 { return None; }

    // Capture raw fingerprint bytes before attempting decryption
    let raw_footer_4 = hex4(&mmap[size as usize - 4..]);
    let formula_offset = gen_header_offset(&fname) as u64;
    let fo = formula_offset as usize;
    let raw_at_formula_9 = if fo + 9 <= mmap.len() { hex4(&mmap[fo..fo + 9]) } else { "?".into() };

    // Try all salts with all iv0/mode combinations
    for skey in salts.iter() {
        for iv0 in &[1u32, 0u32] {
            for mode in &[Snow2Mode::Sub, Snow2Mode::Xor] {
                let mut rd = Cursor::new(&mmap[..]);

                // Method 1: footer pointer
                if size > 8 {
                    if let Ok(Some((header, off, found_iv0, found_mode))) =
                        try_footer(&mut rd, &fname, skey, size, *iv0, *mode)
                    {
                        if let Ok((_, entries, _)) = common::read_meta_iv_mode(&fname, skey, &mut rd, off, found_iv0, found_mode) {
                            if common::validate_entries(&entries).is_ok() {
                                return Some(make_record(
                                    path, size_bytes, fs_created_secs, fs_modified_secs,
                                    skey, found_iv0, found_mode, &header, entries.len() as u32,
                                    "footer", off, formula_offset, raw_footer_4, raw_at_formula_9,
                                ));
                            }
                        }
                    }
                }

                // Method 2: formula offset
                let mut rd = Cursor::new(&mmap[..]);
                if let Ok(Some((header, _))) = common::try_read_and_validate_header_iv(
                    &mut rd, &fname, skey, formula_offset, *iv0, *mode,
                ) {
                    let mut rd2 = Cursor::new(&mmap[..]);
                    if let Ok((_, entries, _)) = common::read_meta_iv_mode(&fname, skey, &mut rd2, formula_offset, *iv0, *mode) {
                        if common::validate_entries(&entries).is_ok() {
                            return Some(make_record(
                                path, size_bytes, fs_created_secs, fs_modified_secs,
                                skey, *iv0, *mode, &header, entries.len() as u32,
                                "formula", formula_offset, formula_offset, raw_footer_4, raw_at_formula_9,
                            ));
                        }
                    }
                }

                // Method 3: fixed offsets
                for &shift in &[0u64, 108, 109] {
                    let mut rd = Cursor::new(&mmap[..]);
                    if let Ok(Some((header, _))) = common::try_read_and_validate_header_iv(
                        &mut rd, &fname, skey, shift, *iv0, *mode,
                    ) {
                        let mut rd2 = Cursor::new(&mmap[..]);
                        if let Ok((_, entries, _)) = common::read_meta_iv_mode(&fname, skey, &mut rd2, shift, *iv0, *mode) {
                            if common::validate_entries(&entries).is_ok() {
                                return Some(make_record(
                                    path, size_bytes, fs_created_secs, fs_modified_secs,
                                    skey, *iv0, *mode, &header, entries.len() as u32,
                                    &format!("fixed:{}", shift), shift, formula_offset, raw_footer_4, raw_at_formula_9,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Failed to decrypt — still report metadata
    Some(ArchiveRecord {
        path: path.to_path_buf(),
        size_bytes,
        fs_created_secs,
        fs_modified_secs,
        salt: "UNKNOWN".into(),
        iv0: 0,
        mode: "UNKNOWN".into(),
        version: 0,
        file_count: 0,
        header_method: "UNKNOWN".into(),
        header_offset: 0,
        formula_offset,
        raw_footer_4,
        raw_at_formula_9,
    })
}

fn try_footer(
    rd: &mut Cursor<&[u8]>,
    fname: &str,
    skey: &str,
    size: u64,
    iv0: u32,
    mode: Snow2Mode,
) -> std::io::Result<Option<(FileHeader, u64, u32, Snow2Mode)>> {
    rd.seek(SeekFrom::End(-4))?;
    let mut f_bytes = [0u8; 4];
    rd.read_exact(&mut f_bytes)?;
    let key = gen_header_key(fname, skey);
    let mut cur = Cursor::new(f_bytes);
    let mut dec = encryption::Snow2Decoder::new_iv_mode(&key, iv0, mode, &mut cur);
    use byteorder::{LittleEndian, ReadBytesExt};
    if let Ok(off) = dec.read_u32::<LittleEndian>() {
        let off = off as u64;
        if off < size.saturating_sub(9) {
            if let Ok(Some((header, _))) = common::try_read_and_validate_header_iv(rd, fname, skey, off, iv0, mode) {
                return Ok(Some((header, off, iv0, mode)));
            }
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn make_record(
    path: &Path,
    size_bytes: u64,
    fs_created_secs: u64,
    fs_modified_secs: u64,
    skey: &str,
    iv0: u32,
    mode: Snow2Mode,
    header: &FileHeader,
    file_count: u32,
    header_method: &str,
    header_offset: u64,
    formula_offset: u64,
    raw_footer_4: String,
    raw_at_formula_9: String,
) -> ArchiveRecord {
    ArchiveRecord {
        path: path.to_path_buf(),
        size_bytes,
        fs_created_secs,
        fs_modified_secs,
        salt: skey.to_string(),
        iv0,
        mode: format!("{:?}", mode),
        version: header.version,
        file_count,
        header_method: header_method.to_string(),
        header_offset,
        formula_offset,
        raw_footer_4,
        raw_at_formula_9,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: scan_archives <directory> [--csv]");
        eprintln!("  Scans all .it/.pack files and reports salt/version/mode/date metadata.");
        std::process::exit(1);
    }
    let dir = &args[1];
    let csv_mode = args.contains(&"--csv".to_string());

    eprintln!("[SCAN] Loading salts...");
    let salts = load_salts();
    eprintln!("[SCAN] Loaded {} salts.", salts.len());

    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .expect("Cannot read directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("it") || e.eq_ignore_ascii_case("pack"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();

    eprintln!("[SCAN] Found {} .it/.pack files. Scanning (parallel)...", paths.len());

    let mut records: Vec<ArchiveRecord> = paths
        .par_iter()
        .filter_map(|p| {
            let r = scan_one(p, &salts);
            if let Some(ref rec) = r {
                let fname = rec.path.file_name().unwrap_or_default().to_string_lossy();
                eprintln!("  {} -> salt={} iv0={} mode={} ver={} files={} method={}",
                    fname, rec.salt, rec.iv0, rec.mode, rec.version, rec.file_count, rec.header_method);
            }
            r
        })
        .collect();

    // Sort by filesystem created date, then by filename
    records.sort_by(|a, b| {
        a.fs_created_secs.cmp(&b.fs_created_secs)
            .then(a.path.file_name().cmp(&b.path.file_name()))
    });

    // Output
    let sep = if csv_mode { "," } else { "\t" };
    println!(
        "{}",
        [
            "filename", "size_bytes", "fs_created", "fs_modified",
            "salt", "iv0", "mode", "version", "file_count",
            "header_method", "header_offset", "formula_offset",
            "raw_footer_4", "raw_at_formula_9"
        ].join(sep)
    );

    for r in &records {
        let fname = r.path.file_name().unwrap_or_default().to_string_lossy();
        if csv_mode {
            println!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                fname, r.size_bytes,
                fmt_ts(r.fs_created_secs), fmt_ts(r.fs_modified_secs),
                r.salt, r.iv0, r.mode, r.version, r.file_count,
                r.header_method, r.header_offset, r.formula_offset,
                r.raw_footer_4, r.raw_at_formula_9
            );
        } else {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                fname, r.size_bytes,
                fmt_ts(r.fs_created_secs), fmt_ts(r.fs_modified_secs),
                r.salt, r.iv0, r.mode, r.version, r.file_count,
                r.header_method, r.header_offset, r.formula_offset,
                r.raw_footer_4, r.raw_at_formula_9
            );
        }
    }

    // Summary stats
    eprintln!("\n=== SUMMARY ===");
    let total = records.len();
    let unknown = records.iter().filter(|r| r.salt == "UNKNOWN").count();
    eprintln!("Total archives:   {}", total);
    eprintln!("Decrypted:        {}", total - unknown);
    eprintln!("Unknown (failed): {}", unknown);

    // Salt frequency
    let mut salt_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &records {
        *salt_counts.entry(r.salt.as_str()).or_insert(0) += 1;
    }
    let mut salt_list: Vec<(&&str, &usize)> = salt_counts.iter().collect();
    salt_list.sort_by(|a, b| b.1.cmp(a.1));
    eprintln!("\nSalt distribution:");
    for (salt, count) in salt_list {
        eprintln!("  {:40} -> {} files", salt, count);
    }

    // Mode frequency
    let mut mode_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &records {
        *mode_counts.entry(r.mode.as_str()).or_insert(0) += 1;
    }
    eprintln!("\nMode distribution:");
    for (mode, count) in &mode_counts {
        eprintln!("  {:10} -> {} files", mode, count);
    }

    // Version distribution
    let mut ver_counts: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
    for r in records.iter().filter(|r| r.salt != "UNKNOWN") {
        *ver_counts.entry(r.version).or_insert(0) += 1;
    }
    let mut ver_list: Vec<(&u8, &usize)> = ver_counts.iter().collect();
    ver_list.sort_by_key(|(v, _)| **v);
    eprintln!("\nVersion distribution:");
    for (ver, count) in ver_list {
        eprintln!("  version {:3} -> {} files", ver, count);
    }

    // Header method frequency
    let mut method_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for r in &records {
        *method_counts.entry(r.header_method.as_str()).or_insert(0) += 1;
    }
    eprintln!("\nHeader method distribution:");
    for (method, count) in &method_counts {
        eprintln!("  {:15} -> {} files", method, count);
    }

    // IV0 distribution
    let mut iv_counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for r in records.iter().filter(|r| r.salt != "UNKNOWN") {
        *iv_counts.entry(r.iv0).or_insert(0) += 1;
    }
    eprintln!("\nIV0 distribution:");
    for (iv0, count) in &iv_counts {
        eprintln!("  iv0={} -> {} files", iv0, count);
    }
}
