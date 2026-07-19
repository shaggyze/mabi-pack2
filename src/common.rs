// common.rs

use crate::encryption;
use anyhow::Error;
use byte_slice_cast::AsSliceOf;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom, ErrorKind as IoErrorKind};
use std::path::Path;

use log::{debug, trace};

#[derive(Debug, Clone)]
pub struct FileHeader { pub checksum: u32, pub version: u8, pub file_cnt: u32 }

impl FileHeader {
    pub fn new<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        trace!("[HEADER] Attempting to read checksum (u32)...");
        let checksum = reader.read_u32::<LittleEndian>()?;
        trace!("[HEADER] Read checksum: 0x{:08X}", checksum);
        trace!("[HEADER] Attempting to read version (u8)...");
        let version = reader.read_u8()?;
        trace!("[HEADER] Read version: {}", version);
        trace!("[HEADER] Attempting to read file_cnt (u32)...");
        let file_cnt = reader.read_u32::<LittleEndian>()?;
        trace!("[HEADER] Read file_cnt: 0x{:08X}", file_cnt);
        Ok(FileHeader { checksum, version, file_cnt })
    }
}

pub fn validate_header(hdr: &FileHeader) -> Result<(), Error> {
    let calculated = (hdr.version as u32).wrapping_add(hdr.file_cnt);
    if calculated == hdr.checksum {
        trace!("[HEADER_VALIDATE] SUCCESS: Calculated sum matched 0x{:08X}", calculated);
        Ok(())
    } else {
        debug!("[HEADER_VALIDATE] FAIL: Calculated 0x{:08X} != Header 0x{:08X}", calculated, hdr.checksum);
        Err(Error::msg(format!("Checksum mismatch: calculated 0x{:08X}, header has 0x{:08X}", calculated, hdr.checksum)))
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry { pub name: String, pub checksum: u32, pub flags: u32, pub offset: u32, pub original_size: u32, pub raw_size: u32, pub key: [u8; 16] }

pub const FLAG_COMPRESSED: u32 = 1;
pub const FLAG_ALL_ENCRYPTED: u32 = 2;
pub const FLAG_HEAD_ENCRYPTED: u32 = 4;

pub trait StreamPositionProvider { fn current_stream_position(&self) -> u64; }
impl<'a, R: Read> StreamPositionProvider for encryption::Snow2Decoder<'a, R> { fn current_stream_position(&self) -> u64 { self.current_stream_position() } }
impl<T: StreamPositionProvider + ?Sized> StreamPositionProvider for &mut T { fn current_stream_position(&self) -> u64 { (**self).current_stream_position() } }

impl FileEntry {
    pub fn new<R>(reader: &mut R) -> Result<Self, std::io::Error> where R: Read + StreamPositionProvider + ?Sized, {
        let str_len_u32 = reader.read_u32::<LittleEndian>()?;
        if str_len_u32 == 0 || str_len_u32 > 4096 { return Err(std::io::Error::new(IoErrorKind::InvalidData, format!("Suspicious filename length: {}", str_len_u32))); }
        let mut fname_bytes = vec![0u8; str_len_u32 as usize * 2];
        reader.read_exact(&mut fname_bytes)?;
        let fname_string = String::from_utf16(fname_bytes.as_slice_of::<u16>().map_err(|_| std::io::Error::new(IoErrorKind::InvalidData, "filename bytes not aligned"))?).map_err(|e| std::io::Error::new(IoErrorKind::InvalidData, e))?;
        let checksum = reader.read_u32::<LittleEndian>()?;
        let flags = reader.read_u32::<LittleEndian>()?;
        let offset = reader.read_u32::<LittleEndian>()?;
        let original_size = reader.read_u32::<LittleEndian>()?;
        let raw_size = reader.read_u32::<LittleEndian>()?;
        let mut key = [0u8; 16];
        reader.read_exact(&mut key)?;
        Ok(FileEntry { name: fname_string, checksum, flags, offset, original_size, raw_size, key })
    }
}

pub fn get_final_file_name(fname: &str) -> Result<String, Error> {
    Path::new(fname).file_name().ok_or_else(|| Error::msg("not a valid file path")).map(|s| s.to_str().unwrap_or("").to_owned())
}

pub fn validate_entries(entries: &[FileEntry]) -> Result<(), Error> {
    for (idx, ent) in entries.iter().enumerate() {
        let key_sum = ent.key.iter().fold(0u32, |s, v| s.wrapping_add(*v as u32));
        let calculated_sum = ent.flags.wrapping_add(ent.offset).wrapping_add(ent.original_size).wrapping_add(ent.raw_size).wrapping_add(key_sum);
        if calculated_sum != ent.checksum {
            trace!("[ENTRIES] Entry {} checksum wrong. Name='{}'. Calc: 0x{:X}, Entry: 0x{:X}.", idx, ent.name, calculated_sum, ent.checksum);
            return Err(Error::msg(format!("entry checksum wrong, file name: {}", ent.name)));
        }
    }
    Ok(())
}

pub fn try_read_and_validate_header_iv<RUND: Read + Seek>(rd: &mut RUND, fname: &str, skey: &str, offset: u64, iv0: u32, mode: encryption::Snow2Mode) -> Result<Option<(FileHeader, u64)>, Error> {
    rd.seek(SeekFrom::Start(offset))?;
    let key = encryption::gen_header_key(fname, skey);
    let mut dec_stream = encryption::Snow2Decoder::new_iv_mode(&key, iv0, mode, rd);
    if let Ok(header) = FileHeader::new(&mut dec_stream) {
        if validate_header(&header).is_ok() { return Ok(Some((header, offset + 9))); }
    }
    Ok(None)
}

pub fn find_header_unified<RUND: Read + Seek>(rd: &mut RUND, fname: &str, skey: &str) -> Result<Option<(FileHeader, u64, u32, encryption::Snow2Mode)>, Error> {
    let size = rd.seek(SeekFrom::End(0))?;
    let modes = [encryption::Snow2Mode::Sub, encryption::Snow2Mode::Xor, encryption::Snow2Mode::ModernBE, encryption::Snow2Mode::ModernLE, encryption::Snow2Mode::LegacyBE, encryption::Snow2Mode::LegacyLE];
    
    for iv0 in &[1, 0] {
        for mode in &modes {
            // Priority 1: Footer pointer
            if size > 8 {
                rd.seek(SeekFrom::End(-4))?;
                let mut f_bytes = [0u8; 4];
                if rd.read_exact(&mut f_bytes).is_ok() {
                    let key = encryption::gen_header_key(fname, skey);
                    let mut cur = Cursor::new(f_bytes);
                    let mut dec = encryption::Snow2Decoder::new_iv_mode(&key, *iv0, *mode, &mut cur);
                    if let Ok(off) = dec.read_u32::<LittleEndian>() {
                        if (off as u64) < size - 9 {
                            if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, off as u64, *iv0, *mode) { 
                                // Deep validation: verify entries before accepting
                                if let Ok((_, entries, _)) = read_meta_iv_mode(fname, skey, rd, off as u64, *iv0, *mode) {
                                    if validate_entries(&entries).is_ok() {
                                        return Ok(Some((header, off as u64, *iv0, *mode)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Priority 2: Generated offset
            let f_off = encryption::gen_header_offset(fname) as u64;
            if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, f_off, *iv0, *mode) { 
                if let Ok((_, entries, _)) = read_meta_iv_mode(fname, skey, rd, f_off, *iv0, *mode) {
                    if validate_entries(&entries).is_ok() {
                        return Ok(Some((header, f_off, *iv0, *mode))); 
                    }
                }
            }
            // Priority 3: Shifts
            for shift in &[0, 108, 109] {
                if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, *shift, *iv0, *mode) { 
                    if let Ok((_, entries, _)) = read_meta_iv_mode(fname, skey, rd, *shift, *iv0, *mode) {
                        if validate_entries(&entries).is_ok() {
                            return Ok(Some((header, *shift, *iv0, *mode)));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn read_meta_iv_mode<RUND: Read + Seek>(fname: &str, skey: &str, rd: &mut RUND, header_offset: u64, iv0: u32, mode: encryption::Snow2Mode) -> Result<(FileHeader, Vec<FileEntry>, u64), Error> {
    let header = try_read_and_validate_header_iv(rd, fname, skey, header_offset, iv0, mode)?.map(|(h, _)| h).ok_or_else(|| Error::msg("Header validation failed"))?;
    let e_key = encryption::gen_entries_key(fname, skey);
    let e_off_gen = encryption::gen_entries_offset(fname) as u64;
    let mut candidate_e_offs = vec![header_offset + 9, header_offset + e_off_gen, encryption::gen_header_offset(fname) as u64 + e_off_gen];
    candidate_e_offs.sort_unstable(); candidate_e_offs.dedup();
    for off in candidate_e_offs {
        if rd.seek(SeekFrom::Start(off)).is_err() { continue; }
        let mut e_dec = encryption::Snow2Decoder::new_iv_mode(&e_key, iv0, mode, rd);
        let mut entries = Vec::with_capacity(header.file_cnt as usize);
        let mut success = true;
        for _ in 0..header.file_cnt {
            match FileEntry::new(&mut e_dec) { 
                Ok(ent) => {
                    // Stricter validation: entry name must be plausible
                    if ent.name.is_empty() || ent.name.len() > 1024 || ent.original_size > 500_000_000 {
                        success = false;
                        break;
                    }
                    entries.push(ent);
                }, 
                Err(_) => { success = false; break; } 
            }
        }
        if success && !entries.is_empty() && validate_entries(&entries).is_ok() { 
            let pos = rd.stream_position().unwrap_or(0);
            let content_offset = (pos + 1023) & !1023u64;
            return Ok((header, entries, content_offset)); 
        }
    }
    Err(Error::msg("Failed entries"))
}

/// Like `find_header_unified` but skips deep entries validation.
/// Used as Phase 1 of the two-phase salt search: validates the header checksum only.
pub fn find_header_only<RUND: Read + Seek>(rd: &mut RUND, fname: &str, skey: &str) -> Result<Option<(FileHeader, u64, u32, encryption::Snow2Mode)>, Error> {
    let size = rd.seek(SeekFrom::End(0))?;

    // Fast path: NA common case — Sub mode, iv0=0, formula offset.
    // Hits on the very first try for all known NA archives.
    let f_off = encryption::gen_header_offset(fname) as u64;
    if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, f_off, 0, encryption::Snow2Mode::Sub) {
        return Ok(Some((header, f_off, 0, encryption::Snow2Mode::Sub)));
    }

    // Full fallback for other regions/formats (KR, TW, footer-pointer archives, etc.)
    // iv0=0 first since NA is confirmed; iv0=1 kept for unknown KR/other behaviour.
    let modes = [encryption::Snow2Mode::Sub, encryption::Snow2Mode::Xor, encryption::Snow2Mode::ModernBE, encryption::Snow2Mode::ModernLE, encryption::Snow2Mode::LegacyBE, encryption::Snow2Mode::LegacyLE];
    for iv0 in &[0u32, 1] {
        for mode in &modes {
            if size > 8 {
                rd.seek(SeekFrom::End(-4))?;
                let mut f_bytes = [0u8; 4];
                if rd.read_exact(&mut f_bytes).is_ok() {
                    let key = encryption::gen_header_key(fname, skey);
                    let mut cur = Cursor::new(f_bytes);
                    let mut dec = encryption::Snow2Decoder::new_iv_mode(&key, *iv0, *mode, &mut cur);
                    if let Ok(off) = dec.read_u32::<LittleEndian>() {
                        if (off as u64) < size - 9 {
                            if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, off as u64, *iv0, *mode) {
                                return Ok(Some((header, off as u64, *iv0, *mode)));
                            }
                        }
                    }
                }
            }
            // Skip Sub+iv0=0+formula — already tried in fast path above
            if !(*iv0 == 0 && matches!(mode, encryption::Snow2Mode::Sub)) {
                if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, f_off, *iv0, *mode) {
                    return Ok(Some((header, f_off, *iv0, *mode)));
                }
            }
            for shift in &[0u64, 108, 109] {
                if let Ok(Some((header, _))) = try_read_and_validate_header_iv(rd, fname, skey, *shift, *iv0, *mode) {
                    return Ok(Some((header, *shift, *iv0, *mode)));
                }
            }
        }
    }
    Ok(None)
}

/// Like `read_meta_iv_mode` but decrypts the entries table with a separate salt.
/// Supports archives where the header salt and entries salt differ.
pub fn read_meta_iv_mode_two_key<RUND: Read + Seek>(fname: &str, header_skey: &str, entries_skey: &str, rd: &mut RUND, header_offset: u64, iv0: u32, mode: encryption::Snow2Mode) -> Result<(FileHeader, Vec<FileEntry>, u64), Error> {
    let header = try_read_and_validate_header_iv(rd, fname, header_skey, header_offset, iv0, mode)?.map(|(h, _)| h).ok_or_else(|| Error::msg("Header validation failed"))?;
    let e_key = encryption::gen_entries_key(fname, entries_skey);
    let e_off_gen = encryption::gen_entries_offset(fname) as u64;
    let mut candidate_e_offs = vec![header_offset + 9, header_offset + e_off_gen, encryption::gen_header_offset(fname) as u64 + e_off_gen];
    candidate_e_offs.sort_unstable(); candidate_e_offs.dedup();
    for off in candidate_e_offs {
        if rd.seek(SeekFrom::Start(off)).is_err() { continue; }
        let mut e_dec = encryption::Snow2Decoder::new_iv_mode(&e_key, iv0, mode, rd);
        let mut entries = Vec::with_capacity(header.file_cnt as usize);
        let mut success = true;
        for _ in 0..header.file_cnt {
            match FileEntry::new(&mut e_dec) {
                Ok(ent) => {
                    if ent.name.is_empty() || ent.name.len() > 1024 || ent.original_size > 500_000_000 {
                        success = false; break;
                    }
                    entries.push(ent);
                },
                Err(_) => { success = false; break; }
            }
        }
        if success && !entries.is_empty() && validate_entries(&entries).is_ok() {
            let pos = rd.stream_position().unwrap_or(0);
            return Ok((header, entries, (pos + 1023) & !1023u64));
        }
    }
    Err(Error::msg("Failed entries"))
}

pub fn read_meta<RUND: Read + Seek>(fname: &str, skey: &str, rd: &mut RUND, h_off: u64) -> Result<(FileHeader, Vec<FileEntry>, u32, encryption::Snow2Mode, u64), Error> {
    let modes = [encryption::Snow2Mode::Sub, encryption::Snow2Mode::Xor, encryption::Snow2Mode::ModernBE, encryption::Snow2Mode::ModernLE, encryption::Snow2Mode::LegacyBE, encryption::Snow2Mode::LegacyLE];
    for iv in &[1, 0] { 
        for mode in &modes {
            if let Ok(res) = read_meta_iv_mode(fname, skey, rd, h_off, *iv, *mode) {
                return Ok((res.0, res.1, *iv, *mode, res.2));
            }
        }
    }
    Err(Error::msg("All candidate entry offsets failed for the given key."))
}



pub fn write_file_to_disk(root_dir: &str, rel_path: &str, content: &[u8]) -> Result<(), Error> {
    let full_path = Path::new(root_dir).join(rel_path.replace(['/', '\\'], &std::path::MAIN_SEPARATOR.to_string()));
    if let Some(parent) = full_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&full_path, content).map_err(Error::new)
}
