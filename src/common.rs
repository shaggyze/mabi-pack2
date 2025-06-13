// common.rs

use crate::encryption;
use anyhow::{Context as AnyhowContext, Error};
use byte_slice_cast::AsSliceOf;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom, ErrorKind as IoErrorKind};
use std::path::Path;

use log::{debug, error, trace};

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub checksum: u32,
    pub version: u8,
    pub file_cnt: u32,
}

impl FileHeader {
    pub fn new<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        trace!("[HEADER] Attempting to read checksum (u32)...");
        let checksum = reader.read_u32::<LittleEndian>()?;
        trace!("[HEADER] Read checksum_raw: 0x{:X} ({})", checksum, checksum);
        trace!("[HEADER] Attempting to read version (u8)...");
        let version = reader.read_u8()?;
        trace!("[HEADER] Read version_raw: {}", version);
        trace!("[HEADER] Attempting to read file_cnt (u32)...");
        let file_cnt = reader.read_u32::<LittleEndian>()?;
        trace!("[HEADER] Read file_cnt_raw: 0x{:X} ({})", file_cnt, file_cnt);
        Ok(FileHeader { checksum, version, file_cnt })
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub checksum: u32,
    pub flags: u32,
    pub offset: u32,
    pub original_size: u32,
    pub raw_size: u32,
    pub key: [u8; 16],
}

pub const FLAG_COMPRESSED: u32 = 1;
pub const FLAG_ALL_ENCRYPTED: u32 = 2;
pub const FLAG_HEAD_ENCRYPTED: u32 = 4;

pub trait StreamPositionProvider {
    fn current_stream_position(&self) -> u64;
}

impl<'a, R: Read> StreamPositionProvider for encryption::Snow2Decoder<'a, R> {
    fn current_stream_position(&self) -> u64 {
        self.stream_position()
    }
}
impl<T: StreamPositionProvider + ?Sized> StreamPositionProvider for &mut T {
    fn current_stream_position(&self) -> u64 {
        (**self).current_stream_position()
    }
}


impl FileEntry {
    pub fn new<R>(reader: &mut R) -> Result<Self, std::io::Error>
    where
        R: Read + StreamPositionProvider + ?Sized,
    {
        let log_read_attempt = |field_name: &str, expected_bytes: usize, r: &R| -> u64 {
            let pos = r.current_stream_position();
            trace!("[ENTRY @ 0x{:X}] Reading {}: {} bytes expected.", pos, field_name, expected_bytes);
            pos
        };

        let log_read_failure = |field_name: &str, pos: u64, expected_bytes: usize, e: &std::io::Error| {
            error!("[ENTRY @ 0x{:X}] FAILED to read {} ({} bytes expected): {}. Kind: {:?}",
                   pos, field_name, expected_bytes, e, e.kind());
        };
        
        let pos_len = log_read_attempt("filename length (num_chars)", 4, reader);
        let str_len_u32 = reader.read_u32::<LittleEndian>().map_err(|e| { log_read_failure("filename length (num_chars)", pos_len, 4, &e); e })?;
        trace!("[ENTRY] Read filename length (num_chars): {} (0x{:X})", str_len_u32, str_len_u32);

        if str_len_u32 == 0 || str_len_u32 > 4096 { 
            debug!("[ENTRY] Suspicious filename length (num_chars): {}. Potential corruption or incorrect decryption key for entries.", str_len_u32);
            return Err(std::io::Error::new(IoErrorKind::InvalidData, format!("Suspicious filename length: {}", str_len_u32)));
        }

        let fname_bytes_len = str_len_u32 as usize * 2;
        let pos_fname = log_read_attempt("filename UTF-16 bytes", fname_bytes_len, reader);
        let mut fname_bytes = vec![0u8; fname_bytes_len];
        reader.read_exact(&mut fname_bytes).map_err(|e| { log_read_failure("filename UTF-16 bytes", pos_fname, fname_bytes_len, &e); e })?;
        trace!("[ENTRY] Read filename_bytes (first 64 hex if long, else full): {:?}", 
            &fname_bytes[..std::cmp::min(fname_bytes.len(), 64)].iter().map(|b| format!("{:02X}",b)).collect::<String>());

        let fname_string = String::from_utf16(fname_bytes.as_slice_of::<u16>().map_err(|e| {
            error!("[ENTRY] Failed to cast filename bytes (len {}) to u16 slice: {:?}", fname_bytes.len(), e);
            std::io::Error::new(IoErrorKind::InvalidData, "filename bytes not aligned for u16 or wrong length")
        })?)
        .map_err(|e| {
            error!("[ENTRY] String::from_utf16 failed for filename: {}", e);
            std::io::Error::new(IoErrorKind::InvalidData, format!("UTF-16 conversion error: {}", e))
        })?;
        trace!("[ENTRY] Decoded filename: '{}'", fname_string);
        
        let read_u32_field = |name: &str, r: &mut R| -> Result<u32, std::io::Error> {
            let pos = log_read_attempt(name, 4, r);
            let val = r.read_u32::<LittleEndian>().map_err(|e| { log_read_failure(name, pos, 4, &e); e })?;
            trace!("[ENTRY for '{}'] Read {}: 0x{:X} ({})", fname_string, name, val, val);
            Ok(val)
        };
        
        let checksum = read_u32_field("entry checksum", reader)?;
        let flags = read_u32_field("entry flags", reader)?;
        let offset = read_u32_field("entry data offset (blocks)", reader)?;
        let original_size = read_u32_field("entry original_size", reader)?;
        let raw_size = read_u32_field("entry raw_size", reader)?;

        let mut key_bytes = [0u8; 16];
        let pos_key = log_read_attempt("entry key", 16, reader);
        reader.read_exact(&mut key_bytes).map_err(|e| { log_read_failure("entry key", pos_key, 16, &e); e })?;
        trace!("[ENTRY for '{}'] Read entry key: {:?}", fname_string, key_bytes);

        Ok(FileEntry { name: fname_string, checksum, flags, offset, original_size, raw_size, key: key_bytes })
    }
}


pub fn get_final_file_name(fname: &str) -> Result<String, Error> {
    Path::new(fname)
        .file_name()
        .ok_or_else(|| Error::msg(format!("not a valid file path: {}", fname)))
        .map(|s| s.to_str().unwrap_or("").to_owned())
}

// --- START OF FIX ---
// Changed function signature to accept `header_offset`
pub fn read_header<RUND: Read + Seek>(
    fname_for_key: &str,
    skey: &str,
    underlying_rd: &mut RUND,
    header_offset: u64,
) -> Result<FileHeader, Error> {
    trace!("[HEADER] read_header: Using fname_for_key='{}', skey='{}', testing at offset 0x{:X}", fname_for_key, skey, header_offset);
    let key = encryption::gen_header_key(fname_for_key, skey);
    trace!("[HEADER] read_header: Generated header key (first 4 bytes): {:?}", &key[..std::cmp::min(key.len(), 4)]);
    
    // No longer calculating offset here, using the one passed in.
    let current_pos_before_seek = underlying_rd.stream_position().context("Failed to get stream position before header seek")?;
    trace!("[HEADER] read_header: Underlying stream position before seek: 0x{:X}", current_pos_before_seek);
    
    // Using the passed-in `header_offset` instead of a locally calculated one.
    underlying_rd.seek(SeekFrom::Start(header_offset)).context(format!("Failed to seek to header offset 0x{:X}", header_offset))?;
    trace!("[HEADER] read_header: Seeked underlying stream to 0x{:X} for header data.", header_offset);
    
    let mut dec_stream = encryption::Snow2Decoder::new(&key, underlying_rd);
    trace!("[HEADER] read_header: Initialized Snow2Decoder for header.");
    
    let header_result = FileHeader::new(&mut dec_stream);
    match &header_result {
        Ok(h) => trace!("[HEADER] read_header: FileHeader::new successfully returned: {:?}", h),
        Err(e) => {
            let dec_stream_pos = dec_stream.current_stream_position();
            error!("[HEADER] read_header: FileHeader::new failed: {}. Decrypting stream pos (approx): 0x{:X}. Error suggests key/offset wrong or data corrupt.", e, dec_stream_pos);
        }
    }
    header_result.map_err(Error::new)
}
// --- END OF FIX ---


pub fn validate_header(hdr: &FileHeader) -> Result<(), Error> {
    trace!("[HEADER] validate_header: Validating header: {:?}", hdr);
    let calculated_value_for_checksum = (hdr.version as u32).wrapping_add(hdr.file_cnt);
    trace!("[HEADER] validate_header: version_u32 ({}) + file_cnt ({}) = calculated_value ({}) vs hdr.checksum ({})",
        hdr.version as u32, hdr.file_cnt, calculated_value_for_checksum, hdr.checksum);
    if calculated_value_for_checksum != hdr.checksum {
        debug!("[HEADER] validate_header: Header checksum mismatch! Calculated: {} (0x{:X}), Expected in header: {} (0x{:X}). Header: {:?}",
            calculated_value_for_checksum, calculated_value_for_checksum, hdr.checksum, hdr.checksum, hdr);
        Err(Error::msg("header checksum wrong"))
    } else {
        debug!("[HEADER] validate_header: Header checksum OK.");
        Ok(())
    }
}

pub fn read_entries<RUND: Read + Seek>(
    fname_for_key: &str,
    header: &FileHeader,
    skey: &str,
    underlying_rd: &mut RUND,
    use_formula_only: bool,
) -> Result<Vec<FileEntry>, Error> {
    debug!("[ENTRIES] read_entries: Reading {} file entries for '{}'. Heuristic Mode: {}", header.file_cnt, fname_for_key, !use_formula_only);

    let entries_key = encryption::gen_entries_key(fname_for_key, skey);
    let formula_calculated_entries_offset = (encryption::gen_header_offset(fname_for_key) + encryption::gen_entries_offset(fname_for_key)) as u64;
    
    let mut candidate_offsets = vec![formula_calculated_entries_offset];
    
    if !use_formula_only {
        debug!("[ENTRIES] Formula failed, trying internal offset heuristics...");
        let offset_header_block_abs = encryption::gen_header_offset(fname_for_key) as u64;
        let offset_entry_sub_block_abs = encryption::gen_entries_offset(fname_for_key) as u64;
        
        candidate_offsets.push(offset_entry_sub_block_abs);
        candidate_offsets.push(offset_header_block_abs + 9);
        if formula_calculated_entries_offset > 8 {
            candidate_offsets.push(formula_calculated_entries_offset - 8);
            candidate_offsets.push(formula_calculated_entries_offset - 4);
        }
        candidate_offsets.push(formula_calculated_entries_offset + 4);
        candidate_offsets.push(formula_calculated_entries_offset + 8);
        candidate_offsets.sort_unstable();
        candidate_offsets.dedup();
    }
    
    let original_rd_pos = underlying_rd.stream_position()?;

    for offset in candidate_offsets {
        trace!("[ENTRIES] Attempting to read entries list from offset 0x{:X}", offset);
        if underlying_rd.seek(SeekFrom::Start(offset)).is_err() {
            trace!("[ENTRIES] Seek to offset 0x{:X} failed, skipping.", offset);
            continue;
        }

        let mut dec_stream = encryption::Snow2Decoder::new(&entries_key, underlying_rd);
        
        let entries_result: Result<Vec<FileEntry>, _> = (0..header.file_cnt)
            .map(|_| FileEntry::new(&mut dec_stream))
            .collect();

        if let Ok(entries) = entries_result {
            debug!("[ENTRIES] Successfully read all {} declared entries from offset 0x{:X}", entries.len(), offset);
            return Ok(entries);
        } else {
            trace!("[ENTRIES] Reading entries from offset 0x{:X} failed.", offset);
        }
    }
    
    underlying_rd.seek(SeekFrom::Start(original_rd_pos))?;
    Err(Error::msg("All candidate entry offsets failed for the given key."))
}


pub fn validate_entries(entries: &[FileEntry]) -> Result<(), Error> {
    for (idx, ent) in entries.iter().enumerate() {
        trace!("[ENTRIES] validate_entries: Validating entry {}/{}: Name: '{}', Details: {:?}", idx + 1, entries.len(), ent.name, ent);
        let key_sum = ent.key.iter().fold(0u32, |s, v| s.wrapping_add(*v as u32));
        let calculated_sum = ent.flags.wrapping_add(ent.offset)
            .wrapping_add(ent.original_size)
            .wrapping_add(ent.raw_size)
            .wrapping_add(key_sum);

        trace!("[ENTRIES] validate_entries: For '{}': flags(0x{:X}) + offset_blocks(0x{:X}) + orig_size({}) + raw_size({}) + key_sum(0x{:X}) = calc_sum(0x{:X}) vs entry_checksum(0x{:X})",
            ent.name, ent.flags, ent.offset, ent.original_size, ent.raw_size, key_sum, calculated_sum, ent.checksum);

        if calculated_sum != ent.checksum {
            error!("[ENTRIES] validate_entries: Entry checksum wrong for file '{}'. Calculated: {} (0x{:X}), Expected: {} (0x{:X}). Entry: {:?}",
                ent.name, calculated_sum, calculated_sum, ent.checksum, ent.checksum, ent);
            return Err(Error::msg(format!("entry checksum wrong, file name: {}",ent.name)));
        }
    }
    debug!("[ENTRIES] validate_entries: All {} entries validated successfully.", entries.len());
    Ok(())
}


pub fn try_read_and_validate_header<RUND: Read + Seek>(
    underlying_rd: &mut RUND,
    fname_for_key: &str,
    skey: &str,
    candidate_offset: u64,
) -> Result<Option<(FileHeader, u64)>, Error> {
    trace!("[HEADER_HEURISTIC] Testing offset 0x{:X} with skey '{}'", candidate_offset, skey);
    
    underlying_rd.seek(SeekFrom::Start(candidate_offset))
        .with_context(|| format!("Heuristic seek to offset 0x{:X} failed", candidate_offset))?;
    
    // --- START OF FIX ---
    // The call to `read_header` now passes the `candidate_offset` it's supposed to be testing.
    let header = match read_header(fname_for_key, skey, underlying_rd, candidate_offset) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };
    // --- END OF FIX ---
    
    if header.version >= 10 || header.file_cnt >= 50000 {
        trace!("[HEADER_HEURISTIC]   Offset 0x{:X} -> Insane header data: {:?}", candidate_offset, header);
        return Ok(None);
    }
    
    if validate_header(&header).is_ok() {
        let pos_after_header = underlying_rd.stream_position()?;
        debug!("[HEADER_HEURISTIC]   SUCCESS! Found valid header at offset 0x{:X} with skey '{}'. Reader now at 0x{:X}", 
              candidate_offset, skey, pos_after_header);
        return Ok(Some((header, pos_after_header)));
    }

    Ok(None)
}