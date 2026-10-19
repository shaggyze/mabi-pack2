// pack_v1.rs - Support for legacy .pack files

use std::fs::{self, File as StdFile};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use walkdir::WalkDir;
use anyhow::{Context, Error};
use log::{info, debug, trace, error, warn};
use memmap2::Mmap;
use rayon::prelude::*;
use crate::common::FileEntry;

pub const PACK_HEADER_MAGIC_REG: &[u8; 4] = b"PACK";
pub const PACK_HEADER_MAGIC_MABI: &[u8; 4] = b"MABI";
/// The index stores each name in a 256-byte NUL-terminated field.
pub const PACK_V1_NAME_MAX: usize = 255;

#[derive(Debug, Clone)]
pub struct PackEntryV1 {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub compressed_size: u32,
}

fn write_file(root_dir: &str, rel_path: &str, content: Vec<u8>) -> Result<(), Error> {
    // Normalize regional separators (¥, ₩, \, /) and refuse paths escaping root_dir.
    let fname = crate::common::safe_join(Path::new(root_dir), rel_path)?;
    trace!("[PACK_V1_WRITE] Preparing to write {} bytes to {}", content.len(), fname.display());
    let par = fname.parent().ok_or_else(|| {
        error!("[PACK_V1_WRITE] Could not get parent directory for {:?}", fname);
        Error::msg(format!("unrecognized path: {}", fname.to_string_lossy()))
    })?;
    fs::create_dir_all(par).context("Failed to create directory")?;
    fs::write(&fname, &content).context("Failed to write file")?;
    debug!("[PACK_V1_WRITE] Successfully wrote '{}' to {}", rel_path, root_dir);
    Ok(())
}

/// Entry flag for Mabinogi's own .pack format (MabinogiResource / MabiPack /
/// Cichol): the entry data is XOR-encrypted with an MT19937 stream seeded from the
/// entry's seed (kept in `FileEntry::checksum`). Never set for .it entries.
pub const FLAG_PACK_SEED_ENCRYPTED: u32 = 0x100;

/// Mabinogi's own .pack header starts with "PACK" and revision 0x0102 (or 0x0101).
/// mabi-patcher's simple PACK format stores a free version number there instead.
pub fn is_mabinogi_pack(input_path: &str) -> bool {
    let mut sig = [0u8; 8];
    StdFile::open(input_path).and_then(|mut f| f.read_exact(&mut sig)).is_ok()
        && &sig[0..4] == b"PACK"
        && (sig[4..8] == [2, 1, 0, 0] || sig[4..8] == [1, 1, 0, 0])
}

/// Minimal MT19937 (32-bit), as used by the .pack cipher.
struct Mt19937 { mt: [u32; 624], i: usize }

impl Mt19937 {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            mt[i] = 1812433253u32.wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30)).wrapping_add(i as u32);
        }
        Mt19937 { mt, i: 624 }
    }
    fn next(&mut self) -> u32 {
        if self.i >= 624 {
            for k in 0..624 {
                let y = (self.mt[k] & 0x8000_0000) | (self.mt[(k + 1) % 624] & 0x7fff_ffff);
                self.mt[k] = self.mt[(k + 397) % 624] ^ (y >> 1) ^ if y & 1 != 0 { 0x9908_b0df } else { 0 };
            }
            self.i = 0;
        }
        let mut y = self.mt[self.i];
        self.i += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }
}

/// Decrypts one Mabinogi .pack entry in place: stream seed = (seed << 7) ^ 0xA9C36DE1.
pub fn decrypt_pack_entry(data: &mut [u8], seed: u32) {
    let mut mt = Mt19937::new((seed << 7) ^ 0xA9C3_6DE1);
    for b in data.iter_mut() {
        *b ^= mt.next() as u8;
    }
}

pub fn run_list_v1_data(input_path: &str) -> Result<Vec<FileEntry>, Error> {
    // Mabinogi's own .pack (e.g. private servers like MabiPro) has a different index.
    if is_mabinogi_pack(input_path) {
        return run_list_logue_data(input_path);
    }
    info!("[PACK_V1] Listing metadata for .pack file: '{}'", input_path);
    let mut file = StdFile::open(input_path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    
    let is_mabi = &magic == PACK_HEADER_MAGIC_MABI;
    let is_reg = &magic == PACK_HEADER_MAGIC_REG;

    if !is_mabi && !is_reg {
        return Err(Error::msg("Invalid pack file magic"));
    }

    let _version = file.read_u32::<LittleEndian>()?;
    let (file_count, index_offset) = if is_mabi {
        let idx_off = file.read_u32::<LittleEndian>()?;
        let cnt = file.read_u32::<LittleEndian>()?;
        (cnt, idx_off)
    } else {
        let cnt = file.read_u32::<LittleEndian>()?;
        let idx_off = file.read_u32::<LittleEndian>()?;
        (cnt, idx_off)
    };

    file.seek(SeekFrom::Start(index_offset as u64))?;

    let mut entries = Vec::with_capacity(file_count as usize);
    for _ in 0..file_count {
        let mut name_buf = [0u8; 256];
        file.read_exact(&mut name_buf)?;
        let name = String::from_utf8_lossy(&name_buf)
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .to_string();
        
        let offset = file.read_u32::<LittleEndian>()?;
        let size = file.read_u32::<LittleEndian>()?;
        let compressed_size = file.read_u32::<LittleEndian>()?;
        let checksum = file.read_u32::<LittleEndian>()?;

        entries.push(FileEntry {
            name,
            offset,
            original_size: size,
            raw_size: compressed_size,
            checksum,
            flags: if size != compressed_size { crate::common::FLAG_COMPRESSED } else { 0 },
            key: [0u8; 16], // Not used for .pack
        });
    }
    Ok(entries)
}

pub fn extract_single_v1(mmap: &Mmap, ent: &FileEntry) -> Result<Vec<u8>, Error> {
    let start = ent.offset as usize;
    let end = start + ent.raw_size as usize;
    if end > mmap.len() {
        return Err(Error::msg("Entry out of bounds"));
    }

    let compressed_data = &mmap[start..end];
    if ent.flags & FLAG_PACK_SEED_ENCRYPTED != 0 {
        let mut data = compressed_data.to_vec();
        decrypt_pack_entry(&mut data, ent.checksum);
        if ent.flags & crate::common::FLAG_COMPRESSED == 0 {
            return Ok(data);
        }
        let mut decoder = ZlibDecoder::new(&data[..]);
        let mut out = Vec::with_capacity(ent.original_size as usize);
        decoder.read_to_end(&mut out).context(format!("Decompression failed for '{}'", ent.name))?;
        return Ok(out);
    }
    if ent.original_size == ent.raw_size {
        Ok(compressed_data.to_vec())
    } else {
        let mut decoder = ZlibDecoder::new(compressed_data);
        let mut decompressed_data = Vec::with_capacity(ent.original_size as usize);
        decoder.read_to_end(&mut decompressed_data).context(format!("Decompression failed for '{}'", ent.name))?;
        Ok(decompressed_data)
    }
}

pub fn run_extract_v1(input_path: &str, output_dir: &str) -> Result<(), Error> {
    info!("[PACK_V1] Starting extraction of .pack file: '{}'", input_path);
    let file = StdFile::open(input_path).context(format!("Failed to open file: {}", input_path))?;
    let mmap = unsafe { Mmap::map(&file).context("Failed to memory map the file")? };
    
    let entries = run_list_v1_data(input_path)?;
    info!("[PACK_V1] Index parsed ({} entries). Starting parallel extraction...", entries.len());

    entries.par_iter().try_for_each(|ent| {
        let data = extract_single_v1(&mmap, ent)?;
        write_file(output_dir, &ent.name, data)?;
        Ok::<(), Error>(())
    })?;

    info!("[PACK_V1] Extraction of .pack completed successfully.");
    Ok(())
}

pub fn run_list_v1(input_path: &str) -> Result<Vec<String>, Error> {
    run_list_v1_data(input_path).map(|v| v.into_iter().map(|e| e.name).collect())
}

pub fn run_pack_v1(input_dir: &str, output_path: &str, version: u32) -> Result<(), Error> {
    info!("[PACK_V1] Creating .pack file: '{}' from '{}'", output_path, input_dir);
    if let Some(parent) = Path::new(output_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut output_file = StdFile::create(output_path).context("Failed to create output file")?;
    
    // Write MABI header (Header size: 16 bytes)
    // Magic(4) + Version(4) + IndexOffset(4) + FileCount(4)
    output_file.write_all(PACK_HEADER_MAGIC_MABI)?;
    output_file.write_u32::<LittleEndian>(version)?;
    output_file.write_u32::<LittleEndian>(0)?; // index_offset placeholder
    output_file.write_u32::<LittleEndian>(0)?; // file_count placeholder

    let input_path_obj = Path::new(input_dir);
    let mut effective_root = input_path_obj.to_path_buf();
    if input_path_obj.is_file() {
        if let Some(parent) = input_path_obj.parent() {
            effective_root = parent.to_path_buf();
            debug!("[PACK_V1] Input is a file. Using parent as root: {:?}", effective_root);
        }
    } else if input_path_obj.file_name().map_or(false, |n| n.to_string_lossy().to_lowercase() == "data") {
        if let Some(parent) = input_path_obj.parent() {
            effective_root = parent.to_path_buf();
            debug!("[PACK_V1] 'data' folder detected. Using parent as root: {:?}", effective_root);
        }
    }

    // Collect files first
    let files: Vec<_> = WalkDir::new(input_path_obj)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    info!("[PACK_V1] Found {} files to pack. Compressing...", files.len());

    let packed_data: Result<Vec<(PackEntryV1, Vec<u8>)>, Error> = files.par_iter().map(|entry| {
        let path = entry.path();
        let rel_path = path.strip_prefix(&effective_root).unwrap();
        // Normalize to backslashes for legacy compatibility, including the regional ¥ / ₩ separators
        let name = rel_path.to_str().unwrap().replace(['/', '¥', '₩'], "\\");
        crate::common::validate_entry_path(&name)?;
        if name.len() > PACK_V1_NAME_MAX {
            return Err(Error::msg(format!(
                "entry path is {} bytes, over the .pack name field limit of {}: {}",
                name.len(), PACK_V1_NAME_MAX, name
            )));
        }

        let mut f = StdFile::open(path)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data)?;
        let compressed_data = encoder.finish()?;

        trace!("[PACK_V1] Compressed '{}': {} -> {}", name, data.len(), compressed_data.len());
        Ok((PackEntryV1 {
            name,
            offset: 0, // placeholder
            size: data.len() as u32,
            compressed_size: compressed_data.len() as u32,
        }, compressed_data))
    }).collect();

    let mut file_data_list = packed_data?;
    let file_count = file_data_list.len() as u32;
    let index_size = file_count * (256 + 4 + 4 + 4 + 4); // name + offset + size + compressed_size + checksum
    let mut current_offset = 16 + index_size;

    for (entry, _data) in &mut file_data_list {
        entry.offset = current_offset;
        current_offset += entry.compressed_size;
    }

    // Now write index
    debug!("[PACK_V1] Writing index ({} entries) at offset 16...", file_count);
    for (entry, _) in &file_data_list {
        let mut name_bytes = [0u8; 256];
        let name_src = entry.name.as_bytes();
        let len = std::cmp::min(name_src.len(), PACK_V1_NAME_MAX);
        name_bytes[..len].copy_from_slice(&name_src[..len]);
        // Rest of name_bytes is already 0
        output_file.write_all(&name_bytes)?;
        output_file.write_u32::<LittleEndian>(entry.offset)?;
        output_file.write_u32::<LittleEndian>(entry.size)?;
        output_file.write_u32::<LittleEndian>(entry.compressed_size)?;
        
        // Checksum: simple sum of metadata fields (observed in some variants)
        let checksum = entry.offset.wrapping_add(entry.size).wrapping_add(entry.compressed_size);
        output_file.write_u32::<LittleEndian>(checksum)?;
    }

    // Now write data
    debug!("[PACK_V1] Writing data blocks starting at offset {}...", 16 + index_size);
    for (_, data) in &file_data_list {
        output_file.write_all(data)?;
    }

    // Update MABI header: Offset 8 = IndexOffset, Offset 12 = FileCount
    output_file.seek(SeekFrom::Start(8))?;
    output_file.write_u32::<LittleEndian>(16)?; // index starts right after header
    output_file.write_u32::<LittleEndian>(file_count)?;

    info!("[PACK_V1] .pack file created successfully (MABI format).");
    Ok(())
}

/// A .pack name field: the name ends at the first NUL; the bytes after it are
/// leftover padding, not part of the name.
fn pack_name(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_string()
}

pub fn run_list_logue_data(input_path: &str) -> Result<Vec<FileEntry>, Error> {
    info!("[PACK_LOGUE] Listing metadata for Logue .pack: '{}'", input_path);
    let mut file = StdFile::open(input_path)?;
    
    // Header (512 bytes)
    let mut sig = [0u8; 8];
    file.read_exact(&mut sig)?;
    if &sig[0..4] != b"PACK" {
        return Err(Error::msg("Not a Logue PACK file"));
    }
    
    let _d1 = file.read_u32::<LittleEndian>()?;
    let file_count = file.read_u32::<LittleEndian>()?;
    file.seek(SeekFrom::Current(8 + 8))?; // Skip FTs
    // Root folder the entry names are relative to (normally "data\").
    let mut root_buf = [0u8; 480];
    file.read_exact(&mut root_buf)?;
    let root = String::from_utf8_lossy(&root_buf).trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string();
    let root = if root.is_empty() || root.ends_with('\\') || root.ends_with('/') { root } else { format!("{}\\", root) };

    // List Header (32 bytes)
    let list_sum = file.read_u32::<LittleEndian>()?;
    let list_header_size = file.read_u32::<LittleEndian>()?;
    let _blank_size = file.read_u32::<LittleEndian>()?;
    let _data_section_size = file.read_u32::<LittleEndian>()?;
    file.seek(SeekFrom::Current(16))?; // Skip zeros
    
    if list_sum != file_count {
        warn!("[PACK_LOGUE] File count mismatch: header={} list={}", file_count, list_sum);
    }

    // The list header's count is the real one (the header count can lag behind).
    let count = if list_sum > 0 { list_sum } else { file_count };
    let mut entries = Vec::with_capacity(count as usize);

    let data_start = 512 + 32 + list_header_size as u64;

    for _ in 0..count {
        let len_or_type = file.read_u8()?;
        let (name, _name_block_size) = if len_or_type < 4 {
            let block_size = (len_or_type as u32 + 1) * 16;
            let mut name_buf = vec![0u8; block_size as usize - 1];
            file.read_exact(&mut name_buf)?;
            let n = pack_name(&name_buf);
            (n, block_size)
        } else if len_or_type == 4 {
            let block_size = 0x60;
            let mut name_buf = vec![0u8; block_size as usize - 1];
            file.read_exact(&mut name_buf)?;
            let n = pack_name(&name_buf);
            (n, block_size)
        } else {
            let name_len = file.read_u32::<LittleEndian>()?;
            let mut name_buf = vec![0u8; name_len as usize];
            file.read_exact(&mut name_buf)?;
            let n = pack_name(&name_buf);
            (n, name_len + 5)
        };
        
        // ITEM_INFO (64 bytes)
        let seed = file.read_u32::<LittleEndian>()?;
        let _zero = file.read_u32::<LittleEndian>()?;
        let offset = file.read_u32::<LittleEndian>()?;
        let compress_size = file.read_u32::<LittleEndian>()?;
        let decompress_size = file.read_u32::<LittleEndian>()?;
        let is_compressed = file.read_u32::<LittleEndian>()?;
        file.seek(SeekFrom::Current(40))?; // Skip FTs
        
        let offset = data_start + offset as u64;
        if offset > u32::MAX as u64 {
            return Err(Error::msg(format!("'{}' starts past 4 GiB, which FileEntry can't address", name)));
        }
        entries.push(FileEntry {
            name: format!("{}{}", root, name),
            offset: offset as u32, // absolute
            original_size: decompress_size,
            raw_size: compress_size,
            checksum: seed, // decryption seed
            flags: FLAG_PACK_SEED_ENCRYPTED | if is_compressed != 0 { crate::common::FLAG_COMPRESSED } else { 0 },
            key: [0u8; 16],
        });
    }
    
    Ok(entries)
}

pub fn run_extract_logue(input_path: &str, output_dir: &str) -> Result<(), Error> {
    info!("[PACK_LOGUE] Starting extraction of Logue .pack: '{}'", input_path);
    let file = StdFile::open(input_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    
    let entries = run_list_logue_data(input_path)?;
    info!("[PACK_LOGUE] Index parsed ({} entries).", entries.len());

    entries.par_iter().try_for_each(|ent| {
        let start = ent.offset as usize;
        let end = start + ent.raw_size as usize;
        if end > mmap.len() {
             return Err(Error::msg(format!("Entry '{}' out of bounds", ent.name)));
        }
        let _ = &mmap[start..end];
        let final_data = extract_single_v1(&mmap, ent)?;
        write_file(output_dir, &ent.name, final_data)?;
        Ok::<(), Error>(())
    })?;

    Ok(())
}

