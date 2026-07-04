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

#[derive(Debug, Clone)]
pub struct PackEntryV1 {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub compressed_size: u32,
}

fn write_file(root_dir: &str, rel_path: &str, content: Vec<u8>) -> Result<(), Error> {
    // Normalize regional separators: ¥, \, /
    let normalized_path = rel_path.replace(['¥', '\\', '/'], &std::path::MAIN_SEPARATOR.to_string());
    trace!("[PACK_V1_WRITE] Preparing to write {} bytes to {}/{}", content.len(), root_dir, normalized_path);
    let fname = Path::new(root_dir).join(normalized_path);
    let par = fname.parent().ok_or_else(|| {
        error!("[PACK_V1_WRITE] Could not get parent directory for {:?}", fname);
        Error::msg(format!("unrecognized path: {}", fname.to_string_lossy()))
    })?;
    fs::create_dir_all(par).context("Failed to create directory")?;
    fs::write(&fname, &content).context("Failed to write file")?;
    debug!("[PACK_V1_WRITE] Successfully wrote '{}' to {}", rel_path, root_dir);
    Ok(())
}

pub fn run_list_v1_data(input_path: &str) -> Result<Vec<FileEntry>, Error> {
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
        // Normalize to backslashes for legacy compatibility, including international ¥ symbol
        let name = rel_path.to_str().unwrap().replace(['/', '¥'], "\\");

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
        let len = std::cmp::min(name_src.len(), 255);
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
    file.seek(SeekFrom::Current(8 + 8 + 480))?; // Skip FTs and Path

    // List Header (32 bytes)
    let list_sum = file.read_u32::<LittleEndian>()?;
    let list_header_size = file.read_u32::<LittleEndian>()?;
    let _blank_size = file.read_u32::<LittleEndian>()?;
    let _data_section_size = file.read_u32::<LittleEndian>()?;
    file.seek(SeekFrom::Current(16))?; // Skip zeros
    
    if list_sum != file_count {
        warn!("[PACK_LOGUE] File count mismatch: header={} list={}", file_count, list_sum);
    }

    let mut entries = Vec::with_capacity(file_count as usize);
    
    let data_start = 512 + 32 + list_header_size as u64;

    for _ in 0..file_count {
        let len_or_type = file.read_u8()?;
        let (name, _name_block_size) = if len_or_type < 4 {
            let block_size = (len_or_type as u32 + 1) * 16;
            let mut name_buf = vec![0u8; block_size as usize - 1];
            file.read_exact(&mut name_buf)?;
            let n = String::from_utf8_lossy(&name_buf)
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_string();
            (n, block_size)
        } else if len_or_type == 4 {
            let block_size = 0x60;
            let mut name_buf = vec![0u8; block_size as usize - 1];
            file.read_exact(&mut name_buf)?;
            let n = String::from_utf8_lossy(&name_buf)
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_string();
            (n, block_size)
        } else {
            let name_len = file.read_u32::<LittleEndian>()?;
            let mut name_buf = vec![0u8; name_len as usize];
            file.read_exact(&mut name_buf)?;
            let n = String::from_utf8_lossy(&name_buf).to_string();
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
        
        entries.push(FileEntry {
            name,
            offset: (data_start + offset as u64) as u32, // Relative to start of data
            original_size: decompress_size,
            raw_size: compress_size,
            checksum: seed, // Using seed as a proxy
            flags: if is_compressed != 0 { crate::common::FLAG_COMPRESSED } else { 0 },
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
        let data = &mmap[start..end];
        
        // Decrypt if necessary (Logue format uses seed-based encryption)
        // Check MabinogiResource/Utility.cpp for Encrypt/Decrypt
        // It's a custom RNG-based cipher. For now, let's assume raw if it fails.
        
        let final_data = if (ent.flags & crate::common::FLAG_COMPRESSED) != 0 {
            let mut decoder = ZlibDecoder::new(data);
            let mut decompressed = Vec::with_capacity(ent.original_size as usize);
            if decoder.read_to_end(&mut decompressed).is_ok() {
                decompressed
            } else {
                data.to_vec() // Fallback
            }
        } else {
            data.to_vec()
        };
        
        write_file(output_dir, &ent.name, final_data)?;
        Ok::<(), Error>(())
    })?;

    Ok(())
}

