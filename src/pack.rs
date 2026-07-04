use crate::common::{self, FileEntry};
use crate::encryption;
use crate::extract::ProgressFn;
use anyhow::{Context, Error};
use byte_slice_cast::AsByteSlice;
use byteorder::{LittleEndian, WriteBytesExt};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write, Cursor};
use std::path::Path;
use walkdir::WalkDir;
use log::{info, debug, trace};
use image_dds::dds_from_image;

fn get_rel_path(root_dir: &str, full_path: &str) -> Result<String, Error> {
    let rel_name = Path::new(full_path).strip_prefix(root_dir).expect(&format!(
        "strip path error, full:{}, root:{}",
        full_path, root_dir
    ));
    Ok(rel_name.to_string_lossy().into_owned())
}

fn need_compress(fname: &str, extra_ext_list: &[&str]) -> bool {
    [".txt", ".xml", ".dds", ".pmg", ".set", ".raw"]
        .iter()
        .chain(extra_ext_list.iter())
        .any(|ext| fname.ends_with(ext))
}

fn pack_file(
    root_dir: &str,
    disk_rel: &str,
    archive_name: &str,
    need_compress: bool,
    auto_dds: bool,
    _encrypt: bool,
    _skey: &str,
    _final_file_name: &str,
    _iv: u32,
) -> Result<(FileEntry, Vec<u8>), Error> {
    trace!("[PACK_FILE] Processing: {} (archive: {})", disk_rel, archive_name);
    let full_path = Path::new(root_dir).join(disk_rel);
    
    let mut data = vec![];
    let mut fp = File::open(&full_path)?;
    fp.read_to_end(&mut data)?;
    
    let mut final_archive_name = archive_name.to_owned();

    if auto_dds && disk_rel.to_lowercase().ends_with(".png") {
        debug!("[PACK_FILE] Auto-DDS: Converting {} to DXT5...", disk_rel);
        let img = image::open(&full_path).context("Failed to open PNG")?.to_rgba8();
        let dds = dds_from_image(&img, image_dds::ImageFormat::BC3RgbaUnormSrgb, image_dds::Quality::Fast, image_dds::Mipmaps::GeneratedAutomatic)
            .map_err(|e| Error::msg(format!("DDS conversion failed: {:?}", e)))?;

        let mut dds_buf = Cursor::new(Vec::new());
        dds.write(&mut dds_buf).map_err(|e| Error::msg(format!("DDS write failed: {:?}", e)))?;
        data = dds_buf.into_inner();

        final_archive_name = archive_name.trim_end_matches(".png").to_owned() + ".dds";
        debug!("[PACK_FILE] Auto-DDS: Renamed entry to {}", final_archive_name);
    }

    let original_size = data.len();
    let mut flags = 0;
    
    let raw_stm = if need_compress || final_archive_name.ends_with(".dds") {
        flags |= common::FLAG_COMPRESSED;
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&data)?;
        e.finish()?
    } else {
        data
    };

    let fkey = [0u8; 16];

    Ok((
        FileEntry {
            name: final_archive_name,
            checksum: 0,
            flags,
            offset: 0,
            original_size: original_size as u32,
            raw_size: raw_stm.len() as u32,
            key: fkey,
        },
        raw_stm,
    ))
}

fn write_header<T>(file_cnt: u32, key: &[u8], wr: &mut T, iv: u32) -> Result<(), Error>
where
    T: Write,
{
    const IT_VERSION: u8 = 2;
    let checksum = file_cnt + IT_VERSION as u32;
    let mut enc_stm = encryption::Snow2Encoder::new_iv(key, iv, wr);
    enc_stm.write_u32::<LittleEndian>(checksum)?;
    enc_stm.write_u8(IT_VERSION)?;
    enc_stm.write_u32::<LittleEndian>(file_cnt)?;
    enc_stm.finish()?; // Explicitly finish to pad and flush
    Ok(())
}

fn write_entries<T>(entries: &[FileEntry], key: &[u8], wr: &mut T, iv: u32) -> Result<(), Error>
where
    T: Write,
{
    let mut enc_stm = encryption::Snow2Encoder::new_iv(key, iv, wr);
    entries
        .iter()
        .map(|ent| -> Result<(), Error> {
            let u16_str: Vec<u16> = ent.name.chars().map(|c| c as u32 as u16).collect();
            enc_stm.write_u32::<LittleEndian>(u16_str.len() as u32)?;
            enc_stm.write_all(u16_str.as_byte_slice())?;
            enc_stm.write_u32::<LittleEndian>(ent.checksum)?;
            enc_stm.write_u32::<LittleEndian>(ent.flags)?;
            enc_stm.write_u32::<LittleEndian>(ent.offset)?;
            enc_stm.write_u32::<LittleEndian>(ent.original_size)?;
            enc_stm.write_u32::<LittleEndian>(ent.raw_size)?;
            enc_stm.write_all(&ent.key)?;
            Ok(())
        })
        .collect::<Result<(), Error>>()?;
    enc_stm.finish()?;
    Ok(())
}

fn ceil_1024(v: u64) -> u64 {
    (v + 1023) & 0u64.wrapping_sub(1024)
}

pub fn run_pack(
    input_folder: &str,
    output_fname: &str,
    skey: &str,
    compress_ext: Vec<&str>,
    auto_dds: bool,
    iv: u32,
    path_prefix: Option<&str>,
    progress_cb: Option<&ProgressFn>,
) -> Result<(), Error> {
    info!("[PACK] Starting pack operation from '{}' to '{}' (IV={}, Prefix={:?})", input_folder, output_fname, iv, path_prefix);

    let input_path = Path::new(input_folder);
    let input_root = if input_path.is_file() {
        input_path.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| input_folder.to_string())
    } else {
        input_folder.to_string()
    };

    let disk_names: Vec<String> = WalkDir::new(input_folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir())
        .map(|e| get_rel_path(&input_root, e.into_path().to_str().unwrap()))
        .collect::<Result<Vec<String>, Error>>()
        .context("traversing dir failed")?;

    let file_names: Vec<(String, String)> = if let Some(prefix) = path_prefix {
        debug!("[PACK] Prefixing all entries under '{}\\'...", prefix);
        disk_names.into_iter().map(|n| {
            let archive_name = format!("{}\\{}", prefix, n.replace("/", "\\"));
            (n, archive_name)
        }).collect()
    } else {
        disk_names.into_iter().map(|n| (n.clone(), n)).collect()
    };

    let entries_size = file_names
        .iter()
        .map(|(_, archive)| archive.chars().count() * 2 + 40)
        .sum::<usize>();

    let final_file_name = common::get_final_file_name(output_fname)?;
    let header_off = encryption::gen_header_offset(&final_file_name);
    let entries_off = encryption::gen_entries_offset(&final_file_name);
    let header_key = encryption::gen_header_key(&final_file_name, skey);
    let entries_key = encryption::gen_entries_key(&final_file_name, skey);

    let fs = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_fname)?;
    let mut stm = BufWriter::new(fs);

    let start_content_off = ceil_1024((header_off as u64) + (entries_off as u64) + (entries_size as u64));

    let total = file_names.len();
    
    let mut content_off = start_content_off;
    let mut entries = Vec::<FileEntry>::with_capacity(file_names.len());
    
    for (idx, (disk_name, archive_name)) in file_names.iter().enumerate() {
        if let Some(cb) = progress_cb {
            cb(idx, total, &format!("Packing: {}", archive_name));
        }
        let encrypt_this_file = output_fname.to_lowercase().ends_with(".it") && !skey.is_empty();
        let (mut ent, content) = pack_file(&input_root, disk_name, archive_name, need_compress(disk_name, &compress_ext), auto_dds, encrypt_this_file, skey, &final_file_name, iv)
            .context(format!("packing {} failed", archive_name))?;

        stm.seek(SeekFrom::Start(content_off))?;
        stm.write_all(&content)?;
        
        ent.offset = ((content_off - start_content_off) / 1024) as u32;
        let key_sum = ent.key.iter().fold(0u32, |s, v| s.wrapping_add(*v as u32));
        ent.checksum = ent.flags.wrapping_add(ent.offset).wrapping_add(ent.original_size).wrapping_add(ent.raw_size).wrapping_add(key_sum);
        
        content_off = ceil_1024(content_off + ent.raw_size as u64);
        entries.push(ent);
    }

    stm.seek(SeekFrom::Start((header_off + entries_off) as u64))?;
    write_entries(&entries, &entries_key, &mut stm, iv).context("writing entries failed")?;

    stm.seek(SeekFrom::Start(header_off as u64))?;
    write_header(entries.len() as u32, &header_key, &mut stm, iv).context("writing header failed")?;

    stm.seek(SeekFrom::End(0))?;
    let footer_val = header_off as u32;
    {
        let mut enc = encryption::Snow2Encoder::new_iv(&header_key, iv, &mut stm);
        enc.write_u32::<LittleEndian>(footer_val)?;
        enc.finish()?;
    }

    if let Some(cb) = progress_cb {
        cb(total, total, "Complete");
    }

    Ok(())
}
