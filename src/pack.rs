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
use rayon::prelude::*;
use std::collections::HashMap;

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackOptions {
    pub entries_key: Option<String>,
    pub template_archive: Option<String>,
    pub encrypt_files: Option<bool>,
    #[serde(default)]
    pub confirm_native_name: bool,
}

pub fn resolve_gui_pack_source(input: &str, prefix: Option<String>) -> (String, Option<String>) {
    if prefix.is_some() {
        return (input.to_string(), prefix);
    }
    let root = Path::new(input);
    if root.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.eq_ignore_ascii_case("data")) {
        return (input.to_string(), Some("data".to_string()));
    }
    let data = root.join("data");
    if data.is_dir() {
        return (data.to_string_lossy().into_owned(), Some("data".to_string()));
    }
    (input.to_string(), None)
}

pub fn validate_output_name(output: &str, confirm_native_name: bool) -> Result<(), Error> {
    let name = common::get_final_file_name(output)?;
    anyhow::ensure!(name.ends_with(".it"),
        "Invalid archive name: use the lowercase .it extension. Please resubmit.");
    let stem = &name[..name.len() - 3];
    anyhow::ensure!(stem.as_bytes().first().is_some_and(u8::is_ascii_lowercase),
        "Invalid archive name: the first character must be a lowercase ASCII letter; internal capitals are allowed. Please resubmit.");
    anyhow::ensure!(stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "Invalid archive name: use ASCII letters, numbers, underscores or hyphens only. Please resubmit.");
    anyhow::ensure!(stem.to_ascii_lowercase().as_str() > "data",
        "Invalid archive name: the name must sort alphabetically after 'data'. Please resubmit.");
    let native = stem.strip_prefix("data_").is_some_and(|suffix|
        suffix.len() == 5 && suffix.bytes().all(|b| b.is_ascii_digit()));
    anyhow::ensure!(!native || confirm_native_name,
        "Native archive name requires confirmation: data_#####.it may cause a load order error or conflict with game updates. Confirm explicitly (CLI: --confirm-native-name), or resubmit a custom name.");
    Ok(())
}

pub fn validate_pack_request(input: &str, output: &str, prefix: Option<&str>, confirm_native_name: bool) -> Result<(), Error> {
    validate_output_name(output, confirm_native_name)?;
    let root = Path::new(input);
    anyhow::ensure!(root.is_dir(),
        "Invalid source structure: select a folder containing a data folder, or wrap the source under data. Please resubmit.");
    let mut data_files = 0;
    let mut outside_files = 0;
    for item in WalkDir::new(root) {
        let item = item.context("Checking source structure failed")?;
        if !item.file_type().is_file() { continue; }
        let relative = item.path().strip_prefix(root)?.to_string_lossy().replace('\\', "/");
        let archive_name = match prefix {
            Some(prefix) => format!("{}/{}", prefix.replace('\\', "/").trim_end_matches('/'), relative),
            None => relative,
        };
        let mut parts = archive_name.split('/');
        if parts.next() == Some("data") && parts.clone().next().is_some()
            && parts.all(|part| !part.is_empty() && part != "." && part != "..") {
            data_files += 1;
        } else {
            outside_files += 1;
        }
    }
    anyhow::ensure!(data_files > 0,
        "Invalid source structure: the archive must contain a data folder with at least one file, including files in subfolders. Select its parent folder or use data wrapping, then resubmit.");
    anyhow::ensure!(outside_files == 0,
        "Invalid source structure: all packed files must be inside the data folder. Remove files outside data or correct wrapping, then resubmit.");
    Ok(())
}

struct PackProfile {
    header_salt: String,
    entries_salt: String,
    iv: u32,
    mode: encryption::Snow2Mode,
    version: u8,
    header_offset: Option<u64>,
    entries_offset: Option<u64>,
    derivation_name: Option<String>,
    entries: HashMap<String, FileEntry>,
    default_flags: Option<u32>,
    encrypt_files: bool,
    pad_payloads: bool,
    pad_archive: bool,
    write_footer: bool,
    forward_slashes: bool,
}

fn normalized_name(name: &str) -> String {
    name.replace('/', "\\").to_ascii_lowercase()
}

impl PackProfile {
    fn load(skey: &str, iv: u32, options: &PackOptions) -> Result<Self, Error> {
        let mut profile = Self {
            header_salt: skey.to_string(),
            entries_salt: options.entries_key.as_deref().unwrap_or(skey).to_string(),
            iv,
            mode: encryption::Snow2Mode::Sub,
            version: 2,
            header_offset: None,
            entries_offset: None,
            derivation_name: None,
            entries: HashMap::new(),
            default_flags: None,
            encrypt_files: options.encrypt_files.unwrap_or(false),
            pad_payloads: false,
            pad_archive: false,
            write_footer: true,
            forward_slashes: false,
        };
        if let Some(template) = &options.template_archive {
            anyhow::ensure!(options.entries_key.is_none() && options.encrypt_files.is_none(),
                "Template settings cannot be combined with manual entries salt or file encryption");
            let mut salts = crate::load_salts();
            if !skey.is_empty() { salts.push(skey.to_string()); }
            let (entries, header_salt, entries_salt, actual_iv, header_off, mode, _) =
                crate::common_ext::run_list_with_key_search_data(template, None, &salts, None)
                    .context("Reading packing template failed")?;
            anyhow::ensure!(header_salt != "UNENCRYPTED", "Packing template must be a modern .it archive");
            let template_name = common::get_final_file_name(template)?;
            let mut reader = File::open(template)?;
            let mut layout = None;
            for name in [template_name.as_str(), "data.it", ""] {
                if let Ok((header, _, _, entries_off)) = common::read_meta_layout_two_key(
                    name, &header_salt, &entries_salt, &mut reader, header_off, actual_iv, mode,
                ) {
                    layout = Some((header.version, entries_off, name.to_string()));
                    break;
                }
            }
            let (version, entries_off, name) = layout.context("Could not determine template layout")?;
            let length = reader.metadata()?.len();
            reader.seek(SeekFrom::End(-4))?;
            let mut footer = [0; 4];
            reader.read_exact(&mut footer)?;
            encryption::snow2_decrypt_mode(&encryption::gen_header_key(&name, &header_salt),
                actual_iv, mode, &mut footer);
            profile.write_footer = u32::from_le_bytes(footer) as u64 == header_off;
            profile.pad_archive = !profile.write_footer && length % 1024 == 0;
            let encrypted: Vec<_> = entries.iter().filter(|e|
                e.flags & (common::FLAG_ALL_ENCRYPTED | common::FLAG_HEAD_ENCRYPTED) != 0).collect();
            profile.pad_payloads = !encrypted.is_empty() && encrypted.iter().all(|e| e.raw_size % 4 == 0);
            profile.forward_slashes = entries.iter().any(|e| e.name.contains('/'))
                && entries.iter().all(|e| !e.name.contains('\\'));
            profile.header_salt = header_salt;
            profile.entries_salt = entries_salt;
            profile.iv = actual_iv;
            profile.mode = mode;
            profile.version = version;
            if header_off != encryption::gen_header_offset(&name) as u64 {
                profile.header_offset = Some(header_off);
            }
            if entries_off != header_off + encryption::gen_entries_offset(&name) as u64 {
                profile.entries_offset = Some(entries_off.checked_sub(header_off)
                    .context("Template entries precede the header, which is not supported for packing")?);
            }
            if name != template_name { profile.derivation_name = Some(name); }
            let mut counts = HashMap::new();
            for entry in &entries { *counts.entry(entry.flags).or_insert(0usize) += 1; }
            profile.default_flags = counts.into_iter().max_by_key(|(flags, count)| (*count, *flags)).map(|(flags, _)| flags);
            profile.entries = entries.into_iter().map(|e| (normalized_name(&e.name), e)).collect();
        }
        Ok(profile)
    }
}

fn get_rel_path(root_dir: &str, full_path: &str) -> Result<String, Error> {
    let rel_name = Path::new(full_path).strip_prefix(root_dir).expect(&format!(
        "strip path error, full:{}, root:{}",
        full_path, root_dir
    ));
    Ok(rel_name.to_string_lossy().into_owned())
}

fn need_compress(fname: &str, extra_ext_list: &[&str]) -> bool {
    let fname = fname.to_lowercase();
    [".txt", ".xml", ".dds", ".pmg", ".set", ".raw"]
        .iter()
        .chain(extra_ext_list.iter())
        .any(|ext| fname.ends_with(&ext.to_lowercase()))
}

fn pack_file(
    root_dir: &str,
    disk_rel: &str,
    archive_name: &str,
    need_compress: bool,
    auto_dds: bool,
    profile: &PackProfile,
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
    if profile.forward_slashes { final_archive_name = final_archive_name.replace('\\', "/"); }
    let source_entry = profile.entries.get(&normalized_name(&final_archive_name));
    if let Some(entry) = source_entry { final_archive_name = entry.name.clone(); }
    let flags = source_entry.map(|e| e.flags).or(profile.default_flags).unwrap_or_else(|| {
        let mut flags = 0;
        if need_compress || final_archive_name.ends_with(".dds") { flags |= common::FLAG_COMPRESSED; }
        if profile.encrypt_files { flags |= common::FLAG_ALL_ENCRYPTED; }
        flags
    });
    
    let mut raw_stm = if flags & common::FLAG_COMPRESSED != 0 {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&data)?;
        e.finish()?
    } else {
        data
    };

    let fkey = source_entry.map(|e| e.key).unwrap_or_else(|| {
        if flags & (common::FLAG_ALL_ENCRYPTED | common::FLAG_HEAD_ENCRYPTED) != 0 {
            md5::compute(&raw_stm).0
        } else {
            [0u8; 16]
        }
    });
    let content_key = encryption::gen_file_key(&final_archive_name, &fkey);
    if profile.pad_payloads && flags & (common::FLAG_ALL_ENCRYPTED | common::FLAG_HEAD_ENCRYPTED) != 0 {
        raw_stm.resize((raw_stm.len() + 3) & !3, 0);
    }
    // Extraction applies full encryption and head encryption in this order.
    if flags & common::FLAG_HEAD_ENCRYPTED != 0 {
        let len = raw_stm.len().min(1024);
        encryption::snow2_encrypt_mode(&content_key, profile.iv, profile.mode, &mut raw_stm[..len]);
    }
    if flags & common::FLAG_ALL_ENCRYPTED != 0 {
        encryption::snow2_encrypt_mode(&content_key, profile.iv, profile.mode, &mut raw_stm);
    }

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

fn write_header<T>(file_cnt: u32, key: &[u8], wr: &mut T, profile: &PackProfile) -> Result<(), Error>
where
    T: Write,
{
    let checksum = file_cnt.wrapping_add(profile.version as u32);
    let mut enc_stm = encryption::Snow2Encoder::new_iv_mode(key, profile.iv, profile.mode, wr);
    enc_stm.write_u32::<LittleEndian>(checksum)?;
    enc_stm.write_u8(profile.version)?;
    enc_stm.write_u32::<LittleEndian>(file_cnt)?;
    enc_stm.finish()?; // Explicitly finish to pad and flush
    Ok(())
}

fn write_entries<T>(entries: &[FileEntry], key: &[u8], wr: &mut T, profile: &PackProfile) -> Result<(), Error>
where
    T: Write,
{
    let mut enc_stm = encryption::Snow2Encoder::new_iv_mode(key, profile.iv, profile.mode, wr);
    entries
        .iter()
        .map(|ent| -> Result<(), Error> {
            let u16_str: Vec<u16> = ent.name.encode_utf16().collect();
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
    run_pack_with_options(input_folder, output_fname, skey, compress_ext, auto_dds, iv, path_prefix, &PackOptions::default(), progress_cb)
}

pub fn run_pack_with_options(
    input_folder: &str,
    output_fname: &str,
    skey: &str,
    compress_ext: Vec<&str>,
    auto_dds: bool,
    iv: u32,
    path_prefix: Option<&str>,
    options: &PackOptions,
    progress_cb: Option<&ProgressFn>,
) -> Result<(), Error> {
    if let Some(template) = &options.template_archive {
        let template_path = std::fs::canonicalize(template)?;
        if Path::new(output_fname).exists() {
            anyhow::ensure!(std::fs::canonicalize(output_fname)? != template_path,
                "Output must not overwrite the original packing template");
        }
    }
    let profile = PackProfile::load(skey, iv, options)?;
    info!("[PACK] Starting pack operation from '{}' to '{}' (IV={}, Prefix={:?})", input_folder, output_fname, iv, path_prefix);

    let input_path = Path::new(input_folder);
    let input_root = if input_path.is_file() {
        input_path.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| input_folder.to_string())
    } else {
        input_folder.to_string()
    };

    let disk_names: Vec<String> = WalkDir::new(input_folder)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .context("traversing dir failed")?
        .into_iter()
        .filter(|e| !e.file_type().is_dir())
        .map(|e| get_rel_path(&input_root, e.into_path().to_str().unwrap()))
        .collect::<Result<Vec<String>, Error>>()
        .context("traversing dir failed")?;
    anyhow::ensure!(!disk_names.is_empty(), "Source contains no files to pack");

    let file_names: Vec<(String, String)> = if let Some(prefix) = path_prefix {
        debug!("[PACK] Prefixing all entries under '{}\\'...", prefix);
        disk_names.into_iter().map(|n| {
            let archive_name = format!("{}\\{}", prefix, n.replace("/", "\\"));
            (n, archive_name)
        }).collect()
    } else {
        disk_names.into_iter().map(|n| {
            let archive_name = n.replace('/', "\\");
            (n, archive_name)
        }).collect()
    };

    for (_, archive_name) in &file_names {
        common::validate_entry_path(archive_name).context("cannot pack this file")?;
    }

    let entries_size = file_names
        .iter()
        .map(|(disk, archive)| {
            let name = if auto_dds && disk.to_lowercase().ends_with(".png") {
                archive.trim_end_matches(".png").to_string() + ".dds"
            } else { archive.clone() };
            let name = profile.entries.get(&normalized_name(&name)).map(|e| e.name.as_str()).unwrap_or(&name);
            name.encode_utf16().count() * 2 + 40
        })
        .sum::<usize>();

    let final_file_name = common::get_final_file_name(output_fname)?;
    let derivation_name = profile.derivation_name.as_deref().unwrap_or(&final_file_name);
    let header_off = profile.header_offset.unwrap_or(encryption::gen_header_offset(derivation_name) as u64);
    let entries_off = profile.entries_offset.unwrap_or(encryption::gen_entries_offset(derivation_name) as u64);
    let header_key = encryption::gen_header_key(derivation_name, &profile.header_salt);
    let entries_key = encryption::gen_entries_key(derivation_name, &profile.entries_salt);
    anyhow::ensure!(entries_off >= 9, "Template entries overlap the header");
    info!("[PACK] Header salt='{}', Entries salt='{}', IV={}, Mode={:?}, Template={:?}",
        profile.header_salt, profile.entries_salt, profile.iv, profile.mode, options.template_archive);

    let fs = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_fname)?;
    let mut stm = BufWriter::new(fs);

    let start_content_off = ceil_1024(header_off + entries_off + ((entries_size as u64 + 3) & !3));
    stm.get_ref().set_len(start_content_off)?;

    let total = file_names.len();

    // Compress files in parallel chunks (bounds peak RAM to ~chunk_size * largest_file).
    // Writing to the archive must remain serial because content_off offsets chain.
    let chunk_size = rayon::current_num_threads().max(1) * 2;
    let mut content_off = start_content_off;
    let mut entries = Vec::<FileEntry>::with_capacity(file_names.len());
    let mut global_idx = 0usize;

    for chunk in file_names.chunks(chunk_size) {
        let chunk_base = global_idx;
        let chunk_results: Vec<Result<(FileEntry, Vec<u8>), Error>> = chunk.par_iter()
            .enumerate()
            .map(|(ci, (disk_name, archive_name))| {
                if let Some(cb) = progress_cb {
                    cb(chunk_base + ci, total, &format!("Packing: {}", archive_name));
                }
                pack_file(&input_root, disk_name, archive_name,
                    need_compress(disk_name, &compress_ext),
                    auto_dds, &profile)
                    .context(format!("packing {} failed", archive_name))
            })
            .collect();

        for result in chunk_results {
            let (mut ent, content) = result?;
            stm.seek(SeekFrom::Start(content_off))?;
            stm.write_all(&content)?;
            ent.offset = ((content_off - start_content_off) / 1024) as u32;
            let key_sum = ent.key.iter().fold(0u32, |s, v| s.wrapping_add(*v as u32));
            ent.checksum = ent.flags.wrapping_add(ent.offset).wrapping_add(ent.original_size)
                .wrapping_add(ent.raw_size).wrapping_add(key_sum);
            content_off = ceil_1024(content_off + ent.raw_size as u64);
            entries.push(ent);
        }
        global_idx += chunk.len();
    }

    stm.seek(SeekFrom::Start(header_off as u64))?;
    write_header(entries.len() as u32, &header_key, &mut stm, &profile).context("writing header failed")?;

    stm.seek(SeekFrom::Start(header_off + entries_off))?;
    write_entries(&entries, &entries_key, &mut stm, &profile).context("writing entries failed")?;

    if profile.pad_archive {
        stm.flush().context("Flushing archive before padding failed")?;
        let length = stm.get_ref().metadata()?.len();
        stm.get_ref().set_len(ceil_1024(length))?;
    }
    if profile.write_footer {
        stm.seek(SeekFrom::End(0))?;
        let footer_val = header_off as u32;
        let mut enc = encryption::Snow2Encoder::new_iv_mode(&header_key, profile.iv, profile.mode, &mut stm);
        enc.write_u32::<LittleEndian>(footer_val)?;
        enc.finish()?;
    }

    stm.flush().context("Flushing packed archive failed")?;
    if let Some(cb) = progress_cb {
        cb(total, total, "Complete");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_suffixes_are_case_insensitive() {
        assert!(need_compress("CONFIG.XML", &[]));
        assert!(need_compress("script.LUA", &[".lua"]));
        assert!(!need_compress("image.PNG", &[]));
    }

    #[test]
    fn run_pack_rejects_invalid_entry_names() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mabi_pack_badname_{}_{}",
            std::process::id(),
            unique
        ));
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("file.txt"), b"x").unwrap();
        let output = dir.join("out.it");
        let error = run_pack(
            src.to_str().unwrap(), output.to_str().unwrap(), "salt", vec![], false, 0,
            Some("data|bad"), None,
        )
        .unwrap_err();
        assert!(
            format!("{:#}", error).contains("entry path"),
            "{:#}",
            error
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
