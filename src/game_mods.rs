//! Puts installed mods into the game: builds `appdata\package\uotiara_00001.it`
//! from the loose files the uotiara installer left in `appdata\data` (mapped as
//! UOTiaraPack.bat maps them), then every installed mod archive on top, in order.
//! The new archive is listed before it replaces the old one, and the first
//! replacement keeps the previous archive as `uotiara_00001.it.bak`.
//!
//! Entries are copied between archives as stored (compressed and encrypted), so
//! a merge reads and writes each payload once. Only loose files and entries that
//! move to data\local are compressed again. The packed loose files are cached in
//! `mods\.cache` until a loose file changes.

use crate::common::{self, FileEntry, FLAG_ALL_ENCRYPTED, FLAG_COMPRESSED, FLAG_HEAD_ENCRYPTED};
use crate::encryption::Snow2Mode;
use anyhow::{Context, Error};
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

pub const ARCHIVE: &str = "uotiara_00001.it";
const HEADER_SALT: &str = "@6QeTuOaDgJlZcBm#9";
const ENTRIES_SALT: &str = "})wWb4?-sVGHNoPKpc";
/// Extensions UOTiaraPack.bat compresses (the pack defaults plus `-f .jpg`).
const COMPRESS_EXT: [&str; 7] = [".txt", ".xml", ".dds", ".pmg", ".set", ".raw", ".jpg"];

#[derive(serde::Serialize, Debug)]
pub struct ApplyReport {
    pub archive: String,
    pub mods: usize,
    pub files: usize,
    /// Mod archives that could not be read, with the reason.
    pub skipped: Vec<String>,
}

/// The `.it` and `.pack` files under `mods_root\web` (by file name, so MOD id
/// order) and then `mods_root\community` (all account folders).
pub fn installed_archives(mods_root: &Path) -> Vec<PathBuf> {
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut items: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        items.sort();
        for p in items {
            if p.is_dir() {
                if !p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) { collect(&p, out); }
            } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("it") || e.eq_ignore_ascii_case("pack")) {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    collect(&mods_root.join("web"), &mut out);
    collect(&mods_root.join("community"), &mut out);
    out
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut items: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    items.sort();
    for p in items {
        if p.is_dir() { walk_files(&p, out) } else { out.push(p) }
    }
}

fn set_readonly(path: &Path, on: bool) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(on);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// Held while mod files are written, removed or merged, so an install never
/// rewrites a file the merge has open.
pub fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The game reads code and xml from data\local (as UOTiaraPack.bat maps them).
fn game_name(name: &str) -> String {
    let name = name.replace('/', "\\");
    let lower = name.to_ascii_lowercase();
    for d in ["code", "xml"] {
        let prefix = format!("data\\{}\\", d);
        if lower.starts_with(&prefix) {
            return format!("data\\local\\{}\\{}", d, &name[prefix.len()..]);
        }
    }
    name
}

/// The loose uotiara files with their archive names, mapped as UOTiaraPack.bat does.
fn loose_files(data: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut add = |dir: &Path, prefix: &str| {
        let mut files = Vec::new();
        walk_files(dir, &mut files);
        for f in files {
            if let Ok(rel) = f.strip_prefix(dir) {
                out.push((format!("{}\\{}", prefix, rel.to_string_lossy().replace('/', "\\")), f));
            }
        }
    };
    add(&data.join("code"), "data\\local\\code");
    add(&data.join("xml"), "data\\local\\xml");
    for d in ["db", "gfx", "locale", "material", "sound"] {
        add(&data.join(d), &format!("data\\{}", d));
    }
    let features = data.join("features.xml.compiled");
    if features.is_file() { out.push(("data\\features.xml.compiled".to_string(), features)); }
    out
}

/// An entry as stored: compressed, unencrypted, ready for the archive.
fn encode(name: String, data: Vec<u8>) -> Result<(FileEntry, Vec<u8>), Error> {
    let lower = name.to_ascii_lowercase();
    let compress = COMPRESS_EXT.iter().any(|e| lower.ends_with(e));
    let original_size = data.len() as u32;
    let raw = if compress {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&data)?;
        e.finish()?
    } else { data };
    Ok((FileEntry {
        name, checksum: 0, flags: if compress { FLAG_COMPRESSED } else { 0 }, offset: 0,
        original_size, raw_size: raw.len() as u32, key: [0; 16],
    }, raw))
}

/// One open `.it` archive.
struct Source {
    mmap: Mmap,
    entries: Vec<FileEntry>,
    content_off: u64,
    iv: u32,
    mode: Snow2Mode,
}

/// Open a `.it` archive, trying the uotiara salts and the name website packages
/// were packed under (the header offset comes from the name) first.
fn open_it(path: &Path, salts: &[String]) -> Result<Source, Error> {
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let own = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut names = vec![ARCHIVE.to_string()];
    for n in [own, "data.it".into(), String::new()] { if !names.contains(&n) { names.push(n); } }
    let mut keys = vec![HEADER_SALT.to_string(), ENTRIES_SALT.to_string()];
    for s in salts { if !keys.contains(s) { keys.push(s.clone()); } }
    for name in &names {
        for hs in &keys {
            let Ok(Some((_, h_off, iv, mode))) = common::find_header_only(&mut Cursor::new(&mmap[..]), name, hs) else { continue };
            for es in std::iter::once(ENTRIES_SALT).chain(keys.iter().map(|s| s.as_str())) {
                if let Ok((_, entries, content_off)) = common::read_meta_iv_mode_two_key(name, hs, es, &mut Cursor::new(&mmap[..]), h_off, iv, mode) {
                    return Ok(Source { mmap, entries, content_off, iv, mode });
                }
            }
        }
    }
    anyhow::bail!("no known salt opens this archive")
}

impl Source {
    /// The entry as stored for the merged archive under `name`. A stored
    /// payload is reused when its encryption still matches; otherwise the file
    /// is decoded and encoded again.
    fn take(&self, ent: &FileEntry, name: String) -> Result<(FileEntry, Vec<u8>), Error> {
        if !self.reencodes(ent, &name) {
            let raw = self.stored(ent)?.to_vec();
            return Ok((FileEntry { name, offset: 0, checksum: 0, ..ent.clone() }, raw));
        }
        let data = crate::extract::extract_single_file_to_memory(&self.mmap, self.content_off, ent, self.iv, self.mode)?;
        encode(name, data)
    }

    /// An encrypted payload must be decoded when its name (part of the file
    /// key) or its cipher settings differ from the merged archive's.
    fn reencodes(&self, ent: &FileEntry, name: &str) -> bool {
        let encrypted = ent.flags & (FLAG_ALL_ENCRYPTED | FLAG_HEAD_ENCRYPTED) != 0;
        let same_cipher = self.iv == 0 && matches!(self.mode, Snow2Mode::Sub);
        encrypted && (name != ent.name || !same_cipher)
    }

    fn stored(&self, ent: &FileEntry) -> Result<&[u8], Error> {
        if ent.raw_size == 0 { return Ok(&[]); }
        let start = self.content_off + ent.offset as u64 * 1024;
        let end = start + ent.raw_size as u64;
        anyhow::ensure!(end <= self.mmap.len() as u64, "{} extends past the archive end", ent.name);
        Ok(&self.mmap[start as usize..end as usize])
    }

    /// Decode a stored payload to prove it reads back, so a corrupt mod is
    /// skipped and never copied into the game archive.
    fn check(&self, ent: &FileEntry) -> Result<(), Error> {
        let data = crate::extract::extract_single_file_to_memory(&self.mmap, self.content_off, ent, self.iv, self.mode)
            .with_context(|| format!("{} does not decode", ent.name))?;
        anyhow::ensure!(data.len() == ent.original_size as usize,
            "{} decodes to {} bytes, expected {}", ent.name, data.len(), ent.original_size);
        Ok(())
    }
}

/// Files in merge order, by lowercase archive name: a later source for the
/// same name replaces the earlier one. Each value is (input, index, name).
#[derive(Default)]
struct Merge(BTreeMap<String, (usize, usize, String)>);

/// A source the merge reads from: an open archive, or loose files on disk.
enum Input { Archive(Source), Files(Vec<PathBuf>) }

impl Merge {
    /// Checks every entry first, so one bad mod is skipped and the others install.
    /// With `decode`, stored payloads that are copied as is are decoded too.
    fn add_archive(&mut self, inputs: &mut Vec<Input>, source: Source, decode: bool) -> Result<(), Error> {
        let names = source.entries.par_iter().map(|ent| {
            let name = game_name(&ent.name);
            common::validate_entry_path(&name)?;
            if source.reencodes(ent, &name) {
                source.take(ent, name.clone())?;
            } else {
                source.stored(ent)?;
                if decode { source.check(ent)?; }
            }
            Ok(name)
        }).collect::<Result<Vec<_>, Error>>()?;
        let src = inputs.len();
        for (i, name) in names.into_iter().enumerate() {
            self.0.insert(name.to_ascii_lowercase(), (src, i, name));
        }
        inputs.push(Input::Archive(source));
        Ok(())
    }

    fn add_files(&mut self, inputs: &mut Vec<Input>, files: Vec<(String, PathBuf)>) -> Result<(), Error> {
        for (name, _) in &files { common::validate_entry_path(name)?; }
        let src = inputs.len();
        let mut paths = Vec::with_capacity(files.len());
        for (i, (name, path)) in files.into_iter().enumerate() {
            self.0.insert(name.to_ascii_lowercase(), (src, i, name));
            paths.push(path);
        }
        inputs.push(Input::Files(paths));
        Ok(())
    }

    /// Encode the merged files (in parallel) and write the archive.
    fn write(self, inputs: &[Input], out: &Path) -> Result<usize, Error> {
        let items = self.0.into_values().collect::<Vec<_>>().into_par_iter()
            .map(|(src, i, name)| match &inputs[src] {
                Input::Archive(source) => source.take(&source.entries[i], name.clone()),
                Input::Files(paths) => std::fs::read(&paths[i]).map_err(Error::from).and_then(|data| encode(name.clone(), data)),
            }.with_context(|| format!("pack {}", name)))
            .collect::<Result<Vec<_>, Error>>()?;
        let count = items.len();
        crate::pack::write_raw_archive(&out.to_string_lossy(), HEADER_SALT, ENTRIES_SALT, 0, items)?;
        Ok(count)
    }
}
/// A cheap fingerprint of the loose files: names, sizes and change times.
fn loose_signature(files: &[(String, PathBuf)]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ARCHIVE.hash(&mut h);
    for (name, path) in files {
        name.hash(&mut h);
        if let Ok(m) = std::fs::metadata(path) {
            m.len().hash(&mut h);
            m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).hash(&mut h);
        }
    }
    format!("{:016x}", h.finish())
}

/// A mod file's path, size and change time: a mod that decoded once under this
/// key is not decoded again until the file changes.
fn mod_key(path: &Path) -> Option<String> {
    let m = std::fs::metadata(path).ok()?;
    let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
    Some(format!("{}|{}|{}", path.display(), m.len(), t))
}

/// The `mod_key`s of mods that decoded on an earlier apply or startup check.
fn read_decoded(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path).map(|s| s.lines().map(String::from).collect()).unwrap_or_default()
}

/// Replace the list by rename: the CLI and the GUI may write it at once. A
/// lost write only means those mods are decoded again.
fn write_decoded(path: &Path, keys: Vec<String>) {
    let Some(dir) = path.parent() else { return };
    if std::fs::create_dir_all(dir).is_err() { return; }
    let tmp = dir.join(format!("decoded-{}.tmp", std::process::id()));
    if std::fs::write(&tmp, keys.join("\n")).is_err() || std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// The packed loose files, rebuilt only when a loose file changed.
fn loose_archive(files: Vec<(String, PathBuf)>, cache: &Path) -> Result<PathBuf, Error> {
    std::fs::create_dir_all(cache)?;
    let archive = cache.join(ARCHIVE);
    let sig_path = cache.join("loose.sig");
    let sig = loose_signature(&files);
    if archive.is_file() && std::fs::read_to_string(&sig_path).is_ok_and(|s| s.trim() == sig) {
        return Ok(archive);
    }
    // The CLI and the GUI may rebuild at once: each writes its own file and
    // renames it in, so the cache is always one complete archive.
    let mut merge = Merge::default();
    let mut inputs = Vec::new();
    let check = files.clone();
    merge.add_files(&mut inputs, files)?;
    let tmp_dir = cache.join(format!("build-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let built = tmp_dir.join(ARCHIVE);
    let written = merge.write(&inputs, &built).and_then(|_| {
        let _ = std::fs::remove_file(&sig_path);
        std::fs::rename(&built, &archive)?;
        // A loose file that changed during the build leaves no signature, so
        // the next apply builds again.
        if loose_signature(&check) == sig { std::fs::write(&sig_path, &sig)?; }
        Ok(())
    });
    let _ = std::fs::remove_dir_all(&tmp_dir);
    written?;
    Ok(archive)
}

/// A `.pack` mod, extracted to a temporary folder (its entries are relative to data\).
fn pack_files(archive: &Path, tmp: &Path) -> Result<Vec<(String, PathBuf)>, Error> {
    let data = tmp.join("data");
    std::fs::create_dir_all(&data)?;
    crate::extract::run_extract_with_key_search(&archive.to_string_lossy(), &data.to_string_lossy(), None, &[], vec![],
        None, false, false, false, None)?;
    let mut files = Vec::new();
    walk_files(&data, &mut files);
    Ok(files.into_iter().filter_map(|f| {
        let rel = f.strip_prefix(tmp).ok()?.to_string_lossy().replace('/', "\\");
        Some((game_name(&rel), f))
    }).collect())
}

/// Pack the loose uotiara files into the cache ahead of time (at startup), so
/// the first apply only copies stored entries. Returns the file count.
pub fn prepare(game_path: &Path, mods_root: &Path) -> Result<usize, Error> {
    let _guard = lock();
    let started = std::time::Instant::now();
    let appdata = crate::launcher::patch::GameRoots::resolve(game_path).appdata;
    let loose = loose_files(&appdata.join("data"));
    let count = loose.len();
    if count > 0 {
        loose_archive(loose, &mods_root.join(".cache"))?;
        log::info!("[MODS] loose uotiara files ready ({} files) in {:?}", count, started.elapsed());
    }
    // Decode new or changed .it mods now, so an apply only copies them.
    let decoded_path = mods_root.join(".cache").join("decoded.txt");
    let mut decoded = read_decoded(&decoded_path);
    let mut added = 0;
    for archive in installed_archives(mods_root) {
        if !archive.extension().is_some_and(|e| e.eq_ignore_ascii_case("it")) { continue; }
        let Some(key) = mod_key(&archive) else { continue };
        if decoded.contains(&key) { continue; }
        let ok = open_it(&archive, &[]).is_ok_and(|s| s.entries.par_iter().all(|e| s.check(e).is_ok()));
        if ok { decoded.insert(key); added += 1; }
    }
    if added > 0 {
        write_decoded(&decoded_path, decoded.into_iter().collect());
        log::info!("[MODS] {} mods decoded and ready in {:?}", added, started.elapsed());
    }
    Ok(count)
}
/// Build and install the merged archive. `game_path` is any path the patcher
/// accepts (install root, appdata, patchdata or Client.exe).
///
/// The base is the loose uotiara files in appdata\data. When that folder holds
/// none, the base is the archive from before mabi-patcher first replaced it
/// (`.bak`), or the current archive when there is no `.bak` yet, so the
/// uotiara content is never replaced by mods alone.
pub fn apply(game_path: &Path, mods_root: &Path, salts: &[String]) -> Result<ApplyReport, Error> {
    let _guard = lock();
    let started = std::time::Instant::now();
    let appdata = crate::launcher::patch::GameRoots::resolve(game_path).appdata;
    let package = appdata.join("package");
    anyhow::ensure!(package.is_dir(), "no package folder in {}", appdata.display());
    let dest = package.join(ARCHIVE);
    let backup = package.join(format!("{}.bak", ARCHIVE));

    // A per-process folder: the CLI and the GUI may run at the same time.
    let work = appdata.join(format!(".mabi-patcher-mods-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;
    let result = (|| {
        let mut merge = Merge::default();
        let mut inputs: Vec<Input> = Vec::new();
        let loose = loose_files(&appdata.join("data"));
        let base = if !loose.is_empty() {
            Some(loose_archive(loose, &mods_root.join(".cache"))?)
        } else if backup.is_file() { Some(backup.clone()) } else if dest.is_file() { Some(dest.clone()) } else { None };
        if let Some(base) = base {
            let source = open_it(&base, salts).with_context(|| format!("read the uotiara base {}", base.display()))?;
            merge.add_archive(&mut inputs, source, false)?;
        }
        log::info!("[MODS] base read in {:?}", started.elapsed());

        // Mods that decoded on an earlier apply, unchanged since.
        let decoded_path = mods_root.join(".cache").join("decoded.txt");
        let decoded = read_decoded(&decoded_path);
        let mut passed = Vec::new();
        let mut report = ApplyReport { archive: dest.to_string_lossy().to_string(), mods: 0, files: 0, skipped: vec![] };
        for (i, archive) in installed_archives(mods_root).into_iter().enumerate() {
            let name = archive.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let is_pack = archive.extension().is_some_and(|e| e.eq_ignore_ascii_case("pack"));
            let key = if is_pack { None } else { mod_key(&archive) };
            let opened = if is_pack {
                pack_files(&archive, &work.join(format!("pack{}", i))).and_then(|files| merge.add_files(&mut inputs, files))
            } else {
                open_it(&archive, salts).and_then(|source| {
                    // Read the key again once the file is mapped: a file replaced
                    // since the first read must be decoded.
                    let cached = key.as_ref().is_some_and(|k| decoded.contains(k)) && mod_key(&archive) == key;
                    merge.add_archive(&mut inputs, source, !cached)
                })
            };
            match opened {
                Ok(()) => { report.mods += 1; passed.extend(key); }
                Err(e) => report.skipped.push(format!("{}: {}", name, e)),
            }
        }
        write_decoded(&decoded_path, passed);
        anyhow::ensure!(!merge.0.is_empty(), "nothing to install: no uotiara files in {} and no readable mods", appdata.join("data").display());
        log::info!("[MODS] {} mods read in {:?}", report.mods, started.elapsed());

        // Write under the final name (the header offset depends on it), check
        // the result opens, then swap it in.
        let out_dir = work.join("out");
        std::fs::create_dir_all(&out_dir)?;
        let built = out_dir.join(ARCHIVE);
        report.files = merge.write(&inputs, &built)?;
        drop(inputs);
        log::info!("[MODS] written in {:?}", started.elapsed());
        let (entries, ..) = crate::common_ext::run_list_with_key_search_data(
            &built.to_string_lossy(), Some(HEADER_SALT.to_string()), salts, None)
            .context("the built archive does not open; the game copy was not changed")?;
        anyhow::ensure!(entries.len() == report.files,
            "the built archive lists {} files, expected {}; the game copy was not changed", entries.len(), report.files);

        if dest.exists() && !backup.exists() {
            std::fs::copy(&dest, &backup).context("back up the current archive")?;
        }
        // Same volume: rename swaps the whole file, so a failure leaves the old one.
        let had = dest.exists();
        set_readonly(&dest, false);
        let swapped = std::fs::rename(&built, &dest)
            .with_context(|| format!("replace {} (is the game running?)", dest.display()));
        if swapped.is_ok() || had { set_readonly(&dest, true); }
        swapped?;
        log::info!("[MODS] installed in {:?}", started.elapsed());
        Ok(report)
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_and_xml_move_to_local() {
        assert_eq!(game_name("data/code/a.txt"), "data\\local\\code\\a.txt");
        assert_eq!(game_name("data\\XML\\B.xml"), "data\\local\\xml\\B.xml");
        assert_eq!(game_name("data\\local\\xml\\c.xml"), "data\\local\\xml\\c.xml");
        assert_eq!(game_name("data\\gfx\\d.dds"), "data\\gfx\\d.dds");
    }

    #[test]
    fn corrupt_stored_payload_is_rejected() {
        let dir = std::env::temp_dir().join(format!("mabi-mods-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ARCHIVE);
        let item = encode("data\\gfx\\a.txt".into(), b"uotiara ".repeat(400)).unwrap();
        crate::pack::write_raw_archive(&path.to_string_lossy(), HEADER_SALT, ENTRIES_SALT, 0, vec![item]).unwrap();

        let good = open_it(&path, &[]).unwrap();
        good.check(&good.entries[0]).unwrap();
        let start = (good.content_off + good.entries[0].offset as u64 * 1024) as usize;
        drop(good);

        let mut bytes = std::fs::read(&path).unwrap();
        for b in &mut bytes[start + 4..start + 24] { *b ^= 0xA5; }
        std::fs::write(&path, &bytes).unwrap();
        let bad = open_it(&path, &[]).unwrap();
        assert!(bad.check(&bad.entries[0]).is_err());
        let mut merge = Merge::default();
        let mut inputs = Vec::new();
        let ent_check = merge.add_archive(&mut inputs, bad, true);
        assert!(ent_check.is_err() && merge.0.is_empty());
        drop(inputs);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
