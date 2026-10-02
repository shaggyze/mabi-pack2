// Nexon NXL manifest patcher (download + apply game updates).
//
// Ported from Rua's uNxlPatcher (https://github.com/shaggyze/Rua):
//   1. Remote manifest hash: branch endpoint (session) or the public CDN hash file.
//   2. GET http://download2.nexon.net/Game/nxl/games/10200/<hash> → zlib JSON manifest.
//   3. Diff against the install: missing file, size change, or a changed objects[]
//      list compared to the cached manifest of the installed version.
//   4. Download each changed file's parts (zlib) in parallel, concatenate in order,
//      write to a temp file and swap it in.
//   5. Only after every file succeeded: store the new hash and cache the manifest,
//      so an interrupted or partial update is picked up again on the next run.
//
// The CLI `update` command uses `patch::run_patcher` (branch-API manifest only,
// SHA1-checked parts, repair mode, cancel). This module is kept as a library
// patcher; note that its no-session fallback (the public CDN hash) is a stale
// 2014 manifest, so pass a session whenever you patch a real install.
//
// Install layout: manifest paths are relative to the folder holding Client.exe.
// The hash file is `patchdata/10200.manifest.hash`, found either inside that
// folder or next to it (official launcher layout); see `GameInstall::locate`.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use super::auth::{self, NexonSession};
use super::patch;

pub const PRODUCT_ID: u32 = 10200;

const CDN_BASE: &str = "http://download2.nexon.net/Game/nxl/games/10200/";
const PART_BASE: &str = "https://download2.nexon.net/Game/nxl/games/10200/10200/";
const USER_AGENT: &str = "NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0";

/// Default number of files patched at once (Rua's MAX_DL).
pub const DEFAULT_FILE_WORKERS: usize = 8;
/// Parts of one file fetched at once (Rua's MAX_PARTS).
const PARTS_PER_FILE: usize = 4;
/// Cap on simultaneous HTTP requests across all files (Rua's MAX_CONCURRENT_HTTP).
/// Opening 100+ connections makes the CDN throttle us.
const MAX_CONCURRENT_HTTP: usize = 16;
/// Attempts per part before the file is reported as failed.
const PART_ATTEMPTS: u32 = 4;

const TEMP_SUFFIX: &str = ".~nxlpatch";

// ── Install layout ────────────────────────────────────────────────────────────

/// Where the game lives on disk.
#[derive(Debug, Clone)]
pub struct GameInstall {
    /// Folder holding Client.exe; manifest paths are relative to it.
    pub root: PathBuf,
    /// Folder holding `10200.manifest.hash` and the cached manifest.
    pub patchdata: PathBuf,
}

impl GameInstall {
    /// Resolve an install from a path to Client.exe or to its folder.
    ///
    /// `patchdata/` is looked for inside that folder, then beside it (the
    /// official launcher keeps `appdata/` and `patchdata/` side by side). If
    /// neither exists, it will be created inside the game folder.
    pub fn locate(path: &Path) -> Result<Self> {
        let root = if path.is_file() {
            path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
        } else {
            path.to_path_buf()
        };
        if !root.is_dir() {
            return Err(anyhow!("Game folder not found: {}", root.display()));
        }
        let inside = root.join("patchdata");
        let beside = root.parent().map(|p| p.join("patchdata"));
        let patchdata = if inside.is_dir() {
            inside
        } else {
            match beside {
                Some(b) if b.is_dir() => b,
                _ => inside,
            }
        };
        Ok(Self { root, patchdata })
    }

    fn hash_file(&self) -> PathBuf {
        self.patchdata.join(format!("{}.manifest.hash", PRODUCT_ID))
    }

    /// Manifest hash of the installed version, if any.
    pub fn local_hash(&self) -> Option<String> {
        std::fs::read_to_string(self.hash_file())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Cached manifest of the installed version (raw CDN bytes at `patchdata/<hash>`).
    fn cached_manifest(&self) -> Option<Manifest> {
        let hash = self.local_hash()?;
        let raw = std::fs::read(self.patchdata.join(&hash)).ok()?;
        Manifest::parse(&hash, raw).ok()
    }

    /// Record `manifest` as the installed version.
    fn store(&self, manifest: &Manifest) -> Result<()> {
        std::fs::create_dir_all(&self.patchdata)
            .with_context(|| format!("create {}", self.patchdata.display()))?;
        std::fs::write(self.patchdata.join(&manifest.hash), &manifest.raw)
            .context("cache manifest")?;
        std::fs::write(self.hash_file(), &manifest.hash).context("write manifest hash")?;
        Ok(())
    }
}

// ── Manifest ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ManifestFile {
    /// Path relative to the game folder, `/`-separated.
    pub path: String,
    /// Decompressed file size.
    pub fsize: u64,
    /// CDN part hashes, in file order.
    pub parts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub hash: String,
    pub files: Vec<ManifestFile>,
    pub dirs: Vec<String>,
    /// Raw (compressed) bytes as served by the CDN; cached in patchdata.
    raw: Vec<u8>,
}

impl Manifest {
    /// Parse the compressed manifest the CDN serves.
    pub fn parse(hash: &str, raw: Vec<u8>) -> Result<Self> {
        let json = inflate(&raw).context("decompress manifest")?;
        let root: serde_json::Value = serde_json::from_slice(&json).context("parse manifest JSON")?;
        let entries = root["files"]
            .as_object()
            .ok_or_else(|| anyhow!("manifest has no 'files' object"))?;

        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (key, v) in entries {
            let path = match decode_filename(key) {
                Some(p) => p,
                None => continue,
            };
            if !is_safe_relative(&path) {
                log::warn!("Skipping unsafe manifest path: {}", path);
                continue;
            }
            let objects: Vec<String> = v["objects"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if objects.first().map(String::as_str) == Some("__DIR__") {
                dirs.push(path);
                continue;
            }
            if objects.is_empty() || !seen.insert(path.to_lowercase()) {
                continue;
            }
            files.push(ManifestFile {
                path,
                fsize: v["fsize"].as_u64().unwrap_or(0),
                parts: objects,
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self { hash: hash.to_string(), files, dirs, raw })
    }

    /// Total download-side size of the given files (decompressed).
    pub fn total_size(files: &[ManifestFile]) -> u64 {
        files.iter().map(|f| f.fsize).sum()
    }
}

/// Manifest keys are base64 of UTF-16LE text with a leading BOM.
pub fn decode_filename(key: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(key).ok()?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    let text = text.trim_start_matches('\u{feff}');
    // Entries can carry trailing NULs that make equal paths compare unequal.
    let text = text.trim_end_matches(|c: char| c.is_control() || c == ' ');
    if text.is_empty() {
        return None;
    }
    Some(text.replace('\\', "/"))
}

fn is_safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !p.as_os_str().is_empty()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
        && !path.contains(':')
}

/// zlib first; fall back to raw deflate after the 2-byte header (what the
/// GUI's reader does) in case the trailer is missing.
fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if flate2::read::ZlibDecoder::new(data).read_to_end(&mut out).is_ok() {
        return Ok(out);
    }
    if data.len() <= 2 {
        return Err(anyhow!("data too short"));
    }
    out.clear();
    flate2::read::DeflateDecoder::new(&data[2..]).read_to_end(&mut out)?;
    Ok(out)
}

// ── Remote ────────────────────────────────────────────────────────────────────

fn http_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .pool_max_idle_per_host(MAX_CONCURRENT_HTTP)
        .build()?)
}

fn get_bytes(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().with_context(|| format!("GET {}", url))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("HTTP {} fetching {}", status, url));
    }
    Ok(resp.bytes()?.to_vec())
}

/// Where the remote hash came from, and any session refresh that happened.
#[derive(Debug, Clone)]
pub struct RemoteHash {
    pub hash: String,
    /// Set when a 401 forced a session refresh: the new expiry in seconds.
    pub refreshed_expires_in: Option<i32>,
}

/// Latest manifest hash.
///
/// With a session this asks the branch endpoint (what the official launcher
/// does), refreshing the session once on 401. Without one, or if that fails,
/// it reads the public `10200.manifest.hash` on the CDN, which needs no login.
pub fn fetch_remote_hash(session: Option<&mut NexonSession>) -> Result<RemoteHash> {
    let client = http_client()?;
    let mut refreshed_expires_in = None;

    if let Some(session) = session {
        let branch = auth::with_session_retry(session, |s| {
            let info = patch::fetch_manifest_once(s)?;
            let body = get_bytes(&client, &info.manifest_url)?;
            Ok(String::from_utf8_lossy(&body).trim().to_string())
        });
        match branch {
            Ok((hash, refreshed)) if is_hash(&hash) => {
                return Ok(RemoteHash { hash, refreshed_expires_in: refreshed });
            }
            Ok((other, refreshed)) => {
                refreshed_expires_in = refreshed;
                log::warn!("Branch endpoint returned an unexpected hash '{}', using the CDN hash", other);
            }
            Err(e) => log::warn!("Branch endpoint failed ({}), using the CDN hash", e),
        }
    }

    let body = get_bytes(&client, &format!("{}{}.manifest.hash", CDN_BASE, PRODUCT_ID))?;
    let hash = String::from_utf8_lossy(&body).trim().to_string();
    if !is_hash(&hash) {
        return Err(anyhow!("CDN returned an invalid manifest hash: '{}'", hash));
    }
    Ok(RemoteHash { hash, refreshed_expires_in })
}

fn is_hash(s: &str) -> bool {
    s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Download and parse the manifest for `hash`.
pub fn fetch_manifest(hash: &str) -> Result<Manifest> {
    let raw = get_bytes(&http_client()?, &format!("{}{}", CDN_BASE, hash))?;
    Manifest::parse(hash, raw)
}

// ── Scan ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeReason {
    Missing,
    SizeChanged,
    ContentChanged,
    Forced,
}

impl std::fmt::Display for ChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChangeReason::Missing => "new",
            ChangeReason::SizeChanged => "size changed",
            ChangeReason::ContentChanged => "content changed",
            ChangeReason::Forced => "re-download",
        })
    }
}

#[derive(Debug, Clone)]
pub struct PendingFile {
    pub file: ManifestFile,
    pub reason: ChangeReason,
}

#[derive(Debug, Clone, Default)]
pub struct PatchOptions {
    /// Re-download every file regardless of local state.
    pub force_all: bool,
    /// Files patched at once (0 = default).
    pub workers: usize,
    /// Paths or `*`/`?` wildcards (case-insensitive) never touched, e.g. local mods.
    pub ignore: Vec<String>,
}

/// Files that need downloading to bring `install` to `manifest`.
pub fn scan(install: &GameInstall, manifest: &Manifest, opts: &PatchOptions) -> Vec<PendingFile> {
    use rayon::prelude::*;

    // Same-size content changes only show up as a different objects[] list
    // compared to the manifest of the installed version.
    let old: Option<HashMap<String, Vec<u8>>> = if opts.force_all {
        None
    } else {
        install.cached_manifest().map(|m| {
            m.files.iter().map(|f| (f.path.to_lowercase(), parts_fingerprint(&f.parts))).collect()
        })
    };

    manifest
        .files
        .par_iter()
        .filter(|f| !is_ignored(&f.path, &opts.ignore))
        .filter_map(|f| {
            let local = std::fs::metadata(install.root.join(&f.path)).ok().map(|m| m.len());
            let reason = match local {
                None => Some(ChangeReason::Missing),
                Some(len) if len != f.fsize => Some(ChangeReason::SizeChanged),
                _ if opts.force_all => Some(ChangeReason::Forced),
                _ => match &old {
                    Some(old) if old.get(&f.path.to_lowercase()) != Some(&parts_fingerprint(&f.parts)) => {
                        Some(ChangeReason::ContentChanged)
                    }
                    _ => None,
                },
            };
            reason.map(|reason| PendingFile { file: f.clone(), reason })
        })
        .collect()
}

fn parts_fingerprint(parts: &[String]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0u8]);
    }
    h.finalize().to_vec()
}

/// Case-insensitive match of `path` against exact paths or `*`/`?` wildcards.
/// `\` and `/` are interchangeable.
pub fn is_ignored(path: &str, patterns: &[String]) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_start_matches('/').to_lowercase();
    let path = norm(path);
    patterns.iter().map(|p| norm(p.trim())).filter(|p| !p.is_empty()).any(|p| wildcard_match(&p, &path))
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ── Download ──────────────────────────────────────────────────────────────────

/// Progress snapshot passed to the caller's callback.
#[derive(Debug, Clone)]
pub struct Progress {
    pub files_done: usize,
    pub files_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// File that just finished (or failed).
    pub current: String,
}

#[derive(Debug, Clone, Default)]
pub struct PatchReport {
    pub patched: usize,
    pub failed: Vec<(String, String)>,
    /// True if the install is now recorded as the manifest's version.
    pub hash_updated: bool,
}

/// Download and install `pending`. The new hash is recorded only when every
/// file succeeded; otherwise failed files are listed and retried next run.
pub fn apply(
    install: &GameInstall,
    manifest: &Manifest,
    pending: &[PendingFile],
    opts: &PatchOptions,
    progress: &(dyn Fn(&Progress) + Sync),
) -> Result<PatchReport> {
    apply_from(PART_BASE, install, manifest, pending, opts, progress)
}

fn apply_from(
    part_base: &str,
    install: &GameInstall,
    manifest: &Manifest,
    pending: &[PendingFile],
    opts: &PatchOptions,
    progress: &(dyn Fn(&Progress) + Sync),
) -> Result<PatchReport> {
    for d in &manifest.dirs {
        let _ = std::fs::create_dir_all(install.root.join(d));
    }

    let client = http_client()?;
    let http = Semaphore::new(MAX_CONCURRENT_HTTP);
    let workers = if opts.workers == 0 { DEFAULT_FILE_WORKERS } else { opts.workers }.clamp(1, 32);

    let next = AtomicUsize::new(0);
    let files_done = AtomicUsize::new(0);
    let bytes_done = AtomicU64::new(0);
    let bytes_total = pending.iter().map(|p| p.file.fsize).sum();
    let failed: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

    std::thread::scope(|s| {
        for _ in 0..workers.min(pending.len().max(1)) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(item) = pending.get(i) else { break };
                let result = patch_file(&client, &http, part_base, &install.root, &item.file);
                if let Err(e) = &result {
                    failed.lock().unwrap().push((item.file.path.clone(), format!("{:#}", e)));
                }
                let done = files_done.fetch_add(1, Ordering::SeqCst) + 1;
                let bytes = bytes_done.fetch_add(item.file.fsize, Ordering::SeqCst) + item.file.fsize;
                progress(&Progress {
                    files_done: done,
                    files_total: pending.len(),
                    bytes_done: bytes,
                    bytes_total,
                    current: item.file.path.clone(),
                });
            });
        }
    });

    let failed = failed.into_inner().unwrap();
    let mut report = PatchReport { patched: pending.len() - failed.len(), failed, hash_updated: false };
    if report.failed.is_empty() {
        install.store(manifest)?;
        report.hash_updated = true;
    }
    Ok(report)
}

/// Fetch all parts of one file (up to PARTS_PER_FILE at once), join them in
/// order into a temp file next to the target, then swap it in.
fn patch_file(
    client: &reqwest::blocking::Client,
    http: &Semaphore,
    part_base: &str,
    root: &Path,
    file: &ManifestFile,
) -> Result<()> {
    let dest = root.join(&file.path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temp = append_suffix(&dest, TEMP_SUFFIX);
    let part_path = |i: usize| append_suffix(&dest, &format!("{}.{}", TEMP_SUFFIX, i));

    let result = (|| -> Result<()> {
        let next = AtomicUsize::new(0);
        let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
        std::thread::scope(|s| {
            for _ in 0..PARTS_PER_FILE.min(file.parts.len()) {
                s.spawn(|| loop {
                    if first_err.lock().unwrap().is_some() {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(hash) = file.parts.get(i) else { break };
                    if let Err(e) = download_part(client, http, part_base, hash, &part_path(i)) {
                        first_err.lock().unwrap().get_or_insert(e.context(format!("part {}", i)));
                        break;
                    }
                });
            }
        });
        if let Some(e) = first_err.into_inner().unwrap() {
            return Err(e);
        }

        let mut out = BufWriter::with_capacity(1 << 20, File::create(&temp).context("create temp file")?);
        for i in 0..file.parts.len() {
            let mut part = File::open(part_path(i))?;
            std::io::copy(&mut part, &mut out)?;
        }
        out.flush()?;
        drop(out);

        let written = std::fs::metadata(&temp)?.len();
        if written != file.fsize {
            return Err(anyhow!("assembled size {} != manifest size {}", written, file.fsize));
        }
        if dest.exists() {
            std::fs::remove_file(&dest).with_context(|| format!("replace {}", dest.display()))?;
        }
        std::fs::rename(&temp, &dest).with_context(|| format!("move into {}", dest.display()))?;
        Ok(())
    })();

    for i in 0..file.parts.len() {
        let _ = std::fs::remove_file(part_path(i));
    }
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// GET one zlib part and stream-decompress it to `out`, retrying transient
/// failures with growing delay.
fn download_part(
    client: &reqwest::blocking::Client,
    http: &Semaphore,
    part_base: &str,
    hash: &str,
    out: &Path,
) -> Result<()> {
    if hash.len() < 2 || !hash.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(anyhow!("invalid part hash '{}'", hash));
    }
    let url = format!("{}{}/{}", part_base, &hash[..2], hash);
    let mut last_err = None;
    for attempt in 0..PART_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 << attempt));
        }
        let _permit = http.acquire();
        match fetch_part(client, &url, out) {
            Ok(()) => return Ok(()),
            Err(PartError::Fatal(e)) => return Err(e),
            Err(PartError::Retry(e)) => {
                log::debug!("{} (attempt {}/{}): {:#}", url, attempt + 1, PART_ATTEMPTS, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("download failed")))
}

enum PartError {
    Retry(anyhow::Error),
    Fatal(anyhow::Error),
}

fn fetch_part(client: &reqwest::blocking::Client, url: &str, out: &Path) -> std::result::Result<(), PartError> {
    let resp = client.get(url).send().map_err(|e| PartError::Retry(e.into()))?;
    let status = resp.status();
    if !status.is_success() {
        let e = anyhow!("HTTP {} fetching {}", status, url);
        // 404/403 will not fix themselves; 5xx and 429 might.
        return Err(if status.is_server_error() || status.as_u16() == 429 {
            PartError::Retry(e)
        } else {
            PartError::Fatal(e)
        });
    }
    let file = File::create(out).map_err(|e| PartError::Fatal(e.into()))?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let mut decoder = flate2::read::ZlibDecoder::new(resp);
    std::io::copy(&mut decoder, &mut writer)
        .and_then(|_| writer.flush())
        .map_err(|e| PartError::Retry(anyhow!("download/decompress: {}", e)))
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Counting semaphore (std has none).
struct Semaphore {
    count: Mutex<usize>,
    cv: Condvar,
}

struct Permit<'a>(&'a Semaphore);

impl Semaphore {
    fn new(n: usize) -> Self {
        Self { count: Mutex::new(n), cv: Condvar::new() }
    }

    fn acquire(&self) -> Permit<'_> {
        let mut c = self.count.lock().unwrap();
        while *c == 0 {
            c = self.cv.wait(c).unwrap();
        }
        *c -= 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.count.lock().unwrap() += 1;
        self.0.cv.notify_one();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;

    fn encode_name(path: &str) -> String {
        let mut bytes = vec![0xFF, 0xFE];
        for u in path.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn manifest(files: &[(&str, u64, &[&str])]) -> Manifest {
        let mut map = serde_json::Map::new();
        for (p, size, parts) in files {
            map.insert(encode_name(p), serde_json::json!({ "fsize": size, "objects": parts }));
        }
        map.insert(encode_name("package"), serde_json::json!({ "fsize": 0, "objects": ["__DIR__"] }));
        let json = serde_json::json!({ "files": map, "buildtime": 1.0 });
        Manifest::parse("ab".repeat(20).as_str(), zlib(json.to_string().as_bytes())).unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nxl-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn decodes_utf16_names() {
        assert_eq!(decode_filename(&encode_name("package\\data_00001.it")).as_deref(), Some("package/data_00001.it"));
        assert_eq!(decode_filename(&encode_name("한글.txt")).as_deref(), Some("한글.txt"));
    }

    #[test]
    fn parses_manifest_and_rejects_unsafe_paths() {
        let m = manifest(&[("Client.exe", 3, &["aa11"]), ("..\\evil.dll", 1, &["bb22"])]);
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].path, "Client.exe");
        assert_eq!(m.dirs, vec!["package".to_string()]);
    }

    #[test]
    fn wildcard_ignore() {
        let pats = vec!["package\\*.mod".to_string(), "data/Fonts/?.ttf".to_string()];
        assert!(is_ignored("package/a.mod", &pats));
        assert!(is_ignored("PACKAGE/X.MOD", &pats));
        assert!(is_ignored("data/fonts/a.ttf", &pats));
        assert!(!is_ignored("data/fonts/ab.ttf", &pats));
        assert!(!is_ignored("package/a.it", &pats));
    }

    #[test]
    fn scan_detects_missing_size_and_content_changes() {
        let dir = temp_dir("scan");
        std::fs::write(dir.join("same.dat"), b"abc").unwrap();
        std::fs::write(dir.join("resized.dat"), b"ab").unwrap();
        std::fs::write(dir.join("changed.dat"), b"xyz").unwrap();
        let install = GameInstall::locate(&dir).unwrap();

        // Installed version: changed.dat had different parts.
        install
            .store(&manifest(&[("same.dat", 3, &["p1"]), ("resized.dat", 3, &["p2"]), ("changed.dat", 3, &["old"])]))
            .unwrap();

        let new = manifest(&[
            ("same.dat", 3, &["p1"]),
            ("resized.dat", 3, &["p2"]),
            ("changed.dat", 3, &["new"]),
            ("missing.dat", 1, &["p4"]),
            ("mods/local.dat", 1, &["p5"]),
        ]);
        let opts = PatchOptions { ignore: vec!["mods/*".into()], ..Default::default() };
        let mut found: Vec<(String, ChangeReason)> =
            scan(&install, &new, &opts).into_iter().map(|p| (p.file.path, p.reason)).collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            found,
            vec![
                ("changed.dat".into(), ChangeReason::ContentChanged),
                ("missing.dat".into(), ChangeReason::Missing),
                ("resized.dat".into(), ChangeReason::SizeChanged),
            ]
        );

        let forced = scan(&install, &new, &PatchOptions { force_all: true, ..Default::default() });
        assert_eq!(forced.len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locate_finds_sibling_patchdata() {
        let dir = temp_dir("locate");
        std::fs::create_dir_all(dir.join("appdata")).unwrap();
        std::fs::create_dir_all(dir.join("patchdata")).unwrap();
        std::fs::write(dir.join("appdata/Client.exe"), b"").unwrap();
        let install = GameInstall::locate(&dir.join("appdata/Client.exe")).unwrap();
        assert_eq!(install.root, dir.join("appdata"));
        assert_eq!(install.patchdata, dir.join("patchdata"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serves zlib parts like the CDN: GET /<xx>/<hash>. Unknown hashes 404.
    fn serve_parts(parts: HashMap<String, Vec<u8>>) -> String {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", server.server_addr().to_ip().unwrap());
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let hash = req.url().rsplit('/').next().unwrap_or("").to_string();
                let resp = match parts.get(&hash) {
                    Some(data) => tiny_http::Response::from_data(zlib(data)),
                    None => tiny_http::Response::from_data(Vec::new()).with_status_code(404),
                };
                let _ = req.respond(resp);
            }
        });
        base
    }

    #[test]
    fn apply_downloads_joins_parts_and_records_hash() {
        let dir = temp_dir("apply");
        std::fs::write(dir.join("old.dat"), b"stale!").unwrap();
        let install = GameInstall::locate(&dir).unwrap();

        let mut parts = HashMap::new();
        parts.insert("aa01".to_string(), b"hello ".to_vec());
        parts.insert("aa02".to_string(), b"world".to_vec());
        parts.insert("bb01".to_string(), vec![7u8; 100_000]);
        let base = serve_parts(parts);

        let m = manifest(&[("data/hello.txt", 11, &["aa01", "aa02"]), ("old.dat", 100_000, &["bb01"])]);
        let pending = scan(&install, &m, &PatchOptions::default());
        assert_eq!(pending.len(), 2);
        let calls = AtomicUsize::new(0);
        let report = apply_from(&base, &install, &m, &pending, &PatchOptions::default(), &|_| {
            calls.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();

        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert!(report.hash_updated);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(std::fs::read(dir.join("data/hello.txt")).unwrap(), b"hello world");
        assert_eq!(std::fs::read(dir.join("old.dat")).unwrap(), vec![7u8; 100_000]);
        assert!(dir.join("package").is_dir());
        assert_eq!(install.local_hash().as_deref(), Some(m.hash.as_str()));
        assert!(scan(&install, &m, &PatchOptions::default()).is_empty());
        let leftovers: Vec<_> = std::fs::read_dir(dir.join("data")).unwrap().flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(TEMP_SUFFIX)).collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_keeps_old_hash_when_a_part_is_missing() {
        let dir = temp_dir("apply-fail");
        std::fs::write(dir.join("keep.dat"), b"original").unwrap();
        let install = GameInstall::locate(&dir).unwrap();
        let mut parts = HashMap::new();
        parts.insert("cc01".to_string(), b"new".to_vec());
        let base = serve_parts(parts);

        let m = manifest(&[("ok.dat", 3, &["cc01"]), ("keep.dat", 5, &["dd404"])]);
        let pending = scan(&install, &m, &PatchOptions::default());
        let report = apply_from(&base, &install, &m, &pending, &PatchOptions::default(), &|_| {}).unwrap();

        assert_eq!(report.patched, 1);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "keep.dat");
        assert!(!report.hash_updated);
        assert!(install.local_hash().is_none());
        assert_eq!(std::fs::read(dir.join("keep.dat")).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn semaphore_caps_concurrency() {
        let sem = Semaphore::new(3);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..12 {
                s.spawn(|| {
                    let _p = sem.acquire();
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(10));
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        assert!(peak.load(Ordering::SeqCst) <= 3);
    }
}
