// Nexon NXL manifest patcher for Mabinogi NA (product 10200).
//
// Follows the NXL patcher flow:
//   1. Remote manifest hash: branch API manifestUrl (needs a session; the public
//      CDN 10200.manifest.hash is a stale 2014 manifest).
//   2. Manifest: GET .../10200/<hash> → zlib → JSON { files: { b64(utf16 path): {fsize, mtime, objects, objects_fsize} } }
//   3. Diff: missing / size changed / objects[] changed vs. the installed manifest
//      (verify mode SHA1-checks every part; force mode re-downloads everything).
//      objects[i] = SHA1 of decompressed part i (4 MiB parts); objects_fsize[i] = compressed size.
//   4. Parts: GET https://download2.nexon.net/Game/nxl/games/10200/10200/<xx>/<hash> → zlib,
//      concatenated in order into `<file>.~nxlpatch`, then renamed over the target.
//   5. On full success: write patchdata/10200.manifest.hash and keep patchdata/<hash>
//      (the compressed manifest) so the next update can diff against it.
//
// Files are patched by a pool of `max_workers` threads; each file fetches up to
// PARTS_PER_FILE parts at once, and a global limiter caps simultaneous HTTP requests
// so the CDN doesn't throttle us.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use super::auth::{self, NexonSession, API_BASE};

/// CDN base for the default product (10200). Kept for callers that only patch
/// Mabinogi; the product-id–aware patch path uses [`cdn_base`] instead.
/// Upper bound for `PatchOptions::max_workers` (CLI `--workers`, API `max_workers`).
pub const MAX_WORKERS: usize = 32;
pub const CDN_BASE: &str = "http://download2.nexon.net/Game/nxl/games/10200/";
/// Part base for the default product (10200). See [`part_base`] for the
/// product-id–aware variant used by the patcher.
pub const PART_BASE: &str = "https://download2.nexon.net/Game/nxl/games/10200/10200/";

/// CDN base for the active product: `…/games/<pid>/` (manifest + hash live here).
pub fn cdn_base() -> String {
    format!("http://download2.nexon.net/Game/nxl/games/{}/", auth::product_id())
}
/// Part base for the active product: `…/games/<pid>/<pid>/` (file parts live under `<xx>/`).
pub fn part_base() -> String {
    let pid = auth::product_id();
    format!("https://download2.nexon.net/Game/nxl/games/{}/{}/", pid, pid)
}
const PARTS_PER_FILE: usize = 4;
const PART_RETRIES: u32 = 3;

static CDN: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .pool_max_idle_per_host(64)
        .user_agent(auth::USER_AGENT)
        .build()
        .expect("failed to build CDN client")
});

// ── Paths ─────────────────────────────────────────────────────────────────────

/// Resolved install layout. Accepts the install root, `appdata\`, `patchdata\`
/// or the path to `Client.exe`.
#[derive(Debug, Clone, Serialize)]
pub struct GameRoots {
    /// Folder that holds `appdata\` and `patchdata\` (e.g. C:\Nexon\Library\mabinogi).
    pub install_root: PathBuf,
    pub appdata: PathBuf,
    pub patchdata: PathBuf,
}

impl GameRoots {
    pub fn resolve(path: impl AsRef<Path>) -> GameRoots {
        let mut p = path.as_ref().to_path_buf();
        if p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false) {
            p = p.parent().map(Path::to_path_buf).unwrap_or(p);
        }
        let name = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let base = if name == "patchdata" || name == "appdata" {
            p.parent().map(Path::to_path_buf).unwrap_or(p.clone())
        } else {
            p.clone()
        };
        let appdata = if base.join("appdata").is_dir() { base.join("appdata") } else { base.clone() };
        // Usual layout is <root>\patchdata; some installs keep it under appdata.
        let patchdata = if base.join("patchdata").is_dir() || !appdata.join("patchdata").is_dir() {
            base.join("patchdata")
        } else {
            appdata.join("patchdata")
        };
        GameRoots { install_root: base, appdata, patchdata }
    }

    pub fn hash_file(&self) -> PathBuf {
        self.patchdata.join(format!("{}.manifest.hash", auth::product_id()))
    }

    pub fn local_hash(&self) -> Option<String> {
        std::fs::read_to_string(self.hash_file())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn client_exe(&self) -> PathBuf {
        self.appdata.join("Client.exe")
    }
}

// ── Manifest ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Decoded relative path with native separators.
    pub path: String,
    pub fsize: u64,
    pub mtime: u64,
    pub objects: Vec<String>,
    pub objects_fsize: Vec<u64>,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub hash: String,
    pub buildtime: f64,
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn parse(hash: &str, compressed: &[u8]) -> Result<Manifest> {
        let json = zlib_decompress(compressed).map_err(|e| anyhow!("manifest decompress: {}", e))?;
        let v: serde_json::Value = serde_json::from_slice(&json)?;
        let files = v["files"].as_object().ok_or_else(|| anyhow!("manifest has no files"))?;
        let mut entries = Vec::with_capacity(files.len());
        for (key, f) in files {
            let objects: Vec<String> = f["objects"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if objects.is_empty() {
                continue;
            }
            let raw_path = decode_path(key);
            // Never let a manifest entry point outside the install folder.
            if let Err(e) = crate::common::safe_join(Path::new(""), &raw_path) {
                log::warn!("[PATCH] skipping manifest entry: {}", e);
                continue;
            }
            entries.push(ManifestEntry {
                path: raw_path.replace('\\', std::path::MAIN_SEPARATOR_STR),
                fsize: f["fsize"].as_f64().unwrap_or(0.0) as u64,
                mtime: f["mtime"].as_f64().unwrap_or(0.0) as u64,
                is_dir: objects[0] == "__DIR__",
                objects_fsize: f["objects_fsize"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_f64().map(|n| n as u64)).collect())
                    .unwrap_or_default(),
                objects,
            });
        }
        Ok(Manifest { hash: hash.to_string(), buildtime: v["buildtime"].as_f64().unwrap_or(0.0), entries })
    }

    /// Folder manifest paths are relative to: the install root when paths start with
    /// `appdata\`, otherwise the appdata folder itself.
    pub fn content_root(&self, roots: &GameRoots) -> PathBuf {
        let prefix = format!("appdata{}", std::path::MAIN_SEPARATOR);
        let with_prefix = self.entries.iter().filter(|e| e.path.to_lowercase().starts_with(&prefix)).count();
        if with_prefix * 2 > self.entries.len() { roots.install_root.clone() } else { roots.appdata.clone() }
    }
}

/// Fetch the current remote manifest hash from the authenticated branch API
/// (manifestUrl → body is the hash). The public `10200.manifest.hash` on the CDN
/// is a stale 2014 manifest — patching against it would downgrade files, so a
/// Nexon session is required. A 401 refreshes `session` in place (persist it).
pub fn remote_manifest_hash(session: Option<&mut NexonSession>) -> Result<String> {
    let session = session.ok_or_else(|| {
        anyhow!("Log in first — the current game manifest is only available with a Nexon session.")
    })?;
    let info = fetch_manifest(session)?;
    if let Ok(body) = CDN.get(&info.manifest_url).send().and_then(|r| r.error_for_status()).and_then(|r| r.text()) {
        if is_hash(body.trim()) {
            return Ok(body.trim().to_string());
        }
    }
    // Some branch URLs point straight at the manifest blob; its name is the hash.
    info.manifest_url
        .rsplit('/')
        .next()
        .filter(|s| is_hash(s))
        .map(String::from)
        .ok_or_else(|| anyhow!("Could not determine manifest hash from {}", info.manifest_url))
}

/// Load manifest `hash` from patchdata, downloading (and caching) it if missing.
pub fn load_manifest(roots: &GameRoots, hash: &str) -> Result<Manifest> {
    let cached = roots.patchdata.join(hash);
    if let Ok(bytes) = std::fs::read(&cached) {
        if let Ok(m) = Manifest::parse(hash, &bytes) {
            return Ok(m);
        }
    }
    let mut bytes = Vec::new();
    CDN.get(format!("{}{}", cdn_base(), hash))
        .send()?
        .error_for_status()?
        .read_to_end(&mut bytes)?;
    let m = Manifest::parse(hash, &bytes)?;
    if std::fs::create_dir_all(&roots.patchdata).is_ok() {
        let _ = std::fs::write(&cached, &bytes);
    }
    Ok(m)
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    pub local_hash: Option<String>,
    pub remote_hash: String,
    pub update_available: bool,
}

/// Compare local and remote manifests. A 401 refreshes `session` in place (persist it).
pub fn check_update(roots: &GameRoots, session: Option<&mut NexonSession>) -> Result<UpdateCheck> {
    let remote_hash = remote_manifest_hash(session)?;
    let local_hash = roots.local_hash();
    Ok(UpdateCheck {
        update_available: local_hash.as_deref() != Some(remote_hash.as_str()),
        local_hash,
        remote_hash,
    })
}

/// Per-folder update status for the multi-install check (a folder-select dialog).
#[derive(Debug, Clone, Serialize)]
pub struct FolderStatus {
    pub path: String,
    pub local_hash: Option<String>,
    pub remote_hash: Option<String>,
    /// true = an update is available, false = up to date, None = `error` is set.
    pub update_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Check each game folder against Nexon's current manifest and report whether it
/// is up to date or needs an update. The remote hash is fetched once and reused
/// across folders (so one session refresh covers them all). A 401 refreshes
/// `session` in place — persist it afterwards.
pub fn check_folders(folders: &[PathBuf], mut session: Option<&mut NexonSession>) -> Vec<FolderStatus> {
    let remote = match remote_manifest_hash(session.as_deref_mut()) {
        Ok(h) => h,
        Err(e) => {
            // No remote hash → every folder reports the same error.
            return folders.iter().map(|p| FolderStatus {
                path: p.display().to_string(),
                local_hash: None,
                remote_hash: None,
                update_available: None,
                error: Some(e.to_string()),
            }).collect();
        }
    };
    folders.iter().map(|p| {
        let roots = GameRoots::resolve(p);
        let local = roots.local_hash();
        FolderStatus {
            path: p.display().to_string(),
            update_available: Some(local.as_deref() != Some(remote.as_str())),
            local_hash: local,
            remote_hash: Some(remote.clone()),
            error: None,
        }
    }).collect()
}

/// Scan an install and return the files that need updating (status + size), without
/// downloading. Thin wrapper over [`run_patcher`] in `scan_only` mode, for the
/// "choose which files to update" dialog. Each [`NeedItem`]'s `reason` is one of
/// `New` / `Size changed` / `Content changed` / `Re-download`.
pub fn scan(
    roots: &GameRoots,
    session: Option<&mut NexonSession>,
    opts: &PatchOptions,
) -> Result<Vec<NeedItem>> {
    let opts = PatchOptions { scan_only: true, ..opts.clone() };
    Ok(run_patcher(roots, session, &opts, &|_| {})?.need)
}

// ── Patching ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchMode {
    /// Missing, size-changed, or objects[] changed vs. installed manifest.
    Update,
    /// Like Update, plus recompress+SHA1 check of size-matching files.
    Verify,
    /// Re-download everything.
    ForceAll,
}

#[derive(Clone)]
pub struct PatchOptions {
    pub mode: PatchMode,
    pub max_workers: usize,
    /// Wildcard patterns (`*`, `?`, case-insensitive) for files never touched.
    pub ignore: Vec<String>,
    /// Scan only; don't download.
    pub scan_only: bool,
    /// Patch against this manifest hash instead of the remote one.
    pub manifest_hash: Option<String>,
    pub cancel: Arc<AtomicBool>,
    /// When set, only these manifest paths are considered (case-insensitive, `\`
    /// and `/` interchangeable) — a "choose which files to update" allow-list.
    /// `None` = every file (the normal diff). Ignored entries are still skipped.
    pub only: Option<Vec<String>>,
    /// Shared pause flag: while set, workers block before each file (and the scan
    /// pauses) until it clears or `cancel` is set. Sits next to `cancel`.
    pub pause: Arc<AtomicBool>,
}

impl Default for PatchOptions {
    fn default() -> Self {
        PatchOptions {
            mode: PatchMode::Update,
            max_workers: 8,
            ignore: Vec::new(),
            scan_only: false,
            manifest_hash: None,
            cancel: Arc::new(AtomicBool::new(false)),
            only: None,
            pause: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Block while `pause` is set, returning early if `cancel` is set. Polls at 100ms.
fn wait_if_paused(pause: &AtomicBool, cancel: &AtomicBool) {
    while pause.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// True if `path` equals one of `only` (case-insensitive, `\`/`/` interchangeable).
fn in_allow_list(path: &str, only: &[String]) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_start_matches('/').to_lowercase();
    let p = norm(path);
    only.iter().any(|o| norm(o) == p)
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PatchEvent {
    Log { message: String },
    Scan { done: usize, total: usize, need: usize, file: String },
    Download { files_done: usize, files_total: usize, bytes: u64, bytes_total: u64, speed_bps: u64, file: String },
    Worker { worker_id: usize, phase: String, file: String, parts_done: usize, parts_total: usize },
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NeedItem {
    pub path: String,
    pub size: u64,
    /// Current size on disk, -1 = missing.
    pub local_size: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PatchResult {
    pub manifest_hash: String,
    pub buildtime: f64,
    pub need: Vec<NeedItem>,
    pub patched: usize,
    pub errors: Vec<String>,
    pub cancelled: bool,
    pub needs_elevation: bool,
    pub up_to_date: bool,
}

/// Run the patcher. `on_event` is called from worker threads.
/// A 401 while fetching the manifest refreshes `session` in place (persist it).
pub fn run_patcher(
    roots: &GameRoots,
    session: Option<&mut NexonSession>,
    opts: &PatchOptions,
    on_event: &(dyn Fn(PatchEvent) + Sync),
) -> Result<PatchResult> {
    let log = |m: String| on_event(PatchEvent::Log { message: m });

    let hash = match &opts.manifest_hash {
        Some(h) => h.clone(),
        None => remote_manifest_hash(session)?,
    };
    let local_hash = roots.local_hash();
    log(format!("Remote manifest {} (local {})", short(&hash), local_hash.as_deref().map(short).unwrap_or("none")));

    let manifest = load_manifest(roots, &hash)?;
    let content_root = manifest.content_root(roots);
    log(format!("{} manifest entries, install root {}", manifest.entries.len(), content_root.display()));

    // Installed manifest, for objects[] diff (catches same-size content changes).
    let old: HashMap<String, Vec<String>> = match (&local_hash, opts.mode) {
        (Some(lh), PatchMode::Update) if *lh != hash => std::fs::read(roots.patchdata.join(lh))
            .ok()
            .and_then(|b| Manifest::parse(lh, &b).ok())
            .map(|m| m.entries.into_iter().map(|e| (e.path.to_lowercase(), e.objects)).collect())
            .unwrap_or_default(),
        _ => HashMap::new(),
    };

    let candidates: Vec<&ManifestEntry> = manifest
        .entries
        .iter()
        .filter(|e| !e.is_dir && !is_ignored(&e.path, &opts.ignore))
        .filter(|e| opts.only.as_ref().is_none_or(|only| in_allow_list(&e.path, only)))
        .collect();

    // ── Scan ──
    let total = candidates.len();
    let scanned = AtomicUsize::new(0);
    let need: Mutex<Vec<(NeedItem, &ManifestEntry)>> = Mutex::new(Vec::new());
    {
        use rayon::prelude::*;
        candidates.par_iter().for_each(|e| {
            wait_if_paused(&opts.pause, &opts.cancel);
            if opts.cancel.load(Ordering::Relaxed) {
                return;
            }
            let full = content_root.join(&e.path);
            let local_size = std::fs::metadata(&full).map(|m| m.len() as i64).unwrap_or(-1);
            let reason = if opts.mode == PatchMode::ForceAll {
                Some("Re-download")
            } else if local_size < 0 {
                Some("New")
            } else if local_size as u64 != e.fsize {
                Some("Size changed")
            } else if old.get(&e.path.to_lowercase()).map(|o| *o != e.objects).unwrap_or(false) {
                Some("Content changed")
            } else if opts.mode == PatchMode::Verify && !verify_file_parts(&full, e) {
                Some("Content changed")
            } else {
                None
            };
            if let Some(r) = reason {
                need.lock().unwrap().push((
                    NeedItem { path: e.path.clone(), size: e.fsize, local_size, reason: r.into() },
                    e,
                ));
            }
            let done = scanned.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 250 == 0 || done == total {
                on_event(PatchEvent::Scan { done, total, need: need.lock().unwrap().len(), file: e.path.clone() });
            }
        });
    }

    let mut need = need.into_inner().unwrap();
    need.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    let mut result = PatchResult {
        manifest_hash: hash.clone(),
        buildtime: manifest.buildtime,
        need: need.iter().map(|(n, _)| n.clone()).collect(),
        ..Default::default()
    };

    if opts.cancel.load(Ordering::Relaxed) {
        // Don't store the new hash — unscanned files would be hidden next time.
        result.cancelled = true;
        log("Scan cancelled.".into());
        return Ok(result);
    }
    log(format!("{} files need updating", need.len()));

    if need.is_empty() {
        // A partial (`only`) run checked just the selected files, so the rest may
        // still be out of date: keep the old hash so the next update rescans them.
        if opts.only.is_none() {
            write_hash(roots, &hash);
            result.up_to_date = true;
        }
        log("Already up to date.".into());
        return Ok(result);
    }
    if opts.scan_only {
        return Ok(result);
    }

    // ── Download ──
    let files_total = need.len();
    let bytes_total: u64 = need.iter().map(|(n, _)| n.size).sum();
    let queue = Mutex::new(need.into_iter().map(|(_, e)| e).collect::<Vec<_>>());
    let files_done = AtomicUsize::new(0);
    let bytes_done = AtomicU64::new(0);
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let elevation = AtomicBool::new(false);
    let workers = opts.max_workers.clamp(1, MAX_WORKERS);
    let limiter = Limiter::new(workers * 2);
    let started = std::time::Instant::now();

    std::thread::scope(|s| {
        for worker_id in 0..workers {
            let (queue, files_done, bytes_done, errors, elevation, limiter, content_root) =
                (&queue, &files_done, &bytes_done, &errors, &elevation, &limiter, &content_root);
            s.spawn(move || loop {
                wait_if_paused(&opts.pause, &opts.cancel);
                if opts.cancel.load(Ordering::Relaxed) {
                    break;
                }
                let entry = match queue.lock().unwrap().pop() {
                    Some(e) => e,
                    None => break,
                };
                let parts_total = entry.objects.len();
                on_event(PatchEvent::Worker {
                    worker_id, phase: "downloading".into(), file: entry.path.clone(), parts_done: 0, parts_total,
                });
                let progress = |parts_done: usize| {
                    on_event(PatchEvent::Worker {
                        worker_id, phase: "downloading".into(), file: entry.path.clone(), parts_done, parts_total,
                    })
                };
                match patch_file(entry, content_root, limiter, &opts.cancel, &progress) {
                    Ok(()) => {
                        let fd = files_done.fetch_add(1, Ordering::Relaxed) + 1;
                        let bd = bytes_done.fetch_add(entry.fsize, Ordering::Relaxed) + entry.fsize;
                        let secs = started.elapsed().as_secs_f64().max(0.001);
                        on_event(PatchEvent::Download {
                            files_done: fd, files_total, bytes: bd, bytes_total,
                            speed_bps: (bd as f64 / secs) as u64, file: entry.path.clone(),
                        });
                        on_event(PatchEvent::Worker {
                            worker_id, phase: "done".into(), file: entry.path.clone(), parts_done: parts_total, parts_total,
                        });
                    }
                    Err(e) => {
                        if let Some(io) = e.downcast_ref::<std::io::Error>() {
                            if io.kind() == std::io::ErrorKind::PermissionDenied {
                                elevation.store(true, Ordering::Relaxed);
                            }
                        }
                        on_event(PatchEvent::Worker {
                            worker_id, phase: "error".into(), file: entry.path.clone(), parts_done: 0, parts_total,
                        });
                        errors.lock().unwrap().push(format!("{}: {}", entry.path, e));
                    }
                }
            });
        }
    });

    result.patched = files_done.load(Ordering::Relaxed);
    result.errors = errors.into_inner().unwrap();
    result.needs_elevation = elevation.load(Ordering::Relaxed);
    result.cancelled = opts.cancel.load(Ordering::Relaxed);

    if result.cancelled {
        log("Cancelled — hash not updated, will resume on next update.".into());
    } else if result.errors.is_empty() {
        if opts.only.is_none() {
            write_hash(roots, &hash);
            result.up_to_date = true;
        }
        log(format!("Patch complete: {} files.", result.patched));
    } else {
        log(format!("Patch finished with {} errors — hash not updated.", result.errors.len()));
    }
    Ok(result)
}

/// Download, decompress and assemble one file; parts fetched in parallel, written in order.
fn patch_file(
    e: &ManifestEntry,
    root: &Path,
    limiter: &Limiter,
    cancel: &AtomicBool,
    progress: &(dyn Fn(usize) + Sync),
) -> Result<()> {
    let dest = crate::common::safe_join(root, &e.path)?;
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp_name = dest.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".~nxlpatch");
    let tmp = dest.with_file_name(tmp_name);

    let result = (|| -> Result<()> {
        let mut out = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?);
        let done = AtomicUsize::new(0);
        for chunk in e.objects.chunks(PARTS_PER_FILE) {
            if cancel.load(Ordering::Relaxed) {
                return Err(anyhow!("cancelled"));
            }
            let datas: Vec<Result<Vec<u8>>> = std::thread::scope(|s| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|obj| {
                        let done = &done;
                        s.spawn(move || {
                            let d = fetch_part(obj, limiter);
                            progress(done.fetch_add(1, Ordering::Relaxed) + 1);
                            d
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(anyhow!("part thread panicked")))).collect()
            });
            for d in datas {
                out.write_all(&d?)?;
            }
        }
        out.flush()?;
        drop(out);
        let written = std::fs::metadata(&tmp)?.len();
        if e.fsize > 0 && written != e.fsize {
            return Err(anyhow!("size mismatch after assemble: got {} expected {}", written, e.fsize));
        }
        if dest.exists() {
            // Clear read-only so the rename can replace it.
            if let Ok(meta) = std::fs::metadata(&dest) {
                let mut perm = meta.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perm.set_readonly(false);
                let _ = std::fs::set_permissions(&dest, perm);
            }
        }
        std::fs::rename(&tmp, &dest)?;
        if e.mtime > 0 {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(e.mtime);
            if let Ok(f) = std::fs::File::options().write(true).open(&dest) {
                let _ = f.set_modified(t);
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn fetch_part(obj: &str, limiter: &Limiter) -> Result<Vec<u8>> {
    // Part names are hex SHA1s; reject anything else (short or non-ASCII names
    // would also panic when sliced).
    let prefix = obj
        .get(..2)
        .filter(|_| obj.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("bad part name {:?}", obj))?;
    let url = format!("{}{}/{}", part_base(), prefix, obj);
    let mut last = anyhow!("no attempts");
    for attempt in 0..PART_RETRIES {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500 * (1 << attempt)));
        }
        let _permit = limiter.acquire();
        let res = (|| -> Result<Vec<u8>> {
            let mut raw = Vec::new();
            CDN.get(&url).send()?.error_for_status()?.read_to_end(&mut raw)?;
            let data = zlib_decompress(&raw).map_err(|e| anyhow!("decompress {}: {}", obj, e))?;
            // Part names are the SHA1 of the decompressed bytes — reject corrupt downloads.
            if !sha1_hex(&data).eq_ignore_ascii_case(obj) {
                return Err(anyhow!("checksum mismatch for part {}", obj));
            }
            Ok(data)
        })();
        match res {
            Ok(d) => return Ok(d),
            Err(e) => last = e,
        }
    }
    Err(anyhow!("{} after {} attempts: {}", url, PART_RETRIES, last))
}

/// Decompressed size of every part except the last.
pub const PART_SIZE: u64 = 4 * 1024 * 1024;

/// objects[i] is the SHA1 of decompressed part i; parts are PART_SIZE bytes
/// (last one is the remainder). objects_fsize is the *compressed* size, so it
/// can't be used as a split point.
pub fn verify_file_parts(path: &Path, e: &ManifestEntry) -> bool {
    if e.objects.is_empty() || (e.fsize + PART_SIZE - 1) / PART_SIZE.max(1) != e.objects.len() as u64 && e.fsize > 0 {
        return true; // unexpected layout — size check already passed
    }
    let mut f = match std::fs::File::open(path) {
        Ok(f) => std::io::BufReader::with_capacity(1 << 20, f),
        Err(_) => return false,
    };
    let mut buf = Vec::new();
    let mut left = e.fsize;
    for obj in &e.objects {
        let n = left.min(PART_SIZE);
        left -= n;
        buf.resize(n as usize, 0);
        if f.read_exact(&mut buf).is_err() || !sha1_hex(&buf).eq_ignore_ascii_case(obj) {
            return false;
        }
    }
    true
}

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Branch / maintenance (authenticated) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ManifestInfo {
    pub manifest_url: String,
    /// Integer version extracted from manifest URL when present (legacy format).
    pub version: i32,
}

#[derive(Deserialize)]
struct BranchResponse {
    #[serde(rename = "manifestUrl")]
    manifest_url: Option<String>,
}

/// GET /game-build/v1/branch/games/10200/public → manifestUrl.
/// Refreshes `session` in place once on 401 (persist it afterwards).
pub fn fetch_manifest(session: &mut NexonSession) -> Result<ManifestInfo> {
    auth::with_refresh(session, |s| fetch_manifest_once(s))
}

/// One branch request, no refresh: a 401 comes back as `AuthError::SessionExpired`
/// so the caller's retry wrapper (`with_refresh` / `with_session_retry`) handles it.
pub fn fetch_manifest_once(s: &NexonSession) -> Result<ManifestInfo> {
    let resp = CDN
        .get(format!("{}/game-build/v1/branch/games/{}/public", API_BASE, auth::product_id()))
        .header("Cookie", s.cookie_header())
        .bearer_auth(s.access_token.clone())
        .send()?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if status.as_u16() == 401 {
        return Err(auth::AuthError::SessionExpired("branch info".into()).into());
    }
    if !status.is_success() {
        return Err(anyhow!("Branch info failed ({}): {}", status, body));
    }
    let branch: BranchResponse = serde_json::from_str(&body)?;
    let manifest_url = branch.manifest_url.ok_or_else(|| anyhow!("No manifestUrl in branch response"))?;
    let version = extract_version(&manifest_url);
    Ok(ManifestInfo { manifest_url, version })
}

/// Latest game version. Refreshes `session` in place once on 401.
pub fn get_latest_version(session: &mut NexonSession) -> Result<i32> {
    Ok(fetch_manifest(session)?.version)
}

/// True if Mabinogi is under maintenance (HTTP 200 from the maintenance endpoint).
pub fn is_maintenance(session: &NexonSession) -> Result<bool> {
    let resp = CDN
        .get(format!("{}/maintenance/v1/products/{}", API_BASE, auth::product_id()))
        .query(&[("lang", "en")])
        .header("Cookie", session.cookie_header())
        .send()?;
    Ok(resp.status().is_success())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Caps simultaneous HTTP requests across all workers.
struct Limiter {
    count: Mutex<usize>,
    cv: Condvar,
    max: usize,
}

struct Permit<'a>(&'a Limiter);

impl Limiter {
    fn new(max: usize) -> Self {
        Limiter { count: Mutex::new(0), cv: Condvar::new(), max }
    }
    fn acquire(&self) -> Permit<'_> {
        let mut c = self.count.lock().unwrap();
        while *c >= self.max {
            c = self.cv.wait(c).unwrap();
        }
        *c += 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.count.lock().unwrap() -= 1;
        self.0.cv.notify_one();
    }
}

fn write_hash(roots: &GameRoots, hash: &str) {
    let _ = std::fs::create_dir_all(&roots.patchdata);
    if let Err(e) = std::fs::write(roots.hash_file(), hash) {
        log::warn!("could not write manifest hash: {}", e);
    }
}

pub fn zlib_decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match flate2::read::ZlibDecoder::new(data).read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(_) if data.len() > 2 => {
            out.clear();
            flate2::read::DeflateDecoder::new(&data[2..]).read_to_end(&mut out)?;
            Ok(out)
        }
        Err(e) => Err(e),
    }
}

/// base64 → UTF-16LE → strip BOM and trailing control chars/spaces.
pub fn decode_path(key: &str) -> String {
    use base64::Engine;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(key) {
        Ok(b) => b,
        Err(_) => return key.to_string(),
    };
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
        .trim_start_matches('\u{FEFF}')
        .trim_end_matches(|c: char| c.is_control() || c == ' ')
        .to_string()
}

/// Case-insensitive wildcard match (`*`, `?`) against the path or its file name.
pub fn is_ignored(path: &str, patterns: &[String]) -> bool {
    let norm = path.replace('\\', "/").to_lowercase();
    let name = norm.rsplit('/').next().unwrap_or(&norm).to_string();
    patterns.iter().any(|p| {
        let p = p.trim().replace('\\', "/").to_lowercase();
        !p.is_empty() && (wildcard(&p, &norm) || (!p.contains('/') && wildcard(&p, &name)))
    })
}

fn wildcard(p: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn is_hash(s: &str) -> bool {
    s.len() >= 32 && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn short(h: &str) -> &str {
    &h[..h.len().min(12)]
}

/// Legacy Hyddwn version format: `.../12345R/...` → 12345.
fn extract_version(url: &str) -> i32 {
    url.split('/')
        .filter_map(|seg| seg.strip_suffix('R'))
        .filter(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
        .find_map(|d| d.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_part_rejects_bad_names_without_panicking() {
        let limiter = Limiter::new(1);
        for bad in ["", "a", "é", "éa0", "../x", "zz"] {
            let e = fetch_part(bad, &limiter).unwrap_err().to_string();
            assert!(e.contains("bad part name"), "{:?}: {}", bad, e);
        }
    }

    #[test]
    fn wildcard_ignore() {
        let pats = vec!["*.ini".to_string(), "package/mod_*.it".to_string()];
        assert!(is_ignored("appdata\\Options.INI", &pats));
        assert!(is_ignored("package\\mod_ui.it", &pats));
        assert!(!is_ignored("package\\data_001.it", &pats));
    }

    #[test]
    fn decode_utf16_bom_path() {
        use base64::Engine;
        let mut b = vec![0xFF, 0xFE];
        for u in "appdata\\Client.exe\0".encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        let key = base64::engine::general_purpose::STANDARD.encode(b);
        assert_eq!(decode_path(&key), "appdata\\Client.exe");
    }

    /// Live CDN round trip using the public (old) manifest; root-level files only.
    /// `cargo test --lib live_patch_small -- --ignored`
    #[test]
    #[ignore]
    fn live_patch_small() {
        let hash = CDN.get(format!("{}{}.manifest.hash", cdn_base(), auth::product_id())).send().unwrap().text().unwrap();
        let tmp = std::env::temp_dir().join(format!("mabi_live_{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("appdata")).unwrap();
        let roots = GameRoots::resolve(&tmp);
        let opts = PatchOptions {
            ignore: vec!["*/*".into()], // root files only (includes multi-part Client.exe)
            manifest_hash: Some(hash.trim().into()),
            max_workers: 4,
            ..Default::default()
        };
        let r = run_patcher(&roots, None, &opts, &|e| if let PatchEvent::Log { message } = e { println!("{}", message) }).unwrap();
        println!("need={} patched={} errors={:?}", r.need.len(), r.patched, r.errors);
        assert!(r.errors.is_empty() && r.patched > 0 && r.patched == r.need.len());
        assert_eq!(roots.local_hash().as_deref(), Some(hash.trim()));
        // Second run: nothing to do.
        let r2 = run_patcher(&roots, None, &opts, &|_| {}).unwrap();
        assert!(r2.need.is_empty() && r2.up_to_date);
        // Verify mode: recompress+SHA1 must accept the files we just wrote.
        let v = run_patcher(&roots, None, &PatchOptions { mode: PatchMode::Verify, ..opts.clone() }, &|_| {}).unwrap();
        assert!(v.need.is_empty(), "verify flagged good files: {:?}", v.need);
        // Corrupt one byte without changing the size → verify must catch it.
        let f = roots.appdata.join("unicows.dll");
        let mut b = std::fs::read(&f).unwrap();
        b[1000] ^= 0xFF;
        std::fs::write(&f, b).unwrap();
        let v = run_patcher(&roots, None, &PatchOptions { mode: PatchMode::Verify, ..opts.clone() }, &|_| {}).unwrap();
        assert_eq!(v.need.len(), 1);
        assert_eq!(v.patched, 1);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn manifest_drops_paths_outside_install() {
        use flate2::{write::ZlibEncoder, Compression};
        let json = serde_json::json!({ "buildtime": 1, "files": {
            "appdata\\Client.exe": { "fsize": 1, "objects": ["a"], "objects_fsize": [1] },
            "..\\..\\evil.dll": { "fsize": 1, "objects": ["b"], "objects_fsize": [1] },
            "C:\\Windows\\evil.dll": { "fsize": 1, "objects": ["c"], "objects_fsize": [1] },
            "\\abs.dll": { "fsize": 1, "objects": ["d"], "objects_fsize": [1] },
        }});
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(json.to_string().as_bytes()).unwrap();
        let m = Manifest::parse("h", &enc.finish().unwrap()).unwrap();
        let paths: Vec<_> = m.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec![format!("appdata{}Client.exe", std::path::MAIN_SEPARATOR)]);
    }

    #[test]
    fn allow_list_matches_case_and_separator_insensitively() {
        let only = vec!["appdata/Client.exe".to_string(), "package\\data_001.it".to_string()];
        assert!(in_allow_list("appdata\\client.exe", &only));
        assert!(in_allow_list("package/data_001.it", &only));
        assert!(!in_allow_list("appdata\\other.dll", &only));
    }

    #[test]
    fn pause_returns_when_cancelled() {
        let pause = AtomicBool::new(true);
        let cancel = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                cancel.store(true, Ordering::Relaxed);
            });
            // Blocks on pause, then unblocks once cancel is set (not just pause clear).
            wait_if_paused(&pause, &cancel);
        });
        assert!(cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn roots_from_any_folder() {
        let tmp = std::env::temp_dir().join(format!("mabi_roots_{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("appdata")).unwrap();
        std::fs::create_dir_all(tmp.join("patchdata")).unwrap();
        for p in [tmp.clone(), tmp.join("appdata"), tmp.join("patchdata"), tmp.join("appdata").join("Client.exe")] {
            let r = GameRoots::resolve(&p);
            assert_eq!(r.install_root, tmp);
            assert_eq!(r.patchdata, tmp.join("patchdata"));
        }
        std::fs::remove_dir_all(&tmp).ok();
    }
}
