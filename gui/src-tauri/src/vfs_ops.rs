//! List-tab archive editing helpers (WinZip/FileZilla-style VFS editing):
//! stat dropped files, validate entry paths, extract a selection to a folder
//! and drag a selection out of the window as real files.

use mabi_pack2::{common, common_ext};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One local file found under a dropped path.
#[derive(Serialize)]
pub struct LocalItem {
    /// Absolute path on disk.
    local: String,
    /// Path relative to the drop: the file name for a dropped file, or
    /// `<dropped folder name>/<sub path>` for files inside a dropped folder.
    rel: String,
    size: u64,
    /// Modification time in milliseconds since the Unix epoch (0 if unknown).
    mtime: u64,
}

fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Expand dropped paths into files: files stay as-is, folders are walked
/// recursively keeping their structure under the folder's own name.
#[tauri::command]
pub fn vfs_stat_paths(paths: Vec<String>) -> Result<Vec<LocalItem>, String> {
    let mut out = Vec::new();
    for p in paths {
        let path = Path::new(&p);
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {}", p, e))?;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if meta.is_file() {
            out.push(LocalItem { local: p.clone(), rel: name, size: meta.len(), mtime: mtime_ms(&meta) });
        } else if meta.is_dir() {
            for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() { continue; }
                let Ok(sub) = entry.path().strip_prefix(path) else { continue };
                let sub = sub.to_string_lossy().replace('\\', "/");
                let m = entry.metadata().map_err(|e| e.to_string())?;
                out.push(LocalItem {
                    local: entry.path().to_string_lossy().to_string(),
                    rel: format!("{}/{}", name, sub),
                    size: m.len(),
                    mtime: mtime_ms(&m),
                });
            }
        }
    }
    Ok(out)
}

/// Check entry paths before they are queued. Returns one entry per input:
/// `None` when the path is fine, or the reason it is refused.
#[tauri::command]
pub fn vfs_validate_entry_paths(paths: Vec<String>) -> Vec<Option<String>> {
    paths.iter()
        .map(|p| common::validate_entry_path(p).err().map(|e| e.to_string()))
        .collect()
}

/// An archive entry to write out, and where it goes relative to the target folder.
#[derive(Deserialize)]
pub struct ExtractItem {
    archive: String,
    entry: String,
    rel: String,
    #[serde(default)]
    key: Option<String>,
}

/// Extract `items` under `root`; returns the distinct top-level
/// paths written (files, or the first folder component of nested items).
fn extract_items(items: &[ExtractItem], root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut tops: Vec<PathBuf> = Vec::new();
    for it in items {
        let dest = common::safe_join(root, &it.rel).map_err(|e| e.to_string())?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let (data, _, _, _) = common_ext::get_entry_data(&it.archive, &it.entry, it.key.clone())
            .map_err(|e| format!("{}: {}", it.entry, e))?;
        std::fs::write(&dest, data).map_err(|e| format!("{}: {}", dest.display(), e))?;
        let first = it.rel.split(['/', '\\']).find(|c| !c.is_empty() && *c != ".").unwrap_or("");
        let top = root.join(first);
        if !tops.contains(&top) { tops.push(top); }
    }
    Ok(tops)
}

/// "Extract selected…": write the given entries into `dest` keeping `rel` paths.
#[tauri::command]
pub async fn vfs_extract_entries(items: Vec<ExtractItem>, dest: String) -> Result<usize, String> {
    extract_items(&items, Path::new(&dest))?;
    Ok(items.len())
}

/// Drag the given entries out of the window: extract them to a temp folder,
/// then start a native OS drag carrying those files (Explorer copies them on drop).
#[tauri::command]
pub async fn vfs_drag_out(window: tauri::WebviewWindow, items: Vec<ExtractItem>) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = (window, items);
        Err(DRAG_UNSUPPORTED.to_string())
    }
    #[cfg(windows)]
    {
        let root = dragout_dir(std::process::id());
        // Files from the previous drag may still be copied by the drop target
        // until it returned, so they are cleared only now, at the next drag.
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let tops = extract_items(&items, &root)?;
        if tops.is_empty() { return Ok(()); }
        start_native_drag(window, tops)
    }
}

const DRAGOUT_PREFIX: &str = "mabi_dragout_";

fn dragout_dir(pid: u32) -> PathBuf {
    std::env::temp_dir().join(format!("{}{}", DRAGOUT_PREFIX, pid))
}

/// At exit: remove this process's drag-out folder.
pub fn remove_own_dragout_dir() {
    let _ = std::fs::remove_dir_all(dragout_dir(std::process::id()));
}

/// At startup: remove drag-out folders left by processes that are gone (crash,
/// elevation restart) or that are older than a day.
pub fn remove_stale_dragout_dirs() {
    let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) else { return };
    let me = std::process::id();
    let day = std::time::Duration::from_secs(24 * 60 * 60);
    let mut sys = sysinfo::System::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.strip_prefix(DRAGOUT_PREFIX)).and_then(|p| p.parse::<u32>().ok()) else { continue };
        if pid == me { continue; }
        let old = e.metadata().and_then(|m| m.modified()).ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > day);
        let spid = sysinfo::Pid::from_u32(pid);
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[spid]), true);
        if old || sys.process(spid).is_none() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

#[cfg(windows)]
fn start_native_drag(window: tauri::WebviewWindow, files: Vec<PathBuf>) -> Result<(), String> {
    let w = window.clone();
    window.run_on_main_thread(move || {
        let icon = drag::Image::Raw(include_bytes!("../icons/32x32.png").to_vec());
        if let Err(e) = drag::start_drag(&w, drag::DragItem::Files(files), icon, |_, _| {}, drag::Options::default()) {
            log::warn!("[VFS] drag-out failed: {}", e);
        }
    }).map_err(|e| e.to_string())
}

#[cfg(not(windows))]
const DRAG_UNSUPPORTED: &str = "Dragging files out of the window is only supported on Windows; use \"Extract selected\" instead.";
