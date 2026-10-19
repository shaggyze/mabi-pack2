//! Commands behind the item lookup, region map and world previews. The frontend picks
//! the archive entries (it owns the loaded entry list); everything heavy — reading the
//! entries, parsing itemdb/propdb/area files and building indexes — happens here so
//! the multi-megabyte XML never crosses the IPC bridge.

use mabi_pack2::itemdb::{self, ItemEntry, ItemIndex, PropClass};
use mabi_pack2::region_map::{self, AreaInfo, RegionInfo};
use mabi_pack2::{common_ext, encryption};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One archive entry, with the metadata the List tab already discovered.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EntryRef {
    archive_path: String,
    entry_name: String,
    key: Option<String>,
    entries_key: Option<String>,
    iv0: Option<u32>,
    h_off: Option<u64>,
    mode: Option<String>,
}

fn clean_key(k: &Option<String>) -> Option<String> {
    match k {
        Some(k) if k.is_empty() || k == "Search/Default" || k == "N/A" || k == "UNENCRYPTED" => None,
        other => other.clone(),
    }
}

fn read_entry(e: &EntryRef) -> Result<Vec<u8>, String> {
    let key = clean_key(&e.key);
    if let (Some(iv), Some(off), Some(m)) = (e.iv0, e.h_off, e.mode.as_deref()) {
        let mode = match m {
            "Xor" => encryption::Snow2Mode::Xor,
            "ModernBE" => encryption::Snow2Mode::ModernBE,
            "ModernLE" => encryption::Snow2Mode::ModernLE,
            "LegacyBE" => encryption::Snow2Mode::LegacyBE,
            "LegacyLE" => encryption::Snow2Mode::LegacyLE,
            _ => encryption::Snow2Mode::Sub,
        };
        common_ext::get_entry_data_exact(&e.archive_path, &e.entry_name, key, clean_key(&e.entries_key), iv, off, mode)
            .map(|r| r.0)
            .map_err(|err| format!("{}: {}", e.entry_name, err))
    } else {
        common_ext::get_entry_data(&e.archive_path, &e.entry_name, key)
            .map(|r| r.0)
            .map_err(|err| format!("{}: {}", e.entry_name, err))
    }
}

/// Merges `id<TAB>text` localization files into one lookup table.
fn load_locals(locals: &[EntryRef]) -> HashMap<String, String> {
    let parts: Vec<(String, String)> = locals
        .par_iter()
        .filter_map(|e| {
            let prefix = itemdb::local_prefix(&e.entry_name)?;
            let bytes = read_entry(e).ok()?;
            Some((prefix, itemdb::decode_text(&bytes)))
        })
        .collect();
    let mut map = HashMap::new();
    for (prefix, text) in parts {
        itemdb::parse_local_txt(&text, &prefix, &mut map);
    }
    map
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

// ── items ────────────────────────────────────────────────────────────────────

static ITEMS: Lazy<Mutex<Option<(String, Arc<ItemIndex>)>>> = Lazy::new(|| Mutex::new(None));

#[derive(Serialize)]
pub struct ItemDbStatus {
    items: usize,
    with_models: usize,
    files: usize,
    errors: Vec<String>,
}

fn items_index() -> Option<Arc<ItemIndex>> {
    ITEMS.lock().ok()?.as_ref().map(|(_, i)| i.clone())
}

/// Builds (or reuses, when `cache_key` matches) the item index from the given
/// itemdb XML entries and their localization files.
#[tauri::command]
pub async fn itemdb_load(sources: Vec<EntryRef>, locals: Vec<EntryRef>, cache_key: String) -> Result<ItemDbStatus, String> {
    if let Some((k, idx)) = ITEMS.lock().map_err(|e| e.to_string())?.as_ref() {
        if *k == cache_key {
            return Ok(ItemDbStatus { items: idx.len(), with_models: idx.with_mesh_count(), files: sources.len(), errors: vec![] });
        }
    }
    blocking(move || {
        let files = sources.len();
        let results: Vec<Result<Vec<ItemEntry>, String>> = sources
            .par_iter()
            .map(|e| read_entry(e).map(|b| itemdb::parse_items(&itemdb::decode_text(&b))))
            .collect();
        let mut lists = Vec::new();
        let mut errors = Vec::new();
        for r in results {
            match r {
                Ok(l) => lists.push(l),
                Err(e) => errors.push(e),
            }
        }
        let local = load_locals(&locals);
        let idx = Arc::new(ItemIndex::build(lists, &local));
        let status = ItemDbStatus { items: idx.len(), with_models: idx.with_mesh_count(), files, errors };
        *ITEMS.lock().map_err(|e| e.to_string())? = Some((cache_key, idx));
        Ok(status)
    })
    .await
}

/// Items whose mesh attributes reference this model name.
#[tauri::command]
pub fn itemdb_for_model(model: String) -> Vec<ItemEntry> {
    items_index().map(|i| i.for_model(&model, 24).into_iter().cloned().collect()).unwrap_or_default()
}

#[tauri::command]
pub fn itemdb_search(query: String, limit: Option<usize>) -> Vec<ItemEntry> {
    let limit = limit.unwrap_or(40).min(200);
    items_index().map(|i| i.search(&query, limit).into_iter().cloned().collect()).unwrap_or_default()
}

// ── props (plaintext propdb only) ────────────────────────────────────────────

static PROPS: Lazy<Mutex<Option<(String, Arc<HashMap<i32, PropClass>>)>>> = Lazy::new(|| Mutex::new(None));

#[derive(Serialize)]
pub struct PropDbStatus {
    classes: usize,
    /// propdb files that were not plaintext XML (encoded) and were skipped.
    skipped: usize,
    /// The classes came from the online PropDB.xml (no plaintext propdb was open).
    remote: bool,
}

/// Plaintext PropDB.xml and its English names, published with the web version of
/// mabi-patcher. Used when the open archives only have an encoded propdb (current
/// clients).
const REMOTE_PROPDB_URL: &str = "https://shaggyze.website/mabipatcher/mabi-files/db/PropDB.xml";
const REMOTE_PROPDB_NAMES_URL: &str = "https://shaggyze.website/mabipatcher/mabi-files/local/xml/PropDB.english.txt";
/// The web version's compact prop list, `[[id, class_name, events, class_path], ...]`
/// (700 KB against 4.2 MB for the XML). Tried first.
const REMOTE_PROPS_JSON_URL: &str = "https://shaggyze.website/mabipatcher/props.json";
/// Downloaded copies are reused for this long before they are fetched again.
const REMOTE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// A file from the web version, cached in %APPDATA%: the cached copy while it is
/// fresh and `valid`, else a new download, else an old cached copy.
fn remote_file(url: &str, file: &str, valid: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let cache = std::env::var_os("APPDATA")
        .map(|a| std::path::PathBuf::from(a).join("com.shaggyze.mabi-patcher").join("web-db").join(file));
    let cached = || cache.as_ref().and_then(|p| std::fs::read(p).ok()).filter(|b| valid(b));
    let fresh = cache.as_ref().and_then(|p| std::fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < REMOTE_MAX_AGE);
    if fresh {
        if let Some(b) = cached() {
            return Some(b);
        }
    }
    let downloaded = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .ok()
        .and_then(|r| {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut std::io::Read::take(r.into_reader(), 64 << 20), &mut buf).ok().map(|_| buf)
        })
        .filter(|b| valid(b));
    match downloaded {
        Some(bytes) => {
            if let Some(p) = &cache {
                let _ = p.parent().map(std::fs::create_dir_all);
                let _ = std::fs::write(p, &bytes);
            }
            log::info!("[PropDB] Downloaded {}", url);
            Some(bytes)
        }
        None => {
            log::warn!("[PropDB] Could not download {}", url);
            cached()
        }
    }
}

/// Prop classes from the web version's props.json (class names and paths; the
/// English names file is mostly untranslated Korean, so it adds little).
fn remote_props_json() -> Option<Vec<PropClass>> {
    let parse = |b: &[u8]| -> Option<Vec<PropClass>> {
        let rows: Vec<serde_json::Value> = serde_json::from_slice(b).ok()?;
        let list: Vec<PropClass> = rows
            .iter()
            .filter_map(|r| {
                let r = r.as_array()?;
                Some(PropClass {
                    id: i32::try_from(r.first()?.as_i64()?).ok()?,
                    class_name: r.get(1)?.as_str()?.to_string(),
                    class_path: r.get(3).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    string_id: String::new(),
                    name: String::new(),
                })
            })
            .collect();
        (!list.is_empty()).then_some(list)
    };
    let bytes = remote_file(REMOTE_PROPS_JSON_URL, "props.json", |b| parse(b).is_some())?;
    parse(&bytes)
}

/// Prop classes from the online PropDB.xml, with `_LT[...]` names resolved from
/// the online English names file.
fn remote_propdb() -> Option<Vec<PropClass>> {
    if let Some(list) = remote_props_json() {
        return Some(list);
    }
    let xml = remote_file(REMOTE_PROPDB_URL, "PropDB.xml", |b| itemdb::parse_propdb(b).is_some())?;
    let mut list = itemdb::parse_propdb(&xml)?;
    if let Some(txt) = remote_file(REMOTE_PROPDB_NAMES_URL, "PropDB.english.txt", |b| !b.is_empty()) {
        if let Some(prefix) = itemdb::local_prefix("local/xml/propdb.english.txt") {
            let mut names = HashMap::new();
            itemdb::parse_local_txt(&itemdb::decode_text(&txt), &prefix, &mut names);
            itemdb::localize_props(&mut list, &names);
        }
    }
    Some(list)
}

#[tauri::command]
pub async fn propdb_load(sources: Vec<EntryRef>, locals: Vec<EntryRef>, cache_key: String) -> Result<PropDbStatus, String> {
    if let Some((k, map)) = PROPS.lock().map_err(|e| e.to_string())?.as_ref() {
        if *k == cache_key {
            return Ok(PropDbStatus { classes: map.len(), skipped: 0, remote: false });
        }
    }
    blocking(move || {
        let mut skipped = 0;
        let mut all: Vec<PropClass> = Vec::new();
        for e in &sources {
            match read_entry(e).ok().and_then(|b| itemdb::parse_propdb(&b)) {
                Some(list) => all.extend(list),
                None => skipped += 1,
            }
        }
        let mut remote = false;
        if all.is_empty() {
            if let Some(list) = remote_propdb() {
                all = list;
                remote = true;
            }
        }
        if !all.is_empty() {
            itemdb::localize_props(&mut all, &load_locals(&locals));
        }
        let map: HashMap<i32, PropClass> = all.into_iter().map(|p| (p.id, p)).collect();
        let status = PropDbStatus { classes: map.len(), skipped, remote };
        *PROPS.lock().map_err(|e| e.to_string())? = Some((cache_key, Arc::new(map)));
        Ok(status)
    })
    .await
}

#[tauri::command]
pub fn propdb_lookup(ids: Vec<i32>) -> Vec<PropClass> {
    let Some(map) = PROPS.lock().ok().and_then(|g| g.as_ref().map(|(_, m)| m.clone())) else { return Vec::new() };
    let mut seen = std::collections::HashSet::new();
    ids.into_iter().filter(|id| seen.insert(*id)).filter_map(|id| map.get(&id).cloned()).collect()
}

/// Model names listed in a prop `.set` file.
#[tauri::command]
pub async fn set_model_names(entry: EntryRef) -> Result<Vec<String>, String> {
    blocking(move || Ok(region_map::parse_set_models(&read_entry(&entry)?).unwrap_or_default())).await
}

// ── regions ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RegionMap {
    region: Option<RegionInfo>,
    areas: Vec<AreaInfo>,
    errors: Vec<String>,
    /// Props dropped to stay under the size cap.
    dropped_props: usize,
}

const MAX_AREAS: usize = 256;
const MAX_PROPS: usize = 60_000;

fn stem(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).to_lowercase();
    base.rsplit_once('.').map(|(s, _)| s.to_string()).unwrap_or(base)
}

/// Loads a region for the map/world previews. `rgn_candidates` are the .rgn files in
/// the previewed file's folder; the first one listing `focus_area` (or the first that
/// parses, when there is no focus) supplies the area list. `area_entries` are the
/// .area files of that folder; only the region's areas are parsed (or just the focus
/// area when no region matches).
#[tauri::command]
pub async fn region_load(rgn_candidates: Vec<EntryRef>, area_entries: Vec<EntryRef>, focus_area: Option<String>) -> Result<RegionMap, String> {
    blocking(move || {
        let mut errors = Vec::new();
        let focus = focus_area.map(|f| stem(&f));
        let mut region: Option<RegionInfo> = None;
        for e in &rgn_candidates {
            match read_entry(e).and_then(|b| region_map::parse_region(&b)) {
                Ok(r) => {
                    let matches = focus
                        .as_ref()
                        .map(|f| r.area_names.iter().any(|a| a.eq_ignore_ascii_case(f)))
                        .unwrap_or(true);
                    if matches {
                        region = Some(r);
                        break;
                    }
                }
                Err(err) => errors.push(format!("{}: {}", e.entry_name, err)),
            }
        }
        let wanted: Vec<String> = match (&region, &focus) {
            (Some(r), _) => r.area_names.iter().map(|a| a.to_lowercase()).collect(),
            (None, Some(f)) => vec![f.clone()],
            (None, None) => Vec::new(),
        };
        let mut picked: Vec<&EntryRef> = area_entries.iter().filter(|e| wanted.contains(&stem(&e.entry_name))).collect();
        picked.truncate(MAX_AREAS);
        let parsed: Vec<Result<AreaInfo, String>> = picked
            .par_iter()
            .map(|e| read_entry(e).and_then(|b| region_map::parse_area(&b)).map_err(|err| format!("{}: {}", e.entry_name, err)))
            .collect();
        let mut areas = Vec::new();
        for p in parsed {
            match p {
                Ok(a) => areas.push(a),
                Err(e) => errors.push(e),
            }
        }
        areas.sort_by(|a, b| a.name.cmp(&b.name));
        let mut budget = MAX_PROPS;
        let mut dropped_props = 0;
        for a in &mut areas {
            if a.props.len() > budget {
                dropped_props += a.props.len() - budget;
                a.props.truncate(budget);
            }
            budget -= a.props.len();
        }
        if region.is_none() && areas.is_empty() {
            return Err(errors.first().cloned().unwrap_or_else(|| "no region or area data found".into()));
        }
        Ok(RegionMap { region, areas, errors, dropped_props })
    })
    .await
}
