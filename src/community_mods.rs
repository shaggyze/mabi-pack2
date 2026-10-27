//! Owner-only Community Mods downloads. Credentials never reach the webview
//! after connection and are retained only in the existing OS credential store.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const ORIGIN: &str = "https://shaggyze.website";
const CREDENTIAL: &str = "community-mod-sync";
const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static TEST_ORIGIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
fn origin() -> &'static str {
    #[cfg(test)]
    if let Some(origin) = TEST_ORIGIN.get() {
        return origin;
    }
    ORIGIN
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommunityMod {
    pub id: String,
    pub revision: String,
    pub title: String,
    pub version: String,
    pub private: bool,
    pub format: String,
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    pub download: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct CommunityFeed {
    pub schema: u8,
    pub owner: String,
    pub mods: Vec<CommunityMod>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Subscription {
    pub revision: String,
    pub sha256: String,
    pub filename: String,
}
#[derive(Debug, Default, Deserialize, Serialize)]
struct State {
    owner: String,
    subscriptions: BTreeMap<String, Subscription>,
}
#[derive(Debug, Serialize)]
pub struct SyncResult {
    pub connected: bool,
    pub owner: String,
    pub mods: Vec<CommunityMod>,
    pub subscriptions: BTreeMap<String, Subscription>,
    pub updated: Vec<String>,
    pub errors: Vec<String>,
}

fn hex(value: &str, count: usize) -> bool {
    value.len() == count
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not connect to Community Mods.".into())
}
fn fetch_feed(token: &str) -> Result<CommunityFeed, String> {
    let response = client()?
        .get(format!("{}/api/community/sync", origin()))
        .bearer_auth(token)
        .send()
        .map_err(|_| "Could not connect to Community Mods.".to_string())?;
    if !response.status().is_success() {
        return Err("Community connection expired or revoked. Connect again in Mods.".into());
    }
    let mut bytes = Vec::new();
    response
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read mod list.")?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("Mod list exceeds its limit.".into());
    }
    let feed: CommunityFeed = serde_json::from_slice(&bytes)
        .map_err(|_| "Invalid Community Mods response.".to_string())?;
    if feed.schema != 1 || feed.owner.is_empty() || feed.mods.len() > 500 {
        return Err("Unsupported Community Mods response.".into());
    }
    for item in &feed.mods {
        validate_item(item)?;
    }
    Ok(feed)
}
fn validate_item(item: &CommunityMod) -> Result<(), String> {
    if !hex(&item.id, 32)
        || !hex(&item.revision, 32)
        || !hex(&item.sha256, 64)
        || !["it", "pack", "zip", "7z", "rar", "mod"].contains(&item.format.as_str())
        || !valid_filename(&item.filename)
        || !item
            .filename
            .to_lowercase()
            .ends_with(&format!(".{}", item.format))
        || item.size < 4
        || item.size > MAX_DOWNLOAD
        || item.download != format!("/api/community/mods/{}/download", item.revision)
    {
        return Err("Invalid Community Mods package metadata.".into());
    }
    Ok(())
}
fn valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 150
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        && !name.ends_with('.')
        && ![
            "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
            "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
        ]
        .contains(&name.split('.').next().unwrap_or("").to_lowercase().as_str())
}
fn account_dir(root: &Path, owner: &str) -> PathBuf {
    let key = format!("{:x}", Sha256::digest(owner.to_lowercase().as_bytes()));
    root.join(&key[..16])
}
fn state(dir: &Path, owner: &str) -> Result<State, String> {
    // The current manifest first; a missing or corrupt one falls back to the previous copy.
    let files = [dir.join("subscriptions.json"), dir.join("subscriptions.previous")];
    if !files.iter().any(|f| f.exists()) {
        return Ok(State {
            owner: owner.into(),
            ..State::default()
        });
    }
    let mut last_err = String::new();
    let mut parsed = None;
    for f in files.iter().filter(|f| f.exists()) {
        match fs::read(f).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice::<State>(&b).map_err(|e| e.to_string())) {
            Ok(s) => { parsed = Some(s); break; }
            Err(e) => last_err = e,
        }
    }
    let state = parsed.ok_or(last_err)?;
    if state.owner != owner {
        return Err("Community subscription account does not match.".into());
    }
    for (id, sub) in &state.subscriptions {
        if !hex(id, 32)
            || !hex(&sub.revision, 32)
            || !hex(&sub.sha256, 64)
            || !valid_filename(&sub.filename)
        {
            return Err("Invalid saved Community subscription.".into());
        }
    }
    Ok(state)
}
fn save_state(dir: &Path, state: &State) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let destination = dir.join("subscriptions.json");
    let temporary = dir.join("subscriptions.pending.json");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    // Windows rename does not replace existing files. Keep a recoverable backup
    // while committing a complete manifest; never truncate the previous file.
    replace_file(&temporary, &destination)
}
fn replace_file(temporary: &Path, destination: &Path) -> Result<(), String> {
    let backup = destination.with_extension("previous");
    if backup.exists() {
        fs::remove_file(&backup).map_err(|e| e.to_string())?;
    }
    let existed = destination.exists();
    if existed {
        fs::rename(destination, &backup).map_err(|e| e.to_string())?;
    }
    if let Err(error) = fs::rename(temporary, destination) {
        if existed {
            let _ = fs::rename(&backup, destination);
        }
        return Err(error.to_string());
    }
    if existed {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}
fn install(token: &str, dir: &Path, item: &CommunityMod) -> Result<Subscription, String> {
    validate_item(item)?;
    let response = client()?
        .get(format!("{}{}", origin(), item.download))
        .bearer_auth(token)
        .send()
        .map_err(|_| "Mod download failed.".to_string())?;
    if !response.status().is_success() {
        return Err("Mod is no longer available or approved.".into());
    }
    let mut bytes = Vec::new();
    response
        .take(item.size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Mod download was interrupted.")?;
    if bytes.len() as u64 != item.size || format!("{:x}", Sha256::digest(&bytes)) != item.sha256 {
        return Err("Mod integrity check failed; previous version was kept.".into());
    }
    // Archive headers depend on their filename: preserve it, isolate mods in
    // separate stable-ID directories instead of renaming private packages.
    let dir = dir.join(&item.id);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let filename = item.filename.clone();
    let destination = dir.join(&filename);
    let temporary = dir.join(format!("{}.pending", item.id));
    fs::write(&temporary, bytes).map_err(|e| e.to_string())?;
    replace_file(&temporary, &destination)?;
    Ok(Subscription {
        revision: item.revision.clone(),
        sha256: item.sha256.clone(),
        filename,
    })
}
pub fn connect(token: &str) -> Result<String, String> {
    let _lock = LOCK.lock().map_err(|_| "Community sync is busy.")?;
    if !token.starts_with("mpcs_") || !hex(&token[5..], 64) {
        return Err("Paste a Community Mods connection key from the website.".into());
    }
    if !crate::launcher::keystore::available() {
        return Err("Community sync needs the Windows credential store on this platform.".into());
    }
    let feed = fetch_feed(token)?;
    crate::launcher::keystore::store_secret(CREDENTIAL, token)?;
    Ok(feed.owner)
}
pub fn disconnect() {
    crate::launcher::keystore::delete_secret(CREDENTIAL);
}
pub fn sync(
    root: &Path,
    subscribe: Option<&str>,
    unsubscribe: Option<&str>,
) -> Result<SyncResult, String> {
    let _lock = LOCK.lock().map_err(|_| "Community sync is busy.")?;
    let Some(token) = crate::launcher::keystore::load_secret(CREDENTIAL) else {
        return Ok(SyncResult {
            connected: false,
            owner: String::new(),
            mods: vec![],
            subscriptions: BTreeMap::new(),
            updated: vec![],
            errors: vec![],
        });
    };
    sync_with_token(root, &token, subscribe, unsubscribe)
}
fn sync_with_token(
    root: &Path,
    token: &str,
    subscribe: Option<&str>,
    unsubscribe: Option<&str>,
) -> Result<SyncResult, String> {
    let feed = fetch_feed(token)?;
    let dir = account_dir(root, &feed.owner);
    let mut state = state(&dir, &feed.owner)?;
    if let Some(id) = unsubscribe {
        if !hex(id, 32) {
            return Err("Invalid Community mod ID.".into());
        }
        // Unsubscribe stops updates; keep the downloaded mod as the user's file.
        state.subscriptions.remove(id);
        save_state(&dir, &state)?;
    }
    let mut updated = Vec::new();
    let mut errors = Vec::new();
    for item in &feed.mods {
        let requested = subscribe == Some(item.id.as_str());
        if !requested && !state.subscriptions.contains_key(&item.id) {
            continue;
        }
        let current = state.subscriptions.get(&item.id);
        if let Some(previous) = current {
            let file = dir.join(&item.id).join(&previous.filename);
            if file.exists() {
                let bytes = fs::read(&file).map_err(|e| e.to_string())?;
                if format!("{:x}", Sha256::digest(&bytes)) != previous.sha256 {
                    errors.push(format!(
                        "{}: local file was edited; automatic replacement was skipped.",
                        item.title
                    ));
                    continue;
                }
                if previous.revision == item.revision && previous.sha256 == item.sha256 {
                    continue;
                }
            }
        }
        if !["it", "pack"].contains(&item.format.as_str()) {
            errors.push(format!(
                "{}: download this archive from the website; automatic sync supports IT/PACK mods.",
                item.title
            ));
            continue;
        }
        match install(token, &dir, item) {
            Ok(installed) => {
                let old = state
                    .subscriptions
                    .insert(item.id.clone(), installed.clone());
                save_state(&dir, &state)?;
                if let Some(old) = old {
                    if old.filename != installed.filename {
                        let _ = fs::remove_file(dir.join(&item.id).join(old.filename));
                    }
                }
                updated.push(item.title.clone());
            }
            Err(error) => errors.push(format!("{}: {error}", item.title)),
        }
    }
    if subscribe.is_some_and(|id| !feed.mods.iter().any(|m| m.id == id)) {
        return Err("Choose an approved mod from your account.".into());
    }
    Ok(SyncResult {
        connected: true,
        owner: feed.owner,
        mods: feed.mods,
        subscriptions: state.subscriptions,
        updated,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_private_download_metadata() {
        let mut item = CommunityMod {
            id: "a".repeat(32),
            revision: "b".repeat(32),
            title: "Fixture".into(),
            version: "1".into(),
            private: true,
            format: "it".into(),
            filename: "pmg-edit.it".into(),
            size: 123,
            sha256: "c".repeat(64),
            download: format!("/api/community/mods/{}/download", "b".repeat(32)),
        };
        assert!(validate_item(&item).is_ok());
        item.download = "https://other.invalid/package.it".into();
        assert!(validate_item(&item).is_err());
        item.download = format!("/api/community/mods/{}/download", "b".repeat(32));
        item.format = "../it".into();
        assert!(validate_item(&item).is_err());
        assert_ne!(
            account_dir(Path::new("mods"), "alice"),
            account_dir(Path::new("mods"), "bob")
        );
        for name in ["../evil.it", "con.it", "a\\b.it", "x.it.", "a:b.it"] {
            assert!(!valid_filename(name));
        }
    }
    #[test]
    fn preserves_previous_file_and_recovers_manifest() {
        let dir = std::env::temp_dir().join(format!("mabi-community-unit-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let old = dir.join("fixture.it");
        fs::write(&old, b"old bytes").unwrap();
        assert!(replace_file(&dir.join("missing.pending"), &old).is_err());
        assert_eq!(fs::read(&old).unwrap(), b"old bytes");
        let pending = dir.join("new.pending");
        fs::write(&pending, b"new verified bytes").unwrap();
        replace_file(&pending, &old).unwrap();
        assert_eq!(fs::read(&old).unwrap(), b"new verified bytes");
        let mut saved = State {
            owner: "alice".into(),
            ..State::default()
        };
        saved.subscriptions.insert(
            "a".repeat(32),
            Subscription {
                revision: "b".repeat(32),
                sha256: "c".repeat(64),
                filename: "pmg-edit.it".into(),
            },
        );
        save_state(&dir, &saved).unwrap();
        assert_eq!(state(&dir, "alice").unwrap().subscriptions.len(), 1);
        assert!(state(&dir, "bob").is_err());
        fs::rename(
            dir.join("subscriptions.json"),
            dir.join("subscriptions.previous"),
        )
        .unwrap();
        assert_eq!(state(&dir, "alice").unwrap().subscriptions.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn syncs_subscribed_revisions_and_preserves_local_files_on_failure() {
        use std::{
            io::Write,
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc, Mutex,
            },
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        TEST_ORIGIN
            .set(format!("http://{}", listener.local_addr().unwrap()))
            .unwrap();
        let data = Arc::new(Mutex::new((
            "b".repeat(32),
            b"old native archive".to_vec(),
            false,
            0usize,
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_data = data.clone();
        let thread_stop = stop.clone();
        let server = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request
                    .to_lowercase()
                    .contains("authorization: bearer fixture-token"));
                let mut state = thread_data.lock().unwrap();
                let bytes = if request.starts_with("GET /api/community/sync ") {
                    serde_json::to_vec(&serde_json::json!({"schema":1,"owner":"alice","mods":[{
                        "id":"a".repeat(32),"revision":state.0,"title":"Edited PMG","version":"1","private":true,"format":"it","filename":"pmg-edit.it",
                        "size":state.1.len(),"sha256":format!("{:x}",Sha256::digest(&state.1)),"download":format!("/api/community/mods/{}/download",state.0)
                    }]})).unwrap()
                } else {
                    state.3 += 1;
                    if state.2 {
                        vec![0; state.1.len()]
                    } else {
                        state.1.clone()
                    }
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(headers.as_bytes()).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let root =
            std::env::temp_dir().join(format!("mabi-community-network-{}", std::process::id()));
        let id = "a".repeat(32);
        let file = account_dir(&root, "alice").join(&id).join("pmg-edit.it");
        let result = sync_with_token(&root, "fixture-token", None, None).unwrap();
        assert!(result.updated.is_empty());
        assert!(!file.exists());
        let first = sync_with_token(&root, "fixture-token", Some(&id), None).unwrap();
        assert_eq!(first.updated.len(), 1);
        assert_eq!(fs::read(&file).unwrap(), b"old native archive");
        {
            let mut state = data.lock().unwrap();
            state.0 = "c".repeat(32);
            state.1 = b"new native archive".to_vec();
        }
        let next = sync_with_token(&root, "fixture-token", None, None).unwrap();
        assert_eq!(next.updated.len(), 1);
        assert_eq!(fs::read(&file).unwrap(), b"new native archive");
        {
            let mut state = data.lock().unwrap();
            state.0 = "d".repeat(32);
            state.1 = b"latest archive".to_vec();
            state.2 = true;
        }
        let failed = sync_with_token(&root, "fixture-token", None, None).unwrap();
        assert_eq!(failed.errors.len(), 1);
        assert_eq!(fs::read(&file).unwrap(), b"new native archive");
        assert_eq!(failed.subscriptions[&id].revision, "c".repeat(32));
        fs::write(&file, b"local edit").unwrap();
        let downloads = data.lock().unwrap().3;
        assert_eq!(
            sync_with_token(&root, "fixture-token", None, None)
                .unwrap()
                .errors
                .len(),
            1
        );
        assert_eq!(data.lock().unwrap().3, downloads);
        assert_eq!(fs::read(&file).unwrap(), b"local edit");
        let result = sync_with_token(&root, "fixture-token", None, Some(&id)).unwrap();
        assert!(result.subscriptions.is_empty());
        assert!(file.exists());
        assert!(sync_with_token(&root, "fixture-token", None, None)
            .unwrap()
            .updated
            .is_empty());
        assert_eq!(data.lock().unwrap().3, downloads);
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
