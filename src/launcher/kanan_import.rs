// Import saved accounts from the Kanan launcher's `profiles.dat`, the way a
// browser imports saved passwords from another browser.
//
// File format (Kanan Launcher, LauncherApp.cpp `saveProfiles` + Crypto.cpp):
//
//   key        = SHA-256(master password bytes)            (no salt, no iterations)
//   cipher     = AES-256-GCM (Windows CNG), 12-byte random nonce,
//                12-byte tag (Kanan uses BCRYPT_AUTH_TAG_LENGTH.dwMinLength,
//                which is 12 for GCM; 16-byte tags are accepted too),
//                AAD = the nonce itself
//   file       = nonce (12) || tag (12) || ciphertext
//   plaintext  = UTF-8 JSON followed by one NUL byte:
//                { "version": 1, "clientPath": "...\\Client.exe",
//                  "profiles": [ { "username", "password", "cmdLine",
//                                  "launchWithKanan" }, ... ] }
//                (`profiles` is `null` when the user saved no accounts.)
//
// mabi-patcher never stores account passwords: only Nexon sessions (in the OS
// keychain via `ProfileStore`). So an import creates/reuses a profile for
// each account and performs a normal email/password login with that
// profile's own device id; the resulting session is what gets saved. When
// Nexon asks for MFA the caller finishes it with [`complete_mfa`].
//
// The master password and decrypted credentials are never logged, printed or
// written anywhere; plaintext buffers are wiped after use (best effort).

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes256;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::{auth, profile};

const NONCE_LEN: usize = 12;
/// GCM tag length Kanan writes (CNG's minimum GCM tag size).
const TAG_LEN: usize = 12;
/// `LauncherApp::PROFILES_VERSION` in Kanan.
pub const KANAN_PROFILES_VERSION: i64 = 1;
/// File name Kanan writes into its working directory.
pub const PROFILES_FILE: &str = "profiles.dat";

const WRONG_PASSWORD: &str = "Wrong master password or unsupported file (Kanan profiles.dat could not be decrypted)";

// ── Secret hygiene ───────────────────────────────────────────────────────────

/// Overwrite a buffer with zeros in a way the optimiser won't elide.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Wipe and clear a string holding a secret.
pub fn wipe_string(s: &mut String) {
    // SAFETY: writing zero bytes keeps the string valid UTF-8.
    wipe(unsafe { s.as_bytes_mut() });
    s.clear();
}

// ── Model ────────────────────────────────────────────────────────────────────

/// One saved Kanan account. The password is wiped on drop and never shown by
/// `Debug`.
pub struct ImportedAccount {
    /// Nexon account email (Kanan's "username").
    pub username: String,
    /// Nexon account password.
    pub password: String,
    /// Extra client command line saved in Kanan (informational).
    pub cmd_line: String,
    /// Kanan's "launch with Kanan" checkbox (informational).
    pub launch_with_kanan: bool,
    /// Kanan's global Client.exe path (shared by all its accounts).
    pub client_path: String,
}

impl std::fmt::Debug for ImportedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedAccount")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("cmd_line", &self.cmd_line)
            .field("launch_with_kanan", &self.launch_with_kanan)
            .field("client_path", &self.client_path)
            .finish()
    }
}

impl Drop for ImportedAccount {
    fn drop(&mut self) {
        wipe_string(&mut self.password);
    }
}

#[derive(Deserialize)]
struct RawSave {
    version: i64,
    #[serde(rename = "clientPath", default)]
    client_path: Option<String>,
    #[serde(default)]
    profiles: Option<Vec<RawProfile>>,
}

#[derive(Deserialize)]
struct RawProfile {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(rename = "cmdLine", default)]
    cmd_line: String,
    #[serde(rename = "launchWithKanan", default)]
    launch_with_kanan: bool,
}

impl Drop for RawProfile {
    fn drop(&mut self) {
        wipe_string(&mut self.password);
    }
}

// ── Decrypt + parse ──────────────────────────────────────────────────────────

/// AES-256-GCM with a 12-byte tag: Kanan passes `BCRYPT_AUTH_TAG_LENGTH`'s
/// `dwMinLength` as the tag size, which Windows CNG reports as 12 for GCM.
type KananGcm = aes_gcm::AesGcm<Aes256, U12, U12>;
/// Full-length-tag variant, tried as a fallback for files from builds or
/// ports that used a 16-byte tag.
type KananGcm16 = aes_gcm::AesGcm<Aes256, U12, U16>;

/// SHA-256 of the master password (Kanan's whole KDF). Wipe after use.
fn derive_key(master_password: &str) -> [u8; 32] {
    Sha256::digest(master_password.as_bytes()).into()
}

/// Open `nonce || tag(tag_len) || ct` with AAD = nonce.
fn open<C: Aead + KeyInit>(key: &[u8], data: &[u8], tag_len: usize) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN + tag_len {
        return None;
    }
    let (nonce, rest) = data.split_at(NONCE_LEN);
    let (tag, ct) = rest.split_at(tag_len);
    // Kanan stores the tag before the ciphertext; RustCrypto expects ct || tag.
    let mut sealed = Vec::with_capacity(ct.len() + tag_len);
    sealed.extend_from_slice(ct);
    sealed.extend_from_slice(tag);
    let n = aes_gcm::aead::Nonce::<C>::try_from(nonce).ok()?;
    C::new_from_slice(key).ok()?.decrypt(&n, Payload { msg: &sealed, aad: nonce }).ok()
}

/// Decrypt a Kanan `profiles.dat` blob into its JSON plaintext (trailing NUL
/// removed). A GCM tag failure means a wrong password or a foreign file.
fn decrypt(data: &[u8], master_password: &str) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!("Not a Kanan profiles.dat (file is too small: {} bytes)", data.len()));
    }
    let mut key = derive_key(master_password);
    let plain = open::<KananGcm>(&key, data, TAG_LEN).or_else(|| open::<KananGcm16>(&key, data, 16));
    wipe(&mut key);
    let mut plain = plain.ok_or_else(|| anyhow!(WRONG_PASSWORD))?;
    while plain.last() == Some(&0) {
        plain.pop();
    }
    Ok(plain)
}

/// Decrypt and parse a Kanan `profiles.dat` with the user's master password.
/// Accounts with an empty username are skipped (Kanan's blank editor row).
pub fn parse_profiles(data: &[u8], master_password: &str) -> Result<Vec<ImportedAccount>> {
    let mut plain = decrypt(data, master_password)?;
    let parsed = serde_json::from_slice::<RawSave>(&plain);
    wipe(&mut plain);
    let save = parsed.map_err(|e| {
        // serde errors carry only a position, never the offending value.
        anyhow!("Decrypted profiles.dat is not in Kanan's format (line {}, column {})", e.line(), e.column())
    })?;
    if save.version != KANAN_PROFILES_VERSION {
        log::warn!("[Kanan import] profiles.dat version {} (expected {}); reading it anyway", save.version, KANAN_PROFILES_VERSION);
    }
    let client_path = save.client_path.unwrap_or_default();
    let mut out = Vec::new();
    for mut raw in save.profiles.unwrap_or_default() {
        let username = raw.username.trim().to_string();
        if username.is_empty() {
            continue;
        }
        out.push(ImportedAccount {
            username,
            password: std::mem::take(&mut raw.password),
            cmd_line: std::mem::take(&mut raw.cmd_line),
            launch_with_kanan: raw.launch_with_kanan,
            client_path: client_path.clone(),
        });
    }
    Ok(out)
}

/// Read and parse a profiles.dat file.
pub fn read_profiles(path: &Path, master_password: &str) -> Result<Vec<ImportedAccount>> {
    let data = std::fs::read(path).map_err(|e| anyhow!("Cannot read {}: {}", path.display(), e))?;
    parse_profiles(&data, master_password)
}

// ── File location ────────────────────────────────────────────────────────────

/// Where Kanan's profiles.dat usually is: Kanan writes it into its working
/// directory, i.e. next to its `Launcher.exe`. Returns the first existing
/// candidate (current directory, then this program's folder).
pub fn default_path() -> Option<PathBuf> {
    candidate_paths().into_iter().find(|p| p.is_file())
}

/// Where Kanan's `profiles.dat` can live. Kanan opens a bare `profiles.dat` in its
/// working directory (LauncherApp.cpp), i.e. beside its `Launcher.exe`, and keeps
/// no registry key, so check the folders Kanan is installed into:
///   - `<Mabinogi>\Kanan\` (the uotiara installer's `$INSTDIR\Kanan`)
///   - `<Mabinogi>\Tiara's Moonshine Mod\Tools\Kanan\` and the same under a
///     `Documents\GitHub\uotiara` checkout
///   - this process's working directory and exe folder
pub fn candidate_paths() -> Vec<PathBuf> {
    const KANAN_SUBDIRS: [&str; 2] = ["Kanan", r"Tiara's Moonshine Mod\Tools\Kanan"];
    let mut dirs: Vec<PathBuf> = Vec::new();
    for game in game_dirs() {
        for sub in KANAN_SUBDIRS {
            dirs.push(game.join(sub));
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        dirs.push(PathBuf::from(home).join(r"Documents\GitHub\uotiara").join(KANAN_SUBDIRS[1]));
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        dirs.push(dir);
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for d in dirs {
        let p = d.join(PROFILES_FILE);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Mabinogi install folders: `HKCU\Software\Nexon\Mabinogi` (default value, the
/// key uotiara's installer reads) and the Nexon Launcher default path.
pub fn game_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Nexon\Mabinogi") {
            if let Ok(dir) = key.get_value::<String, _>("") {
                if !dir.trim().is_empty() {
                    dirs.push(PathBuf::from(dir.trim()));
                }
            }
        }
    }
    let nexon_default = PathBuf::from(r"C:\Nexon\Library\mabinogi\appdata");
    if !dirs.contains(&nexon_default) {
        dirs.push(nexon_default);
    }
    dirs
}

/// Resolve a user-given path: a folder (Kanan's install dir) or
/// `Launcher.exe` means the `profiles.dat` inside it; none = [`default_path`].
pub fn resolve_path(explicit: Option<&Path>) -> Result<PathBuf> {
    match explicit {
        Some(p) if p.is_dir() => Ok(p.join(PROFILES_FILE)),
        Some(p) if p.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false) => {
            Ok(p.parent().unwrap_or(Path::new(".")).join(PROFILES_FILE))
        }
        Some(p) => Ok(p.to_path_buf()),
        None => default_path().ok_or_else(|| {
            anyhow!("Kanan profiles.dat not found here; pass its path (it is next to Kanan's Launcher.exe)")
        }),
    }
}

// ── Import into mabi-patcher profiles ────────────────────────────────────────

/// Result of importing one account.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ImportStatus {
    /// Logged in; the session is saved on the profile.
    LoggedIn { expires_in: i32 },
    /// Nexon wants a one-time code: call [`complete_mfa`].
    MfaRequired { mfa_key: String, mfa_type: String },
    /// Login failed; the profile was still created (log in to it later).
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportOutcome {
    pub username: String,
    pub profile_id: String,
    pub profile_name: String,
    #[serde(flatten)]
    pub status: ImportStatus,
}

/// Game folder from Kanan's Client.exe path (empty when unknown).
fn client_dir_from(client_path: &str) -> String {
    let p = client_path.trim().trim_end_matches('\0');
    if p.is_empty() {
        return String::new();
    }
    // Kanan saves a Windows path; split on either separator so this also
    // works when parsing on another OS.
    if p.to_ascii_lowercase().ends_with(".exe") {
        p.rfind(['\\', '/']).map(|i| p[..i].to_string()).unwrap_or_default()
    } else {
        p.to_string()
    }
}

/// Where an imported account came from: sets the new profile's `profile_type`
/// and the label used in names and messages.
#[derive(Debug, Clone, Copy)]
pub enum ImportSource {
    Kanan,
    Hyddwn,
}

impl ImportSource {
    pub fn profile_type(self) -> &'static str {
        match self {
            ImportSource::Kanan => "kanan",
            ImportSource::Hyddwn => "hyddwn",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ImportSource::Kanan => "Kanan",
            ImportSource::Hyddwn => "Hyddwn Launcher",
        }
    }
}

/// The profile an account imports into: an existing profile with the same
/// email (case-insensitive), else a new profile of `source`'s type named after it.
fn profile_for_import(store: &profile::ProfileStore, acct: &ImportedAccount, source: ImportSource) -> profile::Profile {
    if let Some(p) = store.profiles.iter().find(|p| p.email.eq_ignore_ascii_case(&acct.username)) {
        let mut p = p.clone();
        if p.client_dir.is_empty() {
            p.client_dir = client_dir_from(&acct.client_path);
        }
        return p;
    }
    let mut name = acct.username.clone();
    if store.profiles.iter().any(|p| p.name == name) {
        name = format!("{} ({})", acct.username, source.label());
    }
    let mut p = profile::Profile::new(&name, &acct.username);
    p.profile_type = source.profile_type().to_string();
    p.client_dir = client_dir_from(&acct.client_path);
    p.auto_login = true;
    p
}

/// Create (or reuse) the account's profile, log in with its device id and
/// save the session. The password is used only for this login request.
pub fn import_account(acct: &ImportedAccount) -> Result<ImportOutcome> {
    import_account_from(acct, ImportSource::Kanan)
}

/// [`import_account`] for accounts read from another launcher (`source`).
pub fn import_account_from(acct: &ImportedAccount, source: ImportSource) -> Result<ImportOutcome> {
    let mut store = profile::ProfileStore::load()?;
    let p = profile_for_import(&store, acct, source);
    let (id, name, device_id) = (p.id.clone(), p.name.clone(), p.device_id());
    store.upsert(p);
    store.save()?;

    let status = if acct.password.is_empty() {
        ImportStatus::Failed { error: format!("No password saved in {} for this account", source.label()) }
    } else {
        match auth::login(&acct.username, &acct.password, &device_id) {
            Ok(res) => {
                profile::save_session(&id, &res.session, res.session_expires_in)?;
                ImportStatus::LoggedIn { expires_in: res.session_expires_in }
            }
            Err(e) => match e.downcast_ref::<auth::AuthError>() {
                Some(auth::AuthError::MfaRequired { mfa_key, mfa_type }) => {
                    ImportStatus::MfaRequired { mfa_key: mfa_key.clone(), mfa_type: mfa_type.clone() }
                }
                _ => ImportStatus::Failed { error: e.to_string() },
            },
        }
    };
    Ok(ImportOutcome { username: acct.username.clone(), profile_id: id, profile_name: name, status })
}

/// Finish an MFA challenge from [`import_account`] and save the session.
/// Returns the session lifetime in seconds.
pub fn complete_mfa(profile_id: &str, mfa_key: &str, otp: &str) -> Result<i32> {
    let p = profile::load_profile(profile_id)?;
    let res = auth::login_otp(mfa_key, otp.trim(), &p.device_id())?;
    profile::save_session(profile_id, &res.session, res.session_expires_in)?;
    Ok(res.session_expires_in)
}

// ── CLI ──────────────────────────────────────────────────────────────────────

/// `import-kanan` subcommand definition.
pub fn command() -> clap::Command<'static> {
    clap::Command::new("import-kanan")
        .about("Import saved accounts from Kanan's profiles.dat (asks for the Kanan master password; set MABI_KANAN_PASSWORD to skip the prompt)")
        .arg(clap::Arg::new("file").long("file").short('f').value_name("PATH").help("profiles.dat, or Kanan's folder (default: ./profiles.dat)"))
        .arg(clap::Arg::new("list").long("list").action(clap::ArgAction::SetTrue).help("Only list the accounts found; import nothing"))
}

/// Read a line from the terminal without echoing it.
fn read_hidden(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let r = {
        // Echo comes back when this guard drops (any return path, a panic, and on
        // Windows a Ctrl-C too, through the console control handler).
        let _echo = EchoGuard::new();
        std::io::stdin().lock().read_line(&mut line)
    };
    eprintln!();
    r?;
    let trimmed_len = line.trim_end_matches(['\r', '\n']).len();
    // Shorten in place so the secret isn't copied into a new allocation.
    // SAFETY: zeroing then truncating keeps the string valid UTF-8.
    wipe(unsafe { &mut line.as_bytes_mut()[trimmed_len..] });
    line.truncate(trimmed_len);
    Ok(line)
}

/// Terminal echo turned off for its lifetime; restored on drop.
struct EchoGuard(Option<u32>);

impl EchoGuard {
    fn new() -> Self {
        EchoGuard(echo_off())
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        restore_echo(self.0.take());
    }
}

/// Console mode to restore if Ctrl-C ends the process while echo is off
/// (`u32::MAX` holds nothing to restore). Drop guards don't run on that exit.
#[cfg(windows)]
static SAVED_CONSOLE_MODE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);

#[cfg(windows)]
unsafe extern "system" fn restore_on_ctrl(_ctrl: u32) -> i32 {
    use winapi::um::consoleapi::SetConsoleMode;
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_INPUT_HANDLE;
    let mode = SAVED_CONSOLE_MODE.swap(u32::MAX, std::sync::atomic::Ordering::SeqCst);
    if mode != u32::MAX {
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
    }
    0 // not handled: the default handler still ends the process
}

#[cfg(windows)]
fn echo_off() -> Option<u32> {
    use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_INPUT_HANDLE;
    use winapi::um::wincon::ENABLE_ECHO_INPUT;
    // SAFETY: plain Win32 console calls on the process's stdin handle.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) == 0 {
            return None; // not a console (piped input)
        }
        SAVED_CONSOLE_MODE.store(mode, std::sync::atomic::Ordering::SeqCst);
        winapi::um::consoleapi::SetConsoleCtrlHandler(Some(restore_on_ctrl), 1);
        SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        Some(mode)
    }
}

#[cfg(windows)]
fn restore_echo(saved: Option<u32>) {
    use winapi::um::consoleapi::SetConsoleMode;
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_INPUT_HANDLE;
    if let Some(mode) = saved {
        SAVED_CONSOLE_MODE.store(u32::MAX, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: restores the mode read in `echo_off`; unregisters its Ctrl-C handler.
        unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
            winapi::um::consoleapi::SetConsoleCtrlHandler(Some(restore_on_ctrl), 0);
        }
    }
}

#[cfg(not(windows))]
fn echo_off() -> Option<u32> {
    let ok = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(1)
}

#[cfg(not(windows))]
fn restore_echo(saved: Option<u32>) {
    if saved.is_some() {
        let _ = std::process::Command::new("stty").arg("echo").stdin(std::process::Stdio::inherit()).status();
    }
}

fn read_line(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Run `import-kanan`; returns the process exit code (1 if any account failed).
pub fn run_cli(sub: &clap::ArgMatches) -> Result<i32> {
    let path = resolve_path(sub.get_one::<String>("file").map(Path::new))?;
    let mut master = match std::env::var("MABI_KANAN_PASSWORD") {
        Ok(v) if !v.is_empty() => v,
        _ => read_hidden(&format!("Kanan master password for {}: ", path.display()))?,
    };
    let parsed = read_profiles(&path, &master);
    wipe_string(&mut master);
    let accounts = parsed?;
    println!("Found {} account(s) in {}:", accounts.len(), path.display());
    for a in &accounts {
        println!("  {}", a.username);
    }
    if sub.get_flag("list") || accounts.is_empty() {
        return Ok(0);
    }
    let mut failed = 0;
    for a in &accounts {
        let out = import_account(a)?;
        let mut status = out.status.clone();
        if let ImportStatus::MfaRequired { mfa_key, mfa_type } = &out.status {
            let otp = read_line(&format!("Nexon sent a {} code for {}. Enter it: ", mfa_type, out.username))?;
            status = match complete_mfa(&out.profile_id, mfa_key, &otp) {
                Ok(expires_in) => ImportStatus::LoggedIn { expires_in },
                Err(e) => ImportStatus::Failed { error: e.to_string() },
            };
        }
        match status {
            ImportStatus::LoggedIn { .. } => println!("Imported {} -> profile '{}' (logged in)", out.username, out.profile_name),
            ImportStatus::Failed { error } => {
                failed += 1;
                println!("Imported {} -> profile '{}' (login failed: {}; log in to it later)", out.username, out.profile_name, error);
            }
            ImportStatus::MfaRequired { .. } => unreachable!("handled above"),
        }
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt like Kanan's `encryptString`: JSON + NUL, nonce || tag || ct.
    fn seal<C: Aead + KeyInit>(password: &str, json: &str, nonce: [u8; 12]) -> Vec<u8> {
        let mut plain = json.as_bytes().to_vec();
        plain.push(0);
        let n = aes_gcm::aead::Nonce::<C>::try_from(&nonce[..]).unwrap();
        let sealed = C::new_from_slice(&derive_key(password)).unwrap().encrypt(&n, Payload { msg: &plain, aad: &nonce }).unwrap();
        let tag_len = sealed.len() - plain.len();
        let (ct, tag) = sealed.split_at(sealed.len() - tag_len);
        let mut out = nonce.to_vec();
        out.extend_from_slice(tag);
        out.extend_from_slice(ct);
        out
    }

    fn kanan_encrypt(password: &str, json: &str, nonce: [u8; 12]) -> Vec<u8> {
        seal::<KananGcm>(password, json, nonce)
    }

    #[test]
    fn layout_and_sixteen_byte_tag_fallback() {
        let data = kanan_encrypt("m", "{}", [9; 12]);
        assert_eq!(data.len(), 12 + 12 + 3); // nonce + 12-byte tag + "{}\0"
        let data16 = seal::<KananGcm16>("m", SAMPLE, [9; 12]);
        assert_eq!(parse_profiles(&data16, "m").unwrap().len(), 2);
        assert!(parse_profiles(&data16, "x").unwrap_err().to_string().contains("Wrong master password"));
    }

    const SAMPLE: &str = r#"{"clientPath":"C:\\Nexon\\Mabinogi\\Client.exe","profiles":[
        {"cmdLine":"","launchWithKanan":true,"password":"hunter2","username":"alice@example.com"},
        {"cmdLine":"-x","launchWithKanan":false,"password":"pw2","username":"bob@example.com"}],
        "version":1}"#;

    #[test]
    fn round_trip() {
        let data = kanan_encrypt("master pw", SAMPLE, [7; 12]);
        let accts = parse_profiles(&data, "master pw").unwrap();
        assert_eq!(accts.len(), 2);
        assert_eq!(accts[0].username, "alice@example.com");
        assert_eq!(accts[0].password, "hunter2");
        assert!(accts[0].launch_with_kanan);
        assert_eq!(accts[1].cmd_line, "-x");
        assert_eq!(accts[1].client_path, r"C:\Nexon\Mabinogi\Client.exe");
        assert!(!format!("{:?}", accts[0]).contains("hunter2"));
    }

    #[test]
    fn null_profiles_and_blank_rows() {
        let data = kanan_encrypt("m", r#"{"clientPath":"","profiles":null,"version":1}"#, [1; 12]);
        assert!(parse_profiles(&data, "m").unwrap().is_empty());
        let data = kanan_encrypt("m", r#"{"clientPath":"","profiles":[{"username":"","password":"x"}],"version":1}"#, [2; 12]);
        assert!(parse_profiles(&data, "m").unwrap().is_empty());
    }

    #[test]
    fn wrong_password() {
        let data = kanan_encrypt("right", SAMPLE, [3; 12]);
        let err = parse_profiles(&data, "wrong").unwrap_err().to_string();
        assert!(err.contains("Wrong master password"), "{}", err);
        assert!(!err.contains("hunter2"));
    }

    #[test]
    fn tampered_or_truncated_file() {
        let mut data = kanan_encrypt("m", SAMPLE, [4; 12]);
        // Truncated ciphertext fails authentication.
        let cut = &data[..data.len() - 5];
        assert!(parse_profiles(cut, "m").unwrap_err().to_string().contains("Wrong master password"));
        // Shorter than the header.
        assert!(parse_profiles(&data[..NONCE_LEN + TAG_LEN - 1], "m").unwrap_err().to_string().contains("too small"));
        assert!(parse_profiles(&[], "m").is_err());
        // Modified nonce (it is also the AAD) fails authentication.
        data[0] ^= 1;
        assert!(parse_profiles(&data, "m").unwrap_err().to_string().contains("Wrong master password"));
    }

    #[test]
    fn not_kanan_json() {
        let data = kanan_encrypt("m", r#"{"hello":"world"}"#, [5; 12]);
        let err = parse_profiles(&data, "m").unwrap_err().to_string();
        assert!(err.contains("not in Kanan's format"), "{}", err);
    }

    #[test]
    fn import_target_profile() {
        let acct = ImportedAccount {
            username: "Alice@Example.com".into(),
            password: "x".into(),
            cmd_line: String::new(),
            launch_with_kanan: false,
            client_path: r"C:\Mabi\Client.exe".into(),
        };
        let mut store = profile::ProfileStore::default();
        let p = profile_for_import(&store, &acct, ImportSource::Kanan);
        assert_eq!(p.profile_type, "kanan");
        assert_eq!(p.email, "Alice@Example.com");
        assert!(p.client_dir.ends_with("Mabi"));
        // Same email already present → reused (case-insensitive).
        let existing = profile::Profile::new("main", "alice@example.com");
        let id = existing.id.clone();
        store.upsert(existing);
        assert_eq!(profile_for_import(&store, &acct, ImportSource::Kanan).id, id);
        // A name clash with another account gets a suffix.
        let mut store = profile::ProfileStore::default();
        store.upsert(profile::Profile::new("Alice@Example.com", "other@example.com"));
        assert_eq!(profile_for_import(&store, &acct, ImportSource::Kanan).name, "Alice@Example.com (Kanan)");
    }

    #[test]
    fn resolve_paths() {
        let dir = std::env::temp_dir();
        assert_eq!(resolve_path(Some(&dir)).unwrap(), dir.join(PROFILES_FILE));
        let exe = Path::new("/kanan/Launcher.exe");
        assert_eq!(resolve_path(Some(exe)).unwrap(), Path::new("/kanan").join(PROFILES_FILE));
        let f = Path::new("/x/profiles.dat");
        assert_eq!(resolve_path(Some(f)).unwrap(), f);
    }
}
