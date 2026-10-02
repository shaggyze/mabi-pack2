// Launcher CLI, shared by mabi-patcher.exe (GUI) and the CLI binary.
//
//   login [--profile N] [-u E -p P] [--client DIR]          -u/-p may come from MABI_EMAIL/MABI_PASSWORD
//   login-otp --mfa-key K --otp CODE [--profile N] [-u E] [--client DIR]
//   config [show | ignore add|remove PATTERN | hook EVENT [CMD]]
//   check-update [--profile N] [--game-path P]              exit 2 = update available
//   update [--profile N] [--game-path P] [--force-all|--verify] [--scan-only] [-j N] [--ignore PAT]...
//   launch [--profile N] [--client P] [-u E -p P] [--wait|--no-wait] [--version] [--manifest]
//   import-kanan [--file PATH] [--list]                      Kanan profiles.dat → profiles (prompts for master password)
//
// The game folder defaults to --game-path/--client, then the profile's folder,
// then an auto-detected install. `update` uses `patch::run_patcher` (branch-API
// manifest, SHA1-checked parts, repair, cancel) plus the ignore list and hooks
// from `config`.
//
// Exit codes: 0 = ok, 1 = error, 2 = update available.

use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use std::io::Write;

use super::{auth, config, cookies, detect, launch, news, patch, profile};

pub const NAMES: [&str; 9] =
    ["login", "login-otp", "config", "check-update", "update", "launch", "import-cookies", "news", "import-kanan"];

pub fn commands() -> Vec<Command<'static>> {
    let profile_arg = || Arg::new("profile").long("profile").value_name("NAME").help("Profile to use (default: active/first profile)");
    let game_path_arg = || {
        Arg::new("game-path")
            .long("game-path")
            .short('g')
            .alias("client")
            .short_alias('c')
            .value_name("PATH")
            .help("Install folder, appdata, patchdata or Client.exe (default: profile, then auto-detect)")
    };
    let product_id_arg = || {
        Arg::new("product-id")
            .long("product-id")
            .value_name("ID")
            .help("Nexon product id (default 10200 = Mabinogi)")
    };
    vec![
            Command::new("login")
                .about("Log in to Nexon NA (email/password) or refresh the profile's stored session")
                .arg(profile_arg())
                .arg(Arg::new("email").long("email").alias("username").short('u').value_name("EMAIL").help("Nexon account email (or set MABI_EMAIL)"))
                .arg(Arg::new("password").long("password").short('p').value_name("PASSWORD").help("Nexon account password (or set MABI_PASSWORD)"))
                .arg(Arg::new("client").long("client").short('c').value_name("DIR").help("Store this game folder (or Client.exe path) on the profile")),
            Command::new("login-otp")
                .about("Submit the MFA code after `login` printed an MFA key")
                .arg(profile_arg())
                .arg(Arg::new("mfa-key").long("mfa-key").value_name("KEY").required(true))
                .arg(Arg::new("otp").long("otp").value_name("CODE").required(true))
                .arg(Arg::new("email").long("email").alias("username").short('u').value_name("EMAIL").help("Account email, stored on a new profile"))
                .arg(Arg::new("client").long("client").short('c').value_name("DIR").help("Store this game folder (or Client.exe path) on the profile")),
            Command::new("config")
                .about("Patcher settings: update ignore list and event hooks")
                .subcommand(Command::new("show").about("Print the settings and where they are stored"))
                .subcommand(
                    Command::new("ignore")
                        .about("Add or remove a path/wildcard the patcher must never touch")
                        .arg(Arg::new("action").value_name("add|remove").required(true))
                        .arg(Arg::new("pattern").value_name("PATTERN").required(true)),
                )
                .subcommand(
                    Command::new("hook")
                        .about("Set a command run before/after patching or launching (%PROFILE% = profile name); omit CMD to clear")
                        .arg(Arg::new("event").value_name("before-patch|after-patch|before-launch|after-launch").required(true))
                        .arg(Arg::new("cmd").value_name("CMD")),
                ),
            Command::new("check-update")
                .about("Compare the installed game with the current Nexon manifest (exit 2 = update available)")
                .arg(profile_arg())
                .arg(game_path_arg())
                .arg(product_id_arg())
                .arg(Arg::new("folder").long("folder").value_name("PATH").action(ArgAction::Append).help("A game folder to check (repeatable; checks several installs)"))
                .arg(Arg::new("all-folders").long("all-folders").action(ArgAction::SetTrue).help("Check every auto-detected Mabinogi install")),
            Command::new("update")
                .about("Download and apply game updates from Nexon's CDN")
                .arg(profile_arg())
                .arg(game_path_arg())
                .arg(product_id_arg())
                .arg(Arg::new("force-all").long("force-all").action(ArgAction::SetTrue).conflicts_with("verify").help("Re-download every file"))
                .arg(Arg::new("verify").long("verify").action(ArgAction::SetTrue).help("Repair: also hash-check files whose size matches"))
                .arg(Arg::new("workers").long("workers").short('j').value_name("N").default_value("8").help("Parallel file downloads (max 32)"))
                .arg(Arg::new("ignore").long("ignore").value_name("PATTERN").action(ArgAction::Append).help("Wildcard path never touched (repeatable; added to `config ignore`)"))
                .arg(Arg::new("only").long("only").value_name("FILE").action(ArgAction::Append).help("Only update these manifest paths (repeatable allow-list)"))
                .arg(Arg::new("select").long("select").value_name("LIST_FILE").help("Read the allow-list of paths from a file (one per line)"))
                .arg(Arg::new("folder").long("folder").value_name("PATH").action(ArgAction::Append).help("A game folder to update (repeatable; updates several installs)"))
                .arg(Arg::new("all-folders").long("all-folders").action(ArgAction::SetTrue).help("Update every auto-detected Mabinogi install"))
                .arg(Arg::new("scan-only").long("scan-only").action(ArgAction::SetTrue).help("List files that need updating, don't download")),
            Command::new("launch")
                .about("Log in (if needed) and launch Mabinogi without the Nexon Launcher; waits for the game to exit unless --no-wait")
                .arg(profile_arg())
                .arg(Arg::new("username").short('u').long("username").alias("email").value_name("EMAIL").help("Nexon account email (or MABI_EMAIL; otherwise the profile session is used)"))
                .arg(Arg::new("password").short('p').long("password").value_name("PASSWORD").help("Nexon account password (or set MABI_PASSWORD)"))
                .arg(Arg::new("client").short('c').long("client").alias("game-path").value_name("PATH").help("Mabinogi folder or Client.exe (default: profile, then auto-detect)"))
                .arg(Arg::new("session-file").long("session-file").value_name("FILE").help("Use (and delete) a session JSON file — used by the Linux→Wine hand-off"))
                .arg(Arg::new("remember").long("remember").action(ArgAction::SetTrue).help("Save the session for auto-login (always done; kept for compatibility)"))
                .arg(Arg::new("wait").long("wait").action(ArgAction::SetTrue).conflicts_with("no-wait").help("Wait until the game exits (default)"))
                .arg(Arg::new("no-wait").long("no-wait").action(ArgAction::SetTrue).help("Return right after the game starts"))
                .arg(Arg::new("version").long("version").action(ArgAction::SetTrue).help("Print the latest game version and exit (no launch)"))
                .arg(Arg::new("manifest").long("manifest").action(ArgAction::SetTrue).help("Print the current manifest hash and exit (no launch)"))
                .arg(product_id_arg()),
            Command::new("import-cookies")
                .about("Import a Nexon session from your browsers (Firefox / Chrome / Edge / Brave) into a profile")
                .arg(profile_arg())
                .arg(Arg::new("client").long("client").short('c').value_name("DIR").help("Store this game folder on the profile")),
            Command::new("news")
                .about("Print the Nexon Mabinogi news feed (title, url, date, image)")
                .arg(product_id_arg()),
            super::kanan_import::command(),
    ]
}

/// Apply `--product-id` (if present) to the process-global product id.
fn apply_product_id(sub: &clap::ArgMatches) {
    if let Some(id) = sub.try_get_one::<String>("product-id").ok().flatten().and_then(|s| s.parse::<u32>().ok()) {
        auth::set_product_id(id);
    }
}

/// Run a launcher subcommand; returns the process exit code.
pub fn run(name: &str, sub: &clap::ArgMatches) -> Result<i32> {
    if name == "import-kanan" {
        return super::kanan_import::run_cli(sub);
    }
    run_launcher_cmd(name, sub)
}


fn find_profile(store: &profile::ProfileStore, name: Option<&String>) -> Option<profile::Profile> {
    match name {
        Some(n) => store.profiles.iter()
            .find(|p| p.name.eq_ignore_ascii_case(n) || p.id == *n || p.email.eq_ignore_ascii_case(n))
            .cloned(),
        None => store.active().cloned().or_else(|| store.profiles.first().cloned()),
    }
}

/// Which saved profile a fresh login belongs to.
///
/// With `--profile`, that profile (by name, id or email). Without it, match the
/// login's email, then its Nexon user id. A credentialed login never falls back to
/// the active profile, which may belong to another account. `None` = create one.
fn profile_for_login(
    store: &profile::ProfileStore,
    profile_name: Option<&String>,
    email: &str,
    hashed_user_id: &str,
) -> Option<profile::Profile> {
    if profile_name.is_some() {
        return find_profile(store, profile_name);
    }
    let by_email = || {
        (!email.is_empty())
            .then(|| store.profiles.iter().find(|p| p.email.eq_ignore_ascii_case(email)))
            .flatten()
    };
    let by_user = || {
        (!hashed_user_id.is_empty())
            .then(|| {
                store.profiles.iter().find(|p| {
                    p.session.as_ref().map(|s| s.hashed_user_id.as_str()) == Some(hashed_user_id)
                })
            })
            .flatten()
    };
    by_email().or_else(by_user).cloned()
}

/// Persist a fresh login's session on its profile (see [`profile_for_login`]),
/// creating the profile if none matches; the profile becomes the active one.
/// `client_dir`, when given, is stored as the profile's game folder.
pub fn store_session(
    profile_name: Option<&String>,
    email: &str,
    s: &auth::NexonSession,
    expires: i32,
    client_dir: Option<&String>,
) -> Result<profile::Profile> {
    let mut store = profile::ProfileStore::load()?;
    let mut p = profile_for_login(&store, profile_name, email, &s.hashed_user_id).unwrap_or_else(|| {
        let name = profile_name.cloned().unwrap_or_else(|| {
            if !email.is_empty() {
                email.to_string()
            } else if !s.hashed_user_id.is_empty() {
                format!("nexon-{}", s.hashed_user_id.chars().take(8).collect::<String>())
            } else {
                "nexon".to_string()
            }
        });
        profile::Profile::new(&name, email)
    });
    if !email.is_empty() && p.email.is_empty() {
        p.email = email.to_string();
    }
    if let Some(dir) = client_dir {
        p.client_dir = patch::GameRoots::resolve(dir).install_root.to_string_lossy().into_owned();
    }
    p.auto_login = true;
    let id = p.id.clone();
    store.upsert(p);
    store.active_id = id.clone();
    store.save()?;
    profile::save_session(&id, s, expires)?;
    profile::load_profile(&id)
}

/// Update an existing profile's session; uses the refresh expiry if one happened.
fn save_profile_session(p: &profile::Profile, s: &auth::NexonSession) {
    if let Err(e) = profile::save_session(&p.id, s, s.refreshed_expires_in.unwrap_or(0)) {
        log::warn!("Could not save the session to profile '{}': {}", p.name, e);
    }
}

fn password_arg(sub: &clap::ArgMatches) -> Option<String> {
    sub.get_one::<String>("password")
        .cloned()
        .or_else(|| env_nonempty("MABI_PASSWORD"))
}

/// Account email from `key` (-u), else `MABI_EMAIL` — the env fallback only applies
/// when a password is available too, so a bare `login`/`launch` still uses the profile.
fn email_arg(sub: &clap::ArgMatches, key: &str) -> Option<String> {
    sub.get_one::<String>(key)
        .cloned()
        .or_else(|| password_arg(sub).and_then(|_| env_nonempty("MABI_EMAIL")))
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Device-id tag for a fresh login: the target profile name, else the email.
/// Matches the name `store_session` gives a new profile (so its stored
/// `device_tag` and the login's deviceId agree). Empty → legacy machine id.
fn login_device_id(profile_name: Option<&String>, email: &str) -> String {
    let tag = profile_name.cloned().unwrap_or_else(|| email.to_string());
    auth::device_id(&tag)
}

/// The profile's session, refreshed if expired (email/password accounts).
pub fn profile_session(profile_name: Option<&String>) -> Result<(profile::Profile, auth::NexonSession)> {
    let store = profile::ProfileStore::load()?;
    let p = find_profile(&store, profile_name)
        .ok_or_else(|| anyhow::anyhow!("No profile found — run `login --email ... --password ...` first"))?;
    let mut s = p.session.clone().unwrap_or_default();
    // The top-level token is written by every save path (including the GUI's
    // update_session), so it is the newest NxLSession.
    if !p.session_token.is_empty() {
        s.session_token = p.session_token.clone();
    }
    // Refresh with this profile's device id (unless the stored session already
    // carries one). Legacy profiles have an empty tag → machine-only id.
    if s.device_id.is_empty() && !p.device_tag.is_empty() {
        s.device_id = p.device_id();
    }
    if s.session_token.is_empty() && s.access_token.is_empty() {
        return Err(anyhow::anyhow!("Profile '{}' has no session — log in first", p.name));
    }
    // A session already past its recorded expiry can't be refreshed: don't send it.
    if p.session_expired() {
        let who = if p.email.is_empty() { String::new() } else { format!(" -u {}", p.email) };
        return Err(anyhow::anyhow!(
            "The saved session of profile '{}' has expired — log in again: mabi-patcher login{} --password <PASSWORD> (or use the GUI login)",
            p.name, who
        ));
    }
    let status = if s.access_token.is_empty() { 401 } else { auth::check_session(&mut s).unwrap_or(0) };
    if status != 200 {
        let secs = auth::refresh_with_expiry(&mut s)?;
        if let Err(e) = profile::save_session(&p.id, &s, secs) {
            log::warn!("Could not save the refreshed session to profile '{}': {}", p.name, e);
        }
        s.refreshed_expires_in = None; // persisted
    }
    Ok((p, s))
}

fn print_login(
    r: Result<auth::LoginResult>,
    profile_name: Option<&String>,
    email: &str,
    client_dir: Option<&String>,
) -> Result<i32> {
    match r {
        Ok(res) => {
            let p = store_session(profile_name, email, &res.session, res.session_expires_in, client_dir)?;
            println!("Logged in. Session saved to profile '{}' (expires in {}s).", p.name, res.session_expires_in);
            Ok(0)
        }
        Err(e) => match e.downcast_ref::<auth::AuthError>() {
            Some(auth::AuthError::MfaRequired { mfa_key, mfa_type }) => {
                let who = if email.is_empty() { String::new() } else { format!(" -u {}", email) };
                println!("MFA required ({}). Run:\n  mabi-patcher login-otp{} --mfa-key {} --otp <CODE>", mfa_type, who, mfa_key);
                Ok(1)
            }
            Some(auth::AuthError::CaptchaRequired(_)) => {
                eprintln!("{} — log in once with the GUI browser login, then use the CLI.", e);
                Ok(1)
            }
            _ => Err(e),
        },
    }
}

/// Game folder: --game-path/--client, else the profile's, else an auto-detected install.
fn game_roots(sub: &clap::ArgMatches, p: Option<&profile::Profile>) -> Result<patch::GameRoots> {
    let path = sub.try_get_one::<String>("game-path").ok().flatten()
        .or_else(|| sub.try_get_one::<String>("client").ok().flatten())
        .cloned()
        .or_else(|| p.map(|p| p.client_dir.clone()).filter(|d| !d.is_empty()))
        .or_else(|| {
            let exe = detect::find_game_exe()?;
            log::info!("Found Mabinogi at {}", exe.display());
            Some(exe.to_string_lossy().into_owned())
        })
        .ok_or_else(|| anyhow::anyhow!("Mabinogi install not found; pass --game-path (or set the profile's game folder)"))?;
    Ok(patch::GameRoots::resolve(path))
}

fn cmd_config(sub: &clap::ArgMatches) -> Result<i32> {
    let mut cfg = config::Config::load()?;
    if let Some(m) = sub.subcommand_matches("ignore") {
        let pattern = m.get_one::<String>("pattern").unwrap().trim().to_string();
        match m.get_one::<String>("action").unwrap().as_str() {
            "add" => {
                if !cfg.ignore.iter().any(|p| p.eq_ignore_ascii_case(&pattern)) {
                    cfg.ignore.push(pattern);
                }
            }
            "remove" => cfg.ignore.retain(|p| !p.eq_ignore_ascii_case(&pattern)),
            other => return Err(anyhow::anyhow!("Unknown action '{}'; use add or remove", other)),
        }
        cfg.save()?;
    } else if let Some(m) = sub.subcommand_matches("hook") {
        let event = m.get_one::<String>("event").unwrap();
        *cfg.hooks.slot(event)? = m.get_one::<String>("cmd").cloned().unwrap_or_default();
        cfg.save()?;
    }
    println!("Settings: {}", config::Config::path().display());
    println!("{}", serde_json::to_string_pretty(&cfg)?);
    Ok(0)
}

fn run_launcher_cmd(name: &str, sub: &clap::ArgMatches) -> Result<i32> {
    let profile_name = sub.try_get_one::<String>("profile").ok().flatten();

    match name {
        "login" => {
            let email = email_arg(sub, "email");
            let client = sub.get_one::<String>("client");
            match (email, password_arg(sub)) {
                (Some(e), Some(pw)) => print_login(auth::login(&e, &pw, &login_device_id(profile_name, &e)), profile_name, &e, client),
                (None, None) => {
                    let (p, _) = profile_session(profile_name)?;
                    if let Some(dir) = client {
                        let mut store = profile::ProfileStore::load()?;
                        if let Some(sp) = store.get_mut(&p.id) {
                            sp.client_dir = patch::GameRoots::resolve(dir).install_root.to_string_lossy().into_owned();
                        }
                        store.save()?;
                    }
                    match profile::session_time_left(&profile::load_profile(&p.id).unwrap_or_else(|_| p.clone())) {
                        Some(left) => println!("Session for '{}' is valid ({} left).", p.name, left),
                        None => println!("Session for '{}' is valid.", p.name),
                    }
                    Ok(0)
                }
                (Some(_), None) => Err(anyhow::anyhow!("--password (or MABI_PASSWORD) is required with --email")),
                (None, Some(_)) => Err(anyhow::anyhow!("--email (or MABI_EMAIL) is required with --password")),
            }
        }
        "login-otp" => {
            let key = sub.get_one::<String>("mfa-key").unwrap();
            let otp = sub.get_one::<String>("otp").unwrap();
            // Only a real email (-u / MABI_EMAIL) — never the profile name.
            let email = sub.get_one::<String>("email").cloned().or_else(|| env_nonempty("MABI_EMAIL")).unwrap_or_default();
            print_login(
                auth::login_otp(key, otp, &login_device_id(profile_name, &email)),
                profile_name,
                &email,
                sub.get_one::<String>("client"),
            )
        }
        "config" => cmd_config(sub),
        "check-update" => {
            apply_product_id(sub);
            let (p, mut s) = profile_session(profile_name)?;
            // Multi-folder mode: --folder (repeatable) and/or --all-folders.
            let folders = collect_folders(sub, Some(&p));
            if !folders.is_empty() {
                let statuses = patch::check_folders(&folders, Some(&mut s));
                if s.refreshed_expires_in.is_some() { save_profile_session(&p, &s); }
                let mut any_update = false;
                for st in &statuses {
                    match (st.update_available, &st.error) {
                        (Some(true), _) => { any_update = true; println!("UPDATE  {}", st.path); }
                        (Some(false), _) => println!("OK      {}", st.path),
                        (None, Some(e)) => println!("ERROR   {}  ({})", st.path, e),
                        _ => {}
                    }
                }
                return Ok(if any_update { 2 } else { 0 });
            }
            let roots = game_roots(sub, Some(&p))?;
            let c = patch::check_update(&roots, Some(&mut s));
            if s.refreshed_expires_in.is_some() {
                save_profile_session(&p, &s);
            }
            let c = c?;
            println!("Game folder:     {}", roots.install_root.display());
            println!("Remote manifest: {}", c.remote_hash);
            println!("Local manifest:  {}", c.local_hash.as_deref().unwrap_or("(none)"));
            if c.update_available { println!("Update available."); Ok(2) } else { println!("Up to date."); Ok(0) }
        }
        "update" => {
            apply_product_id(sub);
            let (p, mut s) = profile_session(profile_name)?;
            let cfg = config::Config::load()?;
            let only = allow_list(sub)?;
            // Multi-folder: update each folder in turn. --only/--select apply to all.
            let folders = collect_folders(sub, Some(&p));
            if !folders.is_empty() {
                let mut code = 0;
                for folder in &folders {
                    let roots = patch::GameRoots::resolve(folder);
                    println!("== {} ==", roots.install_root.display());
                    let rc = run_update_one(sub, &cfg, &p, &mut s, &roots, only.clone())?;
                    if rc != 0 { code = rc; }
                }
                return Ok(code);
            }
            let roots = game_roots(sub, Some(&p))?;
            run_update_one(sub, &cfg, &p, &mut s, &roots, only)
        }
        "import-cookies" => {
            apply_product_id(sub);
            let dev = login_device_id(profile_name, "");
            let imp = cookies::import_from_browsers(&dev)?;
            if imp.v20_found {
                eprintln!("Note: Chrome 127+ app-bound (v20) cookies were found but can't be read outside the browser. Use the browser (SSO) login instead.");
            }
            for note in &imp.notes { log::info!("{}", note); }
            match imp.session {
                Some(session) => {
                    let email = String::new();
                    let p = store_session(profile_name, &email, &session,
                        session.refreshed_expires_in.unwrap_or(0), sub.get_one::<String>("client"))?;
                    println!("Imported a session from {} into profile '{}'.",
                        imp.browser.unwrap_or("a browser"), p.name);
                    Ok(0)
                }
                None => { eprintln!("No usable Nexon session found in your browsers."); Ok(1) }
            }
        }
        "news" => {
            apply_product_id(sub);
            let items = news::fetch_news()?;
            for n in &items {
                println!("[{}] {}\n  {}\n  {}", n.category, n.title, n.date, n.url);
            }
            println!("{} items.", items.len());
            Ok(0)
        }
        _ => run_launcher_cmd_rest(name, sub, profile_name),
    }
}

/// A single-folder update run (shared by `update` and its `--folder` loop).
fn run_update_one(
    sub: &clap::ArgMatches,
    cfg: &config::Config,
    p: &profile::Profile,
    s: &mut auth::NexonSession,
    roots: &patch::GameRoots,
    only: Option<Vec<String>>,
) -> Result<i32> {
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let workers: usize = sub.get_one::<String>("workers").map(|w| w.parse()).transpose()
        .map_err(|_| anyhow::anyhow!("--workers must be a number"))?.unwrap_or(8);
    let opts = patch::PatchOptions {
        mode: if sub.get_flag("force-all") { patch::PatchMode::ForceAll }
              else if sub.get_flag("verify") { patch::PatchMode::Verify }
              else { patch::PatchMode::Update },
        max_workers: workers.clamp(1, patch::MAX_WORKERS),
        ignore: sub.get_many::<String>("ignore")
            .map(|v| v.cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .chain(cfg.ignore.iter().cloned())
            .collect(),
        scan_only: sub.get_flag("scan-only"),
        manifest_hash: None,
        cancel,
        only,
        pause: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let on_event = |ev: patch::PatchEvent| match ev {
        patch::PatchEvent::Log { message } => println!("{}", message),
        patch::PatchEvent::Scan { done, total, need, .. } => {
            print!("\rScanning {}/{} — {} need update   ", done, total, need);
            let _ = std::io::stdout().flush();
        }
        patch::PatchEvent::Download { files_done, files_total, bytes, bytes_total, speed_bps, .. } => {
            print!("\r{}/{} files  {:.1}/{:.1} MB  {:.1} MB/s   ", files_done, files_total,
                bytes as f64 / 1048576.0, bytes_total as f64 / 1048576.0, speed_bps as f64 / 1048576.0);
            let _ = std::io::stdout().flush();
        }
        patch::PatchEvent::Worker { .. } => {}
    };
    if !opts.scan_only {
        launch::spawn_hook(&cfg.hooks.before_patch, &p.name, &roots.install_root);
    }
    let r = patch::run_patcher(roots, Some(s), &opts, &on_event);
    if s.refreshed_expires_in.is_some() {
        save_profile_session(p, s);
    }
    let r = r?;
    println!();
    if opts.scan_only {
        for n in &r.need { println!("{:>12}  {:<16} {}", n.size, n.reason, n.path); }
        return Ok(if r.need.is_empty() { 0 } else { 2 });
    }
    for e in &r.errors { eprintln!("  {}", e); }
    if r.needs_elevation { eprintln!("Permission denied — run as administrator."); }
    if r.errors.is_empty() && !r.cancelled {
        launch::spawn_hook(&cfg.hooks.after_patch, &p.name, &roots.install_root);
        Ok(0)
    } else {
        Ok(1)
    }
}

/// Build the update allow-list from `--only` (repeatable) and `--select` (a file
/// of paths, one per line). `None` = no allow-list (the normal full diff).
fn allow_list(sub: &clap::ArgMatches) -> Result<Option<Vec<String>>> {
    let mut list: Vec<String> = sub.get_many::<String>("only")
        .map(|v| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    if let Some(file) = sub.get_one::<String>("select") {
        let text = std::fs::read_to_string(file)
            .map_err(|e| anyhow::anyhow!("cannot read --select file {}: {}", file, e))?;
        for line in text.lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') { list.push(l.to_string()); }
        }
    }
    Ok(if list.is_empty() { None } else { Some(list) })
}

/// Folders to operate on from `--folder` (repeatable) and `--all-folders`.
/// Empty = single-folder mode (use `--game-path`/profile).
fn collect_folders(sub: &clap::ArgMatches, p: Option<&profile::Profile>) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = sub.get_many::<String>("folder")
        .map(|v| v.map(std::path::PathBuf::from).collect())
        .unwrap_or_default();
    if sub.get_flag("all-folders") {
        for exe in detect::find_all_game_exes() {
            if !out.contains(&exe) { out.push(exe); }
        }
    }
    let _ = p;
    out
}

fn run_launcher_cmd_rest(name: &str, sub: &clap::ArgMatches, profile_name: Option<&String>) -> Result<i32> {
    match name {
        "launch" => {
            let wait = !sub.get_flag("no-wait");
            apply_product_id(sub);
            if let Some(f) = sub.get_one::<String>("session-file") {
                return launch_from_session_file(sub, std::path::Path::new(f), wait);
            }
            let (p, mut s) = match email_arg(sub, "username") {
                Some(u) => {
                    let pw = password_arg(sub)
                        .ok_or_else(|| anyhow::anyhow!("--password (or MABI_PASSWORD) is required with --username"))?;
                    let res = auth::login(&u, &pw, &login_device_id(profile_name, &u))?;
                    let p = store_session(profile_name, &u, &res.session, res.session_expires_in, None)?;
                    (p, res.session)
                }
                None => profile_session(profile_name)?,
            };
            if sub.get_flag("manifest") {
                let hash = patch::remote_manifest_hash(Some(&mut s));
                if s.refreshed_expires_in.is_some() {
                    save_profile_session(&p, &s);
                }
                println!("{}", hash?);
                return Ok(0);
            }
            if sub.get_flag("version") {
                let (ver, refreshed) =
                    auth::with_session_retry(&mut s, |s| Ok(patch::fetch_manifest_once(s)?.version))?;
                if let Some(secs) = refreshed {
                    if let Err(e) = profile::save_session(&p.id, &s, secs) {
                        log::warn!("Could not save the refreshed session: {}", e);
                    }
                }
                println!("Latest Mabinogi version: {}", ver);
                return Ok(0);
            }
            let roots = game_roots(sub, Some(&p))?;
            let cfg = config::Config::load()?;
            launch::spawn_hook(&cfg.hooks.before_launch, &p.name, &roots.install_root);
            // Fires as soon as Client.exe has spawned, not when the game exits.
            let on_started = |info: &launch::LaunchInfo, _: &auth::NexonSession| {
                if info.patch_available {
                    println!("Note: a game patch is available (run `mabi-patcher update`).");
                }
                launch::spawn_hook(&cfg.hooks.after_launch, &p.name, &roots.install_root);
            };
            let info = launch::launch_official_with(&mut s, &roots.client_exe(), wait, &on_started);
            let secs = info.as_ref().ok().and_then(|i| i.session_expires_in).or(s.refreshed_expires_in).unwrap_or(0);
            if let Err(e) = profile::save_session(&p.id, &s, secs) {
                log::warn!("Could not save the session to profile '{}': {}", p.name, e);
            }
            let info = info?;
            println!("Launched {} (pid {}).", info.executable, info.pid);
            Ok(0)
        }
        _ => unreachable!(),
    }
}

/// Windows side of the Linux→Wine hand-off: launch with the session from `file`,
/// write the (possibly refreshed) session back to it and print the started marker
/// for the Linux side. The Linux side owns and deletes the file.
fn launch_from_session_file(sub: &clap::ArgMatches, file: &std::path::Path, wait: bool) -> Result<i32> {
    let mut s = launch::read_session_file(file)?;
    let client = sub.get_one::<String>("client")
        .ok_or_else(|| anyhow::anyhow!("--client is required with --session-file"))?;
    let on_started = |info: &launch::LaunchInfo, cur: &auth::NexonSession| {
        if let Err(e) = launch::write_session_file(file, cur) {
            eprintln!("Could not write the session back: {}", e);
        }
        println!("{}", launch::started_line(info));
        let _ = std::io::stdout().flush();
    };
    let res = launch::launch_official_with(&mut s, &patch::GameRoots::resolve(client).client_exe(), wait, &on_started);
    if let Err(e) = launch::write_session_file(file, &s) {
        eprintln!("Could not write the session back: {}", e);
    }
    let info = res?;
    println!("Launched {} (pid {}).", info.executable, info.pid);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> clap::ArgMatches {
        Command::new("mabi-patcher")
            .subcommand_required(true)
            .subcommands(commands())
            .try_get_matches_from(std::iter::once("mabi-patcher").chain(args.iter().copied()))
            .unwrap_or_else(|e| panic!("{:?} failed to parse: {}", args, e))
    }

    #[test]
    fn every_command_and_flag_parses() {
        for name in NAMES {
            assert!(commands().iter().any(|c| c.get_name() == name), "missing command {}", name);
        }
        parse(&["login", "-u", "a@b.c", "-p", "pw", "--profile", "main", "-c", "/games/mabi"]);
        parse(&["login", "--email", "a@b.c", "--password", "pw"]);
        parse(&["login-otp", "--mfa-key", "K", "--otp", "123456", "-u", "a@b.c", "--client", "/g"]);
        parse(&["config", "show"]);
        parse(&["config", "ignore", "add", "mods/*"]);
        parse(&["config", "hook", "before-launch", "echo %PROFILE%"]);
        parse(&["check-update", "--client", "/g", "--profile", "main"]);
        parse(&["check-update", "-g", "/g"]);
        parse(&["update", "-c", "/g", "--force-all", "--scan-only", "-j", "4", "--ignore", "a", "--ignore", "b"]);
        parse(&["update", "--game-path", "/g", "--verify", "--workers", "16"]);
        parse(&["launch", "-u", "a@b.c", "-p", "pw", "-c", "/g", "--remember", "--version", "--wait"]);
        parse(&["launch", "--profile", "main", "--game-path", "/g", "--no-wait", "--manifest"]);
        parse(&["launch", "--session-file", "/tmp/s.json", "--client", "/g"]);
        parse(&["import-kanan", "--file", "C:/Kanan/profiles.dat", "--list"]);

        let m = parse(&["update", "--ignore", "x", "--ignore", "y"]);
        let (_, sub) = m.subcommand().unwrap();
        assert_eq!(sub.get_many::<String>("ignore").unwrap().count(), 2);
    }

    fn store_with(profiles: &[(&str, &str, &str)]) -> profile::ProfileStore {
        let mut store = profile::ProfileStore::default();
        for (name, email, user) in profiles {
            let mut p = profile::Profile::new(name, email);
            p.session = Some(auth::NexonSession { hashed_user_id: user.to_string(), ..Default::default() });
            store.upsert(p);
        }
        store
    }

    #[test]
    fn credentialed_login_never_lands_on_another_accounts_profile() {
        let mut store = store_with(&[("A", "a@x.com", "userA"), ("B", "b@x.com", "userB")]);
        store.active_id = store.profiles[0].id.clone(); // A is active
        let pick = |p: Option<&str>, email: &str, user: &str| {
            profile_for_login(&store, p.map(String::from).as_ref(), email, user).map(|p| p.name)
        };
        // Account B logs in without --profile: B's profile, not the active A.
        assert_eq!(pick(None, "B@x.com", ""), Some("B".into()));
        // Unknown account: a new profile, never the active one.
        assert_eq!(pick(None, "c@x.com", "userC"), None);
        // No email (login-otp without -u): matched by Nexon user id, else new.
        assert_eq!(pick(None, "", "userB"), Some("B".into()));
        assert_eq!(pick(None, "", ""), None);
        // An explicit --profile wins.
        assert_eq!(pick(Some("A"), "b@x.com", "userB"), Some("A".into()));
        assert_eq!(pick(Some("new"), "b@x.com", "userB"), None);
    }

    #[test]
    fn conflicting_flags_are_rejected() {
        let cmd = || Command::new("mabi-patcher").subcommands(commands());
        assert!(cmd().try_get_matches_from(["x", "launch", "--wait", "--no-wait"]).is_err());
        assert!(cmd().try_get_matches_from(["x", "update", "--force-all", "--verify"]).is_err());
        assert!(cmd().try_get_matches_from(["x", "login-otp", "--otp", "1"]).is_err());
    }
}
