// Rua-compatible launcher CLI, shared by mabi-patcher.exe (GUI) and the CLI binary.
//
//   login [--profile N] [--email E --password P]
//   login-otp --mfa-key K --otp CODE [--profile N]
//   check-update [--profile N] [--game-path P]        exit 2 = update available
//   update [--profile N] [--game-path P] [--force-all|--verify] [-j N] [--ignore PAT]...
//   launch [--profile N] [--client P] [-u E -p P] [--no-wait]
//
// Exit codes: 0 = ok, 1 = error, 2 = update available.

use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use std::io::Write;

use super::{auth, launch, patch, profile};

pub const NAMES: [&str; 5] = ["login", "login-otp", "check-update", "update", "launch"];

pub fn commands() -> Vec<Command<'static>> {
    vec![
            Command::new("login")
                .about("Log in to Nexon NA (email/password) or refresh the profile's stored session")
                .arg(Arg::new("profile").long("profile").value_name("NAME").help("Profile to use (default: active/first profile)"))
                .arg(Arg::new("email").long("email").alias("username").short('u').value_name("EMAIL").help("Nexon account email"))
                .arg(Arg::new("password").long("password").short('p').value_name("PASSWORD").help("Nexon account password")),
            Command::new("login-otp")
                .about("Submit the MFA code after `login` printed an MFA key")
                .arg(Arg::new("profile").long("profile").value_name("NAME").help("Profile to use (default: active/first profile)"))
                .arg(Arg::new("mfa-key").long("mfa-key").value_name("KEY").required(true))
                .arg(Arg::new("otp").long("otp").value_name("CODE").required(true)),
            Command::new("check-update")
                .about("Compare the installed game with the current Nexon manifest (exit 2 = update available)")
                .arg(Arg::new("profile").long("profile").value_name("NAME").help("Profile to use (default: active/first profile)"))
                .arg(Arg::new("game-path").long("game-path").short('g').value_name("PATH").help("Install folder, appdata, patchdata or Client.exe (default: profile)")),
            Command::new("update")
                .about("Download and apply game updates from Nexon's CDN")
                .arg(Arg::new("profile").long("profile").value_name("NAME").help("Profile to use (default: active/first profile)"))
                .arg(Arg::new("game-path").long("game-path").short('g').value_name("PATH").help("Install folder, appdata, patchdata or Client.exe (default: profile)"))
                .arg(Arg::new("force-all").long("force-all").action(ArgAction::SetTrue).help("Re-download every file"))
                .arg(Arg::new("verify").long("verify").action(ArgAction::SetTrue).help("Repair: also hash-check files whose size matches"))
                .arg(Arg::new("workers").long("workers").short('j').value_name("N").default_value("8").help("Parallel file downloads"))
                .arg(Arg::new("ignore").long("ignore").value_name("PATTERN").action(ArgAction::Append).help("Wildcard path never touched (repeatable)"))
                .arg(Arg::new("scan-only").long("scan-only").action(ArgAction::SetTrue).help("List files that need updating, don't download")),
            Command::new("launch")
                .about("Log in (if needed) and launch Mabinogi without the Nexon Launcher; waits for the game to exit")
                .arg(Arg::new("profile").long("profile").value_name("NAME").help("Profile to use (default: active/first profile)"))
                .arg(Arg::new("username").short('u').long("username").alias("email").value_name("EMAIL").help("Nexon account email (otherwise the profile session is used)"))
                .arg(Arg::new("password").short('p').long("password").value_name("PASSWORD").help("Nexon account password"))
                .arg(Arg::new("client").short('c').long("client").alias("game-path").value_name("PATH").help("Mabinogi folder or Client.exe (default: profile)"))
                .arg(Arg::new("session-file").long("session-file").value_name("FILE").help("Use (and delete) a session JSON file — used by the Linux→Wine hand-off"))
                .arg(Arg::new("no-wait").long("no-wait").action(ArgAction::SetTrue).help("Return right after the game starts"))
                .arg(Arg::new("manifest").long("manifest").action(ArgAction::SetTrue).help("Print the current manifest hash and exit (no launch)")),
    ]
}

/// Run a launcher subcommand; returns the process exit code.
pub fn run(name: &str, sub: &clap::ArgMatches) -> Result<i32> {
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

/// Persist a session on the named profile, creating the profile if needed.
fn store_session(profile_name: Option<&String>, email: &str, s: &auth::NexonSession, expires: i32) -> Result<()> {
    let mut store = profile::ProfileStore::load()?;
    let id = match find_profile(&store, profile_name) {
        Some(p) => p.id,
        None => {
            let name = profile_name.cloned().unwrap_or_else(|| email.to_string());
            let p = profile::Profile::new(&name, email);
            let id = p.id.clone();
            store.upsert(p);
            store.active_id = id.clone();
            store.save()?;
            id
        }
    };
    profile::save_session(&id, s, expires)
}

/// The profile's session, refreshed if expired (email/password accounts).
fn profile_session(profile_name: Option<&String>) -> Result<(profile::Profile, auth::NexonSession)> {
    let store = profile::ProfileStore::load()?;
    let p = find_profile(&store, profile_name)
        .ok_or_else(|| anyhow::anyhow!("No profile found — run `login --email ... --password ...` first"))?;
    let mut s = p.session.clone().unwrap_or_else(|| auth::NexonSession {
        session_token: p.session_token.clone(),
        ..Default::default()
    });
    if s.session_token.is_empty() && s.access_token.is_empty() {
        return Err(anyhow::anyhow!("Profile '{}' has no session — log in first", p.name));
    }
    let status = if s.access_token.is_empty() { 401 } else { auth::check_session(&mut s).unwrap_or(0) };
    if status != 200 {
        auth::refresh(&mut s)?;
        let _ = profile::save_session(&p.id, &s, 0);
    }
    Ok((p, s))
}

fn print_login(r: Result<auth::LoginResult>, profile_name: Option<&String>, email: &str) -> Result<i32> {
    match r {
        Ok(res) => {
            store_session(profile_name, email, &res.session, res.session_expires_in)?;
            println!("Logged in. Session saved (expires in {}s).", res.session_expires_in);
            Ok(0)
        }
        Err(e) => match e.downcast_ref::<auth::AuthError>() {
            Some(auth::AuthError::MfaRequired { mfa_key, mfa_type }) => {
                println!("MFA required ({}). Run:\n  mabi-patcher login-otp --mfa-key {} --otp <CODE>", mfa_type, mfa_key);
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

fn run_launcher_cmd(name: &str, sub: &clap::ArgMatches) -> Result<i32> {
    let profile_name = sub.get_one::<String>("profile");
    let game_path = |p: Option<&profile::Profile>| -> Result<patch::GameRoots> {
        let path = sub.try_get_one::<String>("game-path").ok().flatten()
            .or_else(|| sub.try_get_one::<String>("client").ok().flatten())
            .cloned()
            .or_else(|| p.map(|p| p.client_dir.clone()).filter(|d| !d.is_empty()))
            .ok_or_else(|| anyhow::anyhow!("--game-path is required (or set the profile's game folder)"))?;
        Ok(patch::GameRoots::resolve(path))
    };

    match name {
        "login" => {
            let email = sub.get_one::<String>("email");
            let password = sub.get_one::<String>("password");
            match (email, password) {
                (Some(e), Some(pw)) => print_login(auth::login(e, pw, &auth::device_id("")), profile_name, e),
                (None, None) => {
                    let (p, _) = profile_session(profile_name)?;
                    println!("Session for '{}' is valid.", p.name);
                    Ok(0)
                }
                _ => Err(anyhow::anyhow!("--email and --password must be given together")),
            }
        }
        "login-otp" => {
            let key = sub.get_one::<String>("mfa-key").unwrap();
            let otp = sub.get_one::<String>("otp").unwrap();
            let email = profile_name.cloned().unwrap_or_default();
            print_login(auth::login_otp(key, otp, &auth::device_id("")), profile_name, &email)
        }
        "check-update" => {
            let (p, s) = profile_session(profile_name)?;
            let roots = game_path(Some(&p))?;
            let c = patch::check_update(&roots, Some(&s))?;
            println!("Remote manifest: {}", c.remote_hash);
            println!("Local manifest:  {}", c.local_hash.as_deref().unwrap_or("(none)"));
            if c.update_available { println!("Update available."); Ok(2) } else { println!("Up to date."); Ok(0) }
        }
        "update" => {
            let (p, s) = profile_session(profile_name)?;
            let roots = game_path(Some(&p))?;
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let opts = patch::PatchOptions {
                mode: if sub.get_flag("force-all") { patch::PatchMode::ForceAll }
                      else if sub.get_flag("verify") { patch::PatchMode::Verify }
                      else { patch::PatchMode::Update },
                max_workers: sub.get_one::<String>("workers").and_then(|w| w.parse().ok()).unwrap_or(8),
                ignore: sub.get_many::<String>("ignore").map(|v| v.cloned().collect()).unwrap_or_default(),
                scan_only: sub.get_flag("scan-only"),
                manifest_hash: None,
                cancel,
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
            let r = patch::run_patcher(&roots, Some(&s), &opts, &on_event)?;
            println!();
            if opts.scan_only {
                for n in &r.need { println!("{:>12}  {:<16} {}", n.size, n.reason, n.path); }
                return Ok(if r.need.is_empty() { 0 } else { 2 });
            }
            for e in &r.errors { eprintln!("  {}", e); }
            if r.needs_elevation { eprintln!("Permission denied — run as administrator."); }
            Ok(if r.errors.is_empty() && !r.cancelled { 0 } else { 1 })
        }
        "launch" => {
            if let Some(f) = sub.get_one::<String>("session-file") {
                let mut s = launch::read_session_file(std::path::Path::new(f))?;
                let client = sub.get_one::<String>("client")
                    .ok_or_else(|| anyhow::anyhow!("--client is required with --session-file"))?;
                let info = launch::launch_official(&mut s, &patch::GameRoots::resolve(client).client_exe(), !sub.get_flag("no-wait"))?;
                println!("Launched {} (pid {}).", info.executable, info.pid);
                return Ok(0);
            }
            let (p, mut s) = match (sub.get_one::<String>("username"), sub.get_one::<String>("password")) {
                (Some(u), Some(pw)) => {
                    let res = auth::login(u, pw, &auth::device_id(""))?;
                    store_session(profile_name, u, &res.session, res.session_expires_in)?;
                    let store = profile::ProfileStore::load()?;
                    (find_profile(&store, profile_name).unwrap_or_else(|| profile::Profile::new(u, u)), res.session)
                }
                _ => profile_session(profile_name)?,
            };
            if sub.get_flag("manifest") {
                println!("{}", patch::remote_manifest_hash(Some(&s))?);
                return Ok(0);
            }
            let roots = game_path(Some(&p))?;
            let wait = !sub.get_flag("no-wait");
            let info = launch::launch_official(&mut s, &roots.client_exe(), wait);
            let _ = profile::save_session(&p.id, &s, 0);
            let info = info?;
            println!("Launched {} (pid {}).", info.executable, info.pid);
            Ok(0)
        }
        _ => unreachable!(),
    }
}
