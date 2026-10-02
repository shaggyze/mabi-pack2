// Game launch without the official Nexon Launcher (the official launch flow,
// with the launcher's pipe server and protocol made standalone):
//
//   1. auth::prepare_launch      account → access → playable → passport (401 → refresh)
//   2. fetch_launch_config       parameters with ${passport} template
//   3. Deploy to %LOCALAPPDATA%\mabi-patcher\nxl3p\:
//        nexon_client.exe        = a copy of this exe, run with --nxl3p-stub
//        bin\nexon_x64.dll       = embedded nxl3p-shim (hands the passport to the game)
//      nexon_api_x64.dll in the game finds the running nexon_client.exe and loads
//      <its dir>\bin\nexon_x64.dll — that's how the ticket gets into Client.exe.
//   4. Ticket → a per-launch named file mapping `Local\mabi-patcher.ticket.{GUID}`
//      whose DACL grants only the current user (and SYSTEM). Its name reaches the
//      shim through the MABI_PATCHER_TICKET_MAP env var, or `--mabi-map <name>` on
//      Client.exe's command line when UAC elevation dropped the environment. The
//      shim copies the ticket, zeroes the mapping and sets `<name>.ready`; the
//      launcher closes the mapping after ready + grace, game exit or a timeout.
//   5. Client.exe is created suspended (env var set), so the SDK pipe
//      \\.\pipe\{79d303ac-...} is bound to its exact PID before it runs; a
//      `requireAdministrator`/`highestAvailable` client (ERROR_ELEVATION_REQUIRED)
//      falls back to ShellExecuteEx. The pipe is first-instance only, rejects
//      remote clients and serves only the game's PID.
//   6. A watcher thread signals the stub's per-launch exit event when the game exits.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::auth::{self, NexonSession, API_BASE};

pub const STUB_FLAG: &str = "--nxl3p-stub";
/// Fixed-name %TEMP% ticket file of older builds; a leftover is deleted at launch.
#[cfg_attr(not(windows), allow(dead_code))]
const LEGACY_TICKET_FILE: &str = "mabi-patcher-nxl3p-ticket.txt";
/// Env var naming the ticket mapping for the shim (inherited by Client.exe).
pub const TICKET_MAP_ENV: &str = "MABI_PATCHER_TICKET_MAP";
/// Client.exe argument carrying the mapping name when the environment is lost
/// (elevated launch through ShellExecuteEx). The game ignores unknown arguments.
pub const TICKET_MAP_ARG: &str = "--mabi-map";
/// Kernel object names: all session-local, all per launch except the launch lock.
const TICKET_MAP_PREFIX: &str = r"Local\mabi-patcher.ticket.";
const STUB_EVENT_PREFIX: &str = r"Local\mabi-patcher.stub.";
/// Named mutex serializing launches (see `win::LaunchLock`).
#[cfg(windows)]
const LAUNCH_MUTEX: &str = r"Local\mabi-patcher.launch";
/// Ticket mapping layout: [magic u32 LE][len u32 LE][UTF-8 ticket], zero padded.
pub const TICKET_MAP_CAPACITY: usize = 4096;
pub const TICKET_MAP_MAGIC: u32 = u32::from_le_bytes(*b"MPT1");
/// Longest ticket accepted (UTF-16 units the shim's buffers take).
const TICKET_MAX_CHARS: usize = 1023;
pub const NEXON_PIPE_NAME: &str = r"\\.\pipe\{79d303ac-af79-46c3-9ae0-6cd4ff4805ad}";
/// Line the Windows build prints (under Wine) once Client.exe has spawned, so the
/// Linux side can fire its after-launch hook: `<marker> pid=N patch=0|1 args=N`.
pub const STARTED_MARKER: &str = "MABI_LAUNCH_STARTED";
/// How long a launch waits for the shim to pick up the ticket, even without `wait`.
#[cfg(windows)]
const SHIM_READY_TIMEOUT_MS: u32 = 60_000;
/// Extra time for the SDK to finish its pipe requests once the shim is ready.
#[cfg(windows)]
const SHIM_GRACE_MS: u64 = 3_000;
/// How long a launch waits for an earlier one to reach shim-ready.
#[cfg(windows)]
const LAUNCH_LOCK_TIMEOUT_MS: u32 = SHIM_READY_TIMEOUT_MS + SHIM_GRACE_MS as u32 + 15_000;

/// Log the shim appends to in %TEMP%; trimmed at launch once it passes `SHIM_LOG_MAX`.
pub const SHIM_LOG_FILE: &str = "mabi-patcher-nxl3p-shim.log";
#[cfg(windows)]
const SHIM_LOG_MAX: u64 = 1024 * 1024;
#[cfg(windows)]
const SHIM_LOG_KEEP: u64 = 256 * 1024;

/// If `path` is larger than `max` bytes, keep only its last `keep` bytes
/// (starting at a line boundary). Missing files are fine.
#[cfg_attr(not(windows), allow(dead_code))]
fn trim_log_file(path: &Path, max: u64, keep: u64) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(()),
    };
    if len <= max {
        return Ok(());
    }
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(len - keep.min(len)))?;
    let mut tail = Vec::new();
    f.read_to_end(&mut tail)?;
    drop(f);
    let start = tail.iter().position(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
    std::fs::write(path, &tail[start..])
}

// ── Per-launch IPC names and encodings (shared, testable) ─────────────────────

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` from 16 random bytes (made a v4 GUID).
#[cfg_attr(not(windows), allow(dead_code))]
fn format_guid(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = |r: std::ops::Range<usize>| b[r].iter().map(|x| format!("{:02X}", x)).collect::<String>();
    format!("{{{}-{}-{}-{}-{}}}", hex(0..4), hex(4..6), hex(6..8), hex(8..10), hex(10..16))
}

/// True for a braced GUID as [`format_guid`] writes it (any hex case).
fn is_braced_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Name of a launch's ticket mapping.
#[cfg_attr(not(windows), allow(dead_code))]
fn ticket_map_name(guid: &str) -> String {
    format!("{}{}", TICKET_MAP_PREFIX, guid)
}

/// True if `name` is a ticket mapping name (what the shim accepts).
pub fn is_ticket_map_name(name: &str) -> bool {
    name.strip_prefix(TICKET_MAP_PREFIX).is_some_and(is_braced_guid)
}

/// Event the shim sets once it holds the ticket: `<mapping name>.ready`.
#[cfg_attr(not(windows), allow(dead_code))]
fn ready_event_name(map_name: &str) -> String {
    format!("{}.ready", map_name)
}

/// Name of a launch's stub-exit event.
#[cfg_attr(not(windows), allow(dead_code))]
fn stub_event_name(guid: &str) -> String {
    format!("{}{}", STUB_EVENT_PREFIX, guid)
}

/// What the nexon_client.exe stub needs: its launch's exit event and the
/// launcher's PID (it exits when either fires).
#[derive(Debug, PartialEq, Eq)]
pub struct StubArgs {
    pub exit_event: String,
    pub parent_pid: u32,
}

/// Arguments after [`STUB_FLAG`] for a stub of this launch.
#[cfg_attr(not(windows), allow(dead_code))]
fn stub_command_args(exit_event: &str, parent_pid: u32) -> Vec<String> {
    vec!["--exit-event".into(), exit_event.into(), "--parent-pid".into(), parent_pid.to_string()]
}

/// Parse the arguments after [`STUB_FLAG`]: exactly `--exit-event <name>
/// --parent-pid <pid>`, a per-launch stub event name and a PID that is neither
/// 0 nor `self_pid`. Anything else is rejected.
pub fn parse_stub_args(args: &[String], self_pid: u32) -> Option<StubArgs> {
    match args {
        [e, name, p, pid] if e == "--exit-event" && p == "--parent-pid" => {
            if !name.strip_prefix(STUB_EVENT_PREFIX).is_some_and(is_braced_guid) {
                return None;
            }
            let parent_pid: u32 = pid.parse().ok()?;
            if parent_pid == 0 || parent_pid == self_pid {
                return None;
            }
            Some(StubArgs { exit_event: name.clone(), parent_pid })
        }
        _ => None,
    }
}

/// Client.exe parameters for the ShellExecuteEx (elevation) path: the mapping
/// name rides on the command line because UAC drops the environment.
#[cfg_attr(not(windows), allow(dead_code))]
fn params_with_map_arg(params: &str, map_name: &str) -> String {
    if params.is_empty() {
        format!("{} {}", TICKET_MAP_ARG, map_name)
    } else {
        format!("{} {} {}", params, TICKET_MAP_ARG, map_name)
    }
}

/// The mapping name from a `--mabi-map <name>` pair in a command line (as the
/// shim finds it), if it is a valid ticket mapping name.
pub fn map_name_from_command_line(cmdline: &str) -> Option<&str> {
    let mut it = cmdline.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == TICKET_MAP_ARG {
            return it.next().map(|n| n.trim_matches('"')).filter(|n| is_ticket_map_name(n));
        }
    }
    None
}

/// The mapping's contents for `ticket`: magic, length, UTF-8 bytes, zero padding.
#[cfg_attr(not(windows), allow(dead_code))]
fn encode_ticket_map(ticket: &str) -> Result<Vec<u8>> {
    let bytes = ticket.as_bytes();
    if bytes.is_empty()
        || bytes.len() > TICKET_MAP_CAPACITY - 8
        || ticket.encode_utf16().count() > TICKET_MAX_CHARS
        || ticket.contains('\0')
    {
        return Err(anyhow!("Invalid launch ticket length"));
    }
    let mut out = vec![0u8; TICKET_MAP_CAPACITY];
    out[..4].copy_from_slice(&TICKET_MAP_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    out[8..8 + bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// Inverse of [`encode_ticket_map`] (the shim's reading, kept here for tests).
#[cfg(test)]
fn decode_ticket_map(view: &[u8]) -> Option<String> {
    if view.len() < 8 || u32::from_le_bytes(view[..4].try_into().ok()?) != TICKET_MAP_MAGIC {
        return None;
    }
    let n = u32::from_le_bytes(view[4..8].try_into().ok()?) as usize;
    if n == 0 || n > view.len() - 8 {
        return None;
    }
    let t = std::str::from_utf8(&view[8..8 + n]).ok()?;
    (t.encode_utf16().count() <= TICKET_MAX_CHARS && !t.contains('\0')).then(|| t.to_string())
}

/// A CreateProcessW environment block (UTF-16 `KEY=VALUE\0…\0`) of `vars` with
/// `key` set to `value` (replacing any existing one, case-insensitively), sorted
/// by key the way Windows keeps it.
#[cfg_attr(not(windows), allow(dead_code))]
fn env_block_with(vars: Vec<(Vec<u16>, Vec<u16>)>, key: &str, value: &str) -> Vec<u16> {
    let upper = |k: &[u16]| String::from_utf16_lossy(k).to_uppercase();
    let key_up = key.to_uppercase();
    let mut entries: Vec<(Vec<u16>, Vec<u16>)> = vars.into_iter().filter(|(k, _)| upper(k) != key_up).collect();
    entries.push((key.encode_utf16().collect(), value.encode_utf16().collect()));
    entries.sort_by_cached_key(|(k, _)| upper(k));
    let mut block = Vec::new();
    for (k, v) in entries {
        block.extend(k);
        block.push(u16::from(b'='));
        block.extend(v);
        block.push(0);
    }
    block.push(0);
    block
}

/// One Client.exe argument for the command line. An argument that already
/// contains a `"` is the caller's own quoting (e.g. `setting:"file://...=Regular, USA"`)
/// and is passed verbatim; one with whitespace and no quotes is wrapped.
#[cfg_attr(not(windows), allow(dead_code))]
fn quote_arg(a: &str) -> String {
    if !a.contains('"') && a.chars().any(char::is_whitespace) { format!("\"{}\"", a) } else { a.to_string() }
}

/// nexon_x64.dll stand-in, built from nxl3p-shim/ by build.rs.
#[cfg(windows)]
static SHIM_DLL: &[u8] = include_bytes!(env!("NXL3P_SHIM_DLL"));

// ── Launch config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LaunchConfig {
    /// Nexon-provided launch arguments (`parameter` array, may contain ${passport}).
    pub arguments: Vec<String>,
    /// Relative path to the client inside the game folder.
    pub executable_path: String,
    pub patch_available: bool,
}

#[derive(Deserialize, Default)]
struct ConfigResponse {
    #[serde(rename = "parameter")]
    arguments: Option<Vec<String>>,
    #[serde(rename = "executablePath")]
    executable_path: Option<String>,
    #[serde(rename = "patch")]
    patch_available: Option<bool>,
}

/// GET /game-build/v1/configuration/games/10200 (Bearer AToken). Refreshes once on 401.
pub fn fetch_launch_config(session: &NexonSession) -> Result<LaunchConfig> {
    let mut s = session.clone();
    fetch_launch_config_mut(&mut s)
}

pub fn fetch_launch_config_mut(session: &mut NexonSession) -> Result<LaunchConfig> {
    auth::with_refresh(session, |s| {
        let resp = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(auth::USER_AGENT)
            .build()?
            .get(format!("{}/game-build/v1/configuration/games/{}", API_BASE, auth::product_id()))
            .header("Cookie", s.cookie_header())
            .bearer_auth(s.access_token.clone())
            .send()?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if status.as_u16() == 401 {
            return Err(auth::AuthError::SessionExpired("game config".into()).into());
        }
        if !status.is_success() {
            return Err(anyhow!("Launch config fetch failed ({}): {}", status, body));
        }
        let cfg: ConfigResponse =
            serde_json::from_str(&body).map_err(|e| anyhow!("Launch config parse error: {} body={}", e, body))?;
        Ok(LaunchConfig {
            arguments: cfg.arguments.unwrap_or_default(),
            executable_path: cfg.executable_path.unwrap_or_else(|| "Client.exe".into()),
            patch_available: cfg.patch_available.unwrap_or(false),
        })
    })
}

impl LaunchConfig {
    /// Substitute ${passport}; make sure a /P: argument exists.
    pub fn build_args(&self, passport: &str) -> Vec<String> {
        let mut args: Vec<String> = self.arguments.iter().map(|a| a.replace("${passport}", passport)).collect();
        if !args.iter().any(|a| a.starts_with("/P:")) {
            args.push(format!("/P:{}", passport));
        }
        args
    }
}

// ── Official launch ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct LaunchInfo {
    pub pid: u32,
    pub executable: String,
    pub argument_count: usize,
    pub patch_available: bool,
    /// New NxLSession lifetime in seconds when the launch chain refreshed the
    /// session (401 → autologin); persist it with the session.
    pub session_expires_in: Option<i32>,
}

/// Log in to the game and start Client.exe the way the official launcher does.
/// `session` is refreshed in place if a 401 forced an autologin — persist it.
/// Returns once the shim has taken the ticket (or after a timeout); with `wait`,
/// blocks until the game exits.
pub fn launch_official(session: &mut NexonSession, client_exe: &Path, wait: bool) -> Result<LaunchInfo> {
    launch_official_with(session, client_exe, wait, &|_, _| {})
}

/// [`launch_official`] with `on_started`, called as soon as Client.exe has spawned
/// (before any waiting) with the launch info and the session as it is now.
pub fn launch_official_with(
    session: &mut NexonSession,
    client_exe: &Path,
    wait: bool,
    on_started: &dyn Fn(&LaunchInfo, &NexonSession),
) -> Result<LaunchInfo> {
    // Linux/macOS: the SDK pipe and nexon_client.exe stub must live inside the
    // game's Wine prefix, so hand off to the Windows build running under Wine.
    #[cfg(not(windows))]
    return wine::launch(session, client_exe, wait, on_started);

    #[cfg(windows)]
    {
        if !client_exe.exists() {
            return Err(anyhow!("Client.exe not found at: {}", client_exe.display()));
        }
        let passport = auth::prepare_launch(session)?;
        let config = fetch_launch_config_mut(session)?;
        let args = config.build_args(&passport);
        log::info!("Launch: {} ({} args)", client_exe.display(), args.len());
        let session: &NexonSession = session;
        let base = LaunchInfo {
            pid: 0,
            executable: client_exe.display().to_string(),
            argument_count: args.len(),
            patch_available: config.patch_available,
            session_expires_in: session.refreshed_expires_in,
        };
        let started = |pid: u32| on_started(&LaunchInfo { pid, ..base.clone() }, session);
        let pid = win::launch(client_exe, &args, &passport, &session.hashed_user_id, wait, &started)?;
        Ok(LaunchInfo { pid, ..base })
    }
}

/// Read a session handed over by `wine::launch`. The Linux side owns (and deletes) the file.
pub fn read_session_file(path: &Path) -> Result<NexonSession> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Write the (possibly refreshed) session back to the hand-off file so the
/// Linux side can persist it. Overwrites in place, keeping the file's 0600 mode.
pub fn write_session_file(path: &Path, session: &NexonSession) -> Result<()> {
    std::fs::write(path, serde_json::to_string(session)?)?;
    Ok(())
}

/// The line the Windows build prints once Client.exe has spawned (see [`STARTED_MARKER`]).
pub fn started_line(info: &LaunchInfo) -> String {
    format!(
        "{} pid={} patch={} args={}",
        STARTED_MARKER,
        info.pid,
        u8::from(info.patch_available),
        info.argument_count
    )
}

/// Parse a [`started_line`] back into launch info (`executable` left empty).
pub fn parse_started_line(line: &str) -> Option<LaunchInfo> {
    let rest = line.trim().strip_prefix(STARTED_MARKER)?;
    let mut info = LaunchInfo {
        pid: 0,
        executable: String::new(),
        argument_count: 0,
        patch_available: false,
        session_expires_in: None,
    };
    for kv in rest.split_whitespace() {
        match kv.split_once('=')? {
            ("pid", v) => info.pid = v.parse().ok()?,
            ("patch", v) => info.patch_available = v == "1",
            ("args", v) => info.argument_count = v.parse().ok()?,
            _ => {}
        }
    }
    Some(info)
}

#[cfg(not(windows))]
mod wine {
    use super::*;

    /// Run `wine mabi-patcher.exe launch --session-file … --client …`.
    /// Env: MABI_WINE_EXE (Windows mabi-patcher.exe, default: next to this binary),
    ///      MABI_WINE or WINE (wine runner, default `wine`), WINEPREFIX (the game's prefix).
    ///
    /// The Windows side writes the (possibly refreshed) session back to the file and
    /// prints [`STARTED_MARKER`] once Client.exe spawned; it also waits for the shim
    /// itself, so this returns only after the ticket was handed over.
    pub fn launch(
        session: &mut NexonSession,
        client_exe: &Path,
        wait: bool,
        on_started: &dyn Fn(&LaunchInfo, &NexonSession),
    ) -> Result<LaunchInfo> {
        let exe = std::env::var_os("MABI_WINE_EXE").map(PathBuf::from).unwrap_or_else(|| {
            std::env::current_exe().unwrap_or_default().with_file_name("mabi-patcher.exe")
        });
        if !exe.exists() {
            return Err(anyhow!(
                "Launching under Linux needs the Windows mabi-patcher.exe (run inside the game's Wine prefix). \
                 Put it next to this binary or set MABI_WINE_EXE, and set WINEPREFIX to the game's prefix."
            ));
        }
        let wine = wine_runner();

        // Hand the session over through a private, freshly created temp file.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let file = std::env::temp_dir().join(format!("mabi-session-{}-{}.json", std::process::id(), nanos));
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file)?;
            f.write_all(serde_json::to_string(session)?.as_bytes())?;
        }
        let result = run_child(session, &wine, &exe, &file, client_exe, wait, on_started);
        let _ = std::fs::remove_file(&file);
        result
    }

    fn run_child(
        session: &mut NexonSession,
        wine: &str,
        exe: &Path,
        file: &Path,
        client_exe: &Path,
        wait: bool,
        on_started: &dyn Fn(&LaunchInfo, &NexonSession),
    ) -> Result<LaunchInfo> {
        use std::io::{BufRead, Write};
        // Pick up the session the Windows side wrote back (refreshed tokens + expiry).
        let merge_back = |session: &mut NexonSession| match read_session_file(file) {
            Ok(back) => session.merge_from(&back),
            Err(e) => log::warn!("Could not read the session back from the Wine side: {}", e),
        };
        let mut cmd = std::process::Command::new(wine);
        cmd.arg(exe)
            .arg("launch")
            .arg("--session-file")
            .arg(to_wine_path(wine, file))
            .arg("--client")
            .arg(to_wine_path(wine, client_exe))
            .stdout(std::process::Stdio::piped());
        if !wait {
            cmd.arg("--no-wait");
        }
        log::info!("Wine launch: {:?}", cmd);
        let mut child = cmd.spawn().map_err(|e| anyhow!("failed to run {}: {}", wine, e))?;
        let mut started: Option<LaunchInfo> = None;
        if let Some(out) = child.stdout.take() {
            let mut lines = std::io::BufReader::new(out).lines();
            for line in lines.by_ref().map_while(Result::ok) {
                match parse_started_line(&line) {
                    Some(mut info) if started.is_none() => {
                        merge_back(session);
                        info.executable = client_exe.display().to_string();
                        info.session_expires_in = session.refreshed_expires_in;
                        on_started(&info, session);
                        started = Some(info);
                        if !wait {
                            break;
                        }
                    }
                    _ => {
                        println!("{}", line);
                        let _ = std::io::stdout().flush();
                    }
                }
            }
            if started.is_some() && !wait {
                // Don't block on the pipe (anything the game side still holds open);
                // keep forwarding the child's last lines in the background so its
                // writes don't fail, and just wait for the child itself.
                std::thread::spawn(move || {
                    for line in lines.map_while(Result::ok) {
                        println!("{}", line);
                    }
                });
            }
        }
        let status = child.wait()?;
        merge_back(session);
        if !status.success() {
            return Err(anyhow!("Wine launch failed ({})", status));
        }
        let mut info = started.unwrap_or(LaunchInfo {
            pid: 0,
            executable: client_exe.display().to_string(),
            argument_count: 0,
            patch_available: false,
            session_expires_in: None,
        });
        info.session_expires_in = session.refreshed_expires_in;
        Ok(info)
    }

    /// Linux path → Windows path inside the prefix (`winepath -w`, else Z:\...).
    fn to_wine_path(wine: &str, p: &Path) -> String {
        let winepath = Path::new(wine).with_file_name("winepath");
        let tool = if winepath.exists() { winepath } else { PathBuf::from("winepath") };
        if let Ok(out) = std::process::Command::new(tool).arg("-w").arg(p).output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() && !s.is_empty() {
                return s;
            }
        }
        let abs = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        format!("Z:{}", abs.display()).replace('/', "\\")
    }
}

/// If this process was started as the nexon_client.exe stub, wait and exit.
/// Call first thing in `main()` of every mabi-patcher binary.
///
/// The stub needs `--exit-event <Local\mabi-patcher.stub.{GUID}> --parent-pid
/// <launcher pid>`; it exits (code 2) on anything else, and otherwise once the
/// launch's exit event is set, the launcher process is gone, or after 120 s.
pub fn run_stub_if_requested() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let pos = match args.iter().position(|a| a == STUB_FLAG) {
        Some(i) => i,
        None => return,
    };
    let code = match parse_stub_args(&args[pos + 1..], std::process::id()) {
        #[cfg(windows)]
        Some(stub) => win::stub_main(&stub),
        #[cfg(not(windows))]
        Some(_) => 0,
        None => 2,
    };
    std::process::exit(code);
}

// ── Custom / direct launch (private servers, user overrides) ─────────────────

/// Split a command line into arguments, honouring double quotes (`"a b"` is
/// one argument, `""` an empty one) and `\"` inside quotes as a literal quote.
pub fn split_command_line(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => { in_quotes = !in_quotes; has_token = true; }
            '\\' if in_quotes && chars.peek() == Some(&'"') => { cur.push('"'); chars.next(); }
            c if c.is_whitespace() && !in_quotes => {
                if has_token { out.push(std::mem::take(&mut cur)); has_token = false; }
            }
            c => { cur.push(c); has_token = true; }
        }
    }
    if has_token { out.push(cur); }
    out
}

/// Launch Client.exe with explicit args, or a user command override.
/// Override variables: {client_dir}, {exe}, {passport}, {args}.
pub fn launch_direct(client_dir: &Path, passport: &str, args: &[String], cmd_override: Option<&str>) -> Result<usize> {
    let exe = client_dir.join("Client.exe");
    if !exe.exists() {
        return Err(anyhow!("Client.exe not found at: {}", exe.display()));
    }
    if let Some(over) = cmd_override.filter(|s| !s.trim().is_empty()) {
        // Split first (quote-aware), then expand each token, so a path with
        // spaces stays one argument; a bare `{args}` token expands to the
        // separate launch arguments.
        let expand = |t: &str| t
            .replace("{client_dir}", &client_dir.to_string_lossy())
            .replace("{exe}", &exe.to_string_lossy())
            .replace("{passport}", passport)
            .replace("{args}", &args.join(" "));
        let mut parts: Vec<String> = Vec::new();
        for tok in split_command_line(over) {
            if tok == "{args}" { parts.extend(args.iter().cloned()); } else { parts.push(expand(&tok)); }
        }
        let (prog, rest) = parts.split_first().ok_or_else(|| anyhow!("Empty launch command"))?;
        let mut cmd = std::process::Command::new(prog);
        cmd.args(rest).current_dir(client_dir);
        detach(&mut cmd);
        log::info!("Direct launch (custom): {}", prog);
        cmd.spawn().map_err(|e| anyhow!("Launch failed: {}", e))?;
        return Ok(rest.len());
    }
    let mut full = args.to_vec();
    let p = format!("/P:{}", passport);
    match full.iter().position(|a| a.starts_with("/P:")) {
        Some(i) => full[i] = p,
        None => full.push(p),
    }
    let mut cmd = client_command(&exe);
    cmd.current_dir(client_dir).args(&full);
    detach(&mut cmd);
    cmd.spawn().map_err(|e| anyhow!("Failed to spawn Client.exe: {}", e))?;
    Ok(full.len())
}

/// Wine runner used off Windows: `MABI_WINE` (e.g. `wine64`, a Proton `wine`
/// binary or a wrapper script), else `WINE`, else `wine`. Set `WINEPREFIX` as usual.
#[cfg(not(windows))]
fn wine_runner() -> String {
    ["MABI_WINE", "WINE"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "wine".to_string())
}

/// Command that runs `exe` (Client.exe) directly: as-is on Windows, through
/// the Wine runner (see `wine_runner`) elsewhere.
fn client_command(exe: &Path) -> std::process::Command {
    #[cfg(windows)]
    {
        std::process::Command::new(exe)
    }
    #[cfg(not(windows))]
    {
        let mut cmd = std::process::Command::new(wine_runner());
        cmd.arg(exe);
        cmd
    }
}

fn detach(_cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        _cmd.creation_flags(0x0000_0008); // DETACHED_PROCESS
    }
}

#[derive(Serialize)]
pub struct LaunchSummary {
    pub executable: String,
    pub argument_count: usize,
    pub patch_available: bool,
}

impl From<&LaunchConfig> for LaunchSummary {
    fn from(c: &LaunchConfig) -> Self {
        Self {
            executable: c.executable_path.clone(),
            argument_count: c.arguments.len(),
            patch_available: c.patch_available,
        }
    }
}

/// Run a hook command (pre/post patch/launch). `%PROFILE%` → profile name.
pub fn run_hook(cmd: &str, working_dir: &Path, profile: &str) -> Result<String> {
    let cmd = replace_ci(cmd, "%PROFILE%", profile);
    run_hook_cmd(&cmd, working_dir)
}

/// Start a hook command without waiting for it (event hooks).
/// `%PROFILE%` is replaced with `profile`. Empty string = no-op.
pub fn spawn_hook(cmd: &str, profile: &str, working_dir: &Path) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }
    let expanded = replace_ci(cmd, "%PROFILE%", profile);
    #[cfg(windows)]
    let mut shell = {
        use std::os::windows::process::CommandExt;
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", &expanded]).creation_flags(0x08000000); // CREATE_NO_WINDOW
        c
    };
    #[cfg(not(windows))]
    let mut shell = {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", &expanded]);
        c
    };
    if working_dir.is_dir() {
        shell.current_dir(working_dir);
    }
    match shell.spawn() {
        Ok(_) => log::info!("Hook started: {}", expanded),
        Err(e) => log::warn!("Hook '{}' failed to start: {}", expanded, e),
    }
}

fn replace_ci(text: &str, needle: &str, with: &str) -> String {
    // ASCII lowering keeps byte offsets valid for slicing `text`.
    let lower = text.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut out = String::new();
    let mut last = 0;
    for (i, _) in lower.match_indices(&needle) {
        out.push_str(&text[last..i]);
        out.push_str(with);
        last = i + needle.len();
    }
    out.push_str(&text[last..]);
    out
}

/// Run a shell hook command synchronously; returns stdout+stderr. Empty = no-op.
pub fn run_hook_cmd(cmd: &str, working_dir: &Path) -> Result<String> {
    if cmd.trim().is_empty() {
        return Ok(String::new());
    }
    #[cfg(windows)]
    let mut c = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", cmd]);
        c
    };
    #[cfg(not(windows))]
    let mut c = {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    let dir = if working_dir.is_dir() { working_dir.to_path_buf() } else { PathBuf::from(".") };
    let out = c.current_dir(dir).output().map_err(|e| anyhow!("Hook command failed to start: {}", e))?;
    let combined = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    log::info!("Hook '{}' exit={}: {}", cmd, out.status, combined.trim());
    Ok(combined)
}

// ── Pipe protocol (shared, testable) ─────────────────────────────────────────

/// Build the response for one SDK pipe request. Returns (response, is_close).
pub fn pipe_response(req: &[u8], ticket: &str, hashed_user_no: &str) -> (Vec<u8>, bool) {
    let v: serde_json::Value = serde_json::from_slice(req).unwrap_or_default();
    let typ = v["type"].as_str().unwrap_or("").to_string();
    let product_id = v["req"]["productId"].as_i64().unwrap_or(10200);
    let mut out = serde_json::json!({ "code": 0, "reqType": typ });
    if let Some(id) = v["id"].as_str().filter(|s| !s.is_empty()) {
        out["id"] = id.into();
    }
    let mut close = false;
    match typ.as_str() {
        "getProductTicket" => {
            out["res"] = serde_json::json!({ "productId": product_id, "ticket": ticket });
        }
        "getSDKConfiguration" => {
            out["res"] = serde_json::json!({
                "ccuServerName": "ccu-edge.nexon.io",
                "ccuServerPort": 8913,
                "hashedUserNo": hashed_user_no,
                "productId": product_id,
            });
        }
        "productActive" | "getClientToken" => {}
        "productClosed" => close = true,
        _ => out["code"] = (-30000005).into(),
    }
    (serde_json::to_vec(&out).unwrap_or_default(), close)
}

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
    use winapi::shared::winerror::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_ELEVATION_REQUIRED, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, WAIT_TIMEOUT,
    };
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::handleapi::{CloseHandle, DuplicateHandle, INVALID_HANDLE_VALUE};
    use winapi::um::minwinbase::{OVERLAPPED, SECURITY_ATTRIBUTES};
    use winapi::um::processthreadsapi::{GetCurrentProcess, GetProcessId, OpenProcess, ResumeThread, TerminateProcess};
    use winapi::um::synchapi::{
        CreateEventW, CreateMutexW, OpenEventW, ReleaseMutex, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
    };
    use winapi::um::winbase::{INFINITE, WAIT_ABANDONED, WAIT_OBJECT_0};
    use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, HANDLE, SYNCHRONIZE};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn os_err(what: &str, code: DWORD) -> anyhow::Error {
        anyhow!("{}: {}", what, std::io::Error::from_raw_os_error(code as i32))
    }

    struct Handle(HANDLE);
    unsafe impl Send for Handle {}
    impl Handle {
        fn raw(&self) -> HANDLE {
            self.0
        }
        fn valid(&self) -> bool {
            !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.valid() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// 16 bytes from the system CSPRNG, as a braced v4 GUID.
    fn new_guid() -> Result<String> {
        let mut b = [0u8; 16];
        if unsafe { winapi::um::ntsecapi::RtlGenRandom(b.as_mut_ptr() as *mut _, 16) } == 0 {
            return Err(anyhow!("Could not create a launch identifier"));
        }
        Ok(format_guid(b))
    }

    /// Security descriptor granting full access to the current user and SYSTEM only
    /// (protected DACL, nothing inherited). Freed on drop.
    struct UserOnlySd(*mut winapi::ctypes::c_void);

    impl UserOnlySd {
        fn new() -> Result<UserOnlySd> {
            use winapi::shared::sddl::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW};
            use winapi::um::processthreadsapi::OpenProcessToken;
            use winapi::um::securitybaseapi::GetTokenInformation;
            use winapi::um::winbase::LocalFree;
            use winapi::um::winnt::{TokenUser, TOKEN_QUERY, TOKEN_USER};
            unsafe {
                let mut token: HANDLE = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(os_err("OpenProcessToken", GetLastError()));
                }
                let token = Handle(token);
                let mut needed: DWORD = 0;
                GetTokenInformation(token.raw(), TokenUser, std::ptr::null_mut(), 0, &mut needed);
                if needed == 0 {
                    return Err(os_err("GetTokenInformation", GetLastError()));
                }
                // u64 storage keeps TOKEN_USER suitably aligned.
                let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
                if GetTokenInformation(token.raw(), TokenUser, buf.as_mut_ptr() as *mut _, needed, &mut needed) == 0 {
                    return Err(os_err("GetTokenInformation", GetLastError()));
                }
                let user = &*(buf.as_ptr() as *const TOKEN_USER);
                let mut sid_str: *mut u16 = std::ptr::null_mut();
                if ConvertSidToStringSidW(user.User.Sid, &mut sid_str) == 0 {
                    return Err(os_err("ConvertSidToStringSid", GetLastError()));
                }
                let mut len = 0;
                while *sid_str.add(len) != 0 {
                    len += 1;
                }
                let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_str, len));
                LocalFree(sid_str as *mut _);
                let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", sid));
                let mut sd: *mut winapi::ctypes::c_void = std::ptr::null_mut();
                if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, std::ptr::null_mut()) == 0 {
                    return Err(os_err("ConvertStringSecurityDescriptor", GetLastError()));
                }
                Ok(UserOnlySd(sd))
            }
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
                lpSecurityDescriptor: self.0,
                bInheritHandle: FALSE,
            }
        }
    }

    impl Drop for UserOnlySd {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { winapi::um::winbase::LocalFree(self.0) };
            }
        }
    }

    /// A new, user-only named event; fails if the name already exists.
    fn private_event(name: &str, sd: &UserOnlySd) -> Result<Handle> {
        let mut sa = sd.attributes();
        let h = Handle(unsafe { CreateEventW(&mut sa, TRUE, FALSE, wide(name).as_ptr()) });
        let err = unsafe { GetLastError() };
        if !h.valid() {
            return Err(os_err("CreateEvent", err));
        }
        if err == ERROR_ALREADY_EXISTS {
            return Err(anyhow!("Launch event name collision; try again"));
        }
        Ok(h)
    }

    /// The per-launch ticket mapping (see the module comment). Dropping it zeroes,
    /// unmaps and closes it; once the last handle (ours, or the shim's while it
    /// reads) is closed the object and its name are gone.
    struct TicketMapping {
        /// Kept open for the mapping's lifetime; closed (after the view is wiped) on drop.
        _handle: Handle,
        view: *mut u8,
        name: String,
    }

    impl TicketMapping {
        fn create(ticket: &str, sd: &UserOnlySd) -> Result<TicketMapping> {
            use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, FILE_MAP_WRITE};
            use winapi::um::winnt::PAGE_READWRITE;
            let mut bytes = encode_ticket_map(ticket)?;
            let name = ticket_map_name(&new_guid()?);
            let mut sa = sd.attributes();
            let handle = Handle(unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    &mut sa,
                    PAGE_READWRITE,
                    0,
                    TICKET_MAP_CAPACITY as DWORD,
                    wide(&name).as_ptr(),
                )
            });
            let err = unsafe { GetLastError() };
            let result = if !handle.valid() {
                Err(os_err("CreateFileMapping", err))
            } else if err == ERROR_ALREADY_EXISTS {
                Err(anyhow!("Ticket mapping name collision; try again"))
            } else {
                let view = unsafe { MapViewOfFile(handle.raw(), FILE_MAP_WRITE, 0, 0, TICKET_MAP_CAPACITY) } as *mut u8;
                if view.is_null() {
                    Err(os_err("MapViewOfFile", unsafe { GetLastError() }))
                } else {
                    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), view, TICKET_MAP_CAPACITY) };
                    Ok(TicketMapping { _handle: handle, view, name })
                }
            };
            wipe(&mut bytes);
            result
        }
    }

    impl Drop for TicketMapping {
        fn drop(&mut self) {
            unsafe {
                for i in 0..TICKET_MAP_CAPACITY {
                    std::ptr::write_volatile(self.view.add(i), 0);
                }
                winapi::um::memoryapi::UnmapViewOfFile(self.view as *const _);
            }
        }
    }

    fn wipe(b: &mut [u8]) {
        for x in b.iter_mut() {
            unsafe { std::ptr::write_volatile(x, 0) };
        }
    }

    /// Stub body: wait on the launch's exit event and the launcher process.
    /// Returns the exit code (0 = signalled, 2 = bad setup, 3 = timed out).
    pub fn stub_main(args: &StubArgs) -> i32 {
        unsafe {
            let ev = Handle(OpenEventW(SYNCHRONIZE, FALSE, wide(&args.exit_event).as_ptr()));
            if !ev.valid() {
                return 2;
            }
            let parent = Handle(OpenProcess(SYNCHRONIZE, FALSE, args.parent_pid));
            if !parent.valid() {
                return 2;
            }
            let handles = [ev.raw(), parent.raw()];
            match WaitForMultipleObjects(2, handles.as_ptr(), FALSE, 120_000) {
                r if r == WAIT_OBJECT_0 || r == WAIT_OBJECT_0 + 1 => 0,
                WAIT_TIMEOUT => 3,
                _ => 2,
            }
        }
    }

    /// Session-wide named mutex serializing launches (also across processes,
    /// e.g. separate Wine launches): the SDK pipe has a fixed name, and is
    /// created first-instance only, so one launch at a time may be between
    /// "pipe created" and "shim ready".
    struct LaunchLock(Handle);

    impl LaunchLock {
        fn acquire() -> Result<LaunchLock> {
            let h = Handle(unsafe { CreateMutexW(std::ptr::null_mut(), FALSE, wide(LAUNCH_MUTEX).as_ptr()) });
            if !h.valid() {
                return Err(anyhow!("CreateMutex failed: {}", std::io::Error::last_os_error()));
            }
            match unsafe { WaitForSingleObject(h.raw(), LAUNCH_LOCK_TIMEOUT_MS) } {
                // Abandoned = a previous launcher died holding it; we own it now.
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(LaunchLock(h)),
                _ => Err(anyhow!("Another game launch is still starting; try again shortly.")),
            }
        }
    }

    impl Drop for LaunchLock {
        fn drop(&mut self) {
            // Runs before the Handle field closes it; same thread that acquired it.
            unsafe { ReleaseMutex(self.0.raw()) };
        }
    }

    fn deploy_dir() -> Result<PathBuf> {
        let base = std::env::var("LOCALAPPDATA").map_err(|_| anyhow!("LOCALAPPDATA not set"))?;
        let dir = PathBuf::from(base).join("mabi-patcher").join("nxl3p");
        std::fs::create_dir_all(dir.join("bin"))?;
        Ok(dir)
    }

    /// Write `bytes`/copy `src` only when the destination differs (it may be in use).
    fn sync_file(dest: &Path, src: Option<&Path>, bytes: Option<&[u8]>) -> Result<()> {
        let want_len = match (src, bytes) {
            (Some(s), _) => std::fs::metadata(s)?.len(),
            (_, Some(b)) => b.len() as u64,
            _ => return Ok(()),
        };
        let same = std::fs::metadata(dest).map(|m| m.len() == want_len).unwrap_or(false)
            && match (src, bytes) {
                (Some(s), _) => {
                    let a = std::fs::metadata(s)?.modified().ok();
                    let b = std::fs::metadata(dest)?.modified().ok();
                    matches!((a, b), (Some(a), Some(b)) if b >= a)
                }
                (_, Some(b)) => std::fs::read(dest).map(|d| d == b).unwrap_or(false),
                _ => true,
            };
        if same {
            return Ok(());
        }
        match (src, bytes) {
            (Some(s), _) => {
                std::fs::copy(s, dest)?;
            }
            (_, Some(b)) => std::fs::write(dest, b)?,
            _ => {}
        }
        Ok(())
    }

    /// The stub process; on drop (failure paths) its exit event is set and it is killed.
    struct StubGuard {
        child: Option<std::process::Child>,
        exit_event: Option<Handle>,
    }

    impl StubGuard {
        fn disarm(mut self) -> (std::process::Child, Handle) {
            (self.child.take().unwrap(), self.exit_event.take().unwrap())
        }
    }

    impl Drop for StubGuard {
        fn drop(&mut self) {
            if let Some(ev) = &self.exit_event {
                unsafe { SetEvent(ev.raw()) };
            }
            if let Some(c) = self.child.as_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    pub fn launch(
        client_exe: &Path,
        args: &[String],
        ticket: &str,
        hashed_user_no: &str,
        wait: bool,
        on_started: &dyn Fn(u32),
    ) -> Result<u32> {
        if SHIM_DLL.is_empty() {
            return Err(anyhow!("This build has no embedded nxl3p shim — rebuild for Windows."));
        }
        // Held until the shim has the ticket (or we gave up) and this launch's
        // pipe server is stopped: the SDK pipe name is fixed.
        let lock = LaunchLock::acquire()?;
        // 1. Deploy stub (copy of ourselves) + shim.
        let dir = deploy_dir()?;
        let stub = dir.join("nexon_client.exe");
        let me = std::env::current_exe()?;
        sync_file(&stub, Some(&me), None).map_err(|e| anyhow!("deploy stub: {}", e))?;
        sync_file(&dir.join("bin").join("nexon_x64.dll"), None, Some(SHIM_DLL))
            .map_err(|e| anyhow!("deploy shim: {}", e))?;

        let tmp = std::env::temp_dir();
        let _ = super::trim_log_file(&tmp.join(super::SHIM_LOG_FILE), super::SHIM_LOG_MAX, super::SHIM_LOG_KEEP);
        // Older builds handed the ticket over in a fixed %TEMP% file; never leave one behind.
        let _ = std::fs::remove_file(tmp.join(LEGACY_TICKET_FILE));

        // 2. Ticket mapping + its ready event, both user-only and per launch.
        let sd = UserOnlySd::new()?;
        let mapping = TicketMapping::create(ticket, &sd)?;
        let shim_ready = private_event(&ready_event_name(&mapping.name), &sd)?;

        // 3. The stub, with its own exit event and our PID (it quits when we do).
        let stub_exit_name = stub_event_name(&new_guid()?);
        let stub_exit = private_event(&stub_exit_name, &sd)?;
        let stub_child = {
            use std::os::windows::process::CommandExt;
            // Null stdio: the stub must not hold our (possibly piped, under Wine)
            // stdout/stderr open after we exit.
            std::process::Command::new(&stub)
                .arg(STUB_FLAG)
                .args(stub_command_args(&stub_exit_name, std::process::id()))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .spawn()
                .map_err(|e| anyhow!("Stub spawn failed: {}", e))?
        };
        let mut stub_guard = StubGuard { child: Some(stub_child), exit_event: Some(stub_exit) };
        std::thread::sleep(std::time::Duration::from_millis(300));
        if let Some(Ok(Some(status))) = stub_guard.child.as_mut().map(|c| c.try_wait()) {
            return Err(anyhow!("The nexon_client.exe helper exited during setup ({})", status));
        }

        // 4. Client.exe: suspended, with the mapping name in its environment, so
        //    the pipe can be bound to its PID before it runs. A client that needs
        //    elevation goes through ShellExecuteEx (UAC prompt) instead; UAC drops
        //    the environment, so the name rides on the command line too.
        let game_dir = client_exe.parent().unwrap_or(Path::new("."));
        let params = args.iter().map(|a| super::quote_arg(a)).collect::<Vec<_>>().join(" ");
        let (game, pipe) = match create_suspended(client_exe, &params, game_dir, &mapping.name) {
            Ok((process, thread)) => {
                let pipe = match PipeServer::start(ticket, hashed_user_no, &process, &sd) {
                    Ok(p) => p,
                    Err(e) => {
                        unsafe { TerminateProcess(process.raw(), 1) };
                        return Err(e);
                    }
                };
                if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
                    let err = os_err("ResumeThread", unsafe { GetLastError() });
                    unsafe { TerminateProcess(process.raw(), 1) };
                    pipe.stop();
                    return Err(err);
                }
                (process, pipe)
            }
            Err(code) if code == ERROR_ELEVATION_REQUIRED => {
                log::info!("Client.exe requires elevation; starting it through ShellExecuteEx");
                let process = shell_execute(client_exe, &params_with_map_arg(&params, &mapping.name), game_dir)?;
                let pipe = match PipeServer::start(ticket, hashed_user_no, &process, &sd) {
                    Ok(p) => p,
                    Err(e) => {
                        unsafe { TerminateProcess(process.raw(), 1) };
                        return Err(e);
                    }
                };
                (process, pipe)
            }
            Err(code) => return Err(os_err(&format!("Failed to start {}", client_exe.display()), code)),
        };
        let pid = unsafe { GetProcessId(game.raw()) };
        log::info!("Client.exe launched pid={}", pid);
        on_started(pid);

        // 5. Even without `wait`, stay until the shim has taken the ticket (or the game
        //    exits, or the timeout passes) so the SDK pipe can serve Client.exe, then
        //    give the SDK a short grace period to finish its pipe requests. The pipe
        //    is only needed during start-up (a no-wait CLI launch exits right after
        //    this), so stop it then and release the launch lock.
        let handles = [shim_ready.raw(), game.raw()];
        let r = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), FALSE, SHIM_READY_TIMEOUT_MS) };
        if r == WAIT_OBJECT_0 {
            std::thread::sleep(std::time::Duration::from_millis(SHIM_GRACE_MS));
        } else if r == WAIT_TIMEOUT {
            log::warn!("nxl3p shim did not report ready within {} s; closed the ticket mapping", SHIM_READY_TIMEOUT_MS / 1000);
        }
        // The shim has the ticket, the game is gone, or we gave up: wipe and close it.
        drop(mapping);
        drop(shim_ready);
        pipe.stop();
        drop(lock);

        // 6. Watcher: game exit → stub exit (runs to completion only with `wait`).
        let (mut stub_child, stub_exit) = stub_guard.disarm();
        let watcher = std::thread::spawn(move || {
            unsafe {
                WaitForSingleObject(game.raw(), INFINITE);
                SetEvent(stub_exit.raw());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = stub_child.kill();
            let _ = stub_child.wait();
            log::info!("Client.exe exited — launch cleanup done");
        });
        if wait {
            let _ = watcher.join();
        }
        Ok(pid)
    }

    /// CreateProcessW(CREATE_SUSPENDED) with `TICKET_MAP_ENV=<map_name>` added to
    /// our environment. Returns (process, main thread) or the Win32 error code.
    fn create_suspended(exe: &Path, params: &str, dir: &Path, map_name: &str) -> std::result::Result<(Handle, Handle), DWORD> {
        use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
        use winapi::um::winbase::{CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, STARTF_USESHOWWINDOW};
        let vars = std::env::vars_os()
            .map(|(k, v)| (k.encode_wide().collect(), v.encode_wide().collect()))
            .collect();
        let mut env = env_block_with(vars, TICKET_MAP_ENV, map_name);
        let app = wide(&exe.to_string_lossy());
        let mut cmdline = wide(&format!("\"{}\" {}", exe.display(), params));
        let dir = wide(&dir.to_string_lossy());
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = 1; // SW_SHOWNORMAL
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                app.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                env.as_mut_ptr() as *mut _,
                dir.as_ptr(),
                &mut si,
                &mut pi,
            )
        };
        // The command line holds the passport: don't leave it in our heap.
        for c in cmdline.iter_mut() {
            unsafe { std::ptr::write_volatile(c, 0) };
        }
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok((Handle(pi.hProcess), Handle(pi.hThread)))
    }

    /// ShellExecuteEx, which shows the UAC prompt for a client manifest that requires
    /// elevation; returns the process handle (enough to read its PID and wait on it).
    fn shell_execute(exe: &Path, params: &str, dir: &Path) -> Result<Handle> {
        use winapi::um::shellapi::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
        let file = wide(&exe.to_string_lossy());
        let params = wide(params);
        let dir = wide(&dir.to_string_lossy());
        let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpFile = file.as_ptr();
        sei.lpParameters = params.as_ptr();
        sei.lpDirectory = dir.as_ptr();
        sei.nShow = 1; // SW_SHOWNORMAL
        if unsafe { ShellExecuteExW(&mut sei) } == 0 || sei.hProcess.is_null() {
            return Err(anyhow!("Failed to start {}: {}", exe.display(), std::io::Error::last_os_error()));
        }
        Ok(Handle(sei.hProcess))
    }

    /// Serves the Nexon SDK pipe to the game process only: frames are
    /// [i32 LE length][UTF-8 JSON]. One overlapped, first-instance pipe instance
    /// (user-only DACL, remote clients rejected), reconnected for each client.
    struct PipeServer {
        pipe: Handle,
        stop: Handle,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    /// Frame size limit (requests are small JSON).
    const MAX_PIPE_FRAME: usize = 1 << 16;
    /// How long one connect / read / write may wait before it is re-checked or dropped.
    const PIPE_IO_TIMEOUT_MS: u32 = 30_000;

    impl PipeServer {
        fn start(ticket: &str, hashed_user_no: &str, game: &Handle, sd: &UserOnlySd) -> Result<PipeServer> {
            use winapi::um::namedpipeapi::CreateNamedPipeW;
            use winapi::um::winbase::{
                FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
            };
            // Our own handle to the game, owned by the server thread.
            let mut dup: HANDLE = std::ptr::null_mut();
            let me = unsafe { GetCurrentProcess() };
            if unsafe { DuplicateHandle(me, game.raw(), me, &mut dup, 0, FALSE, DUPLICATE_SAME_ACCESS) } == 0 {
                return Err(os_err("DuplicateHandle", unsafe { GetLastError() }));
            }
            let game = Handle(dup);
            let game_pid = unsafe { GetProcessId(game.raw()) };
            if game_pid == 0 || unsafe { WaitForSingleObject(game.raw(), 0) } != WAIT_TIMEOUT {
                return Err(anyhow!("The game process is not running"));
            }
            let stop = Handle(unsafe { CreateEventW(std::ptr::null_mut(), TRUE, FALSE, std::ptr::null()) });
            if !stop.valid() {
                return Err(os_err("CreateEvent", unsafe { GetLastError() }));
            }
            let mut sa = sd.attributes();
            let pipe = Handle(unsafe {
                CreateNamedPipeW(
                    wide(NEXON_PIPE_NAME).as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    4096,
                    4096,
                    5000,
                    &mut sa,
                )
            });
            if !pipe.valid() {
                let code = unsafe { GetLastError() };
                if code == ERROR_ACCESS_DENIED || code == ERROR_PIPE_BUSY {
                    return Err(anyhow!(
                        "The Nexon SDK pipe is already in use by another program (is the Nexon Launcher running?). Close it and try again."
                    ));
                }
                return Err(os_err("CreateNamedPipe", code));
            }
            let (raw_pipe, raw_stop) = (pipe.raw() as usize, stop.raw() as usize);
            let (ticket, hashed_user_no) = (ticket.to_string(), hashed_user_no.to_string());
            let thread = std::thread::spawn(move || {
                let mut ticket = ticket;
                serve(raw_pipe as HANDLE, raw_stop as HANDLE, &game, game_pid, &ticket, &hashed_user_no);
                // Wipe our copy of the ticket.
                wipe(unsafe { ticket.as_bytes_mut() });
                ticket.clear();
            });
            Ok(PipeServer { pipe, stop, thread: Some(thread) })
        }

        /// Stop serving, wait for the server thread, close the pipe.
        fn stop(mut self) {
            unsafe {
                SetEvent(self.stop.raw());
                winapi::um::ioapiset::CancelIoEx(self.pipe.raw(), std::ptr::null_mut());
            }
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            // `pipe` and `stop` close on drop, after the thread is done with them.
        }
    }

    /// Outcome of one overlapped operation.
    enum Io {
        Done(DWORD),
        /// Timed out (operation cancelled).
        Timeout,
        /// Stop requested or the game exited (operation cancelled).
        Quit,
        Failed,
    }

    /// Run one overlapped pipe operation `op` (returns the Win32 BOOL) and wait for
    /// it, the stop event or the game's exit.
    fn overlapped_io(pipe: HANDLE, stop: HANDLE, game: HANDLE, op: impl FnOnce(*mut OVERLAPPED) -> i32) -> Io {
        use winapi::um::ioapiset::{CancelIoEx, GetOverlappedResult};
        let ev = Handle(unsafe { CreateEventW(std::ptr::null_mut(), TRUE, FALSE, std::ptr::null()) });
        if !ev.valid() {
            return Io::Failed;
        }
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = ev.raw();
        let mut got: DWORD = 0;
        if op(&mut ov) == 0 {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => return Io::Done(0),
                ERROR_IO_PENDING => {}
                _ => return Io::Failed,
            }
            let handles = [ev.raw(), stop, game];
            let r = unsafe { WaitForMultipleObjects(3, handles.as_ptr(), FALSE, PIPE_IO_TIMEOUT_MS) };
            if r != WAIT_OBJECT_0 {
                unsafe {
                    CancelIoEx(pipe, &mut ov);
                    // Keep `ov` alive until the cancellation has completed.
                    GetOverlappedResult(pipe, &mut ov, &mut got, TRUE);
                }
                return if r == WAIT_TIMEOUT { Io::Timeout } else { Io::Quit };
            }
        }
        if unsafe { GetOverlappedResult(pipe, &mut ov, &mut got, FALSE) } == 0 {
            return Io::Failed;
        }
        Io::Done(got)
    }

    fn signalled(h: HANDLE) -> bool {
        unsafe { WaitForSingleObject(h, 0) == WAIT_OBJECT_0 }
    }

    /// The connected client is the game (by PID) and the game is still running.
    fn authorized(pipe: HANDLE, game: HANDLE, game_pid: DWORD) -> bool {
        let mut pid: u32 = 0;
        let ok = unsafe { winapi::um::winbase::GetNamedPipeClientProcessId(pipe, &mut pid) } != 0;
        if !(ok && pid == game_pid && !signalled(game)) {
            log::warn!("pipe: rejected a client (pid {}) that is not the launched game", pid);
            return false;
        }
        true
    }

    fn serve(pipe: HANDLE, stop: HANDLE, game: &Handle, game_pid: DWORD, ticket: &str, hashed_user_no: &str) {
        use winapi::um::namedpipeapi::{ConnectNamedPipe, DisconnectNamedPipe};
        while !signalled(stop) && !signalled(game.raw()) {
            match overlapped_io(pipe, stop, game.raw(), |ov| unsafe { ConnectNamedPipe(pipe, ov) }) {
                Io::Done(_) => {
                    if authorized(pipe, game.raw(), game_pid) {
                        log::info!("pipe: game connected");
                        serve_client(pipe, stop, game, game_pid, ticket, hashed_user_no);
                    }
                }
                Io::Timeout => continue,
                Io::Quit => break,
                Io::Failed => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
            unsafe { DisconnectNamedPipe(pipe) };
        }
        unsafe { DisconnectNamedPipe(pipe) };
    }

    /// Read or write exactly `buf.len()` bytes.
    fn transfer(pipe: HANDLE, stop: HANDLE, game: HANDLE, buf: &mut [u8], writing: bool) -> bool {
        use winapi::um::fileapi::{ReadFile, WriteFile};
        let mut done = 0;
        while done < buf.len() {
            let rest = &mut buf[done..];
            let (ptr, len) = (rest.as_mut_ptr(), rest.len() as DWORD);
            let r = overlapped_io(pipe, stop, game, |ov| unsafe {
                if writing {
                    WriteFile(pipe, ptr as *const _, len, std::ptr::null_mut(), ov)
                } else {
                    ReadFile(pipe, ptr as *mut _, len, std::ptr::null_mut(), ov)
                }
            });
            match r {
                Io::Done(n) if n > 0 => done += n as usize,
                _ => return false,
            }
        }
        true
    }

    fn serve_client(pipe: HANDLE, stop: HANDLE, game: &Handle, game_pid: DWORD, ticket: &str, hashed_user_no: &str) {
        let game_h = game.raw();
        loop {
            let mut len = [0u8; 4];
            if !transfer(pipe, stop, game_h, &mut len, false) {
                return;
            }
            let n = i32::from_le_bytes(len);
            if n <= 0 || n as usize > MAX_PIPE_FRAME {
                return;
            }
            let mut body = vec![0u8; n as usize];
            if !transfer(pipe, stop, game_h, &mut body, false) || !authorized(pipe, game_h, game_pid) {
                return;
            }
            let (mut resp, close) = pipe_response(&body, ticket, hashed_user_no);
            let typ = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["type"].as_str().map(str::to_string))
                .unwrap_or_default();
            log::info!("pipe: {}", typ.chars().take(40).collect::<String>());
            let mut header = (resp.len() as i32).to_le_bytes();
            let ok = transfer(pipe, stop, game_h, &mut header, true) && transfer(pipe, stop, game_h, &mut resp, true);
            wipe(&mut resp); // may hold the ticket
            if !ok || close {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn trim_log_keeps_tail_on_line_boundary() {
        let path = std::env::temp_dir().join(format!("mabi_trim_log_{}.log", std::process::id()));
        let line = "0123456789abcdef\n"; // 17 bytes
        std::fs::write(&path, line.repeat(100)).unwrap(); // 1700 bytes
        trim_log_file(&path, 2000, 100).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1700, "under the limit: untouched");
        trim_log_file(&path, 1000, 100).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.len() <= 100 && text.starts_with('0') && text.ends_with('\n'), "{:?}", text);
        let _ = std::fs::remove_file(&path);
        trim_log_file(&path, 1, 1).unwrap(); // missing file is fine
    }

    use super::*;

    #[test]
    fn quote_arg_keeps_existing_quotes() {
        assert_eq!(quote_arg("-a"), "-a");
        assert_eq!(quote_arg("C:\\Program Files\\x"), "\"C:\\Program Files\\x\"");
        let s = "setting:\"file://data/features.xml=Regular, USA\"";
        assert_eq!(quote_arg(s), s);
        assert_eq!(quote_arg("\"already quoted\""), "\"already quoted\"");
    }

    #[test]
    fn split_command_line_quotes() {
        let v = |s: &str| split_command_line(s);
        assert!(v("").is_empty());
        assert!(v("   \t ").is_empty());
        assert_eq!(v("a  b\tc"), ["a", "b", "c"]);
        assert_eq!(v(r#""C:\Program Files\Mabi\Client.exe" /P:{passport} {args}"#),
            [r"C:\Program Files\Mabi\Client.exe", "/P:{passport}", "{args}"]);
        assert_eq!(v(r#"--name="a b" x"#), ["--name=a b", "x"]);
        assert_eq!(v(r#""say \"hi\"" end"#), [r#"say "hi""#, "end"]);
        assert_eq!(v(r#"a "" b"#), ["a", "", "b"]);
        assert_eq!(v(r"C:\dir\x.exe"), [r"C:\dir\x.exe"]);
    }

    #[test]
    fn pipe_ticket_and_config() {
        let (r, close) = pipe_response(
            br#"{"type":"getProductTicket","id":"7","req":{"productId":10200}}"#,
            "TICKET",
            "USER",
        );
        let v: serde_json::Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(v["res"]["ticket"], "TICKET");
        assert_eq!(v["id"], "7");
        assert!(!close);
        let (r, _) = pipe_response(br#"{"type":"getSDKConfiguration","req":{"productId":10200}}"#, "T", "USER");
        let v: serde_json::Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(v["res"]["hashedUserNo"], "USER");
        let (_, close) = pipe_response(br#"{"type":"productClosed"}"#, "T", "U");
        assert!(close);
    }

    #[test]
    fn profile_placeholder_is_case_insensitive() {
        assert_eq!(replace_ci("run %profile% now %PROFILE%", "%PROFILE%", "Main"), "run Main now Main");
        assert_eq!(replace_ci("no placeholder", "%PROFILE%", "x"), "no placeholder");
    }

    #[test]
    fn started_line_roundtrip() {
        let info = LaunchInfo {
            pid: 4242,
            executable: "C:/Mabi/Client.exe".into(),
            argument_count: 3,
            patch_available: true,
            session_expires_in: Some(60),
        };
        let back = parse_started_line(&format!("{}\r\n", started_line(&info))).unwrap();
        assert_eq!((back.pid, back.argument_count, back.patch_available), (4242, 3, true));
        assert!(parse_started_line("Launched C:/Mabi/Client.exe (pid 1).").is_none());
    }

    #[test]
    fn guid_and_object_names() {
        let g = format_guid([0xab; 16]);
        assert!(is_braced_guid(&g), "{}", g);
        assert_eq!(&g[15..16], "4", "version nibble");
        assert!(is_braced_guid("{01234567-89ab-cdef-0123-456789ABCDEF}"));
        for bad in ["", "{}", "01234567-89ab-cdef-0123-456789abcdef", "{01234567-89ab-cdef-0123-456789abcdeg}",
            "{0123456789ab-cdef-0123-456789abcdef-}"] {
            assert!(!is_braced_guid(bad), "{}", bad);
        }
        let map = ticket_map_name(&g);
        assert_eq!(map, format!(r"Local\mabi-patcher.ticket.{}", g));
        assert!(is_ticket_map_name(&map));
        assert!(!is_ticket_map_name(&stub_event_name(&g)));
        assert!(!is_ticket_map_name(r"Global\mabi-patcher.ticket.{01234567-89AB-CDEF-0123-456789ABCDEF}"));
        assert_eq!(ready_event_name(&map), format!("{}.ready", map));
        assert!(stub_event_name(&g).starts_with(r"Local\mabi-patcher.stub.{"));
        assert_ne!(format_guid([1; 16]), format_guid([2; 16]));
    }

    #[test]
    fn stub_args_parse_and_reject() {
        let ev = stub_event_name("{01234567-89AB-CDEF-0123-456789ABCDEF}");
        let args = stub_command_args(&ev, 4242);
        assert_eq!(parse_stub_args(&args, 7), Some(StubArgs { exit_event: ev.clone(), parent_pid: 4242 }));
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_stub_args(&args, 4242), None, "own pid as parent");
        assert_eq!(parse_stub_args(&s(&["--exit-event", &ev, "--parent-pid", "0"]), 7), None);
        assert_eq!(parse_stub_args(&s(&["--exit-event", &ev, "--parent-pid", "x"]), 7), None);
        assert_eq!(parse_stub_args(&s(&["--exit-event", &ev, "--parent-pid", "99999999999"]), 7), None);
        assert_eq!(parse_stub_args(&s(&["--exit-event", "MABI_NXL3P_StubExit", "--parent-pid", "5"]), 7), None);
        assert_eq!(parse_stub_args(&s(&["--exit-event", &ev]), 7), None, "missing parent");
        assert_eq!(parse_stub_args(&s(&[]), 7), None, "legacy bare flag");
        assert_eq!(parse_stub_args(&s(&["--parent-pid", "5", "--exit-event", &ev]), 7), None, "order is fixed");
        let mut extra = args.clone();
        extra.push("--more".into());
        assert_eq!(parse_stub_args(&extra, 7), None);
    }

    #[test]
    fn map_arg_round_trip() {
        let map = ticket_map_name("{01234567-89AB-CDEF-0123-456789ABCDEF}");
        let p = params_with_map_arg("/P:abc /L:en", &map);
        assert_eq!(p, format!("/P:abc /L:en --mabi-map {}", map));
        assert_eq!(map_name_from_command_line(&format!("\"C:\\Mabi\\Client.exe\" {}", p)), Some(map.as_str()));
        assert_eq!(params_with_map_arg("", &map), format!("--mabi-map {}", map));
        assert_eq!(map_name_from_command_line("Client.exe /P:abc"), None);
        assert_eq!(map_name_from_command_line("Client.exe --mabi-map"), None);
        assert_eq!(map_name_from_command_line(r"Client.exe --mabi-map Local\evil"), None);
    }

    #[test]
    fn ticket_map_encoding() {
        let v = encode_ticket_map("passport-ü").unwrap();
        assert_eq!(v.len(), TICKET_MAP_CAPACITY);
        assert_eq!(&v[..4], b"MPT1");
        assert_eq!(decode_ticket_map(&v).as_deref(), Some("passport-ü"));
        assert!(encode_ticket_map("").is_err());
        assert!(encode_ticket_map("a\0b").is_err());
        assert!(encode_ticket_map(&"x".repeat(TICKET_MAX_CHARS + 1)).is_err());
        assert!(encode_ticket_map(&"x".repeat(TICKET_MAX_CHARS)).is_ok());
        let mut bad = v.clone();
        bad[0] = 0;
        assert_eq!(decode_ticket_map(&bad), None);
        assert_eq!(decode_ticket_map(&vec![0u8; TICKET_MAP_CAPACITY]), None, "zeroed by the shim");
    }

    #[test]
    fn env_block_sets_and_replaces_key() {
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        let vars = vec![(w("Path"), w(r"C:\x")), (w("mabi_patcher_ticket_map"), w("old")), (w("=C:"), w(r"C:\"))];
        let block = env_block_with(vars, TICKET_MAP_ENV, "NEW");
        let text = String::from_utf16(&block).unwrap();
        assert!(text.ends_with("\0\0"));
        let entries: Vec<&str> = text.trim_end_matches('\0').split('\0').collect();
        assert_eq!(entries, [r"=C:=C:\", "MABI_PATCHER_TICKET_MAP=NEW", r"Path=C:\x"]);
    }

    #[test]
    fn passport_substitution() {
        let c = LaunchConfig { arguments: vec!["/P:${passport}".into(), "/L:en".into()], ..Default::default() };
        assert_eq!(c.build_args("abc"), vec!["/P:abc", "/L:en"]);
        let c = LaunchConfig { arguments: vec!["/L:en".into()], ..Default::default() };
        assert_eq!(c.build_args("abc"), vec!["/L:en", "/P:abc"]);
    }
}
