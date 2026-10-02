// Game launch without the official Nexon Launcher (port of Rua's uGameLaunch /
// uPipeServer / uProtocol, made standalone):
//
//   1. auth::prepare_launch      account → access → playable → passport (401 → refresh)
//   2. fetch_launch_config       parameters with ${passport} template
//   3. Deploy to %LOCALAPPDATA%\mabi-patcher\nxl3p\:
//        nexon_client.exe        = a copy of this exe, run with --nxl3p-stub
//        bin\nexon_x64.dll       = embedded nxl3p-shim (hands the passport to the game)
//      nexon_api_x64.dll in the game finds the running nexon_client.exe and loads
//      <its dir>\bin\nexon_x64.dll — that's how the ticket gets into Client.exe.
//   4. Ticket → %TEMP%\mabi-patcher-nxl3p-ticket.txt (shim reads + deletes it)
//   5. Named pipe \\.\pipe\{79d303ac-...} answers the SDK's getProductTicket /
//      getSDKConfiguration requests.
//   6. ShellExecuteEx Client.exe; a watcher thread cleans up when the game exits.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::auth::{self, NexonSession, API_BASE, PRODUCT_ID};

pub const STUB_FLAG: &str = "--nxl3p-stub";
pub const TICKET_FILE: &str = "mabi-patcher-nxl3p-ticket.txt";
#[cfg(windows)]
const STUB_EXIT_EVENT: &str = "MABI_NXL3P_StubExit";
#[cfg(windows)]
const SHIM_READY_EVENT: &str = "MABI_NXL3P_ShimReady";
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
            .get(format!("{}/game-build/v1/configuration/games/{}", API_BASE, PRODUCT_ID))
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
pub fn run_stub_if_requested() {
    if !std::env::args().skip(1).any(|a| a == STUB_FLAG) {
        return;
    }
    #[cfg(windows)]
    win::stub_main();
    std::process::exit(0);
}

// ── Custom / direct launch (private servers, user overrides) ─────────────────

/// Launch Client.exe with explicit args, or a user command override.
/// Override variables: {client_dir}, {exe}, {passport}, {args}.
pub fn launch_direct(client_dir: &Path, passport: &str, args: &[String], cmd_override: Option<&str>) -> Result<usize> {
    let exe = client_dir.join("Client.exe");
    if !exe.exists() {
        return Err(anyhow!("Client.exe not found at: {}", exe.display()));
    }
    if let Some(over) = cmd_override.filter(|s| !s.trim().is_empty()) {
        let expanded = over
            .replace("{client_dir}", &client_dir.to_string_lossy())
            .replace("{exe}", &exe.to_string_lossy())
            .replace("{passport}", passport)
            .replace("{args}", &args.join(" "));
        let parts: Vec<&str> = expanded.split_whitespace().collect();
        let (prog, rest) = parts.split_first().ok_or_else(|| anyhow!("Empty launch command"))?;
        let mut cmd = std::process::Command::new(prog);
        cmd.args(rest).current_dir(client_dir);
        detach(&mut cmd);
        log::info!("Direct launch (custom): {}", expanded);
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

/// Start a hook command without waiting for it (Rua's event hooks).
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
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use winapi::shared::minwindef::FALSE;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::shared::winerror::WAIT_TIMEOUT;
    use winapi::um::synchapi::{CreateEventW, OpenEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject};
    use winapi::um::winbase::WAIT_OBJECT_0;
    use winapi::um::winnt::HANDLE;

    const SYNCHRONIZE: u32 = 0x0010_0000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Handle(HANDLE);
    unsafe impl Send for Handle {}
    impl Handle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub fn stub_main() {
        unsafe {
            let name = wide(STUB_EXIT_EVENT);
            let ev = OpenEventW(SYNCHRONIZE, FALSE, name.as_ptr());
            if ev.is_null() {
                std::thread::sleep(std::time::Duration::from_secs(120));
            } else {
                WaitForSingleObject(ev, 120_000);
                CloseHandle(ev);
            }
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
        // 1. Deploy stub (copy of ourselves) + shim.
        let dir = deploy_dir()?;
        let stub = dir.join("nexon_client.exe");
        let me = std::env::current_exe()?;
        sync_file(&stub, Some(&me), None).map_err(|e| anyhow!("deploy stub: {}", e))?;
        sync_file(&dir.join("bin").join("nexon_x64.dll"), None, Some(SHIM_DLL))
            .map_err(|e| anyhow!("deploy shim: {}", e))?;

        // 2. Ticket for the shim.
        let ticket_path = std::env::temp_dir().join(TICKET_FILE);
        std::fs::write(&ticket_path, ticket)?;

        // 3. Events, then the stub.
        let stub_exit = Handle(unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, wide(STUB_EXIT_EVENT).as_ptr()) });
        let shim_ready = Handle(unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, wide(SHIM_READY_EVENT).as_ptr()) });
        let mut stub_child = {
            use std::os::windows::process::CommandExt;
            // Null stdio: the stub lives up to 120 s and must not hold our (possibly
            // piped, under Wine) stdout/stderr open after we exit.
            std::process::Command::new(&stub)
                .arg(STUB_FLAG)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .spawn()
                .map_err(|e| anyhow!("Stub spawn failed: {}", e))?
        };
        std::thread::sleep(std::time::Duration::from_millis(300));

        // 4. Pipe server.
        let pipe = PipeServer::start(ticket.to_string(), hashed_user_no.to_string());

        // 5. Client.exe
        let game_dir = client_exe.parent().unwrap_or(Path::new("."));
        let params = args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ");
        let game = match shell_execute(client_exe, &params, game_dir) {
            Ok(h) => h,
            Err(e) => {
                unsafe { SetEvent(stub_exit.0) };
                let _ = stub_child.kill();
                pipe.stop();
                let _ = std::fs::remove_file(&ticket_path);
                return Err(e);
            }
        };
        let pid = unsafe { winapi::um::processthreadsapi::GetProcessId(game.0) };
        log::info!("Client.exe launched pid={}", pid);
        on_started(pid);

        // 6. Even without `wait`, stay until the shim has taken the ticket (or the game
        //    exits, or the timeout passes) so the SDK pipe can serve Client.exe, then
        //    give the SDK a short grace period to finish its pipe requests.
        let handles = [shim_ready.raw(), game.raw()];
        let r = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), FALSE, SHIM_READY_TIMEOUT_MS) };
        if r == WAIT_OBJECT_0 {
            std::thread::sleep(std::time::Duration::from_millis(SHIM_GRACE_MS));
        } else if r == WAIT_TIMEOUT {
            log::warn!("nxl3p shim did not report ready within {} s; removing the ticket file", SHIM_READY_TIMEOUT_MS / 1000);
            let _ = std::fs::remove_file(&ticket_path);
        }
        drop(shim_ready);

        // 7. Watcher: game exit → cleanup (runs to completion only with `wait`).
        let watcher = std::thread::spawn(move || {
            unsafe {
                WaitForSingleObject(game.raw(), winapi::um::winbase::INFINITE);
                SetEvent(stub_exit.raw());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = stub_child.kill();
            let _ = stub_child.wait();
            let _ = std::fs::remove_file(&ticket_path);
            pipe.stop();
            log::info!("Client.exe exited — launch cleanup done");
        });
        if wait {
            let _ = watcher.join();
        }
        Ok(pid)
    }

    fn quote_arg(a: &str) -> String {
        if a.contains(' ') && !a.starts_with('"') { format!("\"{}\"", a) } else { a.to_string() }
    }

    /// ShellExecuteEx so a client manifest that requires elevation still starts.
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

    /// Serves the Nexon SDK pipe: frames are [i32 LE length][UTF-8 JSON].
    pub struct PipeServer {
        stop: Arc<AtomicBool>,
    }

    impl PipeServer {
        pub fn start(ticket: String, hashed_user_no: String) -> PipeServer {
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            std::thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    if let Err(e) = serve_one(&ticket, &hashed_user_no, &flag) {
                        log::warn!("pipe: {}", e);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            });
            PipeServer { stop }
        }

        pub fn stop(&self) {
            self.stop.store(true, Ordering::Relaxed);
            // Unblock a pending ConnectNamedPipe by connecting to it ourselves.
            let _ = std::fs::OpenOptions::new().read(true).write(true).open(NEXON_PIPE_NAME);
        }
    }

    fn serve_one(ticket: &str, hashed_user_no: &str, stop: &AtomicBool) -> Result<()> {
        use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
        use winapi::um::winbase::{PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT};
        let name = wide(NEXON_PIPE_NAME);
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                5000,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(anyhow!("CreateNamedPipe failed: {}", std::io::Error::last_os_error()));
        }
        let ok = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) } != 0
            || std::io::Error::last_os_error().raw_os_error() == Some(535); // ERROR_PIPE_CONNECTED
        if !ok || stop.load(Ordering::Relaxed) {
            unsafe { CloseHandle(h) };
            return Ok(());
        }
        log::info!("pipe: client connected");
        // File takes ownership of the handle and closes it on drop.
        let mut f = unsafe { std::fs::File::from_raw_handle(h as _) };
        loop {
            let mut len = [0u8; 4];
            if f.read_exact(&mut len).is_err() {
                break;
            }
            let n = i32::from_le_bytes(len);
            if n <= 0 || n > 1 << 20 {
                break;
            }
            let mut body = vec![0u8; n as usize];
            f.read_exact(&mut body)?;
            let (resp, close) = pipe_response(&body, ticket, hashed_user_no);
            log::info!("pipe: {}", String::from_utf8_lossy(&body).chars().take(120).collect::<String>());
            f.write_all(&(resp.len() as i32).to_le_bytes())?;
            f.write_all(&resp)?;
            f.flush()?;
            if close {
                break;
            }
        }
        unsafe { DisconnectNamedPipe(h) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn passport_substitution() {
        let c = LaunchConfig { arguments: vec!["/P:${passport}".into(), "/L:en".into()], ..Default::default() };
        assert_eq!(c.build_args("abc"), vec!["/P:abc", "/L:en"]);
        let c = LaunchConfig { arguments: vec!["/L:en".into()], ..Default::default() };
        assert_eq!(c.build_args("abc"), vec!["/L:en", "/P:abc"]);
    }
}
