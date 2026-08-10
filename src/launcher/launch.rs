// Client.exe launch config fetcher and process spawner.
//
// Fetches the official launch arguments from Nexon's game-build API
// (the same endpoint Hyddwn uses), injects the passport token, then
// spawns Client.exe as a detached process.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::auth::NexonSession;

const NEXON_BASE: &str = "https://www.nexon.com";
const PRODUCT_ID: &str = "10200";

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LaunchConfig {
    /// Nexon-provided launch arguments (from `parameter` JSON array).
    pub arguments: Vec<String>,
    /// Relative path to Client.exe inside the game folder (e.g. "Client.exe").
    pub executable_path: String,
    /// Patch available flag from the config response.
    pub patch_available: bool,
}

// ── Response model ────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct ConfigResponse {
    #[serde(rename = "parameter")]
    arguments: Option<Vec<String>>,
    #[serde(rename = "executablePath")]
    executable_path: Option<String>,
    #[serde(rename = "executablePathBit64")]
    executable_path_64: Option<String>,
    #[serde(rename = "patch")]
    patch_available: Option<bool>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetch launch configuration from Nexon's game-build API.
pub fn fetch_launch_config(session: &NexonSession) -> Result<LaunchConfig> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0")
        .build()?;

    let resp = client
        .get(format!("{}/api/game-build/v1/configuration/games/{}", NEXON_BASE, PRODUCT_ID))
        .header("Cookie", session.cookie_header())
        .header("Authorization", format!("Bearer {}", session.access_token))
        .send()?;

    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if !status.is_success() {
        return Err(anyhow!("Launch config fetch failed ({}): {}", status, body));
    }

    let cfg: ConfigResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("Launch config parse error: {} body={}", e, body))?;

    let executable_path = cfg
        .executable_path_64
        .or(cfg.executable_path)
        .unwrap_or_else(|| "Client.exe".to_string());

    Ok(LaunchConfig {
        arguments: cfg.arguments.unwrap_or_default(),
        executable_path,
        patch_available: cfg.patch_available.unwrap_or(false),
    })
}

impl LaunchConfig {
    /// Build the argument list with the passport injected at `/P:`.
    /// Matches Hyddwn's ClientLaunchArguments.ToString() format:
    ///   `code:{Code} ver:{Ver} ... /P:{Passport} logip:{...} ...`
    pub fn build_args(&self, passport: &str) -> Vec<String> {
        let mut args = self.arguments.clone();

        // Find or append the /P: argument
        let passport_arg = format!("/P:{}", passport);
        if let Some(pos) = args.iter().position(|a| a.starts_with("/P:")) {
            args[pos] = passport_arg;
        } else {
            args.push(passport_arg);
        }

        args
    }

    /// Spawn Client.exe as a detached process with the given passport.
    ///
    /// `client_dir` — the Mabinogi installation directory.
    /// Returns the child process handle (you can drop it to detach).
    pub fn spawn_client(&self, client_dir: &Path, passport: &str) -> Result<std::process::Child> {
        let exe = client_dir.join(&self.executable_path);
        if !exe.exists() {
            return Err(anyhow!("Client.exe not found at: {}", exe.display()));
        }

        let args = self.build_args(passport);

        // Single space-joined argument string (matches how Nexon's launcher passes args)
        let arg_str = args.join(" ");

        let mut cmd = std::process::Command::new(&exe);
        cmd.current_dir(client_dir).args(&args);

        // Windows: CREATE_NO_WINDOW + DETACHED_PROCESS so it runs independent of our process
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x00000008); // DETACHED_PROCESS
        }

        log::info!("Launching: {} {}", exe.display(), arg_str);
        let child = cmd.spawn()
            .map_err(|e| anyhow!("Failed to spawn Client.exe: {}", e))?;
        Ok(child)
    }
}

/// Launch Client.exe directly with a custom command string or default args.
/// `cmd_override`: if Some and non-empty, used as-is with variable substitution.
///   Variables: {client_dir}, {passport}, {exe}
///   Plus all API-provided args are available as {args}.
/// Returns the argument count that was used.
pub fn launch_direct(
    client_dir: &Path,
    passport: &str,
    args: &[String],
    cmd_override: Option<&str>,
) -> Result<usize> {
    let exe = client_dir.join("Client.exe");
    if !exe.exists() {
        return Err(anyhow!("Client.exe not found at: {}", exe.display()));
    }

    if let Some(override_cmd) = cmd_override.filter(|s| !s.trim().is_empty()) {
        // Variable substitution in custom command
        let expanded = override_cmd
            .replace("{client_dir}", &client_dir.to_string_lossy())
            .replace("{exe}", &exe.to_string_lossy())
            .replace("{passport}", passport)
            .replace("{args}", &args.join(" "));

        // Split the expanded command into parts and spawn
        let parts: Vec<&str> = expanded.split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow!("Empty launch command"));
        }
        let mut cmd = std::process::Command::new(parts[0]);
        cmd.args(&parts[1..]).current_dir(client_dir);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x00000008); // DETACHED_PROCESS
        }
        log::info!("Direct launch (custom): {}", expanded);
        cmd.spawn().map_err(|e| anyhow!("Launch failed: {}", e))?;
        return Ok(parts.len() - 1);
    }

    // Default: inject passport into API args and spawn
    let passport_arg = format!("/P:{}", passport);
    let mut full_args = args.to_vec();
    if let Some(pos) = full_args.iter().position(|a| a.starts_with("/P:")) {
        full_args[pos] = passport_arg;
    } else {
        full_args.push(passport_arg);
    }

    let arg_count = full_args.len();
    let mut cmd = std::process::Command::new(&exe);
    cmd.current_dir(client_dir).args(&full_args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000008); // DETACHED_PROCESS
    }
    log::info!("Direct launch: {} {}", exe.display(), full_args.join(" "));
    cmd.spawn().map_err(|e| anyhow!("Failed to spawn Client.exe: {}", e))?;
    Ok(arg_count)
}

// ── Serializable summary for Tauri IPC ───────────────────────────────────────

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

/// Run a shell hook command (pre/post launch). Empty string = no-op.
/// Runs synchronously and returns stdout+stderr combined.
pub fn run_hook_cmd(cmd: &str, working_dir: &Path) -> Result<String> {
    if cmd.trim().is_empty() {
        return Ok(String::new());
    }
    let output = std::process::Command::new("cmd")
        .args(["/C", cmd])
        .current_dir(working_dir)
        .output()
        .map_err(|e| anyhow!("Hook command failed to start: {}", e))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    log::info!("Hook '{}' exit={}: {}", cmd, output.status, combined.trim());
    Ok(combined)
}
