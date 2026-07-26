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
        .user_agent("Mozilla/5.0 mabi-patcher/2.0")
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
