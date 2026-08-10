// Nexon NA patch manifest and version info.
//
// Fetches the manifest URL from the branch endpoint, extracts the version
// from the URL pattern (e.g. "12345R"), and checks maintenance status.
// Full patch download (download2.nexon.net file fetching, zlib decompress,
// diff application) is deferred — see plans.ts roadmap item `launch-mabitd`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::auth::NexonSession;

const NEXON_BASE: &str = "https://www.nexon.com";
const PRODUCT_ID: &str = "10200";

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ManifestInfo {
    pub manifest_url: String,
    /// Integer version extracted from manifest URL (e.g. "12345" from "12345R").
    pub version: i32,
}

// ── Response models ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BranchResponse {
    #[serde(rename = "manifestUrl")]
    manifest_url: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetch the manifest URL and extract the latest build version.
pub fn fetch_manifest(session: &NexonSession) -> Result<ManifestInfo> {
    let client = build_client()?;

    let resp = client
        .get(format!("{}/api/game-build/v1/branch/games/{}/public", NEXON_BASE, PRODUCT_ID))
        .header("Cookie", session.cookie_header())
        .send()?;

    let status = resp.status();
    let body = resp.text().unwrap_or_default();

    if !status.is_success() {
        return Err(anyhow!("Manifest fetch failed ({}): {}", status, body));
    }

    let branch: BranchResponse = serde_json::from_str(&body)
        .map_err(|e| anyhow!("Manifest parse error: {} body={}", e, body))?;

    let manifest_url = branch.manifest_url
        .ok_or_else(|| anyhow!("No manifestUrl in branch response"))?;

    let version = extract_version(&manifest_url);

    Ok(ManifestInfo { manifest_url, version })
}

/// Fetch the latest build version (convenience wrapper around `fetch_manifest`).
pub fn get_latest_version(session: &NexonSession) -> Result<i32> {
    Ok(fetch_manifest(session)?.version)
}

/// Check if Mabinogi is currently under maintenance.
/// Returns `true` if maintenance is active (HTTP 200), `false` if not (HTTP 404).
pub fn is_maintenance(session: &NexonSession) -> Result<bool> {
    let resp = build_client()?
        .get(format!("{}/api/maintenance/v1/products/{}", NEXON_BASE, PRODUCT_ID))
        .query(&[("lang", "en")])
        .header("Cookie", session.cookie_header())
        .send()?;

    Ok(resp.status().is_success() && resp.status() != reqwest::StatusCode::NOT_FOUND)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0")
        .build()?)
}

/// Extract version integer from manifest URL.
/// Hyddwn regex: `([\d]*R)` → strip 'R' → parse as i32.
/// Example: `.../12345R/manifest.json` → 12345
fn extract_version(url: &str) -> i32 {
    // Walk path segments looking for one that matches \d+R
    for segment in url.split('/') {
        if segment.ends_with('R') {
            let digits = &segment[..segment.len() - 1];
            if digits.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(v) = digits.parse::<i32>() {
                    return v;
                }
            }
        }
    }
    0
}
