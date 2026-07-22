/// mabi-patcher `.mod` instruction file — TOML-based mod package descriptor.
///
/// A `.mod` file tells mabi-patcher how to build a mod archive:
/// - metadata for the WebUI to display
/// - which files to replace/delete inside the archive
/// - feature flag toggles (features.xml.compiled round-trip)
/// - optional import from uotiaralist.ini
/// - pack/extract settings
/// - API exposure metadata
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModMeta {
    pub name: String,
    pub version: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    /// Target game region: "NA" | "TW" | "JP" | "KR"
    pub game: Option<String>,
    pub min_game_version: Option<u32>,
    pub tags: Option<Vec<String>>,
    pub homepage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackSettings {
    /// Archive filename to produce (e.g. "uotiara_00001.it")
    pub output: Option<String>,
    /// Encryption salt for packing
    pub pack_key: Option<String>,
    /// Salt for extracting the base archive before patching
    pub extract_key: Option<String>,
    /// Wrap output directory in data/ subfolder
    pub wrap_data: Option<bool>,
    /// Pack version (1 = v1/pack, 2 = v2/it)
    pub pack_version: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Replace,
    Delete,
    Patch,
}

impl Default for FileAction {
    fn default() -> Self { FileAction::Replace }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModFile {
    /// Path inside the archive (e.g. "data/db/cutscene/c2/iria_finding.xml")
    pub archive_path: String,
    /// Local file to use as replacement (relative to .mod file). Required for Replace/Patch.
    pub source: Option<String>,
    #[serde(default)]
    pub action: FileAction,
    /// Binary patch: list of (offset_hex, original_hex, patched_hex)
    pub patches: Option<Vec<BytePatch>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytePatch {
    pub offset: String, // hex string e.g. "0x1A4"
    pub original: String,
    pub patched: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureSettings {
    pub enable: Option<Vec<String>>,
    pub disable: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IniImport {
    /// Path to uotiaralist.ini (relative to .mod or absolute)
    pub path: String,
    /// Mod names to import from the ini
    pub entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiSettings {
    /// Expose this mod via the REST API
    pub public: Option<bool>,
    /// Override the API endpoint path
    pub endpoint: Option<String>,
    /// Allow WebUI users to install this mod remotely
    pub allow_remote: Option<bool>,
}

/// Top-level `.mod` file structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModPackage {
    pub meta: ModMeta,
    #[serde(default)]
    pub pack: PackSettings,
    #[serde(default)]
    pub files: Vec<ModFile>,
    #[serde(default)]
    pub features: FeatureSettings,
    pub from_ini: Option<IniImport>,
    pub api: Option<ApiSettings>,
}

impl ModPackage {
    /// Parse a `.mod` file from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_str(&text)
    }

    /// Parse from TOML string.
    pub fn from_str(toml: &str) -> Result<Self> {
        let pkg: ModPackage = toml::from_str(toml)
            .map_err(|e| anyhow::anyhow!("Failed to parse .mod file: {}", e))?;
        pkg.validate()?;
        Ok(pkg)
    }

    fn validate(&self) -> Result<()> {
        if self.meta.name.is_empty() {
            bail!(".mod file must have [meta] name");
        }
        for f in &self.files {
            if f.archive_path.is_empty() {
                bail!("Each [[files]] entry must have archive_path");
            }
            if matches!(f.action, FileAction::Replace | FileAction::Patch) && f.source.is_none() && f.patches.is_none() {
                bail!("[[files]] entry '{}' with action replace/patch must have source or patches", f.archive_path);
            }
        }
        Ok(())
    }

    /// Serialize back to TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| anyhow::anyhow!("Serialize error: {}", e))
    }

    pub fn is_api_public(&self) -> bool {
        self.api.as_ref().and_then(|a| a.public).unwrap_or(false)
    }

    /// Count total file operations defined in this mod.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

/// Scan a directory for .mod files and return their paths + parsed metadata.
pub fn scan_mods(dir: &Path) -> Vec<(std::path::PathBuf, Result<ModPackage>)> {
    let mut results = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "mod").unwrap_or(false) {
                let pkg = ModPackage::load(&path);
                results.push((path, pkg));
            }
        }
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    results
}

/// Generate a template `.mod` file as a TOML string.
pub fn template() -> &'static str {
    r#"# mabi-patcher .mod instruction file
# https://github.com/shaggyze/mabi-pack2

[meta]
name        = "My Mod"
version     = "1.0.0"
author      = "YourName"
description = "Brief description of what this mod does"
game        = "NA"
tags        = ["performance", "visual"]

[pack]
output      = "uotiara_00001.it"
pack_key    = "})wWb4?-sVGHNoPKpc"
extract_key = "@6QeTuOaDgJlZcBm#9"
wrap_data   = true

# --- File replacements -------------------------------------------------------
# Each [[files]] entry maps one archive path to a local file (or deletes it).

[[files]]
archive_path = "data/db/cutscene/c2/iria_finding.xml"
source       = "mod_files/iria_finding.xml"
action       = "replace"

# [[files]]
# archive_path = "data/gfx/fx/effect/heavy_effect.xml"
# action       = "delete"

# --- Feature flag toggles ----------------------------------------------------
[features]
enable  = []
disable = []

# --- Import from uotiaralist.ini (optional) ----------------------------------
# [from_ini]
# path    = "uotiaralist.ini"
# entries = ["Autoproduction Uncaps", "Dungeon Fog Removal 1"]

# --- API settings (optional) -------------------------------------------------
[api]
public       = false
allow_remote = false
"#
}
