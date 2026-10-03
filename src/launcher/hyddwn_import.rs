// Import saved accounts from HyddwnLauncher, the way "Import from Kanan" does.
//
// HyddwnLauncher (Core/ProfileManager.cs, Core/CredentialsStorage.cs) keeps its
// data in %LOCALAPPDATA%\Hyddwn Launcher\, even though the launcher itself is
// installed in the Mabinogi folder:
//
//   clientprofiles.json  [ { "Name", "Location" (Client.exe path), "Guid", "Localization" } ]
//   credentials.json     { "<client profile Guid>": { "Username", "Password" } }
//
// CredentialsStorage base64-encodes the fields in memory, but Json.NET serializes
// the public decoding getters, so the file holds plain text.
//
// Each account with saved credentials becomes a mabi-patcher profile (type
// "hyddwn") through the same login path as Kanan; passwords are only used for
// that login and are never stored or logged.

use super::kanan_import::{self, ImportOutcome, ImportSource, ImportedAccount};
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize)]
struct ClientProfile {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Location", default)]
    location: String,
    #[serde(rename = "Guid", default)]
    guid: String,
}

#[derive(Deserialize)]
struct Credentials {
    #[serde(rename = "Username", default)]
    username: String,
    #[serde(rename = "Password", default)]
    password: String,
}

/// `%LOCALAPPDATA%\Hyddwn Launcher`.
pub fn data_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Hyddwn Launcher"))
}

/// One Hyddwn client profile and its saved login, if any.
pub struct HyddwnAccount {
    /// Hyddwn's client profile name.
    pub profile_name: String,
    pub account: ImportedAccount,
}

/// Read every client profile that has a saved username.
pub fn read_accounts() -> Result<Vec<HyddwnAccount>> {
    let dir = data_dir().ok_or_else(|| anyhow!("LOCALAPPDATA not set"))?;
    let clients: Vec<ClientProfile> = read_json(&dir.join("clientprofiles.json"))?.unwrap_or_default();
    let creds: HashMap<String, Credentials> = read_json(&dir.join("credentials.json"))?.unwrap_or_default();
    Ok(parse(clients, creds))
}

fn parse(clients: Vec<ClientProfile>, mut creds: HashMap<String, Credentials>) -> Vec<HyddwnAccount> {
    clients
        .into_iter()
        .filter_map(|c| {
            let cred = creds.remove(&c.guid)?;
            if cred.username.trim().is_empty() {
                return None;
            }
            Some(HyddwnAccount {
                profile_name: c.name,
                account: ImportedAccount {
                    username: cred.username.trim().to_string(),
                    password: cred.password,
                    cmd_line: String::new(),
                    launch_with_kanan: false,
                    client_path: c.location,
                },
            })
        })
        .collect()
}

/// `Ok(None)` when the file does not exist; Hyddwn writes UTF-8 with a BOM.
fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<Option<T>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("{}: {}", path.display(), e)),
    };
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(text).map(Some).map_err(|e| anyhow!("{}: {}", path.display(), e))
}

/// Log in and save a session for one Hyddwn account.
pub fn import_account(acct: &HyddwnAccount) -> Result<ImportOutcome> {
    kanan_import::import_account_from(&acct.account, ImportSource::Hyddwn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_profiles_with_credentials_by_guid() {
        let clients: Vec<ClientProfile> = serde_json::from_str(
            r#"[{"Name":"Main","Location":"C:\\Nexon\\Client.exe","Guid":"a"},
                {"Name":"NoCreds","Location":"","Guid":"b"}]"#,
        )
        .unwrap();
        let creds: HashMap<String, Credentials> =
            serde_json::from_str(r#"{"a":{"Username":" me@x.com ","Password":"pw"}}"#).unwrap();
        let out = parse(clients, creds);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].profile_name, "Main");
        assert_eq!(out[0].account.username, "me@x.com");
        assert_eq!(out[0].account.client_path, r"C:\Nexon\Client.exe");
    }
}
