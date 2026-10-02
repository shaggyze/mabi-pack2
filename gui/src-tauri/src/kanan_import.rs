// "Import from Kanan" commands: read Kanan's profiles.dat with the master
// password the user types, list its accounts (emails only), then import the
// selected ones by logging in and saving the resulting sessions to profiles.
// The master password and the account passwords never leave this process,
// are never logged, and are not stored (mabi-patcher keeps only sessions).

use mabi_pack2::launcher::kanan_import as kanan;

/// Default profiles.dat location, if one exists (for the file picker).
#[tauri::command]
pub fn kanan_default_path() -> Option<String> {
    kanan::default_path().map(|p| p.to_string_lossy().into_owned())
}

/// Decrypt profiles.dat and return `[{ index, username, has_password }]`.
#[tauri::command]
pub async fn kanan_list_accounts(path: String, master_password: String) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut master_password = master_password;
        let file = kanan::resolve_path(Some(std::path::Path::new(&path))).map_err(|e| e.to_string());
        let accounts = file.and_then(|f| kanan::read_profiles(&f, &master_password).map_err(|e| e.to_string()));
        kanan::wipe_string(&mut master_password);
        let list: Vec<_> = accounts?
            .iter()
            .enumerate()
            .map(|(i, a)| serde_json::json!({ "index": i, "username": a.username, "has_password": !a.password.is_empty() }))
            .collect();
        Ok(serde_json::Value::Array(list))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Import the accounts at `indices`: one profile + login each. Returns one
/// `ImportOutcome` per account (`status`: logged_in | mfa_required | failed).
#[tauri::command]
pub async fn kanan_import_accounts(path: String, master_password: String, indices: Vec<usize>) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut master_password = master_password;
        let file = kanan::resolve_path(Some(std::path::Path::new(&path))).map_err(|e| e.to_string());
        let accounts = file.and_then(|f| kanan::read_profiles(&f, &master_password).map_err(|e| e.to_string()));
        kanan::wipe_string(&mut master_password);
        let accounts = accounts?;
        let mut out = Vec::new();
        for i in indices {
            let Some(acct) = accounts.get(i) else { continue };
            let outcome = kanan::import_account(acct).map_err(|e| e.to_string())?;
            log::info!("[Launcher] Kanan import: {} -> profile '{}'", outcome.username, outcome.profile_name);
            out.push(outcome);
        }
        serde_json::to_value(out).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Finish an MFA challenge from `kanan_import_accounts`; saves the session.
#[tauri::command]
pub async fn kanan_import_otp(profile_id: String, mfa_key: String, otp: String) -> Result<i32, String> {
    tauri::async_runtime::spawn_blocking(move || kanan::complete_mfa(&profile_id, &mfa_key, &otp).map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}
