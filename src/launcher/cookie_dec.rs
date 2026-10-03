use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::prelude::*;

#[cfg(target_os = "windows")]
use winapi::um::dpapi::CryptUnprotectData;
#[cfg(target_os = "windows")]
use winapi::um::wincrypt::CRYPTOAPI_BLOB;

#[cfg(target_os = "windows")]
pub fn dpapi_decrypt(encrypted: &[u8]) -> Result<Vec<u8>, String> {
    use std::ptr;
    let mut data_in = CRYPTOAPI_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_ptr() as *mut _,
    };
    let mut data_out = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let success = unsafe {
        CryptUnprotectData(&mut data_in, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, &mut data_out)
    };
    if success == 0 {
        return Err("CryptUnprotectData failed".to_string());
    }
    let decrypted = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) }.to_vec();
    unsafe { winapi::um::winbase::LocalFree(data_out.pbData as *mut _) };
    Ok(decrypted)
}

#[cfg(not(target_os = "windows"))]
pub fn dpapi_decrypt(_encrypted: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI only available on Windows".to_string())
}

pub fn get_webview2_key() -> Result<Vec<u8>, String> {
    let localappdata = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA not set".to_string())?;
    // Chromium keeps `Local State` at the user-data root, beside (not inside) the `Default` profile.
    let local_state_path = std::path::PathBuf::from(localappdata)
        .join("com.shaggyze.mabi-patcher")
        .join("EBWebView")
        .join("Local State");
    get_chromium_key(&local_state_path)
}

/// Decrypt the AES-256 master key from a Chromium `Local State` file
/// (`os_crypt.encrypted_key`, base64 → strip 5-byte "DPAPI" prefix → DPAPI decrypt).
/// Works for any Chromium browser (Chrome/Edge/Brave) and the app's own WebView2.
pub fn get_chromium_key(local_state_path: &std::path::Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(local_state_path).map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let b64_key = json["os_crypt"]["encrypted_key"].as_str().ok_or("No encrypted_key in Local State")?;
    let decoded = BASE64_STANDARD.decode(b64_key).map_err(|e| e.to_string())?;
    if decoded.len() < 5 || &decoded[0..5] != b"DPAPI" {
        return Err("Invalid key format (expected DPAPI prefix)".to_string());
    }
    dpapi_decrypt(&decoded[5..])
}

/// Chromium cookie DBs at `meta.version` >= 24 prepend SHA-256(host_key) (32
/// bytes) to every cookie value before encrypting it; strip it from the
/// decrypted bytes. Older DBs (and too-short values) are returned unchanged.
pub fn strip_host_hash(decrypted: &[u8], db_version: i64) -> &[u8] {
    const HOST_HASH_LEN: usize = 32;
    if db_version >= 24 && decrypted.len() >= HOST_HASH_LEN {
        &decrypted[HOST_HASH_LEN..]
    } else {
        decrypted
    }
}

/// Decrypt a `v10` AES-256-GCM cookie value; `db_version` is the cookie DB's
/// `meta.version` (see [`strip_host_hash`]).
pub fn decrypt_cookie(encrypted_value: &[u8], key: &[u8], db_version: i64) -> Result<String, String> {
    if encrypted_value.len() < 3 + 12 + 16 || &encrypted_value[0..3] != b"v10" {
        return Err("Invalid cookie format (expected v10 prefix)".to_string());
    }
    let nonce = &encrypted_value[3..3 + 12];
    let ciphertext = &encrypted_value[3 + 12..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce_arr = aes_gcm::Nonce::try_from(nonce).map_err(|_| "Invalid cookie nonce".to_string())?;
    let decrypted = cipher.decrypt(&nonce_arr, ciphertext).map_err(|e| e.to_string())?;
    String::from_utf8(strip_host_hash(&decrypted, db_version).to_vec()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_hash_stripped_only_from_v24_dbs() {
        let mut v = vec![0xAAu8; 32];
        v.extend_from_slice(b"cookie-value");
        assert_eq!(strip_host_hash(&v, 24), b"cookie-value");
        assert_eq!(strip_host_hash(&v, 25), b"cookie-value");
        assert_eq!(strip_host_hash(&v, 23), &v[..]);
        assert_eq!(strip_host_hash(b"short", 24), b"short");
    }

    #[test]
    fn decrypt_cookie_strips_hash_for_v24() {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut plain = vec![0xFFu8; 32];
        plain.extend_from_slice(b"NxLSession-value");
        let ct = cipher.encrypt(&aes_gcm::Nonce::try_from(&nonce[..]).unwrap(), plain.as_slice()).unwrap();
        let mut enc = b"v10".to_vec();
        enc.extend_from_slice(&nonce);
        enc.extend_from_slice(&ct);
        assert_eq!(decrypt_cookie(&enc, &key, 24).unwrap(), "NxLSession-value");
        assert!(decrypt_cookie(&enc, &key, 0).is_err(), "hash bytes are not UTF-8");
    }
}
