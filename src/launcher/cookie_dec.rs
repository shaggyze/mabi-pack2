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
    let local_state_path = std::path::PathBuf::from(localappdata)
        .join("com.shaggyze.mabi-patcher")
        .join("EBWebView")
        .join("Default")
        .join("Local State");
    let text = std::fs::read_to_string(&local_state_path).map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let b64_key = json["os_crypt"]["encrypted_key"].as_str().ok_or("No encrypted_key in Local State")?;
    let decoded = BASE64_STANDARD.decode(b64_key).map_err(|e| e.to_string())?;
    if decoded.len() < 5 || &decoded[0..5] != b"DPAPI" {
        return Err("Invalid key format (expected DPAPI prefix)".to_string());
    }
    dpapi_decrypt(&decoded[5..])
}

pub fn decrypt_cookie(encrypted_value: &[u8], key: &[u8]) -> Result<String, String> {
    if encrypted_value.len() < 3 + 12 + 16 || &encrypted_value[0..3] != b"v10" {
        return Err("Invalid cookie format (expected v10 prefix)".to_string());
    }
    let nonce = &encrypted_value[3..3 + 12];
    let ciphertext = &encrypted_value[3 + 12..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce_arr = aes_gcm::Nonce::from_slice(nonce);
    let decrypted = cipher.decrypt(nonce_arr, ciphertext).map_err(|e| e.to_string())?;
    String::from_utf8(decrypted).map_err(|e| e.to_string())
}
