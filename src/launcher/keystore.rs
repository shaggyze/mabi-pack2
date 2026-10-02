// OS keychain for session secrets.
//
// Credential store: on Windows, session tokens live in the
// Windows Credential Manager (generic credentials under `mabi-patcher\<key>`)
// instead of plaintext in profiles.json. `CredWriteW` / `CredReadW` /
// `CredDeleteW` from advapi32 are used directly (no extra crate needed).
//
// On Linux / macOS / Wine the credential manager is not available here, so
// [`available`] returns false and callers keep the secret in the profile file
// (the previous behaviour). A native backend (keyring's Secret Service /
// Keychain) can be slotted in behind this same interface later; the build in
// this environment has no D-Bus/Secret-Service headers, so it is not wired in
// by default.
//
// Blob format: the UTF-8 secret string, stored verbatim. A
// generic credential blob is capped at CRED_MAX_CREDENTIAL_BLOB_SIZE (2560
// bytes); a larger secret (a full cookie session can exceed it) is split into
// numbered parts `<target>\0`, `<target>\1`, ... and the base credential holds
// only the marker `CHUNK_MARKER<count>`. Secrets are JSON, so the marker can
// never collide with a real value.

#[cfg(windows)]
const TARGET_PREFIX: &str = "mabi-patcher\\";

/// Windows `CRED_MAX_CREDENTIAL_BLOB_SIZE` (5 * 512).
#[cfg(any(windows, test))]
const MAX_BLOB: usize = 5 * 512;

#[cfg(any(windows, test))]
const CHUNK_MARKER: &str = "mabi-patcher-chunks:";

/// Split a secret into blob-sized parts (a single part when it fits).
#[cfg(any(windows, test))]
fn split_blob(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() { return vec![bytes]; }
    bytes.chunks(MAX_BLOB).collect()
}

/// Part count encoded in a base-credential blob, if it is a chunk marker.
#[cfg(any(windows, test))]
fn chunk_count(base_blob: &[u8]) -> Option<usize> {
    std::str::from_utf8(base_blob).ok()?.strip_prefix(CHUNK_MARKER)?.parse().ok()
}

#[cfg(any(windows, test))]
fn part_target(target: &str, i: usize) -> String {
    format!("{}\\{}", target, i)
}

/// True when an OS credential store is available on this platform.
pub fn available() -> bool {
    cfg!(windows)
}

/// Store `secret` under `key` in the OS credential store. No-op error if the
/// store is unavailable (callers check [`available`] first).
pub fn store_secret(key: &str, secret: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let target = format!("{}{}", TARGET_PREFIX, key);
        let old_parts = win::cred_read(&target).and_then(|b| chunk_count(&b)).unwrap_or(0);
        let parts = split_blob(secret.as_bytes());
        let new_parts = if parts.len() == 1 {
            win::cred_write(&target, parts[0])?;
            0
        } else {
            // Parts first, marker last: a failure leaves the base unchanged.
            for (i, part) in parts.iter().enumerate() {
                win::cred_write(&part_target(&target, i), part)?;
            }
            win::cred_write(&target, format!("{}{}", CHUNK_MARKER, parts.len()).as_bytes())?;
            parts.len()
        };
        for i in new_parts..old_parts {
            win::cred_delete(&part_target(&target, i));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (key, secret);
        Err("no OS credential store on this platform".into())
    }
}

/// Load the secret stored under `key`, or `None` if absent / unavailable.
pub fn load_secret(key: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let target = format!("{}{}", TARGET_PREFIX, key);
        let base = win::cred_read(&target)?;
        let bytes = match chunk_count(&base) {
            Some(n) => {
                let mut all = Vec::with_capacity(n * MAX_BLOB);
                for i in 0..n {
                    all.extend(win::cred_read(&part_target(&target, i))?);
                }
                all
            }
            None => base,
        };
        String::from_utf8(bytes).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = key;
        None
    }
}

/// Delete the secret stored under `key` (ignored if absent / unavailable).
pub fn delete_secret(key: &str) {
    #[cfg(windows)]
    {
        let target = format!("{}{}", TARGET_PREFIX, key);
        if let Some(n) = win::cred_read(&target).and_then(|b| chunk_count(&b)) {
            for i in 0..n {
                win::cred_delete(&part_target(&target, i));
            }
        }
        win::cred_delete(&target);
    }
    #[cfg(not(windows))]
    {
        let _ = key;
    }
}

#[cfg(windows)]
mod win {
    use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPVOID};
    use winapi::um::wincred::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC, PCREDENTIALW,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn cred_write(target: &str, data: &[u8]) -> Result<(), String> {
        let target_w = wide(target);
        let mut blob = data.to_vec();
        let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = target_w.as_ptr() as *mut u16;
        cred.CredentialBlobSize = blob.len() as DWORD;
        cred.CredentialBlob = blob.as_mut_ptr();
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
        let ok: BOOL = unsafe { CredWriteW(&mut cred, 0) };
        if ok == FALSE {
            return Err(format!("CredWriteW failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn cred_read(target: &str) -> Option<Vec<u8>> {
        let target_w = wide(target);
        let mut pcred: PCREDENTIALW = std::ptr::null_mut();
        let ok = unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut pcred) };
        if ok == FALSE || pcred.is_null() {
            return None;
        }
        let result = unsafe {
            let c = &*pcred;
            let len = c.CredentialBlobSize as usize;
            if len > 0 && !c.CredentialBlob.is_null() {
                std::slice::from_raw_parts(c.CredentialBlob, len).to_vec()
            } else {
                Vec::new()
            }
        };
        unsafe { CredFree(pcred as LPVOID) };
        Some(result)
    }

    pub fn cred_delete(target: &str) {
        let target_w = wide(target);
        unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_matches_platform() {
        assert_eq!(available(), cfg!(windows));
    }

    #[test]
    fn large_secrets_split_into_blob_sized_parts() {
        let small = vec![b'a'; MAX_BLOB];
        assert_eq!(split_blob(&small).len(), 1);
        assert_eq!(split_blob(b"").len(), 1);
        let big: Vec<u8> = (0..MAX_BLOB * 2 + 7).map(|i| i as u8).collect();
        let parts = split_blob(&big);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.len() <= MAX_BLOB));
        assert_eq!(parts.concat(), big);
        assert_eq!(part_target("mabi-patcher\\id", 2), "mabi-patcher\\id\\2");
    }

    #[test]
    fn chunk_marker_round_trip() {
        assert_eq!(chunk_count(format!("{}3", CHUNK_MARKER).as_bytes()), Some(3));
        assert_eq!(chunk_count(br#"{"session_token":"x"}"#), None);
        assert_eq!(chunk_count(b"\xff\xfe"), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_store_is_unavailable() {
        assert!(store_secret("x", "y").is_err());
        assert_eq!(load_secret("x"), None);
        delete_secret("x"); // no panic
    }
}
