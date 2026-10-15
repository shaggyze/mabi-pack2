// Authenticode check of Client.exe before an official launch.
//
// The official launch hands the game a Nexon login ticket and often runs it
// elevated, so it must start the real Nexon binary. `verify_nexon_client`
// checks the file's signature with WinVerifyTrust (revocation checked across the
// whole chain) and requires the signer's organization to be NEXON. The returned
// guard keeps Client.exe open with read-only sharing until it is dropped, so the
// file cannot be replaced between the check and process creation.

use anyhow::{anyhow, Result};
use std::path::Path;

/// Open handle on a verified Client.exe; other processes can read it but not
/// write, rename or delete it while this lives.
pub struct VerifiedClient {
    #[allow(dead_code)]
    file: std::fs::File,
}

/// Organization name a genuine client signer carries ("NEXON Korea Corporation").
const NEXON_ORG: &str = "NEXON";

/// True if a signer organization name is Nexon's.
fn is_nexon_org(org: &str) -> bool {
    org.to_ascii_uppercase().contains(NEXON_ORG)
}

#[cfg(windows)]
pub fn verify_nexon_client(exe: &Path) -> Result<VerifiedClient> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use winapi::um::winnt::FILE_SHARE_READ;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(exe)
        .map_err(|e| anyhow!("Could not open {}: {}", exe.display(), e))?;
    let org = win::signer_org(exe, file.as_raw_handle() as _)?;
    if !is_nexon_org(&org) {
        return Err(anyhow!(
            "{} is signed by \"{}\", not Nexon. Repair the game files before launching.",
            exe.display(),
            org
        ));
    }
    log::info!("Client.exe signature OK ({})", org);
    Ok(VerifiedClient { file })
}

/// Wine has no Authenticode chain to check against; the Windows side running
/// under Wine performs the check itself.
#[cfg(not(windows))]
pub fn verify_nexon_client(exe: &Path) -> Result<VerifiedClient> {
    let file = std::fs::File::open(exe).map_err(|e| anyhow!("Could not open {}: {}", exe.display(), e))?;
    Ok(VerifiedClient { file })
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::guiddef::GUID;
    use winapi::shared::minwindef::{BOOL, DWORD, FALSE};
    use winapi::um::softpub::WINTRUST_ACTION_GENERIC_VERIFY_V2;
    use winapi::um::wincrypt::{CertGetNameStringW, CERT_CONTEXT, CERT_NAME_ATTR_TYPE};
    use winapi::um::winnt::HANDLE;
    use winapi::um::wintrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    // Leading fields of wintrust.h's CRYPT_PROVIDER_SGNR / CRYPT_PROVIDER_CERT
    // (only read through pointers wintrust returns; the rest is never touched).
    #[repr(C)]
    struct ProviderSigner {
        cb_struct: DWORD,
        verify_as_of: [DWORD; 2],
        cert_count: DWORD,
        certs: *const ProviderCert,
    }
    #[repr(C)]
    struct ProviderCert {
        cb_struct: DWORD,
        cert: *const CERT_CONTEXT,
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WTHelperProvDataFromStateData(state: HANDLE) -> *mut std::ffi::c_void;
        fn WTHelperGetProvSignerFromChain(
            prov: *mut std::ffi::c_void,
            signer: DWORD,
            counter_signer: BOOL,
            counter_index: DWORD,
        ) -> *const ProviderSigner;
    }

    /// Verify `exe` (open as `handle`) and return its signer's organization name.
    pub fn signer_org(exe: &Path, handle: HANDLE) -> Result<String> {
        let path: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as DWORD;
        info.pcwszFilePath = path.as_ptr();
        info.hFile = handle;
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as DWORD;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        unsafe { *data.u.pFile_mut() = &mut info };
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        let status = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut _) };
        let org = if status == 0 { read_org(data.hWVTStateData) } else { None };
        // Always release the verification state, whatever the result.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut _) };

        if status != 0 {
            return Err(anyhow!(
                "{} has no valid Nexon signature (WinVerifyTrust 0x{:08X}). Repair the game files before launching.",
                exe.display(),
                status as u32
            ));
        }
        org.ok_or_else(|| anyhow!("Could not read the signer of {}", exe.display()))
    }

    fn read_org(state: HANDLE) -> Option<String> {
        unsafe {
            let prov = WTHelperProvDataFromStateData(state);
            if prov.is_null() {
                return None;
            }
            let signer = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            if signer.is_null() || (*signer).cert_count == 0 || (*signer).certs.is_null() {
                return None;
            }
            let cert = (*(*signer).certs).cert;
            if cert.is_null() {
                return None;
            }
            let oid = b"2.5.4.10\0"; // szOID_ORGANIZATION_NAME
            let mut buf = [0u16; 256];
            let n = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, oid.as_ptr() as *mut _, buf.as_mut_ptr(), buf.len() as DWORD);
            (n > 1).then(|| String::from_utf16_lossy(&buf[..n as usize - 1]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nexon_org_match() {
        assert!(is_nexon_org("NEXON Korea Corporation"));
        assert!(is_nexon_org("Nexon America Inc."));
        assert!(!is_nexon_org("Evil Corp"));
        assert!(!is_nexon_org(""));
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_file_is_rejected() {
        let dir = std::env::temp_dir().join(format!("mabi_sig_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("Client.exe");
        std::fs::write(&exe, b"MZ not really a program").unwrap();
        assert!(verify_nexon_client(&exe).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live check against the installed client (`cargo test -- --ignored`).
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn installed_client_is_nexon_signed() {
        let exe = Path::new(r"C:\Nexon\Library\mabinogi\appdata\Client.exe");
        if exe.exists() {
            verify_nexon_client(exe).unwrap();
        }
    }
}
