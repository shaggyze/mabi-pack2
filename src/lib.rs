pub mod api;
pub mod area;
pub mod common;
pub mod launcher;
pub mod common_ext;
pub mod encryption;
pub mod extract;
pub mod itemdb;
pub mod list;
pub mod mcp;
pub mod mod_file;
pub mod pack;
pub mod pack_v1;
pub mod patch;
pub mod pmg;
pub mod region_map;
pub mod rgn;

pub const SALTS_URL: &str = "https://shaggyze.website/files/salts.txt";

use std::path::Path;

/// Hardcoded known salts. Most common at the top for performance.
pub const HARDCODED_SALTS: &[&str] = &[
    "@6QeTuOaDgJlZcBm#9",
    "s_U[ht6c%!5gG4NZ|b",
    "F1#/e~MKiAP>|ksz/<",
    "})wWb4?-sVGHNoPKpc",
    "CuAVPMZx:E96:(Rxdw",
    "DaXU_Vx9xy;[ycFz{1",
    "}F33F0}_7X^;b?PM/;",
    "C(K^x&pBEeg7A5;{G9",
    "3@6|3a[@<Ex:L=eN|g",
    "smh=Pdw+%?wk?m4&(y",
    "xGqK]W+_eM5u3[8-8u",
    "1&w2!&w{Q)Fkz4e&p0",
    "@wvK#}'Xp)7DEA_2:#",
    "`K3;Z5~too=|XhHtmh",
    "EqCN'nOCGNaw<8NJ0{",
    "C+V?q-W>?;=iT81qvg",
    "Rzf;Q0v?,oXQQ[YE5m",
    "9t+.<N,jtbznQNrOzE",
    "J'7TL!AGKHGI]5`;(j",
    "0bABB`[YIWF34K!mxz",
    "3H;-s.E9^Txlt17}JD",
    "m5'hA,`aY*fx7opRL7",
    ":vEf?4wrglFd$rA$nc",
    "oD2hPSDm]9QP_!tKy{",
    "aT2d_jL%aX9s5j<7Kk",
    "/O^K7}^i*p)!Y)3_5&",
    "[^Uz6~kxX(j%w2q<X8",
    "C3)eWj]1D6_4?{ZF5d",
    "AAC(*()S&&**&*(A**",
    "]0/N}ofxT<K83MA]fO",
];

use once_cell::sync::Lazy;
use std::sync::Mutex;

static CACHED_SALTS: Lazy<Mutex<Option<Vec<String>>>> = Lazy::new(|| Mutex::new(None));

/// How long the first `load_salts` call waits for the remote salt list. A slower
/// response is still merged into the cache when it arrives.
const REMOTE_SALTS_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// Append the salts listed in `text` (one per line, `#` comments) that are new.
fn merge_salt_lines(text: &str, salts: &mut Vec<String>) {
    for line in text.lines() {
        let s = line.trim();
        if !s.is_empty() && !s.starts_with('#') && !salts.iter().any(|x| x == s) {
            salts.push(s.to_string());
        }
    }
}

fn fetch_remote_salts() -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(REMOTE_SALTS_WAIT)
        .build()
        .ok()?;
    let response = client.get(SALTS_URL).send().ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().ok()
}

/// Built-in salts, then `salts.txt` in the working directory, then the remote
/// list. The first call builds the full list synchronously (waiting at most
/// `REMOTE_SALTS_WAIT` for the network); later calls return the cached list.
pub fn load_salts() -> Vec<String> {
    let mut cache = CACHED_SALTS.lock().unwrap();
    if let Some(ref s) = *cache {
        return s.clone();
    }

    let mut salts: Vec<String> = HARDCODED_SALTS.iter().map(|s| s.to_string()).collect();
    if let Ok(text) = std::fs::read_to_string(Path::new("salts.txt")) {
        merge_salt_lines(&text, &mut salts);
    }

    // The fetch runs on its own thread (a blocking reqwest client must not run
    // inside an async runtime) and is waited for with a bound.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || { let _ = tx.send(fetch_remote_salts()); });
    match rx.recv_timeout(REMOTE_SALTS_WAIT) {
        Ok(Some(text)) => merge_salt_lines(&text, &mut salts),
        Ok(None) => {}
        Err(_) => {
            // Too slow: merge it into the cache whenever it arrives.
            std::thread::spawn(move || {
                if let Ok(Some(text)) = rx.recv() {
                    if let Some(cached) = CACHED_SALTS.lock().unwrap().as_mut() {
                        merge_salt_lines(&text, cached);
                    }
                }
            });
        }
    }

    *cache = Some(salts.clone());
    salts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption;
    use std::io::{Cursor, Read};
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::fs::File;

    #[test]
    fn merge_salt_lines_skips_comments_and_duplicates() {
        let mut salts = vec!["a".to_string()];
        merge_salt_lines("# comment\n a \nb\n\nb\nc", &mut salts);
        assert_eq!(salts, vec!["a", "b", "c"]);
    }

    #[test]
    fn first_load_salts_includes_salts_txt() {
        let local = std::fs::read_to_string("salts.txt").unwrap_or_default();
        let salts = load_salts();
        assert!(salts.len() >= HARDCODED_SALTS.len());
        for line in local.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            assert!(salts.iter().any(|s| s == line), "salts.txt entry {:?} missing", line);
        }
    }

    #[test]
    fn test_snow2_roundtrip() {
        let key = [0u8; 16];
        let mut data = [0xAA; 16];
        let original = data.clone();
        encryption::snow2_encrypt(&key, 1, &mut data);
        encryption::snow2_decrypt(&key, 1, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    #[ignore] // Research scan: only run via `cargo test -- --ignored`
    fn brute_force_header() {
        let path = "gemini-testing/data_00002.it";
        if !Path::new(path).exists() { return; }
        let mut f = File::open(path).unwrap();
        let mut buf = vec![0u8; 1024 * 1024]; 
        let read = f.read(&mut buf).unwrap();
        let buf = &buf[..read];

        let salt = "@6QeTuOaDgJlZcBm#9";
        let fname = "data_00002.it";
        
        let keys = vec![
            encryption::gen_header_key(fname, salt),
            {
                let input: Vec<u16> = (fname.to_lowercase() + salt).encode_utf16().collect();
                let v: Vec<u8> = (0..16).map(|i| input[i % input.len()].wrapping_add(i as u16) as u8).collect();
                v.try_into().unwrap()
            }
        ];

        println!("Starting brute force scan on {} bytes...", buf.len());
        for key in keys {
            for i in 0..(buf.len() - 9) {
                if i % 1024 != 0 { continue; } 
                let mut cur = Cursor::new(&buf[i..i+9]);
                let mut dec = encryption::Snow2Decoder::new_iv(&key, 1, &mut cur);
                if let Ok(checksum) = dec.read_u32::<LittleEndian>() {
                    if let Ok(ver) = dec.read_u8() {
                        if let Ok(count) = dec.read_u32::<LittleEndian>() {
                            let calc = (ver as u32).wrapping_add(count);
                            if calc == checksum && count > 0 && count < 200000 && (ver == 1 || ver == 2) {
                                println!("FOUND HEADER at 0x{:X}! Ver={}, Count={}", i, ver, count);
                            }
                        }
                    }
                }
            }
        }
    }
}
