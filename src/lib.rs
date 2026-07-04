pub mod common;
pub mod common_ext;
pub mod encryption;
pub mod extract;
pub mod list;
pub mod pack;
pub mod pack_v1;
pub mod patch;
pub mod pmg;

pub const SALTS_URL: &str = "https://shaggyze.website/files/salts.txt";

use std::fs::File as StdFile;
use std::io::{BufReader as StdBufReader, BufRead};
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

pub fn load_salts() -> Vec<String> {
    let mut cache = CACHED_SALTS.lock().unwrap();
    if cache.is_none() {
        // Initialize with hardcoded salts immediately and store in cache
        let initial: Vec<String> = HARDCODED_SALTS.iter().map(|s| s.to_string()).collect();
        *cache = Some(initial.clone());
        drop(cache);

        // Start background fetch to augment with local file + remote salts
        std::thread::spawn(|| {
            let mut salts: Vec<String> = HARDCODED_SALTS.iter().map(|s| s.to_string()).collect();
            let local_path = Path::new("salts.txt");

            if local_path.exists() {
                if let Ok(file) = StdFile::open(local_path) {
                    let reader = StdBufReader::new(file);
                    for line in reader.lines() {
                        if let Ok(salt) = line {
                            let s = salt.trim().to_string();
                            if !s.is_empty() && !s.starts_with('#') && !salts.contains(&s) {
                                salts.push(s);
                            }
                        }
                    }
                }
            }

            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build();

            if let Ok(c) = client {
                if let Ok(response) = c.get(SALTS_URL).send() {
                    if response.status().is_success() {
                        if let Ok(text) = response.text() {
                            for line in text.lines() {
                                let s = line.trim().to_string();
                                if !s.is_empty() && !s.starts_with('#') && !salts.contains(&s) {
                                    salts.push(s);
                                }
                            }
                        }
                    }
                }
            }

            let mut cache = CACHED_SALTS.lock().unwrap();
            *cache = Some(salts);
        });

        return initial;
    }
    if let Some(ref s) = *cache {
        return s.clone();
    }
    HARDCODED_SALTS.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption;
    use std::io::{Cursor, Read};
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::fs::File;

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
