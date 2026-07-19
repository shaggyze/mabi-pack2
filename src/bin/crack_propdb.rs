// crack_propdb.rs - Brute-force the PropDB.xml inner SNOW2 layer.
//
// PropDB.xml (and PropStateDB.xml) on disk = base64 text wrapping an encrypted
// binary blob (constant magic fa 8d bc 51 38 e9 09 88 40 66 7c 26, entropy 8.0).
// Decoding chain is believed to be: base64( SNOW2( zlib( utf16le_xml ) ) ).
//
// This tries every salt in salts.txt x a few filename candidates x every Snow2Mode
// x iv0 in {0,1} x a small start-offset, decrypts the prefix, and looks for a zlib
// header (78 9c / 78 01 / 78 da). On a header hit it decrypts the full blob and
// inflates, expecting a UTF-16 LE BOM (ff fe). Prints the winning parameters.
//
// Usage:
//   cargo run --release --bin crack_propdb -- <path-to-PropDB.xml>
// Default path points at the uotiara source PropDB if no arg is given.

use std::fs;
use mabi_pack2::encryption::{self, Snow2Mode};
use miniz_oxide::inflate::{decompress_to_vec_zlib, decompress_to_vec};

const DEFAULT_PROPDB: &str =
    r"C:\Users\Shaggy\Documents\GitHub\uotiara\Tiara's Moonshine Mod\data\db\PropDB.xml";

/// Minimal standard-alphabet base64 decoder (tolerates whitespace/newlines).
fn b64_decode(input: &[u8]) -> Vec<u8> {
    fn val(c: u8) -> i32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as i32,
            b'a'..=b'z' => (c - b'a' + 26) as i32,
            b'0'..=b'9' => (c - b'0' + 52) as i32,
            b'+' => 62,
            b'/' => 63,
            _ => -1, // '=' and whitespace
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in input {
        let v = val(c);
        if v < 0 { continue; }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Scan the first 32 bytes for a zlib header (0x78 CMF, 0x01/0x9c/0xda FLG) at ANY offset.
fn zlib_header_offset(b: &[u8]) -> Option<usize> {
    let n = b.len().min(32);
    for off in 0..n.saturating_sub(1) {
        if b[off] == 0x78 && matches!(b[off + 1], 0x01 | 0x5e | 0x9c | 0xda) {
            return Some(off);
        }
    }
    None
}

/// Try every inflate interpretation and report the first that yields UTF-16-looking XML.
fn try_inflate(full: &[u8], off: usize) -> Option<(String, Vec<u8>)> {
    let attempts: [(&str, Vec<u8>); 3] = [
        ("zlib@off", full.get(off..).unwrap_or(&[]).to_vec()),
        ("raw@off+2", full.get(off + 2..).unwrap_or(&[]).to_vec()),
        ("raw@off", full.get(off..).unwrap_or(&[]).to_vec()),
    ];
    for (label, data) in attempts.iter() {
        let res = if label.starts_with("zlib") {
            decompress_to_vec_zlib(data)
        } else {
            decompress_to_vec(data)
        };
        if let Ok(x) = res {
            if x.len() > 64 { return Some((label.to_string(), x)); }
        }
    }
    None
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_PROPDB.to_string());
    println!("--- Cracking inner SNOW2 of {} ---", path);

    let raw = fs::read(&path).expect("read PropDB.xml");
    let blob = b64_decode(&raw);
    println!("base64-decoded blob: {} bytes, magic = {:02x?}", blob.len(), &blob[..12.min(blob.len())]);

    let salts: Vec<String> = fs::read_to_string("salts.txt")
        .expect("read salts.txt (run from repo root)")
        .lines()
        .map(|l| l.trim_end_matches(['\r', '\n']).to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let names = [
        "propdb.xml", "PropDB.xml", "data/db/propdb.xml", "db/propdb.xml",
        "propstatedb.xml", "propdb", "", "data.it", "language.it",
    ];
    let modes = [
        Snow2Mode::Sub, Snow2Mode::Xor,
        Snow2Mode::ModernBE, Snow2Mode::ModernLE,
        Snow2Mode::LegacyBE, Snow2Mode::LegacyLE,
    ];

    let mut hits = 0u32;
    let mut solved = 0u32;
    for salt in &salts {
        for name in &names {
            let key = encryption::gen_header_key(name, salt);
            for &mode in &modes {
                for iv0 in 0u32..4 {
                    for start in 0..16usize {
                        if start + 64 > blob.len() { break; }
                        let mut prefix = blob[start..start + 64].to_vec();
                        encryption::snow2_decrypt_mode(&key, iv0, mode, &mut prefix);
                        if let Some(off) = zlib_header_offset(&prefix) {
                            hits += 1;
                            println!(
                                "ZLIB HDR: salt={:?} name={:?} mode={:?} iv0={} start={} zoff={}\n  dec[..32]={:02x?}",
                                salt, name, mode, iv0, start, off, &prefix[..32]
                            );
                            // confirm with a full decrypt + every inflate interpretation
                            let mut full = blob[start..].to_vec();
                            encryption::snow2_decrypt_mode(&key, iv0, mode, &mut full);
                            match try_inflate(&full, off) {
                                Some((how, xml)) => {
                                    let bom = xml.get(0..2) == Some(&[0xff, 0xfe][..]);
                                    println!("  *** INFLATE OK via {} -> {} bytes, utf16_bom={}, head={:02x?}",
                                             how, xml.len(), bom, &xml[..24.min(xml.len())]);
                                    println!("  >>> SOLVED: salt={:?} name={:?} mode={:?} iv0={} start={} zoff={} inflate={}",
                                             salt, name, mode, iv0, start, off, how);
                                    solved += 1;
                                }
                                None => println!("  inflate failed (all interpretations) -- header likely coincidental or per-file IV"),
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "\nDone. {} zlib-header hit(s), {} SOLVED. salts={} names={} modes=6 iv=4 start=16",
        hits, solved, salts.len(), names.len()
    );
}
