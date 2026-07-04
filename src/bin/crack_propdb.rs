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
use miniz_oxide::inflate::decompress_to_vec_zlib;

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

fn zlib_header_offset(b: &[u8]) -> Option<usize> {
    for &off in &[0usize, 4, 8] {
        if off + 2 <= b.len() && b[off] == 0x78 && matches!(b[off + 1], 0x01 | 0x9c | 0xda) {
            return Some(off);
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
    for salt in &salts {
        for name in &names {
            let key = encryption::gen_header_key(name, salt);
            for &mode in &modes {
                for iv0 in [0u32, 1] {
                    for start in 0..16usize {
                        if start + 64 > blob.len() { break; }
                        let mut prefix = blob[start..start + 64].to_vec();
                        encryption::snow2_decrypt_mode(&key, iv0, mode, &mut prefix);
                        if let Some(off) = zlib_header_offset(&prefix) {
                            hits += 1;
                            println!(
                                "ZLIB HEADER: salt={:?} name={:?} mode={:?} iv0={} start={} zoff={} head={:02x?}",
                                salt, name, mode, iv0, start, off, &prefix[..12]
                            );
                            // confirm: full decrypt + inflate
                            let mut full = blob[start..].to_vec();
                            encryption::snow2_decrypt_mode(&key, iv0, mode, &mut full);
                            match decompress_to_vec_zlib(&full[off..]) {
                                Ok(xml) => {
                                    let bom = xml.get(0..2) == Some(&[0xff, 0xfe][..]);
                                    println!(
                                        "  *** INFLATE OK -> {} bytes, utf16_bom={}, head={:02x?}",
                                        xml.len(), bom, &xml[..16.min(xml.len())]
                                    );
                                    if bom {
                                        println!("  >>> SOLVED: salt={:?} name={:?} mode={:?} iv0={} start={} zoff={}",
                                                 salt, name, mode, iv0, start, off);
                                    }
                                }
                                Err(e) => println!("  inflate failed: {:?}", e),
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "\nDone. {} zlib-header hit(s). salts={} names={} modes=6 iv=2 start=16",
        hits, salts.len(), names.len()
    );
}
