/// dump_strings.rs — extract printable ASCII strings from a binary file.
/// Focused on finding Mabinogi salt keys near ".it" references.
///
/// Usage:
///   cargo run --features debug --bin dump_strings -- <file> [min_len]

use std::fs::File;
use std::io::{BufReader, Read};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dump_strings <file> [min_len=14]");
        std::process::exit(1);
    }
    let path = &args[1];
    let min_len: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(14);

    let f = File::open(path).expect("Cannot open file");
    let size = f.metadata().unwrap().len();
    eprintln!("[INFO] Reading {} ({} MB)...", path, size / 1_048_576);

    let mut reader = BufReader::with_capacity(1 << 20, f);
    let mut bytes = Vec::with_capacity(size as usize);
    reader.read_to_end(&mut bytes).expect("read failed");

    eprintln!("[INFO] Extracting strings >= {} chars...", min_len);

    let mut all_strings: Vec<(usize, String)> = Vec::new();
    let mut start = 0;
    let mut in_run = false;

    for (i, &b) in bytes.iter().enumerate() {
        if b >= 0x20 && b <= 0x7E {
            if !in_run { start = i; in_run = true; }
        } else {
            if in_run {
                let len = i - start;
                if len >= min_len {
                    let s = String::from_utf8_lossy(&bytes[start..i]).to_string();
                    all_strings.push((start, s));
                }
            }
            in_run = false;
        }
    }
    if in_run && bytes.len() - start >= min_len {
        let s = String::from_utf8_lossy(&bytes[start..]).to_string();
        all_strings.push((start, s));
    }

    eprintln!("[INFO] Found {} strings total.", all_strings.len());

    // Find all ".it" occurrences and show surrounding strings within 512 bytes
    eprintln!("\n=== STRINGS NEAR \".it\" OCCURRENCES ===");
    let mut near_it: Vec<(usize, &str)> = Vec::new();
    for (off, s) in &all_strings {
        if s.ends_with(".it") || s.contains("data.it") || s.contains(".it\"") {
            near_it.push((*off, s.as_str()));
        }
    }
    eprintln!("[INFO] Found {} \".it\" string hits.", near_it.len());
    for (off, s) in &near_it {
        eprintln!("  0x{:08X}: {}", off, s);
        // Also print strings within 512 bytes before/after
        for (o2, s2) in &all_strings {
            let dist = if *o2 > *off { o2 - off } else { off - o2 };
            if dist > 0 && dist <= 512 {
                eprintln!("    [+{}] {}", *o2 as i64 - *off as i64, s2);
            }
        }
        eprintln!();
    }

    // Print ALL salt-like strings (16-26 chars, has special char, no spaces, no path chars)
    eprintln!("\n=== SALT-LIKE STRINGS (16-26 chars, special char, no space/slash/dot) ===");
    let known_salts = [
        "@6QeTuOaDgJlZcBm#9",
        "C(K^x&pBEeg7A5;{G9",
        "CuAVPMZx:E96:(Rxdw",
        "smh=Pdw+%?wk?m4&(y",
        "xGqK]W+_eM5u3[8-8u",
        "}F33F0}_7X^;b?PM/;",
        "3@6|3a[@<Ex:L=eN|g",
        "DaXU_Vx9xy;[ycFz{1",
        "1&w2!&w{Q)Fkz4e&p0",
        "})wWb4?-sVGHNoPKpc",
    ];
    let mut salt_hits: Vec<(usize, &str)> = Vec::new();
    for (off, s) in &all_strings {
        let l = s.len();
        if l < 16 || l > 26 { continue; }
        if s.contains(' ') || s.contains('/') || s.contains('\\') || s.contains('.') { continue; }
        // Must contain at least one special/punctuation char
        let has_special = s.chars().any(|c| !c.is_alphanumeric() && c != '_');
        if !has_special { continue; }
        salt_hits.push((*off, s.as_str()));
    }
    eprintln!("[INFO] {} salt-like strings found.", salt_hits.len());

    let mut seen = std::collections::HashSet::new();
    for (off, s) in &salt_hits {
        if !seen.insert(*s) { continue; }
        let known = if known_salts.contains(s) { " [KNOWN]" } else { " [NEW?]" };
        eprintln!("  0x{:08X}: {}{}", off, s, known);
    }

    // Also print context around known salts to find adjacent unknowns
    eprintln!("\n=== KNOWN SALT LOCATIONS + NEARBY STRINGS ===");
    for (off, s) in &all_strings {
        if known_salts.contains(&s.as_str()) {
            eprintln!("  0x{:08X}: {} [KNOWN]", off, s);
            for (o2, s2) in &all_strings {
                let dist = if *o2 > *off { o2 - off } else { off - o2 };
                if dist > 0 && dist <= 256 {
                    let known2 = if known_salts.contains(&s2.as_str()) { " [KNOWN]" } else { " [NEW?]" };
                    eprintln!("    [{:+5}] {}{}", *o2 as i64 - *off as i64, s2, known2);
                }
            }
            eprintln!();
        }
    }
}
