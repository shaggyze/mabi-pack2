use std::io::{Read, Seek, SeekFrom, BufRead, BufReader};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let files = if args.len() > 1 {
        vec![args[1].clone()]
    } else {
        vec![
            "gemini-testing/data_00002.it".to_string(),
            "gemini-testing/uotiara_00001.it".to_string(),
        ]
    };

    let mut salts = Vec::new();
    if let Ok(f) = File::open("gemini-testing/old_files/salts.txt") {
        let reader = BufReader::new(f);
        for line in reader.lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if !trimmed.is_empty() {
                    salts.push(trimmed.to_string());
                }
            }
        }
    }
    
    let extra_salts = ["XvH6-n8f", "CuAVPMZx:E96:(Rxdw", "@6QeTuOaDgJlZcBm#9", "})wWb4?-sVGHNoPKpc"];
    for s in extra_salts {
        if !salts.contains(&s.to_string()) {
            salts.push(s.to_string());
        }
    }

    let modes = [
        Snow2Mode::Sub,
        Snow2Mode::Xor,
    ];

    for file_path in &files {
        println!("--- Hunting (Global Stream Mode) in: {} ---", file_path);
        let mut f = match File::open(file_path) {
            Ok(file) => file,
            Err(e) => { println!("Error opening {}: {}", file_path, e); continue; },
        };
        let fname = std::path::Path::new(file_path).file_name().unwrap().to_str().unwrap();

        for salt in &salts {
            let key = encryption::gen_header_key(fname, salt);
            for iv0 in &[0, 1] {
                for mode in &modes {
                    // Exhaustive search of first 128KB
                    for off in 0..131072 {
                        if f.seek(SeekFrom::Start(off as u64)).is_err() { break; }
                        let mut decoder = encryption::Snow2Decoder::new_iv_mode(&key, *iv0, *mode, &mut f);
                        
                        // SKIP to match global stream position!
                        decoder.skip_keystream(off as u64);
                        
                        let mut buf = [0u8; 12];
                        if decoder.read_exact(&mut buf).is_ok() {
                            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                            let version = buf[4];
                            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                            
                            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 1000000 && version < 10 {
                                println!("FOUND! Offset: 0x{:X}, Salt: '{}', IV: {}, Mode: {:?} -> Ver: {}, Count: {}, Checksum: 0x{:X}", off, salt, iv0, mode, version, file_cnt, checksum);
                            }
                        }
                    }
                }
            }
        }
    }
}
