use std::io::{Read, Seek, SeekFrom, BufRead, BufReader};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let mut salts = Vec::new();
    if let Ok(f) = File::open("salts.txt") {
        let reader = BufReader::new(f);
        for line in reader.lines() {
            if let Ok(l) = line {
                let trimmed = l.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    salts.push(trimmed.to_string());
                }
            }
        }
    }
    
    // Add extra research salts from previous attempts
    let extra_salts = ["´.)\"Ndõu%{f.ZÝø", "a|3Íu_x.Joì56", "})wWb4?-sVGHNoPKpc", "@6QeTuOaDgJlZcBm#9"];
    for s in extra_salts {
        if !salts.contains(&s.to_string()) { salts.push(s.to_string()); }
    }
    
    let files = [
        ".gemini/testing/exhaustive_test/kr_package/data_00000.it",
        ".gemini/testing/exhaustive_test/kr_package/data_00001.it",
        ".gemini/testing/exhaustive_test/kr_package/data_00002.it",
    ];

    let modes = [
        Snow2Mode::ModernBE,
        Snow2Mode::ModernLE,
        Snow2Mode::LegacyBE,
        Snow2Mode::LegacyLE,
        Snow2Mode::Xor,
        Snow2Mode::Sub,
    ];

    for file_path in &files {
        println!("--- Hunting in: {} ---", file_path);
        let mut f = match File::open(file_path) {
            Ok(file) => file,
            Err(_) => {
                println!("  ERROR: Could not open file: {}", file_path);
                continue;
            }
        };
        let fname = std::path::Path::new(file_path).file_name().unwrap().to_str().unwrap();

        for salt in &salts {
            let key = encryption::gen_header_key(fname, salt);
            for iv0 in &[0, 1] {
                for mode in &modes {
                    let mut candidate_offsets = (0..1024).collect::<Vec<i32>>();
                    // Add formula offset
                    candidate_offsets.push(encryption::gen_header_offset(fname) as i32);
                    // Add footer pointer
                    if let Ok(size) = f.seek(SeekFrom::End(0)) {
                        if size > 8 {
                            let _ = f.seek(SeekFrom::End(-4));
                            let mut f_bytes = [0u8; 4];
                            if f.read_exact(&mut f_bytes).is_ok() {
                                let mut cur = std::io::Cursor::new(f_bytes);
                                let mut dec = encryption::Snow2Decoder::new_iv_mode(&key, *iv0, *mode, &mut cur);
                                if let Ok(off) = byteorder::ReadBytesExt::read_u32::<byteorder::LittleEndian>(&mut dec) {
                                    candidate_offsets.push(off as i32);
                                }
                            }
                        }
                    }
                    candidate_offsets.sort();
                    candidate_offsets.dedup();

                    for off in candidate_offsets {
                        let _ = f.seek(SeekFrom::Start(off as u64));
                        let mut decoder = encryption::Snow2Decoder::new_iv_mode(&key, *iv0, *mode, &mut f);
                        
                        let mut buf = [0u8; 12];
                        if decoder.read_exact(&mut buf).is_ok() {
                            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                            let version = buf[4];
                            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                            
                            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 2000000 && version < 10 {
                                println!("FOUND! Offset: 0x{:X}, Salt: '{}', IV: {}, Mode: {:?} -> Ver: {}, Count: {}", off, salt, iv0, mode, version, file_cnt);
                            }
                        }
                    }
                }
            }
        }
    }
}
