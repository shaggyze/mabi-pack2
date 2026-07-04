use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let files = [
        "gemini-testing/UOTiara WebUI/crack-project/package/data_00341.it",
        "gemini-testing/UOTiara WebUI/crack-project/package/data_00342.it",
    ];
    
    // Most likely salts from breakthrouh and logs
    let salts = [
        "CuAVPMZx:E96:(Rxdw",
        "@6QeTuOaDgJlZcBm#9",
        "smh=Pdw+%?wk?m4&(y",
        "1&w2!&w{Q)Fkz4e&p0",
        "})wWb4?-sVGHNoPKpc",
        "XvH6-n8f",
    ];

    for file_path in &files {
        println!("--- Deep Scanning {} ---", file_path);
        let mut f = match File::open(file_path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let fname = std::path::Path::new(file_path).file_name().unwrap().to_str().unwrap();

        for salt in &salts {
            let key = encryption::gen_header_key(fname, salt);
            for iv0 in &[0, 1] {
                // Try many offsets, including 0
                for off in 0..512 {
                    let _ = f.seek(SeekFrom::Start(off as u64));
                    let mut dec = encryption::Snow2Decoder::new_iv(key.as_slice(), *iv0, &mut f);
                    let mut buf = [0u8; 12];
                    if dec.read_exact(&mut buf).is_ok() {
                        let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        let version = buf[4];
                        let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                        
                        if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 1000000 {
                            println!("  FOUND!! Offset: {}, Salt: '{}', IV0: {} -> Ver: {}, Count: {}", off, salt, iv0, version, file_cnt);
                        }
                    }
                }
            }
        }
    }
}
