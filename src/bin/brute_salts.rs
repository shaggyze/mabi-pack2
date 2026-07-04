use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let target_file = "gemini-testing/uotiara_00004.it";
    let target_offset = 0x91;
    let target_iv0 = 1;
    
    println!("--- Brute Force Salts for {} at offset 0x{:X} ---", target_file, target_offset);
    let mut f = File::open(target_file).expect("Failed to open file");
    let fname = "uotiara_00004.it";

    let mut salts = vec![
        "3@6|3a[@<Ex:L=eN|g",
        "CuAVPMZx:E96:(Rxdw",
        "@6QeTuOaDgJlZcBm#9",
        "DaXU_Vx9xy;[ycFz{1",
        "}F33F0}_7X^;b?PM/;",
        "C(K^x&pBEeg7A5;{G9",
        "smh=Pdw+%?wk?m4&(y",
        "xGqK]W+_eM5u3[8-8u",
        "1&w2!&w{Q)Fkz4e&p0",
        "})wWb4?-sVGHNoPKpc",
        "XvH6-n8f",
    ];

    for salt in &salts {
        let key = encryption::gen_header_key(fname, salt);
        for mode in &[Snow2Mode::Sub, Snow2Mode::Xor] {
            let _ = f.seek(SeekFrom::Start(target_offset));
            let mut decoder = encryption::Snow2Decoder::new_iv_mode(&key, target_iv0, *mode, &mut f);
            
            let mut buf = [0u8; 12];
            if decoder.read_exact(&mut buf).is_ok() {
                let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let version = buf[4];
                let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                
                if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 {
                    println!("FOUND!! Salt: '{}', Mode: {:?} -> Ver: {}, Count: {}", salt, mode, version, file_cnt);
                }
            }
        }
    }
}
