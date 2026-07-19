use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let target_file = "gemini-testing/uotiara_00004.it";
    let target_offset = 0x91;
    let target_iv0 = 1;
    
    println!("--- Searching for Ver=2, Count=8835 in {} at offset 0x{:X} ---", target_file, target_offset);
    let mut f = File::open(target_file).expect("Failed to open file");
    let fname = "uotiara_00004.it";

    let salts = vec![
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
            // Case 1: No skip
            let mut dec1 = encryption::Snow2Decoder::new_iv_mode(&key, target_iv0, *mode, &mut f);
            let mut buf1 = [0u8; 12];
            let _ = dec1.read_exact(&mut buf1);
            
            // Case 2: Skip
            let _ = f.seek(SeekFrom::Start(0));
            let mut dec2 = encryption::Snow2Decoder::new_iv_mode(&key, target_iv0, *mode, &mut f);
            use std::io::Seek;
            let _ = dec2.seek(std::io::SeekFrom::Start(target_offset));
            let mut buf2 = [0u8; 12];
            let _ = dec2.read_exact(&mut buf2);

            for (i, buf) in [buf1, buf2].iter().enumerate() {
                let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let version = buf[4];
                let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                
                if version == 2 && file_cnt == 8835 {
                    println!("FOUND!! Salt: '{}', Mode: {:?}, Skip: {} -> Ver: {}, Count: {}", salt, mode, i == 1, version, file_cnt);
                }
            }
        }
    }
}
