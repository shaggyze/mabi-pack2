use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let salt = "@6QeTuOaDgJlZcBm#9";
    let target_file = "gemini-testing/mabi-pack2-master/data_00002.it";
    let target_offset = 108; // 0x6C
    
    println!("--- Verifying data_00002.it Header at 0x{:X} ---", target_offset);
    let mut f = File::open(target_file).expect("Failed to open file");
    let fname = "data_00002.it";
    let key = encryption::gen_header_key(fname, salt);

    for iv0 in &[0, 1] {
        println!("Testing IV0: {}", iv0);
        let _ = f.seek(SeekFrom::Start(target_offset));
        let mut dec = encryption::Snow2Decoder::new_iv(key.as_slice(), *iv0, &mut f);
        let mut buf = [0u8; 12];
        if let Ok(_) = dec.read_exact(&mut buf) {
            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let version = buf[4];
            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
            
            println!("  Ver: {}, Count: {}, Checksum: 0x{:X}", version, file_cnt, checksum);
            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 {
                println!("  SUCCESS!! IV0={} achieves valid header decryption!", iv0);
            }
        }
    }
}
