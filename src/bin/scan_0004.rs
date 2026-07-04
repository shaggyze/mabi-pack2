use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let salt = "})wWb4?-sVGHNoPKpc";
    let target_file = "gemini-testing/uotiara_00004.it";
    
    println!("--- Searching for Header in {} with Salt {} ---", target_file, salt);
    let mut f = File::open(target_file).expect("Failed to open file");
    let fname = "uotiara_00004.it";
    let key = encryption::gen_header_key(fname, salt);

    let mut data = vec![0u8; 10000];
    let _ = f.read_exact(&mut data);

    for iv0 in &[0, 1] {
        println!("Testing IV0: {}", iv0);
        for off in 0..(data.len() - 12) {
            let mut cur = std::io::Cursor::new(&data[off..off+12]);
            let mut dec = encryption::Snow2Decoder::new_iv(key.as_slice(), *iv0, &mut cur);
            let mut buf = [0u8; 12];
            let _ = dec.read_exact(&mut buf);
            
            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let version = buf[4];
            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
            
            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 100000 && version < 10 {
                println!("  FOUND!! Offset: {}, Ver: {}, Count: {}, Checksum: 0x{:X}", off, version, file_cnt, checksum);
            }
        }
    }
}
