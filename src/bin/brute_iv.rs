use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let target_file = "gemini-testing/UOTiara WebUI/crack-project/package/data_00002.it";
    let fname = "data_00002.it";
    let salt = "@6QeTuOaDgJlZcBm#9";
    let key = encryption::gen_header_key(fname, salt);
    let offset = encryption::gen_header_offset(fname);

    println!("--- Brute Forcing IV for {} ---", target_file);
    let mut f = File::open(target_file).expect("Failed to open file");

    for iv0 in 0..100 {
        let _ = f.seek(SeekFrom::Start(offset as u64));
        let mut dec = encryption::Snow2Decoder::new_iv(key.as_slice(), iv0, &mut f);
        let mut buf = [0u8; 12];
        if let Ok(_) = dec.read_exact(&mut buf) {
            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let version = buf[4];
            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 1000000 {
                println!("  SUCCESS!! IV0={} -> Ver: {}, Count: {}", iv0, version, file_cnt);
            }
        }
    }
}
