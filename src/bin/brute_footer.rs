use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};

fn main() {
    let files = [
        "gemini-testing/UOTiara WebUI/crack-project/package/data_00341.it",
        "gemini-testing/UOTiara WebUI/crack-project/package/data_00342.it",
    ];
    
    let salts = [
        "CuAVPMZx:E96:(Rxdw",
        "@6QeTuOaDgJlZcBm#9",
        "smh=Pdw+%?wk?m4&(y",
        "1&w2!&w{Q)Fkz4e&p0",
        "})wWb4?-sVGHNoPKpc",
        "XvH6-n8f",
    ];

    for file_path in &files {
        let mut f = File::open(file_path).unwrap();
        let len = f.metadata().unwrap().len();
        println!("--- Tail-Brute {} (Len: {}) ---", file_path, len);
        let fname = std::path::Path::new(file_path).file_name().unwrap().to_str().unwrap();

        for salt in &salts {
            let key = encryption::gen_header_key(fname, salt);
            for iv0 in &[0, 1] {
                // Check last 4 bytes as footer
                f.seek(SeekFrom::End(-4)).unwrap();
                let mut raw_footer = [0u8; 4];
                f.read_exact(&mut raw_footer).unwrap();
                
                let mut cur = std::io::Cursor::new(&raw_footer);
                let mut dec = encryption::Snow2Decoder::new_iv(key.as_slice(), *iv0, &mut cur);
                dec.skip_keystream(len - 4);
                
                let mut footer_buf = [0u8; 4];
                if dec.read_exact(&mut footer_buf).is_ok() {
                    let offset = u32::from_le_bytes(footer_buf);
                    if offset > 0 && offset < len as u32 {
                        println!("  POTENTIAL FOOTER! Salt: '{}', IV0: {}, Offset: 0x{:X}", salt, iv0, offset);
                        
                        f.seek(SeekFrom::Start(offset as u64)).unwrap();
                        let mut hdec = encryption::Snow2Decoder::new_iv(key.as_slice(), *iv0, &mut f);
                        hdec.skip_keystream(offset as u64);
                        let mut hbuf = [0u8; 12];
                        if hdec.read_exact(&mut hbuf).is_ok() {
                            let checksum = u32::from_le_bytes([hbuf[0], hbuf[1], hbuf[2], hbuf[3]]);
                            let version = hbuf[4];
                            let file_cnt = u32::from_le_bytes([hbuf[5], hbuf[6], hbuf[7], hbuf[8]]);
                            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 {
                                println!("  !!! HEADER FOUND AT FOOTER OFFSET !!! Ver: {}, Count: {}", version, file_cnt);
                            }
                        }
                    }
                }
            }
        }
    }
}
