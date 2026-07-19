use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use mabi_pack2::encryption::{self, Snow2Mode};
use mabi_pack2::load_salts;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: find_header <file>");
        return;
    }
    let target_file = &args[1];
    let fname = std::path::Path::new(target_file).file_name().unwrap().to_str().unwrap();

    let salts = load_salts();
    println!("--- Finding Header in {} (Trying {} salts) ---", target_file, salts.len());
    let mut f = File::open(target_file).expect("Failed to open file");

    let modes = [
        Snow2Mode::Sub, 
        Snow2Mode::Xor, 
        Snow2Mode::ModernBE, 
        Snow2Mode::ModernLE, 
        Snow2Mode::LegacyBE, 
        Snow2Mode::LegacyLE
    ];

    // Load first 64KB
    let mut data = vec![0u8; 65536];
    let _ = f.seek(SeekFrom::Start(0));
    let read_len = f.read(&mut data).expect("Failed to read file");
    let data = &data[..read_len];

    for skey in &salts {
        let key = encryption::gen_header_key(fname, skey);

        for mode in &modes {
            for &iv0 in &[0, 1] {
                for off in 0..(data.len() - 12) {
                    if off % 1024 == 0 && off > 0 && skey == &salts[0] && mode == &modes[0] && iv0 == 0 {
                        // Progress marker
                    }

                    // CASE 1: Reset cipher at every offset (block reset)
                    {
                        let mut cur = std::io::Cursor::new(&data[off..off+12]);
                        let mut dec = encryption::Snow2Decoder::new_iv_mode(&key, iv0, *mode, &mut cur);
                        let mut buf = [0u8; 12];
                        if dec.read_exact(&mut buf).is_ok() {
                            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                            let version = buf[4];
                            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                            
                            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 2000000 && version < 10 {
                                println!("FOUND (Reset Mode)! Salt: {}, Offset: 0x{:X}, IV: {}, Mode: {:?}, Ver: {}, Count: {}, Checksum: 0x{:X}", skey, off, iv0, mode, version, file_cnt, checksum);
                            }
                        }
                    }
                    
                    // CASE 2: Global stream mode (skip)
                    {
                        let mut cur = std::io::Cursor::new(&data[..]);
                        let mut dec = encryption::Snow2Decoder::new_iv_mode(&key, iv0, *mode, &mut cur);
                        dec.skip_keystream(off as u64);
                        let mut buf = [0u8; 12];
                        if dec.read_exact(&mut buf).is_ok() {
                            let checksum = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                            let version = buf[4];
                            let file_cnt = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
                            
                            if (version as u32).wrapping_add(file_cnt) == checksum && file_cnt > 0 && file_cnt < 2000000 && version < 10 {
                                println!("FOUND (Global Mode)! Salt: {}, Offset: 0x{:X}, IV: {}, Mode: {:?}, Ver: {}, Count: {}, Checksum: 0x{:X}", skey, off, iv0, mode, version, file_cnt, checksum);
                            }
                        }
                    }
                }
            }
        }
    }
}
