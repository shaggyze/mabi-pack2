use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use rayon::prelude::*;

// LCG v1: MSVC rand() based
fn next_byte_v1(state: &mut u32) -> u8 {
    *state = state.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
    let t1 = (*state >> 16) & 0x7FFF;
    *state = state.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
    let t2 = (*state >> 16) & 0x7FFF;
    ((t1 << 15) | t2) as u8
}

// LCG v2: multiplier 0x5D588B65
fn next_byte_v2(state: &mut u32) -> u8 {
    *state = state.wrapping_mul(0x5D588B65).wrapping_add(0x00269EC3);
    (*state >> 16) as u8
}

fn get_ks_4(seed: u32, version: u8) -> [u8; 4] {
    let mut state = seed;
    let mut ks = [0u8; 4];
    for i in 0..4 {
        ks[i] = if version == 1 { next_byte_v1(&mut state) } else { next_byte_v2(&mut state) };
    }
    ks
}

fn main() {
    let file_path = ".gemini/testing/exhaustive_test/kr_package/data_00000.it";
    let mut f = File::open(file_path).expect("Could not open file");
    
    let offsets = [106, 107, 108, 109, 110, 111, 0, 4, 8, 12, 16, 20, 24, 28, 32];
    let expected = b"IT\x01\x00";

    for &off in &offsets {
        println!("--- Hunting at offset 0x{:X} ---", off);
        let mut encrypted = [0u8; 4];
        let _ = f.seek(SeekFrom::Start(off as u64));
        if f.read_exact(&mut encrypted).is_err() { continue; }

        let target_ks = [
            encrypted[0] ^ expected[0],
            encrypted[1] ^ expected[1],
            encrypted[2] ^ expected[2],
            encrypted[3] ^ expected[3],
        ];

        println!("Target KS: {:02X?}", target_ks);

        for version in 1..=2 {
            println!("Brute-forcing LCG v{} (32-bit)...", version);
            
            let found = (0..u32::MAX).into_par_iter().find_map_any(|seed| {
                if version == 1 {
                    let mut s = seed;
                    if next_byte_v1(&mut s) == target_ks[0] {
                        if get_ks_4(seed, 1) == target_ks { return Some(seed); }
                    }
                } else {
                    let mut s = seed;
                    if next_byte_v2(&mut s) == target_ks[0] {
                        if get_ks_4(seed, 2) == target_ks { return Some(seed); }
                    }
                }
                None
            });

            if let Some(seed) = found {
                println!("🎯 SEED FOUND (v{}) at offset 0x{:X}: 0x{:08X} ({})", version, off, seed, seed);
                return;
            }
        }
    }
    println!("No seed found in exhaustive search.");
}
