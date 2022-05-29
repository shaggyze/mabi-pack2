use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

//const KEY_SALT: &str = "@6QeTuOaDgJlZcBm#9";

pub fn gen_header_key(name: &str,skey:&str) -> Vec<u8> {
    let input: Vec<u16> = (name.to_ascii_lowercase() + skey)
        .encode_utf16()
        .collect();
    (0..128)
        .map(|i| input[i % input.len()].wrapping_add(i as u16) as u8)
        .collect()
}

pub fn gen_header_offset(name: &str) -> usize {
    let input: Vec<u16> = name.to_ascii_lowercase().encode_utf16().collect();
    let sum = input.iter().fold(0, |sum, c| sum + *c as usize);
    sum % 312 + 30
}

pub fn gen_entries_key(name: &str,skey:&str) -> Vec<u8> {
    let input: Vec<u16> = (name.to_ascii_lowercase() + skey)
        .encode_utf16()
        .collect();
    let len = input.len();
    (0..128)
        .map(|i| (i + (i % 3 + 2) * input[len - 1 - i % len] as usize) as u8)
        .collect()
}

pub fn gen_entries_offset(name: &str) -> usize {
    let input: Vec<u16> = name.to_ascii_lowercase().encode_utf16().collect();
    let r = input.iter().fold(0, |r, c| r + *c as usize * 3);
    r % 212 + 42
}

pub fn gen_file_key(name: &str, key2: &[u8]) -> Vec<u8> {
    let input: Vec<u16> = name.encode_utf16().collect();
    assert_eq!(key2.len(), 16);
    (0..128)
        .map(|i| {
            input[i % input.len()]
                .wrapping_mul(
                    key2[i % key2.len()]
                        .wrapping_sub(i as u8 / 5 * 5)
                        .wrapping_add(2)
                        .wrapping_add(i as u8) as u16,
                )
                .wrapping_add(i as u16) as u8
        })
        .collect()
}

extern "C" {
    fn c_snow2_loadkey(state_table: *mut u32, key: *const u8);
    fn c_snow2_generate_keystream(state_table: *mut u32, stream: *mut u32);
}

pub struct Snow2Decoder<'a, T: Read> {
    state_table: [u32; 18],
    keystream: [u32; 16],
    cur_index: usize,
    rd: &'a mut T,

    left_buffer: [u8; 4],
    left_buffer_len: usize,
}

impl<'a, T: Read> Snow2Decoder<'a, T> {
    pub fn new(key: &[u8], reader: &'a mut T) -> Box<Self> {
        let mut r = Box::new(Snow2Decoder {
            state_table: [0; 18],
            keystream: [0; 16],
            cur_index: 0,
            rd: reader,

            left_buffer: [0; 4],
            left_buffer_len: 0,
        });
        unsafe {
            c_snow2_loadkey(r.state_table.as_mut_ptr(), key.as_ptr());
            r.generate_key_stream();
        }
        r
    }

    fn generate_key_stream(&mut self) {
        unsafe {
            c_snow2_generate_keystream(self.state_table.as_mut_ptr(), self.keystream.as_mut_ptr());
        }
    }
}

impl<'a, T: Read> Read for Snow2Decoder<'a, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let new_reading_len = buf.len() - self.left_buffer_len;
        let dec_block_len = (new_reading_len + 3) & 0usize.wrapping_sub(4);
        let mut ori_buff = vec![0u8; dec_block_len];
        self.rd.read_exact(&mut ori_buff)?;
        let mut reader_ori = Cursor::new(ori_buff);
        let mut writer_new = Cursor::new(Vec::<u8>::with_capacity(dec_block_len));
        for _ in 0..dec_block_len / 4 {
            let v = reader_ori
                .read_u32::<LittleEndian>()
                .unwrap()
                .wrapping_sub(self.keystream[self.cur_index]);
            writer_new.write_u32::<LittleEndian>(v)?;
            self.cur_index += 1;
            if self.cur_index >= 16 {
                self.generate_key_stream();
                self.cur_index = 0;
            }
        }
        buf[..self.left_buffer_len].copy_from_slice(&self.left_buffer[..self.left_buffer_len]);
        let dec_block = writer_new.into_inner();
        buf[self.left_buffer_len..].copy_from_slice(&dec_block[..new_reading_len]);

        self.left_buffer_len = dec_block_len - new_reading_len;
        self.left_buffer[..self.left_buffer_len].copy_from_slice(&dec_block[new_reading_len..]);
        Ok(buf.len())
    }
}

pub struct Snow2Encoder<'a, T: Write> {
    state_table: [u32; 18],
    keystream: [u32; 16],
    cur_index: usize,
    wr: &'a mut T,

    left_buffer: [u8; 4],
    left_buffer_len: usize,
}

impl<'a, T: Write> Snow2Encoder<'a, T> {
    pub fn new(key: &[u8], writer: &'a mut T) -> Box<Self> {
        let mut r = Box::new(Snow2Encoder {
            state_table: [0; 18],
            keystream: [0; 16],
            cur_index: 0,
            wr: writer,

            left_buffer: [0; 4],
            left_buffer_len: 0,
        });
        unsafe {
            c_snow2_loadkey(r.state_table.as_mut_ptr(), key.as_ptr());
            r.generate_keystream();
        }
        r
    }

    fn end_encoding(&mut self) -> io::Result<()> {
        if self.left_buffer_len != 0 {
            self.left_buffer_len = 0;
            let buffer = self.left_buffer;
            self.write_all(&buffer)?;
        }
        Ok(())
    }

    fn generate_keystream(&mut self) {
        unsafe {
            c_snow2_generate_keystream(self.state_table.as_mut_ptr(), self.keystream.as_mut_ptr());
        }
    }
}

impl<'a, T: Write> Write for Snow2Encoder<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let need_writing_len = buf.len() + self.left_buffer_len;
        let enc_block_len = need_writing_len & 0usize.wrapping_sub(4);
        let new_aligned_vec: Vec<u8>;
        let enc_block = if self.left_buffer_len != 0 {
            // copy block to new memory to avoid performance loss by unaligned memory
            new_aligned_vec = self.left_buffer[..self.left_buffer_len]
                .iter()
                .chain(buf[..enc_block_len - self.left_buffer_len].iter())
                .map(|v| *v)
                .collect();
            &new_aligned_vec
        } else {
            &buf[..enc_block_len]
        };
        let mut ori_buff = Cursor::new(enc_block);
        for _ in 0..enc_block_len / 4 {
            self.wr.write_u32::<LittleEndian>(
                ori_buff
                    .read_u32::<LittleEndian>()
                    .unwrap()
                    .wrapping_add(self.keystream[self.cur_index]),
            )?;
            self.cur_index += 1;
            if self.cur_index >= 16 {
                self.generate_keystream();
                self.cur_index = 0;
            }
        }
        self.left_buffer[..need_writing_len - enc_block_len]
            .copy_from_slice(&buf[enc_block_len - self.left_buffer_len..]);
        self.left_buffer_len = need_writing_len - enc_block_len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.wr.flush()
    }
}

impl<'a, T: Write> Drop for Snow2Encoder<'a, T> {
    fn drop(&mut self) {
        self.end_encoding().expect("writing failed");
        self.flush().expect("flushing failed");
    }
}
