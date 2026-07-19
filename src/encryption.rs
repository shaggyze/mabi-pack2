// encryption.rs - Snow2 C-Binding Implementation with Word-Based Cipher Logic

use std::io::{self, Read, Write, Seek, SeekFrom};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

#[link(name = "c_snow2", kind = "static")]
extern "C" {
    fn c_snow2_loadkey_iv(state_table: *mut u32, key: *const u8, iv0: u32, mode: i32);
    fn c_snow2_generate_keystream(state_table: *mut u32, stream: *mut u32);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Snow2Mode { Sub, Xor, ModernBE, ModernLE, LegacyBE, LegacyLE }

pub struct Snow2Decoder<'a, R: Read> {
    state_table: [u32; 18],
    keystream: [u32; 16],
    cur_index: usize,
    pub rd: &'a mut R,
    key_ref: Vec<u8>,
    iv0: u32,
    mode: Snow2Mode,
    
    left_buffer: [u8; 4],
    left_buffer_len: usize,
    stream_pos: u64,
}

impl<'a, R: Read> Snow2Decoder<'a, R> {
    pub fn new_iv(key: &[u8], iv0: u32, reader: &'a mut R) -> Self {
        Self::new_iv_mode(key, iv0, Snow2Mode::Sub, reader)
    }

    pub fn new_iv_mode(key: &[u8], iv0: u32, mode: Snow2Mode, reader: &'a mut R) -> Self {
        let mut r = Snow2Decoder {
            state_table: [0; 18],
            keystream: [0; 16],
            cur_index: 0,
            rd: reader,
            key_ref: key.to_vec(),
            iv0,
            mode,
            left_buffer: [0; 4],
            left_buffer_len: 0,
            stream_pos: 0,
        };
        unsafe {
            c_snow2_loadkey_iv(r.state_table.as_mut_ptr(), key.as_ptr(), iv0, mode as i32);
            c_snow2_generate_keystream(r.state_table.as_mut_ptr(), r.keystream.as_mut_ptr());
        }
        r
    }

    fn generate_key_stream(&mut self) {
        unsafe {
            c_snow2_generate_keystream(self.state_table.as_mut_ptr(), self.keystream.as_mut_ptr());
        }
    }

    pub fn current_stream_position(&self) -> u64 { self.stream_pos }

    pub fn skip_keystream(&mut self, n: u64) {
        let mut remaining = n;
        
        // Discard from leftover buffer first
        if self.left_buffer_len > 0 {
            let take = std::cmp::min(remaining, self.left_buffer_len as u64);
            self.left_buffer.copy_within(take as usize..self.left_buffer_len, 0);
            self.left_buffer_len -= take as usize;
            remaining -= take;
            self.stream_pos += take;
        }

        if remaining == 0 { return; }

        let words_to_skip = remaining / 4;
        for _ in 0..words_to_skip {
            self.cur_index += 1;
            if self.cur_index >= 16 {
                self.generate_key_stream();
                self.cur_index = 0;
            }
        }
        
        self.stream_pos += words_to_skip * 4;
        remaining %= 4;

        if remaining > 0 {
            let _dummy = [0u8; 4];
            // This is a bit tricky since we need to "consume" a word and buffer the rest
            let ks = self.keystream[self.cur_index];
            let ks_bytes = ks.to_le_bytes();
            
            let take = remaining as usize;
            // The remaining bytes of this word go into the leftover buffer
            self.left_buffer_len = 4 - take;
            self.left_buffer[..self.left_buffer_len].copy_from_slice(&ks_bytes[take..]);
            
            self.cur_index += 1;
            if self.cur_index >= 16 {
                self.generate_key_stream();
                self.cur_index = 0;
            }
            self.stream_pos += remaining;
        }
    }
}

impl<'a, R: Read> Read for Snow2Decoder<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() { return Ok(0); }

        let mut total_written = 0;

        // Serve from leftover buffer
        if self.left_buffer_len > 0 {
            let n = std::cmp::min(buf.len(), self.left_buffer_len);
            buf[..n].copy_from_slice(&self.left_buffer[..n]);
            self.left_buffer.copy_within(n..self.left_buffer_len, 0);
            self.left_buffer_len -= n;
            total_written += n;
            self.stream_pos += n as u64;
            if total_written == buf.len() { return Ok(total_written); }
        }

        let remaining = buf.len() - total_written;
        let words_needed = (remaining + 3) / 4;
        let bytes_to_read = words_needed * 4;

        let mut raw_buf = vec![0u8; bytes_to_read];
        match self.rd.read_exact(&mut raw_buf) {
            Ok(_) => {},
            Err(e) => {
                if total_written > 0 { return Ok(total_written); }
                return Err(e);
            }
        }

        let mut decrypted = Vec::with_capacity(bytes_to_read);
        let mut cur = io::Cursor::new(raw_buf);

        for _ in 0..words_needed {
            let enc_word = cur.read_u32::<LittleEndian>()?;
            let ks = self.keystream[self.cur_index];
            let dec_word = match self.mode {
                Snow2Mode::Sub => enc_word.wrapping_sub(ks),
                _ => enc_word ^ ks,
            };
            decrypted.write_u32::<LittleEndian>(dec_word)?;

            self.cur_index += 1;
            if self.cur_index >= 16 {
                self.generate_key_stream();
                self.cur_index = 0;
            }
        }

        let n = std::cmp::min(remaining, decrypted.len());
        buf[total_written..total_written+n].copy_from_slice(&decrypted[..n]);
        
        if decrypted.len() > n {
            self.left_buffer_len = decrypted.len() - n;
            self.left_buffer[..self.left_buffer_len].copy_from_slice(&decrypted[n..]);
        }
        
        total_written += n;
        self.stream_pos += n as u64;
        Ok(total_written)
    }
}

pub struct Snow2Encoder<'a, W: Write> {
    state_table: [u32; 18],
    keystream: [u32; 16],
    cur_index: usize,
    pub wr: &'a mut W,
    mode: Snow2Mode,

    left_buffer: [u8; 4],
    left_buffer_len: usize,
}

impl<'a, W: Write> Snow2Encoder<'a, W> {
    pub fn new_iv(key: &[u8], iv0: u32, writer: &'a mut W) -> Self {
        Self::new_iv_mode(key, iv0, Snow2Mode::Sub, writer)
    }

    pub fn new_iv_mode(key: &[u8], iv0: u32, mode: Snow2Mode, writer: &'a mut W) -> Self {
        let mut r = Snow2Encoder {
            state_table: [0; 18],
            keystream: [0; 16],
            cur_index: 0,
            wr: writer,
            mode,
            left_buffer: [0; 4],
            left_buffer_len: 0,
        };
        unsafe {
            c_snow2_loadkey_iv(r.state_table.as_mut_ptr(), key.as_ptr(), iv0, mode as i32);
            c_snow2_generate_keystream(r.state_table.as_mut_ptr(), r.keystream.as_mut_ptr());
        }
        r
    }

    fn generate_keystream(&mut self) {
        unsafe {
            c_snow2_generate_keystream(self.state_table.as_mut_ptr(), self.keystream.as_mut_ptr());
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.left_buffer_len > 0 {
            // Pad with zeros as per legacy logic
            let mut final_block = [0u8; 4];
            final_block[..self.left_buffer_len].copy_from_slice(&self.left_buffer[..self.left_buffer_len]);
            let word = u32::from_le_bytes(final_block);
            let ks = self.keystream[self.cur_index];
            let out_word = match self.mode {
                Snow2Mode::Sub => word.wrapping_add(ks),
                _ => word ^ ks,
            };
            self.wr.write_u32::<LittleEndian>(out_word)?;
            self.cur_index = (self.cur_index + 1) % 16;
            if self.cur_index == 0 { self.generate_keystream(); }
            self.left_buffer_len = 0;
        }
        self.wr.flush()
    }
}

impl<'a, W: Write> Write for Snow2Encoder<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut processed = 0;
        let len = buf.len();

        // Fill leftover buffer
        if self.left_buffer_len > 0 && self.left_buffer_len < 4 {
            let n = std::cmp::min(4 - self.left_buffer_len, len);
            self.left_buffer[self.left_buffer_len..self.left_buffer_len+n].copy_from_slice(&buf[..n]);
            self.left_buffer_len += n;
            processed += n;

            if self.left_buffer_len == 4 {
                let word = u32::from_le_bytes(self.left_buffer);
                let ks = self.keystream[self.cur_index];
                let out_word = match self.mode {
                    Snow2Mode::Sub => word.wrapping_add(ks),
                    _ => word ^ ks,
                };
                self.wr.write_u32::<LittleEndian>(out_word)?;
                self.cur_index = (self.cur_index + 1) % 16;
                if self.cur_index == 0 { self.generate_keystream(); }
                self.left_buffer_len = 0;
            }
        }

        // Process full words
        while len - processed >= 4 {
            let word = u32::from_le_bytes(buf[processed..processed+4].try_into().unwrap());
            let ks = self.keystream[self.cur_index];
            let out_word = match self.mode {
                Snow2Mode::Sub => word.wrapping_add(ks),
                _ => word ^ ks,
            };
            self.wr.write_u32::<LittleEndian>(out_word)?;
            self.cur_index = (self.cur_index + 1) % 16;
            if self.cur_index == 0 { self.generate_keystream(); }
            processed += 4;
        }

        // Buffer remaining bytes
        let rem = len - processed;
        if rem > 0 {
            self.left_buffer[..rem].copy_from_slice(&buf[processed..]);
            self.left_buffer_len = rem;
            processed += rem;
        }

        Ok(processed)
    }

    fn flush(&mut self) -> io::Result<()> { self.wr.flush() }
}


impl<'a, W: Write> Drop for Snow2Encoder<'a, W> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

// RESTORED FORMULA LOGIC
pub fn gen_header_key(name: &str, skey: &str) -> [u8; 16] {
    let input: Vec<u16> = (name.to_ascii_lowercase() + skey).encode_utf16().collect();
    let bytes: Vec<u8> = (0..128).map(|i| input[i % input.len()].wrapping_add(i as u16) as u8).collect();
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes[..16]);
    key
}

pub fn gen_header_offset(name: &str) -> u32 {
    let input: Vec<u16> = name.to_ascii_lowercase().encode_utf16().collect();
    let sum = input.iter().fold(0, |sum, c| sum + *c as usize);
    (sum % 312 + 30) as u32
}

pub fn gen_entries_key(name: &str, skey: &str) -> [u8; 16] {
    let input: Vec<u16> = (name.to_ascii_lowercase() + skey).encode_utf16().collect();
    let len = input.len();
    let bytes: Vec<u8> = (0..128).map(|i| (i + (i % 3 + 2) * input[len - 1 - i % len] as usize) as u8).collect();
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes[..16]);
    key
}

pub fn gen_entries_offset(name: &str) -> u32 {
    let input: Vec<u16> = name.to_ascii_lowercase().encode_utf16().collect();
    let r = input.iter().fold(0, |r, c| r + *c as usize * 3);
    (r % 212 + 42) as u32
}

pub fn gen_file_key(file_name: &str, archive_key: &[u8; 16]) -> [u8; 16] {
    let input: Vec<u16> = file_name.encode_utf16().collect();
    let bytes: Vec<u8> = (0..128).map(|i| {
        input[i % input.len()].wrapping_mul(
            archive_key[i % archive_key.len()].wrapping_sub(i as u8 / 5 * 5).wrapping_add(2).wrapping_add(i as u8) as u16
        ).wrapping_add(i as u16) as u8
    }).collect();
    let mut key = [0u8; 16];
    key.copy_from_slice(&bytes[..16]);
    key
}

pub fn snow2_decrypt(key: &[u8], iv0: u32, data: &mut [u8]) {
    snow2_decrypt_mode(key, iv0, Snow2Mode::Sub, data);
}

pub fn snow2_decrypt_mode(key: &[u8], iv0: u32, mode: Snow2Mode, data: &mut [u8]) {
    let mut state = [0u32; 18];
    let mut ks = [0u32; 16];
    unsafe {
        c_snow2_loadkey_iv(state.as_mut_ptr(), key.as_ptr(), iv0, mode as i32);
        c_snow2_generate_keystream(state.as_mut_ptr(), ks.as_mut_ptr());
    }
    
    let mut word_idx = 0;
    let mut processed = 0;
    let len = data.len();

    while len - processed >= 4 {
        let mut word_bytes: [u8; 4] = data[processed..processed+4].try_into().unwrap();
        let enc_word = u32::from_le_bytes(word_bytes);
        let dec_word = match mode {
            Snow2Mode::Sub => enc_word.wrapping_sub(ks[word_idx]),
            _ => enc_word ^ ks[word_idx],
        };
        word_bytes.copy_from_slice(&dec_word.to_le_bytes());
        data[processed..processed+4].copy_from_slice(&word_bytes);
        
        word_idx += 1;
        if word_idx >= 16 {
            unsafe { c_snow2_generate_keystream(state.as_mut_ptr(), ks.as_mut_ptr()); }
            word_idx = 0;
        }
        processed += 4;
    }
    
    if processed < len {
        let rem = len - processed;
        let mut word_bytes = [0u8; 4];
        word_bytes[..rem].copy_from_slice(&data[processed..]);
        let enc_word = u32::from_le_bytes(word_bytes);
        let dec_word = match mode {
            Snow2Mode::Sub => enc_word.wrapping_sub(ks[word_idx]),
            _ => enc_word ^ ks[word_idx],
        };
        let dec_bytes = dec_word.to_le_bytes();
        data[processed..].copy_from_slice(&dec_bytes[..rem]);
    }
}

pub fn snow2_encrypt(key: &[u8], iv0: u32, data: &mut [u8]) {
    snow2_encrypt_mode(key, iv0, Snow2Mode::Sub, data);
}

pub fn snow2_encrypt_mode(key: &[u8], iv0: u32, mode: Snow2Mode, data: &mut [u8]) {
    let mut state = [0u32; 18];
    let mut ks = [0u32; 16];
    unsafe {
        c_snow2_loadkey_iv(state.as_mut_ptr(), key.as_ptr(), iv0, mode as i32);
        c_snow2_generate_keystream(state.as_mut_ptr(), ks.as_mut_ptr());
    }
    
    let mut word_idx = 0;
    let mut processed = 0;
    let len = data.len();

    while len - processed >= 4 {
        let mut word_bytes: [u8; 4] = data[processed..processed+4].try_into().unwrap();
        let dec_word = u32::from_le_bytes(word_bytes);
        let enc_word = match mode {
            Snow2Mode::Sub => dec_word.wrapping_add(ks[word_idx]),
            _ => dec_word ^ ks[word_idx],
        };
        word_bytes.copy_from_slice(&enc_word.to_le_bytes());
        data[processed..processed+4].copy_from_slice(&word_bytes);
        
        word_idx += 1;
        if word_idx >= 16 {
            unsafe { c_snow2_generate_keystream(state.as_mut_ptr(), ks.as_mut_ptr()); }
            word_idx = 0;
        }
        processed += 4;
    }
    
    if processed < len {
        let rem = len - processed;
        let mut word_bytes = [0u8; 4];
        word_bytes[..rem].copy_from_slice(&data[processed..]);
        let dec_word = u32::from_le_bytes(word_bytes);
        let enc_word = match mode {
            Snow2Mode::Sub => dec_word.wrapping_add(ks[word_idx]),
            _ => dec_word ^ ks[word_idx],
        };
        let enc_bytes = enc_word.to_le_bytes();
        data[processed..].copy_from_slice(&enc_bytes[..rem]);
    }
}

impl<'a, T: Write + Seek> Seek for Snow2Encoder<'a, T> { 
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { 
        if self.left_buffer_len > 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Cannot seek while leftover buffer is not empty"));
        }
        self.wr.seek(pos) 
    } 
}

impl<'a, R: Read + Seek> Seek for Snow2Decoder<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                self.rd.seek(SeekFrom::Start(0))?;
                unsafe {
                    c_snow2_loadkey_iv(self.state_table.as_mut_ptr(), self.key_ref.as_ptr(), self.iv0, self.mode as i32);
                    c_snow2_generate_keystream(self.state_table.as_mut_ptr(), self.keystream.as_mut_ptr());
                }
                self.cur_index = 0;
                self.left_buffer_len = 0;
                self.stream_pos = 0;
                if offset > 0 {
                    let mut discard = vec![0u8; offset as usize];
                    self.read_exact(&mut discard)?;
                }
                Ok(self.stream_pos)
            }
            _ => Err(io::Error::new(io::ErrorKind::Unsupported, "Seek only supported from start")),
        }
    }
}
