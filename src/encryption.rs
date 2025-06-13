use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write, Seek, SeekFrom, Error as IoError, ErrorKind as IoErrorKind};

// Key/Offset Generation Functions (assumed correct from your provided code)
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

pub struct Snow2Decoder<'a, R: Read> { // Changed T to R for Reader
    state_table: [u32; 18],
    keystream: [u32; 16],
    cur_index: usize,
    rd: &'a mut R, // Underlying reader
    key_ref: Vec<u8>, // Store a copy of the key if needed for re-init during seek

    left_buffer: [u8; 4], // For bytes leftover from a 4-byte word
    left_buffer_len: usize,
    stream_pos: u64, // Number of decrypted bytes produced
}

impl<'a, R: Read> Snow2Decoder<'a, R> {
    pub fn new(key: &[u8], reader: &'a mut R) -> Self {
        let mut r = Snow2Decoder {
            state_table: [0; 18],
            keystream: [0; 16],
            cur_index: 0,
            rd: reader,
            key_ref: key.to_vec(), // Store key for potential re-initialization
            left_buffer: [0; 4],
            left_buffer_len: 0,
            stream_pos: 0,
        };
        unsafe {
            c_snow2_loadkey(r.state_table.as_mut_ptr(), r.key_ref.as_ptr());
            r.generate_key_stream();
        }
        r
    }

    fn generate_key_stream(&mut self) {
        unsafe {
            c_snow2_generate_keystream(self.state_table.as_mut_ptr(), self.keystream.as_mut_ptr());
        }
    }

    // Public method to get current decrypted stream position
    pub fn stream_position(&self) -> u64 { // Changed to IoResult<u64> to match Seek trait
        self.stream_pos
    }
}

impl<'a, R: Read> Read for Snow2Decoder<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut total_bytes_written_to_buf = 0;

        // 1. Use leftover bytes first
        if self.left_buffer_len > 0 {
            let copy_len = std::cmp::min(buf.len(), self.left_buffer_len);
            buf[..copy_len].copy_from_slice(&self.left_buffer[..copy_len]);
            
            self.left_buffer.copy_within(copy_len..self.left_buffer_len, 0);
            self.left_buffer_len -= copy_len;
            total_bytes_written_to_buf += copy_len;
            self.stream_pos += copy_len as u64;

            if total_bytes_written_to_buf == buf.len() {
                return Ok(total_bytes_written_to_buf);
            }
        }

        let remaining_buf_target_len = buf.len() - total_bytes_written_to_buf;
        if remaining_buf_target_len == 0 {
             return Ok(total_bytes_written_to_buf);
        }

        let words_needed_for_remaining_buf = (remaining_buf_target_len + 3) / 4;
        let bytes_to_read_from_rd_for_decryption = words_needed_for_remaining_buf * 4;

        // If we don't have enough bytes to read for a full decryption operation,
        // and we need to fill the buf, this might be an issue.
        // The original logic read `dec_block_len` which was (new_reading_len + 3) & !3.
        // `new_reading_len` was `buf.len() - self.left_buffer_len`.
        // This is essentially what `bytes_to_read_from_rd_for_decryption` calculates.

        let mut underlying_read_buffer = vec![0u8; bytes_to_read_from_rd_for_decryption];
        
        // This is the critical read_exact call.
        // It needs to fill `underlying_read_buffer` completely.
        match self.rd.read_exact(&mut underlying_read_buffer) {
            Ok(_) => {},
            Err(e)  => {
                // If read_exact fails (e.g. UnexpectedEof), it means we couldn't get enough bytes
                // from the underlying stream to perform the decryption for the requested amount.
                // If we already wrote some bytes from left_buffer, we return that.
                // Otherwise, the error propagates.
                return if total_bytes_written_to_buf > 0 { Ok(total_bytes_written_to_buf) } else { Err(e) };
            }
        }
        
        let mut decrypted_block_bytes_for_current_op = Vec::with_capacity(bytes_to_read_from_rd_for_decryption);
        let mut reader_ori = Cursor::new(underlying_read_buffer); // Cursor over the just-read encrypted bytes

        for _ in 0..words_needed_for_remaining_buf {
            let encrypted_word = reader_ori.read_u32::<LittleEndian>()?;
            let decrypted_word = encrypted_word.wrapping_sub(self.keystream[self.cur_index]);
            decrypted_block_bytes_for_current_op.write_u32::<LittleEndian>(decrypted_word)?;
            
            self.cur_index += 1;
            if self.cur_index >= 16 {
                self.generate_key_stream();
                self.cur_index = 0;
            }
        }

        // Now copy the *actually needed* portion from `decrypted_block_bytes_for_current_op` to `buf`
        let bytes_to_copy_to_buf = std::cmp::min(remaining_buf_target_len, decrypted_block_bytes_for_current_op.len());
        buf[total_bytes_written_to_buf .. total_bytes_written_to_buf + bytes_to_copy_to_buf]
            .copy_from_slice(&decrypted_block_bytes_for_current_op[..bytes_to_copy_to_buf]);
        total_bytes_written_to_buf += bytes_to_copy_to_buf;
        self.stream_pos += bytes_to_copy_to_buf as u64;

        // Store any excess decrypted bytes (from the 4-byte alignment) in left_buffer
        if decrypted_block_bytes_for_current_op.len() > bytes_to_copy_to_buf {
            self.left_buffer_len = decrypted_block_bytes_for_current_op.len() - bytes_to_copy_to_buf;
            // Ensure left_buffer can hold it (it's [u8;4], so max 3 bytes leftover)
            if self.left_buffer_len > self.left_buffer.len() {
                 return Err(IoError::new(IoErrorKind::Other, "Internal logic error: leftover decrypted data exceeds left_buffer capacity"));
            }
            self.left_buffer[..self.left_buffer_len]
                .copy_from_slice(&decrypted_block_bytes_for_current_op[bytes_to_copy_to_buf..]);
        } else {
            self.left_buffer_len = 0;
        }
        
        Ok(total_bytes_written_to_buf)
    }
}

impl<'a, R: Read + Seek> Seek for Snow2Decoder<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                // Seek underlying reader to its absolute start (assuming it corresponds to start of this cipher stream)
                // This is a big assumption. If rd is already a segment, its "0" is not the file's 0.
                // For a stream cipher, seeking generally means re-initializing and discarding.
                self.rd.seek(SeekFrom::Start(0))?; // Seek underlying to its start position.
                
                unsafe {
                    c_snow2_loadkey(self.state_table.as_mut_ptr(), self.key_ref.as_ptr());
                    self.generate_key_stream();
                }
                self.cur_index = 0;
                self.left_buffer_len = 0;
                self.stream_pos = 0;

                if offset > 0 {
                    let mut bytes_to_discard = offset;
                    let mut discard_buf = [0u8; 1024]; // Max buffer size for discarding
                    while bytes_to_discard > 0 {
                        let read_len = std::cmp::min(discard_buf.len() as u64, bytes_to_discard) as usize;
                        let num_read = self.read(&mut discard_buf[..read_len])?;
                        if num_read == 0 { // EOF
                            return Err(IoError::new(IoErrorKind::UnexpectedEof, "EOF reached while seeking by discarding"));
                        }
                        bytes_to_discard -= num_read as u64;
                    }
                }
                Ok(self.stream_pos)
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    let mut bytes_to_discard = offset as u64;
                    let mut discard_buf = [0u8; 1024];
                    while bytes_to_discard > 0 {
                        let read_len = std::cmp::min(discard_buf.len() as u64, bytes_to_discard) as usize;
                        let num_read = self.read(&mut discard_buf[..read_len])?;
                        if num_read == 0 {
                            return Err(IoError::new(IoErrorKind::UnexpectedEof, "EOF reached while seeking forward from current"));
                        }
                        bytes_to_discard -= num_read as u64;
                    }
                    Ok(self.stream_pos)
                } else {
                    // Seeking backward: delegate to Start after calculating new absolute position.
                    let current_pos = self.stream_pos;
                    let new_abs_pos = current_pos.saturating_sub(offset.abs() as u64);
                    self.seek(SeekFrom::Start(new_abs_pos))
                }
            }
            SeekFrom::End(_) => {
                Err(IoError::new(IoErrorKind::Unsupported, "SeekFrom::End is not supported on Snow2Decoder"))
            }
        }
    }
}


pub struct Snow2Encoder<'a, T: Write> {
    state_table: [u32; 18],
    keystream: [u32; 16],
    cur_index: usize,
    wr: &'a mut T,
    key_ref: Vec<u8>, // Stored for re-init if needed, though less common for encoders

    left_buffer: [u8; 4],
    left_buffer_len: usize,
}

impl<'a, T: Write> Snow2Encoder<'a, T> {
    pub fn new(key: &[u8], writer: &'a mut T) -> Box<Self> { // Kept Box<Self> as per original
        let mut r = Box::new(Snow2Encoder {
            state_table: [0; 18],
            keystream: [0; 16],
            cur_index: 0,
            wr: writer,
            key_ref: key.to_vec(),
            left_buffer: [0; 4],
            left_buffer_len: 0,
        });
        unsafe {
            c_snow2_loadkey(r.state_table.as_mut_ptr(), r.key_ref.as_ptr());
            r.generate_keystream();
        }
        r
    }

    fn end_encoding(&mut self) -> io::Result<()> {
        if self.left_buffer_len > 0 {
            // Pad with zeros to make it a full 4-byte block
            let padding_needed = (4 - self.left_buffer_len % 4) % 4;
            let mut final_block_data = self.left_buffer[..self.left_buffer_len].to_vec();
            final_block_data.extend(std::iter::repeat(0).take(padding_needed));

            if !final_block_data.is_empty() { // Should always be true if left_buffer_len > 0
                let word_to_encrypt = u32::from_le_bytes(final_block_data.try_into().map_err(|_| {
                    IoError::new(IoErrorKind::InvalidInput, "Final block for encryption is not 4 bytes after padding")
                })?);
                
                self.wr.write_u32::<LittleEndian>(
                    word_to_encrypt.wrapping_add(self.keystream[self.cur_index])
                )?;
                self.cur_index += 1;
                // Keystream regeneration not strictly needed here as it's the end.
            }
            self.left_buffer_len = 0;
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
        let mut input_buf_cursor = 0; // How much of `buf` we've processed
        let original_buf_len = buf.len();

        // 1. Fill left_buffer if it's partially full
        if self.left_buffer_len > 0 && self.left_buffer_len < 4 {
            let needed_to_fill_left = 4 - self.left_buffer_len;
            let can_take_from_input = std::cmp::min(needed_to_fill_left, original_buf_len - input_buf_cursor);
            
            self.left_buffer[self.left_buffer_len .. self.left_buffer_len + can_take_from_input]
                .copy_from_slice(&buf[input_buf_cursor .. input_buf_cursor + can_take_from_input]);
            self.left_buffer_len += can_take_from_input;
            input_buf_cursor += can_take_from_input;

            if self.left_buffer_len == 4 { // Now we have a full word in left_buffer
                let word = u32::from_le_bytes(self.left_buffer);
                self.wr.write_u32::<LittleEndian>(word.wrapping_add(self.keystream[self.cur_index]))?;
                self.cur_index = (self.cur_index + 1) % 16;
                if self.cur_index == 0 { self.generate_keystream(); }
                self.left_buffer_len = 0;
            }
        }

        // 2. Process full 4-byte words from the rest of buf
        while original_buf_len - input_buf_cursor >= 4 {
            let word = u32::from_le_bytes(buf[input_buf_cursor .. input_buf_cursor + 4].try_into().unwrap());
            self.wr.write_u32::<LittleEndian>(word.wrapping_add(self.keystream[self.cur_index]))?;
            self.cur_index = (self.cur_index + 1) % 16;
            if self.cur_index == 0 { self.generate_keystream(); }
            input_buf_cursor += 4;
        }

        // 3. Store any remaining bytes from buf into left_buffer
        let remaining_in_buf = original_buf_len - input_buf_cursor;
        if remaining_in_buf > 0 {
            self.left_buffer[..remaining_in_buf].copy_from_slice(&buf[input_buf_cursor..]);
            self.left_buffer_len = remaining_in_buf;
        }
        
        Ok(original_buf_len) // Report all input bytes as "processed"
    }

    fn flush(&mut self) -> io::Result<()> {
        // Drop handles final block, but flush can be called explicitly.
        // Forcing end_encoding here might be too aggressive if more writes are coming.
        // Usually, flush just ensures underlying writer is flushed.
        self.wr.flush()
    }
}

impl<'a, T: Write> Drop for Snow2Encoder<'a, T> {
    fn drop(&mut self) {
        if let Err(e) = self.end_encoding() {
            eprintln!("[ERROR] Snow2Encoder: Failed to end encoding during drop: {}", e);
        }
        // Flushing underlying writer is good practice too.
        if let Err(e) = self.wr.flush() {
            eprintln!("[ERROR] Snow2Encoder: Failed to flush underlying writer during drop: {}", e);
        }
    }
}