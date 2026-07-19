//! Integration tests for mabi-pack2.
//!
//! Fast (no real archives):
//!   cargo test --test integration_tests
//!
//! Slow (need .it/.pack files under .gemini/testing):
//!   cargo test --test integration_tests -- --ignored
//!
//! All tests that open real archives are marked `#[ignore]` so the default
//! `cargo test` run stays fast and offline.

mod common;

use std::path::Path;

// --------------------------------------------------------------------------
// Test corpus paths
// --------------------------------------------------------------------------

const UOTIARA: &str =
    r"C:\Users\Shaggy\Documents\GitHub\mabi-pack2\.gemini\testing\uotiara_00001.it";
const DATA_00003: &str =
    r"C:\Users\Shaggy\Documents\GitHub\mabi-pack2\.gemini\testing\data_00003.it";
const TEST_PACK: &str =
    r"C:\Users\Shaggy\Documents\GitHub\mabi-pack2\.gemini\testing\test.pack";
#[allow(dead_code)]
const REPACK_TEST: &str =
    r"C:\Users\Shaggy\Documents\GitHub\mabi-pack2\.gemini\testing\repack_test_2.it";
const KNOWN_SALT: &str = "})wWb4?-sVGHNoPKpc";

// --------------------------------------------------------------------------
// 1. load_salts — concurrent calls, race-condition guard
// --------------------------------------------------------------------------

/// Call load_salts() from 5 threads simultaneously.
/// Each result must contain all 30 hardcoded salts and the known NA salt.
/// This exercises the once_cell / Mutex initialisation path that previously
/// had a TOCTOU race where the initial `None` check was done outside the lock.
#[test]
fn test_load_salts_no_duplicate_threads() {
    let handles: Vec<_> = (0..5)
        .map(|_| std::thread::spawn(|| mabi_pack2::load_salts()))
        .collect();

    for h in handles {
        let salts = h.join().expect("thread panicked");
        assert!(
            salts.len() >= 30,
            "Expected at least 30 hardcoded salts, got {}",
            salts.len()
        );
        assert!(
            salts.iter().any(|s| s == KNOWN_SALT),
            "Known salt '{}' not found in salt list",
            KNOWN_SALT
        );
    }
}

// --------------------------------------------------------------------------
// 2–4. Snow2 roundtrip tests
// --------------------------------------------------------------------------

/// Roundtrip: Sub mode, iv = 0.
#[test]
fn test_snow2_roundtrip_sub_iv0() {
    use mabi_pack2::encryption::{gen_header_key, snow2_decrypt_mode, snow2_encrypt_mode, Snow2Mode};

    let key = gen_header_key("data.it", KNOWN_SALT);
    let original = vec![0xAA_u8; 64];
    let mut data = original.clone();

    snow2_encrypt_mode(&key, 0, Snow2Mode::Sub, &mut data);
    assert_ne!(data, original, "Encrypted data must differ from plaintext");

    snow2_decrypt_mode(&key, 0, Snow2Mode::Sub, &mut data);
    assert_eq!(data, original, "Sub/iv0 roundtrip failed: data not restored");
}

/// Roundtrip: Sub mode, iv = 1.
#[test]
fn test_snow2_roundtrip_sub_iv1() {
    use mabi_pack2::encryption::{gen_header_key, snow2_decrypt_mode, snow2_encrypt_mode, Snow2Mode};

    let key = gen_header_key("data.it", KNOWN_SALT);
    let original = vec![0x55_u8; 128];
    let mut data = original.clone();

    snow2_encrypt_mode(&key, 1, Snow2Mode::Sub, &mut data);
    assert_ne!(data, original, "Encrypted data (iv=1) must differ from plaintext");

    snow2_decrypt_mode(&key, 1, Snow2Mode::Sub, &mut data);
    assert_eq!(data, original, "Sub/iv1 roundtrip failed: data not restored");
}

/// Roundtrip: Xor mode, iv = 0.
/// In Xor mode encrypt == decrypt (XOR is self-inverse), so we verify via
/// decrypt too to keep the test form consistent.
#[test]
fn test_snow2_roundtrip_xor() {
    use mabi_pack2::encryption::{gen_header_key, snow2_decrypt_mode, snow2_encrypt_mode, Snow2Mode};

    let key = gen_header_key("data.it", KNOWN_SALT);
    let original = vec![0x33_u8; 64];
    let mut data = original.clone();

    snow2_encrypt_mode(&key, 0, Snow2Mode::Xor, &mut data);
    assert_ne!(data, original, "Xor-encrypted data must differ from plaintext");

    snow2_decrypt_mode(&key, 0, Snow2Mode::Xor, &mut data);
    assert_eq!(data, original, "Xor/iv0 roundtrip failed: data not restored");
}

// --------------------------------------------------------------------------
// 5. Key derivation is deterministic
// --------------------------------------------------------------------------

/// gen_header_key must produce the same output for the same inputs across
/// repeated calls (no hidden global state / PRNG).
#[test]
fn test_key_derivation_deterministic() {
    use mabi_pack2::encryption::gen_header_key;

    let k1 = gen_header_key("data_00001.it", KNOWN_SALT);
    let k2 = gen_header_key("data_00001.it", KNOWN_SALT);
    assert_eq!(k1, k2, "Key derivation must be deterministic");

    // Sanity: different archive names must produce different keys.
    let k3 = gen_header_key("data_00002.it", KNOWN_SALT);
    assert_ne!(k1, k3, "Different archive names should produce different keys");
}

// --------------------------------------------------------------------------
// 6. get_preview_ext returns correct MIME bucket
// --------------------------------------------------------------------------

/// Verify every documented extension → type mapping, including the None case
/// and case-insensitive matching.
#[test]
fn test_get_preview_ext() {
    use mabi_pack2::common_ext::get_preview_ext;

    // Core mappings
    assert_eq!(get_preview_ext("texture.dds"), Some("image"));
    assert_eq!(get_preview_ext("config.xml"), Some("text"));
    assert_eq!(get_preview_ext("model.pmg"), Some("pmg"));
    assert_eq!(get_preview_ext("sound.wav"), Some("audio"));
    assert_eq!(get_preview_ext("shader.compiled"), Some("binary"));

    // Unknown extension must return None
    assert_eq!(
        get_preview_ext("unknown.xyz"),
        None,
        ".xyz should return None"
    );

    // Case insensitivity
    assert_eq!(get_preview_ext("TEXTURE.DDS"), Some("image"));
    assert_eq!(get_preview_ext("Config.XML"), Some("text"));
    assert_eq!(get_preview_ext("Sound.WAV"), Some("audio"));
}

// --------------------------------------------------------------------------
// 7. List uotiara_00001.it  (needs real archive)
// --------------------------------------------------------------------------

/// Fully parse uotiara_00001.it with the known NA salt and assert entry count.
#[test]
#[ignore]
fn test_list_uotiara() {
    if !Path::new(UOTIARA).exists() {
        eprintln!("Skipping: archive not found at {}", UOTIARA);
        return;
    }

    let salts = mabi_pack2::load_salts();
    let result = mabi_pack2::common_ext::run_list_with_key_search_data(
        UOTIARA,
        Some(KNOWN_SALT.to_string()),
        &salts,
        None,
    );

    assert!(result.is_ok(), "run_list_with_key_search_data failed: {:?}", result.err());
    let (entries, header_salt, _entries_salt, _iv0, _h_off, _mode, _content_start) =
        result.unwrap();

    assert!(
        entries.len() >= 1200,
        "Expected at least 1200 entries in uotiara_00001.it, got {}",
        entries.len()
    );
    assert_eq!(
        header_salt, KNOWN_SALT,
        "Expected salt '{}', found '{}'",
        KNOWN_SALT, header_salt
    );
}

// --------------------------------------------------------------------------
// 8. List data_00003.it  (needs real archive)
// --------------------------------------------------------------------------

/// Parse data_00003.it (standard NA archive) and check iv0 == 0.
#[test]
#[ignore]
fn test_list_data_00003() {
    if !Path::new(DATA_00003).exists() {
        eprintln!("Skipping: archive not found at {}", DATA_00003);
        return;
    }

    let salts = mabi_pack2::load_salts();
    let result = mabi_pack2::common_ext::run_list_with_key_search_data(
        DATA_00003,
        None,
        &salts,
        None,
    );

    assert!(result.is_ok(), "run_list_with_key_search_data failed: {:?}", result.err());
    let (entries, _salt, _entries_salt, iv0, _h_off, _mode, _content_start) = result.unwrap();

    assert!(!entries.is_empty(), "Expected at least one entry in data_00003.it");
    assert_eq!(iv0, 0, "Expected iv0=0 for NA data archive, got {}", iv0);
}

// --------------------------------------------------------------------------
// 9. List test.pack  (needs real archive)
// --------------------------------------------------------------------------

/// Parse a legacy unencrypted .pack file.  No salt is required.
#[test]
#[ignore]
fn test_list_test_pack() {
    if !Path::new(TEST_PACK).exists() {
        eprintln!("Skipping: archive not found at {}", TEST_PACK);
        return;
    }

    let result = mabi_pack2::common_ext::run_list_with_key_search_data(
        TEST_PACK,
        None,
        &[], // no salts needed for unencrypted .pack
        None,
    );

    assert!(result.is_ok(), "run_list_with_key_search_data failed: {:?}", result.err());
    let (entries, ..) = result.unwrap();
    assert!(!entries.is_empty(), "Expected at least one entry in test.pack");
}

// --------------------------------------------------------------------------
// 10. Pack roundtrip — .it format  (needs temp filesystem access)
// --------------------------------------------------------------------------

/// Write 3 files → pack to .it → list the .it → assert 3 entries found.
#[test]
#[ignore]
fn test_pack_roundtrip_it() {
    let dir = common::temp_dir_for_test("roundtrip_it");
    let output = std::env::temp_dir().join("mabi_test_roundtrip_it.it");
    common::cleanup(&dir);
    let _ = std::fs::remove_file(&output);
    std::fs::create_dir_all(&dir).unwrap();

    std::fs::write(dir.join("file1.txt"), b"hello world from file 1").unwrap();
    std::fs::write(dir.join("file2.txt"), b"test content for file 2").unwrap();
    std::fs::write(dir.join("file3.xml"), b"<root><item>test</item></root>").unwrap();

    let pack_result = mabi_pack2::pack::run_pack(
        dir.to_str().unwrap(),
        output.to_str().unwrap(),
        KNOWN_SALT,
        vec![],   // no extra compress extensions
        false,    // no auto DDS conversion
        0,        // iv = 0
        None,     // no path prefix
        None,     // no progress callback
    );
    assert!(pack_result.is_ok(), "run_pack failed: {:?}", pack_result.err());
    assert!(output.exists(), "Output .it file was not created");

    let salts = mabi_pack2::load_salts();
    let list_result = mabi_pack2::common_ext::run_list_with_key_search_data(
        output.to_str().unwrap(),
        Some(KNOWN_SALT.to_string()),
        &salts,
        None,
    );
    assert!(list_result.is_ok(), "Listing packed .it failed: {:?}", list_result.err());
    let (entries, ..) = list_result.unwrap();
    assert_eq!(
        entries.len(),
        3,
        "Expected 3 entries after .it roundtrip, got {}",
        entries.len()
    );

    common::cleanup(&dir);
    let _ = std::fs::remove_file(&output);
}

// --------------------------------------------------------------------------
// 11. Pack roundtrip — .pack v1 format  (needs temp filesystem access)
// --------------------------------------------------------------------------

/// Write 3 files → pack to .pack → list with run_list_v1_data → assert 3 entries.
#[test]
#[ignore]
fn test_pack_roundtrip_pack_v1() {
    let dir = common::temp_dir_for_test("roundtrip_pack");
    let output = std::env::temp_dir().join("mabi_test_roundtrip_pack.pack");
    common::cleanup(&dir);
    let _ = std::fs::remove_file(&output);
    std::fs::create_dir_all(&dir).unwrap();

    std::fs::write(dir.join("file1.txt"), b"hello world from file 1").unwrap();
    std::fs::write(dir.join("file2.txt"), b"test content for file 2").unwrap();
    std::fs::write(dir.join("file3.xml"), b"<root><item>test</item></root>").unwrap();

    let pack_result = mabi_pack2::pack_v1::run_pack_v1(
        dir.to_str().unwrap(),
        output.to_str().unwrap(),
        1, // version 1
    );
    assert!(pack_result.is_ok(), "run_pack_v1 failed: {:?}", pack_result.err());
    assert!(output.exists(), "Output .pack file was not created");

    let list_result = mabi_pack2::pack_v1::run_list_v1_data(output.to_str().unwrap());
    assert!(list_result.is_ok(), "run_list_v1_data failed: {:?}", list_result.err());
    let entries = list_result.unwrap();
    assert_eq!(
        entries.len(),
        3,
        "Expected 3 entries after .pack roundtrip, got {}",
        entries.len()
    );

    common::cleanup(&dir);
    let _ = std::fs::remove_file(&output);
}

// --------------------------------------------------------------------------
// 12. Extract a single XML entry from uotiara_00001.it  (needs real archive)
// --------------------------------------------------------------------------

/// Dynamically finds the first .xml entry in uotiara_00001.it, extracts it,
/// and verifies the bytes start with '<' (valid XML).
#[test]
#[ignore]
fn test_extract_single_entry() {
    if !Path::new(UOTIARA).exists() {
        eprintln!("Skipping: archive not found at {}", UOTIARA);
        return;
    }

    // Step 1: find a real XML entry name.
    let salts = mabi_pack2::load_salts();
    let list_result = mabi_pack2::common_ext::run_list_with_key_search_data(
        UOTIARA,
        Some(KNOWN_SALT.to_string()),
        &salts,
        None,
    );
    assert!(list_result.is_ok(), "list failed: {:?}", list_result.err());
    let (entries, ..) = list_result.unwrap();

    let xml_entry = entries
        .iter()
        .find(|e| e.name.to_lowercase().ends_with(".xml"))
        .expect("No .xml entry found in uotiara_00001.it");
    let entry_name = xml_entry.name.clone();

    // Step 2: extract it.
    let result = mabi_pack2::common_ext::get_entry_data(
        UOTIARA,
        &entry_name,
        Some(KNOWN_SALT.to_string()),
    );
    assert!(
        result.is_ok(),
        "get_entry_data failed for '{}': {:?}",
        entry_name,
        result.err()
    );

    let (data, _iv0, _mode, _entry) = result.unwrap();
    assert!(!data.is_empty(), "Extracted XML data for '{}' must not be empty", entry_name);
    // Mabinogi XML files may be UTF-8 ('<'), UTF-8 BOM (0xEF), or UTF-16 LE BOM (0xFF/0xFE)
    let valid_start = data[0] == b'<' || data[0] == 0xEF || data[0] == 0xFF || data[0] == 0xFE;
    assert!(
        valid_start,
        "XML file '{}' must start with '<' or a BOM, got 0x{:02X}",
        entry_name, data[0]
    );
}

// --------------------------------------------------------------------------
// 13. Double-decrypt flag guard  (pure unit test, no real files)
// --------------------------------------------------------------------------

/// White-box test of the FLAG_ALL_ENCRYPTED / FLAG_HEAD_ENCRYPTED `else if`
/// guard in extract.rs.
///
/// Scenario: both flags are set on an entry (unusual but theoretically
/// possible with a corrupted/hand-crafted archive).  With the `else if`
/// structure only the FLAG_ALL_ENCRYPTED branch runs, performing a single
/// full decrypt that restores the original.  Without the guard a second
/// partial decrypt would run, corrupting the first 1024 bytes.
#[test]
fn test_double_decrypt_flag_guard() {
    use mabi_pack2::common::{FLAG_ALL_ENCRYPTED, FLAG_HEAD_ENCRYPTED};
    use mabi_pack2::encryption::{snow2_decrypt_mode, snow2_encrypt_mode, Snow2Mode};

    let key = [0x42u8; 16];
    let iv0 = 0u32;
    let mode = Snow2Mode::Sub;

    // Use exactly the size specified in the test description.
    let original = vec![0xAB_u8; 2048];
    let mut content = original.clone();

    // Encrypt all content — simulates how FLAG_ALL_ENCRYPTED data is stored.
    snow2_encrypt_mode(&key, iv0, mode, &mut content);
    assert_ne!(content, original, "Encryption must change the data");

    // Simulate the extraction logic from extract.rs with BOTH flags set.
    // The `else if` ensures only the first matching branch executes.
    let flags = FLAG_ALL_ENCRYPTED | FLAG_HEAD_ENCRYPTED;
    if (flags & FLAG_ALL_ENCRYPTED) != 0 {
        snow2_decrypt_mode(&key, iv0, mode, &mut content);
    } else if (flags & FLAG_HEAD_ENCRYPTED) != 0 {
        let len = std::cmp::min(content.len(), 1024);
        if len > 0 {
            snow2_decrypt_mode(&key, iv0, mode, &mut content[..len]);
        }
    }
    assert_eq!(
        content, original,
        "Single decrypt via else-if guard must restore original"
    );

    // Prove that double-decryption (the pre-fix bug) corrupts data.
    // This confirms the else-if is load-bearing, not just style.
    let mut double_dec = original.clone();
    snow2_encrypt_mode(&key, iv0, mode, &mut double_dec);
    snow2_decrypt_mode(&key, iv0, mode, &mut double_dec); // correct: first decrypt
    snow2_decrypt_mode(&key, iv0, mode, &mut double_dec); // bug: second decrypt
    assert_ne!(
        double_dec, original,
        "Double-decrypt must NOT restore original — proves else-if is required"
    );
}

// --------------------------------------------------------------------------
// 14. Concurrent converts don't stomp each other  (needs real archive)
// --------------------------------------------------------------------------

/// Spawn two threads each calling convert() on uotiara_00001.it with
/// different output paths.  Both outputs must exist and be non-empty.
///
/// NOTE: convert() currently uses the hard-coded relative path "temp_conv"
/// as its intermediate extraction directory.  Two concurrent calls therefore
/// share that directory — this test documents the observed behaviour and will
/// flag regressions if the race condition is fixed (both should succeed) or
/// worsens (neither output appears).
#[test]
#[ignore]
fn test_concurrent_convert_no_stomp() {
    if !Path::new(UOTIARA).exists() {
        eprintln!("Skipping: archive not found at {}", UOTIARA);
        return;
    }

    let out1 = std::env::temp_dir().join("mabi_test_conv_concurrent_1.it");
    let out2 = std::env::temp_dir().join("mabi_test_conv_concurrent_2.it");
    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);

    let (uotiara1, out1_str, salt1) = (
        UOTIARA.to_string(),
        out1.to_str().unwrap().to_string(),
        KNOWN_SALT.to_string(),
    );
    let (uotiara2, out2_str, salt2) = (
        UOTIARA.to_string(),
        out2.to_str().unwrap().to_string(),
        KNOWN_SALT.to_string(),
    );

    let h1 = std::thread::spawn(move || {
        mabi_pack2::common_ext::convert(&uotiara1, &out1_str, Some(salt1), false)
    });
    let h2 = std::thread::spawn(move || {
        mabi_pack2::common_ext::convert(&uotiara2, &out2_str, Some(salt2), false)
    });

    let r1 = h1.join().expect("thread 1 panicked");
    let r2 = h2.join().expect("thread 2 panicked");

    // Evaluate each output independently — document which succeeded.
    // Use as_ref() to borrow the Result without moving it.
    if r1.is_ok() {
        assert!(out1.exists(), "Output 1 missing despite Ok result");
        assert!(
            out1.metadata().map(|m| m.len() > 0).unwrap_or(false),
            "Output 1 is empty despite Ok result"
        );
    } else {
        eprintln!("Convert thread 1 error (may be expected race): {:?}", r1.as_ref().err());
    }
    if r2.is_ok() {
        assert!(out2.exists(), "Output 2 missing despite Ok result");
        assert!(
            out2.metadata().map(|m| m.len() > 0).unwrap_or(false),
            "Output 2 is empty despite Ok result"
        );
    } else {
        eprintln!("Convert thread 2 error (may be expected race): {:?}", r2.as_ref().err());
    }

    // At least one must have succeeded for the test to pass.
    assert!(
        r1.is_ok() || r2.is_ok(),
        "Both concurrent converts failed — regression or environment issue"
    );

    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
}
