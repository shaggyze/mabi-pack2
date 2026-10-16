use byteorder::{LittleEndian, WriteBytesExt};
use common::{FileEntry, FLAG_ALL_ENCRYPTED, FLAG_COMPRESSED, FLAG_HEAD_ENCRYPTED};
use encryption::Snow2Mode;
use mabi_pack2::{common, common_ext, encryption, pack};
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const HEADER_SALT: &str = "1&w2!&w{Q)Fkz4e&p0";
const ENTRIES_SALT: &str = "})wWb4?-sVGHNoPKpc";

#[test]
fn packing_names_require_lowercase_initial_and_order_after_data() {
    for name in [
        "uisciasSeedIcons_00004.it",
        "ezAh_00002.it",
        "dataA.it",
        "data_100000.it",
    ] {
        pack::validate_output_name(name, false).unwrap();
    }
    for (name, reason) in [
        ("UisciasSeedIcons_00004.it", "lowercase"),
        ("abc.it", "after 'data'"),
        ("data.it", "after 'data'"),
        ("9mod.it", "lowercase"),
        ("mod.IT", ".it extension"),
        ("mod name.it", "ASCII letters"),
        ("mod.it.exe", ".it extension"),
    ] {
        let error = pack::validate_output_name(name, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains(reason), "{name}: {error}");
        assert!(error.contains("resubmit"), "{name}: {error}");
    }
    let error = pack::validate_output_name("data_02052.it", false)
        .unwrap_err()
        .to_string();
    assert!(error.contains("confirmation") && error.contains("load order error"));
    pack::validate_output_name("data_02052.it", true).unwrap();
    assert!(pack::validate_output_name("Bad.it", true).is_err());
}

#[test]
fn packing_structure_requires_nonempty_data_root_or_explicit_wrapping() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    fs::create_dir_all(input.join("data")).unwrap();
    assert!(pack::validate_pack_request(input.to_str().unwrap(), "mod.it", None, false).is_err());
    write_input(&input, "loose.txt", b"loose");
    assert!(pack::validate_pack_request(input.to_str().unwrap(), "mod.it", None, false).is_err());
    pack::validate_pack_request(input.to_str().unwrap(), "mod.it", Some("data"), false).unwrap();
    assert!(
        pack::validate_pack_request(input.to_str().unwrap(), "mod.it", Some("gfx"), false).is_err()
    );
    fs::remove_file(input.join("loose.txt")).unwrap();
    write_input(&input, "data\\db\\test.xml", b"<test/>");
    pack::validate_pack_request(input.to_str().unwrap(), "mod.it", None, false).unwrap();
    assert!(pack::validate_pack_request(
        input.join("data").to_str().unwrap(),
        "mod.it",
        None,
        false
    )
    .is_err());
    pack::validate_pack_request(
        input.join("data").to_str().unwrap(),
        "mod.it",
        Some("data"),
        false,
    )
    .unwrap();
    write_input(&input, "outside.txt", b"outside");
    let error =
        pack::validate_pack_request(input.to_str().unwrap(), "mod.it", None, false).unwrap_err();
    assert!(error.to_string().contains("all packed files"));
}

#[test]
fn gui_pack_source_accepts_data_or_parent_and_excludes_surrounding_files() {
    let scratch = Scratch::new();
    let root = scratch.0.join("input");
    write_input(&root, "data\\db\\test.xml", b"<test/>");
    write_input(&root, "notes.txt", b"not game data");
    for selected in [&root, &root.join("data")] {
        let (source, prefix) = pack::resolve_gui_pack_source(selected.to_str().unwrap(), None);
        assert_eq!(Path::new(&source), root.join("data"));
        assert_eq!(prefix.as_deref(), Some("data"));
        pack::validate_pack_request(&source, "mod.it", prefix.as_deref(), false).unwrap();
        let output = scratch.0.join("mod.it");
        pack::run_pack_with_options(
            &source,
            output.to_str().unwrap(),
            HEADER_SALT,
            vec![],
            false,
            0,
            prefix.as_deref(),
            &pack::PackOptions::default(),
            None,
        )
        .unwrap();
        let (_, entries, _) = read_meta(&output, HEADER_SALT, HEADER_SALT, 0, Snow2Mode::Sub);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.replace('\\', "/"), "data/db/test.xml");
    }
    let (source, prefix) =
        pack::resolve_gui_pack_source(root.to_str().unwrap(), Some("data".into()));
    assert_eq!(Path::new(&source), root);
    assert_eq!(prefix.as_deref(), Some("data"));
    fs::remove_file(root.join("data").join("db").join("test.xml")).unwrap();
    let (source, prefix) = pack::resolve_gui_pack_source(root.to_str().unwrap(), None);
    assert!(pack::validate_pack_request(&source, "mod.it", prefix.as_deref(), false).is_err());
}

#[test]
fn long_archive_names_make_header_salt_labels_indistinguishable() {
    let name = "UisciasSeedIcons_00004.it";
    let attempted_salt = "@6QeTuOaDgJlZcBm#9";
    assert_eq!(
        encryption::gen_header_key(name, HEADER_SALT),
        encryption::gen_header_key(name, attempted_salt)
    );
    assert_ne!(
        encryption::gen_header_key("data_01467.it", HEADER_SALT),
        encryption::gen_header_key("data_01467.it", attempted_salt)
    );
    assert_ne!(
        encryption::gen_entries_key(name, ENTRIES_SALT),
        encryption::gen_entries_key(name, attempted_salt)
    );
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mabi_pack_proof_{}_{}", std::process::id(), id));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn write_input(root: &Path, name: &str, data: &[u8]) {
    let path = root.join(name.replace('\\', std::path::MAIN_SEPARATOR_STR));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

fn read_meta(
    path: &Path,
    header: &str,
    entries: &str,
    iv: u32,
    mode: Snow2Mode,
) -> (common::FileHeader, Vec<FileEntry>, u64) {
    let name = path.file_name().unwrap().to_str().unwrap();
    let mut reader = fs::File::open(path).unwrap();
    let (_, offset, actual_iv, actual_mode) = common::find_header_only(&mut reader, name, header)
        .unwrap()
        .unwrap();
    assert_eq!(actual_iv, iv);
    let expected_mode = if mode == Snow2Mode::ModernBE {
        Snow2Mode::Xor
    } else {
        mode
    };
    assert_eq!(actual_mode, expected_mode);
    common::read_meta_iv_mode_two_key(name, header, entries, &mut reader, offset, iv, mode).unwrap()
}

// No extraction fallback: prove the bytes obey the recorded encryption flags.
fn strict_content(path: &Path, entry: &FileEntry, start: u64, iv: u32, mode: Snow2Mode) -> Vec<u8> {
    let mut reader = fs::File::open(path).unwrap();
    reader
        .seek(SeekFrom::Start(start + entry.offset as u64 * 1024))
        .unwrap();
    let mut data = vec![0; entry.raw_size as usize];
    reader.read_exact(&mut data).unwrap();
    let key = encryption::gen_file_key(&entry.name, &entry.key);
    if entry.flags & FLAG_ALL_ENCRYPTED != 0 {
        encryption::snow2_decrypt_mode(&key, iv, mode, &mut data);
    }
    if entry.flags & FLAG_HEAD_ENCRYPTED != 0 {
        let len = data.len().min(1024);
        encryption::snow2_decrypt_mode(&key, iv, mode, &mut data[..len]);
    }
    if entry.flags & FLAG_COMPRESSED != 0 {
        let mut decoded = Vec::new();
        flate2::read::ZlibDecoder::new(&data[..])
            .read_to_end(&mut decoded)
            .unwrap();
        data = decoded;
    } else if data.len() > entry.original_size as usize {
        let padding = &data[entry.original_size as usize..];
        assert!(padding.len() <= 3 && padding.iter().all(|b| *b == 0));
        data.truncate(entry.original_size as usize);
    }
    assert_eq!(data.len(), entry.original_size as usize);
    data
}

#[test]
fn manual_separate_salts_and_encrypted_payloads() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    for (name, data) in [
        ("data\\config.xml", b"<root/>".as_slice()),
        ("data\\odd.bin", &[0xAB; 2051]),
        ("empty.bin", &[]),
    ] {
        write_input(&input, name, data);
    }
    let output = scratch.0.join("manual.it");
    pack::run_pack_with_options(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        &pack::PackOptions {
            entries_key: Some(ENTRIES_SALT.into()),
            encrypt_files: Some(true),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let (_, entries, start) = read_meta(&output, HEADER_SALT, ENTRIES_SALT, 0, Snow2Mode::Sub);
    assert_eq!(entries.len(), 3);
    for entry in entries {
        assert_ne!(entry.flags & FLAG_ALL_ENCRYPTED, 0);
        assert_ne!(entry.key, [0; 16]);
        let expected =
            fs::read(input.join(entry.name.replace('\\', std::path::MAIN_SEPARATOR_STR))).unwrap();
        assert_eq!(
            strict_content(&output, &entry, start, 0, Snow2Mode::Sub),
            expected
        );
    }
    let mut reader = fs::File::open(output).unwrap();
    assert!(common::read_meta_iv_mode_two_key(
        "manual.it",
        HEADER_SALT,
        HEADER_SALT,
        &mut reader,
        encryption::gen_header_offset("manual.it") as u64,
        0,
        Snow2Mode::Sub
    )
    .is_err());
}

#[test]
fn default_packing_preserves_single_salt_unencrypted_payload_behavior() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    write_input(&input, "old.txt", b"legacy behavior");
    let output = scratch.0.join("old.it");
    pack::run_pack(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        None,
    )
    .unwrap();
    let (_, entries, start) = read_meta(&output, HEADER_SALT, HEADER_SALT, 0, Snow2Mode::Sub);
    assert_eq!(entries[0].flags, FLAG_COMPRESSED);
    assert_eq!(entries[0].key, [0; 16]);
    assert_eq!(
        strict_content(&output, &entries[0], start, 0, Snow2Mode::Sub),
        b"legacy behavior"
    );
}

#[test]
fn empty_payload_still_has_a_valid_content_region() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    write_input(&input, "empty.bin", &[]);
    let output = scratch.0.join("empty.it");
    pack::run_pack(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        None,
    )
    .unwrap();
    let (_, entries, start) = read_meta(&output, HEADER_SALT, HEADER_SALT, 0, Snow2Mode::Sub);
    let file = fs::File::open(&output).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    assert!(mabi_pack2::extract::extract_single_file_to_memory(
        &mmap,
        start,
        &entries[0],
        0,
        Snow2Mode::Sub
    )
    .unwrap()
    .is_empty());
}

#[test]
fn rest_pack_supports_manual_and_template_options() {
    let stop = mabi_pack2::api::spawn(17430);
    let client = reqwest::blocking::Client::new();
    let url = "http://127.0.0.1:17430/api/v1/pack";
    let mut ready = false;
    for _ in 0..50 {
        if client
            .get("http://127.0.0.1:17430/api/v1/status")
            .send()
            .is_ok()
        {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(ready, "API server did not become ready");
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    write_input(&input, "data\\test.xml", b"<test/>");
    let manual = scratch.0.join("manual.it");
    let response: serde_json::Value = client
        .post(url)
        .json(&serde_json::json!({
            "source": input, "output": manual, "key": HEADER_SALT,
            "pack_options": { "entries_key": ENTRIES_SALT, "encrypt_files": true }
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(response["success"], true, "{response}");
    let output = scratch.0.join("from_template.it");
    let response: serde_json::Value = client
        .post(url)
        .json(&serde_json::json!({
            "source": input, "output": output,
            "pack_options": { "template_archive": manual }
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(response["success"], true, "{response}");
    let (_, entries, start) = read_meta(&output, HEADER_SALT, ENTRIES_SALT, 0, Snow2Mode::Sub);
    assert_eq!(entries[0].flags, FLAG_COMPRESSED | FLAG_ALL_ENCRYPTED);
    assert_eq!(
        strict_content(&output, &entries[0], start, 0, Snow2Mode::Sub),
        b"<test/>"
    );
    let response = client
        .post(url)
        .json(&serde_json::json!({
            "source": input, "output": output, "key": HEADER_SALT,
            "pack_options": { "entries_key": 123 }
        }))
        .send()
        .unwrap();
    assert_eq!(response.status(), 400);
    for (name, confirmation, expected_status) in [
        ("Bad.it", false, 400),
        ("abc.it", false, 400),
        ("data_02052.it", false, 400),
        ("data_02052.it", true, 200),
    ] {
        let destination = scratch.0.join(name);
        let response = client
            .post(url)
            .json(&serde_json::json!({
                "source":input, "output":destination, "key":HEADER_SALT,
                "pack_options":{"confirm_native_name":confirmation}
            }))
            .send()
            .unwrap();
        assert_eq!(response.status(), expected_status, "{name}");
        assert_eq!(destination.exists(), expected_status == 200);
    }
    let invalid_source = scratch.0.join("invalid");
    write_input(&invalid_source, "loose.xml", b"<test/>");
    let destination = scratch.0.join("structure.it");
    let response = client
        .post(url)
        .json(&serde_json::json!({
            "source":invalid_source, "output":destination, "key":HEADER_SALT
        }))
        .send()
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(!destination.exists());
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn utf16_names_and_word_padding_do_not_overlap_content() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    // The serialized table ends two bytes before a 1024-byte boundary.
    for i in 0..15 {
        write_input(&input, &format!("{:02}.bin", i), &[i as u8; 7]);
    }
    write_input(&input, "xxxxxxxxxxxxxxxxx\u{1F600}.bin", b"surrogate pair");
    let output = scratch.0.join("a.it");
    pack::run_pack(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        None,
    )
    .unwrap();
    let (_, entries, start) = read_meta(&output, HEADER_SALT, HEADER_SALT, 0, Snow2Mode::Sub);
    assert_eq!(entries.len(), 16);
    assert_eq!(start, 1024);
    for entry in entries {
        assert_eq!(
            strict_content(&output, &entry, start, 0, Snow2Mode::Sub),
            fs::read(input.join(entry.name)).unwrap()
        );
    }
}

fn fixture(path: &Path, iv: u32, mode: Snow2Mode, compact: bool) -> Vec<(String, Vec<u8>)> {
    fixture_with_padding(path, iv, mode, compact, false)
}

fn fixture_with_padding(
    path: &Path,
    iv: u32,
    mode: Snow2Mode,
    compact: bool,
    native: bool,
) -> Vec<(String, Vec<u8>)> {
    let name = path.file_name().unwrap().to_str().unwrap();
    let header_off = encryption::gen_header_offset(name) as u64;
    let entries_off = header_off
        + if compact {
            9
        } else {
            encryption::gen_entries_offset(name) as u64
        };
    let mut table = Vec::new();
    let mut payload = Vec::new();
    let mut originals = Vec::new();
    for (i, flags) in [
        0,
        FLAG_COMPRESSED | FLAG_ALL_ENCRYPTED,
        FLAG_HEAD_ENCRYPTED,
        FLAG_ALL_ENCRYPTED | FLAG_HEAD_ENCRYPTED,
    ]
    .into_iter()
    .enumerate()
    {
        let name = if native {
            format!("data/sample{}.bin", i)
        } else {
            format!("data\\sample{}.bin", i)
        };
        let original: Vec<u8> = (0..2051).map(|j| (j * 37 + i) as u8).collect();
        let mut raw = if flags & FLAG_COMPRESSED != 0 {
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&original).unwrap();
            enc.finish().unwrap()
        } else {
            original.clone()
        };
        let key = [i as u8 + 1; 16];
        let file_key = encryption::gen_file_key(&name, &key);
        if native && flags & (FLAG_ALL_ENCRYPTED | FLAG_HEAD_ENCRYPTED) != 0 {
            raw.resize((raw.len() + 3) & !3, 0);
        }
        if flags & FLAG_HEAD_ENCRYPTED != 0 {
            let len = raw.len().min(1024);
            encryption::snow2_encrypt_mode(&file_key, iv, mode, &mut raw[..len]);
        }
        if flags & FLAG_ALL_ENCRYPTED != 0 {
            encryption::snow2_encrypt_mode(&file_key, iv, mode, &mut raw);
        }
        let offset = payload.len() as u32 / 1024;
        let checksum = flags
            + offset
            + original.len() as u32
            + raw.len() as u32
            + key.iter().map(|b| *b as u32).sum::<u32>();
        let utf16: Vec<_> = name.encode_utf16().collect();
        table.write_u32::<LittleEndian>(utf16.len() as u32).unwrap();
        for c in utf16 {
            table.write_u16::<LittleEndian>(c).unwrap();
        }
        for value in [
            checksum,
            flags,
            offset,
            original.len() as u32,
            raw.len() as u32,
        ] {
            table.write_u32::<LittleEndian>(value).unwrap();
        }
        table.extend_from_slice(&key);
        payload.extend_from_slice(&raw);
        payload.resize((payload.len() + 1023) & !1023, 0);
        originals.push((name, original));
    }
    let start = (entries_off + ((table.len() as u64 + 3) & !3) + 1023) & !1023;
    let mut out = Cursor::new(vec![0; start as usize]);
    out.set_position(header_off);
    {
        let key = encryption::gen_header_key(name, HEADER_SALT);
        let mut enc = encryption::Snow2Encoder::new_iv_mode(&key, iv, mode, &mut out);
        enc.write_u32::<LittleEndian>(5).unwrap();
        enc.write_u8(1).unwrap();
        enc.write_u32::<LittleEndian>(4).unwrap();
        enc.finish().unwrap();
    }
    out.set_position(entries_off);
    {
        let key = encryption::gen_entries_key(name, ENTRIES_SALT);
        let mut enc = encryption::Snow2Encoder::new_iv_mode(&key, iv, mode, &mut out);
        enc.write_all(&table).unwrap();
        enc.finish().unwrap();
    }
    out.set_position(start);
    out.write_all(&payload).unwrap();
    fs::write(path, out.into_inner()).unwrap();
    originals
}

#[test]
fn template_preserves_separate_salts_modes_versions_keys_and_flags() {
    for (iv, mode, compact) in [
        (0, Snow2Mode::Sub, false),
        (1, Snow2Mode::Xor, true),
        (1, Snow2Mode::ModernBE, false),
        (0, Snow2Mode::ModernLE, true),
        (0, Snow2Mode::LegacyBE, false),
        (1, Snow2Mode::LegacyLE, true),
    ] {
        let scratch = Scratch::new();
        let template = scratch.0.join("original.it");
        let originals = fixture(&template, iv, mode, compact);
        let before = fs::read(&template).unwrap();
        let input = scratch.0.join("input");
        for (name, data) in &originals {
            write_input(&input, name, data);
        }
        let output = scratch.0.join("repacked.it");
        pack::run_pack_with_options(
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            HEADER_SALT,
            vec![".bin"],
            false,
            0,
            None,
            &pack::PackOptions {
                template_archive: Some(template.to_str().unwrap().into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let (old_header, old_entries, _) =
            read_meta(&template, HEADER_SALT, ENTRIES_SALT, iv, mode);
        let (header, entries, start) = read_meta(&output, HEADER_SALT, ENTRIES_SALT, iv, mode);
        assert_eq!(header.version, old_header.version);
        for entry in entries {
            let old = old_entries.iter().find(|e| e.name == entry.name).unwrap();
            assert_eq!(entry.flags, old.flags);
            assert_eq!(entry.key, old.key);
            let expected = &originals
                .iter()
                .find(|(name, _)| name == &entry.name)
                .unwrap()
                .1;
            assert_eq!(&strict_content(&output, &entry, start, iv, mode), expected);
        }
        assert_eq!(fs::read(&template).unwrap(), before);
    }
}

#[test]
fn native_template_preserves_payload_padding_trailer_and_path_style() {
    let scratch = Scratch::new();
    let template = scratch.0.join("original.it");
    let originals = fixture_with_padding(&template, 0, Snow2Mode::Sub, false, true);
    let input = scratch.0.join("input");
    for (name, data) in &originals {
        write_input(&input, name, data);
    }
    let output = scratch.0.join("repacked.it");
    pack::run_pack_with_options(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        &pack::PackOptions {
            template_archive: Some(template.to_str().unwrap().into()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(fs::metadata(&output).unwrap().len() % 1024, 0);
    let (_, entries, start) = read_meta(&output, HEADER_SALT, ENTRIES_SALT, 0, Snow2Mode::Sub);
    let file = fs::File::open(&output).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    for entry in entries {
        assert!(entry.name.starts_with("data/"));
        if entry.flags & (FLAG_ALL_ENCRYPTED | FLAG_HEAD_ENCRYPTED) != 0 {
            assert_eq!(entry.raw_size % 4, 0);
        }
        let expected = &originals
            .iter()
            .find(|(name, _)| name == &entry.name)
            .unwrap()
            .1;
        assert_eq!(
            &strict_content(&output, &entry, start, 0, Snow2Mode::Sub),
            expected
        );
        assert_eq!(
            &mabi_pack2::extract::extract_single_file_to_memory(
                &mmap,
                start,
                &entry,
                0,
                Snow2Mode::Sub
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn template_cannot_be_overwritten_or_combined_with_manual_settings() {
    let scratch = Scratch::new();
    let template = scratch.0.join("original.it");
    fixture(&template, 0, Snow2Mode::Sub, false);
    let before = fs::read(&template).unwrap();
    let input = scratch.0.join("input");
    write_input(&input, "test.bin", b"test");
    let mut options = pack::PackOptions {
        template_archive: Some(template.to_str().unwrap().into()),
        ..Default::default()
    };
    let result = pack::run_pack_with_options(
        input.to_str().unwrap(),
        template.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        &options,
        None,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("must not overwrite"));
    assert_eq!(fs::read(template).unwrap(), before);
    options.entries_key = Some(ENTRIES_SALT.into());
    let output = scratch.0.join("bad.it");
    assert!(pack::run_pack_with_options(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        HEADER_SALT,
        vec![],
        false,
        0,
        None,
        &options,
        None
    )
    .is_err());
    assert!(!output.exists());
}

#[test]
#[ignore = "Set MABI_TEST_ARCHIVE to a local original .it; never modifies it"]
fn real_game_template_roundtrip() {
    let original =
        PathBuf::from(std::env::var("MABI_TEST_ARCHIVE").expect("Set MABI_TEST_ARCHIVE"));
    let before = md5::compute(fs::read(&original).unwrap());
    let salts = mabi_pack2::load_salts();
    let (entries, header_salt, entries_salt, iv, _, mode, start) =
        common_ext::run_list_with_key_search_data(original.to_str().unwrap(), None, &salts, None)
            .unwrap();
    eprintln!(
        "Original: {} entries; HEADER={:?}; ENTRIES={:?}; IV={}; mode={:?}",
        entries.len(),
        header_salt,
        entries_salt,
        iv,
        mode
    );
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    for entry in &entries {
        write_input(
            &input,
            &entry.name,
            &strict_content(&original, entry, start, iv, mode),
        );
    }
    let output = scratch.0.join(original.file_name().unwrap());
    pack::run_pack_with_options(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        "",
        vec![],
        false,
        0,
        None,
        &pack::PackOptions {
            template_archive: Some(original.to_str().unwrap().into()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let (_, repacked, new_start) = read_meta(&output, &header_salt, &entries_salt, iv, mode);
    assert_eq!(repacked.len(), entries.len());
    for entry in repacked {
        let old = entries.iter().find(|e| e.name == entry.name).unwrap();
        assert_eq!(entry.flags, old.flags);
        assert_eq!(entry.key, old.key);
        assert_eq!(
            strict_content(&output, &entry, new_start, iv, mode),
            strict_content(&original, old, start, iv, mode)
        );
    }
    assert_eq!(md5::compute(fs::read(original).unwrap()), before);
}
