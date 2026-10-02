//! Regression guard for legacy `.pack` archives (TODO "Regression Guard").
//!
//! Builds small legacy packs in a temp dir and reads them back through every
//! core entry point the GUI's `AggregateEntry` and the extract / list paths
//! are built from, so a change to `FileEntry` or the legacy readers that leaves
//! a field uninitialised or wrong fails here instead of in the GUI.
//!
//!   cargo test --test legacy_pack_tests

mod common;

use byteorder::{LittleEndian, WriteBytesExt};
use mabi_pack2::{common as core_common, common_ext, encryption, extract, pack_v1};
use std::io::Write;
use std::path::{Path, PathBuf};

const FILES: &[(&str, &[u8])] = &[
    ("db/item.xml", b"<items><item id=\"1\"/><item id=\"2\"/><item id=\"3\"/></items>"),
    ("gfx/tex.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
    ("readme.txt", b"hello hello hello hello hello hello hello hello"),
];

/// Fresh, empty test directory unique to this test.
fn test_dir(name: &str) -> PathBuf {
    let dir = common::temp_dir_for_test(&format!("legacy_pack_{}_{}", name, std::process::id()));
    common::cleanup(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write `FILES` under `<dir>/src/data/` and pack them into `<dir>/test.pack`.
fn build_pack(dir: &Path) -> PathBuf {
    let src = dir.join("src").join("data");
    for (rel, data) in FILES {
        let p = src.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
    }
    let out = dir.join("test.pack");
    pack_v1::run_pack_v1(src.to_str().unwrap(), out.to_str().unwrap(), 1).unwrap();
    out
}

fn archive_name(rel: &str) -> String {
    format!("data\\{}", rel.replace('/', "\\"))
}

#[test]
fn legacy_pack_entries_are_fully_initialised() {
    let dir = test_dir("entries");
    let pack = build_pack(&dir);
    let pack_len = std::fs::metadata(&pack).unwrap().len();

    let entries = pack_v1::run_list_v1_data(pack.to_str().unwrap()).unwrap();
    assert_eq!(entries.len(), FILES.len());
    for (rel, data) in FILES {
        let name = archive_name(rel);
        let e = entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("{} missing", name));
        assert_eq!(e.original_size as usize, data.len(), "{}", name);
        assert!(e.raw_size > 0, "{}", name);
        assert!(e.offset as u64 + e.raw_size as u64 <= pack_len, "{} out of bounds", name);
        assert_eq!(e.key, [0u8; 16], "{}", name);
        let expected_flags = if e.original_size != e.raw_size { core_common::FLAG_COMPRESSED } else { 0 };
        assert_eq!(e.flags, expected_flags, "{}", name);
        assert_eq!(e.checksum, e.offset.wrapping_add(e.original_size).wrapping_add(e.raw_size), "{}", name);
    }

    // The tuple the GUI's AggregateEntry is built from for legacy archives.
    let (listed, salt, entries_salt, iv0, h_off, mode, content_start) =
        common_ext::run_list_with_key_search_data(pack.to_str().unwrap(), None, &[], None).unwrap();
    assert_eq!(listed.len(), FILES.len());
    assert_eq!((salt.as_str(), entries_salt.as_str()), ("UNENCRYPTED", "UNENCRYPTED"));
    assert_eq!((iv0, h_off, content_start), (0, 0, 0));
    assert!(matches!(mode, encryption::Snow2Mode::Sub));
    for (a, b) in listed.iter().zip(entries.iter()) {
        assert_eq!((&a.name, a.offset, a.original_size, a.raw_size, a.flags, a.checksum),
                   (&b.name, b.offset, b.original_size, b.raw_size, b.flags, b.checksum));
    }
    common::cleanup(&dir);
}

#[test]
fn legacy_pack_contents_round_trip() {
    let dir = test_dir("roundtrip");
    let pack = build_pack(&dir);
    let pack_str = pack.to_str().unwrap();

    // Single-entry read (preview path).
    for (rel, data) in FILES {
        let (bytes, iv0, _mode, ent) = common_ext::get_entry_data(pack_str, &archive_name(rel), None).unwrap();
        assert_eq!(&bytes[..], *data, "{}", rel);
        assert_eq!(iv0, 0);
        assert_eq!(ent.name, archive_name(rel));
    }

    // Full extraction through the generic entry point (detects the MABI magic).
    let out = dir.join("out");
    let marker = extract::run_extract_with_key_search(
        pack_str, out.to_str().unwrap(), None, &[], vec![], None, false, false, false, None,
    ).unwrap();
    assert_eq!(marker, "LEGACY_MABI");
    for (rel, data) in FILES {
        let p = out.join("data").join(rel);
        assert_eq!(std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e)), *data);
    }
    common::cleanup(&dir);
}

/// Hand-written legacy pack: `magic` header + one index entry named `name`.
fn write_raw_pack(path: &Path, magic: &[u8; 4], name: &str, data: &[u8]) {
    let mut f = std::fs::File::create(path).unwrap();
    let index_off = 16u32;
    let data_off = index_off + 256 + 16;
    f.write_all(magic).unwrap();
    f.write_u32::<LittleEndian>(1).unwrap(); // version
    if magic == b"MABI" {
        f.write_u32::<LittleEndian>(index_off).unwrap();
        f.write_u32::<LittleEndian>(1).unwrap();
    } else {
        f.write_u32::<LittleEndian>(1).unwrap();
        f.write_u32::<LittleEndian>(index_off).unwrap();
    }
    let mut name_buf = [0u8; 256];
    name_buf[..name.len()].copy_from_slice(name.as_bytes());
    f.write_all(&name_buf).unwrap();
    let len = data.len() as u32;
    f.write_u32::<LittleEndian>(data_off).unwrap();
    f.write_u32::<LittleEndian>(len).unwrap();
    f.write_u32::<LittleEndian>(len).unwrap();
    f.write_u32::<LittleEndian>(data_off + len + len).unwrap();
    f.write_all(data).unwrap();
}

#[test]
fn legacy_pack_magic_variant_reads_back() {
    let dir = test_dir("magic");
    let pack = dir.join("plain.pack");
    write_raw_pack(&pack, b"PACK", "data\\a.txt", b"abc");
    let entries = pack_v1::run_list_v1_data(pack.to_str().unwrap()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "data\\a.txt");
    assert_eq!((entries[0].original_size, entries[0].raw_size, entries[0].flags), (3, 3, 0));

    let out = dir.join("out");
    let marker = extract::run_extract_with_key_search(
        pack.to_str().unwrap(), out.to_str().unwrap(), None, &[], vec![], None, false, false, false, None,
    ).unwrap();
    assert_eq!(marker, "LEGACY_PACK");
    assert_eq!(std::fs::read(out.join("data").join("a.txt")).unwrap(), b"abc");
    common::cleanup(&dir);
}

#[test]
fn legacy_pack_extraction_refuses_path_traversal() {
    let dir = test_dir("traversal");
    for (i, name) in ["..\\..\\escaped.txt", "C:\\escaped.txt", "\\escaped.txt"].iter().enumerate() {
        let pack = dir.join(format!("evil{}.pack", i));
        write_raw_pack(&pack, b"MABI", name, b"pwned");
        let out = dir.join("a").join("b").join("out");
        assert!(pack_v1::run_extract_v1(pack.to_str().unwrap(), out.to_str().unwrap()).is_err(), "{}", name);
    }
    for p in [dir.join("escaped.txt"), dir.join("a").join("escaped.txt"), PathBuf::from("/escaped.txt")] {
        assert!(!p.exists(), "{} was written", p.display());
    }
    common::cleanup(&dir);
}

#[test]
fn legacy_pack_rejects_names_the_game_cannot_load() {
    let dir = test_dir("names");
    let src = dir.join("src");
    // Over the 255-byte .pack name field (but a legal file name on every OS).
    let deep = src.join("a".repeat(120)).join("b".repeat(120)).join("c".repeat(30));
    if std::fs::create_dir_all(deep.parent().unwrap()).and_then(|_| std::fs::write(&deep, b"x")).is_err() {
        common::cleanup(&dir); // filesystem without long-path support: nothing to pack
        return;
    }
    let err = pack_v1::run_pack_v1(src.to_str().unwrap(), dir.join("o.pack").to_str().unwrap(), 1).unwrap_err();
    assert!(err.to_string().contains("limit"), "{}", err);
    common::cleanup(&dir);
}
