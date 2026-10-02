# Archive Formats: `.it` and `.pack`

How Mabinogi's archives are laid out and how mabi-patcher reads and writes
them.

Sources: `src/common.rs` (header and entry parsing, header search),
`src/encryption.rs` and `src/snow2_fast.c` (Snow2 cipher and key
derivation), `src/extract.rs`, `src/pack.rs`, `src/list.rs`,
`src/pack_v1.rs` (legacy `.pack`), `src/common_ext.rs` (convert, full
sequence), `src/lib.rs` (salts).

All integers are little-endian unless stated.

---

## `.it` layout

```
offset 0
  ... padding / other data ...
H = header_offset(name)          9-byte header      (Snow2, header key)
H + E = H + entries_offset(name) entry table        (Snow2, entries key)
C = next 1024-byte boundary       file data, each file starting on a 1024-byte boundary
end - 4                           footer: H as u32    (Snow2, header key)
```

`name` is the archive's **file name** (for example `data_00000.it`), lower
case, as UTF-16. Renaming an `.it` file therefore changes where its header
is and how it is encrypted.

| Value | Formula (`encryption.rs`) |
|---|---|
| `header_offset(name)` | `(sum of UTF-16 code units of name) % 312 + 30` |
| `entries_offset(name)` | `(3 × sum of UTF-16 code units of name) % 212 + 42` |

### Header (9 bytes)

| Field | Type | Notes |
|---|---|---|
| `checksum` | u32 | Must equal `version + file_cnt`. |
| `version` | u8 | The writer uses `2`. |
| `file_cnt` | u32 | Number of entries. |

### Entry (one per file)

| Field | Type | Notes |
|---|---|---|
| `name_len` | u32 | Length in UTF-16 units. The reader rejects 0 and values over 4096. |
| `name` | UTF-16LE × `name_len` | Path inside the archive, usually with `\` separators. |
| `checksum` | u32 | `flags + offset + original_size + raw_size + (sum of the 16 key bytes)`. |
| `flags` | u32 | See below. |
| `offset` | u32 | In 1024-byte blocks from the start of file data `C`. |
| `original_size` | u32 | Size after decompression. |
| `raw_size` | u32 | Size stored in the archive. |
| `key` | 16 bytes | Per-file key material. |

| Flag | Value | Meaning |
|---|---|---|
| `FLAG_COMPRESSED` | `1` | Data is zlib-compressed. |
| `FLAG_ALL_ENCRYPTED` | `2` | Whole file is Snow2-encrypted with the file key. |
| `FLAG_HEAD_ENCRYPTED` | `4` | Only the first 1024 bytes are encrypted. |

The file key is `gen_file_key(entry name, entry key)`.

When reading, the start of file data `C` is the position right after the
entry table, rounded up to 1024. When writing it is
`ceil_1024(H + E + estimated table size)`, with the table size estimated as
`2 × name length + 40` per entry.

---

## Snow2 encryption

The cipher is SNOW 2.0, implemented in C (`src/snow2_fast.c`, compiled by
`build.rs`) and wrapped in Rust as `Snow2Decoder` / `Snow2Encoder`. It works
on 32-bit words.

- **Key** is 16 bytes. **IV**: only the lowest IV word (`iv0`) is used,
  `0` or `1`.
- **Modes** (`Snow2Mode`): `Sub`, `Xor`, `ModernBE`, `ModernLE`, `LegacyBE`,
  `LegacyLE`. `*LE` modes load key words little-endian, others big-endian;
  `Legacy*` modes use 1 instead of 2 for the `clockings` setting in the
  C key setup (`snow_loadkey_fast`). When decrypting,
  `Sub` subtracts the keystream word and every other mode XORs it; the
  encoder adds for `Sub`.
- Data that is not a multiple of 4 bytes is padded on write
  (`Snow2Encoder::finish`).

### Key derivation

Let `input` be the UTF-16 code units of `lowercase(archive name) + salt`, and
`n` its length. For `i` in `0..16`:

| Key | Byte `i` |
|---|---|
| Header key | `(input[i % n] + i) as u8` |
| Entries key | `(i + (i % 3 + 2) × input[n - 1 - i % n]) as u8` |

The file key mixes the entry name's UTF-16 units with the entry's 16 key
bytes (`gen_file_key`).

---

## Salts

The salt is a short text secret per game region and era. Every salt must be
tried until one decrypts a valid header, unless you pass one with `-k`.

`load_salts()` in `src/lib.rs` builds the list:

1. `HARDCODED_SALTS`, a built-in list in `src/lib.rs`, most common first.
2. `salts.txt` in the **current folder**: one salt per line; blank lines and
   lines starting with `#` are skipped.
3. A remote list at `SALTS_URL` (on the project's website), fetched with a
   3-second timeout.

The first call builds the whole list before it returns, waiting at most 3
seconds for the remote list. If the remote list is slower than that, it is
added to the cached list whenever it arrives. Later calls in the same
process return the cached list. A one-shot CLI run therefore uses the
built-in list and `salts.txt`, plus the remote list when it answers in time.

`GET /api/v1/salts` returns the current list.

---

## Finding the header

`extract` and `list` search in two phases (`run_extract_with_key_search`).

**Name variants** tried in order: the real file name, an optional region
override, `data.it`, and an empty name.

**Phase 1 – header.** For each salt (all salts in parallel),
`find_header_only` tries:

1. Fast path: `Sub` mode, `iv0 = 0`, at `header_offset(name)`. This is the
   usual case for NA archives.
2. Then for `iv0` in `0, 1` and every mode: the offset stored in the
   encrypted footer, `header_offset(name)`, and fixed offsets `0`, `108`,
   `109`.

A header is accepted when its checksum matches.

**Phase 2 – entries.** With the header's offset, IV and mode, the entry
table is decrypted first with the same salt, then with every other salt
(archives whose header and entry table use different salts). Candidate table
offsets are `H + 9`, `H + E`, and `header_offset(name) + E`. A table is
accepted when every entry parses, names are 1–1024 characters, no file is
over 500 MB, and every entry checksum matches.

A salt given with `-k` is tried on its own first; if it fails, the full
search runs.

The result reports the header salt used (`salt_used` in the API).

---

## Extracting

For each entry (filtered by the regular expressions given, if any):

1. Read `raw_size` bytes at `C + offset × 1024`.
2. If `FLAG_ALL_ENCRYPTED`, decrypt everything with the file key. If
   `FLAG_HEAD_ENCRYPTED`, decrypt the first 1024 bytes.
3. If `FLAG_COMPRESSED`, zlib-decompress. If that fails, retry on the other
   assumption about encryption (decrypt if it was not marked encrypted, or
   use the raw bytes if it was).
4. Optional conversions (API, GUI): DDS → PNG, `features.xml.compiled` →
   XML, PMG → OBJ.
5. Write to `<output>/<entry name>` with `/`, `\` and `¥` turned into the
   native separator (`common::safe_join`). A name that is absolute, has a
   drive or UNC prefix, contains a `..` component or contains `:` is
   refused, so nothing is written outside the output folder.

A failed entry is logged as a warning and skipped; extraction continues.
Entries are written one after another.

---

## Packing

`pack::run_pack(input, output, salt, compress_ext, auto_dds, iv, prefix)`:

1. Walk the input folder. Entry names are paths relative to it. With a
   prefix (`--wrap-data` = `data`), names become `data\<path>` with `\`
   separators. Every name must pass `common::validate_entry_path`: a safe
   relative path, at most 260 characters (the longest path the client
   handles), and none of `< > : " | ? *` or control characters. One bad
   name stops the pack before anything is written.
2. Read and, when needed, compress files in parallel chunks. Files ending in
   `.txt .xml .dds .pmg .set .raw` or an extra extension (both compared
   without regard to case) are zlib-compressed
   (`FLAG_COMPRESSED`). With `auto_dds`, `.png` files are converted to DXT5
   (`BC3RgbaUnormSrgb`, with mipmaps) and stored as `.dds`.
3. Write file data in order from `C`, each on a 1024-byte boundary.
4. Write the entry table at `H + E` and the header at `H`, both encrypted in
   `Sub` mode with the given `iv` (default 0).
5. Append the encrypted footer.

The writer does **not** encrypt file contents: every entry has an all-zero
`key` and no encryption flag. Only the header, entry table and footer are
encrypted. Entry names are written one UTF-16 unit per character, so
characters outside the Basic Multilingual Plane are not stored correctly.

---

## Legacy `.pack`

Detected by the first four bytes.

### `MABI` (written by mabi-patcher)

| Offset | Field |
|---|---|
| 0 | `"MABI"` |
| 4 | version (u32) |
| 8 | index offset (u32) |
| 12 | file count (u32) |

Each index record: 256-byte name (UTF-8, NUL-padded, at most 255 bytes),
`offset` u32 (absolute), `size` u32, `compressed_size` u32, `checksum` u32
(`offset + size + compressed_size`). The writer puts the index at offset 16,
compresses every file with zlib, and stores names with `\` separators
(`¥` is also turned into `\`). Names are checked like `.it` names and must
also fit the 255-byte name field. If the input folder is itself named `data`,
names start from its parent so they keep the `data\` prefix.

A file is decompressed on read when `size != compressed_size`. Legacy packs
are extracted in parallel.

Version written: CLI `pack` and `convert` use `1`; the API `pack` and the GUI
exe's `pack` use `pack_v1_version` / `--pack-version`, default `999`.

### `PACK`

Read-only. The reader first tries the "Logue / MabinogiResource" layout
(`run_list_logue_data`); if that fails it reads the standard layout, which is
the same as `MABI` except that file count comes before index offset.
Extraction returns the marker `LOGUE_PACK` or `LEGACY_PACK`; `MABI` returns
`LEGACY_MABI`.

---

## Convert and full sequence

| Operation | Steps |
|---|---|
| `convert` (`common_ext::convert`) | Extract the source to a temp folder (`.pack` by extension, `.it` with the salt search). Write `.pack` (version 1) or `.it`. For `.it`, wrap under `data\` if asked and the tree has no `data` folder yet. Salt for the output: given key, else the salt that opened the source, else the first built-in salt. |
| `full-sequence` (`common_ext::run_full_sequence`) | Extract every `.it`/`.pack` in the folder, sorted by name, into one temp folder (later archives overwrite earlier ones), then pack it into one `.it` with the given key or the first built-in salt. |
| `patch/create` (`src/patch.rs`) | Pack only the files in the modified folder that are new or whose MD5 differs from the base folder. |
