//! Parser for Mabinogi .area files — prop placement data.
//!
//! .area files exist in two primary formats:
//!   1. XML text (older): contains `<prop>` elements with x/y/z/id attributes,
//!      optionally encoded as UTF-16 LE with BOM.
//!   2. Binary (newer): compact binary layout, either with an "AREA" magic prefix
//!      or a plain count-first structure.
//!
//! `parse_area` tries each format in turn and falls back to a coordinate heuristic.

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PropEntry {
    pub id: u32,
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AreaData {
    pub props: Vec<PropEntry>,
    pub format: String,
}

// ─── byte helpers ─────────────────────────────────────────────────────────────

fn r_u32_le(b: &[u8], p: usize) -> Option<u32> {
    if p + 4 > b.len() { return None; }
    Some(u32::from_le_bytes([b[p], b[p+1], b[p+2], b[p+3]]))
}

fn r_f32_le(b: &[u8], p: usize) -> Option<f32> {
    if p + 4 > b.len() { return None; }
    Some(f32::from_le_bytes([b[p], b[p+1], b[p+2], b[p+3]]))
}

/// Is this float plausible as a Mabinogi X or Z world coordinate?
/// Regions span roughly 0–16 384; allow some overflow and negatives.
fn is_world_coord(v: f32) -> bool {
    v.is_finite() && v >= -1_000.0 && v <= 24_000.0
}

/// Is this float plausible as a Mabinogi Y (height) coordinate?
/// Terrain height is typically −100 to 500 in NA.
fn is_height(v: f32) -> bool {
    v.is_finite() && v >= -300.0 && v <= 2_000.0
}

// ─── text decode ──────────────────────────────────────────────────────────────

fn decode_to_string(bytes: &[u8]) -> Option<String> {
    // UTF-16 LE (FF FE BOM)
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let words: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&words).ok();
    }
    // UTF-16 BE (FE FF BOM)
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let words: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16(&words).ok();
    }
    // UTF-8 / ASCII
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

// ─── XML attribute extraction ─────────────────────────────────────────────────

/// Extract the value of a named XML attribute from a tag element string.
/// Performs a case-insensitive search with word-boundary checking so that
/// `texturex="…"` does not match when looking for `x="…"`.
fn xml_attr<'a>(elem: &'a str, attr: &str) -> Option<&'a str> {
    let lo = elem.to_ascii_lowercase();
    let pat = format!("{}=\"", attr);
    let mut search = 0usize;
    while let Some(rel) = lo[search..].find(&pat) {
        let abs = search + rel;
        // Word-boundary: char before the attribute name must not be alphanumeric or '_'
        let prev_ok = abs == 0 || {
            let b = lo.as_bytes()[abs - 1];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        if prev_ok {
            let val_start = abs + pat.len();
            if let Some(end) = elem[val_start..].find('"') {
                return Some(&elem[val_start..val_start + end]);
            }
        }
        search = abs + 1;
        if search >= lo.len() { break; }
    }
    None
}

fn xml_f32(elem: &str, attr: &str) -> Option<f32> { xml_attr(elem, attr)?.parse().ok() }
fn xml_u32(elem: &str, attr: &str) -> Option<u32> { xml_attr(elem, attr)?.parse().ok() }

// ─── Format 1: XML ────────────────────────────────────────────────────────────

fn parse_area_xml(bytes: &[u8]) -> Option<AreaData> {
    let text = decode_to_string(bytes)?;
    let lo   = text.to_ascii_lowercase();

    if !lo.contains('<') || !lo.contains("prop") { return None; }

    let mut props   = Vec::new();
    let mut cursor  = 0usize;

    while cursor < lo.len() {
        let Some(rel) = lo[cursor..].find("<prop") else { break };
        let tag_start = cursor + rel;

        // Find the closing '>' of this opening tag
        let Some(close) = lo[tag_start..].find('>') else { break };
        let tag_end = tag_start + close + 1;

        let elem = &text[tag_start..tag_end];

        let x  = xml_f32(elem, "x")
            .or_else(|| xml_f32(elem, "posx"))
            .or_else(|| xml_f32(elem, "xpos"));
        let y  = xml_f32(elem, "y")
            .or_else(|| xml_f32(elem, "posy"))
            .or_else(|| xml_f32(elem, "ypos"));
        let z  = xml_f32(elem, "z")
            .or_else(|| xml_f32(elem, "posz"))
            .or_else(|| xml_f32(elem, "zpos"));
        let id = xml_u32(elem, "id")
            .or_else(|| xml_u32(elem, "classid"))
            .or_else(|| xml_u32(elem, "propid"));

        if let (Some(x), Some(z)) = (x, z) {
            props.push(PropEntry { id: id.unwrap_or(0), x, y: y.unwrap_or(0.0), z });
        }

        cursor = tag_end;
        if props.len() >= 200_000 { break; }
    }

    if props.is_empty() { return None; }
    Some(AreaData { props, format: "xml".to_string() })
}

// ─── Format 2: Binary ─────────────────────────────────────────────────────────

/// Try to parse `count` prop entries starting at byte `offset`.
/// Tries multiple common entry strides (16, 20, 24, 28, 32 bytes).
/// Layout assumed: id(u32) | x(f32) | y(f32) | z(f32) | [extra…]
fn try_parse_entries(bytes: &[u8], offset: usize, count: usize) -> Option<Vec<PropEntry>> {
    for stride in [16usize, 20, 24, 28, 32] {
        if offset + count * stride > bytes.len() { continue; }
        // Validate up to the first 8 entries
        let n_check = count.min(8);
        let mut ok = true;
        for i in 0..n_check {
            let p = offset + i * stride;
            let x = r_f32_le(bytes, p + 4)?;
            let y = r_f32_le(bytes, p + 8)?;
            let z = r_f32_le(bytes, p + 12)?;
            if !is_world_coord(x) || !is_world_coord(z) || !is_height(y) {
                ok = false;
                break;
            }
        }
        if !ok { continue; }

        let mut props = Vec::with_capacity(count.min(100_000));
        for i in 0..count {
            let p = offset + i * stride;
            if p + 16 > bytes.len() { break; }
            let id = r_u32_le(bytes, p).unwrap_or(0);
            let x  = r_f32_le(bytes, p +  4).unwrap_or(0.0);
            let y  = r_f32_le(bytes, p +  8).unwrap_or(0.0);
            let z  = r_f32_le(bytes, p + 12).unwrap_or(0.0);
            props.push(PropEntry { id, x, y, z });
        }
        if !props.is_empty() { return Some(props); }
    }
    None
}

/// Binary format with "AREA" magic: `AREA | ver(u32) | count(u32) | entries…`
fn parse_area_binary_magic(bytes: &[u8]) -> Option<AreaData> {
    if bytes.len() < 12 || &bytes[0..4] != b"AREA" { return None; }

    // Try: magic(4) + version(4) + count(4) + entries
    let count_a = r_u32_le(bytes, 8)? as usize;
    // Also try: magic(4) + count(4) + entries (no explicit version)
    let count_b = r_u32_le(bytes, 4)? as usize;

    for (hdr, count) in [(12, count_a), (8, count_b)] {
        if count == 0 || count > 500_000 { continue; }
        if let Some(props) = try_parse_entries(bytes, hdr, count) {
            return Some(AreaData { props, format: "binary-AREA".to_string() });
        }
    }
    None
}

/// Binary format with count first: `count(u32) | entries…`
fn parse_area_count_first(bytes: &[u8]) -> Option<AreaData> {
    if bytes.len() < 8 { return None; }
    let count = r_u32_le(bytes, 0)? as usize;
    if count == 0 || count > 500_000 { return None; }

    try_parse_entries(bytes, 4, count)
        .map(|props| AreaData { props, format: "binary-count".to_string() })
}

// ─── Format 3: Coordinate heuristic scan ─────────────────────────────────────

/// Scan aligned 4-byte positions looking for valid XYZ coordinate triplets.
/// This is a last-resort fallback and may include false positives.
fn parse_area_heuristic(bytes: &[u8]) -> Option<AreaData> {
    if bytes.len() < 16 { return None; }

    let mut props = Vec::new();
    let mut i = 0usize;

    while i + 12 <= bytes.len() {
        if let (Some(x), Some(y), Some(z)) = (r_f32_le(bytes, i), r_f32_le(bytes, i + 4), r_f32_le(bytes, i + 8)) {
            if is_world_coord(x) && is_world_coord(z) && is_height(y) {
                let id = if i >= 4 { r_u32_le(bytes, i - 4).unwrap_or(0) } else { 0 };
                props.push(PropEntry { id, x, y, z });
                i += 12;
                continue;
            }
        }
        i += 4;
        if props.len() >= 100_000 { break; }
    }

    if props.len() < 3 { return None; }
    Some(AreaData { props, format: "heuristic".to_string() })
}

// ─── Public API ───────────────────────────────────────────────────────────────

pub fn parse_area(bytes: &[u8]) -> Option<AreaData> {
    if bytes.is_empty() { return None; }

    // Detect text formats: UTF-8 XML, or UTF-16 BOM
    let is_text = bytes.starts_with(b"<?xml")
        || bytes.starts_with(b"<area")
        || bytes.starts_with(b"<Area")
        || (bytes.len() >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF)));

    if is_text {
        if let Some(d) = parse_area_xml(bytes) { return Some(d); }
    }

    // Binary formats
    if let Some(d) = parse_area_binary_magic(bytes) { return Some(d); }
    if let Some(d) = parse_area_count_first(bytes)  { return Some(d); }

    // Try XML on non-BOM text that still starts with '<'
    if !is_text && bytes.first().copied() == Some(b'<') {
        if let Some(d) = parse_area_xml(bytes) { return Some(d); }
    }

    // Last resort: coordinate scan
    parse_area_heuristic(bytes)
}
