//! Compact item / prop lookup tables built from Mabinogi's `data/db` XML files.
//!
//! Formats (verified against public references; see notes):
//! * `data/db/itemdb.xml` (optionally split into several `itemdb*.xml` files) holds one
//!   `<Mabi_Item .../>` element per item. Attributes used here: `ID`, `Text_Name0`
//!   (internal name), `Text_Name1` (display name, usually a `_LT[xml.itemdb.N]` token),
//!   `Category`, `File_MaleMesh`, `File_FemaleMesh`, `File_GiantMesh`,
//!   `File_FemaleGiantMesh`, `File_FieldMesh` and `File_InvImage`. Mesh values are model
//!   names without the `.pmg` extension (e.g. `male_rueli_s10`).
//!   Source: mabimods.net "[Guide] Understanding itemdb.xml" (topic 17866) and the
//!   Mabinogi World wiki talk pages quoting raw `<Mabi_Item>` lines; the owner's
//!   website item database uses the same maleMesh/femaleMesh/fieldMesh/invImage fields.
//! * `_LT[xml.itemdb.512]` tokens resolve through `data/local/xml/itemdb.<language>.txt`,
//!   one `id<TAB>text` per line; the key is the file's path below `local/` with the
//!   language suffix dropped (`xml.itemdb`) plus `.id`, compared case-insensitively.
//!   Source: exectails/Mabioned `MabiWorld/Data/Local.cs`.
//! * `data/db/propdb.xml` has `<PropClass ClassID=".." ClassName=".." ClassPath=".."
//!   StringID=".." Name=".."/>` elements (exectails/Mabioned `MabiWorld/Data/PropDb.cs`).
//!   Current clients ship it encoded; `parse_propdb` only accepts plaintext XML and
//!   returns `None` for anything else so callers can skip it quietly.
//!
//! Assumptions not verified against real files: the XML text may be UTF-16 (with or
//! without BOM) or UTF-8; elements may be self-closing or not; attribute names are
//! matched exactly as above, plus any other `File_*Mesh` attribute as an extra mesh slot.

use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;

// ── text decoding ────────────────────────────────────────────────────────────

/// Decodes an XML/text file as UTF-16 (BOM, or the zero-byte pattern of ASCII text)
/// or UTF-8 (lossy).
pub fn decode_text(bytes: &[u8]) -> String {
    let utf16 = |b: &[u8], le: bool| -> String {
        let words: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) })
            .collect();
        String::from_utf16_lossy(&words)
    };
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return utf16(&bytes[2..], true);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return utf16(&bytes[2..], false);
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.len() >= 4 && bytes[0] != 0 && bytes[1] == 0 && bytes[3] == 0 {
        return utf16(bytes, true);
    }
    if bytes.len() >= 4 && bytes[0] == 0 && bytes[1] != 0 && bytes[2] == 0 {
        return utf16(bytes, false);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

// ── minimal streaming element scanner ────────────────────────────────────────

fn unescape(v: &str) -> Cow<'_, str> {
    if !v.contains('&') {
        return Cow::Borrowed(v);
    }
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// Parses `name="value"` pairs of one start tag (`body` is the text after the tag name,
/// up to but excluding the closing `>`).
fn parse_attrs(body: &str) -> Vec<(&str, Cow<'_, str>)> {
    let b = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() && b[i] != b'/' {
            i += 1;
        }
        let name = &body[name_start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            if name.is_empty() {
                i += 1;
            }
            continue;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let q = b[i];
        if q != b'"' && q != b'\'' {
            continue;
        }
        i += 1;
        let v_start = i;
        while i < b.len() && b[i] != q {
            i += 1;
        }
        let value = &body[v_start..i.min(b.len())];
        i += 1;
        if !name.is_empty() {
            out.push((name, unescape(value)));
        }
    }
    out
}

/// Calls `f` with the attributes of every `<tag ...>` start tag in `text`, skipping
/// comments. No DOM is built, so memory stays proportional to one element.
pub fn for_each_element<'a>(text: &'a str, tag: &str, mut f: impl FnMut(&[(&'a str, Cow<'a, str>)])) {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while let Some(rel) = text[pos..].find('<') {
        let start = pos + rel;
        let after = &text[start + 1..];
        if after.starts_with("!--") {
            pos = match after.find("-->") {
                Some(e) => start + 1 + e + 3,
                None => return,
            };
            continue;
        }
        if after.starts_with(tag) {
            let name_end = start + 1 + tag.len();
            let next = bytes.get(name_end).copied().unwrap_or(b'>');
            if next.is_ascii_whitespace() || next == b'/' || next == b'>' {
                // Find the closing '>' outside quotes.
                let mut i = name_end;
                let mut quote: Option<u8> = None;
                while i < bytes.len() {
                    let c = bytes[i];
                    match quote {
                        Some(q) if c == q => quote = None,
                        Some(_) => {}
                        None if c == b'"' || c == b'\'' => quote = Some(c),
                        None if c == b'>' => break,
                        None => {}
                    }
                    i += 1;
                }
                let attrs = parse_attrs(&text[name_end..i.min(bytes.len())]);
                f(&attrs);
                pos = (i + 1).min(text.len());
                continue;
            }
        }
        pos = start + 1;
    }
}

fn attr<'a>(attrs: &'a [(&str, Cow<'_, str>)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_ref())
}

// ── localization ─────────────────────────────────────────────────────────────

/// `data/local/xml/itemdb.english.txt` -> `xml.itemdb`; `None` when the path has no
/// `local` folder.
pub fn local_prefix(entry_path: &str) -> Option<String> {
    let norm = entry_path.replace('\\', "/").to_lowercase();
    let idx = if norm.starts_with("local/") { Some(0) } else { norm.find("/local/").map(|i| i + 1) }?;
    let rest = &norm[idx + "local/".len()..];
    let (dir, file) = match rest.rfind('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => ("", rest),
    };
    let stem = file.split('.').next().unwrap_or(file);
    if stem.is_empty() {
        return None;
    }
    Some(if dir.is_empty() { stem.to_string() } else { format!("{}.{}", dir.replace('/', "."), stem) })
}

/// Adds the `id<TAB>text` lines of one localization file to `map` under `prefix.id`.
pub fn parse_local_txt(text: &str, prefix: &str, map: &mut HashMap<String, String>) {
    for line in text.lines() {
        let Some(tab) = line.find('\t') else { continue };
        let key = line[..tab].trim();
        if key.is_empty() {
            continue;
        }
        let value = line[tab + 1..].trim_end_matches('\r');
        map.insert(format!("{}.{}", prefix, key.to_lowercase()), value.to_string());
    }
}

/// Resolves `_LT[xml.itemdb.512]` through `map`; other text is returned unchanged.
pub fn resolve_text(s: &str, map: &HashMap<String, String>) -> String {
    if let Some(inner) = s.strip_prefix("_LT[").and_then(|r| r.strip_suffix(']')) {
        if let Some(v) = map.get(&inner.to_lowercase()) {
            return v.clone();
        }
    }
    s.to_string()
}

// ── itemdb ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ItemMesh {
    /// `male`, `female`, `giant`, `giant_female`, `field` or the lower-cased middle of
    /// another `File_*Mesh` attribute.
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ItemEntry {
    pub id: u32,
    /// Display name (`Text_Name1`, localized when a matching local file was given).
    pub name: String,
    /// Internal name (`Text_Name0`).
    pub internal: String,
    pub category: String,
    pub meshes: Vec<ItemMesh>,
    pub inv_image: String,
}

fn mesh_kind(attr_name: &str) -> Option<String> {
    let mid = attr_name.strip_prefix("File_")?.strip_suffix("Mesh")?;
    Some(match mid {
        "Male" => "male".into(),
        "Female" => "female".into(),
        "Giant" => "giant".into(),
        "FemaleGiant" => "giant_female".into(),
        "Field" => "field".into(),
        other => other.to_lowercase(),
    })
}

/// Lower-cased file stem: `data/gfx/char/a/Male_X.pmg` -> `male_x`.
pub fn mesh_key(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let lower = base.to_lowercase();
    lower.strip_suffix(".pmg").map(str::to_string).unwrap_or(lower)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Items of one itemdb XML text, names still unresolved.
pub fn parse_items(text: &str) -> Vec<ItemEntry> {
    let mut out = Vec::new();
    for_each_element(text, "Mabi_Item", |attrs| {
        let Some(id) = attr(attrs, "ID").and_then(|v| v.trim().parse::<u32>().ok()) else { return };
        let mut meshes = Vec::new();
        for (k, v) in attrs {
            if let Some(kind) = mesh_kind(k) {
                let v = v.trim();
                if !v.is_empty() && !meshes.iter().any(|m: &ItemMesh| m.name.eq_ignore_ascii_case(v)) {
                    meshes.push(ItemMesh { kind, name: v.to_string() });
                }
            }
        }
        out.push(ItemEntry {
            id,
            name: attr(attrs, "Text_Name1").unwrap_or("").to_string(),
            internal: attr(attrs, "Text_Name0").unwrap_or("").to_string(),
            category: truncate(attr(attrs, "Category").unwrap_or(""), 240),
            meshes,
            inv_image: attr(attrs, "File_InvImage").unwrap_or("").to_string(),
        });
    });
    out
}

/// Item table with model and id lookups.
#[derive(Default)]
pub struct ItemIndex {
    items: Vec<ItemEntry>,
    by_id: HashMap<u32, usize>,
    by_mesh: HashMap<String, Vec<usize>>,
}

impl ItemIndex {
    /// Builds the index from item lists (later lists override earlier ids), resolving
    /// `_LT[...]` names through `local`.
    pub fn build(lists: Vec<Vec<ItemEntry>>, local: &HashMap<String, String>) -> Self {
        let mut idx = ItemIndex::default();
        for list in lists {
            for mut item in list {
                item.name = resolve_text(&item.name, local);
                item.internal = resolve_text(&item.internal, local);
                match idx.by_id.get(&item.id) {
                    Some(&at) => idx.items[at] = item,
                    None => {
                        idx.by_id.insert(item.id, idx.items.len());
                        idx.items.push(item);
                    }
                }
            }
        }
        for (i, item) in idx.items.iter().enumerate() {
            for m in &item.meshes {
                let list = idx.by_mesh.entry(mesh_key(&m.name)).or_default();
                if !list.contains(&i) {
                    list.push(i);
                }
            }
        }
        idx
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn with_mesh_count(&self) -> usize {
        self.items.iter().filter(|i| !i.meshes.is_empty()).count()
    }

    pub fn get(&self, id: u32) -> Option<&ItemEntry> {
        self.by_id.get(&id).map(|&i| &self.items[i])
    }

    /// Items whose mesh attributes name this model (file name, with or without `.pmg`).
    pub fn for_model(&self, model: &str, limit: usize) -> Vec<&ItemEntry> {
        self.by_mesh
            .get(&mesh_key(model))
            .map(|v| v.iter().take(limit).map(|&i| &self.items[i]).collect())
            .unwrap_or_default()
    }

    /// Exact id first, then id prefixes and case-insensitive name matches; items with a
    /// model rank before items without one.
    pub fn search(&self, query: &str, limit: usize) -> Vec<&ItemEntry> {
        let q = query.trim().to_lowercase();
        if q.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut out: Vec<&ItemEntry> = Vec::new();
        if let Ok(id) = q.parse::<u32>() {
            if let Some(it) = self.get(id) {
                out.push(it);
            }
        }
        let mut scored: Vec<(u8, &ItemEntry)> = Vec::new();
        for it in &self.items {
            if out.first().map(|f| f.id == it.id).unwrap_or(false) {
                continue;
            }
            let name = it.name.to_lowercase();
            let internal = it.internal.to_lowercase();
            let rank = if name == q || internal == q {
                0
            } else if name.starts_with(&q) || internal.starts_with(&q) {
                1
            } else if it.id.to_string().starts_with(&q) {
                2
            } else if name.contains(&q) || internal.contains(&q) || it.meshes.iter().any(|m| m.name.to_lowercase().contains(&q)) {
                3
            } else {
                continue;
            };
            let rank = rank * 2 + u8::from(it.meshes.is_empty());
            scored.push((rank, it));
        }
        scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.id.cmp(&b.1.id)));
        out.extend(scored.into_iter().map(|(_, it)| it));
        out.truncate(limit);
        out
    }
}

// ── propdb (plaintext only) ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PropClass {
    pub id: i32,
    pub class_name: String,
    pub class_path: String,
    pub string_id: String,
    pub name: String,
}

/// Prop classes of a plaintext `propdb.xml`; `None` when the bytes are not readable XML
/// (the encoded propdb shipped by current clients).
pub fn parse_propdb(bytes: &[u8]) -> Option<Vec<PropClass>> {
    let text = decode_text(bytes);
    let head: String = text.chars().take(4096).collect();
    if !head.contains('<') || !text.contains("<PropClass") {
        return None;
    }
    let mut out = Vec::new();
    for_each_element(&text, "PropClass", |attrs| {
        let Some(id) = attr(attrs, "ClassID").and_then(|v| v.trim().parse::<i32>().ok()) else { return };
        out.push(PropClass {
            id,
            class_name: attr(attrs, "ClassName").unwrap_or("").to_string(),
            class_path: attr(attrs, "ClassPath").unwrap_or("").to_string(),
            string_id: attr(attrs, "StringID").unwrap_or("").to_string(),
            name: attr(attrs, "Name").unwrap_or("").to_string(),
        });
    });
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Resolves `_LT[...]` names of prop classes.
pub fn localize_props(props: &mut [PropClass], local: &HashMap<String, String>) {
    for p in props {
        p.name = resolve_text(&p.name, local);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEMDB: &str = r#"<?xml version="1.0" encoding="utf-16"?>
<Items>
  <!-- <Mabi_Item ID="1" Text_Name1="commented out" File_MaleMesh="nope"/> -->
  <Mabi_Item ID="17509" DB_StoreType="1" Category="/equip/shoes/" Text_Name0="Studded Boots" Text_Name1="_LT[xml.itemdb.512]"
     File_MaleMesh="male_rueli_s10" File_FemaleMesh="female_rueli_s10" File_FieldMesh="field_shoes_01" File_InvImage="data/gfx/image/item_boots.dds" />
  <Mabi_Item ID="40001" Text_Name1="Wooden &amp; Stick" File_FieldMesh="weapon_stick01" File_MaleMesh="weapon_stick01"></Mabi_Item>
  <Mabi_Item ID="50000" Text_Name1="Apple" Category="/food/"/>
  <Mabi_ItemExtra ID="9" Text_Name1="not an item"/>
</Items>"#;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut v = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn decodes_utf16_and_utf8() {
        assert_eq!(decode_text(&utf16le("<a/>")), "<a/>");
        assert_eq!(decode_text(b"\xEF\xBB\xBF<b/>"), "<b/>");
        let no_bom: Vec<u8> = "<c/>".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_text(&no_bom), "<c/>");
    }

    #[test]
    fn parses_items_and_resolves_names() {
        let text = decode_text(&utf16le(ITEMDB));
        let items = parse_items(&text);
        assert_eq!(items.len(), 3, "comment and other tags are skipped");
        let boots = &items[0];
        assert_eq!(boots.id, 17509);
        assert_eq!(boots.meshes.len(), 3);
        assert_eq!(boots.meshes[0], ItemMesh { kind: "male".into(), name: "male_rueli_s10".into() });
        assert_eq!(boots.meshes[2].kind, "field");
        assert_eq!(items[1].name, "Wooden & Stick");
        assert_eq!(items[1].meshes.len(), 1, "duplicate mesh names collapse");

        let mut local = HashMap::new();
        let prefix = local_prefix("data/local/xml/itemdb.english.txt").unwrap();
        assert_eq!(prefix, "xml.itemdb");
        parse_local_txt("512\tStudded Oregon Boots\r\n513\tOther\n", &prefix, &mut local);
        let idx = ItemIndex::build(vec![items], &local);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.with_mesh_count(), 2);
        let hits = idx.for_model("data\\gfx\\char\\human\\Male_Rueli_S10.pmg", 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Studded Oregon Boots");
        assert!(idx.for_model("unknown_model", 10).is_empty());
    }

    #[test]
    fn search_ranks_ids_and_names() {
        let idx = ItemIndex::build(vec![parse_items(ITEMDB)], &HashMap::new());
        assert_eq!(idx.search("40001", 5)[0].id, 40001);
        let s = idx.search("stick", 5);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].id, 40001);
        assert_eq!(idx.search("apple", 5)[0].id, 50000);
        assert!(idx.search("", 5).is_empty());
        assert!(idx.search("zzz", 5).is_empty());
        // Later lists override earlier ids (split itemdb files).
        let override_list = parse_items(r#"<Mabi_Item ID="50000" Text_Name1="Green Apple"/>"#);
        let idx = ItemIndex::build(vec![parse_items(ITEMDB), override_list], &HashMap::new());
        assert_eq!(idx.get(50000).unwrap().name, "Green Apple");
        assert_eq!(idx.len(), 3);
    }

    #[test]
    fn propdb_plaintext_only() {
        let xml = r#"<PropDB><PropClassList>
            <PropClass ClassID="100" ClassName="prop_tree_01" ClassPath="/tree/" StringID="/prop/tree/" Name="_LT[xml.propdb.100]"/>
            <PropClass ClassID="bad" ClassName="x"/>
        </PropClassList></PropDB>"#;
        let mut props = parse_propdb(xml.as_bytes()).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].class_name, "prop_tree_01");
        let mut local = HashMap::new();
        parse_local_txt("100\tOak Tree", "xml.propdb", &mut local);
        localize_props(&mut props, &local);
        assert_eq!(props[0].name, "Oak Tree");
        // Encoded / binary data is skipped quietly.
        assert!(parse_propdb(&[0x13, 0x88, 0xA1, 0x00, 0x42, 0x99, 0x10, 0x07]).is_none());
        assert!(parse_propdb(b"<xml>no props</xml>").is_none());
    }

    #[test]
    fn local_prefix_variants() {
        assert_eq!(local_prefix("local\\xml\\propdb.korean.txt").as_deref(), Some("xml.propdb"));
        assert_eq!(local_prefix("data/db/itemdb.xml"), None);
        assert_eq!(resolve_text("plain", &HashMap::new()), "plain");
        assert_eq!(resolve_text("_LT[xml.x.1]", &HashMap::new()), "_LT[xml.x.1]");
    }
}
