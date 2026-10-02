//! Region (.rgn), area (.area) and prop-set (.set) readers for the map / world previews.
//!
//! Layouts follow exectails/Mabioned (`MabiWorld/Region.cs`, `Area.cs`, `AreaPlane.cs`,
//! `Plane.cs`, `Square.cs`, `Prop.cs`, `Event.cs`, `Shape.cs`, `EntityParameter.cs`,
//! `Extensions/BinaryRW.cs`) and CodfishBender/MabiMapper (`GenerateTerrain.cs`,
//! `MabiWorld/FileFormats/SetFormat/*`):
//! * All values are little-endian; strings are null-terminated UTF-16LE.
//! * A .rgn holds no terrain: it names its areas (`<name>.area` in the same folder) and
//!   the region bounds. Versions 100, 102 and 103 are supported.
//! * A .area holds props, events and `PlaneX * PlaneY` area planes. Area planes are
//!   stored X-major (`index = ix * PlaneY + iy`), each a `Size x Size` vertex grid
//!   (also X-major) whose last row/column overlaps the next plane. `ShowPlane == 1`
//!   hides a plane. Vertex spacing is the area width / PlaneX / (Size - 1) (200 units in
//!   MabiMapper).
//! * World positions are (X, Y) on the ground with Z as altitude; `*_XZY` vectors are
//!   stored as X, altitude, Y.
//! * A .set starts with `set\0`, a format version, the header size (i32) and, at that
//!   offset, an item count followed by items whose first strings are the model file name
//!   and state name. The version field width is not documented, so 2, 4 and 8 bytes are
//!   tried and the first layout whose item data starts with `pa!`/`pf!` wins.
//!
//! The existing `rgn.rs`/`area.rs` readers predate this module and decode an assumed
//! layout; the previews use this module instead.

use serde::Serialize;

// ── reader ───────────────────────────────────────────────────────────────────

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

type R<T> = Result<T, String>;

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(format!("unexpected end of data at offset {} (need {} bytes)", self.p, n));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> R<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }
    fn i16(&mut self) -> R<i16> {
        let s = self.take(2)?;
        Ok(i16::from_le_bytes([s[0], s[1]]))
    }
    fn u16(&mut self) -> R<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn i32(&mut self) -> R<i32> {
        let s = self.take(4)?;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> R<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn f32(&mut self) -> R<f32> {
        let s = self.take(4)?;
        Ok(f32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// Null-terminated UTF-16LE string.
    fn wstr(&mut self) -> R<String> {
        let mut words = Vec::new();
        loop {
            if self.p + 2 > self.b.len() {
                // Mirrors MabiWorld: an unterminated string runs to the end.
                self.p = self.b.len();
                break;
            }
            let w = u16::from_le_bytes([self.b[self.p], self.b[self.p + 1]]);
            self.p += 2;
            if w == 0 {
                break;
            }
            words.push(w);
            if words.len() > 1 << 20 {
                return Err("string too long".into());
            }
        }
        Ok(String::from_utf16_lossy(&words))
    }
    /// X, Z (altitude), Y on disk -> [x, y, z].
    fn vec_xzy(&mut self) -> R<[f32; 3]> {
        let x = self.f32()?;
        let z = self.f32()?;
        let y = self.f32()?;
        Ok([x, y, z])
    }
    fn vec_xyz(&mut self) -> R<[f32; 3]> {
        Ok([self.f32()?, self.f32()?, self.f32()?])
    }
}

// ── region ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RegionInfo {
    pub version: i32,
    pub id: i32,
    pub group_id: i32,
    pub name: String,
    pub cell_size: i32,
    /// Bottom-left / top-right corners as [x, y, altitude].
    pub bottom_left: [f32; 3],
    pub top_right: [f32; 3],
    pub scene: String,
    /// Area file names without `.area`, in file order.
    pub area_names: Vec<String>,
}

pub fn parse_region(bytes: &[u8]) -> Result<RegionInfo, String> {
    let mut r = Reader::new(bytes);
    let version = r.i32()?;
    if !matches!(version, 100 | 102 | 103) {
        return Err(format!("unsupported region version {}", version));
    }
    let _length = r.i32()?;
    let id = r.i32()?;
    let group_id = r.i32()?;
    let name = r.wstr()?;
    let cell_size = r.i32()?;
    let _sight = r.u8()?;
    let area_count = r.i32()?;
    if !(0..=4096).contains(&area_count) {
        return Err(format!("bad area count {}", area_count));
    }
    let _unk1 = r.i32()?;
    let bottom_left = r.vec_xzy()?;
    let _bottom_right = r.vec_xzy()?;
    let top_right = r.vec_xzy()?;
    let _top_left = r.vec_xzy()?;
    if version > 100 {
        r.skip(12)?; // type, indoor type, unk2
    } else {
        let legacy = r.i32()?;
        if legacy >= 100 {
            r.skip(8)?; // indoor type, unk33
        }
    }
    let scene = r.wstr()?;
    r.skip(4 + 4 + 12 + 4 + 4 + 1 + 4 + 12)?; // colours, light dir, glow overlay
    let _camera = r.wstr()?;
    let _light = r.wstr()?;
    r.skip(12)?; // camera radius, unk7, reference radius
    let mut area_names = Vec::with_capacity(area_count as usize);
    for _ in 0..area_count {
        area_names.push(r.wstr()?);
    }
    Ok(RegionInfo { version, id, group_id, name, cell_size, bottom_left, top_right, scene, area_names })
}

// ── area ─────────────────────────────────────────────────────────────────────

/// Four corners (x0,y0,x1,y1,...) of an entity shape on the ground plane.
pub type ShapeQuad = [f32; 8];

#[derive(Debug, Clone, Serialize)]
pub struct MapProp {
    pub class_id: i32,
    /// Hex entity id (u64 does not survive JSON numbers).
    pub entity_id: String,
    pub name: String,
    pub pos: [f32; 3],
    pub scale: f32,
    pub rotation: f32,
    /// Axis-aligned bounds [x, y, altitude] (version > 200 only, else zero).
    pub bottom_left: [f32; 3],
    pub top_right: [f32; 3],
    pub title: String,
    pub state: String,
    pub shapes: Vec<ShapeQuad>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MapEvent {
    pub entity_id: String,
    pub name: String,
    pub pos: [f32; 3],
    pub event_type: i32,
    pub shapes: Vec<ShapeQuad>,
}

/// Terrain heights of one area as a vertex grid, row-major with X fastest; row 0 is
/// the area's bottom (smallest Y).
#[derive(Debug, Clone, Serialize)]
pub struct AreaTerrain {
    pub cols: u32,
    pub rows: u32,
    pub origin: [f32; 2],
    pub step: [f32; 2],
    pub heights: Vec<f32>,
    pub min: f32,
    pub max: f32,
    /// Area planes across / down and one flag per plane (row-major, X fastest):
    /// 1 when the plane is hidden.
    pub planes_x: u32,
    pub planes_y: u32,
    pub hidden: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AreaInfo {
    pub version: i16,
    pub id: u16,
    pub region_id: u16,
    pub server_name: String,
    pub name: String,
    pub bottom_left: [f32; 3],
    pub top_right: [f32; 3],
    pub props: Vec<MapProp>,
    pub events: Vec<MapEvent>,
    pub terrain: Option<AreaTerrain>,
}

const MAX_SHAPES_KEPT: usize = 16;

/// Corners of a rotated rectangle: direction vectors `[x1, x2, y1, y2]`, half lengths and
/// centre (MabiWorld `Shape.GetPoints`, without its rounding).
fn shape_points(dir: [f32; 4], len: [f32; 2], center: [f32; 2]) -> ShapeQuad {
    let [px, py] = center;
    let (a00, a01, a02, a03) = (dir[0] * len[0], dir[1] * len[0], dir[2] * len[1], dir[3] * len[1]);
    [
        px - a00 - a02, py - a01 - a03,
        px + a00 - a02, py + a01 - a03,
        px + a00 + a02, py + a01 + a03,
        px - a00 + a02, py - a01 + a03,
    ]
}

fn read_shapes(r: &mut Reader, count: u8, legacy: bool, out: &mut Vec<ShapeQuad>) -> R<()> {
    for _ in 0..count {
        if legacy {
            let _point_count = r.u8()?;
            let mut pts = [0f32; 10];
            for p in pts.iter_mut() {
                *p = r.f32()?;
            }
            r.skip(4 + 24)?; // type, position, bounds
            if out.len() < MAX_SHAPES_KEPT {
                out.push([pts[0], pts[1], pts[2], pts[3], pts[4], pts[5], pts[6], pts[7]]);
            }
        } else {
            let (dx1, dx2, dy1, dy2, lx, ly) = (r.f32()?, r.f32()?, r.f32()?, r.f32()?, r.f32()?, r.f32()?);
            let _ty = r.i32()?;
            let (px, py) = (r.f32()?, r.f32()?);
            r.skip(16)?; // bounding box
            if out.len() < MAX_SHAPES_KEPT {
                out.push(shape_points([dx1, dx2, dy1, dy2], [lx, ly], [px, py]));
            }
        }
    }
    Ok(())
}

fn read_params(r: &mut Reader) -> R<()> {
    let n = r.u8()?;
    for _ in 0..n {
        r.skip(1 + 4 + 4)?;
        r.wstr()?;
        r.wstr()?;
    }
    Ok(())
}

fn read_prop(r: &mut Reader, version: i16) -> R<MapProp> {
    let mut class_id = if version > 200 { r.i32()? } else { 0 };
    let entity_id = format!("{:016X}", r.u64()?);
    let name = r.wstr()?;
    let pos = r.vec_xyz()?;
    let shape_count = r.u8()?;
    let _shape_type = r.i32()?;
    let mut shapes = Vec::new();
    let mut kr165 = false;
    if version == 200 {
        read_shapes(r, shape_count, true, &mut shapes)?;
        let unk1 = r.u8()?;
        // KR165 v200 areas carry an extra (usually zero) byte before the id; see
        // MabiWorld Prop.ReadFrom.
        let peek = *r.b.get(r.p).ok_or("unexpected end of data")?;
        kr165 = peek == 0 || (unk1 == 0 && peek == 1);
        if kr165 {
            r.skip(1)?;
        }
        class_id = r.i32()?;
    } else {
        read_shapes(r, shape_count, false, &mut shapes)?;
        r.skip(2)?; // is collision, fixed altitude
    }
    let scale = r.f32()?;
    let rotation = r.f32()?;
    let (bottom_left, top_right) = if version > 200 { (r.vec_xzy()?, r.vec_xzy()?) } else { ([0.0; 3], [0.0; 3]) };
    r.skip(4 + 9 * 4)?; // colour override + 9 colours
    let title = if version > 200 || kr165 { r.wstr()? } else { String::new() };
    let state = r.wstr()?;
    read_params(r)?;
    Ok(MapProp { class_id, entity_id, name, pos, scale, rotation, bottom_left, top_right, title, state, shapes })
}

fn read_event(r: &mut Reader, version: i16) -> R<MapEvent> {
    let entity_id = format!("{:016X}", r.u64()?);
    let name = r.wstr()?;
    let pos = r.vec_xyz()?;
    let shape_count = r.u8()?;
    let _shape_type = r.i32()?;
    let mut shapes = Vec::new();
    read_shapes(r, shape_count, version == 200, &mut shapes)?;
    let event_type = r.i32()?;
    read_params(r)?;
    Ok(MapEvent { entity_id, name, pos, event_type, shapes })
}

struct RawPlane {
    size: usize,
    hidden: bool,
    flat: Option<f32>,
    heights: Vec<f32>,
}

fn read_area_plane(r: &mut Reader, area_version: i16) -> R<RawPlane> {
    let version: Option<u8> = if area_version == 200 { None } else { Some(r.u8()?) };
    let v = version.unwrap_or(0);
    if version.is_some() && v >= 240 {
        r.skip(4)?;
    }
    let size = r.u8()? as usize;
    r.skip(if version.is_some() && v >= 240 { 16 } else { 4 })?; // material slots
    let show_plane = r.u8()?;
    let _use_tiles = r.u8()?;
    r.skip(16)?; // material slot indexes
    let min_h = r.f32()?;
    let max_h = r.f32()?;
    if version.is_some() && (v == 1 || v == 241) {
        r.skip(8)?;
    }
    let mut count = size * size;
    if area_version == 200 && show_plane != 0 {
        count += 1;
    }
    let mut heights = Vec::with_capacity(count);
    for _ in 0..count {
        heights.push(r.f32()?);
        if version.is_some() {
            r.skip(8)?;
        }
        r.skip(4)?; // colour
    }
    heights.truncate(size * size);
    r.skip(4 * 32)?; // 4 squares x 16 x 2 bytes
    #[allow(clippy::float_cmp)]
    let flat = if min_h == max_h { Some(min_h) } else { None };
    Ok(RawPlane { size, hidden: show_plane == 1, flat, heights })
}

fn build_terrain(planes: &[RawPlane], px: usize, py: usize, bl: [f32; 3], tr: [f32; 3]) -> Option<AreaTerrain> {
    let size = planes.first()?.size;
    if size < 2 || px == 0 || py == 0 || planes.iter().any(|p| p.size != size) {
        return None;
    }
    let cols = px * (size - 1) + 1;
    let rows = py * (size - 1) + 1;
    let mut heights = vec![f32::NAN; cols * rows];
    let mut hidden = vec![0u8; px * py];
    for ix in 0..px {
        for iy in 0..py {
            let plane = &planes[ix * py + iy];
            hidden[iy * px + ix] = u8::from(plane.hidden);
            for vx in 0..size {
                for vy in 0..size {
                    let h = plane.flat.unwrap_or_else(|| plane.heights.get(vx * size + vy).copied().unwrap_or(0.0));
                    let gx = ix * (size - 1) + vx;
                    let gy = iy * (size - 1) + vy;
                    let cell = &mut heights[gy * cols + gx];
                    // Shared edges: keep the first visible plane's value.
                    if cell.is_nan() || !plane.hidden {
                        *cell = h;
                    }
                }
            }
        }
    }
    let (mut min, mut max) = (f32::INFINITY, f32::NEG_INFINITY);
    for h in heights.iter_mut() {
        if !h.is_finite() {
            *h = 0.0;
        }
        min = min.min(*h);
        max = max.max(*h);
    }
    let span = |a: f32, b: f32, n: usize| {
        let s = (b - a) / (n.max(2) - 1) as f32;
        if s.is_finite() && s > 0.0 { s } else { 200.0 }
    };
    Some(AreaTerrain {
        cols: cols as u32,
        rows: rows as u32,
        origin: [bl[0], bl[1]],
        step: [span(bl[0], tr[0], cols), span(bl[1], tr[1], rows)],
        heights,
        min,
        max,
        planes_x: px as u32,
        planes_y: py as u32,
        hidden,
    })
}

pub fn parse_area(bytes: &[u8]) -> Result<AreaInfo, String> {
    let mut r = Reader::new(bytes);
    let version = r.i16()?;
    if !(200..=210).contains(&version) {
        return Err(format!("unsupported area version {}", version));
    }
    let _unk8 = r.i16()?;
    let _length = r.i32()?;
    let id = r.u16()?;
    let region_id = r.u16()?;
    let server_name = r.wstr()?;
    let name = r.wstr()?;
    let plane_x = r.i32()?;
    let plane_y = r.i32()?;
    if !(0..=1024).contains(&plane_x) || !(0..=1024).contains(&plane_y) {
        return Err(format!("bad plane grid {}x{}", plane_x, plane_y));
    }
    r.skip(8)?; // unk1, unk2
    let event_count = r.i32()?;
    let _prop_count = r.i32()?;
    r.skip(4 + 4 + 4 + 4 + 4)?; // unk3..unk7
    let bottom_left = r.vec_xzy()?;
    let _bottom_right = r.vec_xzy()?;
    let top_right = r.vec_xzy()?;
    let _top_left = r.vec_xzy()?;
    if version == 203 {
        r.skip(4)?;
    }
    let _version2 = r.i32()?;
    let prop_count = r.i32()?;
    if !(0..=1_000_000).contains(&prop_count) || !(0..=1_000_000).contains(&event_count) {
        return Err(format!("bad entity counts {} / {}", prop_count, event_count));
    }
    let mut props = Vec::with_capacity(prop_count.min(65_536) as usize);
    for i in 0..prop_count {
        props.push(read_prop(&mut r, version).map_err(|e| format!("prop {}: {}", i, e))?);
    }
    let mut events = Vec::with_capacity(event_count.min(65_536) as usize);
    for i in 0..event_count {
        events.push(read_event(&mut r, version).map_err(|e| format!("event {}: {}", i, e))?);
    }
    let (px, py) = (plane_x as usize, plane_y as usize);
    let mut planes = Vec::with_capacity(px * py);
    let mut terrain_ok = true;
    for _ in 0..px * py {
        match read_area_plane(&mut r, version) {
            Ok(p) => planes.push(p),
            Err(_) => {
                // Props/events are still useful when the terrain block is unexpected.
                terrain_ok = false;
                break;
            }
        }
    }
    let terrain = if terrain_ok { build_terrain(&planes, px, py, bottom_left, top_right) } else { None };
    Ok(AreaInfo { version, id, region_id, server_name, name, bottom_left, top_right, props, events, terrain })
}

// ── .set ─────────────────────────────────────────────────────────────────────

/// Model file names referenced by a prop `.set` file, in order (usually the first one
/// is the prop's mesh).
pub fn parse_set_models(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() < 12 || &bytes[0..4] != b"set\0" {
        return None;
    }
    for version_len in [2usize, 4, 8] {
        let hs_off = 4 + version_len;
        let Some(hs) = bytes.get(hs_off..hs_off + 4).map(|s| i32::from_le_bytes([s[0], s[1], s[2], s[3]])) else { continue };
        if hs < (hs_off + 4) as i32 || hs as usize + 4 > bytes.len() {
            continue;
        }
        let mut r = Reader::new(bytes);
        r.p = hs as usize;
        let Ok(count) = r.i32() else { continue };
        if !(1..=4096).contains(&count) {
            continue;
        }
        let mut names = Vec::new();
        let mut ok = true;
        for _ in 0..count {
            let item = (|| -> R<String> {
                r.skip(4)?;
                let size = r.i32()?;
                let file = r.wstr()?;
                let _state = r.wstr()?;
                let sig = r.b.get(r.p..r.p + 3).ok_or("eof")?;
                if sig != b"pa!" && sig != b"pf!" {
                    return Err("bad item signature".into());
                }
                if size < 0 {
                    return Err("bad size".into());
                }
                r.skip(size as usize)?;
                Ok(file)
            })();
            match item {
                Ok(f) => {
                    if !f.is_empty() && !names.contains(&f) {
                        names.push(f);
                    }
                }
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok || !names.is_empty() {
            return Some(names);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct W(Vec<u8>);
    impl W {
        fn i16(&mut self, v: i16) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
        fn u16(&mut self, v: u16) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
        fn i32(&mut self, v: i32) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
        fn u64(&mut self, v: u64) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
        fn u8(&mut self, v: u8) -> &mut Self { self.0.push(v); self }
        fn f32(&mut self, v: f32) -> &mut Self { self.0.extend_from_slice(&v.to_le_bytes()); self }
        fn zeros(&mut self, n: usize) -> &mut Self { self.0.extend(std::iter::repeat(0).take(n)); self }
        fn ws(&mut self, s: &str) -> &mut Self {
            for u in s.encode_utf16() { self.0.extend_from_slice(&u.to_le_bytes()); }
            self.0.extend_from_slice(&[0, 0]);
            self
        }
        /// x, altitude, y on disk.
        fn xzy(&mut self, x: f32, y: f32, z: f32) -> &mut Self { self.f32(x).f32(z).f32(y) }
    }

    fn region_bytes(version: i32) -> Vec<u8> {
        let mut w = W::default();
        w.i32(version).i32(0).i32(1).i32(7).ws("Uladh_Main").i32(100).u8(5).i32(2).i32(0);
        w.xzy(0.0, 0.0, 0.0).xzy(6400.0, 0.0, 0.0).xzy(6400.0, 3200.0, 0.0).xzy(0.0, 3200.0, 0.0);
        if version > 100 { w.i32(0).i32(1).f32(0.0); } else { w.i32(0); }
        w.ws("scene").zeros(4 + 4 + 12 + 4 + 4 + 1 + 4 + 12).ws("cam").ws("light").zeros(12);
        w.ws("Uladh_Main_A").ws("Uladh_Main_B");
        if version >= 103 { w.ws(""); }
        w.0
    }

    #[test]
    fn parses_region_header_and_area_names() {
        for v in [100, 102, 103] {
            let r = parse_region(&region_bytes(v)).unwrap();
            assert_eq!(r.id, 1);
            assert_eq!(r.group_id, 7);
            assert_eq!(r.name, "Uladh_Main");
            assert_eq!(r.area_names, vec!["Uladh_Main_A", "Uladh_Main_B"]);
            assert_eq!(r.top_right, [6400.0, 3200.0, 0.0]);
        }
        assert!(parse_region(&[1, 2, 3]).is_err());
        let mut bad = region_bytes(103);
        bad[0] = 99;
        assert!(parse_region(&bad).is_err());
    }

    fn shape(w: &mut W, cx: f32, cy: f32, half: f32) {
        w.f32(1.0).f32(0.0).f32(0.0).f32(1.0).f32(half).f32(half).i32(0).f32(cx).f32(cy);
        w.f32(cx - half).f32(cy - half).f32(cx + half).f32(cy + half);
    }

    /// Version 201 area: 2x1 area planes of size 5, one prop with a shape, one event.
    fn area_bytes() -> Vec<u8> {
        let mut w = W::default();
        w.i16(201).i16(0).i32(0).u16(3).u16(1).ws("server").ws("Uladh_Main_A");
        w.i32(2).i32(1).i32(0).i32(0).i32(1).i32(1).zeros(20);
        w.xzy(0.0, 0.0, 0.0).xzy(1600.0, 0.0, 0.0).xzy(1600.0, 800.0, 0.0).xzy(0.0, 800.0, 0.0);
        w.i32(0).i32(1);
        // prop
        w.i32(45).u64(0x00A0_0001_0003_0001).ws("tree").f32(100.0).f32(200.0).f32(5.0).u8(1).i32(0);
        shape(&mut w, 100.0, 200.0, 50.0);
        w.u8(1).u8(0).f32(1.5).f32(0.25);
        w.xzy(50.0, 150.0, 0.0).xzy(150.0, 250.0, 300.0);
        w.zeros(40).ws("A Tree").ws("normal");
        w.u8(1).u8(1).i32(0).i32(0).ws("p").ws("<xml/>");
        // event
        w.u64(0x00B0_0001_0003_0001).ws("warp").f32(700.0).f32(400.0).f32(0.0).u8(1).i32(0);
        shape(&mut w, 700.0, 400.0, 100.0);
        w.i32(10).u8(0);
        // planes: version 2, size 5
        for plane in 0..2 {
            w.u8(2).u8(5).zeros(4).u8(0).u8(0).zeros(16).f32(0.0).f32(24.0);
            for i in 0..25 { w.f32((plane * 100 + i) as f32).zeros(8).zeros(4); }
            w.zeros(128);
        }
        w.zeros(65);
        w.0
    }

    #[test]
    fn parses_area_props_events_terrain() {
        let a = parse_area(&area_bytes()).unwrap();
        assert_eq!(a.name, "Uladh_Main_A");
        assert_eq!((a.id, a.region_id), (3, 1));
        assert_eq!(a.props.len(), 1);
        let p = &a.props[0];
        assert_eq!(p.class_id, 45);
        assert_eq!(p.entity_id, "00A0000100030001");
        assert_eq!(p.pos, [100.0, 200.0, 5.0]);
        assert_eq!((p.scale, p.rotation), (1.5, 0.25));
        assert_eq!(p.top_right, [150.0, 250.0, 300.0]);
        assert_eq!((p.title.as_str(), p.state.as_str()), ("A Tree", "normal"));
        assert_eq!(p.shapes[0][..2], [50.0, 150.0]);
        assert_eq!(a.events.len(), 1);
        assert_eq!(a.events[0].event_type, 10);
        let t = a.terrain.unwrap();
        assert_eq!((t.cols, t.rows), (9, 5));
        assert_eq!(t.step, [200.0, 200.0]);
        // Plane 0 vertex (vx=1, vy=0) is index 1*5+0 = 5 -> grid (1, 0).
        assert_eq!(t.heights[1], 5.0);
        // Plane 0 vertex (0, 1) -> index 1 -> grid row 1, col 0.
        assert_eq!(t.heights[9], 1.0);
        // Plane 1 starts at column 4 (shared edge keeps plane 1's later visible value).
        assert_eq!(t.heights[5], 105.0);
        assert_eq!(t.max, 124.0);
        assert_eq!(t.hidden, vec![0, 0]);
    }

    #[test]
    fn area_rejects_garbage_and_survives_truncated_terrain() {
        assert!(parse_area(b"not an area").is_err());
        let full = area_bytes();
        let cut = &full[..full.len() - 300];
        let a = parse_area(cut).unwrap();
        assert_eq!(a.props.len(), 1);
        assert!(a.terrain.is_none());
    }

    #[test]
    fn parses_set_model_names() {
        let mut w = W::default();
        w.0.extend_from_slice(b"set\0");
        w.u16(1).u16(0).i32(16).i32(0); // version (4 bytes), header size 16, padding
        w.i32(2);
        w.i32(0).i32(8).ws("prop_tree_01").ws("normal");
        w.0.extend_from_slice(b"pf!\0");
        w.zeros(4);
        w.i32(0).i32(4).ws("prop_tree_01_ani").ws("wind");
        w.0.extend_from_slice(b"pa!\0");
        assert_eq!(parse_set_models(&w.0).unwrap(), vec!["prop_tree_01", "prop_tree_01_ani"]);
        assert!(parse_set_models(b"nope").is_none());
    }
}
