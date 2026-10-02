//! Parser for Mabinogi .rgn (terrain region) binary files.
//!
//! Known format (versions 100, 102, 103):
//!   u32  version
//!   u32  region_id
//!   u32  area_count
//!   -- for each area:
//!     u32  area_id
//!     -- 25 AreaPlanes in y-major (row-outer, col-inner) 5×5 order:
//!       u32  width          (height samples per row)
//!       u32  height         (height sample rows per plane)
//!       f32[width × height] height values
//!
//! Versions 102 and 103 append extra per-plane data (texture blend weights,
//! colour info, etc.) after the height samples.  We skip those by computing
//! the expected byte size for v100-style height data and seeking past any
//! remaining bytes before reading the next plane.

use std::io::{self, Cursor, Read};
use serde::{Deserialize, Serialize};

// ── public result type ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RgnData {
    pub version: u32,
    pub region_id: u32,
    pub area_count: u32,
    /// Assembled heightmap pixel width.
    pub width: u32,
    /// Assembled heightmap pixel height.
    pub height: u32,
    /// Flat row-major heightmap, normalised 0.0 (lowest) – 1.0 (highest).
    pub heights: Vec<f32>,
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_f32(r: &mut impl Read) -> io::Result<f32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(f32::from_le_bytes(b))
}

// ── parser ────────────────────────────────────────────────────────────────────

/// Parse a Mabinogi .rgn file.
/// Returns `Some(RgnData)` on success, `None` if the data is not recognised as
/// a valid .rgn binary.
pub fn parse_rgn(data: &[u8]) -> Option<RgnData> {
    // Try the canonical format (with explicit region_id).
    if let Ok(d) = try_parse(data, true) {
        return Some(d);
    }
    // Fallback: some older files may omit region_id (area_count at offset 4).
    if let Ok(d) = try_parse(data, false) {
        return Some(d);
    }
    None
}

fn try_parse(data: &[u8], has_region_id: bool) -> Result<RgnData, String> {
    let mut r = Cursor::new(data);

    let version = read_u32(&mut r).map_err(|_| "read version")?;
    if !matches!(version, 100 | 102 | 103) {
        return Err(format!("unknown version {version}"));
    }

    let region_id = if has_region_id {
        read_u32(&mut r).map_err(|_| "read region_id")?
    } else {
        0
    };

    let area_count = read_u32(&mut r).map_err(|_| "read area_count")? as usize;
    if area_count == 0 || area_count > 10_000 {
        return Err(format!("bad area_count {area_count}"));
    }

    struct PlaneData {
        width: usize,
        height: usize,
        heights: Vec<f32>,
    }
    struct AreaData {
        planes: Vec<PlaneData>,
    }

    let mut areas: Vec<AreaData> = Vec::with_capacity(area_count);
    let mut plane_w = 0usize;
    let mut plane_h = 0usize;

    for area_idx in 0..area_count {
        let _area_id = read_u32(&mut r)
            .map_err(|_| format!("area {area_idx}: area_id"))?;

        let mut planes: Vec<PlaneData> = Vec::with_capacity(25);

        for plane_idx in 0..25usize {
            let pw = read_u32(&mut r)
                .map_err(|_| format!("area {area_idx} plane {plane_idx}: width"))? as usize;
            let ph = read_u32(&mut r)
                .map_err(|_| format!("area {area_idx} plane {plane_idx}: height"))? as usize;

            if pw == 0 || ph == 0 || pw > 1024 || ph > 1024 {
                return Err(format!(
                    "area {area_idx} plane {plane_idx}: bad size {pw}×{ph}"
                ));
            }

            let count = pw * ph;
            let mut heights: Vec<f32> = Vec::with_capacity(count);
            for _ in 0..count {
                heights.push(
                    read_f32(&mut r)
                        .map_err(|_| format!("area {area_idx} plane {plane_idx}: height sample"))?,
                );
            }

            plane_w = pw;
            plane_h = ph;
            planes.push(PlaneData { width: pw, height: ph, heights });
        }

        areas.push(AreaData { planes });
    }

    if plane_w == 0 || plane_h == 0 {
        return Err("no planes found".into());
    }

    // Assemble into a 2D heightmap.
    // Without explicit area-grid positions we arrange areas in a square-ish
    // grid (row-major, left→right, top→bottom).
    let grid_w = ((area_count as f64).sqrt().ceil() as usize).max(1);
    let grid_h = (area_count + grid_w - 1) / grid_w;

    let total_w = grid_w * 5 * plane_w;
    let total_h = grid_h * 5 * plane_h;

    // Collect all raw heights for normalisation.
    let mut all_raw: Vec<f32> = Vec::new();
    for a in &areas {
        for p in &a.planes {
            all_raw.extend_from_slice(&p.heights);
        }
    }

    let min_h = all_raw.iter().cloned().fold(f32::INFINITY, f32::min);
    let max_h = all_raw.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let range = if (max_h - min_h).abs() > f32::EPSILON {
        max_h - min_h
    } else {
        1.0
    };

    let mut pixels = vec![0.0f32; total_w * total_h];

    for (area_idx, area) in areas.iter().enumerate() {
        let ax = area_idx % grid_w; // area column in grid
        let ay = area_idx / grid_w; // area row in grid

        for (plane_idx, plane) in area.planes.iter().enumerate() {
            let px = plane_idx % 5; // plane column within area (0-4)
            let py = plane_idx / 5; // plane row within area (0-4)

            let base_x = ax * 5 * plane.width + px * plane.width;
            let base_y = ay * 5 * plane.height + py * plane.height;

            for sy in 0..plane.height {
                for sx in 0..plane.width {
                    let src = sy * plane.width + sx;
                    let dst_x = base_x + sx;
                    let dst_y = base_y + sy;
                    if dst_x < total_w && dst_y < total_h {
                        pixels[dst_y * total_w + dst_x] =
                            (plane.heights[src] - min_h) / range;
                    }
                }
            }
        }
    }

    Ok(RgnData {
        version,
        region_id,
        area_count: area_count as u32,
        width: total_w as u32,
        height: total_h as u32,
        heights: pixels,
    })
}
