use std::io::{self, Cursor, Read};

fn read_le_i32(r: &mut impl Read) -> io::Result<i32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(i32::from_le_bytes(buf))
}

fn read_le_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_le_f32(r: &mut impl Read) -> io::Result<f32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(f32::from_le_bytes(buf))
}

fn read_bytes_exact(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_char_string(r: &mut impl Read, len: i32) -> io::Result<String> {
    if len <= 0 {
        return Ok(String::new());
    }
    let bytes = read_bytes_exact(r, len as usize)?;
    Ok(String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .to_string())
}

fn read_len_prefixed_string(r: &mut impl Read) -> io::Result<String> {
    let len = read_le_i32(r)?;
    read_char_string(r, len)
}

fn read_floats(r: &mut impl Read, count: usize) -> io::Result<Vec<f32>> {
    (0..count).map(|_| read_le_f32(r)).collect()
}

#[derive(Debug, Clone)]
pub struct Vertex {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub nx: f32,
    pub ny: f32,
    pub nz: f32,
    /// BGRA byte order (as stored in file)
    pub b: u8,
    pub g: u8,
    pub r: u8,
    pub a: u8,
    pub u: f32,
    pub v: f32,
}

#[derive(Debug, Clone)]
pub struct SkinEntry {
    pub vertex_index: i32,
    pub a: i32,
    pub scale: f32,
    pub b: i32,
}

#[derive(Debug, Clone)]
pub struct SubMesh {
    pub parts: String,
    pub mesh_name: String,
    pub parts2: String,
    /// LOD identifier: "e" = highest, "2", "3" = lower LODs
    pub stats: String,
    pub normal: String,
    pub color_map: String,
    pub texture_name: String,
    pub minor_matrix: [f32; 16],
    pub major_matrix: [f32; 16],
    pub what_matrix: [f32; 15],
    /// Triangle face index list (meshSort1)
    pub face_indices: Vec<u16>,
    /// Strip face index list (meshSort2)
    pub strip_indices: Vec<u16>,
    pub vertices: Vec<Vertex>,
    pub skins: Vec<SkinEntry>,
}

#[derive(Debug, Clone)]
pub struct MeshGroup {
    /// Parent mesh name (e.g. "backtool", "handtoolr")
    pub label: String,
    /// One SubMesh per LOD level, in file order (highest first)
    pub lods: Vec<SubMesh>,
}

#[derive(Debug, Clone)]
pub struct PmgFile {
    pub mesh_name: String,
    pub version: [u8; 2],
    pub groups: Vec<MeshGroup>,
}

/// Options for OBJ export.
#[derive(Debug, Clone)]
pub struct ObjExportOptions {
    /// Include BGRA vertex colors in `v x y z r g b` extended format.
    pub vertex_colors: bool,
    /// Apply full 4×4 MajorMatrix (rotation + scale + translation) vs. translation only.
    pub full_transform: bool,
    /// If Some(n), export only group n (0-based). If None, export all groups.
    pub group: Option<usize>,
}

impl Default for ObjExportOptions {
    fn default() -> Self {
        ObjExportOptions {
            vertex_colors: true,
            // The MajorMatrix rotation encodes skeleton attachment orientation;
            // for standalone model viewing only the translation is meaningful.
            full_transform: false,
            // Export only the first group (back-slot); handtoolr is the same
            // weapon at a different character bone and creates duplicates.
            group: Some(0),
        }
    }
}

fn strip_to_obj_tris(strip: &[u16]) -> Vec<u16> {
    let mut tris = Vec::new();
    for i in 0..strip.len().saturating_sub(2) {
        let (a, b, c) = (strip[i], strip[i + 1], strip[i + 2]);
        if a == b || b == c || a == c { continue; }
        if i % 2 == 0 { tris.extend_from_slice(&[a, b, c]); }
        else           { tris.extend_from_slice(&[b, a, c]); }
    }
    tris
}

impl PmgFile {
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty PMG file (stub entry)"));
        }
        let mut r = Cursor::new(data);
        parse_pmg(&mut r)
    }

    /// Export as OBJ with default options (full transform, vertex colors, all groups).
    pub fn to_obj(&self) -> String {
        self.to_obj_with(&ObjExportOptions::default())
    }

    /// Export as Wavefront OBJ with explicit options.
    ///
    /// The global origin is the MajorMatrix translation of the first non-empty
    /// sub-mesh; all vertex positions are expressed relative to it so the model
    /// is centred near the origin.
    ///
    /// When `full_transform` is true the complete 4×4 MajorMatrix is applied
    /// (row-major: position row = rows 0-2 × column vector, translation in
    /// column 3, i.e. indices [3],[7],[11]).  When false only the translation
    /// component is applied (same behaviour as the old code).
    ///
    /// When `vertex_colors` is true each `v` line carries `r g b` channels
    /// (0-1 float) derived from the BGRA byte stored per-vertex.  Most viewers
    /// (f3d, Blender, MeshLab) recognise this extension.
    pub fn to_obj_with(&self, opts: &ObjExportOptions) -> String {
        let mut out = String::new();
        out.push_str("# PMG export\n");

        // Collect the groups we want to export.
        let groups: Vec<&MeshGroup> = match opts.group {
            Some(idx) => self.groups.get(idx).into_iter().collect(),
            None       => self.groups.iter().collect(),
        };

        // Global origin: translation from the first non-empty sub-mesh's MajorMatrix.
        // We subtract this so the combined model sits near origin.
        let origin: [f32; 3] = groups.iter()
            .flat_map(|g| g.lods.iter())
            .find(|l| !l.vertices.is_empty())
            .map(|l| [l.major_matrix[3], l.major_matrix[7], l.major_matrix[11]])
            .unwrap_or([0.0; 3]);

        let mut vert_base = 1usize;
        for group in groups {
            for lod in &group.lods {
                if lod.vertices.is_empty() || (lod.face_indices.is_empty() && lod.strip_indices.is_empty()) {
                    continue;
                }

                let m = &lod.major_matrix; // row-major 4×4

                let obj_name = if lod.mesh_name.is_empty() {
                    group.label.clone()
                } else {
                    lod.mesh_name.clone()
                };
                out.push_str(&format!("o {}\n", obj_name));
                if !lod.texture_name.is_empty() {
                    out.push_str(&format!("usemtl {}\n", lod.texture_name));
                }

                for v in &lod.vertices {
                    let (px, py, pz) = if opts.full_transform {
                        // Full affine: p' = M × [x y z 1]^T (row-major = column 3 is translation)
                        (
                            m[0]*v.x + m[1]*v.y + m[2]*v.z  + m[3]  - origin[0],
                            m[4]*v.x + m[5]*v.y + m[6]*v.z  + m[7]  - origin[1],
                            m[8]*v.x + m[9]*v.y + m[10]*v.z + m[11] - origin[2],
                        )
                    } else {
                        (v.x + m[3] - origin[0], v.y + m[7] - origin[1], v.z + m[11] - origin[2])
                    };

                    if opts.vertex_colors {
                        // BGRA → r/g/b as 0-1 floats
                        let r = v.r as f32 / 255.0;
                        let g = v.g as f32 / 255.0;
                        let b = v.b as f32 / 255.0;
                        out.push_str(&format!("v {:.6} {:.6} {:.6} {:.6} {:.6} {:.6}\n", px, py, pz, r, g, b));
                    } else {
                        out.push_str(&format!("v {:.6} {:.6} {:.6}\n", px, py, pz));
                    }
                }

                // Transform normals by the 3×3 upper-left of MajorMatrix.
                for v in &lod.vertices {
                    let (nx, ny, nz) = if opts.full_transform {
                        (
                            m[0]*v.nx + m[1]*v.ny + m[2]*v.nz,
                            m[4]*v.nx + m[5]*v.ny + m[6]*v.nz,
                            m[8]*v.nx + m[9]*v.ny + m[10]*v.nz,
                        )
                    } else {
                        (v.nx, v.ny, v.nz)
                    };
                    out.push_str(&format!("vn {:.6} {:.6} {:.6}\n", nx, ny, nz));
                }

                for v in &lod.vertices {
                    out.push_str(&format!("vt {:.6} {:.6}\n", v.u, 1.0 - v.v));
                }

                // Use face_indices (triangle list) if available; otherwise convert strip_indices
                let tris_owned: Vec<u16>;
                let fi: &[u16] = if !lod.face_indices.is_empty() {
                    &lod.face_indices
                } else {
                    tris_owned = strip_to_obj_tris(&lod.strip_indices);
                    &tris_owned
                };
                for t in 0..(fi.len() / 3) {
                    let i0 = (fi[t * 3]     as usize) + vert_base;
                    let i1 = (fi[t * 3 + 1] as usize) + vert_base;
                    let i2 = (fi[t * 3 + 2] as usize) + vert_base;
                    out.push_str(&format!(
                        "f {0}/{0}/{0} {1}/{1}/{1} {2}/{2}/{2}\n",
                        i0, i1, i2
                    ));
                }

                vert_base += lod.vertices.len();
            }
        }
        out
    }
}

fn parse_pmg(r: &mut Cursor<&[u8]>) -> io::Result<PmgFile> {
    // --- Global PmgHead (142 bytes) ---
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic[..3] != b"pmg" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a PMG file"));
    }

    let mut version = [0u8; 2];
    r.read_exact(&mut version)?;
    // Non-fatal: known version is [2,1] but try parsing anything

    let head_length = read_le_i32(r)? as usize;

    let mut name_buf = [0u8; 32];
    r.read_exact(&mut name_buf)?;
    let mesh_name = String::from_utf8_lossy(&name_buf)
        .trim_end_matches('\0')
        .to_string();

    // unknow[96] + mesh_count[4] = 100 bytes to reach 142 total
    // 6(magic+ver) + 4(len) + 32(name) + 96(unknow) + 4(mesh_count) = 142
    read_bytes_exact(r, 100)?;

    // --- PmHead section (head_length - 142 bytes) ---
    let pmhead_section_len = head_length.saturating_sub(142);
    let pmhead_data = read_bytes_exact(r, pmhead_section_len)?;

    let groups = parse_pmhead_section(&pmhead_data)?;

    // --- PmObject blocks (until EOF) ---
    let mut all_submeshes: Vec<SubMesh> = Vec::new();
    loop {
        let mut mini = [0u8; 10];
        match r.read_exact(&mut mini) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        if &mini[..4] != b"pm!\0" {
            break;
        }

        let sub_version = [mini[4], mini[5]];
        let pm_length = i32::from_le_bytes([mini[6], mini[7], mini[8], mini[9]]) as usize;
        if pm_length < 10 {
            break;
        }

        let data_len = pm_length - 10;
        let data = read_bytes_exact(r, data_len)?;

        let sm = match sub_version {
            [2, 0] => parse_submesh_v20(&data),
            [1, 7] => parse_submesh_v17(&data),
            _ => {
                log::warn!("[PMG] Unknown PmObject sub-version [{},{}] — skipping block ({} bytes)", sub_version[0], sub_version[1], data_len);
                continue;
            }
        };
        match sm {
            Ok(s) => all_submeshes.push(s),
            Err(e) => log::warn!("[PMG] Failed to parse v{}.{} submesh: {}", sub_version[0], sub_version[1], e),
        }
    }

    // Pair sub-meshes back into groups using the PmHead label order.
    // The PmHead section tells us how many LODs per group; we consume
    // sub-meshes in file order to fill them.
    let groups = assign_submeshes_to_groups(groups, all_submeshes);

    Ok(PmgFile {
        mesh_name,
        version,
        groups,
    })
}

/// Parses the PmHead section into skeleton groups (label + lod_count each).
fn parse_pmhead_section(data: &[u8]) -> io::Result<Vec<(String, usize)>> {
    let mut r = Cursor::new(data);
    let mut groups = Vec::new();

    while (r.position() as usize) < data.len() {
        // 64-byte group label (1 byte per char)
        let label_bytes = match read_bytes_exact(&mut r, 64) {
            Ok(b) => b,
            Err(_) => break,
        };
        let label = String::from_utf8_lossy(&label_bytes)
            .trim_end_matches('\0')
            .to_string();

        let count = match read_le_i32(&mut r) {
            Ok(c) => c as usize,
            Err(_) => break,
        };

        // Skip count × 204-byte PmHead entries (we extract what we need
        // from the PmObject blocks instead)
        if read_bytes_exact(&mut r, count * 204).is_err() {
            break;
        }

        groups.push((label, count));
    }

    Ok(groups)
}

fn assign_submeshes_to_groups(
    skeletons: Vec<(String, usize)>,
    submeshes: Vec<SubMesh>,
) -> Vec<MeshGroup> {
    if skeletons.is_empty() {
        // No PmHead section found; wrap everything in one group so geometry isn't lost
        let label = submeshes.first().map(|s| s.parts.clone()).unwrap_or_default();
        return vec![MeshGroup { label, lods: submeshes }];
    }
    let mut it = submeshes.into_iter();
    skeletons
        .into_iter()
        .map(|(_, count)| {
            let lods: Vec<SubMesh> = (0..count).filter_map(|_| it.next()).collect();
            let label = lods.first().map(|s| s.parts.clone()).unwrap_or_default();
            MeshGroup { label, lods }
        })
        .collect()
}

/// Parses a PmObject data block for sub-mesh version 2.0.
fn parse_submesh_v20(data: &[u8]) -> io::Result<SubMesh> {
    let mut r = Cursor::new(data);

    let minor_raw = read_floats(&mut r, 16)?;
    let major_raw = read_floats(&mut r, 16)?;
    let mut minor_matrix = [0f32; 16];
    let mut major_matrix = [0f32; 16];
    minor_matrix.copy_from_slice(&minor_raw);
    major_matrix.copy_from_slice(&major_raw);

    let _part_no      = read_le_i32(&mut r)?;
    read_bytes_exact(&mut r, 8)?;  // empty8
    let _count        = read_le_i32(&mut r)?;
    read_bytes_exact(&mut r, 36)?; // empty36

    let face_vertex   = read_le_i32(&mut r)? as usize;
    let _face_count   = read_le_i32(&mut r)?;
    let strip_fv      = read_le_i32(&mut r)? as usize;
    let _strip_fc     = read_le_i32(&mut r)?;
    let mesh_count    = read_le_i32(&mut r)? as usize;
    let skin_count    = read_le_i32(&mut r)? as usize;

    read_bytes_exact(&mut r, 32)?; // empty32
    let _f            = read_le_i32(&mut r)?;
    let _face_size    = read_le_i32(&mut r)?;
    let _strip_size   = read_le_i32(&mut r)?;
    let _mesh_size    = read_le_i32(&mut r)?;
    let _skin_size    = read_le_i32(&mut r)?;
    read_bytes_exact(&mut r, 4)?;  // empty4

    let parts        = read_len_prefixed_string(&mut r)?;
    let mesh_name    = read_len_prefixed_string(&mut r)?;
    let parts2       = read_len_prefixed_string(&mut r)?;
    let stats        = read_len_prefixed_string(&mut r)?;
    let normal       = read_len_prefixed_string(&mut r)?;
    let color_map    = read_len_prefixed_string(&mut r)?;
    let texture_name = read_len_prefixed_string(&mut r)?;

    read_bytes_exact(&mut r, 4)?;  // unknow[4]

    let what_raw = read_floats(&mut r, 15)?;
    let mut what_matrix = [0f32; 15];
    what_matrix.copy_from_slice(&what_raw);

    let face_indices: Vec<u16>  = (0..face_vertex).map(|_| read_le_u16(&mut r)).collect::<io::Result<_>>()?;
    let strip_indices: Vec<u16> = (0..strip_fv).map(|_| read_le_u16(&mut r)).collect::<io::Result<_>>()?;

    let vertices = (0..mesh_count).map(|_| read_vertex(&mut r)).collect::<io::Result<_>>()?;
    let skins    = (0..skin_count).map(|_| read_skin(&mut r)).collect::<io::Result<_>>()?;

    Ok(SubMesh {
        parts,
        mesh_name,
        parts2,
        stats,
        normal,
        color_map,
        texture_name,
        minor_matrix,
        major_matrix,
        what_matrix,
        face_indices,
        strip_indices,
        vertices,
        skins,
    })
}

/// Parses a PmObject data block for sub-mesh version 1.7.
/// v1.7 uses fixed-width char arrays instead of length-prefixed strings.
fn parse_submesh_v17(data: &[u8]) -> io::Result<SubMesh> {
    let mut r = Cursor::new(data);

    let parts    = read_char_string(&mut r, 32)?;
    let mesh_name = read_char_string(&mut r, 128)?;
    let parts2   = read_char_string(&mut r, 32)?;
    let stats    = read_char_string(&mut r, 32)?;
    let normal   = read_char_string(&mut r, 32)?;
    let color_map = read_char_string(&mut r, 32)?;

    let minor_raw = read_floats(&mut r, 16)?;
    let major_raw = read_floats(&mut r, 16)?;
    let mut minor_matrix = [0f32; 16];
    let mut major_matrix = [0f32; 16];
    minor_matrix.copy_from_slice(&minor_raw);
    major_matrix.copy_from_slice(&major_raw);

    let _part_no     = read_le_i32(&mut r)?;
    read_bytes_exact(&mut r, 8)?;  // empty8
    let texture_name = read_char_string(&mut r, 32)?;
    let _count       = read_le_i32(&mut r)?;
    read_bytes_exact(&mut r, 36)?; // empty36

    let face_vertex  = read_le_i32(&mut r)? as usize;
    let _face_count  = read_le_i32(&mut r)?;
    let strip_fv     = read_le_i32(&mut r)? as usize;
    let _strip_fc    = read_le_i32(&mut r)?;
    let mesh_count   = read_le_i32(&mut r)? as usize;
    let skin_count   = read_le_i32(&mut r)? as usize;

    read_bytes_exact(&mut r, 32)?; // empty32
    let _f           = read_le_i32(&mut r)?;
    let _face_size   = read_le_i32(&mut r)?;
    let _strip_size  = read_le_i32(&mut r)?;
    let _mesh_size   = read_le_i32(&mut r)?;
    let _skin_size   = read_le_i32(&mut r)?;
    read_bytes_exact(&mut r, 8)?;  // empty4 + unknow[4]

    let what_raw = read_floats(&mut r, 15)?;
    let mut what_matrix = [0f32; 15];
    what_matrix.copy_from_slice(&what_raw);

    let face_indices: Vec<u16>  = (0..face_vertex).map(|_| read_le_u16(&mut r)).collect::<io::Result<_>>()?;
    let strip_indices: Vec<u16> = (0..strip_fv).map(|_| read_le_u16(&mut r)).collect::<io::Result<_>>()?;

    let vertices = (0..mesh_count).map(|_| read_vertex(&mut r)).collect::<io::Result<_>>()?;
    let skins    = (0..skin_count).map(|_| read_skin(&mut r)).collect::<io::Result<_>>()?;

    Ok(SubMesh {
        parts,
        mesh_name,
        parts2,
        stats,
        normal,
        color_map,
        texture_name,
        minor_matrix,
        major_matrix,
        what_matrix,
        face_indices,
        strip_indices,
        vertices,
        skins,
    })
}

/// 36-byte vertex: xyz(12) + normals(12) + BGRA(4) + uv(8)
fn read_vertex(r: &mut impl Read) -> io::Result<Vertex> {
    let x  = read_le_f32(r)?;
    let y  = read_le_f32(r)?;
    let z  = read_le_f32(r)?;
    let nx = read_le_f32(r)?;
    let ny = read_le_f32(r)?;
    let nz = read_le_f32(r)?;
    let mut rgba = [0u8; 4];
    r.read_exact(&mut rgba)?;
    let u  = read_le_f32(r)?;
    let v  = read_le_f32(r)?;
    Ok(Vertex { x, y, z, nx, ny, nz, b: rgba[0], g: rgba[1], r: rgba[2], a: rgba[3], u, v })
}

/// 16-byte skin entry: Num(4) + a(4) + Scale(4) + b(4)
fn read_skin(r: &mut impl Read) -> io::Result<SkinEntry> {
    let vertex_index = read_le_i32(r)?;
    let a            = read_le_i32(r)?;
    let scale        = read_le_f32(r)?;
    let b            = read_le_i32(r)?;
    Ok(SkinEntry { vertex_index, a, scale, b })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn parse_weapon_pmg() {
        let data = std::fs::read(
            r"C:\Users\Shaggy\Software\pmg\tmp_weapon_dkknighttwohandsword.pmg",
        )
        .unwrap();
        let pmg = PmgFile::parse(&data).unwrap();
        println!("mesh_name: {}", pmg.mesh_name);
        for (i, g) in pmg.groups.iter().enumerate() {
            println!("group[{}]: {} ({} LODs)", i, g.label, g.lods.len());
            for (j, lod) in g.lods.iter().enumerate() {
                println!(
                    "  lod[{}] stats='{}' verts={} faces={} tex='{}'",
                    j,
                    lod.stats,
                    lod.vertices.len(),
                    lod.face_indices.len() / 3,
                    lod.texture_name,
                );
            }
        }
        assert_eq!(pmg.groups.len(), 2);
        let bt = &pmg.groups[0];
        assert_eq!(bt.label, "backtool");
        assert_eq!(bt.lods.len(), 3);
        // First LOD in file is the simplified mesh (27 verts); the full-detail has 143
        let max_verts = bt.lods.iter().map(|l| l.vertices.len()).max().unwrap();
        assert_eq!(max_verts, 143);
        // OBJ export includes all components (blade + handle)
        let obj = pmg.to_obj();
        assert!(obj.contains("backtool"));
        assert!(obj.contains("item_arms01_m"));
        assert!(obj.contains("weapon_twohandsword_l")); // blade texture
    }
}
