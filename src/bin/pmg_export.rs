use mabi_pack2::pmg::{ObjExportOptions, PmgFile};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut input = r"C:\Users\Shaggy\Software\pmg\tmp_weapon_dkknighttwohandsword.pmg".to_string();
    let mut output = r"C:\Users\Shaggy\Software\pmg\output.obj".to_string();
    let mut opts = ObjExportOptions::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--group" => {
                i += 1;
                opts.group = args.get(i).and_then(|s| s.parse().ok());
            }
            "--no-colors"    => opts.vertex_colors = false,
            "--no-transform" => opts.full_transform = false,
            s if !s.starts_with("--") && input == r"C:\Users\Shaggy\Software\pmg\tmp_weapon_dkknighttwohandsword.pmg" => {
                input = s.to_string();
            }
            s if !s.starts_with("--") => {
                output = s.to_string();
            }
            _ => {}
        }
        i += 1;
    }

    let data = std::fs::read(&input).expect("failed to read PMG");
    let pmg = PmgFile::parse(&data).expect("failed to parse PMG");

    println!("mesh: {}", pmg.mesh_name);
    for (gi, g) in pmg.groups.iter().enumerate() {
        println!("group[{}] '{}' — {} sub-meshes", gi, g.label, g.lods.len());
        for (li, lod) in g.lods.iter().enumerate() {
            let total_faces = lod.face_indices.len() / 3;
            println!(
                "  lod[{}] mesh='{}' parts2='{}' stats='{}' normal='{}' colormap='{}' tex='{}' \
                 verts={} faces={} strips={} skins={}",
                li,
                lod.mesh_name,
                lod.parts2,
                lod.stats,
                lod.normal,
                lod.color_map,
                lod.texture_name,
                lod.vertices.len(),
                total_faces,
                lod.strip_indices.len(),
                lod.skins.len(),
            );
            // Sample major matrix translation
            let m = &lod.major_matrix;
            println!(
                "         major_matrix translation = ({:.3}, {:.3}, {:.3})",
                m[3], m[7], m[11]
            );
        }
    }

    let obj = pmg.to_obj_with(&opts);
    std::fs::write(&output, &obj).expect("failed to write OBJ");
    println!(
        "Wrote {} bytes → {} [colors={} full_transform={} group={:?}]",
        obj.len(), output, opts.vertex_colors, opts.full_transform, opts.group
    );
}
