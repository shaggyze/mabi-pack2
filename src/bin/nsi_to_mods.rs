/// nsi_to_mods — convert uotiara.nsi into a set of .mod files.
///
/// Usage:
///   nsi_to_mods --nsi <path/to/uotiara.nsi> --out <output_dir>
///
/// Each Section in the NSI becomes one .mod file under:
///   <output_dir>/<group>/<sanitized_name>.mod
///
/// Source paths in the .mod files are relative from the output file back
/// to the NSI directory (where "Tiara's Moonshine Mod/..." lives).
use std::path::{Path, PathBuf};

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '_' })
        .collect::<String>()
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// Compute a relative path from `from_dir` to `to_path`.
fn rel_path(from_dir: &Path, to_path: &Path) -> String {
    // Build "../.." prefix from from_dir depth relative to a common ancestor
    let from = from_dir.canonicalize().unwrap_or_else(|_| from_dir.to_path_buf());
    let to   = to_path.canonicalize().unwrap_or_else(|_| to_path.to_path_buf());

    // Count how many components from_dir has beyond the common prefix
    let from_parts: Vec<_> = from.components().collect();
    let to_parts:   Vec<_> = to.components().collect();
    let common = from_parts.iter().zip(to_parts.iter()).take_while(|(a, b)| a == b).count();
    let up = from_parts.len() - common;
    let down: Vec<_> = to_parts[common..].iter().map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
    let mut parts: Vec<String> = (0..up).map(|_| "..".to_string()).collect();
    parts.extend(down);
    parts.join("/")
}

/// Human-readable category labels for the website.
fn category_label(raw: &str) -> &'static str {
    match raw {
        "db"            => "Database Tweaks",
        "code"          => "Code / Text",
        "xml"           => "UI & XML",
        "gfx"           => "Graphics & FX",
        "material"      => "Materials & Textures",
        "sound"         => "Sound Removals",
        "world"         => "World / Minimap",
        "locale"        => "Locale / Language",
        "layout2"       => "UI Layout",
        "skill"         => "Skills",
        "commerce"      => "Commerce",
        "petinfo"       => "Pet Info",
        "cutscene"      => "Cutscene Removals",
        "c2"            => "Cutscenes — Iria",
        "c3"            => "Cutscenes — G3",
        "c4"            => "Cutscenes — G4",
        "drama"         => "Saga 1 Cutscenes",
        "drama2"        => "Saga 2 Cutscenes",
        "fonts"         => "Font Packs",
        "optional_mods" => "Optional / Readme",
        "risky_mods_add"=> "Risky Mods",
        _               => "Other",
    }
}

fn emit_ts(nsi_path: &str, out_path: &str) -> anyhow::Result<()> {
    let mods = mabi_pack2::api::parse_uotiara_nsi(nsi_path)?;

    let mut ts = String::from(
        "// Auto-generated from uotiara.nsi — do not edit manually.\n\
         // Run: nsi_to_mods --nsi uotiara.nsi --ts src/data/mods.ts\n\n\
         export interface ModDef {\n  id: number\n  name: string\n  category: string\n  files: number\n  hasDelete: boolean\n}\n\n\
         export const ALL_MODS: ModDef[] = [\n"
    );

    for m in &mods {
        let id    = m["id"].as_u64().unwrap_or(0);
        let name  = m["name"].as_str().unwrap_or("").replace('"', "\\\"");
        let group = m["group"].as_str().unwrap_or("");
        let subdir = group.split('/').last().unwrap_or("misc");
        let cat_label = category_label(subdir);
        let files_arr = m["files"].as_array();
        let file_count = files_arr.map(|f| f.len()).unwrap_or(0);
        let has_delete = files_arr.map(|f| f.iter().any(|e| e["action"].as_str() == Some("delete"))).unwrap_or(false);

        ts.push_str(&format!(
            "  {{ id: {id}, name: \"{name}\", category: \"{cat}\", files: {fc}, hasDelete: {hd} }},\n",
            id = id, name = name, cat = cat_label, fc = file_count, hd = has_delete
        ));
    }

    ts.push_str("];\n\n");

    // Unique sorted categories
    let mut cats: Vec<String> = mods.iter()
        .map(|m| {
            let g = m["group"].as_str().unwrap_or("");
            let s = g.split('/').last().unwrap_or("misc");
            category_label(s).to_string()
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    cats.sort();

    ts.push_str("export const MOD_CATEGORIES = [\n");
    for c in &cats {
        ts.push_str(&format!("  \"{}\",\n", c));
    }
    ts.push_str("] as const;\n\n");
    ts.push_str("export type ModCategory = typeof MOD_CATEGORIES[number];\n");

    std::fs::write(out_path, &ts)?;
    println!("Wrote {} mods to {}", mods.len(), out_path);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut nsi_path  = String::new();
    let mut out_dir   = String::new();
    let mut ts_out    = String::new(); // --ts <file>: emit mods.ts catalog instead
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--nsi" => { i += 1; nsi_path = args[i].clone(); }
            "--out" => { i += 1; out_dir  = args[i].clone(); }
            "--ts"  => { i += 1; ts_out   = args[i].clone(); }
            _ => {}
        }
        i += 1;
    }
    if nsi_path.is_empty() {
        eprintln!("Usage: nsi_to_mods --nsi <uotiara.nsi> [--out <dir>] [--ts <mods.ts>]");
        std::process::exit(1);
    }

    // --ts mode: emit TypeScript catalog and exit
    if !ts_out.is_empty() {
        return emit_ts(&nsi_path, &ts_out);
    }

    if out_dir.is_empty() {
        eprintln!("Usage: nsi_to_mods --nsi <uotiara.nsi> --out <dir>");
        std::process::exit(1);
    }

    let nsi_abs = PathBuf::from(&nsi_path).canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&nsi_path));
    let nsi_dir = nsi_abs.parent().expect("nsi has no parent");

    let mods = mabi_pack2::api::parse_uotiara_nsi(&nsi_path)?;
    let out_root = PathBuf::from(&out_dir);

    let mut written = 0usize;
    let mut skipped = 0usize;

    for m in &mods {
        let id   = m["id"].as_u64().unwrap_or(0) as u32;
        let name = m["name"].as_str().unwrap_or("unknown").to_string();
        let group_raw = m["group"].as_str().unwrap_or("misc");
        // NSI group path e.g. "Data Mods/db" → use last component as subdir
        let subdir = group_raw.split('/').last().map(sanitize).unwrap_or_else(|| "misc".into());
        let file_name = format!("MOD{:04}_{}.mod", id, sanitize(&name));

        let mod_dir = out_root.join(&subdir);
        std::fs::create_dir_all(&mod_dir)?;
        let mod_path = mod_dir.join(&file_name);

        let files_arr = match m["files"].as_array() {
            Some(f) if !f.is_empty() => f,
            _ => { skipped += 1; continue; }
        };

        let mut toml = format!(
            "# mabi-patcher .mod — auto-generated from uotiara.nsi\n\
             # MOD{id}: {name}\n\n\
             [meta]\n\
             name        = \"{name}\"\n\
             version     = \"1.0\"\n\
             author      = \"ShaggyZE\"\n\
             description = \"{name} (uotiara mod)\"\n\
             game        = \"NA\"\n\
             tags        = [\"{subdir}\"]\n\n\
             [pack]\n\
             output      = \"uotiara_00001.it\"\n\
             pack_key    = \"}})wWb4?-sVGHNoPKpc\"\n\
             wrap_data   = true\n\
             pack_version = 2\n\n",
            id = id, name = name, subdir = subdir
        );

        for f in files_arr {
            let action = f["action"].as_str().unwrap_or("replace");
            let dest   = match f["dest"].as_str() { Some(d) => d, None => continue };

            if action == "delete" {
                toml.push_str(&format!(
                    "[[files]]\narchive_path = \"data/{dest}\"\naction       = \"delete\"\n\n",
                    dest = dest
                ));
            } else {
                let src_rel = match f["src"].as_str() { Some(s) => s, None => continue };
                // src_rel is relative to nsi_dir, e.g. "Tiara's Moonshine Mod/data/db/foo.xml"
                let abs_src = nsi_dir.join(src_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
                let rel_from_mod = rel_path(&mod_dir, &abs_src);
                toml.push_str(&format!(
                    "[[files]]\narchive_path = \"data/{dest}\"\nsource       = \"{src}\"\naction       = \"replace\"\n\n",
                    dest = dest,
                    src  = rel_from_mod.replace('\\', "/"),
                ));
            }
        }

        std::fs::write(&mod_path, &toml)?;
        written += 1;
        println!("  wrote {}/{}", subdir, file_name);
    }

    println!("\n{} .mod files written, {} skipped (no data files)", written, skipped);
    Ok(())
}
