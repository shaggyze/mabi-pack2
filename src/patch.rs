// patch.rs - Differential Patching Module

use crate::{pack};
use anyhow::{Error};
use std::fs;
use std::path::{Path};
use rayon::prelude::*;
use md5;

fn get_file_md5(path: &Path) -> Result<String, Error> {
    let data = fs::read(path)?;
    let digest = md5::compute(data);
    Ok(format!("{:x}", digest))
}

pub fn create_patch(
    base_dir: &str,
    modified_dir: &str,
    output_it: &str,
    skey: &str,
    iv: u32,
) -> Result<(), Error> {
    let base_path = Path::new(base_dir);
    let mod_path = Path::new(modified_dir);
    let temp_patch_dir = Path::new("temp_patch_work");
    
    if temp_patch_dir.exists() {
        fs::remove_dir_all(temp_patch_dir)?;
    }
    fs::create_dir_all(temp_patch_dir)?;

    // Collect all files in modified_dir
    let mod_files: Vec<_> = walkdir::WalkDir::new(mod_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    let patch_files: Vec<_> = mod_files.par_iter().filter_map(|entry| {
        let p = entry.path();
        let rel = p.strip_prefix(mod_path).unwrap();
        let b_p = base_path.join(rel);

        let is_different = if !b_p.exists() {
            true
        } else {
            let mod_md5 = get_file_md5(p).unwrap_or_default();
            let base_md5 = get_file_md5(&b_p).unwrap_or_default();
            mod_md5 != base_md5
        };

        if is_different {
            Some((p.to_path_buf(), rel.to_path_buf()))
        } else {
            None
        }
    }).collect();

    for (src, rel) in &patch_files {
        let dst = temp_patch_dir.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    }

    if patch_files.is_empty() {
        return Err(Error::msg("No differences found between folders."));
    }

    pack::run_pack(
        temp_patch_dir.to_str().unwrap(),
        output_it,
        skey,
        vec![],
        false,
        iv,
        None,
        None
    )?;

    fs::remove_dir_all(temp_patch_dir)?;
    Ok(())
}
