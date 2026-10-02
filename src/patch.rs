// patch.rs - Differential Patching Module

use crate::{pack};
use anyhow::{Error};
use std::fs;
use std::path::{Path, PathBuf};
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
    // Private work folder under the system temp dir; only this folder is removed.
    let temp_patch_dir = unique_temp_dir("mabi_patch")?;
    let result = build_patch(base_path, mod_path, &temp_patch_dir, output_it, skey, iv);
    let _ = fs::remove_dir_all(&temp_patch_dir);
    result
}

/// Create a new, empty directory under the system temp dir with a unique name.
fn unique_temp_dir(prefix: &str) -> Result<PathBuf, Error> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    for attempt in 0..100u32 {
        let dir = std::env::temp_dir().join(format!("{}_{}_{}_{}", prefix, std::process::id(), nanos, attempt));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::msg("could not create a unique temp folder"))
}

fn build_patch(
    base_path: &Path,
    mod_path: &Path,
    temp_patch_dir: &Path,
    output_it: &str,
    skey: &str,
    iv: u32,
) -> Result<(), Error> {
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
        temp_patch_dir.to_str().ok_or_else(|| Error::msg("non-UTF8 temp path"))?,
        output_it,
        skey,
        vec![],
        false,
        iv,
        None,
        None
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_patch_uses_private_temp_dir() {
        let dir = unique_temp_dir("mabi_patch_test").unwrap();
        let (base, modified) = (dir.join("base"), dir.join("mod"));
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&modified).unwrap();
        fs::write(base.join("same.txt"), b"same").unwrap();
        fs::write(modified.join("same.txt"), b"same").unwrap();
        fs::write(modified.join("new.txt"), b"new").unwrap();
        // A folder with the old fixed name in the cwd must be left alone.
        let cwd_marker = Path::new("temp_patch_work");
        let pre_existing = cwd_marker.exists();

        let out = dir.join("patch.it");
        create_patch(base.to_str().unwrap(), modified.to_str().unwrap(), out.to_str().unwrap(), "salt", 0).unwrap();
        assert!(out.is_file());
        assert_eq!(cwd_marker.exists(), pre_existing);
        let _ = fs::remove_dir_all(&dir);
    }
}
