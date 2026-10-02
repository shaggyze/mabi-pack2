use std::path::PathBuf;

fn main() {
    cc::Build::new().file("src/snow2_fast.c").compile("c_snow2");
    println!("cargo:rerun-if-changed=src/snow2.h");
    println!("cargo:rerun-if-changed=src/snow2tab.h");
    println!("cargo:rerun-if-changed=src/snow2_fast.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=stdc++");
    }
    build_nxl3p_shim();
}

/// Build nxl3p-shim (the nexon_x64.dll stand-in) for the target and expose its path
/// as NXL3P_SHIM_DLL so launcher::launch can embed it with include_bytes!.
/// Set NXL3P_SHIM_PREBUILT=<path to dll> to skip the nested build.
fn build_nxl3p_shim() {
    println!("cargo:rerun-if-changed=nxl3p-shim/src/lib.rs");
    println!("cargo:rerun-if-changed=nxl3p-shim/Cargo.toml");
    println!("cargo:rerun-if-changed=nxl3p-shim/Cargo.lock");
    println!("cargo:rerun-if-changed=nxl3p-shim/.cargo/config.toml");
    println!("cargo:rerun-if-env-changed=NXL3P_SHIM_PREBUILT");
    if let Ok(pre) = std::env::var("NXL3P_SHIM_PREBUILT") {
        println!("cargo:rerun-if-changed={}", pre);
    }
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("nxl3p_shim.dll");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        // Not used off Windows; embed an empty placeholder.
        std::fs::write(&dest, b"").unwrap();
        println!("cargo:rustc-env=NXL3P_SHIM_DLL={}", dest.display());
        return;
    }

    if let Ok(pre) = std::env::var("NXL3P_SHIM_PREBUILT") {
        std::fs::copy(&pre, &dest).expect("copy NXL3P_SHIM_PREBUILT");
        println!("cargo:rustc-env=NXL3P_SHIM_DLL={}", dest.display());
        return;
    }

    let target = std::env::var("TARGET").unwrap();
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let shim_dir = manifest_dir.join("nxl3p-shim");
    let target_dir = out_dir.join("nxl3p-shim-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(&shim_dir)
        .args(["build", "--release", "--target", &target, "--target-dir"])
        .arg(&target_dir);
    // Don't leak the parent build's flags (e.g. -C lto) into the nested build.
    for var in [
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTFLAGS",
        "CARGO_MAKEFLAGS",
        "CARGO_PRIMARY_PACKAGE",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    let status = cmd.status().expect("failed to run cargo for nxl3p-shim");
    assert!(status.success(), "building nxl3p-shim failed");

    let built = target_dir.join(&target).join("release").join("nxl3p_shim.dll");
    std::fs::copy(&built, &dest).expect("nxl3p_shim.dll missing after build");
    println!("cargo:rustc-env=NXL3P_SHIM_DLL={}", dest.display());
}
