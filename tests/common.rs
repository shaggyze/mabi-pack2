//! Shared helpers for mabi-pack2 integration tests.
//! This file is included as `mod common;` from each integration test crate.
//! It is also compiled by Cargo as its own (empty) test target — dead_code
//! warnings are suppressed here to keep that build clean.

#![allow(dead_code)]

pub fn temp_dir_for_test(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("mabi_test_{}", name))
}

pub fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn test_corpus_file(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("MABI_TEST_CORPUS").map(|root| std::path::PathBuf::from(root).join(name))
}
