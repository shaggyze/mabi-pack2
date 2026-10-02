//! Integration tests for the REST API layer (src/api.rs).
//!
//! Fast (no real archives, no network):
//!   cargo test --test api_tests
//!
//! Slow (need .it/.pack files under .gemini/testing):
//!   cargo test --test api_tests -- --ignored
//!
//! Each test binds its own port to avoid collisions between tests running
//! in parallel in the same binary.

mod common;

use mabi_pack2::api;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const UOTIARA: &str =
    r"C:\Users\Shaggy\Documents\GitHub\mabi-pack2\.gemini\testing\uotiara_00001.it";
const KNOWN_SALT: &str = "})wWb4?-sVGHNoPKpc";

/// Start the API server on loopback at `port` and wait until it accepts
/// connections (bind happens on a background thread, so this avoids a race
/// between spawn() returning and the server actually listening).
fn start_server(port: u16) -> Arc<AtomicBool> {
    let stop = api::spawn(port);
    let client = reqwest::blocking::Client::new();
    let url = format!("http://127.0.0.1:{}/api/v1/status", port);
    for _ in 0..50 {
        if client.get(&url).send().is_ok() {
            return stop;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("API server on port {} did not start within 5s", port);
}

fn stop_server(stop: Arc<AtomicBool>) {
    stop.store(true, Ordering::Relaxed);
}

// --------------------------------------------------------------------------
// Fast tests
// --------------------------------------------------------------------------

#[test]
fn test_status_endpoint() {
    let stop = start_server(17401);
    let resp: serde_json::Value = reqwest::blocking::get("http://127.0.0.1:17401/api/v1/status")
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(resp["success"], true);
    assert_eq!(resp["data"]["app"], "mabi-patcher");
    assert_eq!(resp["data"]["api"], "v1");
    stop_server(stop);
}

#[test]
fn test_mod_template_endpoint() {
    let stop = start_server(17402);
    let resp: serde_json::Value = reqwest::blocking::get("http://127.0.0.1:17402/api/v1/mod-template")
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(resp["success"], true);
    let template = resp["data"]["template"].as_str().expect("template should be a string");
    assert!(template.contains("[meta]"), "template should contain a [meta] section");
    stop_server(stop);
}

#[test]
fn test_mods_list_endpoint_returns_ok_even_when_dir_missing() {
    let stop = start_server(17403);
    let resp: serde_json::Value = reqwest::blocking::get("http://127.0.0.1:17403/api/v1/mods")
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(resp["success"], true);
    assert!(resp["data"]["mods"].is_array());
    stop_server(stop);
}

#[test]
fn test_mod_file_read_returns_raw_toml_text() {
    let stop = start_server(17416);
    let path = common::temp_dir_for_test("api_mod_file_read.mod");
    std::fs::write(&path, "[meta]\nname = \"test\"\nversion = \"1.0.0\"\n").unwrap();

    let resp: serde_json::Value = reqwest::blocking::get(format!(
        "http://127.0.0.1:17416/api/v1/mod-file?path={}",
        urlencoding_encode(&path.to_string_lossy())
    ))
    .expect("request failed")
    .json()
    .expect("invalid JSON");
    assert_eq!(resp["success"], true, "{:?}", resp);
    let content = resp["data"]["content"].as_str().unwrap_or("");
    assert!(content.contains("name = \"test\""), "expected raw TOML text, got: {}", content);

    let _ = std::fs::remove_file(&path);
    stop_server(stop);
}

/// Minimal percent-encoding for query params in tests (avoids pulling in a
/// urlencoding crate just for one test).
fn urlencoding_encode(s: &str) -> String {
    s.chars().map(|c| {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            c.to_string()
        } else {
            format!("%{:02X}", c as u32)
        }
    }).collect()
}

#[test]
fn test_unknown_route_returns_404() {
    let stop = start_server(17404);
    let resp = reqwest::blocking::get("http://127.0.0.1:17404/api/v1/does-not-exist")
        .expect("request failed");
    assert_eq!(resp.status(), 404);
    stop_server(stop);
}

#[test]
fn test_cors_preflight_options() {
    let stop = start_server(17405);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .request(reqwest::Method::OPTIONS, "http://127.0.0.1:17405/api/v1/status")
        .send()
        .expect("request failed");
    assert_eq!(resp.status(), 204);
    assert!(resp.headers().get("access-control-allow-origin").is_some());
    stop_server(stop);
}

#[test]
fn test_extract_missing_archive_field_returns_400() {
    let stop = start_server(17406);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("http://127.0.0.1:17406/api/v1/extract")
        .json(&serde_json::json!({ "output": "C:\\nowhere" }))
        .send()
        .expect("request failed");
    assert_eq!(resp.status(), 400);
    stop_server(stop);
}

#[test]
fn test_origin_check_blocks_cross_origin_and_allows_same_origin() {
    let stop = start_server(17412);
    let client = reqwest::blocking::Client::new();
    let url = "http://127.0.0.1:17412/api/v1/status";

    // Cross-origin (e.g. a malicious webpage's JS calling this over the
    // user's own browser on localhost) is rejected, independent of any token.
    let cross = client.get(url).header("Origin", "http://evil.example.com").send().unwrap();
    assert_eq!(cross.status(), 403);

    // Same-origin (Origin matches this request's own Host header) is allowed.
    let same = client.get(url).header("Origin", "http://127.0.0.1:17412").send().unwrap();
    assert_eq!(same.status(), 200);

    // No Origin header at all (curl, reqwest, the MCP client — non-browser
    // clients don't send one) is allowed.
    let none = client.get(url).send().unwrap();
    assert_eq!(none.status(), 200);

    stop_server(stop);
}

// --------------------------------------------------------------------------
// Auth guard tests (non-loopback bind)
// --------------------------------------------------------------------------

/// `MABI_API_TOKEN` is a process-wide env var, so both auth scenarios (no
/// token set / token set) must run sequentially in one test — otherwise they
/// race each other when cargo runs tests in parallel threads.
#[test]
fn test_auth_guard_scenarios() {
    fn wait_up(client: &reqwest::blocking::Client, url: &str) -> bool {
        for _ in 0..50 {
            if client.get(url).send().is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    let client = reqwest::blocking::Client::new();

    // Scenario 1: non-loopback bind, no token set — must refuse to serve.
    std::env::remove_var("MABI_API_TOKEN");
    let stop1 = Arc::new(AtomicBool::new(false));
    let stop1b = Arc::clone(&stop1);
    std::thread::spawn(move || { let _ = api::run_server("0.0.0.0", 17407, stop1b); });
    let url1 = "http://127.0.0.1:17407/api/v1/status";
    assert!(wait_up(&client, url1), "server did not start");
    let resp = client.get(url1).send().unwrap();
    assert_eq!(resp.status(), 503, "should refuse to serve without MABI_API_TOKEN set");
    stop1.store(true, Ordering::Relaxed);

    // Scenario 2: non-loopback bind, token set — wrong token rejected, right token accepted.
    std::env::set_var("MABI_API_TOKEN", "test-secret-token");
    let stop2 = Arc::new(AtomicBool::new(false));
    let stop2b = Arc::clone(&stop2);
    std::thread::spawn(move || { let _ = api::run_server("0.0.0.0", 17408, stop2b); });
    let url2 = "http://127.0.0.1:17408/api/v1/status";
    assert!(wait_up(&client, url2), "server did not start");

    let wrong = client.get(url2).header("Authorization", "Bearer nope").send().unwrap();
    assert_eq!(wrong.status(), 401);

    let right = client.get(url2).header("Authorization", "Bearer test-secret-token").send().unwrap();
    assert_eq!(right.status(), 200);

    stop2.store(true, Ordering::Relaxed);
    std::env::remove_var("MABI_API_TOKEN");
}

// --------------------------------------------------------------------------
// WebUI static file serving
// --------------------------------------------------------------------------

#[test]
fn test_webui_static_serving() {
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("gui").join("dist");
    if !dist.join("index.html").exists() {
        eprintln!("skipping: {} not built (run `npm run build` in gui/)", dist.display());
        return;
    }
    std::env::set_var("MABI_WEBUI_DIR", &dist);

    let stop = start_server(17411);
    let client = reqwest::blocking::Client::new();

    // Root serves index.html
    let root = client.get("http://127.0.0.1:17411/").send().unwrap();
    assert_eq!(root.status(), 200);
    assert!(root.headers().get("content-type").unwrap().to_str().unwrap().contains("text/html"));

    // Unknown client-side route falls back to index.html (SPA behavior)
    let spa = client.get("http://127.0.0.1:17411/some/spa/route").send().unwrap();
    assert_eq!(spa.status(), 200);
    assert!(spa.headers().get("content-type").unwrap().to_str().unwrap().contains("text/html"));

    // A real asset is served with the right content-type, not the SPA fallback
    let asset_name = std::fs::read_dir(dist.join("assets")).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|n| n.ends_with(".js"))
        .expect("expected at least one built .js asset");
    let asset = client.get(&format!("http://127.0.0.1:17411/assets/{}", asset_name)).send().unwrap();
    assert_eq!(asset.status(), 200);
    assert!(asset.headers().get("content-type").unwrap().to_str().unwrap().contains("javascript"));

    // Note: a literal ".." path-traversal attempt isn't testable through
    // reqwest here — well-behaved HTTP clients normalize dot-segments out of
    // the URL before the request is ever sent (RFC 3986), so this would only
    // verify reqwest's own URL handling, not handle_static's guard. The guard
    // (rejecting any ".." path segment) is exercised by inspection instead.

    // The API still works alongside static serving
    let status = client.get("http://127.0.0.1:17411/api/v1/status").send().unwrap();
    assert_eq!(status.status(), 200);

    stop_server(stop);
    std::env::remove_var("MABI_WEBUI_DIR");
}

// --------------------------------------------------------------------------
// Slow tests — need real archives
// --------------------------------------------------------------------------

#[test]
#[ignore]
fn test_list_endpoint_against_real_archive() {
    if !std::path::Path::new(UOTIARA).exists() {
        eprintln!("skipping: {} not present", UOTIARA);
        return;
    }
    let stop = start_server(17409);
    let client = reqwest::blocking::Client::new();
    let resp: serde_json::Value = client
        .post("http://127.0.0.1:17409/api/v1/list")
        .json(&serde_json::json!({ "archive": UOTIARA, "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(resp["success"], true);
    assert!(resp["data"]["count"].as_u64().unwrap_or(0) > 0, "expected at least one entry");
    stop_server(stop);
}

#[test]
#[ignore]
fn test_extract_and_pack_roundtrip_via_api() {
    if !std::path::Path::new(UOTIARA).exists() {
        eprintln!("skipping: {} not present", UOTIARA);
        return;
    }
    let stop = start_server(17410);
    // uotiara_00001.it has thousands of entries; a full unfiltered extract
    // takes 90s+ (see .gemini/testing timing notes) which exceeds the
    // platform's default socket read timeout over HTTP. Filter down to one
    // small known file so this test exercises the API wiring, not archive
    // throughput (that's covered directly against extract.rs, not via HTTP).
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();

    let extract_dir = common::temp_dir_for_test("api_extract_roundtrip");
    common::cleanup(&extract_dir);

    let extract_resp: serde_json::Value = client
        .post("http://127.0.0.1:17410/api/v1/extract")
        .json(&serde_json::json!({
            "archive": UOTIARA,
            "output": extract_dir.to_string_lossy(),
            "key": KNOWN_SALT,
            "filters": ["features.xml.compiled"],
        }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(extract_resp["success"], true, "extract failed: {:?}", extract_resp);
    assert!(extract_dir.exists());

    let repack_path = common::temp_dir_for_test("api_extract_roundtrip_repacked.it");
    let pack_resp: serde_json::Value = client
        .post("http://127.0.0.1:17410/api/v1/pack")
        .json(&serde_json::json!({
            "source": extract_dir.to_string_lossy(),
            "output": repack_path.to_string_lossy(),
            "key": KNOWN_SALT,
        }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(pack_resp["success"], true, "pack failed: {:?}", pack_resp);
    assert!(repack_path.exists());

    common::cleanup(&extract_dir);
    let _ = std::fs::remove_file(&repack_path);
    stop_server(stop);
}

// --------------------------------------------------------------------------
// Rich preview / convert / pmg export — need real archives
// --------------------------------------------------------------------------

#[test]
#[ignore]
fn test_preview_features_compiled_decompiles_to_text() {
    if !std::path::Path::new(UOTIARA).exists() {
        eprintln!("skipping: {} not present", UOTIARA);
        return;
    }
    let stop = start_server(17413);
    let client = reqwest::blocking::Client::new();

    // get_entry_data requires an exact archive-internal path match (not a
    // substring like the extract filter regex) — discover the real path
    // via list rather than assuming it's stored bare at the archive root.
    let list_resp: serde_json::Value = client
        .post("http://127.0.0.1:17413/api/v1/list")
        .json(&serde_json::json!({ "archive": UOTIARA, "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    let entries = list_resp["data"]["entries"].as_array().cloned().unwrap_or_default();
    let entry_name = entries.iter()
        .filter_map(|e| e["name"].as_str())
        .find(|n| n.to_lowercase().ends_with("features.xml.compiled"));
    let Some(entry_name) = entry_name else {
        eprintln!("skipping: no features.xml.compiled entry found in {}", UOTIARA);
        stop_server(stop);
        return;
    };

    let resp: serde_json::Value = client
        .post("http://127.0.0.1:17413/api/v1/preview")
        .json(&serde_json::json!({
            "archive": UOTIARA,
            "entry_name": entry_name,
            "key": KNOWN_SALT,
        }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(resp["success"], true, "preview failed for {}: {:?}", entry_name, resp);
    assert_eq!(resp["data"]["file_type"], "text", "expected .compiled to decompile to text: {:?}", resp);
    let text = resp["data"]["content_text"].as_str().unwrap_or("");
    assert!(text.contains("<?xml"), "expected decompiled XML, got: {}", text);
    stop_server(stop);
}

#[test]
#[ignore]
fn test_preview_pmg_entry_if_present() {
    if !std::path::Path::new(UOTIARA).exists() {
        eprintln!("skipping: {} not present", UOTIARA);
        return;
    }
    let stop = start_server(17414);
    let client = reqwest::blocking::Client::new();

    let list_resp: serde_json::Value = client
        .post("http://127.0.0.1:17414/api/v1/list")
        .json(&serde_json::json!({ "archive": UOTIARA, "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    let entries = list_resp["data"]["entries"].as_array().cloned().unwrap_or_default();
    let pmg_entry = entries.iter()
        .filter_map(|e| e["name"].as_str())
        .find(|n| n.to_lowercase().ends_with(".pmg"));

    let Some(entry_name) = pmg_entry else {
        eprintln!("skipping: no .pmg entry found in {}", UOTIARA);
        stop_server(stop);
        return;
    };

    let resp: serde_json::Value = client
        .post("http://127.0.0.1:17414/api/v1/preview")
        .json(&serde_json::json!({ "archive": UOTIARA, "entry_name": entry_name, "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(resp["success"], true, "preview failed for {}: {:?}", entry_name, resp);
    assert_eq!(resp["data"]["file_type"], "pmg");
    let vcount = resp["data"]["pmg_geometry"]["vertex_count"].as_u64().unwrap_or(0);
    assert!(vcount > 0, "expected a renderable PMG LOD, got: {:?}", resp["data"]["pmg_geometry"]);
    stop_server(stop);
}

#[test]
#[ignore]
fn test_convert_it_to_pack_and_back() {
    // Use a tiny synthetic .it rather than the full UOTIARA archive — convert()
    // is just extract+repack under the hood (already covered at scale by
    // test_extract_and_pack_roundtrip_via_api), and a full-archive round trip
    // here would take minutes for no additional coverage.
    let stop = start_server(17415);
    let client = reqwest::blocking::Client::new();

    let src_dir = common::temp_dir_for_test("api_convert_src");
    common::cleanup(&src_dir);
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("hello.txt"), b"hello mabi-pack2 convert test").unwrap();

    let seed_it = common::temp_dir_for_test("api_convert_seed.it");
    let pack_resp: serde_json::Value = client
        .post("http://127.0.0.1:17415/api/v1/pack")
        .json(&serde_json::json!({ "source": src_dir.to_string_lossy(), "output": seed_it.to_string_lossy(), "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(pack_resp["success"], true, "seed pack failed: {:?}", pack_resp);

    let as_pack = common::temp_dir_for_test("api_convert_roundtrip.pack");
    let convert_resp: serde_json::Value = client
        .post("http://127.0.0.1:17415/api/v1/convert")
        .json(&serde_json::json!({ "input": seed_it.to_string_lossy(), "output": as_pack.to_string_lossy(), "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(convert_resp["success"], true, "it->pack convert failed: {:?}", convert_resp);
    assert!(as_pack.exists());

    let back_to_it = common::temp_dir_for_test("api_convert_roundtrip_back.it");
    let convert_back_resp: serde_json::Value = client
        .post("http://127.0.0.1:17415/api/v1/convert")
        .json(&serde_json::json!({ "input": as_pack.to_string_lossy(), "output": back_to_it.to_string_lossy(), "key": KNOWN_SALT }))
        .send()
        .expect("request failed")
        .json()
        .expect("invalid JSON");
    assert_eq!(convert_back_resp["success"], true, "pack->it convert failed: {:?}", convert_back_resp);
    assert!(back_to_it.exists());

    common::cleanup(&src_dir);
    let _ = std::fs::remove_file(&seed_it);
    let _ = std::fs::remove_file(&as_pack);
    let _ = std::fs::remove_file(&back_to_it);
    stop_server(stop);
}
