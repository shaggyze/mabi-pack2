// Debug probe for the Nexon regional-auth login endpoint.
// Credentials come from MABI_EMAIL / MABI_PASSWORD; never hardcode them here.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("pmg_export uses the Nexon launcher module, which is only built on Windows");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() {
    let email = std::env::var("MABI_EMAIL").expect("set MABI_EMAIL");
    let password = std::env::var("MABI_PASSWORD").expect("set MABI_PASSWORD");

    println!("Testing auth directly with plaintext on regional-auth with correct JSON fields...");
    let dev = mabi_pack2::launcher::auth::device_id("");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("NexonLauncher.nxl-release-18.14.10-220-fc7480c-coreapp-3.3.0")
        .build().unwrap();

    let req = serde_json::json!({
        "autoLogin": false,
        "captchaToken": "M".repeat(64),
        "captchaVersion": "v3",
        "clientId": "7853644408",
        "deviceId": dev,
        "id": email,
        "localTime": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        "password": password,
        "scope": "us.launcher.all",
        "timeOffset": 0,
    });

    let resp = client
        .post("https://www.nexon.com/api/regional-auth/v1.0/no-auth/launcher/email/login")
        .json(&req)
        .send().unwrap();
    println!("Status: {}", resp.status());
    println!("Body: {}", resp.text().unwrap());
}
