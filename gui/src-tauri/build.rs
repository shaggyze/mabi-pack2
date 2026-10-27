fn main() {
    // The Browser tab's userscript bridge is an inline plugin so a capability can
    // grant web pages these two commands and nothing else (capabilities/userscripts.json).
    tauri_build::try_build(tauri_build::Attributes::new().plugin(
        "userscripts",
        tauri_build::InlinedPlugin::new()
            .commands(&["page_ready", "gm"])
            .default_permission(tauri_build::DefaultPermissionRule::AllowAllCommands),
    ))
    .expect("failed to run tauri-build");
}
