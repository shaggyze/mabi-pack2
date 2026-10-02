# mabi-patcher documentation

mabi-patcher (repository `shaggyze/mabi-pack2`, crate `mabi-pack2-core`) is a
toolset for Mabinogi. It does four jobs:

- reads and writes the game's `.it` and legacy `.pack` archives,
- logs in to Nexon NA, patches the game from Nexon's CDN and launches it
  without the official Nexon Launcher,
- runs a local REST API (and the same web UI as the desktop app) and an MCP
  server for other tools,
- ships a desktop GUI (Tauri) with a 3D model preview, item lookup, region
  map and 3D world preview, archive editing and a mod loader.

All behaviour described in these pages comes from the source code. Each page
names the files it was taken from.

## Pages

| Page | What it covers |
|---|---|
| [CLI.md](CLI.md) | Every command and flag of `mabi-patcher`, with examples and exit codes. |
| [API.md](API.md) | The REST server (`mabi-patcher serve`): every route, its body and its response, plus the token and environment variables. |
| [NEXON_AUTH.md](NEXON_AUTH.md) | Nexon login: email and password, 2FA (OTP), device verification, browser/TPA login, browser cookie import, refresh, the 401 retry, cookies, the product id and per-profile device ids. |
| [SESSION.md](SESSION.md) | Profiles, where sessions are stored (Windows Credential Manager or `profiles.json`), the shared hooks and ignore list, GUI settings, and how expiry works. |
| [NXL_PATCHER.md](NXL_PATCHER.md) | The NXL manifest, update, repair (verify), force and scan-only modes, choosing files, several installs, pause and resume, and parallel downloads. |
| [LAUNCH.md](LAUNCH.md) | Launching the game: passport, the `nexon_client.exe` stub, the nxl3p shim, the SDK pipe, and Wine on Linux. |
| [PACK_FORMAT.md](PACK_FORMAT.md) | The `.it` archive format, salts, Snow2 encryption, legacy `.pack`, and how extract and pack work. |
| [GUI.md](GUI.md) | The desktop app: tabs (Dashboard, Extract, Pack, List, Differ, Jobs, Mods, Patcher, Features, Launcher, Settings), the preview pane, the 3D viewer (PMG, DDS, navmesh, effects), item lookup, the region map and 3D world, List-tab archive editing, the Mods tab with the website catalogue, and settings. |
| [MCP.md](MCP.md) | The built-in MCP server (`mabi-patcher mcp`) and its tools. |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Building on Windows and Linux, `build.bat`, the pre-commit gate, CI, tests, where the version number lives, and known issues. |

## Binaries at a glance

| Binary | Built from | Purpose |
|---|---|---|
| `mabi-patcher` (CLI) | `src/bin/mabi-pack-cli.rs` | Archive tools, launcher commands, `serve`, `mcp`. |
| `mabi-patcher.exe` (GUI) | `gui/src-tauri/` | Desktop app. Also accepts the launcher commands, `serve`, `mcp` and a few archive commands on the command line. |
| `pmg_export` | `src/bin/pmg_export.rs` | Despite its name, currently a Nexon login debug probe (see [DEVELOPMENT.md](DEVELOPMENT.md)). |
| `nxl3p_shim.dll` | `nxl3p-shim/` | Stand-in for `nexon_x64.dll`; built by `build.rs` and embedded in the Windows exe. |

## Credentials

No page in this folder contains a real email, password, token or archive
salt. Examples use placeholders such as `you@example.com` and the environment
variables the code reads: `MABI_EMAIL`, `MABI_PASSWORD` and `MABI_API_TOKEN`.
