# mabi-pack2

Utilities for Mabinogi `.it` and `.pack` archives with robust error handling and high-performance parallel processing.

## Features
- **Parallel Processing**: Multi-threaded extraction, packing, and key searching (powered by `rayon`).
- **Memory Mapping**: High-speed I/O using `memmap2`.
- **Legacy Support**: Full support for both modern `.it` and legacy `.pack` (V1) formats.
- **Modern GUI**: Professional explorer interface with 3D mesh preview, hex viewer, and drag-and-drop support.
- **Windows Integration**: Automatic file associations and context menu integration (fully localized).
- **On-Demand Conversion**: Right-click to convert between `.dds` and `.png` in the explorer.
- **Progress Tracking**: Real-time progress bars for extraction and packing operations.
- **Deep Localization**: Multilingual interface supporting English, Chinese, Japanese, and Korean.

## Roadmap
For advanced features like **Virtual Merging**, **Archive Drag-and-Drop Injection**, and **FileZilla-style Conflict Resolution**, please see the [TODO.md](./TODO.md) file.

## Installation

### CLI
Requires [Rust](https://rustup.rs/) 1.70+.
```bash
git clone https://github.com/shaggyze/mabi-pack2.git
cd mabi-pack2
cargo build --release
```

### GUI
Requires Node.js and Tauri prerequisites.
```bash
cd gui
npm install
npm run tauri build
```

## Usage

### Extracting
```bash
# Basic extraction (auto-detects salt from built-in list)
mabi-pack2 extract -i data_00.it -o ./output

# With specific key and regex filter
mabi-pack2 extract -i data_00.it -o ./output -k "MySalt" -f "\.xml$"

# Legacy .pack format
mabi-pack2 extract -i data_00.pack -o ./output
```

### Packing
```bash
# Modern .it archive
mabi-pack2 pack -i ./input_folder -o new_pack.it -k "SecretKey"

# Wrap files under a virtual data/ root (matches game's expected layout)
mabi-pack2 pack -i ./input_folder -o new_pack.it -k "SecretKey" --wrap-data

# Legacy .pack archive
mabi-pack2 pack -i ./input_folder -o new_pack.pack
```

### Listing
```bash
mabi-pack2 list -i data_00.it
mabi-pack2 list -i data_00.it -k "MySalt" -o filelist.txt
```

### Batch Extraction
```bash
# Extract all .it/.pack archives in a folder into one merged output tree
mabi-pack2 batch -i ./archives_folder -o ./output

# Keep each archive in its own subfolder (no merge)
mabi-pack2 batch -i ./archives_folder -o ./output --no-merge

# Parallel processing (4 archives at once), with regex filter
mabi-pack2 batch -i ./archives_folder -o ./output -j 4 -f "\.xml$"
```

### Shell Integration (Windows)
Dragging a `.it` or `.pack` file onto the exe opens it directly in the GUI.  
Right-clicking a registered file type gives an "Open with mabi-pack2" context menu entry.

## Launcher & Patcher (Nexon NA, no official launcher needed)

Logs in, patches and launches Mabinogi NA the same way Rua does (ported to Rust):

- **Login**: email/password with MFA codes, or browser/SSO (Google etc.) via TPA
  exchange. Expired tokens are refreshed automatically (401 → autologin → retry).
- **Launch**: account → access → playable → passport, then a built-in
  `nexon_client.exe` stub + `nexon_x64.dll` shim (embedded in the exe) and the
  Nexon SDK named pipe hand the passport to `Client.exe`. Maintenance and
  region blocks are reported before launching.
- **Patcher**: current manifest from Nexon's branch API, parallel downloads
  (files × 4 parts, capped total connections, retries, SHA1-checked parts),
  Repair (hash-check every file), re-download all, ignore list, cancel/resume.

```sh
mabi-patcher login --email you@example.com --password '...'   # MFA → prints login-otp command
mabi-patcher login-otp --mfa-key KEY --otp 123456
mabi-patcher check-update --game-path "C:\Nexon\Library\mabinogi"   # exit 2 = update available
mabi-patcher update --game-path "C:\Nexon\Library\mabinogi" [--verify|--force-all] [-j 8] [--ignore "*.ini"]
mabi-patcher launch --game-path "C:\Nexon\Library\mabinogi"
```

Also: `mabi-patcher config [show | ignore add|remove PATTERN | hook EVENT [CMD]]` keeps a
persistent ignore list (merged with `--ignore`) and hooks run before/after patching and
launching (`%PROFILE%` = profile name). `login`/`launch` read the password from
`MABI_PASSWORD` when `--password` is omitted, and the email from `MABI_EMAIL` when `-u` is
omitted but a password is available. Without `--profile`, a login is saved to the profile
with the same email (or Nexon account), otherwise to a new one — never to another account's; `login --client DIR` stores the game folder on
the profile; when no folder is given or stored, an installed game is auto-detected.
`launch --version` prints the latest game version; `--no-wait` returns once the game has
taken its login ticket. The after-launch hook fires as soon as the client has started.

The GUI exe accepts the same commands (`mabi-patcher.exe launch ...`, or Rua's
`--cli launch ...` form). The local API (`mabi-patcher serve`, port 7331) exposes them
under `/api/v1/launcher/*` (login, login/otp, login/tpa, session/check, update/check,
update + update/status + update/cancel, launch) in place of a DLL.

**Linux / Steam Deck:** the native Linux build logs in and patches directly. To launch,
put the Windows `mabi-patcher.exe` next to it (or set `MABI_WINE_EXE`) and set
`WINEPREFIX` to the game's prefix. `MABI_WINE` (or `WINE`) picks the Wine runner, e.g.
`wine64`, a Proton `wine` binary or a wrapper script; default `wine`. `launch` then hands the session to the Windows
build under Wine, because the SDK pipe and stub must run inside the prefix.

## Global Options
- `-v`: Info logging
- `-vv`: Debug logging
- `-vvv`: Trace logging (full details)

---

## Game patcher and launcher CLI

`mabi-patcher` can patch and launch Mabinogi NA without the Nexon Launcher, on
Windows and on Linux (the game runs through Wine there). The patcher downloads
from Nexon's NXL CDN, 8 files at a time with a shared cap of 16 connections,
and retries failed parts. A 401 from Nexon refreshes the saved session once and
retries.

```sh
mabi-patcher login -u you@example.com -p '...' --profile Main -c /games/mabinogi/appdata
mabi-patcher check-update          # exit 0 = up to date, 2 = update available
mabi-patcher update                # --force-all, --scan-only, -j N, --ignore 'mods/*'
mabi-patcher launch --wait         # uses the active profile; MABI_WINE picks the Wine runner
mabi-patcher login-otp -u you@example.com --mfa-key KEY --otp 123456   # if login asks for 2FA
mabi-patcher config ignore add 'mods/*'                                # saved ignore list
mabi-patcher config hook before-launch 'notify-send %PROFILE%'         # before/after patch or launch
```

`-c` takes the folder holding `Client.exe` (or the exe itself). The installed
version is read from `patchdata/10200.manifest.hash`, inside that folder or
beside it. Without `-c` or a saved folder it looks for an existing install
(Nexon Launcher config, uninstall entries, common folders and Wine prefixes).
Build the Linux binary with `./build-linux.sh`.

## GUI

The GUI is a single `mabi-pack2.exe` binary that acts as both CLI (when given a subcommand) and GUI (when launched normally or by double-clicking a registered archive).

### Requirements
- **Windows 10/11** (x64)
- **Microsoft WebView2 Runtime** — if not installed, the app will offer to download and install it automatically on first launch.

### Installation
- **Installer**: Run `mabi-pack2_1.x.x_x64-setup.exe` (NSIS) or the `.msi` — installs the app, registers file associations, and ensures WebView2 is present.
- **Portable**: Drop `mabi-pack2.exe` anywhere and run it. Settings save to `%APPDATA%\mabi-pack2\config.json` by default; place a `config.json` next to the exe to switch to portable mode (settings stay beside the exe).

### Tabs

| Tab | Purpose |
|-----|---------|
| **Extract** | Extract `.it` or `.pack` archives. Auto-detects the salt; override with a custom key if needed. |
| **Pack** | Create `.it` or `.pack` archives from a folder. Supports `--wrap-data` mode to prepend a `data/` root. |
| **List** | Browse archive contents without extracting. Click any entry to preview it in the side panel. |
| **Diff** | Compare two archives and highlight added / removed / changed entries. |
| **Console** | Live log output from the current operation. |
| **Settings** | Configure locale, theme, file associations, shell menu, and config location. |

### Preview Panel
The side panel auto-previews selected files based on type:
- **Images** (`.dds`, `.png`, `.jpg`, …) — rendered inline with zoom
- **3D Models** (`.pmg`) — interactive WebGL viewer with rotate/zoom
- **Text / XML** — syntax-highlighted source view
- **Binary** — hex dump (capped at 64 KB to avoid hangs on large files)

### Settings — Shell & Registry
- **Associate file types** — registers `.it`, `.pack`, `.dds`, `.pmg`, and `.compiled` with the app so they open on double-click.
- **Apply Registry** — writes the associations immediately.
- **Wipe Registry Associations** — removes all `mabi-pack2.*` entries from the registry and refreshes the shell.

### Settings — Config Management
- **Config path** — shows where `config.json` is currently saved.
- **Portable mode toggle** — switches between AppData and the folder beside the exe.
- **Open folder** — opens Explorer with the config file highlighted.
- **Reset Settings** — restores all settings to defaults (keeps the current config location).

### Localization
Switch language in Settings → Locale. Supported: **English**, **繁體中文**, **日本語**, **한국어**.

---

## REST API, WebUI, and MCP mission control

`mabi-pack2 serve` (aka `mabi-patcher serve`) runs a headless HTTP server
exposing pack/extract/list/mod-apply/launcher operations, and — once
`gui/dist` is built (`npm run build` in `gui/`) — serves the WebUI (the same
frontend as the desktop app, pointed at this REST API instead of Tauri IPC)
from the same port:

```bash
mabi-pack2 serve --port 7331          # loopback only by default
mabi-pack2 serve --host 0.0.0.0 --port 7331   # LAN/Docker — requires MABI_API_TOKEN
```

Then open `http://127.0.0.1:7331/`. Full route list, auth model
(loopback always open; non-loopback requires `MABI_API_TOKEN` as a bearer
token; same-origin enforcement blocks drive-by cross-origin requests from
other websites regardless of bind address), and the phased build plan are
in `.gemini/MISSION_CONTROL_PLAN.md`.

**Docker:** `docker compose up` after setting `MABI_API_TOKEN` (required —
the container binds `0.0.0.0`). Builds and serves the WebUI alongside the
API automatically.

**MCP server:** `mcp_server/mission_control.py` exposes the same
operations as MCP tools (plus `launch_game`/`test_mod_for_crash`, which
replace the `mabi-mod-tester` Claude Code skill's screen-automation launch
step with real Nexon auth) for use from Claude Code or any MCP client — see
`mcp_server/README.md`.

## Credits
- Based on original utilities by regomne.
- Enhanced and maintained by ShaggyZE.
