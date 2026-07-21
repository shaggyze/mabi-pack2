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

## Global Options
- `-v`: Info logging
- `-vv`: Debug logging
- `-vvv`: Trace logging (full details)

---

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

## Credits
- Based on original utilities by regomne.
- Enhanced and maintained by ShaggyZE.
