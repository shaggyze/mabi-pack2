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
# Basic extraction (tries hardcoded salts automatically)
mabi-pack2 extract -i data_00.it -o ./output

# With specific key and regex filter
mabi-pack2 extract -i data_00.it -o ./output -k "MySalt" -f "\.xml$"
```

### Packing
```bash
mabi-pack2 pack -i ./input_folder -o new_pack.it -k "SecretKey"
```

### Listing
```bash
mabi-pack2 list -i data_00.it
```

## Global Options
- `-v`: Info logging
- `-vv`: Debug logging
- `-vvv`: Trace logging (Full details)

## Credits
- Based on original utilities by regomne.
- Enhanced and maintained by ShaggyZE.
