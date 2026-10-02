# Desktop GUI

The desktop app is a Tauri 2 program: a TypeScript frontend (`gui/src/`)
and a Rust backend (`gui/src-tauri/src/lib.rs`) that calls the core crate.
The same frontend also runs in a browser as the web UI served by
`mabi-patcher serve` (see [API.md](API.md#web-ui)).

Sources: `gui/index.html`, `gui/src/app.ts`, `gui/src/preview3d/`,
`gui/src/pmgLoader.ts`, `gui/src/platform/`, `gui/src-tauri/src/lib.rs`,
`gui/src-tauri/src/vfs_ops.rs`, `gui/src-tauri/src/world_preview.rs`,
`gui/src-tauri/src/main.rs`, `gui/src-tauri/tauri.conf.json`,
`src/mod_file.rs`, `src/itemdb.rs`, `src/region_map.rs`.

---

## Start-up

`main.rs` does the following before the window opens:

1. If started as the launch stub (`--nxl3p-stub`), as `mcp` or as `serve`,
   do that and exit.
2. If the first argument is a launcher command (or `--cli` plus one), run it
   in the console and exit (see [CLI.md](CLI.md#gui-exe-command-line)).
3. If the first argument is an archive CLI command, run it and exit.
4. On Windows, if the GUI settings have `patcher_run_elevated: true` and the
   process is not elevated, restart through UAC.
5. On Windows, if the WebView2 runtime is missing, offer to download and
   install it (Yes), open the download page (No), or exit (Cancel).
6. Open the window (1100 × 850). A file path passed on the command line is
   opened (`--full` opens it in full-sequence mode). File associations are
   re-registered silently according to the settings. The product id from
   the settings is applied, the tray icon is created (shown only when
   "Minimize to tray on close" is on), and the REST API is started when it
   is enabled (see [Settings](#settings-and-windows-integration)).

The window title, bundle and identifier come from `tauri.conf.json`
(`productName` `mabi-patcher`, identifier `com.shaggyze.mabi-patcher`).
Installers: NSIS (English, Japanese, Korean, Traditional Chinese) and MSI.
The bundle registers `.it`, `.pack` and `.mod`.

---

## Tabs

The sidebar order is Dashboard, Extract, Pack, List, Differ, Jobs, Mods,
Patcher, Features, Launcher, Settings (`gui/index.html`).

| Tab | What it does |
|---|---|
| **Dashboard** | CPU, RAM, disk and network meters; patch progress; a **News** card with the latest Nexon Mabinogi news (up to 12 items; maintenance notices are marked; click to open in the browser; **Refresh**); recent activity. |
| **Extract** | Extract an archive to a folder. Salt history, "auto convert to PNG", and full-sequence mode (extract a whole folder of archives). |
| **Pack** | Pack a folder into `.it` or `.pack`. Salt history and "auto DDS" (PNG → DDS). Offers to wrap entries under `data\` when the folder has none. |
| **List** | Browse one archive, or a whole folder of archives in full-sequence mode, as a tree. Click an entry to preview it. Extract selected or all entries, convert the archive to `.it` or `.pack`, and edit it like a file manager (see [Editing archives in the List tab](#editing-archives-in-the-list-tab)). |
| **Differ** | Pick an old and a new folder and an output file: builds a patch archive of the changed files (`create_patch`). |
| **Jobs** | A queue of extract, pack, differ, merge and apply-mod jobs with input, output and key; "Run All" and "Clear Done". |
| **Mods** | Local `.mod` files with Apply buttons, and the website mod catalogue (search, category, install / remove). See [Mods tab](#mods-tab). |
| **Patcher** | Installed vs. available version; **Patch**, **Verify**, **Repair**, **Choose files…** (scan, then tick the files to patch and press **Patch selected**), **Check all installs** (every Mabinogi install found on the PC, with its status and a button to patch it), **Pause** / **Resume** and **Stop**. See [NXL_PATCHER.md](NXL_PATCHER.md#gui-extras). |
| **Features** | Load an archive's `features.xml.compiled`, search the feature list, edit and save it back. The file stores only a hash of each feature name; where a name in `src/data/feature_names.txt` (from uotiara's Fetitor list, built into the exe) has that hash, it is shown next to the hash and is searchable. |
| **Launcher** | Profiles, email/password login with an email verification code field, browser login, import from the official launcher, **Import from browser** (reads a Nexon login from Firefox, Chrome, Edge or Brave; see [NEXON_AUTH.md](NEXON_AUTH.md#browser-cookie-import)), log out, game folder with **Check all installs**, launch. If a launch finds the session expired and it cannot be refreshed, the app offers to log in again. See [LAUNCH.md](LAUNCH.md#gui-launch-modes). |
| **Settings** | Sub-tabs Autostart, Engine, File Assoc, Launcher, Patcher and Themes: language, theme, start-up behaviour, list and audio options, parallel processing, the in-app REST API, minimize to tray, portable mode, config location, file associations, patcher options, hooks, product id, reset. |

The interface is translated into English, Traditional Chinese, Japanese and
Korean (`gui/src/locales.ts`).

---

## Preview pane

Selecting an entry in the List tab (or opening a loose file) shows it in the
side panel, with **Visual**, **Hex** and **Details** sub-tabs.

| Type | Extensions | Preview |
|---|---|---|
| Image | `.dds .png .jpg .bmp` | Decoded image. |
| Text | `.xml .txt .data .csh`, `.mml` | Text (first 32 KiB from the API). `.compiled` files that decode as compiled XML are shown as text. An `itemdb*.xml` entry also gets an item search box (see [Item lookup](#item-lookup)). |
| 3D model | `.pmg` | Textured 3D viewer (below). |
| Navigation mesh | `.gm` | 3D navmesh viewer. |
| Effect | `.eff` | Effect-group placement viewer. |
| Region / area | `.rgn`, `.area` | 2D region map, with a 3D world view on demand (see [Region map and 3D world](#region-map-and-3d-world)). Falls back to the parsed region and area data (web UI, loose files, or when the map cannot be built). |
| Animation | `.set` | Header summary: frames, bones, duration. `.anievent` is parsed too. |
| Audio | `.wav .mp3 .ogg .nxa` | Player with autoplay and loop options. IMA ADPCM `.wav` is converted to PCM. |
| Other | | Hex dump. |

---

## 3D preview

In the desktop app, `.pmg`, `.gm` and `.eff` files are shown with viewers
ported from the project website's preview (`gui/src/preview3d/`, using
three.js). The browser web UI has no raw-bytes route, so it falls back to the
simpler Rust-parsed PMG preview (`pmgLoader.ts`, fed by `pmg_geometry` from
`/api/v1/preview`).

### PMG models (`pmg.ts`, `modelViewer.ts`)

- Parses PMG submesh versions 1.7, 2.0 and 3.0, applies each submesh's
  transform matrix, turns triangle strips into triangles, and groups submeshes
  by texture: one mesh per texture.
- Vertex colours are used when they vary.
- Controls: drag to rotate, wheel to zoom, touch; double-click resets the
  camera.
- Toolbar:

| Button | Effect |
|---|---|
| Rotate | Auto-rotate on/off. |
| Wire | Wireframe on/off. |
| Textures | Load DDS textures. |
| Accurate DDS | Rounded DXT decoding plus alpha cut-outs. |
| HQ | Antialiasing and full pixel ratio. |
| Reset | Reset the camera. |
| GLB | Export the textured model as glTF binary. |
| OBJ | Export the geometry as Wavefront OBJ. |
| PNG | Save the current view as an image. |

The toggles are saved in browser storage under `preview3d-settings`.
Defaults: rotate on, HQ on, textures on, accurate DDS off, wireframe off.

The status line shows the PMG version, material, vertex and face counts, and
texture progress (`textures 3/4 (1 not found)`).

### Textures (`dds.ts`, `ddsDecode.ts`, `ddsWorker.ts`)

A texture named `foo` in the model is looked up as `foo.dds`:

- **Model inside an archive:** among `.dds` entries in all loaded archives,
  by file name (ignoring case and folder). An entry from the same archive as
  the model wins; otherwise the newest copy (the last archive loaded).
- **Loose model file:** `find_loose_texture` looks next to the model, then
  walks up to four parent folders (each searched up to 8 levels deep and
  50 000 entries). It stops at a folder named `data` or at your home folder.
  Texture names containing `/`, `\`, `:` or `..` are rejected.

DDS files are decoded off the UI thread by a pool of web workers and cached
per archive and texture name. Supported formats: DXT1, DXT3, DXT5 and
uncompressed 16, 24 and 32 bits per pixel.

### Navmesh and effects

- `.gm` (`navmesh.ts`): parsed into triangles and shown with vertex and face
  counts.
- `.eff` (`effect.ts`): effect-group XML (UTF-16 with BOM or UTF-8) shown as
  placements, with group and effect counts.

### Item lookup

Built from the game's item database in the open archives (`src/itemdb.rs`,
commands in `gui/src-tauri/src/world_preview.rs`): `data/db/itemdb*.xml`
(`<Mabi_Item>` elements with `ID`, `Text_Name0`, `Text_Name1`, `Category`
and the `File_*Mesh` model names), with `_LT[...]` names resolved from
`data/local/xml/itemdb.<language>.txt`, in the UI language if present, else
English. The index is built in Rust once per set of open archives.

- In the PMG viewer, an overlay lists the items that use the shown model
  (up to 8), and the **Items** button opens a search box.
- Previewing an `itemdb*.xml` entry shows the same search box above the
  text.
- Search by item name or id (up to 30 results). Each result has a button
  per model (Male, Female, Giant, Giant (F), Dropped); clicking it opens
  that `.pmg` from the open archives, preferring the copy next to the
  current entry. A model that is not in the open archives is reported in
  the log.

### Region map and 3D world

For a `.rgn` or `.area` entry (`gui/src/preview3d/worldPanel.ts`,
`mapView.ts`, `worldView.ts`, `worldData.ts`; parsing in
`src/region_map.rs`):

- The region is loaded from the archive folder of the selected entry: the
  `.rgn` (for an `.area`, a matching `.rgn` in the same folder if there is
  one, else that area alone) and every `.area` next to it. `.rgn` versions
  100, 102 and 103 are read.
- **Map** (default) is a top-down 2D view: area outlines, terrain height
  shading, props and events (warps, triggers, spawn areas). Drag to pan,
  wheel to zoom, hover for details.
- **3D** builds a height-mapped terrain per area, prop markers (up to
  30 000 boxes), event outlines and the real models of the props nearest
  the camera target (up to 64 at a time, loaded from `.set` and `.pmg`
  files in the open archives). Left-drag orbits, right-drag pans, wheel
  zooms.
- **Terrain**, **Props** and **Events** toggle layers; **Reset** resets the
  view.
- Prop class names and models come from `data/db/propdb.xml`, but only when
  it is plain-text XML. Current clients ship it encoded, so it is skipped
  quietly and the status line says that prop names need a plaintext
  `propdb.xml`.

### PMG to OBJ outside the viewer

- Extract with "auto convert PMG" (API `auto_convert_pmg`) writes `.obj` next
  to the other files.
- `export_pmg_obj` (GUI) and `POST /api/v1/pmg/export` (API) export one entry.

---

## Mods

### `.mod` files

A `.mod` file is TOML (`src/mod_file.rs`). Print a template with
`mabi-patcher mod template`.

```toml
[meta]
name        = "My Mod"           # required
version     = "1.0.0"
author      = "YourName"
description = "What it does"
game        = "NA"               # NA | TW | JP | KR
tags        = ["visual"]
# min_game_version = 0
# homepage = "https://..."

[pack]
output      = "uotiara_00001.it"
pack_key    = "<salt>"
extract_key = "<salt>"
wrap_data   = true
# pack_version = 2

[[files]]
archive_path = "data/db/example.xml"   # required
source       = "mod_files/example.xml" # relative to the mod folder
action       = "replace"               # replace (default) | delete | patch

[[files]]
archive_path = "data/gfx/example.bin"
action       = "patch"
patches = [ { offset = "0x1A4", original = "00", patched = "FF" } ]

[features]
enable  = ["<hash hex>"]
disable = ["<hash hex>"]

[api]
public       = false
allow_remote = false
# endpoint   = "..."
```

Validation (`ModPackage::validate`): `meta.name` must be set; every
`[[files]]` entry needs `archive_path`; `replace` and `patch` need `source`
or `patches`.

### Applying a mod

`apply_mod` (GUI) and `POST /api/v1/mod/apply` (API):

1. Extract the whole archive to a temp folder.
2. For each `[[files]]` entry, with a leading `data/` or `data\` removed from
   `archive_path`:
   - `delete`: remove the file (counted as skipped if missing).
   - `replace`: copy `source` over it.
   - `patch`: write each `patched` hex string at its `offset` (hex, with or
     without `0x`), growing the file if needed; or copy `source` if there
     are no patches. `original` is not checked.
3. `[features]`: in `features.xml.compiled`, `enable` hashes have their empty
   conditions removed; `disable` hashes get the single condition `FALSE`.
4. Repack over the original archive with the key given or the salt that
   opened it.

The `[pack]` settings and `[api]` options are parsed and shown, but the
apply step uses the key passed in the request, not `pack_key`/`extract_key`.

### Mods tab

The **Mods** tab (`gui/index.html`, `gui/src/app.ts`) has two views.

**Local** lists the `.mod` files in the `mods` folder next to the exe
(`list_mod_files`), each with name, version, author, file count, tags and an
**Apply** button. Files that fail to parse are shown with their error.
"Open Folder" opens the folder; "New .mod Template" creates one from the
template.

**Online (website)** browses the mod catalogue on the project website:

| Item | Behaviour |
|---|---|
| Catalogue source | `mod_remote_url` in the settings if it is an `http(s)` URL, else `https://shaggyze.website/mabipatcher/mods`. |
| Fetching | `fetch_web_mods_catalog` (Rust, so no CORS limits). A JSON array or object answer is used as is. For an HTML page, it finds the page's `assets/index-*.js` bundle and reads the catalogue array (`[{id:…,name:…,category:…}]`) out of it. |
| Filters | Search (name, description, author, category, tags), category, "Installed only". A counter shows shown / total / installed. |
| Format | `.it (newer)` or `.pack (older / private)`. |
| Install | `install_web_mod` posts `{"selected":[id],"format":…}` to `<catalogue origin>/api/pack` (180 s timeout) and saves the returned archive as `mods\web\MOD<id, 4 digits> - <name>.<it|pack>` next to the exe. A 401/403 answer means the website wants a logged-in account. |
| Installed state | `list_installed_web_mods` reads the ids from file names in `mods\web\`. Installed mods show a badge, **Reinstall** and **Remove**. |
| Remove | `remove_web_mod` deletes every file in `mods\web\` whose name starts with `MOD<id>`. |

Website data is shown with `textContent` only, never as HTML.

Installing a website mod only downloads the package into `mods\web\`;
nothing copies it into the game folder.

### Editing archives in the List tab

The List tab edits an open archive much like FileZilla or WinZip edit a
folder (`gui/src/app.ts`, `gui/src-tauri/src/vfs_ops.rs`). Changes are
queued, not written at once: the queue can be saved without applying
(`<archive>.pending.json`) and is applied in one rebuild
(`apply_vfs_changes`). Operations: delete, rename, add, merge (see
[API.md](API.md#mods)).

| Action | How |
|---|---|
| Select | Click; Ctrl+click toggles; Shift+click selects a range. Files and folders can be mixed. |
| Add files | Drag files or folders from Explorer onto the tree. The folder under the pointer is highlighted and receives them; a dropped folder keeps its structure. |
| Drop an archive | Dropping a `.it` or `.pack` asks whether to **Merge Contents** into the open archive or **Add as File**. |
| Move | Drag selected rows with the mouse onto another folder (Esc cancels). |
| Delete, rename | **Delete** queues deletion of the selection; **F2** renames it. Also in the right-click menu. |
| Extract | Right-click → **Extract Selected To…** writes the selection to a folder, keeping relative paths. |
| Drag out | Dragging selected rows out of the window hands them to Windows as real files: they are extracted to a temp folder (`%TEMP%\mabi_dragout_<pid>`, cleared at the next drag-out) and Explorer copies them on drop. Windows only (`drag` crate); elsewhere use **Extract Selected To…**. |

**Name checks.** Every new path is checked with `validate_entry_path`
before it is queued (no `..`, absolute or drive paths, at most 260
characters, no characters Windows rejects). Refused paths are logged and
skipped.

**Conflicts.** When an added, moved or merged file would replace an
existing entry (including entries that pending changes will create), a
"Target file already exists" dialog shows source and target size and date
and offers **Overwrite**, **Overwrite if source newer**, **Overwrite if
different size**, **Rename** (with a suggested `name (1).ext`), **Skip**,
**Always use this action** for the rest of the batch, and **Cancel**, which
queues nothing from the operation. Archive entries store no dates, so the
archive file's own modified time is used for entries inside it. For a
merge, the decisions are stored with the merge as `skip` and `rename`
lists.

---

## Settings and Windows integration

- **REST API** (Settings → Engine): "Run the REST API while the app is
  open" starts the same API as `mabi-patcher serve` inside the desktop app,
  on `127.0.0.1` only, at the chosen port (default 7331). The Mods tab
  badge shows `API :<port>` or "API off".
- **Minimize to tray** (Settings → Engine): closing the window hides it to
  the system tray instead of quitting. Left-click the tray icon or choose
  **Show** to bring it back; **Quit** exits.
- **Start with Windows (in the tray)** (Settings → Engine, Windows only):
  adds a per-user Run entry `"<exe>" --minimized`, so mabi-patcher starts
  hidden in the tray when you sign in. See [SESSION.md](SESSION.md#gui-settings).
- **Session countdown** (Launcher tab): each profile in the profile list
  shows how long its saved session is still valid (`29d 4h`, `2h 15m`,
  `45m`, `Expired`), updated every minute. An expired session is not tried:
  auto-login and Launch go straight to the re-login prompt.
- **Product ID** (Settings → Patcher → Advanced): the Nexon product used
  for patching, launching and news (default `10200`). Only change it if you
  know you need to.
- **Ignore list and hooks** (Settings → Patcher): stored in the shared
  patcher `config.json`, so the CLI and REST API use the same values (see
  [SESSION.md](SESSION.md#patcher-settings-configjson)). The GUI runs its
  hooks itself and waits for them.
- **File associations**: `.it`, `.pack`, `.it` full-sequence, `.dds`, `.pmg`
  and `.compiled`, each with its own description. "Apply Registry" writes
  them; "Wipe Registry Associations" removes all `mabi-pack2.*` entries.
- **Portable mode** and **config location**: see
  [SESSION.md](SESSION.md#gui-settings).
- **Elevation**: the app can ask to restart as administrator
  (`request_elevation`).
- **Console**: `execute_terminal_command` runs a command through `cmd /C` or
  `sh -c` and returns its output.
- **Logs**: `open_log_file` opens the GUI log; the log level is a setting.

---

## Web UI differences

`gui/src/platform/` swaps Tauri calls for REST calls when not running in
Tauri (`isTauri()`):

| Area | Web UI behaviour |
|---|---|
| `invoke` | Mapped to `/api/v1/...` routes for dashboard, extract, pack, list, mods, launcher and preview (`webApi.ts`). Desktop-only commands throw an error; this includes the news feed, browser import, patch scan, pause and install checks, and the List tab's drag-out and extract-selected. |
| File dialogs | You type a server-side path instead. |
| Saving files | Triggers a browser download instead. |
| Events | No live progress or log events. |
| 3D viewer | Uses the Rust-parsed PMG preview only. No item lookup, region map or world view. |
