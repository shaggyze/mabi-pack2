# Development

How to build, test and release mabi-patcher, and a list of known problems in
the current code.

Sources: `Cargo.toml`, `build.rs`, `build.bat`, `build-all.bat`,
`build-linux.sh`, `Dockerfile`, `scripts/precommit-check.sh`,
`.githooks/pre-commit`, `.claude/settings.json`, `.claude/hooks/`,
`.github/workflows/cli.yml`, `tests/`, `gui/src-tauri/tauri.conf.json`.

---

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Core library crate `mabi_pack2`: archive formats, REST API (`api.rs`), MCP server (`mcp.rs`), mods, item and prop tables (`itemdb.rs`), region maps (`region_map.rs`), launcher (`src/launcher/`). |
| `src/launcher/` | Nexon login (`auth.rs`), browser cookie import (`cookies.rs`, `cookie_dec.rs`), keychain (`keystore.rs`), profiles, shared config, install detection, patcher, launch, news feed, and the launcher CLI. |
| `src/bin/mabi-pack-cli.rs` | The `mabi-patcher` CLI. |
| `src/bin/` (others) | Helper and research binaries (see below). |
| `src/snow2_fast.c` | Snow2 cipher in C, compiled by `build.rs`. |
| `nxl3p-shim/` | The `nexon_x64.dll` replacement used by `launch` (see [LAUNCH.md](LAUNCH.md#the-nxl3p-shim)). |
| `gui/` | Tauri 2 desktop app: TypeScript frontend in `gui/src/`, Rust backend in `gui/src-tauri/` (`lib.rs`, `main.rs`, `vfs_ops.rs` for List-tab editing, `world_preview.rs` for the item lookup and region previews). |
| `tests/` | Integration, API and legacy `.pack` tests. |
| `mods/` | Example `.mod` files. |

---

## Binaries

`Cargo.toml` sets `autobins = false`, so only listed binaries are built.

| Binary | Source | Built by default |
|---|---|---|
| `mabi-patcher` | `src/bin/mabi-pack-cli.rs` | yes |
| `pmg_export` | `src/bin/pmg_export.rs` | yes. Despite the name, it is currently a debug probe for the Nexon regional-auth login, not a PMG exporter. |
| `brute_footer`, `brute_force`, `brute_iv`, `brute_salts`, `find_exact`, `find_header`, `verify_tw`, `scan_0004`, `scan_mini`, `scan_archives`, `brute_force_kr`, `brute_force_lambda`, `dump_strings`, `crack_propdb` | `src/bin/*.rs` | no; need `--features debug` |

---

## Building

### Requirements

- Rust (stable) and a C compiler for `build.rs` (`cc` crate).
- For the GUI: Node.js and npm, plus the Tauri 2 prerequisites.
- For the Windows launch feature: a Windows target, so `nxl3p-shim` can be
  built.

### `build.rs`

1. Compiles `src/snow2_fast.c` with `cc`; links `stdc++` on Linux.
2. Builds the nxl3p shim with a nested `cargo build --release --target <target>`
   in `nxl3p-shim/` (separate target folder, parent `RUSTFLAGS` removed) and
   exposes its path as `NXL3P_SHIM_DLL`. Set `NXL3P_SHIM_PREBUILT=<dll>` to
   use a ready-made DLL instead. Non-Windows targets embed an empty file.

### CLI only

```sh
cargo build --release --bin mabi-patcher        # target/release/mabi-patcher
./build-linux.sh                                # also copies it to release/mabi-patcher-linux-x86_64
```

### Desktop app (Windows)

`build.bat`:

1. Reads the version from `gui/src-tauri/tauri.conf.json` (PowerShell).
2. Runs `git config core.hooksPath .githooks` to turn on the pre-commit gate.
3. Kills any running `mabi-patcher.exe` and deletes the old exe and
   installers.
4. `npm install` and `npm run tauri build` in `gui/`.
5. Copies `gui\src-tauri\target\release\mabi-patcher*` to the repository root
   and checks that `mabi-patcher.exe` exists.

`build-all.bat` does the same after a deep clean (`gui\dist` and
`gui\src-tauri\target` are removed first).

### Web UI and Docker

The web UI is the GUI frontend built with `npm run build` in `gui/`.
`mabi-patcher serve` looks for it in a `webui` folder next to the exe (see
[API.md](API.md#web-ui)). The `Dockerfile` builds both and runs
`mabi-patcher serve --host $MABI_HOST --port $MABI_PORT`. The Rust stage
copies `build.rs` and `nxl3p-shim/` too, because `build.rs` needs them.

---

## Pre-commit gate

`scripts/precommit-check.sh` refuses a commit unless these pass:

| Step | Command |
|---|---|
| Type check | `cargo check --release --bins --lib` |
| Lint (errors only) | `cargo clippy --release --bins --lib` |
| Library tests | `cargo test --release --lib` |
| Integration tests | `cargo test --release --tests` |
| GUI type check (only when files under `gui/` changed) | `npx --no-install tsc --noEmit` in `gui/` |
| GUI crate check (same condition) | `cargo check` in `gui/src-tauri` (with `--target $GUI_TARGET` if set) |

"Changed" means staged, unstaged or untracked files. The GUI steps need
`gui/node_modules`; set `SKIP_GUI_CHECK=1` to skip them.

It runs from:

- `.githooks/pre-commit`, enabled with `git config core.hooksPath .githooks`
  (`build.bat` does this);
- the Claude Code `PreToolUse` hook `.claude/hooks/check-before-commit.sh`,
  which runs it before any `git commit` command and blocks the call on
  failure.

Do not bypass it with `--no-verify`.

`.claude/hooks/session-start.sh` prepares Claude Code cloud sessions only
(`CLAUDE_CODE_REMOTE=true`): adds clippy and rustfmt, fetches and builds all
targets, and runs `npm install` in `gui/`.

---

## Tests

| Where | What | Run with |
|---|---|---|
| Library (`src/**`) | Unit tests: archive paths and salts, path safety, packing, patcher, auth, profiles, keychain, cookie import, launch, news, REST API, MCP, item and region parsers. On Linux: 56 pass, 3 ignored (a live patch test, a PMG test and a header brute-force test need real files or the network). | `cargo test --release --lib` |
| `tests/api_tests.rs` | REST API tests: 11 pass, 5 ignored. | `cargo test --release --test api_tests` |
| `tests/integration_tests.rs` | Archive round trips: 7 pass, 7 ignored. | `cargo test --release --test integration_tests` |
| `tests/legacy_pack_tests.rs` | Builds small legacy `.pack` archives and reads them back through every core reader: 5 pass. | `cargo test --release --test legacy_pack_tests` |

`cargo test --release --tests` runs the library tests and all of `tests/`.
Counts are from a Linux run at version 2.0.5; some unit tests only exist on
Windows or only off Windows.

The ignored integration and API tests need real game archives.
`tests/common.rs` sets `TEST_CORPUS` to a fixed Windows path; change it
locally to run them.

---

## Continuous integration

`.github/workflows/cli.yml` runs on pushes and pull requests to the
`mabi-patcher` branch, on `ubuntu-latest` and `windows-latest`:

1. `cargo build --release --bins`
2. `cargo test --release --lib`
3. `cargo test --release --tests` (ignored tests stay ignored)
4. Uploads `target/release/mabi-patcher[.exe]` as an artifact.

CI does not build the GUI.

---

## Version number

Set it with one command from the repository root, then rebuild:

```
set-version.bat 2.0.6              (Windows; runs scripts\set-version.ps1)
scripts/set-version.sh 2.0.6       (Linux / macOS / Git Bash)
```

Run either one with no version to print the current one. The script
changes every file that holds the number, and nothing else:

| File | Field |
|---|---|
| `Cargo.toml` | `[package] version` |
| `gui/src-tauri/Cargo.toml` | `[package] version` |
| `gui/src-tauri/tauri.conf.json` | `version` |
| `gui/package.json` | `version` |
| `gui/package-lock.json` | the two `gui` package entries |
| `Cargo.lock` | the `mabi-pack2-core` entry |
| `gui/src-tauri/Cargo.lock` | the `mabi-pack2-core` and `mabi-patcher` entries |

Everything else reads the version from those files:

- The Windows file properties of `mabi-patcher.exe` (File version and
  Product version) come from `version` in `tauri.conf.json`, which
  `tauri-build` writes into the exe's resources at build time.
- The GUI window title, the main heading and the sidebar tag ask the exe
  for its version at startup (`get_app_version`, the GUI crate's
  `CARGO_PKG_VERSION`). `gui/index.html` holds no version, and the
  `title` strings in `gui/src/locales.ts` use a `{version}` placeholder.
- `build.bat` reads `version` from `tauri.conf.json`.
- The command line's `--version` comes from the crate (`CARGO_PKG_VERSION`).

If the exe still shows an old version after a bump, the GUI crate was not
rebuilt: run `build.bat` again (or `cargo clean -p mabi-patcher` in
`gui/src-tauri`).

---

## Known issues

Problems and limits that are still in the code. Paths are relative to the
repository root.

### Build and packaging

- `src/bin/pmg_export.rs` is a login debug probe, not a PMG exporter, but is
  built and shipped with the normal binaries. A comment in `src/api.rs`
  still says `/api/v1/pmg/export` matches it.

### Archives

- The `.it` writer never encrypts file contents.
- Applying a mod, VFS edits or features to a `.pack` archive goes through the
  `.it` writer at a `.pack` path in some paths (GUI, API `mod/vfs/apply`),
  and the "salt" passed on may be a marker such as `LEGACY_PACK`.
- The desktop app's `apply_vfs_changes` does not re-check delete, rename and
  add paths itself; it relies on the List tab checking them when they are
  queued. The API's `mod/vfs/apply` does check them.

### REST API

- `extract/stream` is not actually streamed: all events are sent together
  when extraction finishes.
- Launcher routes do not save profiles; `profile/load` returns the session
  token in its response.

### Nexon login and launch

- `get_webview2_key` reads `EBWebView\Default\Local State`; Chromium-based
  WebView2 normally keeps `Local State` in `EBWebView\` itself, so the
  official-launcher import may not find the key.
- The OS keychain is only used on Windows (`src/launcher/keystore.rs`).
  There is no Linux or macOS backend yet, so there (and under Wine)
  `profiles.json` keeps session tokens in plain text. There is no file
  locking on `profiles.json`.
- The pipe only serves the launched game's PID and the stub follows its
  launcher's lifetime; both rely on `GetNamedPipeClientProcessId`,
  `CREATE_SUSPENDED` and named-object security working, which current Wine
  supports but which is only exercised on real Windows/Wine, not in CI.
- Browser cookie import cannot read Chrome 127+ app-bound (`v20`) cookies;
  use the browser login instead.

### Patcher

- With `--only` / **Patch selected**, the new manifest hash is written when
  the selected files succeed. Files that were not selected are then no
  longer compared by content on the next update, so a same-size change in
  one of them is only found by **Verify**.

### Mods

- `.mod` `[pack]` and `[api]` settings are parsed but not used when applying.
- `patch` actions do not check `original` bytes.

### GUI

- Three ProgID schemes are in use: the CLI registers "Mabinogi IT Archive",
  the GUI `mabi-pack2.*`, and the Tauri bundle `mabi-patcher.archive`.
- The GUI exe's archive command line lists `--extract-all` as a known
  command with no definition; `--auto-dds`, `--additional_data` and `-c` have
  no effect.
- `get_managed_version` sends the manifest build time to a third-party
  server over plain HTTP.
- The Mods tab reads the website catalogue out of the site's minified
  JavaScript bundle (`fetch_web_mods_catalog`), because the site has no JSON
  list. A change to the site's build can break it.

### List tab editing

- Dragging files out of the window relies on WebView2 keeping mouse capture
  while the pointer leaves the window; it is Windows only.
- **Extract Selected To…** (and drag-out) overwrites existing files in the
  target folder without asking.
- Pending moves and adds show at their new place in the tree only after the
  changes are applied (deletes and renames are marked on the existing rows;
  adds are listed at the bottom).
- Merge conflict decisions are matched against the extracted file paths of
  the source archive. For a `.pack` source these may not match the names the
  dialog showed, so a skip or rename can be missed.

### Previews

- The region map, 3D world view and item search work only for files inside
  open archives, and only in the desktop app (not for loose files or in the
  web UI).
- 3D world terrain is shaded by height only, not coloured by its textures.
- Prop names and models need a plain-text `propdb.xml`; current clients ship
  it encoded, so props show as markers without names.
- The older `src/rgn.rs` and `src/area.rs` readers decode an assumed layout
  that does not match real files. They are kept as the fallback preview
  (web UI, loose files); the map uses `src/region_map.rs`.
