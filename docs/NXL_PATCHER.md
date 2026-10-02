# NXL Patcher

How mabi-patcher updates and repairs a Mabinogi NA install from Nexon's NXL
CDN, without the Nexon Launcher.

Source: `src/launcher/patch.rs` (used by the CLI, GUI, API and MCP).

The paths below use product `10200` (Mabinogi), the default. `--product-id`
(CLI), `product_id` (API) or Settings → Patcher → Advanced → Product ID (GUI)
replaces it everywhere, including the hash file name.

---

## Overview

```
1. GET /game-build/v1/branch/games/10200/public   (needs a session) → manifestUrl
2. GET manifestUrl                                  → manifest hash (text)
3. GET http://download2.nexon.net/Game/nxl/games/10200/<hash>   → zlib JSON manifest
4. Scan the install against the manifest            → list of files to fetch
5. For each file: GET its parts, unzip, SHA1-check, join in order, swap in
6. All files OK → write patchdata/10200.manifest.hash
```

A Nexon session is required. The public `10200.manifest.hash` on the CDN is
an old manifest (the code calls it "a stale 2014 manifest"); patching
against it would downgrade files, so the patcher refuses to run without a
session: `Log in first — the current game manifest is only available with a
Nexon session.` A `401` on the branch call refreshes the session once (see
[NEXON_AUTH.md](NEXON_AUTH.md#the-401-retry)).

---

## Install layout

`GameRoots::resolve(path)` accepts the install folder, `appdata`,
`patchdata` or `Client.exe`, and works out:

| Field | Rule |
|---|---|
| `install_root` | The given folder; its parent if the folder is named `appdata` or `patchdata`; the exe's folder for a `.exe`. |
| `appdata` | `install_root\appdata` if it exists, else `install_root`. |
| `patchdata` | `install_root\patchdata` if it exists, or if `appdata\patchdata` does not; otherwise `appdata\patchdata`. |
| Client | `appdata\Client.exe` |

Manifest paths are relative to the **content root**: `install_root` when more
than half of the manifest paths start with `appdata\`, otherwise `appdata`.

The installed version is the text in `patchdata\10200.manifest.hash`. The
compressed manifest for that hash is kept as `patchdata\<hash>`.

---

## Manifest

The manifest is zlib-compressed JSON (the code also accepts raw deflate after
a 2-byte header):

```json
{
  "buildtime": 1700000000.0,
  "files": {
    "<base64 of UTF-16LE path>": {
      "fsize": 123456,
      "mtime": 1700000000,
      "objects": ["<sha1 of part 0>", "<sha1 of part 1>"],
      "objects_fsize": [40000, 12000]
    }
  }
}
```

| Item | Meaning |
|---|---|
| Key | Base64 of the UTF-16LE path. A leading BOM and trailing control characters and spaces are removed; `\` is turned into the native separator. |
| `fsize` | Decompressed file size. |
| `mtime` | Unix time; set on the file after it is written. |
| `objects[i]` | SHA-1 of decompressed part `i`. Every part is 4 MiB (`PART_SIZE`) except the last. |
| `objects_fsize[i]` | Compressed size of part `i` (not used to split the file). |
| `objects[0] == "__DIR__"` | A folder entry; skipped. |
| Entries with no `objects` | Skipped. |

Parts are downloaded from:

```
https://download2.nexon.net/Game/nxl/games/10200/10200/<first 2 chars of hash>/<hash>
```

---

## Modes

`PatchMode` decides why a file is fetched. The scan runs in parallel
(rayon) and checks each file in this order:

| Reason | When |
|---|---|
| `Re-download` | Mode is `ForceAll`. |
| `New` | The file is missing. |
| `Size changed` | Size on disk differs from `fsize`. |
| `Content changed` | Mode is `Update`, the installed manifest differs from the new one, and this file's `objects` list changed. This catches same-size changes. |
| `Content changed` | Mode is `Verify` and reading the file in 4 MiB parts gives a SHA-1 that does not match `objects`. |

| Mode | CLI | API `mode` | GUI |
|---|---|---|---|
| `Update` | default | `update` (default) | Patch |
| `Verify` (repair) | `--verify` | `verify` | Verify |
| `ForceAll` | `--force-all` | `force_all` or `force` | Force repair (Settings → Patcher) |

**Scan only** (`--scan-only`, API `scan_only`) stops after the scan and
returns the list without downloading. The CLI prints `size  reason  path`
for each file and exits 2 if anything needs updating. `patch::scan` is the
same scan as a function; it backs `POST /api/v1/launcher/update/scan`, the
MCP tool `scan_update` and the GUI's **Choose files…** dialog.

**Ignore list.** Files matching any ignore pattern are neither scanned nor
touched. The CLI combines `--ignore` with the saved `config ignore` list.
Patterns use `*` and `?`, ignore case, and match the whole path or, for a
pattern without `/`, just the file name.

**Up to date.** If nothing needs fetching, the new hash is written and the
result says `up_to_date`.

### Choosing files

`PatchOptions::only` is an allow-list of manifest paths (CLI `--only` and
`--select`, API and MCP `only`, GUI **Choose files…** then **Patch
selected**). Only listed files are scanned and fetched; matching ignores
case and treats `\` and `/` alike, and the ignore list still applies.

The hash rule below does not change: when every selected file succeeds,
the new manifest hash is written. Files you did not select are then no
longer compared by `objects` on the next `Update` run, so a same-size change
in one of them is only found by `Verify`.

### Several installs

`patch::check_folders` compares several game folders with the current
manifest. It fetches the remote hash once and returns, per folder,
`{ path, local_hash, remote_hash, update_available, error }`. Callers: CLI
`check-update --folder/--all-folders`, `update --folder/--all-folders` (which
patches each folder in turn), API `POST /api/v1/launcher/folders/check`,
MCP `check_folders`, and the GUI's **Check all installs** buttons on the
Patcher and Launcher tabs. `--all-folders` uses `detect::find_all_game_exes`:
the Nexon Launcher's `appconfig.json`, Windows uninstall entries and the
usual install folders on every drive.

---

## Downloads

| Setting | Value | Where |
|---|---|---|
| Files at once | `max_workers`: default 8, clamped to 1–32 (`MAX_WORKERS`) | CLI `-j`, API `max_workers`, GUI option |
| Parts per file at once | 4 (`PARTS_PER_FILE`) | constant |
| Total HTTP requests at once | `max_workers × 2` (16 by default) | `Limiter` |
| Attempts per part | 3 (`PART_RETRIES`), waiting 1 s then 2 s between tries | constant |
| HTTP timeout | 180 s per request; up to 64 idle connections per host | `CDN` client |

Each worker takes the next file from a shared queue. For each file:

1. Fetch parts in groups of four, each in its own thread and each holding one
   limiter slot while its request runs.
2. Unzip each part and compare its SHA-1 with the part name; a mismatch counts
   as a failed attempt.
3. Write the parts in order to `<file>.~nxlpatch`.
4. Check the joined size equals `fsize`.
5. Clear the read-only flag on the old file, rename the temp file over it,
   and set its modified time to `mtime`.

On any error the temp file is deleted and the error is recorded as
`<path>: <error>`; other files carry on. A permission error sets
`needs_elevation`.

Each file is written under the content root with `common::safe_join`.
Manifest entries whose path is absolute, has a drive prefix or contains
`..` are skipped when the manifest is parsed (logged as `skipping manifest
entry`).

### Pause

Pausing is a second shared flag next to the cancel flag (GUI **Pause** /
**Resume**: `patch_pause`, `patch_resume`; API `POST
/api/v1/launcher/update/pause` and `/resume`; MCP `update_pause`,
`update_resume`). While it is set, the scan waits and each worker finishes
the file it is on, then waits before taking the next one. Cancelling also
ends a pause.

### Cancel and resume

Cancellation is a shared flag (CLI: none; GUI Stop button: `patch_cancel`;
API: `POST /api/v1/launcher/update/cancel`). Workers stop taking new files and
a file in progress stops before its next group of parts.

The new manifest hash is written **only** when every file succeeded and the
run was not cancelled. Otherwise the old hash stays, so the next run scans
again and picks up the remaining files (`Cancelled — hash not updated, will
resume on next update.`).

### Progress events

`run_patcher` reports through `PatchEvent` (JSON tag `kind`):

| Event | Fields | When |
|---|---|---|
| `log` | `message` | Status lines. |
| `scan` | `done, total, need, file` | Every 250 files and at the end of the scan. |
| `download` | `files_done, files_total, bytes, bytes_total, speed_bps, file` | After each finished file. `bytes` counts whole file sizes. |
| `worker` | `worker_id, phase, file, parts_done, parts_total` | Per worker: `downloading`, `done`, `error`. |

The GUI turns these into `patch-progress` (scan = first 10 %, download =
remaining 90 %, at most about 10 per second) and `patch-worker` events.

### Result

`PatchResult`:

| Field | Meaning |
|---|---|
| `manifest_hash` | The manifest patched against. |
| `buildtime` | From the manifest. |
| `need` | List of `{ path, size, local_size (-1 = missing), reason }`. |
| `patched` | Files written. |
| `errors` | `"<path>: <error>"` strings. |
| `cancelled` | Run was cancelled. |
| `needs_elevation` | A permission error happened. |
| `up_to_date` | Hash was written. |

---

## GUI extras

`gui/src-tauri/src/lib.rs` adds a few commands around the patcher:

| Command | What it does |
|---|---|
| `patch_game_files` | Runs the patcher with the mode, workers, ignore list, `only` list and hooks from the Patcher tab. |
| `patch_scan` | The scan for **Choose files…**. |
| `patch_check_all_installs` | **Check all installs**: detected installs plus any extra folders, with the folder holding `Client.exe` for each. |
| `patch_pause`, `patch_resume`, `patch_cancel` | Pause, Resume and Stop. |
| `check_patch_version` | Local and remote hash, plus a "managed version" number for each. |
| `verify_game_files` | Size-only check of every file against the installed manifest; returns up to 50 missing and 50 mismatched paths. Reads `appdata\version.dat` for the local version. |
| `repair_game_files` | Starts `MabiTDown.exe /repair` if present in the game folder, else the first `NGMDll.exe` found under `Program Files\Nexon`, else falls back to `verify_game_files`. |
| `clear_patch_cache` | Deletes `patchdata\Patch`. |

The "managed version" is looked up by sending the manifest `buildtime` to an
external service over plain HTTP (`get_managed_version`, posting
`Action=CV&buildtime=...` to `theproffessorslaboratory.net/api.php`). If that
fails the number is missing or `0`.

---

## Notes

- `Verify` reads every file in full, so it is much slower than `Update`.
- `check-update` only compares hashes; it does not download the manifest.
