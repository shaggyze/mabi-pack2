# mabi-patcher REST API

`mabi-patcher serve` runs a small HTTP server that exposes archive, mod and
launcher operations as JSON routes, and serves the built web UI from the same
port. The web UI is the desktop frontend (`gui/`) pointed at this API instead
of Tauri IPC (`gui/src/platform/webApi.ts`).

Source: `src/api.rs`. Server library: `tiny_http`.

```
mabi-patcher serve [--host 127.0.0.1] [--port 7331]
```

---

## Basics

| Item | Value |
|---|---|
| Default address | `http://127.0.0.1:7331` (`DEFAULT_PORT = 7331`) |
| Route prefix | `/api/v1/` |
| Request body | JSON, for every `POST` route |
| Query string | Ignored when matching routes; read only by the `GET` routes listed below |
| Concurrency | One request at a time. The server handles each request to completion before reading the next. `launcher/update` is the only job that runs in the background. |
| Where it runs | `mabi-patcher serve`, `mabi-patcher.exe serve` (the desktop exe, no window), inside the desktop app when Settings → Engine → "Run the REST API while the app is open" is on (always `127.0.0.1`, port from the settings), and on a random loopback port for the MCP server. |

### Response envelope

Every JSON route answers with the same shape:

```json
{ "success": true,  "data": { ... }, "error": null }
{ "success": false, "data": null,    "error": "message" }
```

The tables below describe `data`. Error status codes are `400` for a missing
or invalid field, `404` for unknown routes or missing things, `500` for
operation failures, plus the launcher codes in
[Launcher errors](#launcher-errors).

Exception: `POST /api/v1/extract/stream` answers with `text/event-stream`.

### CORS

Every response carries `Access-Control-Allow-Origin: *`,
`Access-Control-Allow-Methods: GET, POST, OPTIONS` and
`Access-Control-Allow-Headers: Content-Type, Authorization`. `OPTIONS`
requests get an empty `204`, before any auth check.

---

## Security

`check_auth` in `src/api.rs` runs before routing.

1. **Origin check (always).** If the request has an `Origin` header, it must be
   `http://<Host header>`, `https://<Host header>`, or start with `tauri://`.
   Anything else gets `403 Cross-origin requests are not allowed`, whatever the
   bind address. This stops other web pages in your browser from calling the
   API on localhost.
2. **Loopback is open.** If the server was started with `--host` `127.0.0.1`,
   `localhost` or `::1`, no token is needed.
3. **Any other bind needs a token.**
   - If `MABI_API_TOKEN` is unset or empty, every request gets `503`
     (`MABI_API_TOKEN must be set when the API is bound to a non-loopback address`).
   - Otherwise the request must send `Authorization: Bearer <MABI_API_TOKEN>`,
     else `401`.

Note: the check is on the bind address, not on where the request came from.
A server bound to `0.0.0.0` needs the token even for requests from the same
machine.

Paths in request bodies are paths on the server's own disk. Most routes read
and write wherever they are told to (archives, output folders, game
folders). Only expose the server beyond loopback with a token you trust.
`/api/v1/mod-file` is the exception: it only reads files inside the `mods`
folder (see [Mods](#mods)).

### Environment variables

| Variable | Meaning |
|---|---|
| `MABI_API_TOKEN` | Bearer token. Required for non-loopback binds. |
| `MABI_WEBUI_DIR` | Folder holding the built web UI (`gui/dist`). |
| `MABI_HOST`, `MABI_PORT` | Read only by the Docker `ENTRYPOINT`, which passes them to `--host`/`--port`. The binary itself does not read them. |

### Stopping the server

In an interactive terminal, `serve` stops when you press Enter
(`ctrlc_handler` in `src/bin/mabi-pack-cli.rs`). When standard input is not a
terminal (Docker, a service, a pipe) it keeps running until the process is
stopped.

---

## Web UI

Any `GET` whose path does not start with `/api/` is served from the web UI
folder, found in this order:

1. `MABI_WEBUI_DIR`, if it is a folder;
2. a `webui/` folder next to the running executable;
3. `gui/dist` relative to the current folder.

`/` serves `index.html`. A path that is not a file also falls back to
`index.html` (single-page app routing). A path with a `..` segment gets `400`.
If no folder is found the answer is `404` with a hint to run `npm run build`
in `gui/`.

---

## Routes

### Status and helpers

| Method | Path | Body / query | `data` |
|---|---|---|---|
| GET | `/api/v1/status` | — | `{ app: "mabi-patcher", version, api: "v1", port }`. `port` is the port the server is actually bound to. |
| GET | `/api/v1/salts` | — | Array of known salt strings (see [PACK_FORMAT.md](PACK_FORMAT.md#salts)). |
| POST | `/api/v1/fs/check-data-folder` | `{ path }` | `{ has_data_folder }`: true if `path` is named `data` or has a `data` subfolder. |
| GET | `/api/v1/mabi-version` | — | Windows only. Reads `HKLM\SOFTWARE\WOW6432Node\Nexon\Mabinogi` or `HKLM\SOFTWARE\Nexon\Mabinogi`: `{ installed_version, client_dir, registry_key }`. `404` if not found, `501` on other systems. |

### Archives

| Method | Path | Body | `data` |
|---|---|---|---|
| POST | `/api/v1/extract` | `{ archive, output, key?, filters?: [regex], auto_convert_png?, auto_convert_features?, auto_convert_pmg? }` | `{ archive, output, salt_used }`. `salt_used` is the salt that opened the archive, or `LEGACY_MABI`, `LEGACY_PACK` or `LOGUE_PACK` for legacy packs. |
| POST | `/api/v1/extract/stream` | Same as `extract` without the `auto_convert_*` flags. | Server-sent events: `progress` (`{done,total,pct,name}`) then `done` (`{success:true,salt}`) or `error` (`{success:false,error}`). All events are sent together when extraction finishes, not live. |
| POST | `/api/v1/pack` | `{ source, output, key, formats?: [ext], iv?, path_prefix?, wrap_data?, auto_convert_dds?, pack_v1_version? }` | `{ source, output, format }` where `format` is `it` or `pack_v1`. `key` is required even for `.pack`. An output ending in `.pack` writes a legacy pack with header version `pack_v1_version` (default `999`). `path_prefix` wins over `wrap_data` (which means `data`). `auto_convert_dds` turns `.png` files into DXT5 `.dds` entries. |
| POST | `/api/v1/list` | `{ archive, key? }` | `{ archive, count, entries: [{ name }] }` |
| POST | `/api/v1/convert` | `{ input, output, key?, wrap_data? }` | `{ input, output }`. Converts between `.it` and `.pack` (same as the CLI `convert`, but `wrap_data` defaults to `false`). |
| POST | `/api/v1/preview` | `{ archive, entry_name, key? }` | See [Preview](#preview). |
| POST | `/api/v1/pmg/export` | `{ archive, entry_name, key?, output?, group?: integer, no_colors?, no_transform? }` | With `output`: writes an OBJ file, `{ output, bytes }`. Without: `{ obj, bytes }` with the OBJ text inline. |
| POST | `/api/v1/patch/create` | `{ base_dir, modified_dir, output, key, iv? }` | `{ base_dir, modified_dir, output }`. Packs every file in `modified_dir` that is new or whose MD5 differs from `base_dir` into `output`. Fails if nothing differs. Works in a new, uniquely named folder under the system temp folder and deletes only that folder. |

#### Preview

`/api/v1/preview` reads one entry and returns:

```json
{
  "name": "...", "size": 0, "raw_size": 0, "offset": 0, "checksum": 0, "flags": 0,
  "file_type": "image|text|mml|pmg|rgn|area|set|audio|binary|gm|anievent|unknown|error",
  "content_text": "...", "content_image": "<base64>", "raw_bytes": [ ... ],
  "source": "<archive file name>", "salt": "<key or 'Search/Default'>",
  "full_preview_size": 0, "truncated": false,
  "pmg_geometry": { ... }, "rgn_data": { ... }, "area_data": { ... }
}
```

| `file_type` | Filled fields |
|---|---|
| `image` (`.dds .png .jpg .bmp`) | `content_image` (base64). |
| `text` (`.xml .txt .data .csh .eff`), `mml` | `content_text`, first 32 KiB. |
| `pmg` | `pmg_geometry`: `positions, normals (empty), uvs, indices, mesh_name, texture_name, vertex_count, face_count, vertex_colors, avg_color`, from the LOD with the most vertices. |
| `rgn` | `rgn_data`. |
| `area` | `area_data`. |
| `set` | `content_text` with frame, bone and duration counts from the header. |
| `audio` (`.wav .mp3 .ogg .nxa`) | `raw_bytes` up to 8 MiB. IMA ADPCM `.wav` up to 2 MiB is converted to PCM first. |
| `binary` `.compiled` | Converted to `text` when it decodes as compiled XML. |

`raw_bytes` is otherwise capped at 32 KiB (and empty for `pmg`, `rgn`, `mml`).

### Mods

| Method | Path | Body / query | `data` |
|---|---|---|---|
| GET | `/api/v1/mods` | — | `{ dir, count, mods: [{ file, name, version, author, tags, public, files, error }] }` from the `mods` folder next to the executable. |
| GET | `/api/v1/mod-template` | — | `{ template }` (TOML text). |
| GET | `/api/v1/mod-file` | `?path=` | `{ path, content }`: the raw text of a file in the `mods` folder. `path` is a name or relative path inside that folder, or an absolute path that resolves inside it. Anything else (`..`, a path outside, a folder) gets `403`. |
| POST | `/api/v1/mod/apply` | `{ mod_toml (or mod), archive, key?, mod_dir? }` | `{ name, version, archive, replaced, deleted, patched, skipped, status: "applied" }`. See [GUI.md](GUI.md#mods) for the `.mod` format. `mod_dir` resolves relative `source` paths (default: the system temp folder). |
| POST | `/api/v1/mod/vfs/apply` | `{ archive, key?, changes: [change] }` | `{ archive, changes, stats: { deleted, renamed, added, merged } }`. Every `path`, `from`, `to` and `dest` is checked with `validate_entry_path` (see [CLI.md](CLI.md#pack)) and must stay inside the archive; a bad one fails the request with `500`. |
| POST | `/api/v1/mod/pending/save` | `{ archive, changes: [...] }` | `{ archive, count }`. Writes `<archive>.pending.json`; an empty list deletes it. |
| GET | `/api/v1/mod/pending` | `?archive=` | `{ archive, changes }` (empty list when there is no file). |

`changes` items for `mod/vfs/apply` (tagged by `op`):

| `op` | Fields | Effect |
|---|---|---|
| `delete` | `path` | Remove the entry. |
| `rename` | `from`, `to` | Move an entry. |
| `add` | `dest`, `local_src` | Copy a file from the server's disk into the archive. |
| `merge` | `src_archive`, `src_key?` | Copy every entry of another archive in, overwriting. |

`.mod` `archive_path` values are checked the same way when the mod is
parsed, so a mod cannot write outside the archive tree.

`mod/apply`, `mod/vfs/apply` and `features/save` all extract the whole
archive to a temporary folder, change it, and repack it over the original
with the key given or the salt that opened it.

### features.xml

| Method | Path | Body | `data` |
|---|---|---|---|
| POST | `/api/v1/features/get` | `{ archive, key? }` | The parsed `features.xml.compiled` as JSON (`404` if the archive has none). |
| POST | `/api/v1/features/save` | `{ archive, key?, features_json: "<JSON string>" }` | `{ archive, features, servers, bytes, status: "saved" }`. Encodes the JSON back to the binary format and repacks the archive. |

### Launcher

These routes are stateless: they take a session in the body and return the
(possibly refreshed) session. They do **not** read or write saved profiles,
except the `profile/*` routes. See [NEXON_AUTH.md](NEXON_AUTH.md) for the
flow.

A `session` object has this shape (`NexonSession` in
`src/launcher/auth.rs`):

```json
{
  "access_token": "<AToken>", "g_access_token": "<g_AToken>",
  "session_token": "<NxLSession>", "hashed_user_id": "<NexonUserID>",
  "nx_gun": "", "id_token": "", "tpa": false
}
```

| Method | Path | Body | `data` |
|---|---|---|---|
| POST | `/api/v1/launcher/login` | `{ email (or username), password, device_id?, profile? }` | `{ session, expiresIn }`, or `{ mfa_required: true, mfa_key, mfa_type }`, or `{ captcha_required: true, code, message }`. |
| POST | `/api/v1/launcher/login/otp` | `{ mfa_key, otp, device_id?, profile? }` | `{ session, expiresIn }` |
| POST | `/api/v1/launcher/login/tpa` | `{ tpa_session, device_id?, profile? }` | `{ session, expiresIn }` (browser/SSO login; see [NEXON_AUTH.md](NEXON_AUTH.md#browser-login-tpa)). |
| POST | `/api/v1/launcher/autologin` | `{ session_token }` | `{ session, expiresIn }` |
| POST | `/api/v1/launcher/session/check` | `{ session }` | `{ valid, status, refreshed, session }`. Refreshes once on 401. |
| POST | `/api/v1/launcher/passport` | `{ session }` | `{ passport, session }` (runs the full pre-launch chain). |
| POST | `/api/v1/launcher/maintenance` | `{ session }` | `{ maintenance }` |
| POST | `/api/v1/launcher/version` | `{ session }` | `{ version, manifest_url, session }` |
| POST | `/api/v1/launcher/update/check` | `{ game_path, session?, product_id? }` | `{ check: { local_hash, remote_hash, update_available }, roots: { install_root, appdata, patchdata }, session }`. Without a valid session it fails, because the current manifest needs one. |
| POST | `/api/v1/launcher/update` | `{ game_path, session?, mode?: "update"\|"verify"\|"force_all"\|"force", max_workers?, ignore?: [pattern], only?: [path], scan_only?, profile?, product_id? }` | `{ started: true }`. Starts a background job; `409` if one is already running. `max_workers` (default 8) is clamped to 1–32. `only` limits the run to those manifest paths. Unless `scan_only` is set, the shared `before_patch` hook runs first and `after_patch` runs after a run with no errors that was not cancelled; `%PROFILE%` becomes `profile`. |
| GET | `/api/v1/launcher/update/status` | — | `{ running, log: [..], files_done, files_total, bytes, bytes_total, speed_bps, scan_done, scan_total, result, error, session }`. `result` is the patch result (see [NXL_PATCHER.md](NXL_PATCHER.md#result)). |
| POST | `/api/v1/launcher/update/cancel` | — | `{ cancelling }` (true if a job was running). |
| POST | `/api/v1/launcher/update/pause` | — | `{ paused }` (true if a job was running). Workers finish the file they are on, then wait. |
| POST | `/api/v1/launcher/update/resume` | — | `{ resumed }` (true if a job was running). |
| POST | `/api/v1/launcher/update/scan` | `{ game_path, session?, mode?, ignore?, only?, product_id? }` | `{ roots, need: [{ path, size, local_size, reason }], session }`. Lists the files that need updating without downloading (`patch::scan`). |
| POST | `/api/v1/launcher/folders/check` | `{ folders?: [path], all_folders?, session?, product_id? }` | `{ folders: [{ path, local_hash, remote_hash, update_available, error? }], session }`. `all_folders: true` adds every auto-detected install. `400` if no folder is given. The remote hash is fetched once for all folders. |
| GET | `/api/v1/launcher/config` | — | The shared patcher settings: `{ ignore: [...], hooks: { before_patch, after_patch, before_launch, after_launch } }` (empty hooks are left out). |
| POST | `/api/v1/launcher/config` | `{ ignore?, hooks? }` | The saved settings. Fields left out keep their value. Same file as the CLI `config` and the desktop app (see [SESSION.md](SESSION.md#patcher-settings-configjson)). |
| POST | `/api/v1/launcher/import/cookies` | `{ device_id?, profile? }` | `{ session, browser, v20_found, notes, imported }`. Reads a Nexon session from Firefox, Chrome, Edge or Brave (see [NEXON_AUTH.md](NEXON_AUTH.md#browser-cookie-import)). `imported` is false when nothing usable was found; `v20_found` means Chrome 127+ cookies were seen but cannot be decrypted. Does not save a profile. |
| GET | `/api/v1/launcher/news` | `?product_id=` | `{ items: [{ id, category, title, summary, url, date, image, maintenance }] }`. Public feed, no session. `502` if the feed cannot be fetched. |
| POST | `/api/v1/launcher/launch` | `{ session, client_exe \| client_dir \| game_path, product_id? }` | `{ pid, executable, argumentCount, patchAvailable, sessionExpiresIn, session }`. Does not wait for the game to exit. |

`device_id` overrides the device id; otherwise it is derived from the machine
and the optional `profile` string (see
[NEXON_AUTH.md](NEXON_AUTH.md#device-id)).

`product_id` sets the Nexon product for the rest of the server process (see
[CLI.md](CLI.md#launcher-commands)); `0` means the default `10200`.

#### Profiles

| Method | Path | Body | `data` |
|---|---|---|---|
| GET | `/api/v1/launcher/profiles` | — | `{ profiles: [summary] }`. Summaries have no tokens. |
| POST | `/api/v1/launcher/profile/save` | `{ name, email, client_dir?, auto_login?, id? }` | `{ id }`. Creates a profile, or updates the one with `id`. |
| POST | `/api/v1/launcher/profile/delete` | `{ id }` | `{ deleted }` |
| POST | `/api/v1/launcher/profile/activate` | `{ id }` | `{ activated }` |
| POST | `/api/v1/launcher/profile/load` | `{ id }` | The profile summary. If `auto_login` is on and the session has not expired, it also includes `session_token_for_autologin` (the NxLSession token). |
| POST | `/api/v1/launcher/profile/session` | `{ id, session_token, expires_in? }` | `{ updated: true }` |

A summary has `id, name, email, client_dir, auto_login, has_session,
session_valid, created_at, last_login_at, profile_type, login_ip, login_port,
chat_ip, chat_port, is_official`.

#### Launcher errors

`auth_err` in `src/api.rs` maps login and launch errors:

| Condition | Answer |
|---|---|
| 2FA needed | `200`, `data.mfa_required = true` |
| CAPTCHA needed | `200`, `data.captcha_required = true` |
| Session expired and refresh failed | `401` |
| Device verification needed (Nexon code 20027) | `403` |
| Game not playable (maintenance, region block, HTTP 400 from playable) | `503` |
| Anything else | `500` |

---

## Examples

```sh
# Status
curl -s http://127.0.0.1:7331/api/v1/status

# List an archive
curl -s -X POST http://127.0.0.1:7331/api/v1/list \
  -H 'Content-Type: application/json' \
  -d '{"archive":"C:/Nexon/Library/mabinogi/appdata/package/data_00000.it"}'

# Log in (password from the environment)
curl -s -X POST http://127.0.0.1:7331/api/v1/launcher/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$MABI_EMAIL\",\"password\":\"$MABI_PASSWORD\"}"

# Non-loopback server: send the token
curl -s -H "Authorization: Bearer $MABI_API_TOKEN" http://192.168.1.10:7331/api/v1/status
```

---

## Docker

`Dockerfile` builds the web UI and the CLI and runs
`mabi-patcher serve --host ${MABI_HOST} --port ${MABI_PORT}` with
`MABI_HOST=0.0.0.0` and `MABI_PORT=7331`. The web UI is copied to
`/usr/local/bin/webui`, which matches the "next to the executable" rule.
`docker-compose.yml` refuses to start unless `MABI_API_TOKEN` is set, maps
port 7331, mounts archives at `/data/archives` (read-only) and `./mods` at
`/data/mods`, and health-checks `/api/v1/status` with the token.

