# MCP Server

mabi-patcher has a built-in [Model Context Protocol](https://modelcontextprotocol.io)
server, so an AI client (Claude Code, Claude Desktop and others) can list,
extract, pack, mod, patch and launch through the same binary. There is no
separate server to install.

Source: `src/mcp.rs`. Entry points: `src/bin/mabi-pack-cli.rs` (CLI) and
`gui/src-tauri/src/main.rs` (GUI exe) both call `mcp::run_if_requested()`.

`src/mcp.rs` replaces the older Python `mcp_server/` folder, which has been
removed.

---

## Running it

```
mabi-patcher mcp
```

The GUI exe accepts the same argument (`mabi-patcher.exe mcp`).

Register it with Claude Code:

```
claude mcp add mabi-patcher -- /path/to/mabi-patcher mcp
```

For other clients, configure a stdio server whose command is the
mabi-patcher binary and whose only argument is `mcp`.

---

## How it works

| Aspect | Behaviour |
|---|---|
| Transport | JSON-RPC 2.0 over stdin/stdout, one message per line. Batches (JSON arrays) are accepted. |
| Logging | Warnings and errors go to **stderr** only; stdout carries the protocol. |
| Backend | On start, `api::spawn_ephemeral()` binds the REST API (see [API.md](API.md)) to `127.0.0.1` on a random free port in a background thread. Every tool is a call to that API. |
| Lifetime | Runs until stdin closes. Exit code 0, or 1 with `mcp: <error>` on stderr. |
| Protocol version | Echoes the client's `protocolVersion`; default `2025-06-18`. |
| Server info | `name: mabi-patcher`, `version`: the crate version. |
| Capabilities | `tools` only. |

| Method | Response |
|---|---|
| `initialize` | Protocol version, capabilities, server info. |
| `ping` | `{}` |
| `tools/list` | Every tool with a JSON Schema built from its parameter table. |
| `tools/call` | See below. |
| Notifications (no `id`) | No response. |
| Anything else | Error `-32601` (`Method not found`). |
| Line that is not JSON | Error `-32700` with `id: null`. |

### Tool results

A `tools/call` result has one text item holding pretty-printed JSON:

```json
{ "status": 200, "result": { ...API response body... } }
```

`isError` is `true` when the API answered with HTTP 400 or above, or when the
call failed before reaching the API (unknown tool, no profile, and so on;
the text is then the error message).

### Sessions and profiles

Tools fall into four kinds (`Kind` in `src/mcp.rs`):

| Kind | Request | Extra handling |
|---|---|---|
| `Get` | `GET` with the arguments as a query string | none |
| `Post` | `POST` with the arguments as the JSON body | none |
| `Session` | `POST` | If no `session` argument is given, the session is loaded from the profile named by `profile` (name, id or email), else the active profile (`cli::profile_session`). If `game_path` is missing, the profile's `client_dir` is used. |
| `Login` | `POST` | A returned session is saved to a profile with `cli::store_session` (same rules as the CLI `login`; see [SESSION.md](SESSION.md#choosing-a-profile)). |

After a successful call, if the response contains a `session` (a login, or a
session that was refreshed after a `401`), it is written back to the profile,
with `expiresIn` as its lifetime. The result then has
`session_saved_to_profile: "<name>"`, or `session_not_saved: "<reason>"`.

**Secrets never reach the model.** Before a result is returned, these fields
are removed at every depth of the JSON (`SECRET_FIELDS`):

`session`, `session_token`, `sessionToken`, `access_token`, `accessToken`,
`passport`, `id_token`, `nx_gun`.

Note that `nexon_login` still takes the account password as a tool argument,
so it passes through the AI client. Use the CLI `login` (with `MABI_EMAIL` /
`MABI_PASSWORD`) if you would rather not do that; the MCP tools then use the
saved session.

---

## Tools

Common parameters:

| Parameter | Meaning |
|---|---|
| `archive` | Path to a `.it` or `.pack` archive (required where listed). |
| `key` | Archive salt; omit to auto-detect. |
| `profile` | Saved profile name, id or email; default the active profile. |
| `game_path` | Mabinogi install folder; default the profile's folder. |

Required parameters are in **bold**. "API route" is the REST route the tool
calls; see [API.md](API.md) for the full request and response.

### Archives

| Tool | API route | Parameters |
|---|---|---|
| `status` | `GET /api/v1/status` | none |
| `list_archive` | `POST /api/v1/list` | **archive**, key |
| `extract` | `POST /api/v1/extract` | **archive**, **output**, key, filters (regular expressions), auto_convert_png, auto_convert_pmg, auto_convert_features |
| `pack` | `POST /api/v1/pack` | **source**, **output**, key, formats (extra extensions to compress; the output format follows the output file's extension), iv, path_prefix, wrap_data, auto_convert_dds, pack_v1_version |
| `preview` | `POST /api/v1/preview` | **archive**, **entry_name**, key |
| `convert` | `POST /api/v1/convert` | **input**, **output**, key, wrap_data |
| `pmg_export` | `POST /api/v1/pmg/export` | **archive**, **entry_name**, **output**, key, group, no_colors, no_transform |
| `salts` | `GET /api/v1/salts` | none |
| `check_data_folder` | `POST /api/v1/fs/check-data-folder` | **path** |
| `mabi_version` | `GET /api/v1/mabi-version` | none |

### Mods and patches

| Tool | API route | Parameters |
|---|---|---|
| `list_mods` | `GET /api/v1/mods` | none |
| `mod_template` | `GET /api/v1/mod-template` | none |
| `read_mod_file` | `GET /api/v1/mod-file` | **path** (a file in the `mods` folder; anything else is refused with `403`) |
| `apply_mod` | `POST /api/v1/mod/apply` | **archive**, key, mod_toml (TOML text; `mod` is an alias), mod_dir |
| `apply_vfs_changes` | `POST /api/v1/mod/vfs/apply` | **archive**, **changes**, key |
| `save_pending_changes` | `POST /api/v1/mod/pending/save` | **archive**, **changes** |
| `load_pending_changes` | `GET /api/v1/mod/pending` | **archive** |
| `get_features` | `POST /api/v1/features/get` | **archive**, key |
| `save_features` | `POST /api/v1/features/save` | **archive**, **features_json**, key |
| `create_patch` | `POST /api/v1/patch/create` | **base_dir**, **modified_dir**, **output**, key, iv |

### Nexon login and session

| Tool | Kind | API route | Parameters |
|---|---|---|---|
| `nexon_login` | Login | `POST /api/v1/launcher/login` | **email**, **password**, profile. May answer `mfa_required` (then call `nexon_login_otp`) or `captcha_required`. |
| `nexon_login_otp` | Login | `POST /api/v1/launcher/login/otp` | **mfa_key**, **otp**, email (names the profile), profile |
| `nexon_login_tpa` | Login | `POST /api/v1/launcher/login/tpa` | **tpa_session**, profile |
| `import_cookies` | Login | `POST /api/v1/launcher/import/cookies` | profile. Imports a session from Firefox, Chrome, Edge or Brave and saves it to a profile; `v20_found` means Chrome 127+ cookies could not be read (see [NEXON_AUTH.md](NEXON_AUTH.md#browser-cookie-import)). |
| `nexon_session_check` | Session | `POST /api/v1/launcher/session/check` | profile |
| `nexon_maintenance` | Session | `POST /api/v1/launcher/maintenance` | profile |
| `nexon_version` | Session | `POST /api/v1/launcher/version` | profile |

### Patching and launching

| Tool | Kind | API route | Parameters |
|---|---|---|---|
| `check_update` | Session | `POST /api/v1/launcher/update/check` | profile, game_path |
| `update` | Session | `POST /api/v1/launcher/update` | profile, game_path, mode (`update`, `force`, `verify`), scan_only, max_workers, ignore. Starts in the background; poll `update_status`. |
| `update_status` | Get | `GET /api/v1/launcher/update/status` | none |
| `update_cancel` | Post | `POST /api/v1/launcher/update/cancel` | none |
| `update_pause` | Post | `POST /api/v1/launcher/update/pause` | none. Workers finish their current file, then wait. |
| `update_resume` | Post | `POST /api/v1/launcher/update/resume` | none |
| `scan_update` | Session | `POST /api/v1/launcher/update/scan` | profile, game_path, mode, ignore, only, product_id. Lists the files that need updating, with size and reason (`New`, `Size changed`, `Content changed`, `Re-download`), without downloading. |
| `check_folders` | Session | `POST /api/v1/launcher/folders/check` | profile, folders, all_folders, product_id. Up to date or update available, per game folder. |
| `get_config` | Get | `GET /api/v1/launcher/config` | none. The shared hooks and ignore list. |
| `set_config` | Post | `POST /api/v1/launcher/config` | ignore, hooks (`before_patch`, `after_patch`, `before_launch`, `after_launch`). Fields left out keep their value. |
| `news` | Get | `GET /api/v1/launcher/news` | product_id. Title, link, date and image of each news item. |
| `launch` | Session | `POST /api/v1/launcher/launch` | profile, game_path, client_dir, client_exe |

See [NXL_PATCHER.md](NXL_PATCHER.md) and [LAUNCH.md](LAUNCH.md).

### Profiles

| Tool | API route | Parameters |
|---|---|---|
| `profiles` | `GET /api/v1/launcher/profiles` | none (summaries without tokens) |
| `profile_save` | `POST /api/v1/launcher/profile/save` | **name**, **email**, id, client_dir, auto_login |
| `profile_delete` | `POST /api/v1/launcher/profile/delete` | **id** |
| `profile_activate` | `POST /api/v1/launcher/profile/activate` | **id** |

### `test_mod_for_crash` (local, Windows only)

Runs one crash-test trial inside the MCP process by chaining other tools. Use
it to binary-search which part of a mod makes the game crash.

| Parameter | Meaning |
|---|---|
| **archive** | Archive to test. **It is overwritten**; keep a backup. |
| **remove_entries** | Array of regular expressions. Extracted files whose path (with `/` separators, relative to the extract folder) matches any of them are removed. |
| key | Salt for extraction. |
| profile, game_path, client_dir | Passed to `launch`. |
| survive_seconds | How long the client must run without crashing. Default 90. |

Steps:

1. Fails at once on non-Windows systems.
2. `extract` the archive to `%TEMP%\mabi_crashtest_<pid>_<ms>`.
3. Delete the matching files. If none matched, fail
   (`No extracted entries matched remove_entries; nothing to test`).
4. Clear the read-only flag if set, then `pack` the folder back over the
   archive with the `salt_used` that extraction reported.
5. `launch` the game.
6. Every 3 s until `survive_seconds` pass, ask PowerShell
   (`Get-WinEvent`) for an Application log event with ID 1000 whose message
   mentions `client.exe`.
7. Delete the temp folder and restore the read-only flag.

Result: `{ verdict: "crashed" | "survived", removed_count, event }`, where
`event` holds the matching event's `TimeCreated` and `Message`.

---

## Tests

`src/mcp.rs` contains unit tests:

| Test | Checks |
|---|---|
| `every_tool_has_a_route_and_unique_name` | Each non-local tool has an API path and no name repeats. |
| `secrets_are_stripped_recursively` | Secret fields are removed at every depth. |
| `initialize_list_and_unknown_method` | `initialize`, `tools/list`, and the `-32601` error. |
| `tools_call_reaches_the_api` | A tool call goes through an ephemeral API server. |

Run them with `cargo test --lib mcp::`. CI and the pre-commit gate run all
library tests, so these are included (see
[DEVELOPMENT.md](DEVELOPMENT.md#tests)).

