# mabi-patcher CLI Reference

The `mabi-patcher` binary covers archive work (extract, pack, list, convert),
the Nexon launcher and patcher, the REST server and the MCP server.

```
mabi-patcher [-v...] <command> [options]
```

Sources: `src/bin/mabi-pack-cli.rs` (archive commands, `serve`, `mod`,
`mcp`), `src/launcher/cli.rs` (launcher commands), `src/launcher/config.rs`
(`config`).

---

## Global options

| Option | Description |
|---|---|
| `-v`, `--verbose` | Repeat for more detail. `-v` = info, `-vv` = debug, `-vvv` = trace. With one or more `-v`, the same log is also appended to `log.txt` in the current folder. |
| `-V`, `--version` | Print the program version (from `Cargo.toml`). |
| `-h`, `--help` | Help for the program or a command. |

---

## Archive commands

### `extract`

Extract a `.it` or `.pack` archive.

```
mabi-patcher extract -i ARCHIVE [-o FOLDER] [-k SALT] [-f REGEX]...
```

| Option | Description |
|---|---|
| `-i`, `--input ARCHIVE` | **Required.** Archive to extract. |
| `-o`, `--output FOLDER` | Output folder. If omitted, a folder named after the archive (without extension) is used. |
| `-k`, `--key SALT` | Salt to try first. Without it, every known salt is tried (see [PACK_FORMAT.md](PACK_FORMAT.md#salts)). |
| `-f`, `--filter REGEX` | Only extract entries whose name matches this regular expression. Repeatable; an entry is kept if any filter matches. Ignored for legacy `.pack` files. |

The archive type is detected from its first four bytes: `MABI` or `PACK`
means a legacy pack, anything else is treated as `.it`.

Entry names are joined to the output folder with `common::safe_join`. A name
that is absolute, has a drive or UNC prefix, contains a `..` component, or
contains `:` is refused (`unsafe path ...`, logged as a warning and
skipped), so nothing is written outside the output folder.

### `pack`

Build an archive from a folder.

```
mabi-patcher pack -i FOLDER -o OUTPUT -k SALT [--iv 0|1] [-f EXT]... [--wrap-data]
```

| Option | Description |
|---|---|
| `-i`, `--input FOLDER` | **Required.** Folder to pack. |
| `-o`, `--output PACK_NAME` | **Required.** Output file. A name ending in `.pack` writes a legacy MABI `.pack` (version 1); anything else writes a `.it`. |
| `-k`, `--key SALT` | **Required** (even for `.pack`, where it is not used). Salt for the `.it` header and entry table. |
| `--iv IV` | Snow2 initial vector, `0` or `1`. Default `0`. |
| `-f`, `--compress-format EXT` | Also compress files ending in `EXT` (repeatable). The match is a plain "ends with" that ignores case, so pass the dot: `-f .lua`. `.txt .xml .dds .pmg .set .raw` are always compressed. |
| `--wrap-data` | Store every entry under a virtual `data\` folder. |

Before anything is written, every entry name is checked
(`common::validate_entry_path`): it must be a safe relative path, at most
260 characters (`MAX_ENTRY_PATH_LEN`), and free of characters Windows does
not allow in file names (`< > : " | ? *` and control characters). One bad
name stops the pack with `cannot pack this file`. A legacy `.pack` also
limits each name to 255 bytes.

### `list`

Print the entry names of an archive.

```
mabi-patcher list -i ARCHIVE [-k SALT] [-o FILE]
```

| Option | Description |
|---|---|
| `-i`, `--input ARCHIVE` | **Required.** Archive to list. |
| `-k`, `--key SALT` | Salt to try first. |
| `-o`, `--output FILE` | Write the list to `FILE` instead of standard output. |

### `batch`

Extract every `.it` and `.pack` in a folder (not recursive), in name order.

```
mabi-patcher batch -i FOLDER -o OUT [-k SALT] [--no-merge] [-f REGEX]... [-j N]
```

| Option | Description |
|---|---|
| `-i`, `--input FOLDER` | **Required.** Folder holding the archives. |
| `-o`, `--output OUT_FOLDER` | **Required.** Destination. By default every archive is extracted into this one folder, so later archives overwrite earlier ones. |
| `-k`, `--key SALT` | Salt to try first. |
| `--no-merge` | Extract each archive into `OUT/<archive name>/` instead. |
| `-f`, `--filter REGEX` | Only extract matching entries (repeatable). |
| `-j`, `--jobs N` | Archives extracted at once. Default `1`. `0` means twice the number of logical CPUs. |

With `-j 1` the salt found for one archive is tried first on the next one,
and per-archive progress is shown on one line. With more jobs only
completion lines are printed.

### `convert`

Convert between `.it` and `.pack`.

```
mabi-patcher convert -i INPUT -o OUTPUT [-k SALT]
```

| Option | Description |
|---|---|
| `-i`, `--input INPUT` | **Required.** Source archive. |
| `-o`, `--output OUTPUT` | **Required.** Destination; the extension (`.pack` or not) picks the format. |
| `-k`, `--key SALT` | Salt for reading a `.it` source and for writing a `.it` destination. |

The source is extracted to a temporary folder and repacked. When writing a
`.it`, entries are wrapped under `data\` unless the extracted tree already has
a `data` folder. The salt used for the output is, in order: `-k`, the salt
that opened the source, or the first built-in salt.
(`common_ext::convert`)

### `full-sequence`

Extract every `.it`/`.pack` in a folder, in name order, into one tree and
pack the result into a single `.it`.

```
mabi-patcher full-sequence -i FOLDER -o ALL_DATA.IT [-k SALT]
```

| Option | Description |
|---|---|
| `-i`, `--input FOLDER` | **Required.** Folder with the archives. |
| `-o`, `--output FILE` | **Required.** Output `.it`. |
| `-k`, `--key SALT` | Salt to try first when reading and to use when writing. Without it, the first built-in salt is used for the output. |

### `mod`

Work with `.mod` instruction files (TOML; see [GUI.md](GUI.md#mods)).

| Command | Description |
|---|---|
| `mod inspect -f FILE` | Parse and validate a `.mod` file and print it as JSON. Exit code 1 on a parse error. |
| `mod template` | Print a blank `.mod` template to standard output. |
| `mod list [-d DIR]` | List `.mod` files in `DIR` (default `mods`), showing `[OK]` with name and version, or `[ERR]` with the parse error. |

---

## Server commands

### `serve`

Run the REST API and web UI. See [API.md](API.md).

```
mabi-patcher serve [-p PORT] [--host HOST]
```

| Option | Description | Default |
|---|---|---|
| `-p`, `--port PORT` | Port to listen on. | `7331` |
| `--host HOST` | Address to bind. Anything other than `127.0.0.1`, `localhost` or `::1` requires `MABI_API_TOKEN`. | `127.0.0.1` |

In an interactive terminal the server stops when you press Enter. Otherwise
it runs until the process is stopped. See
[API.md](API.md#stopping-the-server).

### `mcp`

Run the built-in MCP server on standard input and output. See [MCP.md](MCP.md).

```
mabi-patcher mcp
```

---

## Launcher commands

These commands log in to Nexon NA, patch and launch the game. They are
shared by the CLI and the GUI exe (see
[GUI exe command line](#gui-exe-command-line)).

**Game folder.** Commands that need the game find it in this order:
`--game-path`/`--client`, then the profile's saved folder, then an
auto-detected install (`src/launcher/detect.rs`: the Nexon Launcher's
`appconfig.json`, Windows uninstall entries, common install folders on every
drive, and on Linux the same folders inside Wine prefixes, Lutris, Bottles
and Steam/Proton `compatdata`). The path may be the install folder,
`appdata`, `patchdata` or `Client.exe` itself.

**Profile.** `--profile NAME` matches a profile by name, id or email (case
does not matter). Without it, the active profile is used, else the first one.
See [SESSION.md](SESSION.md).

**Exit codes.**

| Code | Meaning |
|---|---|
| `0` | Success / up to date. |
| `1` | Error, MFA required, CAPTCHA required, a patch that ended with errors or was cancelled, or `import-cookies` found no session. |
| `2` | Update available (`check-update`, for any folder when several are checked), or files need updating (`update --scan-only`). |

**Product id.** `check-update`, `update`, `launch`, `import-cookies` and
`news` take `--product-id N` (default `10200`, Mabinogi). It changes the
product used for the Nexon access, playable and passport calls, the
game-build and maintenance calls, the CDN paths, the
`<product id>.manifest.hash` file name and the news feed. Only change it
if you know you need to.

### `login`

Log in with email and password, or check (and refresh) the stored session.

```
mabi-patcher login [--profile NAME] [-u EMAIL -p PASSWORD] [-c DIR]
```

| Option | Description |
|---|---|
| `--profile NAME` | Profile to save to or check. |
| `-u`, `--email EMAIL` | Account email. Alias `--username`. Falls back to `MABI_EMAIL`, but only when a password is also available. |
| `-p`, `--password PASSWORD` | Account password. Falls back to `MABI_PASSWORD`. |
| `-c`, `--client DIR` | Save this game folder (or `Client.exe` path) on the profile. |

Behaviour:

- With an email and password: logs in and saves the session. Without
  `--profile`, the session goes to the profile with the same email, else the
  one with the same Nexon user id, else a new profile (named after the email).
  It never lands on another account's profile. The profile becomes active.
- With neither: loads the profile's session, checks it, refreshes it if it is
  no longer valid, and prints `Session for '<name>' is valid.`
- With only one of the two: error.
- If Nexon asks for 2FA, the command prints the exact `login-otp` command to
  run and exits with code 1.
- If Nexon asks for a CAPTCHA, the command exits with code 1 and asks you to
  log in once with the GUI's browser login.
- If Nexon asks to verify the device (code 20027), the login is retried up
  to 4 times, waiting 2, 4 and 6 seconds, in case you confirm Nexon's email
  meanwhile (see [NEXON_AUTH.md](NEXON_AUTH.md#email-and-password-login)).

### `login-otp`

Finish a 2FA login with the code Nexon sent.

```
mabi-patcher login-otp --mfa-key KEY --otp CODE [--profile NAME] [-u EMAIL] [-c DIR]
```

| Option | Description |
|---|---|
| `--mfa-key KEY` | **Required.** Key printed by `login`. |
| `--otp CODE` | **Required.** The one-time code. |
| `--profile NAME` | Profile to save the session to. |
| `-u`, `--email EMAIL` | Account email, used to match or name the profile. Falls back to `MABI_EMAIL`. Without it the profile is matched by Nexon user id. |
| `-c`, `--client DIR` | Save this game folder on the profile. |

CAPTCHA and device-verification answers are handled as for `login`.

### `config`

Show or change patcher settings: the ignore list and event hooks
(`src/launcher/config.rs`). Every form prints the settings file path and its
contents. The desktop app and the REST API (`GET`/`POST
/api/v1/launcher/config`) read and write the same file, so all three share
one set of hooks and ignore patterns.

```
mabi-patcher config [show]
mabi-patcher config ignore add|remove PATTERN
mabi-patcher config hook EVENT [CMD]
```

| Form | Description |
|---|---|
| `config` or `config show` | Print the settings. |
| `config ignore add PATTERN` | Add a path or wildcard (`*`, `?`) the patcher must never touch. Duplicates (ignoring case) are skipped. |
| `config ignore remove PATTERN` | Remove a pattern (ignoring case). |
| `config hook EVENT CMD` | Set the command for `before-patch`, `after-patch`, `before-launch` or `after-launch` (underscores and any case are accepted). |
| `config hook EVENT` | Clear that hook. |

**Ignore patterns** are matched case-insensitively against the manifest path
(with `/` separators) or, when the pattern has no `/`, against the file name
alone. Example: `*.ini` matches `appdata/Options.INI`; `package/mod_*.it`
matches `package/mod_ui.it`.

**Hooks** run through `cmd /C` on Windows and `sh -c` elsewhere, in the game's
install folder, without waiting for them to finish. `%PROFILE%` (any case) is
replaced with the profile name. `before-patch` and `after-patch` do not run
for `update --scan-only`; `after-patch` runs only when the patch finished with
no errors and was not cancelled. `after-launch` runs as soon as `Client.exe`
has started, not when it exits.

### `check-update`

Compare the installed game with Nexon's current manifest.

```
mabi-patcher check-update [--profile NAME] [-g PATH] [--folder PATH]... [--all-folders] [--product-id N]
```

| Option | Description |
|---|---|
| `--profile NAME` | Profile whose session is used. A session is required. |
| `-g`, `--game-path PATH` | Game folder. Aliases `-c`, `--client`. |
| `--folder PATH` | Check this game folder. Repeatable, to check several installs. |
| `--all-folders` | Also check every auto-detected install (`detect::find_all_game_exes`). |
| `--product-id N` | See [Product id](#launcher-commands). |

With one folder it prints the game folder, the remote manifest hash and the
local one (`patchdata/<product id>.manifest.hash`), then `Update available.`
(exit 2) or `Up to date.` (exit 0).

With `--folder` or `--all-folders` it fetches the remote hash once and
prints one line per folder: `UPDATE`, `OK` or `ERROR` with the reason. Exit
2 if any folder needs an update.

### `update`

Download and apply game updates. See [NXL_PATCHER.md](NXL_PATCHER.md).

```
mabi-patcher update [--profile NAME] [-g PATH] [--force-all | --verify] [--scan-only] [-j N] [--ignore PATTERN]...
                    [--only FILE]... [--select LIST_FILE] [--folder PATH]... [--all-folders] [--product-id N]
```

| Option | Description |
|---|---|
| `--profile NAME` | Profile whose session is used. A session is required. |
| `-g`, `--game-path PATH` | Game folder. Aliases `-c`, `--client`. |
| `--force-all` | Re-download every file. Cannot be combined with `--verify`. |
| `--verify` | Repair mode: also SHA1-check files whose size already matches. |
| `--scan-only` | Only list the files that need updating (size, reason, path). Exit 2 if any, else 0. |
| `-j`, `--workers N` | Files downloaded at once. Default `8`, clamped to 1–32. |
| `--ignore PATTERN` | Path or wildcard never touched. Repeatable; added to the saved `config ignore` list. |
| `--only FILE` | Only consider this manifest path. Repeatable. Matching ignores case and treats `\` and `/` alike. Ignored files stay ignored. |
| `--select LIST_FILE` | Read more `--only` paths from a file, one per line; blank lines and lines starting with `#` are skipped. |
| `--folder PATH` | Update this game folder. Repeatable; folders are patched one after another, with the same options. |
| `--all-folders` | Also update every auto-detected install. |
| `--product-id N` | See [Product id](#launcher-commands). |

To choose files, run `update --scan-only` first, keep the paths you want and
pass them back with `--only` or `--select`. When the selected files all
succeed, the new manifest hash is written as after a full update (see
[NXL_PATCHER.md](NXL_PATCHER.md#choosing-files)).

With several folders, each one prints a `== <folder> ==` header; the exit
code is the last non-zero code, else 0.

Progress is printed on one line (scan count, then files, MB and MB/s). Errors
are printed at the end. A permission error prints
`Permission denied — run as administrator.`

### `launch`

Log in if needed and launch the game. See [LAUNCH.md](LAUNCH.md).

```
mabi-patcher launch [--profile NAME] [-c PATH] [-u EMAIL -p PASSWORD] [--wait | --no-wait] [--version] [--manifest]
```

| Option | Description |
|---|---|
| `--profile NAME` | Profile to use. |
| `-c`, `--client PATH` | Game folder or `Client.exe`. Alias `--game-path`. |
| `-u`, `--username EMAIL` | Log in with this account first (alias `--email`; falls back to `MABI_EMAIL` when a password is available). The session is saved like `login` does. Without it, the profile's session is used. |
| `-p`, `--password PASSWORD` | Password for `-u`. Falls back to `MABI_PASSWORD`. |
| `--wait` | Wait until the game exits. This is the default. Cannot be combined with `--no-wait`. |
| `--no-wait` | Return once the game has started and taken its login ticket. |
| `--version` | Print `Latest Mabinogi version: N` and exit without launching. |
| `--manifest` | Print the current remote manifest hash and exit without launching. |
| `--remember` | Accepted for compatibility; the session is always saved. |
| `--session-file FILE` | Internal: used by the Linux side to hand a session to the Windows build under Wine. Requires `--client`. |
| `--product-id N` | See [Product id](#launcher-commands). |

If Nexon reports that a patch is available, the command prints
`Note: a game patch is available (run 'mabi-patcher update').` On success it
prints `Launched <exe> (pid N).`

### `import-cookies`

Import a Nexon session from a web browser you are already logged in with.

```
mabi-patcher import-cookies [--profile NAME] [-c DIR] [--product-id N]
```

| Option | Description |
|---|---|
| `--profile NAME` | Profile to save the session to. Without it, the session's Nexon user id picks the profile, else a new one is made. |
| `-c`, `--client DIR` | Save this game folder on the profile. |

Browsers are tried in order: Firefox, Chrome, Edge, Brave
(`src/launcher/cookies.rs`); the first one with a usable session wins. See
[NEXON_AUTH.md](NEXON_AUTH.md#browser-cookie-import). On success it prints
`Imported a session from <browser> into profile '<name>'.` and exits 0;
otherwise `No usable Nexon session found in your browsers.` and exit 1.
Chrome 127+ protects its cookies (`v20`), so they cannot be read; the
command then prints a note to use the browser login instead.

### `import-kanan`

Import the accounts saved in the Kanan launcher's `profiles.dat`.

```
mabi-patcher import-kanan [--file PATH] [--list]
```

| Option | Description |
|---|---|
| `-f`, `--file PATH` | Kanan's `profiles.dat`, Kanan's folder, or its `Launcher.exe`. Default: `profiles.dat` in the current folder, then next to this program. |
| `--list` | Only print the account emails found; import nothing. |

The command asks for your Kanan master password without echoing it (or reads
it from `MABI_KANAN_PASSWORD`). It prints the account emails found, never
the passwords. For each account it creates a `kanan` profile (or reuses the
profile with the same email), logs in once with that profile's device id and
saves the session. Passwords are not stored. If Nexon asks for a code, the
command prompts for it. A wrong master password prints
`Wrong master password or unsupported file`. Exit 1 if any login failed (the
profile is still created; log in to it later). See
[SESSION.md](SESSION.md#importing-from-kanan).

### `news`

Print the Mabinogi news feed: category, title, date and link for each item,
then the number of items. No login is needed.

```
mabi-patcher news [--product-id N]
```

---

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `MABI_EMAIL` | `login`, `login-otp`, `launch` | Account email when `-u` is not given. For `login` and `launch` it is only used when a password is also available. |
| `MABI_PASSWORD` | `login`, `launch` | Account password when `-p` is not given. |
| `MABI_KANAN_PASSWORD` | `import-kanan` | Kanan master password (skips the prompt). |
| `MABI_WINE` / `WINE` | `launch` on Linux | Wine runner (for example `wine64`, a Proton `wine` binary or a script). Default `wine`. |
| `MABI_WINE_EXE` | `launch` on Linux | Path to the Windows `mabi-patcher.exe`. Default: next to the Linux binary. |
| `WINEPREFIX` | `launch` and auto-detect on Linux | The game's Wine prefix. |
| `MABI_API_TOKEN` | `serve` | Bearer token required for a non-loopback bind. |
| `MABI_WEBUI_DIR` | `serve` | Folder holding the built web UI. |

---

## Examples

```sh
# Log in once and remember the game folder (password from the environment)
export MABI_PASSWORD='<your password>'
mabi-patcher login -u you@example.com --profile Main -c "C:\Nexon\Library\mabinogi"

# Nexon asked for 2FA: login printed this command
mabi-patcher login-otp -u you@example.com --mfa-key <KEY> --otp 123456

# Check, patch if needed, launch
mabi-patcher check-update
if [ $? -eq 2 ]; then mabi-patcher update -j 8 --ignore 'mods/*'; fi
mabi-patcher launch --no-wait

# Repair the install
mabi-patcher update --verify

# Saved ignore list and hooks
mabi-patcher config ignore add '*.ini'
mabi-patcher config hook before-launch 'echo starting %PROFILE%'

# Archives
mabi-patcher extract -i data_00.it -o ./out -f '\.xml$'
mabi-patcher pack -i ./out -o mymod.it -k '<salt>' --wrap-data
mabi-patcher batch -i ./package -o ./all -j 0
mabi-patcher convert -i old.pack -o new.it
```

PowerShell form of check-then-patch:

```powershell
mabi-patcher check-update --game-path "C:\Nexon\Library\mabinogi"
if ($LASTEXITCODE -eq 2) { mabi-patcher update --game-path "C:\Nexon\Library\mabinogi" }
```

---

## GUI exe command line

The desktop `mabi-patcher.exe` (`gui/src-tauri/src/main.rs`) also takes
commands:

- The nine launcher commands (`login`, `login-otp`, `config`,
  `check-update`, `update`, `launch`, `import-cookies`, `news`,
  `import-kanan`), either
  directly (`mabi-patcher.exe launch ...`) or with `--cli` first
  (`mabi-patcher.exe --cli launch ...`). Flags are the same as above.
- `mcp`, which runs the MCP server.
- `serve [--host HOST] [-p PORT]`, which runs the REST API and web UI
  without a window (`api::serve_from_args`), with the same rules as the CLI
  `serve`.
- A small archive CLI with its own flags:

| Command | Notes |
|---|---|
| `extract -i ARCHIVE -o FOLDER [-k SALT] [-f REGEX]...` | `-o` is required here. `.pack` input is extracted without filters. |
| `pack -i FOLDER -o OUTPUT [-k SALT] [--wrap-data] [-f EXT]... [--pack-version N]` | `-k` is required for `.it`. `--pack-version` (default `999`) is the version written into a `.pack` header. `--auto-dds` and `--additional_data` are accepted but have no effect. |
| `list -i ARCHIVE [-k SALT] [-o FILE]` | |
| `batch ...` | Same flags as the CLI `batch`. |
| `--convert FILE` | Convert `FILE` from `.it` to `.pack` or the other way, next to the original. |
| `--extract-here FILE` | Extract `FILE` into a folder named after it. |
| `--extract-all-near FILE` | Extract every `.it`/`.pack` in `FILE`'s folder. |
| `FILE.it` or `FILE.pack` (only argument) | Opens it in the GUI. |

Any other first argument that is an existing path is opened in the GUI;
`--full` opens it in full-sequence mode.
