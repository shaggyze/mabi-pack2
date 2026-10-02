# Profiles and Session Storage

How mabi-patcher remembers accounts, sessions and settings between runs.

Sources: `src/launcher/profile.rs`, `src/launcher/keystore.rs`,
`src/launcher/config.rs`, `src/launcher/cli.rs`, `gui/src-tauri/src/lib.rs`,
`gui/src-tauri/src/main.rs`.

---

## Where files live

| File | Windows | Linux / other | Written by |
|---|---|---|---|
| `profiles.json` | `%APPDATA%\mabi-patcher\profiles.json` | `~/.config/mabi-patcher/profiles.json` | CLI, GUI, API, MCP |
| Session secrets | Windows Credential Manager, generic credentials named `mabi-patcher\<profile id>` | inside `profiles.json` | CLI, GUI, API, MCP |
| `config.json` (patcher settings: ignore list, hooks) | `%APPDATA%\mabi-patcher\config.json` | `~/.config/mabi-patcher/config.json` | CLI `config`, GUI, API `launcher/config` |
| GUI settings | `%APPDATA%\com.shaggyze.mabi-patcher\config.json` (Tauri app config folder), or `config.json` next to the exe in portable mode | same rule | GUI |
| Launch deploy folder | `%LOCALAPPDATA%\mabi-patcher\nxl3p\` | — | `launch` (Windows) |
| Passport ticket (short-lived) | In memory only: a per-launch named file mapping `Local\mabi-patcher.ticket.{GUID}` readable only by the current user and SYSTEM (see [LAUNCH.md](LAUNCH.md#launch-steps-windows)) | — | `launch`; zeroed by the shim after reading, and wiped and closed by the launcher once the shim is ready (+3 s), the game exits or 60 s pass |
| Linux→Wine session hand-off | — | `$TMPDIR/mabi-session-<pid>-<nanos>.json`, mode `0600`, deleted after launch | `launch` on Linux |
| Installed manifest | `<install>\patchdata\10200.manifest.hash` and `<install>\patchdata\<hash>` | same | `update` |
| Pending archive edits | `<archive>.pending.json` next to the archive | same | GUI / API |

The data folder is `profile::data_dir()`: `%APPDATA%\mabi-patcher` on
Windows (or `.\mabi-patcher` if `APPDATA` is unset), `$HOME/.config/mabi-patcher`
elsewhere (or `./mabi-patcher` if `HOME` is unset).

### Where session tokens are kept

Session tokens (`NxLSession`, `AToken`, `g_AToken` and the rest) are the
secret part of a profile. Passwords are never stored.

- **Windows.** `ProfileStore::save()` writes each profile's `session_token`
  and `session` to the Windows Credential Manager as one JSON blob (target
  `mabi-patcher\<profile id>`, `src/launcher/keystore.rs`) and blanks them
  in `profiles.json`. `ProfileStore::load()` reads them back. A
  `profiles.json` that still holds plain-text tokens (from an older
  version) is migrated on first load: the tokens move to the Credential
  Manager and the file is rewritten without them. Deleting a profile also
  deletes its credential.
- **Linux, macOS and Wine.** There is no keychain backend yet
  (`keystore::available()` is false), so the tokens stay in
  `profiles.json` as plain JSON, protected only by the user's file
  permissions.

---

## `profiles.json`

```json
{
  "profiles": [ { ...profile... } ],
  "active_id": "<id of the last-used profile>"
}
```

### Profile fields

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Random UUID v4, stable across renames. |
| `name` | string | Display name. The CLI names new profiles after the email, or `nexon-<first 8 of user id>`, or `nexon`. |
| `email` | string | Nexon account email. |
| `session_token` | string | `NxLSession`. Written by every save path; the CLI treats it as the newest token. |
| `session_expires_at` | number | Unix time when the session is expected to expire. |
| `client_dir` | string | Game install folder. The CLI stores the resolved install root. |
| `auto_login` | bool | Auto-login on selection. The CLI sets it to `true` on every login. |
| `created_at`, `last_login_at` | number | Unix times. |
| `profile_type` | string | `nexon` (default), `hyddwn`, `kanan` or `manual`. |
| `device_tag` | string | Mixed into this profile's Nexon device id (see [NEXON_AUTH.md](NEXON_AUTH.md#device-id)), so two profiles never share one. New profiles get their name; profiles saved by older versions have none and keep the machine-only id. |
| `login_ip`, `login_port`, `chat_ip`, `chat_port`, `is_official` | | Server settings for private servers (GUI). |
| `session` | object | The full cookie session (`NexonSession`; see [NEXON_AUTH.md](NEXON_AUTH.md#session-fields)). Needed for browser/SSO accounts, which cannot be rebuilt from `NxLSession` alone. |

Empty strings and a missing `session` are left out of the file. On Windows
`session_token` and `session` are always left out (they live in the
Credential Manager, see above).

### Summaries

Lists sent to the GUI and the API (`ProfileSummary`) never include tokens.
They add two computed fields: `has_session` (a token is stored) and
`session_valid` (see below).

---

## Choosing a profile

**Explicit `--profile NAME`** (CLI) or `profile` (MCP): matches name, id or
email, ignoring case.

**No profile given, reading a session** (`check-update`, `update`, `launch`
without `-u`, `login` without credentials): the active profile, else the
first one. If there is none: `No profile found — run 'login --email ...
--password ...' first`.

**No profile given, saving a new login** (`login`, `login-otp`, `launch -u`):
`profile_for_login` picks

1. the profile with the same email (ignoring case), else
2. the profile whose saved session has the same Nexon user id, else
3. a new profile.

It never falls back to the active profile, so logging in as account B does
not overwrite account A's session. After saving, that profile becomes the
active one.

---

## Expiry

Two separate things expire:

| Item | How long | How it is tracked |
|---|---|---|
| `NxLSession` (the login) | `loginSessionExpiresIn` from the login answer, default 24 h | `session_expires_at = now + expires_in` |
| `AToken` (access) | Short; Nexon decides | Not tracked. Detected by a `401`. |

`Profile::is_session_valid()` is true when a token is stored and
`session_expires_at` is later than now minus 60 seconds (a small allowance
for clock skew). It feeds `session_valid` in summaries and the API's
`profile/load`. The CLI does **not** rely on it: before each command it asks
Nexon (`GET /account/v1/account`) and refreshes on anything but `200`.

A stored session whose `session_expires_at` has passed (`Profile::session_expired()`;
an unknown expiry of `0` never counts) is not sent to Nexon at all, since it
could only get a `401`:

- CLI: commands that use the profile's session stop at once with
  `The saved session of profile '<name>' has expired — log in again: ...`.
  `login` without arguments prints the time left (`Session for 'x' is valid (29d 4h left).`).
- GUI: auto-login on start or on profile selection, and **Launch**, go straight
  to the re-login prompt instead of trying the session.

Summaries include `session_expires_at` (0 when there is no session). The GUI's
Launcher tab shows the time left after each profile in the profile list,
refreshed every 60 s: `29d 4h`, `2h 15m`, `45m`, `<1m` or `Expired`
(`profile::format_expiry` has the same rules).

When a refresh happens, the new lifetime is passed back in
`refreshed_expires_in` and written to `session_expires_at`. A save with an
unknown lifetime (`0`) leaves `session_expires_at` unchanged.

Browser/SSO sessions (`tpa = true`) cannot be refreshed. When they expire
the user must log in through the browser again.

---

## Importing from Kanan

`src/launcher/kanan_import.rs` reads the Kanan launcher's `profiles.dat`
(written into Kanan's working folder, next to its `Launcher.exe`). The user
types their Kanan master password; it is never stored or logged.

Format (from Kanan's `LauncherApp.cpp` and `Crypto.cpp`):

| Part | Value |
|---|---|
| Key | SHA-256 of the master password (no salt, no iterations). |
| Cipher | AES-256-GCM (Windows CNG). The nonce is also the associated data. |
| File | 12-byte nonce, then the 12-byte tag (CNG's minimum GCM tag size, which Kanan uses), then the ciphertext. 16-byte tags are accepted too. |
| Plaintext | JSON plus a NUL byte: `{"version":1,"clientPath":"...Client.exe","profiles":[{"username","password","cmdLine","launchWithKanan"}]}`. `profiles` is `null` when empty. |

A failed tag check gives `Wrong master password or unsupported file`.

mabi-patcher stores sessions, not passwords. So each selected account gets a
profile (`profile_type` `kanan`; an existing profile with the same email is
reused; the game folder comes from Kanan's `clientPath`), is logged in once
with that profile's device id (`auth::login`), and the session is saved with
`profile::save_session` (into the keychain on Windows). An MFA challenge is
finished with `kanan_import::complete_mfa`. If the login fails, the profile
is kept without a session. The decrypted passwords are wiped from memory
after use (best effort).

Entry points: CLI `import-kanan` ([CLI.md](CLI.md#import-kanan)) and the GUI
**Import from Kanan** button in the Launcher tab (Tauri commands
`kanan_list_accounts`, `kanan_import_accounts`, `kanan_import_otp`).

---

## Save paths

| Function | Used by | What it writes |
|---|---|---|
| `profile::save_session(id, session, expires)` | CLI after login, refresh or launch; MCP | `session_token`, the full `session` (without `refreshed_expires_in`), `session_expires_at` (when known), `last_login_at`. |
| `profile::update_session(id, token, expires)` | GUI, API `profile/session` | `session_token` (also copied into the stored `session`), `session_expires_at`, `last_login_at`. |
| `ProfileStore::save()` | everything | Rewrites the whole `profiles.json`. |

There is no file locking. Two processes saving at the same time can lose one
of the writes.

The GUI also has `launcher_save_profile_session`, which calls
`profile::save_session` with a full session (for example after
**Import from browser**).

---

## Patcher settings (`config.json`)

Written by `mabi-patcher config`, the GUI (Settings → Patcher: ignore list
and hooks) and `POST /api/v1/launcher/config`; read by `update`, `launch`,
the GUI and the API's `launcher/update`. One file, so the CLI, GUI and REST
API share the same hooks and ignore list.

The first time the GUI loads it while it is still empty, the GUI copies
its own older settings (`pre_patch_cmd`, `post_patch_cmd`,
`pre_launch_cmd`, `post_launch_cmd`, `patcher_ignore_list` from the GUI
`config.json`) into it.

```json
{
  "ignore": ["mods/*", "*.ini"],
  "hooks": {
    "before_patch": "...", "after_patch": "...",
    "before_launch": "...", "after_launch": "..."
  }
}
```

Empty hook strings are left out. See [CLI.md](CLI.md#config) for how
patterns and hooks behave.

---

## GUI settings

The GUI keeps its own `config.json` (`Config` struct in
`gui/src-tauri/src/lib.rs`) with theme, locale, log level, file associations,
salt history and last key, auto-convert options, pack options, audio
options, patcher game path and more, including:

| Field | Setting | Default |
|---|---|---|
| `api_enabled`, `api_port` | Settings → Engine: run the REST API inside the app on `127.0.0.1:<port>` | off, `7331` |
| `minimize_to_tray` | Settings → Engine: closing the window hides it to the system tray (left-click the tray icon or **Show** to restore, **Quit** to exit) | off |
| (registry) | Settings → Engine → **Start with Windows (in the tray)**: writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `mabi-patcher` = `"<path to exe>" --minimized` (the path is quoted, so folders with spaces work); unticking deletes the value. The checkbox reads the registry, not `config.json`. Windows only. | off |

Started with `--minimized`, the GUI hides its window at start-up and shows the
tray icon (even when "Minimize to tray on close" is off); with no tray
available it starts minimized instead.
| `product_id` | Settings → Patcher → Advanced → Product ID | `10200` |

- Default location: Tauri's app config folder, which on Windows is
  `%APPDATA%\com.shaggyze.mabi-patcher\config.json`.
- Portable mode: a `config.json` next to the exe. Settings → Portable mode
  moves it there and back.
- If `patcher_run_elevated` is true, the GUI asks for administrator rights at
  start-up (`main.rs`). The check reads the portable `config.json` next to
  the exe first, then the one in the app config folder, like the rest of
  the GUI.
- Settings → Reset restores the defaults and keeps the location.
