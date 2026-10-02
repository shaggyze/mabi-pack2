# Launching the Game

How mabi-patcher starts Mabinogi NA without the Nexon Launcher. Everything
needed is built into the executable.

Sources: `src/launcher/launch.rs`, `nxl3p-shim/src/lib.rs`, `build.rs`,
`src/launcher/cli.rs`, `gui/src-tauri/src/lib.rs` (`launcher_launch`).

---

## Why a stub and a shim are needed

`Client.exe` does not take its login ticket only from the command line. Its
`nexon_api_x64.dll` looks for a running `nexon_client.exe`, loads
`<that folder>\bin\nexon_x64.dll` and asks it for the ticket. It also talks
to the Nexon SDK over a named pipe. mabi-patcher provides all three:

| Piece | What it is |
|---|---|
| `nexon_client.exe` | A copy of the running mabi-patcher exe, started with `--nxl3p-stub --exit-event <name> --parent-pid <pid>`. It does nothing but wait. |
| `bin\nexon_x64.dll` | The nxl3p shim (`nxl3p-shim/`), embedded in the Windows exe at build time. |
| Pipe `\\.\pipe\{79d303ac-af79-46c3-9ae0-6cd4ff4805ad}` | Answers the SDK's requests. |

---

## Launch steps (Windows)

`launch_official_with(session, client_exe, wait, on_started)`:

1. **Check** that `Client.exe` exists.
2. **Passport.** `auth::prepare_launch` runs account → access → playable →
   passport, refreshing once on a 401 (see
   [NEXON_AUTH.md](NEXON_AUTH.md#launch-chain)). Maintenance and region
   blocks stop the launch here with a clear message.
3. **Launch config.** `GET /game-build/v1/configuration/games/10200` (the
   product id; see [NEXON_AUTH.md](NEXON_AUTH.md))
   (Bearer `AToken`, refresh on 401) returns `parameter` (argument list),
   `executablePath` and `patch`. Every `${passport}` in the arguments is
   replaced with the passport; if no argument starts with `/P:`,
   `/P:<passport>` is added.
4. **Deploy** to `%LOCALAPPDATA%\mabi-patcher\nxl3p\`:
   - `nexon_client.exe`: copied from the current exe when its size differs or
     it is older;
   - `bin\nexon_x64.dll`: written from the embedded shim when its bytes differ.
   If the build has no embedded shim (empty), the launch fails with
   `This build has no embedded nxl3p shim — rebuild for Windows.`
5. **Clean-up of old files.** The shim log in `%TEMP%` is trimmed (see
   below). A `%TEMP%\mabi-patcher-nxl3p-ticket.txt` left by an older build
   (which handed the ticket over in that file) is deleted.
6. **Ticket mapping.** A security descriptor is built that grants access
   only to the current user and SYSTEM (`D:P(A;;GA;;;SY)(A;;GA;;;<user SID>)`).
   With it, a 4 KiB named file mapping `Local\mabi-patcher.ticket.{GUID}`
   (a new random GUID per launch) is created and filled with
   `"MPT1"`, the UTF-8 length (u32 LE) and the passport. An existing object of
   that name fails the launch instead of being reused. Nothing is written to
   disk. The shim-ready event `<mapping name>.ready` is created the same way.
7. **Stub.** A per-launch exit event `Local\mabi-patcher.stub.{GUID}` (same
   descriptor), then the stub is started with no window and no inherited
   standard streams:
   `nexon_client.exe --nxl3p-stub --exit-event <event> --parent-pid <launcher pid>`.
   After 300 ms the launch fails if the stub already exited.
8. **Client.exe** is created **suspended** with `CreateProcessW`, in its own
   folder, with `MABI_PATCHER_TICKET_MAP=<mapping name>` added to its
   environment. Arguments with spaces are quoted. While it is suspended the
   pipe server (below) is bound to its process, then its main thread is
   resumed. If `CreateProcessW` fails with `ERROR_ELEVATION_REQUIRED` (a
   client manifest with `requireAdministrator`/`highestAvailable`), the client
   is started with `ShellExecuteEx` instead, which shows the UAC prompt and
   still returns the process handle (so the PID is known). An elevated
   process does not inherit the environment, so in this path
   `--mabi-map <mapping name>` is appended to the arguments as well; the game
   ignores the unknown argument and the shim reads it (this fixes "Failed to
   Init NXALauncher" on elevated starts). `on_started(pid)` is called at once;
   the CLI fires the `after-launch` hook here.
9. **Wait for the shim**, even without `wait`: until the shim sets
   `<mapping name>.ready`, the game exits, or 60 s pass. After the signal it
   waits another 3 s so the SDK can finish its pipe requests. Then the
   mapping is zeroed, unmapped and closed (the shim has already zeroed it
   after reading), the pipe server is stopped and the launch lock released.
   On any failure before this point the mapping is wiped the same way and
   the stub is told to exit.
10. **Clean-up thread.** When `Client.exe` exits: set the stub's exit event,
    then kill and reap the stub. With `wait` (the CLI default) the command
    blocks until this is done; with `--no-wait` it returns now.

Launches are serialized by the session-local mutex `Local\mabi-patcher.launch`
(held from step 4 to the end of step 9), because the SDK pipe has a fixed
name. All other kernel objects are per launch. Their names never contain the
ticket, and the ticket, passport and tokens are never logged.

The stub itself (`run_stub_if_requested`, called first in `main` of both
executables) accepts exactly `--exit-event <Local\mabi-patcher.stub.{GUID}>
--parent-pid <pid>`; the PID may not be 0 or the stub's own. Anything else,
an event that does not exist or a parent that is not running makes it exit
with code 2. Otherwise it waits until the event is set, the launcher process
exits, or 120 s pass.

---

## The nxl3p shim

`nxl3p-shim` is a small Windows DLL (`cdylib`) that replaces the official
launcher's `nexon_x64.dll`.

Exports:

| Export | Behaviour |
|---|---|
| `GetDLLInterface()` | Returns NULL, so the caller falls back to the v1 path below. |
| `nxapi_get_func_addr(code)` | Returns a function pointer for each code. |

| Code | Function | Behaviour |
|---|---|---|
| `0xBEEF0001` | `init(param)` | Finds the mapping name in `MABI_PATCHER_TICKET_MAP` (then clears that variable) or, failing that, in `--mabi-map <name>` on the process command line; only `Local\mabi-patcher.ticket.{GUID}` names are accepted. Opens the mapping, copies the ticket, **zeroes the mapping**, stores the ticket and sets `<name>.ready`. A `param` of 0 or above `0xFFFF` means product `10200`. Returns 0, or `-1` when no ticket could be read (a repeated call keeps an already loaded ticket). |
| `0xBEEF0002` | `close()` | Zeroes and clears the stored ticket. |
| `0xBEEF0003` | `getProductId(buf, size)` | Writes the product id as a wide string. |
| `0xBEEF0004` | `getProductTicket(buf, size)` | Writes the ticket as a wide string; returns `-2` if no ticket was loaded. |
| other | — | Writes an empty string. |

Buffers are WCHAR, NUL-terminated and truncated to fit; a null buffer or
zero size returns `-1`.

The shim logs each call (never the ticket itself) to
`%TEMP%\mabi-patcher-nxl3p-shim.log`. At each launch, once that file is
over 1 MiB, the launcher keeps only its last 256 KiB (from a line start).

Build: `build.rs` runs a nested `cargo build --release --target <target>` in
`nxl3p-shim/` with a separate target folder and the parent's `RUSTFLAGS`
removed, then exposes the DLL path as `NXL3P_SHIM_DLL` for
`include_bytes!`. Set `NXL3P_SHIM_PREBUILT=<path to dll>` to skip the nested
build. For non-Windows targets an empty file is embedded. The shim links the
C runtime statically on `x86_64-pc-windows-msvc`
(`nxl3p-shim/.cargo/config.toml`) so it has no `vcruntime` dependency inside
the game.

---

## The SDK pipe

The pipe is created once per launch, before `Client.exe` runs, with
`FILE_FLAG_FIRST_PIPE_INSTANCE` (if any other program, such as the Nexon
Launcher, already owns the name, the launch fails instead of sharing it),
`PIPE_REJECT_REMOTE_CLIENTS`, one instance, overlapped I/O and the
user-only security descriptor. Each client is checked with
`GetNamedPipeClientProcessId`: only the launched game's PID is served (checked
again before each answer); any other client is disconnected and logged. A
connect, read or write waits at most 30 s, and the server stops when it is
told to or the game exits.

Each frame is a little-endian `i32` length followed by UTF-8 JSON. Frames
larger than 64 KiB, or with a non-positive length, end the connection.
Only the request `type` is logged.
`pipe_response` answers by request `type`:

| `type` | Response `res` |
|---|---|
| `getProductTicket` | `{ productId, ticket }` |
| `getSDKConfiguration` | `{ ccuServerName: "ccu-edge.nexon.io", ccuServerPort: 8913, hashedUserNo, productId }` |
| `productActive`, `getClientToken` | none (`code: 0`) |
| `productClosed` | none; closes the connection |
| anything else | `code: -30000005` |

Every response has `code` and `reqType`, plus the request's `id` when one was
sent. The default product id is `10200`.

---

## Linux, Steam Deck and Wine

The Linux build logs in and patches natively, but the stub, shim and pipe
must live inside the game's Wine prefix. So on non-Windows systems
`launch` hands off to the Windows build running under Wine (`mod wine` in
`launch.rs`):

1. Find the Windows exe: `MABI_WINE_EXE`, else `mabi-patcher.exe` next to the
   Linux binary. If missing, the error explains both options.
2. Pick the Wine runner: `MABI_WINE`, else `WINE`, else `wine`.
3. Write the session to a new private temp file
   (`mabi-session-<pid>-<nanos>.json`, created exclusively with mode `0600`).
4. Run:

   ```
   <wine> mabi-patcher.exe launch --session-file <file> --client <Client.exe> [--no-wait]
   ```

   Both paths are converted with `winepath -w` (the `winepath` next to the
   runner if there is one), falling back to `Z:\...`.
5. The Windows side launches as above, writes the possibly refreshed session
   back to the file, and prints one line once `Client.exe` has started:

   ```
   MABI_LAUNCH_STARTED pid=<n> patch=<0|1> args=<n>
   ```

6. The Linux side reads the child's output, forwarding every other line. On
   the marker it merges the session back, fires `on_started` (the
   `after-launch` hook) and, with `--no-wait`, stops reading (a background
   thread keeps draining output).
7. When the child exits, the session is merged back once more and the temp
   file is deleted. A non-zero exit becomes `Wine launch failed (...)`. The CLI
   then saves the session to the profile.

Set `WINEPREFIX` to the game's prefix before running. Build the Linux binary
with `./build-linux.sh` (see [DEVELOPMENT.md](DEVELOPMENT.md)).

```sh
export WINEPREFIX="$HOME/Games/mabinogi"
export MABI_WINE=wine64            # optional
mabi-patcher launch -c "$WINEPREFIX/drive_c/Nexon/Library/mabinogi" --no-wait
```

---

## GUI launch modes

`launcher_launch` in the GUI has three modes:

| Mode | When | What happens |
|---|---|---|
| Private server | `login_ip` is set | Starts `Client.exe` with `/login <ip>:<port>` (port default 11000) and `/P:0`, no Nexon login. A "launch command override" may replace the command (see below). Off Windows, `Client.exe` runs through the Wine runner. |
| Nexon Launcher | `use_nexon_launcher` | Starts `NexonLauncher.exe --game=<product id>` from `%LOCALAPPDATA%\Programs\Nexon\Nexon Launcher\` or `C:\Program Files (x86)\Nexon\Nexon Launcher\`. |
| Official (default) | otherwise | Needs a session; runs `launch_official` without waiting, with the selected profile's device id. If the session has expired and cannot be refreshed, the GUI asks whether to log in again instead of only showing an error. |

**Launch command override.** The command is split into arguments first
(`launch::split_command_line`): double quotes group words, `""` is an empty
argument and `\"` inside quotes is a literal quote. Then `{client_dir}`,
`{exe}`, `{passport}` and `{args}` are filled in inside each argument, so a
path with spaces stays one argument. An argument that is exactly `{args}`
becomes the separate launch arguments. Example:
`"C:\Program Files\Tool\run.exe" "{exe}" {args}`.

The GUI's pre- and post-launch hook commands run synchronously (it waits for
them), unlike the CLI hooks. The GUI expects `Client.exe` directly inside
the chosen folder.

---

## Hooks

CLI hooks are set with `mabi-patcher config hook` (see
[CLI.md](CLI.md#config)). `before-launch` runs before the login chain;
`after-launch` runs as soon as `Client.exe` has started. Both run in the
install folder, do not block, and expand `%PROFILE%`.
