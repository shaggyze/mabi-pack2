# Nexon NA Authentication

How mabi-patcher logs in to Nexon NA, refreshes the session and prepares a
game launch.

Source: `src/launcher/auth.rs` (all HTTP calls), `src/launcher/cli.rs`
(how the CLI uses them), `src/launcher/cookie_dec.rs` and
`src/launcher/cookies.rs` (browser cookie decryption and import).

All endpoints below are relative to `API_BASE = https://www.nexon.com/api`.
The game is product `10200` (`DEFAULT_PRODUCT_ID`). `set_product_id` changes
it for the whole process (CLI `--product-id`, API `product_id`, GUI
Settings → Patcher → Advanced); `0` means the default. Every `10200` below
is that product id.

---

## Request headers

Every call goes through one shared HTTP client (30 s timeout) and sends:

| Header | Value |
|---|---|
| `User-Agent` | `USER_AGENT` in `auth.rs`: a Nexon Launcher / Electron browser string. |
| `Accept` | `application/json, text/plain, */*` |
| `Accept-Language` | `en-GB` |
| `x-arena-fe-version` | `ARENA_VER` in `auth.rs` (an `nxl-v...` launcher build id). |
| `x-nxl-session-id` | A random 32-hex-character id, made once per process. |
| `Cookie` | The session cookies, when the call needs them (see below). |

Cookies are handled by hand, not by a cookie jar. `Set-Cookie` headers from
every response are merged back into the session; empty values are ignored.

---

## Session fields

`NexonSession` holds one field per cookie:

| Field | Cookie | Notes |
|---|---|---|
| `session_token` | `NxLSession` | Long-lived launcher session. Used to refresh. |
| `access_token` | `AToken` | Short-lived access token. Sent as `Bearer` on account and game-build calls. |
| `g_access_token` | `g_AToken` | Game-scoped token. Sent as `Bearer` on the passport call (falls back to `AToken` when empty). |
| `hashed_user_id` | `NexonUserID` | Hashed user number. Also taken from `hashedUserNo` in a login response body. Used to match profiles and in the SDK pipe. |
| `nx_gun` | `NxGUN` | Kept if present. |
| `id_token` | `id_token` | Kept if present. |
| `tpa` | — | `true` for browser/SSO sessions, which cannot be refreshed. |
| `refreshed_expires_in` | — | New NxLSession lifetime after an in-place refresh, so the caller can store it. Not saved to disk. |

The `Cookie` header is built as `NxLSession=..; AToken=..; g_AToken=..;
NexonUserID=..; NxGUN=..; id_token=..`, skipping empty values.

The login response body's `loginSessionExpiresIn` gives the session lifetime
in seconds. If absent, 86400 (24 h) is assumed.

---

## Email and password login

```
POST /account/v1/no-auth/login/launcher
{ "id": "<email>", "password": "<password>", "deviceId": "<device id>",
  "deviceType": "PC", "locale": "en" }
```

| Result | Meaning |
|---|---|
| `200` | Logged in. Cookies come in `Set-Cookie`. If neither `NxLSession` nor `AToken` is set, the login is treated as failed. |
| `206` | 2FA required. Body has `mfaKey` and `mfaType` (default `email`). Returned as `AuthError::MfaRequired`. |
| Error code `1013`, `70018`, `70019`, or `captchaToken` in the body | CAPTCHA required (`AuthError::CaptchaRequired`). Only the browser login can pass it. |
| Error code `20027` | Nexon wants this device verified (`AuthError::DeviceTrustRequired`): use the link in Nexon's email or log in once with the official launcher. The login is retried up to 4 times in all (`DEVICE_TRUST_RETRIES`), waiting 2, 4 and 6 seconds, so confirming the email meanwhile lets it through. |
| Anything else | `AuthError::Http { status, code, body }`. |

The error code is read from the `x-arena-web-errorcode` header, else from the
JSON `code` field (number or string).

### 2FA (OTP)

```
POST /account/v1/no-auth/login/launcher/otp
{ "mfaKey": "<from the 206 answer>", "otp": "<code>", "deviceId": "<device id>",
  "deviceType": "PC", "locale": "en" }
```

`200` = logged in, same as above. Other answers are mapped like the login:
CAPTCHA codes give `CaptchaRequired`, `20027` gives `DeviceTrustRequired`
(with the same retries), anything else is an `Http` error; get a fresh
`mfaKey` by logging in again.

On the CLI, `login` prints the `login-otp` command to run, with the key and
your email filled in, and exits with code 1. The API and GUI return
`{ mfa_required, mfa_key, mfa_type }` as data.

---

## Browser login (TPA)

For Google, social and other accounts that cannot use email and password.

1. The user logs in at `https://www.nexon.com/account/en/login`.
   - **GUI:** `nexon_login_webview` opens that page in an embedded window,
     deletes the window's old cookie store first, and polls the WebView2 cookie
     database every 2 seconds
     (`%LOCALAPPDATA%\com.shaggyze.mabi-patcher\EBWebView\Default\Network\Cookies`).
     Cookie values are decrypted with the WebView2 key (AES-GCM, key protected
     by DPAPI) in `cookie_dec.rs`.
   - **Official launcher import:** `import_from_nexon_launcher` reads
     `%APPDATA%\NexonLauncher\Network\Cookies` (values decrypted with DPAPI).
     The cookie database is copied to a temp file first to avoid lock
     conflicts.
2. From the `nexon.com` cookies:
   - `NxLSession` **and** `AToken` present: used as the session directly.
   - else `TpaSession` present: exchanged right away (it is single-use and
     expires in seconds):

     ```
     POST /account/v1/no-auth/login/tpa/launcher
     Cookie: TpaSession=<value>
     { "clientId": "<CLIENT_ID in auth.rs>", "deviceId": "<device id>",
       "localTime": <unix ms>, "timeOffset": <minutes west of UTC>, "autoLogin": true }
     ```

   - neither: not logged in yet; keep polling.
3. A rejected exchange stops the GUI's polling and reports the error.

Sessions from the browser or the TPA exchange are marked `tpa = true`.
Sessions imported from the official launcher are marked `tpa = false`, since
they are launcher sessions and can be refreshed.

The API route `POST /api/v1/launcher/login/tpa` takes a `tpa_session` value
and performs only the exchange step.

---

## Browser cookie import

`cookies::import_from_browsers` reads the `nexon.com` cookies of a browser
you are already logged in with, then builds the session exactly like step 2
above (`NxLSession` + `AToken` directly, else a `TpaSession` exchange).
Used by CLI `import-cookies`, API `POST /api/v1/launcher/import/cookies`,
MCP `import_cookies` and the GUI's **Import from browser** button.

| Browser | Cookie store | Decryption |
|---|---|---|
| Firefox | `cookies.sqlite` in the profile chosen from `profiles.ini` (the `[Install…]` default, else the `Default=1` profile, else any profile with a `cookies.sqlite`); `%APPDATA%\Mozilla\Firefox` on Windows, `~/.mozilla/firefox` elsewhere | none (plain text) |
| Chrome, Edge, Brave | `%LOCALAPPDATA%\<browser>\User Data\Default\Network\Cookies` | `v10` values: AES-256-GCM with the key from `User Data\Local State` (DPAPI-protected); values without a prefix: DPAPI |

Browsers are tried in that order and the first usable session wins. Each
cookie database is copied to a temp file first.

**Limitation: Chrome 127+ (`v20`).** Newer Chrome-based browsers encrypt
cookies with an app-bound key that only the browser itself can unlock.
These values cannot be decrypted from outside, and the import does not try
to read browser memory. When it sees them it reports `v20_found` (and a
note), and you should use the normal browser login instead. Chrome, Edge and
Brave decryption needs Windows (DPAPI); on other systems only Firefox is
read.

---

## Refresh (autologin)

```
POST /regional-auth/v1.0/no-auth/login/launcher/autologin
Cookie: NxLSession=<value>
{ "deviceId": "<device id>", "deviceType": "PC", "locale": "en" }
```

- `200`: new cookies are merged into the session. Fields the answer does not
  carry (for example `NxGUN`, `id_token`) are kept. If the answer has no
  `NxLSession`, the old one is kept. `refreshed_expires_in` is set.
- Nexon code `20182`: this is a browser/SSO session, which cannot be
  refreshed. The user must use the browser login again.
- Anything else: `SessionExpired`.

`refresh` refuses up front when `tpa` is true or no `NxLSession` is stored.

The code comment notes that the older `/account/v1/.../autologin` path now
returns 404.

---

## The 401 retry

Every authenticated call that gets HTTP `401` returns a typed
`AuthError::SessionExpired`. Two wrappers handle it:

| Wrapper | Used by | Behaviour |
|---|---|---|
| `with_refresh(session, f)` | launch chain, branch/manifest fetch, launch config | Run `f`. If it fails with an expired-session error, refresh once and run `f` again. |
| `with_session_retry(session, f)` | `launch --version` | Same, and also returns the new expiry so the caller can save it. |

Only typed errors trigger the retry: `SessionExpired` or `Http { status: 401 }`.
Error text is never inspected, so a message such as "downloaded 401 files" is
not mistaken for a 401. If the refresh itself fails, the result is still a
`SessionExpired` that includes both errors, so the API answers `401`.

After any refresh the CLI saves the new session and expiry on the profile.

### Checking a stored session

`check_session` calls `GET /account/v1/account` with the cookies and
`Bearer AToken`, merges any returned cookies, and returns the status
(`200` = valid). The CLI's `profile_session` treats any status other than
`200` (or a missing `AToken`) as expired and refreshes.

---

## Launch chain

`prepare_launch` follows the official launcher's order, inside
`with_refresh`:

| Step | Call | Notes |
|---|---|---|
| 1 | `GET /account/v1/account` | Cookies + `Bearer AToken`. `401` → refresh. |
| 2 | `POST /game-auth2/v1/access` `{ "productId": "10200" }` | Cookies only (the code notes that a Bearer here causes a 401). Reads `isPlayable`, `isDeveloper`, `ipBlocked`, `required2FA`. `ipBlocked` → "Access blocked from your region/IP". `200` with `isPlayable = false` → "Mabinogi is currently unavailable (under maintenance or not yet open)". |
| 3 | `POST /game-auth2/v1/playable` `{ "productId": "10200" }` | Cookies only. `400` → not playable for this account. |
| 4 | `POST /passport/v2/passport` `{ "productId": "10200" }` | Cookies + `Bearer g_AToken`. Returns `{ "passport": "..." }`. |

The passport is then used for the launch; see [LAUNCH.md](LAUNCH.md).

Other authenticated calls:

| Call | Used for |
|---|---|
| `GET /game-build/v1/configuration/games/10200` (Bearer AToken) | Launch arguments (`parameter`), `executablePath`, `patch`. |
| `GET /game-build/v1/branch/games/10200/public` (Bearer AToken) | `manifestUrl` for the patcher and for `launch --version`. |
| `GET /maintenance/v1/products/10200?lang=en` | Maintenance flag: HTTP success means "under maintenance". |

---

## Device id

`device_id(tag)` returns a stable per-machine id, matching the Nexon
Launcher's method: SHA-256 of `WMI UUID + MachineGuid + tag`, as lowercase
hex.

| Platform | Inputs |
|---|---|
| Windows | `wmic csproduct get uuid` (falls back to PowerShell `Win32_ComputerSystemProduct.UUID`) and `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`. |
| Other | `/etc/machine-id`, else `/var/lib/dbus/machine-id`. |

The result is cached per tag for the life of the process.

**Per-profile device ids.** Each profile has a `device_tag` (see
[SESSION.md](SESSION.md#profile-fields)), so two profiles on one machine get
different device ids and do not invalidate each other's sessions. New
profiles use their name as the tag; profiles saved by older versions have an
empty tag and keep the machine-only id.

| Caller | Tag |
|---|---|
| CLI `login`, `login-otp`, `launch -u` | The `--profile` name, else the email. |
| CLI `import-cookies` | The `--profile` name, else empty. |
| CLI refresh (`profile_session`) | The session's stored device id, else the profile's `device_tag`. |
| GUI | The selected profile's `device_tag`, else the login email (empty for imports). |
| API | The request's `device_id` if given, else the `profile` string. |

---

## Error summary

| `AuthError` | Meaning | CLI | API |
|---|---|---|---|
| `MfaRequired` | Submit an OTP. | Prints the `login-otp` command, exit 1. | `200`, `mfa_required` |
| `CaptchaRequired` | Use the browser login. | Message, exit 1. | `200`, `captcha_required` |
| `DeviceTrustRequired` | Verify the device (after 4 tries). | Error, exit 1. | `403` |
| `SessionExpired` | Log in again. | Error, exit 1. | `401` |
| `NotPlayable` | Maintenance, region block or not playable. | Error, exit 1. | `503` |
| `Http` | Any other failure. | Error, exit 1. | `500` |
