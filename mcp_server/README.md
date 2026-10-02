# mabi-patcher Mission Control (MCP server)

A stdio MCP server exposing mabi-patcher's pack/extract/mod/launcher
operations as tools, by acting as a thin HTTP client of the REST API in
`src/api.rs`. See `.gemini/MISSION_CONTROL_PLAN.md` Phase 3.

## Requirements

- `mabi-patcher serve` (or `mabi-pack2 serve`) running and reachable.
- Python packages `mcp` and `httpx` (both already pulled in by the `mcp` pip
  package; no separate `httpx` install needed).

## Configuration (env vars)

| Var | Default | Purpose |
|---|---|---|
| `MABI_API_BASE` | `http://127.0.0.1:7331` | Base URL of the running REST API |
| `MABI_API_TOKEN` | *(none)* | Bearer token, only needed if the API is bound to a non-loopback host |
| `MABI_GAME_DIR` | `C:\Nexon\Library\mabinogi\appdata` | Default game directory for `test_mod_for_crash` |
| `MABI_TEST_ARCHIVE` | `package\uotiara_00001.it` | Default archive (relative to `MABI_GAME_DIR`) for `test_mod_for_crash` |
| `MABI_TEST_KEY` | (uotiara's known salt) | Default decryption key for `test_mod_for_crash` |

## Running

```
python mcp_server/mission_control.py
```

Runs over stdio — register it with your MCP host (Claude Code, etc.) as a
command rather than running it standalone in normal use.

## Safety note

`launcher_login`, `launcher_launch`, `launch_game`, and `test_mod_for_crash`
authenticate with a real Nexon account and launch the real Mabinogi client.
They were implemented against the documented auth flow and existing REST
endpoints but have not been exercised against a live account — no Nexon
credentials were available when this was written. Review before first use.
