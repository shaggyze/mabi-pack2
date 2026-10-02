"""mabi-patcher Mission Control — MCP server.

A thin stdio MCP server that's an HTTP client of the mabi-patcher REST API
(src/api.rs). One tool per REST route, plus a couple of composite tools
(launch_game, test_mod_for_crash) that port workflows currently only
automated by the `mabi-mod-tester` Claude Code skill into a real, repeatable
tool surface — see .gemini/MISSION_CONTROL_PLAN.md Phase 3.

Requires `mabi-patcher serve` (or `mabi-pack2 serve`) running and reachable
at MABI_API_BASE (default http://127.0.0.1:7331). If the server is bound to
anything other than loopback, set MABI_API_TOKEN to match its token.

SAFETY NOTE: `launcher_login`, `launcher_launch`, and `test_mod_for_crash`
authenticate with a *real* Nexon account and launch the *real* Mabinogi
client. They are implemented against the documented Nexon auth flow and the
existing REST endpoints, but were not exercised end-to-end against a live
account in the session that wrote this file — no Nexon credentials were
available to test with. Treat them as reviewed-but-unverified until you've
run them once yourself.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = os.environ.get("MABI_API_BASE", "http://127.0.0.1:7331")
API_TOKEN = os.environ.get("MABI_API_TOKEN")

# Defaults matching the mabi-mod-tester skill's documented setup — override
# via tool args or these env vars for a different machine/install.
GAME_DIR = os.environ.get("MABI_GAME_DIR", r"C:\Nexon\Library\mabinogi\appdata")
DEFAULT_ARCHIVE_REL = os.environ.get("MABI_TEST_ARCHIVE", r"package\uotiara_00001.it")
DEFAULT_PACK_KEY = os.environ.get("MABI_TEST_KEY", "})wWb4?-sVGHNoPKpc")

mcp = FastMCP("mabi-mission-control")


# ── HTTP plumbing ────────────────────────────────────────────────────────────

def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}


def _unwrap(resp: httpx.Response) -> Any:
    try:
        body = resp.json()
    except ValueError:
        resp.raise_for_status()
        raise RuntimeError(f"Malformed (non-JSON) response from {resp.request.url}")
    if not isinstance(body, dict) or "success" not in body:
        raise RuntimeError(f"Malformed API response from {resp.request.url}: {body!r}")
    if not body["success"]:
        raise RuntimeError(body.get("error") or f"Request to {resp.request.url} failed ({resp.status_code})")
    return body["data"]


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    resp = httpx.get(f"{API_BASE}{path}", params=params, headers=_headers(), timeout=120)
    return _unwrap(resp)


def _post(path: str, json: dict[str, Any] | None = None) -> Any:
    resp = httpx.post(f"{API_BASE}{path}", json=json or {}, headers=_headers(), timeout=180)
    return _unwrap(resp)


# ── Status / info ────────────────────────────────────────────────────────────

@mcp.tool()
def status() -> dict:
    """Get mabi-patcher server status: app name, version, API version, port."""
    return _get("/api/v1/status")


@mcp.tool()
def mabi_version() -> dict | None:
    """Locally installed Mabinogi version + client directory, read from the Windows registry. None if not installed/not Windows."""
    try:
        return _get("/api/v1/mabi-version")
    except RuntimeError:
        return None


@mcp.tool()
def salts() -> list[str]:
    """List all known archive-decryption salts (hardcoded + fetched from the salt list URL)."""
    return _get("/api/v1/salts")


# ── Archive operations ───────────────────────────────────────────────────────

@mcp.tool()
def list_archive(archive: str, key: str | None = None) -> dict:
    """List the contents of a .it/.pack archive. Omit `key` to auto-search known salts."""
    return _post("/api/v1/list", {"archive": archive, "key": key})


@mcp.tool()
def extract_archive(archive: str, output: str, key: str | None = None, filters: list[str] | None = None) -> dict:
    """Extract a .it/.pack archive to a folder. `filters` are regexes matched against entry names (omit for all entries)."""
    return _post("/api/v1/extract", {"archive": archive, "output": output, "key": key, "filters": filters or []})


@mcp.tool()
def pack_archive(
    source: str,
    output: str,
    key: str,
    formats: list[str] | None = None,
    iv: int = 0,
    path_prefix: str | None = None,
) -> dict:
    """Pack a folder into an archive. Output extension decides format: `.pack` -> legacy unencrypted PACK/MABI, anything else -> modern encrypted .it."""
    return _post("/api/v1/pack", {
        "source": source, "output": output, "key": key,
        "formats": formats or [], "iv": iv, "path_prefix": path_prefix,
    })


@mcp.tool()
def check_data_folder(path: str) -> bool:
    """Check whether `path` is (or directly contains) a `data` folder — used to decide if packing needs a data/ wrap prefix."""
    return _post("/api/v1/fs/check-data-folder", {"path": path})["has_data_folder"]


@mcp.tool()
def create_patch(base_dir: str, modified_dir: str, output: str, key: str, iv: int = 0) -> dict:
    """Create a binary diff-patch archive containing only the files that differ between base_dir and modified_dir."""
    return _post("/api/v1/patch/create", {
        "base_dir": base_dir, "modified_dir": modified_dir, "output": output, "key": key, "iv": iv,
    })


@mcp.tool()
def convert_archive(input: str, output: str, key: str | None = None, wrap_data: bool = False) -> dict:
    """Convert an archive between .it and .pack formats (decided by the output extension)."""
    return _post("/api/v1/convert", {"input": input, "output": output, "key": key, "wrap_data": wrap_data})


# ── Preview (image/text/3D mesh/terrain/audio) ───────────────────────────────

@mcp.tool()
def preview_entry(archive: str, entry_name: str, key: str | None = None) -> dict:
    """Preview a single entry inside an archive without extracting it to disk.

    Returns a dict whose shape depends on `file_type`: image (`content_image`,
    base64 PNG), text/mml/set (`content_text`), pmg (`pmg_geometry`: Three.js-
    ready vertices/normals/uvs/indices/vertex_colors for 3D rendering), rgn
    (`rgn_data`: terrain heightmap), area (`area_data`: prop placement list),
    audio (`raw_bytes` as a playable WAV byte array), or binary (`raw_bytes`
    for a hex view; capped at 32KB except audio, capped at 8MB).
    """
    return _post("/api/v1/preview", {"archive": archive, "entry_name": entry_name, "key": key})


@mcp.tool()
def export_pmg_to_obj(
    archive: str,
    entry_name: str,
    key: str | None = None,
    output: str | None = None,
    group: int | None = None,
    no_colors: bool = False,
    no_transform: bool = False,
) -> dict:
    """Export a .pmg mesh entry to Wavefront OBJ (for Blender/3D tools).

    If `output` is given, writes the .obj file there and returns its path;
    otherwise returns the OBJ text directly in the response.
    """
    return _post("/api/v1/pmg/export", {
        "archive": archive, "entry_name": entry_name, "key": key, "output": output,
        "group": group, "no_colors": no_colors, "no_transform": no_transform,
    })


# ── Mods / VFS ───────────────────────────────────────────────────────────────

@mcp.tool()
def list_mods() -> dict:
    """List .mod package files found in the mods/ folder next to the server binary, with parsed metadata."""
    return _get("/api/v1/mods")


@mcp.tool()
def mod_template() -> str:
    """Get an example .mod TOML template, for authoring new mod packages."""
    return _get("/api/v1/mod-template")["template"]


@mcp.tool()
def apply_mod(mod_toml: str, archive: str, key: str | None = None, mod_dir: str | None = None) -> dict:
    """Apply a .mod TOML package's file operations (replace/delete/patch/feature toggles) to an archive in-place."""
    return _post("/api/v1/mod/apply", {"mod_toml": mod_toml, "archive": archive, "key": key, "mod_dir": mod_dir})


@mcp.tool()
def apply_vfs_changes(archive: str, changes: list[dict], key: str | None = None) -> dict:
    """Apply a list of VFS changes (ops: delete/rename/add/merge) to an archive in-place."""
    return _post("/api/v1/mod/vfs/apply", {"archive": archive, "key": key, "changes": changes})


@mcp.tool()
def save_pending_changes(archive: str, changes: list[dict]) -> dict:
    """Persist pending VFS changes for an archive to <archive>.pending.json (pass an empty list to clear)."""
    return _post("/api/v1/mod/pending/save", {"archive": archive, "changes": changes})


@mcp.tool()
def load_pending_changes(archive: str) -> list:
    """Load previously-saved pending VFS changes for an archive."""
    return _get("/api/v1/mod/pending", params={"archive": archive})["changes"]


@mcp.tool()
def get_features(archive: str, key: str | None = None) -> dict:
    """Extract and parse features.xml.compiled from an archive into structured JSON (feature hash -> conditions)."""
    return _post("/api/v1/features/get", {"archive": archive, "key": key})


@mcp.tool()
def save_features(archive: str, features_json: str, key: str | None = None) -> dict:
    """Re-encode a modified features JSON blob (from get_features) and write it back into an archive."""
    return _post("/api/v1/features/save", {"archive": archive, "key": key, "features_json": features_json})


# ── Launcher (Windows-only server-side; will error if the server isn't Windows) ──

@mcp.tool()
def launcher_login(username: str, password: str, remember: bool = False) -> dict:
    """Log into Nexon with a Mabinogi account's email/password. Returns {session, expiresIn} — pass `session` to launcher_launch."""
    return _post("/api/v1/launcher/login", {"username": username, "password": password, "remember": remember})


@mcp.tool()
def launcher_autologin(session_token: str) -> dict:
    """Refresh a Nexon session from a previously-saved session token, without a password."""
    return _post("/api/v1/launcher/autologin", {"session_token": session_token})


@mcp.tool()
def launcher_check_maintenance(session: dict) -> bool:
    """Check whether Mabinogi is currently under maintenance."""
    return _post("/api/v1/launcher/maintenance", {"session": session})["maintenance"]


@mcp.tool()
def launcher_get_version(session: dict) -> int:
    """Get the latest published Mabinogi build version from Nexon."""
    return _post("/api/v1/launcher/version", {"session": session})["version"]


@mcp.tool()
def launcher_list_profiles() -> list[dict]:
    """List saved launcher profiles (accounts) — no session tokens included."""
    return _get("/api/v1/launcher/profiles")["profiles"]


@mcp.tool()
def launcher_save_profile(
    name: str, email: str, client_dir: str = "", auto_login: bool = False, id: str | None = None
) -> str:
    """Create (id=None) or update (id=<existing>) a launcher profile. Returns the profile ID."""
    return _post("/api/v1/launcher/profile/save", {
        "id": id, "name": name, "email": email, "client_dir": client_dir, "auto_login": auto_login,
    })["id"]


@mcp.tool()
def launcher_delete_profile(id: str) -> bool:
    """Delete a launcher profile by ID."""
    return _post("/api/v1/launcher/profile/delete", {"id": id})["deleted"]


@mcp.tool()
def launcher_load_profile(id: str) -> dict:
    """Load a launcher profile's details. Includes `session_token_for_autologin` if it has a valid remembered session."""
    return _post("/api/v1/launcher/profile/load", {"id": id})


@mcp.tool()
def launcher_update_profile_session(id: str, session_token: str, expires_in: int) -> dict:
    """Persist a fresh session token + expiry (seconds) onto a launcher profile."""
    return _post("/api/v1/launcher/profile/session", {"id": id, "session_token": session_token, "expires_in": expires_in})


@mcp.tool()
def launcher_launch(session: dict, client_dir: str) -> dict:
    """Fetch the official launch config, obtain a passport, and spawn Client.exe directly — bypasses the Nexon Launcher UI entirely, unlike screen-automation approaches."""
    return _post("/api/v1/launcher/launch", {"session": session, "client_dir": client_dir})


# ── Composite tools ──────────────────────────────────────────────────────────

@mcp.tool()
def launch_game(client_dir: str, profile_id: str | None = None, username: str | None = None, password: str | None = None) -> dict:
    """Log in (or resume a saved profile's session) and launch Mabinogi with a real auth token.

    Replaces mabi-mod-tester's screen-automation "click the Nexon Launcher's
    PLAY button" step with the actual auth+spawn flow. Provide either
    `profile_id` (a profile saved via launcher_save_profile with a valid
    remembered session) or `username`+`password` for a fresh login.
    """
    session: dict
    if profile_id:
        profile = _post("/api/v1/launcher/profile/load", {"id": profile_id})
        token = profile.get("session_token_for_autologin")
        if not token:
            raise RuntimeError(
                f"Profile '{profile_id}' has no valid remembered session. "
                "Log in once with launcher_login (remember=True) and save the "
                "session onto this profile with launcher_update_profile_session."
            )
        auth = _post("/api/v1/launcher/autologin", {"session_token": token})
        session = auth["session"]
        _post("/api/v1/launcher/profile/session", {
            "id": profile_id, "session_token": session["session_token"], "expires_in": auth.get("expiresIn", 86400),
        })
    elif username and password:
        auth = _post("/api/v1/launcher/login", {"username": username, "password": password, "remember": True})
        session = auth["session"]
    else:
        raise RuntimeError("Provide either profile_id (with a saved session) or username+password.")

    return _post("/api/v1/launcher/launch", {"session": session, "client_dir": client_dir})


def _clear_readonly(path: Path) -> bool:
    """Clear the read-only attribute if set; return whether it was set (so the caller can restore it)."""
    was_readonly = not os.access(path, os.W_OK)
    if was_readonly:
        subprocess.run(["attrib", "-r", str(path)], check=False, shell=True)
    return was_readonly


def _restore_readonly(path: Path):
    subprocess.run(["attrib", "+r", str(path)], check=False, shell=True)


def _watch_for_crash(since: float, timeout_seconds: int) -> dict | None:
    """Poll the Windows Application event log for an Event 1000 naming client.exe, newer than `since` (unix time)."""
    deadline = time.time() + timeout_seconds
    ps_script = (
        "Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=(Get-Date).AddSeconds(-%d)} "
        "-ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'client\\.exe' } "
        "| Select-Object -First 1 -Property TimeCreated, Message | ConvertTo-Json -Compress"
    )
    while time.time() < deadline:
        elapsed_window = int(time.time() - since) + 5
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script % elapsed_window],
            capture_output=True, text=True, timeout=15,
        )
        out = result.stdout.strip()
        if out:
            import json
            try:
                return json.loads(out)
            except ValueError:
                pass
        time.sleep(3)
    return None


@mcp.tool()
def test_mod_for_crash(
    remove_entries: list[str],
    client_dir: str,
    profile_id: str | None = None,
    username: str | None = None,
    password: str | None = None,
    archive_rel: str = DEFAULT_ARCHIVE_REL,
    key: str = DEFAULT_PACK_KEY,
    game_dir: str = GAME_DIR,
    survive_seconds: int = 90,
) -> dict:
    """Run one trial of the crash-test binary search against the mod archive.

    Extracts `game_dir/archive_rel`, removes any entry whose path matches one
    of the `remove_entries` regexes, repacks over the original archive, then
    launches Mabinogi (real auth via launch_game, not screen automation) and
    watches the Windows Event Log for an Application Error (Event 1000)
    naming client.exe within `survive_seconds`.

    Returns {"verdict": "crashed"|"survived", "removed_count": int, "event": {...}|None}.
    The caller (you) does the actual binary search by calling this repeatedly
    with different `remove_entries` sets, same as the manual mabi-mod-tester
    workflow — this tool just replaces the launch step and formalizes the
    crash-detection step.
    """
    archive_path = Path(game_dir) / archive_rel
    was_readonly = _clear_readonly(archive_path)
    tmp_dir = Path(tempfile.gettempdir()) / f"mabi_crashtest_{uuid.uuid4().hex}"

    try:
        extract_archive(str(archive_path), str(tmp_dir), key=key)

        patterns = [re.compile(p) for p in remove_entries]
        removed = 0
        for f in tmp_dir.rglob("*"):
            if f.is_file():
                rel = str(f.relative_to(tmp_dir)).replace("\\", "/")
                if any(p.search(rel) for p in patterns):
                    f.unlink()
                    removed += 1

        if removed == 0:
            raise RuntimeError(f"No extracted files matched any of {remove_entries!r} — nothing to test.")

        pack_archive(str(tmp_dir), str(archive_path), key)

        launch_time = time.time()
        launch_game(client_dir, profile_id=profile_id, username=username, password=password)

        event = _watch_for_crash(launch_time, survive_seconds)
        return {
            "verdict": "crashed" if event else "survived",
            "removed_count": removed,
            "event": event,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        if was_readonly:
            _restore_readonly(archive_path)


if __name__ == "__main__":
    mcp.run()
