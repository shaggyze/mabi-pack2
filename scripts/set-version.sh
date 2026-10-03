#!/usr/bin/env bash
# Set the app version everywhere it is written down.
#   scripts/set-version.sh 2.0.6     set the version
#   scripts/set-version.sh           print the current version
# The GUI reads its version from the exe at runtime (get_app_version), and build.bat
# reads it from gui/src-tauri/tauri.conf.json, so only these files hold the number:
#   Cargo.toml, gui/src-tauri/Cargo.toml, gui/src-tauri/tauri.conf.json,
#   gui/package.json, gui/package-lock.json, Cargo.lock, gui/src-tauri/Cargo.lock
# Windows: set-version.bat in the repository root does the same.
set -euo pipefail
cd "$(dirname "$0")/.."

current() { sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1; }

if [ $# -eq 0 ]; then
    echo "Current version: $(current)"
    exit 0
fi

new="$1"
if ! printf '%s' "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Version must look like 2.0.6 (three numbers), got '$new'." >&2
    exit 1
fi
export NEW_VERSION="$new"

# edit FILE PERL_SUBSTITUTION EXPECTED_COUNT
# MODE=check counts the substitutions without writing; MODE=write applies them.
MODE=check
failed=0
edit() {
    local file="$1" expr="$2" want="$3" got inplace=()
    [ "$MODE" = write ] && inplace=(-i)
    if [ ! -f "$file" ]; then
        got=missing
    else
        # STDERR carries the number of substitutions (stdout is discarded).
        got=$(perl -0777 ${inplace[@]+"${inplace[@]}"} -pe "\$n = ($expr); END { print STDERR \$n + 0 }" "$file" 2>&1 >/dev/null) || true
    fi
    if [ "$got" != "$want" ]; then
        if [ "$MODE" = check ]; then
            echo "  $file: expected $want change(s), found ${got:-0}" >&2
            failed=1
            return 0
        fi
        echo "  $file: expected $want change(s), made ${got:-0}" >&2
        exit 1
    fi
    [ "$MODE" = write ] && echo "  $file"
    return 0
}

edit_all() {
    edit Cargo.toml                    's/^(\[package\]\r?\n(?:[^\[\n]*\n)*?version = ")[^"]*"/${1}$ENV{NEW_VERSION}"/m' 1
    edit gui/src-tauri/Cargo.toml      's/^(\[package\]\r?\n(?:[^\[\n]*\n)*?version = ")[^"]*"/${1}$ENV{NEW_VERSION}"/m' 1
    edit gui/src-tauri/tauri.conf.json 's/^(  "version": ")[^"]*"/${1}$ENV{NEW_VERSION}"/m' 1
    edit gui/package.json              's/^(  "version": ")[^"]*"/${1}$ENV{NEW_VERSION}"/m' 1
    edit gui/package-lock.json         's/("name": "gui",\r?\n\s*"version": ")[^"]*"/${1}$ENV{NEW_VERSION}"/g' 2
    edit Cargo.lock                    's/(name = "mabi-pack2-core"\r?\nversion = ")[^"]*"/${1}$ENV{NEW_VERSION}"/g' 1
    edit gui/src-tauri/Cargo.lock      's/(name = "(?:mabi-pack2-core|mabi-patcher)"\r?\nversion = ")[^"]*"/${1}$ENV{NEW_VERSION}"/g' 2
}

# Check every file first so a failure leaves nothing half-changed (as set-version.ps1).
edit_all
if [ "$failed" -ne 0 ]; then
    echo "No files changed." >&2
    exit 1
fi
echo "Setting version $(current) -> $new"
MODE=write
edit_all
echo "Done. Rebuild to pick up the new version (build.bat or cargo build)."
