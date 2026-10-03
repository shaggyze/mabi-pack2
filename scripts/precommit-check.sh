#!/usr/bin/env bash
# Pre-commit gate: the commit is refused unless the same checks build.bat and CI rely on pass.
#   - cargo check + clippy (errors only; existing warnings are allowed) for the core crate
#   - all lib unit tests plus the non-ignored tests/ suites, as CI runs them
#   - when GUI files are staged: TypeScript type-check and the GUI crate's cargo check
# Set SKIP_GUI_CHECK=1 to skip the GUI part on a machine without node_modules.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

fail() { echo "pre-commit: $1 failed, commit blocked." >&2; exit 1; }
step() { echo "pre-commit: $1..." >&2; }

step "cargo check"
cargo check --release --bins --lib --quiet || fail "cargo check"

step "cargo clippy"
cargo clippy --release --bins --lib --quiet || fail "cargo clippy"

step "lib tests"
cargo test --release --lib --quiet || fail "cargo test --lib"

step "integration tests"
cargo test --release --tests --quiet || fail "cargo test --tests"

# Staged files, plus unstaged/untracked ones: the Claude hook runs before `git add` in
# `git add -A && git commit`, so nothing may be staged yet.
changed="$(git diff --cached --name-only 2>/dev/null; git diff HEAD --name-only 2>/dev/null; git ls-files --others --exclude-standard 2>/dev/null)"
if [ -z "${SKIP_GUI_CHECK:-}" ] && echo "$changed" | grep -q '^gui/'; then
    if [ -d gui/node_modules ]; then
        step "GUI type-check"
        (cd gui && npx --no-install tsc --noEmit) || fail "GUI tsc"
    else
        echo "pre-commit: gui/node_modules missing, run 'npm install' in gui (or set SKIP_GUI_CHECK=1)." >&2
        exit 1
    fi
    step "GUI cargo check"
    (cd gui/src-tauri && cargo check --quiet ${GUI_TARGET:+--target "$GUI_TARGET"}) || fail "GUI cargo check"
fi

echo "pre-commit: all checks passed." >&2
