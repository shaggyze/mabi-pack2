#!/bin/bash
# SessionStart hook: prepare mabi-pack2 for Claude Code cloud sessions.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# Rust toolchain components used for linting/formatting
if command -v rustup >/dev/null 2>&1; then
  rustup component add clippy rustfmt >/dev/null 2>&1 || true
fi

# Fetch crates and pre-build the library, CLI and tests so cargo test/clippy start warm
cargo fetch
cargo build --all-targets

# GUI frontend (TypeScript/Vite) dependencies
if [ -f gui/package.json ]; then
  (cd gui && npm install --no-audit --no-fund)
fi
