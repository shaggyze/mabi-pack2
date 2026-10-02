#!/usr/bin/env sh
# Build the mabi-patcher CLI for Linux (archive tools + NXL patcher + launcher).
# Output: release/mabi-patcher-linux-x86_64
set -e
cd "$(dirname "$0")"
cargo build --release --bin mabi-patcher
mkdir -p release
cp target/release/mabi-patcher release/mabi-patcher-linux-x86_64
echo "Built release/mabi-patcher-linux-x86_64"
