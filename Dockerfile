# mabi-patcher REST API + WebUI — Docker image
# Runs the headless HTTP server (API + built WebUI) for UOTiara integration.
#
# Build:
#   docker build -t mabi-patcher .
#
# Run (standalone):
#   docker run -p 7331:7331 -e MABI_API_TOKEN=change-me \
#     -v /path/to/archives:/data/archives:ro \
#     -v /path/to/mods:/data/mods \
#     mabi-patcher
#
# Or use docker-compose.yml. MABI_API_TOKEN is required whenever the server
# is reachable from outside the container (see src/api.rs::check_auth) —
# launcher credentials and mod-apply are too sensitive to leave open.

# ── WebUI build stage ────────────────────────────────────────────────────────
FROM node:22-slim AS webui-builder

WORKDIR /build/gui

COPY gui/package.json gui/package-lock.json* ./
RUN npm install

COPY gui/tsconfig.json gui/vite.config.ts gui/index.html ./
COPY gui/src ./src
# NOTE: intentionally not copying gui/src-tauri — this is a plain `vite build`
# (via `npm run build`'s `tsc && vite build`), no Tauri/Rust toolchain needed
# for the WebUI bundle itself.
RUN npm run build

# ── Rust build stage ─────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

WORKDIR /build

# System deps needed to compile C-backed crates (zstd, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
# build.rs only builds the nxl3p shim for Windows targets, but it watches these files.
COPY nxl3p-shim ./nxl3p-shim

# Build only the CLI binary (no Tauri/GUI)
RUN cargo build --release --bin mabi-patcher

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /build/target/release/mabi-patcher /usr/local/bin/mabi-patcher

# Copy the built WebUI bundle — resolved via the `<exe_dir>/webui` convention
# in src/api.rs::webui_dir(), so `mabi-patcher serve` hosts API + WebUI together.
COPY --from=webui-builder /build/gui/dist /usr/local/bin/webui

# Working directories — mount your archives and mods here
RUN mkdir -p /data/archives /data/mods

WORKDIR /data

EXPOSE 7331

# Bind 0.0.0.0 so requests from outside the container reach the server.
# Override MABI_HOST / MABI_PORT via environment or docker-compose.
# MABI_API_TOKEN has no default on purpose — the server refuses to serve a
# non-loopback bind without one (see src/api.rs::check_auth).
ENV MABI_HOST=0.0.0.0
ENV MABI_PORT=7331

ENTRYPOINT ["sh", "-c", "mabi-patcher serve --host ${MABI_HOST} --port ${MABI_PORT}"]
