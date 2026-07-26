# mabi-patcher REST API server — Docker image
# Runs the headless HTTP server for UOTiara WebUI integration.
#
# Build:
#   docker build -t mabi-patcher .
#
# Run (standalone):
#   docker run -p 7331:7331 \
#     -v /path/to/archives:/data/archives:ro \
#     -v /path/to/mods:/data/mods \
#     mabi-patcher
#
# Or use docker-compose.yml.

# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.82-slim-bookworm AS builder

WORKDIR /build

# System deps needed to compile C-backed crates (zstd, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build only the CLI binary (no Tauri/GUI)
RUN cargo build --release --bin mabi-pack-cli

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /build/target/release/mabi-pack-cli /usr/local/bin/mabi-patcher

# Working directories — mount your archives and mods here
RUN mkdir -p /data/archives /data/mods

WORKDIR /data

EXPOSE 7331

# Bind 0.0.0.0 so requests from outside the container reach the server.
# Override MABI_HOST / MABI_PORT via environment or docker-compose.
ENV MABI_HOST=0.0.0.0
ENV MABI_PORT=7331

ENTRYPOINT ["sh", "-c", "mabi-patcher serve --host ${MABI_HOST} --port ${MABI_PORT}"]
