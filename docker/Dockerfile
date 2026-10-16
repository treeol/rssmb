# Multi-stage Dockerfile for RSSMB
# Stage 1: Build
# MSRV is 1.78 (rust-toolchain.toml, needed for Cargo.lock v4).
FROM rust:1.90-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --bin rssmb

# Stage 2: Runtime (minimal)
FROM debian:bookworm-slim

# Install ca-certificates for TLS and create a non-root user (UID 1000)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 rssmb \
    && useradd -u 1000 -g 1000 -r -s /bin/false rssmb

COPY --from=builder /build/target/release/rssmb /usr/local/bin/rssmb

# Create the config directory so bind-mounting a config file works
# (Docker creates a directory if the parent doesn't exist).
RUN mkdir -p /etc/rssmb

# Config is NOT baked in — mount it as a volume (see docker/compose.yml).
# The server will fail fast if /etc/rssmb/rssmb.toml is missing.

# Health endpoint on 8080, SMB on 445
EXPOSE 445 8080

USER rssmb

ENTRYPOINT ["rssmb", "--config", "/etc/rssmb/rssmb.toml"]
