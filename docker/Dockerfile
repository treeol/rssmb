# Multi-stage Dockerfile for RSSMB
# Stage 1: Build a fully static musl binary
# Builder image: rust 1.93 — the lockfile's sspi 0.23 requires
# rustc >= 1.93, which is the workspace rust-version (MSRV). Pinned
# deliberately (not floating `rust:1`) so release image builds are
# reproducible and stable regressions can't break them unprompted;
# bump the pin together with rust-version.
FROM rust:1.93-bookworm AS builder

# Install musl tools for static linking
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY . .

# Build a fully static binary with musl. Strip symbols for a smaller image.
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-s"
RUN cargo build --release --target x86_64-unknown-linux-musl --bin rssmb

# Stage 2: Runtime — FROM scratch, just the static binary
FROM scratch

# Copy the static binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rssmb /rssmb

# Create the config directory so bind-mounting a config file works
# (Docker creates a directory if the parent doesn't exist).
# In scratch we can't mkdir, but Docker will create parent dirs for
# bind-mount targets automatically.

# Health endpoint on 8080, SMB on 445
EXPOSE 445 8080

# Run as UID 1000 (non-root). scratch has no /etc/passwd, but Docker
# resolves numeric UIDs without it.
USER 1000:1000

ENTRYPOINT ["/rssmb", "--config", "/etc/rssmb/rssmb.toml"]
