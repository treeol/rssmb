#!/usr/bin/env bash
# R-07a A/B build recipe — builds the three benchmark binaries with identical
# release profiles and prints sha256, size, and (for musl mimalloc) the
# mi_malloc symbol count. Every A/B number must come from binaries built here.
set -euo pipefail
cd "$(dirname "$0")/../.."

OUT=${1:-/tmp/ab}
mkdir -p "$OUT"

echo "== main (glibc, local) =="
git worktree add -f /tmp/ab-src-main 90a70086e 2>/dev/null || true
(cd /tmp/ab-src-main && RUSTUP_TOOLCHAIN=stable cargo build --release --locked -p rssmb-cli)
cp /tmp/ab-src-main/target/release/rssmb "$OUT/ab-main-glibc"

# NOTE: in the wakil sandbox the docker `-v /mnt/...` mount exposes the HOST
# path, so a git worktree inside the sandbox is invisible to the container.
# Build from `git archive` piped into the container instead. Output goes to a
# gitignored repo path (tmp/) for the same reason.
echo "== main (glibc, local) =="
git worktree add --detach tmp/ab-main-src 90a70086e 2>/dev/null || true
(cd tmp/ab-main-src && RUSTUP_TOOLCHAIN=stable cargo build --release --locked -p rssmb-cli)
cp tmp/ab-main-src/target/release/rssmb "$OUT/ab-main-glibc"

echo "== main (musl, container) =="
git archive 90a70086e | docker run --rm -i -e RUSTUP_TOOLCHAIN=stable \
  clux/muslrust:stable sh -c \
  'mkdir -p /build && tar -x -C /build && cd /build && cargo build --release --locked -p rssmb-cli \
   --target x86_64-unknown-linux-musl \
   --config "target.x86_64-unknown-linux-musl.linker=\"x86_64-linux-musl-gcc\"" \
   && cp target/x86_64-unknown-linux-musl/release/rssmb /out/rssmb && echo BUILD_OK'
cp tmp/ab-main-musl "$OUT/ab-main-musl"

echo "== mimalloc (musl, container) =="
git archive HEAD | docker run --rm -i -e RUSTUP_TOOLCHAIN=stable \
  clux/muslrust:stable sh -c \
  'mkdir -p /build && tar -x -C /build && cd /build && cargo build --release --locked -p rssmb-cli \
   --target x86_64-unknown-linux-musl --features mimalloc \
   --config "target.x86_64-unknown-linux-musl.linker=\"x86_64-linux-musl-gcc\"" \
   && cp target/x86_64-unknown-linux-musl/release/rssmb /out/rssmb && echo BUILD_OK'
cp tmp/ab-mimalloc-musl "$OUT/ab-mimalloc-musl"

echo
echo "== digests =="
for b in ab-main-glibc ab-main-musl ab-mimalloc-musl; do
  printf '%s  sha256=%s  size=%s  mi_malloc_symbols=%s\n' \
    "$b" \
    "$(sha256sum "$OUT/$b" | cut -d' ' -f1)" \
    "$(stat -c%s "$OUT/$b")" \
    "$(nm "$OUT/$b" 2>/dev/null | grep -c mi_malloc || echo n/a)"
done

echo "== mimalloc (musl, container) =="
docker run --rm -e RUSTUP_TOOLCHAIN=stable -v /home/valon/coding/rssmb:/src -v "$OUT:/out" -w /src/rssmb \
  clux/muslrust:stable cargo build --release --locked -p rssmb-cli --target x86_64-unknown-linux-musl \
  --features mimalloc --config 'target.x86_64-unknown-linux-musl.linker="x86_64-linux-musl-gcc"'
cp target/x86_64-unknown-linux-musl/release/rssmb "$OUT/ab-mimalloc-musl"

echo
echo "== digests =="
for b in ab-main-glibc ab-main-musl ab-mimalloc-musl; do
  printf '%s  sha256=%s  size=%s  mi_malloc_symbols=%s\n' \
    "$b" \
    "$(sha256sum "$OUT/$b" | cut -d' ' -f1)" \
    "$(stat -c%s "$OUT/$b")" \
    "$(nm "$OUT/$b" 2>/dev/null | grep -c mi_malloc || echo n/a)"
done