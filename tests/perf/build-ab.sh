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
(cd /tmp/ab-src-main && cargo build --release --locked -p rssmb-cli)
cp /tmp/ab-src-main/target/release/rssmb "$OUT/ab-main-glibc"

echo "== main (musl, container) =="
docker run --rm -v "$PWD/..:/src:ro" -v "$OUT:/out" -w /src \
  clux/muslrust:stable cargo build --release --locked -p rssmb-cli --target x86_64-unknown-linux-musl \
  --config 'target.x86_64-unknown-linux-musl.linker="x86_64-linux-musl-gcc"'
cp target/x86_64-unknown-linux-musl/release/rssmb "$OUT/ab-main-musl" 2>/dev/null || true

echo "== mimalloc (musl, container) =="
docker run --rm -v "$PWD/..:/src:ro" -v "$OUT:/out" -w /src \
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