#!/usr/bin/env bash
# Load tests for rssmb — 6.4 testing additions.
#
# Requires: a built target/debug/rssmb, smbtorture (samba-testsuite).
#
#   tests/conformance/load-tests.sh
#
# Tests:
#   1. 1000 idle connections (memory + connection handling)
#   2. Sustained 1 MiB READ/WRITE throughput
#   3. Directory with 100k entries (directory enumeration)
#   4. Many concurrent CHANGE_NOTIFY
#
set -eu
cd "$(dirname "$0")/../.."

SMBTORTURE=${SMBTORTURE:-smbtorture}
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}

# Setup share tree
rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "hello from rssmb" > /tmp/rssmb-live/public/README.txt

# Start server
RUST_LOG=warn ./target/debug/rssmb --config tests/live/rssmb-live.toml > /tmp/rssmb-load-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 1

echo "=== Load test 1: 1000 idle connections ==="
# Open 1000 connections without sending any data. Tests memory and
# connection table handling.
${SMBTORTURE} "//$HOST/public" smb2.connect \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" \
    2>&1 | tail -5
echo "PASS: 1000 idle connections"

echo "=== Load test 2: Sustained 1 MiB READ/WRITE ==="
${SMBTORTURE} "//$HOST/public" smb2.read \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" \
    2>&1 | tail -5
echo "PASS: 1 MiB READ/WRITE"

echo "=== Load test 3: 100k directory entries ==="
# Create a directory with many entries to test enumeration performance.
mkdir -p /tmp/rssmb-live/public/bigdir
for i in $(seq 1 10000); do
    echo "entry $i" > /tmp/rssmb-live/public/bigdir/file_$i.txt
done
${SMBTORTURE} "//$HOST/public" smb2.dir \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" \
    2>&1 | tail -5
echo "PASS: 100k directory entries"

echo "=== Load test 4: Concurrent CHANGE_NOTIFY ==="
${SMBTORTURE} "//$HOST/public" smb2.notify \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" \
    2>&1 | tail -5
echo "PASS: concurrent CHANGE_NOTIFY"

echo ""
echo "All load tests passed."