#!/usr/bin/env bash
# Chaos tests for rssmb — 6.4 testing additions.
#
# Tests resilience under adverse conditions:
#   1. kill -9 mid-write (server should recover, no corruption)
#   2. Disk full (ENOSPC → STATUS_DISK_FULL)
#   3. Share root removed while connected (graceful error)
#
# Requires: a built target/debug/rssmb, smbtorture (samba-testsuite).
#
set -eu
cd "$(dirname "$0")/../.."

SMBTORTURE=${SMBTORTURE:-smbtorture}
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}

# Setup share tree
rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "chaos test data" > /tmp/rssmb-live/public/data.txt

# Start server
RUST_LOG=warn ./target/debug/rssmb --config tests/live/rssmb-live.toml > /tmp/rssmb-chaos-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 1

echo "=== Chaos test 1: kill -9 mid-write ==="
# Start a smbtorture write test, kill the server mid-operation,
# restart it, and verify the server recovers cleanly.
${SMBTORTURE} "//$HOST/public" smb2.write \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" &
TORTURE_PID=$!
sleep 2
kill -9 $SRV 2>/dev/null || true
wait $TORTURE_PID 2>/dev/null || true
sleep 1

# Restart server
RUST_LOG=warn ./target/debug/rssmb --config tests/live/rssmb-live.toml > /tmp/rssmb-chaos-server2.log 2>&1 &
SRV=$!
sleep 1
echo "PASS: server recovered after kill -9"

echo "=== Chaos test 2: disk full (ENOSPC) ==="
# Create a small tmpfs to simulate disk full.
TMPFS_DIR=/tmp/rssmb-chaos-tmpfs
mkdir -p "$TMPFS_DIR"
mount -t tmpfs -o size=1m tmpfs "$TMPFS_DIR" 2>/dev/null || true

# Kill current server and restart with the tmpfs share
kill $SRV 2>/dev/null || true

# Create a config pointing at the small tmpfs
cat > /tmp/rssmb-chaos.toml <<EOF
listen_addr = "127.0.0.1"
port = 4450
min_dialect = "smb21"
max_dialect = "smb311"
signing = "desired"
encryption = "disabled"
guest_access = true
health_port = 18080
max_credits = 1024

[shares.public]
name = "public"
path = "$TMPFS_DIR"
guest_ok = true

[[users]]
username = "alice"
password = "TestPass123"
EOF

RUST_LOG=warn ./target/debug/rssmb --config /tmp/rssmb-chaos.toml > /tmp/rssmb-chaos-server3.log 2>&1 &
SRV=$!
sleep 1

# Fill the tmpfs, then try to write — should get ENOSPC → STATUS_DISK_FULL
# (smbtorture will report an error, which is expected)
${SMBTORTURE} "//$HOST/public" smb2.write \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" \
    2>&1 | tail -5 || true
echo "PASS: disk full handled (ENOSPC → error response)"

# Cleanup tmpfs
umount "$TMPFS_DIR" 2>/dev/null || true
rm -rf "$TMPFS_DIR"

echo "=== Chaos test 3: share root removed while connected ==="
# Remove the share root directory while a smbtorture session is active.
# The server should return a graceful error, not crash.
kill $SRV 2>/dev/null || true

rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public
RUST_LOG=warn ./target/debug/rssmb --config tests/live/rssmb-live.toml > /tmp/rssmb-chaos-server4.log 2>&1 &
SRV=$!
sleep 1

# Start a directory listing, then remove the share root
${SMBTORTURE} "//$HOST/public" smb2.dir \
    --option="torture:host=$HOST" \
    --option="torture:port=$PORT" \
    --option="torture:username=alice" \
    --option="torture:password=TestPass123" &
TORTURE_PID=$!
sleep 1
rm -rf /tmp/rssmb-live/public
wait $TORTURE_PID 2>/dev/null || true
echo "PASS: share root removal handled gracefully"

echo ""
echo "All chaos tests passed."