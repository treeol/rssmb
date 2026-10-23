#!/usr/bin/env bash
# publish_on_close integration tests: rclone --inplace + inotifywait.
#
# Starts rssmb with publish_on_close ON, then:
#   1. rclone copyto a 64 MiB file with --inplace to the share;
#      the runner polls ls -A on the backing dir every 100 ms, asserting
#      the final name NEVER appears until the copy completes.
#   2. inotifywait on the backing dir during a second copy, asserting
#      only MOVED_TO for the final name (temp → final publish).
#
# Usage: tests/conformance/poc-rclone-test.sh
# Requires: rclone, inotify-tools, rssmb binary at $RSSMB or ../../target/debug/rssmb
set -euo pipefail
cd "$(dirname "$0")/../.."

RSSMB_BIN="${RSSMB:-./target/debug/rssmb}"
CONFIG="tests/conformance/poc-on.toml"
SHARE_DIR="/tmp/rssmb-poc/public"
RC=0

# Clean and prepare the share tree.
rm -rf /tmp/rssmb-poc
mkdir -p "$SHARE_DIR"

# Start the server.
RUST_LOG=info "$RSSMB_BIN" --config "$CONFIG" > /tmp/poc-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; rm -rf /tmp/rssmb-poc' EXIT
sleep 1

echo "=== rclone --inplace test ==="

# Create a 64 MiB source file.
dd if=/dev/urandom of=/tmp/poc-source.bin bs=1M count=64 2>/dev/null

# Configure rclone with an SMB backend for rssmb.
export RCLONE_SMB_HOST="127.0.0.1"
export RCLONE_SMB_PORT="4450"
export RCLONE_SMB_USER="alice"
export RCLONE_SMB_PASS=$(rclone obscure "TestPass123")

# Poll ls -A every 100 ms during the copy; record the transcript.
TRANSCRIPT=/tmp/poc-rclone-transcript.txt
: > "$TRANSCRIPT"
FINAL_SEEN_DURING=false
(
  while true; do
    entries=$(ls -A "$SHARE_DIR" 2>/dev/null)
    echo "$(date +%H:%M:%S.%N) $entries" >> "$TRANSCRIPT"
    if echo "$entries" | grep -q '^poc-rclone-test\.bin$'; then
      FINAL_SEEN_DURING=true
    fi
    sleep 0.1
  done
) &
POLLER=$!

# Run rclone copy with --inplace.
if rclone copyto /tmp/poc-source.bin ":smb:public/poc-rclone-test.bin --inplace --smb-host=127.0.0.1 --smb-port=4450 --smb-user=alice --smb-pass="$RCLONE_SMB_PASS" 2>&1; then
  echo "  rclone copy completed successfully"
else
  echo "  ❌ rclone copy failed" >&2
  RC=1
fi

kill $POLLER 2>/dev/null || true
wait $POLLER 2>/dev/null || true

# The final name must not have appeared during the copy (only temp).
if grep -q '^poc-rclone-test\.bin$' "$TRANSCRIPT"; then
  echo "  ❌ FAIL: final name appeared on backing dir during copy (should be hidden until publish)"
  RC=1
else
  echo "  ✅ PASS: final name never appeared on backing dir during copy"
fi

# After the copy, the final name must exist and the temp must be gone.
if [ -f "$SHARE_DIR/poc-rclone-test.bin" ]; then
  echo "  ✅ PASS: final name exists after copy"
else
  echo "  ❌ FAIL: final name missing after copy"
  RC=1
fi
if ls -A "$SHARE_DIR" | grep -q '^\.rssmb-tmp\.'; then
  echo "  ❌ FAIL: temp file remains after publish"
  RC=1
else
  echo "  ✅ PASS: no temp file remains after publish"
fi

# Verify data integrity.
if cmp -s "$SHARE_DIR/poc-rclone-test.bin" /tmp/poc-source.bin; then
  echo "  ✅ PASS: data integrity verified (64 MiB match)"
else
  echo "  ❌ FAIL: data mismatch"
  RC=1
fi

echo
echo "=== inotifywait transcript test ==="

# Clean the share for the second test.
rm -f "$SHARE_DIR/poc-rclone-test.bin"
rm -f "$SHARE_DIR"/.rssmb-tmp.* 2>/dev/null || true

# Create a smaller source file for the inotify test.
dd if=/dev/urandom of=/tmp/poc-source2.bin bs=1M count=8 2>/dev/null

# Start inotifywait on the backing dir, watching for MOVED_TO events.
INOTIFY_LOG=/tmp/poc-inotify.log
: > "$INOTIFY_LOG"
inotifywait -m -e MOVED_TO,CREATE,MODIFY,DELETE "$SHARE_DIR" > "$INOTIFY_LOG" 2>&1 &
INOTIFY=$!

# Run rclone copy with --inplace.
rclone copyto /tmp/poc-source2.bin ":smb:public/poc-inotify-test.bin --inplace --smb-host=127.0.0.1 --smb-port=4450 --smb-user=alice --smb-pass="$RCLONE_SMB_PASS" 2>&1 || true

sleep 0.5
kill $INOTIFY 2>/dev/null || true
wait $INOTIFY 2>/dev/null || true

echo "  inotifywait transcript:"
cat "$INOTIFY_LOG" | sed 's/^/    /'

# Assert: only MOVED_TO for the final name (the publish rename).
# Temp CREATE/MODIFY events are on .rssmb-tmp.* — those are OK.
# The final name must appear via MOVED_TO.
if grep -q "MOVED_TO.*poc-inotify-test\.bin" "$INOTIFY_LOG"; then
  echo "  ✅ PASS: MOVED_TO for final name observed"
else
  echo "  ❌ FAIL: no MOVED_TO for final name in transcript"
  RC=1
fi

# No CREATE event for the final name (it should be MOVED_TO, not CREATE).
if grep -E "CREATE.*poc-inotify-test\.bin$" "$INOTIFY_LOG" | grep -qv "rssmb-tmp"; then
  echo "  ❌ FAIL: CREATE event for final name (should be MOVED_TO only)"
  RC=1
else
  echo "  ✅ PASS: no CREATE for final name"
fi

echo
echo "=== Transcript summary ==="
echo "rclone poll transcript ($TRANSCRIPT):"
cat "$TRANSCRIPT" | sed 's/^/  /'
echo
echo "inotifywait transcript ($INOTIFY_LOG):"
cat "$INOTIFY_LOG" | sed 's/^/  /'

if [ $RC -eq 0 ]; then
  echo
  echo "✅ publish_on_close rclone+inotify integration: PASS"
else
  echo
  echo "❌ publish_on_close rclone+inotify integration: FAIL"
fi
exit $RC