#!/usr/bin/env bash
# smbtorture baseline runner for rssmb.
#
# Starts rssmb on loopback:4450 with a temp share tree, runs a curated
# set of smbtorture suites, and records pass/fail per suite.
#
#   tests/conformance/run-smbtorture.sh [suite ...]      (default: all)
#
# Output: tests/conformance/results.md (pass/fail per suite).
# Requires: smbtorture (samba-testsuite on Debian/Ubuntu), a built
# target/debug/rssmb.
set -u
cd "$(dirname "$0")/../.."

SMBTORTURE=${SMBTORTURE:-smbtorture}
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}
SUITES=${*:-"smb2.connect smb2.read smb2.dir smb2.compound smb2.create smb2.setinfo smb2.getinfo smb2.session smb2.credits smb2.ioctl rpc.srvsvc"}

# Setup share tree — must match tests/live/rssmb-live.toml paths.
rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "hello from rssmb" > /tmp/rssmb-live/public/README.txt
echo "data" > /tmp/rssmb-live/public/data.txt
echo "secret" > /tmp/rssmb-live/private/s.txt

# Start server.
RUST_LOG=info ./target/debug/rssmb --config tests/live/rssmb-live.toml > /tmp/rssmb-torture-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 1

# Run each suite and record results.
RESULTS=tests/conformance/results.md
echo "# smbtorture baseline — $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RESULTS"
echo "" >> "$RESULTS"
echo "| Suite | Result | Notes |" >> "$RESULTS"
echo "|---|---|---|" >> "$RESULTS"

rc=0
for suite in $SUITES; do
  echo -n "Running $suite ... "
  # smbclient-style UNC: //$HOST/public
  # --option to set the port (smbtorture uses --unresolvable=local)
  if timeout 120 "$SMBTORTURE" "////$HOST/public" "$suite" \
      --option="torture:share=public" \
      --option="torture:host=$HOST" \
      --option="torture:port=$PORT" \
      --option="torture:username=alice" \
      --option="torture:password=TestPass123" \
      > "/tmp/torture-$suite.log" 2>&1; then
    echo "PASS"
    echo "| $suite | ✅ PASS | |" >> "$RESULTS"
  else
    exit_code=$?
    echo "FAIL (exit $exit_code)"
    # Extract a one-line summary from the log.
    summary=$(grep -i "FAIL\|error\|SKIP\|panic" "/tmp/torture-$suite.log" | head -3 | tr '\n' ' ' | head -c 200)
    echo "| $suite | ❌ FAIL | $summary |" >> "$RESULTS"
    rc=1
  fi
done

echo "" >> "$RESULTS"
echo "Full logs: /tmp/torture-*.log" >> "$RESULTS"

echo "Results written to $RESULTS"
exit $rc