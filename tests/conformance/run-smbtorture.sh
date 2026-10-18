#!/usr/bin/env bash
# smbtorture baseline runner for rssmb.
#
# Starts rssmb on loopback:4450 with a temp share tree, runs a curated
# set of smbtorture suites, and records pass/fail per suite and per
# subtest in tests/conformance/results.md.
#
#   tests/conformance/run-smbtorture.sh [suite ...]      (default: all)
#
# Requires: smbtorture (samba-testsuite on Debian/Ubuntu), a built
# target/debug/rssmb.
set -u
cd "$(dirname "$0")/../.."

SMBTORTURE=${SMBTORTURE:-smbtorture}
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}
SHARE=${RSSMB_SHARE:-public}
SUITES=${*:-"smb2.connect smb2.read smb2.dir smb2.compound smb2.create smb2.setinfo smb2.getinfo smb2.session smb2.credits smb2.ioctl smb2.lock smb2.lease smb2.durable-v2-open smb2.notify smb2.rename smb2.delete-on-close-perms smb2.sharemode rpc.srvsvc"}

# Fail fast on an unusable share path. The nightly run 39108340146
# silently passed an empty host into the UNC ("\\\public"), and every
# suite then failed identically with NT_STATUS_OBJECT_NAME_NOT_FOUND.
if [ -z "$HOST" ] || [ -z "$PORT" ] || [ -z "$SHARE" ]; then
  echo "FATAL: RSSMB_HOST/RSSMB_PORT/RSSMB_SHARE must be non-empty" >&2
  echo "  got HOST='$HOST' PORT='$PORT' SHARE='$SHARE'" >&2
  exit 2
fi
UNC="//$HOST/$SHARE"
if [ -z "${UNC#//}" ] || [[ "$UNC" == *"//*" || "$UNC" == *"/" ]]; then
  echo "FATAL: malformed share path '$UNC'" >&2
  exit 2
fi

# Setup share tree — must match tests/live/rssmb-live.toml paths.
rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "hello from rssmb" > /tmp/rssmb-live/public/README.txt
echo "data" > /tmp/rssmb-live/public/data.txt
echo "secret" > /tmp/rssmb-live/private/s.txt

# Start server (unless the caller manages one, e.g. the CI job).
if [ "${RSSMB_EXTERNAL_SERVER:-0}" != "1" ]; then
  RUST_LOG=info ./target/debug/rssmb --config tests/live/rssmb-live.toml > /tmp/rssmb-torture-server.log 2>&1 &
  SRV=$!
  trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
  sleep 1
fi

# Run each suite and record results.
RESULTS=tests/conformance/results.md
echo "# smbtorture baseline — $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RESULTS"
echo "" >> "$RESULTS"
echo "- Server: rssmb $(grep -m1 '^version' Cargo.toml | cut -d'"' -f2) ($(git rev-parse --short HEAD 2>/dev/null || echo unknown))" >> "$RESULTS"
echo "- smbtorture: $($SMBTORTURE --version 2>&1 | head -1)" >> "$RESULTS"
echo "- Target: //$HOST:$PORT/$SHARE" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "| Suite | Result | Subtests (pass/fail/error/skip) | Failing subtests |" >> "$RESULTS"
echo "|---|---|---|---|" >> "$RESULTS"

rc=0
for suite in $SUITES; do
  echo -n "Running $suite ... "
  # smbtorture ignores torture:port options (verified via strace on 4.19.5:
  # it dials 445 regardless). The supported flags are -p/--smb-ports and
  # -U user%pass. UNC is plain //host/share — the host:port form is not
  # accepted by this build either.
  if timeout 120 "$SMBTORTURE" -p "$PORT" -U "${RSSMB_USER:-alice}%${RSSMB_PASSWORD:-TestPass123}" \
      "//$HOST/$SHARE" "$suite" \
      --option="torture:share=$SHARE" \
      > "/tmp/torture-$suite.log" 2>&1; then
    result="✅ PASS"
  else
    result="❌ FAIL"
    rc=1
  fi
  # Per-subtest tallies. smbtorture 4.19.5 emits, per subtest:
  #   "test: <name>" ... then "success: <name>" or "failure: <name> ["
  #   (or "error: <name>"), plus "SKIP:" for skipped subtests.
  total=$(grep -cE '^test: ' "/tmp/torture-$suite.log" || true)
  fail=$(grep -cE '^(failure|error): ' "/tmp/torture-$suite.log" || true)
  skip=$(grep -cE '^skipped|SKIP' "/tmp/torture-$suite.log" || true)
  pass=$((total - fail))
  failing=$(grep -oE '^(failure|error): [a-zA-Z0-9._-]+' "/tmp/torture-$suite.log" \
            | sed 's/^failure: //;s/^error: //' | sort -u | paste -sd ', ' -)
  notes="$pass/$fail/0/$skip"
  echo "$result (subtests $notes)"
  # shellcheck disable=SC2016  # literal pipes are table cells, not commands
  echo "| $suite | $result | $notes | ${failing:- } |" >> "$RESULTS"
done

echo "" >> "$RESULTS"
echo "Full logs: /tmp/torture-*.log" >> "$RESULTS"

echo "Results written to $RESULTS"
exit $rc
