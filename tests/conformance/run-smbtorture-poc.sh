#!/usr/bin/env bash
# smbtorture baseline runner with publish_on_close ON.
#
# Same as run-smbtorture.sh but starts the server with
# tests/live/rssmb-live-poc.toml (publish_on_close=true on the public share).
# Results are written to tests/conformance/results-poc.md.
#
#   tests/conformance/run-smbtorture-poc.sh [suite ...]      (default: all)
set -u
cd "$(dirname "$0")/../.."

SMBTORTURE=${SMBTORTURE:-smbtorture}
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}
SHARE=${RSSMB_SHARE:-public}
SUITES=${*:-"smb2.connect smb2.read smb2.dir smb2.compound smb2.create smb2.setinfo smb2.getinfo smb2.session smb2.credits smb2.ioctl smb2.lock smb2.lease smb2.durable-v2-open smb2.notify smb2.rename smb2.delete-on-close-perms smb2.sharemode rpc.srvsvc"}

if [ -z "$HOST" ] || [ -z "$PORT" ] || [ -z "$SHARE" ]; then
  echo "FATAL: RSSMB_HOST/RSSMB_PORT/RSSMB_SHARE must be non-empty" >&2
  exit 2
fi
UNC="//$HOST/$SHARE"
if [ -z "${UNC#//}" ] || [[ "$UNC" == *"//*" || "$UNC" == *"/" ]]; then
  echo "FATAL: malformed share path '$UNC'" >&2
  exit 2
fi

# Setup share tree.
rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "hello from rssmb" > /tmp/rssmb-live/public/README.txt
echo "data" > /tmp/rssmb-live/public/data.txt
echo "secret" > /tmp/rssmb-live/private/s.txt

# Start server with publish_on_close ON.
if [ "${RSSMB_EXTERNAL_SERVER:-0}" != "1" ]; then
  RUST_LOG=info ./target/debug/rssmb --config tests/live/rssmb-live-poc.toml > /tmp/rssmb-torture-poc-server.log 2>&1 &
  SRV=$!
  trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
  sleep 1
fi

RESULTS=tests/conformance/results-poc.md
echo "# smbtorture baseline (publish_on_close ON) — $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RESULTS"
echo "" >> "$RESULTS"
echo "- Server: rssmb $(grep -m1 '^version' Cargo.toml | cut -d'"' -f2) ($(git rev-parse --short HEAD 2>/dev/null || echo unknown))" >> "$RESULTS"
echo "- smbtorture: $($SMBTORTURE --version 2>&1 | head -1)" >> "$RESULTS"
echo "- Target: //$HOST:$PORT/$SHARE (publish_on_close=true)" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "| Suite | Result | Subtests (pass/fail/error/skip) | Failing subtests |" >> "$RESULTS"
echo "|---|---|---|---|" >> "$RESULTS"

suite_timeout() {
  case "$1" in
    smb2.lease) echo 300 ;;
    smb2.notify) echo 240 ;;
    *) echo 120 ;;
  esac
}

rc=0
for suite in $SUITES; do
  tmo=$(suite_timeout "$suite")
  echo -n "Running $suite (${tmo}s budget) ... "
  start=$SECONDS
  timeout -k 10 "$tmo" "$SMBTORTURE" -p "$PORT" -U "${RSSMB_USER:-alice}%${RSSMB_PASSWORD:-TestPass123}" \
      "//$HOST/$SHARE" "$suite" \
      --option="torture:share=$SHARE" \
      > "/tmp/torture-poc-$suite.log" 2>&1
  st=$?
  dur=$((SECONDS - start))
  if [ "$st" -eq 124 ] || [ "$st" -eq 137 ]; then
    echo "⚠️ INCOMPLETE (killed at ${dur}s, budget ${tmo}s — no count recorded)"
    echo "| $suite | ⚠️ INCOMPLETE | — (truncated after ${tmo}s, no count) | — |" >> "$RESULTS"
    rc=1
    continue
  fi
  if grep -qE 'smb_panic|PANIC|Segmentation fault' "/tmp/torture-poc-$suite.log"; then
    result="❌ FAIL (client panic)"
    rc=1
    echo "$result (subtest tally unreliable)"
    echo "| $suite | $result | — (panic in client, tally unreliable) | — |" >> "$RESULTS"
    continue
  fi
  if [ "$st" -eq 0 ]; then
    result="✅ PASS"
  else
    result="❌ FAIL (rc=$st)"
    rc=1
  fi
  total=$(grep -cE '^test: ' "/tmp/torture-poc-$suite.log" || true)
  fail=$(grep -cE '^(failure|error): ' "/tmp/torture-poc-$suite.log" || true)
  skip=$(grep -cE '^skipped|SKIP' "/tmp/torture-poc-$suite.log" || true)
  pass=$((total - fail))
  failing=$(grep -oE '^(failure|error): [a-zA-Z0-9._-]+' "/tmp/torture-poc-$suite.log" \
            | sed 's/^failure: //;s/^error: //' | sort -u | paste -sd ', ' -)
  notes="$pass/$fail/0/$skip"
  echo "$result (subtests $notes) [${dur}s]"
  echo "| $suite | $result | $notes | ${failing:- } |" >> "$RESULTS"
done

echo "" >> "$RESULTS"
echo "Full logs: /tmp/torture-poc-*.log" >> "$RESULTS"

echo "Results written to $RESULTS"
exit $rc