#!/usr/bin/env bash
# Live interop harness: start rssmb on loopback:4450 with a temp share tree,
# drive it with impacket (a real SMB2 client), stop it, report.
#
#   tests/live/run.sh [scenario ...]      (default: all)
#
# Needs: a built target/debug/rssmb and a Python with impacket
# (set PY=/path/to/python; default /tmp/smbvenv/bin/python).
set -u
cd "$(dirname "$0")/../.."
PY=${PY:-/tmp/smbvenv/bin/python}
SCEN=${*:-"guest guestpriv alice badpass signed enum_guest enum_user"}
LOG=/tmp/rssmb-live-server.log

rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "hello from rssmb" > /tmp/rssmb-live/public/README.txt
echo "secret" > /tmp/rssmb-live/private/s.txt

RUST_LOG=${RUST_LOG:-info,rssmb_server=debug,rssmb_auth=debug} \
  ./target/debug/rssmb --config tests/live/rssmb-live.toml >"$LOG" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
sleep 0.7

run_scenarios() {
  for s in "$@"; do
    if timeout 20 "$PY" tests/live/client.py "$s" >"/tmp/live-$s.log" 2>&1; then
      echo "PASS $s"
    else
      echo "FAIL $s   (see /tmp/live-$s.log)"; rc=1
    fi
  done
}

rc=0
plain=""; signed=""
for s in $SCEN; do
  case $s in signed) signed=1 ;; *) plain="$plain $s" ;; esac
done
# Scenarios run against the signing=required server.
SIGNED_SCEN="signed guestsigned badpass tamper"
[ -n "$plain" ] && run_scenarios $plain

# "signed": same scenarios against a server with signing = "required".
if [ -n "$signed" ]; then
  kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
  RUST_LOG=${RUST_LOG:-info,rssmb_server=debug,rssmb_auth=debug} \
    ./target/debug/rssmb --config tests/live/rssmb-live-signed.toml >"$LOG.signed" 2>&1 &
  SRV=$!
  sleep 0.7
  for s in $SIGNED_SCEN; do
    if [ "$s" = tamper ]; then
      if timeout 40 "$PY" tests/live/tamper.py >/tmp/live-tamper.log 2>&1; then
        echo "PASS tamper (signed)"; else echo "FAIL tamper (see /tmp/live-tamper.log)"; rc=1; fi
    else
      if timeout 20 "$PY" tests/live/client.py "$s" >"/tmp/live-$s-req.log" 2>&1; then
        echo "PASS $s (signed)"; else echo "FAIL $s (signed, see /tmp/live-$s-req.log)"; rc=1; fi
    fi
  done
fi
echo "server log: $LOG"
exit $rc
