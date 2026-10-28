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
SCEN=${*:-"guest guestpriv alice badpass signed rename bigwrite dirclasses encrypted enum_guest enum_user share_comments share_get_info r30_reopen r11_eof"}
LOG=/tmp/rssmb-live-server.log

rm -rf /tmp/rssmb-live && mkdir -p /tmp/rssmb-live/public /tmp/rssmb-live/private
echo "hello from rssmb" > /tmp/rssmb-live/public/README.txt
echo "secret" > /tmp/rssmb-live/private/s.txt

run_scenarios() {
  for s in "$@"; do
    if timeout 20 "$PY" tests/live/client.py "$s" >"/tmp/live-$s.log" 2>&1; then
      echo "PASS $s"
    else
      echo "FAIL $s   (see /tmp/live-$s.log)"; rc=1
    fi
  done
}

start_server() {
  local cfg="$1"; shift
  RUST_LOG=${RUST_LOG:-info,rssmb_server=debug,rssmb_auth=debug} \
    ./target/debug/rssmb --config "$cfg" >"$1" 2>&1 &
  SRV=$!
  sleep 0.7
}

rc=0

# Partition scenarios into tiers by server config.
plain=""; signed=""; encrypted=""
for s in $SCEN; do
  case $s in
    signed)        signed=1 ;;
    encrypted)     encrypted=1 ;;
    *)             plain="$plain $s" ;;
  esac
done

# Tier 1: default config (signing=desired, encryption=disabled).
if [ -n "$plain" ]; then
  start_server tests/live/rssmb-live.toml "$LOG"
  run_scenarios $plain
  kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
fi

# Tier 2: signing=required config.
if [ -n "$signed" ]; then
  start_server tests/live/rssmb-live-signed.toml "$LOG.signed"
  for s in signed guestsigned badpass tamper; do
    case "$s" in
      tamper)
        if timeout 40 "$PY" tests/live/tamper.py >/tmp/live-tamper.log 2>&1; then
          echo "PASS tamper (signed)"; else echo "FAIL tamper (see /tmp/live-tamper.log)"; rc=1; fi
        ;;
      *)
        if timeout 20 "$PY" tests/live/client.py "$s" >"/tmp/live-$s-req.log" 2>&1; then
          echo "PASS $s (signed)"; else echo "FAIL $s (signed, see /tmp/live-$s-req.log)"; rc=1; fi
        ;;
    esac
  done
  kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
fi

# Tier 3: encryption=desired config (SMB 3.1.1 with GCM).
if [ -n "$encrypted" ]; then
  start_server tests/live/rssmb-live-encrypted.toml "$LOG.encrypted"
  run_scenarios encrypted bigwrite_311
  kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
fi

echo "server log: $LOG"
exit $rc