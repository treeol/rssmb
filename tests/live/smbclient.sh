#!/usr/bin/env bash
# smbclient interop tests for rssmb.
#
# Requires: smbclient installed on the host, a built target/debug/rssmb.
#
#   tests/live/smbclient.sh [scenario ...]      (default: all)
#
# Scenarios:
#   list_anon     smbclient -L //host -N (anonymous share listing)
#   list_alice    smbclient -L //host -U alice (authenticated listing)
#   ls            smbclient //host/public -U alice -c 'ls'
#   get           smbclient //host/public -U alice -c 'get README.txt /tmp/rssmb-smbclient-get.txt'
#   put           smbclient //host/public -U alice -c 'put /tmp/rssmb-smbclient-put.txt upload.txt'
#   smb2          smbclient -m SMB2 //host/public -U alice -c 'ls'
#   smb3          smbclient -m SMB3 //host/public -U alice -c 'ls'
#   smb311        smbclient -m SMB3_11 //host/public -U alice -c 'ls'
set -u
cd "$(dirname "$0")/../.."
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}
SCEN=${*:-"list_anon list_alice ls get put smb2 smb3 smb311"}

# Use an array so word-splitting doesn't break the --option argument.
SMBCLIENT=(smbclient "--option=client min protocol=SMB2" "--port=$PORT")

rc=0

run() {
  local label="$1"; shift
  echo -n "$label ... "
  if timeout 30 "$@" >/tmp/smbclient-$label.log 2>&1; then
    echo "PASS"
  else
    echo "FAIL (see /tmp/smbclient-$label.log)"; rc=1
  fi
}

for s in $SCEN; do
  case "$s" in
    list_anon)
      run "$s" "${SMBCLIENT[@]}" -L "//$HOST" -N
      ;;
    list_alice)
      run "$s" "${SMBCLIENT[@]}" -L "//$HOST" -U 'alice%TestPass123'
      ;;
    ls)
      run "$s" "${SMBCLIENT[@]}" "//$HOST/public" -U 'alice%TestPass123' -c 'ls'
      ;;
    get)
      run "$s" "${SMBCLIENT[@]}" "//$HOST/public" -U 'alice%TestPass123' -c 'get README.txt /tmp/rssmb-smbclient-get.txt'
      # Verify the downloaded content.
      if [ -f /tmp/rssmb-smbclient-get.txt ]; then
        content=$(cat /tmp/rssmb-smbclient-get.txt)
        expected="hello from rssmb"
        if [ "$content" != "$expected" ]; then
          echo "  content mismatch: got '$content', expected '$expected'"; rc=1
        fi
      fi
      ;;
    put)
      echo "uploaded via smbclient" > /tmp/rssmb-smbclient-put.txt
      run "$s" "${SMBCLIENT[@]}" "//$HOST/public" -U 'alice%TestPass123' \
        -c 'put /tmp/rssmb-smbclient-put.txt upload.txt; del upload.txt'
      ;;
    smb2)
      run "$s" "${SMBCLIENT[@]}" -m SMB2 "//$HOST/public" -U 'alice%TestPass123' -c 'ls'
      ;;
    smb3)
      run "$s" "${SMBCLIENT[@]}" -m SMB3 "//$HOST/public" -U 'alice%TestPass123' -c 'ls'
      ;;
    smb311)
      run "$s" "${SMBCLIENT[@]}" -m SMB3_11 "//$HOST/public" -U 'alice%TestPass123' -c 'ls'
      ;;
    *)
      echo "unknown scenario: $s" >&2; rc=1
      ;;
  esac
done

exit $rc