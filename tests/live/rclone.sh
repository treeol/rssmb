#!/usr/bin/env bash
# rclone (go-smb2 backend) interop tests for rssmb.
#
# go-smb2 is a strict SPNEGO initiator: it requires negState and
# supportedMech on the server's first negTokenResp (RFC 4178 §4.2.2),
# which lenient clients (smbclient, Linux CIFS) tolerate being absent.
#
# Requires: rclone installed on the host, a running rssmb server.
#
#   tests/live/rclone.sh [scenario ...]      (default: all)
#
# Scenarios:
#   lsd     rclone lsd :smb:                       (share listing, expects "public")
#   ls      rclone ls :smb:public                  (expects README.txt)
#   copy    rclone copyto <tmp> :smb:public/rclone-upload.txt, then
#           rclone cat it back and compare with the local file
set -u
cd "$(dirname "$0")/../.."
HOST=${RSSMB_HOST:-127.0.0.1}
PORT=${RSSMB_PORT:-4450}
SCEN=${*:-"lsd ls copy"}

# On-the-fly :smb: backend via flags; no rclone config file.
RCLONE=(rclone --config /dev/null --contimeout 10s --timeout 20s --retries 1 --low-level-retries 1
  --smb-host "$HOST" --smb-port "$PORT" --smb-user alice
  --smb-pass "$(rclone obscure TestPass123)")

rc=0

# run <label> <expect-grep-pattern|""> cmd...
run() {
  local label="$1"; shift
  local expect="$1"; shift
  echo -n "$label ... "
  if timeout 30 "$@" >/tmp/rclone-$label.log 2>&1; then
    if [ -n "$expect" ] && ! grep -q -- "$expect" /tmp/rclone-$label.log; then
      echo "FAIL (missing '$expect', see /tmp/rclone-$label.log)"; rc=1
    else
      echo "PASS"
    fi
  else
    echo "FAIL (see /tmp/rclone-$label.log)"; rc=1
  fi
}

for s in $SCEN; do
  case "$s" in
    lsd)
      run "$s" "public" "${RCLONE[@]}" lsd :smb:
      ;;
    ls)
      run "$s" "README.txt" "${RCLONE[@]}" ls :smb:public
      ;;
    copy)
      tmp=$(mktemp /tmp/rssmb-rclone-upload.XXXXXX)
      echo "uploaded via rclone $(date +%s%N)" > "$tmp"
      run "${s}_put" "" "${RCLONE[@]}" copyto "$tmp" :smb:public/rclone-upload.txt
      run "${s}_cat" "" "${RCLONE[@]}" cat :smb:public/rclone-upload.txt
      if ! cmp -s "$tmp" /tmp/rclone-${s}_cat.log; then
        echo "  content mismatch: downloaded file differs from $tmp"; rc=1
      fi
      "${RCLONE[@]}" deletefile :smb:public/rclone-upload.txt >/dev/null 2>&1 || true
      rm -f "$tmp"
      ;;
    *)
      echo "unknown scenario: $s" >&2; rc=1
      ;;
  esac
done

exit $rc
