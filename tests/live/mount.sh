#!/usr/bin/env bash
# Real kernel CIFS mount against a running rssmb (Linux cifs.ko client).
#
#   tests/live/mount.sh <server-ip> [vers] [extra mount opts]
#
# Runs a throwaway privileged Alpine container (host kernel's cifs module),
# mounts //<ip>/public on port 4450 as the test user, and exercises
# ls / read / write / mkdir / rename / 64 MiB of O_DIRECT 1 MiB writes /
# delete / rmdir, then unmounts.
# Expects rssmb started with tests/live/rssmb-mount.toml (or
# rssmb-mount-encrypted.toml with: mount.sh <ip> 3.1.1 ,seal).
set -u
IP=${1:?server ip}
VERS=${2:-2.1}
EXTRA=${3:-}
exec timeout 180 docker run --rm --privileged alpine:latest sh -c "
set -e
apk add --no-cache cifs-utils >/dev/null 2>&1
mkdir -p /mnt/s
mount -t cifs //$IP/public /mnt/s -o port=4450,username=alice,password=TestPass123,vers=$VERS,noserverino$EXTRA \
  || { dmesg | grep -i cifs | tail -8; exit 1; }
echo '--- mounted'; mount | grep /mnt/s
echo '--- ls';      ls -la /mnt/s
echo '--- read';    cat /mnt/s/README.txt
echo '--- write';   echo 'written via kernel cifs' > /mnt/s/k.txt; cat /mnt/s/k.txt
echo '--- append';  echo 'line2' >> /mnt/s/k.txt; cat /mnt/s/k.txt
                    [ \"\$(cat /mnt/s/k.txt)\" = \"\$(printf 'written via kernel cifs\nline2')\" ] || { echo 'APPEND LOST DATA'; exit 1; }
echo '--- overwrite'; printf 'short' > /mnt/s/k2.txt; printf 'xy' > /mnt/s/k2.txt
                    [ \"\$(cat /mnt/s/k2.txt)\" = xy ] || { echo 'OVERWRITE WRONG'; exit 1; }; rm /mnt/s/k2.txt
echo '--- uncached'; sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
                    [ \"\$(cat /mnt/s/k.txt | wc -l)\" = 2 ] || { echo 'DATA NOT ON SERVER'; exit 1; }
echo '--- mkdir';   mkdir /mnt/s/dir1; echo inner > /mnt/s/dir1/inner.txt; ls -la /mnt/s/dir1
echo '--- rename';  mv /mnt/s/k.txt /mnt/s/dir1/renamed.txt; ls /mnt/s /mnt/s/dir1
echo '--- big';     dd if=/dev/urandom of=/tmp/big bs=1k count=300 2>/dev/null; cp /tmp/big /mnt/s/big.bin
                    cmp /tmp/big /mnt/s/big.bin && echo 'big file roundtrip OK (300 KiB)'
echo '--- direct1M'; dmesg -c >/dev/null 2>&1 || true
                    dd if=/dev/zero of=/mnt/s/big1m.bin bs=1M count=64 oflag=direct 2>&1 || true
                    sz=\$(stat -c %s /mnt/s/big1m.bin)
                    [ \"\$sz\" = 67108864 ] || { echo \"DIRECT 1M WRITE SIZE WRONG: \$sz\"; dmesg | grep -i cifs | tail -8; exit 1; }
                    if dmesg 2>/dev/null | grep -iE 'cifs.*(reconnect|abort|Send error)'; then echo 'CIFS RECONNECT DURING 1M WRITES'; exit 1; fi
                    echo 'direct 1 MiB writes OK (64 MiB, no reconnect)'; rm /mnt/s/big1m.bin
echo '--- delete';  rm /mnt/s/big.bin /mnt/s/dir1/renamed.txt /mnt/s/dir1/inner.txt; rmdir /mnt/s/dir1; ls -la /mnt/s
umount /mnt/s && echo '--- unmounted OK'
"
