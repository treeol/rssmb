#!/usr/bin/env python3
"""publish_on_close live scenario (impacket, host-side).

Client A (SMB2.1): CREATE a new file via putFile-style create, SET_INFO
EndOfFile to 64 MiB, write half of it. While A's handle is open:
  - host ls -A on the backing dir shows ONLY a `.rssmb-tmp.*` entry;
  - client B (second connection) lists the dir and sees the FINAL name with
    the right size (64 MiB), not the temp;
  - client B opens by final name and reads back A's data (same file).
Then A closes: the final file exists, complete, and no temp remains.
"""
import io
import os
import sys

from impacket import smb3structs
from impacket.smbconnection import SMBConnection

HOST = os.environ.get("RSSMB_HOST", "127.0.0.1")
PORT = int(os.environ.get("RSSMB_PORT", "4450"))
SHARE = "public"
BACKING = os.environ.get("RSSMB_BACKING", "/tmp/rssmb-live-pub/public")
NAME = "big.bin"
SIZE = 64 * 1024 * 1024
HALF = 32 * 1024 * 1024


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def connect():
    c = SMBConnection(HOST, HOST, sess_port=PORT,
                      preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=30)
    c.login("alice", "TestPass123")
    return c


def main():
    # Client A: create a new file with an open handle, keep it open.
    a = connect()
    tid_a = a.connectTree(SHARE)
    # FILE_OVERWRITE_IF (5): creates if missing — a "new file" disposition.
    fid_a = a.createFile(tid_a, f"\\{NAME}", 0x12019F, shareMode=7,
                         creationDisposition=smb3structs.FILE_OVERWRITE_IF)
    a.setTimeout(180)
    # Pre-size to 64 MiB: SET_INFO FileEndOfFileInformation (class 20),
    # payload = 8-byte little-endian EOF.
    import struct as _struct
    a.setInfo(tid_a, fid_a, smb3structs.SMB2_FILE_END_OF_FILE_INFO, _struct.pack("<Q", SIZE))
    # Write the first half in 1 MiB chunks.
    chunk = b"Z" * (1024 * 1024)
    off = 0
    while off < HALF:
        a.writeFile(tid_a, fid_a, chunk, offset=off)
        off += len(chunk)

    # 1) Host ls -A: only the temp (plus any pre-seeded fixtures like
    # README.txt — the pending file must be a temp, and the final name must
    # be absent).
    entries = sorted(e.name for e in os.scandir(BACKING))
    if not entries:
        fail("backing dir empty — nothing was created")
    temps = [e for e in entries if e.startswith(".rssmb-tmp.")]
    if len(temps) != 1:
        fail(f"expected exactly one .rssmb-tmp.* entry while pending, got {entries}")
    print(f"ok: host ls -A shows temp: {temps[0]} (fixtures: {entries})")
    if os.path.exists(os.path.join(BACKING, NAME)):
        fail("final name visible on backing fs while pending")

    # 2) Client B (second connection): list, see final name with right size.
    b = connect()
    listing = list(b.listPath(SHARE, "*"))
    names = [e.get_longname() for e in listing]
    if NAME not in names:
        fail(f"client B listing missing final name {NAME}: {names}")
    big = [e for e in listing if e.get_longname() == NAME][0]
    if int(big.get_filesize()) != SIZE:
        fail(f"client B sees wrong size {big.get_filesize()}, expected {SIZE}")
    leaked = [n for n in names if n.startswith(".rssmb-tmp.")]
    if leaked:
        fail(f"temp name leaked to SMB listing: {leaked}")
    print(f"ok: client B sees {NAME} size {big.get_filesize()} and no temps")

    # 3) Client B opens by final name -> same file, reads A's data.
    tid_b = b.connectTree(SHARE)
    fid_b = b.createFile(tid_b, f"\\{NAME}", 0x120089, shareMode=7,
                          creationDisposition=smb3structs.FILE_OPEN)
    b.setTimeout(180)
    data = b.readFile(tid_b, fid_b, 0, 4096)
    if data != b"Z" * 4096:
        fail(f"client B read wrong data through final name: {data[:16]!r}")
    print("ok: client B reads A's data via final name")
    b.closeFile(tid_b, fid_b)

    # 4) A closes: publish. The final file exists, complete; no temp
    # remains (pre-seeded fixtures like README.txt are untouched).
    a.closeFile(tid_a, fid_a)
    entries = sorted(e.name for e in os.scandir(BACKING))
    if NAME not in entries or any(e.startswith(".rssmb-tmp.") for e in entries):
        fail(f"after close expected {NAME} and no temps, got {entries}")
    st = os.stat(os.path.join(BACKING, NAME))
    if st.st_size != SIZE:
        fail(f"published file wrong size {st.st_size}, expected {SIZE}")
    with open(os.path.join(BACKING, NAME), "rb") as f:
        if f.read(4096) != b"Z" * 4096:
            fail("published file data wrong")
        f.seek(SIZE - 1)
        if f.read(1) != b"\x00":
            fail("published file sparse tail not zero")
    print("PASS: publish_on_close end-to-end")


if __name__ == "__main__":
    main()