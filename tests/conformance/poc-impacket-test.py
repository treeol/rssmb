#!/usr/bin/env python3
"""
impacket two-client publish_on_close integration test.

Tests the publish_on_close behavior with real SMB2 clients:
  1. putFile — host sees only temp during write, final after publish
  2. SMB listing shows final name, no temp
  3. Two-handle scenario — A creates+writes, B lists, A closes → publish,
     B reads back via SMB to verify data integrity

Asserts:
  - No temp name ever reaches the SMB client (directory listing).
  - Host ls -A shows only the temp, never the final name until publish.
  - After publish, final name on disk with correct data.
"""
import io
import os
import sys
import shutil
import subprocess
import time
import threading

from impacket.smbconnection import SMBConnection
from impacket import smb3structs
from impacket.smb3structs import (FILE_READ_DATA, FILE_WRITE_DATA,
                                    FILE_SHARE_READ, FILE_SHARE_WRITE,
                                    FILE_NON_DIRECTORY_FILE,
                                    FILE_OVERWRITE_IF, FILE_OPEN)

HOST = "127.0.0.1"
PORT = 4450
SHARE = "public"
SHARE_PATH = "/tmp/rssmb-poc/public"


def connect():
    return SMBConnection(HOST, HOST, sess_port=PORT,
                         preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)


def ls(c, share):
    return sorted(f.get_longname() for f in c.listPath(share, "*"))


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.join(script_dir, "..", "..")
    rssmb_bin = os.environ.get("RSSMB", os.path.join(repo_root, "target", "debug", "rssmb"))
    config = os.path.join(script_dir, "poc-on.toml")

    shutil.rmtree("/tmp/rssmb-poc", ignore_errors=True)
    os.makedirs(SHARE_PATH, exist_ok=True)

    server = subprocess.Popen(
        [rssmb_bin, "--config", config],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
    )
    time.sleep(2)

    rc = 0
    try:
        # ── Test 1: putFile — host sees only temp during write ──
        print("=== Test 1: putFile (host sees only temp, final after publish) ===")

        host_snapshots = []
        stop_polling = threading.Event()

        def write_file():
            c = connect()
            c.login("alice", "TestPass123")
            data = bytes(range(256)) * (4 * 1024 * 1024 // 256)
            c.putFile(SHARE, "poc_test_1.bin", io.BytesIO(data).read)
            c.logoff()

        def poll_host():
            while not stop_polling.is_set():
                entries = os.listdir(SHARE_PATH)
                host_snapshots.append(entries)
                time.sleep(0.05)

        t = threading.Thread(target=poll_host, daemon=True)
        t.start()
        write_file()
        stop_polling.set()
        t.join(timeout=5)

        entries_after = os.listdir(SHARE_PATH)
        assert "poc_test_1.bin" in entries_after, (
            f"Final name must exist after publish, got {entries_after}"
        )
        assert not any(e.startswith(".rssmb-tmp.") for e in entries_after), (
            f"Temp must be gone after publish, got {entries_after}"
        )
        print(f"  [host] after publish: {entries_after}")

        temps_seen = any(
            any(e.startswith(".rssmb-tmp.") for e in snap)
            for snap in host_snapshots
        )
        final_during = any("poc_test_1.bin" in snap for snap in host_snapshots)
        if temps_seen:
            assert not final_during, (
                "Final name appeared on host DURING the write (before publish)"
            )
            print(f"  [host] temp observed during write, final NOT seen — PASS")
        else:
            print(f"  [host] write too fast to poll — SKIP")

        with open(os.path.join(SHARE_PATH, "poc_test_1.bin"), "rb") as f:
            content = f.read()
        expected = bytes(range(256)) * (4 * 1024 * 1024 // 256)
        assert content == expected, "Data mismatch after publish"
        print(f"  [host] data integrity: {len(content)} bytes — PASS")
        print("  ✅ Test 1: PASS")

        # ── Test 2: SMB listing shows final name, no temp ──
        print("\n=== Test 2: SMB listing shows final name, no temp ===")
        c = connect()
        c.login("alice", "TestPass123")
        names = ls(c, SHARE)
        assert "poc_test_1.bin" in names, f"Final name must appear, got {names}"
        assert not any(n.startswith(".rssmb-tmp.") for n in names), (
            f"No temp in listing, got {names}"
        )
        print(f"  [SMB] listing: {names}")
        c.logoff()
        print("  ✅ Test 2: PASS")

        # ── Test 3: Two-handle — A creates+writes+closes, B reads back ──
        print("\n=== Test 3: Two-handle (A creates+writes+closes, B reads) ===")
        c = connect()
        c.login("alice", "TestPass123")
        smb = c._SMBConnection
        tid = smb.connectTree(SHARE)

        fid = smb.create(tid, "poc_test_2.txt",
                         FILE_READ_DATA | FILE_WRITE_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, 0)
        smb.write(tid, fid, b"two-handle data\n", 0, len(b"two-handle data\n"))
        print("  [A] created + wrote, handle open")

        entries = os.listdir(SHARE_PATH)
        temps = [e for e in entries if e.startswith(".rssmb-tmp.")]
        finals = [e for e in entries if not e.startswith(".rssmb-tmp.")]
        assert len(temps) >= 1, f"Expected temp on host, got {entries}"
        assert "poc_test_2.txt" not in finals, (
            f"Final name must NOT exist on host while pending, got {entries}"
        )
        print(f"  [host] only temp: {entries}")

        # B lists — sees final name, no temp.
        c2 = connect()
        c2.login("alice", "TestPass123")
        names2 = ls(c2, SHARE)
        assert "poc_test_2.txt" in names2, f"B must see final name, got {names2}"
        assert not any(n.startswith(".rssmb-tmp.") for n in names2), (
            f"B must not see temp, got {names2}"
        )
        print(f"  [B] listing: {names2}")
        c2.logoff()

        # A closes — publishes (smb.close() now works after credit fix).
        smb.close(tid, fid)
        c.logoff()
        time.sleep(0.3)

        entries2 = os.listdir(SHARE_PATH)
        assert "poc_test_2.txt" in entries2, (
            f"Final name must exist after publish, got {entries2}"
        )
        assert not any("poc_test_2" in e for e in entries2 if e.startswith(".rssmb-tmp.")), (
            f"Temp for poc_test_2 must be gone, got {entries2}"
        )
        print(f"  [host] after publish: {entries2}")

        # B reads back via SMB to verify data integrity.
        c3 = connect()
        c3.login("alice", "TestPass123")
        buf2 = io.BytesIO()
        c3.getFile(SHARE, "poc_test_2.txt", buf2.write)
        c3.logoff()
        assert buf2.getvalue() == b"two-handle data\n", (
            f"Data mismatch: expected 'two-handle data\\n', got {buf2.getvalue()!r}"
        )
        print(f"  [B] read-back via SMB: {buf2.getvalue()!r} — PASS")
        print("  ✅ Test 3: PASS")

        print("\n✅ All publish_on_close integration tests: PASS")
        return 0

    except AssertionError as e:
        print(f"\n❌ FAIL — {e}", file=sys.stderr)
        rc = 1
    except Exception as e:
        print(f"\n❌ ERROR — {e}", file=sys.stderr)
        import traceback; traceback.print_exc()
        rc = 2
    finally:
        server.terminate()
        server.wait()
        shutil.rmtree("/tmp/rssmb-poc", ignore_errors=True)

    return rc


if __name__ == "__main__":
    sys.exit(main())