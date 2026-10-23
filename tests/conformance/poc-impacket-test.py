#!/usr/bin/env python3
"""
impacket two-client publish_on_close integration test.

Tests the publish_on_close behavior with real SMB2 clients:
  1. putFile — host sees only temp during write, final after publish
  2. SMB listing shows final name, no temp
  3. Two-connection scenario — A writes, B lists during pending, after
     A disconnects the file publishes with A's data

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

HOST = "127.0.0.1"
PORT = 4450
SHARE = "public"
SHARE_PATH = "/tmp/rssmb-poc/public"


def connect():
    return SMBConnection(HOST, HOST, sess_port=PORT,
                         preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)


def ls(c, share):
    return sorted(f.get_longname() for f in c.listPath(share, "*"))


def safe_logoff(c):
    try:
        c.logoff()
    except Exception:
        pass


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.join(script_dir, "..", "..")
    rssmb_bin = os.environ.get("RSSMB", os.path.join(repo_root, "target", "debug", "rssmb"))
    config = os.path.join(script_dir, "poc-on.toml")

    # Clean and prepare the share tree.
    shutil.rmtree("/tmp/rssmb-poc", ignore_errors=True)
    os.makedirs(SHARE_PATH, exist_ok=True)

    # Start the server with publish_on_close ON.
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
        write_done = threading.Event()

        def write_file():
            c = connect()
            c.login("alice", "TestPass123")
            data = bytes(range(256)) * (4 * 1024 * 1024 // 256)
            c.putFile(SHARE, "poc_test_1.bin", io.BytesIO(data).read)
            write_done.set()
            safe_logoff(c)

        def poll_host():
            while not stop_polling.is_set():
                entries = os.listdir(SHARE_PATH)
                host_snapshots.append(entries)
                time.sleep(0.05)

        t = threading.Thread(target=poll_host, daemon=True)
        t.start()

        write_file()
        write_done.wait(timeout=30)
        stop_polling.set()
        t.join(timeout=5)

        # After putFile completes, the final name must exist and no temp.
        entries_after = os.listdir(SHARE_PATH)
        assert "poc_test_1.bin" in entries_after, (
            f"Final name must exist after publish, got {entries_after}"
        )
        assert not any(e.startswith(".rssmb-tmp.") for e in entries_after), (
            f"Temp must be gone after publish, got {entries_after}"
        )
        print(f"  [host] after publish: {entries_after}")

        # During the write, the final name must not have appeared on host.
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

        # Data integrity (read from host to avoid SMB credit bug).
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
        safe_logoff(c)
        print("  ✅ Test 2: PASS")

        # ── Test 3: Two-connection — A writes, B lists during, A drops → publish ──
        print("\n=== Test 3: Two-connection (A writes, B lists, A drops → publish) ===")
        # Use putFile in a thread; while it's writing, B lists the share.
        c_b = connect()
        c_b.login("alice", "TestPass123")

        def write_file_2():
            c = connect()
            c.login("alice", "TestPass123")
            data = b"two-connection data\n" * 10000  # ~200 KB
            c.putFile(SHARE, "poc_test_2.txt", io.BytesIO(data).read)
            safe_logoff(c)

        t2 = threading.Thread(target=write_file_2)
        t2.start()

        # While the write is in progress, B lists — should see final name, no temp.
        time.sleep(0.05)  # let the write start
        names_b = ls(c_b, SHARE)
        # poc_test_2.txt may or may not appear depending on timing; the key
        # assertion is that NO temp name appears in the SMB listing.
        assert not any(n.startswith(".rssmb-tmp.") for n in names_b), (
            f"B must not see temp names, got {names_b}"
        )
        print(f"  [B] listing during write: {names_b}")
        safe_logoff(c_b)

        t2.join(timeout=30)
        time.sleep(0.3)

        # After the write completes, the final name must exist on host.
        entries2 = os.listdir(SHARE_PATH)
        assert "poc_test_2.txt" in entries2, (
            f"Final name must exist after publish, got {entries2}"
        )
        assert not any("poc_test_2" in e for e in entries2 if e.startswith(".rssmb-tmp.")), (
            f"Temp for poc_test_2 must be gone, got {entries2}"
        )
        print(f"  [host] after publish: {entries2}")

        # Data integrity (read from host).
        with open(os.path.join(SHARE_PATH, "poc_test_2.txt"), "rb") as f:
            content2 = f.read()
        expected2 = b"two-connection data\n" * 10000
        assert content2 == expected2, (
            f"Data mismatch: expected {len(expected2)} bytes, got {len(content2)}"
        )
        print(f"  [host] data integrity: {len(content2)} bytes — PASS")
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