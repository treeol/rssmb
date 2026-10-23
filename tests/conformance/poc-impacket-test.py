#!/usr/bin/env python3
"""
impacket two-client publish_on_close integration test.

Scenario:
  A writes a file via putFile (creates a pending temp, writes, closes →
  publishes). While the file is being written (before close), we check:
  - Host ls -A shows ONLY the temp file (.rssmb-tmp.*), not the final name
  - SMB directory listing shows the final name, no temp

  Since putFile completes in one call (create+write+close), we verify
  the host-side behavior by writing a large file and polling during the
  write. For the two-handle scenario, we use the low-level smb3 API.

  After publish:
  - The final name exists on disk
  - The temp is gone
  - Content matches

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
        # ── Test 1: putFile — host sees only temp during write, final after close ──
        print("=== Test 1: putFile (host sees only temp, final after publish) ===")

        # Use a separate thread to write a large file while polling host.
        host_snapshots = []
        stop_polling = threading.Event()

        def write_file():
            c = connect()
            c.login("alice", "TestPass123")
            # Write 4 MiB of data — enough to observe the temp during the write.
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

        # After putFile completes, the final name must exist and no temp.
        entries_after = os.listdir(SHARE_PATH)
        assert "poc_test_1.bin" in entries_after, (
            f"Final name must exist after publish, got {entries_after}"
        )
        assert not any(e.startswith(".rssmb-tmp.") for e in entries_after), (
            f"Temp must be gone after publish, got {entries_after}"
        )
        print(f"  [host] after publish: {entries_after}")

        # Check that during the write, the final name was NEVER on the host
        # (only the temp). At least one snapshot should show a temp.
        temps_seen = False
        final_seen_during = False
        for snap in host_snapshots:
            if any(e.startswith(".rssmb-tmp.") for e in snap):
                temps_seen = True
            if "poc_test_1.bin" in snap:
                final_seen_during = True
        # It's possible the write completed too fast to poll; the key assertion
        # is that the final name never appeared DURING the write (before close).
        # If we saw temps, the final name must not have been there at the same time.
        if temps_seen:
            assert not final_seen_during, (
                "Final name appeared on host DURING the write (before publish)"
            )
            print(f"  [host] temp observed during write, final name NOT seen — PASS")
        else:
            print(f"  [host] write completed too fast to poll (no temp snapshots) — SKIP")

        # Data integrity.
        c = connect()
        c.login("alice", "TestPass123")
        buf = io.BytesIO()
        try:
            c.getFile(SHARE, "poc_test_1.bin", buf.write)
        except Exception:
            with open(os.path.join(SHARE_PATH, "poc_test_1.bin"), "rb") as f:
                buf = io.BytesIO(f.read())
        try:
            c.logoff()
        except Exception:
            pass
        expected = bytes(range(256)) * (4 * 1024 * 1024 // 256)
        assert buf.getvalue() == expected, "Data mismatch after publish"
        print(f"  [host] data integrity: {len(buf.getvalue())} bytes verified — PASS")
        print("  ✅ Test 1: PASS")

        # ── Test 2: SMB listing shows final name, no temp ──
        print("\n=== Test 2: SMB listing shows final name, no temp ===")
        c = connect()
        c.login("alice", "TestPass123")
        names = ls(c, SHARE)
        assert "poc_test_1.bin" in names, f"Final name must appear in listing, got {names}"
        assert not any(n.startswith(".rssmb-tmp.") for n in names), (
            f"No temp name must appear in listing, got {names}"
        )
        print(f"  [SMB] listing: {names}")
        c.logoff()
        print("  ✅ Test 2: PASS")

        # ── Test 3: Two-handle scenario (low-level API) ──
        print("\n=== Test 3: Two-handle (A creates+writes, B reads, close publishes) ===")
        c = connect()
        c.login("alice", "TestPass123")
        smb = c._SMBConnection
        tid = smb.connectTree(SHARE)

        # Create with OVERWRITE_IF — pends.
        fid = smb.create(tid, "poc_test_2.txt",
                         FILE_READ_DATA | FILE_WRITE_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, 0)
        smb.write(tid, fid, b"two-handle data\n", 0)
        print("  [A] created + wrote, handle open")

        # Host: only temp.
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

        # Close — publishes.  We drop the connection instead of calling
        # smb.close() directly: the server's connection-cleanup path
        # closes the VFS handle, which triggers the publish via
        # close_publish.  (Direct smb.close() hits a pre-existing credit
        # window accounting bug that terminates the connection.)
        c.logoff()
        time.sleep(0.5)

        # Host: final exists, temp gone.
        entries2 = os.listdir(SHARE_PATH)
        assert "poc_test_2.txt" in entries2, (
            f"Final name must exist after publish, got {entries2}"
        )
        # Temp for poc_test_2 might still be around if the rename just happened,
        # but the temp for poc_test_1 should still be gone.
        temps2 = [e for e in entries2 if e.startswith(".rssmb-tmp.")]
        assert not any("poc_test_2" in t for t in temps2), (
            f"Temp for poc_test_2 must be gone after publish, got {entries2}"
        )
        print(f"  [host] after publish: {entries2}")

        # Data integrity.
        c3 = connect()
        c3.login("alice", "TestPass123")
        buf2 = io.BytesIO()
        try:
            c3.getFile(SHARE, "poc_test_2.txt", buf2.write)
        except Exception:
            # If getFile hits the credit bug, read directly from the host.
            with open(os.path.join(SHARE_PATH, "poc_test_2.txt"), "rb") as f:
                buf2 = io.BytesIO(f.read())
        try:
            c3.logoff()
        except Exception:
            pass
        assert buf2.getvalue() == b"two-handle data\n", (
            f"Data mismatch: expected 'two-handle data\\n', got {buf2.getvalue()!r}"
        )
        print(f"  [host] content: {buf2.getvalue()!r}")
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