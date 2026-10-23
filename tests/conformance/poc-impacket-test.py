#!/usr/bin/env python3
"""
impacket two-client publish_on_close integration test.

Scenario:
  A opens a new file on the share and writes data to it (file is pending).
  B lists the directory — the final name must appear (the temp is hidden,
  but the pending entry is synthesized in directory listings).
  B opens the same final name (attach to the pending entry).
  Host filesystem: ls -A shows ONLY the temp file, not the final name
  (the final name doesn't exist on disk until A or B's last close).
  A closes — not last (B still open). No publish.
  B closes — last close. Publish: temp → final.
  After: the final name exists on disk with the last-written data.

Asserts:
  - No temp name ever reaches the SMB client (directory listing).
  - The final name appears in the directory listing while pending.
  - Host ls -A shows only the temp, never the final name until publish.
  - After last close, the final name exists on disk with correct data.
"""
import io
import os
import sys
import shutil
import subprocess
import time

from impacket.smbconnection import SMBConnection
from impacket import smb3structs
from impacket.smb3structs import (FILE_READ_DATA, FILE_WRITE_DATA,
                                    FILE_SHARE_READ, FILE_SHARE_WRITE,
                                    FILE_NON_DIRECTORY_FILE,
                                    FILE_OVERWRITE_IF, FILE_OPEN)

HOST = "127.0.0.1"
PORT = 4450


def connect():
    return SMBConnection(HOST, HOST, sess_port=PORT,
                         preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)


def ls(c, share):
    names = sorted(f.get_longname() for f in c.listPath(share, "*"))
    return names


def main():
    share_path = "/tmp/rssmb-poc/public"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.join(script_dir, "..", "..")
    rssmb_bin = os.environ.get("RSSMB", os.path.join(repo_root, "target", "debug", "rssmb"))
    config = os.path.join(script_dir, "poc-on.toml")
    # Clean and prepare the share tree.
    shutil.rmtree("/tmp/rssmb-poc", ignore_errors=True)
    os.makedirs(share_path, exist_ok=True)

    # Start the server with publish_on_close ON.
    server = subprocess.Popen(
        [rssmb_bin, "--config", config],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
    )
    time.sleep(2)

    try:
        # Client A: connect, create (OVERWRITE_IF), write — keep handle open.
        conn_a = connect()
        conn_a.login("alice", "TestPass123")
        print(f"  [A] connected, dialect: {conn_a.getDialect()}")
        smb_a = conn_a._SMBConnection
        tid_a = smb_a.connectTree("public")
        fid_a = smb_a.create(tid_a, "poc_test.txt",
                             FILE_READ_DATA | FILE_WRITE_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, 0)
        smb_a.write(tid_a, fid_a, b"A writes this data\n", 0)
        print(f"  [A] created + wrote, handle open")

        # Host check: ls -A shows only the temp, not the final name.
        entries = os.listdir(share_path)
        temps = [e for e in entries if e.startswith(".rssmb-tmp.")]
        finals = [e for e in entries if not e.startswith(".rssmb-tmp.")]
        assert len(temps) >= 1, f"Expected at least one temp file on host, got {entries}"
        assert "poc_test.txt" not in finals, (
            f"Final name must NOT exist on host while pending, got {entries}"
        )
        print(f"  [host] ls shows only temp: {entries}")

        # Client B: connect, list dir, open same file (attach).
        conn_b = connect()
        conn_b.login("alice", "TestPass123")
        print(f"  [B] connected, dialect: {conn_b.getDialect()}")

        # B lists the directory — the final name must appear, no temp.
        names_b = ls(conn_b, "public")
        assert "poc_test.txt" in names_b, (
            f"Final name must appear in SMB listing while pending, got {names_b}"
        )
        assert not any(n.startswith(".rssmb-tmp.") for n in names_b), (
            f"No temp name must appear in SMB listing, got {names_b}"
        )
        print(f"  [B] SMB listing shows final name, no temp: {names_b}")

        # B opens the same file (attach to pending, FILE_OPEN).
        smb_b = conn_b._SMBConnection
        tid_b = smb_b.connectTree("public")
        fid_b = smb_b.create(tid_b, "poc_test.txt",
                             FILE_READ_DATA | FILE_WRITE_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             FILE_NON_DIRECTORY_FILE, FILE_OPEN, 0)
        print(f"  [B] opened same file (attach)")

        # A closes — not last (B still has a handle).
        smb_a.close(tid_a, fid_a)
        conn_a.disconnect()
        print("  [A] closed + disconnected (not last)")

        # Host check again: still only temp.
        entries2 = os.listdir(share_path)
        assert "poc_test.txt" not in entries2, (
            f"Final name must not exist on host before last close, got {entries2}"
        )
        print(f"  [host] still only temp: {entries2}")

        # B closes — last close, publishes.
        smb_b.close(tid_b, fid_b)
        conn_b.disconnect()
        time.sleep(0.5)  # allow rename to settle

        # Host check: final name now exists, temp gone.
        entries3 = os.listdir(share_path)
        assert "poc_test.txt" in entries3, (
            f"Final name must exist after last close (publish), got {entries3}"
        )
        assert not any(e.startswith(".rssmb-tmp.") for e in entries3), (
            f"Temp must be gone after publish, got {entries3}"
        )
        print(f"  [host] after publish: {entries3}")

        # Data integrity: file content is A's data.
        buf = io.BytesIO()
        conn_c = connect()
        conn_c.login("alice", "TestPass123")
        conn_c.getFile("public", "poc_test.txt", buf.write)
        conn_c.disconnect()
        content = buf.getvalue()
        assert content == b"A writes this data\n", (
            f"Content mismatch: expected A's data, got {content!r}"
        )
        print(f"  [host] content verified: {content!r}")

        print("\n✅ impacket two-client scenario: PASS")
        print("   - No temp name ever reached the SMB client")
        print("   - Final name appeared in SMB listing while pending")
        print("   - Host ls showed only temp until last close")
        print("   - After publish: final name on disk with correct data")
        return 0

    except AssertionError as e:
        print(f"\n❌ impacket two-client scenario: FAIL — {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n❌ impacket two-client scenario: ERROR — {e}", file=sys.stderr)
        import traceback; traceback.print_exc()
        return 2
    finally:
        server.terminate()
        server.wait()
        shutil.rmtree("/tmp/rssmb-poc", ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())