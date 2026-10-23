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
import os
import sys
import shutil
import subprocess
import time

sys.path.insert(0, "/tmp/venv/lib/python3.11/site-packages")
from impacket.smbconnection import SMBConnection


def main():
    share_path = "/tmp/rssmb-poc/public"
    # Clean and prepare the share tree.
    shutil.rmtree("/tmp/rssmb-poc", ignore_errors=True)
    os.makedirs(share_path, exist_ok=True)

    # Start the server with publish_on_close ON.
    server = subprocess.Popen(
        [
            os.environ.get("RSSMB", "/mnt/rssmb/.target/debug/rssmb"),
            "--config",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "poc-on.toml"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "RUST_LOG": "info"},
    )
    time.sleep(2)

    try:
        # Client A: connect, create, write.
        conn_a = SMBConnection("127.0.0.1", "127.0.0.1", "A", sess_port=4450)
        conn_a.login("alice", "TestPass123")
        print(f"  [A] connected, dialect: {conn_a.getDialect()}")

        # Create a new file (FILE_CREATE disposition).
        fid_a = conn_a.createFile(
            "public", "poc_test.txt",
            desiredAccess=0x120116,  # GENERIC_READ | GENERIC_WRITE | DELETE
            shareAccess=0x07,  # READ | WRITE | DELETE
            createDisposition=0x01,  # FILE_CREATE
            createOptions=0,
        )
        conn_a.writeFile("public", fid_a, b"A writes this data")

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
        conn_b = SMBConnection("127.0.0.1", "127.0.0.1", "B", sess_port=4450)
        conn_b.login("alice", "TestPass123")
        print(f"  [B] connected, dialect: {conn_b.getDialect()}")

        # B lists the directory — the final name must appear, no temp.
        listing = conn_b.listPath("public", "*")
        names = [e.get_longfilename() for e in listing]
        assert "poc_test.txt" in names, (
            f"Final name must appear in SMB listing while pending, got {names}"
        )
        assert not any(n.startswith(".rssmb-tmp.") for n in names), (
            f"No temp name must appear in SMB listing, got {names}"
        )
        print(f"  [B] SMB listing shows final name, no temp: {[n for n in names if not n.startswith('.')]}")

        # B opens the same file (attach to pending, FILE_OPEN).
        fid_b = conn_b.createFile(
            "public", "poc_test.txt",
            desiredAccess=0x120116,
            shareAccess=0x07,
            createDisposition=0x01,  # FILE_OPEN
            createOptions=0,
        )
        conn_b.writeFile("public", fid_b, b"B writes more data")

        # A closes — not last.
        conn_a.closeFile("public", fid_a)
        print("  [A] closed (not last)")

        # Host check again: still only temp.
        entries2 = os.listdir(share_path)
        assert "poc_test.txt" not in entries2, (
            f"Final name must not exist on host before last close, got {entries2}"
        )
        print(f"  [host] still only temp: {entries2}")

        # B closes — last close, publishes.
        conn_b.closeFile("public", fid_b)
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

        # Data integrity: file content is B's last write.
        with open(os.path.join(share_path, "poc_test.txt"), "rb") as f:
            content = f.read()
        assert content == b"B writes more data", (
            f"Content mismatch: expected B's data, got {content!r}"
        )
        print(f"  [host] content verified: {content!r}")

        conn_a.disconnect()
        conn_b.disconnect()

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