"""Golden/response capture for CREATE semantics (Campaign A, G2).

Sends raw SMB2 CREATE via impacket's low-level SMB3 and parses the
SMB2Create_Response directly — create_action, file attributes, and the
create-context blob — for a fixed sequence of creates.

  usage: g2_capture.py <host> [label]
Prints one JSON line per CREATE on stdout.
"""
import io
import json
import os
import sys

sys.path.insert(0, "/tmp/smbvenv/lib/python3.11/site-packages")

from impacket.smbconnection import SMBConnection  # noqa: E402
from impacket.smb3 import SessionError  # noqa: E402
from impacket import smb3structs  # noqa: E402
from impacket.smb3structs import (  # noqa: E402
    SMB2Create_Response,
    SMB2_OPLOCK_LEVEL_LEASE,
    SMB2_OPLOCK_LEVEL_BATCH,
    SMB2_OPLOCK_LEVEL_NONE,
)


def connect(host):
    c = SMBConnection(
        host, host, sess_port=4450,
        preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10,
    )
    c.login("alice", "TestPass123")
    return c


def create_probe(sc, tid, fname, disposition, create_opts=0, share=0x7,
                 access=0x00120089, oplock=SMB2_OPLOCK_LEVEL_NONE, attrs=0x80):
    """CREATE via impacket's own high-level SMB3.create, with a hook on
    SMB2Create_Response decoding to capture the full response fields."""
    captured = {}

    import impacket.smb3 as smb3mod

    orig_decode = SMB2Create_Response.getData  # marker, not used

    class _Capture(SMB2Create_Response):
        pass

    # Patch SMB3.create's local reference is not feasible; instead patch the
    # module-level SMB2Create_Response used inside SMB3.create via the class
    # attribute 'fields' — no. Cleanest: wrap recvSMB once.
    orig_recv = sc.recvSMB
    state = {"done": False}

    def hooked_recv(packet_id):
        ans = orig_recv(packet_id)
        if not state["done"]:
            try:
                if ans["Command"] == smb3structs.SMB2_CREATE and ans["Status"] == 0:
                    resp = SMB2Create_Response(ans["Data"])
                    captured["create_action"] = int(resp["CreateAction"])
                    captured["file_attributes"] = int(resp["FileAttributes"])
                    captured["oplock_level"] = int(resp["OplockLevel"])
                    captured["end_of_file"] = int(resp["EndOfFile"])
                    captured["contexts_len"] = int(resp["CreateContextsLength"])
                    captured["contexts_hex"] = (
                        resp["CreateContexts"].getData().hex()
                        if captured["contexts_len"] else ""
                    )
            except Exception:
                pass
            state["done"] = True
        return ans

    sc.recvSMB = hooked_recv
    try:
        fid = sc.create(tid, fname, access, share, create_opts, disposition,
                        attrs, oplockLevel=oplock)
    except SessionError as e:
        return {"status": e.get_error_code()}
    finally:
        sc.recvSMB = orig_recv
    out = {"status": 0, "file_id": fid.hex() if isinstance(fid, bytes) else str(fid)}
    out.update(captured)
    return out


def main():
    host = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else host
    c = connect(host)
    sc = c._SMBConnection
    tid = sc.connectTree("public")

    # clean targets
    for f in ("g2_a.txt", "g2_b.txt"):
        try:
            c.deleteFile("public", f)
        except Exception:
            pass

    results = {"label": label}

    # 1. OpenIf on a missing file -> expect Created (0x2), attr 0x20
    r = create_probe(sc, tid, "g2_a.txt", disposition=0x03)
    results["openif_new"] = r
    # 2. OpenIf on existing -> Opened (0x1)
    r = create_probe(sc, tid, "g2_a.txt", disposition=0x03)
    results["openif_existing"] = r
    # 3. Open on existing -> Opened
    r = create_probe(sc, tid, "g2_a.txt", disposition=0x01)
    results["open_existing"] = r
    # 4. OverwriteIf on existing -> Overwritten (0x3)
    r = create_probe(sc, tid, "g2_a.txt", disposition=0x05)
    results["overwriteif_existing"] = r
    # 5. OverwriteIf on missing -> Created
    r = create_probe(sc, tid, "g2_b.txt", disposition=0x05)
    results["overwriteif_new"] = r
    # 6. Supersede on existing -> Superseded (0x0)
    r = create_probe(sc, tid, "g2_b.txt", disposition=0x00)
    results["supersede_existing"] = r
    # 7. Create on existing -> OBJECT_NAME_COLLISION
    r = create_probe(sc, tid, "g2_b.txt", disposition=0x02)
    results["create_existing"] = r

    for f in ("g2_a.txt", "g2_b.txt"):
        try:
            c.deleteFile("public", f)
        except Exception:
            pass
    c.logoff()
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
