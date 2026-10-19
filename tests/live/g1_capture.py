"""Golden probe for DH2Q (durable handle v2 request) response semantics
(Campaign A, G1).

Sends raw SMB2 CREATEs carrying a DH2Q create context (batch oplock, or
lease) and parses the CREATE response contexts by hand, asserting the DH2Q
response blob (negotiated timeout + flags) byte-for-byte against Samba.

  usage: g1_capture.py <host> [label]
"""
import json
import struct
import sys
import uuid as uuid_mod

sys.path.insert(0, "/tmp/smbvenv/lib/python3.11/site-packages")

from impacket.smbconnection import SMBConnection  # noqa: E402
from impacket import smb3structs  # noqa: E402
from impacket.smb3structs import (  # noqa: E402
    SMB2Create,
    SMB2Create_Response,
    SMB2Packet,
    SMB2_OPLOCK_LEVEL_BATCH,
    SMB2_OPLOCK_LEVEL_NONE,
)

# lease states (MS-SMB2 2.2.13.2.10 / 2.2.14.2)
LEASE_RH = 0x05
LEASE_RWH = 0x07
OPLOCK_LEVEL_LEASE = 0xFF


def connect(host):
    c = SMBConnection(host, host, sess_port=4450,
                      preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)
    c.login("alice", "TestPass123")
    return c


def build_ctx(name, data):
    """One SMB2_CREATE_CONTEXT (MS-SMB2 2.2.13.2), padded to 8 bytes."""
    name = name.encode("ascii")
    name_off = 16
    name_len = len(name)
    data_off = (name_off + name_len + 7) & ~7
    blob = struct.pack("<IHHHHI", 0, name_off, name_len, 0, data_off, len(data))
    blob += name + b"\x00" * (data_off - name_off - name_len) + data
    blob += b"\x00" * ((8 - len(blob) % 8) % 8)
    return blob


def parse_contexts(raw):
    """Parse a create-context chain into [(name_hex, data_hex)]."""
    out = []
    off = 0
    while off + 16 <= len(raw):
        nxt, name_off, name_len, _res, data_off, data_len = struct.unpack_from(
            "<IHHHHI", raw, off)
        name = raw[off + name_off: off + name_off + name_len]
        data = raw[off + data_off: off + data_off + data_len]
        out.append((name.hex(), data.hex()))
        if nxt == 0:
            break
        off += nxt
    return out


def raw_dh2q_create(sc, tid, fname, timeout, create_guid, oplock,
                    lease_key=None, lease_state=None):
    """Raw CREATE with DH2Q (+ optional RqLs v1) contexts. Returns the
    response status, oplock level, and the parsed response contexts."""
    smb2Create = SMB2Create()
    smb2Create["SecurityFlags"] = 0
    smb2Create["RequestedOplockLevel"] = oplock
    smb2Create["ImpersonationLevel"] = 0x02
    smb2Create["DesiredAccess"] = 0x00120089 | 0x00000002
    smb2Create["FileAttributes"] = 0x80
    smb2Create["ShareAccess"] = 0x7
    smb2Create["CreateDisposition"] = 0x03  # OpenIf
    smb2Create["CreateOptions"] = 0
    name = fname.encode("utf-16le")
    smb2Create["NameLength"] = len(name)
    smb2Create["Buffer"] = name

    dh2q_data = struct.pack("<II", timeout, 0) + b"\x00" * 8 + create_guid
    ctxs = [build_ctx("DH2Q", dh2q_data)]
    if lease_key is not None:
        rqls_data = lease_key + struct.pack("<II", lease_state, 0) + struct.pack("<Q", 0)
        ctxs.append(build_ctx("RqLs", rqls_data))
        smb2Create["RequestedOplockLevel"] = OPLOCK_LEVEL_LEASE

    contexts_buf = b"".join(ctxs)
    base_len = len(SMB2Packet()) + SMB2Create.SIZE + len(smb2Create["Buffer"])
    pad = (8 - (base_len % 8)) % 8
    smb2Create["Buffer"] += b"\x00" * pad
    smb2Create["CreateContextsOffset"] = base_len + pad
    smb2Create["CreateContextsLength"] = len(contexts_buf)
    smb2Create["Buffer"] += contexts_buf

    packet = SMB2Packet()
    packet["Command"] = smb3structs.SMB2_CREATE
    packet["TreeID"] = tid
    packet["Data"] = smb2Create
    packet["SessionID"] = sc._Session["SessionID"]

    pid = sc.sendSMB(packet)
    ans = sc.recvSMB(pid)
    out = {"status": int(ans["Status"])}
    try:
        ans.isValidAnswer(0)
    except Exception:
        return out
    resp = SMB2Create_Response(ans["Data"])
    ctx_len = int(resp["CreateContextsLength"])
    buf = resp["Buffer"] if ctx_len else b""
    out.update({
        "create_action": int(resp["CreateAction"]),
        "oplock_level": int(resp["OplockLevel"]),
        "contexts": parse_contexts(buf[:ctx_len]) if ctx_len else [],
    })
    return out


def main():
    host = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else host
    c = connect(host)
    sc = c._SMBConnection
    tid = sc.connectTree("public")

    for f in ("g1_probe.txt", "g1_probe2.txt", "g1_probe3.txt"):
        try:
            c.deleteFile("public", f)
        except Exception:
            pass

    results = {"label": label}

    # 1. DH2Q, client timeout=UINT32_MAX, batch oplock.
    #    Golden (Samba 4.19.5): DH2Q response blob present, timeout=300000,
    #    flags=0, oplock_level=0x09 (batch).
    r = raw_dh2q_create(sc, tid, "g1_probe.txt", 0xFFFFFFFF,
                        uuid_mod.uuid4().bytes, SMB2_OPLOCK_LEVEL_BATCH)
    results["dh2q_max_timeout_batch"] = r

    # 2. DH2Q, timeout=0, batch oplock. Golden: timeout echo=60000.
    r = raw_dh2q_create(sc, tid, "g1_probe2.txt", 0,
                        uuid_mod.uuid4().bytes, SMB2_OPLOCK_LEVEL_BATCH)
    results["dh2q_zero_timeout_batch"] = r

    # 3. DH2Q, timeout=60000, no oplock/lease. Recorded for the G5 gating
    #    comparison (Samba: durable NOT granted without batch/lease).
    r = raw_dh2q_create(sc, tid, "g1_probe3.txt", 60000,
                        uuid_mod.uuid4().bytes, SMB2_OPLOCK_LEVEL_NONE)
    results["dh2q_no_oplock"] = r

    # 4. DH2Q + RWH lease (G5 lease condition — Campaign B picks this up;
    #    recorded here for completeness). Golden: blob + lease echo RWH.
    lease_key = uuid_mod.uuid4().bytes
    r = raw_dh2q_create(sc, tid, "g1_probe4.txt", 0xFFFFFFFF,
                        uuid_mod.uuid4().bytes, OPLOCK_LEVEL_LEASE,
                        lease_key=lease_key, lease_state=LEASE_RWH)
    results["dh2q_rwh_lease"] = r

    c.logoff()
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
