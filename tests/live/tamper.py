#!/usr/bin/env python3
"""Negative signing check against a server with signing = "required".

After a signed login, send one request (a) unsigned and (b) with a corrupted
signature. Both must be discarded (no reply → timeout). Then confirm the
session still works with a correctly signed request.
"""
import os
import sys

from impacket.smbconnection import SMBConnection
from impacket import smb3structs, nmb

HOST = os.environ.get("RSSMB_HOST", "127.0.0.1")
PORT = int(os.environ.get("RSSMB_PORT", "4450"))

c = SMBConnection(HOST, HOST, sess_port=PORT, preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=3)
c.login("alice", "TestPass123")
smb = c._SMBConnection
assert smb._Session["SigningActivated"], "signing not active"

orig_sign = smb.signSMB


def try_tree_connect(label, mutate):
    smb.signSMB = mutate
    try:
        smb.connectTree("public")
    except nmb.NetBIOSTimeout:
        print(f"  {label}: discarded (no reply) as expected")
        return True
    except Exception as e:
        print(f"  {label}: unexpected error {e!r}")
        return False
    finally:
        smb.signSMB = orig_sign
    print(f"  {label}: SERVER ACCEPTED IT")
    return False


def unsigned(packet):
    packet["Flags"] &= ~smb3structs.SMB2_FLAGS_SIGNED
    packet["Signature"] = b"\x00" * 16


def corrupt(packet):
    orig_sign(packet)
    sig = bytearray(packet["Signature"])
    sig[0] ^= 0xFF
    packet["Signature"] = bytes(sig)


ok = try_tree_connect("unsigned request", unsigned)
# The discarded requests consumed message ids the server never answered; a
# fresh connection keeps the follow-up check independent of that.
c2 = SMBConnection(HOST, HOST, sess_port=PORT, preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=3)
c2.login("alice", "TestPass123")
smb = c2._SMBConnection
orig_sign = smb.signSMB
ok &= try_tree_connect("corrupted signature", corrupt)

c3 = SMBConnection(HOST, HOST, sess_port=PORT, preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=5)
c3.login("alice", "TestPass123")
names = sorted(f.get_longname() for f in c3.listPath("public", "*"))
print("  correctly signed follow-up works:", names)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
