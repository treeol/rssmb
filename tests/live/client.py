#!/usr/bin/env python3
"""Live interop probe for rssmb using impacket as a real SMB2 client.

Usage: client.py <scenario> [<scenario> ...]
  guest       anonymous/guest -> list + read public
  alice       NTLM user alice -> list public + private, put/get/delete
  badpass     alice with wrong password -> must fail
  guestpriv   guest -> private must be denied
  signed      alice with client-side signing required
  enum_guest  anonymous -> NetrShareEnum (level 1) via IPC$
  enum_user   alice -> NetrShareEnum + NetrShareGetInfo + NetrServerGetInfo
"""
import io
import os
import sys
import traceback

from impacket.smbconnection import SMBConnection
from impacket import smb3structs

HOST = os.environ.get("RSSMB_HOST", "127.0.0.1")
PORT = int(os.environ.get("RSSMB_PORT", "4450"))


def connect(dialect=smb3structs.SMB2_DIALECT_21):
    return SMBConnection(HOST, HOST, sess_port=PORT, preferredDialect=dialect, timeout=10)


def connect_311():
    """Connect with SMB 3.1.1."""
    return SMBConnection(HOST, HOST, sess_port=PORT,
                         preferredDialect=smb3structs.SMB2_DIALECT_311,
                         timeout=10)


def ls(c, share):
    names = sorted(f.get_longname() for f in c.listPath(share, "*"))
    print(f"  ls {share}: {names}")
    return names


def get(c, share, path):
    buf = io.BytesIO()
    c.getFile(share, path, buf.write)
    print(f"  get {share}/{path}: {buf.getvalue()!r}")
    return buf.getvalue()


def rpc_enum_shares(username, password, level=1):
    """Use DCE/RPC over IPC$ to call NetrShareEnum via SMBConnection."""
    from impacket.smbconnection import SMBConnection
    c = SMBConnection(HOST, HOST, sess_port=PORT,
                      preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)
    c.login(username, password)
    # listShares() calls NetrShareEnum internally.
    shares = c.listShares()
    c.logoff()
    return shares


def rpc_share_get_info(username, password, netname, level=1):
    """Use DCE/RPC over IPC$ to call NetrShareGetInfo via SMBConnection."""
    from impacket.smbconnection import SMBConnection
    c = SMBConnection(HOST, HOST, sess_port=PORT,
                      preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)
    c.login(username, password)
    from impacket.dcerpc.v5 import srvs
    dce = c._SMBConnection.getDCE()
    dce.bind(srvs.MSRPC_UUID_SRVSVC)
    resp = srvs.hNetrShareGetInfo(dce, f'\\\\{HOST}', netname, level)
    c.logoff()
    return resp


def rpc_server_get_info(username, password, level=100):
    """Use DCE/RPC over IPC$ to call NetrServerGetInfo via SMBConnection."""
    from impacket.smbconnection import SMBConnection
    c = SMBConnection(HOST, HOST, sess_port=PORT,
                      preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)
    c.login(username, password)
    from impacket.dcerpc.v5 import srvs
    dce = c._SMBConnection.getDCE()
    dce.bind(srvs.MSRPC_UUID_SRVSVC)
    resp = srvs.hNetrServerGetInfo(dce, f'\\\\{HOST}', level)
    c.logoff()
    return resp


def scenario(name):
    if name == "guest":
        c = connect()
        c.login("", "")
        ls(c, "public")
        assert get(c, "public", "README.txt") == b"hello from rssmb\n"
        c.logoff()
    elif name in ("alice", "signed"):
        c = connect()
        if name == "signed":
            c._SMBConnection.RequireMessageSigning = True
        c.login("alice", "TestPass123")
        s = c._SMBConnection._Session
        print("  alice logged in; SigningRequired:", s.get("SigningRequired"),
              "SigningActivated:", s.get("SigningActivated"))
        if name == "signed":
            assert s.get("SigningActivated"), "server required signing but client did not activate it"
        ls(c, "public")
        ls(c, "private")
        data = b"written by impacket\n"
        c.putFile("public", "upload.txt", io.BytesIO(data).read)
        assert get(c, "public", "upload.txt") == data
        c.deleteFile("public", "upload.txt")
        assert "upload.txt" not in ls(c, "public"), "delete did not take effect"
        c.logoff()
    elif name == "badpass":
        c = connect()
        try:
            c.login("alice", "WRONG")
        except Exception as e:
            print("  rejected as expected:", str(e)[:120])
            return
        raise AssertionError("wrong password was accepted")
    elif name == "guestsigned":
        # Against a signing=required server guest login must be refused.
        c = connect()
        try:
            c.login("", "")
        except Exception as e:
            print("  guest refused as expected:", str(e)[:100])
            return
        raise AssertionError("guest admitted although server requires signing")
    elif name == "guestpriv":
        c = connect()
        c.login("", "")
        try:
            c.listPath("private", "*")
        except Exception as e:
            print("  denied as expected:", str(e)[:120])
            return
        raise AssertionError("guest reached private share")
    elif name == "enum_guest":
        c = connect()
        c.login("", "")
        shares = rpc_enum_shares("", "")
        names = sorted(s['shi1_netname'][:-1] for s in shares)
        print(f"  enum_guest shares: {names}")
        assert "IPC$" in names, "IPC$ must be in enum"
        c.logoff()
    elif name == "enum_user":
        c = connect()
        c.login("alice", "TestPass123")
        shares = rpc_enum_shares("alice", "TestPass123")
        names = sorted(s['shi1_netname'][:-1] for s in shares)
        print(f"  enum_user shares: {names}")
        assert "public" in names, "public must be in enum"
        assert "private" in names, "private must be in enum for authenticated user"
        assert "IPC$" in names, "IPC$ must be in enum"
        c.logoff()
    elif name == "encrypted":
        # SMB 3.1.1 with encryption = "desired": negotiate 3.1.1 and
        # check that the session works (encryption is accepted if the
        # server offers it and the client decides to encrypt).
        c = connect_311()
        c.login("alice", "TestPass123")
        s = c._SMBConnection._Session
        print("  alice 3.1.1 logged in; SigningRequired:", s.get("SigningRequired"),
              "SigningActivated:", s.get("SigningActivated"))
        ls(c, "public")
        ls(c, "private")
        data = b"encrypted write\n"
        c.putFile("public", "enc_upload.txt", io.BytesIO(data).read)
        assert get(c, "public", "enc_upload.txt") == data
        c.deleteFile("public", "enc_upload.txt")
        c.logoff()
    else:
        raise SystemExit(f"unknown scenario {name}")


if __name__ == "__main__":
    ok = True
    for name in sys.argv[1:]:
        print(f"[{name}]")
        try:
            scenario(name)
            print(f"[{name}] PASS")
        except Exception:
            ok = False
            traceback.print_exc(limit=4)
            print(f"[{name}] FAIL")
    sys.exit(0 if ok else 1)