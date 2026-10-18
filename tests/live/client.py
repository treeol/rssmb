#!/usr/bin/env python3
"""Live interop probe for rssmb using impacket as a real SMB2 client.

Usage: client.py <scenario> [<scenario> ...]
  guest       anonymous/guest -> list + read public
  alice       NTLM user alice -> list public + private, put/get/delete
  badpass     alice with wrong password -> must fail
  guestpriv   guest -> private must be denied
  signed      alice with client-side signing required
  rename      alice -> put/rename/get/delete (exercises SET_INFO rename)
  dirclasses  alice -> QUERY_DIRECTORY with each MS-FSCC directory info class
  enum_guest  anonymous -> NetrShareEnum (level 1) via IPC$
  enum_user   alice -> NetrShareEnum + NetrShareGetInfo + NetrServerGetInfo
  bigwrite    alice 2.1 -> WRITE exactly MaxWriteSize OK; MaxWriteSize+1 rejected,
              connection stays open
  bigwrite_311  same over SMB 3.1.1 (unsealed: impacket has no AES-GCM)
  share_comments  alice -> NetrShareEnum (name, type, remark) triples match config
  share_get_info  alice -> NetrShareGetInfo(public) == (public, Pub, 0); unknown share fails
"""
import io
import os
import sys
import traceback

from impacket.smbconnection import SMBConnection
from impacket import smb3structs

HOST = os.environ.get("RSSMB_HOST", "127.0.0.1")
PORT = int(os.environ.get("RSSMB_PORT", "4450"))


def connect(dialect=smb3structs.SMB2_DIALECT_21, require_signing=False):
    c = SMBConnection(HOST, HOST, sess_port=PORT, preferredDialect=dialect, timeout=10)
    if require_signing:
        c._SMBConnection.RequireMessageSigning = True
    return c


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
    """DCE/RPC over \\pipe\\srvsvc (IPC$): NetrShareGetInfo via impacket."""
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, srvs
    c = SMBConnection(HOST, HOST, sess_port=PORT,
                      preferredDialect=smb3structs.SMB2_DIALECT_21, timeout=10)
    c.login(username, password)
    t = transport.SMBTransport(HOST, PORT, r'\srvsvc', smb_connection=c)
    dce = t.get_dce_rpc()
    dce.connect()
    try:
        dce.bind(srvs.MSRPC_UUID_SRVS)
        return srvs.hNetrShareGetInfo(dce, netname, level)
    finally:
        dce.disconnect()
        c.logoff()


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
        c = connect(require_signing=(name == "signed"))
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
    elif name == "dirclasses":
        # QUERY_DIRECTORY with every MS-FSCC §2.4 directory class; each
        # response is decoded with impacket's own per-class parser, so a
        # wrong class number or layout shows up as missing/garbled names.
        from impacket import smb as smb1
        from impacket.smb3structs import (FILE_DIRECTORY_INFORMATION, FILE_FULL_DIRECTORY_INFORMATION,
                                          FILE_BOTH_DIRECTORY_INFORMATION, FILENAMES_INFORMATION,
                                          FILEID_BOTH_DIRECTORY_INFORMATION,
                                          FILEID_FULL_DIRECTORY_INFORMATION, FILE_READ_DATA,
                                          FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_DIRECTORY_FILE,
                                          FILE_OPEN, FILE_LIST_DIRECTORY)
        classes = [
            ("FileDirectoryInformation", FILE_DIRECTORY_INFORMATION, smb1.SMBFindFileDirectoryInfo),
            ("FileFullDirectoryInformation", FILE_FULL_DIRECTORY_INFORMATION, smb1.SMBFindFileFullDirectoryInfo),
            ("FileBothDirectoryInformation", FILE_BOTH_DIRECTORY_INFORMATION, smb1.SMBFindFileBothDirectoryInfo),
            ("FileNamesInformation", FILENAMES_INFORMATION, smb1.SMBFindFileNamesInfo),
            ("FileIdBothDirectoryInformation", FILEID_BOTH_DIRECTORY_INFORMATION, smb1.SMBFindFileIdBothDirectoryInfo),
            ("FileIdFullDirectoryInformation", FILEID_FULL_DIRECTORY_INFORMATION, smb1.SMBFindFileIdFullDirectoryInfo),
        ]
        c = connect()
        c.login("alice", "TestPass123")
        smb = c._SMBConnection
        payload = b"dirclasses\n"
        c.putFile("public", "dirclass-probe.txt", io.BytesIO(payload).read)
        tid = smb.connectTree("public")
        expected = {".", "..", "README.txt", "dirclass-probe.txt"}
        try:
            for label, code, parser in classes:
                fid = smb.create(tid, "", FILE_READ_DATA | FILE_LIST_DIRECTORY,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE, FILE_OPEN, 0)
                buf = smb.queryDirectory(tid, fid, "*", informationClass=code, maxBufferSize=65536)
                smb.close(tid, fid)
                names, sizes, off = set(), {}, 0
                while True:
                    e = parser(smb1.SMB.FLAGS2_UNICODE, data=buf[off:])
                    n = e["FileName"].decode("utf-16le")
                    names.add(n)
                    if "EndOfFile" in e.fields:
                        sizes[n] = e["EndOfFile"]
                    if e["NextEntryOffset"] == 0:
                        break
                    assert e["NextEntryOffset"] % 8 == 0, f"{label}: unaligned NextEntryOffset"
                    off += e["NextEntryOffset"]
                assert expected <= names, f"{label} (0x{code:02x}): got {sorted(names)}"
                if sizes:
                    assert sizes.get("dirclass-probe.txt") == len(payload), \
                        f"{label}: EndOfFile {sizes.get('dirclass-probe.txt')}"
                print(f"  {label} (0x{code:02x}): {sorted(names)}")
            # Non-directory classes: 14 = FilePositionInformation, 200 =
            # undefined. MS-SMB2 3.3.5.18 -> STATUS_INVALID_INFO_CLASS.
            from impacket.smb3 import SessionError
            from impacket.nt_errors import STATUS_INVALID_INFO_CLASS
            for code in (14, 200):
                fid = smb.create(tid, "", FILE_READ_DATA | FILE_LIST_DIRECTORY,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE, FILE_OPEN, 0)
                try:
                    smb.queryDirectory(tid, fid, "*", informationClass=code, maxBufferSize=65536)
                    raise AssertionError(f"class {code} unexpectedly succeeded")
                except SessionError as e:
                    assert e.get_error_code() == STATUS_INVALID_INFO_CLASS, \
                        f"class {code}: 0x{e.get_error_code():08x}"
                    print(f"  class {code}: STATUS_INVALID_INFO_CLASS (expected)")
                finally:
                    smb.close(tid, fid)
        finally:
            c.deleteFile("public", "dirclass-probe.txt")
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
    elif name == "rename":
        # Exercise SET_INFO FileRenameInformation (class 10) — the path
        # that was broken by the InfoType decode bug.
        c = connect()
        c.login("alice", "TestPass123")
        data = b"rename test\n"
        c.putFile("public", "before.txt", io.BytesIO(data).read)
        assert get(c, "public", "before.txt") == data
        # Rename before.txt -> after.txt
        c.rename("public", "before.txt", "after.txt")
        assert "before.txt" not in ls(c, "public"), "old name still present after rename"
        assert "after.txt" in ls(c, "public"), "new name missing after rename"
        assert get(c, "public", "after.txt") == data, "content changed during rename"
        c.deleteFile("public", "after.txt")
        assert "after.txt" not in ls(c, "public"), "delete did not take effect"
        c.logoff()
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
    elif name in ("bigwrite", "bigwrite_311"):
        # WRITE of exactly the advertised MaxWriteSize must succeed;
        # MaxWriteSize + 1 must be rejected with STATUS_INVALID_PARAMETER
        # and the connection must stay usable. Unencrypted only: impacket
        # offers AES-CCM, rssmb implements AES-GCM, so impacket cannot seal.
        # Sealed full-size writes are covered by tests/live/mount.sh (seal).
        from impacket.smb3structs import (FILE_READ_DATA, FILE_WRITE_DATA, FILE_SHARE_READ,
                                          FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE)
        from impacket.smb3 import SessionError
        from impacket.nt_errors import STATUS_INVALID_PARAMETER
        c = connect_311() if name == "bigwrite_311" else connect()
        c.login("alice", "TestPass123")
        smb = c._SMBConnection
        maxw = smb._Connection["MaxWriteSize"]
        print(f"  dialect=0x{smb._Connection['Dialect']:04x} MaxWriteSize={maxw}")
        assert maxw == 1024 * 1024, f"expected 1 MiB MaxWriteSize, got {maxw}"
        tid = smb.connectTree("public")
        fid = smb.create(tid, "bigwrite.bin", FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_READ,
                         FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, 0)
        data = bytes(range(256)) * (maxw // 256)
        n = smb.write(tid, fid, data, 0, maxw)
        assert n == maxw, f"full-size write returned {n}"
        print(f"  WRITE {maxw} bytes: OK")
        # Oversized by one byte: lift the client-side clamp to send it.
        smb._Connection["MaxWriteSize"] = maxw + 1
        try:
            smb.write(tid, fid, data + b"X", 0, maxw + 1)
            raise AssertionError("WRITE of MaxWriteSize+1 unexpectedly succeeded")
        except SessionError as e:
            assert e.get_error_code() == STATUS_INVALID_PARAMETER, hex(e.get_error_code())
            print("  WRITE MaxWriteSize+1: STATUS_INVALID_PARAMETER (expected)")
        finally:
            smb._Connection["MaxWriteSize"] = maxw
        # Connection still alive and data intact.
        smb.close(tid, fid)
        buf = io.BytesIO()
        c.getFile("public", "bigwrite.bin", buf.write)
        assert buf.getvalue() == data, "read-back mismatch"
        print(f"  read-back {len(buf.getvalue())} bytes: OK (connection still open)")
        c.deleteFile("public", "bigwrite.bin")
        c.logoff()
    elif name == "share_comments":
        # NetrShareEnum level 1: every (name, remark) pair must match the
        # config exactly (tests/live/rssmb-live*.toml: public "Pub",
        # private "Priv"; IPC$ has an empty remark). Catches deferred-string
        # ordering errors and NULL-vs-empty remark pointers.
        shares = rpc_enum_shares("alice", "TestPass123")
        pairs = [(s['shi1_netname'][:-1], s['shi1_type'], s['shi1_remark'][:-1]) for s in shares]
        print(f"  NetrShareEnum: {pairs}")
        assert sorted(pairs) == sorted([
            ("public", 0, "Pub"),
            ("private", 0, "Priv"),
            ("IPC$", 0x80000003, ""),
        ]), pairs
    elif name == "share_get_info":
        # NetrShareGetInfo level 1 (MS-SRVS 3.1.4.10), decoded by impacket's
        # hNetrShareGetInfo: (name, remark, type) for "public" must match
        # the config; an unknown share must fail with NERR_NetNameNotFound.
        r = rpc_share_get_info("alice", "TestPass123", "public\x00")
        info = r['InfoStruct']['ShareInfo1']
        got = (info['shi1_netname'][:-1], info['shi1_remark'][:-1], info['shi1_type'])
        print(f"  NetrShareGetInfo(public): {got}")
        assert got == ("public", "Pub", 0), got
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        try:
            rpc_share_get_info("alice", "TestPass123", "nosuchshare\x00")
            raise AssertionError("NetrShareGetInfo(nosuchshare) unexpectedly succeeded")
        except DCERPCException as e:
            assert e.get_error_code() == 2310, hex(e.get_error_code())  # NERR_NetNameNotFound
            print("  NetrShareGetInfo(nosuchshare): NERR_NetNameNotFound (expected)")
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