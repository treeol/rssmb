# smbtorture baseline — 2026-10-19T06:52:19Z

- Server: rssmb 0.1.3 (21527b4) — branch conf/durable-v2
- smbtorture: 4.19.5 (docker container, Ubuntu 24.04 build)
- Target: //172.17.0.3:4450/public

| Suite | Result | Subtests (pass/fail) | Failing subtests |
|---|---|---|---|
| smb2.connect | ❌ FAIL | 0/1 | connect |
| smb2.read | ❌ FAIL | 1/4 | access,dir eof,position |
| smb2.dir | ❌ FAIL | 2/7 | 1kfiles_rename,fixed large-files,many modify,one sorted |
| smb2.compound | ❌ FAIL | 1/0 |   |
| smb2.create | ❌ FAIL | 6/11 | acldir,aclfile blob,delete dosattr_tmp_dir,gentest impersonation,leading-slash mkdir-dup,nulldacl open,quota-fake-file |
| smb2.setinfo | ❌ FAIL | 0/1 | setinfo |
| smb2.getinfo | ❌ FAIL | 0/8 | complex,fsinfo getinfo_access,granted normalized,qfile_buffercheck qfs_buffercheck,qsec_buffercheck |
| smb2.session | ❌ FAIL | 46/20 | bind1,bind2 bind_invalid_auth,bind_negative_smb210d bind_negative_smb2to3d,bind_negative_smb2to3s bind_negative_smb3to3d,bind_negative_smb3to3s reauth1,reauth2 reconnect2 |
| smb2.credits | ❌ FAIL | 0/3 | session_setup_credits_granted,single_req_credits_granted skipped_mid |
| smb2.ioctl | ❌ FAIL | 44/29 | (unchanged — copy-chunk & friends) |
| smb2.lock | ❌ FAIL | 3/22 | (Campaign C scope) |
| smb2.lease | ❌ FAIL | 5/36 | (Campaign B scope; the 8/31 recorded after Campaign A was a mid-suite truncation artifact of the harness's flat 120 s cap — the uncapped re-measure is 5/36, see tests/conformance/lease-analysis.md; 3 subtests skip at golden parity) |
| smb2.durable-v2-open | ❌ FAIL | 14/1 | app-instance (not implemented: no Samba 4.19.5 golden — Samba itself fails this subtest; documented in tests/conformance/durable-v2-open-analysis.md) |
| smb2.notify | ❌ FAIL | 1/0 |   |
| smb2.rename | ❌ FAIL | 3/9 | close-full-information,msword no_share_delete_but_delete_access,no_share_delete_no_delete_access no_sharing,rename_dir_openfile share_delete_and_delete_access,share_delete_no_delete_access simple_nodelete |
| smb2.delete-on-close-perms | ❌ FAIL | 6/3 | CREATE_IF,OVERWRITE_IF READONLY |
| smb2.sharemode | ❌ FAIL | 0/3 | access-sharemode,bug14375 sharemode-access |
| rpc.srvsvc | ❌ FAIL | 2/15 | srvsvc |

## Changes vs previous baseline (2026-10-18, b5a41d9 — 115/305)

- **smb2.durable-v2-open: 0/15 → 14/15** (Campaign A). The single remaining
  failure, app-instance, is documented as not-implemented: Samba 4.19.5 has
  no server-side AppInstanceId handling, so no golden behavior exists to
  match.
- smb2.create: 5/12 → 6/11 — +1 pass (`delete`); the create_action/file
  attribute fixes (correct Created/Opened/Overwritten/Superseded mapping,
  ARCHIVE without NORMAL) also fixed the `delete` subtest. Expected G2 side
  effect, reported not chased.
- smb2.session: 44/22 → 46/20 — +2 (bind_negative_smb202/smb210s) from the
  PreviousSessionId/session-semantics work.
- smb2.lease: 3/36 → 5/36 — the post-Campaign-A run recorded 8/31, but
  that count came from a log truncated mid-suite by the harness's flat
  120 s cap; the uncapped re-measure (tests/conformance/lease-analysis.md)
  is 5/36 (31 failing; 3 subtests skip at golden parity). The real +2 over
  the pre-A 3/36 is from the G2 create_action/file-attribute fixes.
  Campaign B targets the remaining 31.

No suite regressed.

Full logs: /tmp/torture-*.log
