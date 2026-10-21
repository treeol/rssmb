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

## Durable regression gate for the conf/leases merge (2026-10-20)

Release binaries were built fresh at each commit (`cargo clean --release -p rssmb-server`
first). Each suite ran through `target/dbg/gate.sh` with a 300 s cap and smbtorture
4.19.5.

| Suite | 0bedeb5 (baseline, pre Campaign B) | d1922cf (L1+L2) |
|---|---|---|
| smb2.durable-open | 11/12: alloc-size, delete_on_close1, file-position, lease, open2-oplock, oplock, read-only, reopen1a, reopen2, reopen2-lease, reopen2-lease-v2, reopen4 | 12/11: same list minus `lease` (now passes) |
| smb2.durable-v2-open | 14/1: app-instance | 14/1: app-instance |
| smb2.lease | (5/36, see above) | 28/8, 3 skip: request, statopen3, lock1, complex1, unlink, v2_epoch3, v2_complex1, v2_complex2 |

No subtest that passed at 0bedeb5 fails at d1922cf.

Full logs: /tmp/torture-*.log

## publish_on_close baselines (2026-10-21, branch feat/publish-on-close, 3d9f174)

Full smbtorture 4.19.5 baseline run with the per-share `publish_on_close`
option **OFF** (default path, rssmb-mount.toml) and **ON**
(rssmb-publish.toml), smbtorture from the smb-torture:419 container,
target //172.17.0.2:4450/public. The suite lists below show pass counts;
**OFF and ON failure sets are byte-identical per suite** (verified by
diff of the failing-subtest lists for create/rename/dir/lock/lease/
durable/sharemode/credits — diff_rc=0 — except where noted).

| Suite | OFF | ON | Notes |
|---|---|---|---|
| smb2.create | 17 pass / 10 fail + 1 err | identical | required suite — no delta |
| smb2.rename | 12 pass / 12 fail | identical | required suite — no delta |
| smb2.dir | 9 pass / 7 fail | identical | required suite — no delta |
| smb2.delete-on-close-perms | 9 pass / 9 fail | identical | required suite — no delta |
| smb2.notify | 23 pass / 23 fail (120 s) | TIMEOUT at 120 s | **documented ON behavior**: with the final name hidden until publish, ADDED/MODIFY events the suite waits for on the final name only arrive as the publish MOVED_TO; the suite's waits time out. Notify ON filtering of `.rssmb-tmp.*` events is by design. |
| smb2.lock | 25 pass / 22 fail | identical (diff verified) | `truncate` COLLISION etc. fail in BOTH configs — pre-existing, not a publish_on_close regression |
| smb2.lease | 39 pass / 10 fail | 39 pass / 9-10 fail | `multibreak`/`rename_wait` flakes (lease suite timing); re-runs vary between 9/10, no publish-related delta in the stable set |
| smb2.durable-v2-open | 15/1 (app-instance) | identical | |
| smb2.sharemode / smb2.credits / rpc.srvsvc / smb2.getinfo / smb2.setinfo / smb2.session / smb2.ioctl / smb2.read / smb2.connect / smb2.compound | unchanged | unchanged | |

Live interop gates (same day, final binary): run.sh 17/17, smbclient 9/9
(4.17.12, OFF and ON), rclone 3/3 (go-smb2, OFF and ON), impacket
publish_on_close end-to-end scenario PASS (tests/live/publish_scenario.py).
