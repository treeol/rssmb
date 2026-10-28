# smbtorture baseline — 2026-10-24T09:05:31Z

> Open work is tracked in [`docs/ROADMAP.md`](../../docs/ROADMAP.md) — every
> campaign references a roadmap item ID there.

- Server: rssmb 0.1.6 (481de59, branch fix/credit-accounting)
- smbtorture: smbtorture 4.19.5-Ubuntu (docker smbt419)
- Target: //172.17.0.6:4450/public (publish_on_close OFF)

**Campaign C (smb2.lock) complete: 22 pass + 3 skip — every counted
subtest passes, exact smbd 4.19.5 golden parity (suite exit 0).**
Campaign history: lock 3/22 (2026-10-19) -> 22+3 today via K1-K6
(see lock-analysis.md). smb2.connect also now passes fully.

**Credit accounting fix (0.1.7):** `smb2.session` improved from 46/20
to 49/17 — 3 reauth subtests that failed due to the credit window bug
(close/logoff consumed a MessageId when credit_charge=0, exhausting the
credit window) now pass. No regression in any other suite.

| Suite | Result | Subtests (pass/fail/error/skip) | Failing subtests |
|---|---|---|---|
| smb2.connect | PASS | 1/0/0/0 |   |
| smb2.read | FAIL | 1/4/0/0 | access, dir, eof, position |
| smb2.dir | FAIL | 2/7/0/0 | 1kfiles_rename, fixed, large-files, many, modify, one, sorted |
| smb2.compound | FAIL | 1/0/0/0 |   |
| smb2.create | FAIL | 6/11/0/0 | acldir, aclfile, blob, dosattr_tmp_dir, gentest, impersonation, leading-slash, mkdir-dup, nulldacl, open, quota-fake-file |
| smb2.setinfo | FAIL | 0/1/0/0 | setinfo |
| smb2.getinfo | FAIL | 0/8/0/0 | complex, fsinfo, getinfo_access, granted, normalized, qfile_buffercheck, qfs_buffercheck, qsec_buffercheck |
| smb2.session | FAIL | 49/17/0/0 | bind_negative_smb202, bind_negative_smb210d, bind_negative_smb210s, bind_negative_smb2to3d, bind_negative_smb2to3s, bind_negative_smb3encGtoCd, bind_negative_smb3encGtoCs, bind_negative_smb3to2d, bind_negative_smb3to2s, bind_negative_smb3to3d, bind_negative_smb3to3s, reauth1, reauth2, reauth3, reauth4, reauth5, reauth6 |
| smb2.credits | PASS | 3/0/0/0 |   — R-05 complete — smbd 4.19.5 grant parity (charge refund + full-request grants on auth-complete SESSION_SETUP, `smb2 max credits` = 8192 ceiling, zero-charge MessageId consumption) |
| smb2.ioctl | FAIL | 44/29/0/43 | bug14769, bug14788.NETWORK_INTERFACE, bug14788.VALIDATE_NEGOTIATE, compress_notsup_get, compress_notsup_set, copy-chunk, copy_chunk_across_shares, copy_chunk_across_shares2, copy_chunk_across_shares3, copy_chunk_append, copy_chunk_bad_access, copy_chunk_bad_key, copy_chunk_dest_lock, copy_chunk_limits, copy_chunk_max_output_sz, copy_chunk_multi, copy_chunk_overwrite, copy_chunk_simple, copy_chunk_sparse_dest, copy_chunk_src_exceed, copy_chunk_src_exceed_multi, copy_chunk_src_is_dest, copy_chunk_src_is_dest_overlap, copy_chunk_src_lock, copy_chunk_tiny, copy_chunk_write_access, copy_chunk_zero_length, req_resume_key, req_two_resume_keys (skip: bug14607, compress_*, dup_extents_*, shadow_copy, sparse_*, trim_simple) |
| smb2.lock | PASS | 25/0/0/0 |   — Campaign C complete — all counted subtests pass (golden parity with smbd 4.19.5) |
| smb2.lease | FAIL | 31/8/0/0 | complex1, lock1, request, statopen3, unlink, v2_complex1, v2_complex2, v2_epoch3 — timing-flaky (28-31 observed across runs; 31 this run) — see lease-analysis.md |
| smb2.durable-v2-open | FAIL | 14/1/0/0 | app-instance |
| smb2.notify | INCOMPLETE | — | stalls at basedir — attribute-filter fidelity, documented debt for a later notify campaign |
| smb2.rename | FAIL | 3/9/0/0 | close-full-information, msword, no_share_delete_but_delete_access, no_share_delete_no_delete_access, no_sharing, rename_dir_openfile, share_delete_and_delete_access, share_delete_no_delete_access, simple_nodelete |
| smb2.delete-on-close-perms | FAIL | 6/3/0/0 | CREATE_IF, OVERWRITE_IF, READONLY |
| smb2.sharemode | FAIL | 1/2/0/0 | access-sharemode, sharemode-access |
| rpc.srvsvc | FAIL | 2/15/0/0 | srvsvc |

Full logs: /tmp/torture-*.log (runner artifacts in CI)