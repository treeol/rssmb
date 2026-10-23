# smbtorture baseline — 2026-10-23T15:36:03Z

- Server: rssmb 0.1.5 (0666d7d, branch conf/locks)
- smbtorture: smbtorture 4.19.5-Ubuntu
- Target: //127.0.0.1/public (docker smb-torture:419 -> loopback:4450)

**Campaign C (smb2.lock) complete: 22 pass + 3 skip — every counted
subtest passes, exact smbd 4.19.5 golden parity (suite exit 0).**
Campaign history: lock 3/22 (2026-10-19) -> 22+3 today via K1-K6
(see lock-analysis.md). smb2.connect also now passes fully.

| Suite | Result | Subtests (pass/fail/error/skip) | Failing subtests |
|---|---|---|---|
| smb2.connect | PASS | 1/0/0/0 |   — Campaign C side fix (TDIS/LOGOFF statuses) — suite fully passes |
| smb2.read | FAIL | 1/4/0/1 | access, dir, eof, position (skip: bug14607) |
| smb2.dir | FAIL | 2/7/0/1 | 1kfiles_rename, fixed, large-files, many, modify, one, sorted (skip: file-index) |
| smb2.compound | FAIL | 1/0/0/0 |   |
| smb2.create | FAIL | 6/11/0/1 | acldir, aclfile, blob, dosattr_tmp_dir, gentest, impersonation, leading-slash, mkdir-dup, nulldacl, open, quota-fake-file (skip: path-length) |
| smb2.setinfo | FAIL | 0/1/0/0 | setinfo |
| smb2.getinfo | FAIL | 0/8/0/0 | complex, fsinfo, getinfo_access, granted, normalized, qfile_buffercheck, qfs_buffercheck, qsec_buffercheck |
| smb2.session | FAIL | 46/20/0/42 | bind1, bind2, bind_invalid_auth, bind_negative_smb202, bind_negative_smb210d, bind_negative_smb210s, bind_negative_smb2to3d, bind_negative_smb2to3s, bind_negative_smb3encGtoCd, bind_negative_smb3encGtoCs, bind_negative_smb3to2d, bind_negative_smb3to2s, bind_negative_smb3to3d, bind_negative_smb3to3s, reauth1, reauth2, reauth3, reauth4, reauth5, reauth6 (skip: bind_different_user, bind_negative_smb3signC30toGd, bind_negative_smb3signC30toGs, bind_negative_smb3signCtoGd, bind_negative_smb3signCtoGs, bind_negative_smb3signCtoHd, bind_negative_smb3signCtoHs, bind_negative_smb3signGtoC30d, bind_negative_smb3signGtoC30s, bind_negative_smb3signGtoCd, bind_negative_smb3signGtoCs, bind_negative_smb3signGtoH2Xd, bind_negative_smb3signGtoH2Xs, bind_negative_smb3signGtoHd, bind_negative_smb3signGtoHs, bind_negative_smb3signH2XtoGd, bind_negative_smb3signH2XtoGs, bind_negative_smb3signHtoCd, bind_negative_smb3signHtoCs, bind_negative_smb3signHtoGd, bind_negative_smb3signHtoGs, bind_negative_smb3sneCtoGd, bind_negative_smb3sneCtoGs, bind_negative_smb3sneGtoCd, bind_negative_smb3sneGtoCs, bind_negative_smb3sneGtoHd, bind_negative_smb3sneGtoHs, bind_negative_smb3sneHtoGd, bind_negative_smb3sneHtoGs, encryption-aes-128-ccm, encryption-aes-128-gcm, encryption-aes-256-ccm, encryption-aes-256-gcm, expire1e, expire1n, expire1s, expire2e, expire2s, expire_disconnect, signing-aes-128-cmac, signing-aes-128-gmac, signing-hmac-sha-256) |
| smb2.credits | FAIL | 0/3/0/0 | session_setup_credits_granted, single_req_credits_granted, skipped_mid |
| smb2.ioctl | FAIL | 44/29/0/43 | bug14769, bug14788.NETWORK_INTERFACE, bug14788.VALIDATE_NEGOTIATE, compress_notsup_get, compress_notsup_set, copy-chunk, copy_chunk_across_shares, copy_chunk_across_shares2, copy_chunk_across_shares3, copy_chunk_append, copy_chunk_bad_access, copy_chunk_bad_key, copy_chunk_dest_lock, copy_chunk_limits, copy_chunk_max_output_sz, copy_chunk_multi, copy_chunk_overwrite, copy_chunk_simple, copy_chunk_sparse_dest, copy_chunk_src_exceed, copy_chunk_src_exceed_multi, copy_chunk_src_is_dest, copy_chunk_src_is_dest_overlap, copy_chunk_src_lock, copy_chunk_tiny, copy_chunk_write_access, copy_chunk_zero_length, req_resume_key, req_two_resume_keys (skip: bug14607, compress_create_with_attr, compress_dir_inherit, compress_file_flag, compress_inherit_disable, compress_invalid_buf, compress_invalid_format, compress_perms, compress_query_file_attr, compress_set_file_attr, dup_extents_bad_handle, dup_extents_compressed_dest, dup_extents_compressed_src, dup_extents_dest_lock, dup_extents_len_beyond_dest, dup_extents_len_beyond_src, dup_extents_len_zero, dup_extents_simple, dup_extents_sparse_both, dup_extents_sparse_dest, dup_extents_sparse_src, dup_extents_src_is_dest, dup_extents_src_is_dest_overlap, dup_extents_src_lock, shadow_copy, sparse_compressed, sparse_copy_chunk, sparse_dir_flag, sparse_file_attr, sparse_file_flag, sparse_hole_dealloc, sparse_lock, sparse_perms, sparse_punch, sparse_punch_invalid, sparse_qar, sparse_qar_malformed, sparse_qar_multi, sparse_qar_ob1, sparse_qar_overflow, sparse_set_nobuf, sparse_set_oversize, trim_simple) |
| smb2.lock | PASS | 25/0/0/3 |   (skip: ctdb-delrec-deadlock, replay_broken_windows, rw-none) — Campaign C complete — all counted subtests pass (golden parity with smbd 4.19.5: 22 pass / 3 skip) |
| smb2.lease | FAIL | 30/9/0/3 | complex1, lock1, rename_wait, request, statopen3, unlink, v2_complex1, v2_complex2, v2_epoch3 (skip: dynamic_share, v2_request, v2_request_parent) — rename_wait/multibreak timing-flaky (28-31 observed across runs; 30 this run) — see lease-analysis.md |
| smb2.durable-v2-open | FAIL | 14/1/0/0 | app-instance |
| smb2.notify | INCOMPLETE | 1/1/0/0 | valid-req — stalls at basedir — attribute-filter fidelity, documented debt for a later notify campaign |
| smb2.rename | FAIL | 3/9/0/0 | close-full-information, msword, no_share_delete_but_delete_access, no_share_delete_no_delete_access, no_sharing, rename_dir_openfile, share_delete_and_delete_access, share_delete_no_delete_access, simple_nodelete |
| smb2.delete-on-close-perms | FAIL | 6/3/0/0 | CREATE_IF, OVERWRITE_IF, READONLY |
| smb2.sharemode | FAIL | 1/2/0/0 | access-sharemode, sharemode-access |
| rpc.srvsvc | FAIL | 2/15/0/1 | srvsvc (skip: srvsvc) |

Full logs: /tmp/torture-*.log (runner artifacts in CI)
