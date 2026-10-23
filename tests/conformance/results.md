# smbtorture baseline — 2026-10-23T10:51:18Z

- Server: rssmb 0.1.5 (203b55a)
- smbtorture: smbtorture 4.19.5-Ubuntu
- Target: //172.17.0.6:4450/public

| Suite | Result | Subtests (pass/fail/error/skip) | Failing subtests |
|---|---|---|---|
| smb2.connect | ❌ FAIL | 0/1/0/0 | connect |
| smb2.read | ❌ FAIL | 1/4/0/0 | access,dir eof,position |
| smb2.dir | ❌ FAIL | 2/7/0/0 | 1kfiles_rename,fixed large-files,many modify,one sorted |
| smb2.compound | ❌ FAIL | 1/0/0/0 |   |
| smb2.create | ❌ FAIL | 6/11/0/0 | acldir,aclfile blob,dosattr_tmp_dir gentest,impersonation leading-slash,mkdir-dup nulldacl,open quota-fake-file |
| smb2.setinfo | ❌ FAIL | 0/1/0/0 | setinfo |
| smb2.getinfo | ❌ FAIL | 0/8/0/0 | complex,fsinfo getinfo_access,granted normalized,qfile_buffercheck qfs_buffercheck,qsec_buffercheck |
| smb2.session | ❌ FAIL | 46/20/0/0 | bind1,bind2 bind_invalid_auth,bind_negative_smb202 bind_negative_smb210d,bind_negative_smb210s bind_negative_smb2to3d,bind_negative_smb2to3s bind_negative_smb3encGtoCd,bind_negative_smb3encGtoCs bind_negative_smb3to2d,bind_negative_smb3to2s bind_negative_smb3to3d,bind_negative_smb3to3s reauth1,reauth2 reauth3,reauth4 reauth5,reauth6 |
| smb2.credits | ❌ FAIL | 0/3/0/0 | session_setup_credits_granted,single_req_credits_granted skipped_mid |
| smb2.ioctl | ❌ FAIL | 44/29/0/0 | bug14769,bug14788.NETWORK_INTERFACE bug14788.VALIDATE_NEGOTIATE,compress_notsup_get compress_notsup_set,copy-chunk copy_chunk_across_shares,copy_chunk_across_shares2 copy_chunk_across_shares3,copy_chunk_append copy_chunk_bad_access,copy_chunk_bad_key copy_chunk_dest_lock,copy_chunk_limits copy_chunk_max_output_sz,copy_chunk_multi copy_chunk_overwrite,copy_chunk_simple copy_chunk_sparse_dest,copy_chunk_src_exceed copy_chunk_src_exceed_multi,copy_chunk_src_is_dest copy_chunk_src_is_dest_overlap,copy_chunk_src_lock copy_chunk_tiny,copy_chunk_write_access copy_chunk_zero_length,req_resume_key req_two_resume_keys |
| smb2.lock | ❌ FAIL | 3/22/0/0 | async,auto-unlock cancel,cancel-logoff cancel-tdis,contend context,errorcode lock,multiple-unlock overlap,range replay_broken_windows,replay_smb3_specification_durable replay_smb3_specification_multi,rw-exclusive rw-shared,stacking unlock,valid-request zerobytelength,zerobyteread |
| smb2.lease | ❌ FAIL | 31/8/0/0 | complex1,lock1 request,statopen3 unlink,v2_complex1 v2_complex2,v2_epoch3 — NOTE: rename_wait and multibreak PASS this run but are timing-flaky (28–31 total observed across 2026-10-20…23 runs; see lease-analysis.md) |
| smb2.durable-v2-open | ❌ FAIL | 14/1/0/0 | app-instance |
| smb2.notify | ⚠️ INCOMPLETE | — (stalls at `basedir`, no count) | hangs at subtest `basedir`: attribute-change filter fidelity (SETATTR on the watched dir must not match, on a child must) — known debt for a later notify campaign, NOT a budget problem (see lock-analysis.md) |
| smb2.rename | ❌ FAIL | 3/9/0/0 | close-full-information,msword no_share_delete_but_delete_access,no_share_delete_no_delete_access no_sharing,rename_dir_openfile share_delete_and_delete_access,share_delete_no_delete_access simple_nodelete |
| smb2.delete-on-close-perms | ❌ FAIL | 6/3/0/0 | CREATE_IF,OVERWRITE_IF READONLY |
| smb2.sharemode | ❌ FAIL | 1/2/0/0 | access-sharemode,sharemode-access |
| rpc.srvsvc | ❌ FAIL | 2/15/0/0 | srvsvc |

Full logs: /tmp/torture-*.log
