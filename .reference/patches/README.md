# Patches to the vendored `smb-rs` checkout

`smb-rs/` is gitignored (third-party, base commit `7c7d4a6`). rssmb needs local
fixes to its `smb-msg` / `smb-dtyp` crates; they are kept here so a fresh
checkout or a Docker build gets the same code:

```sh
git -C smb-rs checkout 7c7d4a6
git -C smb-rs apply ../patches/smb-rs-rssmb.patch
```

Regenerate after changing smb-rs: `git -C smb-rs diff > patches/smb-rs-rssmb.patch`.

What the patch contains (server-side decoding of real client traffic):

- `CloseRequest.flags` is a plain field (clients send Flags=0).
- `CreateRequest`: no create contexts → don't align/read past the name;
  seek to the header-relative CreateContextsOffset otherwise.
- Create-context offsets: saturating arithmetic (cifs.ko sends `QFid` with
  DataOffset=0, which panicked with an arithmetic overflow).
- `OplockLevel`: Batch (0x09) and Lease (0xFF) request levels.
- Saturating length arithmetic in compressed-message and ACE parsing.
- `QueryInfoResponse::from_bytes`, `FileTime::as_u64`, `Default` derives.
- `IoctlRequest`: OutputOffset/OutputCount are read but not asserted to be 0
  (MS-SMB2 2.2.31; smbclient SMB3 sends non-zero values).
- `NegotiateContextType::Unknown(u16)` / `NegotiateContextValue::Unknown`:
  unrecognized negotiate contexts (e.g. Samba's POSIX extensions, 0x0100)
  decode as raw data instead of failing the whole NEGOTIATE (MS-SMB2 3.3.5.4:
  ignore unknown contexts). `NegotiateContextType` is now a magic-tagged enum,
  not `repr(u16)`; use `.id()` for the wire value.
- `HashAlgorithm`, `EncryptionCipher`, `SigningAlgorithmId`,
  `CompressionAlgorithm`: magic-tagged enums with `Unknown(u16)` catch-all
  and `.id()` method. Unrecognized IDs inside negotiate contexts no longer
  fail the whole request. `Dialect` is left as `repr(u16)` — too many cast
  sites to change, and real clients send known dialect values.

Step 9 in `docs/next-steps.md` replaces this with a proper fork/vendor.
