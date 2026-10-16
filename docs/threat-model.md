# RSSMB Threat Model

## What RSSMB Is

A standalone SMB2/3 server for Windows and Linux clients. No Active Directory,
no Kerberos, no macOS. Single service-OS user with per-share access lists.

## What RSSMB Defends Against

### Network attackers (unauthenticated)

- **Passive eavesdropping:** AES-128-GCM encryption (SMB 3.x). Signing
  required by default (HMAC-SHA256).
- **Pre-auth tampering:** SMB 3.1.1 pre-auth integrity (SHA-512 hash
  exchange) detects tampering before authentication completes.
- **Credential stuffing / brute force:** Per-IP auth failure throttling
  (exponential backoff + hard cooldown). Per-connection failure cap.
- **Connection flooding:** Global + per-IP connection limits.
- **Malformed protocol frames:** All parsers are bounds-checked and
  fuzzed (6 existing + 3 new targets). Panic-catching (`catch_unwind`)
  in the read loop guards `parse_payload`; downstream handlers, signing,
  crypto, and cleanup are outside the catch_unwind scope. Build profiles
  do not set `panic=abort`, so `catch_unwind` is effective.
- **Path traversal / symlink escapes:** cap-std confinement with
  openat2(RESOLVE_BENEATH) on Linux ≥5.6. TOCTOU-free. Symlink policy
  configurable per share (Never / WithinShare).
- **Name canonicalization attacks:** NFC normalization, control/reserved
  char rejection, UTF-16 length limits, trailing dot/space rejection.
- **Credit exhaustion / sequence confusion:** MessageId sequence window
  with bounded state (HashSet capped at max_grant width), overflow-safe
  arithmetic, all-or-nothing deduction.
- **Replay attacks:** NTLM MsvAvTimestamp presence check (configurable).
  The server requires the client to include a timestamp AV_PAIR in the
  AUTHENTICATE blob. This is a presence check, not full replay detection
  (no comparison against server time, no freshness window). A captured
  AUTHENTICATE can still be replayed within an active challenge window.

### Malicious authenticated users

- **Unauthorized share access:** Per-share `valid_users`, `read_users`,
  `write_users` access lists. TREE_CONNECT gate enforces `read_users`.
  CREATE/WRITE/SET_INFO enforce `write_access`.
- **Unauthorized writes:** `read_only` shares reject mutating operations.
  SET_INFO class guards prevent attribute/EoF abuse.
- **Denial via lock exhaustion:** Per-file lock lists bounded by
  OpenTable entry lifetime. Tree-disconnect / logoff releases all locks.
- **Stale durable handle reuse:** DH2C validates username + share before
  re-attaching. Writable durables refused on read-only reconnect.

## What RSSMB Does NOT Defend Against

- **Local users with share write access:** A local user with write access
  to a share root can create hard links, modify files, exhaust inodes,
  or replace directory entries between path resolution and file open.
  cap-std confinement mitigates symlink escapes but cannot prevent
  concurrent modification by other local processes.
- **Root:** A root user on the host can read the config file (passwords
  / NT hashes), inspect process memory, intercept traffic, and modify
  the share root. RSSMB does not defend against a compromised host.
- **Side-channel attacks:** No timing-attack mitigation beyond
  constant-time comparison in auth paths. No speculative-execution
  hardening.
- **Post-auth privilege escalation via SMB:** RSSMB does not implement
  per-file ACLs (security descriptors are synthesized from POSIX mode
  bits; SET_INFO Security is accepted but not persisted). A user with
  write access to a share can modify any file they can open.
- **Kernel bugs:** cap-std relies on the kernel's openat2 / O_NOFOLLOW
  implementation. A kernel bug in these paths bypasses confinement.

## External Security Review

**Status: pending.** An external security review is required before
calling RSSMB 1.0. This document, the source code, and the test suite
should be provided to the reviewer.

## Scope for Review

- NTLM authentication (NTLMv2, MIC verification, session key derivation)
- SPNEGO/NTLM token parsing (pre-auth attack surface)
- Path confinement (cap-std, openat2, symlink policy)
- Name validation (NFC, length limits, reserved chars)
- Credit/MessageId tracking (sequence window, overflow safety)
- Connection lifecycle (graceful drain, SIGHUP reload)
- Config handling (deny_unknown_fields, validation, file permissions)