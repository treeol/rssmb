# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ (development — not production-ready) |
| 1.0.x   | Planned (after external security review) |

RSSMB is pre-1.0. Security fixes are applied to the latest `main` only.

## Reporting a Vulnerability

**Do not open a public issue.**

Use **GitHub Security Advisories** (Security tab → Advisories → Report a
vulnerability). This keeps reports private and lets the maintainers
coordinate a fix and CVE without a public issue.

Include:
- A description of the vulnerability and its impact
- Steps to reproduce (proof of concept, if possible)
- Affected versions
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours. If the report is
accepted, a fix will be prepared and a CVE requested. Credit is given
unless you prefer anonymity.

## Threat Model

See [docs/threat-model.md](docs/threat-model.md) for what RSSMB defends
against and what it does not.

## Security Features

- **SMB 3.1.1 pre-auth integrity** (SHA-512 hash)
- **Signing required by default** (HMAC-SHA256)
- **Encryption supported** (AES-128-GCM)
- **NTLM AUTHENTICATE message MIC verification** (MS-NLMP 3.2.5.1.2)
- **Auth failure throttling** (per-IP exponential backoff + cooldown)
- **Path confinement** (cap-std, openat2/RESOLVE_BENEATH — TOCTOU-free)
- **Name validation** (NFC normalization, control/reserved char rejection)
- **MessageId sequence window** (credit tracking with bounded state)
- **Connection limits** (global + per-IP)
- **Idle timeout** (default 900s)
- **Config file permission warnings** (world/group-readable)