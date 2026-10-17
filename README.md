<div align="center">

# RSSMB

A pure-Rust SMB2/3 file server for container-native environments.

[![CI](https://img.shields.io/github/actions/workflow/status/rssmb/rssmb/ci.yml?label=CI)](https://github.com/rssmb/rssmb/actions/workflows/ci.yml)
[![Interop](https://img.shields.io/github/actions/workflow/status/rssmb/rssmb/interop-ci.yml?label=Interop)](https://github.com/rssmb/rssmb/actions/workflows/interop-ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://www.rust-lang.org/)

SMB 2.1 – 3.1.1 · AES-128-GCM encryption · NTLMv2 auth · 5 MB static binary

</div>

---

RSSMB is a standalone SMB2/3 file server written entirely in Rust. No Samba,
no external C libraries — just Rust and the Linux kernel. It is designed for
cloud-native file serving: a single static binary that runs in a `scratch`
container, mounts config as a secret, and serves shares from a data volume.

The server negotiates SMB 2.1 through 3.1.1 with AES-128-GCM encryption,
NTLMv2 authentication via SPNEGO, and SrvSvc share enumeration. It has been
tested against the Linux kernel CIFS client, `smbclient`, GNOME Files
(Nautilus), and Samba's `smbtorture` conformance suite.

## Table of contents

- [Why RSSMB?](#why-rssmb)
- [Features](#features)
- [Quick start](#quick-start)
- [Building from source](#building-from-source)
- [Configuration](#configuration)
- [Security](#security)
- [Testing & conformance](#testing--conformance)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [License](#license)

## Why RSSMB?

| | RSSMB | Samba |
|---|---|---|
| **Runtime dependencies** | ✅ None (static binary) | ❌ glibc, libtalloc, libldb, libtdb, … |
| **Container image** | ✅ ~5 MB (`FROM scratch`) | ❌ ~100 MB+ (Debian/Ubuntu base) |
| **Attack surface** | ✅ Pure Rust, no C FFI | ⚠️ ~1 M LOC C |
| **Config** | ✅ One TOML file, hot-reload via SIGHUP | ⚠️ `smb.conf` + `pdbedit` + `net` |
| **Users** | ✅ Config file (NT hashes) | ⚠️ Multiple backends (tdbsam, ldapsam, …) |
| **Scope** | 🎯 File serving for containers | 🎯 General-purpose SMB/AD/DC |

RSSMB does not aim to replace Samba in Active Directory environments. It
targets the common case: **serve files from a volume to SMB clients with
minimal overhead and maximal security**.

## Features

### 📡 SMB protocol

- SMB 2.1 – 3.1.1 dialect negotiation
- AES-128-GCM encryption (SMB 3.x) with SHA-512 pre-auth integrity (3.1.1)
- HMAC-SHA256 message signing (required by default)
- NTLMv2 authentication via SPNEGO with AUTHENTICATE message MIC verification
- `KEY_EXCH` session key derivation (ExportedSessionKey)
- Large MTU (1 MiB) with multi-credit flow control
- Durable handles v2 (DH2Q / DH2C) with reconnection
- `CHANGE_NOTIFY` — inotify-backed directory change notifications
- Mandatory byte-range locks (all-or-nothing batch)
- Case-insensitive path lookup (NFC-aware, multi-component)
- Security descriptors synthesized from POSIX uid/gid/mode

### 🔒 Security

- Path confinement via `cap-std` + `openat2(RESOLVE_BENEATH)` — TOCTOU-free
- Per-share symlink policy (`Never` / `WithinShare`)
- NFC name normalization, control/reserved character rejection, length limits
- Per-IP authentication throttling (exponential backoff + hard cooldown)
- Global and per-IP connection limits
- MessageId sequence window (bounded state, overflow-safe)
- Per-share access lists: `valid_users`, `read_users`, `write_users`
- `deny_unknown_fields` config validation with permission warnings
- `catch_unwind` in the read loop for malformed-frame resilience

### ⚙️ Operations

- Graceful shutdown (SIGTERM / SIGINT with bounded drain)
- SIGHUP live-reload of users and shares without restart
- Prometheus metrics on `/metrics`, health on `/healthz`
- Structured JSON logging (`--log-format json`)
- `rssmb check-config` validates configuration before startup
- `rssmb hash-password` generates NT hashes

## Quick start

The Docker image is a **~5 MB static binary in `FROM scratch`** — no OS,
no shell, no dynamic libraries. Just the binary and the config/data volumes
you mount.

```sh
# 1. Create data directories owned by UID 1000 (the container's user)
mkdir -p data/public data/homes
sudo chown -R 1000:1000 data

# 2. Lock down the config file (it contains credentials)
chmod 600 config/rssmb.toml

# 3. Start the server
docker compose -f docker/compose.yml up -d --build

# 4. Verify it's healthy
curl -s localhost:8080/healthz
docker logs -f rssmb   # Ctrl-C to stop following
```

> **💡 Dev config:** `config/rssmb.toml` ships with a guest-access `public`
> share, a `homes` share, and test account `alice` / `TestPass123` —
> **not for production.** For production, copy `config/rssmb.example.toml`
> to `config/rssmb.toml` and edit it (signing required, guest disabled,
> real users with NT hashes).

> **📁 File permissions:** The container runs as UID 1000 and reads
> `config/rssmb.toml` through a read-only bind mount. If your host user
> is not UID 1000, use `sudo chown 1000 config/rssmb.toml` (keeping mode
> `600`), or `sudo chgrp 1000 config/rssmb.toml && chmod 640`. Without
> this, the server logs a "config file is world-readable" warning.

> **🔌 Port 445:** Must be free on the host (stop a local Samba first). If
> it isn't, change the mapping in `docker/compose.yml` to e.g.
> `"4450:445"` and add `port=4450` to the mount options below.

### Mount it (Linux)

```sh
sudo mount -t cifs //127.0.0.1/public /mnt/rssmb \
  -o username=alice,password=TestPass123,vers=3.1.1,uid=$(id -u),gid=$(id -g)
ls -la /mnt/rssmb
echo hi > /mnt/rssmb/hello.txt
cat data/public/hello.txt
sudo umount /mnt/rssmb
```

Without a mount:

```sh
smbclient //127.0.0.1/public -U alice%TestPass123 -m SMB2 -c 'ls; get README.md'
```

### Stop

```sh
docker compose -f docker/compose.yml down
```

## Building from source

Requires Rust 1.85+ (stable).

```sh
cargo build --release
cargo test --workspace
```

Run the server:

```sh
cargo run --release --bin rssmb -- --config config/rssmb.toml
```

CLI subcommands:

```sh
rssmb check-config --config config/rssmb.toml   # validate config
rssmb hash-password <password>                  # generate NT hash
```

## Configuration

See `config/rssmb.example.toml` for production-safe defaults. Key settings:

### Server settings

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_addr` / `port` | `0.0.0.0:445` | SMB bind address |
| `min_dialect` / `max_dialect` | `smb21` / `smb311` | SMB dialect range |
| `signing` | `required` | `required` (reject unsigned + disable guest) · `desired` · `disabled` |
| `encryption` | `desired` | `required` · `desired` · `disabled` (SMB 3.1.1 AES-128-GCM) |
| `guest_access` | `false` | Allow anonymous guest logons (only `guest_ok` shares) |
| `max_connections_per_ip` | `0` (`100` in example config) | Per-IP connection limit (`0` = unlimited) |
| `max_frame_size` | `1048576` | Maximum SMB frame size (1 MiB) |
| `max_credits` | `1024` | Maximum outstanding credits |
| `health_bind_addr` / `health_port` | `0.0.0.0` / `8080` | HTTP health/metrics endpoint |
| `shutdown_grace_secs` | `10` | Graceful drain timeout on SIGTERM/SIGINT |

### Per-share settings (`[shares.<name>]`)

| Key | Description |
|-----|-------------|
| `path` | Share root directory |
| `read_only` | Reject all mutating operations |
| `guest_ok` | Allow guest access to this share |
| `browseable` | Show in `NetrShareEnum` listing |
| `valid_users` | Restrict to named users (empty = all authenticated) |
| `read_users` | Restrict read access (empty = all `valid_users`) |
| `write_users` | Restrict write access (empty = all `valid_users`) |

### Users (`[[users]]`)

Each user needs a `username` and either a `password` (plaintext) or
`nt_hash` (hex — preferred, generate with `rssmb hash-password`). Set
`disabled = true` to deactivate an account without removing it.

> **🔒 Security:** The config file may contain password-equivalent secrets.
> `chmod 600` it and mount it as a secret in Kubernetes (not a ConfigMap).

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting policy and
[`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

**Status:** Pre-1.0. The [MS-NLMP], [MS-SMB2], and [MS-SRVS] protocol
implementations have been hardened through multiple rounds of automated
review (Mashūra) covering NTLM authentication, SPNEGO parsing, path
confinement, credit tracking, connection lifecycle, delete-on-close
semantics, and config validation.

[MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp
[MS-SMB2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2
[MS-SRVS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs

## Testing & conformance

```sh
cargo test --workspace          # 520 unit + integration tests
tests/live/run.sh               # impacket-based interop (needs Python)
tests/live/mount.sh <server-ip> # real kernel CIFS mount (needs Docker --privileged)
tests/conformance/run-smbtorture.sh   # smbtorture baseline (needs samba-testsuite)
```

### CI

Every push and PR runs:

| Workflow | Checks |
|---------|--------|
| **ci.yml** | `cargo fmt --check` · `cargo clippy -D warnings` · `cargo build --locked` · `cargo test --workspace` · `cargo deny check` (advisories, licenses, bans, sources) · `cargo audit` |
| **interop-ci.yml** | impacket interop · `smbclient` interop · nightly `smbtorture` conformance · nightly fuzz campaigns (9 targets, 5 min each) |

### Fuzz targets

9 targets covering the attack surface:

```
parse_payload · read_netbios_frame · extract_ntlm_token · extract_mech_types
proto_decode_header · proto_decode_plain_request · normalize_path
ntlm_authenticate · decrypt_transform
```

## Architecture

```
crates/
  rssmb-proto/          SMB2/3 wire protocol types (pure-Rust, no smb_msg)
  rssmb-wire-adapter/   Server-side wire codec over rssmb-proto
  rssmb-auth/           NTLM acceptor (sspi), SPNEGO, credential store
  rssmb-vfs/            VFS trait + LocalFs (cap-std) and MemoryFs backends
  rssmb-rpc-server/     DCE/RPC server-side: SrvSvc share enumeration
  rssmb-server/         Core server: connection engine, session, tree, opens
  rssmb-cli/            Server binary: config, signals, health endpoint
  rssmb-tests/          Integration test harness
docker/                 Dockerfile + docker-compose
config/                 Example configurations
fuzz/                   cargo-fuzz targets
```

Each crate is independently testable. The protocol layer
(`rssmb-proto` / `rssmb-wire-adapter`) has zero server dependencies and can
be reused in other SMB tools.

## Roadmap

**Implemented (1.0 scope):**
- ✅ SMB 2.1 – 3.1.1 with encryption, signing, and NTLMv2
- ✅ Durable handles v2, byte-range locks, change notify
- ✅ SIGHUP hot-reload, Prometheus metrics, graceful shutdown
- ✅ `smbtorture` conformance, impacket/smbclient interop, fuzzing

**Recently implemented:**
- ✅ File leases v1/v2 (R, RH, RW) and traditional oplocks (Level II, Exclusive, Batch)
- ✅ SMB over QUIC transport (TLS 1.3, ALPN `smb`, UDP/443)
- ✅ Multichannel (SMB 3.x session binding, shared state across channels)

**Not yet implemented:**
- Kerberos authentication
- Persistent handles (TLER resilient)
- `FSCTL_QUERY_NETWORK_INTERFACE_INFO` NIC enumeration (multichannel capability advertised; interface discovery returns `NotSupported` until real NIC enumeration is added)

## License

[Apache-2.0](LICENSE) · Copyright 2024–2026 RSSMB Contributors
