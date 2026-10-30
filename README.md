<div align="center">

# RSSMB

A pure-Rust SMB2/3 file server for container-native environments.

[![CI](https://github.com/treeol/rssmb/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/treeol/rssmb/actions/workflows/ci.yml)
[![Interop](https://github.com/treeol/rssmb/actions/workflows/interop-ci.yml/badge.svg?branch=main)](https://github.com/treeol/rssmb/actions/workflows/interop-ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/MSRV-1.93-orange.svg)](https://www.rust-lang.org/)

SMB 2.1 – 3.1.1 · AES-128-GCM encryption · NTLMv2 auth · ~8 MB static binary

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
- [Contributing](#contributing)
- [License](#license)

## Why RSSMB?

| | RSSMB | Samba |
|---|---|---|
| **Runtime dependencies** | ✅ None (static binary) | ❌ glibc, libtalloc, libldb, libtdb, … |
| **Container image** | ✅ ~8 MB (`FROM scratch`) | ❌ ~100 MB+ (Debian/Ubuntu base) |
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
- Durable handles v1/v2 (DHnQ/DHnC, DH2Q/DH2C) with reconnection —
  smb2.durable-v2-open 14/15 (smbtorture 4.19.5; the one failure is
  AppInstanceId, which Samba 4.19.5 itself does not implement — see
  `tests/conformance/results.md`)
- File leases v1/v2 (R, RH, RW, RWH) and traditional oplocks with break handling
- Byte-range locks with blocking, CANCEL, LockSequence replay detection —
  smb2.lock 22/22 (smbtorture 4.19.5, full parity with smbd — 25/0/0/0
  in the 2026-10-28 v0.1.9 baseline;
  `tests/conformance/results.md`)
- Multichannel (SMB 3.x): session binding across connections and
  `FSCTL_QUERY_NETWORK_INTERFACE_INFO` interface discovery
- SMB over QUIC (SMB 3.1.1 over TLS 1.3, ALPN `smb`, UDP/443) — traverse
  firewalls that block TCP/445
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

The Docker image is a **~8 MB static binary in `FROM scratch`** — no OS,
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

## Prebuilt releases

Each [GitHub release](https://github.com/treeol/rssmb/releases) ships
static musl binaries for `x86_64` and `aarch64` Linux (with `SHA256SUMS`),
and a multi-arch image:

```sh
docker pull ghcr.io/treeol/rssmb:latest   # or :0.1.10
docker run -d --name rssmb -p 445:445 \
  -v ./config/rssmb.toml:/etc/rssmb/rssmb.toml:ro \
  -v ./data:/data ghcr.io/treeol/rssmb:latest
```

## Building from source

Requires Rust 1.93+ (stable).

```sh
cargo build --release
cargo test --workspace
```

Release/Docker builds (musl target) use [mimalloc](https://github.com/microsoft/mimalloc)
as the global allocator — feature-gated (`mimalloc`, **on by default**). Same-rig
A/B medians (kernel CIFS mount, fio r16, 1 MiB direct reads, 3 runs per cell;
test env, tmpfs — absolute numbers are rig-dependent):

| | musl system (0.1.9) | musl + mimalloc (0.1.10) | glibc system |
|---|---|---|---|
| unsealed read | 378 MiB/s | **2480 MiB/s** | 1262 MiB/s |
| sealed read | 327 MiB/s | **942 MiB/s** | 523 MiB/s |

That is ~6.6× the musl system allocator unsealed and ~2.9× sealed, at a cost of
~+8 MB idle RSS and ~+6% binary size. Disable with `--no-default-features` if
you need the smallest binary. The A/B protocol and build recipe:
`tests/perf/build-ab.sh`, `tmp/stress/ab-bench*.sh`.

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
| `max_frame_size` | `1048576` | Maximum SMB2 payload size = advertised MaxRead/MaxWrite/MaxTransactSize (capped at 1 MiB, min 65536); the wire frame limit adds a fixed 64 KiB header allowance |
| `max_credits` | `8192` | Maximum SMB2 credit window per connection (smbd `smb2 max credits` parity) |
| `health_bind_addr` / `health_port` | `0.0.0.0` / `8080` | HTTP health/metrics endpoint |
| `shutdown_grace_secs` | `10` | Graceful drain timeout on SIGTERM/SIGINT |
| `leases` | `true` | SMB 2.1+ file leases and traditional oplocks |
| `multichannel` | `false` | SMB 3.x multichannel (advertised only when usable interfaces exist; disabled by default until binding hardening lands) |
| `ntlm_require_timestamp` | `false` | Require MsvAvTimestamp in NTLMv2 AUTHENTICATE (anti-replay) |
| `ntlm_max_clock_skew_secs` | `600` | Max clock skew (seconds) for NTLMv2 timestamp freshness check; `0` = presence-only |
| `multichannel_interfaces` | `[]` | Pin advertised addresses for NAT/Kubernetes (empty = enumerate host NICs) |
| `quic_enabled` | `false` | SMB over QUIC (SMB 3.1.1 over TLS 1.3, UDP) |
| `quic_port` | `443` | UDP port for SMB over QUIC |
| `quic_cert_path` / `quic_key_path` | — | PEM TLS certificate chain / private key (required when `quic_enabled`) |

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
| `publish_on_close` | Write new files under a hidden `.rssmb-tmp.*` name and atomically rename to the final name on the last close (default `false`). SMB clients always see the final name; host-side watchers/backups never observe a pre-sized file with no data. CHANGE_NOTIFY directory watches map temp events to the client-visible final name so no temp name ever surfaces. Multi-handle attaches publish on the last close; an attach that rolls back to zero publishes instead of orphaning the temp. Rename-with-replace does the move + collision handling under one table-level lock. Close-publish renames under the table write lock; attach is phantom-free (no mint-then-abort). |

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
cargo test --workspace          # 646 unit + integration tests
tests/live/run.sh               # impacket-based interop (needs Python)
tests/live/mount.sh <server-ip> # real kernel CIFS mount (needs Docker --privileged)
tests/conformance/run-smbtorture.sh   # smbtorture baseline (needs samba-testsuite)
```

`tests/live/mount.sh` is **not run in CI**: it mounts with the host kernel's
`cifs` module from a `docker run --privileged` container, which GitHub-hosted
runners don't offer reliably. Run it locally before releases. It is the only
test that drives a real kernel client, including sealed (`seal`) 1 MiB
O_DIRECT writes.

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

The tracked list of everything open lives in [`docs/ROADMAP.md`](docs/ROADMAP.md) —
items `R-01`…`R-29` across priorities P0–P3, plus accepted-never exclusions.
Every campaign and PR references a roadmap item ID.

## Contributing

Follow [`docs/WORKING-METHOD.md`](docs/WORKING-METHOD.md) — the rules for
roadmap references, conformance campaigns, golden behaviour, reviews, and
releases.

## License

[Apache-2.0](LICENSE) · Copyright 2026 Valon Mamudi
