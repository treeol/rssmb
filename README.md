# RSSMB — Pure-Rust SMB2/3 Server

[![CI](https://github.com/rssmb/rssmb/actions/workflows/ci.yml/badge.svg)](https://github.com/rssmb/rssmb/actions/workflows/ci.yml)
[![Interop CI](https://github.com/rssmb/rssmb/actions/workflows/interop-ci.yml/badge.svg)](https://github.com/rssmb/rssmb/actions/workflows/interop-ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://www.rust-lang.org/)

A standalone SMB2/3 file server written in pure Rust, designed for
container-native deployment (Docker, Swarm, Kubernetes). No Samba, no
external C libraries — just Rust and the Linux kernel.

Negotiates SMB 2.1 through 3.1.1 with AES-128-GCM encryption, NTLMv2
authentication, and SrvSvc share enumeration. Tested against the Linux
kernel CIFS client, `smbclient`, GNOME Files (Nautilus), and Samba's
`smbtorture` conformance suite.

## Features

**SMB protocol**
- SMB 2.1 → 3.1.1 dialect negotiation
- AES-128-GCM encryption (SMB 3.x), SHA-512 pre-auth integrity (3.1.1)
- HMAC-SHA256 signing (required by default)
- NTLMv2 authentication via SPNEGO, AUTHENTICATE message MIC verification
- KEY_EXCH session key derivation (ExportedSessionKey)
- Large MTU (1 MiB) with multi-credit flow control
- Durable handles v2 (DH2Q/DH2C) with reconnection
- CHANGE_NOTIFY (inotify-backed directory change notifications)
- Byte-range locks (mandatory, all-or-nothing batch)
- Case-insensitive path lookup (NFC-aware)
- Security descriptors synthesized from POSIX uid/gid/mode

**Security**
- Path confinement via `cap-std` + `openat2(RESOLVE_BENEATH)` — TOCTOU-free
- Per-share symlink policy (`Never` / `WithinShare`)
- NFC name normalization, control/reserved char rejection, length limits
- Per-IP auth throttling (exponential backoff + hard cooldown)
- Global + per-IP connection limits
- MessageId sequence window (bounded state, overflow-safe)
- Per-share access lists: `valid_users`, `read_users`, `write_users`
- `deny_unknown_fields` config validation, config permission warnings
- `catch_unwind` in the read loop for malformed-frame resilience

**Operations**
- Graceful shutdown (SIGTERM/SIGINT, bounded drain)
- SIGHUP live-reload of users and shares without restart
- Prometheus metrics on `/metrics`, health on `/healthz`
- Structured JSON logging (`--log-format json`)
- `rssmb check-config` validates config before startup
- `rssmb hash-password` generates NT hashes

## Quick start (Docker)

```sh
mkdir -p data/public data/homes && sudo chown -R 1000:1000 data
chmod 600 config/rssmb.toml   # contains credentials; see note below
docker compose -f docker/compose.yml up -d --build
docker logs -f rssmb   # Ctrl-C to stop following
curl -s localhost:8080/healthz
```

The dev config (`config/rssmb.toml`) ships with a guest-access `public`
share, a `homes` share, and a test account `alice` / `TestPass123` —
**not for production.** For production, copy `config/rssmb.example.toml`
to `config/rssmb.toml` and edit it (signing required, guest disabled, real
users with NT hashes).

The container runs as UID 1000 and reads `config/rssmb.toml` through a
read-only bind mount, so the file must stay readable by UID 1000. If your
host user is not UID 1000, use `sudo chown 1000 config/rssmb.toml`
(keeping mode `600`), or `sudo chgrp 1000 config/rssmb.toml && chmod 640 config/rssmb.toml`.
Without this, the server logs a "config file is world-readable" warning on
startup.

Port 445 on the host must be free (stop a local Samba first). If it
isn't, change the mapping in `docker/compose.yml` to e.g. `"4450:445"`
and add `port=4450` to the mount options below.

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

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_addr` / `port` | `0.0.0.0:445` | Bind address |
| `min_dialect` / `max_dialect` | `smb21` / `smb311` | SMB dialect range |
| `signing` | `required` | `required` (reject unsigned + disable guest) · `desired` · `disabled` |
| `encryption` | `desired` | `required` · `desired` · `disabled` (SMB 3.1.1 AES-128-GCM) |
| `guest_access` | `false` | Allow anonymous guest logons (only `guest_ok` shares) |
| `max_connections_per_ip` | `0` (`100` in example config) | Per-IP connection limit (`0` = unlimited) |
| `max_frame_size` | `1048576` | Maximum SMB frame size (1 MiB) |
| `max_credits` | `1024` | Maximum outstanding credits |
| `health_port` | `8080` | HTTP health/metrics endpoint |
| `shutdown_grace_secs` | `10` | Graceful drain timeout on SIGTERM/SIGINT |

Per share (`[shares.<name>]`):

| Key | Description |
|-----|-------------|
| `path` | Share root directory |
| `read_only` | Reject all mutating operations |
| `guest_ok` | Allow guest access to this share |
| `browseable` | Show in `NetrShareEnum` listing |
| `valid_users` | Restrict to named users (empty = all authenticated) |
| `read_users` | Restrict read access (empty = all `valid_users`) |
| `write_users` | Restrict write access (empty = all `valid_users`) |

Users (`[[users]]`): `username`, `password` (plaintext) or `nt_hash` (hex,
preferred — generate with `rssmb hash-password`), `disabled`.

The config file may contain password-equivalent secrets — `chmod 600` it
and mount it as a secret in Kubernetes (not a ConfigMap).

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting policy and
[`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

**Status:** Pre-1.0. An external security review is required before the 1.0
release. The [MS-NLMP], [MS-SMB2], and [MS-SRVS] protocol implementations have
been hardened through three rounds of automated review (Mashūra) covering
NTLM authentication, SPNEGO parsing, path confinement, credit tracking, and
config validation.

[MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp
[MS-SMB2]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2
[MS-SRVS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs

## Testing & conformance

```sh
cargo test --workspace          # 503 unit + integration tests
tests/live/run.sh               # impacket-based interop (needs Python)
tests/live/mount.sh <server-ip> # real kernel CIFS mount (needs Docker --privileged)
tests/conformance/run-smbtorture.sh   # smbtorture baseline (needs samba-testsuite)
```

CI runs on every push and PR:

- **ci.yml** — `cargo fmt --check`, `cargo clippy -D warnings`, `cargo build
  --locked`, `cargo test --workspace`, `cargo deny check` (advisories,
  licenses, bans, sources), `cargo audit`
- **interop-ci.yml** — unit tests, impacket interop, `smbclient` interop,
  nightly `smbtorture` conformance, nightly fuzz campaigns (9 targets, 5
  min each)

Fuzz targets (9): `parse_payload`, `read_netbios_frame`, `extract_ntlm_token`,
`extract_mech_types`, `proto_decode_header`, `proto_decode_plain_request`,
`normalize_path`, `ntlm_authenticate`, `decrypt_transform`.

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

## Roadmap

**Not yet implemented (post-1.0):**
- Oplocks and leases
- Multichannel
- Kerberos authentication
- Persistent handles (TLER resilient)
- QUIC transport (SMB 3.1.1 alternative)

## License

MIT OR Apache-2.0
