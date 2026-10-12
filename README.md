# RSSMB — A Pure-Rust SMB2/3 Server for Dynamic Container Environments

[![CI](https://github.com/rssmb/rssmb/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

A pure-Rust SMB2/3 **server** designed for dynamic deployment in Docker/Swarm/Kubernetes.
Leverages Rust's memory safety for a robust, exploit-resistant file-sharing server.

## Status

**Mountable over SMB 2.1.** A Linux kernel CIFS mount (`mount -t cifs … vers=2.1`)
works for ls, read, write, append, overwrite, mkdir, rename, delete and a
300 KiB round-trip, with and without message signing. See `docs/next-steps.md`
for the step-by-step plan and what remains.

- ✅ Phase 0 — Workspace, wire codec, types, VFS trait, crypto, config
- ✅ Phase 1 — Transport + connection engine (TCP listener, framing, credits, negotiate)
- ✅ Phase 2 — Secure sessions: NTLMv2 + SMB 2.1 signing done; SMB 3.x and encryption done (3.1.1 AES-128-GCM)
- ✅ Phase 3 — Core file serving (create/read/write/close, metadata, directory)
- ✅ Phase 4 — DCE/RPC server-side: SrvSvc share enumeration (NetrShareEnum/GetInfo/ServerGetInfo via IPC$)
- ⬜ Phase 5 — Oplocks + leases
- ⬜ Phase 6 — Container-native + production readiness
- ⬜ Phase 7 — Fuzzing + conformance
- ⬜ Phase 8 — Advanced (Kerberos, durable handles, multichannel, QUIC)

## Architecture

```
rssmb/
  crates/
    rssmb-wire-adapter/  — Server-side wire codec over smb-msg (server feature)
    rssmb-auth/          — NTLM acceptor via sspi, SPNEGO, credential store
    rssmb-vfs/           — VFS trait + LocalFs and MemoryFs backends
    rssmb-rpc-server/    — DCE/RPC server-side (SrvSvc share enumeration)
    rssmb-server/        — Core server: connection engine, session, tree, opens, crypto
    rssmb-cli/           — Server binary with config, signals, health endpoint
    rssmb-tests/         — Integration test harness
  docker/                — Dockerfile + docker-compose for dev/test
  config/                — Example configuration
```

## Building

```sh
cargo build
cargo test --workspace
```

## Running

```sh
cargo run --bin rssmb -- --config config/rssmb.toml
```

## Try it (Docker)

`config/rssmb.toml` ships with two shares (`public` = guest-ok, `homes` =
users only) and a test account `alice` / `TestPass123` — change it before
exposing the server.

```sh
git -C smb-rs apply ../patches/smb-rs-rssmb.patch   # once, on a fresh smb-rs checkout
mkdir -p data/public data/homes && sudo chown -R 1000:1000 data
docker compose -f docker/compose.yml up -d --build
docker logs -f rssmb                                # Ctrl-C to stop following
curl -s localhost:8080/healthz
```

Port 445 on the host must be free (stop a local Samba first). If it isn't,
change the mapping in `docker/compose.yml` to e.g. `"4450:445"` and add
`port=4450` to the mount options below.

Mount it on Linux (needs `cifs-utils`):

```sh
sudo mkdir -p /mnt/rssmb
sudo mount -t cifs //127.0.0.1/public /mnt/rssmb \
  -o username=alice,password=TestPass123,vers=2.1,uid=$(id -u),gid=$(id -g)
ls -la /mnt/rssmb; echo hi > /mnt/rssmb/hello.txt; cat data/public/hello.txt
sudo umount /mnt/rssmb
```

Or without a mount: `smbclient //127.0.0.1/public -U alice%TestPass123 -m SMB2 -c 'ls; get README.md'`.

Stop it: `docker compose -f docker/compose.yml down`.

## Mounting

The server currently negotiates **SMB 2.1 only**, so clients must allow it:

```sh
# Linux kernel client (as root):
mount -t cifs //SERVER/public /mnt/smb -o username=alice,password=...,vers=2.1
# add ,sign to require signing from the client side; add port=N for a non-445 port
```

macOS Finder, Windows 11 and recent GNOME defaults prefer SMB 3.x and may refuse
2.1 until Step 7b/7c lands.

## Configuration

See `config/rssmb.toml` for all options. Key settings:

- `listen_addr` / `port` — bind address (default: `0.0.0.0:445`)
- `min_dialect` / `max_dialect` — SMB dialect range (default: `smb21` to `smb311`).
  Only SMB 2.1 is negotiated today regardless of `max_dialect`.
- `signing` — `required` | `desired` | `disabled` (default: `required`).
  `required` rejects unsigned/forged requests **and disables guest/anonymous
  logons** (they have no key and cannot sign). `desired` and `disabled` both
  sign only when the client requires it — signing cannot be refused.
- `encryption` — `required` | `desired` | `disabled` (default: `desired`). Not implemented yet.
- `guest_access` — allow anonymous logons as guest (only for shares with `guest_ok`)
- `health_port` — HTTP health/metrics endpoint (default: `8080`)
- `[shares.<name>]` — `path`, `read_only`, `guest_ok`, `valid_users`
- `[[users]]` — `username`, `password`, `disabled` (NTLMv2; passwords are plaintext
  in the file — mount it as a secret)

## Testing

```sh
cargo test --workspace          # unit tests
tests/live/run.sh               # real SMB2 client (impacket) against a local server
tests/live/mount.sh <server-ip> # real Linux kernel CIFS mount via a privileged container
```

`tests/live/run.sh` needs a Python with impacket (`PY=/path/to/python`).
`tests/live/mount.sh` needs Docker with `--privileged` and a server started with
`tests/live/rssmb-mount.toml` reachable from the container.

## License

MIT OR Apache-2.0
