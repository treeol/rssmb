# Contributing to RSSMB

Thanks for your interest in contributing! RSSMB is pre-1.0 — the core
protocol implementation is complete, but there's plenty to improve.

## Prerequisites

- **Rust 1.85+** (stable channel)
- **Linux** — the server uses `cap-std` + `openat2(RESOLVE_BENEATH)` for path
  confinement, which is Linux-specific
- **Docker** — for running interop tests (`tests/live/mount.sh`)

## Getting Started

```sh
git clone <repo-url> rssmb && cd rssmb
cargo build
cargo test --workspace
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## Development Workflow

1. Create a branch from `main`
2. Make your changes
3. Run the local checks:
   ```sh
   cargo fmt
   cargo clippy --all-targets -- -D warnings
   cargo test --workspace
   ```
4. If touching protocol, auth, or VFS code, run interop tests:
   ```sh
   tests/live/run.sh              # impacket (needs Python)
   tests/live/smbclient.sh        # smbclient
   ```
5. Commit with conventional commit format:
   - `feat(server): add ...`
   - `fix(auth): handle ...`
   - `docs: update ...`
   - `test: add ...`
6. Open a PR — CI runs automatically

## CI Checks

Every push and PR runs:
- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --locked`
- `cargo test --workspace`
- `cargo deny check` (advisories, licenses, bans, sources)
- `cargo audit`
- Interop: impacket + `smbclient`

Nightly (scheduled):
- `smbtorture` conformance baseline
- Fuzz campaigns (9 targets, 5 min each)

## Project Structure

```
crates/
  rssmb-proto/          SMB2/3 wire protocol types
  rssmb-wire-adapter/   Server-side wire codec
  rssmb-auth/           NTLM acceptor, SPNEGO, credential store
  rssmb-vfs/            VFS trait + LocalFs and MemoryFs backends
  rssmb-rpc-server/     DCE/RPC server-side: SrvSvc share enumeration
  rssmb-server/         Core server: connection engine, session, tree, opens
  rssmb-cli/            Server binary: config, signals, health endpoint
  rssmb-tests/          Integration test harness
```

## Security Reports

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for
vulnerability reporting.

## License

By contributing, you agree that your contributions are licensed under
MIT OR Apache-2.0.