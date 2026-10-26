# Lock Audit — std::sync guards across .await + dual-lock ServerState fields

Inventory taken 2026-10-23 on `refactor/dispatch-split` branch.

## 1. std::sync lock guards held across .await points

**No confirmed instances found.** All std::sync guards in the server
crate are scoped to temporary expressions or explicit `let` bindings
that are dropped before the next `.await`:

- `send_unsolicited` (async_helpers.rs:87-94,106): `encryption_ref().read().unwrap()`
  and `signing_ref().read().unwrap()` are scoped inside `if let` expressions that
  complete (and drop the guard) before the `.await` at `write_tx.send` (line 163).
- `teardown_previous_session` (mod.rs:1155-1278): `session_registry.read/write()`,
  `retired_sessions.write()` — each in a scoped block dropped before subsequent
  `.await` calls.
- `handle_plain` retired-session gate (mod.rs:981-984):
  `state.retired_sessions.read().unwrap().contains(&sid)` is a temporary
  dropped at end of statement — not held across await.
- `handle_plain` negotiate gate (mod.rs:909-926): uses `tokio::sync::Mutex`
  (`negotiate_record.lock().await`), not std — safe across awaits.

### Per-site inspection results (2026-10-26, `fix/lock-audit` branch)

All five sites were inspected by hand (read in full context); **no site
holds a std::sync guard across an `.await`. `clippy::await_holding_lock`
(confirming) now gates CI** (see §3).

- `ioctl.rs:95-96` (`FSCTL_VALIDATE_NEGOTIATE_INFO`): `negotiate_record` is
  `Arc<tokio::sync::Mutex<Option<NegotiateRecord>>>` — `.lock().await` takes
  a **tokio async** mutex guard, which is await-safe by construction. The
  guarded body (dialect check, VNI match) is synchronous and returns or
  falls through; no further `.await` is hit while the guard is alive.
- `ioctl.rs:185-186` (`FSCTL_QUERY_NETWORK_INTERFACE_INFO`): same
  tokio-mutex guard; the body checks dialect and reads the lock-free
  `interface_snapshot.get()`. Safe.
- `quic.rs:650` (`test_quic_connection_limiter_refuses_when_full`):
  `_held_guard` is a **test-only RAII admission** from
  `conn_limiter.try_admit` (not a `std::sync` lock guard) held across a
  spawned server task on purpose — it saturates the global connection
  limit so the test can assert refusal. Test-only; no production code
  holds it.
- `connection.rs:650` (encrypt error-reply path): no lock guard at all —
  the code reads `st` fields (key material struct) and calls
  `nonce_source.next()` / `crypto::encrypt_message`. The audit's line
  pointer was stale; the actual preauth hash guards (`preauth_hash_response`,
  `preauth_conn`, `preauth_sessions` std Mutex guards, connection.rs:1014-1029)
  are taken and dropped synchronously inside their `if let` scopes —
  no `.await` inside.
- `connection.rs:1880` (`test_cleanup_drains_opens_and_async_ops_on_disconnect`):
  a `#[tokio::test]` struct literal building a `ConnState`; the std
  `StdRwLock` fields (`active`, `session_shared`) are written once at
  construction and never guarded across an `.await`. Test-only.

**§1 verdict: all sites inspected; zero std::sync guards held across
`.await` anywhere in the server crate.** The earlier "may hold a std
RwLock guard" worry for ioctl.rs was unfounded — the field is a tokio
mutex, not std.

## 2. ServerState fields with dual std/tokio lock variants — resolutions (2026-10-26)

| Field pair | std variant | tokio variant | Resolution |
|---|---|---|---|
| **identities** | `identities_swap: StdRwLock<Arc<IdentityStore>>` (lib.rs) | ~~`identities: Arc<IdentityStore>`~~ | **Collapsed to one.** The boot Arc had zero readers — every auth path uses `identities_snapshot()` (re-cloned per SESSION_SETUP round, sees SIGHUP reloads). Field removed (fix/lock-audit commit 2). Single source: `identities_snapshot()`. |
| **shares** | `shares_swap: StdRwLock<Arc<HashMap<String, ShareConfig>>>` (lib.rs) | `config.shares` (immutable via `Arc<ServerConfig>`) | **Documented split, no change.** All production share lookups (TREE_CONNECT tree_connect.rs, ioctl.rs, write.rs, change_notify.rs, publish-on-close orphan sweep connection.rs) go through `shares_snapshot()`; the `config.shares` path is only read at startup/reload time (construction, validation, CLI logging). Not a dual-lock: the config Arc is never locked, and no runtime lookup reads it. |
| **sessions** | `session_registry: Arc<StdRwLock<HashMap<u64, Arc<SessionShared>>>` + `retired_sessions: StdRwLock<HashSet<u64>>` (lib.rs) | `sessions: Arc<tokio::sync::RwLock<Vec<Arc<Session>>>` (lib.rs) | **Canonical order documented (below); dead `add_session` removed.** |
| **signing/encryption vs trees/opens** | `signing`, `encryption`: `Arc<StdRwLock<HashMap<...>>>` (SessionShared/SessionArcs, dispatch/mod.rs) | `trees`, `opens`: `Arc<tokio::sync::RwLock<...>>` | **Documented split, no change.** The flavor split follows await semantics: `signing`/`encryption` guards are only ever held over synchronous crypto (sign/verify/transform — scoped blocks at mod.rs:946, session_setup.rs:235, async_helpers.rs closure, logoff.rs:106), so std RwLock is correct and faster; `trees`/`opens` are held across `.await` points, so they must be tokio flavors. Std guards on signing/encryption are never alive across an `.await` (verified by hand + `clippy::await_holding_lock`, §3). |

### Canonical session-table order

When `session_registry`, `sessions`, and `retired_sessions` are touched
in the same region, the canonical order (as used by
`teardown_previous_session`, dispatch/mod.rs) is:

1. `session_registry` (read for lookup / write for insert+remove)
2. `sessions` (tokio write, via `remove_session`)
3. `retired_sessions` (write insert)

Every existing site takes these guards **sequentially** — no site holds
two of the three guards simultaneously (`teardown_previous_session` drops
each before taking the next) — so the order is documentation, not a
deadlock fix. New code touching multiple session tables must follow this
order and keep the guards non-overlapping.

`SessionArcs` (dispatch/mod.rs) duplicating the SessionShared Arcs is
inherent to the per-connection snapshot design (ConnState.active); both
hold the same Arcs, so it is aliasing, not a dual lock.

## 3. Clippy gate

`clippy::await_holding_lock` (stable clippy 1.99.1) is enabled in CI as
`-Dclippy::await_holding_lock` alongside `-Dclippy::all`
(`.github/workflows/ci.yml`, `.github/workflows/interop-ci.yml`).
Verified clean across the whole workspace on 2026-10-26 (0 fires) —
machine-confirming §1: no std::sync guard is held across an `.await`
anywhere in the server crate.

## Status: complete (2026-10-26, `fix/lock-audit`)

All sites inspected (§1), all four dual-lock pairs resolved or
documented (§2), lint gate added (§3). The former "Next debt items"
list is closed by this branch; ROADMAP R-06.